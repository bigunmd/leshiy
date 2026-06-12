//! The TUN engine: device → userspace netstack → leshiy `Tunnel`.
//!
//! Each TCP flow opens a mux stream to its destination; each UDP flow opens a datagram
//! association. The `TunSession` guard (held for the engine's lifetime) restores DNS/IPv6
//! on exit, and the override routes auto-clear when the device drops.
use crate::netstack;
use crate::route_plan::RoutePlan;
use crate::sys::{PlatformOps, PrivilegedOps, TunSession};
use ipstack::IpStackStream;
use leshiy_client::{ByteCounters, ProxyStream, Tunnel};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Configuration for one full-tunnel session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunConfig {
    pub tun_name: String,
    /// TUN MTU — kept below the transport's to absorb TLS + mux framing overhead.
    pub mtu: u16,
    pub tun_addr: IpAddr,
    /// The VPN server's own IP (excepted from the tunnel to avoid a routing loop).
    pub server_ip: IpAddr,
    /// The original default gateway, captured before routes are changed.
    pub orig_gateway: IpAddr,
    /// DNS resolver(s) forced while the tunnel is up (queries ride the tunnel).
    pub dns: Vec<IpAddr>,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            tun_name: "leshiy0".into(),
            mtu: 1400,
            tun_addr: "10.71.0.2".parse().unwrap(),
            server_ip: "0.0.0.0".parse().unwrap(),
            orig_gateway: "0.0.0.0".parse().unwrap(),
            dns: vec!["1.1.1.1".parse().unwrap()],
        }
    }
}

/// Format a destination as the `host:port` target the egress expects.
pub(crate) fn target_of(dst: SocketAddr) -> String {
    match dst {
        SocketAddr::V4(_) => dst.to_string(),
        SocketAddr::V6(a) => format!("{}:{}", a.ip(), a.port()),
    }
}

/// Idle timeout for a UDP association (no teardown signal on UDP).
const UDP_IDLE: Duration = Duration::from_secs(60);

pub struct TunEngine;

impl TunEngine {
    /// Run until the device errors or the process is signalled. Owns the `TunSession`
    /// guard for the duration, so DNS/IPv6 are restored when this future is dropped.
    ///
    /// `counters` accumulate tunneled bytes (up = device→tunnel, down = tunnel→device); the
    /// helper samples them for the GUI's live throughput. Callers that don't display stats
    /// (e.g. the `leshiy tun` CLI) can pass a throwaway `Arc::new(ByteCounters::new())`.
    pub async fn run(
        tunnel: Arc<dyn Tunnel>,
        cfg: TunConfig,
        counters: Arc<ByteCounters>,
    ) -> std::io::Result<()> {
        let plan = RoutePlan::full_tunnel(cfg.server_ip, cfg.orig_gateway, cfg.tun_addr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let TunSession { device, guard } = PlatformOps
            .start(&cfg.tun_name, cfg.mtu, &plan, &cfg.dns)
            .await?;
        let mut ip_stack = netstack::build(device, cfg.mtu)?;
        tracing::info!(tun = %cfg.tun_name, mtu = cfg.mtu, server_ip = %cfg.server_ip, "tun engine running; reading packets from the device");
        let result = accept_loop(&mut ip_stack, tunnel, counters).await;
        tracing::info!(?result, "tun engine accept loop exited");
        drop(guard); // restore DNS + IPv6
        result
    }
}

async fn accept_loop(
    ip_stack: &mut ipstack::IpStack,
    tunnel: Arc<dyn Tunnel>,
    counters: Arc<ByteCounters>,
) -> std::io::Result<()> {
    loop {
        match ip_stack.accept().await.map_err(to_io)? {
            IpStackStream::Tcp(tcp) => {
                let dst = tcp.peer_addr();
                tracing::debug!(%dst, "tcp flow opened");
                let t = tunnel.clone();
                let c = counters.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_tcp(t, dst, tcp, c).await {
                        tracing::info!(%dst, "tcp flow ended: {e}");
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                let dst = udp.peer_addr();
                tracing::debug!(%dst, "udp flow opened");
                let t = tunnel.clone();
                let c = counters.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_udp(t, dst, udp, c).await {
                        tracing::info!(%dst, "udp flow ended: {e}");
                    }
                });
            }
            // ICMP and unparseable packets are dropped in this phase — but log so we can tell
            // packets ARE arriving from the device (vs. nothing being read at all).
            IpStackStream::UnknownTransport(_) => {
                tracing::debug!("read a non-TCP/UDP packet (dropped)")
            }
            IpStackStream::UnknownNetwork(_) => {
                tracing::debug!("read an unparseable packet (dropped)")
            }
        }
    }
}

async fn pump_tcp(
    tunnel: Arc<dyn Tunnel>,
    dst: SocketAddr,
    flow: ipstack::IpStackTcpStream,
    counters: Arc<ByteCounters>,
) -> std::io::Result<()> {
    let stream = tunnel.open(&target_of(dst)).await.map_err(to_io)?;
    relay_tcp(flow, stream, &counters).await
}

/// Bidirectional copy between a device flow and a tunnel stream, metering bytes:
/// device→tunnel counts as **up**, tunnel→device as **down**. Generic over the flow so the
/// counting is unit-testable with an in-memory duplex.
async fn relay_tcp<F>(
    mut flow: F,
    mut stream: Box<dyn ProxyStream>,
    counters: &ByteCounters,
) -> std::io::Result<()>
where
    F: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            inbound = stream.recv() => match inbound {
                Ok(b) if !b.is_empty() => {
                    counters.add_down(b.len() as u64);
                    flow.write_all(&b).await?;
                }
                _ => break,
            },
            r = flow.read(&mut buf) => {
                let n = r?;
                if n == 0 { break; }
                counters.add_up(n as u64);
                stream.send(buf[..n].to_vec()).await.map_err(to_io)?;
            }
        }
    }
    let _ = stream.close().await;
    Ok(())
}

async fn pump_udp(
    tunnel: Arc<dyn Tunnel>,
    dst: SocketAddr,
    mut flow: ipstack::IpStackUdpStream,
    counters: Arc<ByteCounters>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut assoc = tunnel.open_datagram(&target_of(dst)).await.map_err(to_io)?;
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            inbound = assoc.recv() => match inbound {
                Ok(b) if !b.is_empty() => {
                    counters.add_down(b.len() as u64);
                    flow.write_all(&b).await?;
                }
                _ => break,
            },
            r = flow.read(&mut buf) => {
                let n = r?;
                if n == 0 { break; }
                counters.add_up(n as u64);
                assoc.send(buf[..n].to_vec()).await.map_err(to_io)?;
            }
            _ = tokio::time::sleep(UDP_IDLE) => break,
        }
    }
    let _ = assoc.close().await;
    Ok(())
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_string_ipv4_is_host_port() {
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        assert_eq!(target_of(dst), "1.2.3.4:443");
    }

    #[test]
    fn default_mtu_is_1400() {
        assert_eq!(TunConfig::default().mtu, 1400);
    }

    use async_trait::async_trait;
    use leshiy_client::Result as ClientResult;

    /// Fake tunnel stream: `recv` yields `to_return` once (then EOF), `send` is discarded.
    struct FakeStream {
        to_return: Option<Vec<u8>>,
        /// When true, `recv` never resolves — used to isolate the upload direction.
        recv_pends: bool,
    }

    #[async_trait]
    impl ProxyStream for FakeStream {
        async fn send(&mut self, _data: Vec<u8>) -> ClientResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> ClientResult<Vec<u8>> {
            if self.recv_pends {
                std::future::pending::<()>().await;
            }
            // Some(bytes) once, then an empty Vec which callers treat as EOF.
            Ok(self.to_return.take().unwrap_or_default())
        }
        async fn close(&mut self) -> ClientResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn relay_counts_upload_bytes() {
        use tokio::io::AsyncWriteExt;
        let counters = ByteCounters::new();
        // Test holds one duplex end; the relay reads the other as its `flow`.
        let (mut near, far) = tokio::io::duplex(64);
        near.write_all(b"hello").await.unwrap(); // 5 bytes device→tunnel (up)
        near.shutdown().await.unwrap(); // EOF so the relay's flow.read returns 0 → break
        let stream = Box::new(FakeStream {
            to_return: None,
            recv_pends: true, // no download traffic in this test
        });
        relay_tcp(far, stream, &counters).await.unwrap();
        assert_eq!(counters.totals(), (5, 0));
    }

    #[tokio::test]
    async fn relay_counts_download_bytes() {
        let counters = ByteCounters::new();
        // Keep `near` alive (unread) so the relay's flow.read stays pending; the loop ends
        // when the fake stream returns its one chunk and then an empty (EOF) Vec.
        let (_near, far) = tokio::io::duplex(64);
        let stream = Box::new(FakeStream {
            to_return: Some(b"world!".to_vec()), // 6 bytes tunnel→device (down)
            recv_pends: false,
        });
        relay_tcp(far, stream, &counters).await.unwrap();
        assert_eq!(counters.totals(), (0, 6));
    }
}
