//! The TUN engine: device → userspace netstack → leshiy `Tunnel`.
//!
//! Each TCP flow opens a mux stream to its destination; each UDP flow opens a datagram
//! association. The `TunSession` guard (held for the engine's lifetime) restores DNS/IPv6
//! on exit, and the override routes auto-clear when the device drops.
use crate::netstack;
use crate::route_plan::RoutePlan;
use crate::sys::{PlatformOps, PrivilegedOps, TunSession};
use ipstack::IpStackStream;
use leshiy_client::Tunnel;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

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
    pub async fn run(tunnel: Arc<dyn Tunnel>, cfg: TunConfig) -> std::io::Result<()> {
        let plan = RoutePlan::full_tunnel(cfg.server_ip, cfg.orig_gateway, cfg.tun_addr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let TunSession { device, guard } = PlatformOps
            .start(&cfg.tun_name, cfg.mtu, &plan, &cfg.dns)
            .await?;
        let mut ip_stack = netstack::build(device, cfg.mtu)?;
        tracing::info!(tun = %cfg.tun_name, mtu = cfg.mtu, server_ip = %cfg.server_ip, "tun engine running; reading packets from the device");
        let result = accept_loop(&mut ip_stack, tunnel).await;
        tracing::info!(?result, "tun engine accept loop exited");
        drop(guard); // restore DNS + IPv6
        result
    }
}

async fn accept_loop(
    ip_stack: &mut ipstack::IpStack,
    tunnel: Arc<dyn Tunnel>,
) -> std::io::Result<()> {
    loop {
        match ip_stack.accept().await.map_err(to_io)? {
            IpStackStream::Tcp(tcp) => {
                let dst = tcp.peer_addr();
                tracing::info!(%dst, "tcp flow opened (read a packet from the device)");
                let t = tunnel.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_tcp(t, dst, tcp).await {
                        tracing::info!(%dst, "tcp flow ended: {e}");
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                let dst = udp.peer_addr();
                tracing::info!(%dst, "udp flow opened (read a packet from the device)");
                let t = tunnel.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_udp(t, dst, udp).await {
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
    mut flow: ipstack::IpStackTcpStream,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tunnel.open(&target_of(dst)).await.map_err(to_io)?;
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            inbound = stream.recv() => match inbound {
                Ok(b) if !b.is_empty() => flow.write_all(&b).await?,
                _ => break,
            },
            r = flow.read(&mut buf) => {
                let n = r?;
                if n == 0 { break; }
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
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut assoc = tunnel.open_datagram(&target_of(dst)).await.map_err(to_io)?;
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            inbound = assoc.recv() => match inbound {
                Ok(b) if !b.is_empty() => flow.write_all(&b).await?,
                _ => break,
            },
            r = flow.read(&mut buf) => {
                let n = r?;
                if n == 0 { break; }
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
}
