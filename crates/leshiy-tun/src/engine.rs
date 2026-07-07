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
use tokio::sync::Notify;

/// Configuration for one full-tunnel session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunConfig {
    pub tun_name: String,
    /// TUN MTU — kept below the transport's to absorb TLS + mux framing overhead.
    pub mtu: u16,
    pub tun_addr: IpAddr,
    /// IPv6 address for the TUN interface. `Some` carries IPv6 *through* the tunnel
    /// (dual-stack); `None` keeps the session IPv4-only with the v6 kill-switch. Best-effort
    /// on the host side — a backend that can't assign it fails closed to the kill-switch.
    pub tun_addr6: Option<IpAddr>,
    /// The VPN server's own IP (excepted from the tunnel to avoid a routing loop).
    pub server_ip: IpAddr,
    /// The original default gateway (server-family), captured before routes are changed.
    pub orig_gateway: IpAddr,
    /// The original IPv6 default gateway, for routing IPv6 split-tunnel excludes (bypass) around
    /// the tunnel when the server is reached over IPv4. `None` = no v6 gateway (v6 excludes then
    /// ride the tunnel).
    pub orig_gateway6: Option<IpAddr>,
    /// DNS resolver(s) forced while the tunnel is up (queries ride the tunnel).
    pub dns: Vec<IpAddr>,
    /// Two-directional split-tunnel plan (manual rules + subscriptions, merged). Empty (the
    /// default) = plain full tunnel.
    pub split: leshiy_client::SplitPlan,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            tun_name: "leshiy0".into(),
            mtu: 1400,
            tun_addr: "10.71.0.2".parse().unwrap(),
            // Dual-stack by default: a ULA on the TUN so IPv6 rides the tunnel. Backends that
            // don't carry v6 (Android/stub) zero this in the engine via CARRIES_V6 and fail
            // closed to the kill-switch, so this default is safe on every platform.
            tun_addr6: Some("fd00:71::2".parse().unwrap()),
            server_ip: "0.0.0.0".parse().unwrap(),
            orig_gateway: "0.0.0.0".parse().unwrap(),
            orig_gateway6: None,
            dns: vec!["1.1.1.1".parse().unwrap()],
            split: leshiy_client::SplitPlan::default(),
        }
    }
}

impl TunConfig {
    /// Force the system DNS through the tunnel? Only when the base policy is Exclude
    /// (full-tunnel-ish); under an Include base most traffic is direct, so the resolver is left
    /// untouched.
    pub fn force_dns(&self) -> bool {
        matches!(self.split.base_mode, leshiy_client::SplitMode::Exclude)
    }

    /// Apply the IPv6 fail-closed kill-switch? Only when we are **not** carrying IPv6 through
    /// the tunnel (`tun_addr6` is `None`) AND the base mode tunnels the default route (Exclude).
    /// With a v6 TUN address, IPv6 rides the tunnel via the `::/1` override, so killing it would
    /// break connectivity; under an Include base the un-tunneled majority must stay reachable.
    pub fn ipv6_killswitch(&self) -> bool {
        self.tun_addr6.is_none() && matches!(self.split.base_mode, leshiy_client::SplitMode::Exclude)
    }
}

/// Format a destination as the `host:port` target the egress expects. `SocketAddr`'s Display
/// brackets IPv6 correctly (`[2001:db8::1]:443`), which the egress/resolver parse; the old V6
/// arm emitted an unbracketed, unresolvable `2001:db8::1:443`.
pub(crate) fn target_of(dst: SocketAddr) -> String {
    dst.to_string()
}

/// Idle timeout for a UDP association (no teardown signal on UDP). Kept short so an
/// idle device (e.g. after a DNS burst) lets the tunnel quiesce sooner, which matters
/// for battery on mobile.
const UDP_IDLE: Duration = Duration::from_secs(30);

/// Above this many installed routes, warn about routing-table bloat / slow per-OS install.
const ROUTE_WARN_THRESHOLD: usize = 5000;

/// Aborts the wrapped task on drop. Ties the detached domain-resolver task's lifetime to the
/// engine future, so it stops the instant the session ends or is aborted (rather than
/// continuing to mutate routes after disconnect).
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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
        cancel: Arc<Notify>,
    ) -> std::io::Result<()> {
        // Platforms whose backend doesn't carry IPv6 (Android/stub) must not leave a v6 TUN
        // address set — otherwise the kill-switch would be skipped and v6 would leak around a
        // v6-unaware backend. Zero it here so those platforms fail closed.
        let mut cfg = cfg;
        if !<PlatformOps as PrivilegedOps>::CARRIES_V6 {
            cfg.tun_addr6 = None;
        }
        // Drop provably-redundant rules (e.g. Include rules under an Exclude base with no
        // excludes are already tunneled) before installing routes / resolving domains.
        let (eff_include, eff_exclude) = cfg.split.effective();
        let include_cidrs: Vec<crate::route_plan::Cidr> =
            eff_include.cidrs.iter().copied().map(Into::into).collect();
        let exclude_cidrs: Vec<crate::route_plan::Cidr> =
            eff_exclude.cidrs.iter().copied().map(Into::into).collect();
        let plan = RoutePlan::from_split(
            cfg.split.base_mode,
            &include_cidrs,
            &exclude_cidrs,
            cfg.server_ip,
            cfg.orig_gateway,
            cfg.orig_gateway6,
            cfg.tun_addr,
            cfg.tun_addr6,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        // Large rule sets bloat the routing table — and on macOS/Windows each route is a
        // separate `route`/`netsh` subprocess, so a big list installs slowly. Warn so it's
        // diagnosable (the engine still proceeds).
        let route_count = plan.via_tun.len() + plan.bypass.len();
        if route_count > ROUTE_WARN_THRESHOLD {
            tracing::warn!(
                route_count,
                "split-tunnel: large rule set; route installation may be slow (esp. macOS/Windows)"
            );
        }
        let TunSession {
            device,
            guard,
            controller,
        } = PlatformOps
            .start(
                &cfg.tun_name,
                cfg.mtu,
                &plan,
                &cfg.dns,
                cfg.force_dns(),
                cfg.ipv6_killswitch(),
            )
            .await?;
        let mut ip_stack = netstack::build(device, cfg.mtu)?;
        tracing::info!(tun = %cfg.tun_name, mtu = cfg.mtu, server_ip = %cfg.server_ip, "tun engine running; reading packets from the device");

        // Keep a handle to the controller for the fast in-process bypass teardown below (the
        // resolver, if spawned, takes its own clone).
        let teardown_controller = controller.clone();
        // Domain rules (if any) are resolved + refreshed by a background task. `AbortOnDrop`
        // (declared after `guard`, so dropped before it) stops the task before `guard`'s
        // teardown removes the routes it installed — clean on both normal exit and abort.
        let has_domains = !eff_include.domains.is_empty() || !eff_exclude.domains.is_empty();
        let _resolver = has_domains.then(move || {
            AbortOnDrop(tokio::spawn(crate::resolver::run_resolver(
                controller,
                eff_include.domains,
                eff_exclude.domains,
                crate::resolver::REFRESH,
            )))
        });

        // Run until the accept loop errors OR the caller signals a graceful stop. We must NOT rely
        // on the spawned task being aborted for teardown: aborting drops the netstack mid-flight,
        // and the Wintun reader's blocking `WaitForMultipleObjects` is only released by the
        // session's clean shutdown path — which a cancellation-context drop skips. The adapter then
        // never releases and the next session fails with "rings already registered" (0x4DF). So the
        // caller signals `cancel`; we return normally and tear down in a controlled order, which
        // guarantees the route/DNS restore (`guard`) runs to completion before we return.
        let result = tokio::select! {
            biased;
            () = cancel.notified() => {
                tracing::info!("tun engine cancel requested; tearing down");
                Ok(())
            }
            r = accept_loop(&mut ip_stack, tunnel, counters) => {
                tracing::info!(?r, "tun engine accept loop exited");
                r
            }
        };
        drop(_resolver); // stop the resolver BEFORE teardown removes its routes
        // Remove bypass routes in-process (fast) BEFORE dropping the guard, so a large rule set
        // doesn't hit the guard's slow per-route subprocess fallback (which makes disconnect take
        // minutes and wedges reconnect). No-op on Linux (its guard batches) / when there are none.
        teardown_controller.teardown_bypass().await;
        drop(ip_stack); // release the netstack/TUN device (override routes auto-clear)
        drop(guard); // restore DNS + IPv6 (bypass list now empty) — runs to completion here
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
                stream
                    .send(bytes::Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .map_err(to_io)?;
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
                assoc
                    .send(bytes::Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .map_err(to_io)?;
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
    fn target_string_ipv6_is_bracketed() {
        let dst: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(target_of(dst), "[2001:db8::1]:443");
    }

    #[test]
    fn default_mtu_is_1400() {
        assert_eq!(TunConfig::default().mtu, 1400);
    }

    #[test]
    fn default_split_is_empty_exclude() {
        let c = TunConfig::default();
        assert!(c.split.is_empty());
        assert_eq!(c.split.base_mode, leshiy_client::SplitMode::Exclude);
    }

    #[test]
    fn dual_stack_default_forces_dns_but_not_killswitch() {
        // Default is Exclude + dual-stack (tun_addr6 Some): DNS forced, IPv6 carried (not killed).
        let c = TunConfig::default();
        assert!(c.force_dns());
        assert!(!c.ipv6_killswitch());
    }

    #[test]
    fn ipv4_only_applies_killswitch() {
        // Without a v6 TUN address, IPv6 is fail-closed under an Exclude base.
        let c = TunConfig {
            tun_addr6: None,
            ..TunConfig::default()
        };
        assert!(c.ipv6_killswitch());
    }

    #[test]
    fn include_mode_disables_dns_and_ipv6_killswitch() {
        use leshiy_client::{SplitMode, SplitPlan};
        let c = TunConfig {
            split: SplitPlan {
                base_mode: SplitMode::Include,
                ..Default::default()
            },
            ..TunConfig::default()
        };
        assert!(!c.force_dns());
        assert!(!c.ipv6_killswitch());
    }

    use async_trait::async_trait;
    use leshiy_client::Result as ClientResult;

    /// Fake tunnel stream: `recv` yields `to_return` once (then EOF), `send` is discarded.
    struct FakeStream {
        to_return: Option<bytes::Bytes>,
        /// When true, `recv` never resolves — used to isolate the upload direction.
        recv_pends: bool,
    }

    #[async_trait]
    impl ProxyStream for FakeStream {
        async fn send(&mut self, _data: bytes::Bytes) -> ClientResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> ClientResult<bytes::Bytes> {
            if self.recv_pends {
                std::future::pending::<()>().await;
            }
            // Some(bytes) once, then an empty chunk which callers treat as EOF.
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
            to_return: Some(bytes::Bytes::from_static(b"world!")), // 6 bytes tunnel→device (down)
            recv_pends: false,
        });
        relay_tcp(far, stream, &counters).await.unwrap();
        assert_eq!(counters.totals(), (0, 6));
    }
}
