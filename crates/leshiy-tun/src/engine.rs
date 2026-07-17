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
use tokio::sync::Semaphore;

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
            // IPv4-only by default; dual-stack is opt-in via `with_ipv6()`. Carrying IPv6 through
            // the tunnel requires the *server* to have working outbound v6 — otherwise the client
            // OS (which prefers IPv6) blackholes every v6-preferred flow and the VPN appears dead.
            // The default therefore fail-closes v6 with the kill-switch; callers that know their
            // server carries v6 opt in explicitly.
            tun_addr6: None,
            server_ip: "0.0.0.0".parse().unwrap(),
            orig_gateway: "0.0.0.0".parse().unwrap(),
            orig_gateway6: None,
            dns: vec!["1.1.1.1".parse().unwrap()],
            split: leshiy_client::SplitPlan::default(),
        }
    }
}

impl TunConfig {
    /// The IPv6 ULA assigned to the TUN interface when dual-stack is opted into. A ULA
    /// (`fd00::/8`) so it never collides with a real prefix; the `::/1`+`8000::/1` override
    /// carries all v6 through the tunnel.
    pub fn default_tun_addr6() -> IpAddr {
        "fd00:71::2".parse().unwrap()
    }

    /// Opt into carrying IPv6 *through* the tunnel (dual-stack), assigning the TUN's v6 ULA.
    /// Only meaningful when the server has working outbound IPv6; otherwise leave it off so v6
    /// is fail-closed by the kill-switch. Backends that can't carry v6 (Android/stub) still zero
    /// this via the [`PrivilegedOps::CARRIES_V6`](crate::sys::PrivilegedOps::CARRIES_V6) gate.
    #[must_use]
    pub fn with_ipv6(mut self) -> Self {
        self.tun_addr6 = Some(Self::default_tun_addr6());
        self
    }

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
        self.tun_addr6.is_none()
            && matches!(self.split.base_mode, leshiy_client::SplitMode::Exclude)
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

/// Cap on concurrently-serviced flows (TCP + UDP + ICMP-echo). Each device flow spawns a task
/// holding a mux stream and a per-flow buffer; without a cap a local process opening sockets (or
/// `ping -f`-ing many hosts) faster than they complete grows tasks/mux-streams without bound and
/// exhausts memory (M10). Past the cap, new flows are dropped — which to the originating app looks
/// like ordinary packet loss / an unreachable host, exactly what an overloaded link produces.
const MAX_CONCURRENT_FLOWS: usize = 4096;

/// Aborts the wrapped task on drop. Ties the detached domain-resolver task's lifetime to the
/// engine future, so it stops the instant the session ends or is aborted (rather than
/// continuing to mutate routes after disconnect).
///
/// On the *normal* shutdown path, prefer [`shutdown`](Self::shutdown), which additionally awaits
/// the task's termination so no route-installing `.await` is still in flight (and racing the
/// bypass teardown that runs next) — the `Drop` path is only the abnormal-cancellation backstop.
struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);
impl AbortOnDrop {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
    /// Abort the task and wait for it to actually stop before returning. Combined with the
    /// backends recording each bypass route *before* issuing its OS call, this guarantees the
    /// resolver can neither leave a route unrecorded nor push a new one concurrently with the
    /// teardown that runs immediately after — closing the cross-session route-leak (H7).
    async fn shutdown(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
            let _ = handle.await; // returns Err(Cancelled); we only need it fully stopped
        }
    }
}
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
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
    /// Run until cancelled. Equivalent to [`run_with_reattach`](Self::run_with_reattach) with a
    /// reattach signal that never fires — which is every platform but Android.
    pub async fn run(
        tunnel: Arc<dyn Tunnel>,
        cfg: TunConfig,
        counters: Arc<ByteCounters>,
        cancel: Arc<Notify>,
    ) -> std::io::Result<()> {
        Self::run_with_reattach(tunnel, cfg, counters, cancel, Arc::new(Notify::new())).await
    }

    /// As [`run`](Self::run), but re-attaches to a newly-established TUN device each time
    /// `reattach` fires, keeping the dialed tunnel.
    ///
    /// Android's route updates work this way: a `VpnService` interface's routes are immutable, so
    /// changing them means `establish()`ing a new one and picking up its fd. See
    /// [`PrivilegedOps::reattach_device`](crate::sys::PrivilegedOps::reattach_device).
    pub async fn run_with_reattach(
        tunnel: Arc<dyn Tunnel>,
        cfg: TunConfig,
        counters: Arc<ByteCounters>,
        cancel: Arc<Notify>,
        reattach: Arc<Notify>,
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
        // Include a lower-bound estimate of the domain-driven routes (≥1 per domain) so a large
        // subscription list warns up front, not only once the resolver installs them (M12).
        let domain_route_estimate = eff_include.domains.len() + eff_exclude.domains.len();
        let route_count = plan.via_tun.len() + plan.bypass.len() + domain_route_estimate;
        if route_count > ROUTE_WARN_THRESHOLD {
            tracing::warn!(
                route_count,
                domain_route_estimate,
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
        tracing::info!(tun = %cfg.tun_name, mtu = cfg.mtu, server_ip = %cfg.server_ip, "tun engine running; reading packets from the device");

        // Keep a handle to the controller for the fast in-process bypass teardown below (the
        // resolver, if spawned, takes its own clone).
        let teardown_controller = controller.clone();
        // Domain rules (if any) are resolved + refreshed by a background task. `AbortOnDrop`
        // (declared after `guard`, so dropped before it) stops the task before `guard`'s
        // teardown removes the routes it installed — clean on both normal exit and abort.
        let has_domains = !eff_include.domains.is_empty() || !eff_exclude.domains.is_empty();
        let mut resolver = has_domains.then(move || {
            AbortOnDrop::new(tokio::spawn(crate::resolver::run_resolver(
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
        let result = pump(device, cfg.mtu, tunnel, counters, cancel, reattach).await;
        // Stop the resolver BEFORE teardown removes its routes — and *await* its termination, so no
        // in-flight route install can push into `installed_bypass` after teardown drains it (H7).
        if let Some(r) = resolver.as_mut() {
            r.shutdown().await;
        }
        drop(resolver);
        // Remove bypass routes in-process (fast) BEFORE dropping the guard, so a large rule set
        // doesn't hit the guard's slow per-route subprocess fallback (which makes disconnect take
        // minutes and wedges reconnect). No-op on Linux (its guard batches) / when there are none.
        teardown_controller.teardown_bypass().await;
        // `pump` already dropped the netstack + device (override routes auto-clear).
        drop(guard); // restore DNS + IPv6 (bypass list now empty) — runs to completion here
        result
    }
}

/// What ended a pump iteration.
enum Pumped {
    Stop(std::io::Result<()>),
    Reattach,
}

/// Read packets until cancelled, rebuilding the netstack whenever `reattach` fires.
///
/// The netstack owns the device, so re-attaching means constructing a new one — and its per-flow
/// session state does not survive, because there is nothing to migrate it into. In-flight
/// connections therefore break, which is why callers must only reattach when the route set
/// genuinely changed. What *does* survive is the dialed tunnel, so a route change costs no
/// REALITY handshake.
///
/// This returns before the caller's teardown so the netstack and device are released in the
/// controlled order the Wintun path needs (see `run_with_reattach`).
async fn pump(
    mut device: tun::AsyncDevice,
    mtu: u16,
    tunnel: Arc<dyn Tunnel>,
    counters: Arc<ByteCounters>,
    cancel: Arc<Notify>,
    reattach: Arc<Notify>,
) -> std::io::Result<()> {
    // Shared across reattach so the flow cap is global to the session, not reset per device.
    let flow_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_FLOWS));
    loop {
        let mut ip_stack = netstack::build(device, mtu)?;
        let pumped = tokio::select! {
            biased;
            () = cancel.notified() => {
                tracing::info!("tun engine cancel requested; tearing down");
                Pumped::Stop(Ok(()))
            }
            () = reattach.notified() => Pumped::Reattach,
            r = accept_loop(&mut ip_stack, tunnel.clone(), counters.clone(), flow_sem.clone()) => {
                tracing::info!(?r, "tun engine accept loop exited");
                Pumped::Stop(r)
            }
        };
        // Release the old netstack and its fd before taking the new one. The platform requires a
        // superseded interface's fd to be closed; dropping the device does that.
        drop(ip_stack);
        match pumped {
            Pumped::Stop(r) => return r,
            Pumped::Reattach => {
                device = PlatformOps.reattach_device().await?;
                tracing::info!("tun device reattached; routes updated, tunnel kept");
            }
        }
    }
}

async fn accept_loop(
    ip_stack: &mut ipstack::IpStack,
    tunnel: Arc<dyn Tunnel>,
    counters: Arc<ByteCounters>,
    flow_sem: Arc<Semaphore>,
) -> std::io::Result<()> {
    loop {
        match ip_stack.accept().await.map_err(to_io)? {
            IpStackStream::Tcp(tcp) => {
                let dst = tcp.peer_addr();
                // Bound concurrent flows (M10): drop the flow if we're at the cap. Held for the
                // task's lifetime, so the permit frees when the flow ends.
                let Ok(permit) = flow_sem.clone().try_acquire_owned() else {
                    tracing::debug!(%dst, "flow cap reached; dropping tcp flow");
                    continue;
                };
                tracing::debug!(%dst, "tcp flow opened");
                let t = tunnel.clone();
                let c = counters.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = pump_tcp(t, dst, tcp, c).await {
                        tracing::info!(%dst, "tcp flow ended: {e}");
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                let dst = udp.peer_addr();
                let Ok(permit) = flow_sem.clone().try_acquire_owned() else {
                    tracing::debug!(%dst, "flow cap reached; dropping udp flow");
                    continue;
                };
                tracing::debug!(%dst, "udp flow opened");
                let t = tunnel.clone();
                let c = counters.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = pump_udp(t, dst, udp, c).await {
                        tracing::info!(%dst, "udp flow ended: {e}");
                    }
                });
            }
            // ipstack surfaces every non-TCP/UDP packet here, one accept per packet with no
            // session behind it, so an echo request is handled start-to-finish in one task.
            // ICMP echo rides the tunnel (ADR-0030); everything else is still dropped.
            IpStackStream::UnknownTransport(u) => {
                let Ok(permit) = flow_sem.clone().try_acquire_owned() else {
                    tracing::debug!("flow cap reached; dropping icmp echo");
                    continue;
                };
                let t = tunnel.clone();
                let c = counters.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = relay_icmp_echo(t, u, c).await {
                        tracing::debug!("icmp echo dropped: {e}");
                    }
                });
            }
            IpStackStream::UnknownNetwork(_) => {
                tracing::debug!("read an unparseable packet (dropped)")
            }
        }
    }
}

/// How long to wait for an echo reply before giving up on one request. Past this the association
/// is dropped and the packet is simply never answered — which is what an unreachable host looks
/// like anyway, so `ping` reports the loss it should.
const ICMP_REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay one ICMP echo request through the tunnel and write the reply back to the device.
///
/// One association per request. That sounds wasteful until you notice ipstack hands us each
/// non-TCP/UDP packet as an independent one-shot with no session behind it, so there is nothing
/// to keep alive between packets — and `ping` emits one per second, so the four frames this costs
/// are noise. It buys us no cache, no idle expiry, and no lifetime bugs.
///
/// Anything that is not an echo request is dropped here, before it reaches the tunnel: Redirect
/// and friends only mean something relative to a routing topology the exit does not share.
async fn relay_icmp_echo(
    tunnel: Arc<dyn Tunnel>,
    u: ipstack::IpStackUnknownTransport,
    counters: Arc<ByteCounters>,
) -> std::io::Result<()> {
    use leshiy_core::icmp;

    let (src, dst) = (u.src_addr(), u.dst_addr());
    let v6 = dst.is_ipv6();
    let want = if v6 {
        icmp::IPPROTO_ICMPV6
    } else {
        icmp::IPPROTO_ICMPV4
    };
    if u.ip_protocol().0 != want {
        return Err(std::io::Error::other("not ICMP"));
    }
    let req = u.payload().to_vec();
    if icmp::parse_echo_request(&req, v6).is_none() {
        return Err(std::io::Error::other("not an echo request"));
    }

    // The association target is a bare IP — ICMP has no ports.
    let mut flow = tunnel
        .open_icmp(&dst.to_string())
        .await
        .map_err(|e| std::io::Error::other(format!("open: {e}")))?;
    counters.add_up(req.len() as u64);
    flow.send(req.into())
        .await
        .map_err(|e| std::io::Error::other(format!("send: {e}")))?;

    let reply = tokio::time::timeout(ICMP_REPLY_TIMEOUT, flow.recv())
        .await
        .map_err(|_| std::io::Error::other("echo reply timed out"))?
        .map_err(|e| std::io::Error::other(format!("recv: {e}")))?;
    counters.add_down(reply.len() as u64);
    let _ = flow.close().await;

    let mut reply = reply.to_vec();
    if !icmp::is_echo_reply(&reply, v6) {
        return Err(std::io::Error::other("peer returned a non-echo-reply"));
    }
    // The server restored the identifier but could only finish a v4 checksum: a v6 one covers a
    // pseudo-header of both addresses, and the server has no business knowing our TUN address.
    // We do, so we complete it here. ipstack writes the payload verbatim with no transport
    // checksum of its own, so an unfinished one would just be dropped by the local stack.
    if v6 && let (IpAddr::V6(s), IpAddr::V6(d)) = (dst, src) {
        // Reply direction: it comes *from* the pinged host *to* us.
        if !icmp::set_v6_checksum(&mut reply, &s.octets(), &d.octets()) {
            return Err(std::io::Error::other("reply too short to checksum"));
        }
    }
    u.send(reply)
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
    fn default_is_ipv4_only_with_killswitch() {
        // Dual-stack is opt-in: the default session is IPv4-only (Exclude base), so DNS is forced
        // and IPv6 is fail-closed by the kill-switch rather than carried through the tunnel.
        let c = TunConfig::default();
        assert_eq!(c.tun_addr6, None);
        assert!(c.force_dns());
        assert!(c.ipv6_killswitch());
    }

    #[test]
    fn opt_in_ipv6_carries_v6_and_drops_killswitch() {
        // Explicitly opting into dual-stack assigns the TUN's v6 ULA and, under the Exclude base,
        // carries IPv6 through the tunnel (no kill-switch).
        let c = TunConfig::default().with_ipv6();
        assert_eq!(c.tun_addr6, Some(TunConfig::default_tun_addr6()));
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
