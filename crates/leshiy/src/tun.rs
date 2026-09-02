//! `leshiy tun`: dial the URI to a Tunnel, discover the server IP + original gateway,
//! and run the full-tunnel engine. Must run with root / CAP_NET_ADMIN.
use anyhow::{Context, Result, anyhow};
use leshiy_client::{
    RealTransport, ReconnectParams, ReconnectingTunnel, Transport as _, TransportPref,
};
use leshiy_reality::config::RealityUri;
use leshiy_tun::{TunConfig, TunEngine};
use std::sync::Arc;

/// Bind the combined mode's SOCKS listener, refusing anything but a loopback address.
///
/// Not a routing concern — LAN replies work fine, since only prefix-length 0 is suppressed
/// from the main table. The problem is exposure: an unauthenticated SOCKS5 proxy reachable
/// off-host is both an abuse vector and a loud signal to scanners, and service mode would
/// turn a one-off `--socks 0.0.0.0:1080` into a permanent, boot-time exposure.
async fn bind_local_socks(addr: &str) -> Result<tokio::net::TcpListener> {
    let parsed: std::net::SocketAddr = addr.parse().with_context(|| format!("parse {addr}"))?;
    if !parsed.ip().is_loopback() {
        anyhow::bail!(
            "--socks {addr} is not a loopback address; combined VPN+proxy mode only binds \
             loopback, since an off-host SOCKS5 proxy would be an open relay. Use \
             127.0.0.1 or ::1, or run `leshiy client` separately if you really want this."
        );
    }
    tokio::net::TcpListener::bind(parsed)
        .await
        .with_context(|| format!("bind SOCKS5 listener on {addr}"))
}

/// Report a usable tunnel once the dial has succeeded and the SOCKS port (if any) is held.
fn announce(tun_name: &str, socks: Option<&str>) {
    let scope = if crate::service::running_under_wsl() {
        " (WSL2: this tunnels WSL traffic only — Windows apps are unaffected)"
    } else {
        ""
    };
    crate::ui::ok(&format!(
        "full-tunnel VPN up on {}{scope}",
        crate::ui::value(tun_name)
    ));
    match socks {
        Some(s) => {
            crate::ui::ok(&format!(
                "local SOCKS5 proxy on {} (TCP CONNECT; UDP rides the tunnel itself)",
                crate::ui::value(s)
            ));
            crate::sdnotify::ready(&format!("tunnel up on {tun_name}, SOCKS5 on {s}"));
        }
        None => crate::sdnotify::ready(&format!("tunnel up on {tun_name}")),
    }
}

pub async fn run(
    uri: &str,
    transport: crate::cli::Transport,
    mtu: u16,
    tun_name: &str,
    dns: &str,
    ipv6: bool,
    socks: Option<&str>,
) -> Result<()> {
    let parsed = RealityUri::parse(uri).map_err(|e| anyhow!("bad uri: {e}"))?;
    // Bind the optional SOCKS listener up front: everything below mutates the host (TUN
    // device, routes, DNS), and an EADDRINUSE discovered afterwards would leave the
    // machine half-reconfigured.
    let socks_listener = match socks {
        Some(addr) => Some(bind_local_socks(addr).await?),
        None => None,
    };
    // Resolve the server's IP for the /32 route exception (avoids the routing loop).
    let server_ip = tokio::net::lookup_host(&parsed.server_addr)
        .await
        .context("resolve server addr")?
        .next()
        .ok_or_else(|| anyhow!("no address for server {}", parsed.server_addr))?
        .ip();
    // Capture the current default gateway (matching the server's family, so the server-IP
    // exception can point at it) BEFORE we change any routes.
    let orig_gateway = if server_ip.is_ipv4() {
        leshiy_tun::discover::default_gateway_v4().await
    } else {
        leshiy_tun::discover::default_gateway_v6().await
    }
    .context("discover default gateway")?;
    // Best-effort v6 gateway for routing IPv6 split-tunnel excludes when the server is v4-reached
    // (when it's v6-reached, `orig_gateway` already is the v6 gateway).
    let orig_gateway6 = if server_ip.is_ipv6() {
        None
    } else {
        leshiy_tun::discover::default_gateway_v6().await.ok()
    };

    let pref = match transport {
        crate::cli::Transport::Auto => TransportPref::Auto,
        crate::cli::Transport::Quic => TransportPref::Quic,
        crate::cli::Transport::Tcp => TransportPref::Tcp,
    };
    let seed: Arc<dyn leshiy_client::Tunnel> = Arc::from(
        RealTransport
            .dial(uri, pref)
            .await
            .map_err(|e| anyhow!("dial: {e}"))?,
    );
    // Wrap so the full-tunnel session auto-reconnects if the upstream drops (WSL2 NAT reset,
    // sleep/resume, idle eviction) instead of wedging until restart — the TUN device, routes,
    // and DNS stay in place across reconnects.
    let tunnel =
        ReconnectingTunnel::spawn(RealTransport, uri, pref, seed, ReconnectParams::default());

    let cfg = TunConfig {
        tun_name: tun_name.to_string(),
        mtu,
        server_ip,
        orig_gateway,
        orig_gateway6,
        // Dual-stack is opt-in (`--ipv6`): only carry v6 when asked, else fail-closed (kill-switch).
        tun_addr6: ipv6.then(TunConfig::default_tun_addr6),
        dns: vec![dns.parse().context("parse --dns")?],
        ..TunConfig::default()
    };
    tracing::info!(%server_ip, %orig_gateway, tun = %cfg.tun_name, "starting full-tunnel VPN");
    announce(tun_name, socks);
    // The CLI doesn't display throughput; pass a throwaway counter.
    let counters = Arc::new(leshiy_client::ByteCounters::new());
    // Cooperative-stop signal, fired on Ctrl-C *or* SIGTERM so the engine tears down
    // cleanly (restores routes/DNS + releases the TUN device) instead of the process being
    // killed mid-flight. `systemctl stop` sends SIGTERM, and its default disposition would
    // strand the default route on a dead TUN device — i.e. leave the host with no network.
    // Handlers are installed before the engine starts, so a signal cannot land in the gap.
    let mut shutdown = crate::signals::install().context("install shutdown handlers")?;
    let cancel = Arc::new(tokio::sync::Notify::new());
    let sig_cancel = cancel.clone();
    tokio::spawn(async move {
        let sig = shutdown.recv().await;
        tracing::info!(signal = sig, "shutdown signal received; stopping VPN");
        // Tell systemd teardown started, so restoring routes/DNS is not mistaken for a
        // hang and SIGKILLed part-way through.
        crate::sdnotify::stopping();
        sig_cancel.notify_one();
    });

    // Combined mode: the SOCKS5 listener and the TUN engine share ONE tunnel. `open()`
    // takes `&self` and `ReconnectingTunnel` is `Send + Sync`, so both can drive it
    // concurrently. No routing loop results: the local table (rule priority 0) is consulted
    // before the tunnel's policy rules, so loopback SOCKS traffic never enters the TUN, and
    // the server's /32 exception keeps the tunnel's own socket outside it.
    let socks_task = socks_listener.map(|listener| {
        let (t, c) = (tunnel.clone(), counters.clone());
        tokio::spawn(async move { leshiy_client::serve_metered_on(t, listener, c).await })
    });

    let engine = TunEngine::run(tunnel, cfg, counters, cancel).await;

    // The SOCKS task owns no host state, so drop it first; the engine's teardown is what
    // restores routes and DNS and must always be the thing we wait on.
    if let Some(t) = socks_task {
        t.abort();
    }
    engine.map_err(|e| anyhow!("tun engine: {e}"))
}
