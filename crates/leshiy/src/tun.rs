//! `leshiy tun`: dial the URI to a Tunnel, discover the server IP + original gateway,
//! and run the full-tunnel engine. Must run with root / CAP_NET_ADMIN.
use anyhow::{Context, Result, anyhow};
use leshiy_client::{ReconnectParams, ReconnectingTunnel, RealTransport, Transport as _, TransportPref};
use leshiy_reality::config::RealityUri;
use leshiy_tun::{TunConfig, TunEngine};
use std::sync::Arc;

pub async fn run(
    uri: &str,
    transport: crate::cli::Transport,
    mtu: u16,
    tun_name: &str,
    dns: &str,
) -> Result<()> {
    let parsed = RealityUri::parse(uri).map_err(|e| anyhow!("bad uri: {e}"))?;
    // Resolve the server's IP for the /32 route exception (avoids the routing loop).
    let server_ip = tokio::net::lookup_host(&parsed.server_addr)
        .await
        .context("resolve server addr")?
        .next()
        .ok_or_else(|| anyhow!("no address for server {}", parsed.server_addr))?
        .ip();
    // Capture the current default gateway BEFORE we change any routes.
    let orig_gateway = leshiy_tun::discover::default_gateway_v4()
        .await
        .context("discover default gateway")?;

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
    let tunnel = ReconnectingTunnel::spawn(RealTransport, uri, pref, seed, ReconnectParams::default());

    let cfg = TunConfig {
        tun_name: tun_name.to_string(),
        mtu,
        server_ip,
        orig_gateway,
        dns: vec![dns.parse().context("parse --dns")?],
        ..TunConfig::default()
    };
    tracing::info!(%server_ip, %orig_gateway, tun = %cfg.tun_name, "starting full-tunnel VPN");
    // The CLI doesn't display throughput; pass a throwaway counter.
    let counters = Arc::new(leshiy_client::ByteCounters::new());
    // Cooperative-stop signal, fired on Ctrl-C so the engine tears down cleanly (restores
    // routes/DNS + releases the TUN device) instead of the process being killed mid-flight.
    let cancel = Arc::new(tokio::sync::Notify::new());
    let sig_cancel = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("ctrl-c received; stopping VPN");
            sig_cancel.notify_one();
        }
    });
    TunEngine::run(tunnel, cfg, counters, cancel)
        .await
        .map_err(|e| anyhow!("tun engine: {e}"))
}
