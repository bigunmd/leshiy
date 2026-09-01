//! `leshiy vpn`: drive a full-tunnel VPN through the privileged `leshiy-helper` daemon.
//! This process stays unprivileged; the helper owns the TUN/routes/DNS. Ctrl-C (SIGINT) or
//! `systemctl stop` (SIGTERM) tears down.
use anyhow::{Context, Result};
use leshiy_client::settings::TransportPref;
use leshiy_helper::{HelperClient, StartParams};
use std::time::Duration;

/// Teardown must be bounded: `systemctl stop` allows only `TimeoutStopSec` before SIGKILL,
/// and a wedged helper must not burn that window. When the helper does not acknowledge, our
/// exit still tears the session down — it stops on the `Subscribe` stream dropping.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

async fn stop_bounded(client: &HelperClient) {
    crate::sdnotify::stopping();
    match tokio::time::timeout(STOP_TIMEOUT, client.stop()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "helper rejected stop"),
        Err(_) => tracing::warn!(?STOP_TIMEOUT, "helper did not acknowledge stop in time"),
    }
}

pub async fn run(
    uri: &str,
    transport: crate::cli::Transport,
    mtu: u16,
    tun_name: &str,
    dns: &str,
    socket: &str,
    ipv6: bool,
) -> Result<()> {
    let pref = match transport {
        crate::cli::Transport::Auto => TransportPref::Auto,
        crate::cli::Transport::Quic => TransportPref::Quic,
        crate::cli::Transport::Tcp => TransportPref::Tcp,
    };

    // Installed before the VPN is started so a stop arriving during start-up still reaches
    // the `client.stop()` path below rather than killing us and leaving the helper running.
    let mut shutdown = crate::signals::install().context("install shutdown handlers")?;

    let client = HelperClient::connect_path(socket);

    // Every await between here and the event loop must race the stop signal. Installing the
    // handler replaced SIGINT/SIGTERM's default "die now" disposition, so an un-raced await
    // would *swallow* Ctrl-C and leave the user unable to interrupt an unresponsive helper.
    tokio::select! {
        r = client.start_vpn(StartParams {
            uri: uri.to_string(),
            transport: pref,
            mtu,
            tun_name: tun_name.to_string(),
            dns: dns.to_string(),
            // The CLI is full-tunnel for now; split-tunnel is configured via the desktop app.
            split_tunnel: Default::default(),
            // Dual-stack is opt-in (`--ipv6`): only carry v6 when the server supports it.
            ipv6,
        }) => r.context("start VPN via helper")?,
        sig = shutdown.recv() => {
            tracing::info!(signal = sig, "interrupted during start-up");
            // The request may already have reached the helper, so stop is best-effort
            // rather than skipped — otherwise an interrupt could strand a live tunnel.
            stop_bounded(&client).await;
            return Ok(());
        }
    }
    tracing::info!("VPN started via helper; press Ctrl-C to disconnect");

    let mut events = tokio::select! {
        r = client.subscribe() => r.context("subscribe to helper")?,
        sig = shutdown.recv() => {
            tracing::info!(signal = sig, "disconnecting");
            stop_bounded(&client).await;
            return Ok(());
        }
    };
    tokio::select! {
        sig = shutdown.recv() => {
            tracing::info!(signal = sig, "disconnecting");
        }
        _ = async {
            while let Some(evt) = events.recv().await {
                if let Some(state) = evt.state {
                    crate::ui::eline(&format!("vpn: {}", crate::ui::value(&format!("{state:?}"))));
                    tracing::info!(?state, "vpn state");
                }
            }
        } => {
            tracing::warn!("helper closed the event stream");
        }
    }

    stop_bounded(&client).await;
    Ok(())
}
