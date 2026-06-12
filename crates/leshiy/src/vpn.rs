//! `leshiy vpn`: drive a full-tunnel VPN through the privileged `leshiy-helper` daemon.
//! This process stays unprivileged; the helper owns the TUN/routes/DNS. Ctrl-C tears down.
use anyhow::{Context, Result};
use leshiy_client::settings::TransportPref;
use leshiy_helper::{HelperClient, StartParams};

pub async fn run(
    uri: &str,
    transport: crate::cli::Transport,
    mtu: u16,
    tun_name: &str,
    dns: &str,
    socket: &str,
) -> Result<()> {
    let pref = match transport {
        crate::cli::Transport::Auto => TransportPref::Auto,
        crate::cli::Transport::Quic => TransportPref::Quic,
        crate::cli::Transport::Tcp => TransportPref::Tcp,
    };

    let client = HelperClient::connect_path(socket);
    client
        .start_vpn(StartParams {
            uri: uri.to_string(),
            transport: pref,
            mtu,
            tun_name: tun_name.to_string(),
            dns: dns.to_string(),
            // The CLI is full-tunnel for now; split-tunnel is configured via the desktop app.
            split_tunnel: Default::default(),
        })
        .await
        .context("start VPN via helper")?;
    tracing::info!("VPN started via helper; press Ctrl-C to disconnect");

    // Stream events to the console until the user interrupts.
    let mut events = client.subscribe().await.context("subscribe to helper")?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("disconnecting");
        }
        _ = async {
            while let Some(evt) = events.recv().await {
                if let Some(state) = evt.state {
                    tracing::info!(?state, "vpn state");
                }
            }
        } => {
            tracing::warn!("helper closed the event stream");
        }
    }

    client.stop().await.context("stop VPN via helper")?;
    Ok(())
}
