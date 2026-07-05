//! Owns the tunnel-engine driver: parse the URI, dial, wrap in a reconnecting tunnel,
//! and run `TunEngine` over the (android-injected) TUN fd until cancelled.
use crate::error::BridgeError;
use crate::status::{ConnState, next_on_dial_result};
use leshiy_client::{
    ByteCounters, RealTransport, ReconnectParams, ReconnectingTunnel, Transport as _, TransportPref,
};
use leshiy_reality::config::RealityUri;
use leshiy_tun::{TunConfig, TunEngine};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::sync::watch;

/// Parse + validate a `leshiy://` URI without performing any network I/O.
pub fn validate_uri(uri: &str) -> Result<RealityUri, BridgeError> {
    RealityUri::parse(uri).map_err(|e| BridgeError::BadUri {
        reason: e.to_string(),
    })
}

/// Resolve the server IP, build a reconnecting tunnel, and run the engine until `cancel`.
///
/// The TUN fd must already be injected (android) via `leshiy_tun::sys::android::set_tun_fd`
/// before this is called.
pub async fn run_engine(
    uri: String,
    counters: Arc<ByteCounters>,
    cancel: Arc<Notify>,
    state_tx: watch::Sender<ConnState>,
) -> std::io::Result<()> {
    let _ = state_tx.send(ConnState::Connecting);
    let parsed = validate_uri(&uri).map_err(|e| {
        let _ = state_tx.send(ConnState::Failed);
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
    })?;
    let server_ip = match tokio::net::lookup_host(&parsed.server_addr)
        .await
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(a) => a.ip(),
        None => {
            let _ = state_tx.send(ConnState::Failed);
            return Err(std::io::Error::other("no address for server"));
        }
    };
    let pref = TransportPref::Auto;
    let dial = RealTransport.dial(&uri, pref).await;
    let _ = state_tx.send(next_on_dial_result(dial.is_ok()));
    let seed: Arc<dyn leshiy_client::Tunnel> =
        Arc::from(dial.map_err(|e| std::io::Error::other(format!("dial: {e}")))?);
    let tunnel =
        ReconnectingTunnel::spawn(RealTransport, &uri, pref, seed, ReconnectParams::default());
    // On Android the VpnService owns routing/DNS; `server_ip` is still excepted from the
    // tunnel to avoid a routing loop. `orig_gateway` is unused by the android backend.
    let cfg = TunConfig {
        mtu: 1400,
        server_ip,
        ..TunConfig::default()
    };
    let result = TunEngine::run(tunnel, cfg, counters, cancel).await;
    // The engine ended (device closed / fatal). A clean stop() teardown is reflected by the
    // Kotlin side; publishing Failed here covers unexpected exits so the UI never sticks on
    // Connected after the tunnel is gone.
    let _ = state_tx.send(ConnState::Failed);
    result
}

#[cfg(test)]
pub fn sample_uri_for_test() -> String {
    leshiy_reality::config::format_reality_uri(
        &[7u8; 32],
        "vps.example.com:443",
        "www.microsoft.com",
        &[1u8, 2, 3, 4, 0, 0, 0, 0],
    )
}
