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
use std::sync::atomic::{AtomicU64, Ordering};
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
#[allow(clippy::too_many_arguments)] // one handle per bridge control/observation channel
pub async fn run_engine(
    uri: String,
    counters: Arc<ByteCounters>,
    cancel: Arc<Notify>,
    reattach: Arc<Notify>,
    kick: Arc<Notify>,
    state_tx: watch::Sender<ConnState>,
    rtt_ms: Arc<AtomicU64>,
    tunnel_slot: crate::bridge::TunnelSlot,
) -> std::io::Result<()> {
    let _ = state_tx.send(ConnState::Connecting);
    let parsed = validate_uri(&uri).map_err(|e| {
        let _ = state_tx.send(ConnState::Failed);
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
    })?;
    let pref = TransportPref::Auto;
    // The host has already routed traffic into the interface, so giving up here would blackhole
    // the device until someone noticed. Keep trying instead — the server may be briefly down, or
    // the phone not yet online (a boot-time connect) — publishing Failed once so the UI can say
    // so, and dialing again at once when the host reports a network change.
    let (server_addr, uri_ref) = (&parsed.server_addr, &uri);
    let (server_ip, seed) = retry_until(
        || async move {
            let ip = tokio::net::lookup_host(server_addr)
                .await
                .ok()?
                .next()?
                .ip();
            let tunnel = RealTransport.dial(uri_ref, pref).await.ok()?;
            Some((ip, Arc::<dyn leshiy_client::Tunnel>::from(tunnel)))
        },
        ReconnectParams::default(),
        &kick,
        || {
            let _ = state_tx.send(next_on_dial_result(false));
        },
    )
    .await;
    let _ = state_tx.send(next_on_dial_result(true));
    // `spawn_with_kick`, not `spawn`: the VpnService watches the default network and tells us the
    // moment it changes, which the tunnel itself can only discover by timing out.
    let tunnel = ReconnectingTunnel::spawn_with_kick(
        RealTransport,
        &uri,
        pref,
        seed,
        ReconnectParams::default(),
        kick,
    );
    *tunnel_slot.lock().unwrap() = Some(Arc::downgrade(&tunnel));

    // Sample the tunnel's keepalive RTT (~1 Hz) into the shared cell the status poller reads.
    // Runs until the engine is cancelled; `tunnel` is an `Arc`, so this clone is cheap.
    {
        let rtt_tunnel = tunnel.clone();
        let rtt_cancel = cancel.clone();
        let rtt_cell = rtt_ms.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = rtt_cancel.notified() => break,
                    _ = tick.tick() => {
                        let ms = rtt_tunnel
                            .rtt_micros()
                            .map(|us| ((us + 500) / 1000).max(1))
                            .unwrap_or(0);
                        rtt_cell.store(ms, Ordering::Relaxed);
                    }
                }
            }
        });
    }
    // On Android the VpnService owns routing/DNS; `server_ip` is still excepted from the
    // tunnel to avoid a routing loop. `orig_gateway` is unused by the android backend.
    let cfg = TunConfig {
        mtu: 1400,
        server_ip,
        ..TunConfig::default()
    };
    // `run_with_reattach`, not `run`: on Android a split-tunnel route change means the service
    // establishes a fresh interface and hands us its fd, and the engine must pick it up without
    // re-dialing (see `LeshiyBridge::reattach_tun`).
    let result = TunEngine::run_with_reattach(tunnel, cfg, counters, cancel, reattach).await;
    // The engine ended (device closed / fatal). A clean stop() teardown is reflected by the
    // Kotlin side; publishing Failed here covers unexpected exits so the UI never sticks on
    // Connected after the tunnel is gone.
    let _ = state_tx.send(ConnState::Failed);
    result
}

/// Run `attempt` until it yields a value, sleeping with capped exponential backoff between
/// failures (`on_fail` runs after each). A `kick` cuts the current wait short. Never gives up:
/// the caller is torn down from outside (runtime shutdown) when the user stops the tunnel.
async fn retry_until<T, F, Fut>(
    mut attempt: F,
    params: ReconnectParams,
    kick: &Notify,
    mut on_fail: impl FnMut(),
) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let mut failures = 0u32;
    loop {
        if let Some(value) = attempt().await {
            return value;
        }
        on_fail();
        let delay = leshiy_client::backoff_delay(failures, params.base, params.max);
        failures = failures.saturating_add(1);
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = kick.notified() => {}
        }
    }
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

#[cfg(test)]
mod tests {
    use super::retry_until;
    use leshiy_client::ReconnectParams;
    use std::cell::Cell;
    use std::time::Duration;
    use tokio::sync::Notify;
    use tokio::time::Instant;

    fn params() -> ReconnectParams {
        ReconnectParams {
            base: Duration::from_millis(500),
            max: Duration::from_secs(30),
            hold: Duration::from_secs(5),
        }
    }

    /// A failed first dial used to end the engine, leaving the VPN interface up with nothing
    /// reading it: every packet blackholed until the user noticed and disconnected.
    #[tokio::test(start_paused = true)]
    async fn keeps_retrying_with_backoff_until_it_connects() {
        let attempts = Cell::new(0);
        let failures = Cell::new(0);
        let started = Instant::now();
        let got = retry_until(
            || {
                attempts.set(attempts.get() + 1);
                let n = attempts.get();
                async move { (n == 4).then_some(n) }
            },
            params(),
            &Notify::new(),
            || failures.set(failures.get() + 1),
        )
        .await;
        assert_eq!((got, failures.get()), (4, 3));
        // 0.5 + 1 + 2 s of exponential backoff between the four attempts.
        assert_eq!(started.elapsed(), Duration::from_millis(3500));
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_change_retries_at_once() {
        let kick = Notify::new();
        kick.notify_one(); // the host saw the default network change mid-backoff
        let attempts = Cell::new(0);
        let started = Instant::now();
        retry_until(
            || {
                attempts.set(attempts.get() + 1);
                let n = attempts.get();
                async move { (n == 2).then_some(()) }
            },
            ReconnectParams {
                base: Duration::from_secs(60),
                ..params()
            },
            &kick,
            || {},
        )
        .await;
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
