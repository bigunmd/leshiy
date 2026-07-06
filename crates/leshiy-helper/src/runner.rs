//! The `VpnRunner` seam: "start/stop a VPN + observe state/stats". The control server is
//! generic over it, so unit tests drive a privilege-free fake while production uses
//! `EngineRunner` (builds the tunnel + runs `TunEngine` in a managed task).
use crate::error::HelperError;
use crate::proto::StartParams;
use leshiy_client::settings::TransportPref;
use leshiy_client::{
    ByteCounters, Rates, RealTransport, ReconnectParams, ReconnectingTunnel, State, Throughput,
    Transport, Tunnel,
};
use leshiy_reality::config::RealityUri;
use leshiy_tun::{TunConfig, TunEngine};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How long to wait for the REALITY dial/handshake before giving up. A stuck dial must fail so
/// `start` can reset the state to `Disconnected` rather than leave the GUI spinning forever.
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// Upper bound on the graceful engine teardown (route/DNS restore). Generous because a large
/// split-tunnel ruleset removes many routes; if it's exceeded we proceed anyway (the helper is
/// either staying alive for a fresh session or about to exit, which the OS cleans up).
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// Zeroed rates — the resting value published before connecting and after disconnect.
/// Validate a client-supplied TUN interface name before it reaches privileged
/// command construction (H5).
///
/// `tun_name` flows from the unprivileged caller into root-run network tooling:
/// on Linux it is *text-templated* into an `ip -batch` script, and on Windows
/// into `netsh`/`route` argv. An unvalidated value (newline, leading `-`, `=`,
/// spaces, shell/option metacharacters) can inject extra commands or options
/// run as root. We accept only a conservative interface-name charset within the
/// Linux IFNAMSIZ limit.
fn validate_tun_name(name: &str) -> Result<(), HelperError> {
    if name.is_empty() || name.len() > 15 {
        return Err(HelperError::Engine(
            "invalid tun name: length must be 1..=15".into(),
        ));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(HelperError::Engine(
            "invalid tun name: only [A-Za-z0-9_] allowed".into(),
        ));
    }
    Ok(())
}

fn zero_rates() -> Rates {
    Rates {
        up_bps: 0,
        down_bps: 0,
        total_up: 0,
        total_down: 0,
    }
}

/// Sample the engine's byte counters once per second and publish per-second rates for the GUI.
/// Runs until aborted (the engine task aborts it on exit). Kept separate so the timing loop is
/// easy to reason about; the rate math itself lives in (and is tested by) `Throughput`.
async fn sample_throughput(counters: Arc<ByteCounters>, stats_tx: watch::Sender<Rates>) {
    let mut tput = Throughput::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await; // the first tick completes immediately — skip it so the first delta is real
    loop {
        tick.tick().await;
        let (up, down) = counters.totals();
        stats_tx.send_replace(tput.sample(up, down, Duration::from_secs(1)));
    }
}

/// Abstracts a running (or idle) VPN session. `start` is expected to return promptly
/// once the tunnel is dialed and the engine task is spawned; ongoing state/stats are
/// published on the `watch` channels.
#[async_trait::async_trait]
pub trait VpnRunner: Send + Sync {
    async fn start(&self, params: &StartParams) -> Result<(), HelperError>;
    async fn stop(&self);
    fn state(&self) -> State;
    fn subscribe_state(&self) -> watch::Receiver<State>;
    fn subscribe_stats(&self) -> watch::Receiver<Rates>;
}

/// A running engine session: the spawned task plus the `Notify` used to ask it to stop
/// gracefully (see [`EngineRunner::stop`] — we cancel cooperatively, never `abort`, so the
/// Wintun adapter is released cleanly on Windows).
struct Session {
    task: JoinHandle<()>,
    cancel: Arc<tokio::sync::Notify>,
}

/// Production runner: dials the URI to a `Tunnel`, resolves the server IP + original
/// gateway, and runs `TunEngine::run` in a spawned task. On exit (engine returns or it's
/// cancelled by `stop`), state flips back to `Disconnected`.
pub struct EngineRunner {
    state_tx: watch::Sender<State>,
    stats_tx: watch::Sender<Rates>,
    session: Mutex<Option<Session>>,
}

impl Default for EngineRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineRunner {
    pub fn new() -> Self {
        let (state_tx, _) = watch::channel(State::Disconnected);
        let (stats_tx, _) = watch::channel(zero_rates());
        EngineRunner {
            state_tx,
            stats_tx,
            session: Mutex::new(None),
        }
    }

    /// The full-tunnel VPN carries UDP via tunnel **datagrams**, which only REALITY (TCP)
    /// provides — QUIC datagrams are unimplemented and `QuicTunnel` can't relay the VPN's
    /// flows. So force REALITY regardless of the user's (proxy) transport preference, matching
    /// `leshiy tun`/`leshiy vpn` (which default `--transport tcp`).
    fn pref(_t: TransportPref) -> TransportPref {
        TransportPref::Tcp
    }

    /// The fallible body of `start`: resolve the server, dial the tunnel, and spawn the engine.
    /// Kept separate so `start` can uniformly reset the published state to `Disconnected` if any
    /// of these steps fails (rather than leaving the GUI wedged on "Connecting").
    async fn start_session(&self, params: &StartParams) -> Result<(), HelperError> {
        // Validate the client-supplied interface name before it can reach any
        // privileged command construction (H5).
        validate_tun_name(&params.tun_name)?;
        let parsed = RealityUri::parse(&params.uri)
            .map_err(|e| HelperError::Engine(format!("bad uri: {e}")))?;
        let server_ip = tokio::net::lookup_host(&parsed.server_addr)
            .await
            .map_err(|e| HelperError::Engine(format!("resolve server addr: {e}")))?
            .next()
            .ok_or_else(|| HelperError::Engine("no address for server".into()))?
            .ip();
        // Gateway matching the server's family (so a v6-reached server gets a v6 exception).
        let orig_gateway = if server_ip.is_ipv4() {
            leshiy_tun::discover::default_gateway_v4().await
        } else {
            leshiy_tun::discover::default_gateway_v6().await
        }
        .map_err(|e| HelperError::Engine(format!("discover default gateway: {e}")))?;
        // Best-effort v6 gateway for IPv6 split-tunnel excludes (v4-reached server).
        let orig_gateway6 = if server_ip.is_ipv6() {
            None
        } else {
            leshiy_tun::discover::default_gateway_v6().await.ok()
        };

        tracing::info!(server = %parsed.server_addr, %server_ip, %orig_gateway, "dialing server");
        // Bound the dial so a stuck handshake fails (and resets state) instead of pinning the GUI
        // on "Connecting" indefinitely.
        let dialed = tokio::time::timeout(
            DIAL_TIMEOUT,
            RealTransport.dial(&params.uri, Self::pref(params.transport)),
        )
        .await
        .map_err(|_| HelperError::Engine("dial timed out".into()))?
        // Surface the real dial error (don't swallow it) so failures are diagnosable.
        .map_err(|e| HelperError::Engine(format!("dial failed: {e}")))?;
        let seed: Arc<dyn Tunnel> = Arc::from(dialed);
        // Auto-reconnect the full-tunnel session if the upstream drops (WSL2 NAT reset,
        // sleep/resume, idle eviction). Without this the engine keeps running over a dead tunnel:
        // new flows fail with "connection refused" while the GUI still shows Connected. The TUN
        // device, routes, and DNS stay in place across reconnects.
        let tunnel: Arc<dyn Tunnel> = ReconnectingTunnel::spawn(
            RealTransport,
            params.uri.clone(),
            Self::pref(params.transport),
            seed,
            ReconnectParams::default(),
        );
        tracing::info!("tunnel dialed; bringing up the TUN engine");

        let cfg = TunConfig {
            tun_name: params.tun_name.clone(),
            mtu: params.mtu,
            server_ip,
            orig_gateway,
            orig_gateway6,
            dns: vec![
                params
                    .dns
                    .parse()
                    .map_err(|_| HelperError::Engine("invalid dns address".into()))?,
            ],
            split: params.split_tunnel.clone(),
            ..TunConfig::default()
        };

        let state_tx = self.state_tx.clone();
        let stats_tx = self.stats_tx.clone();
        let counters = Arc::new(ByteCounters::new());
        // Cooperative-stop signal: `stop` fires this and the engine returns gracefully (see
        // `TunEngine::run`). We never `abort` the task — that wedges the Wintun teardown.
        let cancel = Arc::new(tokio::sync::Notify::new());
        let engine_cancel = cancel.clone();
        state_tx.send_replace(State::Connected);
        let handle = tokio::spawn(async move {
            // Publish live throughput while the engine runs; abort the sampler on exit.
            let sampler = tokio::spawn(sample_throughput(counters.clone(), stats_tx.clone()));
            if let Err(e) = TunEngine::run(tunnel, cfg, counters, engine_cancel).await {
                tracing::warn!("tun engine exited: {e}");
            }
            sampler.abort();
            // Reset the rates so the GUI doesn't display a frozen speed after disconnect.
            stats_tx.send_replace(zero_rates());
            state_tx.send_replace(State::Disconnected);
        });
        *self.session.lock().unwrap() = Some(Session {
            task: handle,
            cancel,
        });
        Ok(())
    }
}

#[async_trait::async_trait]
impl VpnRunner for EngineRunner {
    async fn start(&self, params: &StartParams) -> Result<(), HelperError> {
        if matches!(self.state(), State::Connecting | State::Connected) {
            return Err(HelperError::AlreadyRunning);
        }
        self.state_tx.send_replace(State::Connecting);
        // If ANY setup step below fails, reset to Disconnected before returning — otherwise the
        // state stays "Connecting" forever and the GUI hangs on the spinner with no way back.
        let result = self.start_session(params).await;
        if result.is_err() {
            self.state_tx.send_replace(State::Disconnected);
        }
        result
    }

    async fn stop(&self) {
        // Take the session out (drop the lock before awaiting). Ask the engine to stop
        // GRACEFULLY (`cancel`) rather than aborting the task: an aborted task drops the netstack
        // from a cancellation context, which can't release the Wintun reader's blocking wait, so
        // the device drop hangs and the adapter is never freed (next session → 0x4DF). The
        // graceful path returns from `TunEngine::run` after the route/DNS restore completes. Bound
        // the wait so a pathological teardown can't hang the helper forever.
        let session = self.session.lock().unwrap().take();
        if let Some(Session { task, cancel }) = session {
            tracing::info!("stop: signalling engine cancel and awaiting graceful teardown");
            cancel.notify_one();
            match tokio::time::timeout(STOP_TIMEOUT, task).await {
                Ok(_) => tracing::info!("stop: engine teardown complete"),
                Err(_) => tracing::warn!("stop: engine teardown timed out; proceeding"),
            }
        }
        self.state_tx.send_replace(State::Disconnected);
    }

    fn state(&self) -> State {
        *self.state_tx.borrow()
    }
    fn subscribe_state(&self) -> watch::Receiver<State> {
        self.state_tx.subscribe()
    }
    fn subscribe_stats(&self) -> watch::Receiver<Rates> {
        self.stats_tx.subscribe()
    }
}

/// Privilege-free `VpnRunner` fake used by unit tests AND the `duplex_dispatch` integration
/// test (which can only see the crate's public API). `#[doc(hidden)]` — not a stable surface.
#[doc(hidden)]
pub mod test_support {
    use super::*;

    /// A privilege-free runner used by the runner + control-server tests.
    pub struct FakeRunner {
        pub state_tx: watch::Sender<State>,
        pub stats_tx: watch::Sender<Rates>,
        pub started: Arc<Mutex<Vec<StartParams>>>,
    }

    impl FakeRunner {
        pub fn new() -> Self {
            let (state_tx, _) = watch::channel(State::Disconnected);
            let (stats_tx, _) = watch::channel(zero_rates());
            FakeRunner {
                state_tx,
                stats_tx,
                started: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Default for FakeRunner {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl VpnRunner for FakeRunner {
        async fn start(&self, params: &StartParams) -> Result<(), HelperError> {
            self.started.lock().unwrap().push(params.clone());
            self.state_tx.send_replace(State::Connected);
            Ok(())
        }
        async fn stop(&self) {
            self.state_tx.send_replace(State::Disconnected);
        }
        fn state(&self) -> State {
            *self.state_tx.borrow()
        }
        fn subscribe_state(&self) -> watch::Receiver<State> {
            self.state_tx.subscribe()
        }
        fn subscribe_stats(&self) -> watch::Receiver<Rates> {
            self.stats_tx.subscribe()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeRunner;
    use super::*;
    use leshiy_client::settings::TransportPref;

    fn params() -> StartParams {
        StartParams {
            uri: "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000".into(),
            transport: TransportPref::Tcp,
            mtu: 1400,
            tun_name: "leshiy0".into(),
            dns: "1.1.1.1".into(),
            split_tunnel: Default::default(),
        }
    }

    #[test]
    fn validate_tun_name_accepts_valid() {
        assert!(validate_tun_name("leshiy0").is_ok());
        assert!(validate_tun_name("utun5").is_ok());
        assert!(validate_tun_name("tun_1").is_ok());
    }

    #[test]
    fn validate_tun_name_rejects_injection_and_bad_length() {
        assert!(validate_tun_name("").is_err());
        assert!(validate_tun_name("waytoolonginterface").is_err()); // >15
        assert!(validate_tun_name("leshiy0\nroute add 0.0.0.0/0").is_err()); // newline → ip -batch injection
        assert!(validate_tun_name("-rf").is_err()); // leading dash → option injection
        assert!(validate_tun_name("name=x").is_err()); // '=' → netsh option confusion
        assert!(validate_tun_name("a b").is_err()); // space
        assert!(validate_tun_name("a;b").is_err()); // metachar
    }

    #[tokio::test]
    async fn fake_runner_tracks_state_and_records_start() {
        let r = FakeRunner::new();
        assert_eq!(r.state(), State::Disconnected);
        r.start(&params()).await.unwrap();
        assert_eq!(r.state(), State::Connected);
        assert_eq!(r.started.lock().unwrap().len(), 1);
        r.stop().await;
        assert_eq!(r.state(), State::Disconnected);
    }
}
