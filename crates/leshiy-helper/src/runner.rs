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

/// Warn when graceful teardown takes this long, but keep owning and awaiting cleanup.
/// Process exit or a new session before route/DNS restoration is unsafe.
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
    session: tokio::sync::Mutex<Option<Session>>,
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
            session: tokio::sync::Mutex::new(None),
        }
    }

    /// The full-tunnel VPN carries UDP via tunnel **datagrams**. Both transports now provide them
    /// — REALITY via mux datagrams and QUIC via CONNECT-UDP (RFC 9298) — so the user's transport
    /// preference is honored as-is (no longer forced to REALITY/TCP).
    fn pref(t: TransportPref) -> TransportPref {
        t
    }

    /// Preparation has no TUN/route mutations and may be cancelled by Stop.
    async fn prepare(params: &StartParams) -> Result<(Arc<dyn Tunnel>, TunConfig), HelperError> {
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
            // Dual-stack is opt-in: only carry v6 when the caller asked (and the server supports
            // it), else stay IPv4-only with the v6 kill-switch.
            tun_addr6: params.ipv6.then(TunConfig::default_tun_addr6),
            ..TunConfig::default()
        };

        Ok((tunnel, cfg))
    }

    /// Own the worker before polling preparation. The same seam drives hermetic lifecycle tests.
    async fn start_prepared<P, T, R, F>(&self, prepare: P, run: R) -> Result<(), HelperError>
    where
        P: std::future::Future<Output = Result<T, HelperError>> + Send + 'static,
        T: Send + 'static,
        R: FnOnce(T, Arc<tokio::sync::Notify>) -> F + Send + 'static,
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut slot = self
            .session
            .try_lock()
            .map_err(|_| HelperError::AlreadyRunning)?;
        if slot.as_ref().is_some_and(|s| !s.task.is_finished()) {
            return Err(HelperError::AlreadyRunning);
        }
        let cancel = Arc::new(tokio::sync::Notify::new());
        let worker_cancel = cancel.clone();
        let state = self.state_tx.clone();
        let stats = self.stats_tx.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        state.send_replace(State::Connecting);
        let task = tokio::spawn(async move {
            let prepared = tokio::select! {
                biased;
                () = worker_cancel.notified() => Err(HelperError::Engine("startup cancelled".into())),
                result = prepare => result,
            };
            match prepared {
                Ok(prepared) => {
                    state.send_replace(State::Connected);
                    let _ = ready_tx.send(Ok(()));
                    // Never select cancellation against the running engine: it owns OS cleanup.
                    run(prepared, worker_cancel).await;
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            }
            stats.send_replace(zero_rates());
            state.send_replace(State::Disconnected);
        });
        *slot = Some(Session { task, cancel });
        drop(slot);
        ready_rx
            .await
            .unwrap_or_else(|_| Err(HelperError::Engine("startup worker exited".into())))
    }
}

#[async_trait::async_trait]
impl VpnRunner for EngineRunner {
    async fn start(&self, params: &StartParams) -> Result<(), HelperError> {
        let params = params.clone();
        let stats = self.stats_tx.clone();
        self.start_prepared(
            async move { Self::prepare(&params).await },
            move |(tunnel, cfg), cancel| async move {
                let counters = Arc::new(ByteCounters::new());
                let sampler = tokio::spawn(sample_throughput(counters.clone(), stats));
                if let Err(e) = TunEngine::run(tunnel, cfg, counters, cancel).await {
                    tracing::warn!("tun engine exited: {e}");
                }
                sampler.abort();
            },
        )
        .await
    }

    async fn stop(&self) {
        // Keep the handle in the slot even if this stop future is cancelled. Holding the lock
        // serializes concurrent stops; start uses try_lock and rejects while we drain.
        let mut slot = self.session.lock().await;
        if let Some(Session { task, cancel }) = slot.as_mut() {
            cancel.notify_one();
            if tokio::time::timeout(STOP_TIMEOUT, &mut *task)
                .await
                .is_err()
            {
                tracing::warn!("stop: engine teardown is slow; awaiting route/DNS restoration");
                let _ = task.await;
            }
        }
        *slot = None;
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
            ipv6: false,
        }
    }

    #[tokio::test]
    async fn stop_cancels_pending_startup_before_engine_install() {
        let runner = Arc::new(EngineRunner::new());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let installed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let installed_worker = installed.clone();
        let r = runner.clone();
        let start = tokio::spawn(async move {
            r.start_prepared(
                async move {
                    let _ = entered_tx.send(());
                    let _ = release_rx.await;
                    Ok(())
                },
                move |(), _| async move {
                    installed_worker.store(true, std::sync::atomic::Ordering::SeqCst);
                },
            )
            .await
        });
        entered_rx.await.unwrap();
        runner.stop().await;
        assert!(start.await.unwrap().is_err());
        assert!(!installed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(runner.state(), State::Disconnected);
    }

    #[tokio::test]
    async fn stop_timeout_and_cancelled_wait_keep_draining_owned() {
        let runner = Arc::new(EngineRunner::new());
        let (stopping_tx, stopping_rx) = tokio::sync::oneshot::channel();
        let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
        runner
            .start_prepared(async { Ok(()) }, move |(), cancel| async move {
                cancel.notified().await;
                let _ = stopping_tx.send(());
                let _ = cleanup_rx.await;
            })
            .await
            .unwrap();
        let r = runner.clone();
        let stop = tokio::spawn(async move { r.stop().await });
        stopping_rx.await.unwrap();
        tokio::time::sleep(STOP_TIMEOUT + Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert!(
            !stop.is_finished(),
            "stop must not acknowledge incomplete cleanup"
        );
        assert_ne!(runner.state(), State::Disconnected);
        assert!(matches!(
            runner
                .start_prepared(async { Ok(()) }, |(), _| async {})
                .await,
            Err(HelperError::AlreadyRunning)
        ));
        stop.abort(); // cancel the waiter, never the engine
        assert!(stop.await.unwrap_err().is_cancelled());
        assert!(
            runner
                .session
                .lock()
                .await
                .as_ref()
                .is_some_and(|s| !s.task.is_finished())
        );
        assert!(matches!(
            runner
                .start_prepared(async { Ok(()) }, |(), _| async {})
                .await,
            Err(HelperError::AlreadyRunning)
        ));
        let r = runner.clone();
        let final_stop = tokio::spawn(async move { r.stop().await });
        cleanup_tx.send(()).unwrap();
        final_stop.await.unwrap();
        assert_eq!(runner.state(), State::Disconnected);
        assert!(runner.session.lock().await.is_none());
        runner
            .start_prepared(async { Ok(()) }, |(), _| async {})
            .await
            .unwrap();
        runner.stop().await;
    }

    #[tokio::test]
    async fn startup_failure_allows_retry() {
        let runner = EngineRunner::new();
        assert!(
            runner
                .start_prepared(
                    async { Err::<(), _>(HelperError::Engine("test failure".into())) },
                    |(), _| async {}
                )
                .await
                .is_err()
        );
        assert_eq!(runner.state(), State::Disconnected);
        runner
            .start_prepared(async { Ok(()) }, |(), _| async {})
            .await
            .unwrap();
        runner.stop().await;
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
