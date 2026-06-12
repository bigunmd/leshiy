//! The `VpnRunner` seam: "start/stop a VPN + observe state/stats". The control server is
//! generic over it, so unit tests drive a privilege-free fake while production uses
//! `EngineRunner` (builds the tunnel + runs `TunEngine` in a managed task).
use crate::error::HelperError;
use crate::proto::StartParams;
use leshiy_client::settings::TransportPref;
use leshiy_client::{Rates, RealTransport, State, Transport, Tunnel};
use leshiy_reality::config::RealityUri;
use leshiy_tun::{TunConfig, TunEngine};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::watch;
use tokio::task::JoinHandle;

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

/// Production runner: dials the URI to a `Tunnel`, resolves the server IP + original
/// gateway, and runs `TunEngine::run` in a spawned task. On exit (engine returns or the
/// task is aborted by `stop`), state flips back to `Disconnected`.
pub struct EngineRunner {
    state_tx: watch::Sender<State>,
    stats_tx: watch::Sender<Rates>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Default for EngineRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineRunner {
    pub fn new() -> Self {
        let (state_tx, _) = watch::channel(State::Disconnected);
        let (stats_tx, _) = watch::channel(Rates {
            up_bps: 0,
            down_bps: 0,
            total_up: 0,
            total_down: 0,
        });
        EngineRunner {
            state_tx,
            stats_tx,
            task: Mutex::new(None),
        }
    }

    fn pref(t: TransportPref) -> TransportPref {
        t
    }
}

#[async_trait::async_trait]
impl VpnRunner for EngineRunner {
    async fn start(&self, params: &StartParams) -> Result<(), HelperError> {
        if matches!(self.state(), State::Connecting | State::Connected) {
            return Err(HelperError::AlreadyRunning);
        }
        self.state_tx.send_replace(State::Connecting);

        let parsed = RealityUri::parse(&params.uri)
            .map_err(|e| HelperError::Engine(format!("bad uri: {e}")))?;
        let server_ip = tokio::net::lookup_host(&parsed.server_addr)
            .await
            .map_err(|e| HelperError::Engine(format!("resolve server addr: {e}")))?
            .next()
            .ok_or_else(|| HelperError::Engine("no address for server".into()))?
            .ip();
        let orig_gateway = leshiy_tun::discover::default_gateway_v4()
            .await
            .map_err(|e| HelperError::Engine(format!("discover default gateway: {e}")))?;

        let tunnel: Arc<dyn Tunnel> = Arc::from(
            RealTransport
                .dial(&params.uri, Self::pref(params.transport))
                .await
                .map_err(|_| HelperError::Engine("dial failed".into()))?,
        );

        let cfg = TunConfig {
            tun_name: params.tun_name.clone(),
            mtu: params.mtu,
            server_ip,
            orig_gateway,
            dns: vec![
                params
                    .dns
                    .parse()
                    .map_err(|_| HelperError::Engine("invalid dns address".into()))?,
            ],
            ..TunConfig::default()
        };

        let state_tx = self.state_tx.clone();
        state_tx.send_replace(State::Connected);
        let handle = tokio::spawn(async move {
            if let Err(e) = TunEngine::run(tunnel, cfg).await {
                tracing::warn!("tun engine exited: {e}");
            }
            state_tx.send_replace(State::Disconnected);
        });
        *self.task.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn stop(&self) {
        if let Some(h) = self.task.lock().unwrap().take() {
            h.abort();
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
            let (stats_tx, _) = watch::channel(Rates {
                up_bps: 0,
                down_bps: 0,
                total_up: 0,
                total_down: 0,
            });
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
        }
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
