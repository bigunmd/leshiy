//! `ReconnectingTunnel`: a [`Tunnel`] that transparently re-dials its upstream when the
//! underlying connection drops, so a long-lived session (notably the full-tunnel `tun`
//! engine) survives network blips without being torn down and rebuilt.
//!
//! The full-tunnel engine ([`leshiy_tun::TunEngine`]) takes a single `Arc<dyn Tunnel>` and
//! loops forever reading packets from the device; it never re-dials. So if the one tunnel it
//! was handed dies (WSL2 NAT reset, sleep/resume, idle eviction, …), every new flow's
//! `tunnel.open()` fails and the session wedges — new connections surface as "connection
//! refused" — until the user restarts. Wrapping the dialed tunnel in a `ReconnectingTunnel`
//! fixes that without touching the engine: the device, routes, and DNS stay in place while a
//! background task re-dials with backoff and swaps in the fresh tunnel.
//!
//! While a re-dial is in flight, `open`/`open_datagram` **hold briefly** (waiting for the new
//! tunnel) and then **fail closed** — a quick reconnect is invisible to apps, and a longer
//! outage fails the flow rather than leaking traffic outside the tunnel.
use crate::error::{ClientError, Result};
use crate::settings::TransportPref;
use crate::stream::{DatagramFlow, ProxyStream};
use crate::supervisor::backoff_delay;
use crate::transport::{Transport, Tunnel};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

/// Default reconnect tuning, matching the SOCKS supervisor's backoff
/// ([`crate::runtime::SupervisorConfig`]).
#[derive(Clone, Copy, Debug)]
pub struct ReconnectParams {
    /// Initial backoff between re-dial attempts.
    pub base: Duration,
    /// Backoff cap (`min(base * 2^attempt, max)`).
    pub max: Duration,
    /// How long `open`/`open_datagram` wait for a live tunnel during a reconnect before
    /// failing closed.
    pub hold: Duration,
}

impl Default for ReconnectParams {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(500),
            max: Duration::from_secs(30),
            hold: Duration::from_secs(5),
        }
    }
}

/// Aborts the wrapped task on drop, tying the reconnect supervisor's lifetime to the
/// `ReconnectingTunnel`: when the engine releases its `Arc`, the background re-dial loop stops
/// instead of running forever.
struct AbortOnDrop(JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A [`Tunnel`] that owns reconnection internally. Construct with [`ReconnectingTunnel::spawn`].
pub struct ReconnectingTunnel {
    /// The current live tunnel, or `None` while a re-dial is in flight. Republished by the
    /// background supervisor task; `open`/`open_datagram` read it and await changes.
    current: watch::Receiver<Option<Arc<dyn Tunnel>>>,
    hold: Duration,
    _task: AbortOnDrop,
}

impl ReconnectingTunnel {
    /// Wrap an already-dialed `seed` tunnel so subsequent drops auto-reconnect. The initial
    /// dial is the caller's responsibility (preserving its fail-fast semantics); this only
    /// handles re-dials after the seed — or a later tunnel — drops.
    pub fn spawn<T: Transport + 'static>(
        transport: T,
        uri: impl Into<String>,
        pref: TransportPref,
        seed: Arc<dyn Tunnel>,
        params: ReconnectParams,
    ) -> Arc<dyn Tunnel> {
        let (tx, rx) = watch::channel(Some(seed.clone()));
        let uri = uri.into();
        let task = tokio::spawn(supervise(transport, uri, pref, seed, params, tx));
        Arc::new(ReconnectingTunnel {
            current: rx,
            hold: params.hold,
            _task: AbortOnDrop(task),
        })
    }
}

/// Background loop: wait for the live tunnel to drop, then re-dial with capped exponential
/// backoff, republishing the new tunnel each time it succeeds. Exits when the wrapper is
/// dropped (the `watch::Sender` send fails) or aborted.
async fn supervise<T: Transport>(
    transport: T,
    uri: String,
    pref: TransportPref,
    seed: Arc<dyn Tunnel>,
    params: ReconnectParams,
    tx: watch::Sender<Option<Arc<dyn Tunnel>>>,
) {
    let mut current = seed;
    loop {
        // Wait until the live tunnel reports it has dropped.
        current.closed().await;
        tracing::warn!("tunnel dropped; reconnecting");
        // Publish "no tunnel" so in-flight `open()`s hold rather than hit a dead tunnel. If the
        // receiver is gone the wrapper was dropped — stop.
        if tx.send(None).is_err() {
            return;
        }
        // Re-dial with capped exponential backoff until it succeeds.
        let mut attempt = 0u32;
        loop {
            match transport.dial(&uri, pref).await {
                Ok(tunnel) => {
                    let tunnel: Arc<dyn Tunnel> = Arc::from(tunnel);
                    current = tunnel.clone();
                    if tx.send(Some(tunnel)).is_err() {
                        return; // wrapper dropped
                    }
                    tracing::info!("tunnel reconnected");
                    break;
                }
                Err(_) => {
                    let delay = backoff_delay(attempt, params.base, params.max);
                    tracing::debug!(attempt, ?delay, "reconnect dial failed; backing off");
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

#[async_trait]
impl Tunnel for ReconnectingTunnel {
    async fn open(&self, target: &str) -> Result<Box<dyn ProxyStream>> {
        let deadline = Instant::now() + self.hold;
        let mut rx = self.current.clone();
        loop {
            // `borrow_and_update` marks the current version seen, so a later `changed()` waits
            // for the *next* publish (no missed wakeup if the supervisor swaps mid-call).
            let cur = rx.borrow_and_update().clone();
            // A live tunnel whose open succeeds → done. Otherwise (no tunnel, or a stale/closed
            // one) fall through and wait for the supervisor to publish a fresh one.
            if let Some(tunnel) = cur
                && let Ok(stream) = tunnel.open(target).await
            {
                return Ok(stream);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::ConnectFailed);
            }
            // Wait (bounded) for the supervisor to republish. Timed out, or the sender dropped
            // (wrapper gone) → fail closed.
            match timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => continue,
                _ => return Err(ClientError::ConnectFailed),
            }
        }
    }

    async fn open_datagram(&self, target: &str) -> Result<Box<dyn DatagramFlow>> {
        let deadline = Instant::now() + self.hold;
        let mut rx = self.current.clone();
        loop {
            let cur = rx.borrow_and_update().clone();
            if let Some(tunnel) = cur
                && let Ok(flow) = tunnel.open_datagram(target).await
            {
                return Ok(flow);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::ConnectFailed);
            }
            match timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => continue,
                _ => return Err(ClientError::ConnectFailed),
            }
        }
    }

    async fn open_icmp(&self, target: &str) -> Result<Box<dyn DatagramFlow>> {
        let deadline = Instant::now() + self.hold;
        let mut rx = self.current.clone();
        loop {
            let cur = rx.borrow_and_update().clone();
            if let Some(tunnel) = cur
                && let Ok(flow) = tunnel.open_icmp(target).await
            {
                return Ok(flow);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::ConnectFailed);
            }
            match timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => continue,
                _ => return Err(ClientError::ConnectFailed),
            }
        }
    }

    async fn closed(&self) {
        // The wrapper self-heals, so from the engine's perspective it never closes.
        std::future::pending::<()>().await;
    }

    fn rtt_micros(&self) -> Option<u64> {
        // Report the live generation's latency.
        self.current.borrow().as_ref().and_then(|t| t.rtt_micros())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::Notify;

    /// A fake tunnel. `open` succeeds while `alive` is true and fails once it's cleared (like a
    /// real tunnel whose mux has closed). `closed()` resolves when `drop_signal` fires. Each
    /// generation has its own `alive`/`drop_signal`, so dropping one never affects another.
    struct FakeTunnel {
        drop_signal: Arc<Notify>,
        alive: Arc<AtomicBool>,
    }
    #[async_trait]
    impl Tunnel for FakeTunnel {
        async fn open(&self, _target: &str) -> Result<Box<dyn ProxyStream>> {
            if self.alive.load(Ordering::SeqCst) {
                Ok(Box::new(OkStream))
            } else {
                Err(ClientError::ConnectFailed)
            }
        }
        async fn closed(&self) {
            self.drop_signal.notified().await;
        }
    }

    struct OkStream;
    #[async_trait]
    impl ProxyStream for OkStream {
        async fn send(&mut self, _data: bytes::Bytes) -> Result<()> {
            Ok(())
        }
        async fn recv(&mut self) -> Result<bytes::Bytes> {
            Ok(bytes::Bytes::new())
        }
        async fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// A transport that hands out fresh, independent `FakeTunnel`s and counts dials. `dial_ok`
    /// toggles whether re-dials succeed (to exercise the fail-closed path).
    struct CountingTransport {
        dials: Arc<AtomicUsize>,
        dial_ok: bool,
    }
    #[async_trait]
    impl Transport for CountingTransport {
        async fn dial(&self, _uri: &str, _pref: TransportPref) -> Result<Box<dyn Tunnel>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            if self.dial_ok {
                Ok(Box::new(FakeTunnel {
                    drop_signal: Arc::new(Notify::new()), // fresh; never fired by these tests
                    alive: Arc::new(AtomicBool::new(true)),
                }))
            } else {
                Err(ClientError::ConnectFailed)
            }
        }
    }

    fn fast_params() -> ReconnectParams {
        ReconnectParams {
            base: Duration::from_millis(5),
            max: Duration::from_millis(20),
            hold: Duration::from_millis(500),
        }
    }

    /// Build a seed tunnel plus the handles to drop it: clear `alive`, then `notify_one()`
    /// (latches, so the supervisor sees the drop even if it isn't yet awaiting `closed()`).
    fn seed() -> (Arc<dyn Tunnel>, Arc<AtomicBool>, Arc<Notify>) {
        let alive = Arc::new(AtomicBool::new(true));
        let signal = Arc::new(Notify::new());
        let t: Arc<dyn Tunnel> = Arc::new(FakeTunnel {
            drop_signal: signal.clone(),
            alive: alive.clone(),
        });
        (t, alive, signal)
    }

    #[tokio::test]
    async fn reconnects_after_drop() {
        let dials = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            dials: dials.clone(),
            dial_ok: true,
        };
        let (seed, alive, signal) = seed();
        let tunnel = ReconnectingTunnel::spawn(
            transport,
            "leshiy://x",
            TransportPref::Tcp,
            seed,
            fast_params(),
        );

        // Seeded: open works immediately, no dial yet.
        assert!(tunnel.open("example.com:443").await.is_ok());
        assert_eq!(dials.load(Ordering::SeqCst), 0);

        // Drop the seed: its open() now fails and closed() resolves, so the supervisor re-dials.
        alive.store(false, Ordering::SeqCst);
        signal.notify_one();

        // open() holds through the reconnect and then succeeds on the fresh tunnel.
        assert!(
            tunnel.open("example.com:443").await.is_ok(),
            "open must succeed again after auto-reconnect"
        );
        assert!(
            dials.load(Ordering::SeqCst) >= 1,
            "supervisor must have re-dialed at least once"
        );
    }

    #[tokio::test]
    async fn open_during_failed_reconnect_holds_then_fails_closed() {
        let dials = Arc::new(AtomicUsize::new(0));
        // Re-dials always fail, so after the seed drops there is never a live tunnel.
        let transport = CountingTransport {
            dials: dials.clone(),
            dial_ok: false,
        };
        let (seed, alive, signal) = seed();
        let tunnel = ReconnectingTunnel::spawn(
            transport,
            "leshiy://x",
            TransportPref::Tcp,
            seed,
            fast_params(),
        );

        alive.store(false, Ordering::SeqCst);
        signal.notify_one(); // drop the seed; reconnect will loop forever failing

        let start = Instant::now();
        let res = tunnel.open("example.com:443").await;
        assert!(res.is_err(), "must fail closed when no tunnel comes back");
        assert!(
            start.elapsed() >= Duration::from_millis(400),
            "must hold ~the configured window before failing, not fail instantly"
        );
    }
}
