//! UniFFI-exposed control object: `start(fd, uri, listener)` / `stop()`.
use crate::error::BridgeError;
use crate::status::{ConnState, Status};
use leshiy_client::ByteCounters;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::sync::Notify;

/// Callback the host (Kotlin/Swift) implements to receive ~1 Hz status pushes.
#[uniffi::export(callback_interface)]
pub trait StatusListener: Send + Sync {
    fn on_status(&self, status: Status);
}

struct Running {
    cancel: Arc<Notify>,
    /// Signalled by [`LeshiyBridge::reattach_tun`] when the host establishes a new TUN to change
    /// routes; the engine picks the injected fd up without re-dialing.
    reattach: Arc<Notify>,
    /// Signalled by [`LeshiyBridge::network_changed`]; forces the reconnect supervisor to re-dial.
    kick: Arc<Notify>,
    // Keeping the runtime alive keeps the engine + poller tasks running; dropping it stops them.
    _rt: Runtime,
    // Held so the state channel outlives the session (the poller clones its own receiver).
    _state_rx: tokio::sync::watch::Receiver<ConnState>,
}

/// Control handle for a single VPN session (one per process).
#[derive(uniffi::Object)]
pub struct LeshiyBridge {
    inner: Mutex<Option<Running>>,
}

#[uniffi::export]
impl LeshiyBridge {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
        })
    }

    /// Start the tunnel over `tun_fd` (from `VpnService.establish().detachFd()`), dialing `uri`.
    /// Pushes `Status` to `listener` ~once per second until [`stop`](Self::stop).
    pub fn start(
        &self,
        tun_fd: i32,
        uri: String,
        listener: Box<dyn StatusListener>,
    ) -> Result<(), BridgeError> {
        let mut guard = self.inner.lock().unwrap();
        if guard.is_some() {
            return Err(BridgeError::AlreadyRunning);
        }
        // Reject a bad URI up front (no runtime/fd churn on failure).
        crate::runtime::validate_uri(&uri)?;

        #[cfg(target_os = "android")]
        leshiy_tun::sys::set_tun_fd(tun_fd);
        #[cfg(not(target_os = "android"))]
        let _ = tun_fd; // fd injection is android-only; host builds validate the plumbing.

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| BridgeError::BadUri {
                reason: format!("runtime: {e}"),
            })?;
        let counters = Arc::new(ByteCounters::new());
        let cancel = Arc::new(Notify::new());
        let reattach = Arc::new(Notify::new());
        let kick = Arc::new(Notify::new());
        // Shared cell holding the latest keepalive RTT (ms); the engine updates it, poller reads it.
        let rtt_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (state_tx, state_rx) = tokio::sync::watch::channel(ConnState::Disconnected);

        // Engine driver task.
        let engine_uri = uri.clone();
        let engine_counters = counters.clone();
        let engine_cancel = cancel.clone();
        let engine_reattach = reattach.clone();
        let engine_kick = kick.clone();
        let engine_rtt = rtt_ms.clone();
        rt.spawn(async move {
            if let Err(e) = crate::runtime::run_engine(
                engine_uri,
                engine_counters,
                engine_cancel,
                engine_reattach,
                engine_kick,
                state_tx,
                engine_rtt,
            )
            .await
            {
                tracing::warn!("engine stopped: {e}");
            }
        });

        // Status poller (~1 Hz): read live state + counters and notify the host.
        let poll_counters = counters.clone();
        let poll_cancel = cancel.clone();
        let poll_state_rx = state_rx.clone();
        let poll_rtt = rtt_ms.clone();
        rt.spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = poll_cancel.notified() => break,
                    _ = tick.tick() => {
                        let (up, down) = poll_counters.totals();
                        listener.on_status(Status {
                            state: *poll_state_rx.borrow(),
                            up_bytes: up,
                            down_bytes: down,
                            rtt_ms: poll_rtt.load(std::sync::atomic::Ordering::Relaxed) as u32,
                        });
                    }
                }
            }
        });

        *guard = Some(Running {
            cancel,
            reattach,
            kick,
            _rt: rt,
            _state_rx: state_rx,
        });
        Ok(())
    }

    /// Tell the tunnel the default network changed, so it re-dials now instead of waiting to
    /// find out.
    ///
    /// When Wi-Fi drops to cellular the old socket's source address is gone, but nothing on the
    /// wire says so — the peer just stops being reachable. Left alone the mux would spend its
    /// whole idle timeout discovering what the OS already told us, stranding every flow for the
    /// duration. The host knows first; this passes that on.
    ///
    /// Call only on a genuine change of network, not on every callback: a re-dial costs a REALITY
    /// handshake and drops in-flight flows.
    pub fn network_changed(&self) -> Result<(), BridgeError> {
        let guard = self.inner.lock().unwrap();
        let running = guard.as_ref().ok_or(BridgeError::NotRunning)?;
        // `notify_one` latches, so a change racing the supervisor's `select!` is not lost.
        running.kick.notify_one();
        Ok(())
    }

    /// Hand the engine a TUN fd from a fresh `VpnService.Builder.establish()`, so a route change
    /// takes effect **without re-dialing the tunnel**.
    ///
    /// Android's VPN routes are immutable once established, so changing them means establishing a
    /// new interface; the platform keeps the old fd valid until it is dropped and routes outgoing
    /// packets to the new one. Re-dialing instead would burn a REALITY handshake on every route
    /// change — the last thing worth repeating on a censored path.
    ///
    /// The netstack's per-flow state does not survive, so in-flight connections break: call this
    /// only when the route set actually changed, never on an unchanged refresh.
    pub fn reattach_tun(&self, tun_fd: i32) -> Result<(), BridgeError> {
        let guard = self.inner.lock().unwrap();
        let running = guard.as_ref().ok_or(BridgeError::NotRunning)?;

        #[cfg(target_os = "android")]
        leshiy_tun::sys::set_tun_fd(tun_fd);
        #[cfg(not(target_os = "android"))]
        let _ = tun_fd; // fd injection is android-only; host builds validate the plumbing.

        // `notify_one` latches a permit, so this is not lost if the engine happens to be between
        // `select!`s — which would otherwise strand the new fd and leave the old routes live.
        running.reattach.notify_one();
        Ok(())
    }

    /// Stop the tunnel and tear down the engine + poller. Idempotent.
    pub fn stop(&self) {
        if let Some(running) = self.inner.lock().unwrap().take() {
            running.cancel.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::BridgeError;

    #[test]
    fn bad_uri_is_rejected() {
        // `RealityUri` is not `Debug`, so match instead of `unwrap_err()`.
        assert!(matches!(
            crate::runtime::validate_uri("not-a-leshiy-uri"),
            Err(BridgeError::BadUri { .. })
        ));
    }

    #[test]
    fn good_uri_parses() {
        let uri = crate::runtime::sample_uri_for_test();
        assert!(crate::runtime::validate_uri(&uri).is_ok());
    }
}
