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
    // Keeping the runtime alive keeps the engine + poller tasks running; dropping it stops them.
    _rt: Runtime,
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

        // Engine driver task.
        let engine_uri = uri.clone();
        let engine_counters = counters.clone();
        let engine_cancel = cancel.clone();
        rt.spawn(async move {
            if let Err(e) =
                crate::runtime::run_engine(engine_uri, engine_counters, engine_cancel).await
            {
                tracing::warn!("engine stopped: {e}");
            }
        });

        // Status poller (~1 Hz): read counters and notify the host.
        let poll_counters = counters.clone();
        let poll_cancel = cancel.clone();
        rt.spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = poll_cancel.notified() => break,
                    _ = tick.tick() => {
                        let (up, down) = poll_counters.totals();
                        // Phase 1 spike: report `Connected` as a placeholder. Real state comes
                        // from wiring the supervisor's `watch::Receiver<State>` in Phase 2.
                        listener.on_status(Status {
                            state: ConnState::Connected,
                            up_bytes: up,
                            down_bytes: down,
                        });
                    }
                }
            }
        });

        *guard = Some(Running { cancel, _rt: rt });
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
