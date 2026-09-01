//! Cooperative-shutdown signals.
//!
//! `systemctl stop` sends **SIGTERM**, whose default disposition terminates the process
//! immediately. For `tun`/`vpn` that is not a clean exit: the engine's teardown — which
//! restores the routing table, the policy rules and `/etc/resolv.conf` — never runs, and
//! the host is left with its default route pointed at a dead TUN device, i.e. no network.
//! SIGINT (Ctrl-C) was already handled; SIGTERM must reach the same path.
//!
//! Handlers are installed eagerly by [`install`] rather than lazily inside the awaiting
//! task, because a signal arriving between "engine started" and "task first polled" would
//! otherwise still hit the default disposition. `tokio`'s `Signal` buffers a delivery, so
//! a signal racing ahead of [`Shutdown::recv`] is still observed.

/// A registered set of shutdown signals. Holding this keeps the handlers installed.
pub struct Shutdown {
    #[cfg(unix)]
    sigint: tokio::signal::unix::Signal,
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
}

/// Install the shutdown-signal handlers, replacing SIGTERM's default "terminate now"
/// disposition. Call this *before* mutating any host state.
#[cfg(unix)]
pub fn install() -> std::io::Result<Shutdown> {
    use tokio::signal::unix::{SignalKind, signal};
    Ok(Shutdown {
        sigint: signal(SignalKind::interrupt())?,
        sigterm: signal(SignalKind::terminate())?,
    })
}

/// Windows has no SIGTERM; Ctrl-C is the only cooperative stop.
#[cfg(not(unix))]
pub fn install() -> std::io::Result<Shutdown> {
    Ok(Shutdown {})
}

impl Shutdown {
    /// Resolve on the first SIGINT or SIGTERM, returning which one fired so the caller
    /// can log the reason it is tearing down.
    #[cfg(unix)]
    pub async fn recv(&mut self) -> &'static str {
        tokio::select! {
            _ = self.sigint.recv() => "SIGINT",
            _ = self.sigterm.recv() => "SIGTERM",
        }
    }

    #[cfg(not(unix))]
    pub async fn recv(&mut self) -> &'static str {
        let _ = tokio::signal::ctrl_c().await;
        "SIGINT"
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Send `sig` to our own process. Uses `kill(1)` so the test needs no new dependency.
    fn raise_at_self(sig: &str) {
        let pid = std::process::id().to_string();
        let st = std::process::Command::new("kill")
            .args([&format!("-{sig}"), &pid])
            .status()
            .expect("spawn kill");
        assert!(st.success(), "kill -{sig} {pid} failed");
    }

    async fn expect_signal(sd: &mut Shutdown, want: &str) {
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), sd.recv())
            .await
            .unwrap_or_else(|_| panic!("{want} not observed within 5s"));
        assert_eq!(got, want);
    }

    /// The regression guard for `systemctl stop`: SIGTERM must reach the cooperative
    /// path instead of killing the process. Were the handler not installed, the default
    /// disposition would terminate this test binary outright — so reaching the
    /// assertions at all is itself part of what is being proven.
    ///
    /// Signal disposition is process-wide, so both cases live in **one** test: two
    /// parallel tests raising signals would cross-talk, since every `Shutdown` in the
    /// process observes every delivery.
    #[tokio::test]
    async fn catches_sigterm_and_sigint() {
        let mut sd = install().expect("install handlers");

        raise_at_self("TERM");
        expect_signal(&mut sd, "SIGTERM").await;

        // Deliver while nothing is awaiting `recv`, proving the buffering that makes
        // eager `install()` safe against the start-up race.
        raise_at_self("INT");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        expect_signal(&mut sd, "SIGINT").await;
    }
}
