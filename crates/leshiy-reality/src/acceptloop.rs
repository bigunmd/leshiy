//! Backoff and log throttling for a failing `accept()`.
//!
//! An `accept()` error is usually transient (a peer that RSTs while still in the accept queue),
//! but it can also be *persistent*: under FD exhaustion (`EMFILE`/`ENFILE`) the listener stays
//! readable and `accept()` returns the same error immediately, forever. Retrying such an error in
//! a bare loop — even with a `yield_now()` between attempts — is an unbounded busy loop.
//!
//! That is not hypothetical. A deployed server hit `EMFILE` and spun at ~62_000 iterations per
//! second, emitting one `warn!` per iteration: 7.8 GB of syslog in seven days, which filled the
//! disk, which made SQLite fail to size its WAL, which crash-looped the process, which pinned the
//! box's CPU in `rsyslogd`/`systemd-journald` retrying writes to a full filesystem.
//!
//! So a persistent failure must be *slowed* (exponential delay, capped) and *quiet* (log the first
//! one, then at most one line per [`LOG_EVERY`], carrying the suppressed count). Neither the delay
//! nor the throttle changes behaviour for the transient case: a single failure sleeps 5 ms and
//! logs once, which is invisible next to normal accept latency.

use std::time::{Duration, Instant};

/// Delay after the first failed `accept()`. Small enough that an isolated transient error costs
/// nothing measurable, large enough that a persistent one cannot spin.
const BASE_DELAY: Duration = Duration::from_millis(5);

/// Ceiling on the backoff delay. At the cap a wedged listener retries once a second — frequent
/// enough to recover promptly when FDs are freed, rare enough to be free.
const MAX_DELAY: Duration = Duration::from_secs(1);

/// Minimum gap between two logged accept failures. The first failure in a run always logs.
const LOG_EVERY: Duration = Duration::from_secs(30);

/// What the caller should do about one failed `accept()`.
#[derive(Debug, PartialEq, Eq)]
pub struct AcceptFailure {
    /// How long to sleep before attempting `accept()` again.
    pub delay: Duration,
    /// `Some(n)` when this failure should be logged, where `n` is the number of failures
    /// suppressed since the previous logged one (0 for the first). `None` means stay quiet.
    pub log_suppressed: Option<u64>,
}

/// Exponential backoff + log throttle across a run of consecutive `accept()` failures.
///
/// Both counters reset on the first success, so an intermittent error never accumulates into a
/// long delay and every fresh run of trouble logs immediately.
pub struct AcceptBackoff {
    consecutive: u32,
    /// When the last failure was logged. `None` until one has been.
    last_logged: Option<Instant>,
    /// Failures dropped since the last logged one.
    suppressed: u64,
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl AcceptBackoff {
    pub fn new() -> Self {
        Self {
            consecutive: 0,
            last_logged: None,
            suppressed: 0,
        }
    }

    /// A successful `accept()`: forget the run entirely.
    pub fn record_success(&mut self) {
        self.consecutive = 0;
        self.last_logged = None;
        self.suppressed = 0;
    }

    /// A failed `accept()` at `now`. Returns the delay to sleep and whether to log.
    pub fn record_failure(&mut self, now: Instant) -> AcceptFailure {
        // Saturating so a run long enough to overflow the shift still just sits at MAX_DELAY.
        let delay = BASE_DELAY
            .saturating_mul(1u32 << self.consecutive.min(20))
            .min(MAX_DELAY);
        self.consecutive = self.consecutive.saturating_add(1);

        let due = match self.last_logged {
            None => true, // first failure of this run always speaks up
            Some(t) => now.duration_since(t) >= LOG_EVERY,
        };
        if due {
            let suppressed = self.suppressed;
            self.last_logged = Some(now);
            self.suppressed = 0;
            AcceptFailure {
                delay,
                log_suppressed: Some(suppressed),
            }
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            AcceptFailure {
                delay,
                log_suppressed: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_failure_delays_by_base_and_logs() {
        let mut b = AcceptBackoff::new();
        let got = b.record_failure(Instant::now());
        assert_eq!(got.delay, BASE_DELAY);
        assert_eq!(
            got.log_suppressed,
            Some(0),
            "the first failure of a run must be logged, with nothing suppressed yet"
        );
    }

    #[test]
    fn delay_doubles_and_clamps_at_the_ceiling() {
        let mut b = AcceptBackoff::new();
        let t = Instant::now();
        assert_eq!(b.record_failure(t).delay, Duration::from_millis(5));
        assert_eq!(b.record_failure(t).delay, Duration::from_millis(10));
        assert_eq!(b.record_failure(t).delay, Duration::from_millis(20));
        assert_eq!(b.record_failure(t).delay, Duration::from_millis(40));
        // ...and eventually pins to MAX_DELAY rather than growing without bound.
        for _ in 0..40 {
            b.record_failure(t);
        }
        assert_eq!(b.record_failure(t).delay, MAX_DELAY);
    }

    /// The bug this module exists to prevent: a persistent error must never produce a
    /// zero-length delay, at any point in an arbitrarily long run.
    #[test]
    fn no_failure_ever_yields_a_zero_delay() {
        let mut b = AcceptBackoff::new();
        let t = Instant::now();
        for i in 0..10_000 {
            let d = b.record_failure(t).delay;
            assert!(d >= BASE_DELAY, "iteration {i} produced a {d:?} delay");
        }
    }

    #[test]
    fn success_resets_delay_and_logging() {
        let mut b = AcceptBackoff::new();
        let t = Instant::now();
        b.record_failure(t);
        b.record_failure(t);
        b.record_success();
        let got = b.record_failure(t);
        assert_eq!(got.delay, BASE_DELAY, "delay must restart at the base");
        assert_eq!(
            got.log_suppressed,
            Some(0),
            "a fresh run of failures must log immediately again"
        );
    }

    #[test]
    fn logging_is_throttled_within_the_window() {
        let mut b = AcceptBackoff::new();
        let t = Instant::now();
        assert!(b.record_failure(t).log_suppressed.is_some());
        // Everything inside the window stays quiet.
        for _ in 0..1000 {
            assert_eq!(b.record_failure(t).log_suppressed, None);
        }
    }

    #[test]
    fn logging_resumes_after_the_window_and_reports_the_suppressed_count() {
        let mut b = AcceptBackoff::new();
        let t = Instant::now();
        b.record_failure(t); // logged
        for _ in 0..500 {
            b.record_failure(t); // suppressed
        }
        let got = b.record_failure(t + LOG_EVERY);
        assert_eq!(
            got.log_suppressed,
            Some(500),
            "the resumed log line must report how many failures it stood in for"
        );
        // ...and the counter starts over.
        for _ in 0..3 {
            b.record_failure(t + LOG_EVERY);
        }
        assert_eq!(
            b.record_failure(t + LOG_EVERY + LOG_EVERY).log_suppressed,
            Some(3)
        );
    }

    /// 62_000 failures/sec was the observed spin rate. Under this backoff the same run is
    /// bounded to a handful of log lines and at most ~1 attempt/sec once warmed up.
    #[test]
    fn a_persistent_failure_run_is_bounded_in_both_attempts_and_logs() {
        let mut b = AcceptBackoff::new();
        let start = Instant::now();
        let mut now = start;
        let mut attempts = 0u32;
        let mut logs = 0u32;
        // Simulate one hour of a wedged listener, advancing the clock by each returned delay.
        while now.duration_since(start) < Duration::from_secs(3600) {
            let f = b.record_failure(now);
            if f.log_suppressed.is_some() {
                logs += 1;
            }
            now += f.delay;
            attempts += 1;
        }
        assert!(
            attempts <= 3700,
            "an hour wedged should be ~1 attempt/sec, got {attempts}"
        );
        assert!(
            logs <= 121,
            "an hour wedged should be ~1 log per 30s, got {logs}"
        );
    }
}
