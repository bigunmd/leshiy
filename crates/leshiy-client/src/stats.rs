//! Byte accounting and live up/down speed derivation.
//!
//! `ByteCounters` is shared (via `Arc`) with the proxy pump in Plan 2; `Throughput`
//! turns successive counter totals into per-second rates. Both are sockets-free and
//! deterministic, so they unit-test cleanly.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;

/// Wait for the next throughput-sampling instant, **parking** (no periodic wakeups)
/// while the app is backgrounded — the key battery optimization for the ~1 Hz stats
/// sampler on Android. `fg` carries the foreground state (`true` = visible).
///
/// - While backgrounded, this awaits a foreground change instead of ticking, so the
///   CPU is not woken once per second when nobody is watching the stats.
/// - While foregrounded, it returns after `period` (or early if the app goes
///   background, so the caller re-evaluates and parks promptly).
///
/// Returns `false` if the foreground sender was dropped (sampler should stop).
pub async fn await_next_sample(fg: &mut watch::Receiver<bool>, period: Duration) -> bool {
    // Park while backgrounded — no wakeups until foreground returns.
    while !*fg.borrow_and_update() {
        if fg.changed().await.is_err() {
            return false;
        }
    }
    // Foregrounded: tick after `period`, or wake early on a foreground change.
    tokio::select! {
        _ = tokio::time::sleep(period) => true,
        r = fg.changed() => r.is_ok(),
    }
}

/// Cumulative byte counters for one tunnel session.
#[derive(Debug, Default)]
pub struct ByteCounters {
    up: AtomicU64,
    down: AtomicU64,
}

impl ByteCounters {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add `n` bytes sent client→server.
    pub fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }
    /// Add `n` bytes received server→client.
    pub fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }
    /// `(total_up, total_down)` since creation.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }
}

/// A single throughput sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rates {
    pub up_bps: u64,
    pub down_bps: u64,
    pub total_up: u64,
    pub total_down: u64,
}

/// Stateful helper: remembers the previous totals and computes per-second deltas.
#[derive(Debug, Default)]
pub struct Throughput {
    last_up: u64,
    last_down: u64,
}

impl Throughput {
    pub fn new() -> Self {
        Self::default()
    }

    /// Given the current cumulative totals and the elapsed time since the previous
    /// sample, return the per-second rates and remember the new totals. A counter
    /// that went backwards (reset on reconnect) saturates to zero rather than panicking.
    pub fn sample(&mut self, total_up: u64, total_down: u64, elapsed: Duration) -> Rates {
        let secs = elapsed.as_secs_f64().max(1e-9);
        let up_bps = ((total_up.saturating_sub(self.last_up)) as f64 / secs) as u64;
        let down_bps = ((total_down.saturating_sub(self.last_down)) as f64 / secs) as u64;
        self.last_up = total_up;
        self.last_down = total_down;
        Rates {
            up_bps,
            down_bps,
            total_up,
            total_down,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let c = ByteCounters::new();
        c.add_up(10);
        c.add_up(5);
        c.add_down(100);
        assert_eq!(c.totals(), (15, 100));
    }

    #[test]
    fn throughput_computes_per_second_deltas() {
        let mut t = Throughput::new();
        let r = t.sample(1000, 4000, Duration::from_secs(1));
        assert_eq!(r.up_bps, 1000);
        assert_eq!(r.down_bps, 4000);
        assert_eq!(r.total_up, 1000);

        // Second sample: only +500 up, +0 down over 1s.
        let r2 = t.sample(1500, 4000, Duration::from_secs(1));
        assert_eq!(r2.up_bps, 500);
        assert_eq!(r2.down_bps, 0);
    }

    #[test]
    fn throughput_handles_counter_reset() {
        let mut t = Throughput::new();
        t.sample(1000, 1000, Duration::from_secs(1));
        // Counters reset to a lower value (reconnect) — must not panic/underflow.
        let r = t.sample(50, 50, Duration::from_secs(1));
        assert_eq!(r.up_bps, 0);
        assert_eq!(r.down_bps, 0);
    }

    #[tokio::test]
    async fn sampler_ticks_when_foreground() {
        let (_tx, mut rx) = watch::channel(true);
        assert!(await_next_sample(&mut rx, Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn sampler_parks_when_background_then_resumes() {
        let (tx, mut rx) = watch::channel(false); // start backgrounded
        // Parked: must NOT tick even though the period is tiny — it awaits a change.
        let parked = tokio::time::timeout(
            Duration::from_millis(200),
            await_next_sample(&mut rx, Duration::from_millis(10)),
        )
        .await;
        assert!(parked.is_err(), "must park (no tick) while backgrounded");

        // Foreground again → the next call ticks.
        tx.send(true).unwrap();
        assert!(await_next_sample(&mut rx, Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn sampler_stops_when_sender_dropped_while_parked() {
        let (tx, mut rx) = watch::channel(false);
        drop(tx);
        // Sender gone while backgrounded → stop sampling.
        assert!(!await_next_sample(&mut rx, Duration::from_millis(10)).await);
    }

    #[test]
    fn rates_round_trips_json() {
        let r = Rates {
            up_bps: 1,
            down_bps: 2,
            total_up: 3,
            total_down: 4,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Rates = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
