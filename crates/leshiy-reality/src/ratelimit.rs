//! Lock-light async token-bucket rate limiter. ADR-0019: the lock is held only for
//! synchronous arithmetic, never across the `sleep().await`.
use std::sync::Mutex;
use tokio::time::{Duration, Instant};

pub struct TokenBucket {
    rate: f64,     // bytes per second
    capacity: f64, // max burst (>= any single consume() n)
    state: Mutex<State>,
}
struct State {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// `rate_bytes_per_sec` > 0. Capacity = max(rate, 1 MiB) so a relay batch always fits.
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        let rate = rate_bytes_per_sec.max(1) as f64;
        let capacity = rate.max(1024.0 * 1024.0);
        TokenBucket {
            rate,
            capacity,
            state: Mutex::new(State {
                tokens: capacity.min(rate),
                last: Instant::now(),
            }),
        }
    }

    /// Wait until `n` bytes of allowance are available, then consume them.
    pub async fn consume(&self, n: u64) {
        let need = (n as f64).min(self.capacity);
        loop {
            let wait = {
                let mut s = self.state.lock().unwrap();
                let now = Instant::now();
                let elapsed = now.duration_since(s.last).as_secs_f64();
                s.last = now;
                s.tokens = (s.tokens + elapsed * self.rate).min(self.capacity);
                if s.tokens >= need {
                    s.tokens -= need;
                    None
                } else {
                    Some(Duration::from_secs_f64((need - s.tokens) / self.rate))
                }
            }; // guard dropped here — never held across the await below
            match wait {
                None => return,
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn initial_burst_is_immediate_then_throttles() {
        let tb = TokenBucket::new(1000); // 1000 bytes/sec; capacity = 1 MiB, initial tokens = 1000 (= rate)
        let t0 = tokio::time::Instant::now();
        tb.consume(1000).await; // initial tokens → immediate
        assert_eq!(t0.elapsed(), Duration::ZERO);
        tb.consume(1000).await; // must wait ~1s to refill
        assert_eq!(t0.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn consume_larger_than_rate_waits_proportionally() {
        let tb = TokenBucket::new(1000);
        let t0 = tokio::time::Instant::now();
        tb.consume(500).await; // immediate (from initial 1000)
        tb.consume(1000).await; // 500 left → need 500 more → 0.5s
        assert_eq!(t0.elapsed(), Duration::from_millis(500));
    }
}
