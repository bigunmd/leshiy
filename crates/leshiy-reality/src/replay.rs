//! Replay guard for authenticated ClientHellos.
//!
//! Without this, an on-path adversary can capture a registered user's
//! ClientHello and replay it within the timestamp window. The replayer cannot
//! complete the handshake (it lacks the client's ephemeral key), but the
//! server's *behavior* diverges for a recognized auth payload (it takes over
//! the connection instead of relaying to dest) — a confirmation oracle that
//! reveals "this ClientHello belongs to a registered user".
//!
//! The guard records the `(client_random ‖ session_id)` of every accepted
//! ClientHello for the duration of the acceptance window. An exact replay is
//! detected and the caller downgrades it to a genuine dest relay, removing the
//! oracle. Legitimate clients use a fresh random per connection (`OsRng`), so
//! they never collide.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Key = client_random (32) ‖ session_id (32).
type Key = [u8; 64];

/// Build the replay key from a ClientHello's random and session_id.
/// Returns `None` if either field is not 32 bytes.
pub fn replay_key(random: &[u8], session_id: &[u8]) -> Option<Key> {
    if random.len() != 32 || session_id.len() != 32 {
        return None;
    }
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(random);
    k[32..].copy_from_slice(session_id);
    Some(k)
}

struct Inner {
    // (key, inserted_at_secs), oldest at the front.
    order: VecDeque<(Key, u64)>,
}

/// Bounded, TTL-based set of recently-seen ClientHello keys.
pub struct ReplayGuard {
    ttl_secs: u64,
    max_entries: usize,
    inner: Mutex<Inner>,
}

impl ReplayGuard {
    /// `ttl` should cover the full acceptance window (≈ `2 * max_time_diff`).
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl_secs: ttl.as_secs(),
            max_entries: 100_000,
            inner: Mutex::new(Inner {
                order: VecDeque::new(),
            }),
        }
    }

    /// Record `key` seen at `now` (unix secs). Returns `true` if the key was
    /// already present within the TTL window — i.e. this is a replay.
    pub fn check_and_record(&self, key: Key, now: u64) -> bool {
        let mut inner = self.inner.lock().unwrap();

        // Evict expired entries from the front (oldest first).
        let cutoff = now.saturating_sub(self.ttl_secs);
        while let Some(&(_, ts)) = inner.order.front() {
            if ts < cutoff {
                inner.order.pop_front();
            } else {
                break;
            }
        }

        // Replay if a live entry with the same key exists.
        if inner.order.iter().any(|(k, _)| *k == key) {
            return true;
        }

        // Cap memory: drop the oldest if at capacity.
        if inner.order.len() >= self.max_entries {
            inner.order.pop_front();
        }
        inner.order.push_back((key, now));
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Key {
        [b; 64]
    }

    #[test]
    fn first_sight_is_not_replay() {
        let g = ReplayGuard::new(Duration::from_secs(240));
        assert!(!g.check_and_record(key(1), 1000));
    }

    #[test]
    fn second_sight_within_ttl_is_replay() {
        let g = ReplayGuard::new(Duration::from_secs(240));
        assert!(!g.check_and_record(key(1), 1000));
        assert!(g.check_and_record(key(1), 1100)); // within 240s window
    }

    #[test]
    fn distinct_keys_are_independent() {
        let g = ReplayGuard::new(Duration::from_secs(240));
        assert!(!g.check_and_record(key(1), 1000));
        assert!(!g.check_and_record(key(2), 1000));
    }

    #[test]
    fn key_expires_after_ttl() {
        let g = ReplayGuard::new(Duration::from_secs(240));
        assert!(!g.check_and_record(key(1), 1000));
        // Far past the window: the old entry is purged, so it looks fresh again.
        assert!(!g.check_and_record(key(1), 2000));
    }

    #[test]
    fn replay_key_requires_32_byte_fields() {
        assert!(replay_key(&[0u8; 32], &[0u8; 32]).is_some());
        assert!(replay_key(&[0u8; 16], &[0u8; 32]).is_none());
        assert!(replay_key(&[0u8; 32], &[0u8; 8]).is_none());
    }
}
