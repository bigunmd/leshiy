//! Per-user model + the DB-free enforcement seam (ADR-0018). All datapath methods are
//! non-blocking in-memory ops (ADR-0019).
//!
//! ADR-0019 hot-path discipline: `authorize`/`add_usage`/`still_allowed` take only brief SYNC
//! locks (map read-lock + per-entry `Mutex<Def>`). The map read-lock is dropped before the
//! per-entry def lock is acquired in `authorize`. No `.await` is ever held under any lock.
use crate::ratelimit::TokenBucket;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone, Debug)]
pub struct User {
    pub short_id: [u8; 8],
    pub enabled: bool,
    pub expires_at: Option<u64>, // unix secs; None = never
    pub data_cap: Option<u64>,   // total bytes up+down; None = unlimited
    pub rate_up: Option<u32>,    // bytes/sec; None = unlimited
    pub rate_down: Option<u32>,
}

/// Cheap, cloneable handles given to the datapath after authorize().
#[derive(Clone)]
pub struct UserLimits {
    pub up: Option<Arc<TokenBucket>>,
    pub down: Option<Arc<TokenBucket>>,
}

/// Enforcement seam. CONTRACT: every method is a non-blocking in-memory op
/// (atomics / short read-lock) — no I/O, no lock across an await. (ADR-0019.)
pub trait UserStore: Send + Sync {
    fn authorize(&self, short_id: &[u8; 8], now: u64) -> Option<UserLimits>;
    fn add_usage(&self, short_id: &[u8; 8], up: u64, down: u64);
    fn still_allowed(&self, short_id: &[u8; 8], now: u64) -> bool;
}

/// Admin interface for runtime user management. All methods are safe to call on a live server.
pub trait UserAdmin: Send + Sync {
    /// Insert or update a user. If the user already exists, replaces the definition while
    /// preserving accumulated usage counters (re-upsert carries usage over).
    fn upsert(&self, user: User);
    /// Remove a user. Returns `true` if found and removed.
    fn remove(&self, short_id: &[u8; 8]) -> bool;
    /// Enable or disable a user live. Returns `true` if the user existed.
    fn set_enabled(&self, short_id: &[u8; 8], on: bool) -> bool;
    /// Reset usage counters to zero. Returns `true` if the user existed.
    fn reset_usage(&self, short_id: &[u8; 8]) -> bool;
    /// Snapshot of all users with their current usage counters.
    fn snapshot(&self) -> Vec<UserStatus>;
}

/// Snapshot of a user and their current usage counters.
#[derive(Clone, Debug)]
pub struct UserStatus {
    pub user: User,
    pub used_up: u64,
    pub used_down: u64,
}

/// Mutable definition (rate limits, caps, enabled flag). Held under a per-entry Mutex.
/// Kept small so the lock is brief — no I/O while holding it.
struct Def {
    enabled: bool,
    expires_at: Option<u64>,
    data_cap: Option<u64>,
    up: Option<Arc<TokenBucket>>,
    down: Option<Arc<TokenBucket>>,
    rate_up: Option<u32>, // kept for snapshot()
    rate_down: Option<u32>,
}

struct Entry {
    short_id: [u8; 8],
    def: Mutex<Def>,
    used_up: AtomicU64,
    used_down: AtomicU64,
}

pub struct InMemoryUserStore {
    users: RwLock<HashMap<[u8; 8], Arc<Entry>>>,
}

impl InMemoryUserStore {
    pub fn new(users: Vec<User>) -> Self {
        let s = InMemoryUserStore {
            users: RwLock::new(HashMap::new()),
        };
        for u in users {
            s.upsert(u);
        }
        s
    }

    /// Convenience for the M1.5a wiring: all short_ids as unlimited users (current behavior).
    pub fn from_short_ids(ids: impl IntoIterator<Item = [u8; 8]>) -> Self {
        Self::new(
            ids.into_iter()
                .map(|short_id| User {
                    short_id,
                    enabled: true,
                    expires_at: None,
                    data_cap: None,
                    rate_up: None,
                    rate_down: None,
                })
                .collect(),
        )
    }

    fn def_of(u: &User) -> Def {
        Def {
            enabled: u.enabled,
            expires_at: u.expires_at,
            data_cap: u.data_cap,
            up: u.rate_up.map(|r| Arc::new(TokenBucket::new(r as u64))),
            down: u.rate_down.map(|r| Arc::new(TokenBucket::new(r as u64))),
            rate_up: u.rate_up,
            rate_down: u.rate_down,
        }
    }

    /// Predicate over a locked Def + usage atomics. Called with the def lock held.
    ///
    /// Lock ordering is always map-then-def: `authorize` drops the map read-lock before
    /// acquiring the def lock; `still_allowed` holds the map read-lock throughout (which is
    /// safe — it never tries to acquire the write-lock, and the map lock is always taken
    /// before the def lock). Both call sites are correct.
    fn ok(def: &Def, used: u64, now: u64) -> bool {
        if !def.enabled {
            return false;
        }
        if let Some(exp) = def.expires_at
            && now > exp
        {
            return false;
        }
        if let Some(cap) = def.data_cap
            && used >= cap
        {
            return false;
        }
        true
    }
}

impl UserStore for InMemoryUserStore {
    fn authorize(&self, short_id: &[u8; 8], now: u64) -> Option<UserLimits> {
        // Read-lock the map, clone the Arc, then DROP the map lock before touching the def mutex.
        let e = {
            let g = self.users.read().unwrap();
            g.get(short_id)?.clone() // drop g here
        };
        // Map lock is gone. Briefly lock the per-entry def — no await, no I/O.
        let def = e.def.lock().unwrap();
        let used = e
            .used_up
            .load(Ordering::Relaxed)
            .saturating_add(e.used_down.load(Ordering::Relaxed));
        if !Self::ok(&def, used, now) {
            return None;
        }
        Some(UserLimits {
            up: def.up.clone(),
            down: def.down.clone(),
        })
    }

    fn add_usage(&self, short_id: &[u8; 8], up: u64, down: u64) {
        let g = self.users.read().unwrap();
        if let Some(e) = g.get(short_id) {
            if up > 0 {
                e.used_up.fetch_add(up, Ordering::Relaxed);
            }
            if down > 0 {
                e.used_down.fetch_add(down, Ordering::Relaxed);
            }
        }
        // g (read-lock) dropped here
    }

    fn still_allowed(&self, short_id: &[u8; 8], now: u64) -> bool {
        let g = self.users.read().unwrap();
        let Some(e) = g.get(short_id) else {
            return false;
        };
        let used = e
            .used_up
            .load(Ordering::Relaxed)
            .saturating_add(e.used_down.load(Ordering::Relaxed));
        let def = e.def.lock().unwrap();
        Self::ok(&def, used, now)
        // g (read-lock) + def (Mutex) both dropped here
    }
}

impl UserAdmin for InMemoryUserStore {
    fn upsert(&self, user: User) {
        let mut g = self.users.write().unwrap();
        match g.get(&user.short_id) {
            Some(e) => {
                // Existing entry: replace the def but keep usage atomics.
                *e.def.lock().unwrap() = Self::def_of(&user);
            }
            None => {
                g.insert(
                    user.short_id,
                    Arc::new(Entry {
                        short_id: user.short_id,
                        def: Mutex::new(Self::def_of(&user)),
                        used_up: AtomicU64::new(0),
                        used_down: AtomicU64::new(0),
                    }),
                );
            }
        }
    }

    fn remove(&self, short_id: &[u8; 8]) -> bool {
        self.users.write().unwrap().remove(short_id).is_some()
    }

    fn set_enabled(&self, short_id: &[u8; 8], on: bool) -> bool {
        let g = self.users.read().unwrap();
        match g.get(short_id) {
            Some(e) => {
                e.def.lock().unwrap().enabled = on;
                true
            }
            None => false,
        }
    }

    fn reset_usage(&self, short_id: &[u8; 8]) -> bool {
        let g = self.users.read().unwrap();
        match g.get(short_id) {
            Some(e) => {
                e.used_up.store(0, Ordering::Relaxed);
                e.used_down.store(0, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    fn snapshot(&self) -> Vec<UserStatus> {
        let g = self.users.read().unwrap();
        g.values()
            .map(|e| {
                let d = e.def.lock().unwrap();
                UserStatus {
                    user: User {
                        short_id: e.short_id,
                        enabled: d.enabled,
                        expires_at: d.expires_at,
                        data_cap: d.data_cap,
                        rate_up: d.rate_up,
                        rate_down: d.rate_down,
                    },
                    used_up: e.used_up.load(Ordering::Relaxed),
                    used_down: e.used_down.load(Ordering::Relaxed),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(short_id: [u8; 8]) -> User {
        User {
            short_id,
            enabled: true,
            expires_at: None,
            data_cap: None,
            rate_up: None,
            rate_down: None,
        }
    }

    #[test]
    fn authorize_gates_enabled_expiry_cap() {
        let mut disabled = user([1; 8]);
        disabled.enabled = false;
        let mut expired = user([2; 8]);
        expired.expires_at = Some(100);
        let mut capped = user([3; 8]);
        capped.data_cap = Some(10);
        let ok = user([4; 8]);
        let store = InMemoryUserStore::new(vec![disabled, expired, capped, ok]);

        assert!(store.authorize(&[1; 8], 200).is_none()); // disabled
        assert!(store.authorize(&[2; 8], 200).is_none()); // expired (now>expiry)
        assert!(store.authorize(&[2; 8], 50).is_some()); // not yet expired
        assert!(store.authorize(&[9; 8], 200).is_none()); // unknown short_id
        assert!(store.authorize(&[4; 8], 200).is_some()); // ok

        store.add_usage(&[3; 8], 6, 6); // 12 > cap 10
        assert!(store.authorize(&[3; 8], 200).is_none()); // over cap
        assert!(!store.still_allowed(&[3; 8], 200));
    }

    #[test]
    fn limits_expose_buckets_only_when_capped() {
        let mut u = user([5; 8]);
        u.rate_down = Some(1000);
        let store = InMemoryUserStore::new(vec![u]);
        let lim = store.authorize(&[5; 8], 0).unwrap();
        assert!(lim.up.is_none()); // unlimited up → no bucket
        assert!(lim.down.is_some()); // capped down → bucket
    }

    #[test]
    fn admin_upsert_remove_and_live_disable() {
        let store = InMemoryUserStore::new(vec![]);
        store.upsert(User {
            short_id: [1; 8],
            enabled: true,
            expires_at: None,
            data_cap: None,
            rate_up: None,
            rate_down: None,
        });
        assert!(store.authorize(&[1; 8], 0).is_some()); // visible immediately
        store.set_enabled(&[1; 8], false);
        assert!(store.authorize(&[1; 8], 0).is_none()); // live disable reflected
        assert!(!store.still_allowed(&[1; 8], 0)); // mid-session re-check sees it too
        store.set_enabled(&[1; 8], true);
        store.add_usage(&[1; 8], 100, 200);
        store.reset_usage(&[1; 8]);
        let snap = store.snapshot();
        let s = snap.iter().find(|u| u.user.short_id == [1; 8]).unwrap();
        assert_eq!((s.used_up, s.used_down), (0, 0));
        assert!(store.remove(&[1; 8]));
        assert!(store.authorize(&[1; 8], 0).is_none()); // gone
    }

    #[test]
    fn upsert_preserves_usage_on_redefine() {
        let store = InMemoryUserStore::new(vec![]);
        store.upsert(User {
            short_id: [2; 8],
            enabled: true,
            expires_at: None,
            data_cap: None,
            rate_up: None,
            rate_down: None,
        });
        store.add_usage(&[2; 8], 1000, 0);
        // redefine same user with a data cap — usage must carry over
        store.upsert(User {
            short_id: [2; 8],
            enabled: true,
            expires_at: None,
            data_cap: Some(5000),
            rate_up: None,
            rate_down: None,
        });
        let s = store
            .snapshot()
            .into_iter()
            .find(|u| u.user.short_id == [2; 8])
            .unwrap();
        assert_eq!(s.used_up, 1000);
    }
}
