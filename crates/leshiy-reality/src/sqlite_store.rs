//! Sqlite-backed UserStore: in-memory hot path + off-hot-path persistence (ADR-0021).
//! The datapath only ever touches the inner InMemoryUserStore; sqlite is used by open(),
//! the write-through on UserAdmin mutations, and the background flusher.
use crate::user::{InMemoryUserStore, User, UserAdmin, UserLimits, UserStatus, UserStore};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

pub struct SqliteUserStore {
    mem: InMemoryUserStore,
    db: Mutex<Connection>,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS users (
    short_id BLOB PRIMARY KEY,
    enabled INTEGER NOT NULL,
    expires_at INTEGER,
    data_cap INTEGER,
    rate_up INTEGER,
    rate_down INTEGER,
    used_up INTEGER NOT NULL DEFAULT 0,
    used_down INTEGER NOT NULL DEFAULT 0
)";

fn row_to_user(
    short_id: [u8; 8],
    enabled: i64,
    expires_at: Option<i64>,
    data_cap: Option<i64>,
    rate_up: Option<i64>,
    rate_down: Option<i64>,
) -> User {
    User {
        short_id,
        enabled: enabled != 0,
        expires_at: expires_at.map(|v| v as u64),
        data_cap: data_cap.map(|v| v as u64),
        rate_up: rate_up.map(|v| v as u32),
        rate_down: rate_down.map(|v| v as u32),
    }
}

impl SqliteUserStore {
    /// Open (creating schema if needed) and load all rows into the in-memory store.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(&format!("PRAGMA journal_mode=WAL;\n{SCHEMA}"))?;
        let mem = InMemoryUserStore::new(vec![]);
        {
            let mut stmt = conn.prepare(
                "SELECT short_id,enabled,expires_at,data_cap,rate_up,rate_down,used_up,used_down FROM users",
            )?;
            let rows = stmt.query_map([], |r| {
                let sid: Vec<u8> = r.get(0)?;
                Ok((
                    sid,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            })?;
            for row in rows {
                let (sid, enabled, exp, cap, ru, rd, uu, ud) = row?;
                let Ok(short_id) = <[u8; 8]>::try_from(sid.as_slice()) else {
                    continue;
                };
                mem.upsert(row_to_user(short_id, enabled, exp, cap, ru, rd));
                mem.add_usage(&short_id, uu as u64, ud as u64); // seed usage from 0
            }
        }
        Ok(SqliteUserStore {
            mem,
            db: Mutex::new(conn),
        })
    }

    fn persist_def(&self, u: &User) -> rusqlite::Result<()> {
        let c = self.db.lock().unwrap_or_else(|e| e.into_inner());
        c.execute(
            "INSERT INTO users (short_id,enabled,expires_at,data_cap,rate_up,rate_down,used_up,used_down)
             VALUES (?1,?2,?3,?4,?5,?6,COALESCE((SELECT used_up FROM users WHERE short_id=?1),0),
                     COALESCE((SELECT used_down FROM users WHERE short_id=?1),0))
             ON CONFLICT(short_id) DO UPDATE SET enabled=?2,expires_at=?3,data_cap=?4,rate_up=?5,rate_down=?6",
            rusqlite::params![
                &u.short_id[..],
                u.enabled as i64,
                u.expires_at.map(|v| v as i64),
                u.data_cap.map(|v| v as i64),
                u.rate_up.map(|v| v as i64),
                u.rate_down.map(|v| v as i64)
            ],
        )?;
        Ok(())
    }

    /// Persist the current in-memory usage counters for all users (what the bg flusher runs).
    pub fn flush_now(&self) -> rusqlite::Result<()> {
        let snap = self.mem.snapshot();
        let c = self.db.lock().unwrap_or_else(|e| e.into_inner());
        for s in snap {
            c.execute(
                "UPDATE users SET used_up=?2, used_down=?3 WHERE short_id=?1",
                rusqlite::params![&s.user.short_id[..], s.used_up as i64, s.used_down as i64],
            )?;
        }
        Ok(())
    }
}

// Datapath = pure in-memory delegation (ADR-0021: never touches sqlite).
impl UserStore for SqliteUserStore {
    fn authorize(&self, id: &[u8; 8], now: u64) -> Option<UserLimits> {
        self.mem.authorize(id, now)
    }
    fn add_usage(&self, id: &[u8; 8], up: u64, down: u64) {
        self.mem.add_usage(id, up, down)
    }
    fn still_allowed(&self, id: &[u8; 8], now: u64) -> bool {
        self.mem.still_allowed(id, now)
    }
}

// Control plane = in-memory mutate + sqlite write-through (rare).
impl UserAdmin for SqliteUserStore {
    fn upsert(&self, user: User) {
        self.mem.upsert(user.clone());
        if let Err(e) = self.persist_def(&user) {
            tracing::warn!(error = %e, "sqlite write-through (upsert) failed");
        }
    }
    fn remove(&self, id: &[u8; 8]) -> bool {
        let r = self.mem.remove(id);
        if r {
            let c = self.db.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = c.execute(
                "DELETE FROM users WHERE short_id=?1",
                rusqlite::params![&id[..]],
            ) {
                tracing::warn!(error = %e, "sqlite write-through failed");
            }
        }
        r
    }
    fn set_enabled(&self, id: &[u8; 8], on: bool) -> bool {
        let r = self.mem.set_enabled(id, on);
        if r {
            let c = self.db.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = c.execute(
                "UPDATE users SET enabled=?2 WHERE short_id=?1",
                rusqlite::params![&id[..], on as i64],
            ) {
                tracing::warn!(error = %e, "sqlite write-through failed");
            }
        }
        r
    }
    fn reset_usage(&self, id: &[u8; 8]) -> bool {
        let r = self.mem.reset_usage(id);
        if r {
            let c = self.db.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = c.execute(
                "UPDATE users SET used_up=0,used_down=0 WHERE short_id=?1",
                rusqlite::params![&id[..]],
            ) {
                tracing::warn!(error = %e, "sqlite write-through failed");
            }
        }
        r
    }
    fn snapshot(&self) -> Vec<UserStatus> {
        self.mem.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::{User, UserAdmin, UserStore};

    // Compile-time check: SqliteUserStore is Send+Sync and coercible to both Arc<dyn …>.
    fn _assert_send_sync_and_arc<T: Send + Sync + UserStore + UserAdmin + 'static>(s: T) {
        let a = std::sync::Arc::new(s);
        let _: std::sync::Arc<dyn UserStore> = a.clone();
        let _: std::sync::Arc<dyn UserAdmin> = a;
    }

    fn tmp_db() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "leshiy-sqlite-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn users_and_usage_survive_reopen() {
        let path = tmp_db();
        {
            let store = SqliteUserStore::open(&path).unwrap();
            store.upsert(User {
                short_id: [1; 8],
                enabled: true,
                expires_at: None,
                data_cap: Some(1000),
                rate_up: None,
                rate_down: None,
            });
            store.add_usage(&[1; 8], 100, 200); // in-memory atomics
            store.flush_now().unwrap(); // persist usage (what the bg flusher does)
        } // drop closes the connection
        {
            let store = SqliteUserStore::open(&path).unwrap(); // reload
            assert!(store.authorize(&[1; 8], 0).is_some()); // user restored
            let s = store
                .snapshot()
                .into_iter()
                .find(|u| u.user.short_id == [1; 8])
                .unwrap();
            assert_eq!(s.user.data_cap, Some(1000)); // definition restored
            assert_eq!((s.used_up, s.used_down), (100, 200)); // usage restored
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_through_visible_in_fresh_open() {
        let path = tmp_db();
        let store = SqliteUserStore::open(&path).unwrap();
        store.upsert(User {
            short_id: [2; 8],
            enabled: true,
            expires_at: None,
            data_cap: None,
            rate_up: None,
            rate_down: None,
        });
        // a SEPARATE open sees the definition immediately (write-through, no flush needed)
        let other = SqliteUserStore::open(&path).unwrap();
        assert!(other.snapshot().iter().any(|u| u.user.short_id == [2; 8]));
        store.remove(&[2; 8]);
        let other2 = SqliteUserStore::open(&path).unwrap();
        assert!(!other2.snapshot().iter().any(|u| u.user.short_id == [2; 8])); // delete write-through
        let _ = std::fs::remove_file(&path);
    }
}
