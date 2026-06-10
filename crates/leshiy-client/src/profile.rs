//! Stored server configs ("profiles") and their on-disk store.
//!
//! A profile wraps one `leshiy://` URI plus display metadata. Import validates the
//! URI through `leshiy-reality` so malformed links never enter the store.
use crate::error::{ClientError, Result};
use leshiy_reality::config::RealityUri;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// One saved server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable opaque id (UUID v4).
    pub id: String,
    /// User-facing label.
    pub name: String,
    /// The full `leshiy://` link (validated on import).
    pub uri: String,
    /// Unix seconds when imported.
    pub created_at: u64,
    /// Last measured latency in ms, if ever probed (reserved; populated in a later plan).
    pub last_latency_ms: Option<u32>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Profile {
    /// Build a validated profile from a `leshiy://` URI. Returns `InvalidUri` if the
    /// link does not parse — note the error carries no parse detail (no oracle).
    pub fn from_uri(uri: &str, name: &str) -> Result<Profile> {
        RealityUri::parse(uri).map_err(|_| ClientError::InvalidUri)?;
        Ok(Profile {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            uri: uri.to_string(),
            created_at: now_secs(),
            last_latency_ms: None,
        })
    }
}

/// In-memory collection of profiles plus the currently-selected one. Persistence is
/// added in the next task; the struct already derives `Serialize`/`Deserialize`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileStore {
    profiles: Vec<Profile>,
    active_id: Option<String>,
}

impl ProfileStore {
    /// Validate `uri`, store a new profile, and return its id.
    pub fn import(&mut self, uri: &str, name: &str) -> Result<String> {
        let profile = Profile::from_uri(uri, name)?;
        let id = profile.id.clone();
        self.profiles.push(profile);
        Ok(id)
    }

    /// All stored profiles, in insertion order.
    pub fn list(&self) -> &[Profile] {
        &self.profiles
    }

    /// The active profile, if one is selected and still present.
    pub fn active(&self) -> Option<&Profile> {
        let id = self.active_id.as_deref()?;
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Select the active profile. Returns `false` if no profile has that id.
    pub fn set_active(&mut self, id: &str) -> bool {
        if self.profiles.iter().any(|p| p.id == id) {
            self.active_id = Some(id.to_string());
            true
        } else {
            false
        }
    }

    /// Rename a profile. Returns `false` if not found.
    pub fn rename(&mut self, id: &str, name: &str) -> bool {
        match self.profiles.iter_mut().find(|p| p.id == id) {
            Some(p) => {
                p.name = name.to_string();
                true
            }
            None => false,
        }
    }

    /// Load the store from `path`. A missing file yields an empty store (first run).
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| ClientError::Store(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ClientError::Io(e)),
        }
    }

    /// Persist the store to `path` atomically (write a sibling temp file, then rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data =
            serde_json::to_vec_pretty(self).map_err(|e| ClientError::Store(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Remove a profile. Clears the active pointer if it pointed at this one.
    /// Returns `false` if not found.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        let removed = self.profiles.len() != before;
        if removed && self.active_id.as_deref() == Some(id) {
            self.active_id = None;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leshiy_reality::config::format_reality_uri;

    fn sample_uri() -> String {
        format_reality_uri(
            &[7u8; 32],
            "vps.example.com:443",
            "www.example.com",
            &[1, 2, 3, 4, 0, 0, 0, 0],
        )
    }

    #[test]
    fn from_uri_accepts_valid_link() {
        let p = Profile::from_uri(&sample_uri(), "Frankfurt").unwrap();
        assert_eq!(p.name, "Frankfurt");
        assert!(!p.id.is_empty());
        assert!(p.last_latency_ms.is_none());
    }

    #[test]
    fn from_uri_rejects_garbage() {
        assert!(matches!(
            Profile::from_uri("https://nope", "x"),
            Err(ClientError::InvalidUri)
        ));
    }

    #[test]
    fn ids_are_unique() {
        let a = Profile::from_uri(&sample_uri(), "a").unwrap();
        let b = Profile::from_uri(&sample_uri(), "b").unwrap();
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn store_import_list_and_active() {
        let mut store = ProfileStore::default();
        assert_eq!(store.list().len(), 0);

        let id = store.import(&sample_uri(), "Frankfurt").unwrap();
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].name, "Frankfurt");

        // Garbage import is rejected and does not mutate the store.
        assert!(matches!(
            store.import("nope", "x"),
            Err(ClientError::InvalidUri)
        ));
        assert_eq!(store.list().len(), 1);

        // Activation.
        assert!(store.set_active(&id));
        assert_eq!(store.active().unwrap().id, id);
        assert!(!store.set_active("missing"));
    }

    #[test]
    fn store_rename_and_remove() {
        let mut store = ProfileStore::default();
        let id = store.import(&sample_uri(), "Old").unwrap();

        assert!(store.rename(&id, "New"));
        assert_eq!(store.list()[0].name, "New");
        assert!(!store.rename("missing", "x"));

        store.set_active(&id);
        assert!(store.remove(&id));
        assert_eq!(store.list().len(), 0);
        // Removing the active profile clears the active pointer.
        assert!(store.active().is_none());
        assert!(!store.remove(&id));
    }

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("leshiy-test-{}.json", uuid::Uuid::new_v4()))
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let store = ProfileStore::load(&temp_path()).unwrap();
        assert_eq!(store.list().len(), 0);
        assert!(store.active().is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = temp_path();
        let mut store = ProfileStore::default();
        let id = store.import(&sample_uri(), "A").unwrap();
        store.set_active(&id);
        store.save(&path).unwrap();

        let reloaded = ProfileStore::load(&path).unwrap();
        assert_eq!(reloaded.list().len(), 1);
        assert_eq!(reloaded.active().unwrap().id, id);

        let _ = std::fs::remove_file(&path);
    }
}
