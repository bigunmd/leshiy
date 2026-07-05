//! UniFFI-exposed profile store: multiple saved servers, persisted to a JSON file.
//! Wraps the tested `leshiy_client::ProfileStore` so the app owns no profile logic.
use crate::error::BridgeError;
use leshiy_client::ProfileStore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A saved server, flattened for the UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProfileInfo {
    pub id: String,
    pub name: String,
    pub uri: String,
    pub is_active: bool,
}

/// Persistent, thread-safe profile store over a JSON file (the app's `filesDir`).
#[derive(uniffi::Object)]
pub struct ProfileManager {
    store: Mutex<ProfileStore>,
    path: PathBuf,
}

#[uniffi::export]
impl ProfileManager {
    /// Load (or start empty) from `store_path`.
    #[uniffi::constructor]
    pub fn new(store_path: String) -> Arc<Self> {
        let path = PathBuf::from(store_path);
        let store = ProfileStore::load(&path).unwrap_or_default();
        Arc::new(Self {
            store: Mutex::new(store),
            path,
        })
    }

    /// Validate + save a new profile; returns its id.
    pub fn add(&self, uri: String, name: String) -> Result<String, BridgeError> {
        let mut store = self.store.lock().unwrap();
        let id = store.import(&uri, &name).map_err(|_| BridgeError::BadUri {
            reason: "invalid uri".into(),
        })?;
        self.persist(&store)?;
        Ok(id)
    }

    pub fn list(&self) -> Vec<ProfileInfo> {
        let store = self.store.lock().unwrap();
        let active = store.active().map(|p| p.id.clone());
        store
            .list()
            .iter()
            .map(|p| ProfileInfo {
                id: p.id.clone(),
                name: p.name.clone(),
                uri: p.uri.clone(),
                is_active: active.as_deref() == Some(p.id.as_str()),
            })
            .collect()
    }

    pub fn remove(&self, id: String) -> Result<(), BridgeError> {
        let mut store = self.store.lock().unwrap();
        store.remove(&id);
        self.persist(&store)
    }

    pub fn set_active(&self, id: String) -> Result<(), BridgeError> {
        let mut store = self.store.lock().unwrap();
        if !store.set_active(&id) {
            return Err(BridgeError::NoSuchProfile);
        }
        self.persist(&store)
    }

    /// The active profile's URI, if one is selected.
    pub fn active_uri(&self) -> Option<String> {
        self.store.lock().unwrap().active().map(|p| p.uri.clone())
    }
}

impl ProfileManager {
    fn persist(&self, store: &ProfileStore) -> Result<(), BridgeError> {
        store.save(&self.path).map_err(|e| BridgeError::Store {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp() -> String {
        // Unique per process + call, so parallel tests and leftover files from prior runs
        // never collide (a reused path would reload a stale store).
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir()
            .join(format!(
                "leshiy-pm-test-{}-{}.json",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn sample_uri() -> String {
        leshiy_reality::config::format_reality_uri(
            &[7u8; 32],
            "vps.example.com:443",
            "www.example.com",
            &[1, 2, 3, 4, 0, 0, 0, 0],
        )
    }

    #[test]
    fn add_list_activate_persists() {
        let path = tmp();
        let pm = ProfileManager::new(path.clone());
        let id = pm.add(sample_uri(), "Frankfurt".into()).unwrap();
        assert_eq!(pm.list().len(), 1);
        pm.set_active(id).unwrap();
        assert_eq!(pm.active_uri(), Some(sample_uri()));

        // A fresh manager over the same file sees the persisted active profile.
        let pm2 = ProfileManager::new(path);
        assert!(pm2.list()[0].is_active);
        assert_eq!(pm2.active_uri(), Some(sample_uri()));
    }

    #[test]
    fn add_rejects_garbage() {
        let pm = ProfileManager::new(tmp());
        assert!(matches!(
            pm.add("nope".into(), "x".into()),
            Err(BridgeError::BadUri { .. })
        ));
    }

    #[test]
    fn set_active_unknown_errs() {
        let pm = ProfileManager::new(tmp());
        assert!(matches!(
            pm.set_active("missing".into()),
            Err(BridgeError::NoSuchProfile)
        ));
    }
}
