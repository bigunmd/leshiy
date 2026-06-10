//! Stored server configs ("profiles") and their on-disk store.
//!
//! A profile wraps one `leshiy://` URI plus display metadata. Import validates the
//! URI through `leshiy-reality` so malformed links never enter the store.
use crate::error::{ClientError, Result};
use leshiy_reality::config::RealityUri;
use serde::{Deserialize, Serialize};
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
}
