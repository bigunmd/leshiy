//! TOML config for the REALITY server, mapped to leshiy_reality::config::ServerAuthConfig.
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use leshiy_reality::config::ServerAuthConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
pub struct RealityServerConfig {
    pub listen: String,
    pub dest: String,
    pub server_names: Vec<String>,
    pub static_private_key_b64: String,
    pub short_ids: Vec<String>, // hex, 8 bytes each
    pub max_time_diff_secs: u64,
    /// Public host:port used in leshiy:// URIs. Written by server-init; if empty, not used.
    #[serde(default)]
    pub host: String,
    /// Path to the Unix control socket. Defaults to `<config_dir>/leshiy.sock`.
    #[serde(default)]
    pub control_socket: Option<String>,
    /// Path to the sqlite user database. When set, users survive restart.
    /// If absent, falls back to in-memory store seeded from `short_ids`.
    #[serde(default)]
    pub user_db: Option<String>,
}

impl RealityServerConfig {
    pub fn to_auth_config(&self) -> Result<ServerAuthConfig> {
        let key_vec = URL_SAFE_NO_PAD
            .decode(&self.static_private_key_b64)
            .context("bad static key b64")?;
        let key: [u8; 32] = key_vec
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("static key must be 32 bytes"))?;
        let mut short_ids = HashSet::new();
        for s in &self.short_ids {
            let v = hex::decode(s).with_context(|| format!("bad short_id hex: {s}"))?;
            let id: [u8; 8] = v
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("short_id must be 8 bytes: {s}"))?;
            short_ids.insert(id);
        }
        Ok(ServerAuthConfig {
            static_secret: Zeroizing::new(key),
            server_names: self.server_names.iter().cloned().collect(),
            short_ids,
            max_time_diff: Duration::from_secs(self.max_time_diff_secs),
            dest: self.dest.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_to_auth_config() {
        let c = RealityServerConfig {
            listen: "0.0.0.0:443".into(),
            dest: "www.microsoft.com:443".into(),
            server_names: vec!["www.microsoft.com".into()],
            static_private_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode([5u8; 32]),
            short_ids: vec!["0102030400000000".into()],
            max_time_diff_secs: 120,
            host: "www.example.com:443".into(),
            control_socket: None,
            user_db: None,
        };
        let ac = c.to_auth_config().unwrap();
        assert_eq!(ac.dest, "www.microsoft.com:443");
        assert!(ac.sni_allowed("www.microsoft.com"));
        assert!(ac.short_id_allowed(&[1, 2, 3, 4, 0, 0, 0, 0]));
        assert_eq!(*ac.static_secret, [5u8; 32]);
    }
}
