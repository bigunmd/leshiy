//! REALITY server/client configuration.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashSet;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::error::{RealityError, Result};

pub struct ServerAuthConfig {
    pub static_secret: Zeroizing<[u8; 32]>,
    pub server_names: HashSet<String>,
    pub short_ids: HashSet<[u8; 8]>,
    pub max_time_diff: Duration,
    pub dest: String, // host:port of the borrowed site
}

#[derive(Clone)]
pub struct ClientAuthConfig {
    pub server_public: [u8; 32],
    pub short_id: [u8; 8],
    pub sni: String,
}

impl ServerAuthConfig {
    pub fn short_id_allowed(&self, id: &[u8; 8]) -> bool {
        self.short_ids.contains(id)
    }
    pub fn sni_allowed(&self, sni: &str) -> bool {
        self.server_names.contains(sni)
    }
}

/// leshiy://<base64url server_pubkey>@<host:port>?sni=<sni>&sid=<hex short_id>
pub fn format_reality_uri(
    server_public: &[u8; 32],
    host_port: &str,
    sni: &str,
    short_id: &[u8; 8],
) -> String {
    format!(
        "leshiy://{}@{}?sni={}&sid={}",
        URL_SAFE_NO_PAD.encode(server_public),
        host_port,
        sni,
        hex::encode(short_id),
    )
}

pub struct RealityUri {
    pub server_addr: String,
    pub client: ClientAuthConfig,
}

impl RealityUri {
    pub fn parse(s: &str) -> Result<RealityUri> {
        let rest = s
            .strip_prefix("leshiy://")
            .ok_or_else(|| RealityError::Malformed("missing leshiy:// scheme".into()))?;
        let (auth, hostq) = rest
            .split_once('@')
            .ok_or_else(|| RealityError::Malformed("missing @".into()))?;
        let pk_vec = URL_SAFE_NO_PAD
            .decode(auth)
            .map_err(|_| RealityError::Malformed("bad base64 pubkey".into()))?;
        let server_public: [u8; 32] = pk_vec
            .as_slice()
            .try_into()
            .map_err(|_| RealityError::Malformed("pubkey must be 32 bytes".into()))?;
        let (host_port, query) = hostq
            .split_once('?')
            .ok_or_else(|| RealityError::Malformed("missing query".into()))?;
        let mut sni = None;
        let mut sid = None;
        for kv in query.split('&') {
            match kv.split_once('=') {
                Some(("sni", v)) => sni = Some(v.to_string()),
                Some(("sid", v)) => sid = Some(v.to_string()),
                _ => {}
            }
        }
        let sni = sni.ok_or_else(|| RealityError::Malformed("missing sni".into()))?;
        let sid_hex = sid.ok_or_else(|| RealityError::Malformed("missing sid".into()))?;
        let sid_vec =
            hex::decode(&sid_hex).map_err(|_| RealityError::Malformed("bad sid hex".into()))?;
        let short_id: [u8; 8] = sid_vec
            .as_slice()
            .try_into()
            .map_err(|_| RealityError::Malformed("sid must be 8 bytes".into()))?;
        Ok(RealityUri {
            server_addr: host_port.to_string(),
            client: ClientAuthConfig {
                server_public,
                short_id,
                sni,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_uri_roundtrip() {
        let pk = [7u8; 32];
        let sid = [1u8, 2, 3, 4, 0, 0, 0, 0];
        let uri = format_reality_uri(&pk, "vps.example.com:443", "www.microsoft.com", &sid);
        let p = RealityUri::parse(&uri).unwrap();
        assert_eq!(p.server_addr, "vps.example.com:443");
        assert_eq!(p.client.server_public, pk);
        assert_eq!(p.client.sni, "www.microsoft.com");
        assert_eq!(p.client.short_id, sid);
    }

    #[test]
    fn reality_uri_rejects_garbage() {
        assert!(RealityUri::parse("https://nope").is_err()); // wrong scheme
        assert!(RealityUri::parse("leshiy://bad@h:1").is_err()); // pubkey not 32 bytes
        // valid 32-byte pubkey but no ?sni=&sid= query → missing params
        let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert!(RealityUri::parse(&format!("leshiy://{pk}@h:1")).is_err());
    }
}
