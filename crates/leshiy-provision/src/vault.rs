//! Encrypted vault: server records and their issued client configs.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// SSH authentication secret. Never serialized in cleartext outside the sealed
/// vault blob; wrapped in `Zeroizing` so it is wiped on drop.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SshSecret {
    /// Used by `redacted_for_sharing` — no credential present.
    None,
    Password(Zeroizing<String>),
    PrivateKey {
        pem: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

// Manual Debug so secrets never leak into logs.
impl std::fmt::Debug for SshSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            SshSecret::None => "None",
            SshSecret::Password(_) => "Password(<redacted>)",
            SshSecret::PrivateKey { .. } => "PrivateKey(<redacted>)",
        };
        f.write_str(kind)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuicInfo {
    pub addr: String,
    pub sni: String,
    pub cert_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub short_id: String,
    pub label: String,
    pub uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerRecord {
    pub id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub ssh_user: String,
    pub ssh_secret: SshSecret,
    pub host_key_fp: String,
    pub public_host: String,
    pub image_ref: String,
    pub container: String,
    pub reality_public_b64: String,
    pub quic: Option<QuicInfo>,
    pub clients: Vec<ClientConfig>,
    pub created_at: u64,
}

impl ServerRecord {
    /// A copy with the SSH secret removed — the `--connection-only` backup form.
    pub fn redacted_for_sharing(&self) -> ServerRecord {
        let mut r = self.clone();
        r.ssh_secret = SshSecret::None;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ServerRecord {
        ServerRecord {
            id: "srv1".into(),
            label: "my-vps".into(),
            host: "203.0.113.5".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::Password("hunter2".to_string().into()),
            host_key_fp: "SHA256:abc".into(),
            public_host: "203.0.113.5:443".into(),
            image_ref: "ghcr.io/x/leshiy:1.4.0".into(),
            container: "leshiy".into(),
            reality_public_b64: "PUBKEY".into(),
            quic: None,
            clients: vec![ClientConfig {
                short_id: "0102030400000000".into(),
                label: "self".into(),
                uri: "leshiy://PUBKEY@203.0.113.5:443?sni=x&sid=0102030400000000".into(),
            }],
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn record_json_round_trips() {
        let r = sample();
        let json = serde_json::to_string(&r).unwrap();
        let back: ServerRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, r.id);
        assert_eq!(back.clients.len(), 1);
        assert_eq!(back.clients[0].short_id, "0102030400000000");
        match back.ssh_secret {
            SshSecret::Password(p) => assert_eq!(&*p, "hunter2"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn redacted_drops_ssh_secret_but_keeps_clients() {
        let r = sample().redacted_for_sharing();
        assert!(matches!(r.ssh_secret, SshSecret::None));
        assert_eq!(r.clients.len(), 1);
    }

    #[test]
    fn ssh_secret_debug_redacts_contents() {
        let pw = SshSecret::Password("hunter2".to_string().into());
        assert!(!format!("{pw:?}").contains("hunter2"));
        let key = SshSecret::PrivateKey {
            pem: "PRIVATE-KEY-MATERIAL".to_string().into(),
            passphrase: Some("secret-pass".to_string().into()),
        };
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("PRIVATE-KEY-MATERIAL"));
        assert!(!dbg.contains("secret-pass"));
    }

    #[test]
    fn private_key_secret_json_round_trips() {
        let mut r = sample();
        r.ssh_secret = SshSecret::PrivateKey {
            pem: "PEMDATA".to_string().into(),
            passphrase: Some("pp".to_string().into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ServerRecord = serde_json::from_str(&json).unwrap();
        match back.ssh_secret {
            SshSecret::PrivateKey { pem, passphrase } => {
                assert_eq!(&*pem, "PEMDATA");
                assert_eq!(passphrase.as_deref().map(|p| &**p), Some("pp"));
            }
            _ => panic!("wrong variant"),
        }
    }
}
