//! Encrypted vault: server records and their issued client configs.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

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

const MAGIC: &[u8] = b"LVAULT1\n";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| Error::Vault(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| Error::Vault(format!("argon2: {e}")))?;
    Ok(key)
}

/// Encrypt `records` under a passphrase, returning the full vault blob.
pub fn seal(records: &[ServerRecord], passphrase: &str) -> Result<Vec<u8>> {
    let plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(records).map_err(|e| Error::Vault(format!("encode: {e}")))?,
    );

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| Error::Vault("encrypt failed".into()))?;

    let mut out = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(1u8); // version
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a vault blob produced by [`seal`].
pub fn open(blob: &[u8], passphrase: &str) -> Result<Vec<ServerRecord>> {
    let header = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;
    if blob.len() < header || &blob[..MAGIC.len()] != MAGIC {
        return Err(Error::Vault("not a leshiy vault".into()));
    }
    let version = blob[MAGIC.len()];
    if version != 1 {
        return Err(Error::Vault(format!(
            "unsupported vault version: {version}"
        )));
    }
    let salt = &blob[MAGIC.len() + 1..MAGIC.len() + 1 + SALT_LEN];
    let nonce = &blob[MAGIC.len() + 1 + SALT_LEN..header];
    let ct = &blob[header..];

    let key = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let pt = zeroize::Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), ct)
            .map_err(|_| Error::Vault("decrypt failed (wrong passphrase or corrupt)".into()))?,
    );
    serde_json::from_slice(&pt).map_err(|e| Error::Vault(format!("decode: {e}")))
}

use std::path::Path;

/// In-memory collection of server records, persisted as a sealed blob.
#[derive(Default)]
pub struct Vault {
    records: Vec<ServerRecord>,
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load and decrypt the vault at `path`. A missing file yields an empty vault.
    pub fn load(path: &Path, passphrase: &str) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Self {
                records: open(&bytes, passphrase)?,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Encrypt and atomically write the vault to `path`.
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
        let blob = seal(&self.records, passphrase)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &blob)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    fn matches(rec: &ServerRecord, key: &str) -> bool {
        rec.id == key || rec.label == key
    }

    /// Insert, or replace an existing record with the same `id`.
    pub fn upsert(&mut self, rec: ServerRecord) {
        if let Some(slot) = self.records.iter_mut().find(|r| r.id == rec.id) {
            *slot = rec;
        } else {
            self.records.push(rec);
        }
    }

    pub fn get(&self, id_or_label: &str) -> Option<&ServerRecord> {
        self.records.iter().find(|r| Self::matches(r, id_or_label))
    }

    pub fn get_mut(&mut self, id_or_label: &str) -> Option<&mut ServerRecord> {
        self.records
            .iter_mut()
            .find(|r| Self::matches(r, id_or_label))
    }

    pub fn remove(&mut self, id_or_label: &str) -> bool {
        let before = self.records.len();
        self.records.retain(|r| !Self::matches(r, id_or_label));
        self.records.len() != before
    }

    pub fn list(&self) -> &[ServerRecord] {
        &self.records
    }

    /// Seal a single record (optionally connection-only) under `passphrase`.
    pub fn export_one(
        &self,
        id_or_label: &str,
        connection_only: bool,
        passphrase: &str,
    ) -> Result<Vec<u8>> {
        let rec = self
            .get(id_or_label)
            .ok_or_else(|| Error::Vault(format!("no server {id_or_label:?}")))?;
        let out = if connection_only {
            rec.redacted_for_sharing()
        } else {
            rec.clone()
        };
        seal(std::slice::from_ref(&out), passphrase)
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

    #[test]
    fn seal_open_round_trips() {
        let recs = vec![sample()];
        let blob = seal(&recs, "correct horse").unwrap();
        assert!(blob.starts_with(b"LVAULT1\n"));
        let back = open(&blob, "correct horse").unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].id, "srv1");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(&[sample()], "right").unwrap();
        assert!(open(&blob, "wrong").is_err());
    }

    #[test]
    fn tamper_fails_aead() {
        let mut blob = seal(&[sample()], "pw").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a ciphertext byte
        assert!(open(&blob, "pw").is_err());
    }

    #[test]
    fn bad_version_byte_rejected() {
        let mut blob = seal(&[sample()], "pw").unwrap();
        blob[super::MAGIC.len()] = 9; // bogus version
        let err = open(&blob, "pw").unwrap_err();
        assert!(format!("{err}").contains("version"));
    }

    #[test]
    fn upsert_get_remove() {
        let mut v = Vault::new();
        v.upsert(sample());
        assert_eq!(v.list().len(), 1);
        assert!(v.get("srv1").is_some());
        assert!(v.get("my-vps").is_some()); // by label
        assert!(v.remove("srv1"));
        assert_eq!(v.list().len(), 0);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("lvault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("servers.lvault");
        let mut v = Vault::new();
        v.upsert(sample());
        v.save(&path, "pw").unwrap();
        let loaded = Vault::load(&path, "pw").unwrap();
        assert_eq!(loaded.list().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_missing_file_is_empty() {
        let v = Vault::load(std::path::Path::new("/nonexistent/x.lvault"), "pw").unwrap();
        assert_eq!(v.list().len(), 0);
    }

    #[test]
    fn export_connection_only_strips_secret() {
        let mut v = Vault::new();
        v.upsert(sample());
        let blob = v.export_one("srv1", true, "share-pw").unwrap();
        let recs = open(&blob, "share-pw").unwrap();
        assert!(matches!(recs[0].ssh_secret, SshSecret::None));
        assert_eq!(recs[0].clients.len(), 1);
    }
}
