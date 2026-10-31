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
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub connector_uri: Option<String>,
    #[serde(default)]
    pub downstream: Option<String>,
    /// True when this server was provisioned as a non-root user and its
    /// privileged commands must run via `sudo` (day-2 ops prompt for the sudo
    /// password). The password itself is never persisted.
    #[serde(default)]
    pub sudo: bool,
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
    let params = Params::new(64 * 1024, 3, 1, Some(32))
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
    snapshot: std::sync::Mutex<Option<Vec<u8>>>,
    transaction_lock: Option<(std::path::PathBuf, std::fs::File)>,
}

/// Outcome of merging backup records into a vault.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub added: usize,
    pub replaced: usize,
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
                snapshot: std::sync::Mutex::new(Some(bytes)),
                transaction_lock: None,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Hold the cross-process write lock through remote work and persistence.
    pub fn load_locked(path: &Path, passphrase: &str) -> Result<Self> {
        let lock = Self::lock(path)?;
        let mut vault = Self::load(path, passphrase)?;
        vault.transaction_lock = Some((path.to_path_buf(), lock));
        Ok(vault)
    }

    fn lock(path: &Path) -> Result<std::fs::File> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut name = path.as_os_str().to_owned();
        name.push(".lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(name)?;
        lock.try_lock()
            .map_err(|e| Error::Vault(format!("vault busy: {e}; retry after reloading")))?;
        Ok(lock)
    }

    /// Encrypt and atomically write the vault to `path`.
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
        let blob = seal(&self.records, passphrase)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        if self
            .transaction_lock
            .as_ref()
            .is_some_and(|(locked_path, _)| locked_path != path)
        {
            return Err(Error::Vault(
                "cannot save transaction to a different path".into(),
            ));
        }
        let _lock = if self.transaction_lock.is_none() {
            Some(Self::lock(path)?)
        } else {
            None
        };
        let mut snapshot = self.snapshot.lock().unwrap();
        let current = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if current != *snapshot {
            return Err(Error::Vault("vault changed concurrently; remote operations may already have succeeded; reload and reconcile before retrying".into()));
        }
        let tmp = path.with_extension(format!("{}.tmp", rand::random::<u128>()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&blob)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        *snapshot = Some(blob);
        #[cfg(unix)]
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(())
    }

    fn index(&self, key: &str) -> Option<usize> {
        if let Some(i) = self.records.iter().position(|r| r.id == key) {
            return Some(i);
        }
        let mut matches = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.label == key);
        let (i, _) = matches.next()?;
        matches.next().is_none().then_some(i)
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
        self.index(id_or_label).map(|i| &self.records[i])
    }

    pub fn get_mut(&mut self, id_or_label: &str) -> Option<&mut ServerRecord> {
        self.index(id_or_label).map(|i| &mut self.records[i])
    }

    pub fn remove(&mut self, id_or_label: &str) -> bool {
        let Some(i) = self.index(id_or_label) else {
            return false;
        };
        self.records.remove(i);
        true
    }

    /// Remove only an exact resolved ID, never a coinciding label.
    pub fn remove_id(&mut self, id: &str) -> bool {
        let before = self.records.len();
        self.records.retain(|r| r.id != id);
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

    /// Seal every record under `passphrase` — the whole-vault backup form.
    ///
    /// The output is byte-compatible with an on-disk vault, so a phone backup restores through
    /// `leshiy remote restore` and a CLI backup imports into the phone.
    pub fn export_all(&self, passphrase: &str) -> Result<Vec<u8>> {
        seal(&self.records, passphrase)
    }

    /// Merge `recs`, replacing any record with the same id.
    ///
    /// The conflict count uses id-only matching to agree with [`Vault::upsert`]. Counting with
    /// [`Vault::get`] would be wrong: it also matches on label, so a backup record whose label
    /// collided with a *different* local server would be reported replaced while `upsert`
    /// actually appends it.
    pub fn import_records(&mut self, recs: Vec<ServerRecord>) -> ImportSummary {
        let mut summary = ImportSummary::default();
        for rec in recs {
            if self.records.iter().any(|r| r.id == rec.id) {
                summary.replaced += 1;
            } else {
                summary.added += 1;
            }
            self.upsert(rec);
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_save_is_rejected_and_original_survives() {
        let path = std::env::temp_dir().join(format!(
            "leshiy-vault-cas-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut first = Vault::load(&path, "test").unwrap();
        let mut stale = Vault::load(&path, "test").unwrap();
        first.upsert(sample());
        first.save(&path, "test").unwrap();
        let mut other = sample();
        other.id = "other".into();
        stale.upsert(other);
        assert!(stale.save(&path, "test").is_err());
        assert_eq!(Vault::load(&path, "test").unwrap().list()[0].id, "srv1");
    }

    #[test]
    fn locked_transaction_excludes_other_process() {
        const CHILD: &str = "LESHIY_VAULT_LOCK_TEST";
        if let Some(path) = std::env::var_os(CHILD) {
            assert!(Vault::load_locked(Path::new(&path), "test").is_err());
            return;
        }
        let path = std::env::temp_dir().join(format!(
            "leshiy-vault-lock-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let vault = Vault::load_locked(&path, "test").unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "vault::tests::locked_transaction_excludes_other_process",
            ])
            .env(CHILD, &path)
            .status()
            .unwrap();
        assert!(result.success());
        drop(vault);
        assert!(Vault::load_locked(&path, "test").is_ok());
    }

    #[test]
    fn exact_id_wins_over_another_records_label() {
        let mut v = Vault::new();
        let mut other = sample();
        other.id = "other".into();
        other.label = "srv1".into();
        v.upsert(other);
        v.upsert(sample());
        assert_eq!(v.get("srv1").unwrap().id, "srv1");
        assert!(v.remove_id("srv1"));
        assert_eq!(v.list()[0].id, "other");
    }

    #[test]
    fn ambiguous_label_cannot_delete_multiple_records() {
        let mut v = Vault::new();
        v.upsert(sample());
        let mut other = sample();
        other.id = "other".into();
        v.upsert(other);
        assert!(v.get("my-vps").is_none());
        assert!(!v.remove("my-vps"));
        assert_eq!(v.list().len(), 2);
    }

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
            image_ref: "ghcr.io/x/leshiy:1.5.0".into(),
            container: "leshiy".into(),
            reality_public_b64: "PUBKEY".into(),
            quic: None,
            clients: vec![ClientConfig {
                short_id: "0102030400000000".into(),
                label: "self".into(),
                uri: "leshiy://PUBKEY@203.0.113.5:443?sni=x&sid=0102030400000000".into(),
            }],
            created_at: 1_700_000_000,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
            sudo: false,
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

    #[test]
    fn export_all_round_trips_every_record() {
        let mut v = Vault::new();
        v.upsert(sample());
        let mut second = sample();
        second.id = "srv2".into();
        second.label = "other".into();
        v.upsert(second);

        let blob = v.export_all("backup-pw").unwrap();
        let back = open(&blob, "backup-pw").unwrap();
        assert_eq!(back.len(), 2);
        let ids: Vec<&str> = back.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"srv1") && ids.contains(&"srv2"));
    }

    /// Migration is the whole point: a restored vault must still be able to manage its servers,
    /// which it cannot do without the SSH secret.
    #[test]
    fn export_all_keeps_ssh_secrets() {
        let mut v = Vault::new();
        v.upsert(sample());
        let blob = v.export_all("backup-pw").unwrap();
        match &open(&blob, "backup-pw").unwrap()[0].ssh_secret {
            SshSecret::Password(p) => assert_eq!(&**p, "hunter2"),
            _ => panic!("ssh secret lost in backup"),
        }
    }

    #[test]
    fn export_all_wrong_passphrase_fails() {
        let mut v = Vault::new();
        v.upsert(sample());
        let blob = v.export_all("right").unwrap();
        assert!(open(&blob, "wrong").is_err());
    }

    #[test]
    fn export_all_tamper_fails_aead() {
        let mut v = Vault::new();
        v.upsert(sample());
        let mut blob = v.export_all("pw").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open(&blob, "pw").is_err());
    }

    #[test]
    fn import_records_counts_added() {
        let mut v = Vault::new();
        let s = v.import_records(vec![sample()]);
        assert_eq!(
            s,
            ImportSummary {
                added: 1,
                replaced: 0
            }
        );
        assert_eq!(v.list().len(), 1);
    }

    #[test]
    fn import_records_replaces_by_id_and_imported_wins() {
        let mut v = Vault::new();
        v.upsert(sample());
        let mut incoming = sample();
        incoming.host = "198.51.100.9".into();

        let s = v.import_records(vec![incoming]);
        assert_eq!(
            s,
            ImportSummary {
                added: 0,
                replaced: 1
            }
        );
        assert_eq!(v.list().len(), 1);
        assert_eq!(v.get("srv1").unwrap().host, "198.51.100.9");
    }

    /// `get` matches id OR label, but `upsert` replaces by id only. A label collision must
    /// therefore count as *added* and leave both records in place — counting it as "replaced"
    /// would report something the vault did not do.
    #[test]
    fn import_records_label_collision_counts_as_added() {
        let mut v = Vault::new();
        v.upsert(sample()); // id: srv1, label: my-vps
        let mut incoming = sample();
        incoming.id = "srv2".into();
        incoming.label = "my-vps".into(); // same label, different server

        let s = v.import_records(vec![incoming]);
        assert_eq!(
            s,
            ImportSummary {
                added: 1,
                replaced: 0
            }
        );
        assert_eq!(
            v.list().len(),
            2,
            "both records must survive a label collision"
        );
    }

    #[test]
    fn import_records_counts_a_mixed_batch() {
        let mut v = Vault::new();
        v.upsert(sample());
        let mut fresh = sample();
        fresh.id = "srv2".into();

        let s = v.import_records(vec![sample(), fresh]);
        assert_eq!(
            s,
            ImportSummary {
                added: 1,
                replaced: 1
            }
        );
        assert_eq!(v.list().len(), 2);
    }
}
