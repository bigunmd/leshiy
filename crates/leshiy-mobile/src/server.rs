//! UniFFI-exposed day-2 server management, backed by the encrypted vault.
//!
//! Every op loads a `ServerRecord` from the vault, connects with the stored SSH secret (host key
//! pinned — MITM-checked, as the CLI's `connect_pinned`), runs the engine op, and persists the
//! mutated record. The SSH secret never crosses the FFI boundary; it lives only in the vault.
use crate::error::BridgeError;
use crate::provision::{ProvisionConfig, ProvisionListener, provision_record};
use leshiy_provision::RusshTransport;
use leshiy_provision::engine;
use leshiy_provision::ssh::{SshTarget, Transport};
use leshiy_provision::vault::{ServerRecord, Vault};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Debug, Clone, uniffi::Record)]
pub struct ServerInfo {
    pub id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    /// True when this server runs privileged commands via `sudo` (non-root SSH
    /// user). Day-2 ops must supply the sudo password; it's never persisted.
    pub sudo: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RemoteUserInfo {
    pub short_id: String,
    pub label: Option<String>,
    pub enabled: bool,
    /// The client's `leshiy://` URI from the vault, if we issued it (empty for an
    /// orphan credential seen on the server but not in our records). Lets the UI
    /// show a QR / copyable link for re-provisioning a device.
    pub uri: String,
}

/// Vault-backed manager for provisioned servers (one unlocked instance per session).
#[derive(uniffi::Object)]
pub struct ServerManager {
    vault: Mutex<Vault>,
    path: PathBuf,
    passphrase: Zeroizing<String>,
}

fn err(e: impl std::fmt::Display) -> BridgeError {
    BridgeError::Provision {
        reason: e.to_string(),
    }
}

impl ServerManager {
    fn rt() -> Result<tokio::runtime::Runtime, BridgeError> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(err)
    }

    fn record(&self, id: &str) -> Result<ServerRecord, BridgeError> {
        self.vault
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(BridgeError::NoSuchProfile)
    }

    fn persist(&self, rec: ServerRecord) -> Result<(), BridgeError> {
        let mut v = self.vault.lock().unwrap();
        v.upsert(rec);
        v.save(&self.path, &self.passphrase).map_err(err)
    }

    async fn connect(
        rec: &ServerRecord,
        sudo: Option<String>,
    ) -> Result<RusshTransport, BridgeError> {
        let mut t = RusshTransport::new();
        let fp = t
            .connect(
                &SshTarget {
                    host: rec.host.clone(),
                    port: rec.port,
                    user: rec.ssh_user.clone(),
                },
                &rec.ssh_secret,
            )
            .await
            .map_err(err)?;
        if fp != rec.host_key_fp {
            return Err(err(format!(
                "host key mismatch for {} (possible MITM)",
                rec.host
            )));
        }
        if let (true, Some(pw)) = (rec.sudo, sudo) {
            t.set_sudo_password(Some(Zeroizing::new(pw)));
        }
        Ok(t)
    }
}

#[uniffi::export]
impl ServerManager {
    /// Open (or create, if missing) the on-device vault under `passphrase`.
    #[uniffi::constructor]
    pub fn open(vault_path: String, passphrase: String) -> Result<Arc<Self>, BridgeError> {
        let path = PathBuf::from(vault_path);
        let vault = Vault::load(&path, &passphrase).map_err(err)?;
        Ok(Arc::new(Self {
            vault: Mutex::new(vault),
            path,
            passphrase: Zeroizing::new(passphrase),
        }))
    }

    pub fn servers(&self) -> Vec<ServerInfo> {
        self.vault
            .lock()
            .unwrap()
            .list()
            .iter()
            .map(|r| ServerInfo {
                id: r.id.clone(),
                label: r.label.clone(),
                host: r.host.clone(),
                port: r.port,
                sudo: r.sudo,
            })
            .collect()
    }

    /// Provision a server, persist its record to the vault (so it's manageable), return the URI.
    pub fn provision(
        &self,
        cfg: ProvisionConfig,
        listener: Box<dyn ProvisionListener>,
    ) -> Result<String, BridgeError> {
        let rt = Self::rt()?;
        let rec = rt.block_on(provision_record(&cfg, &*listener))?;
        let uri = rec
            .clients
            .first()
            .map(|c| c.uri.clone())
            .ok_or_else(|| err("no client issued"))?;
        self.persist(rec)?;
        Ok(uri)
    }

    /// Issue a new client credential; returns its `leshiy://` URI.
    pub fn add_user(
        &self,
        server_id: String,
        label: String,
        sudo_password: Option<String>,
    ) -> Result<String, BridgeError> {
        let mut rec = self.record(&server_id)?;
        let rt = Self::rt()?;
        let cc = rt.block_on(async {
            let mut t = Self::connect(&rec, sudo_password).await?;
            engine::add_user(&mut t, &mut rec, &label, "")
                .await
                .map_err(err)
        })?;
        self.persist(rec)?;
        Ok(cc.uri)
    }

    pub fn list_users(
        &self,
        server_id: String,
        sudo_password: Option<String>,
    ) -> Result<Vec<RemoteUserInfo>, BridgeError> {
        let rec = self.record(&server_id)?;
        let rt = Self::rt()?;
        let users = rt.block_on(async {
            let mut t = Self::connect(&rec, sudo_password).await?;
            engine::list_users(&mut t, &rec).await.map_err(err)
        })?;
        Ok(users
            .into_iter()
            .map(|u| {
                let client = rec.clients.iter().find(|c| c.short_id == u.short_id);
                RemoteUserInfo {
                    short_id: u.short_id,
                    label: client.map(|c| c.label.clone()),
                    enabled: u.enabled,
                    uri: client.map(|c| c.uri.clone()).unwrap_or_default(),
                }
            })
            .collect())
    }

    pub fn delete_user(
        &self,
        server_id: String,
        short_id: String,
        sudo_password: Option<String>,
    ) -> Result<(), BridgeError> {
        let mut rec = self.record(&server_id)?;
        let rt = Self::rt()?;
        rt.block_on(async {
            let mut t = Self::connect(&rec, sudo_password).await?;
            engine::delete_user(&mut t, &mut rec, &short_id)
                .await
                .map_err(err)
        })?;
        self.persist(rec)
    }

    /// Whether the server's container is currently running.
    pub fn status(
        &self,
        server_id: String,
        sudo_password: Option<String>,
    ) -> Result<bool, BridgeError> {
        let rec = self.record(&server_id)?;
        let rt = Self::rt()?;
        rt.block_on(async {
            let mut t = Self::connect(&rec, sudo_password).await?;
            engine::status(&mut t, &rec).await.map_err(err)
        })
    }

    /// Stop + remove the server (optionally purge its data volume), then drop it from the vault.
    pub fn teardown(
        &self,
        server_id: String,
        purge: bool,
        sudo_password: Option<String>,
    ) -> Result<(), BridgeError> {
        let rec = self.record(&server_id)?;
        let rt = Self::rt()?;
        rt.block_on(async {
            let mut t = Self::connect(&rec, sudo_password).await?;
            engine::teardown(&mut t, &rec, purge).await.map_err(err)
        })?;
        let mut v = self.vault.lock().unwrap();
        v.remove(&server_id);
        v.save(&self.path, &self.passphrase).map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leshiy_provision::vault::SshSecret;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp() -> String {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir()
            .join(format!(
                "leshiy-sm-{}-{}.vault",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn rec(id: &str) -> ServerRecord {
        ServerRecord {
            id: id.into(),
            label: id.into(),
            host: "1.2.3.4".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::Password("pw".to_string().into()),
            host_key_fp: "fp".into(),
            public_host: "1.2.3.4:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "x".into(),
            quic: None,
            clients: vec![],
            created_at: 0,
            role: "single".into(),
            connector_uri: None,
            downstream: None,
            sudo: false,
        }
    }

    #[test]
    fn open_fresh_is_empty() {
        let sm = ServerManager::open(tmp(), "pass".into()).unwrap();
        assert!(sm.servers().is_empty());
    }

    #[test]
    fn round_trips_saved_server() {
        let path = tmp();
        let mut v = Vault::new();
        v.upsert(rec("berlin"));
        v.save(std::path::Path::new(&path), "pass").unwrap();

        let sm = ServerManager::open(path, "pass".into()).unwrap();
        let servers = sm.servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "berlin");
    }

    #[test]
    fn servers_expose_sudo_flag() {
        let path = tmp();
        let mut v = Vault::new();
        let mut r = rec("berlin");
        r.sudo = true;
        v.upsert(r);
        v.upsert(rec("oslo")); // sudo: false
        v.save(std::path::Path::new(&path), "pass").unwrap();

        let sm = ServerManager::open(path, "pass".into()).unwrap();
        let by_id: std::collections::HashMap<_, _> = sm
            .servers()
            .into_iter()
            .map(|s| (s.id.clone(), s))
            .collect();
        assert!(by_id["berlin"].sudo, "sudo server must report sudo=true");
        assert!(!by_id["oslo"].sudo, "root server must report sudo=false");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let path = tmp();
        let mut v = Vault::new();
        v.upsert(rec("berlin"));
        v.save(std::path::Path::new(&path), "right").unwrap();
        assert!(ServerManager::open(path, "wrong".into()).is_err());
    }
}
