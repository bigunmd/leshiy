//! UniFFI-exposed day-2 server management, backed by the encrypted vault.
//!
//! Every op loads a `ServerRecord` from the vault, connects with the stored SSH secret (host key
//! pinned — MITM-checked, as the CLI's `connect_pinned`), runs the engine op, and persists the
//! mutated record. The SSH secret never crosses the FFI boundary; it lives only in the vault.
use crate::error::BridgeError;
use crate::provision::{
    ProvisionConfig, ProvisionListener, ProvisionUpdate, provision_record, resolve_image_ref,
    status_str, step_str,
};
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
    /// Chain role: `single` | `entry` | `middle` | `exit`.
    pub role: String,
    /// Downstream server id (next hop toward the internet), for the chain view.
    pub downstream: Option<String>,
    /// True when this node exposes a connector credential (exit/middle) usable as a downstream.
    pub has_connector: bool,
    /// The image ref currently running, so the UI can show `current → target` and whether an
    /// upgrade would change anything.
    pub image_ref: String,
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

/// What an [`ServerManager::import_backup`] merge did, so the UI can say so.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportReport {
    pub added: u32,
    pub replaced: u32,
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

/// Push one progress line the engine doesn't emit (it starts at PullImage; persistence is ours).
fn emit(listener: &dyn ProvisionListener, step: &str, status: &str, detail: &str) {
    listener.on_update(ProvisionUpdate {
        step: step.to_string(),
        status: status.to_string(),
        detail: detail.to_string(),
    });
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
                role: r.role.clone(),
                downstream: r.downstream.clone(),
                has_connector: r.connector_uri.is_some(),
                image_ref: r.image_ref.clone(),
            })
            .collect()
    }

    /// A saved node's connector credential (exit/middle), for wiring an upstream to it.
    pub fn connector_uri(&self, id: String) -> Option<String> {
        self.vault
            .lock()
            .unwrap()
            .get(&id)
            .and_then(|r| r.connector_uri.clone())
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

    /// Pull a new image and recreate the container. Users, keys and client URIs survive — they
    /// live on the data volume, which only `teardown(purge: true)` removes. Returns the image
    /// ref now running.
    ///
    /// This is not the same as re-provisioning: `engine::provision` reuses an already-running
    /// container by design, so it reports every step Done and changes nothing. Upgrade is the
    /// only route to a new image *or* to new container run-flags.
    pub fn upgrade(
        &self,
        server_id: String,
        image_ref: Option<String>,
        sudo_password: Option<String>,
        listener: Box<dyn ProvisionListener>,
    ) -> Result<String, BridgeError> {
        let mut rec = self.record(&server_id)?;
        let image = resolve_image_ref(image_ref.as_deref());
        let rt = Self::rt()?;
        rt.block_on(async {
            emit(&*listener, "Connect", "Started", &rec.host);
            let mut t = Self::connect(&rec, sudo_password).await?;
            emit(&*listener, "Connect", "Done", "");
            engine::upgrade(&mut t, &mut rec, &image, |e| {
                listener.on_update(ProvisionUpdate {
                    step: step_str(e.step),
                    status: status_str(e.status),
                    detail: e.detail.clone(),
                });
            })
            .await
            .map_err(err)
        })?;
        // Only reached when the new container is actually up: `engine::upgrade` leaves the record
        // untouched on failure, so the vault can never name a version that isn't running.
        emit(&*listener, "Persist", "Started", "");
        self.persist(rec)?;
        emit(&*listener, "Persist", "Done", "");
        Ok(image)
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

    /// Seal every saved record under `backup_passphrase` — the whole-vault backup form, returned
    /// for the caller to write (Android hands it to the Storage Access Framework, whose
    /// `content://` URIs are not paths Rust could open).
    ///
    /// The passphrase is deliberately independent of the device vault passphrase, so the two can
    /// be rotated separately. The returned blob is ciphertext: this does not breach the
    /// no-cleartext-secrets-over-FFI contract this module opens with.
    pub fn export_backup(&self, backup_passphrase: String) -> Result<Vec<u8>, BridgeError> {
        let pass = Zeroizing::new(backup_passphrase);
        self.vault.lock().unwrap().export_all(&pass).map_err(err)
    }

    /// Decrypt a backup blob under `backup_passphrase` and merge it into the vault, persisting
    /// under the device passphrase. Records with a matching id are replaced.
    ///
    /// Decryption comes first, so a wrong passphrase or a corrupt file leaves the vault untouched.
    pub fn import_backup(
        &self,
        blob: Vec<u8>,
        backup_passphrase: String,
    ) -> Result<ImportReport, BridgeError> {
        let pass = Zeroizing::new(backup_passphrase);
        let recs = leshiy_provision::vault::open(&blob, &pass).map_err(err)?;
        let mut v = self.vault.lock().unwrap();
        let summary = v.import_records(recs);
        v.save(&self.path, &self.passphrase).map_err(err)?;
        Ok(ImportReport {
            added: summary.added as u32,
            replaced: summary.replaced as u32,
        })
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
    fn servers_expose_role_and_connector() {
        let path = tmp();
        let mut v = Vault::new();
        let mut exit = rec("berlin");
        exit.role = "exit".into();
        exit.connector_uri = Some("leshiy://conn".into());
        let mut entry = rec("riga");
        entry.role = "entry".into();
        entry.downstream = Some("berlin".into());
        v.upsert(exit);
        v.upsert(entry);
        v.save(std::path::Path::new(&path), "pass").unwrap();

        let sm = ServerManager::open(path, "pass".into()).unwrap();
        let by_id: std::collections::HashMap<_, _> = sm
            .servers()
            .into_iter()
            .map(|s| (s.id.clone(), s))
            .collect();
        assert_eq!(by_id["berlin"].role, "exit");
        assert!(by_id["berlin"].has_connector);
        assert_eq!(by_id["riga"].role, "entry");
        assert_eq!(by_id["riga"].downstream.as_deref(), Some("berlin"));
        assert!(!by_id["riga"].has_connector);
        assert_eq!(
            sm.connector_uri("berlin".into()).as_deref(),
            Some("leshiy://conn")
        );
        assert_eq!(sm.connector_uri("riga".into()), None);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let path = tmp();
        let mut v = Vault::new();
        v.upsert(rec("berlin"));
        v.save(std::path::Path::new(&path), "right").unwrap();
        assert!(ServerManager::open(path, "wrong".into()).is_err());
    }

    #[test]
    fn servers_expose_the_running_image_ref() {
        let path = tmp();
        let mut v = Vault::new();
        v.upsert(rec("berlin")); // rec() sets image_ref: "img"
        v.save(std::path::Path::new(&path), "pass").unwrap();

        let sm = ServerManager::open(path, "pass".into()).unwrap();
        assert_eq!(sm.servers()[0].image_ref, "img");
    }

    struct NullListener;
    impl ProvisionListener for NullListener {
        fn on_update(&self, _update: ProvisionUpdate) {}
    }

    /// The record lookup must come first: an unknown id is a local error, and dialling SSH to
    /// discover that would be both slow and wrong.
    #[test]
    fn upgrade_an_unknown_server_fails_before_it_dials_anything() {
        let sm = ServerManager::open(tmp(), "pass".into()).unwrap();
        let e = sm
            .upgrade("nope".into(), None, None, Box::new(NullListener))
            .unwrap_err();
        assert!(matches!(e, BridgeError::NoSuchProfile));
    }

    /// Seed a record straight into the vault and persist it — the manager's own write path.
    /// Provisioning for real would need a live SSH host.
    fn seed(sm: &ServerManager, id: &str) {
        let mut v = sm.vault.lock().unwrap();
        v.upsert(rec(id));
        v.save(&sm.path, &sm.passphrase).unwrap();
    }

    #[test]
    fn backup_round_trips_onto_a_fresh_device() {
        let sm = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        seed(&sm, "berlin");
        let blob = sm.export_backup("backup-pw".into()).unwrap();

        // A new phone: its own vault, its own passphrase, empty.
        let fresh = ServerManager::open(tmp(), "other-device-pw".into()).unwrap();
        assert!(fresh.servers().is_empty());

        let report = fresh.import_backup(blob, "backup-pw".into()).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(report.replaced, 0);
        assert_eq!(fresh.servers()[0].id, "berlin");
    }

    /// The backup passphrase and the device passphrase are independent: import must decrypt with
    /// the former and persist with the latter.
    #[test]
    fn imported_records_persist_under_the_device_passphrase() {
        let src = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        seed(&src, "berlin");
        let blob = src.export_backup("backup-pw".into()).unwrap();

        let path = tmp();
        let sm = ServerManager::open(path.clone(), "new-device".into()).unwrap();
        sm.import_backup(blob, "backup-pw".into()).unwrap();

        let reopened = ServerManager::open(path, "new-device".into()).unwrap();
        assert_eq!(reopened.servers().len(), 1);
        assert_eq!(reopened.servers()[0].id, "berlin");
    }

    #[test]
    fn import_backup_wrong_passphrase_fails_and_changes_nothing() {
        let src = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        seed(&src, "berlin");
        let blob = src.export_backup("right".into()).unwrap();

        let sm = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        assert!(sm.import_backup(blob, "wrong".into()).is_err());
        assert!(
            sm.servers().is_empty(),
            "a failed import must not mutate the vault"
        );
    }

    #[test]
    fn import_backup_rejects_a_file_that_is_not_a_vault() {
        let sm = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        assert!(
            sm.import_backup(b"definitely not a vault".to_vec(), "pw".into())
                .is_err()
        );
    }

    /// Phone → CLI: `leshiy remote restore` reads the file and calls the bare
    /// `vault::open` (`remote_cli.rs`), *not* `import_backup`. An export must therefore open with
    /// that function alone, or the interop claim is only true of our own round trip.
    #[test]
    fn an_export_opens_with_the_bare_vault_fn_that_cli_restore_uses() {
        let sm = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        seed(&sm, "berlin");
        let blob = sm.export_backup("backup-pw".into()).unwrap();

        let recs = leshiy_provision::vault::open(&blob, "backup-pw").unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, "berlin");
    }

    /// CLI → phone: `leshiy remote backup --out f` writes `export_one`'s output — a sealed
    /// one-element array. Import must take it unchanged.
    #[test]
    fn imports_a_blob_produced_by_the_cli_remote_backup() {
        let mut cli_vault = Vault::new();
        cli_vault.upsert(rec("berlin"));
        let blob = cli_vault.export_one("berlin", false, "share-pw").unwrap();

        let sm = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        let report = sm.import_backup(blob, "share-pw".into()).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(sm.servers()[0].id, "berlin");
    }

    #[test]
    fn importing_a_known_id_reports_replaced() {
        let src = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        seed(&src, "berlin");
        let blob = src.export_backup("backup-pw".into()).unwrap();

        let sm = ServerManager::open(tmp(), "device-pw".into()).unwrap();
        seed(&sm, "berlin"); // same id already present
        let report = sm.import_backup(blob, "backup-pw".into()).unwrap();
        assert_eq!(report.added, 0);
        assert_eq!(report.replaced, 1);
    }
}
