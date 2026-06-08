//! REALITY server CLI: init (keygen + config + URI) and run.
use crate::reality_config::RealityServerConfig;
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use leshiy_reality::config::format_reality_uri;
use leshiy_reality::control::{UriIssuer, serve_control};
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::server::run_reality_server;
use leshiy_reality::sqlite_store::SqliteUserStore;
use leshiy_reality::user::{InMemoryUserStore, User, UserAdmin, UserStore};
use rand::RngCore;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub fn init(host: &str, dest: &str, listen: Option<&str>, out: &str) -> Result<()> {
    // server static x25519 keypair (raw bytes zeroized on drop)
    let mut sk_bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *sk_bytes);
    let sk = StaticSecret::from(*sk_bytes);
    let pk = PublicKey::from(&sk).to_bytes();
    // random short_id
    let mut short_id = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut short_id);
    // sni/server_names = the dest hostname
    let sni = dest
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(dest)
        .to_string();
    let port = host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(443);
    let listen = listen
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("0.0.0.0:{port}"));

    // Provision the sqlite user DB in the same directory as the config file.
    let out_path = Path::new(out);
    let out_dir = out_path.parent().unwrap_or(Path::new("."));
    let db_path = out_dir.join("leshiy-users.db");
    let db_path_str = db_path.to_string_lossy().into_owned();

    // Open the DB, upsert the first user (unlimited), and flush to disk.
    {
        let store = SqliteUserStore::open(&db_path)
            .with_context(|| format!("create user DB at {db_path_str}"))?;
        store.upsert(User {
            short_id,
            enabled: true,
            expires_at: None,
            data_cap: None,
            rate_up: None,
            rate_down: None,
        });
        store
            .flush_now()
            .with_context(|| format!("flush user DB at {db_path_str}"))?;
    }
    // Restrict the DB file to owner-only (0600) — consistent with the config file.
    // The DB holds short_ids + usage counters, not private keys, but 0600 is defence-in-depth.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
    }

    let cfg = RealityServerConfig {
        listen,
        dest: dest.to_string(),
        server_names: vec![sni.clone()],
        static_private_key_b64: URL_SAFE_NO_PAD.encode(*sk_bytes),
        short_ids: vec![], // DB is the registry; short_ids unused when user_db is set.
        max_time_diff_secs: 120,
        host: host.to_string(),
        control_socket: None,
        user_db: Some(db_path_str),
    };
    write_secret_file(out, &toml::to_string_pretty(&cfg)?)?;
    println!("REALITY server config written to {out}");
    println!("Share this URI with clients:");
    println!("{}", format_reality_uri(&pk, host, &sni, &short_id));
    Ok(())
}

/// Write a config containing the static key with owner-only perms (0600).
/// Uses `create_new` so it never clobbers an existing server identity.
fn write_secret_file(path: &str, contents: &str) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("create {path} (refusing to overwrite)"))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("write {path}"))?;
    Ok(())
}

/// Compute the default control socket path: `<config_dir>/leshiy.sock`.
pub(crate) fn default_sock_path(config: &str) -> String {
    let p = Path::new(config);
    let dir = p.parent().unwrap_or(Path::new("."));
    dir.join("leshiy.sock").to_string_lossy().into_owned()
}

/// Derive the x25519 public key bytes from the auth config's static secret.
fn pubkey_bytes(auth: &leshiy_reality::config::ServerAuthConfig) -> [u8; 32] {
    let sk = StaticSecret::from(*auth.static_secret);
    PublicKey::from(&sk).to_bytes()
}

pub async fn run(config: &str) -> Result<()> {
    let toml_str = std::fs::read_to_string(config).with_context(|| format!("read {config}"))?;
    let cfg: RealityServerConfig = toml::from_str(&toml_str).context("parse config")?;
    let auth = Arc::new(cfg.to_auth_config()?);

    // Build the user store. When user_db is configured, open the sqlite store and spawn
    // a background flusher (sqlite off the tokio runtime via spawn_blocking). Otherwise,
    // fall back to the M1.5b in-memory store seeded from short_ids (back-compat).
    let (user_store, admin_store): (Arc<dyn UserStore>, Arc<dyn UserAdmin>) = if let Some(
        ref db_path,
    ) = cfg.user_db
    {
        let store = Arc::new(
            SqliteUserStore::open(Path::new(db_path))
                .with_context(|| format!("open user DB at {db_path}"))?,
        );
        // Background flusher: persist in-memory usage counters every 10 s.
        // Uses spawn_blocking so sqlite I/O never blocks a tokio worker thread.
        {
            let s = store.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                loop {
                    tick.tick().await;
                    let flusher = s.clone();
                    match tokio::task::spawn_blocking(move || flusher.flush_now()).await {
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "usage flush failed; will retry next tick")
                        }
                        Err(e) => tracing::warn!(error = %e, "usage flush task panicked"),
                        Ok(Ok(())) => {}
                    }
                }
            });
        }
        (store.clone(), store)
    } else {
        let store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::from_short_ids(
            auth.short_ids.iter().copied(),
        ));
        (store.clone(), store)
    };

    let cert = Arc::new(ServerCert::generate());
    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;

    // Spawn the control socket alongside the REALITY server.
    let sock_path = cfg
        .control_socket
        .clone()
        .unwrap_or_else(|| default_sock_path(config));
    let server_public = pubkey_bytes(&auth);
    let issuer = UriIssuer {
        server_public,
        host: cfg.host.clone(),
    };
    {
        let sp = sock_path.clone();
        tokio::spawn(async move {
            let _ = serve_control(Path::new(&sp), admin_store, issuer).await;
        });
    }

    tracing::info!(listen = %cfg.listen, dest = %cfg.dest, sock = %sock_path, "leshiy REALITY server up");

    run_reality_server(listener, auth, user_store, cert)
        .await
        .map_err(|e| anyhow::anyhow!("server: {e}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn secret_file_is_owner_only_and_no_clobber() {
        let p = std::env::temp_dir().join(format!("leshiy-sec-{}.toml", std::process::id()));
        let ps = p.to_str().unwrap();
        let _ = std::fs::remove_file(&p);

        write_secret_file(ps, "key=secret").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");

        // create_new must refuse to overwrite an existing identity file
        assert!(write_secret_file(ps, "key=other").is_err());

        std::fs::remove_file(&p).unwrap();
    }
}
