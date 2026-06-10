//! REALITY server CLI: init (keygen + config + URI) and run.
use crate::reality_config::RealityServerConfig;
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use leshiy_reality::config::{QuicEndpoint, format_reality_uri_full};
use leshiy_reality::control::{UriIssuer, serve_control};
use leshiy_reality::egress::{DirectEgress, Egress};
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

/// What `init` produced — consumed by `quickstart` and the installer.
pub struct InitOutput {
    pub config_path: String,
    pub uri: String,
    pub listen: String,
    pub quic_listen: Option<String>,
}

/// Options for `server-init`. Bundles all the CLI args into one struct to avoid
/// clippy::too-many-arguments on the `init` function.
pub struct InitOptions<'a> {
    pub host: &'a str,
    pub dest: &'a str,
    pub listen: Option<&'a str>,
    pub out: &'a str,
    pub quic_listen: Option<&'a str>,
    pub quic_domain: Option<&'a str>,
    pub quic_cert: Option<&'a str>,
    pub quic_key: Option<&'a str>,
    /// Optional exit-node `leshiy://` URI (must have a `quic=` endpoint).
    pub connector: Option<&'a str>,
}

pub fn init(opts: InitOptions<'_>) -> Result<InitOutput> {
    let InitOptions {
        host,
        dest,
        listen,
        out,
        quic_listen,
        quic_domain,
        quic_cert,
        quic_key,
        connector,
    } = opts;
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

    // --- Validate --connector URI (must parse and have a quic= endpoint) ---
    if let Some(uri) = connector {
        let u = leshiy_reality::config::RealityUri::parse(uri).context("connector uri")?;
        if u.quic.is_none() {
            return Err(anyhow::anyhow!("--connector uri has no quic= endpoint"));
        }
    }

    // --- Optional QUIC provisioning ---
    let quic_endpoint: Option<QuicEndpoint> = if let Some(ql) = quic_listen {
        // Require cert+key to be provided together; one without the other is a footgun.
        if quic_cert.is_some() != quic_key.is_some() {
            return Err(anyhow::anyhow!(
                "--quic-cert and --quic-key must be provided together"
            ));
        }
        let domain = quic_domain.unwrap_or("cdn.example.com").to_string();
        let (_cert_path_str, _key_path_str, cert_sha256_hex) =
            if let (Some(cp), Some(kp)) = (quic_cert, quic_key) {
                // Operator-provided cert/key: compute the fingerprint from the PEM.
                let cert_pem = std::fs::read(cp).with_context(|| format!("read quic cert {cp}"))?;
                let mut reader = std::io::BufReader::new(cert_pem.as_slice());
                let der = rustls_pemfile::certs(&mut reader)
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no cert in {cp}"))?
                    .with_context(|| format!("parse cert {cp}"))?;
                let fingerprint = leshiy_quic::endpoint::cert_sha256(der.as_ref());
                (cp.to_string(), kp.to_string(), hex::encode(fingerprint))
            } else {
                // Self-signed: generate with rcgen.
                let cert_key = rcgen::generate_simple_self_signed(vec![domain.clone()])
                    .context("generate self-signed QUIC cert")?;
                let cert_pem = cert_key.cert.pem();
                let key_pem = cert_key.key_pair.serialize_pem();
                let cert_path = out_dir.join("leshiy-quic.crt");
                let key_path = out_dir.join("leshiy-quic.key");
                let cert_path_str = cert_path.to_string_lossy().into_owned();
                let key_path_str = key_path.to_string_lossy().into_owned();
                // Write cert (world-readable is fine; it's a public cert).
                std::fs::write(&cert_path, &cert_pem)
                    .with_context(|| format!("write quic cert {cert_path_str}"))?;
                // Write key with 0600 permissions.
                write_secret_file(&key_path_str, &key_pem)?;
                // Compute SHA-256 fingerprint from the DER bytes.
                let fingerprint = leshiy_quic::endpoint::cert_sha256(cert_key.cert.der().as_ref());
                println!("QUIC cert written to {cert_path_str}");
                println!("QUIC key written to {key_path_str}");
                (cert_path_str, key_path_str, hex::encode(fingerprint))
            };
        let fingerprint_bytes = hex::decode(&cert_sha256_hex)
            .ok()
            .and_then(|v| v.as_slice().try_into().ok());
        Some(QuicEndpoint {
            // Advertise the QUIC endpoint on the PUBLIC host, not the bind address (`ql`, which
            // is typically 0.0.0.0 and undialable). The runtime still BINDS `ql`.
            addr: advertised_quic_addr(host, ql),
            sni: domain,
            cert_sha256: fingerprint_bytes,
        })
    } else {
        None
    };

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
        // The BIND address (e.g. 0.0.0.0:443) — what the server listens on at runtime.
        quic_listen: quic_listen.map(|s| s.to_string()),
        quic_cert_path: quic_endpoint.as_ref().and_then(|_| {
            if quic_cert.is_some() {
                quic_cert.map(|s| s.to_string())
            } else {
                // self-signed path: derive from out_dir
                Some(
                    out_path
                        .parent()
                        .unwrap_or(Path::new("."))
                        .join("leshiy-quic.crt")
                        .to_string_lossy()
                        .into_owned(),
                )
            }
        }),
        quic_key_path: quic_endpoint.as_ref().and_then(|_| {
            if quic_key.is_some() {
                quic_key.map(|s| s.to_string())
            } else {
                Some(
                    out_path
                        .parent()
                        .unwrap_or(Path::new("."))
                        .join("leshiy-quic.key")
                        .to_string_lossy()
                        .into_owned(),
                )
            }
        }),
        quic_domain: quic_endpoint.as_ref().map(|q| q.sni.clone()),
        quic_cert_sha256: quic_endpoint
            .as_ref()
            .and_then(|q| q.cert_sha256.as_ref().map(hex::encode)),
        connector: connector.map(|s| s.to_string()),
    };
    let uri = format_reality_uri_full(&pk, host, &sni, &short_id, quic_endpoint.as_ref());
    write_secret_file(out, &toml::to_string_pretty(&cfg)?)?;
    println!("REALITY server config written to {out}");
    println!("Share this URI with clients:");
    println!("{uri}");
    Ok(InitOutput {
        config_path: out.to_string(),
        uri,
        listen: cfg.listen.clone(),
        quic_listen: cfg.quic_listen.clone(),
    })
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

/// Derive the publicly-advertised QUIC endpoint address from the public `host` and the QUIC
/// `bind` address. The bind address is often `0.0.0.0:<port>` (all interfaces), which must NOT
/// be put in a client URI — advertise the public host's IP with the QUIC bind port instead.
fn advertised_quic_addr(host: &str, bind: &str) -> String {
    let host_ip = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let port = bind.rsplit_once(':').map(|(_, p)| p).unwrap_or("443");
    format!("{host_ip}:{port}")
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

    // --- Build the egress (shared by REALITY and QUIC fronts) ---
    let egress: Arc<dyn Egress> = match &cfg.connector {
        Some(uri) => {
            let u = leshiy_reality::config::RealityUri::parse(uri)
                .map_err(|e| anyhow::anyhow!("connector uri: {e}"))?;
            let q = u
                .quic
                .ok_or_else(|| anyhow::anyhow!("connector uri has no quic= endpoint"))?;
            let v = match q.cert_sha256 {
                Some(p) => leshiy_quic::endpoint::CertVerification::Pinned(p),
                None => leshiy_quic::endpoint::CertVerification::Roots,
            };
            let addr = tokio::net::lookup_host(&q.addr)
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("resolve connector addr {}", q.addr))?;
            tracing::info!(exit = %q.addr, "connector enabled");
            Arc::new(
                leshiy_quic::connector::ConnectorEgress::connect(
                    addr,
                    &q.sni,
                    u.client.short_id,
                    v,
                )
                .await
                .context("connect to exit")?,
            ) as Arc<dyn Egress>
        }
        None => Arc::new(DirectEgress),
    };

    // --- Optional QUIC server (shares the SAME UserStore) ---
    let quic_endpoint_cfg: Option<QuicEndpoint> = if let Some(ref ql) = cfg.quic_listen {
        let qaddr: std::net::SocketAddr = ql
            .parse()
            .with_context(|| format!("quic_listen addr: {ql}"))?;
        let cert_path = cfg
            .quic_cert_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("quic_listen set but quic_cert_path missing"))?;
        let key_path = cfg
            .quic_key_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("quic_listen set but quic_key_path missing"))?;

        // Parse PEM cert chain.
        let cert_pem =
            std::fs::read(cert_path).with_context(|| format!("read quic cert {cert_path}"))?;
        let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .with_context(|| format!("parse quic cert PEM {cert_path}"))?;

        // Parse PEM private key.
        let key_pem =
            std::fs::read(key_path).with_context(|| format!("read quic key {key_path}"))?;
        let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
        let key = rustls_pemfile::private_key(&mut key_reader)
            .with_context(|| format!("parse quic key PEM {key_path}"))?
            .ok_or_else(|| anyhow::anyhow!("no private key found in {key_path}"))?;

        let domain = cfg
            .quic_domain
            .clone()
            .unwrap_or_else(|| "cdn.example.com".into());

        // Always derive the pin from the cert we actually loaded, so issued URIs stay
        // consistent even if the operator rotated the cert without updating the config hash.
        let pin = leshiy_quic::endpoint::cert_sha256(certs[0].as_ref());
        // Warn if the operator's config hash is present but doesn't match the real cert.
        if let Some(config_hash) = cfg.quic_cert_sha256.as_deref() {
            let config_bytes: Option<[u8; 32]> = hex::decode(config_hash)
                .ok()
                .and_then(|v| v.as_slice().try_into().ok());
            if config_bytes.as_ref() != Some(&pin) {
                tracing::warn!(
                    "config quic_cert_sha256 does not match the loaded cert; \
                     using the loaded cert's fingerprint"
                );
            }
        }
        let cert_sha256 = Some(pin);

        // Spawn QUIC server with the SAME store and the SAME egress.
        let qstore: Arc<dyn UserStore> = user_store.clone();
        let masq = leshiy_quic::masquerade::Masquerade::default();
        let qegress = egress.clone();
        tokio::spawn(async move {
            if let Err(e) =
                leshiy_quic::server::run_quic_server(qaddr, certs, key, qstore, masq, qegress).await
            {
                tracing::error!(error = %e, "QUIC server exited");
            }
        });
        tracing::info!(quic_listen = %qaddr, "leshiy QUIC server up");

        Some(QuicEndpoint {
            // Advertise on the public host, not the bind address (`ql`, often 0.0.0.0).
            addr: advertised_quic_addr(&cfg.host, ql),
            sni: domain,
            cert_sha256,
        })
    } else {
        None
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
        quic: quic_endpoint_cfg,
    };
    {
        let sp = sock_path.clone();
        tokio::spawn(async move {
            let _ = serve_control(Path::new(&sp), admin_store, issuer).await;
        });
    }

    tracing::info!(listen = %cfg.listen, dest = %cfg.dest, sock = %sock_path, "leshiy REALITY server up");

    run_reality_server(listener, auth, user_store, egress, cert)
        .await
        .map_err(|e| anyhow::anyhow!("server: {e}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn init_returns_uri_and_listen() {
        let dir = std::env::temp_dir().join(format!("leshiy-init-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("server.toml");
        let out_s = out.to_str().unwrap();
        let res = init(InitOptions {
            host: "203.0.113.5:443",
            dest: "www.microsoft.com:443",
            listen: None,
            out: out_s,
            quic_listen: None,
            quic_domain: None,
            quic_cert: None,
            quic_key: None,
            connector: None,
        })
        .unwrap();
        assert!(res.uri.starts_with("leshiy://"));
        assert_eq!(res.listen, "0.0.0.0:443");
        assert!(res.quic_listen.is_none());
        assert_eq!(res.config_path, out_s);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn advertised_quic_addr_uses_public_host_with_bind_port() {
        assert_eq!(
            advertised_quic_addr("203.0.113.5:443", "0.0.0.0:443"),
            "203.0.113.5:443"
        );
        assert_eq!(
            advertised_quic_addr("203.0.113.5:443", "0.0.0.0:8443"),
            "203.0.113.5:8443"
        );
        // IPv6 host literal: rsplit on ':' keeps the bracketed address intact.
        assert_eq!(
            advertised_quic_addr("[2001:db8::1]:443", "0.0.0.0:443"),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn init_advertises_quic_on_public_host_not_bind_addr() {
        let dir = std::env::temp_dir().join(format!("leshiy-quic-adv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("server.toml");
        let out_s = out.to_str().unwrap();
        let res = init(InitOptions {
            host: "203.0.113.5:443",
            dest: "www.microsoft.com:443",
            listen: None,
            out: out_s,
            quic_listen: Some("0.0.0.0:443"),
            quic_domain: None,
            quic_cert: None,
            quic_key: None,
            connector: None,
        })
        .unwrap();
        // The client URI must advertise the PUBLIC host, never the all-interfaces bind addr.
        assert!(
            res.uri.contains("quic=203.0.113.5:443"),
            "uri should advertise public host: {}",
            res.uri
        );
        assert!(
            !res.uri.contains("0.0.0.0"),
            "uri must not leak the bind addr: {}",
            res.uri
        );
        // The written config still BINDS on all interfaces.
        let cfg_txt = std::fs::read_to_string(&out).unwrap();
        assert!(
            cfg_txt.contains("quic_listen = \"0.0.0.0:443\""),
            "config should bind 0.0.0.0: {cfg_txt}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

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
