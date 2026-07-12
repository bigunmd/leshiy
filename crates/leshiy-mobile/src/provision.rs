//! UniFFI wrapper for remote server provisioning (single-role) over SSH.
//!
//! Reuses `leshiy_provision::engine::provision` (russh + Docker-over-SSH) unchanged; this layer
//! only maps a flat config to `ProvisionParams`, forwards progress, and returns the issued URI.
use crate::error::BridgeError;
use leshiy_provision::RusshTransport;
use leshiy_provision::engine::{self, ProgressEvent, ProvisionParams, ProvisionRole, Status, Step};
use leshiy_provision::ssh::SshTarget;
use leshiy_provision::vault::SshSecret;
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProvisionConfig {
    pub host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    /// SSH password auth. Used when `ssh_private_key` is empty/None.
    pub ssh_password: Option<String>,
    /// SSH private key (PEM). Takes precedence over the password when present.
    pub ssh_private_key: Option<String>,
    /// Passphrase protecting `ssh_private_key`, if any.
    pub ssh_key_passphrase: Option<String>,
    pub dest: String,
    pub listen_port: u16,
    pub label: Option<String>,
    pub sudo_password: Option<String>,
    /// Enable QUIC on this UDP port (advanced). None = TCP-only REALITY.
    pub quic_port: Option<u16>,
    /// Container image override. None = the release matching this build.
    pub image_ref: Option<String>,
    /// Label for the first (self) client. None = "self".
    pub user_label: Option<String>,
    /// Force the container's DNS resolver (`--dns`). None = host detection + public fallback.
    pub dns_override: Option<String>,
    /// Chain role: `single` (default) | `entry` | `middle` | `exit`.
    pub role: String,
    /// Downstream server id (local vault ref), stored on the record for the chain view.
    /// None for single/exit or an external (pasted) downstream.
    pub downstream: Option<String>,
    /// The downstream's connector `leshiy://` URI to wire in (entry/middle only).
    pub connector: Option<String>,
}

/// A single progress line pushed to the UI as provisioning advances.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProvisionUpdate {
    pub step: String,
    pub status: String,
    pub detail: String,
}

#[uniffi::export(callback_interface)]
pub trait ProvisionListener: Send + Sync {
    fn on_update(&self, update: ProvisionUpdate);
}

fn step_str(s: Step) -> String {
    format!("{s:?}")
}
fn status_str(s: Status) -> String {
    format!("{s:?}")
}

/// True when the private key in `pem` needs a passphrase to decode (it's encrypted, or
/// unreadable as-is). Lets the Deploy UI prompt for the key passphrase only when required.
#[uniffi::export]
pub fn key_needs_passphrase(pem: String) -> bool {
    leshiy_provision::ssh::key_needs_passphrase(&pem)
}

/// Pick SSH auth: a private key (with optional passphrase) if present, else a password.
fn ssh_secret(cfg: &ProvisionConfig) -> SshSecret {
    match cfg
        .ssh_private_key
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        Some(pem) => SshSecret::PrivateKey {
            pem: Zeroizing::new(pem.clone()),
            passphrase: cfg
                .ssh_key_passphrase
                .clone()
                .filter(|s| !s.is_empty())
                .map(Zeroizing::new),
        },
        None => SshSecret::Password(Zeroizing::new(cfg.ssh_password.clone().unwrap_or_default())),
    }
}

/// Parse a role string into `ProvisionRole` (mirrors the CLI). `single` is explicit;
/// anything unknown is an error.
pub fn parse_role(s: &str) -> Result<ProvisionRole, BridgeError> {
    match s {
        "single" => Ok(ProvisionRole::Single),
        "entry" => Ok(ProvisionRole::Entry),
        "middle" => Ok(ProvisionRole::Middle),
        "exit" => Ok(ProvisionRole::Exit),
        other => Err(BridgeError::Provision {
            reason: format!("unknown role {other:?} (expected single|entry|middle|exit)"),
        }),
    }
}

/// Map the flat config to engine params (CLI-matching defaults). Pure + testable.
pub fn build_params(cfg: &ProvisionConfig, now: u64) -> ProvisionParams {
    let label = cfg.label.clone().unwrap_or_else(|| cfg.host.clone());
    // Unknown roles fall back to Single; the app only ever sends validated roles.
    let role = parse_role(cfg.role.trim()).unwrap_or(ProvisionRole::Single);
    // Exit/middle nodes must expose a QUIC connector; default it to the listen port.
    let quic_port = if matches!(role, ProvisionRole::Exit | ProvisionRole::Middle) {
        cfg.quic_port.or(Some(cfg.listen_port))
    } else {
        cfg.quic_port
    };
    ProvisionParams {
        id: format!("{}-{}", cfg.host, cfg.ssh_port),
        label,
        target: SshTarget {
            host: cfg.host.clone(),
            port: cfg.ssh_port,
            user: cfg.ssh_user.clone(),
        },
        secret: ssh_secret(cfg),
        public_host: format!("{}:{}", cfg.host, cfg.listen_port),
        dest_sni: cfg.dest.clone(),
        image_ref: cfg
            .image_ref
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                concat!("ghcr.io/bigunmd/leshiy:v", env!("CARGO_PKG_VERSION")).to_string()
            }),
        container: "leshiy".into(),
        quic_port,
        listen_port: cfg.listen_port,
        user_label: cfg
            .user_label
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "self".into()),
        now,
        role,
        connector: cfg.connector.clone(),
        downstream: cfg.downstream.clone(),
        sudo: cfg.sudo_password.is_some(),
        dns_override: cfg.dns_override.clone().filter(|s| !s.trim().is_empty()),
    }
}

/// Stateless provisioning entry point.
#[derive(uniffi::Object)]
pub struct Provisioner;

#[uniffi::export]
impl Provisioner {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    /// Provision the target and return the issued client `leshiy://` URI.
    ///
    /// Blocking: it owns a tokio runtime and drives the async engine to completion. Call it off
    /// the UI thread (Kotlin: `Dispatchers.IO`). This avoids UniFFI's `Send`-future requirement,
    /// which the engine's `&mut dyn FnMut` progress callback can't satisfy.
    pub fn provision(
        &self,
        cfg: ProvisionConfig,
        listener: Box<dyn ProvisionListener>,
    ) -> Result<String, BridgeError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| BridgeError::Provision {
                reason: format!("runtime: {e}"),
            })?;
        let rec = rt.block_on(provision_record(&cfg, &*listener))?;
        rec.clients
            .first()
            .map(|c| c.uri.clone())
            .ok_or(BridgeError::Provision {
                reason: "no client issued".into(),
            })
    }
}

/// Provision core: dial + run the engine, forwarding progress. Returns the full `ServerRecord`
/// so callers can persist it (management) or extract just the URI. Shared by `Provisioner` and
/// `ServerManager`.
pub(crate) async fn provision_record(
    cfg: &ProvisionConfig,
    listener: &dyn ProvisionListener,
) -> Result<leshiy_provision::vault::ServerRecord, BridgeError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let params = build_params(cfg, now);
    let mut transport = RusshTransport::new();
    if let Some(pw) = &cfg.sudo_password {
        transport.set_sudo_password(Some(Zeroizing::new(pw.clone())));
    }
    let mut on_event = |e: ProgressEvent| {
        listener.on_update(ProvisionUpdate {
            step: step_str(e.step),
            status: status_str(e.status),
            detail: e.detail,
        });
    };
    engine::provision(&mut transport, &params, &mut on_event)
        .await
        .map_err(|e| BridgeError::Provision {
            reason: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ProvisionConfig {
        ProvisionConfig {
            host: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            ssh_password: Some("pw".into()),
            ssh_private_key: None,
            ssh_key_passphrase: None,
            dest: "www.microsoft.com:443".into(),
            listen_port: 443,
            label: None,
            sudo_password: None,
            quic_port: None,
            image_ref: None,
            user_label: None,
            dns_override: None,
            role: "single".into(),
            downstream: None,
            connector: None,
        }
    }

    #[test]
    fn parse_role_maps_and_rejects() {
        assert_eq!(parse_role("single").unwrap(), ProvisionRole::Single);
        assert_eq!(parse_role("entry").unwrap(), ProvisionRole::Entry);
        assert_eq!(parse_role("middle").unwrap(), ProvisionRole::Middle);
        assert_eq!(parse_role("exit").unwrap(), ProvisionRole::Exit);
        assert!(parse_role("bogus").is_err());
    }

    #[test]
    fn exit_middle_auto_enable_quic() {
        let mut c = cfg();
        c.role = "exit".into();
        assert_eq!(build_params(&c, 1).quic_port, Some(c.listen_port));
        let mut m = cfg();
        m.role = "middle".into();
        m.quic_port = Some(9000);
        assert_eq!(build_params(&m, 1).quic_port, Some(9000));
    }

    #[test]
    fn entry_carries_connector_and_downstream() {
        let mut c = cfg();
        c.role = "entry".into();
        c.connector = Some("leshiy://conn".into());
        c.downstream = Some("berlin".into());
        let p = build_params(&c, 1);
        assert_eq!(p.role, ProvisionRole::Entry);
        assert_eq!(p.connector.as_deref(), Some("leshiy://conn"));
        assert_eq!(p.downstream.as_deref(), Some("berlin"));
        assert_eq!(p.quic_port, None);
    }

    #[test]
    fn single_stays_unchained() {
        let p = build_params(&cfg(), 1);
        assert_eq!(p.role, ProvisionRole::Single);
        assert!(p.connector.is_none() && p.downstream.is_none());
    }

    #[test]
    fn key_auth_selected_when_pem_present() {
        let mut c = cfg();
        c.ssh_private_key = Some("-----BEGIN OPENSSH PRIVATE KEY-----".into());
        assert!(matches!(
            super::ssh_secret(&c),
            leshiy_provision::vault::SshSecret::PrivateKey { .. }
        ));
    }

    #[test]
    fn password_auth_when_no_key() {
        assert!(matches!(
            super::ssh_secret(&cfg()),
            leshiy_provision::vault::SshSecret::Password(_)
        ));
    }

    #[test]
    fn build_params_defaults_single_role() {
        let p = build_params(&cfg(), 100);
        assert_eq!(p.target.host, "1.2.3.4");
        assert_eq!(p.target.port, 22);
        assert_eq!(p.listen_port, 443);
        assert_eq!(p.public_host, "1.2.3.4:443");
        assert_eq!(p.container, "leshiy");
        assert_eq!(p.role, ProvisionRole::Single);
        assert_eq!(p.user_label, "self");
        assert!(p.connector.is_none());
        assert!(!p.sudo);
    }

    #[test]
    fn label_defaults_to_host() {
        let p = build_params(&cfg(), 100);
        assert_eq!(p.label, "1.2.3.4");
    }

    #[test]
    fn sudo_flag_follows_password() {
        let mut c = cfg();
        c.sudo_password = Some("s".into());
        assert!(build_params(&c, 100).sudo);
    }
}
