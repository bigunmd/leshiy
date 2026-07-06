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
    pub ssh_password: String,
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

/// Map the flat config to engine params (single-role, CLI-matching defaults). Pure + testable.
pub fn build_params(cfg: &ProvisionConfig, now: u64) -> ProvisionParams {
    let label = cfg.label.clone().unwrap_or_else(|| cfg.host.clone());
    ProvisionParams {
        id: format!("{}-{}", cfg.host, cfg.ssh_port),
        label,
        target: SshTarget {
            host: cfg.host.clone(),
            port: cfg.ssh_port,
            user: cfg.ssh_user.clone(),
        },
        secret: SshSecret::Password(Zeroizing::new(cfg.ssh_password.clone())),
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
        quic_port: cfg.quic_port,
        listen_port: cfg.listen_port,
        user_label: cfg
            .user_label
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "self".into()),
        now,
        role: ProvisionRole::Single,
        connector: None,
        downstream: None,
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
            ssh_password: "pw".into(),
            dest: "www.microsoft.com:443".into(),
            listen_port: 443,
            label: None,
            sudo_password: None,
            quic_port: None,
            image_ref: None,
            user_label: None,
            dns_override: None,
        }
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
