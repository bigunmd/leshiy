//! `leshiy remote` — drive leshiy-provision from the CLI.

use anyhow::{Context, Result};
use leshiy_provision::engine::{self, ProgressEvent, ProvisionParams, Status, Step};
use leshiy_provision::ssh::{RusshTransport, SshTarget};
use leshiy_provision::vault::{SshSecret, Vault};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn vault_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("leshiy").join("servers.lvault")
}

pub fn prompt_passphrase(confirm: bool) -> Result<String> {
    let pass = rpassword::prompt_password("Vault passphrase: ").context("read passphrase")?;
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")
            .context("read confirm passphrase")?;
        anyhow::ensure!(pass == again, "passphrases do not match");
    }
    Ok(pass)
}

pub fn parse_ssh_host(spec: &str) -> Result<(String, String, u16)> {
    let (user, rest) = spec
        .split_once('@')
        .context("--host must be user@host[:port]")?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("bad port")?),
        None => (rest.to_string(), 22u16),
    };
    anyhow::ensure!(!user.is_empty() && !host.is_empty(), "empty user or host");
    Ok((user.to_string(), host, port))
}

fn step_name(s: Step) -> &'static str {
    match s {
        Step::Connect => "connect",
        Step::Preflight => "preflight",
        Step::DockerReady => "docker",
        Step::DetectExisting => "detect",
        Step::PullImage => "pull",
        Step::RunContainer => "run",
        Step::IssueUser => "issue-user",
        Step::Persist => "persist",
    }
}

fn render_progress(e: &ProgressEvent) {
    let mark = match e.status {
        Status::Started => "…",
        Status::Done => "✓",
        Status::Failed => "✗",
    };
    crate::ui::eline(&format!("{mark} {} {}", step_name(e.step), e.detail));
}

/// URI to stdout (copy/pipe), QR + summary to stderr (decoration).
fn render_client(uri: &str) {
    println!("{uri}");
    crate::ui::eline(&crate::quickstart::qr_for_stdout(uri));
    crate::ui::eline(&crate::ui::field("config", &crate::ui::url(uri)));
}

pub async fn run(cmd: crate::cli::RemoteCmd) -> Result<()> {
    use crate::cli::RemoteCmd;
    match cmd {
        RemoteCmd::Ls => {
            let pass = prompt_passphrase(false)?;
            let vault = Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
            for r in vault.list() {
                println!("{}", r.id);
                crate::ui::eline(&crate::ui::field("label", &crate::ui::value(&r.label)));
                crate::ui::eline(&crate::ui::field("host", &crate::ui::value(&r.public_host)));
                crate::ui::eline(&crate::ui::field("clients", &r.clients.len().to_string()));
            }
            Ok(())
        }
        RemoteCmd::Provision {
            host,
            key,
            password_stdin,
            dest,
            quic,
            image,
            label,
            user_label,
        } => {
            let (user, h, port) = parse_ssh_host(&host)?;
            let secret = if let Some(keypath) = key {
                let pem = std::fs::read_to_string(&keypath)
                    .with_context(|| format!("read key {keypath}"))?;
                SshSecret::PrivateKey {
                    pem: Zeroizing::new(pem),
                    passphrase: None,
                }
            } else if password_stdin {
                let mut line = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut line)?;
                SshSecret::Password(Zeroizing::new(line.trim_end().to_string()))
            } else {
                SshSecret::Password(Zeroizing::new(rpassword::prompt_password(
                    "SSH password: ",
                )?))
            };

            let id = format!("{h}-{port}");
            let label = label.unwrap_or_else(|| h.clone());
            let reality_port: u16 = dest
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(443);
            let public_host = format!("{h}:{reality_port}");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let params = ProvisionParams {
                id: id.clone(),
                label,
                target: SshTarget {
                    host: h,
                    port,
                    user,
                },
                secret,
                public_host,
                dest_sni: dest,
                image_ref: image,
                container: "leshiy".into(),
                quic_port: quic,
                reality_port,
                user_label,
                now,
            };

            let mut transport = RusshTransport::new();
            let rec = engine::provision(&mut transport, &params, &mut |e| render_progress(&e))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Persist into the vault.
            let pass = prompt_passphrase(true)?;
            let mut vault =
                Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
            if let Some(first) = rec.clients.first() {
                let uri = first.uri.clone();
                vault.upsert(rec);
                vault
                    .save(&vault_path(), &pass)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                crate::ui::ok(&format!("server {id} provisioned"));
                render_client(&uri);
            }
            Ok(())
        }
        _ => anyhow::bail!("not yet implemented"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_path_ends_with_expected_file() {
        let p = vault_path();
        assert!(p.ends_with("leshiy/servers.lvault"));
    }

    #[test]
    fn parse_ssh_host_variants() {
        assert_eq!(
            parse_ssh_host("root@1.2.3.4").unwrap(),
            ("root".into(), "1.2.3.4".into(), 22)
        );
        assert_eq!(
            parse_ssh_host("root@1.2.3.4:2222").unwrap(),
            ("root".into(), "1.2.3.4".into(), 2222)
        );
        assert!(parse_ssh_host("no-at-sign").is_err());
    }
}
