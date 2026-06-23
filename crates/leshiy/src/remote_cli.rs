//! `leshiy remote` — drive leshiy-provision from the CLI.

use anyhow::{Context, Result};
use leshiy_provision::engine::{self, ProgressEvent, ProvisionParams, Status, Step};
use leshiy_provision::ssh::{RusshTransport, SshTarget, Transport};
use leshiy_provision::vault::{ServerRecord, SshSecret, Vault};
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

/// Connect and verify the returned host-key fingerprint against the pinned value
/// stored in `rec.host_key_fp`. Returns an error if the fingerprint does not match
/// (possible MITM) or if the connection itself fails.
async fn connect_pinned(rec: &ServerRecord) -> Result<RusshTransport> {
    let mut transport = RusshTransport::new();
    let fp = transport
        .connect(
            &SshTarget {
                host: rec.host.clone(),
                port: rec.port,
                user: rec.ssh_user.clone(),
            },
            &rec.ssh_secret,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    anyhow::ensure!(
        fp == rec.host_key_fp,
        "host key mismatch for {}: pinned {}, got {} — refusing to continue (possible MITM)",
        rec.host,
        rec.host_key_fp,
        fp
    );
    Ok(transport)
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
                let line = Zeroizing::new(line);
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
        RemoteCmd::User { cmd } => {
            use crate::cli::RemoteUserCmd;
            let pass = prompt_passphrase(false)?;
            let mut vault =
                Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
            match cmd {
                RemoteUserCmd::Add { server, label } => {
                    let mut rec = vault
                        .get(&server)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
                    let mut transport = connect_pinned(&rec).await?;
                    let cc = engine::add_user(&mut transport, &mut rec, &label, "")
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    vault.upsert(rec);
                    vault
                        .save(&vault_path(), &pass)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    render_client(&cc.uri);
                    Ok(())
                }
                RemoteUserCmd::Ls { server } => {
                    let rec = vault
                        .get(&server)
                        .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
                    for c in &rec.clients {
                        crate::ui::eline(&crate::ui::field(&c.label, &crate::ui::id(&c.short_id)));
                        println!("{}", c.uri);
                    }
                    Ok(())
                }
            }
        }
        RemoteCmd::Status { server } => {
            let pass = prompt_passphrase(false)?;
            let vault = Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
            let rec = vault
                .get(&server)
                .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
            let mut transport = connect_pinned(rec).await?;
            let up = engine::status(&mut transport, rec)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            crate::ui::eline(&crate::ui::field("running", &up.to_string()));
            Ok(())
        }
        RemoteCmd::Backup {
            server,
            connection_only,
            out,
        } => {
            let pass = prompt_passphrase(false)?;
            let vault = Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
            let share = prompt_passphrase(true)?;
            let blob = vault
                .export_one(&server, connection_only, &share)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            std::fs::write(&out, &blob).with_context(|| format!("write {out}"))?;
            crate::ui::ok(&format!("backup written to {out}"));
            Ok(())
        }
        RemoteCmd::Restore { file } => {
            let blob = std::fs::read(&file).with_context(|| format!("read {file}"))?;
            let share = rpassword::prompt_password("Backup passphrase: ")?;
            let recs =
                leshiy_provision::vault::open(&blob, &share).map_err(|e| anyhow::anyhow!("{e}"))?;
            let pass = prompt_passphrase(false)?;
            let mut vault =
                Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
            for r in recs {
                crate::ui::ok(&format!("restored {}", r.id));
                vault.upsert(r);
            }
            vault
                .save(&vault_path(), &pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(())
        }
        RemoteCmd::Teardown { server, purge } => {
            let pass = prompt_passphrase(false)?;
            let mut vault =
                Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
            let rec = vault
                .get(&server)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
            let mut transport = connect_pinned(&rec).await?;
            engine::teardown(&mut transport, &rec, purge)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            vault.remove(&server);
            vault
                .save(&vault_path(), &pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            crate::ui::ok(&format!("server {server} torn down"));
            Ok(())
        }
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

    #[test]
    fn backup_then_restore_round_trips_via_vault() {
        // Pure vault round-trip exercising the export/import the CLI arms use.
        use leshiy_provision::vault::{ClientConfig, ServerRecord, SshSecret, Vault};
        let mut v = Vault::new();
        v.upsert(ServerRecord {
            id: "s1".into(),
            label: "v".into(),
            host: "h".into(),
            port: 22,
            ssh_user: "root".into(),
            ssh_secret: SshSecret::Password("p".to_string().into()),
            host_key_fp: "fp".into(),
            public_host: "h:443".into(),
            image_ref: "img".into(),
            container: "leshiy".into(),
            reality_public_b64: "x".into(),
            quic: None,
            clients: vec![ClientConfig {
                short_id: "01".into(),
                label: "self".into(),
                uri: "leshiy://x@h:443?sid=01".into(),
            }],
            created_at: 0,
        });
        let blob = v.export_one("s1", false, "share").unwrap();
        let recs = leshiy_provision::vault::open(&blob, "share").unwrap();
        assert_eq!(recs[0].id, "s1");
    }
}
