//! `leshiy remote` — drive leshiy-provision from the CLI.

use anyhow::{Context, Result};
use leshiy_provision::engine::{
    self, ProgressEvent, ProvisionParams, ProvisionRole, RemoteUser, Status, Step,
};
use leshiy_provision::ssh::{RusshTransport, SshTarget, Transport};
use leshiy_provision::vault::{ClientConfig, ServerRecord, SshSecret, Vault};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn vault_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("leshiy").join("servers.lvault")
}

pub fn prompt_passphrase_with(prompt: &str, confirm: bool) -> Result<zeroize::Zeroizing<String>> {
    let pass =
        zeroize::Zeroizing::new(rpassword::prompt_password(prompt).context("read passphrase")?);
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")
            .context("read confirm passphrase")?;
        anyhow::ensure!(*pass == again, "passphrases do not match");
    }
    Ok(pass)
}

pub fn prompt_passphrase(confirm: bool) -> Result<zeroize::Zeroizing<String>> {
    prompt_passphrase_with("Vault passphrase: ", confirm)
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
        Step::Firewall => "firewall",
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
    // Sudo-provisioned servers need the sudo password for every privileged
    // command; prompt for it here so all day-2 ops (user add/rm, status,
    // teardown) work. The password is used for this session only, never stored.
    if rec.sudo {
        let pw = rpassword::prompt_password("sudo password: ")?;
        transport.set_sudo_password(Some(Zeroizing::new(pw)));
    }
    Ok(transport)
}

/// Pair each server user with its local label (if known). Users present on the
/// server but absent from the vault get `None` (orphans).
pub fn annotate_users(
    remote: &[RemoteUser],
    clients: &[ClientConfig],
) -> Vec<(String, Option<String>, bool)> {
    remote
        .iter()
        .map(|u| {
            let label = clients
                .iter()
                .find(|c| c.short_id == u.short_id)
                .map(|c| c.label.clone());
            (u.short_id.clone(), label, u.enabled)
        })
        .collect()
}

/// Validate a user-supplied listen port (rejects 0).
pub fn resolve_listen_port(port: u16) -> Result<u16> {
    anyhow::ensure!(port != 0, "port must be between 1 and 65535");
    Ok(port)
}

pub fn parse_role(s: &str) -> Result<ProvisionRole> {
    match s {
        "single" => Ok(ProvisionRole::Single),
        "exit" => Ok(ProvisionRole::Exit),
        "middle" => Ok(ProvisionRole::Middle),
        "entry" => Ok(ProvisionRole::Entry),
        other => anyhow::bail!("unknown role {other:?} (expected single|exit|middle|entry)"),
    }
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
                crate::ui::eline(&crate::ui::field(
                    "role",
                    &crate::ui::value(if r.role.is_empty() { "single" } else { &r.role }),
                ));
                if let Some(ds) = &r.downstream {
                    crate::ui::eline(&crate::ui::field("downstream", &crate::ui::value(ds)));
                }
                crate::ui::eline(&crate::ui::field("host", &crate::ui::value(&r.public_host)));
                crate::ui::eline(&crate::ui::field("clients", &r.clients.len().to_string()));
            }
            Ok(())
        }
        RemoteCmd::Provision {
            host,
            key,
            password_stdin,
            sudo,
            sudo_password_stdin,
            dest,
            dns,
            quic,
            port: cli_port,
            image,
            label,
            user_label,
            role,
            downstream,
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

            // --sudo-password-stdin implies --sudo. Gather the sudo password now
            // (stdin read, if any, happens before other prompts).
            let use_sudo = sudo || sudo_password_stdin;
            let sudo_password: Option<Zeroizing<String>> = if use_sudo {
                if sudo_password_stdin {
                    let mut line = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut line)?;
                    Some(Zeroizing::new(
                        line.trim_end_matches(['\n', '\r']).to_string(),
                    ))
                } else {
                    Some(Zeroizing::new(rpassword::prompt_password(
                        "sudo password: ",
                    )?))
                }
            } else {
                None
            };

            let listen_port = resolve_listen_port(cli_port)?;
            let id = format!("{h}-{port}");
            let label = label.unwrap_or_else(|| h.clone());
            let public_host = format!("{h}:{listen_port}");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Parse and validate the role string.
            let role = parse_role(&role)?;

            // Hoist passphrase prompt + vault load here — single prompt for both downstream
            // lookup (entry/middle) and the final persist after provisioning.
            let pass = prompt_passphrase(true)?;
            let mut vault =
                Vault::load(&vault_path(), &pass).map_err(|e| anyhow::anyhow!("{e}"))?;

            // exit/middle expose a QUIC carrier; default it to the listen port if unset.
            let quic = match role {
                ProvisionRole::Exit | ProvisionRole::Middle => Some(quic.unwrap_or(listen_port)),
                _ => quic,
            };

            // entry/middle must select a downstream with a connector credential.
            let (connector, downstream_id) = match role {
                ProvisionRole::Entry | ProvisionRole::Middle => {
                    let ds = downstream.ok_or_else(|| {
                        anyhow::anyhow!("--role {} requires --downstream <server>", role.as_str())
                    })?;
                    let rec = vault
                        .get(&ds)
                        .ok_or_else(|| anyhow::anyhow!("no server {ds}"))?;
                    let cred = rec.connector_uri.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "server {ds} has no connector credential \
                             (provision it as --role exit or middle)"
                        )
                    })?;
                    (Some(cred), Some(rec.id.clone()))
                }
                _ => (None, None),
            };

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
                listen_port,
                user_label,
                now,
                role,
                connector,
                downstream: downstream_id,
                sudo: use_sudo,
                dns_override: dns,
            };

            let mut transport = RusshTransport::new();
            transport.set_sudo_password(sudo_password);
            let rec = engine::provision(&mut transport, &params, &mut |e| render_progress(&e))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Persist into the vault (reuse the already-loaded vault and pass).
            vault.upsert(rec.clone());
            vault
                .save(&vault_path(), &pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Role-aware presentation.
            match role {
                ProvisionRole::Exit | ProvisionRole::Middle => {
                    if let Some(cred) = rec.connector_uri.clone() {
                        crate::ui::ok(&format!("server {id} provisioned as {}", role.as_str()));
                        crate::ui::eline(&crate::ui::heading(
                            "connector credential — pass as --downstream when provisioning the next hop:",
                        ));
                        println!("{cred}"); // stdout: the connector credential
                    }
                }
                _ => {
                    if let Some(first) = rec.clients.first() {
                        let uri = first.uri.clone();
                        crate::ui::ok(&format!("server {id} provisioned"));
                        render_client(&uri);
                    }
                }
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
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
                    let mut transport = connect_pinned(&rec).await?;
                    let users = leshiy_provision::engine::list_users(&mut transport, &rec)
                        .await
                        .context("list users on server")?;
                    let rows = annotate_users(&users, &rec.clients);
                    if rows.is_empty() {
                        crate::ui::eline("(no users on server)");
                    }
                    for (short_id, label, enabled) in rows {
                        let label = label.unwrap_or_else(|| "(not in vault)".into());
                        let state = if enabled { "enabled" } else { "disabled" };
                        crate::ui::eline(&crate::ui::field(
                            &label,
                            &format!("{} {}", crate::ui::id(&short_id), state),
                        ));
                        println!("{short_id}");
                    }
                    Ok(())
                }
                RemoteUserCmd::Rm { server, short_id } => {
                    let mut rec = vault
                        .get(&server)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
                    let mut transport = connect_pinned(&rec).await?;
                    leshiy_provision::engine::delete_user(&mut transport, &mut rec, &short_id)
                        .await
                        .context("delete user on server")?;
                    vault.upsert(rec);
                    vault.save(&vault_path(), &pass).context("save vault")?;
                    crate::ui::ok(&format!("deleted user {short_id} on {server}"));
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
            let share = prompt_passphrase_with("Backup share passphrase: ", true)?;
            let blob = vault
                .export_one(&server, connection_only, &share)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            std::fs::write(&out, &blob).with_context(|| format!("write {out}"))?;
            crate::ui::ok(&format!("backup written to {out}"));
            Ok(())
        }
        RemoteCmd::Restore { file } => {
            let blob = std::fs::read(&file).with_context(|| format!("read {file}"))?;
            let share = zeroize::Zeroizing::new(
                rpassword::prompt_password("Backup passphrase: ")
                    .context("read backup passphrase")?,
            );
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
    fn resolve_listen_port_rejects_zero() {
        assert_eq!(resolve_listen_port(443).unwrap(), 443);
        assert_eq!(resolve_listen_port(8443).unwrap(), 8443);
        assert!(resolve_listen_port(0).is_err());
    }

    #[test]
    fn parse_role_maps_known_roles() {
        use leshiy_provision::engine::ProvisionRole;
        assert_eq!(parse_role("single").unwrap(), ProvisionRole::Single);
        assert_eq!(parse_role("exit").unwrap(), ProvisionRole::Exit);
        assert_eq!(parse_role("middle").unwrap(), ProvisionRole::Middle);
        assert_eq!(parse_role("entry").unwrap(), ProvisionRole::Entry);
        assert!(parse_role("bogus").is_err());
    }

    #[test]
    fn annotate_users_matches_labels_and_flags_orphans() {
        use leshiy_provision::engine::RemoteUser;
        use leshiy_provision::vault::ClientConfig;
        let remote = vec![
            RemoteUser {
                short_id: "01".into(),
                enabled: true,
                expires_at: None,
                data_cap: None,
                used_up: 0,
                used_down: 0,
            },
            RemoteUser {
                short_id: "02".into(),
                enabled: false,
                expires_at: None,
                data_cap: None,
                used_up: 0,
                used_down: 0,
            },
        ];
        let clients = vec![ClientConfig {
            short_id: "01".into(),
            label: "phone".into(),
            uri: "u".into(),
        }];
        let rows = annotate_users(&remote, &clients);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("01".into(), Some("phone".into()), true));
        assert_eq!(rows[1], ("02".into(), None, false)); // on server, not in vault
    }

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
            role: "single".into(),
            connector_uri: None,
            downstream: None,
            sudo: false,
        });
        let blob = v.export_one("s1", false, "share").unwrap();
        let recs = leshiy_provision::vault::open(&blob, "share").unwrap();
        assert_eq!(recs[0].id, "s1");
        assert!(leshiy_provision::vault::open(&blob, "wrong-passphrase").is_err());
    }
}
