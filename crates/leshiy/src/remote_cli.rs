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

/// Read a secret from the terminal. Interchangeable with [`crate::wizard::secret`], so a
/// flow can prompt in whichever style `-i` selected without branching at every call site.
fn tty_secret(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password(format!("{prompt}: ")).context("read secret")?,
    ))
}

type SecretPrompt = fn(&str) -> Result<Zeroizing<String>>;

fn secret_prompt(interactive: bool) -> SecretPrompt {
    if interactive {
        crate::wizard::secret
    } else {
        tty_secret
    }
}

/// Slurp stdin for a `--*-stdin` flag. Callers apply their own trimming, which differs
/// per flag: `--password-stdin` strips all trailing whitespace, the others only the line
/// ending, and a password may legitimately end in a space.
fn read_stdin_secret() -> Result<Zeroizing<String>> {
    let mut line = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut line)?;
    Ok(Zeroizing::new(line))
}

/// Unlock the vault, prompting in the style `-i` implies.
///
/// `confirm` applies to the non-interactive path only. Interactively we know whether the
/// file exists, so a passphrase is confirmed exactly when one is being *set* — asking a
/// returning operator to type an existing passphrase twice teaches nothing.
fn open_vault(interactive: bool, confirm: bool) -> Result<(Zeroizing<String>, Vault)> {
    let path = vault_path();
    let pass = if interactive {
        if path.exists() {
            crate::wizard::secret("Vault passphrase")?
        } else {
            crate::ui::hint(&format!(
                "creating a new encrypted vault at {}",
                path.display()
            ));
            crate::wizard::secret_confirmed("New vault passphrase")?
        }
    } else {
        prompt_passphrase(confirm)?
    };
    let vault = Vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((pass, vault))
}

/// The argument a subcommand cannot run without when `-i` is not there to ask for it.
///
/// These were clap-required until `-i` made them `Option`. Checking them up front keeps
/// the old behaviour of failing *before* the vault passphrase prompt: a typo in the argv
/// should not cost the operator a passphrase they then watch get thrown away.
pub fn missing_required_arg(cmd: &crate::cli::RemoteCmd) -> Option<&'static str> {
    use crate::cli::{RemoteCmd as R, RemoteUserCmd as U};
    let server = Some("a server");
    match cmd {
        R::Provision { host: None, .. } => Some("--host"),
        R::Provision { dest: None, .. } => Some("--dest"),
        R::Status { server: None }
        | R::Upgrade { server: None, .. }
        | R::Teardown { server: None, .. }
        | R::Backup { server: None, .. } => server,
        R::Backup { out: None, .. } => Some("--out"),
        R::Restore { file: None } => Some("a backup file"),
        R::User {
            cmd: U::Add { server: None, .. } | U::Ls { server: None } | U::Rm { server: None, .. },
        } => server,
        R::User {
            cmd: U::Rm { short_id: None, .. },
        } => Some("a user short_id"),
        _ => None,
    }
}

/// Resolve the server a day-2 subcommand acts on: the named one, a menu choice under
/// `-i`, or an error that names the escape hatch.
fn pick_server(
    vault: &Vault,
    given: Option<String>,
    interactive: bool,
    prompt: &str,
) -> Result<String> {
    if given.is_none() {
        anyhow::ensure!(
            interactive,
            "a server is required (or pass -i to pick one from your vault)"
        );
    }
    crate::remote_wizard::pick_server(vault, given, prompt)
}

/// Show the flag-only invocation for what the operator just picked from a menu.
fn echo_equivalent(interactive: bool, cmd: &crate::wizard::CommandLine) {
    if interactive {
        crate::ui::eline(&crate::ui::label(&format!(
            "  next time: {}",
            cmd.render(78)
        )));
    }
}

pub fn parse_ssh_host(spec: &str) -> Result<(String, String, u16)> {
    let (user, rest) = spec
        .split_once('@')
        .context("--host must be user@host[:port]")?;
    // Bracket-aware so `user@[2001:db8::1]:22` and bare `user@2001:db8::1` both parse; the host
    // is returned without brackets (used for the SSH dial + re-joined for LESHIY_HOST).
    let (host, port) = match leshiy_reality::addr::split_host_port(rest) {
        (h, Some(p)) => (h.to_string(), p.parse().context("bad port")?),
        (h, None) => (h.to_string(), 22u16),
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

pub async fn run(cmd: crate::cli::RemoteCmd, interactive: bool) -> Result<()> {
    use crate::cli::RemoteCmd;
    if interactive {
        crate::wizard::require_tty()?;
    } else if let Some(what) = missing_required_arg(&cmd) {
        anyhow::bail!("{what} is required — pass it, or add -i to be asked for it");
    }
    match cmd {
        RemoteCmd::Ls => {
            let (_pass, vault) = open_vault(interactive, false)?;
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
            key_passphrase_stdin,
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
            let flags = crate::remote_wizard::ProvisionFlags {
                host,
                key,
                sudo: sudo || sudo_password_stdin,
                dest,
                dns,
                port: cli_port,
                quic,
                image,
                label,
                user_label,
                role,
                downstream,
            };

            // Interactively the vault comes first: the downstream picker reads it, the
            // overwrite check reads it, and a mistyped passphrase should cost nothing but
            // retyping it. Non-interactively the flags are validated first instead, so a
            // bad argv never charges the operator a passphrase before rejecting it.
            let (plan, pass, mut vault) = if interactive {
                let (pass, vault) = open_vault(true, true)?;
                let plan = crate::remote_wizard::plan_interactively(flags, &vault).await?;
                (plan, pass, vault)
            } else {
                let plan = crate::remote_wizard::plan_from_flags(flags)?;
                let (pass, vault) = open_vault(false, true)?;
                (plan, pass, vault)
            };

            let (user, h, port) = parse_ssh_host(&plan.host)?;
            let listen_port = resolve_listen_port(plan.port)?;
            let id = format!("{h}-{port}");
            let ask = secret_prompt(interactive);
            let secret = if let Some(keypath) = plan.key.clone() {
                let pem = Zeroizing::new(
                    std::fs::read_to_string(&keypath)
                        .with_context(|| format!("read key {keypath}"))?,
                );
                // Encrypted keys can't be decoded without their passphrase; prompt
                // (or read stdin) only when the key actually needs one.
                let passphrase = if leshiy_provision::ssh::key_needs_passphrase(&pem) {
                    Some(if key_passphrase_stdin {
                        Zeroizing::new(
                            read_stdin_secret()?
                                .trim_end_matches(['\n', '\r'])
                                .to_string(),
                        )
                    } else {
                        ask("SSH key passphrase")?
                    })
                } else {
                    None
                };
                SshSecret::PrivateKey { pem, passphrase }
            } else if password_stdin {
                SshSecret::Password(Zeroizing::new(read_stdin_secret()?.trim_end().to_string()))
            } else {
                SshSecret::Password(ask("SSH password")?)
            };

            // --sudo-password-stdin implies --sudo. Gather the sudo password now
            // (stdin read, if any, happens before other prompts).
            let use_sudo = plan.sudo;
            let sudo_password: Option<Zeroizing<String>> = if use_sudo {
                if sudo_password_stdin {
                    Some(Zeroizing::new(
                        read_stdin_secret()?
                            .trim_end_matches(['\n', '\r'])
                            .to_string(),
                    ))
                } else {
                    Some(ask("sudo password")?)
                }
            } else {
                None
            };

            let label = plan.label.clone().unwrap_or_else(|| h.clone());
            // Bracket a bare IPv6 host so LESHIY_HOST is a valid `[v6]:port`.
            let public_host = leshiy_reality::addr::join_host_port(&h, listen_port);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Parse and validate the role string.
            let role = parse_role(&plan.role)?;

            // exit/middle expose a QUIC carrier; default it to the listen port if unset.
            let quic = match role {
                ProvisionRole::Exit | ProvisionRole::Middle => {
                    Some(plan.quic.unwrap_or(listen_port))
                }
                _ => plan.quic,
            };

            // entry/middle must select a downstream with a connector credential.
            let (connector, downstream_id) = match role {
                ProvisionRole::Entry | ProvisionRole::Middle => {
                    let ds = plan.downstream.clone().ok_or_else(|| {
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
                dest_sni: plan.dest.clone(),
                image_ref: plan.image.clone(),
                container: "leshiy".into(),
                quic_port: quic,
                listen_port,
                user_label: plan.user_label.clone(),
                now,
                role,
                connector,
                downstream: downstream_id,
                sudo: use_sudo,
                dns_override: plan.dns.clone(),
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
            let (pass, mut vault) = open_vault(interactive, false)?;
            match cmd {
                RemoteUserCmd::Add { server, label } => {
                    let server =
                        pick_server(&vault, server, interactive, "Server to add a client to")?;
                    let label = match label {
                        Some(l) => l,
                        None if interactive => crate::wizard::text(
                            "Label for the new client",
                            Some(crate::cli::DEFAULT_CLIENT_LABEL),
                        )?,
                        None => crate::cli::DEFAULT_CLIENT_LABEL.to_string(),
                    };
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
                    let mut c = crate::wizard::CommandLine::new("leshiy remote user add");
                    c.arg(&server).opt("--label", Some(&label));
                    echo_equivalent(interactive, &c);
                    Ok(())
                }
                RemoteUserCmd::Ls { server } => {
                    let server =
                        pick_server(&vault, server, interactive, "Server to list users on")?;
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
                    let server =
                        pick_server(&vault, server, interactive, "Server to remove a user from")?;
                    let mut rec = vault
                        .get(&server)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
                    let mut transport = connect_pinned(&rec).await?;
                    // Listing first lets `-i` offer the live users by label; without it the
                    // operator would have to know a 16-hex id by heart.
                    let short_id = match short_id {
                        Some(s) => s,
                        None => {
                            anyhow::ensure!(
                                interactive,
                                "a user short_id is required (or pass -i to pick one)"
                            );
                            let users = leshiy_provision::engine::list_users(&mut transport, &rec)
                                .await
                                .context("list users on server")?;
                            crate::remote_wizard::pick_user(
                                &annotate_users(&users, &rec.clients),
                                None,
                            )?
                        }
                    };
                    anyhow::ensure!(
                        !interactive
                            || crate::wizard::confirm(
                                &format!("Delete user {short_id} on {server}?"),
                                false
                            )?,
                        "cancelled"
                    );
                    leshiy_provision::engine::delete_user(&mut transport, &mut rec, &short_id)
                        .await
                        .context("delete user on server")?;
                    vault.upsert(rec);
                    vault.save(&vault_path(), &pass).context("save vault")?;
                    crate::ui::ok(&format!("deleted user {short_id} on {server}"));
                    let mut c = crate::wizard::CommandLine::new("leshiy remote user rm");
                    c.arg(&server).arg(&short_id);
                    echo_equivalent(interactive, &c);
                    Ok(())
                }
            }
        }
        RemoteCmd::Status { server } => {
            let (_pass, vault) = open_vault(interactive, false)?;
            let server = pick_server(&vault, server, interactive, "Server to show status for")?;
            let rec = vault
                .get(&server)
                .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
            let mut transport = connect_pinned(rec).await?;
            let up = engine::status(&mut transport, rec)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            crate::ui::eline(&crate::ui::field("running", &up.to_string()));
            let mut c = crate::wizard::CommandLine::new("leshiy remote status");
            c.arg(&server);
            echo_equivalent(interactive, &c);
            Ok(())
        }
        RemoteCmd::Upgrade {
            server,
            image,
            latest,
        } => {
            // Resolved before the vault passphrase prompt so a network failure doesn't
            // strand the user having already typed it.
            let image = if latest {
                let repo = crate::lifecycle::DEFAULT_REPO;
                let tag = crate::lifecycle::latest_version(repo)?;
                format!("ghcr.io/{repo}:{tag}")
            } else {
                image.unwrap_or_else(|| crate::cli::DEFAULT_IMAGE.to_string())
            };
            let (pass, mut vault) = open_vault(interactive, false)?;
            let server = pick_server(&vault, server, interactive, "Server to upgrade")?;
            let mut rec = vault
                .get(&server)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
            let from = rec.image_ref.clone();
            let mut transport = connect_pinned(&rec).await?;
            engine::upgrade(&mut transport, &mut rec, &image, |e| {
                crate::ui::eline(&crate::ui::field(
                    &format!("{:?}", e.step),
                    &format!("{:?} {}", e.status, e.detail),
                ));
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            // Persist only after the container is actually up — `engine::upgrade` leaves the
            // record alone on failure, so this can't record a version that isn't running.
            vault.upsert(rec);
            vault
                .save(&vault_path(), &pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            crate::ui::ok(&format!("server {server} upgraded: {from} -> {image}"));
            Ok(())
        }
        RemoteCmd::Backup {
            server,
            connection_only,
            out,
        } => {
            let (_pass, vault) = open_vault(interactive, false)?;
            let server = pick_server(&vault, server, interactive, "Server to back up")?;
            // `--connection-only` is a bare flag, so an unset one is indistinguishable from
            // an explicit `false`; only offer the choice when it was not already asserted.
            let connection_only = connection_only
                || (interactive
                    && crate::wizard::confirm(
                        "Strip SSH credentials, so the file is safe to share?",
                        false,
                    )?);
            let out = match out {
                Some(o) => o,
                None if interactive => {
                    crate::wizard::text("Write the backup to", Some(&format!("{server}.lvault")))?
                }
                None => anyhow::bail!("--out is required (or pass -i to be asked for it)"),
            };
            let share = if interactive {
                crate::wizard::secret_confirmed("Passphrase to encrypt the backup with")?
            } else {
                prompt_passphrase_with("Backup share passphrase: ", true)?
            };
            let blob = vault
                .export_one(&server, connection_only, &share)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            std::fs::write(&out, &blob).with_context(|| format!("write {out}"))?;
            crate::ui::ok(&format!("backup written to {out}"));
            let mut c = crate::wizard::CommandLine::new("leshiy remote backup");
            c.arg(&server)
                .flag("--connection-only", connection_only)
                .opt("--out", Some(&out));
            echo_equivalent(interactive, &c);
            Ok(())
        }
        RemoteCmd::Restore { file } => {
            let file = match file {
                Some(f) => f,
                None if interactive => crate::wizard::text("Backup file to restore", None)?,
                None => anyhow::bail!("a backup file is required (or pass -i to be asked for it)"),
            };
            let blob = std::fs::read(&file).with_context(|| format!("read {file}"))?;
            let share = if interactive {
                crate::wizard::secret("Passphrase the backup was encrypted with")?
            } else {
                zeroize::Zeroizing::new(
                    rpassword::prompt_password("Backup passphrase: ")
                        .context("read backup passphrase")?,
                )
            };
            let recs =
                leshiy_provision::vault::open(&blob, &share).map_err(|e| anyhow::anyhow!("{e}"))?;
            let (pass, mut vault) = open_vault(interactive, false)?;
            for r in recs {
                crate::ui::ok(&format!("restored {}", r.id));
                vault.upsert(r);
            }
            vault
                .save(&vault_path(), &pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut c = crate::wizard::CommandLine::new("leshiy remote restore");
            c.arg(&file);
            echo_equivalent(interactive, &c);
            Ok(())
        }
        RemoteCmd::Teardown { server, purge } => {
            let (pass, mut vault) = open_vault(interactive, false)?;
            let server = pick_server(&vault, server, interactive, "Server to tear down")?;
            let rec = vault
                .get(&server)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no server {server}"))?;
            // Same flag-vs-unset problem as `--connection-only`: only offer to escalate to
            // a purge when the operator has not already asked for one.
            let purge = purge
                || (interactive
                    && crate::wizard::confirm(
                        "Also delete its keys and users? This cannot be undone",
                        false,
                    )?);
            if interactive {
                crate::ui::warn(&format!(
                    "this removes the leshiy container from {}{}",
                    rec.public_host,
                    if purge {
                        " and destroys its identity, users and client URIs"
                    } else {
                        ""
                    }
                ));
                anyhow::ensure!(
                    crate::wizard::confirm(&format!("Tear down {server}?"), false)?,
                    "cancelled"
                );
            }
            let mut transport = connect_pinned(&rec).await?;
            engine::teardown(&mut transport, &rec, purge)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            vault.remove(&server);
            vault
                .save(&vault_path(), &pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            crate::ui::ok(&format!("server {server} torn down"));
            let mut c = crate::wizard::CommandLine::new("leshiy remote teardown");
            c.arg(&server).flag("--purge", purge);
            echo_equivalent(interactive, &c);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without `-i`, a missing argument must be caught before the vault passphrase prompt.
    /// These were clap-required before `-i` relaxed them, and regressing this means the
    /// operator types a passphrase only to be told their argv was wrong.
    #[test]
    fn missing_required_args_are_detected_for_every_subcommand() {
        use crate::cli::{Cli, Cmd};
        use clap::Parser;

        let missing_for = |argv: &[&str]| -> Option<&'static str> {
            match Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("{argv:?} must parse, got: {e}"))
                .cmd
            {
                Cmd::Remote { cmd, .. } => missing_required_arg(&cmd),
                _ => panic!("expected Remote"),
            }
        };

        assert_eq!(
            missing_for(&["leshiy", "remote", "provision"]),
            Some("--host")
        );
        assert_eq!(
            missing_for(&["leshiy", "remote", "provision", "--host", "root@h"]),
            Some("--dest")
        );
        for sub in ["status", "upgrade", "teardown"] {
            assert_eq!(missing_for(&["leshiy", "remote", sub]), Some("a server"));
        }
        assert_eq!(
            missing_for(&["leshiy", "remote", "backup"]),
            Some("a server")
        );
        assert_eq!(
            missing_for(&["leshiy", "remote", "backup", "srv"]),
            Some("--out")
        );
        assert_eq!(
            missing_for(&["leshiy", "remote", "restore"]),
            Some("a backup file")
        );
        for sub in ["add", "ls", "rm"] {
            assert_eq!(
                missing_for(&["leshiy", "remote", "user", sub]),
                Some("a server")
            );
        }
        assert_eq!(
            missing_for(&["leshiy", "remote", "user", "rm", "srv"]),
            Some("a user short_id")
        );
    }

    /// The mirror image: a fully specified argv must not be flagged, or the flag-driven
    /// path would refuse to run at all.
    #[test]
    fn fully_specified_invocations_are_never_flagged_as_missing() {
        use crate::cli::{Cli, Cmd};
        use clap::Parser;

        for argv in [
            vec!["leshiy", "remote", "ls"],
            vec![
                "leshiy",
                "remote",
                "provision",
                "--host",
                "root@h",
                "--dest",
                "d:443",
            ],
            vec!["leshiy", "remote", "status", "srv"],
            vec!["leshiy", "remote", "upgrade", "srv"],
            vec!["leshiy", "remote", "teardown", "srv"],
            vec!["leshiy", "remote", "backup", "srv", "--out", "b.lvault"],
            vec!["leshiy", "remote", "restore", "b.lvault"],
            vec!["leshiy", "remote", "user", "add", "srv"],
            vec!["leshiy", "remote", "user", "ls", "srv"],
            vec!["leshiy", "remote", "user", "rm", "srv", "abcd"],
        ] {
            let Cmd::Remote { cmd, .. } = Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{argv:?} must parse, got: {e}"))
                .cmd
            else {
                panic!("expected Remote")
            };
            assert_eq!(
                missing_required_arg(&cmd),
                None,
                "{argv:?} is complete but was flagged as missing an argument"
            );
        }
    }

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
        // IPv6: bracketed (with/without port) and bare — host returned without brackets.
        assert_eq!(
            parse_ssh_host("root@[2001:db8::1]:2222").unwrap(),
            ("root".into(), "2001:db8::1".into(), 2222)
        );
        assert_eq!(
            parse_ssh_host("root@[2001:db8::1]").unwrap(),
            ("root".into(), "2001:db8::1".into(), 22)
        );
        assert_eq!(
            parse_ssh_host("root@2001:db8::1").unwrap(),
            ("root".into(), "2001:db8::1".into(), 22)
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
