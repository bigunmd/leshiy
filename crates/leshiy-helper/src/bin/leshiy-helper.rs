//! `leshiy-helper`: the privileged VPN control daemon. Owns the TUN/route/DNS lifecycle
//! and serves an authenticated newline-JSON control socket. Run as root or with
//! `CAP_NET_ADMIN`; the unprivileged caller (`leshiy vpn`, or the GUI) drives it.
//!
//! Subcommands: `run` (default — serve the control socket), `install` / `uninstall`
//! (privileged self-install: grant `cap_net_admin+ep` on this binary or write+enable the
//! systemd unit, create `/run/leshiy`). The GUI elevates into `install`/`uninstall`.
use anyhow::{Context, Result};
use clap::Parser;
use leshiy_helper::{EngineRunner, default_socket_path, serve_control};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

/// Leading subcommand. `run` is the default (no subcommand = serve, as today).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sub {
    Run,
    Install,
    Uninstall,
}

/// Classify the first CLI token. Only the exact words `install`/`uninstall`/`run` are
/// subcommands; anything else (a flag like `--socket`, or nothing) means `run`.
fn parse_subcommand(first: Option<&str>) -> Sub {
    match first {
        Some("install") => Sub::Install,
        Some("uninstall") => Sub::Uninstall,
        _ => Sub::Run,
    }
}

/// Flags for the `run` subcommand. Parsed by clap from args *after* an optional `run`.
#[derive(Parser)]
#[command(name = "leshiy-helper", about = "Leshiy privileged VPN helper daemon")]
struct RunArgs {
    /// Control socket path. Created 0o660 (owner root, group e.g. `leshiy`).
    #[arg(long, default_value = "/run/leshiy/helper.sock")]
    socket: PathBuf,
    /// uid permitted to drive the helper (SO_PEERCRED). Defaults to the launching uid.
    #[arg(long)]
    allow_uid: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "leshiy_helper=info".into()),
        )
        .init();

    let raw: Vec<String> = std::env::args().collect();
    match parse_subcommand(raw.get(1).map(String::as_str)) {
        Sub::Install => return install(),
        Sub::Uninstall => return uninstall(),
        Sub::Run => {}
    }

    // `run`: parse the run flags, skipping an explicit leading `run` token if present.
    let run_args: Vec<String> = if raw.get(1).map(String::as_str) == Some("run") {
        std::iter::once(raw[0].clone())
            .chain(raw.into_iter().skip(2))
            .collect()
    } else {
        raw
    };
    let args = RunArgs::parse_from(run_args);
    let allow_uid = args
        .allow_uid
        .unwrap_or_else(|| nix::unistd::getuid().as_raw());

    if let Some(parent) = args.socket.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create socket dir {}", parent.display()))?;
    }

    let runner = Arc::new(EngineRunner::new());
    tracing::info!(socket = %args.socket.display(), allow_uid, "leshiy-helper listening");
    serve_control(&args.socket, runner, allow_uid)
        .await
        .context("control server")?;
    Ok(())
}

/// Privileged self-install. Idempotent. Grants `cap_net_admin+ep` on this binary so an
/// unprivileged caller can drive a VPN, and creates the socket's runtime directory.
/// (Alternatively writes+enables the systemd unit — see scripts/leshiy-helper.service.)
fn install() -> Result<()> {
    let exe = std::env::current_exe().context("locate own binary")?;

    // Runtime dir for the control socket: /run/leshiy, group `leshiy`, mode 0750.
    let sock_dir = default_socket_path()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/leshiy"));
    std::fs::create_dir_all(&sock_dir).with_context(|| format!("create {}", sock_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o750))
            .with_context(|| format!("chmod 0750 {}", sock_dir.display()))?;
    }
    // Best-effort group ownership (no-op if the `leshiy` group does not exist).
    let _ = Command::new("chgrp").arg("leshiy").arg(&sock_dir).status();

    // Grant the file capability on our own binary (the no-systemd path).
    let status = Command::new("setcap")
        .arg("cap_net_admin+ep")
        .arg(&exe)
        .status()
        .context("run setcap (need root)")?;
    if !status.success() {
        anyhow::bail!("setcap cap_net_admin+ep {} failed", exe.display());
    }

    println!(
        "installed: setcap cap_net_admin+ep {}; runtime dir {} (group leshiy, 0750)",
        exe.display(),
        sock_dir.display()
    );
    println!(
        "(systemd alternative: install scripts/leshiy-helper.service and \
         `systemctl enable --now leshiy-helper@$(id -u)`)"
    );
    Ok(())
}

/// Reverse `install`: drop the file capability and remove the stale control socket.
fn uninstall() -> Result<()> {
    let exe = std::env::current_exe().context("locate own binary")?;
    let _ = Command::new("setcap").arg("-r").arg(&exe).status();
    let _ = std::fs::remove_file(default_socket_path());
    println!(
        "uninstalled: setcap -r {}; removed {}",
        exe.display(),
        default_socket_path().display()
    );
    println!(
        "(if installed via systemd: `systemctl disable --now leshiy-helper@$(id -u)` and \
         remove /etc/systemd/system/leshiy-helper.service)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subcommand_maps_keywords_and_defaults_to_run() {
        assert_eq!(parse_subcommand(Some("install")), Sub::Install);
        assert_eq!(parse_subcommand(Some("uninstall")), Sub::Uninstall);
        assert_eq!(parse_subcommand(Some("run")), Sub::Run);
        // No subcommand → run (preserves today's behavior).
        assert_eq!(parse_subcommand(None), Sub::Run);
        // An unknown leading token is treated as a `run` flag, not a subcommand.
        assert_eq!(parse_subcommand(Some("--socket")), Sub::Run);
    }
}
