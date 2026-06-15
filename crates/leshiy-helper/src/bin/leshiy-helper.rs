//! `leshiy-helper`: the privileged VPN control daemon. Owns the TUN/route/DNS lifecycle and
//! serves an authenticated newline-JSON control channel. Launched with privilege:
//! root/`CAP_NET_ADMIN` on Linux/macOS, UAC-elevated on Windows.
//!
//! Subcommands: `run` (serve the control channel — works on all OSes; `--ephemeral` exits
//! after one session for the on-demand GUI model); `install`/`uninstall` (Linux-only:
//! `setcap`/systemd). On macOS/Windows the GUI launches `run --ephemeral` on demand, so no
//! install step is needed.
use anyhow::{Context, Result};
use clap::Parser;
use leshiy_helper::{Auth, Endpoint, EngineRunner, ServeMode, default_socket_path, serve_control};
use std::sync::Arc;

/// Leading subcommand. `run` is the default (no subcommand = serve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sub {
    Run,
    Install,
    Uninstall,
}

/// Classify the first CLI token. Only `install`/`uninstall`/`run` are subcommands; anything
/// else (a flag, or nothing) means `run`.
fn parse_subcommand(first: Option<&str>) -> Sub {
    match first {
        Some("install") => Sub::Install,
        Some("uninstall") => Sub::Uninstall,
        _ => Sub::Run,
    }
}

/// Flags for `run`, parsed after an optional leading `run` token.
#[derive(Parser)]
#[command(name = "leshiy-helper", about = "Leshiy privileged VPN helper daemon")]
struct RunArgs {
    /// Unix: control socket path (default: the canonical per-OS path).
    #[arg(long)]
    socket: Option<std::path::PathBuf>,
    /// Windows: named pipe name (default: \\.\pipe\leshiy-helper).
    #[arg(long)]
    pipe: Option<String>,
    /// Unix: uid permitted to drive the helper (peer-uid auth). Defaults to the launching uid.
    #[arg(long)]
    allow_uid: Option<u32>,
    /// Windows: user SID permitted to drive the helper (pipe DACL). Required on Windows.
    #[arg(long)]
    allow_sid: Option<String>,
    /// Serve one session then exit (the on-demand GUI model). Default: persistent (daemon).
    #[arg(long)]
    ephemeral: bool,
    /// Unix: confirm that granting control to uid 0 (root-only) is intentional.
    /// Required when `--allow-uid 0` so it can't happen by accident. (M6)
    #[arg(long)]
    allow_root: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let raw: Vec<String> = std::env::args().collect();
    match parse_subcommand(raw.get(1).map(String::as_str)) {
        Sub::Install => return install(),
        Sub::Uninstall => return uninstall(),
        Sub::Run => {}
    }

    let run_args: Vec<String> = if raw.get(1).map(String::as_str) == Some("run") {
        std::iter::once(raw[0].clone())
            .chain(raw.into_iter().skip(2))
            .collect()
    } else {
        raw
    };
    let args = RunArgs::parse_from(run_args);
    let mode = if args.ephemeral {
        ServeMode::Ephemeral
    } else {
        ServeMode::Persistent
    };
    let (endpoint, auth) = resolve(&args, mode)?;

    let runner = Arc::new(EngineRunner::new());
    tracing::info!(?mode, "leshiy-helper listening");
    let result = serve_control(&endpoint, runner, auth, mode).await;

    // The ephemeral helper must actually terminate when the session ends. Returning from `main`
    // can hang on tokio-runtime / Wintun reader-thread teardown (the helper would linger in
    // Task Manager and block the next connect). Force an immediate, clean process exit instead.
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            tracing::error!("control server: {e}");
            std::process::exit(1);
        }
    }
}

/// Initialise tracing. The elevated helper runs with no visible console (especially on Windows,
/// where it's launched `-WindowStyle Hidden`), so its logs are otherwise invisible. Write them to
/// `<temp>/leshiy-helper.log` (append) so connect/disconnect issues are diagnosable, and also mirror
/// to stderr when a console is attached. Falls back to stderr-only if the log file can't be opened.
fn init_tracing() {
    let directives = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "leshiy_helper=info,leshiy_tun=info,leshiy_client=info,leshiy_reality=info".into()
    });
    let log_path = std::env::temp_dir().join("leshiy-helper.log");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(file) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(&directives))
                .with_ansi(false)
                // A fresh handle per event (cheap fd dup) — append mode keeps lines ordered.
                .with_writer(move || file.try_clone().expect("clone log file handle"))
                .init();
            tracing::info!(log = %log_path.display(), "leshiy-helper log file");
        }
        Err(_) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(&directives))
                .init();
        }
    }
}

/// Resolve the run flags into an endpoint + authorization, per OS.
#[cfg(unix)]
fn resolve(args: &RunArgs, mode: ServeMode) -> Result<(Endpoint, Auth)> {
    let path = args.socket.clone().unwrap_or_else(default_socket_path);
    // M6: the long-lived daemon must NOT silently default the allowed uid to the
    // launching uid — an operator widening socket perms to "fix" connectivity is
    // a foot-gun. Require an explicit --allow-uid in persistent mode.
    let uid = match args.allow_uid {
        Some(u) => u,
        None => {
            if matches!(mode, ServeMode::Persistent) {
                anyhow::bail!(
                    "--allow-uid is required in persistent mode (the uid permitted to drive the helper)"
                );
            }
            nix::unistd::getuid().as_raw()
        }
    };
    // M6: granting control to uid 0 means "root only"; require explicit confirmation
    // so it can't be selected by accident.
    if uid == 0 && !args.allow_root {
        anyhow::bail!(
            "--allow-uid 0 grants control to root only; pass --allow-root to confirm this is intended"
        );
    }
    Ok((Endpoint::Socket(path), Auth { uid, sid: None }))
}

#[cfg(windows)]
fn resolve(args: &RunArgs, _mode: ServeMode) -> Result<(Endpoint, Auth)> {
    let name = args
        .pipe
        .clone()
        .unwrap_or_else(|| default_socket_path().to_string_lossy().into_owned());
    let sid = args
        .allow_sid
        .clone()
        .context("--allow-sid is required on Windows (the user SID the pipe grants access to)")?;
    Ok((
        Endpoint::Pipe(name),
        Auth {
            uid: 0,
            sid: Some(sid),
        },
    ))
}

/// Privileged self-install (Linux only): grant `cap_net_admin+ep` on this binary + create the
/// runtime dir. macOS/Windows use the on-demand model (the GUI launches `run --ephemeral`).
#[cfg(target_os = "linux")]
fn install() -> Result<()> {
    use std::path::PathBuf;
    use std::process::Command;
    let exe = std::env::current_exe().context("locate own binary")?;
    let sock_dir = default_socket_path()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/leshiy"));
    std::fs::create_dir_all(&sock_dir).with_context(|| format!("create {}", sock_dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o750))
        .with_context(|| format!("chmod 0750 {}", sock_dir.display()))?;
    let _ = Command::new("chgrp").arg("leshiy").arg(&sock_dir).status();
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
        "(systemd alternative: scripts/leshiy-helper.service + `systemctl enable --now leshiy-helper@$(id -u)`)"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install() -> Result<()> {
    println!(
        "install is not required on this platform — the GUI launches leshiy-helper on demand \
         (run --ephemeral, elevated via UAC / osascript)."
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall() -> Result<()> {
    use std::process::Command;
    let exe = std::env::current_exe().context("locate own binary")?;
    let _ = Command::new("setcap").arg("-r").arg(&exe).status();
    let _ = std::fs::remove_file(default_socket_path());
    println!(
        "uninstalled: setcap -r {}; removed {}",
        exe.display(),
        default_socket_path().display()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn uninstall() -> Result<()> {
    println!("uninstall is a no-op on this platform (on-demand model installs nothing).");
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
        assert_eq!(parse_subcommand(None), Sub::Run);
        assert_eq!(parse_subcommand(Some("--socket")), Sub::Run);
    }

    #[cfg(unix)]
    fn args(extra: &[&str]) -> RunArgs {
        let mut v = vec!["leshiy-helper"];
        v.extend_from_slice(extra);
        RunArgs::parse_from(v)
    }

    #[cfg(unix)]
    #[test]
    fn persistent_requires_explicit_allow_uid() {
        // No --allow-uid in persistent mode is a foot-gun (silent getuid default). (M6)
        assert!(resolve(&args(&[]), ServeMode::Persistent).is_err());
        let (_, auth) = resolve(&args(&["--allow-uid", "1000"]), ServeMode::Persistent).unwrap();
        assert_eq!(auth.uid, 1000);
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_defaults_allow_uid() {
        // Ephemeral may default to the launching uid (the on-demand GUI passes it explicitly).
        assert!(resolve(&args(&[]), ServeMode::Ephemeral).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn uid_zero_requires_allow_root() {
        assert!(resolve(&args(&["--allow-uid", "0"]), ServeMode::Persistent).is_err());
        let (_, auth) = resolve(
            &args(&["--allow-uid", "0", "--allow-root"]),
            ServeMode::Persistent,
        )
        .unwrap();
        assert_eq!(auth.uid, 0);
    }
}
