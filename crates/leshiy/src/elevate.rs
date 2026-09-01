//! Self-elevation for the subcommands that need `CAP_NET_ADMIN` (TUN mode).
//!
//! The old advice was to symlink the binary into a root-PATH directory, because
//! `~/.local/bin` is absent from sudo's `secure_path`. That is unnecessary: re-executing
//! *our own absolute path* sidesteps `secure_path` entirely, since sudo only consults PATH
//! when the command is a bare name. It is also strictly safer than the alternative people
//! reach for — adding a user-writable directory to `secure_path` puts every sudo
//! invocation on the system at the mercy of that directory.
//!
//! Three details are load-bearing:
//!
//! * **The loop guard is an argv flag, not an environment variable.** sudo runs `env_reset`
//!   by default, so `Command::env()` is wiped before exec and `sudo VAR=1 …` is refused
//!   outright unless sudoers grants `setenv`. argv survives untouched.
//! * **We do not pass `-E`.** It fails under default sudoers, and it would hand
//!   attacker-influenced `LD_PRELOAD`/`LD_LIBRARY_PATH` to a root process.
//! * **Privilege is tested by capability, not just uid.** `setcap cap_net_admin+ep` is a
//!   supported deployment for this project, and such a process is not uid 0 yet needs no
//!   elevation at all.

use anyhow::{Context, Result};

/// Hidden flag marking an already-elevated re-exec, so the child cannot recurse.
pub const GUARD_FLAG: &str = "--already-elevated";

/// `CAP_NET_ADMIN` is capability bit 12.
const CAP_NET_ADMIN_BIT: u32 = 12;

/// Parse a `/proc/self/status` field into its raw value.
fn status_field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

/// Effective uid and effective capability mask, as reported by the kernel.
fn euid_and_capeff(status: &str) -> (Option<u32>, Option<u64>) {
    // "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
    let euid = status_field(status, "Uid")
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok());
    let capeff = status_field(status, "CapEff").and_then(|v| u64::from_str_radix(v, 16).ok());
    (euid, capeff)
}

/// Does this process already have what TUN mode needs?
fn is_privileged(status: &str) -> bool {
    let (euid, capeff) = euid_and_capeff(status);
    if euid == Some(0) {
        return true;
    }
    capeff.is_some_and(|c| c & (1 << CAP_NET_ADMIN_BIT) != 0)
}

/// True when the running process can open a TUN device and mutate routes.
pub fn have_privileges() -> bool {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => is_privileged(&s),
        // Without `/proc` we cannot prove we are privileged; let the operation try and
        // fail on its own rather than elevate on a guess.
        Err(_) => true,
    }
}

/// Re-execute this process under `sudo`, forwarding the original arguments, and exit with
/// the child's status. Returns `Ok(None)` when elevation is unnecessary.
///
/// `already_elevated` is the parsed value of [`GUARD_FLAG`]; when set we never recurse, so
/// a failure to actually gain privileges surfaces as the real underlying error instead of
/// an infinite sudo loop.
pub async fn ensure_root(already_elevated: bool) -> Result<Option<std::process::ExitCode>> {
    if have_privileges() || already_elevated {
        return Ok(None);
    }
    let exe = std::env::current_exe().context("resolve the running binary path")?;
    // Same binary-planting control the GUI's pkexec path uses: absolute, canonical, and
    // not writable by group/other (nor its parent directory).
    let exe = leshiy_helper::validate_elevation_target(&exe)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("validate this binary before elevating it")?;

    require_password_channel()?;

    crate::ui::hint(&format!(
        "VPN mode needs root; re-running via sudo: {}",
        crate::ui::value(&exe.display().to_string())
    ));

    // Held, never awaited: registration alone replaces SIGINT/SIGTERM's default "die now"
    // disposition. Parent and child share a foreground process group, so Ctrl-C hits both;
    // absorbing it here lets the elevated child finish restoring routes and DNS instead of
    // the prompt returning while root is still mid-teardown.
    let _absorbs_signals_for_child = crate::signals::install().ok();

    // `--` stops sudo parsing a path that begins with `-` as its own option. `args_os`
    // preserves arguments that are not valid UTF-8.
    let status = tokio::process::Command::new("sudo")
        .arg("--")
        .arg(&exe)
        .args(std::env::args_os().skip(1))
        .arg(GUARD_FLAG)
        .status()
        .await
        .context("run sudo (is it installed and on PATH?)")?;
    Ok(Some(exit_code_of(status)))
}

/// Mirror the child's fate, using the shell convention of `128 + signal` when it was
/// killed, so callers and scripts see the same status they would without the re-exec.
fn exit_code_of(status: std::process::ExitStatus) -> std::process::ExitCode {
    if let Some(code) = status.code() {
        return std::process::ExitCode::from(code as u8);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return std::process::ExitCode::from(128u8.saturating_add(sig as u8));
        }
    }
    std::process::ExitCode::FAILURE
}

/// sudo needs somewhere to ask for the password. Under cron, CI or a systemd unit there is
/// neither a TTY nor an askpass helper, and sudo's own failure ("no tty present") does not
/// explain what to do about it.
fn require_password_channel() -> Result<()> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() || std::env::var_os("SUDO_ASKPASS").is_some() {
        return Ok(());
    }
    // No TTY and no askpass still leaves one valid case: sudo needs no password at all,
    // because the credential is cached or sudoers grants NOPASSWD. `sudo -n` answers that
    // without prompting, which keeps scripted and CI use working.
    if sudo_needs_no_password() {
        return Ok(());
    }
    anyhow::bail!(
        "need root but there is no terminal to prompt on. Run it from a terminal, set \
         SUDO_ASKPASS to a helper, or pre-authorize with `sudo -v` first. For an \
         unattended service, install a system unit that already runs as root instead."
    )
}

fn sudo_needs_no_password() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNPRIV: &str = "Name:\tleshiy\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n";
    const ROOT: &str = "Name:\tleshiy\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n";
    /// Exactly `CAP_NET_ADMIN` (bit 12 = 0x1000), non-root: the `setcap` deployment.
    const SETCAP: &str = "Name:\tleshiy\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000001000\n";

    #[test]
    fn parses_euid_and_capeff() {
        assert_eq!(euid_and_capeff(UNPRIV), (Some(1000), Some(0)));
        assert_eq!(euid_and_capeff(ROOT).0, Some(0));
        assert_eq!(euid_and_capeff(SETCAP), (Some(1000), Some(0x1000)));
    }

    #[test]
    fn root_is_privileged() {
        assert!(is_privileged(ROOT));
    }

    /// A `setcap cap_net_admin+ep` process is not uid 0 but needs no elevation. Gating on
    /// uid alone would pointlessly prompt for a password on a supported deployment.
    #[test]
    fn cap_net_admin_without_root_is_privileged() {
        assert!(is_privileged(SETCAP));
    }

    #[test]
    fn plain_user_is_not_privileged() {
        assert!(!is_privileged(UNPRIV));
    }

    /// Capabilities other than `CAP_NET_ADMIN` must not count as privileged.
    #[test]
    fn an_unrelated_capability_does_not_qualify() {
        let cap_chown_only = "Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000001\n";
        assert!(!is_privileged(cap_chown_only));
    }

    #[test]
    fn missing_fields_are_not_mistaken_for_privilege() {
        assert!(!is_privileged("Name:\tleshiy\n"));
    }

    /// The guard short-circuits before any sudo attempt, so a child that still lacks
    /// privileges reports the real error instead of spawning sudo forever.
    #[tokio::test]
    async fn guard_flag_prevents_recursion() {
        assert!(ensure_root(true).await.unwrap().is_none());
    }
}
