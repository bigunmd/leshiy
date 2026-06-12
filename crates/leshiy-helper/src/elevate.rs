//! On-demand privileged-helper elevation for the GUI (all desktop platforms). Launches an
//! elevated `leshiy-helper run --ephemeral` for the session; the unprivileged GUI then connects
//! to the per-OS endpoint. Linux uses `pkexec` (or runs directly if the GUI is already root,
//! e.g. an AppImage launched with sudo); macOS uses `osascript`; Windows uses UAC.
//!
//! Kept in `leshiy-helper` (not the Tauri crate) so the Windows path is covered by the
//! `x86_64-pc-windows-gnu` cross-check. Runtime behavior (the actual prompt) is verified on
//! real hardware — a USER TODO.
use std::path::Path;

/// Ensure a helper is answering the default endpoint: if one already is, return; otherwise
/// elevate + launch an ephemeral helper and poll the endpoint (up to ~5s) until it's ready.
pub async fn ensure_running(bin: &Path) -> std::io::Result<()> {
    if crate::is_installed() {
        return Ok(());
    }
    spawn_ephemeral_helper(bin)?;
    for _ in 0..100 {
        if crate::is_installed() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(std::io::Error::other(
        "the VPN helper did not start in time (elevation declined or failed)",
    ))
}

/// Launch `leshiy-helper run --ephemeral` elevated and backgrounded, so the GUI can connect to
/// the per-OS endpoint. Returns once the elevation prompt is dismissed; poll the endpoint to
/// learn when the helper is actually ready.
pub fn spawn_ephemeral_helper(bin: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::spawn(bin)
    }
    #[cfg(target_os = "windows")]
    {
        windows::spawn(bin)
    }
    #[cfg(target_os = "linux")]
    {
        linux::spawn(bin)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = bin;
        Err(std::io::Error::other(
            "on-demand helper elevation is not supported on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::process::Command;

    pub fn spawn(bin: &Path) -> std::io::Result<()> {
        let uid = nix::unistd::getuid().as_raw();
        let sock = crate::default_socket_path();
        // If the GUI is already root (e.g. an AppImage launched with `sudo`), launch directly —
        // skipping pkexec also avoids needing a polkit agent / session bus.
        let mut cmd = if nix::unistd::geteuid().is_root() {
            Command::new(bin)
        } else {
            let mut c = Command::new("pkexec");
            c.arg(bin);
            c
        };
        cmd.arg("run")
            .arg("--ephemeral")
            .arg("--socket")
            .arg(&sock)
            .arg("--allow-uid")
            .arg(uid.to_string());
        // CRITICAL for AppImage: it exports LD_LIBRARY_PATH/LD_PRELOAD pointing at its bundled
        // (often mismatched) libs. If pkexec or the helper inherits them, system libraries
        // (libpolkit/glib) load the wrong versions and fail (undefined symbol). Run the child
        // with the system library environment.
        cmd.env_remove("LD_LIBRARY_PATH").env_remove("LD_PRELOAD");
        // Detach: the helper serves the socket for the session; we poll the endpoint for ready.
        cmd.spawn()?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::Path;
    use std::process::Command;

    pub fn spawn(bin: &Path) -> std::io::Result<()> {
        let uid = current_uid()?;
        let sock = crate::default_socket_path();
        // Background the root helper inside the elevated shell; osascript returns after launch.
        // Output is discarded (NOT a predictable /tmp path — that would invite a symlink
        // attack on a root-written file). Each interpolated value is POSIX single-quoted
        // (`sh_squote`) so a path containing `'` can't break out / inject; the whole shell
        // command is then escaped for the AppleScript double-quoted string layer.
        let inner = format!(
            "{} run --ephemeral --socket {} --allow-uid {} >/dev/null 2>&1 &",
            sh_squote(&bin.display().to_string()),
            sh_squote(&sock.display().to_string()),
            uid
        );
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            inner.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let status = Command::new("osascript").arg("-e").arg(script).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "osascript administrator elevation failed or was declined",
            ))
        }
    }

    fn current_uid() -> std::io::Result<u32> {
        let out = Command::new("id").arg("-u").output()?;
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .map_err(|_| std::io::Error::other("could not parse current uid from `id -u`"))
    }

    /// POSIX single-quote a string for safe embedding in a /bin/sh command (the `do shell
    /// script` body): wrap in `'…'`, replacing each `'` with `'\''`.
    fn sh_squote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::path::Path;
    use std::process::Command;

    pub fn spawn(bin: &Path) -> std::io::Result<()> {
        let sid = current_sid()?;
        let pipe = crate::default_socket_path(); // \\.\pipe\leshiy-helper on Windows
        let args = format!(
            "run --ephemeral --pipe {} --allow-sid {}",
            pipe.display(),
            sid
        );
        // -Verb RunAs triggers UAC; no -Wait so the helper keeps running in the background.
        // -WindowStyle Hidden suppresses the helper's console window (it's a background daemon).
        // The binary path is PowerShell single-quoted (ps_squote: `'` -> `''`) so a path with
        // an apostrophe can't break out. `args` is constants + the SID (no quotes).
        let ps = format!(
            "Start-Process -FilePath {} -ArgumentList '{}' -Verb RunAs -WindowStyle Hidden",
            ps_squote(&bin.display().to_string()),
            args
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "UAC elevation (Start-Process -Verb RunAs) failed or was declined",
            ))
        }
    }

    /// Current user's SID via `whoami /user /fo csv /nh` → `"name","S-1-5-..."`.
    fn current_sid() -> std::io::Result<String> {
        let out = Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()?;
        let s = String::from_utf8_lossy(&out.stdout);
        s.rsplit(',')
            .next()
            .map(|f| f.trim().trim_matches('"').to_string())
            .filter(|sid| sid.starts_with("S-"))
            .ok_or_else(|| std::io::Error::other("could not parse current SID from `whoami /user`"))
    }

    /// PowerShell single-quote a string: wrap in `'…'`, replacing each `'` with `''`.
    fn ps_squote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }
}
