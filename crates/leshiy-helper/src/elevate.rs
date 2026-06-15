//! On-demand privileged-helper elevation for the GUI (all desktop platforms). Launches an
//! elevated `leshiy-helper run --ephemeral` for the session; the unprivileged GUI then connects
//! to the per-OS endpoint. Linux uses `pkexec` (or runs directly if the GUI is already root,
//! e.g. an AppImage launched with sudo); macOS uses `osascript`; Windows uses UAC.
//!
//! Kept in `leshiy-helper` (not the Tauri crate) so the Windows path is covered by the
//! `x86_64-pc-windows-gnu` cross-check. Runtime behavior (the actual prompt) is verified on
//! real hardware — a USER TODO.
use std::path::{Path, PathBuf};

/// Validate the helper binary before running it with elevated privileges (H6).
///
/// `bin` is chosen by the unprivileged GUI; if an attacker can influence which
/// file we launch — a relative path resolved against a writable CWD, or a binary
/// sitting in a directory another unprivileged user can write to — they get
/// root/Admin code execution via binary planting. We canonicalize (resolving
/// symlinks and requiring existence), require an absolute path, and on Unix
/// refuse to elevate a binary whose file or parent directory is group/other
/// writable.
fn validate_helper_binary(bin: &Path) -> std::io::Result<PathBuf> {
    let canon = bin.canonicalize()?;
    if !canon.is_absolute() {
        return Err(std::io::Error::other(
            "refusing to elevate: helper binary path is not absolute",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let check = |p: &Path| -> std::io::Result<()> {
            let mode = std::fs::metadata(p)?.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(std::io::Error::other(format!(
                    "refusing to elevate: {} is group/other-writable (mode {:o}) — \
                     a non-owner could plant a malicious binary",
                    p.display(),
                    mode & 0o7777
                )));
            }
            Ok(())
        };
        check(&canon)?;
        if let Some(parent) = canon.parent() {
            check(parent)?;
        }
    }
    Ok(canon)
}

/// Ensure a helper is answering the default endpoint: if one already is, return; otherwise
/// elevate + launch an ephemeral helper and poll the endpoint (up to ~5s) until it's ready.
pub async fn ensure_running(bin: &Path) -> std::io::Result<()> {
    if helper_responds().await {
        return Ok(());
    }
    // Validate the binary path BEFORE elevating it (H6).
    let bin = validate_helper_binary(bin)?;
    spawn_ephemeral_helper(&bin)?;
    for _ in 0..100 {
        if helper_responds().await {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(std::io::Error::other(
        "the VPN helper did not start in time (elevation declined or failed)",
    ))
}

/// True only if a **live** helper answers the default endpoint. This is a real connect +
/// request — robust against a stale Unix socket *file* left behind by a previous ephemeral
/// helper (which a file-existence check would wrongly report as "running"). On Windows the
/// pipe vanishes with the process, so this also works there.
async fn helper_responds() -> bool {
    crate::HelperClient::connect(crate::default_endpoint())
        .get_status()
        .await
        .is_ok()
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
        // If the GUI is itself root, the allowed uid is 0; confirm it explicitly
        // so the helper's accidental-root guard accepts it (M6).
        if uid == 0 {
            cmd.arg("--allow-root");
        }
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
        // If the GUI is itself root (uid 0), confirm it for the helper's
        // accidental-root guard (M6).
        let allow_root = if uid == 0 { " --allow-root" } else { "" };
        let inner = format!(
            "{} run --ephemeral --socket {} --allow-uid {}{} >/dev/null 2>&1 &",
            sh_squote(&bin.display().to_string()),
            sh_squote(&sock.display().to_string()),
            uid,
            allow_root
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn unique_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("leshiy-elev-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    fn write_exe(dir: &Path, mode: u32) -> PathBuf {
        let p = dir.join("leshiy-helper");
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn accepts_owner_only_writable_binary() {
        let dir = unique_dir("ok");
        let exe = write_exe(&dir, 0o755);
        let got = validate_helper_binary(&exe).unwrap();
        assert!(got.is_absolute());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_world_writable_binary() {
        let dir = unique_dir("ww");
        let exe = write_exe(&dir, 0o757); // other-writable → plantable
        assert!(validate_helper_binary(&exe).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_world_writable_parent_dir() {
        let dir = unique_dir("wwdir");
        let exe = write_exe(&dir, 0o755);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_helper_binary(&exe).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_nonexistent_path() {
        assert!(validate_helper_binary(Path::new("/nonexistent/leshiy-helper-xyz")).is_err());
    }
}
