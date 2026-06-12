//! On-demand privileged-helper elevation for the GUI (macOS + Windows). Launches an elevated
//! `leshiy-helper run --ephemeral` for the session; the unprivileged GUI then connects to the
//! per-OS endpoint. Linux uses the installed daemon (systemd/setcap) instead, so this module's
//! real bodies are macOS/Windows-only.
//!
//! Kept in `leshiy-helper` (not the Tauri crate) so the Windows path is covered by the
//! `x86_64-pc-windows-gnu` cross-check. Runtime behavior (the actual UAC/osascript prompt) is
//! verified on real hardware — a USER TODO.
use std::path::Path;

/// Ensure a helper is answering the default endpoint: if one already is, return; otherwise
/// elevate + launch an ephemeral helper and poll the endpoint (up to ~5s) until it's ready.
/// Used by the GUI on macOS/Windows before connecting.
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
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = bin;
        Err(std::io::Error::other(
            "on-demand helper elevation is only used on macOS/Windows (Linux uses the daemon)",
        ))
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
        let inner = format!(
            "'{}' run --ephemeral --socket '{}' --allow-uid {} >/tmp/leshiy-helper.log 2>&1 &",
            bin.display(),
            sock.display(),
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
        let ps = format!(
            "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
            bin.display(),
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
}
