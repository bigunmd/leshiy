//! System-proxy seam. The supervisor calls `set`/`clear` to point the OS at the
//! local SOCKS5 port (and, with the kill switch, to *leave it set* on an unexpected
//! drop so apps fail closed). Real per-OS implementations land in Plan 4; the trait
//! lets the supervisor be tested with a recording fake.
use crate::error::Result;
// `ClientError` is only constructed by the per-OS proxy impls (gsettings/networksetup/registry),
// which are cfg'd out on targets like Android — import it only where those impls compile.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use crate::error::ClientError;
use std::net::SocketAddr;

/// Sets/clears the operating-system proxy.
pub trait SystemProxy: Send + Sync {
    /// Point the system proxy at the given local SOCKS5 address.
    fn set(&self, socks: SocketAddr) -> Result<()>;
    /// Remove any proxy this object set.
    fn clear(&self) -> Result<()>;
}

/// Blanket impl so a boxed proxy satisfies the supervisor's `P: SystemProxy`.
impl SystemProxy for Box<dyn SystemProxy> {
    fn set(&self, socks: SocketAddr) -> Result<()> {
        (**self).set(socks)
    }
    fn clear(&self) -> Result<()> {
        (**self).clear()
    }
}

// --- pure command/registry builders (OS-agnostic, always compiled & tested) ---

/// macOS `networksetup` args to set the SOCKS proxy for one network service.
#[allow(dead_code)]
pub(crate) fn macos_set_args(service: &str, host: &str, port: u16) -> Vec<String> {
    vec![
        "-setsocksfirewallproxy".to_string(),
        service.to_string(),
        host.to_string(),
        port.to_string(),
    ]
}

/// macOS `networksetup` args to turn the SOCKS proxy off for one network service.
#[allow(dead_code)]
pub(crate) fn macos_clear_args(service: &str) -> Vec<String> {
    vec![
        "-setsocksfirewallproxystate".to_string(),
        service.to_string(),
        "off".to_string(),
    ]
}

/// Linux GNOME `gsettings` invocations to enable a manual SOCKS proxy.
// Used by the Linux sysproxy path and the unit tests only; gate it so it isn't dead code
// when the crate is cross-compiled for a non-Linux target (e.g. the Phase 3 Windows check).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_set_invocations(host: &str, port: u16) -> Vec<Vec<String>> {
    vec![
        vec![
            "set".to_string(),
            "org.gnome.system.proxy".to_string(),
            "mode".to_string(),
            "manual".to_string(),
        ],
        vec![
            "set".to_string(),
            "org.gnome.system.proxy.socks".to_string(),
            "host".to_string(),
            host.to_string(),
        ],
        vec![
            "set".to_string(),
            "org.gnome.system.proxy.socks".to_string(),
            "port".to_string(),
            port.to_string(),
        ],
    ]
}

/// Linux GNOME `gsettings` invocation to disable the proxy.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_clear_invocations() -> Vec<Vec<String>> {
    vec![vec![
        "set".to_string(),
        "org.gnome.system.proxy".to_string(),
        "mode".to_string(),
        "none".to_string(),
    ]]
}

/// Windows WinINET `ProxyServer` value pointing traffic at a local SOCKS proxy.
#[allow(dead_code)]
pub(crate) fn windows_proxy_server(host: &str, port: u16) -> String {
    format!("socks={host}:{port}")
}

/// A do-nothing proxy for headless/test/unsupported environments.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopProxy;

impl SystemProxy for NoopProxy {
    fn set(&self, _socks: SocketAddr) -> Result<()> {
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        Ok(())
    }
}

// --- Linux executor (GNOME gsettings) ---

/// Sets the GNOME system SOCKS proxy via `gsettings`.
#[cfg(target_os = "linux")]
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxProxy;

#[cfg(target_os = "linux")]
impl SystemProxy for LinuxProxy {
    fn set(&self, socks: SocketAddr) -> Result<()> {
        run_gsettings(linux_set_invocations(&socks.ip().to_string(), socks.port()))
    }
    fn clear(&self) -> Result<()> {
        run_gsettings(linux_clear_invocations())
    }
}

#[cfg(target_os = "linux")]
fn run_gsettings(invocations: Vec<Vec<String>>) -> Result<()> {
    for args in invocations {
        let status = std::process::Command::new("gsettings")
            .args(&args)
            .status()
            .map_err(|e| ClientError::Proxy(e.to_string()))?;
        if !status.success() {
            return Err(ClientError::Proxy("gsettings exited non-zero".to_string()));
        }
    }
    Ok(())
}

// --- macOS executor (networksetup) ---

/// Sets the macOS SOCKS proxy on every enabled network service via `networksetup`.
#[cfg(target_os = "macos")]
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosProxy;

#[cfg(target_os = "macos")]
impl SystemProxy for MacosProxy {
    fn set(&self, socks: SocketAddr) -> Result<()> {
        let host = socks.ip().to_string();
        for svc in macos_services()? {
            run_networksetup(macos_set_args(&svc, &host, socks.port()))?;
        }
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        for svc in macos_services()? {
            run_networksetup(macos_clear_args(&svc))?;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn macos_services() -> Result<Vec<String>> {
    let out = std::process::Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| ClientError::Proxy(e.to_string()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with('*') && !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect())
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: Vec<String>) -> Result<()> {
    let status = std::process::Command::new("networksetup")
        .args(&args)
        .status()
        .map_err(|e| ClientError::Proxy(e.to_string()))?;
    if !status.success() {
        return Err(ClientError::Proxy(
            "networksetup exited non-zero".to_string(),
        ));
    }
    Ok(())
}

// --- Windows executor (WinINET registry via winreg) ---

/// Sets the Windows WinINET system proxy to the local SOCKS port via the registry.
/// Note: does not emit the WinINET refresh notification (unsafe FFI; see plan).
#[cfg(target_os = "windows")]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsProxy;

#[cfg(target_os = "windows")]
const WININET_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(target_os = "windows")]
impl SystemProxy for WindowsProxy {
    fn set(&self, socks: SocketAddr) -> Result<()> {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(WININET_KEY)
            .map_err(|e| ClientError::Proxy(e.to_string()))?;
        key.set_value(
            "ProxyServer",
            &windows_proxy_server(&socks.ip().to_string(), socks.port()),
        )
        .map_err(|e| ClientError::Proxy(e.to_string()))?;
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| ClientError::Proxy(e.to_string()))?;
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey_with_flags(WININET_KEY, KEY_SET_VALUE)
            .map_err(|e| ClientError::Proxy(e.to_string()))?;
        key.set_value("ProxyEnable", &0u32)
            .map_err(|e| ClientError::Proxy(e.to_string()))?;
        Ok(())
    }
}

// --- factory ---

/// Returns the system-proxy implementation for the current OS, or `NoopProxy` on
/// unsupported platforms. The supervisor accepts the boxed result via the blanket impl.
pub fn system_proxy() -> Box<dyn SystemProxy> {
    #[cfg(target_os = "linux")]
    {
        return Box::new(LinuxProxy);
    }
    #[cfg(target_os = "macos")]
    {
        return Box::new(MacosProxy);
    }
    #[cfg(target_os = "windows")]
    {
        return Box::new(WindowsProxy);
    }
    #[allow(unreachable_code)]
    {
        Box::new(NoopProxy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_is_infallible() {
        let p = NoopProxy;
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        assert!(p.set(addr).is_ok());
        assert!(p.clear().is_ok());
    }

    #[test]
    fn macos_args_build() {
        let set_owned = macos_set_args("Wi-Fi", "127.0.0.1", 1080);
        let set: Vec<&str> = set_owned.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            set,
            ["-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "1080"]
        );
        let clear_owned = macos_clear_args("Wi-Fi");
        let clear: Vec<&str> = clear_owned.iter().map(|s| s.as_str()).collect();
        assert_eq!(clear, ["-setsocksfirewallproxystate", "Wi-Fi", "off"]);
    }

    #[test]
    fn linux_invocations_build() {
        let set = linux_set_invocations("127.0.0.1", 1080);
        let first: Vec<&str> = set[0].iter().map(|s| s.as_str()).collect();
        assert_eq!(first, ["set", "org.gnome.system.proxy", "mode", "manual"]);
        assert!(set.iter().any(|c| {
            let v: Vec<&str> = c.iter().map(|s| s.as_str()).collect();
            v == ["set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"]
        }));
        assert!(set.iter().any(|c| {
            let v: Vec<&str> = c.iter().map(|s| s.as_str()).collect();
            v == ["set", "org.gnome.system.proxy.socks", "port", "1080"]
        }));
        let clear = linux_clear_invocations();
        let cv: Vec<&str> = clear[0].iter().map(|s| s.as_str()).collect();
        assert_eq!(cv, ["set", "org.gnome.system.proxy", "mode", "none"]);
    }

    #[test]
    fn windows_proxy_server_is_socks() {
        assert_eq!(
            windows_proxy_server("127.0.0.1", 1080),
            "socks=127.0.0.1:1080"
        );
    }
}
