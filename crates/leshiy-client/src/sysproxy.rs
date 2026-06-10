//! System-proxy seam. The supervisor calls `set`/`clear` to point the OS at the
//! local SOCKS5 port (and, with the kill switch, to *leave it set* on an unexpected
//! drop so apps fail closed). Real per-OS implementations land in Plan 4; the trait
//! lets the supervisor be tested with a recording fake.
use crate::error::Result;
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
