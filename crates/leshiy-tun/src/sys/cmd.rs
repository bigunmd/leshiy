//! Small `unsafe`-free helpers for the macOS/Windows backends: run a privileged
//! command and map a non-zero exit to an `io::Error`, plus pure argument builders
//! (unit-tested) so command construction is verifiable without invoking anything.
//!
//! The runner functions (`run`/`run_capture`) are compiled only for the real macOS /
//! Windows targets where the backends use them; the pure argument-builders also compile
//! under `test`, so they (and their unit tests) run on the Linux host via `cargo test`.

/// Run `program args...`, mapping spawn failure or a non-zero exit to `io::Error`.
/// Best-effort callers (teardown) ignore the `Result`; setup callers propagate it.
// `allow(dead_code)`: the Windows backend starts consuming this in Task 3.7; until then
// the cross-target check would flag it unused. Remove the allow once it has a caller.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[allow(dead_code)]
pub fn run(program: &str, args: &[&str]) -> std::io::Result<()> {
    let out = std::process::Command::new(program).args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Run a command and return its captured stdout as a `String` (trimmed).
/// Used to read state we must restore later (e.g. the current DNS servers).
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[allow(dead_code)]
pub fn run_capture(program: &str, args: &[&str]) -> std::io::Result<String> {
    let out = std::process::Command::new(program).args(args).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(std::io::Error::other(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

// ---------------------------------------------------------------------------
// Windows `netsh` argument builders (pure; OS-independent; host-testable).
//
// These live here — not in `windows.rs` — because the `windows` module is
// `#[cfg(target_os = "windows")]`, so it is never compiled on the Linux host and its
// `#[cfg(test)]` would not run here. Placed in `cmd` (gated `any(macos, windows, test)`)
// they compile and unit-test under host `cargo test -p leshiy-tun`. `win_`-prefixed so a
// future macOS builder set can coexist in this shared module without a name clash.
// `windows.rs::start()` calls these via `cmd::win_*`.

/// `netsh interface ipv4 set dnsservers name=<iface> static <ip> primary`.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn win_dns_set_static_args(iface: &str, dns: &str) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={iface}"),
        "static".into(),
        dns.to_string(),
        "primary".into(),
    ]
}

/// `netsh interface ipv4 set dnsservers name=<iface> dhcp` — restore DHCP-assigned DNS.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn win_dns_reset_dhcp_args(iface: &str) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={iface}"),
        "dhcp".into(),
    ]
}

/// `netsh interface ipv4 add route <dest_cidr> <iface> <gateway>` — host-exception
/// (server) route out the original interface via the original gateway.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn win_route_add_via_gateway_args(
    dest_cidr: &str,
    gateway: &str,
    orig_iface: &str,
) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "add".into(),
        "route".into(),
        dest_cidr.to_string(),
        orig_iface.to_string(),
        gateway.to_string(),
    ]
}

/// `netsh interface ipv4 add route <dest_cidr> <iface>` — send a CIDR through the tun
/// interface by name (no ifindex FFI needed).
#[cfg(any(target_os = "windows", test))]
pub(crate) fn win_route_add_via_iface_args(dest_cidr: &str, iface: &str) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "add".into(),
        "route".into(),
        dest_cidr.to_string(),
        iface.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_set_static_args() {
        let args = win_dns_set_static_args("leshiy0", "1.1.1.1");
        assert_eq!(
            args,
            vec![
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                "name=leshiy0",
                "static",
                "1.1.1.1",
                "primary"
            ]
        );
    }

    #[test]
    fn dns_reset_dhcp_args() {
        let args = win_dns_reset_dhcp_args("leshiy0");
        assert_eq!(
            args,
            vec![
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                "name=leshiy0",
                "dhcp"
            ]
        );
    }

    #[test]
    fn route_add_via_gateway_args_win() {
        let args = win_route_add_via_gateway_args("203.0.113.7/32", "192.168.1.1", "Ethernet");
        assert_eq!(
            args,
            vec![
                "interface",
                "ipv4",
                "add",
                "route",
                "203.0.113.7/32",
                "Ethernet",
                "192.168.1.1"
            ]
        );
    }

    #[test]
    fn route_add_via_iface_args_win() {
        let args = win_route_add_via_iface_args("0.0.0.0/1", "leshiy0");
        assert_eq!(
            args,
            vec!["interface", "ipv4", "add", "route", "0.0.0.0/1", "leshiy0"]
        );
    }
}
