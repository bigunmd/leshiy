//! Small `unsafe`-free helpers for the macOS/Windows backends: run a privileged
//! command and map a non-zero exit to an `io::Error`, plus pure argument builders
//! (unit-tested) so command construction is verifiable without invoking anything.
//!
//! The runner functions (`run`/`run_capture`) compile for the real macOS / Windows targets
//! where the backends use them, and also under host `test` (so the host-type-checked macOS
//! backend can call them on Linux); the pure argument-builders likewise compile under
//! `test`, so they (and their unit tests) run on the Linux host via `cargo test`.

/// Run `program args...`, mapping spawn failure or a non-zero exit to `io::Error`.
/// Best-effort callers (teardown) ignore the `Result`; setup callers propagate it.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(crate) fn run(program: &str, args: &[&str]) -> std::io::Result<()> {
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
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(crate) fn run_capture(program: &str, args: &[&str]) -> std::io::Result<String> {
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

/// `netsh interface ipv6 add address <iface> <v6>` — add an IPv6 address to the tun adapter so
/// IPv6 can ride the tunnel (the `tun` crate assigns only the v4 address at creation).
#[cfg(any(target_os = "windows", test))]
pub(crate) fn win_v6_addr_add_args(iface: &str, v6: &str) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv6".into(),
        "add".into(),
        "address".into(),
        iface.to_string(),
        v6.to_string(),
    ]
}

/// `netsh interface ipv4 delete route <dest_cidr> <iface> <gateway>` — remove a bypass route
/// on teardown. Mirrors the gateway add builder. (via_tun / include routes are managed through
/// the net_route IP Helper API, not netsh, so there's no `*_via_iface` builder.)
#[cfg(any(target_os = "windows", test))]
pub(crate) fn win_route_del_via_gateway_args(
    dest_cidr: &str,
    gateway: &str,
    orig_iface: &str,
) -> Vec<String> {
    vec![
        "interface".into(),
        "ipv4".into(),
        "delete".into(),
        "route".into(),
        dest_cidr.to_string(),
        orig_iface.to_string(),
        gateway.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// macOS `networksetup` / BSD `route` argument builders (pure; host-testable).
// `mac_`-prefixed to coexist with the `win_*` builders in this shared module.
// `macos.rs::start()` calls these via `cmd::mac_*`.

/// `networksetup -setdnsservers <service> <ip...>`. An empty list clears DNS via the
/// literal `empty` keyword (networksetup's reset sentinel).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn mac_dns_set_args(service: &str, dns: &[std::net::IpAddr]) -> Vec<String> {
    let mut v = vec!["-setdnsservers".to_string(), service.to_string()];
    if dns.is_empty() {
        v.push("empty".to_string());
    } else {
        v.extend(dns.iter().map(|ip| ip.to_string()));
    }
    v
}

/// `route -n add -net <dest>/<prefix> <gateway>` — host-exception (server) route via the
/// original gateway. Used as a fallback if `net-route`'s gateway add is rejected.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn mac_route_add_via_gateway_args(dest: &str, prefix: u8, gateway: &str) -> Vec<String> {
    vec![
        "-n".into(),
        "add".into(),
        "-net".into(),
        format!("{dest}/{prefix}"),
        gateway.to_string(),
    ]
}

/// `route -n add -net <dest>/<prefix> -interface <iface>` — send a CIDR through the utun
/// device by *name* (no ifindex FFI needed).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn mac_route_add_via_iface_args(dest: &str, prefix: u8, iface: &str) -> Vec<String> {
    vec![
        "-n".into(),
        "add".into(),
        "-net".into(),
        format!("{dest}/{prefix}"),
        "-interface".into(),
        iface.to_string(),
    ]
}

/// `route -n delete -net <dest>/<prefix>` — remove a route by destination (BSD `route`
/// matches on the destination net). Used for split-tunnel teardown / dynamic removal.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn mac_route_del_args(dest: &str, prefix: u8) -> Vec<String> {
    vec![
        "-n".into(),
        "delete".into(),
        "-net".into(),
        format!("{dest}/{prefix}"),
    ]
}

/// `ifconfig <iface> inet6 <v6> prefixlen 64 alias` — add an IPv6 address to the utun so IPv6
/// can ride the tunnel (the `tun` crate assigns only the v4 address at creation).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn mac_ifconfig_v6_add_args(iface: &str, v6: &str) -> Vec<String> {
    vec![
        iface.to_string(),
        "inet6".into(),
        v6.to_string(),
        "prefixlen".into(),
        "64".into(),
        "alias".into(),
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
    fn mac_dns_set_args_lists_each_server() {
        let dns: Vec<std::net::IpAddr> =
            vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()];
        let args = mac_dns_set_args("Wi-Fi", &dns);
        assert_eq!(args, vec!["-setdnsservers", "Wi-Fi", "1.1.1.1", "9.9.9.9"]);
    }

    #[test]
    fn mac_dns_set_args_empty_uses_empty_keyword() {
        let args = mac_dns_set_args("Wi-Fi", &[]);
        assert_eq!(args, vec!["-setdnsservers", "Wi-Fi", "empty"]);
    }

    #[test]
    fn mac_route_add_via_gateway_args_v4() {
        let args = mac_route_add_via_gateway_args("203.0.113.7", 32, "192.168.1.1");
        assert_eq!(
            args,
            vec!["-n", "add", "-net", "203.0.113.7/32", "192.168.1.1"]
        );
    }

    #[test]
    fn mac_route_add_via_iface_args_v4() {
        let args = mac_route_add_via_iface_args("0.0.0.0", 1, "utun7");
        assert_eq!(
            args,
            vec!["-n", "add", "-net", "0.0.0.0/1", "-interface", "utun7"]
        );
    }

    #[test]
    fn win_route_del_via_gateway_args_builds() {
        let args = win_route_del_via_gateway_args("198.51.100.0/24", "192.168.1.1", "Ethernet");
        assert_eq!(
            args,
            vec![
                "interface",
                "ipv4",
                "delete",
                "route",
                "198.51.100.0/24",
                "Ethernet",
                "192.168.1.1"
            ]
        );
    }

    #[test]
    fn mac_route_del_args_builds() {
        let args = mac_route_del_args("198.51.100.0", 24);
        assert_eq!(args, vec!["-n", "delete", "-net", "198.51.100.0/24"]);
    }

    #[test]
    fn win_v6_addr_add_args_builds() {
        let args = win_v6_addr_add_args("leshiy0", "fd00:71::2");
        assert_eq!(
            args,
            vec![
                "interface",
                "ipv6",
                "add",
                "address",
                "leshiy0",
                "fd00:71::2"
            ]
        );
    }

    #[test]
    fn mac_ifconfig_v6_add_args_builds() {
        let args = mac_ifconfig_v6_add_args("utun7", "fd00:71::2");
        assert_eq!(
            args,
            vec!["utun7", "inet6", "fd00:71::2", "prefixlen", "64", "alias"]
        );
    }
}
