//! Bracket-aware `host:port` helpers.
//!
//! A bare IPv6 literal must be bracketed before it is joined with a port
//! (`2001:db8::1` + 443 → `[2001:db8::1]:443`) and cannot be split with a naive
//! `rsplit_once(':')` (which would treat the final hextet as the port). These
//! helpers centralize that so every address-formatting site handles IPv6.

use std::net::{Ipv6Addr, SocketAddr};

/// Join a host and port, bracketing the host if it is a bare IPv6 literal.
/// IPv4 literals, domains, and already-bracketed hosts are left as-is.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Return `hostport` unchanged if it already carries a port (bracket-aware),
/// otherwise append `:default_port` — bracketing a bare IPv6 literal in the
/// process.
pub fn ensure_port(hostport: &str, default_port: u16) -> String {
    // Already a full socket address: `v4:port` or `[v6]:port`.
    if hostport.parse::<SocketAddr>().is_ok() {
        return hostport.to_string();
    }
    // Bare IPv6 literal (no port) — bracket it and add the default.
    if hostport.parse::<Ipv6Addr>().is_ok() {
        return format!("[{hostport}]:{default_port}");
    }
    // `[v6]` bracketed but without a port.
    if hostport.starts_with('[') && hostport.ends_with(']') {
        return format!("{hostport}:{default_port}");
    }
    // Domain or IPv4 with a port already (hostnames never contain ':', so the
    // final `:port` is unambiguous here).
    match hostport.rsplit_once(':') {
        Some((_, p)) if p.parse::<u16>().is_ok() => hostport.to_string(),
        _ => format!("{hostport}:{default_port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_brackets_bare_ipv6() {
        assert_eq!(join_host_port("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(join_host_port("::1", 80), "[::1]:80");
    }

    #[test]
    fn join_leaves_ipv4_and_domain() {
        assert_eq!(join_host_port("1.2.3.4", 443), "1.2.3.4:443");
        assert_eq!(join_host_port("example.com", 443), "example.com:443");
    }

    #[test]
    fn ensure_port_brackets_bare_ipv6_with_default() {
        assert_eq!(ensure_port("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn ensure_port_keeps_existing_port() {
        assert_eq!(ensure_port("1.2.3.4:80", 443), "1.2.3.4:80");
        assert_eq!(ensure_port("[2001:db8::1]:80", 443), "[2001:db8::1]:80");
        assert_eq!(ensure_port("example.com:80", 443), "example.com:80");
    }

    #[test]
    fn ensure_port_adds_default_to_bare_host() {
        assert_eq!(ensure_port("example.com", 443), "example.com:443");
        assert_eq!(ensure_port("1.2.3.4", 443), "1.2.3.4:443");
    }

    #[test]
    fn ensure_port_brackets_v6_literal_without_port() {
        assert_eq!(ensure_port("[2001:db8::1]", 443), "[2001:db8::1]:443");
    }
}
