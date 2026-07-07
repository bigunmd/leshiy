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

/// Split a `host:port` / `[v6]:port` / bare-host string into `(host, Option<port>)`. The host is
/// returned **without** brackets. A bare IPv6 literal is treated as host-only (no port), since its
/// colons are part of the address.
pub fn split_host_port(s: &str) -> (&str, Option<&str>) {
    if let Some(rest) = s.strip_prefix('[')
        && let Some((host, after)) = rest.split_once(']')
    {
        return (host, after.strip_prefix(':').filter(|p| !p.is_empty()));
    }
    if s.parse::<Ipv6Addr>().is_ok() {
        return (s, None); // bare IPv6 literal — the colons aren't a port separator
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        _ => (s, None),
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

    #[test]
    fn split_host_port_handles_all_forms() {
        assert_eq!(
            split_host_port("example.com:22"),
            ("example.com", Some("22"))
        );
        assert_eq!(split_host_port("1.2.3.4:22"), ("1.2.3.4", Some("22")));
        assert_eq!(split_host_port("example.com"), ("example.com", None));
        // Bracketed v6, with and without a port — host comes back unbracketed.
        assert_eq!(
            split_host_port("[2001:db8::1]:22"),
            ("2001:db8::1", Some("22"))
        );
        assert_eq!(split_host_port("[2001:db8::1]"), ("2001:db8::1", None));
        // Bare v6 literal: the colons are the address, not a port separator.
        assert_eq!(split_host_port("2001:db8::1"), ("2001:db8::1", None));
        assert_eq!(split_host_port("::1"), ("::1", None));
    }
}
