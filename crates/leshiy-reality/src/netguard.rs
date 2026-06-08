//! SSRF guard: resolve a target and reject forbidden address classes.
//!
//! Link-local (169.254.0.0/16, fe80::/10), unspecified (0.0.0.0/::), and
//! multicast addresses are never legitimate relay targets and could expose
//! cloud-metadata endpoints or miscellaneous host services. Loopback and
//! private (RFC 1918) addresses are intentionally allowed — the in-process
//! tests rely on 127.0.0.1, and a proxy legitimately reaches RFC 1918 hosts.
//!
//! Returns the resolved `SocketAddr` so callers connect to the resolved
//! address, preventing DNS-rebinding attacks.

use crate::{RealityError, Result};
use std::net::{IpAddr, SocketAddr};

/// Resolve `target` (e.g. `"example.com:443"` or `"127.0.0.1:80"`) and
/// return the first resolved `SocketAddr` after verifying it is not
/// link-local, unspecified, or multicast.
pub async fn resolve_checked(target: &str) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host(target)
        .await
        .map_err(RealityError::Io)?;

    let addr = addrs
        .next()
        .ok_or_else(|| RealityError::Malformed(format!("no address resolved for {target}")))?;

    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                return Err(RealityError::Malformed(
                    "forbidden target address".to_string(),
                ));
            }
            if v4.is_unspecified() {
                return Err(RealityError::Malformed(
                    "forbidden target address".to_string(),
                ));
            }
            if v4.is_multicast() {
                return Err(RealityError::Malformed(
                    "forbidden target address".to_string(),
                ));
            }
        }
        IpAddr::V6(v6) => {
            // Unicast link-local: fe80::/10
            if v6.is_unicast_link_local() {
                return Err(RealityError::Malformed(
                    "forbidden target address".to_string(),
                ));
            }
            if v6.is_unspecified() {
                return Err(RealityError::Malformed(
                    "forbidden target address".to_string(),
                ));
            }
            if v6.is_multicast() {
                return Err(RealityError::Malformed(
                    "forbidden target address".to_string(),
                ));
            }
        }
    }

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_allowed() {
        // 127.0.0.1 must always be reachable (in-process tests depend on it)
        let addr = resolve_checked("127.0.0.1:80").await.unwrap();
        assert_eq!(addr.ip(), IpAddr::V4("127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn private_rfc1918_allowed() {
        // 10.0.0.1 is private — legitimate proxy target
        let addr = resolve_checked("10.0.0.1:443").await.unwrap();
        assert_eq!(addr.ip(), IpAddr::V4("10.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn link_local_metadata_blocked() {
        // 169.254.169.254 — AWS/GCP/Azure instance metadata
        let err = resolve_checked("169.254.169.254:80").await.unwrap_err();
        assert!(
            matches!(err, RealityError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn unspecified_blocked() {
        let err = resolve_checked("0.0.0.0:80").await.unwrap_err();
        assert!(
            matches!(err, RealityError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn multicast_blocked() {
        // 224.0.0.1 — IPv4 multicast
        let err = resolve_checked("224.0.0.1:80").await.unwrap_err();
        assert!(
            matches!(err, RealityError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }
}
