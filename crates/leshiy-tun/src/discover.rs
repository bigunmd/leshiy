//! Pre-session network discovery: the original default gateway, captured *before* any
//! routing change, so the server-IP exception can point at it.
//!
//! Desktop-only: it reads the live routing table via `net-route`. On Android (and any other
//! non-desktop target) there is no `net-route` and no notion of a "default gateway" to capture —
//! `VpnService` owns routing — so a stub is provided that is never called on that path.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod imp {
    use net_route::Handle;
    use std::net::IpAddr;

    /// The current IPv4 default gateway. Reads the live routing table; call this before
    /// installing the tunnel's override routes.
    pub async fn default_gateway_v4() -> std::io::Result<IpAddr> {
        default_gateway(false).await
    }

    /// The current IPv6 default gateway (for reaching an IPv6 server / v6 split-tunnel bypass).
    pub async fn default_gateway_v6() -> std::io::Result<IpAddr> {
        default_gateway(true).await
    }

    async fn default_gateway(v6: bool) -> std::io::Result<IpAddr> {
        let handle = Handle::new()?;
        for r in handle.list().await? {
            if r.prefix == 0
                && r.destination.is_ipv6() == v6
                && let Some(gw) = r.gateway
                && gw.is_ipv6() == v6
            {
                return Ok(gw);
            }
        }
        Err(std::io::Error::other(if v6 {
            "no IPv6 default gateway found"
        } else {
            "no IPv4 default gateway found"
        }))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod imp {
    use std::net::IpAddr;

    /// Stub for targets without `net-route` (e.g. Android, where `VpnService` owns routing). The
    /// engine's Android path builds its `TunConfig` without gateway discovery, so these are never
    /// reached; they exist only so the crate compiles for the Android NDK.
    pub async fn default_gateway_v4() -> std::io::Result<IpAddr> {
        unsupported()
    }
    pub async fn default_gateway_v6() -> std::io::Result<IpAddr> {
        unsupported()
    }
    fn unsupported() -> std::io::Result<IpAddr> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "default gateway discovery is not supported on this platform (routing is owned by the OS VPN service)",
        ))
    }
}

pub use imp::{default_gateway_v4, default_gateway_v6};
