//! Fallback for exotic targets only. Linux, macOS (utun), Windows (Wintun), and Android
//! (`VpnService`) all have real backends; this stub covers any other OS by refusing to start
//! rather than misbehaving.
use super::{PrivilegedOps, TunSession};
use crate::route_plan::RoutePlan;
use std::net::IpAddr;

pub struct StubOps;

#[async_trait::async_trait]
impl PrivilegedOps for StubOps {
    async fn start(
        &self,
        _tun_name: &str,
        _mtu: u16,
        _plan: &RoutePlan,
        _dns: &[IpAddr],
        _force_dns: bool,
        _ipv6_killswitch: bool,
    ) -> std::io::Result<TunSession> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "VPN mode is unsupported on this platform",
        ))
    }
}
