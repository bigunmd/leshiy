//! Non-Linux placeholder. Windows (Wintun) and macOS (utun) backends land in Phase 3;
//! until then the engine refuses to start on those platforms rather than misbehaving.
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
    ) -> std::io::Result<TunSession> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "VPN mode is Linux-only in this phase (Windows/macOS land in Phase 3)",
        ))
    }
}
