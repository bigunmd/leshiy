//! Windows privileged ops: Wintun device (`tun` crate; requires `wintun.dll` beside the
//! binary), routes (`net-route` + `netsh`), DNS (`netsh`), smart-multi-homed-resolution
//! disable, IPv6 leak mitigation, all restored on teardown. Compile-checked on Linux via
//! cross-target `cargo check`; runtime-verified only on real Windows (Task 3.8 smoke).
use super::{PrivilegedOps, TunSession};
use crate::route_plan::RoutePlan;
use std::net::IpAddr;

pub struct WindowsOps;

#[async_trait::async_trait]
impl PrivilegedOps for WindowsOps {
    async fn start(
        &self,
        _tun_name: &str,
        _mtu: u16,
        _plan: &RoutePlan,
        _dns: &[IpAddr],
    ) -> std::io::Result<TunSession> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Windows backend not yet implemented (Phase 3)",
        ))
    }
}
