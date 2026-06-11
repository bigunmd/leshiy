//! macOS privileged ops: utun device (`tun` crate), routes (`net-route` + `route`),
//! DNS (`networksetup`/`scutil`), IPv6 leak mitigation (`networksetup -setv6off`),
//! all restored on teardown. Compile-checked on Linux via cross-target `cargo check`;
//! runtime-verified only on real macOS (Task 3.4 smoke).
//!
//! NOTE (Phase 3 execution, 2026-06-11): macOS implementation is DEFERRED to real Apple
//! hardware / a CI runner with the SDK — this box cannot cross-check it (`ring`'s C build
//! needs an Apple clang+SDK). This skeleton keeps the `cfg` seam complete; Tasks 3.1–3.4
//! fill it there.
use super::{PrivilegedOps, TunSession};
use crate::route_plan::RoutePlan;
use std::net::IpAddr;

pub struct MacOsOps;

#[async_trait::async_trait]
impl PrivilegedOps for MacOsOps {
    async fn start(
        &self,
        _tun_name: &str,
        _mtu: u16,
        _plan: &RoutePlan,
        _dns: &[IpAddr],
    ) -> std::io::Result<TunSession> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "macOS backend not yet implemented (Phase 3)",
        ))
    }
}
