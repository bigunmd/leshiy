//! Privileged OS operations: create the TUN device, install/restore routes & DNS, and
//! (Linux) a fail-closed IPv6 kill-switch. Implementations require the process to already
//! hold privilege (root / `CAP_NET_ADMIN`) — this crate grants none of its own.
use crate::route_plan::{Cidr, RoutePlan};
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxOps as PlatformOps;

// Compiled on the macOS target AND under host `test`, so the backend is type-checked on
// the Linux build box (this box can't cross-`check` for macOS — `ring`'s C build needs an
// Apple SDK). It only *runs* on macOS; the `#[ignore]`d smoke is macOS-gated. The module
// carries `#![cfg_attr(not(target_os = "macos"), allow(dead_code))]` so the host-test
// compile doesn't flag the (host-unused) `MacOsOps` as dead.
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOsOps as PlatformOps;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsOps as PlatformOps;

// Android: the TUN fd is created by the OS `VpnService` (routing/DNS owned by it). The backend
// just wraps that fd; no `net-route`, no privilege elevation. The fd is injected via
// `android::set_tun_fd` by the mobile bridge before the engine starts.
#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::AndroidOps as PlatformOps;
#[cfg(target_os = "android")]
pub use android::{set_tun_fd, take_tun_fd};

// Shared command runner + pure argument-builders for the macOS + Windows backends.
// Gated to also compile under `test` so the pure builders (and their unit tests) run on
// the Linux host via `cargo test` — the privileged glue in macos.rs/windows.rs stays
// OS-gated, but the OS-independent argument construction is host-verifiable.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
mod cmd;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
)))]
mod stub;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
)))]
pub use stub::StubOps as PlatformOps;

/// An opened TUN device plus an RAII guard that restores DNS / IPv6 state on drop, and a
/// [`RouteController`] for runtime route mutation (split-tunnel domain rules).
///
/// `via_tun` (default-override / include) routes auto-clear when the device closes, but
/// **`bypass` routes point at the original gateway and do NOT** — so the `guard`'s `Drop`
/// must explicitly remove any bypass routes it installed (true even on a hard abort).
pub struct TunSession {
    pub device: tun::AsyncDevice,
    pub guard: Box<dyn Send>,
    /// Lives as long as the session; the domain-resolver task (Phase B) uses it to add/remove
    /// routes for resolved domains. A `NullController` until a backend provides a live one.
    pub controller: Arc<dyn RouteController>,
}

#[async_trait::async_trait]
pub trait PrivilegedOps: Send + Sync {
    /// Whether this backend actually carries IPv6 *through* the tunnel (assigns a v6 TUN
    /// address and installs v6 routes). Defaults to `false`: a backend that hasn't implemented
    /// v6 leaves it here, and the engine then zeroes `tun_addr6` so IPv6 is fail-closed by the
    /// kill-switch instead of leaking around a v6-unaware backend. Overridden to `true` by
    /// backends that carry v6 (Linux, macOS).
    const CARRIES_V6: bool = false;

    /// Create + configure the TUN device, apply the route plan + DNS + IPv6 policy, and
    /// return a session whose drop restores the prior network state.
    ///
    /// `force_dns` / `ipv6_killswitch` gate the DNS override and the IPv6 fail-closed
    /// kill-switch: both are on for full-tunnel / Exclude mode (today's behavior) and off for
    /// Include mode (where most traffic is direct, so changing the system resolver / disabling
    /// IPv6 would break the un-tunneled majority).
    async fn start(
        &self,
        tun_name: &str,
        mtu: u16,
        plan: &RoutePlan,
        dns: &[IpAddr],
        force_dns: bool,
        ipv6_killswitch: bool,
    ) -> std::io::Result<TunSession>;
}

/// Runtime route mutation for split-tunnel **domain** rules (resolved IPs added/removed while
/// the session is live). Exclude mode mutates orig-gateway `bypass` routes; Include mode
/// mutates tun-interface `via_tun` routes — the resolver picks which based on the plan's mode.
#[async_trait::async_trait]
pub trait RouteController: Send + Sync {
    async fn add_bypass(&self, cidr: &Cidr) -> std::io::Result<()>;
    async fn remove_bypass(&self, cidr: &Cidr) -> std::io::Result<()>;
    async fn add_via_tun(&self, cidr: &Cidr) -> std::io::Result<()>;
    async fn remove_via_tun(&self, cidr: &Cidr) -> std::io::Result<()>;

    /// Bulk-remove ALL installed bypass routes in-process (via the OS routing API), clearing the
    /// shared tracking list. The engine calls this on graceful shutdown BEFORE dropping the RAII
    /// guard — so a large rule set is torn down with fast in-process deletes instead of falling
    /// back to the guard's per-route subprocess path (`netsh`/`route` per CIDR = thousands of
    /// process spawns = minutes, which wedges disconnect/reconnect). After this the guard's `Drop`
    /// finds an empty list and does nothing. Default: no-op (NullController; Linux, whose `Drop`
    /// already batches all deletes through a single `ip -batch` process).
    async fn teardown_bypass(&self) {}
}

/// No-op controller for sessions without runtime route control (no domain rules, the stub
/// backend, and tests). A live per-OS controller lands in Phase B.
pub struct NullController;

#[async_trait::async_trait]
impl RouteController for NullController {
    async fn add_bypass(&self, _c: &Cidr) -> std::io::Result<()> {
        Ok(())
    }
    async fn remove_bypass(&self, _c: &Cidr) -> std::io::Result<()> {
        Ok(())
    }
    async fn add_via_tun(&self, _c: &Cidr) -> std::io::Result<()> {
        Ok(())
    }
    async fn remove_via_tun(&self, _c: &Cidr) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_controller_is_noop() {
        let c = NullController;
        let cidr = Cidr {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 8,
        };
        c.add_bypass(&cidr).await.unwrap();
        c.remove_bypass(&cidr).await.unwrap();
        c.add_via_tun(&cidr).await.unwrap();
        c.remove_via_tun(&cidr).await.unwrap();
    }
}
