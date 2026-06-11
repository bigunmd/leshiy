//! Privileged OS operations: create the TUN device, install/restore routes & DNS, and
//! (Linux) a fail-closed IPv6 kill-switch. Implementations require the process to already
//! hold privilege (root / `CAP_NET_ADMIN`) — this crate grants none of its own.
use crate::route_plan::RoutePlan;
use std::net::IpAddr;

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

// Shared command runner + pure argument-builders for the macOS + Windows backends.
// Gated to also compile under `test` so the pure builders (and their unit tests) run on
// the Linux host via `cargo test` — the privileged glue in macos.rs/windows.rs stays
// OS-gated, but the OS-independent argument construction is host-verifiable.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
mod cmd;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod stub;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use stub::StubOps as PlatformOps;

/// An opened TUN device plus an RAII guard that restores DNS / IPv6 state on drop. The
/// default-override routes auto-clear when the device closes, so even a hard crash can't
/// leave the host with a black-holed default route.
pub struct TunSession {
    pub device: tun::AsyncDevice,
    pub guard: Box<dyn Send>,
}

#[async_trait::async_trait]
pub trait PrivilegedOps: Send + Sync {
    /// Create + configure the TUN device, apply the route plan + DNS + IPv6 policy, and
    /// return a session whose drop restores the prior network state.
    async fn start(
        &self,
        tun_name: &str,
        mtu: u16,
        plan: &RoutePlan,
        dns: &[IpAddr],
    ) -> std::io::Result<TunSession>;
}
