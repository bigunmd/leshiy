//! Android privileged ops: there are none. On Android the TUN interface is created and fully
//! configured (address, routes, DNS, MTU, per-app rules) by the system `VpnService.Builder`;
//! `VpnService.establish()` hands back a file descriptor. This backend just wraps that fd as a
//! `tun::AsyncDevice` (the `tun` crate's `raw_fd` path, `src/platform/android/`) so the shared
//! `ipstack` → `TunEngine` pipeline runs unchanged. No routing, no DNS, no IPv6 work happens
//! here — `RoutePlan`/`dns`/`force_dns`/`ipv6_killswitch` are owned by the Kotlin service and
//! ignored. There is also no privileged route mutation, so the controller is a `NullController`.
//!
//! The fd is injected out-of-band via [`set_tun_fd`] by the mobile bridge immediately before the
//! engine starts (one session per process), and consumed once by [`AndroidOps::start`].
use super::{NullController, PrivilegedOps, TunSession};
use crate::route_plan::RoutePlan;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

/// The TUN fd from `VpnService.establish()`, parked here by the bridge for `AndroidOps::start`.
/// The Kotlin side transfers ownership (`ParcelFileDescriptor.detachFd()`), so Rust closes it
/// when the device drops (`close_fd_on_drop(true)`).
static TUN_FD: Mutex<Option<RawFd>> = Mutex::new(None);

/// Inject the VpnService-provided TUN fd. Call exactly once, right before starting the engine.
pub fn set_tun_fd(fd: RawFd) {
    *TUN_FD.lock().unwrap() = Some(fd);
}

/// Take the injected TUN fd (consuming it). Returns `None` if none was set.
pub fn take_tun_fd() -> Option<RawFd> {
    TUN_FD.lock().unwrap().take()
}

pub struct AndroidOps;

#[async_trait::async_trait]
impl PrivilegedOps for AndroidOps {
    async fn start(
        &self,
        _tun_name: &str,
        _mtu: u16,
        _plan: &RoutePlan,
        _dns: &[IpAddr],
        _force_dns: bool,
        _ipv6_killswitch: bool,
    ) -> std::io::Result<TunSession> {
        Ok(TunSession {
            device: device_from_injected_fd("start")?,
            guard: Box::new(()), // VpnService owns routes/DNS; nothing to restore here.
            controller: Arc::new(NullController),
        })
    }

    /// Pick up the fd from a fresh `VpnService.Builder.establish()` — the only way to change an
    /// Android VPN's routes, since they are immutable once established. The old device is already
    /// dropped by the caller (closing its fd, as the platform requires); routes and DNS belong to
    /// the OS here, so there is no session state to rebuild.
    async fn reattach_device(&self) -> std::io::Result<tun::AsyncDevice> {
        device_from_injected_fd("reattach")
    }
}

/// Wrap the injected `VpnService` fd as an async TUN device. The `tun` crate's Android path uses
/// the fd directly (no ioctl/up). We own it (Kotlin detached it), so close it on drop — that is
/// both what the platform requires of a superseded interface and what unblocks the reader on stop.
fn device_from_injected_fd(what: &str) -> std::io::Result<tun::AsyncDevice> {
    let fd = take_tun_fd().ok_or_else(|| {
        std::io::Error::other(format!(
            "no VpnService TUN fd was injected before {what} (set_tun_fd)"
        ))
    })?;
    let mut cfg = tun::Configuration::default();
    cfg.raw_fd(fd).close_fd_on_drop(true);
    tun::create_as_async(&cfg).map_err(to_io)
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
