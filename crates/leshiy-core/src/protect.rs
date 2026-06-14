//! Android socket-protect seam.
//!
//! On Android the app's tunnel runs inside a `VpnService`, which captures *all* of the app's
//! sockets by default — including the very socket we use to reach the VPN server, which would
//! loop traffic back into the tunnel and deadlock. `VpnService.protect(fd)` exempts a socket so
//! it egresses the underlying physical network instead.
//!
//! The dial crates ([`leshiy-reality`], [`leshiy-quic`]) live below the platform layer and can't
//! call the Kotlin service directly, so the mobile bridge registers a callback here once at
//! startup ([`set_protect`]); the dial path calls [`protect_fd`] on each outbound socket's fd
//! *before* connecting. If no callback is registered (e.g. running the dial off-device in a
//! test), `protect_fd` is a no-op returning `false`.
use std::os::fd::RawFd;
use std::sync::OnceLock;

/// Callback that calls `VpnService.protect(fd)`; returns whether protection succeeded.
type ProtectFn = Box<dyn Fn(RawFd) -> bool + Send + Sync>;

static PROTECT: OnceLock<ProtectFn> = OnceLock::new();

/// Register the protect callback (the mobile bridge does this once, before the first dial).
/// Subsequent calls are ignored (the first registration wins).
pub fn set_protect(f: ProtectFn) {
    let _ = PROTECT.set(f);
}

/// Protect a socket fd from the VPN so it routes over the physical network. Returns `false` if
/// no callback is registered or the OS call failed; callers proceed regardless (best-effort).
pub fn protect_fd(fd: RawFd) -> bool {
    PROTECT.get().map(|f| f(fd)).unwrap_or(false)
}
