#![forbid(unsafe_code)]
//! Leshiy core protocol: handshake, framing, version negotiation, mux.

pub mod error;
pub mod frame;
pub mod handshake;
pub mod mux;
// Android-only: a registry for the `VpnService.protect(fd)` callback, so the outbound tunnel
// socket bypasses the VPN (no loop). Lives here because it's the dependency sink shared by the
// reality/quic dial crates. No-op (absent) on every other platform.
#[cfg(target_os = "android")]
pub mod protect;
pub mod session;
pub mod transport;
pub mod version;

pub use error::{Error, Result};
pub use transport::{FrameRead, FrameWrite};
