#![forbid(unsafe_code)]
//! Leshiy privileged VPN helper: an authenticated Unix-socket control daemon that owns
//! the TUN/route/DNS lifecycle on behalf of an unprivileged caller (CLI today, the
//! desktop GUI in Phase 5).
//!
//! The control protocol mirrors `leshiy-reality`'s control socket: newline-delimited
//! JSON over a Unix socket, with per-connection peer-uid authorization. The helper runs
//! the full `TunEngine` in-process (the spec's allowed engine-in-helper model); fd-passing
//! (`SCM_RIGHTS`) to keep keys unprivileged is future hardening.
//!
//! **Platform support:** the daemon side (control server, `EngineRunner`, peer-uid auth)
//! is Unix-only — it relies on Unix domain sockets and `SO_PEERCRED`/`getpeereid`. Those
//! modules are gated to `cfg(unix)`. The protocol types, the install probe, and the
//! `HelperClient` caller API are cross-platform; on non-Unix `HelperClient`'s calls return
//! an "unsupported platform" error so the desktop app still builds (Windows VPN-via-helper
//! is a documented follow-up: named pipes + ACL/signature auth).
#[cfg(unix)]
pub mod auth;
pub mod client;
pub mod error;
mod install;
pub mod proto;
#[cfg(unix)]
pub mod runner;
#[cfg(unix)]
pub mod server;
pub use client::HelperClient;
pub use error::HelperError;
pub use install::{default_socket_path, is_installed};
pub use proto::{Event, Request, Response, StartParams, Status};
#[cfg(unix)]
pub use runner::{EngineRunner, VpnRunner};
#[cfg(unix)]
pub use server::serve_control;

// Re-exported so callers speak the same state/stats vocabulary as the supervisor.
pub use leshiy_client::{Rates, State};
