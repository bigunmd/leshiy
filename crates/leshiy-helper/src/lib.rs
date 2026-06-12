#![cfg_attr(not(windows), forbid(unsafe_code))]
//! Leshiy privileged VPN helper: an authenticated control daemon that owns the TUN/route/DNS
//! lifecycle on behalf of an unprivileged caller (CLI today, the desktop GUI).
//!
//! The control protocol is newline-delimited JSON; framing/dispatch is generic over
//! `AsyncRead + AsyncWrite`, with a per-OS [`transport`]: a Unix domain socket on Linux+macOS
//! (peer authorized by uid via `SO_PEERCRED`/`getpeereid`), or a Windows named pipe with an
//! explicit security descriptor scoped to the launching user's SID (ADR-0029). The helper runs
//! the full `TunEngine` in-process (the spec's allowed engine-in-helper model); fd-passing
//! (`SCM_RIGHTS`) to keep keys unprivileged is future hardening.
//!
//! The daemon is launched with privilege (root/`CAP_NET_ADMIN` on Unix, UAC-elevated on
//! Windows). On Win/macOS the GUI launches it on demand (`run --ephemeral`); on Linux it is
//! installed (setcap/systemd). The crate is `#![forbid(unsafe_code)]` everywhere except the
//! Windows pipe security descriptor (ADR-0029), which is the only audited `unsafe`.
#[cfg(unix)]
pub mod auth;
pub mod client;
pub mod elevate;
pub mod error;
mod install;
pub mod proto;
pub mod runner;
pub mod server;
pub mod transport;

pub use client::HelperClient;
pub use error::HelperError;
pub use install::{default_endpoint, default_socket_path, is_installed};
pub use proto::{Event, Request, Response, StartParams, Status};
pub use runner::{EngineRunner, VpnRunner};
pub use server::{Auth, ServeMode, serve_control};
pub use transport::Endpoint;

// Re-exported so callers speak the same state/stats vocabulary as the supervisor.
pub use leshiy_client::{Rates, State};
