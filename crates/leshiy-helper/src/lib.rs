#![forbid(unsafe_code)]
//! Leshiy privileged VPN helper: an authenticated Unix-socket control daemon that owns
//! the TUN/route/DNS lifecycle on behalf of an unprivileged caller (CLI today, the
//! desktop GUI in Phase 5).
//!
//! The control protocol mirrors `leshiy-reality`'s control socket: newline-delimited
//! JSON over a Unix socket, with per-connection `SO_PEERCRED` uid authorization. The
//! helper runs the full `TunEngine` in-process (the spec's allowed engine-in-helper
//! model); fd-passing (`SCM_RIGHTS`) to keep keys unprivileged is future hardening.
//!
pub mod error;
pub use error::HelperError;
