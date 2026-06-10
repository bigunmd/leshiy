#![forbid(unsafe_code)]
//! REALITY-style auth + prober passthrough for Leshiy (server front door + client embed).
pub mod auth;
pub mod client;
pub mod config;
// The control socket is a Unix-domain-socket server feature (live user management).
// Gate it to Unix so the client embed (e.g. the desktop app) compiles on Windows.
#[cfg(unix)]
pub mod control;
pub mod egress;
pub mod error;
pub mod handshake;
pub mod netguard;
pub mod ratelimit;
pub mod server;
pub mod sqlite_store;
pub mod tunnel;
pub mod user;

pub use egress::{DirectEgress, Egress, EgressRead, EgressWrite};
pub use error::{RealityError, Result};
