#![forbid(unsafe_code)]
//! REALITY-style auth + prober passthrough for Leshiy (server front door + client embed).
pub mod auth;
pub mod client;
pub mod config;
pub mod control;
pub mod error;
pub mod handshake;
pub mod netguard;
pub mod ratelimit;
pub mod server;
pub mod sqlite_store;
pub mod tunnel;
pub mod user;

pub use error::{RealityError, Result};
