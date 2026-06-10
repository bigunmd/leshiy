//! Leshiy desktop client control library (GUI-agnostic).
//!
//! Plan 1 scope: typed errors, persisted profiles, persisted settings, and
//! throughput accounting. Networking (tunnel engine, system proxy, supervisor)
//! arrives in Plan 2.
#![forbid(unsafe_code)]

pub mod error;
pub mod settings;
pub mod stats;

pub use error::{ClientError, Result};
pub use settings::{Settings, TransportPref};
pub use stats::{ByteCounters, Rates, Throughput};
