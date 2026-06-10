//! Leshiy desktop client control library (GUI-agnostic).
//!
//! Plan 1 scope: typed errors, persisted profiles, persisted settings, and
//! throughput accounting. Networking (tunnel engine, system proxy, supervisor)
//! arrives in Plan 2.
#![forbid(unsafe_code)]

pub mod error;
pub mod profile;
pub mod settings;
pub mod stats;
pub mod stream;
pub mod transport;

pub use error::{ClientError, Result};
pub use profile::{Profile, ProfileStore};
pub use settings::{Settings, TransportPref};
pub use stats::{ByteCounters, Rates, Throughput};
pub use stream::ProxyStream;
pub use transport::{Transport, Tunnel};
