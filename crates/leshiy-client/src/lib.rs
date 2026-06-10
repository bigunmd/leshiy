//! Leshiy desktop client control library (GUI-agnostic).
//!
//! Provides the data + stats core (typed errors, persisted profiles and settings,
//! throughput accounting) and the tunnel engine's functional core: the
//! [`ProxyStream`]/[`Tunnel`]/[`Transport`]/[`SystemProxy`] seams, the metered
//! byte-[`pump()`], and the pure supervisor state [`Machine`]. The real REALITY/QUIC
//! adapters, the async supervisor shell, and the per-OS system-proxy implementations
//! land in later plans.
#![forbid(unsafe_code)]

pub mod adapter;
pub mod error;
pub mod listener;
pub mod profile;
pub mod pump;
pub mod runtime;
pub mod settings;
pub mod stats;
pub mod stream;
pub mod supervisor;
pub mod sysproxy;
pub mod transport;

pub use adapter::{QuicTunnel, RealTransport, RealityTunnel};
pub use error::{ClientError, Result};
pub use listener::serve_metered;
pub use profile::{Profile, ProfileStore};
pub use pump::pump;
pub use runtime::{SupervisorConfig, SupervisorHandle, spawn_supervisor};
pub use settings::{Settings, TransportPref};
pub use stats::{ByteCounters, Rates, Throughput};
pub use stream::ProxyStream;
pub use supervisor::{Action, Input, Machine, State, backoff_delay};
pub use sysproxy::{NoopProxy, SystemProxy};
pub use transport::{Transport, Tunnel};
