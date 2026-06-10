//! Real transport adapters bridging the Plan 2 trait seams (`Transport`/`Tunnel`/
//! `ProxyStream`) to `leshiy-reality` and `leshiy-quic`.
pub mod reality;

pub use reality::RealityTunnel;
