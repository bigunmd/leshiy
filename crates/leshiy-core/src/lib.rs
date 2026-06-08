#![forbid(unsafe_code)]
//! Leshiy core protocol: handshake, framing, version negotiation, mux.

pub mod error;
pub mod frame;
pub mod handshake;
pub mod mux;
pub mod session;
pub mod transport;
pub mod version;

pub use error::{Error, Result};
pub use transport::{FrameRead, FrameWrite};
