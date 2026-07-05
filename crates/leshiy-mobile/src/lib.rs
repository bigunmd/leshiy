//! Mobile bridge: drives the leshiy REALITY tunnel over a VpnService-provided TUN fd,
//! exposed to Kotlin/Swift via UniFFI.
#![forbid(unsafe_code)]

mod bridge;
mod error;
mod profiles;
mod runtime;
mod status;

pub use bridge::{LeshiyBridge, StatusListener};
pub use error::BridgeError;
pub use profiles::{ProfileInfo, ProfileManager};
pub use status::{ConnState, Status};

uniffi::setup_scaffolding!();
