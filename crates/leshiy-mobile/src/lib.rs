//! Mobile bridge: drives the leshiy REALITY tunnel over a VpnService-provided TUN fd,
//! exposed to Kotlin/Swift via UniFFI.
#![forbid(unsafe_code)]

mod bridge;
mod dns;
mod error;
mod profiles;
mod provision;
mod release_sig;
mod runtime;
mod server;
mod status;

pub use bridge::{LeshiyBridge, StatusListener};
pub use error::BridgeError;
pub use profiles::{ProfileInfo, ProfileManager};
pub use provision::{
    ProvisionConfig, ProvisionListener, ProvisionUpdate, Provisioner, default_image_ref,
};
pub use release_sig::verify_release_checksums;
pub use server::{RemoteUserInfo, ServerInfo, ServerManager};
pub use status::{ConnState, Status};

uniffi::setup_scaffolding!();
