use thiserror::Error;

/// Errors surfaced across the FFI boundary to Kotlin/Swift.
#[derive(Debug, Error, uniffi::Error)]
pub enum BridgeError {
    #[error("bad uri: {reason}")]
    BadUri { reason: String },
    #[error("no tun fd injected")]
    NoTunFd,
    #[error("bridge already running")]
    AlreadyRunning,
    #[error("bridge not running")]
    NotRunning,
    #[error("profile store: {reason}")]
    Store { reason: String },
    #[error("no such profile")]
    NoSuchProfile,
}
