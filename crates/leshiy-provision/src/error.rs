//! Crate-wide error type.

/// Result alias used throughout `leshiy-provision`.
pub type Result<T> = std::result::Result<T, Error>;

/// All failure modes surfaced by the provisioning engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh: {0}")]
    Ssh(String),
    #[error("remote command failed (exit {code}): {stderr}")]
    Command { code: i32, stderr: String },
    #[error("vault: {0}")]
    Vault(String),
    #[error("host key mismatch for {host}: pinned {pinned}, got {seen}")]
    HostKeyMismatch {
        host: String,
        pinned: String,
        seen: String,
    },
    #[error("parse: {0}")]
    Parse(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
