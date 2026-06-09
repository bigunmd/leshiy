#![forbid(unsafe_code)]

pub mod client;
pub mod connector;
pub mod endpoint;
pub mod masquerade;
pub mod server;

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection: {0}")]
    Conn(String),
    #[error("protocol: {0}")]
    Protocol(String),
    /// The H3 CONNECT got a non-200 response from the peer. This is a PER-STREAM
    /// failure on a HEALTHY connection (e.g. the Exit's egress replied 502) — it must
    /// NOT trigger a connection-level reconnect.
    #[error("connect status {0}")]
    ConnectStatus(u16),
}

pub type Result<T> = std::result::Result<T, QuicError>;
