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
}

pub type Result<T> = std::result::Result<T, QuicError>;
