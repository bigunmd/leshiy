use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise error: {0}")]
    Noise(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("frame too large: {0} bytes (max {max})", max = crate::frame::MAX_PLAINTEXT)]
    FrameTooLarge(usize),
    #[error("version negotiation failed: {0}")]
    Version(String),
    #[error("connection closed")]
    Closed,
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::Noise(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
