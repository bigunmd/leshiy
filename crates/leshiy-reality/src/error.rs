use thiserror::Error;

#[derive(Error, Debug)]
pub enum RealityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls parse: {0}")]
    Tls(#[from] leshiy_tls::TlsError),
    #[error("malformed client hello: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, RealityError>;
