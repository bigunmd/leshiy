use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("truncated: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },
    #[error("unexpected content type {0:#04x}")]
    UnexpectedContentType(u8),
    #[error("tls alert received (level {level}, desc {desc})")]
    Alert { level: u8, desc: u8 },
}

pub type Result<T> = std::result::Result<T, TlsError>;
