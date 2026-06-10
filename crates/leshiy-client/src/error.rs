//! Crate-wide error type. Connection failures collapse to one generic variant so
//! the UI cannot become an auth/probe oracle (consistent with the silent-server ethos).

/// Errors surfaced by the client control library.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Any failure to establish a tunnel. Deliberately undifferentiated — no reason leaked.
    #[error("connection failed")]
    ConnectFailed,
    /// The supplied string is not a valid `leshiy://` config link.
    #[error("invalid config link")]
    InvalidUri,
    /// Persistence / serialization failure.
    #[error("storage error: {0}")]
    Store(String),
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, ClientError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_connect_failure_has_no_detail() {
        // The message must not vary by cause — no oracle.
        assert_eq!(ClientError::ConnectFailed.to_string(), "connection failed");
    }

    #[test]
    fn invalid_uri_has_no_detail() {
        // Symmetric to the ConnectFailed test: the message must not vary by cause.
        assert_eq!(ClientError::InvalidUri.to_string(), "invalid config link");
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let err: ClientError = io.into();
        assert!(matches!(err, ClientError::Io(_)));
    }
}
