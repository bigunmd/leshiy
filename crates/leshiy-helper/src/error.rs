//! Helper error type. Mirrors `leshiy-client`'s thiserror style; auth failures are a
//! single undifferentiated variant so a peer learns nothing from a rejection.

/// Errors surfaced by the helper library and returned to callers as `Response::Err`.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// The connecting peer's uid is not the allowed uid. The peer is told nothing
    /// beyond this generic word (the connection is simply closed server-side).
    #[error("unauthorized")]
    Unauthorized,
    /// `StartVpn` was requested while a session is already active.
    #[error("a VPN session is already running")]
    AlreadyRunning,
    /// The supplied request could not be parsed as JSON.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// The TUN engine / tunnel build failed.
    #[error("engine error: {0}")]
    Engine(String),
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_stable() {
        assert_eq!(HelperError::Unauthorized.to_string(), "unauthorized");
        assert_eq!(
            HelperError::AlreadyRunning.to_string(),
            "a VPN session is already running"
        );
        let e = HelperError::Engine("boom".into());
        assert_eq!(e.to_string(), "engine error: boom");
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let err: HelperError = io.into();
        assert!(matches!(err, HelperError::Io(_)));
    }
}
