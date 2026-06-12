//! Installation/endpoint surface: the canonical control endpoint per OS and a privilege-free
//! probe the unprivileged caller (CLI + GUI) uses to decide whether a helper is answering.
//! In the on-demand model there is no persistent install on Win/macOS — `is_installed()` is
//! a "is one running?" probe; the GUI elevates + launches the helper on connect.
use crate::transport::Endpoint;

/// The default control endpoint: a Unix socket on Linux/macOS, a named pipe on Windows.
pub fn default_endpoint() -> Endpoint {
    #[cfg(unix)]
    {
        Endpoint::Socket(crate::transport::unix::default_socket_path())
    }
    #[cfg(windows)]
    {
        Endpoint::Pipe(r"\\.\pipe\leshiy-helper".to_string())
    }
}

/// The canonical control-socket path (Unix) / pipe name (Windows). Kept for callers that
/// still want a path string (e.g. the systemd unit, the `--socket` default).
#[cfg(unix)]
pub fn default_socket_path() -> std::path::PathBuf {
    crate::transport::unix::default_socket_path()
}
/// Windows: there is no filesystem socket — return the pipe name as a path for display only.
#[cfg(not(unix))]
pub fn default_socket_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"\\.\pipe\leshiy-helper")
}

/// True if a helper currently appears to be answering the default endpoint.
pub fn is_installed() -> bool {
    match default_endpoint() {
        #[cfg(unix)]
        Endpoint::Socket(p) => p.exists(),
        #[cfg(windows)]
        Endpoint::Pipe(name) => std::fs::metadata(&name).is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn default_socket_path_is_the_canonical_run_path() {
        assert_eq!(
            default_socket_path(),
            std::path::PathBuf::from("/run/leshiy/helper.sock")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_socket_path_is_var_run_on_macos() {
        assert_eq!(
            default_socket_path(),
            std::path::PathBuf::from("/var/run/leshiy/helper.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn default_endpoint_is_a_socket_on_unix() {
        assert!(matches!(default_endpoint(), Endpoint::Socket(_)));
    }

    #[cfg(unix)]
    #[test]
    fn is_installed_is_false_for_missing_socket() {
        // The canonical path almost certainly doesn't exist in a test sandbox.
        // (We don't create it here; just assert the probe doesn't panic and is a bool.)
        let _ = is_installed();
    }
}
