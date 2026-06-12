//! Control-channel transport seam. A Unix domain socket on Linux+macOS (peer authorized by
//! uid), or a Windows named pipe with an explicit security descriptor (ADR-0029). The
//! protocol framing/dispatch in `server.rs` is generic over the stream type; only listening,
//! connecting, and per-connection authorization live here.

/// Where the control channel lives. `Socket` on Unix; `Pipe` on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Unix domain socket path (Linux + macOS).
    #[cfg(unix)]
    Socket(std::path::PathBuf),
    /// Windows named pipe name (e.g. `\\.\pipe\leshiy-helper`).
    #[cfg(windows)]
    Pipe(String),
}

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;
