//! Windows named-pipe transport.
//!
//! **Security (fail-closed).** A named pipe created with the OS default security descriptor
//! is openable by any process in the session — there is no peer authorization, unlike the
//! Unix `peer_uid` gate. So the server side is **not yet enabled**: `serve` refuses to start
//! until Phase B (ADR-0029) creates the pipe from an explicit `SECURITY_ATTRIBUTES` (DACL
//! scoped to `allow.sid` + a mandatory-integrity label) AND verifies the connecting client's
//! token SID. The client side (`connect`) is safe to ship.
use crate::runner::VpnRunner;
use crate::server::{Auth, ServeMode};
use crate::transport::Endpoint;
use std::sync::Arc;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

/// Serve the control channel over a named pipe.
///
/// **Currently fails closed.** Authorizing the caller on Windows requires an explicit pipe
/// security descriptor scoped to `allow.sid` plus a client-token SID check (Phase B /
/// ADR-0029). Until that lands, we refuse to start rather than accept unauthenticated
/// connections (a default-security pipe would be an auth bypass).
pub async fn serve(
    _endpoint: &Endpoint,
    _runner: Arc<dyn VpnRunner>,
    _allow: Auth,
    _mode: ServeMode,
) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "windows VPN helper not yet enabled: the named-pipe security descriptor + client-SID \
         authorization (ADR-0029) are not implemented, and we refuse to serve an \
         unauthenticated pipe",
    ))
}

/// Connect a client to the named pipe, retrying briefly while the server is busy creating
/// the next instance (`ERROR_PIPE_BUSY` = 231).
pub async fn connect(name: &str) -> std::io::Result<NamedPipeClient> {
    loop {
        match ClientOptions::new().open(name) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(231) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}
