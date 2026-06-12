//! Windows named-pipe transport.
//!
//! **Phase A (this file):** safe named-pipe plumbing using the OS default security
//! descriptor. This works when the GUI and helper run at the **same** integrity level.
//! **Phase B (ADR-0029):** replace `ServerOptions::create` with a pipe created from an
//! explicit `SECURITY_ATTRIBUTES` (DACL scoped to the launching user's SID + a medium
//! mandatory integrity label) so an unprivileged medium-IL GUI can open the pipe served by
//! the UAC-elevated high-IL helper. That is the crate's only `unsafe`.
use crate::runner::VpnRunner;
use crate::server::{Auth, ServeMode, handle_stream, session_ended};
use crate::transport::Endpoint;
use std::sync::Arc;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};

/// Serve the control channel over a named pipe. Phase A uses default pipe security; Phase B
/// will scope it to `allow.sid` with a medium IL label.
pub async fn serve(
    endpoint: &Endpoint,
    runner: Arc<dyn VpnRunner>,
    _allow: Auth,
    mode: ServeMode,
) -> std::io::Result<()> {
    let Endpoint::Pipe(name) = endpoint;
    let mut ever_connected = false;
    let mut first = true;
    loop {
        // Phase B replaces this with a pipe built from a user-SID security descriptor.
        let server = ServerOptions::new()
            .first_pipe_instance(first)
            .create(name)?;
        first = false;
        server.connect().await?;
        match mode {
            ServeMode::Persistent => {
                let runner = runner.clone();
                tokio::spawn(async move {
                    let _ = handle_stream(server, runner).await;
                });
            }
            ServeMode::Ephemeral => {
                handle_stream(server, runner.clone()).await?;
                if session_ended(runner.as_ref(), &mut ever_connected) {
                    return Ok(());
                }
            }
        }
    }
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
