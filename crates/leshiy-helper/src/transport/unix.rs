//! Unix domain socket transport (Linux + macOS). The peer is authorized by uid
//! (`auth::peer_uid`: `SO_PEERCRED` on Linux, `getpeereid` on macOS) against `allow_uid`.
use crate::auth::{authorize, peer_uid};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};

/// Canonical socket path: `/run/leshiy` on Linux, `/var/run/leshiy` on macOS.
pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/leshiy/helper.sock")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/run/leshiy/helper.sock")
    }
}

/// Bind the listener and restrict the socket to `allow_uid` (owner `allow_uid`, mode 0600),
/// so only that unprivileged user can connect (the helper itself runs as root).
pub fn bind(path: &Path, allow_uid: u32) -> std::io::Result<UnixListener> {
    let _ = std::fs::remove_file(path); // unlink stale
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    // Defense-in-depth: when the helper is root (production), hand the socket to the
    // unprivileged caller so only it can open it. Best-effort — a non-root helper (tests)
    // can't chown to another uid; the `peer_uid` check in `accept` is the real auth gate.
    let _ = nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(allow_uid)), None);
    Ok(listener)
}

/// Accept one connection. Returns `Some(stream)` only if the peer uid is authorized; an
/// unauthorized peer is dropped silently (`Ok(None)`) — no oracle.
pub async fn accept(
    listener: &UnixListener,
    allow_uid: u32,
) -> std::io::Result<Option<UnixStream>> {
    let (conn, _) = listener.accept().await?;
    match peer_uid(&conn) {
        Ok(uid) if authorize(uid, allow_uid) => Ok(Some(conn)),
        _ => Ok(None),
    }
}

/// Connect a client to the socket.
pub async fn connect(path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(path).await
}
