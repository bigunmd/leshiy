//! Minimal `sd_notify` client, so a unit can be `Type=notify`.
//!
//! This is what makes `leshiy service start` honest: systemd blocks until we send
//! `READY=1`, and reports failure if we never do. Without it the only options are
//! `Type=exec` (proves the process launched, not that the tunnel connected) or dialing
//! twice — once to check, once in the service — which is both wasteful and racy, since
//! the check can succeed and the service's own dial still fail.
//!
//! Implemented against `std` alone; the protocol is one datagram of newline-separated
//! `KEY=VALUE` pairs to the `AF_UNIX` socket named by `$NOTIFY_SOCKET`.

use std::os::unix::net::UnixDatagram;

/// Report to systemd, if we are running under it. A missing `$NOTIFY_SOCKET` means we are
/// not, so every function here is a no-op in a normal foreground run.
fn notify(payload: &str) {
    let Some(addr) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let addr = std::path::PathBuf::from(addr);
    let Ok(sock) = UnixDatagram::unbound() else {
        return;
    };

    // A leading '@' selects the abstract namespace, which has no filesystem entry and so
    // cannot be addressed by path. Modern systemd usually passes a real path, but the
    // abstract form is still legal and silently unsupported by `send_to`.
    let bytes = addr.as_os_str().as_encoded_bytes();
    let sent = if let Some(name) = bytes.strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        std::os::unix::net::SocketAddr::from_abstract_name(name)
            .and_then(|a| sock.send_to_addr(payload.as_bytes(), &a))
    } else {
        sock.send_to(payload.as_bytes(), &addr)
    };
    if let Err(e) = sent {
        tracing::debug!(error = %e, "sd_notify failed");
    }
}

/// Announce that start-up finished and the service is genuinely usable.
pub fn ready(status: &str) {
    notify(&format!("READY=1\nSTATUS={status}\n"));
}

/// Announce that teardown has begun, so systemd does not treat the delay as a hang.
pub fn stopping() {
    notify("STOPPING=1\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NOTIFY_SOCKET` is process-global, so both cases live in one test: run in
    /// parallel, one would clear the variable while the other was mid-send.
    #[test]
    fn noop_without_socket_then_delivers_ready_with_one() {
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        ready("connected");
        stopping();

        let dir = std::env::temp_dir().join(format!("leshiy-sdn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();

        unsafe { std::env::set_var("NOTIFY_SOCKET", &path) };
        ready("connected");
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };

        let mut buf = [0u8; 256];
        let n = listener.recv(&mut buf).unwrap();
        let got = String::from_utf8_lossy(&buf[..n]);
        assert!(got.contains("READY=1"), "{got}");
        assert!(got.contains("STATUS=connected"), "{got}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
