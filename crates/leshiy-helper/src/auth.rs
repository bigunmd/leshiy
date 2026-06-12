//! Control-socket authorization. `authorize` is the pure, security-critical decision;
//! `peer_uid` extracts the connecting peer's uid from the kernel: `SO_PEERCRED` on Linux,
//! `getpeereid` on macOS/BSD. On any mismatch the server closes the connection silently
//! (no oracle to the peer). Unix-only (the module is gated `cfg(unix)` in `lib.rs`).
use std::os::fd::AsFd;
use tokio::net::UnixStream;

/// Authorize a connection: the peer uid must exactly equal the configured allowed uid.
/// Root (uid 0) is **not** special-cased — it is allowed only when `allowed_uid == 0`.
pub fn authorize(peer_uid: u32, allowed_uid: u32) -> bool {
    peer_uid == allowed_uid
}

/// Read the connecting peer's uid from a Unix stream. Linux uses `SO_PEERCRED`; macOS/BSD
/// use `getpeereid` (nix gates `getpeereid` to `cfg(bsd)` and `PeerCredentials` to Linux,
/// so the two paths are mutually exclusive).
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        let creds = getsockopt(&stream.as_fd(), PeerCredentials)
            .map_err(|e| std::io::Error::other(format!("SO_PEERCRED: {e}")))?;
        Ok(creds.uid())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let (uid, _gid) = nix::unistd::getpeereid(stream.as_fd())
            .map_err(|e| std::io::Error::other(format!("getpeereid: {e}")))?;
        Ok(uid.as_raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_only_matches_exact_uid() {
        assert!(authorize(1000, 1000));
        assert!(!authorize(1001, 1000));
        assert!(!authorize(0, 1000)); // even root is rejected if it's not the allowed uid
        assert!(authorize(0, 0)); // root allowed only when explicitly configured
    }

    #[tokio::test]
    async fn peer_uid_reads_our_own_uid_over_a_socketpair() {
        // A connected UnixStream pair: both ends are this process, so SO_PEERCRED
        // reports our own uid. Confirms the nix getsockopt path actually works here.
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let got = peer_uid(&a).expect("peercred");
        assert_eq!(got, nix::unistd::getuid().as_raw());
    }
}
