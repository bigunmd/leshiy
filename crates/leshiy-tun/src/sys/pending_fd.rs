//! Own detached Android descriptors until the TUN device consumes them.
use std::os::fd::RawFd;
use std::sync::Mutex;

/// Ownership is transferred by the host's detachFd, not borrowed.
pub struct PendingTunFd(Option<RawFd>);

impl PendingTunFd {
    pub fn new(fd: RawFd) -> Self {
        Self(Some(fd))
    }

    pub fn into_raw(mut self) -> RawFd {
        self.0.take().expect("pending descriptor already consumed")
    }
}

impl Drop for PendingTunFd {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take() {
            let _ = nix::unistd::close(fd);
        }
    }
}

static TUN_FD: Mutex<Option<PendingTunFd>> = Mutex::new(None);

pub fn set_tun_fd(fd: RawFd) {
    *TUN_FD.lock().unwrap_or_else(|e| e.into_inner()) = Some(PendingTunFd::new(fd));
}

pub fn clear_tun_fd() {
    TUN_FD.lock().unwrap_or_else(|e| e.into_inner()).take();
}

pub fn take_tun_fd() -> Option<RawFd> {
    TUN_FD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .map(PendingTunFd::into_raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn rejected_or_cancelled_pending_owner_closes_without_injection() {
        let (mut peer, fd) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let pending = PendingTunFd::new(fd.into_raw_fd());
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(pending);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn pending_replacement_and_stop_close_descriptors_but_take_transfers() {
        let (mut first_peer, first) = UnixStream::pair().unwrap();
        let (mut second_peer, second) = UnixStream::pair().unwrap();
        first_peer.set_nonblocking(true).unwrap();
        second_peer.set_nonblocking(true).unwrap();
        set_tun_fd(first.into_raw_fd());
        set_tun_fd(second.into_raw_fd());
        assert_eq!(first_peer.read(&mut [0]).unwrap(), 0);
        clear_tun_fd();
        assert_eq!(second_peer.read(&mut [0]).unwrap(), 0);
        assert!(take_tun_fd().is_none());

        let (mut peer, fd) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        set_tun_fd(fd.into_raw_fd());
        let transferred = take_tun_fd().unwrap();
        clear_tun_fd();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        nix::unistd::close(transferred).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
