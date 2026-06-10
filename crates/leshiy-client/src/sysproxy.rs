//! System-proxy seam. The supervisor calls `set`/`clear` to point the OS at the
//! local SOCKS5 port (and, with the kill switch, to *leave it set* on an unexpected
//! drop so apps fail closed). Real per-OS implementations land in Plan 4; the trait
//! lets the supervisor be tested with a recording fake.
use crate::error::Result;
use std::net::SocketAddr;

/// Sets/clears the operating-system proxy.
pub trait SystemProxy: Send + Sync {
    /// Point the system proxy at the given local SOCKS5 address.
    fn set(&self, socks: SocketAddr) -> Result<()>;
    /// Remove any proxy this object set.
    fn clear(&self) -> Result<()>;
}

/// A do-nothing proxy for headless/test/unsupported environments.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopProxy;

impl SystemProxy for NoopProxy {
    fn set(&self, _socks: SocketAddr) -> Result<()> {
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_is_infallible() {
        let p = NoopProxy;
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        assert!(p.set(addr).is_ok());
        assert!(p.clear().is_ok());
    }
}
