//! Encrypted, in-tunnel version + capability negotiation (never on the cleartext wire).
use crate::error::{Error, Result};

/// Capability bit: the peer understands the `Datagram` frame type (UDP associations
/// over the mux). Negotiated through `Hello.capabilities`; datagram frames are only
/// emitted after both peers advertise it.
pub const CAP_DATAGRAM: u64 = 1 << 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub version: u16,
    pub min_supported: u16,
    pub capabilities: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    pub version: u16,
    pub capabilities: u64,
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&self.version.to_be_bytes());
        v.extend_from_slice(&self.min_supported.to_be_bytes());
        v.extend_from_slice(&self.capabilities.to_be_bytes());
        v
    }
    pub fn decode(b: &[u8]) -> Result<Hello> {
        if b.len() < 12 {
            return Err(Error::Version("short HELLO".into()));
        }
        Ok(Hello {
            version: u16::from_be_bytes([b[0], b[1]]),
            min_supported: u16::from_be_bytes([b[2], b[3]]),
            capabilities: u64::from_be_bytes(b[4..12].try_into().unwrap()),
        })
    }
}

/// Effective version = min(maxes), valid only if >= both mins. Caps are intersected.
pub fn negotiate(local: &Hello, peer: &Hello) -> Result<Negotiated> {
    let version = local.version.min(peer.version);
    if version < local.min_supported || version < peer.min_supported {
        return Err(Error::Version(format!(
            "no common version (local {}..={}, peer {}..={})",
            local.min_supported, local.version, peer.min_supported, peer.version
        )));
    }
    Ok(Negotiated {
        version,
        capabilities: local.capabilities & peer.capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrips() {
        let h = Hello {
            version: 1,
            min_supported: 1,
            capabilities: 0b101,
        };
        assert_eq!(Hello::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn negotiate_picks_min_max_and_intersects_caps() {
        let local = Hello {
            version: 3,
            min_supported: 1,
            capabilities: 0b111,
        };
        let peer = Hello {
            version: 2,
            min_supported: 1,
            capabilities: 0b011,
        };
        let n = negotiate(&local, &peer).unwrap();
        assert_eq!(n.version, 2); // min(3,2)
        assert_eq!(n.capabilities, 0b011); // intersection
    }

    #[test]
    fn datagram_cap_negotiated_only_when_both_advertise() {
        let with = Hello {
            version: 1,
            min_supported: 1,
            capabilities: CAP_DATAGRAM,
        };
        let without = Hello {
            version: 1,
            min_supported: 1,
            capabilities: 0,
        };
        assert_eq!(
            negotiate(&with, &with).unwrap().capabilities & CAP_DATAGRAM,
            CAP_DATAGRAM
        );
        assert_eq!(
            negotiate(&with, &without).unwrap().capabilities & CAP_DATAGRAM,
            0
        );
    }

    #[test]
    fn negotiate_fails_when_no_overlap() {
        let local = Hello {
            version: 1,
            min_supported: 1,
            capabilities: 0,
        };
        let peer = Hello {
            version: 5,
            min_supported: 4,
            capabilities: 0,
        };
        assert!(negotiate(&local, &peer).is_err()); // local max 1 < peer min 4
    }
}
