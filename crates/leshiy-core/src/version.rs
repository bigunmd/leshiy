//! Encrypted, in-tunnel version + capability negotiation (never on the cleartext wire).
use crate::error::{Error, Result};

/// Capability bit: the peer understands the `Datagram` frame type (UDP associations
/// over the mux). Negotiated through `Hello.capabilities`; datagram frames are only
/// emitted after both peers advertise it.
pub const CAP_DATAGRAM: u64 = 1 << 0;

/// Capability bit: the peer understands the `Ping`/`Pong` keepalive frames and will
/// echo a `Ping` with a `Pong`. Negotiated through `Hello.capabilities`; the mux only
/// runs its keepalive (periodic ping + idle-read timeout) when both peers advertise it,
/// so a silently-blackholed tunnel (no FIN/RST — the TSPU/DPI and NAT-rebind failure
/// mode) is detected and `closed()` fires instead of the reader blocking forever.
pub const CAP_KEEPALIVE: u64 = 1 << 1;

/// Capability bit: the peer understands per-stream flow control (the `WindowUpdate` frame and
/// credit accounting). Negotiated through `Hello.capabilities`; only when both peers advertise it
/// does the mux apply windowing. When active, the shared reader never blocks delivering data to a
/// slow stream (it backpressures the sender via credits instead), so one stalled stream can no
/// longer head-of-line-block the whole tunnel.
pub const CAP_FLOWCONTROL: u64 = 1 << 2;

/// Capability bit: the peer understands `icmp:`-scheme datagram associations, i.e. it can egress
/// ICMP **echo** on behalf of the tunnel (see ADR-0030). Negotiated through `Hello.capabilities`;
/// the client only forwards echo once both peers advertise it, and otherwise keeps dropping ICMP
/// exactly as it always has, so an un-upgraded server degrades silently rather than breaking.
/// Deliberately not a new frame type — reusing `Open`/`Datagram` keeps a leshiy connection's
/// frame-type histogram unchanged (ADR-0008).
pub const CAP_ICMP: u64 = 1 << 3;

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
    fn keepalive_cap_negotiated_only_when_both_advertise() {
        let with = Hello {
            version: 1,
            min_supported: 1,
            capabilities: CAP_KEEPALIVE,
        };
        let without = Hello {
            version: 1,
            min_supported: 1,
            capabilities: 0,
        };
        assert_eq!(
            negotiate(&with, &with).unwrap().capabilities & CAP_KEEPALIVE,
            CAP_KEEPALIVE
        );
        assert_eq!(
            negotiate(&with, &without).unwrap().capabilities & CAP_KEEPALIVE,
            0
        );
    }

    #[test]
    fn flowcontrol_cap_negotiated_only_when_both_advertise() {
        let with = Hello {
            version: 1,
            min_supported: 1,
            capabilities: CAP_FLOWCONTROL,
        };
        let without = Hello {
            version: 1,
            min_supported: 1,
            capabilities: 0,
        };
        assert_eq!(
            negotiate(&with, &with).unwrap().capabilities & CAP_FLOWCONTROL,
            CAP_FLOWCONTROL
        );
        assert_eq!(
            negotiate(&with, &without).unwrap().capabilities & CAP_FLOWCONTROL,
            0
        );
    }

    #[test]
    fn icmp_cap_negotiated_only_when_both_advertise() {
        let with = Hello {
            version: 1,
            min_supported: 1,
            capabilities: CAP_ICMP,
        };
        let without = Hello {
            version: 1,
            min_supported: 1,
            capabilities: 0,
        };
        assert_eq!(
            negotiate(&with, &with).unwrap().capabilities & CAP_ICMP,
            CAP_ICMP
        );
        // An un-upgraded server must leave the bit clear, so the client keeps dropping ICMP.
        assert_eq!(
            negotiate(&with, &without).unwrap().capabilities & CAP_ICMP,
            0
        );
    }

    /// Every capability must own a distinct bit — a collision would silently activate one feature
    /// when the peer advertised another.
    #[test]
    fn every_capability_owns_a_distinct_bit() {
        let caps = [
            ("CAP_DATAGRAM", CAP_DATAGRAM),
            ("CAP_KEEPALIVE", CAP_KEEPALIVE),
            ("CAP_FLOWCONTROL", CAP_FLOWCONTROL),
            ("CAP_ICMP", CAP_ICMP),
        ];
        for (i, (a_name, a)) in caps.iter().enumerate() {
            assert_eq!(a.count_ones(), 1, "{a_name} must be a single bit");
            for (b_name, b) in &caps[i + 1..] {
                assert_eq!(a & b, 0, "{a_name} and {b_name} share a bit");
            }
        }
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
