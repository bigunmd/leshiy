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

/// Capability bit: the peer understands [`Hello::idle_tolerance`] and will honour it (ADR-0031).
/// Without it both sides keep the symmetric 45s default — which is the safety property that
/// matters: a new client talking to an old server must not believe it was granted grace it wasn't,
/// or its watchdog would sit on a dead session for minutes.
pub const CAP_IDLE_TOLERANCE: u64 = 1 << 4;

/// Seconds of peer silence tolerated when [`CAP_IDLE_TOLERANCE`] is not negotiated — the historic
/// symmetric behaviour, and what an always-awake peer asks for.
pub const DEFAULT_IDLE_TOLERANCE: u32 = 45;

/// Ceiling on a peer's requested tolerance. This is attacker-controlled input: without a cap a
/// client could ask us to hold its socket and tasks open indefinitely, which is a free
/// resource-exhaustion lever.
pub const MAX_IDLE_TOLERANCE: u32 = 900;

/// Floor, so a peer cannot request a tolerance under the ping interval and trip itself.
pub const MIN_IDLE_TOLERANCE: u32 = 15;

// The bounds must bracket the default, or the no-cap fallback would be a value the clamp itself
// rejects — the two paths would disagree. Cheaper to catch here than in a test.
const _: () = assert!(MIN_IDLE_TOLERANCE <= DEFAULT_IDLE_TOLERANCE);
const _: () = assert!(DEFAULT_IDLE_TOLERANCE <= MAX_IDLE_TOLERANCE);

/// Apply the protocol's bounds to a requested tolerance. Both peers run this over the same
/// constants, which is what lets them agree without a round trip — the HELLO exchange is
/// simultaneous, so no side can echo a granted value back.
pub fn clamp_idle_tolerance(requested: u32) -> u32 {
    requested.clamp(MIN_IDLE_TOLERANCE, MAX_IDLE_TOLERANCE)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub version: u16,
    pub min_supported: u16,
    pub capabilities: u64,
    /// "Please tolerate up to this many seconds of silence from me" (ADR-0031). Meaningful only
    /// when both peers advertise [`CAP_IDLE_TOLERANCE`]. An always-awake peer asks for
    /// [`DEFAULT_IDLE_TOLERANCE`]; a phone asks for far more, because it suspends its CPU and
    /// cannot ping while it sleeps.
    pub idle_tolerance: u32,
}

impl Hello {
    /// A hello for an always-awake peer: no idle-tolerance request beyond the default.
    pub fn new(version: u16, min_supported: u16, capabilities: u64) -> Hello {
        Hello {
            version,
            min_supported,
            capabilities,
            idle_tolerance: DEFAULT_IDLE_TOLERANCE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    pub version: u16,
    pub capabilities: u64,
    /// Seconds of the **peer's** silence we will tolerate before declaring the link dead — our
    /// reader's idle timeout. This is what *they* asked for.
    pub local_idle_tolerance: u32,
    /// Seconds of **our** silence the peer will tolerate before tearing the session down — what
    /// *we* asked for. The wall-clock watchdog uses it to tell whether a suspend outlasted the
    /// peer's patience.
    ///
    /// Deliberately separate from `local_idle_tolerance`: "how long I tolerate them" and "how long
    /// they tolerate me" are different questions with different answers the moment one peer sleeps
    /// and the other doesn't.
    pub peer_idle_tolerance: u32,
}

impl Hello {
    /// Wire format: `version | min_supported | capabilities`, then `idle_tolerance` appended
    /// (ADR-0031). The trailing field is invisible to a peer that predates it — see [`decode`].
    ///
    /// [`decode`]: Hello::decode
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&self.version.to_be_bytes());
        v.extend_from_slice(&self.min_supported.to_be_bytes());
        v.extend_from_slice(&self.capabilities.to_be_bytes());
        v.extend_from_slice(&self.idle_tolerance.to_be_bytes());
        v
    }

    /// Decode a HELLO. Only the first 12 bytes are required, so a peer predating
    /// [`CAP_IDLE_TOLERANCE`] decodes fine and reports the default; trailing bytes from a *newer*
    /// peer are read if present and ignored otherwise. That two-way tolerance is what makes the
    /// field appendable without a version bump.
    pub fn decode(b: &[u8]) -> Result<Hello> {
        if b.len() < 12 {
            return Err(Error::Version("short HELLO".into()));
        }
        Ok(Hello {
            version: u16::from_be_bytes([b[0], b[1]]),
            min_supported: u16::from_be_bytes([b[2], b[3]]),
            capabilities: u64::from_be_bytes(b[4..12].try_into().unwrap()),
            idle_tolerance: if b.len() >= 16 {
                u32::from_be_bytes(b[12..16].try_into().unwrap())
            } else {
                DEFAULT_IDLE_TOLERANCE
            },
        })
    }
}

/// Effective version = min(maxes), valid only if >= both mins. Caps are intersected, and each
/// side's idle tolerance is honoured (clamped) only when both advertise [`CAP_IDLE_TOLERANCE`].
pub fn negotiate(local: &Hello, peer: &Hello) -> Result<Negotiated> {
    let version = local.version.min(peer.version);
    if version < local.min_supported || version < peer.min_supported {
        return Err(Error::Version(format!(
            "no common version (local {}..={}, peer {}..={})",
            local.min_supported, local.version, peer.min_supported, peer.version
        )));
    }
    let capabilities = local.capabilities & peer.capabilities;
    // Fall back to the symmetric default unless BOTH understand the field. A peer that never sent
    // one decodes as the default anyway, but relying on that would silently honour a stale value
    // from a peer that sent the bytes without advertising the cap.
    let honoured = capabilities & CAP_IDLE_TOLERANCE != 0;
    Ok(Negotiated {
        version,
        capabilities,
        local_idle_tolerance: if honoured {
            clamp_idle_tolerance(peer.idle_tolerance)
        } else {
            DEFAULT_IDLE_TOLERANCE
        },
        peer_idle_tolerance: if honoured {
            clamp_idle_tolerance(local.idle_tolerance)
        } else {
            DEFAULT_IDLE_TOLERANCE
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrips() {
        let h = Hello::new(1, 1, 0b101);
        assert_eq!(Hello::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn negotiate_picks_min_max_and_intersects_caps() {
        let local = Hello::new(3, 1, 0b111);
        let peer = Hello::new(2, 1, 0b011);
        let n = negotiate(&local, &peer).unwrap();
        assert_eq!(n.version, 2); // min(3,2)
        assert_eq!(n.capabilities, 0b011); // intersection
    }

    #[test]
    fn datagram_cap_negotiated_only_when_both_advertise() {
        let with = Hello::new(1, 1, CAP_DATAGRAM);
        let without = Hello::new(1, 1, 0);
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
        let with = Hello::new(1, 1, CAP_KEEPALIVE);
        let without = Hello::new(1, 1, 0);
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
        let with = Hello::new(1, 1, CAP_FLOWCONTROL);
        let without = Hello::new(1, 1, 0);
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
        let with = Hello::new(1, 1, CAP_ICMP);
        let without = Hello::new(1, 1, 0);
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

    // --- idle tolerance (ADR-0031) ---------------------------------------------------

    fn hello_tol(caps: u64, tol: u32) -> Hello {
        Hello {
            version: 1,
            min_supported: 1,
            capabilities: caps,
            idle_tolerance: tol,
        }
    }

    /// The compatibility hinge: a 12-byte HELLO from a peer that predates the field must decode,
    /// reporting the default rather than erroring or reading garbage.
    #[test]
    fn a_hello_without_the_tolerance_field_decodes_to_the_default() {
        let old_wire = {
            let h = hello_tol(CAP_DATAGRAM, 600);
            h.encode()[..12].to_vec() // exactly what an old peer puts on the wire
        };
        assert_eq!(old_wire.len(), 12);
        let decoded = Hello::decode(&old_wire).unwrap();
        assert_eq!(decoded.idle_tolerance, DEFAULT_IDLE_TOLERANCE);
        assert_eq!(decoded.capabilities, CAP_DATAGRAM);
    }

    #[test]
    fn hello_with_tolerance_roundtrips() {
        let h = hello_tol(CAP_IDLE_TOLERANCE, 600);
        assert_eq!(h.encode().len(), 16);
        assert_eq!(Hello::decode(&h.encode()).unwrap(), h);
    }

    /// Trailing bytes a future peer might append must not break us.
    #[test]
    fn decode_ignores_bytes_beyond_the_known_fields() {
        let mut wire = hello_tol(CAP_IDLE_TOLERANCE, 600).encode();
        wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(Hello::decode(&wire).unwrap().idle_tolerance, 600);
    }

    /// The safety property. A phone asking for 10 minutes must NOT believe it got them from a
    /// server that never advertised the cap — its watchdog would sit on a dead session for nine
    /// of them instead of re-dialing.
    #[test]
    fn tolerance_is_ignored_unless_both_peers_advertise_the_cap() {
        let phone = hello_tol(CAP_IDLE_TOLERANCE, 600);
        let old_server = hello_tol(0, DEFAULT_IDLE_TOLERANCE);
        let n = negotiate(&phone, &old_server).unwrap();
        assert_eq!(n.peer_idle_tolerance, DEFAULT_IDLE_TOLERANCE);
        assert_eq!(n.local_idle_tolerance, DEFAULT_IDLE_TOLERANCE);
    }

    /// "How long I tolerate them" and "how long they tolerate me" are different answers the moment
    /// one peer sleeps: the phone asks for 600s, the server asks for the default, and each side
    /// must end up with both numbers the right way round.
    #[test]
    fn each_side_tolerates_what_the_other_asked_for() {
        let phone = hello_tol(CAP_IDLE_TOLERANCE, 600);
        let server = hello_tol(CAP_IDLE_TOLERANCE, DEFAULT_IDLE_TOLERANCE);

        // On the phone: it will tolerate the server's 45s of silence; the server grants it 600s.
        let on_phone = negotiate(&phone, &server).unwrap();
        assert_eq!(on_phone.local_idle_tolerance, DEFAULT_IDLE_TOLERANCE);
        assert_eq!(on_phone.peer_idle_tolerance, 600);

        // On the server: the mirror image. Both sides agree without any round trip.
        let on_server = negotiate(&server, &phone).unwrap();
        assert_eq!(on_server.local_idle_tolerance, 600);
        assert_eq!(on_server.peer_idle_tolerance, DEFAULT_IDLE_TOLERANCE);
        assert_eq!(on_phone.peer_idle_tolerance, on_server.local_idle_tolerance);
        assert_eq!(on_phone.local_idle_tolerance, on_server.peer_idle_tolerance);
    }

    /// The tolerance is attacker-controlled: an unbounded request would pin a server socket and
    /// its tasks open for as long as the client liked.
    #[test]
    fn an_outrageous_request_is_capped_not_honoured() {
        let greedy = hello_tol(CAP_IDLE_TOLERANCE, u32::MAX);
        let server = hello_tol(CAP_IDLE_TOLERANCE, DEFAULT_IDLE_TOLERANCE);
        let on_server = negotiate(&server, &greedy).unwrap();
        assert_eq!(on_server.local_idle_tolerance, MAX_IDLE_TOLERANCE);
        // And the greedy peer computes the same ceiling for itself — no round trip needed.
        assert_eq!(
            negotiate(&greedy, &server).unwrap().peer_idle_tolerance,
            MAX_IDLE_TOLERANCE
        );
    }

    /// A request under the ping interval would have the peer time us out between our own pings.
    #[test]
    fn a_too_small_request_is_floored() {
        let silly = hello_tol(CAP_IDLE_TOLERANCE, 0);
        let server = hello_tol(CAP_IDLE_TOLERANCE, DEFAULT_IDLE_TOLERANCE);
        assert_eq!(
            negotiate(&server, &silly).unwrap().local_idle_tolerance,
            MIN_IDLE_TOLERANCE
        );
    }

    /// The default must survive its own clamp, or the no-cap fallback would silently differ from
    /// the value both peers believe they agreed on. (That the bounds bracket the default is
    /// asserted at compile time, next to the constants; this pins the consequence.)
    #[test]
    fn the_default_is_not_itself_clamped() {
        assert_eq!(
            clamp_idle_tolerance(DEFAULT_IDLE_TOLERANCE),
            DEFAULT_IDLE_TOLERANCE
        );
    }

    #[test]
    fn negotiate_fails_when_no_overlap() {
        let local = Hello::new(1, 1, 0);
        let peer = Hello::new(5, 4, 0);
        assert!(negotiate(&local, &peer).is_err()); // local max 1 < peer min 4
    }
}
