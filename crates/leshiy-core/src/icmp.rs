//! ICMP echo header codec (ADR-0030): pure byte manipulation, no sockets, no policy.
//!
//! Both ends need a little of this. The client must recognise an echo **request** before it
//! forwards anything (everything else stays dropped), and the server must restore the client's
//! original identifier on the reply — a ping socket overwrites the id with its own port on send,
//! so without this the reply would not match the request that the user's `ping` issued.
//!
//! ICMPv4 and ICMPv6 share the echo header layout, differing only in the type numbers:
//!
//! ```text
//!  0      7 8     15 16                    31
//! +--------+--------+------------------------+
//! |  Type  |  Code  |        Checksum        |
//! +--------+--------+------------------------+
//! |     Identifier  |    Sequence Number     |
//! +-----------------+------------------------+
//! |  Data ...
//! ```
//!
//! The **checksums differ**, though, and that asymmetry drives who fixes what: an ICMPv4 checksum
//! covers only the ICMP message, so the server can compute it. An ICMPv6 checksum also covers an
//! IPv6 pseudo-header of the source and destination addresses — which the server cannot know,
//! because the client's TUN address is not its business. So for v6 the server leaves the checksum
//! zeroed and the client, which knows both addresses, completes it. See [`v6_checksum`].

/// ICMPv4 echo request type (RFC 792).
pub const V4_ECHO_REQUEST: u8 = 8;
/// ICMPv4 echo reply type.
pub const V4_ECHO_REPLY: u8 = 0;
/// ICMPv6 echo request type (RFC 4443).
pub const V6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 echo reply type.
pub const V6_ECHO_REPLY: u8 = 129;

/// IP protocol number for ICMPv4.
pub const IPPROTO_ICMPV4: u8 = 1;
/// IP next-header number for ICMPv6.
pub const IPPROTO_ICMPV6: u8 = 58;

/// Length of the echo header preceding the payload.
pub const HEADER_LEN: usize = 8;

const OFF_TYPE: usize = 0;
const OFF_CODE: usize = 1;
const OFF_CHECKSUM: usize = 2;
const OFF_ID: usize = 4;
const OFF_SEQ: usize = 6;

/// The identifier/sequence pair correlating an echo reply with its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo {
    pub id: u16,
    pub seq: u16,
}

/// Read the echo header if `msg` is an echo **request** of the given family, else `None`.
///
/// Only echo is carried. Redirect, Destination Unreachable and friends are meaningful solely
/// against a routing topology the peer does not share, so forwarding them would be a spoofing
/// surface rather than a feature (ADR-0030).
pub fn parse_echo_request(msg: &[u8], v6: bool) -> Option<Echo> {
    let want = if v6 { V6_ECHO_REQUEST } else { V4_ECHO_REQUEST };
    if msg.len() < HEADER_LEN || msg[OFF_TYPE] != want || msg[OFF_CODE] != 0 {
        return None;
    }
    Some(Echo {
        id: u16::from_be_bytes([msg[OFF_ID], msg[OFF_ID + 1]]),
        seq: u16::from_be_bytes([msg[OFF_SEQ], msg[OFF_SEQ + 1]]),
    })
}

/// Is `msg` an echo **reply** of the given family?
pub fn is_echo_reply(msg: &[u8], v6: bool) -> bool {
    let want = if v6 { V6_ECHO_REPLY } else { V4_ECHO_REPLY };
    msg.len() >= HEADER_LEN && msg[OFF_TYPE] == want
}

/// Overwrite the echo identifier, zeroing the checksum (which the write invalidates).
///
/// Returns false — leaving `msg` untouched — if it is too short to be an echo message. The
/// caller must then recompute the checksum: [`set_v4_checksum`] for ICMPv4, or [`v6_checksum`]
/// once the addresses are known for ICMPv6.
#[must_use]
pub fn set_id(msg: &mut [u8], id: u16) -> bool {
    if msg.len() < HEADER_LEN {
        return false;
    }
    msg[OFF_ID..OFF_ID + 2].copy_from_slice(&id.to_be_bytes());
    msg[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&[0, 0]);
    true
}

/// The RFC 1071 internet checksum: one's-complement sum of 16-bit big-endian words, folded and
/// inverted. A trailing odd byte is padded on the right with zero.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    fold(sum)
}

/// Fold the carries out of a 32-bit accumulator and invert, yielding the wire checksum.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Recompute and write the ICMPv4 checksum over the whole message, in place.
///
/// Returns false if `msg` is too short to be an echo message.
#[must_use]
pub fn set_v4_checksum(msg: &mut [u8]) -> bool {
    if msg.len() < HEADER_LEN {
        return false;
    }
    msg[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&[0, 0]);
    let ck = checksum(msg);
    msg[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&ck.to_be_bytes());
    true
}

/// The ICMPv6 checksum for `msg` sent from `src` to `dst`, over the RFC 2460 §8.1 pseudo-header
/// (src, dst, upper-layer length, next-header) followed by the message with its checksum zeroed.
///
/// Separate from [`set_v4_checksum`] because only the party that knows both addresses can compute
/// it — for a reply that is the client, not the server.
pub fn v6_checksum(msg: &[u8], src: &[u8; 16], dst: &[u8; 16]) -> u16 {
    let mut sum: u32 = 0;
    for addr in [src, dst] {
        for c in addr.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
    }
    // Upper-layer packet length as a 32-bit field, then three zero bytes and the next header.
    let len = msg.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;
    sum += u32::from(IPPROTO_ICMPV6);

    // The message itself, with the checksum field read as zero rather than mutating the caller's
    // buffer.
    let mut chunks = msg.chunks_exact(2);
    for (i, c) in (&mut chunks).enumerate() {
        if i * 2 == OFF_CHECKSUM {
            continue; // checksum field counts as zero
        }
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    fold(sum)
}

/// Write an ICMPv6 checksum computed for `src`→`dst` into `msg`, in place.
///
/// Returns false if `msg` is too short to be an echo message.
#[must_use]
pub fn set_v6_checksum(msg: &mut [u8], src: &[u8; 16], dst: &[u8; 16]) -> bool {
    if msg.len() < HEADER_LEN {
        return false;
    }
    msg[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&[0, 0]);
    let ck = v6_checksum(msg, src, dst);
    msg[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&ck.to_be_bytes());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// type=8 code=0, checksum zeroed, id=0, seq=0. The only non-zero word is 0x0800, so the
    /// one's-complement sum is 0x0800 and the checksum is its inverse.
    #[test]
    fn checksum_matches_a_hand_computed_echo_request() {
        let msg = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(checksum(&msg), 0xf7ff);
    }

    /// The defining property of the internet checksum: re-running it over a message that already
    /// carries its own correct checksum yields zero. This is exactly the check the receiving
    /// stack performs, so a message failing it would be dropped on the floor by the peer.
    #[test]
    fn checksum_over_a_completed_message_is_zero() {
        for len in [0usize, 1, 2, 3, 17, 56] {
            let mut msg = vec![0u8; HEADER_LEN + len];
            msg[0] = V4_ECHO_REQUEST;
            msg[OFF_ID..OFF_ID + 2].copy_from_slice(&0x1234u16.to_be_bytes());
            msg[OFF_SEQ..OFF_SEQ + 2].copy_from_slice(&7u16.to_be_bytes());
            for (i, b) in msg[HEADER_LEN..].iter_mut().enumerate() {
                *b = i as u8;
            }
            assert!(set_v4_checksum(&mut msg));
            assert_eq!(checksum(&msg), 0, "payload len {len}");
        }
    }

    /// An odd trailing byte pads right, not left. Getting this backwards produces a checksum that
    /// is wrong only for odd-length payloads — which `ping -s 9` would hit and nothing else would.
    #[test]
    fn checksum_pads_a_trailing_odd_byte_on_the_right() {
        assert_eq!(checksum(&[0x12]), checksum(&[0x12, 0x00]));
        assert_ne!(checksum(&[0x12]), checksum(&[0x00, 0x12]));
    }

    #[test]
    fn parses_an_echo_request_id_and_seq() {
        let msg = [V4_ECHO_REQUEST, 0, 0xf7, 0xd4, 0x12, 0x34, 0x00, 0x2a];
        assert_eq!(
            parse_echo_request(&msg, false),
            Some(Echo {
                id: 0x1234,
                seq: 42
            })
        );
    }

    /// Only echo requests are carried; every other ICMP type stays dropped (ADR-0030).
    #[test]
    fn rejects_everything_that_is_not_an_echo_request() {
        let echo_reply = [V4_ECHO_REPLY, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_echo_request(&echo_reply, false), None);
        // Destination Unreachable.
        let unreachable = [3u8, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_echo_request(&unreachable, false), None);
        // Redirect — the spoofing surface we most want to refuse.
        let redirect = [5u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_echo_request(&redirect, false), None);
        // Right type, nonzero code is not a well-formed echo.
        let bad_code = [V4_ECHO_REQUEST, 3, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_echo_request(&bad_code, false), None);
    }

    /// The v4 and v6 type numbers overlap dangerously: 128/129 are echo for v6 while 8/0 are echo
    /// for v4, and v4 type 0 is *reply*. Reading a message with the wrong family must not match.
    #[test]
    fn echo_types_do_not_cross_families() {
        let v4_req = [V4_ECHO_REQUEST, 0, 0, 0, 0, 0, 0, 0];
        let v6_req = [V6_ECHO_REQUEST, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_echo_request(&v4_req, false).is_some());
        assert!(parse_echo_request(&v4_req, true).is_none());
        assert!(parse_echo_request(&v6_req, true).is_some());
        assert!(parse_echo_request(&v6_req, false).is_none());
        assert!(is_echo_reply(&[V4_ECHO_REPLY, 0, 0, 0, 0, 0, 0, 0], false));
        assert!(!is_echo_reply(&[V4_ECHO_REPLY, 0, 0, 0, 0, 0, 0, 0], true));
        assert!(is_echo_reply(&[V6_ECHO_REPLY, 0, 0, 0, 0, 0, 0, 0], true));
    }

    /// The server's job: put the user's original id back on the reply, then re-checksum.
    #[test]
    fn set_id_restores_the_identifier_and_the_message_re_checksums() {
        // As a ping socket hands it back: id rewritten to the socket's port.
        let mut msg = vec![V4_ECHO_REPLY, 0, 0, 0, 0xbe, 0xef, 0x00, 0x01, b'h', b'i'];
        assert!(set_id(&mut msg, 0x1234));
        assert_eq!(&msg[OFF_ID..OFF_ID + 2], &[0x12, 0x34]);
        // set_id must invalidate the checksum rather than leave a stale one that would verify.
        assert_eq!(&msg[OFF_CHECKSUM..OFF_CHECKSUM + 2], &[0, 0]);
        assert!(set_v4_checksum(&mut msg));
        assert_eq!(checksum(&msg), 0);
        // The reply now correlates with the request the user's ping actually sent.
        assert!(is_echo_reply(&msg, false));
        assert_eq!(u16::from_be_bytes([msg[OFF_ID], msg[OFF_ID + 1]]), 0x1234);
    }

    /// Short buffers must be refused, not panic on a slice out of range — this parses bytes that
    /// arrive from the network.
    #[test]
    fn short_messages_are_refused_not_panicked_on() {
        for len in 0..HEADER_LEN {
            let mut buf = vec![0u8; len];
            assert_eq!(parse_echo_request(&buf, false), None, "len {len}");
            assert!(!is_echo_reply(&buf, false), "len {len}");
            assert!(!set_id(&mut buf, 1), "len {len}");
            assert!(!set_v4_checksum(&mut buf), "len {len}");
            assert!(!set_v6_checksum(&mut buf, &[0; 16], &[0; 16]), "len {len}");
        }
    }

    /// v6 folds a pseudo-header of both addresses in, so the same message checksums differently
    /// depending on where it is going — which is precisely why the server cannot compute it.
    ///
    /// Note the checksum is a *sum*, so it is commutative in src/dst: swapping the two yields an
    /// identical value and proves nothing. Vary one endpoint instead.
    #[test]
    fn v6_checksum_covers_the_address_pseudo_header() {
        let msg = [V6_ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0x00, 0, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let other_dst = [0xfd, 0x00, 0, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        assert_ne!(
            v6_checksum(&msg, &src, &dst),
            v6_checksum(&msg, &src, &other_dst),
            "a different destination must checksum differently"
        );
        // And it is not merely the v4 checksum: the pseudo-header genuinely contributes.
        assert_ne!(v6_checksum(&msg, &src, &dst), checksum(&msg));
    }

    /// A completed v6 message verifies to zero when re-checksummed over the same pseudo-header —
    /// the receiving stack's check.
    #[test]
    fn completed_v6_message_verifies_to_zero() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0x00, 0, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut msg = vec![V6_ECHO_REPLY, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 1, 2, 3, 4];
        assert!(set_v6_checksum(&mut msg, &src, &dst));
        // Verification re-runs the same computation; the carried checksum makes it fold to zero.
        let mut verify = msg.clone();
        let carried = u16::from_be_bytes([verify[OFF_CHECKSUM], verify[OFF_CHECKSUM + 1]]);
        verify[OFF_CHECKSUM] = 0;
        verify[OFF_CHECKSUM + 1] = 0;
        let recomputed = v6_checksum(&verify, &src, &dst);
        assert_eq!(carried, recomputed);
    }
}
