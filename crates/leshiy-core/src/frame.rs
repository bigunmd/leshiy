//! Plaintext frame (de)serialization. Pure, no I/O, no crypto.
use crate::error::{Error, Result};
use bytes::Bytes;

/// Max plaintext per frame: Noise message max (65535) minus the 16-byte AEAD tag.
pub const MAX_PLAINTEXT: usize = 65535 - 16;
/// Largest stream/datagram payload we put in a single frame.
///
/// The size-limiting transport is the REALITY app-data path, which must look like
/// genuine TLS 1.3: each frame is sealed into ONE record whose TLSInnerPlaintext
/// (RFC 8446 §5.2) — `frame.encode()` (5-byte header + payload) plus the 1-byte
/// inner content-type — must not exceed 2^14. So payload ≤ 16384 − 5 − 1 = 16378.
/// Chunking to this keeps every transport's records within the TLS cap; the Noise
/// path's larger [`MAX_PLAINTEXT`] limit is a non-issue (smaller frames are always
/// safe). A frame larger than one record is writable but UNREADABLE on the REALITY
/// path (read_record rejects oversized records), which deadlocks the stream.
pub const MAX_FRAME_PAYLOAD: usize = 16384 - HEADER_LEN - 1;
/// High bit of the type byte marks a frame whose unknown type MUST abort the session.
pub const CRITICAL_BIT: u8 = 0x80;
const HEADER_LEN: usize = 5; // u32 stream_id + u8 type

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    Hello = 0,
    Bye = 1,
    Open = 2,
    Data = 3,
    Close = 4,
    Datagram = 5,
    /// Keepalive probe (stream_id 0, empty payload). Non-critical: a peer that doesn't
    /// understand it ignores it. Only emitted once `CAP_KEEPALIVE` is negotiated.
    Ping = 6,
    /// Keepalive response — sent in reply to a received `Ping`. Non-critical.
    Pong = 7,
    /// Per-stream flow-control credit: payload is a 4-byte big-endian `u32` count of bytes the
    /// receiver has consumed (and so re-grants to the sender) for `stream_id`. Non-critical: a
    /// peer that doesn't understand it ignores it. Only emitted once `CAP_FLOWCONTROL` is
    /// negotiated.
    WindowUpdate = 8,
}

pub fn is_critical(ftype: u8) -> bool {
    ftype & CRITICAL_BIT != 0
}
pub fn base_type(ftype: u8) -> u8 {
    ftype & !CRITICAL_BIT
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub stream_id: u32,
    pub ftype: u8, // base type, optionally OR'd with CRITICAL_BIT
    /// Reference-counted payload so it can be sliced/forwarded without copying.
    pub payload: Bytes,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.payload.len() <= MAX_PLAINTEXT,
            "payload {} exceeds MAX_PLAINTEXT {}",
            self.payload.len(),
            MAX_PLAINTEXT
        );
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.push(self.ftype);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from a borrowed slice (copies the payload). Prefer
    /// [`decode_from_bytes`](Self::decode_from_bytes) on the hot path.
    pub fn decode(buf: &[u8]) -> Result<Frame> {
        Self::decode_from_bytes(Bytes::copy_from_slice(buf))
    }

    /// Decode from an owned [`Bytes`]; the payload is a zero-copy slice of `buf`.
    pub fn decode_from_bytes(buf: Bytes) -> Result<Frame> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Protocol("frame shorter than header".into()));
        }
        let stream_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let ftype = buf[4];
        Ok(Frame {
            stream_id,
            ftype,
            payload: buf.slice(HEADER_LEN..),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_data_frame() {
        let f = Frame {
            stream_id: 7,
            ftype: FrameType::Data as u8,
            payload: Bytes::from_static(b"hello"),
        };
        let bytes = f.encode();
        let got = Frame::decode(&bytes).unwrap();
        assert_eq!(got.stream_id, 7);
        assert_eq!(got.ftype, FrameType::Data as u8);
        assert_eq!(got.payload.as_ref(), b"hello");
    }

    #[test]
    fn decode_from_bytes_is_zero_copy_slice() {
        let f = Frame {
            stream_id: 7,
            ftype: FrameType::Data as u8,
            payload: Bytes::from_static(b"hello"),
        };
        let got = Frame::decode_from_bytes(Bytes::from(f.encode())).unwrap();
        assert_eq!(got.stream_id, 7);
        assert_eq!(got.payload.as_ref(), b"hello");
    }

    #[test]
    fn critical_bit_helpers() {
        let t = FrameType::Open as u8 | CRITICAL_BIT;
        assert!(is_critical(t));
        assert_eq!(base_type(t), FrameType::Open as u8);
    }

    #[test]
    fn decode_rejects_short_header() {
        assert!(Frame::decode(&[0, 0, 0]).is_err());
    }

    #[test]
    fn decode_header_only_yields_empty_payload() {
        let buf = [0u8, 0, 0, 7, FrameType::Close as u8];
        let f = Frame::decode(&buf).unwrap();
        assert_eq!(f.stream_id, 7);
        assert_eq!(f.ftype, FrameType::Close as u8);
        assert!(f.payload.is_empty());
    }

    #[test]
    fn roundtrip_datagram_frame() {
        let f = Frame {
            stream_id: 9,
            ftype: FrameType::Datagram as u8,
            payload: Bytes::from_static(b"udp-payload"),
        };
        let got = Frame::decode(&f.encode()).unwrap();
        assert_eq!(got.stream_id, 9);
        assert_eq!(got.ftype, FrameType::Datagram as u8);
        assert_eq!(got.payload.as_ref(), b"udp-payload");
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn prop_roundtrip(stream_id in any::<u32>(), ftype in any::<u8>(), payload in proptest::collection::vec(any::<u8>(), 0..1000)) {
            let f = Frame { stream_id, ftype, payload: Bytes::from(payload.clone()) };
            let got = Frame::decode(&f.encode()).unwrap();
            prop_assert_eq!(got.stream_id, stream_id);
            prop_assert_eq!(got.ftype, ftype);
            prop_assert_eq!(got.payload, payload);
        }
    }
}
