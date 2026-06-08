//! TLS record layer: [content_type | legacy_version 0x0303 | u16 len | payload].
//! Sans-I/O codec + async read/write helpers. No crypto.
use crate::error::{Result, TlsError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HANDSHAKE: u8 = 0x16;
pub const ALERT: u8 = 0x15;
pub const APPLICATION_DATA: u8 = 0x17;
const HEADER_LEN: usize = 5;
/// TLS record payload hard cap (RFC 8446 §5.1): 2^14 + small slack handled by caller.
pub const MAX_RECORD_PAYLOAD: usize = 16384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub content_type: u8,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(self.content_type);
        out.extend_from_slice(&[0x03, 0x03]); // legacy_record_version
        let len = u16::try_from(self.payload.len()).expect("payload exceeds u16");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode one record from the front of `buf`; returns (record, bytes_consumed).
    pub fn decode(buf: &[u8]) -> Result<(Record, usize)> {
        if buf.len() < HEADER_LEN {
            return Err(TlsError::Truncated {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total = HEADER_LEN + len;
        if buf.len() < total {
            return Err(TlsError::Truncated {
                need: total,
                have: buf.len(),
            });
        }
        Ok((
            Record {
                content_type: buf[0],
                payload: buf[HEADER_LEN..total].to_vec(),
            },
            total,
        ))
    }
}

pub async fn write_record<W: AsyncWrite + Unpin>(w: &mut W, r: &Record) -> Result<()> {
    w.write_all(&r.encode()).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<Record> {
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Record {
        content_type: hdr[0],
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_record() {
        let r = Record {
            content_type: HANDSHAKE,
            payload: vec![1, 2, 3, 4],
        };
        let bytes = r.encode();
        // wire: [type][0x03 0x03][00 04][payload]
        assert_eq!(&bytes[..3], &[HANDSHAKE, 0x03, 0x03]);
        assert_eq!(&bytes[3..5], &[0x00, 0x04]);
        let (got, consumed) = Record::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(got.content_type, HANDSHAKE);
        assert_eq!(got.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn decode_truncated_is_err() {
        assert!(Record::decode(&[HANDSHAKE, 0x03, 0x03, 0x00]).is_err());
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn prop_record_roundtrip(ct in any::<u8>(), payload in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let r = Record { content_type: ct, payload: payload.clone() };
            let (got, n) = Record::decode(&r.encode()).unwrap();
            prop_assert_eq!(n, payload.len() + 5);
            prop_assert_eq!(got.content_type, ct);
            prop_assert_eq!(got.payload, payload);
        }
    }
}
