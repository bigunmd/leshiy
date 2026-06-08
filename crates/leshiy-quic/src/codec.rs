//! Per-stream target header: u16 big-endian length + UTF-8 "host:port".
use crate::{QuicError, Result};

pub fn encode_target(target: &str) -> Vec<u8> {
    let b = target.as_bytes();
    let mut out = (b.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

/// Decode from an in-memory buffer (test helper); returns (target, remaining).
pub fn decode_target_from(buf: &[u8]) -> Result<(String, &[u8])> {
    if buf.len() < 2 {
        return Err(QuicError::Protocol("short target len".into()));
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return Err(QuicError::Protocol("short target body".into()));
    }
    let s = std::str::from_utf8(&buf[2..2 + n])
        .map_err(|_| QuicError::Protocol("target not utf8".into()))?;
    Ok((s.to_string(), &buf[2 + n..]))
}

/// Read a target header from a quinn RecvStream (async).
pub async fn read_target<R: tokio::io::AsyncReadExt + Unpin>(r: &mut R) -> Result<String> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    // SOCKS5 domain (≤255) + ":65535" → ≤261 bytes.
    if n == 0 || n > 261 {
        return Err(QuicError::Protocol("bad target len".into()));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    String::from_utf8(body).map_err(|_| QuicError::Protocol("target not utf8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_roundtrip() {
        let enc = encode_target("example.com:443");
        assert_eq!(enc.len(), 2 + "example.com:443".len());
        // simulate a reader holding exactly these bytes
        let (target, rest) = decode_target_from(&enc).unwrap();
        assert_eq!(target, "example.com:443");
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_rejects_short() {
        assert!(decode_target_from(&[0x00]).is_err()); // truncated len
        assert!(decode_target_from(&[0x00, 0x05, b'a']).is_err()); // len says 5, have 1
    }
}
