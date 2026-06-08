//! TLS 1.3 record layer (RFC 8446 §5.2): TLSCiphertext seal/open.
use crate::error::{Result, TlsError};
use crate::tls13::suite::CipherSuite;

const APPLICATION_DATA: u8 = 0x17;

fn nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let s = seq.to_be_bytes(); // 8 bytes
    n[4..12]
        .iter_mut()
        .zip(s.iter())
        .for_each(|(ni, &si)| *ni ^= si);
    n
}

/// Build a TLSCiphertext record: AEAD-seal `plaintext||inner_type` (TLSInnerPlaintext,
/// no padding) with nonce = iv^seq and AAD = the 5-byte outer header.
pub fn seal_record(
    suite: CipherSuite,
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    inner_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(inner_type);
    let ct_len = inner.len() + suite.tag_len();
    let len = u16::try_from(ct_len).map_err(|_| TlsError::Malformed {
        what: "record",
        detail: "too large".into(),
    })?;
    let header = [APPLICATION_DATA, 0x03, 0x03, (len >> 8) as u8, len as u8];
    let n = nonce(iv, seq);
    let ct = suite
        .aead_seal(key, &n, &header, &inner)
        .ok_or(TlsError::Malformed {
            what: "record",
            detail: "seal".into(),
        })?;
    let mut out = Vec::with_capacity(5 + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse + AEAD-open a TLSCiphertext record. Returns (inner_type, plaintext).
pub fn open_record(
    suite: CipherSuite,
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    record: &[u8],
) -> Result<(u8, Vec<u8>)> {
    if record.len() < 5 {
        return Err(TlsError::Truncated {
            need: 5,
            have: record.len(),
        });
    }
    let header = &record[0..5];
    let body = &record[5..];
    let n = nonce(iv, seq);
    let mut inner = suite
        .aead_open(key, &n, header, body)
        .ok_or(TlsError::Malformed {
            what: "record",
            detail: "open/tag".into(),
        })?;
    // strip trailing zero padding; last non-zero byte is the real content type
    while let Some(&0) = inner.last() {
        inner.pop();
    }
    let inner_type = inner.pop().ok_or(TlsError::Malformed {
        what: "record",
        detail: "empty inner".into(),
    })?;
    Ok((inner_type, inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::suite::CipherSuite;

    #[test]
    fn roundtrip_all_suites() {
        for s in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let key = vec![9u8; s.key_len()];
            let iv = [1u8; 12];
            let rec = seal_record(s, &key, &iv, 0, 0x16, b"handshake-bytes").unwrap();
            assert_eq!(rec[0], 0x17); // outer type = application_data
            assert_eq!(&rec[1..3], &[0x03, 0x03]);
            let (inner_type, pt) = open_record(s, &key, &iv, 0, &rec).unwrap();
            assert_eq!(inner_type, 0x16);
            assert_eq!(pt, b"handshake-bytes");
        }
    }

    #[test]
    fn nonce_uses_sequence_number() {
        let s = CipherSuite::Aes128GcmSha256;
        let key = vec![9u8; 16];
        let iv = [0u8; 12];
        // seq 0 and seq 1 must produce different ciphertext for the same plaintext
        let r0 = seal_record(s, &key, &iv, 0, 0x17, b"x").unwrap();
        let r1 = seal_record(s, &key, &iv, 1, 0x17, b"x").unwrap();
        assert_ne!(r0, r1);
        // and each opens only at its own seq
        assert!(open_record(s, &key, &iv, 1, &r0).is_err());
        assert_eq!(open_record(s, &key, &iv, 1, &r1).unwrap().0, 0x17);
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn prop_record_roundtrip(seq in any::<u32>(), itype in 1u8..=255, pt in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let s = CipherSuite::ChaCha20Poly1305Sha256;
            let key = vec![4u8; 32]; let iv = [2u8; 12];
            let rec = seal_record(s, &key, &iv, seq as u64, itype, &pt).unwrap();
            let (t, got) = open_record(s, &key, &iv, seq as u64, &rec).unwrap();
            prop_assert_eq!(t, itype);
            prop_assert_eq!(got, pt);
        }
    }
}
