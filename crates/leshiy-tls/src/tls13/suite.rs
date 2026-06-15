//! TLS 1.3 cipher suites: hash + AEAD parameters and dispatch.
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use sha2::{Digest, Sha256, Sha384};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn from_u16(v: u16) -> Option<CipherSuite> {
        match v {
            0x1301 => Some(CipherSuite::Aes128GcmSha256),
            0x1302 => Some(CipherSuite::Aes256GcmSha384),
            0x1303 => Some(CipherSuite::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }
    pub fn to_u16(self) -> u16 {
        match self {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::Aes256GcmSha384 => 0x1302,
            CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }
    pub fn hash_len(self) -> usize {
        match self {
            CipherSuite::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }
    pub fn key_len(self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 16,
            _ => 32,
        }
    }
    pub fn iv_len(self) -> usize {
        12
    }
    pub fn tag_len(self) -> usize {
        16
    }

    /// One-shot hash over `data` with this suite's hash function.
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            CipherSuite::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
            _ => Sha256::digest(data).to_vec(),
        }
    }

    pub fn aead_seal(
        self,
        key: &[u8],
        nonce12: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
    ) -> Option<Vec<u8>> {
        let p = Payload { msg: pt, aad };
        match self {
            CipherSuite::Aes128GcmSha256 => {
                let n = AesNonce::from_slice(nonce12);
                Aes128Gcm::new_from_slice(key).ok()?.encrypt(n, p).ok()
            }
            CipherSuite::Aes256GcmSha384 => {
                let n = AesNonce::from_slice(nonce12);
                Aes256Gcm::new_from_slice(key).ok()?.encrypt(n, p).ok()
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let n = ChaNonce::from_slice(nonce12);
                ChaCha20Poly1305::new_from_slice(key)
                    .ok()?
                    .encrypt(n, p)
                    .ok()
            }
        }
    }

    /// In-place AEAD seal: `buf` holds the plaintext on entry; on success the tag
    /// is appended in place (no separate ciphertext allocation). Returns `None` on
    /// a bad key length. Mirrors [`aead_seal`](Self::aead_seal) byte-for-byte.
    pub fn aead_seal_in_place(
        self,
        key: &[u8],
        nonce12: &[u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Option<()> {
        match self {
            CipherSuite::Aes128GcmSha256 => {
                let n = AesNonce::from_slice(nonce12);
                Aes128Gcm::new_from_slice(key)
                    .ok()?
                    .encrypt_in_place(n, aad, buf)
                    .ok()
            }
            CipherSuite::Aes256GcmSha384 => {
                let n = AesNonce::from_slice(nonce12);
                Aes256Gcm::new_from_slice(key)
                    .ok()?
                    .encrypt_in_place(n, aad, buf)
                    .ok()
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let n = ChaNonce::from_slice(nonce12);
                ChaCha20Poly1305::new_from_slice(key)
                    .ok()?
                    .encrypt_in_place(n, aad, buf)
                    .ok()
            }
        }
    }

    /// In-place AEAD open: `buf` holds `ciphertext||tag` on entry; on success it is
    /// decrypted and truncated to the plaintext. Returns `None` on auth failure.
    pub fn aead_open_in_place(
        self,
        key: &[u8],
        nonce12: &[u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Option<()> {
        match self {
            CipherSuite::Aes128GcmSha256 => {
                let n = AesNonce::from_slice(nonce12);
                Aes128Gcm::new_from_slice(key)
                    .ok()?
                    .decrypt_in_place(n, aad, buf)
                    .ok()
            }
            CipherSuite::Aes256GcmSha384 => {
                let n = AesNonce::from_slice(nonce12);
                Aes256Gcm::new_from_slice(key)
                    .ok()?
                    .decrypt_in_place(n, aad, buf)
                    .ok()
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let n = ChaNonce::from_slice(nonce12);
                ChaCha20Poly1305::new_from_slice(key)
                    .ok()?
                    .decrypt_in_place(n, aad, buf)
                    .ok()
            }
        }
    }

    pub fn aead_open(
        self,
        key: &[u8],
        nonce12: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
    ) -> Option<Vec<u8>> {
        let p = Payload { msg: ct, aad };
        match self {
            CipherSuite::Aes128GcmSha256 => {
                let n = AesNonce::from_slice(nonce12);
                Aes128Gcm::new_from_slice(key).ok()?.decrypt(n, p).ok()
            }
            CipherSuite::Aes256GcmSha384 => {
                let n = AesNonce::from_slice(nonce12);
                Aes256Gcm::new_from_slice(key).ok()?.decrypt(n, p).ok()
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let n = ChaNonce::from_slice(nonce12);
                ChaCha20Poly1305::new_from_slice(key)
                    .ok()?
                    .decrypt(n, p)
                    .ok()
            }
        }
    }
}

/// Running TLS handshake transcript (stores bytes, hashes on demand).
pub struct Transcript {
    suite: CipherSuite,
    buf: Vec<u8>,
}

impl Transcript {
    pub fn new(suite: CipherSuite) -> Self {
        Transcript {
            suite,
            buf: Vec::new(),
        }
    }
    pub fn update(&mut self, msg: &[u8]) {
        self.buf.extend_from_slice(msg);
    }
    pub fn hash(&self) -> Vec<u8> {
        self.suite.hash(&self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_params() {
        let s = CipherSuite::Aes128GcmSha256;
        assert_eq!(s.to_u16(), 0x1301);
        assert_eq!(s.hash_len(), 32);
        assert_eq!(s.key_len(), 16);
        assert_eq!(
            CipherSuite::from_u16(0x1302),
            Some(CipherSuite::Aes256GcmSha384)
        );
        assert_eq!(CipherSuite::Aes256GcmSha384.hash_len(), 48);
        assert_eq!(CipherSuite::Aes256GcmSha384.key_len(), 32);
        assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.key_len(), 32);
        assert_eq!(CipherSuite::from_u16(0x9999), None);
    }

    #[test]
    fn aead_roundtrip_all_suites() {
        for s in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let key = vec![7u8; s.key_len()];
            let nonce = [3u8; 12];
            let ct = s.aead_seal(&key, &nonce, b"aad", b"plaintext").unwrap();
            assert_eq!(ct.len(), b"plaintext".len() + 16);
            let pt = s.aead_open(&key, &nonce, b"aad", &ct).unwrap();
            assert_eq!(pt, b"plaintext");
            assert!(s.aead_open(&key, &nonce, b"different-aad", &ct).is_none());
        }
    }

    #[test]
    fn in_place_matches_allocating_aead() {
        for s in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let key = vec![7u8; s.key_len()];
            let nonce = [3u8; 12];
            let pt = b"the-quick-brown-fox".to_vec();
            // In-place seal must produce the same ciphertext as the allocating path.
            let want = s.aead_seal(&key, &nonce, b"aad", &pt).unwrap();
            let mut buf = pt.clone();
            assert!(
                s.aead_seal_in_place(&key, &nonce, b"aad", &mut buf)
                    .is_some()
            );
            assert_eq!(buf, want, "{s:?} in-place seal mismatch");
            // In-place open recovers the plaintext and truncates the tag.
            assert!(
                s.aead_open_in_place(&key, &nonce, b"aad", &mut buf)
                    .is_some()
            );
            assert_eq!(buf, pt, "{s:?} in-place open mismatch");
            // Wrong AAD fails and is rejected.
            let mut bad = want.clone();
            assert!(
                s.aead_open_in_place(&key, &nonce, b"nope", &mut bad)
                    .is_none()
            );
        }
    }

    #[test]
    fn transcript_hash() {
        let mut t = Transcript::new(CipherSuite::Aes128GcmSha256);
        t.update(b"abc");
        // SHA-256("abc")
        assert_eq!(
            hex::encode(t.hash()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
