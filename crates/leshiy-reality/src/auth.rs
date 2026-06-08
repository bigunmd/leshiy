//! REALITY-style auth: HKDF key derivation + AES-256-GCM session_id seal/open.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const HKDF_INFO: &[u8] = b"leshiy-reality";
const SID_OFFSET: usize = 39; // ClientHello: type(1)+len(3)+ver(2)+random(32)+sid_len(1)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthPayload {
    pub version: [u8; 3],
    pub unix_secs: u32,
    pub short_id: [u8; 8],
}

impl AuthPayload {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..3].copy_from_slice(&self.version);
        b[3] = 0;
        b[4..8].copy_from_slice(&self.unix_secs.to_be_bytes());
        b[8..16].copy_from_slice(&self.short_id);
        b
    }
    pub fn decode(b: &[u8; 16]) -> AuthPayload {
        let mut version = [0u8; 3];
        version.copy_from_slice(&b[0..3]);
        let unix_secs = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let mut short_id = [0u8; 8];
        short_id.copy_from_slice(&b[8..16]);
        AuthPayload {
            version,
            unix_secs,
            short_id,
        }
    }
}

/// auth_key = HKDF-SHA256(ikm = X25519 shared, salt = ch_random[0..20], info = "leshiy-reality").
/// Returned zeroizing so the derived key is wiped on drop.
pub fn derive_auth_key(shared: &[u8; 32], ch_random: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&ch_random[0..20]), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, &mut *okm)
        .expect("32 is a valid HKDF length");
    okm
}

/// Returns the 32-byte session_id (16 ciphertext + 16 GCM tag).
pub fn seal_session_id(
    auth_key: &[u8; 32],
    ch_random: &[u8; 32],
    payload: &AuthPayload,
    aad: &[u8],
) -> [u8; 32] {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let nonce = Nonce::from_slice(&ch_random[20..32]);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &payload.encode(),
                aad,
            },
        )
        .expect("aes-gcm seal");
    let mut sid = [0u8; 32];
    sid.copy_from_slice(&ct); // 16 ct + 16 tag = 32
    sid
}

/// Returns the 16-byte plaintext if the tag verifies, else None.
pub fn open_session_id(
    auth_key: &[u8; 32],
    ch_random: &[u8; 32],
    session_id: &[u8; 32],
    aad: &[u8],
) -> Option<[u8; 16]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let nonce = Nonce::from_slice(&ch_random[20..32]);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: session_id,
                aad,
            },
        )
        .ok()?;
    if pt.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&pt);
    Some(out)
}

/// AAD = the ClientHello bytes with the 32-byte session_id field zeroed.
pub fn aad_from_client_hello(ch: &[u8]) -> Vec<u8> {
    let mut aad = ch.to_vec();
    if ch.len() > SID_OFFSET {
        let sid_len = ch.get(SID_OFFSET - 1).copied().unwrap_or(0) as usize;
        let end = (SID_OFFSET + sid_len).min(aad.len());
        for b in &mut aad[SID_OFFSET..end] {
            *b = 0;
        }
    }
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_roundtrip() {
        let p = AuthPayload {
            version: [1, 2, 3],
            unix_secs: 0xAABBCCDD,
            short_id: [9; 8],
        };
        assert_eq!(AuthPayload::decode(&p.encode()), p);
    }

    #[test]
    fn seal_open_roundtrip() {
        let auth_key = [7u8; 32];
        let random = [3u8; 32];
        let aad = b"the-clienthello-with-sid-zeroed";
        let p = AuthPayload {
            version: [0, 0, 1],
            unix_secs: 1_700_000_000,
            short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        };
        let sid = seal_session_id(&auth_key, &random, &p, aad);
        assert_eq!(sid.len(), 32);
        let got = open_session_id(&auth_key, &random, &sid, aad).unwrap();
        assert_eq!(AuthPayload::decode(&got), p);
    }

    #[test]
    fn open_fails_wrong_key() {
        let random = [3u8; 32];
        let aad = b"aad";
        let p = AuthPayload {
            version: [0, 0, 1],
            unix_secs: 1,
            short_id: [0; 8],
        };
        let sid = seal_session_id(&[7u8; 32], &random, &p, aad);
        assert!(open_session_id(&[8u8; 32], &random, &sid, aad).is_none());
    }

    #[test]
    fn open_fails_tampered_aad() {
        let random = [3u8; 32];
        let p = AuthPayload {
            version: [0, 0, 1],
            unix_secs: 1,
            short_id: [0; 8],
        };
        let sid = seal_session_id(&[7u8; 32], &random, &p, b"aad-1");
        assert!(open_session_id(&[7u8; 32], &random, &sid, b"aad-2").is_none());
    }

    #[test]
    fn aad_zeroes_only_session_id() {
        use leshiy_tls::client_hello::build_client_hello;
        use leshiy_tls::fingerprint::Profile;
        let ch = build_client_hello(
            &Profile::yandex(),
            "a.example",
            &[1u8; 32],
            &[0u8; 1184],
            [2u8; 32],
        );
        let aad = aad_from_client_hello(&ch);
        assert_eq!(aad.len(), ch.len());
        // session_id is 32 bytes at offset 39..71 and must be zero in the AAD
        assert!(aad[39..71].iter().all(|&b| b == 0));
        // bytes before 39 unchanged
        assert_eq!(&aad[..39], &ch[..39]);
    }
}
