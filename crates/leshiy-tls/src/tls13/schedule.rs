//! TLS 1.3 key schedule (RFC 8446 §7.1): the secret tree + traffic keys + Finished.
use crate::tls13::kdf::{derive_secret, hkdf_expand_label, hkdf_extract};
use crate::tls13::suite::CipherSuite;

fn zeros(suite: CipherSuite) -> Vec<u8> {
    vec![0u8; suite.hash_len()]
}

/// early_secret = HKDF-Extract(salt=0, IKM=0^hashlen).
pub fn early_secret(suite: CipherSuite) -> Vec<u8> {
    hkdf_extract(suite, &[], &zeros(suite))
}

/// handshake_secret = HKDF-Extract(salt=Derive-Secret(early,"derived",""), IKM=ecdhe).
pub fn handshake_secret(suite: CipherSuite, early: &[u8], ecdhe: &[u8]) -> Vec<u8> {
    let empty_hash = suite.hash(&[]);
    let derived = hkdf_expand_label(suite, early, "derived", &empty_hash, suite.hash_len());
    hkdf_extract(suite, &derived, ecdhe)
}

/// master_secret = HKDF-Extract(salt=Derive-Secret(hs,"derived",""), IKM=0^hashlen).
pub fn master_secret(suite: CipherSuite, handshake: &[u8]) -> Vec<u8> {
    let empty_hash = suite.hash(&[]);
    let derived = hkdf_expand_label(suite, handshake, "derived", &empty_hash, suite.hash_len());
    hkdf_extract(suite, &derived, &zeros(suite))
}

pub fn client_hs_traffic(suite: CipherSuite, hs: &[u8], th_chsh: &[u8]) -> Vec<u8> {
    derive_secret(suite, hs, "c hs traffic", th_chsh)
}
pub fn server_hs_traffic(suite: CipherSuite, hs: &[u8], th_chsh: &[u8]) -> Vec<u8> {
    derive_secret(suite, hs, "s hs traffic", th_chsh)
}
pub fn client_ap_traffic(suite: CipherSuite, master: &[u8], th_sfin: &[u8]) -> Vec<u8> {
    derive_secret(suite, master, "c ap traffic", th_sfin)
}
pub fn server_ap_traffic(suite: CipherSuite, master: &[u8], th_sfin: &[u8]) -> Vec<u8> {
    derive_secret(suite, master, "s ap traffic", th_sfin)
}

/// (key, iv) for a traffic secret. iv is always 12 bytes.
pub fn traffic_key(suite: CipherSuite, traffic_secret: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let key = hkdf_expand_label(suite, traffic_secret, "key", b"", suite.key_len());
    let iv_v = hkdf_expand_label(suite, traffic_secret, "iv", b"", 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_v);
    (key, iv)
}

/// Finished verify_data = HMAC-Hash(finished_key, transcript_hash),
/// finished_key = HKDF-Expand-Label(base_key, "finished", "", hash_len).
pub fn finished_verify_data(
    suite: CipherSuite,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let fk = hkdf_expand_label(suite, base_key, "finished", b"", suite.hash_len());
    match suite {
        CipherSuite::Aes256GcmSha384 => {
            let mut m = <Hmac<sha2::Sha384>>::new_from_slice(&fk).expect("hmac key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut m = <Hmac<sha2::Sha256>>::new_from_slice(&fk).expect("hmac key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::suite::{CipherSuite, Transcript};

    const S: CipherSuite = CipherSuite::Aes128GcmSha256;
    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }
    fn fx(name: &str) -> String {
        // read a `name = <hex>` line from tests/fixtures/rfc8448.md
        let f = std::fs::read_to_string(format!(
            "{}/tests/fixtures/rfc8448.md",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        f.lines()
            .find_map(|l| {
                l.strip_prefix(&format!("{name} = "))
                    .map(|v| v.trim().to_string())
            })
            .expect(name)
    }

    #[test]
    fn rfc8448_secret_tree() {
        let ecdhe = h(&fx("ecdhe_shared"));
        // transcript CH..SH from the committed raw handshake bytes
        let mut th = Transcript::new(S);
        th.update(&h(&fx("client_hello")));
        th.update(&h(&fx("server_hello")));
        let th_chsh = th.hash();

        let early = early_secret(S);
        assert_eq!(hex::encode(&early), fx("early_secret"));
        let hs = handshake_secret(S, &early, &ecdhe);
        assert_eq!(hex::encode(&hs), fx("handshake_secret"));
        assert_eq!(
            hex::encode(client_hs_traffic(S, &hs, &th_chsh)),
            fx("client_hs_traffic")
        );
        assert_eq!(
            hex::encode(server_hs_traffic(S, &hs, &th_chsh)),
            fx("server_hs_traffic")
        );
        let master = master_secret(S, &hs);
        assert_eq!(hex::encode(&master), fx("master_secret"));

        // server handshake write key/iv (RFC 8448)
        let (key, iv) = traffic_key(S, &h(&fx("server_hs_traffic")));
        assert_eq!(hex::encode(key), "3fce516009c21727d0f2e4e86ee403bc");
        assert_eq!(hex::encode(iv), "5d313eb2671276ee13000b30");
    }

    #[test]
    fn finished_roundtrip_all_suites() {
        for s in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let base = vec![5u8; s.hash_len()];
            let th = s.hash(b"transcript");
            let a = finished_verify_data(s, &base, &th);
            let b = finished_verify_data(s, &base, &th);
            assert_eq!(a, b);
            assert_eq!(a.len(), s.hash_len());
            let (key, iv) = traffic_key(s, &base);
            assert_eq!(key.len(), s.key_len());
            assert_eq!(iv.len(), 12);
        }
    }
}
