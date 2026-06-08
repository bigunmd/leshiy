//! TLS 1.3 HKDF helpers (RFC 8446 §7.1), dispatched by suite hash.
use crate::tls13::suite::CipherSuite;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

/// HKDF-Extract(salt, ikm) using the suite's hash.
pub fn hkdf_extract(suite: CipherSuite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::Aes256GcmSha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
        _ => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
    }
}

/// HKDF-Expand-Label(secret, label, context, length) per RFC 8446 §7.1.
pub fn hkdf_expand_label(
    suite: CipherSuite,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    // HkdfLabel = u16(length) | u8(len("tls13 "+label)) | "tls13 "+label | u8(len(context)) | context
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full_label.len() + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut okm = vec![0u8; length];
    match suite {
        CipherSuite::Aes256GcmSha384 => {
            Hkdf::<Sha384>::from_prk(secret)
                .expect("prk len")
                .expand(&info, &mut okm)
                .expect("hkdf expand len");
        }
        _ => {
            Hkdf::<Sha256>::from_prk(secret)
                .expect("prk len")
                .expand(&info, &mut okm)
                .expect("hkdf expand len");
        }
    }
    okm
}

/// Derive-Secret(secret, label, transcript_hash) = HKDF-Expand-Label(secret, label, th, hash_len).
pub fn derive_secret(
    suite: CipherSuite,
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8],
) -> Vec<u8> {
    hkdf_expand_label(suite, secret, label, transcript_hash, suite.hash_len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::suite::CipherSuite;

    #[test]
    fn expand_label_known_vector() {
        // RFC 8448 §3: derive server handshake write key from the
        // server_handshake_traffic_secret via HKDF-Expand-Label(secret,"key","",16).
        let secret =
            hex::decode("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
                .unwrap();
        let key = hkdf_expand_label(CipherSuite::Aes128GcmSha256, &secret, "key", b"", 16);
        assert_eq!(hex::encode(key), "3fce516009c21727d0f2e4e86ee403bc");
        let iv = hkdf_expand_label(CipherSuite::Aes128GcmSha256, &secret, "iv", b"", 12);
        assert_eq!(hex::encode(iv), "5d313eb2671276ee13000b30");
    }

    #[test]
    fn extract_zero_is_early_secret() {
        // HKDF-Extract(salt=0, IKM=0^hashlen) = early_secret (RFC 8448 §3)
        let es = hkdf_extract(CipherSuite::Aes128GcmSha256, &[], &[0u8; 32]);
        assert_eq!(
            hex::encode(es),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );
    }
}
