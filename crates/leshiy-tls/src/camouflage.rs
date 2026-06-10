//! Per-connection TLS camouflage randomisation, matching Chromium/BoringSSL.
//!
//! Real Chromium does not send a frozen ClientHello: it randomises its GREASE
//! values and shuffles its TLS extension order on every connection. A static
//! emission (constant GREASE + fixed extension order) is itself a fingerprint, so
//! Leshiy reproduces both behaviours from fresh per-connection entropy.
//!
//! The entropy MUST be independent of anything on the wire (in particular the
//! TLS `random`, which is sent in clear): deriving GREASE from observable bytes
//! would let an adversary who reads this source recompute and detect us.
use sha2::{Digest, Sha256};

/// Returns true for GREASE values (RFC 8701): 0x?A?A where both bytes are equal.
pub(crate) fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// The set of per-connection GREASE values for one ClientHello, derived the way
/// BoringSSL does (see `ssl_get_grease_value`). `group` is used for BOTH the
/// supported_groups GREASE and the key_share GREASE (they always match in a real
/// Chromium hello); `ext1`/`ext2` are the two extension-list GREASE values and are
/// guaranteed distinct.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Grease {
    pub cipher: u16,
    pub group: u16,
    pub ext1: u16,
    pub ext2: u16,
    pub version: u16,
}

/// Map one seed byte to a GREASE value: high nibble kept, low nibble forced to
/// 0xA, mirrored across both bytes. e.g. 0xC3 -> 0xCA -> 0xCACA.
fn grease_from_byte(b: u8) -> u16 {
    let byte = (b & 0xf0) | 0x0a;
    ((byte as u16) << 8) | byte as u16
}

/// Derive the per-connection GREASE set from independent entropy (NOT from any
/// on-wire value). Uses one seed byte per GREASE slot.
pub(crate) fn derive_grease(entropy: &[u8; 32]) -> Grease {
    let cipher = grease_from_byte(entropy[0]);
    let group = grease_from_byte(entropy[1]);
    let ext1 = grease_from_byte(entropy[2]);
    let mut ext2 = grease_from_byte(entropy[3]);
    let version = grease_from_byte(entropy[4]);
    if ext2 == ext1 {
        // BoringSSL: the two fake extensions must not have the same value.
        // XOR by 0x1010 preserves the GREASE pattern and yields a distinct value.
        ext2 ^= 0x1010;
    }
    Grease {
        cipher,
        group,
        ext1,
        ext2,
        version,
    }
}

/// Expand `entropy` into `n` deterministic bytes, domain-separated by `domain`.
/// A simple SHA-256 counter stream — enough to drive shuffling and to fill the
/// opaque bytes of a GREASE-ECH from per-connection entropy.
fn expand(entropy: &[u8; 32], domain: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut counter = 0u8;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(entropy);
        h.update(domain);
        h.update([counter]);
        out.extend_from_slice(&h.finalize());
        counter = counter.wrapping_add(1);
    }
    out.truncate(n);
    out
}

/// A per-connection permutation of `0..n`, derived from independent `entropy`
/// (domain-separated from GREASE). Chromium shuffles its TLS extensions on every
/// connection (`ShuffleChromeTLSExtensions`); applying this to the non-GREASE
/// extension slots reproduces that behaviour so JA3 varies per connection.
pub(crate) fn chrome_ext_permutation(entropy: &[u8; 32], n: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    if n <= 1 {
        return perm;
    }
    // One u32 per Fisher-Yates step.
    let stream = expand(entropy, b"leshiy-ext-shuffle", (n - 1) * 4);
    let mut s = 0;
    for i in (1..n).rev() {
        let r = u32::from_le_bytes([stream[s], stream[s + 1], stream[s + 2], stream[s + 3]]);
        s += 4;
        let j = (r as usize) % (i + 1);
        perm.swap(i, j);
    }
    perm
}

/// Build a GREASE-ECH (`encrypted_client_hello`) OUTER body, as Chromium emits when
/// it has no real ECH config from DNS. Structure (draft-ietf-tls-esni §5):
///   [type=outer 0x00][kdf_id u16][aead_id u16][config_id u8][enc_len u16][enc][payload_len u16][payload]
/// with HKDF-SHA256 (0x0001) + AES-128-GCM (0x0001), a 32-byte X25519 `enc`, and a
/// random "encrypted" payload. All opaque bytes come from the per-connection
/// entropy stream; a server without a matching config_id ignores the extension.
pub(crate) fn grease_ech_outer(entropy: &[u8; 32]) -> Vec<u8> {
    // config_id(1) + enc(32) + payload_len_selector(1) + payload(up to 208).
    let stream = expand(entropy, b"leshiy-ech", 1 + 32 + 1 + 208);
    let config_id = stream[0];
    let enc = &stream[1..33];
    // Payload length 144..=208, derived from entropy (Chromium varies it per conn).
    let payload_len = 144 + (stream[33] as usize % 65);
    let payload = &stream[34..34 + payload_len];

    let mut b = Vec::with_capacity(8 + enc.len() + payload_len);
    b.push(0x00); // ECHClientHelloType = outer
    b.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf_id  = HKDF-SHA256
    b.extend_from_slice(&0x0001u16.to_be_bytes()); // aead_id = AES-128-GCM
    b.push(config_id);
    b.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    b.extend_from_slice(enc);
    b.extend_from_slice(&(payload_len as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BoringSSL derives each GREASE value from a seed byte: take the high nibble,
    /// set the low nibble to 0xA, and mirror across both bytes (0xΩaΩa). The
    /// supported_groups and key_share GREASE share one index; the two extension
    /// GREASE values must differ. These seed bytes reproduce the tls.peet.ws
    /// capture (cipher=0xCACA, group=0x6A6A, ext=0x5A5A/0x4A4A, version=0x0A0A).
    #[test]
    fn derive_grease_matches_boringssl_model() {
        let mut entropy = [0u8; 32];
        entropy[0] = 0xc3; // cipher  -> 0xCACA
        entropy[1] = 0x6f; // group   -> 0x6A6A
        entropy[2] = 0x5a; // ext1    -> 0x5A5A
        entropy[3] = 0x40; // ext2    -> 0x4A4A
        entropy[4] = 0x0e; // version -> 0x0A0A
        let g = derive_grease(&entropy);
        assert_eq!(g.cipher, 0xcaca);
        assert_eq!(g.group, 0x6a6a);
        assert_eq!(g.ext1, 0x5a5a);
        assert_eq!(g.ext2, 0x4a4a);
        assert_eq!(g.version, 0x0a0a);
        // All derived values must themselves be valid GREASE.
        for v in [g.cipher, g.group, g.ext1, g.ext2, g.version] {
            assert!(is_grease(v), "{v:#06x} should be a valid GREASE value");
        }
    }

    /// When the two extension seed bytes share a high nibble (and would collide),
    /// BoringSSL forces them apart so the ClientHello has no duplicate extension.
    #[test]
    fn derive_grease_forces_distinct_extension_values() {
        let mut entropy = [0u8; 32];
        entropy[2] = 0x50; // ext1 -> 0x5A5A
        entropy[3] = 0x5f; // ext2 -> would also be 0x5A5A
        let g = derive_grease(&entropy);
        assert_ne!(
            g.ext1, g.ext2,
            "the two extension GREASE values must differ"
        );
        assert!(is_grease(g.ext2));
    }

    /// The permutation must be a genuine permutation of 0..n (no lost/duplicated
    /// indices) for every length we care about.
    #[test]
    fn chrome_ext_permutation_is_a_valid_permutation() {
        let entropy = [0x5au8; 32];
        for n in [0usize, 1, 2, 16] {
            let mut perm = chrome_ext_permutation(&entropy, n);
            assert_eq!(perm.len(), n);
            perm.sort_unstable();
            assert_eq!(perm, (0..n).collect::<Vec<_>>());
        }
    }

    /// Same entropy -> same order (deterministic); different entropy -> different
    /// order (so JA3 varies connection-to-connection, like real Chromium).
    #[test]
    fn chrome_ext_permutation_depends_on_entropy() {
        let a = chrome_ext_permutation(&[0x11u8; 32], 16);
        let a2 = chrome_ext_permutation(&[0x11u8; 32], 16);
        let b = chrome_ext_permutation(&[0x22u8; 32], 16);
        assert_eq!(a, a2, "deterministic for the same entropy");
        assert_ne!(a, b, "different entropy must shuffle differently");
    }

    /// The GREASE-ECH outer body must have Chromium's structure: outer type, the
    /// HKDF-SHA256 / AES-128-GCM cipher suite, a 32-byte X25519 `enc`, and a
    /// length-prefixed payload — all self-consistent and ~186 bytes, not the
    /// 1-byte stub. It is deterministic for a given entropy.
    #[test]
    fn grease_ech_outer_has_chromium_structure() {
        let body = grease_ech_outer(&[0x37u8; 32]);
        assert_eq!(body[0], 0x00, "ECHClientHelloType = outer");
        assert_eq!(
            u16::from_be_bytes([body[1], body[2]]),
            0x0001,
            "kdf=HKDF-SHA256"
        );
        assert_eq!(
            u16::from_be_bytes([body[3], body[4]]),
            0x0001,
            "aead=AES-128-GCM"
        );
        // config_id at body[5]; enc_length at body[6..8].
        let enc_len = u16::from_be_bytes([body[6], body[7]]) as usize;
        assert_eq!(enc_len, 32, "enc is a 32-byte X25519 public key");
        let payload_off = 8 + enc_len;
        let payload_len = u16::from_be_bytes([body[payload_off], body[payload_off + 1]]) as usize;
        // Body is fully consumed by header + enc + payload (no trailing junk).
        assert_eq!(body.len(), payload_off + 2 + payload_len);
        assert!(
            body.len() >= 180,
            "realistic GREASE-ECH is ~186 bytes, got {}",
            body.len()
        );
        // Deterministic for the same entropy.
        assert_eq!(body, grease_ech_outer(&[0x37u8; 32]));
    }
}
