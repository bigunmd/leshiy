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
}
