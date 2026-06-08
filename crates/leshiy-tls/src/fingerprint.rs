//! Declarative browser TLS fingerprint profiles. Values mirror a real capture
//! (see tests/fixtures/SOURCE.md); ordering is significant for JA3/JA4 reproduction.
//!
//! `Profile::yandex()` is the default profile — it uses the Chrome 134 (Mac) field
//! layout documented as a fallback in SOURCE.md (see "Authenticity & Fallback" section).
//! The field lists are chosen so that when projected into a `ClientHelloView`, the
//! computed JA4 equals the committed fixture `yandex.ja4`.

/// Primary GREASE placeholder value (RFC 8701, §3.1).
/// Any value where both bytes are equal and their lower nibble is 0xA is valid.
/// JA4/JA3 strip all GREASE values before hashing, so changing this constant
/// does not affect the computed fingerprint hashes.
const GREASE: u16 = 0x0a0a;

/// Secondary GREASE value used where a second GREASE entry is needed in the same
/// extension list (e.g. the trailing GREASE extension in the Yandex profile).
/// Must be a different GREASE value than `GREASE` so that rustls does not reject
/// the ClientHello with `DuplicateExtension`.  0x1a1a satisfies the GREASE
/// predicate: `(0x1a1a & 0x0f0f) == 0x0a0a` and `0x1a == 0x1a`.
const GREASE2: u16 = 0x1a1a;

/// Declarative browser TLS fingerprint profile.
///
/// All list fields carry their values in **wire order** including GREASE placeholders
/// at the positions a real browser would place them. The JA3/JA4 functions in `ja.rs`
/// automatically strip GREASE before computing fingerprint hashes.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Identifying name for this profile (e.g. "yandex", "chrome").
    pub name: &'static str,
    /// Cipher suites in wire order; includes GREASE placeholder(s) in real positions.
    pub cipher_suites: Vec<u16>,
    /// Extension type IDs in wire order; includes GREASE placeholder(s) in real positions.
    pub extensions: Vec<u16>,
    /// Supported elliptic curve groups (extension 0x000A) in wire order.
    pub supported_groups: Vec<u16>,
    /// EC point formats (extension 0x000B): typically just `[0x00]` (uncompressed).
    pub ec_point_formats: Vec<u8>,
    /// Signature algorithms (extension 0x000D) in wire order (NOT sorted).
    pub sig_algs: Vec<u16>,
    /// Supported TLS versions (extension 0x002B) in wire order; first entry is often GREASE.
    pub supported_versions: Vec<u16>,
    /// ALPN protocols in wire order; e.g. `["h2", "http/1.1"]`.
    pub alpn: Vec<String>,
}

impl Profile {
    /// Default profile: Yandex Browser (Russia-blending camouflage).
    ///
    /// Field values are taken from the Chrome 134 (Mac) fixture documented in
    /// `tests/fixtures/SOURCE.md` (see "Authenticity & Fallback Rationale").
    /// When these lists are projected into a `ClientHelloView` (with `has_sni = true`),
    /// `ja4(&view)` produces the exact JA4 string committed in `tests/fixtures/yandex.ja4`.
    ///
    /// JA4 part A breakdown: `t13d1516h2`
    ///   - protocol = `t` (TCP/TLS)
    ///   - version  = `13` (TLS 1.3, from supported_versions containing 0x0304)
    ///   - sni      = `d` (has_sni = true, domain present)
    ///   - ciphers  = `15` (15 non-GREASE cipher suites)
    ///   - exts     = `16` (16 non-GREASE extensions)
    ///   - alpn     = `h2` (first+last chars of "h2")
    pub fn yandex() -> Profile {
        Profile {
            name: "yandex",

            // 1 GREASE placeholder (position 0) + 15 real cipher suites.
            // Non-GREASE count = 15 → JA4 Part A nci = 15.
            // Source: SOURCE.md "Cipher Suites" table.
            cipher_suites: vec![
                GREASE, // position 0: GREASE placeholder (any 0x?A?A)
                4865,   // 0x1301 TLS_AES_128_GCM_SHA256
                4866,   // 0x1302 TLS_AES_256_GCM_SHA384
                4867,   // 0x1303 TLS_CHACHA20_POLY1305_SHA256
                49195,  // 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                49199,  // 0xC02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                49196,  // 0xC02C TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                49200,  // 0xC030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                52393,  // 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                52392,  // 0xCCA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                49171,  // 0xC013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                49172,  // 0xC014 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                156,    // 0x009C TLS_RSA_WITH_AES_128_GCM_SHA256
                157,    // 0x009D TLS_RSA_WITH_AES_256_GCM_SHA384
                47,     // 0x002F TLS_RSA_WITH_AES_128_CBC_SHA
                53,     // 0x0035 TLS_RSA_WITH_AES_256_CBC_SHA
            ],

            // GREASE at start, 16 real extensions, GREASE at end — as real Chrome does.
            // Non-GREASE count = 16 → JA4 Part A nex = 16.
            // Order from the observed JA3 capture in SOURCE.md:
            //   51,27,65281,18,45,0,35,5,11,43,16,65037,23,17613,13,10
            extensions: vec![
                GREASE, // position 0: GREASE extension (before first real extension)
                51,     // 0x0033 key_share
                27,     // 0x001B compress_certificate
                65281,  // 0xFF01 renegotiation_info
                18,     // 0x0012 signed_certificate_timestamp (SCT)
                45,     // 0x002D psk_key_exchange_modes
                0,      // 0x0000 server_name (SNI)
                35,     // 0x0023 session_ticket
                5,      // 0x0005 status_request
                11,     // 0x000B ec_point_formats
                43,     // 0x002B supported_versions
                16,     // 0x0010 ALPN
                65037,  // 0xFE0D encrypted_client_hello (ECH / GREASE outer in real Chrome)
                23,     // 0x0017 extended_master_secret
                17613,  // 0x44CD application_settings (ALPS)
                13,     // 0x000D signature_algorithms
                10,     // 0x000A supported_groups
                GREASE2, // position 17: second GREASE extension (after last real extension)
                        // Must differ from position-0 GREASE to avoid DuplicateExtension.
            ],

            // GREASE + 4 real groups.
            // Source: SOURCE.md "Supported Groups" table.
            supported_groups: vec![
                GREASE, // GREASE placeholder
                4588,   // 0x11EC X25519MLKEM768 (hybrid post-quantum)
                29,     // 0x001D x25519
                23,     // 0x0017 secp256r1 (P-256)
                24,     // 0x0018 secp384r1 (P-384)
            ],

            // Uncompressed only — the universal Chrome/Yandex ec_point_format.
            ec_point_formats: vec![0x00],

            // 8 signature algorithms in wire order (NOT sorted).
            // Source: SOURCE.md "Signature Algorithms" table.
            sig_algs: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0804, // rsa_pss_rsae_sha256
                0x0401, // rsa_pkcs1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0805, // rsa_pss_rsae_sha384
                0x0501, // rsa_pkcs1_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0601, // rsa_pkcs1_sha512
            ],

            // GREASE + TLS 1.3 + TLS 1.2, as Chrome sends.
            supported_versions: vec![
                GREASE, // GREASE placeholder
                0x0304, // TLS 1.3
                0x0303, // TLS 1.2
            ],

            alpn: vec!["h2".into(), "http/1.1".into()],
        }
    }

    /// Secondary profile: Chrome (approximation).
    ///
    /// TODO: Replace with a dedicated Chrome fixture when available. For now this
    /// delegates to `yandex()` since both are Chromium-based and share the same
    /// TLS field layout for Chrome 134 (Mac). A real Chrome fixture may differ in
    /// minor extension details.
    pub fn chrome() -> Profile {
        let mut p = Profile::yandex();
        p.name = "chrome";
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ja::{ClientHelloView, ja4};

    fn fixture_str(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap()
        .trim()
        .to_string()
    }

    /// Build a ClientHelloView from the yandex Profile (has_sni=true) and assert that
    /// the computed JA4 equals the committed fixture in tests/fixtures/yandex.ja4.
    ///
    /// Expected JA4: t13d1516h2_8daaf6152771_d8a2da3f94cd
    ///   Part A: t=TCP/TLS  13=TLS1.3  d=SNI-domain  15=15-ciphers  16=16-exts  h2=ALPN
    #[test]
    fn yandex_profile_reproduces_fixture_ja4() {
        let p = Profile::yandex();
        let view = ClientHelloView {
            legacy_version: 0x0303,
            cipher_suites: p.cipher_suites.clone(),
            extensions: p.extensions.clone(),
            supported_groups: p.supported_groups.clone(),
            ec_point_formats: p.ec_point_formats.clone(),
            sig_algs: p.sig_algs.clone(),
            alpn: p.alpn.clone(),
            has_sni: true,
            supported_versions: p.supported_versions.clone(),
        };
        assert_eq!(ja4(&view), fixture_str("yandex.ja4"));
    }

    /// Verify the GREASE constant used in all lists is a valid GREASE value.
    #[test]
    fn grease_constant_is_valid() {
        // 0x0a0a: low nibbles of both bytes are 0xa, and both bytes are equal.
        assert_eq!(GREASE & 0x0f0f, 0x0a0a);
        assert_eq!(GREASE >> 8, GREASE & 0xff);
    }

    /// Verify that chrome() delegates to yandex() for now (same JA4 result).
    #[test]
    fn chrome_profile_same_ja4_as_yandex() {
        let yandex_view = {
            let p = Profile::yandex();
            ClientHelloView {
                legacy_version: 0x0303,
                cipher_suites: p.cipher_suites.clone(),
                extensions: p.extensions.clone(),
                supported_groups: p.supported_groups.clone(),
                ec_point_formats: p.ec_point_formats.clone(),
                sig_algs: p.sig_algs.clone(),
                alpn: p.alpn.clone(),
                has_sni: true,
                supported_versions: p.supported_versions.clone(),
            }
        };
        let chrome_view = {
            let p = Profile::chrome();
            ClientHelloView {
                legacy_version: 0x0303,
                cipher_suites: p.cipher_suites.clone(),
                extensions: p.extensions.clone(),
                supported_groups: p.supported_groups.clone(),
                ec_point_formats: p.ec_point_formats.clone(),
                sig_algs: p.sig_algs.clone(),
                alpn: p.alpn.clone(),
                has_sni: true,
                supported_versions: p.supported_versions.clone(),
            }
        };
        assert_eq!(ja4(&yandex_view), ja4(&chrome_view));
    }
}
