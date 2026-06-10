//! Build a profile-fingerprinted TLS 1.3 ClientHello handshake message.
//!
//! The built message round-trips through `ClientHelloView::parse` and produces the
//! committed JA4 fixture. Like real Chromium, each connection randomises its GREASE
//! values and shuffles the non-GREASE extension order (see `camouflage`), so the JA4
//! is stable but the JA3 varies connection-to-connection. SNI (0x0000) and key_share
//! (0x0033) are injected from the call arguments.
use crate::camouflage::{Grease, chrome_ext_permutation, derive_grease, is_grease};
use crate::fingerprint::Profile;
use rand::RngCore;

/// Build a ClientHello handshake message (starts with 0x01) from `profile`.
///
/// - `sni`: inserted as the `server_name` extension body.
/// - `x25519_pub`: 32-byte x25519 public key, inserted in the `key_share` extension.
/// - `mlkem_ek`: 1184-byte ML-KEM-768 encapsulation key, included in the 0x11EC key_share entry.
/// - `random`: 32-byte client random (pass fresh entropy in production; deterministic in tests).
///
/// The `legacy_session_id` is set to 32 bytes (mirrors current Chromium behaviour).
/// GREASE extension entries from the profile are emitted with an empty body, which
/// is correct for JA4/JA3 round-trips (those fingerprints only care about the type IDs).
///
/// The key_share (0x0033) extension emits three entries in order:
///   1. GREASE (group = per-connection GREASE value, 1-byte key 0x00) — matches browser CH
///   2. X25519MLKEM768 (0x11EC): mlkem_ek(1184) ‖ x25519_pub(32) = 1216 bytes
///   3. X25519 (0x001D): x25519_pub(32) bytes
pub fn build_client_hello(
    profile: &Profile,
    sni: &str,
    x25519_pub: &[u8; 32],
    mlkem_ek: &[u8; 1184],
    random: [u8; 32],
) -> Vec<u8> {
    // Fresh per-connection entropy for GREASE values + extension shuffle. This MUST
    // be independent of `random` (which is sent in clear): deriving the camouflage
    // from an on-wire value would let an adversary recompute and detect it.
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    build_client_hello_with_entropy(profile, sni, x25519_pub, mlkem_ek, random, entropy)
}

/// Like [`build_client_hello`] but with caller-supplied camouflage `entropy`, for
/// deterministic tests. `entropy` drives the per-connection GREASE values and the
/// extension shuffle; it is never transmitted.
pub fn build_client_hello_with_entropy(
    profile: &Profile,
    sni: &str,
    x25519_pub: &[u8; 32],
    mlkem_ek: &[u8; 1184],
    random: [u8; 32],
    entropy: [u8; 32],
) -> Vec<u8> {
    let grease = derive_grease(&entropy);
    let mut body = Vec::new();

    // legacy_version: 0x0303 (TLS 1.2 compat)
    body.extend_from_slice(&[0x03, 0x03]);

    // random (32 bytes)
    body.extend_from_slice(&random);

    // legacy_session_id: 32 bytes (mirrors Chromium — all-zeros or random)
    body.push(32u8);
    body.extend_from_slice(&random);

    // cipher_suites: u16 length-prefixed list; substitute the per-connection cipher
    // GREASE value into the GREASE placeholder.
    let cs_bytes: Vec<u8> = profile
        .cipher_suites
        .iter()
        .map(|&c| if is_grease(c) { grease.cipher } else { c })
        .flat_map(|c| c.to_be_bytes())
        .collect();
    body.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cs_bytes);

    // compression methods: 1 method = null (0x00)
    body.extend_from_slice(&[0x01, 0x00]);

    // extensions: the non-GREASE extensions are shuffled per connection (Chromium's
    // ShuffleChromeTLSExtensions); one GREASE extension is pinned first (empty body)
    // and one last (single 0x00 byte), carrying the per-connection ext1/ext2 values.
    let middle: Vec<u16> = profile
        .extensions
        .iter()
        .copied()
        .filter(|t| !is_grease(*t))
        .collect();
    let perm = chrome_ext_permutation(&entropy, middle.len());

    let mut ext_bytes = Vec::new();
    // leading GREASE extension (empty body)
    ext_bytes.extend_from_slice(&grease.ext1.to_be_bytes());
    ext_bytes.extend_from_slice(&0u16.to_be_bytes());
    // real extensions in shuffled order
    for &idx in &perm {
        let etype = middle[idx];
        let ebody = build_extension(etype, profile, sni, x25519_pub, mlkem_ek, &grease);
        ext_bytes.extend_from_slice(&etype.to_be_bytes());
        ext_bytes.extend_from_slice(&(ebody.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&ebody);
    }
    // trailing GREASE extension (single 0x00 byte)
    ext_bytes.extend_from_slice(&grease.ext2.to_be_bytes());
    ext_bytes.extend_from_slice(&1u16.to_be_bytes());
    ext_bytes.push(0x00);

    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    // Wrap in Handshake header: [0x01][u24 body_len][body]
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(0x01); // ClientHello
    let blen = body.len() as u32;
    msg.push((blen >> 16) as u8);
    msg.push((blen >> 8) as u8);
    msg.push(blen as u8);
    msg.extend_from_slice(&body);
    msg
}

/// Build the body bytes for a single TLS extension identified by `etype`.
///
/// Only the extension types that appear in the Yandex profile are handled; all
/// other types (including GREASE entries and opaque extensions whose bodies
/// are zero-length for fingerprinting purposes) return an empty `Vec`.
fn build_extension(
    etype: u16,
    profile: &Profile,
    sni: &str,
    x25519_pub: &[u8; 32],
    mlkem_ek: &[u8; 1184],
    grease: &Grease,
) -> Vec<u8> {
    match etype {
        // server_name (SNI) — RFC 6066 §3
        // Structure: [list_len u16][name_type u8 = 0x00][host_len u16][host bytes]
        0x0000 => {
            let host = sni.as_bytes();
            let mut b = Vec::new();
            // entry = name_type(1) + host_len(2) + host(n)
            let entry_len = 1u16 + 2u16 + host.len() as u16;
            b.extend_from_slice(&entry_len.to_be_bytes()); // ServerNameList length
            b.push(0x00); // name_type = host_name
            b.extend_from_slice(&(host.len() as u16).to_be_bytes());
            b.extend_from_slice(host);
            b
        }

        // supported_groups (elliptic_curves) — RFC 8422
        // Structure: [list_len u16][group u16 ...]; GREASE placeholder gets the
        // per-connection group value (shared with key_share).
        0x000a => {
            let groups: Vec<u16> = profile
                .supported_groups
                .iter()
                .map(|&g| if is_grease(g) { grease.group } else { g })
                .collect();
            list_u16_with_u16len(&groups)
        }

        // ec_point_formats — RFC 8422
        // Structure: [count u8][format u8 ...]
        0x000b => {
            let mut b = Vec::with_capacity(1 + profile.ec_point_formats.len());
            b.push(profile.ec_point_formats.len() as u8);
            b.extend_from_slice(&profile.ec_point_formats);
            b
        }

        // signature_algorithms — RFC 8446 §4.2.3
        // Structure: [list_len u16][scheme u16 ...]
        0x000d => list_u16_with_u16len(&profile.sig_algs),

        // ALPN — RFC 7301
        // Structure: [protocol_list_len u16][proto_len u8][proto bytes] ...
        0x0010 => {
            let mut protos = Vec::new();
            for a in &profile.alpn {
                protos.push(a.len() as u8);
                protos.extend_from_slice(a.as_bytes());
            }
            let mut b = Vec::with_capacity(2 + protos.len());
            b.extend_from_slice(&(protos.len() as u16).to_be_bytes()); // protocol_list length
            b.extend_from_slice(&protos);
            b
        }

        // supported_versions — RFC 8446 §4.2.1
        // In ClientHello: [versions_len u8][version u16 ...]
        0x002b => {
            let versions_bytes_len = (profile.supported_versions.len() * 2) as u8;
            let mut b = Vec::with_capacity(1 + profile.supported_versions.len() * 2);
            b.push(versions_bytes_len);
            for &v in &profile.supported_versions {
                let v = if is_grease(v) { grease.version } else { v };
                b.extend_from_slice(&v.to_be_bytes());
            }
            b
        }

        // key_share — RFC 8446 §4.2.8
        // In ClientHello: [client_shares_len u16][group u16][key_exchange_len u16][key_exchange bytes]
        // We emit three entries in browser order:
        //   1. GREASE (group = per-connection GREASE value, 1-byte key 0x00)
        //   2. X25519MLKEM768 (0x11EC): mlkem_ek(1184) || x25519_pub(32) = 1216 bytes
        //   3. X25519 (0x001D): x25519_pub(32) bytes
        0x0033 => {
            let mut entries = Vec::new();
            // GREASE key_share — group equals the per-connection supported_groups
            // GREASE value (BoringSSL uses one index for both), 1-byte key.
            entries.extend_from_slice(&grease.group.to_be_bytes());
            entries.extend_from_slice(&1u16.to_be_bytes());
            entries.push(0x00);
            // X25519MLKEM768 (0x11ec): ek(1184) || x25519(32) = 1216
            entries.extend_from_slice(&0x11ecu16.to_be_bytes());
            entries.extend_from_slice(&1216u16.to_be_bytes());
            entries.extend_from_slice(mlkem_ek);
            entries.extend_from_slice(x25519_pub);
            // X25519 (0x001d): 32
            entries.extend_from_slice(&0x001du16.to_be_bytes());
            entries.extend_from_slice(&32u16.to_be_bytes());
            entries.extend_from_slice(x25519_pub);
            let mut b = (entries.len() as u16).to_be_bytes().to_vec();
            b.extend_from_slice(&entries);
            b
        }

        // renegotiation_info (0xff01) — RFC 5746 §3.3.
        // Body: [renegotiated_connection_len u8 = 0x00] (empty, initial handshake).
        // rustls validates this field; an empty body triggers decode_error(50).
        0xff01 => vec![0x00],

        // psk_key_exchange_modes (0x002d) — RFC 8446 §4.2.9.
        // Body: [modes_len u8 = 0x01][mode psk_dhe_ke = 0x01].
        // rustls requires at least one valid mode; an empty body is a decode_error.
        0x002d => vec![0x01, 0x01],

        // status_request (0x0005) — RFC 6066 §8.
        // Body: [status_type=ocsp(1) u8][responder_id_list_len u16=0][request_extensions_len u16=0].
        // rustls validates the status_type byte; an empty body is a decode_error.
        0x0005 => vec![0x01, 0x00, 0x00, 0x00, 0x00],

        // compress_certificate (0x001b) — RFC 8879 §3.
        // Body: [algorithms_len u8 = 0x02][algorithm brotli = 0x00 0x02].
        // rustls validates the algorithm list; an empty body is a decode_error.
        0x001b => vec![0x02, 0x00, 0x02],

        // encrypted_client_hello (0xfe0d) — draft-ietf-tls-esni §5.
        // rustls knows this extension and tries to parse the body.  The
        // minimal valid body is a single byte with EchClientHelloType =
        // ClientHelloInner (0x01), which carries no additional payload.
        // This lets rustls parse the extension cleanly without triggering
        // a decode_error.  The extension is then ignored by the server.
        0xfe0d => vec![0x01],

        // application_settings / ALPS (0x44cd) — draft-vvv-tls-alps.
        // Body: [supported_protocols_list_len u16][proto_len u8][proto bytes].
        // Authentic Yandex/Chromium advertises only "h2" here (the protocol that
        // negotiates application settings), distinct from the ALPN list.
        0x44cd => vec![0x00, 0x03, 0x02, b'h', b'2'],

        // All remaining extension types:
        //   - GREASE entries: empty body is valid (GREASE is ignored by servers)
        //   - session_ticket (0x0023): empty body = no session ticket to offer
        //   - extended_master_secret (0x0017): empty body (flag-style extension)
        //   - signed_certificate_timestamp (0x0012): empty body (client request)
        //
        // JA4/JA3 only inspect extension type IDs, so bodies here do not affect
        // the fingerprint hash.
        _ => Vec::new(),
    }
}

/// Helper: encode a `&[u16]` slice as [list_len_in_bytes u16][item u16 ...].
fn list_u16_with_u16len(items: &[u16]) -> Vec<u8> {
    let inner: Vec<u8> = items.iter().flat_map(|x| x.to_be_bytes()).collect();
    let mut b = Vec::with_capacity(2 + inner.len());
    b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    b.extend_from_slice(&inner);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::Profile;
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

    /// Gate test (Task 5): build a ClientHello with `Profile::yandex()`, then parse
    /// it back through `ClientHelloView::parse` and assert:
    ///
    /// 1. `ja4(&view) == fixture "yandex.ja4"` — fingerprint round-trip is correct.
    /// 2. `view.has_sni` — server_name extension is present.
    /// 3. Raw bytes contain the literal SNI hostname.
    /// 4. Raw bytes contain the supplied 32-byte key_share public key.
    #[test]
    fn built_clienthello_matches_fixture_ja4_and_carries_sni() {
        let ks = [0x42u8; 32];
        let bytes = build_client_hello(
            &Profile::yandex(),
            "www.example.com",
            &ks,
            &[0u8; 1184],
            [0xAA; 32],
        );

        // Must parse cleanly
        let view = ClientHelloView::parse(&bytes).expect("parse should succeed");

        // JA4 fingerprint must match the committed fixture
        let expected_ja4 = fixture_str("yandex.ja4");
        assert_eq!(
            ja4(&view),
            expected_ja4,
            "JA4 mismatch: got '{}', expected '{}'",
            ja4(&view),
            expected_ja4
        );

        // SNI extension must be detected by the parser
        assert!(view.has_sni, "parser should detect server_name extension");

        // Raw bytes must contain the literal SNI host string
        assert!(
            bytes.windows(15).any(|w| w == b"www.example.com"),
            "raw bytes must contain the SNI hostname 'www.example.com'"
        );

        // Raw bytes must contain the 32-byte key_share public key
        assert!(
            bytes.windows(32).any(|w| w == ks),
            "raw bytes must contain the key_share public key"
        );
    }

    /// Walk a built ClientHello handshake message and return the raw body bytes of
    /// the first extension whose type equals `etype`.
    fn ext_body(msg: &[u8], etype: u16) -> Option<Vec<u8>> {
        // [type 1][len u24][ver 2][random 32][sid_len 1][sid][cs_len u16][cs][comp_len 1][comp]
        let mut i = 4 + 2 + 32;
        let sid_len = msg[i] as usize;
        i += 1 + sid_len;
        let cs_len = u16::from_be_bytes([msg[i], msg[i + 1]]) as usize;
        i += 2 + cs_len;
        let comp_len = msg[i] as usize;
        i += 1 + comp_len;
        let _ext_total = u16::from_be_bytes([msg[i], msg[i + 1]]) as usize;
        i += 2;
        while i + 4 <= msg.len() {
            let t = u16::from_be_bytes([msg[i], msg[i + 1]]);
            let l = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
            let body = msg[i + 4..i + 4 + l].to_vec();
            if t == etype {
                return Some(body);
            }
            i += 4 + l;
        }
        None
    }

    /// ALPS (application_settings, 0x44CD) must advertise a single protocol "h2",
    /// matching authentic Yandex 26.4. Body layout (ApplicationSettings):
    ///   [supported_protocols_list_len u16][proto_len u8][proto bytes]
    /// For "h2": list_len=3, then 0x02 "h2" → [0x00,0x03,0x02,b'h',b'2'].
    #[test]
    fn alps_extension_advertises_h2() {
        let ch = build_client_hello(
            &Profile::yandex(),
            "www.example.com",
            &[0x42u8; 32],
            &[0u8; 1184],
            [0xAA; 32],
        );
        let body = ext_body(&ch, 0x44cd).expect("ALPS extension must be present");
        assert_eq!(body, vec![0x00, 0x03, 0x02, b'h', b'2']);
    }

    /// Per-connection GREASE: the builder substitutes the BoringSSL-derived GREASE
    /// values into every GREASE slot. supported_groups and key_share must share one
    /// value; the two extension GREASE values must differ; JA4 is invariant.
    #[test]
    fn per_connection_grease_substituted_into_clienthello() {
        use crate::camouflage::{derive_grease, is_grease};
        let mut entropy = [0u8; 32];
        entropy[0] = 0xc3; // cipher  -> 0xCACA
        entropy[1] = 0x6f; // group   -> 0x6A6A
        entropy[2] = 0x5a; // ext1    -> 0x5A5A
        entropy[3] = 0x40; // ext2    -> 0x4A4A
        entropy[4] = 0x0e; // version -> 0x0A0A
        let g = derive_grease(&entropy);
        let ch = build_client_hello_with_entropy(
            &Profile::yandex(),
            "ex.com",
            &[1u8; 32],
            &[0u8; 1184],
            [2u8; 32],
            entropy,
        );
        let view = ClientHelloView::parse(&ch).expect("parse should succeed");

        assert!(
            view.cipher_suites.contains(&g.cipher),
            "cipher GREASE must be substituted"
        );
        assert_eq!(
            view.supported_groups.first(),
            Some(&g.group),
            "supported_groups GREASE"
        );
        assert!(
            view.supported_versions.contains(&g.version),
            "supported_versions GREASE"
        );

        // key_share's GREASE entry must equal the supported_groups GREASE value.
        let ks_body = ext_body(&ch, 0x0033).expect("key_share present");
        let first_group = u16::from_be_bytes([ks_body[2], ks_body[3]]);
        assert_eq!(
            first_group, g.group,
            "key_share GREASE must equal supported_groups GREASE"
        );

        // The two extension-list GREASE values: first == ext1, last == ext2, distinct.
        let gx: Vec<u16> = view
            .extensions
            .iter()
            .copied()
            .filter(|x| is_grease(*x))
            .collect();
        assert_eq!(gx.first(), Some(&g.ext1), "leading extension GREASE");
        assert_eq!(gx.last(), Some(&g.ext2), "trailing extension GREASE");
        assert_ne!(g.ext1, g.ext2);

        // JA4 must be unchanged (GREASE is stripped before hashing).
        assert_eq!(ja4(&view), fixture_str("yandex.ja4"));
    }

    /// The non-GREASE extensions are shuffled per connection (like Chromium), so the
    /// order — and thus JA3 — varies; but the extension SET, the pinned leading/
    /// trailing GREASE, and the JA4 are all invariant.
    #[test]
    fn extensions_shuffle_per_connection_preserving_set_and_ja4() {
        use crate::camouflage::is_grease;
        use crate::ja::ja3;

        let build = |shuffle_byte: u8| {
            let mut e = [0u8; 32];
            e[8] = shuffle_byte; // vary only the shuffle entropy
            let ch = build_client_hello_with_entropy(
                &Profile::yandex(),
                "ex.com",
                &[1u8; 32],
                &[0u8; 1184],
                [2u8; 32],
                e,
            );
            ClientHelloView::parse(&ch).expect("parse")
        };
        let v1 = build(0x11);
        let v2 = build(0x22);

        let non_grease = |v: &ClientHelloView| -> Vec<u16> {
            v.extensions
                .iter()
                .copied()
                .filter(|x| !is_grease(*x))
                .collect()
        };

        // Order differs across connections...
        assert_ne!(
            non_grease(&v1),
            non_grease(&v2),
            "extension order should vary per connection"
        );
        // ...but the SET is identical.
        let (mut s1, mut s2) = (non_grease(&v1), non_grease(&v2));
        s1.sort_unstable();
        s2.sort_unstable();
        assert_eq!(s1, s2, "extension set must be preserved");

        // One GREASE pinned first, one pinned last.
        assert!(is_grease(*v1.extensions.first().unwrap()), "leading GREASE");
        assert!(is_grease(*v1.extensions.last().unwrap()), "trailing GREASE");

        // JA4 invariant (sorts before hashing); JA3 varies (order-sensitive).
        assert_eq!(ja4(&v1), fixture_str("yandex.ja4"));
        assert_eq!(ja4(&v2), fixture_str("yandex.ja4"));
        assert_ne!(ja3(&v1), ja3(&v2), "JA3 should differ across connections");
    }
}
