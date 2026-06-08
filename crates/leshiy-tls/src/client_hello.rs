//! Build a byte-exact, profile-fingerprinted TLS 1.3 ClientHello handshake message.
//!
//! The built message is designed to round-trip through `ClientHelloView::parse`
//! and produce the same JA4/JA3 as the committed fixture. Extension order and
//! GREASE placement follow the `Profile` exactly; only SNI (0x0000) and
//! key_share (0x0033) are injected from the call arguments.
use crate::fingerprint::Profile;

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
///   1. GREASE (group 0x0a0a, 1-byte key 0x00) — matches browser CH
///   2. X25519MLKEM768 (0x11EC): mlkem_ek(1184) ‖ x25519_pub(32) = 1216 bytes
///   3. X25519 (0x001D): x25519_pub(32) bytes
pub fn build_client_hello(
    profile: &Profile,
    sni: &str,
    x25519_pub: &[u8; 32],
    mlkem_ek: &[u8; 1184],
    random: [u8; 32],
) -> Vec<u8> {
    let mut body = Vec::new();

    // legacy_version: 0x0303 (TLS 1.2 compat)
    body.extend_from_slice(&[0x03, 0x03]);

    // random (32 bytes)
    body.extend_from_slice(&random);

    // legacy_session_id: 32 bytes (mirrors Chromium — all-zeros or random)
    body.push(32u8);
    body.extend_from_slice(&random);

    // cipher_suites: u16 length-prefixed list
    let cs_bytes: Vec<u8> = profile
        .cipher_suites
        .iter()
        .flat_map(|c| c.to_be_bytes())
        .collect();
    body.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cs_bytes);

    // compression methods: 1 method = null (0x00)
    body.extend_from_slice(&[0x01, 0x00]);

    // extensions: iterate in profile order, building each body
    let mut ext_bytes = Vec::new();
    for &etype in &profile.extensions {
        let ebody = build_extension(etype, profile, sni, x25519_pub, mlkem_ek);
        ext_bytes.extend_from_slice(&etype.to_be_bytes());
        ext_bytes.extend_from_slice(&(ebody.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&ebody);
    }
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
        // Structure: [list_len u16][group u16 ...]
        0x000a => list_u16_with_u16len(&profile.supported_groups),

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
            for v in &profile.supported_versions {
                b.extend_from_slice(&v.to_be_bytes());
            }
            b
        }

        // key_share — RFC 8446 §4.2.8
        // In ClientHello: [client_shares_len u16][group u16][key_exchange_len u16][key_exchange bytes]
        // We emit three entries in browser order:
        //   1. GREASE (group 0x0a0a, 1-byte key 0x00)
        //   2. X25519MLKEM768 (0x11EC): mlkem_ek(1184) || x25519_pub(32) = 1216 bytes
        //   3. X25519 (0x001D): x25519_pub(32) bytes
        0x0033 => {
            let mut entries = Vec::new();
            // GREASE key_share (group 0x0a0a, 1-byte key) — matches browser CH
            entries.extend_from_slice(&0x0a0au16.to_be_bytes());
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

        // All remaining extension types:
        //   - GREASE entries: empty body is valid (GREASE is ignored by servers)
        //   - session_ticket (0x0023): empty body = no session ticket to offer
        //   - extended_master_secret (0x0017): empty body (flag-style extension)
        //   - signed_certificate_timestamp (0x0012): empty body (client request)
        //   - application_settings / ALPS (0x44cd): unknown to rustls, ignored
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
}
