//! ClientHello field extraction + JA3/JA4 fingerprints (GREASE-normalized).
use crate::error::{Result, TlsError};
use md5::{Digest as _, Md5};
use sha2::Sha256;

pub struct ClientHelloView {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub sig_algs: Vec<u16>,
    pub alpn: Vec<String>,
    pub has_sni: bool,
    pub supported_versions: Vec<u16>,
}

/// Returns true for GREASE values (RFC 8701): 0x?A?A where both bytes are equal.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

impl ClientHelloView {
    /// Parse a Handshake(ClientHello) message: [msg_type=0x01][u24 len][body].
    pub fn parse(msg: &[u8]) -> Result<ClientHelloView> {
        let mut p = Parser::new(msg);
        let mt = p.u8()?;
        if mt != 0x01 {
            return Err(TlsError::Malformed {
                what: "clienthello",
                detail: format!("msg_type {mt:#x}"),
            });
        }
        let _len = p.u24()?;
        let legacy_version = p.u16()?; // 0x0303
        p.skip(32)?; // random
        let sid = p.u8()? as usize;
        p.skip(sid)?; // legacy_session_id
        let cs_len = p.u16()? as usize;
        let mut cipher_suites = Vec::new();
        for _ in 0..cs_len / 2 {
            cipher_suites.push(p.u16()?);
        }
        let comp = p.u8()? as usize;
        p.skip(comp)?;
        // extensions
        let mut extensions = Vec::new();
        let mut supported_groups = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut sig_algs = Vec::new();
        let mut alpn = Vec::new();
        let mut has_sni = false;
        let mut supported_versions = Vec::new();
        if p.remaining() >= 2 {
            let ext_total = p.u16()? as usize;
            let end = p.pos + ext_total;
            while p.pos < end {
                let etype = p.u16()?;
                let elen = p.u16()? as usize;
                let ebody = p.take(elen)?;
                extensions.push(etype);
                match etype {
                    0x0000 => has_sni = true,
                    0x000a => {
                        let mut q = Parser::new(ebody);
                        let l = q.u16()? as usize;
                        for _ in 0..l / 2 {
                            supported_groups.push(q.u16()?);
                        }
                    }
                    0x000b => {
                        let mut q = Parser::new(ebody);
                        let l = q.u8()? as usize;
                        for _ in 0..l {
                            ec_point_formats.push(q.u8()?);
                        }
                    }
                    0x000d => {
                        let mut q = Parser::new(ebody);
                        let l = q.u16()? as usize;
                        for _ in 0..l / 2 {
                            sig_algs.push(q.u16()?);
                        }
                    }
                    0x0010 => {
                        let mut q = Parser::new(ebody);
                        let _total = q.u16()?;
                        while q.remaining() > 0 {
                            let n = q.u8()? as usize;
                            let s = q.take(n)?;
                            alpn.push(String::from_utf8_lossy(s).into());
                        }
                    }
                    0x002b => {
                        let mut q = Parser::new(ebody);
                        let l = q.u8()? as usize;
                        for _ in 0..l / 2 {
                            supported_versions.push(q.u16()?);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(ClientHelloView {
            legacy_version,
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats,
            sig_algs,
            alpn,
            has_sni,
            supported_versions,
        })
    }
}

/// Compute JA3 fingerprint: MD5 of "SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats".
/// GREASE values are excluded. Version comes from legacy_version (0x0303 = 771) per JA3 spec.
/// Extension list preserves observed order (JA3 is order-sensitive for its hash).
pub fn ja3(v: &ClientHelloView) -> String {
    let j_u16 = |xs: &[u16]| {
        xs.iter()
            .filter(|x| !is_grease(**x))
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    // JA3 uses legacy_version (0x0303 = 771), NOT supported_versions
    let ver = v.legacy_version;
    let s = format!(
        "{},{},{},{},{}",
        ver,
        j_u16(&v.cipher_suites),
        j_u16(&v.extensions),
        j_u16(&v.supported_groups),
        v.ec_point_formats
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    );
    hex::encode(Md5::digest(s.as_bytes()))
}

/// Compute JA4 fingerprint: "JA4_a_JA4_b_JA4_c".
///
/// - Part A: protocol(t) + TLS version (from supported_versions) + SNI(d/i) + cipher_count(2)
///   + ext_count(2) + ALPN(first+last char of first ALPN protocol)
/// - Part B: SHA-256[:6] of sorted hex cipher IDs (GREASE excluded), hex-encoded = 12 chars
/// - Part C: SHA-256[:6] of sorted non-SNI/non-ALPN extension IDs joined by ","
///   + "_" + sig algs in hello order (not sorted), hex-encoded = 12 chars
pub fn ja4(v: &ClientHelloView) -> String {
    // Part A: determine TLS version from supported_versions (take max non-GREASE)
    let ver = match v
        .supported_versions
        .iter()
        .filter(|x| !is_grease(**x))
        .max()
        .copied()
    {
        Some(0x0304) => "13",
        Some(0x0303) => "12",
        Some(0x0302) => "11",
        Some(0x0301) => "10",
        _ => "12", // fallback
    };
    let sni = if v.has_sni { "d" } else { "i" };
    // Count non-GREASE ciphers and extensions
    let nci = v.cipher_suites.iter().filter(|x| !is_grease(**x)).count();
    let nex = v.extensions.iter().filter(|x| !is_grease(**x)).count();
    // ALPN: first and last character of first ALPN protocol string
    let alpn_tag = v
        .alpn
        .first()
        .map(|a| {
            let b = a.as_bytes();
            format!(
                "{}{}",
                b.first().map(|c| *c as char).unwrap_or('0'),
                b.last().map(|c| *c as char).unwrap_or('0')
            )
        })
        .unwrap_or_else(|| "00".into());
    let a = format!("t{ver}{sni}{nci:02}{nex:02}{alpn_tag}");

    // Part B: SHA-256 of sorted hex cipher IDs (GREASE excluded), take first 6 bytes (12 hex chars)
    let b = {
        let mut ciphers: Vec<u16> = v
            .cipher_suites
            .iter()
            .filter(|x| !is_grease(**x))
            .copied()
            .collect();
        ciphers.sort_unstable();
        let s = ciphers
            .iter()
            .map(|x| format!("{x:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        hex::encode(&Sha256::digest(s.as_bytes())[..6])
    };

    // Part C: sorted non-SNI/non-ALPN extensions + "_" + sig algs in hello order
    let c = {
        let mut exts: Vec<u16> = v
            .extensions
            .iter()
            .filter(|x| !is_grease(**x) && **x != 0x0000 && **x != 0x0010)
            .copied()
            .collect();
        exts.sort_unstable();
        let exts_s = exts
            .iter()
            .map(|x| format!("{x:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let sig_s = v
            .sig_algs
            .iter()
            .filter(|x| !is_grease(**x))
            .map(|x| format!("{x:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let c_input = if sig_s.is_empty() {
            exts_s
        } else {
            format!("{exts_s}_{sig_s}")
        };
        hex::encode(&Sha256::digest(c_input.as_bytes())[..6])
    };

    format!("{a}_{b}_{c}")
}

/// ML-KEM-768 client share extracted from the 0x11EC key_share entry.
/// Body layout: ek(1184) ‖ x25519(32) = 1216 bytes.
pub struct MlKemClientShare {
    /// 1184-byte ML-KEM-768 encapsulation key.
    pub ek: Vec<u8>,
    /// 32-byte x25519 public key (hybrid component).
    pub x25519: [u8; 32],
}

/// REALITY-relevant raw fields pulled from a ClientHello handshake message.
pub struct ClientHelloFields {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub key_share_x25519: Option<[u8; 32]>,
    pub key_share_mlkem: Option<MlKemClientShare>,
    pub sni: Option<String>,
}

/// Parse the fields REALITY needs (no JA computation). Bounds-checked, no panics.
pub fn extract_client_hello_fields(msg: &[u8]) -> Result<ClientHelloFields> {
    let mut p = Parser::new(msg);
    if p.u8()? != 0x01 {
        return Err(TlsError::Malformed {
            what: "clienthello",
            detail: "not ClientHello".into(),
        });
    }
    let _len = p.u24()?;
    let _legacy_version = p.u16()?;
    let mut random = [0u8; 32];
    random.copy_from_slice(p.take(32)?);
    let sid_len = p.u8()? as usize;
    let session_id = p.take(sid_len)?.to_vec();
    let cs_len = p.u16()? as usize;
    p.skip(cs_len)?;
    let comp = p.u8()? as usize;
    p.skip(comp)?;
    let mut key_share_x25519 = None;
    let mut key_share_mlkem = None;
    let mut sni = None;
    if p.remaining() >= 2 {
        let ext_total = p.u16()? as usize;
        let end = p.pos + ext_total;
        while p.pos < end {
            let etype = p.u16()?;
            let elen = p.u16()? as usize;
            let ebody = p.take(elen)?;
            match etype {
                0x0000 => {
                    // server_name: list_len(2) entry_type(1) name_len(2) name
                    let mut q = Parser::new(ebody);
                    let _list = q.u16()?;
                    let _ty = q.u8()?;
                    let nlen = q.u16()? as usize;
                    sni = Some(String::from_utf8_lossy(q.take(nlen)?).into_owned());
                }
                0x0033 => {
                    // key_share: client_shares = list_len(2) { group(2) keylen(2) key }*
                    let mut q = Parser::new(ebody);
                    let _list = q.u16()?;
                    while q.remaining() >= 4 {
                        let group = q.u16()?;
                        let klen = q.u16()? as usize;
                        let key = q.take(klen)?;
                        match (group, klen) {
                            (0x001d, 32) => {
                                let mut k = [0u8; 32];
                                k.copy_from_slice(key);
                                key_share_x25519 = Some(k);
                            }
                            (0x11ec, 1216) => {
                                // X25519MLKEM768: ek(1184) || x25519(32)
                                let ek = key[0..1184].to_vec();
                                let mut x25519 = [0u8; 32];
                                x25519.copy_from_slice(&key[1184..1216]);
                                key_share_mlkem = Some(MlKemClientShare { ek, x25519 });
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(ClientHelloFields {
        random,
        session_id,
        key_share_x25519,
        key_share_mlkem,
        sni,
    })
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(TlsError::Truncated {
                need: n,
                have: self.remaining(),
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn u24(&mut self) -> Result<u32> {
        self.need(3)?;
        let v = ((self.buf[self.pos] as u32) << 16)
            | ((self.buf[self.pos + 1] as u32) << 8)
            | self.buf[self.pos + 2] as u32;
        self.pos += 3;
        Ok(v)
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Test 1: Yandex fixture — construct ClientHelloView from documented field
    // lists and assert JA3 + JA4 match the committed fixture values.
    //
    // Values taken from:
    //   tests/fixtures/SOURCE.md — field breakdown
    //   tests/fixtures/yandex.ja3 — committed MD5 hash
    //   tests/fixtures/yandex.ja4 — committed JA4 string
    //
    // JA3 raw string from SOURCE.md (extension order is ORDER-SENSITIVE):
    //   771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,
    //   51-27-65281-18-45-0-35-5-11-43-16-65037-23-17613-13-10,4588-29-23-24,0
    //
    // JA4 Part A: t13d1516h2 (15 ciphers, 16 non-GREASE extensions, ALPN first = h2)
    // ---------------------------------------------------------------------------
    #[test]
    fn ja_matches_yandex_fixture() {
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

        // Cipher suites: 15 non-GREASE values from SOURCE.md (in hello order, no GREASE)
        // JA4 counts 15 non-GREASE ciphers → nci=15
        let cipher_suites: Vec<u16> = vec![
            4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47,
            53,
        ];

        // Extension order from JA3 raw string (order-sensitive for JA3):
        //   51,27,65281,18,45,0,35,5,11,43,16,65037,23,17613,13,10
        // That is 16 non-GREASE extensions → nex=16 for JA4 Part A.
        let extensions: Vec<u16> = vec![
            51,    // 0x0033 key_share
            27,    // 0x001B compress_certificate
            65281, // 0xFF01 renegotiation_info
            18,    // 0x0012 signed_certificate_timestamp
            45,    // 0x002D psk_key_exchange_modes
            0,     // 0x0000 server_name (SNI)
            35,    // 0x0023 session_ticket
            5,     // 0x0005 status_request
            11,    // 0x000B ec_point_formats
            43,    // 0x002B supported_versions
            16,    // 0x0010 ALPN
            65037, // 0xFE0D ECH / encrypted_client_hello
            23,    // 0x0017 extended_master_secret
            17613, // 0x44CD application_settings (ALPS)
            13,    // 0x000D signature_algorithms
            10,    // 0x000A supported_groups
        ];

        // Supported groups from JA3 raw string (non-GREASE): 4588,29,23,24
        let supported_groups: Vec<u16> = vec![4588, 29, 23, 24];

        // Signature algorithms in hello order (from SOURCE.md):
        //   0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601
        let sig_algs: Vec<u16> = vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];

        // Supported versions include 0x0304 (TLS 1.3) → JA4 ver = "13"
        let supported_versions: Vec<u16> = vec![0x0304, 0x0303];

        let view = ClientHelloView {
            legacy_version: 0x0303, // 771 for JA3
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats: vec![0x00],
            sig_algs,
            alpn: vec!["h2".into(), "http/1.1".into()],
            has_sni: true,
            supported_versions,
        };

        // yandex.ja3 has the MD5 hash on line 1 and the raw JA3 string on line 2.
        // We compare against the hash only (line 1).
        let ja3_file = std::fs::read_to_string(format!(
            "{}/tests/fixtures/yandex.ja3",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let expected_ja3 = ja3_file.lines().next().unwrap().trim().to_string();
        let expected_ja4 = fixture_str("yandex.ja4");

        assert_eq!(
            ja3(&view),
            expected_ja3,
            "JA3 mismatch — check extension order and legacy_version"
        );
        assert_eq!(
            ja4(&view),
            expected_ja4,
            "JA4 mismatch — check part A counts, cipher/ext sorting, sig alg order"
        );
    }

    // ---------------------------------------------------------------------------
    // Test 2: Parser unit test — build a minimal synthetic ClientHello byte
    // sequence, parse it with ClientHelloView::parse, and assert extracted fields.
    // ---------------------------------------------------------------------------
    #[test]
    fn parser_synthetic_clienthello() {
        // Build a minimal ClientHello handshake message:
        //   msg_type = 0x01
        //   u24 length (filled in below)
        //   legacy_version = 0x0303
        //   random = [0x00; 32]
        //   session_id = [] (len=0)
        //   cipher_suites = [0x1301, 0x1302] (2 suites, 4 bytes)
        //   compression = [0x00] (null, 1 method, 2 bytes total: len + method)
        //   extensions:
        //     SNI 0x0000: "test.example"
        //     supported_groups 0x000A: [0x001D x25519]
        //
        let sni_host = b"test.example"; // 12 bytes
        let sni_entry_len: u16 = 1 + 2 + sni_host.len() as u16; // type(1) + len(2) + host
        let sni_list_len: u16 = sni_entry_len;
        let sni_ext_body_len: u16 = 2 + sni_entry_len; // list_len(2) + entry

        let mut ext_bytes: Vec<u8> = Vec::new();
        // Extension: SNI (0x0000)
        ext_bytes.extend_from_slice(&0x0000u16.to_be_bytes()); // type
        ext_bytes.extend_from_slice(&sni_ext_body_len.to_be_bytes()); // ext len
        ext_bytes.extend_from_slice(&sni_list_len.to_be_bytes()); // list len
        ext_bytes.push(0x00); // name_type = host_name
        ext_bytes.extend_from_slice(&(sni_host.len() as u16).to_be_bytes()); // host len
        ext_bytes.extend_from_slice(sni_host); // host bytes

        // Extension: supported_groups (0x000A): [0x001D]
        let groups_inner: Vec<u8> = 0x001Du16.to_be_bytes().to_vec();
        let groups_len = groups_inner.len() as u16;
        let groups_ext_len = 2 + groups_len; // list_len(2) + groups
        ext_bytes.extend_from_slice(&0x000Au16.to_be_bytes()); // type
        ext_bytes.extend_from_slice(&groups_ext_len.to_be_bytes()); // ext len
        ext_bytes.extend_from_slice(&groups_len.to_be_bytes()); // inner list len
        ext_bytes.extend_from_slice(&groups_inner); // the groups

        // Assemble the ClientHello body (without msg_type and u24 length)
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length = 0
        body.extend_from_slice(&4u16.to_be_bytes()); // cipher_suites length = 4
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&0x1302u16.to_be_bytes()); // TLS_AES_256_GCM_SHA384
        body.push(1); // compression methods length = 1
        body.push(0); // null compression
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes()); // extensions length
        body.extend_from_slice(&ext_bytes);

        // Build the full handshake message: [0x01][u24 len][body]
        let body_len = body.len() as u32;
        let mut msg: Vec<u8> = vec![
            0x01, // ClientHello msg_type
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        msg.extend_from_slice(&body);

        let view = ClientHelloView::parse(&msg).expect("parse should succeed");

        assert_eq!(view.legacy_version, 0x0303);
        assert_eq!(view.cipher_suites, vec![0x1301u16, 0x1302u16]);
        assert!(view.has_sni, "SNI extension should be detected");
        assert_eq!(
            view.supported_groups,
            vec![0x001Du16],
            "supported_groups should contain x25519"
        );
        // Extension list: SNI(0x0000) first, then supported_groups(0x000A)
        assert_eq!(
            view.extensions,
            vec![0x0000u16, 0x000Au16],
            "extensions list should preserve order"
        );
    }

    // ---------------------------------------------------------------------------
    // Test 4: extract_client_hello_fields — round-trip through build_client_hello
    // ---------------------------------------------------------------------------
    #[test]
    fn extract_fields_from_built_clienthello() {
        use crate::client_hello::build_client_hello;
        use crate::fingerprint::Profile;
        let ks = [0x11u8; 32];
        let rnd = [0x22u8; 32];
        let mut mlkem_ek = [0u8; 1184];
        // fill with a recognizable pattern
        for (i, b) in mlkem_ek.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        let ch = build_client_hello(&Profile::yandex(), "example.org", &ks, &mlkem_ek, rnd);
        let f = extract_client_hello_fields(&ch).unwrap();
        assert_eq!(f.random, rnd);
        assert_eq!(f.session_id.len(), 32);
        // 0x001d entry must still be extracted
        assert_eq!(f.key_share_x25519, Some(ks));
        assert_eq!(f.sni.as_deref(), Some("example.org"));
        // 0x11ec entry must now also be extracted
        let mlkem = f.key_share_mlkem.expect("key_share_mlkem should be Some");
        assert_eq!(mlkem.ek.len(), 1184);
        assert_eq!(mlkem.ek, mlkem_ek.as_ref());
        assert_eq!(mlkem.x25519, ks);
    }

    // ---------------------------------------------------------------------------
    // Test 3: GREASE detection
    // ---------------------------------------------------------------------------
    #[test]
    fn grease_detection() {
        // Known GREASE values per RFC 8701
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0x2a2a));
        assert!(is_grease(0xfafa));
        // Non-GREASE
        assert!(!is_grease(0x0303));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0000));
        assert!(!is_grease(0x44cd));
    }
}
