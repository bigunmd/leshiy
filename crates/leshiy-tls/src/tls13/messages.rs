//! Generic TLS 1.3 handshake message codecs (RFC 8446 §4). Sans-I/O, bounds-checked.
use crate::error::{Result, TlsError};

fn hs_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let l = body.len() as u32;
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(msg_type);
    m.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    m.extend_from_slice(body);
    m
}

/// Return (msg_type, body) of a single handshake message.
pub fn parse_hs_msg(msg: &[u8]) -> Result<(u8, &[u8])> {
    if msg.len() < 4 {
        return Err(TlsError::Truncated {
            need: 4,
            have: msg.len(),
        });
    }
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let end = 4 + len;
    if msg.len() < end {
        return Err(TlsError::Truncated {
            need: end,
            have: msg.len(),
        });
    }
    Ok((msg[0], &msg[4..end]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHelloParams {
    pub suite: u16,
    pub server_random: [u8; 32],
    pub session_id_echo: Vec<u8>,
    pub key_share_group: u16,
    pub key_share: Vec<u8>,
}

/// Build a minimal TLS 1.3 ServerHello with supported_versions(0x0304) + key_share.
pub fn build_server_hello(p: &ServerHelloParams) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&p.server_random);
    body.push(p.session_id_echo.len() as u8);
    body.extend_from_slice(&p.session_id_echo);
    body.extend_from_slice(&p.suite.to_be_bytes());
    body.push(0x00); // compression
    // extensions: supported_versions (0x002b) + key_share (0x0033)
    let mut ext = Vec::new();
    // supported_versions: selected_version 0x0304
    ext.extend_from_slice(&0x002bu16.to_be_bytes());
    ext.extend_from_slice(&0x0002u16.to_be_bytes());
    ext.extend_from_slice(&0x0304u16.to_be_bytes());
    // key_share: group + u16 len + key
    ext.extend_from_slice(&0x0033u16.to_be_bytes());
    let ks_len = 2 + 2 + p.key_share.len();
    ext.extend_from_slice(&(ks_len as u16).to_be_bytes());
    ext.extend_from_slice(&p.key_share_group.to_be_bytes());
    ext.extend_from_slice(&(p.key_share.len() as u16).to_be_bytes());
    ext.extend_from_slice(&p.key_share);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    hs_msg(0x02, &body)
}

fn take_bytes<'a>(buf: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *at + n > buf.len() {
        return Err(TlsError::Truncated {
            need: *at + n,
            have: buf.len(),
        });
    }
    let s = &buf[*at..*at + n];
    *at += n;
    Ok(s)
}

pub fn parse_server_hello(msg: &[u8]) -> Result<ServerHelloParams> {
    let (mt, body) = parse_hs_msg(msg)?;
    if mt != 0x02 {
        return Err(TlsError::Malformed {
            what: "serverhello",
            detail: "wrong type".into(),
        });
    }
    let trunc = || TlsError::Malformed {
        what: "serverhello",
        detail: "truncated".into(),
    };
    let mut p = 0usize;
    take_bytes(body, &mut p, 2)?; // legacy_version
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(take_bytes(body, &mut p, 32)?);
    let sid_len = take_bytes(body, &mut p, 1)?[0] as usize;
    let session_id_echo = take_bytes(body, &mut p, sid_len)?.to_vec();
    if p + 2 > body.len() {
        return Err(trunc());
    }
    let suite = u16::from_be_bytes([body[p], body[p + 1]]);
    p += 2;
    take_bytes(body, &mut p, 1)?; // compression
    // extensions
    if p + 2 > body.len() {
        return Err(trunc());
    }
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(body.len());
    let mut key_share_group = 0u16;
    let mut key_share = Vec::new();
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[p], body[p + 1]]);
        let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + elen > ext_end {
            break;
        }
        if etype == 0x0033 && elen >= 4 {
            key_share_group = u16::from_be_bytes([body[p], body[p + 1]]);
            let kl = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
            if p + 4 + kl <= ext_end {
                key_share = body[p + 4..p + 4 + kl].to_vec();
            }
        }
        p += elen;
    }
    Ok(ServerHelloParams {
        suite,
        server_random,
        session_id_echo,
        key_share_group,
        key_share,
    })
}

/// Copy a ServerHello but replace its key_share data with `new_share`.
///
/// Accepts group 0x001d (x25519, share 32 B) and 0x11ec (X25519MLKEM768, share 1120 B).
/// The caller passes the correct bytes for the group: for 0x11ec that is `ct(1088)‖server_x25519(32)`.
pub fn adapt_server_hello(dest_sh: &[u8], new_share: &[u8]) -> Result<Vec<u8>> {
    let mut p = parse_server_hello(dest_sh)?;
    match (p.key_share_group, new_share.len()) {
        (0x001d, 32) | (0x11ec, 1120) => {
            p.key_share = new_share.to_vec();
        }
        _ => {
            return Err(TlsError::Malformed {
                what: "serverhello",
                detail: "unexpected key_share group/len".into(),
            });
        }
    }
    Ok(build_server_hello(&p))
}

pub fn build_encrypted_extensions(alpn: Option<&str>) -> Vec<u8> {
    let mut ext = Vec::new();
    if let Some(a) = alpn {
        // ALPN extension 0x0010
        let mut protos = Vec::new();
        protos.push(a.len() as u8);
        protos.extend_from_slice(a.as_bytes());
        ext.extend_from_slice(&0x0010u16.to_be_bytes());
        ext.extend_from_slice(&((protos.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(protos.len() as u16).to_be_bytes());
        ext.extend_from_slice(&protos);
    }
    let mut body = (ext.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&ext);
    hs_msg(0x08, &body)
}

pub fn build_certificate(cert_der: &[u8]) -> Vec<u8> {
    // context(1=0) + cert_list(u24) { cert(u24 len + der) + extensions(u16=0) }
    let mut entry = Vec::new();
    let l = cert_der.len() as u32;
    entry.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    entry.extend_from_slice(cert_der);
    entry.extend_from_slice(&[0x00, 0x00]); // entry extensions: empty
    let mut body = vec![0x00]; // cert_request_context: empty
    let ll = entry.len() as u32;
    body.extend_from_slice(&[(ll >> 16) as u8, (ll >> 8) as u8, ll as u8]);
    body.extend_from_slice(&entry);
    hs_msg(0x0b, &body)
}

pub fn parse_certificate(msg: &[u8]) -> Result<Vec<u8>> {
    let (mt, body) = parse_hs_msg(msg)?;
    if mt != 0x0b {
        return Err(TlsError::Malformed {
            what: "certificate",
            detail: "wrong type".into(),
        });
    }
    if body.is_empty() {
        return Err(TlsError::Malformed {
            what: "certificate",
            detail: "empty".into(),
        });
    }
    let ctx_len = body[0] as usize;
    let mut p = 1 + ctx_len;
    if p + 3 > body.len() {
        return Err(TlsError::Truncated {
            need: p + 3,
            have: body.len(),
        });
    }
    p += 3; // cert_list length
    if p + 3 > body.len() {
        return Err(TlsError::Truncated {
            need: p + 3,
            have: body.len(),
        });
    }
    let cl = ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | body[p + 2] as usize;
    p += 3;
    if p + cl > body.len() {
        return Err(TlsError::Truncated {
            need: p + cl,
            have: body.len(),
        });
    }
    Ok(body[p..p + cl].to_vec())
}

pub fn build_certificate_verify(alg: u16, signature: &[u8]) -> Vec<u8> {
    let mut body = alg.to_be_bytes().to_vec();
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    hs_msg(0x0f, &body)
}

pub fn parse_certificate_verify(msg: &[u8]) -> Result<(u16, Vec<u8>)> {
    let (mt, body) = parse_hs_msg(msg)?;
    if mt != 0x0f || body.len() < 4 {
        return Err(TlsError::Malformed {
            what: "certverify",
            detail: "bad".into(),
        });
    }
    let alg = u16::from_be_bytes([body[0], body[1]]);
    let slen = u16::from_be_bytes([body[2], body[3]]) as usize;
    if 4 + slen > body.len() {
        return Err(TlsError::Truncated {
            need: 4 + slen,
            have: body.len(),
        });
    }
    Ok((alg, body[4..4 + slen].to_vec()))
}

pub fn build_finished(verify_data: &[u8]) -> Vec<u8> {
    hs_msg(0x14, verify_data)
}

pub fn parse_finished(msg: &[u8]) -> Result<Vec<u8>> {
    let (mt, body) = parse_hs_msg(msg)?;
    if mt != 0x14 {
        return Err(TlsError::Malformed {
            what: "finished",
            detail: "wrong type".into(),
        });
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_hello_roundtrip_and_adapt() {
        // minimal SH: suite 0x1301, x25519 key_share with a dummy 32-byte key
        let params = ServerHelloParams {
            suite: 0x1301,
            server_random: [9u8; 32],
            session_id_echo: vec![1, 2, 3],
            key_share_group: 0x001d,
            key_share: vec![0xAA; 32],
        };
        let sh = build_server_hello(&params);
        let got = parse_server_hello(&sh).unwrap();
        assert_eq!(got.suite, 0x1301);
        assert_eq!(got.server_random, [9u8; 32]);
        assert_eq!(got.session_id_echo, vec![1, 2, 3]);
        assert_eq!(got.key_share_group, 0x001d);
        assert_eq!(got.key_share, vec![0xAA; 32]);

        let adapted = adapt_server_hello(&sh, &[0xBBu8; 32]).unwrap();
        let got2 = parse_server_hello(&adapted).unwrap();
        assert_eq!(got2.key_share, vec![0xBB; 32]); // replaced
        assert_eq!(got2.server_random, [9u8; 32]); // preserved
        assert_eq!(got2.suite, 0x1301);

        // also works for 0x11ec group with 1120-byte share
        let params_mlkem = ServerHelloParams {
            suite: 0x1301,
            server_random: [7u8; 32],
            session_id_echo: vec![],
            key_share_group: 0x11ec,
            key_share: vec![0xDD; 1120],
        };
        let sh_mlkem = build_server_hello(&params_mlkem);
        let adapted_mlkem = adapt_server_hello(&sh_mlkem, &[0xEEu8; 1120]).unwrap();
        let got3 = parse_server_hello(&adapted_mlkem).unwrap();
        assert_eq!(got3.key_share_group, 0x11ec);
        assert_eq!(got3.key_share, vec![0xEE; 1120]);
    }

    #[test]
    fn other_message_roundtrips() {
        let ee = build_encrypted_extensions(Some("h2"));
        assert_eq!(ee[0], 0x08); // EncryptedExtensions msg type
        let cert = build_certificate(b"DERBYTES");
        assert_eq!(cert[0], 0x0b);
        assert_eq!(parse_certificate(&cert).unwrap(), b"DERBYTES");
        let cv = build_certificate_verify(0x0807, &[5u8; 64]);
        assert_eq!(cv[0], 0x0f);
        assert_eq!(
            parse_certificate_verify(&cv).unwrap(),
            (0x0807u16, vec![5u8; 64])
        );
        let fin = build_finished(&[7u8; 32]);
        assert_eq!(fin[0], 0x14);
        assert_eq!(parse_finished(&fin).unwrap(), vec![7u8; 32]);
    }
}
