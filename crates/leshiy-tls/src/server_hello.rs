//! Minimal ServerHello parsing + alert detection (no key schedule).
use crate::error::{Result, TlsError};

pub struct ServerHelloInfo {
    pub cipher_suite: u16,
    pub selected_group: Option<u16>,
    pub server_key_share: Option<Vec<u8>>,
}

/// If a record is an Alert, surface it as an error; otherwise Ok.
pub fn check_not_alert(content_type: u8, payload: &[u8]) -> Result<()> {
    if content_type == crate::record::ALERT {
        let level = payload.first().copied().unwrap_or(0);
        let desc = payload.get(1).copied().unwrap_or(0);
        return Err(TlsError::Alert { level, desc });
    }
    Ok(())
}

pub fn parse_server_hello(msg: &[u8]) -> Result<ServerHelloInfo> {
    if msg.first() != Some(&0x02) {
        return Err(TlsError::Malformed {
            what: "serverhello",
            detail: "not a ServerHello".into(),
        });
    }
    // Layout: [0x02][u24 len][0x0303][32 random][sid_len][sid...][cipher u16][comp u8][ext_len u16][exts...]
    // Position after msg_type(1) + u24_len(3) + legacy_version(2) + random(32) = 38
    let mut pos = 4 + 2 + 32;
    let sid_len = msg.get(pos).copied().ok_or(TlsError::Truncated {
        need: pos + 1,
        have: msg.len(),
    })? as usize;
    pos += 1 + sid_len;
    let cipher_suite = u16::from_be_bytes([
        msg.get(pos).copied().ok_or(TlsError::Truncated {
            need: pos + 2,
            have: msg.len(),
        })?,
        msg.get(pos + 1).copied().ok_or(TlsError::Truncated {
            need: pos + 2,
            have: msg.len(),
        })?,
    ]);
    pos += 2 + 1; // cipher(2) + compression(1)

    let mut selected_group = None;
    let mut server_key_share = None;

    if pos + 2 <= msg.len() {
        let ext_len = u16::from_be_bytes([msg[pos], msg[pos + 1]]) as usize;
        pos += 2;
        let end = (pos + ext_len).min(msg.len());
        while pos + 4 <= end {
            let etype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
            let elen = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
            pos += 4;
            if pos + elen > end {
                break;
            }
            if etype == 0x0033 && elen >= 4 {
                // key_share extension
                selected_group = Some(u16::from_be_bytes([msg[pos], msg[pos + 1]]));
                let kl = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
                if pos + 4 + kl <= end {
                    server_key_share = Some(msg[pos + 4..pos + 4 + kl].to_vec());
                }
            }
            pos += elen;
        }
    }

    Ok(ServerHelloInfo {
        cipher_suite,
        selected_group,
        server_key_share,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_server_hello() {
        // Handshake(0x02 ServerHello): type, u24 len, 0x0303, 32 random, sid=0, cipher=0x1301, comp=0x00, ext_len=0
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00); // session_id len
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        body.push(0x00); // compression
        body.extend_from_slice(&0u16.to_be_bytes()); // extensions length 0
        let mut msg = vec![0x02];
        let l = body.len() as u32;
        msg.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        msg.extend_from_slice(&body);
        let info = parse_server_hello(&msg).unwrap();
        assert_eq!(info.cipher_suite, 0x1301);
    }

    #[test]
    fn detects_alert_record_payload() {
        // an Alert record payload: [level=2 fatal][desc=40 handshake_failure]
        assert!(matches!(
            check_not_alert(crate::record::ALERT, &[0x02, 0x28]),
            Err(crate::error::TlsError::Alert { level: 2, desc: 40 })
        ));
    }
}
