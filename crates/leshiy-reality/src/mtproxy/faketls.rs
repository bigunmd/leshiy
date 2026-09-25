//! The MTProxy fake-TLS envelope: HMAC-authenticated ClientHello in, a ServerHello flight out,
//! then the obfuscated2 stream carried inside TLS application-data records.
//!
//! The client proves knowledge of the secret by putting `HMAC-SHA256(secret, ClientHello with a
//! zeroed random)` in the random field, with the last four bytes XOR-ed with its Unix time. The
//! server answers ServerHello + ChangeCipherSpec + one application-data record, and proves
//! itself with `HMAC-SHA256(secret, client_random ‖ response with a zeroed random)` in the
//! ServerHello random.
//!
//! Unlike the reference proxies, the ServerHello is not synthesized: it is the one the borrowed
//! site just sent in reply to this very ClientHello, and the application-data record is sized
//! like that site's first encrypted flight. What an observer sees is the real site's handshake.
use hmac::{Hmac, Mac};
use leshiy_tls::record::{self, Record, read_record};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// The 32-byte random in a handshake record: 5 (record hdr) + 4 (handshake hdr) + 2 (version).
const RANDOM: std::ops::Range<usize> = 11..43;
const CHANGE_CIPHER_SPEC: u8 = 0x14;
/// RFC 8446 §4.1.3: a ServerHello whose random is this is a HelloRetryRequest.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
/// A server's first encrypted flight (EncryptedExtensions … Finished) is written in one go, as one
/// record or one per message. Records arriving within this gap of the previous one belong to it;
/// after that the dest is waiting for the client, which will never answer it.
const FLIGHT_GAP: std::time::Duration = std::time::Duration::from_millis(25);
const FLIGHT_MAX_RECORDS: usize = 8;

/// The client's ClientHello random as sent. Keys the response MAC and the replay guard.
pub(crate) type ClientDigest = [u8; 32];

/// Check a ClientHello record payload against `secret`. The record header is reconstructed as
/// `16 03 01` — the only one Telegram clients send, so any other header fails the MAC anyway.
pub(crate) fn authenticate(
    ch_payload: &[u8],
    secret: &[u8; 16],
    now_secs: u32,
    max_skew: std::time::Duration,
) -> Option<ClientDigest> {
    let len = u16::try_from(ch_payload.len()).ok()?;
    let mut msg = Vec::with_capacity(5 + ch_payload.len());
    msg.extend_from_slice(&[record::HANDSHAKE, 0x03, 0x01]);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(ch_payload);
    let digest: ClientDigest = msg.get(RANDOM)?.try_into().ok()?;
    msg[RANDOM].fill(0);
    let mac = hmac(secret, &[&msg])?;
    // Both checks always run: which one failed must not show in the timing.
    let mac_ok: bool = mac[..28].ct_eq(&digest[..28]).into();
    let mut ts = [0u8; 4];
    for (t, (d, m)) in ts.iter_mut().zip(digest[28..].iter().zip(&mac[28..])) {
        *t = d ^ m;
    }
    let skew_ok = u64::from(now_secs.abs_diff(u32::from_le_bytes(ts))) <= max_skew.as_secs();
    (mac_ok && skew_ok).then_some(digest)
}

/// What the borrowed site answered to the forwarded ClientHello.
pub(crate) struct DestFlight {
    server_hello: Record,
    app_len: usize,
}

/// Read the dest's ServerHello and size its first encrypted flight. `None` if the dest answered
/// with anything we cannot mirror (an alert, a HelloRetryRequest, a malformed record).
pub(crate) async fn read_dest_flight<R: AsyncRead + Unpin>(dest: &mut R) -> Option<DestFlight> {
    let server_hello = read_record(dest).await.ok()?;
    let p = &server_hello.payload;
    let is_sh = server_hello.content_type == record::HANDSHAKE
        && p.first() == Some(&0x02)
        && p.get(6..38).is_some_and(|r| r != HRR_RANDOM);
    if !is_sh {
        return None;
    }
    let mut app_len = 0;
    for _ in 0..FLIGHT_MAX_RECORDS {
        let next = if app_len == 0 {
            read_record(dest).await.ok()?
        } else {
            match tokio::time::timeout(FLIGHT_GAP, read_record(dest)).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) | Err(_) => break,
            }
        };
        match next.content_type {
            CHANGE_CIPHER_SPEC => {}
            record::APPLICATION_DATA => app_len += next.payload.len(),
            _ => return None,
        }
    }
    (app_len > 0).then_some(DestFlight {
        server_hello,
        app_len: app_len.min(record::MAX_RECORD_PAYLOAD),
    })
}

/// The server's fake-TLS answer: the dest's ServerHello (random replaced by our MAC), a
/// ChangeCipherSpec, and one application-data record of the dest's flight size.
pub(crate) fn server_response(
    client: &ClientDigest,
    flight: &DestFlight,
    secret: &[u8; 16],
    rng: &mut impl RngCore,
) -> Option<Vec<u8>> {
    let mut out = flight.server_hello.encode();
    out[RANDOM].fill(0);
    out.extend_from_slice(&[CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out.extend_from_slice(&[record::APPLICATION_DATA, 0x03, 0x03]);
    out.extend_from_slice(&u16::try_from(flight.app_len).ok()?.to_be_bytes());
    let body = out.len();
    out.resize(body + flight.app_len, 0);
    rng.fill_bytes(&mut out[body..]);
    let mac = hmac(secret, &[client, &out])?;
    out[RANDOM].copy_from_slice(&mac);
    Some(out)
}

/// Next chunk of the client's stream: the payload of its next application-data record, skipping
/// ChangeCipherSpec. `None` on EOF or on any other record type (the session ends).
pub(crate) async fn read_app_data<R: AsyncRead + Unpin>(r: &mut R) -> Option<Vec<u8>> {
    loop {
        let rec = read_record(r).await.ok()?;
        match rec.content_type {
            CHANGE_CIPHER_SPEC => continue,
            record::APPLICATION_DATA => return Some(rec.payload),
            _ => return None,
        }
    }
}

/// Send `data` to the client as application-data records of at most one TLS record each.
pub(crate) async fn write_app_data<W: AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    for chunk in data.chunks(record::MAX_RECORD_PAYLOAD) {
        let rec = Record {
            content_type: record::APPLICATION_DATA,
            payload: chunk.to_vec(),
        };
        w.write_all(&rec.encode()).await?;
    }
    w.flush().await
}

fn hmac(secret: &[u8; 16], parts: &[&[u8]]) -> Option<[u8; 32]> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).ok()?;
    for p in parts {
        m.update(p);
    }
    Some(m.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SECRET: [u8; 16] = [0x11; 16];
    const NOW: u32 = 1_780_000_000;
    const SKEW: Duration = Duration::from_secs(120);

    /// A ClientHello payload signed the way tdlib signs it (independent of `authenticate`).
    fn telegram_client_hello(secret: &[u8; 16], ts: u32) -> Vec<u8> {
        let mut rec = vec![
            0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
        ];
        rec.extend_from_slice(&[0u8; 32]); // random, filled below
        rec.push(32);
        rec.extend_from_slice(&[0x77; 32]); // session id
        rec.extend_from_slice(&[0xab; 400]); // rest of the hello; content is irrelevant to the MAC
        let len = (rec.len() - 5) as u16;
        rec[3..5].copy_from_slice(&len.to_be_bytes());
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        m.update(&rec);
        let mut mac: [u8; 32] = m.finalize().into_bytes().into();
        for (b, t) in mac[28..].iter_mut().zip(ts.to_le_bytes()) {
            *b ^= t;
        }
        rec[11..43].copy_from_slice(&mac);
        rec[5..].to_vec()
    }

    fn dest_server_hello(random: [u8; 32]) -> Record {
        let mut p = vec![0x02, 0x00, 0x00, 0x56, 0x03, 0x03];
        p.extend_from_slice(&random);
        p.extend_from_slice(&[0x20; 33]);
        p.extend_from_slice(&[0x13, 0x01, 0x00, 0x00, 0x2e]);
        Record {
            content_type: record::HANDSHAKE,
            payload: p,
        }
    }

    #[test]
    fn authenticates_client_hello_signed_with_secret() {
        let ch = telegram_client_hello(&SECRET, NOW - 30);
        let digest = authenticate(&ch, &SECRET, NOW, SKEW).expect("authentic");
        assert_eq!(&digest[..], &ch[6..38]);
    }

    #[test]
    fn rejects_client_hello_signed_with_another_secret() {
        let ch = telegram_client_hello(&[0x12; 16], NOW);
        assert!(authenticate(&ch, &SECRET, NOW, SKEW).is_none());
    }

    #[test]
    fn rejects_client_hello_outside_time_window() {
        let ch = telegram_client_hello(&SECRET, NOW - 121);
        assert!(authenticate(&ch, &SECRET, NOW, SKEW).is_none());
        let ch = telegram_client_hello(&SECRET, NOW + 121);
        assert!(authenticate(&ch, &SECRET, NOW, SKEW).is_none());
    }

    #[test]
    fn rejects_truncated_client_hello() {
        assert!(authenticate(&[0x01, 0x00], &SECRET, NOW, SKEW).is_none());
    }

    /// tdlib's check of the server answer: fixed record prefixes and the HMAC over
    /// `client_random ‖ response-with-zeroed-random`.
    #[test]
    fn server_response_passes_telegram_client_verification() {
        let client: ClientDigest = [0x33; 32];
        let flight = DestFlight {
            server_hello: dest_server_hello([0x99; 32]),
            app_len: 2048,
        };
        let resp = server_response(&client, &flight, &SECRET, &mut rand::rngs::OsRng).unwrap();

        assert_eq!(&resp[..3], &[0x16, 0x03, 0x03]);
        let sh_len = usize::from(u16::from_be_bytes([resp[3], resp[4]]));
        let tail = &resp[5 + sh_len..];
        assert_eq!(
            &tail[..9],
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03]
        );
        assert_eq!(usize::from(u16::from_be_bytes([tail[9], tail[10]])), 2048);
        assert_eq!(tail.len(), 11 + 2048);

        let mut zeroed = resp.clone();
        zeroed[11..43].fill(0);
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&SECRET).unwrap();
        m.update(&client);
        m.update(&zeroed);
        let want: [u8; 32] = m.finalize().into_bytes().into();
        assert_eq!(&resp[11..43], &want);
    }

    #[test]
    fn server_response_keeps_the_dest_server_hello_body() {
        let sh = dest_server_hello([0x99; 32]);
        let flight = DestFlight {
            server_hello: sh.clone(),
            app_len: 100,
        };
        let resp = server_response(&[0; 32], &flight, &SECRET, &mut rand::rngs::OsRng).unwrap();
        let enc = sh.encode();
        assert_eq!(&resp[..11], &enc[..11]);
        assert_eq!(&resp[43..enc.len()], &enc[43..]);
    }

    async fn flight_from(records: &[Record]) -> Option<DestFlight> {
        let bytes: Vec<u8> = records.iter().flat_map(Record::encode).collect();
        read_dest_flight(&mut bytes.as_slice()).await
    }

    fn app(len: usize) -> Record {
        Record {
            content_type: record::APPLICATION_DATA,
            payload: vec![0; len],
        }
    }

    fn ccs() -> Record {
        Record {
            content_type: CHANGE_CIPHER_SPEC,
            payload: vec![1],
        }
    }

    #[tokio::test]
    async fn dest_flight_sums_split_encrypted_records() {
        let f = flight_from(&[
            dest_server_hello([1; 32]),
            ccs(),
            app(40),
            app(3000),
            app(90),
        ])
        .await
        .unwrap();
        assert_eq!(f.app_len, 3130);
    }

    /// A dest that sent its flight and now waits for the client must not stall the handshake.
    #[tokio::test(start_paused = true)]
    async fn dest_flight_ends_when_dest_goes_quiet() {
        let (mut ours, mut dest) = tokio::io::duplex(1 << 16);
        for r in [dest_server_hello([1; 32]), ccs(), app(600)] {
            dest.write_all(&r.encode()).await.unwrap();
        }
        let f = read_dest_flight(&mut ours).await.unwrap();
        assert_eq!(f.app_len, 600);
        drop(dest);
    }

    #[tokio::test]
    async fn dest_flight_rejects_hello_retry_request() {
        assert!(
            flight_from(&[dest_server_hello(HRR_RANDOM), ccs(), app(2000)])
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn dest_flight_rejects_alert() {
        let alert = Record {
            content_type: record::ALERT,
            payload: vec![2, 40],
        };
        assert!(flight_from(&[alert]).await.is_none());
    }
}
