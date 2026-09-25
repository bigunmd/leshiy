//! The MTProxy "obfuscated2" layer: a 64-byte handshake that seeds two AES-256-CTR streams.
//!
//! Client side: the Telegram app derives its keys by hashing handshake bytes with the proxy
//! secret, so only a holder of the secret can recover the protocol tag. Upstream side: the
//! proxy opens its own obfuscated2 session to a Telegram DC, keyed by the handshake bytes alone
//! (the DC has no secret). Bytes are passed through between the two sessions unmodified —
//! both run the "secure intermediate" framing, so no re-framing is needed.
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// AES-256 in CTR mode with a 128-bit big-endian counter, as MTProto specifies.
pub(crate) type AesCtr = ctr::Ctr128BE<aes::Aes256>;

pub(crate) const HANDSHAKE_LEN: usize = 64;
/// "Secure intermediate" (random-padded) framing — the only tag a fake-TLS client sends.
const PROTO_TAG_SECURE: [u8; 4] = [0xdd; 4];
const KEY_IV: std::ops::Range<usize> = 8..56;
const PROTO_TAG: std::ops::Range<usize> = 56..60;

/// Telegram's production DCs 1–5 (IPv4), port 443. The client names a DC by index; a negative
/// index is the same DC's media endpoint, which on a direct connection is the same address.
const DCS: [&str; 5] = [
    "149.154.175.50:443",
    "149.154.167.51:443",
    "149.154.175.100:443",
    "149.154.167.91:443",
    "149.154.171.5:443",
];

/// The two cipher streams for one side of the relay: `dec` for bytes arriving from that
/// peer, `enc` for bytes sent to it.
pub(crate) struct Ciphers {
    pub dec: AesCtr,
    pub enc: AesCtr,
}

/// A client handshake that decrypted to a valid protocol tag.
pub(crate) struct ClientSession {
    pub ciphers: Ciphers,
    pub dc: i16,
}

/// Recover the client's streams and requested DC, or `None` if the handshake was not made
/// with `secret` (the protocol tag decrypts to garbage).
pub(crate) fn accept_client(hs: &[u8; HANDSHAKE_LEN], secret: &[u8; 16]) -> Option<ClientSession> {
    let fwd = key_iv(&hs[KEY_IV]);
    let rev = reversed_key_iv(&hs[KEY_IV]);
    let mut dec = new_ctr(&keyed(&fwd[..32], secret), &fwd[32..]);
    let enc = new_ctr(&keyed(&rev[..32], secret), &rev[32..]);
    let mut plain = *hs;
    dec.apply_keystream(&mut plain);
    if plain[PROTO_TAG] != PROTO_TAG_SECURE {
        return None;
    }
    Some(ClientSession {
        ciphers: Ciphers { dec, enc },
        dc: i16::from_le_bytes([plain[60], plain[61]]),
    })
}

/// The handshake to send a DC, and the streams that go with it.
pub(crate) struct Upstream {
    pub hello: [u8; HANDSHAKE_LEN],
    pub ciphers: Ciphers,
}

/// Build a fresh upstream handshake for a DC connection.
pub(crate) fn upstream(rng: &mut impl RngCore) -> Upstream {
    let mut rnd = [0u8; HANDSHAKE_LEN];
    loop {
        rng.fill_bytes(&mut rnd);
        if !is_reserved(&rnd) {
            break;
        }
    }
    rnd[PROTO_TAG].copy_from_slice(&PROTO_TAG_SECURE);
    let fwd = key_iv(&rnd[KEY_IV]);
    let rev = reversed_key_iv(&rnd[KEY_IV]);
    let mut enc = new_ctr(&fwd[..32], &fwd[32..]);
    let dec = new_ctr(&rev[..32], &rev[32..]);
    // The first 56 bytes go out in the clear; the tail (proto tag + DC) is encrypted, and the
    // encryptor's counter advances past all 64 so the stream continues from there.
    let mut sealed = rnd;
    enc.apply_keystream(&mut sealed);
    let mut hello = rnd;
    hello[PROTO_TAG.start..].copy_from_slice(&sealed[PROTO_TAG.start..]);
    Upstream {
        hello,
        ciphers: Ciphers { dec, enc },
    }
}

/// The DC address for a client-requested index, or `None` for anything outside DCs 1–5
/// (test DCs, CDN DCs), which a direct-mode proxy cannot serve.
pub(crate) fn dc_addr(dc: i16) -> Option<&'static str> {
    let idx = usize::from(dc.unsigned_abs().checked_sub(1)?);
    DCS.get(idx).copied()
}

/// Nonces a DC would misread as another protocol (HTTP verbs, TLS, other MTProto transports).
fn is_reserved(rnd: &[u8; HANDSHAKE_LEN]) -> bool {
    const RESERVED_START: [[u8; 4]; 7] = [
        *b"HEAD",
        *b"POST",
        *b"GET ",
        *b"OPTI",
        [0x16, 0x03, 0x01, 0x02],
        [0xdd; 4],
        [0xee; 4],
    ];
    rnd[0] == 0xef || RESERVED_START.iter().any(|r| rnd[..4] == *r) || rnd[4..8] == [0; 4]
}

fn key_iv(src: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(src);
    out
}

fn reversed_key_iv(src: &[u8]) -> [u8; 48] {
    let mut out = key_iv(src);
    out.reverse();
    out
}

fn keyed(prekey: &[u8], secret: &[u8; 16]) -> [u8; 32] {
    Sha256::new()
        .chain_update(prekey)
        .chain_update(secret)
        .finalize()
        .into()
}

fn new_ctr(key: &[u8], iv: &[u8]) -> AesCtr {
    // Both slices come from fixed-size arrays split at compile-time offsets (32/16).
    AesCtr::new(key.into(), iv.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [0x42; 16];

    /// What a Telegram client sends: random bytes with the tag + DC in the encrypted tail,
    /// keyed by the secret. Written independently of `accept_client`, from the transport spec.
    fn client_handshake(secret: &[u8; 16], dc: i16) -> ([u8; HANDSHAKE_LEN], AesCtr, AesCtr) {
        let mut rnd = [0x5au8; HANDSHAKE_LEN];
        for (i, b) in rnd.iter_mut().enumerate() {
            *b = b.wrapping_add((i as u8).wrapping_mul(7));
        }
        rnd[56..60].copy_from_slice(&[0xdd; 4]);
        rnd[60..62].copy_from_slice(&dc.to_le_bytes());
        let enc_key: [u8; 32] = Sha256::new()
            .chain_update(&rnd[8..40])
            .chain_update(secret)
            .finalize()
            .into();
        let mut enc = AesCtr::new((&enc_key).into(), (&rnd[40..56]).into());
        let mut rev = [0u8; 48];
        rev.copy_from_slice(&rnd[8..56]);
        rev.reverse();
        let dec_key: [u8; 32] = Sha256::new()
            .chain_update(&rev[..32])
            .chain_update(secret)
            .finalize()
            .into();
        let dec = AesCtr::new((&dec_key).into(), (&rev[32..]).into());
        let mut sealed = rnd;
        enc.apply_keystream(&mut sealed);
        let mut wire = rnd;
        wire[56..].copy_from_slice(&sealed[56..]);
        (wire, enc, dec)
    }

    #[test]
    fn accepts_client_handshake_and_reads_dc() {
        let (wire, _, _) = client_handshake(&SECRET, -2);
        let s = accept_client(&wire, &SECRET).expect("valid handshake");
        assert_eq!(s.dc, -2);
    }

    #[test]
    fn rejects_handshake_made_with_another_secret() {
        let (wire, _, _) = client_handshake(&[0x43; 16], 2);
        assert!(accept_client(&wire, &SECRET).is_none());
    }

    #[test]
    fn client_streams_interoperate_after_handshake() {
        let (wire, mut cli_enc, mut cli_dec) = client_handshake(&SECRET, 2);
        let mut s = accept_client(&wire, &SECRET).unwrap();
        let mut up = *b"client payload";
        cli_enc.apply_keystream(&mut up);
        s.ciphers.dec.apply_keystream(&mut up);
        assert_eq!(&up, b"client payload");
        let mut down = *b"server payload";
        s.ciphers.enc.apply_keystream(&mut down);
        cli_dec.apply_keystream(&mut down);
        assert_eq!(&down, b"server payload");
    }

    /// The DC's side of the upstream session, per the spec: it decrypts with the forward key
    /// and must find the tag; it replies on the reversed key.
    #[test]
    fn upstream_hello_decrypts_to_secure_tag_at_the_dc() {
        let mut u = upstream(&mut rand::rngs::OsRng);
        let mut dc_dec = AesCtr::new((&u.hello[8..40]).into(), (&u.hello[40..56]).into());
        let mut plain = u.hello;
        dc_dec.apply_keystream(&mut plain);
        assert_eq!(plain[56..60], [0xdd; 4]);
        assert!(!is_reserved(&u.hello));

        let mut rev = [0u8; 48];
        rev.copy_from_slice(&u.hello[8..56]);
        rev.reverse();
        let mut dc_enc = AesCtr::new((&rev[..32]).into(), (&rev[32..]).into());
        let mut reply = *b"dc reply";
        dc_enc.apply_keystream(&mut reply);
        u.ciphers.dec.apply_keystream(&mut reply);
        assert_eq!(&reply, b"dc reply");

        let mut sent = *b"to dc";
        u.ciphers.enc.apply_keystream(&mut sent);
        dc_dec.apply_keystream(&mut sent);
        assert_eq!(&sent, b"to dc");
    }

    #[test]
    fn dc_index_maps_to_production_dcs_only() {
        assert_eq!(dc_addr(1), Some("149.154.175.50:443"));
        assert_eq!(dc_addr(-5), Some("149.154.171.5:443"));
        assert_eq!(dc_addr(0), None);
        assert_eq!(dc_addr(6), None);
        assert_eq!(dc_addr(10002), None);
        assert_eq!(dc_addr(i16::MIN), None);
    }

    #[test]
    fn reserved_nonces_are_detected() {
        let mut r = [1u8; HANDSHAKE_LEN];
        assert!(!is_reserved(&r));
        r[..4].copy_from_slice(b"GET ");
        assert!(is_reserved(&r));
        let mut r = [1u8; HANDSHAKE_LEN];
        r[0] = 0xef;
        assert!(is_reserved(&r));
        let mut r = [1u8; HANDSHAKE_LEN];
        r[4..8].copy_from_slice(&[0; 4]);
        assert!(is_reserved(&r));
    }
}
