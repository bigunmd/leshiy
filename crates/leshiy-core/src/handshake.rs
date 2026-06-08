//! Noise IK handshake with the protocol major bound into the prologue.
use crate::error::Result;
use snow::{Builder, HandshakeState};
use zeroize::Zeroizing;

pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Wire-incompatible epoch. Bump only on handshake/cipher/framing changes.
pub const PROTOCOL_MAJOR: u16 = 1;

/// Prologue mixed into the handshake hash. Never sent in cleartext;
/// a mismatch makes the handshake MAC fail (fail-closed, stealthy).
///
/// Binds `b"leshiy"`, the protocol `major`, and the full Noise suite string
/// (per ADR-0008). Binding the suite means even a cipher-suite-only change is
/// fail-closed, independent of the major bump.
pub fn prologue(major: u16) -> Vec<u8> {
    let mut p = b"leshiy".to_vec();
    p.extend_from_slice(&major.to_be_bytes());
    p.extend_from_slice(NOISE_PARAMS.as_bytes());
    p
}

pub struct Keypair {
    /// Public X25519 key — safe to share.
    pub public: Vec<u8>,
    /// Private X25519 key — zeroized on drop; never clone or log.
    ///
    /// Note: `snow` (0.9.x) keeps its own internal copy of the private key
    /// inside `HandshakeState` that is NOT covered by `Zeroize`; this wrapper
    /// only protects the caller-side copy. See ADR-0003.
    pub private: Zeroizing<Vec<u8>>,
}

pub fn generate_keypair() -> Result<Keypair> {
    let kp = Builder::new(NOISE_PARAMS.parse()?).generate_keypair()?;
    Ok(Keypair {
        public: kp.public,
        private: Zeroizing::new(kp.private),
    })
}

pub fn build_initiator(
    server_pub: &[u8],
    client_priv: &[u8],
    major: u16,
) -> Result<HandshakeState> {
    Ok(Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(client_priv)
        .remote_public_key(server_pub)
        .prologue(&prologue(major))
        .build_initiator()?)
}

pub fn build_responder(server_priv: &[u8], major: u16) -> Result<HandshakeState> {
    Ok(Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(server_priv)
        .prologue(&prologue(major))
        .build_responder()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_32_bytes() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.public.len(), 32);
        assert_eq!(kp.private.len(), 32);
    }

    #[test]
    fn ik_handshake_completes_and_encrypts() {
        let server = generate_keypair().unwrap();
        let client = generate_keypair().unwrap();
        let mut ini = build_initiator(&server.public, &client.private, PROTOCOL_MAJOR).unwrap();
        let mut res = build_responder(&server.private, PROTOCOL_MAJOR).unwrap();

        let mut buf = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap(); // msg1
        let mut tmp = [0u8; 1024];
        res.read_message(&buf[..n], &mut tmp).unwrap();
        let n = res.write_message(&[], &mut buf).unwrap(); // msg2
        ini.read_message(&buf[..n], &mut tmp).unwrap();

        let mut ts_i = ini.into_transport_mode().unwrap();
        let mut ts_r = res.into_transport_mode().unwrap();
        let n = ts_i.write_message(b"ping", &mut buf).unwrap();
        let mut out = [0u8; 1024];
        let m = ts_r.read_message(&buf[..n], &mut out).unwrap();
        assert_eq!(&out[..m], b"ping");

        // reverse direction uses an independent ChaChaPoly subkey
        let n2 = ts_r.write_message(b"pong", &mut buf).unwrap();
        let mut out2 = [0u8; 1024];
        let m2 = ts_i.read_message(&buf[..n2], &mut out2).unwrap();
        assert_eq!(&out2[..m2], b"pong");
    }

    #[test]
    fn major_mismatch_fails() {
        let server = generate_keypair().unwrap();
        let client = generate_keypair().unwrap();
        let mut ini = build_initiator(&server.public, &client.private, 1).unwrap();
        let mut res = build_responder(&server.private, 2).unwrap(); // different major
        let mut buf = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        let mut tmp = [0u8; 1024];
        assert!(res.read_message(&buf[..n], &mut tmp).is_err());
    }
}
