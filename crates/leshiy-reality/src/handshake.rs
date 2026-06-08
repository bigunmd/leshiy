//! REALITY authed TLS 1.3 handshake drivers (server + client) on the tls13 crypto core.
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;

/// Standard Ed25519 SubjectPublicKeyInfo prefix (RFC 8410): the 32-byte key follows.
/// `30 2a 30 05 06 03 2b 65 70 03 21 00`
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Compute HMAC-SHA512(key, data).
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha512>>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// Find the Ed25519 SPKI in a DER cert and return the 32-byte public key.
pub fn extract_ed25519_pubkey(der: &[u8]) -> Option<[u8; 32]> {
    der.windows(12)
        .position(|w| w == ED25519_SPKI_PREFIX)
        .and_then(|i| {
            der.get(i + 12..i + 44).map(|k| {
                let mut out = [0u8; 32];
                out.copy_from_slice(k);
                out
            })
        })
}

/// The server's process-lifetime ed25519 identity + a self-signed DER cert template.
pub struct ServerCert {
    der_template: Vec<u8>,
    signing_key: SigningKey,
}

impl ServerCert {
    /// Generate a fresh ed25519 identity and a self-signed DER cert via rcgen.
    ///
    /// Approach (b): let rcgen generate the Ed25519 KeyPair, build the self-signed cert,
    /// then recover the 32-byte seed from the PKCS#8 DER (`serialize_der()[16..48]`)
    /// so that `signing_key.verifying_key()` matches the cert's embedded public key.
    ///
    /// Ring's PKCS#8 v2 layout (83 bytes total):
    ///   [0..2]   30 51             SEQUENCE header
    ///   [2..5]   02 01 00          version = 0
    ///   [5..12]  30 05 06 03 2b 65 70  AlgorithmIdentifier (ed25519)
    ///   [12..16] 04 22 04 20       OCTET STRING wrappers
    ///   [16..48] <seed>            32-byte private seed
    ///   [48..51] 81 21 00          [1] IMPLICIT BIT STRING header
    ///   [51..83] <pubkey>          32-byte public key
    pub fn generate() -> ServerCert {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("rcgen keygen");

        // Recover the 32-byte seed from the PKCS#8 v2 DER at offset 16..48.
        let pkcs8 = key_pair.serialize_der();
        assert!(
            pkcs8.len() >= 48,
            "unexpected PKCS#8 length: {} (need ≥ 48)",
            pkcs8.len()
        );
        let seed: [u8; 32] = pkcs8[16..48].try_into().expect("seed slice is 32 bytes");
        let signing_key = SigningKey::from_bytes(&seed);

        // Sanity check: the ed25519-dalek pubkey must match the rcgen pubkey raw bytes.
        let dalek_pub = signing_key.verifying_key().to_bytes();
        let rcgen_pub = key_pair.public_key_raw();
        assert_eq!(
            dalek_pub.as_ref(),
            rcgen_pub,
            "PKCS#8 seed recovery mismatch: dalek pubkey != rcgen pubkey"
        );

        let params =
            rcgen::CertificateParams::new(vec!["leshiy".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");

        ServerCert {
            der_template: cert.der().to_vec(),
            signing_key,
        }
    }

    /// Return the server's 32-byte ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Per-connection cert DER: clone the template, overwrite the last 64 bytes (the
    /// ed25519 signature BIT STRING content) with HMAC-SHA512(auth_key, pubkey).
    pub fn signed_for(&self, auth_key: &[u8; 32]) -> Vec<u8> {
        let mut der = self.der_template.clone();
        let mac = hmac_sha512(auth_key, &self.public_key_bytes());
        let n = der.len();
        der[n - 64..].copy_from_slice(&mac);
        der
    }

    /// Sign `content` with the server's ed25519 key (for CertificateVerify).
    pub fn sign_transcript(&self, content: &[u8]) -> Vec<u8> {
        self.signing_key.sign(content).to_bytes().to_vec()
    }
}

/// Verify an ed25519 signature (for CertificateVerify on the client side).
pub fn verify_ed25519(pubkey: &[u8; 32], content: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    vk.verify_strict(content, &ed25519_dalek::Signature::from_bytes(&sig_arr))
        .is_ok()
}

use crate::error::{RealityError, Result};
use leshiy_tls::ja::extract_client_hello_fields;
use leshiy_tls::record::{HANDSHAKE, Record};
use leshiy_tls::tls13::messages::{
    adapt_server_hello, build_certificate, build_certificate_verify, build_encrypted_extensions,
    build_finished, parse_finished, parse_hs_msg,
};
use leshiy_tls::tls13::mlkem::{MlKemDecapKey, decapsulate, encapsulate};
use leshiy_tls::tls13::record::{open_record, seal_record};
use leshiy_tls::tls13::schedule::{
    client_ap_traffic, client_hs_traffic, early_secret, finished_verify_data, handshake_secret,
    master_secret, server_ap_traffic, server_hs_traffic, traffic_key,
};
use leshiy_tls::tls13::suite::{CipherSuite, Transcript};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const CV_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\x00";

pub struct TlsSession {
    pub suite: CipherSuite,
    pub client_key: Vec<u8>,
    pub client_iv: [u8; 12],
    pub server_key: Vec<u8>,
    pub server_iv: [u8; 12],
}

pub struct ServerHandshake {
    suite: CipherSuite,
    client_hs_key: Vec<u8>,
    client_hs_iv: [u8; 12],
    /// client_handshake_traffic_secret (base for client Finished)
    client_finished_secret: Vec<u8>,
    /// hash snapshot through server Finished (for client Finished verify)
    transcript_through_server_fin: Vec<u8>,
    session: TlsSession,
}

/// Run the server side up to (and including) sending its Finished. Returns the flight to
/// send to the client and a continuation to verify the client's Finished.
pub fn server_handshake(
    client_hello: &[u8],
    dest_server_hello: &[u8],
    auth_key: &[u8; 32],
    cert: &ServerCert,
) -> Result<(ServerHandshake, Vec<u8>)> {
    let fields = extract_client_hello_fields(client_hello).map_err(RealityError::Tls)?;
    let sh_params = leshiy_tls::tls13::messages::parse_server_hello(dest_server_hello)
        .map_err(RealityError::Tls)?;
    let suite = CipherSuite::from_u16(sh_params.suite)
        .ok_or_else(|| RealityError::Malformed("bad suite".into()))?;

    let group = sh_params.key_share_group;
    let (server_share, shared): (Vec<u8>, Zeroizing<Vec<u8>>) = if group == 0x11ec {
        // X25519MLKEM768: encapsulate with client's ML-KEM ek + fresh x25519 DH
        let cs = fields
            .key_share_mlkem
            .ok_or_else(|| RealityError::Malformed("no mlkem share in client hello".into()))?;
        let (ct, ss_mlkem) = encapsulate(&cs.ek)
            .ok_or_else(|| RealityError::Malformed("mlkem encapsulate failed".into()))?;
        // fresh server x25519, DH with the client's x25519 from the 0x11ec share
        let mut sk_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sk_bytes);
        let server_sk = StaticSecret::from(sk_bytes);
        let server_pub = PublicKey::from(&server_sk).to_bytes();
        let ss_x = server_sk
            .diffie_hellman(&PublicKey::from(cs.x25519))
            .to_bytes();
        // server share = ct(1088) ‖ server_x25519(32) = 1120
        let mut share = ct.to_vec();
        share.extend_from_slice(&server_pub);
        // combined ECDHE = ss_mlkem(32) ‖ ss_x25519(32) = 64  (ML-KEM first)
        let mut sh_secret = ss_mlkem.to_vec();
        sh_secret.extend_from_slice(&ss_x);
        (share, Zeroizing::new(sh_secret))
    } else {
        // x25519 path: fresh server ephemeral, DH with client's x25519 public key
        let client_pub = fields
            .key_share_x25519
            .ok_or_else(|| RealityError::Malformed("no x25519 key_share".into()))?;
        let mut sk_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sk_bytes);
        let server_sk = StaticSecret::from(sk_bytes);
        let server_pub = PublicKey::from(&server_sk).to_bytes();
        let ss_x = server_sk
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes();
        (server_pub.to_vec(), Zeroizing::new(ss_x.to_vec()))
    };

    // ServerHello: copy dest, replace key_share with our computed server share
    let sh = adapt_server_hello(dest_server_hello, &server_share).map_err(RealityError::Tls)?;

    // transcript: CH‖SH → handshake secrets
    let mut tr = Transcript::new(suite);
    tr.update(client_hello);
    tr.update(&sh);
    let th_chsh = tr.hash();
    let early = early_secret(suite);
    let hs = handshake_secret(suite, &early, &shared[..]);
    let s_hs = server_hs_traffic(suite, &hs, &th_chsh);
    let c_hs = client_hs_traffic(suite, &hs, &th_chsh);
    let (s_hs_key, s_hs_iv) = traffic_key(suite, &s_hs);
    let (c_hs_key, c_hs_iv) = traffic_key(suite, &c_hs);

    // Build flight messages, updating transcript after each
    let ee = build_encrypted_extensions(None);
    tr.update(&ee);

    let der = cert.signed_for(auth_key);
    let cert_msg = build_certificate(&der);
    tr.update(&cert_msg);

    // CertVerify: sign 0x20*64 || context || Transcript-Hash(CH..Certificate)
    let mut cv_content = vec![0x20u8; 64];
    cv_content.extend_from_slice(CV_CONTEXT);
    cv_content.extend_from_slice(&tr.hash()); // snapshot through Certificate
    let cv_sig = cert.sign_transcript(&cv_content);
    let cv_msg = build_certificate_verify(0x0807, &cv_sig);
    tr.update(&cv_msg);

    // server Finished: verify_data = HMAC(finished_key, Transcript-Hash(CH..CertVerify))
    let s_fin_vd = finished_verify_data(suite, &s_hs, &tr.hash());
    let fin_msg = build_finished(&s_fin_vd);
    tr.update(&fin_msg);
    let th_sfin = tr.hash(); // snapshot through server Finished

    // application secrets (transcript through server Finished)
    let master = master_secret(suite, &hs);
    let c_ap = client_ap_traffic(suite, &master, &th_sfin);
    let s_ap = server_ap_traffic(suite, &master, &th_sfin);
    let (client_key, client_iv) = traffic_key(suite, &c_ap);
    let (server_key, server_iv) = traffic_key(suite, &s_ap);

    // Coalesce EE‖Cert‖CertVerify‖Finished into ONE encrypted record (server_hs key, seq 0)
    let mut inner = Vec::new();
    inner.extend_from_slice(&ee);
    inner.extend_from_slice(&cert_msg);
    inner.extend_from_slice(&cv_msg);
    inner.extend_from_slice(&fin_msg);
    let enc =
        seal_record(suite, &s_hs_key, &s_hs_iv, 0, 0x16, &inner).map_err(RealityError::Tls)?;

    // flight = plaintext SH record prepended to the encrypted record
    let mut flight = Record {
        content_type: HANDSHAKE,
        payload: sh,
    }
    .encode();
    flight.extend_from_slice(&enc);

    let sh_state = ServerHandshake {
        suite,
        client_hs_key: c_hs_key,
        client_hs_iv: c_hs_iv,
        client_finished_secret: c_hs,
        transcript_through_server_fin: th_sfin,
        session: TlsSession {
            suite,
            client_key,
            client_iv,
            server_key,
            server_iv,
        },
    };
    Ok((sh_state, flight))
}

impl ServerHandshake {
    /// Verify the client's Finished (one encrypted record) and return the session.
    pub fn finish(self, client_finished_record: &[u8]) -> Result<TlsSession> {
        let (inner_type, msg) = open_record(
            self.suite,
            &self.client_hs_key,
            &self.client_hs_iv,
            0,
            client_finished_record,
        )
        .map_err(RealityError::Tls)?;
        if inner_type != 0x16 {
            return Err(RealityError::Malformed("expected handshake".into()));
        }
        let vd = parse_finished(&msg).map_err(RealityError::Tls)?;
        let expected = finished_verify_data(
            self.suite,
            &self.client_finished_secret,
            &self.transcript_through_server_fin,
        );
        if !bool::from(vd.as_slice().ct_eq(expected.as_slice())) {
            return Err(RealityError::Malformed("client Finished mismatch".into()));
        }
        Ok(self.session)
    }
}

/// Result of the client handshake: the session + the client's Finished record to send.
pub struct ClientHandshakeOut {
    pub session: TlsSession,
    pub client_finished_record: Vec<u8>,
}

/// Process the server flight; verify identity + CertVerify + server Finished; produce the
/// client Finished record + session. `client_ephemeral_priv` is the x25519 secret bytes
/// used in the ClientHello key_share. `auth_key` is the REALITY shared secret.
/// `mlkem_dk` is the ML-KEM-768 decapsulation key generated in `build_authed_client_hello`;
/// it is used when the server selects group 0x11ec (X25519MLKEM768).
pub fn client_handshake(
    client_hello: &[u8],
    server_flight: &[u8],
    client_ephemeral_priv: &[u8; 32],
    auth_key: &[u8; 32],
    mlkem_dk: &MlKemDecapKey,
) -> Result<ClientHandshakeOut> {
    // 1. read plaintext ServerHello record
    let (sh_rec, consumed) = Record::decode(server_flight).map_err(RealityError::Tls)?;
    if sh_rec.content_type != HANDSHAKE {
        return Err(RealityError::Malformed("expected SH record".into()));
    }
    let sh = sh_rec.payload;
    let sh_params =
        leshiy_tls::tls13::messages::parse_server_hello(&sh).map_err(RealityError::Tls)?;
    let suite = CipherSuite::from_u16(sh_params.suite)
        .ok_or_else(|| RealityError::Malformed("bad suite".into()))?;

    // 2. shared + handshake secrets — branch on negotiated group
    let shared: Zeroizing<Vec<u8>> = if sh_params.key_share_group == 0x11ec {
        // X25519MLKEM768: ct(1088) ‖ server_x25519(32) = 1120 bytes
        if sh_params.key_share.len() != 1120 {
            return Err(RealityError::Malformed(
                "bad mlkem server share length (expected 1120)".into(),
            ));
        }
        let ct = &sh_params.key_share[0..1088];
        let mut server_x = [0u8; 32];
        server_x.copy_from_slice(&sh_params.key_share[1088..1120]);
        let ss_mlkem = decapsulate(mlkem_dk, ct)
            .ok_or_else(|| RealityError::Malformed("mlkem decapsulate failed".into()))?;
        let client_sk = StaticSecret::from(*client_ephemeral_priv);
        let ss_x = client_sk
            .diffie_hellman(&PublicKey::from(server_x))
            .to_bytes();
        // combined ECDHE = ss_mlkem(32) ‖ ss_x25519(32) = 64  (ML-KEM first)
        let mut sh_secret = ss_mlkem.to_vec();
        sh_secret.extend_from_slice(&ss_x);
        Zeroizing::new(sh_secret)
    } else {
        // x25519 path
        if sh_params.key_share_group != 0x001d || sh_params.key_share.len() != 32 {
            return Err(RealityError::Malformed(
                "server key_share not x25519 or mlkem".into(),
            ));
        }
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&sh_params.key_share);
        let client_sk = StaticSecret::from(*client_ephemeral_priv);
        let ss_x = client_sk
            .diffie_hellman(&PublicKey::from(server_pub))
            .to_bytes();
        Zeroizing::new(ss_x.to_vec())
    };
    let mut tr = Transcript::new(suite);
    tr.update(client_hello);
    tr.update(&sh);
    let th_chsh = tr.hash();
    let early = early_secret(suite);
    let hs = handshake_secret(suite, &early, &shared[..]);
    let s_hs = server_hs_traffic(suite, &hs, &th_chsh);
    let c_hs = client_hs_traffic(suite, &hs, &th_chsh);
    let (s_hs_key, s_hs_iv) = traffic_key(suite, &s_hs);
    let (c_hs_key, c_hs_iv) = traffic_key(suite, &c_hs);

    // 3. decrypt the encrypted flight record (the rest of server_flight after the SH record)
    let enc = &server_flight[consumed..];
    let (it, inner) = open_record(suite, &s_hs_key, &s_hs_iv, 0, enc).map_err(RealityError::Tls)?;
    if it != 0x16 {
        return Err(RealityError::Malformed("expected handshake".into()));
    }

    // 4. parse EE, Certificate, CertVerify, Finished in sequence; update transcript after each
    let mut off = 0usize;
    let next_msg = |buf: &[u8], off: &mut usize| -> Result<Vec<u8>> {
        let (_t, body) = parse_hs_msg(&buf[*off..]).map_err(RealityError::Tls)?;
        let total = 4 + body.len();
        let m = buf[*off..*off + total].to_vec();
        *off += total;
        Ok(m)
    };

    // EE
    let ee = next_msg(&inner, &mut off)?;
    tr.update(&ee);

    // Certificate
    let cert_msg = next_msg(&inner, &mut off)?;
    let der =
        leshiy_tls::tls13::messages::parse_certificate(&cert_msg).map_err(RealityError::Tls)?;
    tr.update(&cert_msg);

    // 5. IDENTITY: HMAC-SHA512(auth_key, cert_pub) == cert signature (last 64 bytes of DER)
    let cert_pub = extract_ed25519_pubkey(&der)
        .ok_or_else(|| RealityError::Malformed("no ed25519 pubkey".into()))?;
    if der.len() < 64 || !bool::from(hmac_sha512(auth_key, &cert_pub).ct_eq(&der[der.len() - 64..]))
    {
        return Err(RealityError::Malformed(
            "server identity (HMAC) mismatch".into(),
        ));
    }

    // CertVerify — snapshot is through Certificate (tr already updated through cert_msg)
    let cv_msg = next_msg(&inner, &mut off)?;
    let (alg, sig) = leshiy_tls::tls13::messages::parse_certificate_verify(&cv_msg)
        .map_err(RealityError::Tls)?;

    // 6. genuine CertVerify over Transcript-Hash(CH..Certificate)
    let mut cv_content = vec![0x20u8; 64];
    cv_content.extend_from_slice(CV_CONTEXT);
    cv_content.extend_from_slice(&tr.hash()); // tr currently includes through Certificate
    if alg != 0x0807 || !verify_ed25519(&cert_pub, &cv_content, &sig) {
        return Err(RealityError::Malformed("CertVerify failed".into()));
    }
    tr.update(&cv_msg);

    // 7. verify server Finished
    let fin_msg = next_msg(&inner, &mut off)?;
    let s_vd = parse_finished(&fin_msg).map_err(RealityError::Tls)?;
    let expected_s = finished_verify_data(suite, &s_hs, &tr.hash());
    if !bool::from(s_vd.as_slice().ct_eq(expected_s.as_slice())) {
        return Err(RealityError::Malformed("server Finished mismatch".into()));
    }
    tr.update(&fin_msg);
    let th_sfin = tr.hash(); // snapshot through server Finished

    // 8. app secrets (must match server)
    let master = master_secret(suite, &hs);
    let c_ap = client_ap_traffic(suite, &master, &th_sfin);
    let s_ap = server_ap_traffic(suite, &master, &th_sfin);
    let (client_key, client_iv) = traffic_key(suite, &c_ap);
    let (server_key, server_iv) = traffic_key(suite, &s_ap);

    // 9. client Finished (covers through server Finished), encrypted with client_hs key
    let c_vd = finished_verify_data(suite, &c_hs, &th_sfin);
    let c_fin_msg = build_finished(&c_vd);
    let c_fin_rec =
        seal_record(suite, &c_hs_key, &c_hs_iv, 0, 0x16, &c_fin_msg).map_err(RealityError::Tls)?;

    Ok(ClientHandshakeOut {
        session: TlsSession {
            suite,
            client_key,
            client_iv,
            server_key,
            server_iv,
        },
        client_finished_record: c_fin_rec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_signed_for_embeds_hmac_and_extractable_pubkey() {
        let cert = ServerCert::generate();
        let auth_key = [0x42u8; 32];
        let der = cert.signed_for(&auth_key);
        let pubkey = extract_ed25519_pubkey(&der).unwrap();
        assert_eq!(pubkey.len(), 32);
        // signature (last 64 bytes) == HMAC-SHA512(auth_key, pubkey)
        let sig = &der[der.len() - 64..];
        assert_eq!(sig, hmac_sha512(&auth_key, &pubkey).as_slice());
        assert_eq!(pubkey, cert.public_key_bytes());
    }
}
