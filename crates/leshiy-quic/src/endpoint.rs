//! quinn endpoint construction: BBR server + a client with SHA-256 cert pinning or webpki roots.
use crate::Result;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn bbr_transport() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
    ));
    // Send keepalive PINGs well within the idle timeout so an otherwise-idle tunnel — or one whose
    // UDP path is briefly disrupted (e.g. WSL2 NAT rebind, sleep/resume) — stays alive and the
    // break is detected promptly, instead of the connection silently dying after 30s idle. Quinn
    // disables keepalive by default; without it an idle QUIC tunnel is torn down on idle timeout.
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    Arc::new(transport)
}

/// How the client verifies the server's TLS certificate.
#[derive(Clone)]
pub enum CertVerification {
    /// Verify against the Mozilla webpki roots (SNI is threaded via `ep.connect` call-site).
    Roots,
    /// Trust exactly the cert whose end-entity DER SHA-256 equals this pin (self-signed self-host).
    Pinned([u8; 32]),
}

/// Compute the SHA-256 digest of a certificate DER encoding.
pub fn cert_sha256(der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(der);
    h.finalize().into()
}

/// Server endpoint with BBR congestion control.
pub fn server_endpoint(
    listen: std::net::SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Endpoint> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| crate::QuicError::Conn(format!("server tls: {e}")))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| crate::QuicError::Conn(format!("server cert: {e}")))?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = u32::MAX;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| crate::QuicError::Conn(format!("quic server cfg: {e}")))?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(quic_crypto));
    cfg.transport_config(bbr_transport());
    Endpoint::server(cfg, listen).map_err(Into::into)
}

/// Client endpoint using the specified certificate verification strategy.
pub fn client_endpoint(verification: CertVerification) -> Result<Endpoint> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    let mut crypto = match verification {
        CertVerification::Roots => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        CertVerification::Pinned(pin) => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin }))
            .with_no_client_auth(),
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| crate::QuicError::Conn(format!("{e}")))?;
    let mut ccfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    ccfg.transport_config(bbr_transport());
    ep.set_default_client_config(ccfg);
    Ok(ep)
}

/// A [`rustls::client::danger::ServerCertVerifier`] that accepts exactly the cert whose
/// end-entity DER SHA-256 matches the stored pin.
///
/// # Security
/// This verifier skips CA-chain, hostname, and expiry checks (appropriate for a self-signed cert
/// that is pinned out-of-band). It DOES verify the TLS handshake signatures, proving that the
/// server possesses the pinned cert's private key. Blanket-accepting signatures without
/// verification would be an authentication bypass.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if cert_sha256(end_entity.as_ref()) == self.pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate pin mismatch".into()))
        }
    }

    // CRITICAL: still verify the handshake signatures (proves the server holds the pinned
    // cert's private key); we only skip CA-chain / hostname / expiry (fine — we pinned the
    // exact cert).
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
