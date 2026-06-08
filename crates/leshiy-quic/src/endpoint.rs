//! quinn endpoint construction: BBR server + a test client that accepts a pinned/self-signed cert.
use crate::Result;
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn bbr_transport() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(transport)
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
    let mut cfg = ServerConfig::with_single_cert(certs, key)
        .map_err(|e| crate::QuicError::Conn(format!("server cfg: {e}")))?;
    cfg.transport_config(bbr_transport());
    Endpoint::server(cfg, listen).map_err(Into::into)
}

/// Client endpoint. `insecure_skip_verify` accepts ANY server cert — TEST ONLY (M2c adds real
/// verification). Requires the `dangerous-insecure-skip-verify` feature when `true`.
pub fn client_endpoint(insecure_skip_verify: bool) -> Result<Endpoint> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    if !insecure_skip_verify {
        return Err(crate::QuicError::Conn(
            "real certificate verification is not implemented until M2c".into(),
        ));
    }

    // insecure_skip_verify == true path
    build_insecure_client_endpoint()
}

#[cfg(feature = "dangerous-insecure-skip-verify")]
fn build_insecure_client_endpoint() -> Result<Endpoint> {
    let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    let crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("bad protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
    .with_no_client_auth();
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| crate::QuicError::Conn(format!("{e}")))?;
    let mut ccfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    ccfg.transport_config(bbr_transport());
    ep.set_default_client_config(ccfg);
    Ok(ep)
}

#[cfg(not(feature = "dangerous-insecure-skip-verify"))]
fn build_insecure_client_endpoint() -> Result<Endpoint> {
    Err(crate::QuicError::Conn(
        "insecure skip-verify requires the 'dangerous-insecure-skip-verify' feature (test-only)"
            .into(),
    ))
}

#[cfg(feature = "dangerous-insecure-skip-verify")]
#[derive(Debug)]
struct AcceptAnyServerCert;

#[cfg(feature = "dangerous-insecure-skip-verify")]
impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
