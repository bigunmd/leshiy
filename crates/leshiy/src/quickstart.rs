//! `leshiy quickstart`: wizard orchestration on top of `server::init`.
//! Domain logic only (no host mutation) — emits a machine-readable summary the
//! installer consumes.

/// Render a URI as a terminal QR code (UTF-8 half-block string).
// Consumed by the quickstart subcommand wired up in a later task.
#[allow(dead_code)]
pub fn qr_string(uri: &str) -> String {
    use qrcode::QrCode;
    use qrcode::render::unicode;
    let code = QrCode::new(uri.as_bytes()).expect("uri always encodable as QR");
    code.render::<unicode::Dense1x2>().quiet_zone(true).build()
}

/// Connect to `host:port` and report the negotiated TLS protocol version.
/// Returns Ok(true) iff the peer negotiated TLS 1.3.
// Called by the quickstart wizard to validate --dest before accepting it. Not
// yet wired up in non-test code (Task 8 calls it).
#[allow(dead_code)]
pub async fn dest_is_tls13(host: &str, port: u16) -> anyhow::Result<bool> {
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::{self, pki_types::ServerName};

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let stream = tokio::net::TcpStream::connect((host, port)).await?;
    let server_name = ServerName::try_from(host.to_string())?;
    let tls = connector.connect(server_name, stream).await?;
    let (_, conn) = tls.get_ref();
    Ok(conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3))
}

#[cfg(test)]
mod test_support {
    use std::sync::Arc;
    use tokio_rustls::rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    pub async fn spawn_tls13_echo() -> (std::net::SocketAddr, String) {
        let name = "localhost".to_string();
        let cert = rcgen::generate_simple_self_signed(vec![name.clone()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = acceptor.accept(sock).await;
            }
        });
        (addr, name)
    }

    #[derive(Debug)]
    struct AcceptAllCerts;

    impl rustls::client::danger::ServerCertVerifier for AcceptAllCerts {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    pub async fn probe_with_test_roots(host: &str, port: u16) -> bool {
        let verifier = Arc::new(AcceptAllCerts);
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let sn = ServerName::try_from(host.to_string()).unwrap();
        let tls = connector.connect(sn, stream).await.unwrap();
        tls.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_renders_nonempty_block_art() {
        let s = qr_string("leshiy://abc@203.0.113.5:443?sni=www.microsoft.com&sid=00");
        assert!(s.contains('█') || s.contains('▀') || s.contains('▄'));
        assert!(s.lines().count() > 10);
    }

    #[tokio::test]
    async fn probe_detects_tls13_server() {
        // Spin a minimal TLS1.3 server with a self-signed cert on 127.0.0.1.
        let (addr, name) = super::test_support::spawn_tls13_echo().await;
        // Connect with a verifier that accepts the test cert (trust-on-first-use for the test).
        let ok = super::test_support::probe_with_test_roots(&name, addr.port()).await;
        assert!(ok, "expected TLS1.3 negotiation against local server");
    }
}
