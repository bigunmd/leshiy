//! `leshiy quickstart`: wizard orchestration on top of `server::init`.
//! Domain logic only (no host mutation) — emits a machine-readable summary the
//! installer consumes.

/// Render a URI as a terminal QR code (UTF-8 half-block string).
///
/// Uses the **low** error-correction level: a share URI is read off a clean screen, so the
/// ~15% redundancy of level M isn't needed — level L keeps the QR a few versions smaller
/// (notably for the longer QUIC URIs, ~225 bytes), which matters for terminal scannability.
pub fn qr_string(uri: &str) -> String {
    use qrcode::render::unicode;
    use qrcode::{EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::L)
        .expect("uri always encodable as QR");
    code.render::<unicode::Dense1x2>().quiet_zone(true).build()
}

/// QR for `uri`, unless it is wider than `term_cols` — then return a short hint to widen/copy
/// instead of an unscannable wrapped blob. `term_cols == None` (width unknown, e.g. piped)
/// renders the QR. Callers always print the plain URI above the QR, so the hint loses nothing.
pub fn qr_or_hint(uri: &str, term_cols: Option<usize>) -> String {
    let qr = qr_string(uri);
    let qr_cols = qr.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    match term_cols {
        Some(cols) if qr_cols > cols => format!(
            "(QR is {qr_cols} cols wide — widen your terminal to \u{2265}{qr_cols} columns to \
             scan it, or copy the URI above.)"
        ),
        _ => qr,
    }
}

/// Render the QR for `uri` sized to the current terminal (hint if too narrow / unknown-wide).
pub fn qr_for_stdout(uri: &str) -> String {
    let cols = terminal_size::terminal_size().map(|(w, _h)| w.0 as usize);
    qr_or_hint(uri, cols)
}

/// Connect to `host:port` and report the negotiated TLS protocol version.
/// Returns Ok(true) iff the peer negotiated TLS 1.3.
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

use anyhow::{Context, Result};

pub struct QuickstartOpts<'a> {
    pub host: &'a str,
    pub dest: &'a str,
    pub out: &'a str,
    pub listen: Option<&'a str>,
    pub quic_listen: Option<&'a str>,
    pub quic_sni: Option<&'a str>,
    pub no_probe: bool,
    pub summary_json: bool,
    pub role: crate::cli::Role,
    pub exit_uri: Option<&'a str>,
}

pub async fn run(opts: QuickstartOpts<'_>) -> Result<()> {
    use crate::cli::Role;
    // Role-specific preconditions.
    let connector: Option<&str> = match opts.role {
        Role::Entry => Some(
            opts.exit_uri
                .ok_or_else(|| anyhow::anyhow!("--role entry requires --exit-uri <EXIT_URI>"))?,
        ),
        Role::Exit => {
            if opts.quic_listen.is_none() {
                return Err(anyhow::anyhow!(
                    "--role exit requires --quic-listen <public-host:port> (the carrier the entry dials)"
                ));
            }
            None
        }
        Role::Single => None,
    };
    // 1. Validate the dest negotiates TLS1.3 (unless explicitly skipped).
    if !opts.no_probe {
        let (h, p) = opts.dest.rsplit_once(':').unwrap_or((opts.dest, "443"));
        let port: u16 = p.parse().context("dest port")?;
        match dest_is_tls13(h, port).await {
            Ok(true) => eprintln!("dest {h}:{port} negotiates TLS1.3 ✓"),
            Ok(false) => {
                return Err(anyhow::anyhow!(
                    "dest {h}:{port} did not negotiate TLS1.3 — pick a modern site (see README)"
                ));
            }
            Err(e) => return Err(anyhow::anyhow!("could not probe dest {h}:{port}: {e}")),
        }
    }
    // 2. Reuse the existing server-init logic (keygen + config + sqlite + URI).
    let out = crate::server::init(crate::server::InitOptions {
        host: opts.host,
        dest: opts.dest,
        listen: opts.listen,
        out: opts.out,
        quic_listen: opts.quic_listen,
        quic_domain: opts.quic_sni,
        quic_cert: None,
        quic_key: None,
        connector,
    })?;
    // 3. Show the QR for phones (or the connector credential for exit role).
    match opts.role {
        Role::Exit => {
            println!(
                "\nThis is the EXIT's connector credential — give it to the entry's --exit-uri:"
            );
            println!("{}", out.uri);
        }
        Role::Single | Role::Entry => {
            println!("\nShare with clients — scan to import on a device:");
            println!("{}", qr_for_stdout(&out.uri));
        }
    }
    // 4. Emit the machine-readable summary the installer parses.
    if opts.summary_json {
        let summary = serde_json::json!({
            "config_path": out.config_path,
            "uri": out.uri,
            "listen": out.listen,
            "quic_listen": out.quic_listen,
        });
        println!("{summary}");
    }
    Ok(())
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

    const SAMPLE_URI: &str = "leshiy://abc@203.0.113.5:443?sni=www.microsoft.com&sid=00";

    #[test]
    fn qr_or_hint_renders_when_wide_enough() {
        let s = qr_or_hint(SAMPLE_URI, Some(200));
        assert!(s.contains('█') || s.contains('▀') || s.contains('▄'));
        assert!(!s.contains("widen your terminal"));
    }

    #[test]
    fn qr_or_hint_warns_when_too_narrow() {
        let s = qr_or_hint(SAMPLE_URI, Some(10));
        assert!(s.contains("widen your terminal"));
        assert!(!s.contains('█') && !s.contains('▀') && !s.contains('▄'));
    }

    #[test]
    fn qr_or_hint_renders_when_width_unknown() {
        let s = qr_or_hint(SAMPLE_URI, None);
        assert!(s.contains('█') || s.contains('▀') || s.contains('▄'));
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
