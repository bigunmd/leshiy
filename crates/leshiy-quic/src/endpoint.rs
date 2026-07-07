//! quinn endpoint construction: BBR server + a client with SHA-256 cert pinning or webpki roots.
use crate::Result;
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Tear down a QUIC connection after this long with no activity. Keepalive PINGs (below) refresh
/// it, so this only fires when the path is genuinely dead.
const QUIC_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Keepalive PING cadence — comfortably inside [`QUIC_IDLE_TIMEOUT`] so an otherwise-idle tunnel
/// (or one whose UDP path briefly rebinds on sleep/resume) stays alive and a real break is detected
/// promptly. Must stay well below the idle timeout.
const QUIC_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

fn bbr_transport() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // `try_from` only fails for a duration exceeding quinn's varint ceiling — impossible for a
    // fixed 30s const, so the expect is unreachable in practice.
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(QUIC_IDLE_TIMEOUT).expect("30s is a valid QUIC idle timeout"),
    ));
    // Quinn disables keepalive by default; without it an idle QUIC tunnel is torn down on idle
    // timeout even when both ends are healthy.
    transport.keep_alive_interval(Some(QUIC_KEEPALIVE_INTERVAL));
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
    // Build the UDP socket ourselves so a v6 wildcard is dual-stack (accepts
    // IPv4 clients as v4-mapped), then hand it to quinn via Endpoint::new.
    let socket = server_udp_socket(listen)?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| crate::QuicError::Conn("no async runtime".into()))?;
    Endpoint::new(quinn::EndpointConfig::default(), Some(cfg), socket, runtime).map_err(Into::into)
}

/// Bind the QUIC/UDP server socket. For a v6 wildcard/literal (`[::]`), enable
/// dual-stack (`IPV6_V6ONLY=false`) so the one socket also serves IPv4 clients as
/// v4-mapped; a v4 literal binds v4-only.
fn server_udp_socket(listen: SocketAddr) -> Result<std::net::UdpSocket> {
    let domain = if listen.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .map_err(|e| crate::QuicError::Conn(format!("udp socket: {e}")))?;
    if listen.is_ipv6() {
        sock.set_only_v6(false)
            .map_err(|e| crate::QuicError::Conn(format!("IPV6_V6ONLY(false): {e}")))?;
    }
    sock.set_reuse_address(true).ok();
    sock.bind(&listen.into())
        .map_err(|e| crate::QuicError::Conn(format!("bind {listen}: {e}")))?;
    Ok(sock.into())
}

/// Wildcard client bind matching the family of the QUIC server target: a v4 UDP
/// socket cannot reach a v6 server endpoint (and vice versa), so the client
/// socket must be bound in the target's address family.
fn client_bind_wildcard(target: SocketAddr) -> SocketAddr {
    if target.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    }
}

/// Client endpoint using the specified certificate verification strategy, its UDP
/// socket bound in the same address family as `target`.
pub fn client_endpoint(verification: CertVerification, target: SocketAddr) -> Result<Endpoint> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let mut ep = Endpoint::client(client_bind_wildcard(target))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn client_bind_wildcard_matches_target_family() {
        let v4: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(client_bind_wildcard(v4), "0.0.0.0:0".parse().unwrap());
        assert_eq!(client_bind_wildcard(v6), "[::]:0".parse().unwrap());
    }

    #[test]
    fn server_udp_socket_matches_family() {
        let v6 = server_udp_socket("[::]:0".parse().unwrap()).unwrap();
        assert!(v6.local_addr().unwrap().is_ipv6());
        let v4 = server_udp_socket("0.0.0.0:0".parse().unwrap()).unwrap();
        assert!(v4.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn client_endpoint_binds_target_family() {
        // The client UDP socket must match the server's family — a v4 socket cannot
        // reach a v6 QUIC endpoint. Verified via the bound local address.
        let v4: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let ep4 = client_endpoint(CertVerification::Roots, v4).unwrap();
        assert!(ep4.local_addr().unwrap().is_ipv4());

        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let ep6 = client_endpoint(CertVerification::Roots, v6).unwrap();
        assert!(ep6.local_addr().unwrap().is_ipv6());
    }
}
