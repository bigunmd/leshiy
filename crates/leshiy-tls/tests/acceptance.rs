//! Real-server acceptance integration tests (Task 7 + M1.4a Task 1 Step 4).
//!
//! Starts a rustls TLS 1.3 server (self-signed cert via rcgen) on an ephemeral
//! port. A raw tokio TCP client writes our crafted ClientHello as a HANDSHAKE
//! record, reads the first record back, and asserts:
//!   - the record is NOT an Alert (`check_not_alert` returns Ok)
//!   - `parse_server_hello` succeeds
//!   - the selected cipher suite is a TLS 1.3 suite (0x1301/0x1302/0x1303)
//!
//! M1.4a Task 1 Step 4: The PQ acceptance test uses the default (PQ-preferring) rustls
//! provider and asserts that rustls selects group 0x11EC (X25519MLKEM768) without HRR.
use leshiy_tls::client_hello::build_client_hello;
use leshiy_tls::fingerprint::Profile;
use leshiy_tls::record::{HANDSHAKE, Record, read_record, write_record};
use leshiy_tls::server_hello::{check_not_alert, parse_server_hello};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Build a rustls ServerConfig using the aws-lc-rs (PQ-preferring) provider.
fn make_server_config(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("bad protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("failed to build ServerConfig"),
    )
}

#[tokio::test]
async fn rustls_server_accepts_our_clienthello() {
    // Generate a self-signed certificate for www.example.com.
    // rcgen 0.13: `generate_simple_self_signed` returns `CertifiedKey { cert, key_pair }`.
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["www.example.com".to_string()]).unwrap();

    // Build the rustls ServerConfig from the DER-encoded cert and PKCS8 key.
    let cert_der: CertificateDer<'static> = cert.into();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let acceptor = TlsAcceptor::from(make_server_config(cert_der, key_der));

    // Bind an ephemeral port and spawn the TLS acceptor in the background.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Accept one connection; ignore the TLS handshake result (the server side
        // will fail after we only send ClientHello without completing the handshake,
        // but that's fine — we only care about the ServerHello it sends back).
        if let Ok((sock, _)) = listener.accept().await {
            let _ = acceptor.accept(sock).await;
        }
    });

    // Connect with a raw TCP stream so we can write a bare ClientHello.
    let mut tcp = TcpStream::connect(addr).await.unwrap();

    // Build our fingerprinted ClientHello with a real ML-KEM ek (dummy zeros for test).
    let ch = build_client_hello(
        &Profile::yandex(),
        "www.example.com",
        &[7u8; 32],
        &[0u8; 1184],
        [9u8; 32],
    );

    // Wrap the ClientHello in a TLS HANDSHAKE record and send it.
    write_record(
        &mut tcp,
        &Record {
            content_type: HANDSHAKE,
            payload: ch,
        },
    )
    .await
    .unwrap();

    // Read the first record the server sends back.
    let rec = read_record(&mut tcp).await.unwrap();

    // Assert it is NOT a TLS Alert (i.e. rustls accepted our ClientHello).
    check_not_alert(rec.content_type, &rec.payload)
        .expect("server sent a TLS Alert — our ClientHello was rejected");

    // Assert we can parse a valid ServerHello out of the record payload.
    let info = parse_server_hello(&rec.payload).expect("failed to parse ServerHello");

    // The selected cipher suite must be a TLS 1.3 suite.
    assert!(
        matches!(info.cipher_suite, 0x1301..=0x1303),
        "unexpected cipher suite: {:#06x} (expected a TLS 1.3 suite)",
        info.cipher_suite
    );
}

/// M1.4a Task 1 Step 4: Verify rustls (default PQ-preferring provider) selects
/// group 0x11EC (X25519MLKEM768) when our ClientHello includes a real ML-KEM key share.
/// The server must respond with a ServerHello (not HRR, not Alert) using group 0x11EC.
#[tokio::test]
async fn rustls_pq_server_selects_mlkem_group() {
    use leshiy_tls::tls13::mlkem;

    // Generate a real ML-KEM keypair so the ek is cryptographically valid.
    let (_dk, mlkem_ek) = mlkem::generate();

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["pq.example.com".to_string()]).unwrap();

    let cert_der: CertificateDer<'static> = cert.into();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    // Use the DEFAULT rustls provider — aws-lc-rs, which is PQ-preferring (X25519MLKEM768 first).
    let acceptor = TlsAcceptor::from(make_server_config(cert_der, key_der));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await {
            // The server side will abort when we don't complete the handshake — that's fine.
            let _ = acceptor.accept(sock).await;
        }
    });

    let mut tcp = TcpStream::connect(addr).await.unwrap();

    // Build ClientHello with the real ML-KEM ek and a dummy x25519 key.
    let ch = build_client_hello(
        &Profile::yandex(),
        "pq.example.com",
        &[0x42u8; 32],
        &mlkem_ek,
        [0xABu8; 32],
    );

    write_record(
        &mut tcp,
        &Record {
            content_type: HANDSHAKE,
            payload: ch,
        },
    )
    .await
    .unwrap();

    let rec = read_record(&mut tcp).await.unwrap();

    // Must NOT be an alert — rustls must have accepted the CH.
    check_not_alert(rec.content_type, &rec.payload)
        .expect("rustls PQ server sent Alert — our 0x11EC key_share was not accepted");

    let info = parse_server_hello(&rec.payload).expect("failed to parse PQ ServerHello");

    // Rustls (default PQ provider) MUST select group 0x11EC (X25519MLKEM768).
    // If it sends HRR instead, our key_share emission is wrong.
    assert_eq!(
        info.selected_group,
        Some(0x11ec),
        "expected rustls to select group 0x11EC (X25519MLKEM768), got: {:?}",
        info.selected_group
    );

    // The selected cipher suite must be a TLS 1.3 suite.
    assert!(
        matches!(info.cipher_suite, 0x1301..=0x1303),
        "unexpected cipher suite: {:#06x}",
        info.cipher_suite
    );
}
