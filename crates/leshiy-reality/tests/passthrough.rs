// Integration gate for M1.3d Task 2:
//   unauthed_is_relayed_to_dest — plain ClientHello is transparently relayed through
//   a real rustls TLS 1.3 "dest"; the client receives the dest's ServerHello.
//
// The Outcome::Authed assertion from M1.2 is removed — the authed path is covered
// by the in-process e2e in Task 4 (reality_e2e.rs).
use leshiy_reality::config::ServerAuthConfig;
use leshiy_reality::egress::DirectEgress;
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::server::serve_connection;
use leshiy_reality::user::InMemoryUserStore;
use leshiy_tls::record::{HANDSHAKE, Record, read_record, write_record};
use leshiy_tls::server_hello::{check_not_alert, parse_server_hello};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

/// Spawn a rustls TLS 1.3 "dest" server (self-signed cert for www.example.com).
/// Returns the addr as "127.0.0.1:<port>".
async fn spawn_rustls_dest() -> String {
    // rcgen 0.13: generate_simple_self_signed returns CertifiedKey { cert, key_pair }
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["www.example.com".to_string()]).unwrap();

    let cert_der: CertificateDer<'static> = cert.into();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let server_cfg = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("bad protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("failed to build rustls ServerConfig");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        loop {
            if let Ok((sock, _)) = listener.accept().await {
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acc.accept(sock).await;
                });
            }
        }
    });

    addr
}

fn server_cfg(secret: [u8; 32], dest: String) -> Arc<ServerAuthConfig> {
    Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new(secret),
        server_names: HashSet::from(["www.example.com".to_string()]),
        short_ids: HashSet::from([[1u8, 2, 3, 4, 0, 0, 0, 0]]),
        max_time_diff: Duration::from_secs(120),
        dest,
    })
}

/// Unauthed client sends a plain (non-auth) ClientHello. serve_connection relays it
/// to the rustls dest; the client should receive the dest's ServerHello back.
#[tokio::test]
async fn unauthed_is_relayed_to_dest() {
    let dest = spawn_rustls_dest().await;
    let cfg = server_cfg([0x55; 32], dest);
    let cert = Arc::new(ServerCert::generate());

    // Bind the "front door" listener and serve one connection.
    let fl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let faddr = fl.local_addr().unwrap();
    let cfg2 = cfg.clone();
    let cert2 = cert.clone();
    tokio::spawn(async move {
        let (sock, _) = fl.accept().await.unwrap();
        let store = std::sync::Arc::new(InMemoryUserStore::from_short_ids(
            cfg2.short_ids.iter().copied(),
        ));
        let _ = serve_connection(
            sock,
            cfg2,
            store,
            std::sync::Arc::new(DirectEgress::allowing_private()),
            cert2,
            1000,
        )
        .await;
    });

    // Connect as an unauthed client with a plain (non-auth) ClientHello.
    let mut c = TcpStream::connect(faddr).await.unwrap();
    let ch = leshiy_tls::client_hello::build_client_hello(
        &leshiy_tls::fingerprint::Profile::yandex(),
        "www.example.com",
        &[3u8; 32],
        &[0u8; 1184],
        [4u8; 32],
    );
    write_record(
        &mut c,
        &Record {
            content_type: HANDSHAKE,
            payload: ch,
        },
    )
    .await
    .unwrap();

    // The dest's ServerHello should come back through the relay.
    let rec = tokio::time::timeout(std::time::Duration::from_secs(5), read_record(&mut c))
        .await
        .expect("timed out waiting for relayed ServerHello")
        .expect("read_record failed");

    check_not_alert(rec.content_type, &rec.payload)
        .expect("dest sent a TLS Alert — relay did not forward ServerHello");
    parse_server_hello(&rec.payload).expect("failed to parse relayed ServerHello");
}
