//! MTProxy on the REALITY listener, end to end in-process: a client built from the Telegram
//! transport spec, a real rustls TLS 1.3 dest, and a fake Telegram DC behind a test `Egress`.
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use leshiy_reality::config::ServerAuthConfig;
use leshiy_reality::egress::{Egress, EgressRead, EgressWrite};
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::mtproxy::MtProxySecret;
use leshiy_reality::replay::ReplayGuard;
use leshiy_reality::server::serve_connection;
use leshiy_reality::user::InMemoryUserStore;
use leshiy_tls::record::{APPLICATION_DATA, HANDSHAKE, Record, read_record, write_record};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

type AesCtr = ctr::Ctr128BE<Aes256>;

const SECRET_HEX: &str = "00112233445566778899aabbccddeeff";
const NOW: u32 = 1_780_000_000;
const SNI: &str = "www.example.com";

async fn spawn_rustls_dest() -> String {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let cfg = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![CertificateDer::from(cert)], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let _ = acc.accept(sock).await;
            });
        }
    });
    addr
}

/// A fake Telegram DC: validates the obfuscated2 header the proxy sends, then echoes every
/// byte back re-encrypted — so the client seeing its own plaintext proves both directions.
struct FakeDc {
    opened: Mutex<Vec<String>>,
}

struct DuplexRead(ReadHalf<DuplexStream>);
struct DuplexWrite(WriteHalf<DuplexStream>);

#[async_trait::async_trait]
impl EgressRead for DuplexRead {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf).await
    }
}

#[async_trait::async_trait]
impl EgressWrite for DuplexWrite {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_all(buf).await
    }
    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.0.shutdown().await
    }
}

#[async_trait::async_trait]
impl Egress for FakeDc {
    async fn open(
        &self,
        target: &str,
    ) -> leshiy_reality::Result<(Box<dyn EgressRead>, Box<dyn EgressWrite>)> {
        self.opened.lock().unwrap().push(target.to_string());
        let (proxy_side, mut dc) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut hello = [0u8; 64];
            dc.read_exact(&mut hello).await.unwrap();
            let mut dec = AesCtr::new((&hello[8..40]).into(), (&hello[40..56]).into());
            let mut rev = [0u8; 48];
            rev.copy_from_slice(&hello[8..56]);
            rev.reverse();
            let mut enc = AesCtr::new((&rev[..32]).into(), (&rev[32..]).into());
            let mut plain = hello;
            dec.apply_keystream(&mut plain);
            assert_eq!(plain[56..60], [0xdd; 4], "proxy sent a bad upstream tag");
            let mut buf = [0u8; 4096];
            loop {
                let n = match dc.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                dec.apply_keystream(&mut buf[..n]);
                enc.apply_keystream(&mut buf[..n]);
                if dc.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        });
        let (r, w) = tokio::io::split(proxy_side);
        Ok((Box::new(DuplexRead(r)), Box::new(DuplexWrite(w))))
    }
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// A real ClientHello (so the rustls dest answers it) signed the way Telegram clients sign it.
fn telegram_client_hello(secret: &[u8; 16], ts: u32) -> Vec<u8> {
    let mut payload = leshiy_tls::client_hello::build_client_hello(
        &leshiy_tls::fingerprint::Profile::yandex(),
        SNI,
        &[4u8; 32],
        &[0u8; 1184],
        [0u8; 32],
    );
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(&payload);
    let mut mac = hmac(secret, &[&rec]);
    for (b, t) in mac[28..].iter_mut().zip(ts.to_le_bytes()) {
        *b ^= t;
    }
    payload[6..38].copy_from_slice(&mac);
    payload
}

async fn spawn_front(
    cfg: Arc<ServerAuthConfig>,
    egress: Arc<FakeDc>,
    replay: Arc<ReplayGuard>,
) -> std::net::SocketAddr {
    let fl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = fl.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = fl.accept().await {
            let (c, e, r) = (cfg.clone(), egress.clone(), replay.clone());
            tokio::spawn(async move {
                let store = Arc::new(InMemoryUserStore::from_short_ids(std::iter::empty()));
                let _ =
                    serve_connection(sock, c, store, e, Arc::new(ServerCert::generate()), r, NOW)
                        .await;
            });
        }
    });
    addr
}

struct Harness {
    front: std::net::SocketAddr,
    dc: Arc<FakeDc>,
}

async fn harness() -> Harness {
    let dest = spawn_rustls_dest().await;
    let cfg = Arc::new(ServerAuthConfig {
        static_secret: Zeroizing::new([0x55; 32]),
        server_names: HashSet::from([SNI.to_string()]),
        short_ids: HashSet::new(),
        max_time_diff: Duration::from_secs(120),
        dest,
        dest_by_sni: Default::default(),
        mtproxy: Some(MtProxySecret::from_hex(SECRET_HEX).unwrap()),
    });
    let dc = Arc::new(FakeDc {
        opened: Mutex::new(Vec::new()),
    });
    let replay = Arc::new(ReplayGuard::new(Duration::from_secs(240)));
    Harness {
        front: spawn_front(cfg, dc.clone(), replay).await,
        dc,
    }
}

fn secret() -> [u8; 16] {
    let mut s = [0u8; 16];
    hex::decode_to_slice(SECRET_HEX, &mut s).unwrap();
    s
}

/// Send the hello and read the server's first flight: (ServerHello, next two records).
async fn hello_exchange(c: &mut tokio::net::TcpStream, ch: &[u8]) -> Vec<Record> {
    write_record(
        c,
        &Record {
            content_type: HANDSHAKE,
            payload: ch.to_vec(),
        },
    )
    .await
    .unwrap();
    let mut recs = Vec::new();
    for _ in 0..3 {
        let r = tokio::time::timeout(Duration::from_secs(5), read_record(c))
            .await
            .expect("server answered")
            .expect("record");
        recs.push(r);
    }
    recs
}

fn server_mac_valid(client_random: &[u8], recs: &[Record]) -> bool {
    let mut resp: Vec<u8> = recs.iter().flat_map(Record::encode).collect();
    let got = resp[11..43].to_vec();
    resp[11..43].fill(0);
    hmac(&secret(), &[client_random, &resp])[..] == got[..]
}

#[tokio::test]
async fn telegram_client_is_relayed_to_the_requested_dc() {
    let h = harness().await;
    let mut c = tokio::net::TcpStream::connect(h.front).await.unwrap();
    let ch = telegram_client_hello(&secret(), NOW - 5);

    let recs = hello_exchange(&mut c, &ch).await;
    assert!(
        server_mac_valid(&ch[6..38], &recs),
        "server hello MAC must verify"
    );
    assert_eq!(recs[1].content_type, 0x14);
    assert_eq!(recs[2].content_type, APPLICATION_DATA);

    // obfuscated2 header for DC 2, keyed with the secret, then a first payload.
    let mut rnd = [0x3cu8; 64];
    rnd[56..60].copy_from_slice(&[0xdd; 4]);
    rnd[60..62].copy_from_slice(&2i16.to_le_bytes());
    let enc_key: [u8; 32] = Sha256::new()
        .chain_update(&rnd[8..40])
        .chain_update(secret())
        .finalize()
        .into();
    let mut enc = AesCtr::new((&enc_key).into(), (&rnd[40..56]).into());
    let mut rev = [0u8; 48];
    rev.copy_from_slice(&rnd[8..56]);
    rev.reverse();
    let dec_key: [u8; 32] = Sha256::new()
        .chain_update(&rev[..32])
        .chain_update(secret())
        .finalize()
        .into();
    let mut dec = AesCtr::new((&dec_key).into(), (&rev[32..]).into());
    let mut sealed = rnd;
    enc.apply_keystream(&mut sealed);
    let mut first = rnd.to_vec();
    first[56..].copy_from_slice(&sealed[56..]);
    let mut ping = b"ping through the proxy".to_vec();
    enc.apply_keystream(&mut ping);
    first.extend_from_slice(&ping);
    write_record(
        &mut c,
        &Record {
            content_type: APPLICATION_DATA,
            payload: first,
        },
    )
    .await
    .unwrap();

    let echo = tokio::time::timeout(Duration::from_secs(5), read_record(&mut c))
        .await
        .expect("echo arrived")
        .unwrap();
    assert_eq!(echo.content_type, APPLICATION_DATA);
    let mut got = echo.payload;
    dec.apply_keystream(&mut got);
    assert_eq!(&got, b"ping through the proxy");
    assert_eq!(*h.dc.opened.lock().unwrap(), vec!["149.154.167.51:443"]);
}

#[tokio::test]
async fn hello_with_wrong_secret_gets_the_real_dest() {
    let h = harness().await;
    let mut c = tokio::net::TcpStream::connect(h.front).await.unwrap();
    let ch = telegram_client_hello(&[0x99; 16], NOW);

    let recs = hello_exchange(&mut c, &ch).await;
    assert!(!server_mac_valid(&ch[6..38], &recs));
    assert!(h.dc.opened.lock().unwrap().is_empty());
}

#[tokio::test]
async fn replayed_hello_gets_the_real_dest() {
    let h = harness().await;
    let ch = telegram_client_hello(&secret(), NOW);

    let mut first = tokio::net::TcpStream::connect(h.front).await.unwrap();
    assert!(server_mac_valid(
        &ch[6..38],
        &hello_exchange(&mut first, &ch).await
    ));

    let mut replay = tokio::net::TcpStream::connect(h.front).await.unwrap();
    assert!(!server_mac_valid(
        &ch[6..38],
        &hello_exchange(&mut replay, &ch).await
    ));
}
