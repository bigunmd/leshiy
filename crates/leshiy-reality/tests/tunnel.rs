use leshiy_core::mux::{Mux, Role};
use leshiy_core::version::Hello;
use leshiy_reality::auth::derive_auth_key;
use leshiy_reality::client::build_authed_client_hello;
use leshiy_reality::config::ClientAuthConfig;
use leshiy_reality::handshake::ServerCert;
use leshiy_reality::tunnel::{establish_client, establish_server, into_transport};
use leshiy_tls::fingerprint::Profile;
use leshiy_tls::record::{HANDSHAKE, Record, write_record};
use leshiy_tls::tls13::messages::{ServerHelloParams, build_server_hello};
use x25519_dalek::{PublicKey, StaticSecret};

fn hello() -> Hello {
    Hello::new(1, 1, 0)
}

fn sample_dest_sh(suite: u16) -> Vec<u8> {
    build_server_hello(&ServerHelloParams {
        suite,
        server_random: [0x33; 32],
        session_id_echo: vec![],
        key_share_group: 0x001d,
        key_share: vec![0xCC; 32],
    })
}

async fn run(suite_u16: u16) {
    let server_static = StaticSecret::from([0x55u8; 32]);
    let server_public = PublicKey::from(&server_static).to_bytes();
    let cfg = ClientAuthConfig {
        server_public,
        short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        sni: "www.example.com".into(),
    };
    let (ch, ephem, mlkem_dk) = build_authed_client_hello(&Profile::yandex(), &cfg, 1_700_000_000);
    let f = leshiy_tls::ja::extract_client_hello_fields(&ch).unwrap();
    let shared = server_static
        .diffie_hellman(&PublicKey::from(f.key_share_x25519.unwrap()))
        .to_bytes();
    let auth_key = derive_auth_key(&shared, &f.random);
    let cert = ServerCert::generate();
    let dest_sh = sample_dest_sh(suite_u16);

    let (c_io, s_io) = tokio::io::duplex(65536);

    let ch_for_client = ch.clone();
    let ch_for_server = ch.clone();
    let ephem2 = *ephem;
    let ak = *auth_key;

    // server task: read ClientHello record, then establish
    let srv = tokio::spawn(async move {
        let (mut sr, sw) = tokio::io::split(s_io);
        let chrec = leshiy_tls::record::read_record(&mut sr).await.unwrap();
        let (session, r, w) = establish_server(sr, sw, &chrec.payload, &dest_sh, &ak, &cert)
            .await
            .unwrap();
        let (tr, tw) = into_transport(&session, Role::Server, r, w);
        let mut mux = Mux::start(tr, tw, hello(), Role::Server).await.unwrap();
        let mut stream = mux.accept().await.unwrap();
        let data = stream.recv().await.unwrap();
        stream.send(data).await.unwrap(); // echo
    });

    // client: split c_io, send ClientHello record on the writer half, then establish
    let (cr, mut cw) = tokio::io::split(c_io);
    write_record(
        &mut cw,
        &Record {
            content_type: HANDSHAKE,
            payload: ch_for_client,
        },
    )
    .await
    .unwrap();
    let (session, r, w) = establish_client(cr, cw, &ch_for_server, &ephem2, &ak, &mlkem_dk)
        .await
        .unwrap();
    let (tr, tw) = into_transport(&session, Role::Client, r, w);
    let mut mux = Mux::start(tr, tw, hello(), Role::Client).await.unwrap();
    let mut s = mux.open("echo").await.unwrap();
    // Largest payload the mux puts in ONE frame (MAX_FRAME_PAYLOAD): exercises the TLS
    // record-size boundary — a max-size frame must seal into a single readable app-data
    // record. A larger frame would be writable but rejected by read_record (>2^14+slack),
    // deadlocking the stream — the regression this guards against.
    let payload = vec![7u8; leshiy_core::frame::MAX_FRAME_PAYLOAD];
    s.send(payload.clone().into()).await.unwrap();
    let got = s.recv().await.unwrap();
    assert_eq!(got, payload);
    srv.await.unwrap();
}

#[tokio::test]
async fn tunnel_echo_all_suites() {
    run(0x1301).await;
    run(0x1302).await;
    run(0x1303).await;
}
