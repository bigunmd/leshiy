use leshiy_reality::client::build_authed_client_hello;
use leshiy_reality::config::ClientAuthConfig;
use leshiy_reality::handshake::{ServerCert, client_handshake, server_handshake};
use leshiy_tls::fingerprint::Profile;
use leshiy_tls::tls13::messages::{ServerHelloParams, build_server_hello};
use leshiy_tls::tls13::suite::CipherSuite;
use x25519_dalek::{PublicKey, StaticSecret};

fn sample_dest_sh_x25519(suite: u16) -> Vec<u8> {
    // a minimal valid dest ServerHello offering an x25519 key_share (data is dummy; server replaces it)
    build_server_hello(&ServerHelloParams {
        suite,
        server_random: [0x33; 32],
        session_id_echo: vec![],
        key_share_group: 0x001d,
        key_share: vec![0xCC; 32],
    })
}

fn sample_dest_sh_mlkem(suite: u16) -> Vec<u8> {
    // a minimal valid dest ServerHello offering an X25519MLKEM768 key_share (server replaces the share)
    build_server_hello(&ServerHelloParams {
        suite,
        server_random: [0x44; 32],
        session_id_echo: vec![],
        key_share_group: 0x11ec,
        key_share: vec![0xBB; 1120],
    })
}

fn run_suite_x25519(suite_u16: u16) {
    let server_static = StaticSecret::from([0x55u8; 32]);
    let server_public = PublicKey::from(&server_static).to_bytes();
    let cfg = ClientAuthConfig {
        server_public,
        short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        sni: "www.example.com".into(),
    };
    let (ch, ephem, mlkem_dk) = build_authed_client_hello(&Profile::yandex(), &cfg, 1_700_000_000);

    // server recomputes auth_key the same way classify does (X25519 static x client ephem + HKDF)
    let f = leshiy_tls::ja::extract_client_hello_fields(&ch).unwrap();
    let client_pub = f.key_share_x25519.unwrap();
    let shared = server_static
        .diffie_hellman(&PublicKey::from(client_pub))
        .to_bytes();
    let auth_key = leshiy_reality::auth::derive_auth_key(&shared, &f.random);

    let cert = ServerCert::generate();
    let dest_sh = sample_dest_sh_x25519(suite_u16);
    let (sh_state, flight) = server_handshake(&ch, &dest_sh, &auth_key, &cert).unwrap();
    let out = client_handshake(&ch, &flight, &ephem, &auth_key, &mlkem_dk).unwrap();
    let server_session = sh_state.finish(&out.client_finished_record).unwrap();

    // both sides agree on app keys
    assert_eq!(out.session.client_key, server_session.client_key);
    assert_eq!(out.session.client_iv, server_session.client_iv);
    assert_eq!(out.session.server_key, server_session.server_key);
    assert_eq!(out.session.server_iv, server_session.server_iv);
    assert_eq!(
        server_session.suite,
        CipherSuite::from_u16(suite_u16).unwrap()
    );
}

fn run_suite_mlkem(suite_u16: u16) {
    let server_static = StaticSecret::from([0x55u8; 32]);
    let server_public = PublicKey::from(&server_static).to_bytes();
    let cfg = ClientAuthConfig {
        server_public,
        short_id: [1, 2, 3, 4, 0, 0, 0, 0],
        sni: "www.example.com".into(),
    };
    let (ch, ephem, mlkem_dk) = build_authed_client_hello(&Profile::yandex(), &cfg, 1_700_000_000);

    // server recomputes auth_key
    let f = leshiy_tls::ja::extract_client_hello_fields(&ch).unwrap();
    let client_pub = f.key_share_x25519.unwrap();
    let shared = server_static
        .diffie_hellman(&PublicKey::from(client_pub))
        .to_bytes();
    let auth_key = leshiy_reality::auth::derive_auth_key(&shared, &f.random);

    let cert = ServerCert::generate();
    // dest SH uses group 0x11ec — both sides must use the X25519MLKEM768 path
    let dest_sh = sample_dest_sh_mlkem(suite_u16);
    let (sh_state, flight) = server_handshake(&ch, &dest_sh, &auth_key, &cert).unwrap();
    let out = client_handshake(&ch, &flight, &ephem, &auth_key, &mlkem_dk).unwrap();
    let server_session = sh_state.finish(&out.client_finished_record).unwrap();

    // both sides must agree on ALL app keys (the pair test catches any byte-order swap)
    assert_eq!(
        out.session.client_key, server_session.client_key,
        "client_key mismatch for 0x11ec group (suite {suite_u16:#x})"
    );
    assert_eq!(
        out.session.client_iv, server_session.client_iv,
        "client_iv mismatch for 0x11ec group (suite {suite_u16:#x})"
    );
    assert_eq!(
        out.session.server_key, server_session.server_key,
        "server_key mismatch for 0x11ec group (suite {suite_u16:#x})"
    );
    assert_eq!(
        out.session.server_iv, server_session.server_iv,
        "server_iv mismatch for 0x11ec group (suite {suite_u16:#x})"
    );
    assert_eq!(
        server_session.suite,
        CipherSuite::from_u16(suite_u16).unwrap()
    );
}

#[test]
fn handshake_pair_x25519_all_suites() {
    run_suite_x25519(0x1301);
    run_suite_x25519(0x1302);
    run_suite_x25519(0x1303);
}

#[test]
fn handshake_pair_mlkem_all_suites() {
    // Proves the 0x11ec (X25519MLKEM768) path: server encapsulates, client decapsulates.
    // A byte-order swap in the combined ECDHE (ss_mlkem ‖ ss_x25519) makes keys disagree.
    run_suite_mlkem(0x1301);
    run_suite_mlkem(0x1302);
    run_suite_mlkem(0x1303);
}

#[test]
fn wrong_auth_key_client_rejects_server() {
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
    let real_auth = leshiy_reality::auth::derive_auth_key(&shared, &f.random);

    let cert = ServerCert::generate();
    let dest_sh = sample_dest_sh_x25519(0x1301);
    let (_sh_state, flight) = server_handshake(&ch, &dest_sh, &real_auth, &cert).unwrap();
    // client uses a WRONG auth_key → identity HMAC check fails
    let wrong = [0u8; 32];
    assert!(client_handshake(&ch, &flight, &ephem, &wrong, &mlkem_dk).is_err());
}
