//! Privileged end-to-end smoke: HelperClient → serve_control(EngineRunner) → real TUN.
//! Ignored by default (needs CAP_NET_ADMIN + a reachable leshiy server). Run with:
//!   LESHIY_TEST_URI='leshiy://…' sudo -E cargo test -p leshiy-helper --test root_smoke -- --ignored
#![cfg(unix)]
use leshiy_client::State;
use leshiy_client::settings::TransportPref;
use leshiy_helper::{
    Auth, Endpoint, EngineRunner, HelperClient, ServeMode, StartParams, serve_control,
};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN + LESHIY_TEST_URI; run with sudo -E … -- --ignored"]
async fn helper_brings_up_real_tun() {
    let uri = std::env::var("LESHIY_TEST_URI").expect("set LESHIY_TEST_URI to a reachable server");
    let dir = std::env::temp_dir().join(format!("leshiy-helper-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("smoke.sock");

    let runner = Arc::new(EngineRunner::new());
    let me = nix::unistd::getuid().as_raw();
    {
        let sock = sock.clone();
        let runner = runner.clone();
        tokio::spawn(async move {
            let _ = serve_control(
                &Endpoint::Socket(sock),
                runner,
                Auth { uid: me, sid: None },
                ServeMode::Persistent,
            )
            .await;
        });
    }
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let client = HelperClient::connect_path(&sock);
    client
        .start_vpn(StartParams {
            uri,
            transport: TransportPref::Tcp,
            mtu: 1400,
            tun_name: "leshiy-smoke0".into(),
            dns: "1.1.1.1".into(),
            split_tunnel: Default::default(),
        })
        .await
        .expect("start_vpn");

    // Give the engine a moment, then confirm the helper reports Connected.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let status = client.get_status().await.expect("status");
    assert_eq!(status.state, State::Connected);

    client.stop().await.expect("stop");
}
