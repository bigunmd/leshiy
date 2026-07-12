//! Transport-agnostic dispatch test: drive the generic `handle_stream` over an in-memory
//! duplex pipe (no real socket/pipe), proving the protocol logic is transport-independent.
use leshiy_client::State;
use leshiy_client::settings::TransportPref;
use leshiy_helper::proto::{Request, Response, StartParams};
use leshiy_helper::runner::test_support::FakeRunner;
use leshiy_helper::server::handle_stream;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn params() -> StartParams {
    StartParams {
        uri: "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000".into(),
        transport: TransportPref::Tcp,
        mtu: 1400,
        tun_name: "leshiy0".into(),
        dns: "1.1.1.1".into(),
        split_tunnel: Default::default(),
        ipv6: false,
    }
}

/// One request per connection (the wire model). Open a fresh duplex, send a line, read one.
async fn roundtrip(runner: Arc<FakeRunner>, req: &Request) -> Response {
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let _ = handle_stream(server, runner).await;
    });
    let mut c = BufReader::new(client);
    let mut payload = serde_json::to_string(req).unwrap();
    payload.push('\n');
    c.get_mut().write_all(payload.as_bytes()).await.unwrap();
    let mut line = String::new();
    c.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

#[tokio::test]
async fn start_then_status_over_duplex() {
    let runner = Arc::new(FakeRunner::new());
    assert_eq!(
        roundtrip(runner.clone(), &Request::StartVpn(params())).await,
        Response::Ok
    );
    assert_eq!(runner.started.lock().unwrap().len(), 1);
    match roundtrip(runner.clone(), &Request::GetStatus).await {
        Response::Status { status } => assert_eq!(status.state, State::Connected),
        other => panic!("expected Status, got {other:?}"),
    }
    assert_eq!(roundtrip(runner, &Request::Stop).await, Response::Ok);
}
