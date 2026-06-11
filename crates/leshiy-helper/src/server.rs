//! Authenticated control server. Mirrors `leshiy-reality/src/control.rs`: a Unix socket
//! carrying newline-delimited JSON, with a per-connection `SO_PEERCRED` uid gate. The
//! server is generic over a `VpnRunner` so tests drive a fake without privilege.
use crate::auth::{authorize, peer_uid};
use crate::proto::{Event, Request, Response, Status};
use crate::runner::VpnRunner;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// Maximum bytes accepted per request line (same cap rationale as `control.rs`): a
/// peer streaming bytes with no newline hits the cap and yields a parse error, not OOM.
const MAX_LINE: u64 = 64 * 1024;

/// Serve the control socket at `path`, authorizing only connections from `allow_uid`.
/// Runs until the listener errors. Mirrors `control.rs`'s bind/unlink/permissions setup.
pub async fn serve_control(
    path: &Path,
    runner: Arc<dyn VpnRunner>,
    allow_uid: u32,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path); // unlink stale
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0o660: owner (root) + group (e.g. `leshiy`) read/write; world none.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    loop {
        let (conn, _) = listener.accept().await?;
        let runner = runner.clone();
        tokio::spawn(async move {
            let _ = handle(conn, runner, allow_uid).await;
        });
    }
}

async fn handle(
    conn: UnixStream,
    runner: Arc<dyn VpnRunner>,
    allow_uid: u32,
) -> std::io::Result<()> {
    // Silent rejection: if the peer is not authorized, drop the connection with no reply.
    match peer_uid(&conn) {
        Ok(uid) if authorize(uid, allow_uid) => {}
        _ => return Ok(()),
    }

    let mut r = BufReader::new(conn.take(MAX_LINE));
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    // Recover the raw stream (mirrors control.rs: Take<UnixStream> → UnixStream).
    let mut stream = r.into_inner().into_inner();

    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(req) => req,
        Err(e) => {
            return write_line(
                &mut stream,
                &Response::Err {
                    message: format!("bad request: {e}"),
                },
            )
            .await;
        }
    };

    match req {
        Request::StartVpn(params) => {
            let resp = match runner.start(&params).await {
                Ok(()) => Response::Ok,
                Err(e) => Response::Err {
                    message: e.to_string(),
                },
            };
            write_line(&mut stream, &resp).await
        }
        Request::Stop => {
            runner.stop().await;
            write_line(&mut stream, &Response::Ok).await
        }
        Request::GetStatus => {
            let status = Status {
                state: runner.state(),
                rates: *runner.subscribe_stats().borrow(),
            };
            write_line(&mut stream, &Response::Status { status }).await
        }
        Request::Subscribe => subscribe_loop(stream, runner).await,
    }
}

/// Stream `Event` frames as state/stats change, starting with one snapshot frame. Ends
/// when the runner's channels close or the write fails (caller disconnected).
async fn subscribe_loop(mut stream: UnixStream, runner: Arc<dyn VpnRunner>) -> std::io::Result<()> {
    let mut state_rx = runner.subscribe_state();
    let mut stats_rx = runner.subscribe_stats();

    // Initial snapshot so a fresh subscriber immediately sees the current state. Copy the
    // values out first so the `watch::Ref` guards (RwLockReadGuard, !Send) are dropped
    // before the await — otherwise the handler future is not Send and cannot be spawned.
    let snapshot = Event {
        state: Some(*state_rx.borrow_and_update()),
        rates: Some(*stats_rx.borrow_and_update()),
    };
    write_line(&mut stream, &Response::Event(snapshot)).await?;

    loop {
        let evt = tokio::select! {
            changed = state_rx.changed() => match changed {
                Ok(()) => Event { state: Some(*state_rx.borrow_and_update()), rates: None },
                Err(_) => break,
            },
            changed = stats_rx.changed() => match changed {
                Ok(()) => Event { state: None, rates: Some(*stats_rx.borrow_and_update()) },
                Err(_) => break,
            },
        };
        if write_line(&mut stream, &Response::Event(evt))
            .await
            .is_err()
        {
            break; // caller hung up
        }
    }
    Ok(())
}

async fn write_line(stream: &mut UnixStream, resp: &Response) -> std::io::Result<()> {
    let mut out = serde_json::to_string(resp)
        .unwrap_or_else(|_| "{\"resp\":\"err\",\"message\":\"serialize\"}".to_string());
    out.push('\n');
    stream.write_all(out.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Request, Response, StartParams};
    use crate::runner::test_support::FakeRunner;
    use leshiy_client::State;
    use leshiy_client::settings::TransportPref;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    async fn line(sock: &std::path::Path, req: &Request) -> String {
        let mut s = tokio::net::UnixStream::connect(sock).await.unwrap();
        let mut payload = serde_json::to_string(req).unwrap();
        payload.push('\n');
        s.write_all(payload.as_bytes()).await.unwrap();
        let mut r = BufReader::new(s);
        let mut out = String::new();
        r.read_line(&mut out).await.unwrap();
        out
    }

    fn params() -> StartParams {
        StartParams {
            uri: "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000".into(),
            transport: TransportPref::Tcp,
            mtu: 1400,
            tun_name: "leshiy0".into(),
            dns: "1.1.1.1".into(),
        }
    }

    async fn spawn(allow_uid: u32) -> (std::path::PathBuf, Arc<FakeRunner>) {
        let dir = std::env::temp_dir().join(format!("leshiy-helper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join(format!("h-{}.sock", uuid_like()));
        let runner = Arc::new(FakeRunner::new());
        let r2 = runner.clone();
        let path = sock.clone();
        tokio::spawn(async move {
            let _ = serve_control(&path, r2, allow_uid).await;
        });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        (sock, runner)
    }

    fn uuid_like() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn me() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    #[tokio::test]
    async fn start_status_stop_roundtrip_for_allowed_uid() {
        let (sock, runner) = spawn(me()).await;

        let resp = line(&sock, &Request::StartVpn(params())).await;
        let r: Response = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(r, Response::Ok);
        assert_eq!(runner.started.lock().unwrap().len(), 1);

        let resp = line(&sock, &Request::GetStatus).await;
        let r: Response = serde_json::from_str(resp.trim()).unwrap();
        match r {
            Response::Status { status } => assert_eq!(status.state, State::Connected),
            other => panic!("expected Status, got {other:?}"),
        }

        let resp = line(&sock, &Request::Stop).await;
        assert_eq!(
            serde_json::from_str::<Response>(resp.trim()).unwrap(),
            Response::Ok
        );
    }

    #[tokio::test]
    async fn unauthorized_uid_gets_no_reply() {
        // Tell the server to allow a uid that is NOT ours; our connection must be closed
        // with zero bytes (silent rejection — no oracle).
        let (sock, _runner) = spawn(me().wrapping_add(1)).await;
        let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let mut payload = serde_json::to_string(&Request::GetStatus).unwrap();
        payload.push('\n');
        let _ = s.write_all(payload.as_bytes()).await;
        let mut r = BufReader::new(s);
        let mut out = String::new();
        // Silent rejection: the peer receives NO Response line. The server rejects on
        // peercred before reading, so closing with our unread request still buffered makes
        // Linux signal an RST (ConnectionReset) rather than a clean FIN (0 bytes). Both mean
        // "no oracle" — assert no Response bytes arrived, accepting either signal.
        match r.read_line(&mut out).await {
            Ok(n) => assert_eq!(n, 0, "rejected peer must get an empty (closed) response"),
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset,
                "only a reset is acceptable; got {e:?}"
            ),
        }
        assert!(
            out.is_empty(),
            "a rejected peer must receive no Response bytes"
        );
    }

    #[tokio::test]
    async fn subscribe_streams_state_events() {
        let (sock, runner) = spawn(me()).await;
        let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let mut payload = serde_json::to_string(&Request::Subscribe).unwrap();
        payload.push('\n');
        s.write_all(payload.as_bytes()).await.unwrap();
        let mut r = BufReader::new(s);

        // First frame: the initial snapshot (Disconnected).
        let mut first = String::new();
        r.read_line(&mut first).await.unwrap();
        let f: Response = serde_json::from_str(first.trim()).unwrap();
        assert!(matches!(f, Response::Event(_)));

        // Drive a state change; expect a pushed Event carrying Connected.
        let _ = runner.state_tx.send(State::Connected);
        let mut next = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(2), r.read_line(&mut next))
            .await
            .expect("event within 2s")
            .unwrap();
        match serde_json::from_str::<Response>(next.trim()).unwrap() {
            Response::Event(e) => assert_eq!(e.state, Some(State::Connected)),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_line_returns_err_not_panic() {
        let (sock, _runner) = spawn(me()).await;
        let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
        s.write_all(b"{not json}\n").await.unwrap();
        let mut r = BufReader::new(s);
        let mut out = String::new();
        r.read_line(&mut out).await.unwrap();
        match serde_json::from_str::<Response>(out.trim()).unwrap() {
            Response::Err { .. } => {}
            other => panic!("expected Err, got {other:?}"),
        }
    }
}
