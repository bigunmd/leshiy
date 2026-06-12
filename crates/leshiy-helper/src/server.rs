//! Authenticated control server. The newline-JSON framing + dispatch are generic over the
//! stream type (`handle_stream`/`subscribe_loop`/`write_line`), so the same logic serves a
//! Unix domain socket (Linux+macOS) and a Windows named pipe. Listening + per-connection
//! authorization live in `crate::transport`.
use crate::proto::{Event, Request, Response, Status};
use crate::runner::VpnRunner;
use crate::transport::Endpoint;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Maximum bytes accepted per request line (same cap rationale as `control.rs`): a peer
/// streaming bytes with no newline hits the cap and yields a parse error, not OOM.
const MAX_LINE: u64 = 64 * 1024;

/// Who is permitted to drive the helper. Unix uses `uid`; Windows uses `sid`. The field for
/// the other OS is simply ignored, so the struct is constructible on every platform.
#[derive(Debug, Clone, Default)]
pub struct Auth {
    /// Unix: the peer uid allowed to connect (`SO_PEERCRED`/`getpeereid`).
    pub uid: u32,
    /// Windows: the user SID allowed to connect (named-pipe DACL).
    pub sid: Option<String>,
}

/// Whether the server keeps serving (a persistent daemon, e.g. Linux systemd) or exits after
/// one session completes (the on-demand GUI model on macOS/Windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeMode {
    Persistent,
    Ephemeral,
}

/// Serve the control channel at `endpoint`, authorizing the caller per OS, until the listener
/// errors (`Persistent`) or one VPN session completes (`Ephemeral`).
pub async fn serve_control(
    endpoint: &Endpoint,
    runner: Arc<dyn VpnRunner>,
    allow: Auth,
    mode: ServeMode,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let Endpoint::Socket(path) = endpoint;
        let listener = crate::transport::unix::bind(path, allow.uid)?;
        let mut ever_connected = false;
        loop {
            let Some(conn) = crate::transport::unix::accept(&listener, allow.uid).await? else {
                continue; // unauthorized peer: dropped silently
            };
            match mode {
                ServeMode::Persistent => {
                    let runner = runner.clone();
                    tokio::spawn(async move {
                        let _ = handle_stream(conn, runner).await;
                    });
                }
                ServeMode::Ephemeral => {
                    handle_stream(conn, runner.clone()).await?;
                    if session_ended(runner.as_ref(), &mut ever_connected) {
                        return Ok(());
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        crate::transport::windows::serve(endpoint, runner, allow, mode).await
    }
}

/// Ephemeral exit decision: once we've seen the session go active, exit when it returns to
/// `Disconnected` (the caller sent `Stop`, or the engine exited). Updates `ever_connected`.
/// Used by the Unix accept loop now, and the Windows named-pipe loop once Phase B re-enables
/// it (the Windows `serve` currently fails closed, so it's Unix-only in the interim).
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn session_ended(runner: &dyn VpnRunner, ever_connected: &mut bool) -> bool {
    use crate::State;
    match runner.state() {
        State::Connecting | State::Connected | State::Reconnecting => {
            *ever_connected = true;
            false
        }
        State::Disconnected | State::Error => *ever_connected,
    }
}

/// Handle one request line on an already-authorized stream. Mirrors the one-line-per-
/// connection model; `Subscribe` keeps the stream and streams events until it closes.
pub async fn handle_stream<S>(stream: S, runner: Arc<dyn VpnRunner>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut r = BufReader::new(stream.take(MAX_LINE));
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        return Ok(());
    }
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
    dispatch(&mut stream, req, runner).await
}

async fn dispatch<S>(
    stream: &mut S,
    req: Request,
    runner: Arc<dyn VpnRunner>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match req {
        Request::StartVpn(params) => {
            let resp = match runner.start(&params).await {
                Ok(()) => Response::Ok,
                Err(e) => Response::Err {
                    message: e.to_string(),
                },
            };
            write_line(stream, &resp).await
        }
        Request::Stop => {
            runner.stop().await;
            write_line(stream, &Response::Ok).await
        }
        Request::GetStatus => {
            let status = Status {
                state: runner.state(),
                rates: *runner.subscribe_stats().borrow(),
            };
            write_line(stream, &Response::Status { status }).await
        }
        Request::Subscribe => subscribe_loop(stream, runner).await,
    }
}

async fn subscribe_loop<S>(stream: &mut S, runner: Arc<dyn VpnRunner>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut state_rx = runner.subscribe_state();
    let mut stats_rx = runner.subscribe_stats();
    // Copy values out of their watch::Ref guards before awaiting (the guards are !Send).
    let snapshot = Event {
        state: Some(*state_rx.borrow_and_update()),
        rates: Some(*stats_rx.borrow_and_update()),
    };
    write_line(stream, &Response::Event(snapshot)).await?;
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
        if write_line(stream, &Response::Event(evt)).await.is_err() {
            break; // caller hung up
        }
    }
    Ok(())
}

async fn write_line<S>(stream: &mut S, resp: &Response) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = serde_json::to_string(resp)
        .unwrap_or_else(|_| "{\"resp\":\"err\",\"message\":\"serialize\"}".to_string());
    out.push('\n');
    stream.write_all(out.as_bytes()).await
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::proto::{Request, Response, StartParams};
    use crate::runner::test_support::FakeRunner;
    use crate::transport::Endpoint;
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
            let _ = serve_control(
                &Endpoint::Socket(path),
                r2,
                Auth {
                    uid: allow_uid,
                    sid: None,
                },
                ServeMode::Persistent,
            )
            .await;
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
        assert_eq!(
            serde_json::from_str::<Response>(resp.trim()).unwrap(),
            Response::Ok
        );
        assert_eq!(runner.started.lock().unwrap().len(), 1);

        let resp = line(&sock, &Request::GetStatus).await;
        match serde_json::from_str::<Response>(resp.trim()).unwrap() {
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
        let (sock, _runner) = spawn(me().wrapping_add(1)).await;
        let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let mut payload = serde_json::to_string(&Request::GetStatus).unwrap();
        payload.push('\n');
        let _ = s.write_all(payload.as_bytes()).await;
        let mut r = BufReader::new(s);
        let mut out = String::new();
        match r.read_line(&mut out).await {
            Ok(n) => assert_eq!(n, 0, "rejected peer must get an empty (closed) response"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
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

        let mut first = String::new();
        r.read_line(&mut first).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(first.trim()).unwrap(),
            Response::Event(_)
        ));

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
