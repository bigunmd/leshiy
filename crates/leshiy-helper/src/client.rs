//! `HelperClient`: the caller-side API for the helper's control channel, shared by the CLI
//! (`leshiy vpn`) and the desktop GUI. Transport-agnostic newline-JSON — it connects over the
//! per-OS [`crate::transport`] (Unix socket / Windows named pipe) and frames requests
//! generically.
//!
//! One-shot calls (`start_vpn`/`stop`/`get_status`) open a fresh connection and read one reply
//! line; `subscribe` keeps a connection open in a background task and forwards `Event`s.
use crate::error::HelperError;
use crate::proto::{Event, Request, Response, StartParams, Status};
use crate::transport::Endpoint;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// A handle to a `leshiy-helper`'s control channel. Cheap to clone (holds only the endpoint).
#[derive(Clone)]
pub struct HelperClient {
    endpoint: Endpoint,
}

impl HelperClient {
    /// Bind a client to a control endpoint. No connection is opened until a call.
    pub fn connect(endpoint: Endpoint) -> Self {
        HelperClient { endpoint }
    }

    /// Convenience: bind from a path (Unix socket) / pipe-name string (Windows).
    pub fn connect_path(p: impl AsRef<Path>) -> Self {
        #[cfg(unix)]
        {
            HelperClient {
                endpoint: Endpoint::Socket(p.as_ref().to_path_buf()),
            }
        }
        #[cfg(windows)]
        {
            HelperClient {
                endpoint: Endpoint::Pipe(p.as_ref().to_string_lossy().into_owned()),
            }
        }
    }

    /// Start a full-tunnel VPN. Returns once the helper acknowledges (engine task spawned).
    pub async fn start_vpn(&self, params: StartParams) -> Result<(), HelperError> {
        match self.request(&Request::StartVpn(params)).await? {
            Response::Ok => Ok(()),
            Response::Err { message } => Err(HelperError::Engine(message)),
            other => Err(HelperError::BadRequest(format!(
                "unexpected reply: {other:?}"
            ))),
        }
    }

    /// Tear down the active session (idempotent on the helper side).
    pub async fn stop(&self) -> Result<(), HelperError> {
        match self.request(&Request::Stop).await? {
            Response::Ok => Ok(()),
            Response::Err { message } => Err(HelperError::Engine(message)),
            other => Err(HelperError::BadRequest(format!(
                "unexpected reply: {other:?}"
            ))),
        }
    }

    /// Fetch a one-shot status snapshot.
    pub async fn get_status(&self) -> Result<Status, HelperError> {
        match self.request(&Request::GetStatus).await? {
            Response::Status { status } => Ok(status),
            Response::Err { message } => Err(HelperError::Engine(message)),
            other => Err(HelperError::BadRequest(format!(
                "unexpected reply: {other:?}"
            ))),
        }
    }

    /// Subscribe to state/stats events. The first event is a snapshot; the stream ends when
    /// the helper closes the connection or the receiver is dropped.
    pub async fn subscribe(&self) -> Result<mpsc::Receiver<Event>, HelperError> {
        match &self.endpoint {
            #[cfg(unix)]
            Endpoint::Socket(p) => subscribe_over(crate::transport::unix::connect(p).await?).await,
            #[cfg(windows)]
            Endpoint::Pipe(name) => {
                subscribe_over(crate::transport::windows::connect(name).await?).await
            }
        }
    }

    /// Send one request and read one reply, over a freshly opened connection.
    async fn request(&self, req: &Request) -> Result<Response, HelperError> {
        match &self.endpoint {
            #[cfg(unix)]
            Endpoint::Socket(p) => {
                request_over(crate::transport::unix::connect(p).await?, req).await
            }
            #[cfg(windows)]
            Endpoint::Pipe(name) => {
                request_over(crate::transport::windows::connect(name).await?, req).await
            }
        }
    }
}

/// Framing for a one-shot request/reply over any stream.
async fn request_over<S>(mut stream: S, req: &Request) -> Result<Response, HelperError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload =
        serde_json::to_string(req).map_err(|e| HelperError::BadRequest(e.to_string()))?;
    payload.push('\n');
    stream.write_all(payload.as_bytes()).await?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    match reader.read_line(&mut line).await {
        // Empty reply = silent rejection (unauthorized) or a cleanly closed channel.
        Ok(0) => return Err(HelperError::Unauthorized),
        Ok(_) => {}
        // A reset is how the OS signals a server that closed our unread request without
        // replying — i.e. the same silent rejection, surfaced as RST instead of EOF.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
            return Err(HelperError::Unauthorized);
        }
        Err(e) => return Err(e.into()),
    }
    serde_json::from_str(line.trim()).map_err(|e| HelperError::BadRequest(e.to_string()))
}

/// Send `Subscribe` then forward streamed `Event`s over an mpsc channel.
async fn subscribe_over<S>(mut stream: S) -> Result<mpsc::Receiver<Event>, HelperError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut payload = serde_json::to_string(&Request::Subscribe)
        .map_err(|e| HelperError::BadRequest(e.to_string()))?;
    payload.push('\n');
    stream.write_all(payload.as_bytes()).await?;

    let (tx, rx) = mpsc::channel::<Event>(64);
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // helper closed
                Ok(_) => {
                    if let Ok(Response::Event(evt)) = serde_json::from_str::<Response>(line.trim())
                        && tx.send(evt).await.is_err()
                    {
                        break; // receiver dropped
                    }
                }
                Err(_) => break,
            }
        }
    });
    Ok(rx)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::runner::test_support::FakeRunner;
    use crate::server::{Auth, ServeMode, serve_control};
    use crate::transport::Endpoint;
    use leshiy_client::State;
    use leshiy_client::settings::TransportPref;
    use std::sync::Arc;

    async fn spawn() -> (Endpoint, Arc<FakeRunner>) {
        let dir = std::env::temp_dir().join(format!("leshiy-hc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join(format!(
            "c-{}.sock",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runner = Arc::new(FakeRunner::new());
        let r2 = runner.clone();
        let ep = Endpoint::Socket(sock.clone());
        let ep2 = ep.clone();
        let me = nix::unistd::getuid().as_raw();
        tokio::spawn(async move {
            let _ =
                serve_control(&ep2, r2, Auth { uid: me, sid: None }, ServeMode::Persistent).await;
        });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        (ep, runner)
    }

    fn params() -> StartParams {
        StartParams {
            uri: "leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000".into(),
            transport: TransportPref::Tcp,
            mtu: 1400,
            tun_name: "leshiy0".into(),
            dns: "1.1.1.1".into(),
            split_tunnel: Default::default(),
        }
    }

    #[tokio::test]
    async fn start_get_status_stop() {
        let (ep, _runner) = spawn().await;
        let client = HelperClient::connect(ep);
        client.start_vpn(params()).await.unwrap();
        let status = client.get_status().await.unwrap();
        assert_eq!(status.state, State::Connected);
        client.stop().await.unwrap();
    }

    #[tokio::test]
    async fn subscribe_yields_events() {
        let (ep, runner) = spawn().await;
        let client = HelperClient::connect(ep);
        let mut events = client.subscribe().await.unwrap();
        let first = events.recv().await.expect("snapshot");
        assert!(first.state.is_some());
        let _ = runner.state_tx.send(State::Connected);
        loop {
            let e = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
                .await
                .expect("event within 2s")
                .expect("channel open");
            if e.state == Some(State::Connected) {
                break;
            }
        }
    }
}
