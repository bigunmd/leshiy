//! `HelperClient`: the caller-side API for the helper's control socket, shared by the
//! CLI (`leshiy vpn`) and the Phase 5 desktop GUI. Transport-agnostic newline-JSON.
//!
//! One-shot calls (`start_vpn`/`stop`/`get_status`) open a fresh connection and read one
//! reply line (matching the server's one-line-per-connection model). `subscribe` holds a
//! connection open in a background task and forwards `Event`s over an mpsc channel.
use crate::error::HelperError;
use crate::proto::{Event, Request, Response, StartParams, Status};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

/// A handle to a running `leshiy-helper`'s control socket.
#[derive(Clone)]
pub struct HelperClient {
    socket_path: PathBuf,
}

impl HelperClient {
    /// Bind a client to the helper's socket path. No connection is opened until a call.
    pub fn connect(socket_path: impl AsRef<Path>) -> Self {
        HelperClient {
            socket_path: socket_path.as_ref().to_path_buf(),
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

    /// Subscribe to state/stats events. Returns a receiver that yields `Event`s until the
    /// helper closes the stream or the caller drops the receiver. The first event is a
    /// snapshot of the current state/stats.
    pub async fn subscribe(&self) -> Result<mpsc::Receiver<Event>, HelperError> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
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
                        if let Ok(Response::Event(evt)) =
                            serde_json::from_str::<Response>(line.trim())
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

    /// Send one request, read one reply line, parse it.
    async fn request(&self, req: &Request) -> Result<Response, HelperError> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let mut payload =
            serde_json::to_string(req).map_err(|e| HelperError::BadRequest(e.to_string()))?;
        payload.push('\n');
        stream.write_all(payload.as_bytes()).await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            // Empty reply = silent rejection (unauthorized) or a cleanly closed socket.
            Ok(0) => return Err(HelperError::Unauthorized),
            Ok(_) => {}
            // A reset is how Linux signals a server that closed our unread request without
            // replying — i.e. the same silent rejection, surfaced as RST instead of EOF.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                return Err(HelperError::Unauthorized);
            }
            Err(e) => return Err(e.into()),
        }
        serde_json::from_str(line.trim()).map_err(|e| HelperError::BadRequest(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::test_support::FakeRunner;
    use crate::serve_control;
    use leshiy_client::State;
    use leshiy_client::settings::TransportPref;
    use std::sync::Arc;

    async fn spawn() -> (std::path::PathBuf, Arc<FakeRunner>) {
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
        let path = sock.clone();
        let me = nix::unistd::getuid().as_raw();
        tokio::spawn(async move {
            let _ = serve_control(&path, r2, me).await;
        });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        (sock, runner)
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

    #[tokio::test]
    async fn start_get_status_stop() {
        let (sock, _runner) = spawn().await;
        let client = HelperClient::connect(&sock);
        client.start_vpn(params()).await.unwrap();
        let status = client.get_status().await.unwrap();
        assert_eq!(status.state, State::Connected);
        client.stop().await.unwrap();
    }

    #[tokio::test]
    async fn subscribe_yields_events() {
        let (sock, runner) = spawn().await;
        let client = HelperClient::connect(&sock);
        let mut events = client.subscribe().await.unwrap();
        // First frame = snapshot.
        let first = events.recv().await.expect("snapshot");
        assert!(first.state.is_some());
        // Drive a change and observe the push.
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
