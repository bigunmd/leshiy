use async_trait::async_trait;
use leshiy_client::error::{ClientError, Result};
use leshiy_client::stream::{DatagramFlow, ProxyStream};
use leshiy_client::transport::{Transport, Tunnel};
use leshiy_client::{
    NoopProxy, State, SupervisorConfig, SupervisorHandle, TransportPref, spawn_supervisor,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

struct TestTunnel;
#[async_trait]
impl Tunnel for TestTunnel {
    async fn open(&self, _: &str) -> Result<Box<dyn ProxyStream>> {
        Err(ClientError::ConnectFailed)
    }
    async fn open_datagram(&self, _: &str) -> Result<Box<dyn DatagramFlow>> {
        Err(ClientError::ConnectFailed)
    }
    async fn closed(&self) {
        std::future::pending::<()>().await
    }
}
#[derive(Clone, Default)]
struct RecordingProxy {
    calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    fail_set: bool,
    fail_clear: bool,
}
impl leshiy_client::sysproxy::SystemProxy for RecordingProxy {
    fn set(&self, _: std::net::SocketAddr) -> Result<()> {
        self.calls.lock().unwrap().push("set");
        if self.fail_set {
            Err(ClientError::ConnectFailed)
        } else {
            Ok(())
        }
    }
    fn clear(&self) -> Result<()> {
        self.calls.lock().unwrap().push("clear");
        if self.fail_clear {
            Err(ClientError::ConnectFailed)
        } else {
            Ok(())
        }
    }
}
struct GatedTransport(mpsc::UnboundedSender<oneshot::Sender<Result<Box<dyn Tunnel>>>>);
#[async_trait]
impl Transport for GatedTransport {
    async fn dial(&self, _: &str, _: TransportPref) -> Result<Box<dyn Tunnel>> {
        let (tx, rx) = oneshot::channel();
        self.0.send(tx).unwrap();
        rx.await.unwrap()
    }
}
async fn state(handle: &SupervisorHandle, expected: State) {
    let mut rx = handle.subscribe_state();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if *rx.borrow_and_update() == expected {
                break;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .expect("expected supervisor state");
}
fn config() -> SupervisorConfig {
    SupervisorConfig {
        socks_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    }
}
#[tokio::test]
async fn occupied_port_is_error_without_setting_proxy() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let proxy = RecordingProxy::default();
    let calls = proxy.calls.clone();
    let handle = spawn_supervisor(
        GatedTransport(tx),
        proxy,
        SupervisorConfig {
            socks_addr: occupied.local_addr().unwrap(),
            ..config()
        },
    );
    handle.connect("A".into());
    let _ = rx.recv().await.unwrap().send(Ok(Box::new(TestTunnel)));
    state(&handle, State::Error).await;
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn proxy_set_failure_rolls_back_listener_and_reports_error() {
    let proxy = RecordingProxy {
        fail_set: true,
        ..Default::default()
    };
    let calls = proxy.calls.clone();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handle = spawn_supervisor(GatedTransport(tx), proxy, config());
    handle.connect("A".into());
    let _ = rx.recv().await.unwrap().send(Ok(Box::new(TestTunnel)));
    state(&handle, State::Error).await;
    assert_eq!(*calls.lock().unwrap(), vec!["set", "clear"]);
}

#[tokio::test]
async fn proxy_clear_failure_reports_error_instead_of_disconnected() {
    let proxy = RecordingProxy {
        fail_clear: true,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handle = spawn_supervisor(GatedTransport(tx), proxy, config());
    handle.connect("A".into());
    let _ = rx.recv().await.unwrap().send(Ok(Box::new(TestTunnel)));
    state(&handle, State::Connected).await;
    handle.disconnect();
    state(&handle, State::Error).await;
    handle.disconnect();
    tokio::task::yield_now().await;
    assert_eq!(handle.state(), State::Error);
}

#[tokio::test]
async fn abort_listener_closes_accepted_handshakes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(leshiy_client::serve_metered_on(
        Arc::new(TestTunnel),
        listener,
        Arc::new(leshiy_client::ByteCounters::new()),
    ));
    let mut cli = tokio::net::TcpStream::connect(addr).await.unwrap();
    cli.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    cli.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    task.abort();
    let _ = task.await;
    let closed = tokio::time::timeout(Duration::from_millis(200), cli.read(&mut reply)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "accepted session must close with listener"
    );
}

#[tokio::test]
async fn stale_dial_cannot_complete_new_connection() {
    stale_dial(false).await;
    stale_dial(true).await;
}

async fn stale_dial(fail: bool) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handle = spawn_supervisor(GatedTransport(tx), NoopProxy, config());
    handle.connect("A".into());
    let a = rx.recv().await.unwrap();
    handle.disconnect();
    state(&handle, State::Disconnected).await;
    handle.connect("B".into());
    let b = rx.recv().await.unwrap();
    let _ = a.send(if fail {
        Err(ClientError::ConnectFailed)
    } else {
        Ok(Box::new(TestTunnel))
    });
    // If A is still accepted, it publishes Connected while B is unresolved.
    let mut states = handle.subscribe_state();
    states.borrow_and_update();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), states.changed())
            .await
            .is_err()
    );
    assert_eq!(handle.state(), State::Connecting);
    let _ = b.send(Ok(Box::new(TestTunnel)));
    state(&handle, State::Connected).await;
    handle.disconnect();
    state(&handle, State::Disconnected).await;
}
