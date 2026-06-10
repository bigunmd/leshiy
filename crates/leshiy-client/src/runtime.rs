//! Async supervisor shell: drives the pure `supervisor::Machine` against a real
//! `Transport` + `SystemProxy` + the metered SOCKS5 listener, exposing connection
//! state and live throughput to the UI over `watch` channels.
use crate::listener::serve_metered;
use crate::settings::TransportPref;
use crate::stats::{ByteCounters, Rates, Throughput};
use crate::supervisor::{Action, Input, Machine, State};
use crate::sysproxy::SystemProxy;
use crate::transport::{Transport, Tunnel};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

const STATS_PERIOD: Duration = Duration::from_secs(1);

/// Runtime configuration for the supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub socks_addr: SocketAddr,
    pub pref: TransportPref,
    pub kill_switch: bool,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            socks_addr: "127.0.0.1:1080".parse().unwrap(),
            pref: TransportPref::Auto,
            kill_switch: true,
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
        }
    }
}

enum Command {
    Connect { uri: String },
    Disconnect,
}

/// Handle to a running supervisor: send commands, observe state + throughput.
#[derive(Clone)]
pub struct SupervisorHandle {
    cmd_tx: mpsc::Sender<Command>,
    state_rx: watch::Receiver<State>,
    stats_rx: watch::Receiver<Rates>,
}

impl SupervisorHandle {
    /// Request connecting the given `leshiy://` profile URI.
    pub fn connect(&self, uri: String) {
        let _ = self.cmd_tx.try_send(Command::Connect { uri });
    }
    /// Request disconnecting.
    pub fn disconnect(&self) {
        let _ = self.cmd_tx.try_send(Command::Disconnect);
    }
    /// The current observable state.
    pub fn state(&self) -> State {
        *self.state_rx.borrow()
    }
    /// A receiver for state transitions.
    pub fn subscribe_state(&self) -> watch::Receiver<State> {
        self.state_rx.clone()
    }
    /// A receiver for throughput samples (~1 Hz).
    pub fn subscribe_stats(&self) -> watch::Receiver<Rates> {
        self.stats_rx.clone()
    }
}

/// Start a supervisor actor; returns a handle for control + observation.
pub fn spawn_supervisor<T, P>(transport: T, proxy: P, cfg: SupervisorConfig) -> SupervisorHandle
where
    T: Transport + 'static,
    P: SystemProxy + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(16);
    let (state_tx, state_rx) = watch::channel(State::Disconnected);
    let (stats_tx, stats_rx) = watch::channel(Rates {
        up_bps: 0,
        down_bps: 0,
        total_up: 0,
        total_down: 0,
    });
    let (dial_tx, dial_rx) = mpsc::channel(1);
    let (backoff_tx, backoff_rx) = mpsc::channel(8);
    let (dropped_tx, dropped_rx) = mpsc::channel(8);

    let inner = Inner {
        machine: Machine::new(cfg.kill_switch, cfg.backoff_base, cfg.backoff_max),
        transport: Arc::new(transport),
        proxy,
        socks_addr: cfg.socks_addr,
        pref: cfg.pref,
        current_uri: String::new(),
        current: None,
        counters: Arc::new(ByteCounters::new()),
        throughput: Throughput::new(),
        listener: None,
        closed_monitor: None,
        dial_tx,
        backoff_tx,
        dropped_tx,
        state_tx,
        stats_tx,
    };

    tokio::spawn(run(inner, cmd_rx, dial_rx, backoff_rx, dropped_rx));
    SupervisorHandle {
        cmd_tx,
        state_rx,
        stats_rx,
    }
}

type DialResult = std::result::Result<Box<dyn Tunnel>, ()>;

struct Inner<T, P> {
    machine: Machine,
    transport: Arc<T>,
    proxy: P,
    socks_addr: SocketAddr,
    pref: TransportPref,
    current_uri: String,
    current: Option<Arc<dyn Tunnel>>,
    counters: Arc<ByteCounters>,
    throughput: Throughput,
    listener: Option<JoinHandle<crate::error::Result<()>>>,
    closed_monitor: Option<JoinHandle<()>>,
    dial_tx: mpsc::Sender<DialResult>,
    backoff_tx: mpsc::Sender<()>,
    dropped_tx: mpsc::Sender<()>,
    state_tx: watch::Sender<State>,
    stats_tx: watch::Sender<Rates>,
}

impl<T: Transport + 'static, P: SystemProxy + 'static> Inner<T, P> {
    fn feed(&mut self, input: Input) {
        let actions = self.machine.handle(input);
        self.apply(actions);
    }

    fn apply(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Dial => {
                    let transport = self.transport.clone();
                    let uri = self.current_uri.clone();
                    let pref = self.pref;
                    let tx = self.dial_tx.clone();
                    tokio::spawn(async move {
                        let res = transport.dial(&uri, pref).await.map_err(|_| ());
                        let _ = tx.send(res).await;
                    });
                }
                Action::SetProxy => {
                    let _ = self.proxy.set(self.socks_addr);
                }
                Action::ClearProxy => {
                    let _ = self.proxy.clear();
                }
                Action::StartServing => {
                    if let Some(tunnel) = self.current.clone() {
                        self.counters = Arc::new(ByteCounters::new());
                        self.throughput = Throughput::new();
                        self.listener = Some(tokio::spawn(serve_metered(
                            tunnel.clone(),
                            self.socks_addr,
                            self.counters.clone(),
                        )));
                        let dropped_tx = self.dropped_tx.clone();
                        let watched = tunnel.clone();
                        self.closed_monitor = Some(tokio::spawn(async move {
                            watched.closed().await;
                            let _ = dropped_tx.send(()).await;
                        }));
                    }
                }
                Action::StopServing => {
                    if let Some(h) = self.listener.take() {
                        h.abort();
                    }
                    if let Some(h) = self.closed_monitor.take() {
                        h.abort();
                    }
                    self.current = None;
                }
                Action::ScheduleBackoff(d) => {
                    let tx = self.backoff_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(d).await;
                        let _ = tx.send(()).await;
                    });
                }
                Action::Emit(state) => {
                    let _ = self.state_tx.send(state);
                }
            }
        }
    }

    fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::Connect { uri } => {
                self.current_uri = uri;
                self.feed(Input::Connect);
            }
            Command::Disconnect => self.feed(Input::Disconnect),
        }
    }

    fn on_dial_result(&mut self, res: DialResult) {
        match res {
            Ok(tunnel) => {
                self.current = Some(Arc::from(tunnel));
                self.feed(Input::DialSucceeded);
            }
            Err(()) => self.feed(Input::DialFailed),
        }
    }

    fn emit_stats(&mut self) {
        let (up, down) = self.counters.totals();
        let rates = self.throughput.sample(up, down, STATS_PERIOD);
        let _ = self.stats_tx.send(rates);
    }
}

async fn run<T: Transport + 'static, P: SystemProxy + 'static>(
    mut inner: Inner<T, P>,
    mut cmd_rx: mpsc::Receiver<Command>,
    mut dial_rx: mpsc::Receiver<DialResult>,
    mut backoff_rx: mpsc::Receiver<()>,
    mut dropped_rx: mpsc::Receiver<()>,
) {
    let mut stats = tokio::time::interval(STATS_PERIOD);
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(c) => inner.on_command(c),
                None => break,
            },
            Some(res) = dial_rx.recv() => inner.on_dial_result(res),
            Some(()) = backoff_rx.recv() => inner.feed(Input::BackoffElapsed),
            Some(()) = dropped_rx.recv() => inner.feed(Input::TunnelDropped),
            _ = stats.tick() => inner.emit_stats(),
        }
    }
}
