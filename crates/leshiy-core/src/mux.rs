//! Stream multiplexer over one Session. OPEN carries the target as UTF-8 in its payload.
use crate::error::{Error, Result};
use crate::frame::{Frame, FrameType, MAX_FRAME_PAYLOAD, base_type, is_critical};
use crate::transport::{FrameRead, FrameWrite};
use crate::version::{CAP_FLOWCONTROL, CAP_KEEPALIVE, Hello, Negotiated, negotiate};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Semaphore, mpsc, watch};

/// Upper bound on concurrently-open peer-initiated streams. A peer that exceeds
/// it is aborting the session via resource exhaustion, so we tear the session
/// down rather than grow the stream map without bound. (L3)
const MAX_CONCURRENT_PEER_STREAMS: usize = 1024;

/// Initial per-stream receive window granted to the peer (bytes): the sender may have at most this
/// many bytes in flight before a `WindowUpdate` credits more. Kept well under [`MAX_BUFFERED`] so a
/// compliant peer never trips the runaway guard, and comfortably above [`MAX_FRAME_PAYLOAD`] so a
/// single chunk always fits the window.
const INIT_WINDOW: usize = 256 * 1024;
/// Re-grant credit once the consumer has drained at least this much (half the window), so the
/// sender refills before stalling without flooding the link with `WindowUpdate`s.
const WINDOW_THRESHOLD: usize = INIT_WINDOW / 2;
/// Clamp a single `WindowUpdate`'s credit so a misbehaving peer can't overflow the send permits.
const MAX_CREDIT: usize = INIT_WINDOW;
/// Hard cap on bytes buffered for one stream awaiting its consumer. With flow control a compliant
/// peer stays under [`INIT_WINDOW`]; this is the safety net against a peer that ignores the window
/// (e.g. a pre-flow-control build) — that one stream is reset rather than letting the buffer grow
/// without bound or blocking the shared reader.
const MAX_BUFFERED: usize = 4 * 1024 * 1024;

/// Keepalive timing for a mux. Only takes effect once both peers advertise
/// [`CAP_KEEPALIVE`]; otherwise the mux behaves exactly as before (a blocking read
/// with no idle timeout).
#[derive(Clone, Copy, Debug)]
pub struct KeepaliveConfig {
    /// How often to send a `Ping` on an otherwise-idle tunnel.
    pub interval: Duration,
    /// If no frame of any kind arrives within this window, the link is presumed dead
    /// (silently blackholed — no FIN/RST) and the reader exits so `closed()` fires.
    /// Must be comfortably larger than `interval` (the peer echoes our pings, so a live
    /// idle tunnel still sees a frame every `interval`).
    pub idle_timeout: Duration,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        // 15s probe / 45s death = tolerate two lost probes before declaring the link
        // dead. Short enough that a censored/blackholed tunnel reconnects promptly,
        // long enough not to thrash on a merely slow path.
        Self {
            interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(45),
        }
    }
}

/// A cheap, lock-free read handle for a mux's last measured round-trip latency. Cloneable;
/// hand one to a stats poller so it can read latency without locking the mux.
#[derive(Clone, Default)]
pub struct RttHandle(Arc<AtomicU64>);

impl RttHandle {
    /// Last measured RTT in microseconds, or `None` if no ping has round-tripped yet.
    pub fn micros(&self) -> Option<u64> {
        let v = self.0.load(Ordering::Relaxed);
        (v > 0).then_some(v)
    }
}

/// Correlates keepalive `Ping`s with their echoed `Pong`s to derive round-trip latency.
/// `note_ping_sent` stamps the send time; `note_pong_recv` computes the elapsed RTT.
#[derive(Default)]
struct RttState {
    last_ping: Mutex<Option<Instant>>,
    micros: RttHandle,
}

impl RttState {
    fn note_ping_sent(&self) {
        *self.last_ping.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }
    fn note_pong_recv(&self) {
        if let Some(t) = self
            .last_ping
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            // Clamp to >=1µs so a sub-microsecond RTT still reads as "known".
            let us = t.elapsed().as_micros().max(1).min(u64::MAX as u128) as u64;
            self.micros.0.store(us, Ordering::Relaxed);
        }
    }
    fn handle(&self) -> RttHandle {
        self.micros.clone()
    }
}

/// Which side of the connection owns this mux.
/// Clients allocate odd stream ids; servers allocate even ids.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Whether a stream carries a reliable byte stream (TCP, `Data` frames) or
/// discrete datagrams (UDP, `Datagram` frames).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamKind {
    Tcp,
    Udp,
}

/// Internal commands sent from Stream/Mux to the writer task.
enum Command {
    /// Register a new outgoing stream and send an OPEN frame.
    Open(u32, String, StreamSink),
    /// Write an arbitrary frame (DATA, CLOSE, …).
    Write(Frame),
}

/// The receiver-side handle to a stream, stored in the shared [`Streams`] map. The reader pushes
/// inbound payloads into `data_tx` (unbounded, so a slow consumer never blocks the shared reader),
/// tracks queued bytes in `buffered`, and credits `send_window` when a `WindowUpdate` for this
/// stream arrives.
#[derive(Clone)]
struct StreamSink {
    data_tx: mpsc::UnboundedSender<Bytes>,
    buffered: Arc<AtomicUsize>,
    /// Our credit to *send* on this stream (bytes), or `None` when flow control isn't negotiated.
    send_window: Option<Arc<Semaphore>>,
}

impl StreamSink {
    /// Closing the send window wakes any sender blocked acquiring credit (it errors out) when the
    /// stream is torn down, so a blocked `Stream::send` can never hang after the peer closes.
    fn close(&self) {
        if let Some(sem) = &self.send_window {
            sem.close();
        }
    }
}

/// Build a `WindowUpdate` frame crediting `credit` bytes to `stream_id`.
fn window_update_frame(stream_id: u32, credit: u32) -> Frame {
    Frame {
        stream_id,
        ftype: FrameType::WindowUpdate as u8,
        payload: Bytes::copy_from_slice(&credit.to_be_bytes()),
    }
}

/// Create the receiver/sender halves of a new stream: an unbounded data channel (so the shared
/// reader never blocks delivering to it), a shared buffered-bytes counter, and — when flow control
/// is on — a send window seeded with [`INIT_WINDOW`] credit. `target` is the stream's display
/// target; the OPEN frame's wire payload is sent separately by the caller.
fn new_stream(
    id: u32,
    target: String,
    kind: StreamKind,
    cmd_tx: mpsc::Sender<Command>,
    flowcontrol: bool,
) -> (Stream, StreamSink) {
    let (data_tx, rx) = mpsc::unbounded_channel::<Bytes>();
    let buffered = Arc::new(AtomicUsize::new(0));
    let send_window = flowcontrol.then(|| Arc::new(Semaphore::new(INIT_WINDOW)));
    let sink = StreamSink {
        data_tx,
        buffered: buffered.clone(),
        send_window: send_window.clone(),
    };
    let stream = Stream {
        target,
        kind,
        id,
        tx: cmd_tx,
        rx,
        buffered,
        send_window,
        consumed: 0,
    };
    (stream, sink)
}

/// A logical stream inside a [`Mux`].
pub struct Stream {
    /// The target string carried in the OPEN frame, with any scheme prefix stripped.
    pub target: String,
    /// Whether this stream carries TCP byte-stream data or UDP datagrams.
    pub kind: StreamKind,
    id: u32,
    tx: mpsc::Sender<Command>,
    rx: mpsc::UnboundedReceiver<Bytes>,
    /// Bytes queued for this stream but not yet `recv`'d. Decremented on consume; shared with the
    /// reader, which increments it and enforces [`MAX_BUFFERED`].
    buffered: Arc<AtomicUsize>,
    /// Our send credit (flow control on), or `None`. Drained by `send`, refilled by inbound
    /// `WindowUpdate`s (applied by the reader).
    send_window: Option<Arc<Semaphore>>,
    /// Bytes consumed since the last `WindowUpdate` we emitted (flow control on).
    consumed: usize,
}

impl Stream {
    /// Send payload bytes. TCP streams chunk into `Data` frames; UDP streams send the
    /// whole datagram in one `Datagram` frame (oversized datagrams are rejected).
    ///
    /// Each plaintext frame = 5-byte header + payload. Cap the payload at
    /// [`MAX_FRAME_PAYLOAD`] so the sealed frame fits ONE TLS 1.3 record on the
    /// REALITY transport (the most size-restrictive path); larger frames are
    /// writable but unreadable there, deadlocking the stream.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        match self.kind {
            StreamKind::Tcp => {
                // Chunk via zero-copy `split_to` — each chunk is a refcounted slice
                // of `data`, not a fresh copy.
                let mut data = data;
                while !data.is_empty() {
                    let n = data.len().min(MAX_FRAME_PAYLOAD);
                    let chunk = data.split_to(n);
                    self.acquire_credit(n).await?;
                    self.tx
                        .send(Command::Write(Frame {
                            stream_id: self.id,
                            ftype: FrameType::Data as u8,
                            payload: chunk,
                        }))
                        .await
                        .map_err(|_| Error::Closed)?;
                }
                Ok(())
            }
            StreamKind::Udp => {
                // A datagram is one indivisible frame, so it must itself fit one record.
                if data.len() > MAX_FRAME_PAYLOAD {
                    return Err(Error::Protocol("datagram exceeds max frame payload".into()));
                }
                self.acquire_credit(data.len()).await?;
                self.tx
                    .send(Command::Write(Frame {
                        stream_id: self.id,
                        ftype: FrameType::Datagram as u8,
                        payload: data,
                    }))
                    .await
                    .map_err(|_| Error::Closed)
            }
        }
    }

    /// Block until we hold `n` bytes of send credit for this stream (flow control on), consuming
    /// them. No-op when flow control isn't negotiated. This is where backpressure propagates back
    /// to the data origin (the tun relay / SOCKS client) when the peer's consumer is slow — instead
    /// of the slow stream stalling the shared reader for everyone. A closed window (peer reset the
    /// stream / tunnel died) surfaces as [`Error::Closed`].
    async fn acquire_credit(&self, n: usize) -> Result<()> {
        if let Some(sem) = &self.send_window {
            sem.acquire_many(n as u32)
                .await
                .map_err(|_| Error::Closed)?
                .forget();
        }
        Ok(())
    }

    /// Receive the next payload chunk from the peer.
    pub async fn recv(&mut self) -> Result<Bytes> {
        let chunk = self.rx.recv().await.ok_or(Error::Closed)?;
        // Release the buffer this chunk occupied, and (flow control on) credit the peer once we've
        // drained at least half the window, so a fast, well-behaved transfer keeps flowing.
        self.buffered.fetch_sub(chunk.len(), Ordering::SeqCst);
        if self.send_window.is_some() {
            self.consumed += chunk.len();
            if self.consumed >= WINDOW_THRESHOLD {
                let credit = self.consumed.min(u32::MAX as usize) as u32;
                self.consumed = 0;
                // Best-effort: if the writer is gone the session is already dying.
                let _ = self
                    .tx
                    .send(Command::Write(window_update_frame(self.id, credit)))
                    .await;
            }
        }
        Ok(chunk)
    }

    /// Send a CLOSE frame and remove the stream from the registry.
    pub async fn close(&self) -> Result<()> {
        self.tx
            .send(Command::Write(Frame {
                stream_id: self.id,
                ftype: FrameType::Close as u8,
                payload: Bytes::new(),
            }))
            .await
            .map_err(|_| Error::Closed)
    }
}

/// Shared map of active streams: stream_id → receiver-side handle.
type Streams = Arc<Mutex<HashMap<u32, StreamSink>>>;

/// How often [`suspend_watchdog`] compares the wall clock against the last inbound frame. Bounds
/// how quickly a link that died while the device slept is noticed once the CPU wakes.
const WATCHDOG_POLL: Duration = Duration::from_secs(2);

/// Wall-clock milliseconds since the Unix epoch.
///
/// `SystemTime` is the only suspend-inclusive clock available here: `Instant` — and therefore
/// every `tokio::time` timer — is `CLOCK_MONOTONIC`, which stops while the device is suspended.
/// `CLOCK_BOOTTIME` would be the precise tool but needs `libc::clock_gettime`, and this crate is
/// `#![forbid(unsafe_code)]`.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Has more than `idle_timeout` of *wall-clock* time passed since the last inbound frame?
///
/// `saturating_sub` makes a backwards clock step (NTP correction, user setting the clock) report
/// zero elapsed rather than underflowing into a spurious "dead". A large *forward* step can
/// false-positive, which costs one reconnect — the safe direction to err in.
fn wall_clock_stale(last_millis: u64, now_millis: u64, idle_timeout: Duration) -> bool {
    Duration::from_millis(now_millis.saturating_sub(last_millis)) > idle_timeout
}

/// Force `closed()` once the wall clock shows the link has been silent past `idle_timeout`.
///
/// The reader's own `tokio::time::timeout` cannot cover this case, because it runs on
/// `CLOCK_MONOTONIC` and so does not advance while the device is suspended. A phone that sleeps
/// longer than the peer's idle timeout wakes to a session the peer tore down minutes or hours
/// ago, while its own timer's monotonic budget is nearly untouched — so the mux still reports
/// alive, `open()` cheerfully hands out streams on a dead socket, and apps see flows that hang
/// instead of failing. Comparing the wall clock closes that window: this task's `sleep` is
/// frozen by suspend too, which is exactly right — it fires on the first tick after wake.
///
/// Only meaningful with [`CAP_KEEPALIVE`] negotiated; without it a live-but-idle link legitimately
/// produces no frames and this would false-positive continuously.
///
/// The reader is left to notice the death on its own schedule and exit, so the socket and tasks
/// are still torn down exactly as before — this only makes `closed()`, and therefore the
/// supervisor's re-dial, prompt.
async fn suspend_watchdog(
    last_seen: Arc<AtomicU64>,
    streams: Streams,
    closed_tx: watch::Sender<bool>,
    idle_timeout: Duration,
    poll: Duration,
    now: impl Fn() -> u64 + Send + 'static,
) {
    let mut closed_rx = closed_tx.subscribe();
    loop {
        // Checked before the wait, not only via `changed()`: `subscribe()` marks the value
        // current at that moment as seen, so a session closed before this task was first polled
        // would never produce a `changed()` and this would spin forever.
        if *closed_rx.borrow_and_update() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            // Someone else (reader I/O error, writer death) tore the session down first.
            _ = closed_rx.changed() => return,
        }
        if wall_clock_stale(last_seen.load(Ordering::Relaxed), now(), idle_timeout) {
            tracing::warn!(
                "tunnel silent past the idle timeout in wall-clock terms (suspend?); declaring it dead"
            );
            close_all_streams(&streams);
            let _ = closed_tx.send(true);
            return;
        }
    }
}

/// Drain the stream map, closing every send window — wakes any sender blocked on credit (it
/// errors) and drops each `data_tx` so consumers see EOF. Called when a task tears the session
/// down, so no stream is left hanging.
fn close_all_streams(streams: &Streams) {
    let drained: Vec<StreamSink> = streams
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drain()
        .map(|(_, s)| s)
        .collect();
    for sink in drained {
        sink.close();
    }
}

/// Multiplexer: owns the background reader/writer tasks for one [`Session`].
pub struct Mux {
    cmd_tx: mpsc::Sender<Command>,
    incoming: mpsc::Receiver<Stream>,
    next_id: u32,
    pub negotiated: Negotiated,
    closed_rx: watch::Receiver<bool>,
    /// Whether per-stream flow control was negotiated; controls whether outgoing streams get a
    /// send window.
    flowcontrol: bool,
    /// Last keepalive round-trip latency (lock-free read handle).
    rtt: RttHandle,
}

impl Mux {
    /// Start the mux with the default keepalive timing ([`KeepaliveConfig::default`]).
    /// Keepalive only activates if the peer also advertises [`CAP_KEEPALIVE`]; otherwise
    /// this behaves exactly as a plain mux (blocking read, no idle timeout).
    pub async fn start<R, W>(reader: R, writer: W, local_hello: Hello, role: Role) -> Result<Mux>
    where
        R: FrameRead + Send + 'static,
        W: FrameWrite + Send + 'static,
    {
        Self::start_with_keepalive(
            reader,
            writer,
            local_hello,
            role,
            KeepaliveConfig::default(),
        )
        .await
    }

    /// Start the mux over a completed session:
    /// 1. Exchange HELLO frames (write own, then read peer's) — deadlock-free on
    ///    full-duplex because both sides write before reading.
    /// 2. Spawn a writer task and a reader task.
    /// 3. If [`CAP_KEEPALIVE`] is negotiated, run keepalive: the reader bounds each
    ///    read by `keepalive.idle_timeout` (a silent peer trips `closed()`), answers
    ///    `Ping` with `Pong`, and a sender task emits a `Ping` every `keepalive.interval`.
    pub async fn start_with_keepalive<R, W>(
        mut reader: R,
        mut writer: W,
        local_hello: Hello,
        role: Role,
        keepalive: KeepaliveConfig,
    ) -> Result<Mux>
    where
        R: FrameRead + Send + 'static,
        W: FrameWrite + Send + 'static,
    {
        // --- HELLO exchange (before spawning tasks) ---
        writer
            .write_frame(&Frame {
                stream_id: 0,
                ftype: FrameType::Hello as u8,
                payload: Bytes::from(local_hello.encode()),
            })
            .await?;

        let peer_frame = reader.read_frame().await?;
        if base_type(peer_frame.ftype) != FrameType::Hello as u8 {
            return Err(Error::Version("expected HELLO first".into()));
        }
        let negotiated = negotiate(&local_hello, &Hello::decode(&peer_frame.payload)?)?;

        // --- shared state ---
        let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(256);
        let (inc_tx, incoming) = mpsc::channel::<Stream>(32);
        let (closed_tx, closed_rx) = watch::channel(false);

        // --- writer task: drains cmd_rx, registers streams, sends frames ---
        {
            let w_streams = streams.clone();
            let w_closed = closed_tx.clone();
            tokio::spawn(async move {
                while let Some(cmd) = cmd_rx.recv().await {
                    match cmd {
                        Command::Open(id, target, sink) => {
                            w_streams
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(id, sink);
                            if writer
                                .write_frame(&Frame {
                                    stream_id: id,
                                    ftype: FrameType::Open as u8,
                                    payload: Bytes::from(target.into_bytes()),
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Command::Write(f) => {
                            if base_type(f.ftype) == FrameType::Close as u8
                                && let Some(sink) = w_streams
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .remove(&f.stream_id)
                            {
                                sink.close();
                            }
                            if writer.write_frame(&f).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                // The transport write side died: tear down every stream so no sender hangs.
                close_all_streams(&w_streams);
                let _ = w_closed.send(true);
            });
        }

        let keepalive_on = negotiated.capabilities & CAP_KEEPALIVE != 0;
        let flowcontrol_on = negotiated.capabilities & CAP_FLOWCONTROL != 0;

        // Correlates our keepalive Pings with the peer's echoed Pongs → round-trip latency.
        let rtt = Arc::new(RttState::default());
        let rtt_handle = rtt.handle();

        // Wall-clock stamp of the last inbound frame, for `suspend_watchdog`. Seeded at the
        // handshake, which is the last moment we know the link was alive.
        let last_seen = Arc::new(AtomicU64::new(now_millis()));

        // --- reader task: dispatches inbound frames to per-stream senders ---
        {
            let r_streams = streams.clone();
            let r_rtt = rtt.clone();
            let r_cmd_tx = cmd_tx.clone();
            let r_closed = closed_tx.clone();
            let r_last_seen = last_seen.clone();
            let idle_timeout = keepalive.idle_timeout;
            tokio::spawn(async move {
                loop {
                    // With keepalive negotiated, bound each read by the idle timeout: a
                    // silently blackholed link (no FIN/RST) delivers no frame, so the read
                    // never returns — the timeout fires, we exit, and `closed()` flips so
                    // the supervisor reconnects. Without keepalive, read as before (the peer
                    // won't echo our pings, so an idle timeout would false-positive).
                    let read = reader.read_frame();
                    let f = if keepalive_on {
                        match tokio::time::timeout(idle_timeout, read).await {
                            Ok(Ok(f)) => f,
                            Ok(Err(_)) | Err(_) => break, // I/O error OR idle timeout → dead
                        }
                    } else {
                        match read.await {
                            Ok(f) => f,
                            Err(_) => break,
                        }
                    };
                    // Any frame proves the link was alive just now. Stamped in wall-clock terms
                    // so `suspend_watchdog` can tell real silence from a frozen monotonic timer.
                    r_last_seen.store(now_millis(), Ordering::Relaxed);
                    let bt = base_type(f.ftype);
                    if bt == FrameType::Ping as u8 {
                        // Echo a Pong so the peer can confirm our liveness. Best-effort:
                        // if the writer is gone the session is already dying.
                        let _ = r_cmd_tx
                            .send(Command::Write(Frame {
                                stream_id: 0,
                                ftype: FrameType::Pong as u8,
                                payload: Bytes::new(),
                            }))
                            .await;
                        continue;
                    } else if bt == FrameType::Pong as u8 {
                        // Receipt already reset the idle timer above; record the round-trip.
                        r_rtt.note_pong_recv();
                        continue;
                    } else if bt == FrameType::Open as u8 {
                        // Parse the optional scheme prefix: `udp:` → datagram, `tcp:`/bare → stream.
                        let raw = String::from_utf8_lossy(&f.payload).into_owned();
                        let (kind, target) = match raw.strip_prefix("udp:") {
                            Some(rest) => (StreamKind::Udp, rest.to_string()),
                            None => (
                                StreamKind::Tcp,
                                raw.strip_prefix("tcp:")
                                    .map(|s| s.to_string())
                                    .unwrap_or(raw),
                            ),
                        };
                        let (stream, sink) =
                            new_stream(f.stream_id, target, kind, r_cmd_tx.clone(), flowcontrol_on);
                        {
                            let mut map = r_streams.lock().unwrap_or_else(|e| e.into_inner());
                            if map.len() >= MAX_CONCURRENT_PEER_STREAMS {
                                break; // peer opened too many concurrent streams → abort (L3)
                            }
                            map.insert(f.stream_id, sink);
                        }
                        if inc_tx.send(stream).await.is_err() {
                            break;
                        }
                    } else if bt == FrameType::Data as u8 || bt == FrameType::Datagram as u8 {
                        // DATA (stream) and DATAGRAM (one packet) both route to the per-stream
                        // channel. The channel is UNBOUNDED, so a slow consumer can never block the
                        // shared reader and head-of-line-block other streams; flow control bounds how
                        // much the peer may have in flight. Clone the sink out of the map first so we
                        // never hold the Mutex guard across an .await.
                        let sink = r_streams
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&f.stream_id)
                            .cloned();
                        if let Some(sink) = sink {
                            let n = f.payload.len();
                            let buffered = sink.buffered.fetch_add(n, Ordering::SeqCst) + n;
                            if buffered > MAX_BUFFERED {
                                // The peer is ignoring its window (or there is none): reset just this
                                // stream instead of buffering without bound or stalling the mux.
                                sink.buffered.fetch_sub(n, Ordering::SeqCst);
                                if let Some(sink) = r_streams
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .remove(&f.stream_id)
                                {
                                    sink.close();
                                }
                                let _ = r_cmd_tx
                                    .send(Command::Write(Frame {
                                        stream_id: f.stream_id,
                                        ftype: FrameType::Close as u8,
                                        payload: Bytes::new(),
                                    }))
                                    .await;
                            } else {
                                // Unbounded send: only fails if the consumer dropped its receiver.
                                let _ = sink.data_tx.send(f.payload);
                            }
                        }
                    } else if bt == FrameType::WindowUpdate as u8 {
                        // The peer drained `credit` bytes we sent: refill our send window for this
                        // stream so we may send more. Clamp to keep the semaphore from overflowing.
                        if f.payload.len() >= 4 {
                            let credit = u32::from_be_bytes([
                                f.payload[0],
                                f.payload[1],
                                f.payload[2],
                                f.payload[3],
                            ]) as usize;
                            if let Some(sink) = r_streams
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .get(&f.stream_id)
                                && let Some(sem) = &sink.send_window
                            {
                                sem.add_permits(credit.min(MAX_CREDIT));
                            }
                        }
                    } else if bt == FrameType::Close as u8 {
                        if let Some(sink) = r_streams
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&f.stream_id)
                        {
                            sink.close();
                        }
                    } else if is_critical(f.ftype) {
                        break; // unknown critical frame → abort session
                    }
                    // unknown non-critical frame → silently ignore (continue)
                }
                // The transport read side died: tear down every stream so no sender hangs.
                close_all_streams(&r_streams);
                let _ = r_closed.send(true);
            });
        }

        // --- keepalive sender task: emit a Ping every `interval` so an idle-but-live
        //     tunnel keeps producing frames (the peer echoes Pong), and stop as soon as
        //     the connection is observed closed. Only runs when the cap is negotiated. ---
        if keepalive_on {
            let ka_cmd_tx = cmd_tx.clone();
            let mut ka_closed = closed_rx.clone();
            let interval = keepalive.interval;
            let ka_rtt = rtt.clone();
            tokio::spawn(async move {
                loop {
                    if *ka_closed.borrow() {
                        break; // connection already closed
                    }
                    // Send a keepalive Ping (immediately on the first pass, so latency is known
                    // shortly after connect rather than only after `interval`) and stamp the
                    // send time; the peer echoes a Pong the reader task times.
                    ka_rtt.note_ping_sent();
                    if ka_cmd_tx
                        .send(Command::Write(Frame {
                            stream_id: 0,
                            ftype: FrameType::Ping as u8,
                            payload: Bytes::new(),
                        }))
                        .await
                        .is_err()
                    {
                        break; // writer gone
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {}
                        // The closed flag flipped (or the sender dropped) → re-check at the
                        // top of the loop and exit. `changed()` is Send (unlike `wait_for`).
                        changed = ka_closed.changed() => {
                            if changed.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        // --- suspend watchdog: the reader's idle timeout above runs on CLOCK_MONOTONIC, which
        //     stops while the device is suspended, so it cannot notice a link the peer timed out
        //     while we slept. Gated on the same cap as the reader's timeout, for the same reason:
        //     only with keepalive negotiated does a live link guarantee periodic frames. ---
        if keepalive_on {
            tokio::spawn(suspend_watchdog(
                last_seen,
                streams.clone(),
                closed_tx.clone(),
                keepalive.idle_timeout,
                WATCHDOG_POLL,
                now_millis,
            ));
        }

        let next_id = if role == Role::Client { 1 } else { 2 };
        Ok(Mux {
            cmd_tx,
            incoming,
            next_id,
            negotiated,
            closed_rx,
            flowcontrol: flowcontrol_on,
            rtt: rtt_handle,
        })
    }

    /// A lock-free handle to this mux's last keepalive round-trip latency.
    pub fn rtt_handle(&self) -> RttHandle {
        self.rtt.clone()
    }

    /// Last keepalive round-trip latency in microseconds, or `None` if not yet measured.
    pub fn rtt_micros(&self) -> Option<u64> {
        self.rtt.micros()
    }

    /// Open a new outgoing stream to `target`.
    /// Clients get odd ids, servers get even ids.
    pub async fn open(&mut self, target: &str) -> Result<Stream> {
        let id = self.next_id;
        self.next_id += 2;
        let (stream, sink) = new_stream(
            id,
            target.to_string(),
            StreamKind::Tcp,
            self.cmd_tx.clone(),
            self.flowcontrol,
        );
        self.cmd_tx
            .send(Command::Open(id, target.to_string(), sink))
            .await
            .map_err(|_| Error::Closed)?;
        Ok(stream)
    }

    /// Open a new outgoing UDP datagram association to `target` ("host:port").
    /// Requires the peer to have advertised `CAP_DATAGRAM` during negotiation.
    /// The OPEN frame carries the target with a `udp:` scheme prefix.
    pub async fn open_datagram(&mut self, target: &str) -> Result<Stream> {
        if self.negotiated.capabilities & crate::version::CAP_DATAGRAM == 0 {
            return Err(Error::Protocol("peer does not support CAP_DATAGRAM".into()));
        }
        let id = self.next_id;
        self.next_id += 2;
        let (stream, sink) = new_stream(
            id,
            target.to_string(),
            StreamKind::Udp,
            self.cmd_tx.clone(),
            self.flowcontrol,
        );
        self.cmd_tx
            .send(Command::Open(id, format!("udp:{target}"), sink))
            .await
            .map_err(|_| Error::Closed)?;
        Ok(stream)
    }

    /// Wait for the next inbound stream opened by the peer.
    pub async fn accept(&mut self) -> Result<Stream> {
        self.incoming.recv().await.ok_or(Error::Closed)
    }

    /// A receiver that flips to `true` once this mux's reader or writer task exits
    /// (the underlying connection dropped). Clients `select!`/`wait_for` on this to
    /// detect tunnel loss. The state latches, so a receiver cloned after closure still
    /// observes `true`.
    pub fn closed_receiver(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{PROTOCOL_MAJOR, generate_keypair};
    use crate::session::Session;
    use crate::version::Hello;

    #[test]
    fn rtt_unknown_until_a_ping_round_trips() {
        let s = RttState::default();
        assert!(s.handle().micros().is_none());
        // A stray Pong with no outstanding Ping records nothing.
        s.note_pong_recv();
        assert!(s.handle().micros().is_none());
    }

    #[test]
    fn rtt_recorded_after_ping_then_pong() {
        let s = RttState::default();
        s.note_ping_sent();
        std::thread::sleep(Duration::from_millis(2)); // guarantee a non-zero elapsed
        s.note_pong_recv();
        let us = s.handle().micros().expect("rtt should be known");
        assert!(us >= 1000, "expected >=1ms, got {us}µs");
    }

    fn hello() -> Hello {
        Hello {
            version: 1,
            min_supported: 1,
            capabilities: 0,
        }
    }

    fn hello_dg() -> Hello {
        Hello {
            version: 1,
            min_supported: 1,
            capabilities: crate::version::CAP_DATAGRAM,
        }
    }

    #[tokio::test]
    async fn datagram_open_send_recv_one_assoc() {
        let server = generate_keypair().unwrap();
        let server_pub = server.public.clone();
        let server_priv = server.private.clone();
        let (c_io, s_io) = tokio::io::duplex(16384);

        let srv = tokio::spawn(async move {
            let sess = Session::accept(s_io, &server_priv, PROTOCOL_MAJOR)
                .await
                .unwrap();
            let (r, w) = sess.into_halves();
            let mut mux = Mux::start(r, w, hello_dg(), Role::Server).await.unwrap();
            let mut stream = mux.accept().await.unwrap();
            assert_eq!(stream.kind, StreamKind::Udp);
            assert_eq!(stream.target, "1.2.3.4:53"); // scheme stripped
            let dgram = stream.recv().await.unwrap();
            stream.send(dgram).await.unwrap(); // echo one datagram back
        });

        let client = generate_keypair().unwrap();
        let sess = Session::connect(c_io, &server_pub, &client.private, PROTOCOL_MAJOR)
            .await
            .unwrap();
        let (r, w) = sess.into_halves();
        let mut mux = Mux::start(r, w, hello_dg(), Role::Client).await.unwrap();
        let mut s = mux.open_datagram("1.2.3.4:53").await.unwrap();
        assert_eq!(s.kind, StreamKind::Udp);
        s.send(Bytes::from_static(b"\x00\x01\x02")).await.unwrap();
        let echoed = s.recv().await.unwrap();
        assert_eq!(echoed.as_ref(), b"\x00\x01\x02");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn open_datagram_fails_without_cap() {
        let server = generate_keypair().unwrap();
        let server_pub = server.public.clone();
        let server_priv = server.private.clone();
        let (c_io, s_io) = tokio::io::duplex(16384);
        let srv = tokio::spawn(async move {
            let sess = Session::accept(s_io, &server_priv, PROTOCOL_MAJOR)
                .await
                .unwrap();
            let (r, w) = sess.into_halves();
            // server advertises NO capability
            let _mux = Mux::start(r, w, hello(), Role::Server).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let client = generate_keypair().unwrap();
        let sess = Session::connect(c_io, &server_pub, &client.private, PROTOCOL_MAJOR)
            .await
            .unwrap();
        let (r, w) = sess.into_halves();
        let mut mux = Mux::start(r, w, hello_dg(), Role::Client).await.unwrap();
        // negotiated cap = client(CAP) & server(0) = 0 → open_datagram refused
        assert!(mux.open_datagram("1.2.3.4:53").await.is_err());
        srv.abort();
    }

    #[tokio::test]
    async fn closed_fires_when_reader_errors() {
        use crate::error::Error;
        use crate::frame::{Frame, FrameType};
        use crate::transport::{FrameRead, FrameWrite};
        use core::future::Future;

        // Reader: first call returns a valid HELLO (consumed by `start`); the second
        // call (the reader task's first read) errors, simulating a dropped transport.
        struct MockReader {
            sent_hello: bool,
        }
        impl FrameRead for MockReader {
            fn read_frame(&mut self) -> impl Future<Output = crate::Result<Frame>> + Send {
                let first = !self.sent_hello;
                self.sent_hello = true;
                async move {
                    if first {
                        Ok(Frame {
                            stream_id: 0,
                            ftype: FrameType::Hello as u8,
                            payload: Bytes::from(hello().encode()),
                        })
                    } else {
                        Err(Error::Closed)
                    }
                }
            }
        }

        struct MockWriter;
        impl FrameWrite for MockWriter {
            async fn write_frame(&mut self, _frame: &Frame) -> crate::Result<()> {
                Ok(())
            }
        }

        let mux = Mux::start(
            MockReader { sent_hello: false },
            MockWriter,
            hello(),
            Role::Client,
        )
        .await
        .unwrap();

        let mut closed = mux.closed_receiver();
        tokio::time::timeout(std::time::Duration::from_secs(2), closed.wait_for(|v| *v))
            .await
            .expect("closed signal should fire when the reader task errors")
            .unwrap();

        // The state is latched: a freshly-cloned receiver also observes `true`.
        assert!(*mux.closed_receiver().borrow());
    }

    fn hello_ka() -> Hello {
        Hello {
            version: 1,
            min_supported: 1,
            capabilities: crate::version::CAP_KEEPALIVE,
        }
    }

    fn hello_fc() -> Hello {
        Hello {
            version: 1,
            min_supported: 1,
            capabilities: crate::version::CAP_FLOWCONTROL,
        }
    }

    /// A reader that yields a fixed script of frames, then blocks forever (never EOF,
    /// never errors) — models a silently blackholed link (no FIN/RST).
    struct ScriptedThenSilent {
        frames: std::collections::VecDeque<Frame>,
    }
    impl crate::transport::FrameRead for ScriptedThenSilent {
        fn read_frame(
            &mut self,
        ) -> impl core::future::Future<Output = crate::Result<Frame>> + Send {
            let next = self.frames.pop_front();
            async move {
                match next {
                    Some(f) => Ok(f),
                    None => std::future::pending().await,
                }
            }
        }
    }

    /// A writer that records every frame it's asked to send.
    #[derive(Clone)]
    struct RecordingWriter {
        sent: Arc<Mutex<Vec<Frame>>>,
    }
    impl crate::transport::FrameWrite for RecordingWriter {
        async fn write_frame(&mut self, frame: &Frame) -> crate::Result<()> {
            self.sent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(frame.clone());
            Ok(())
        }
    }

    fn hello_frame(h: Hello) -> Frame {
        Frame {
            stream_id: 0,
            ftype: FrameType::Hello as u8,
            payload: Bytes::from(h.encode()),
        }
    }

    // --- suspend watchdog -------------------------------------------------------------
    // `tokio::time::pause()` controls the *monotonic* clock only, so a suspend is modelled the
    // one way it actually presents: wall clock leaps forward while `last_seen` — which only a
    // real inbound frame advances — stays put. Hence the injected `now`.

    const IDLE: Duration = Duration::from_secs(45);
    const POLL: Duration = Duration::from_millis(10);

    /// Spawn a watchdog over a fake wall clock. Returns the knobs plus a receiver to observe
    /// `closed`, and the handle so the test can abort the task.
    fn spawn_watchdog(
        last_seen_millis: u64,
        now_millis: u64,
    ) -> (
        Arc<AtomicU64>,
        Arc<AtomicU64>,
        watch::Receiver<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let last_seen = Arc::new(AtomicU64::new(last_seen_millis));
        let now = Arc::new(AtomicU64::new(now_millis));
        let (closed_tx, closed_rx) = watch::channel(false);
        let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
        let n = now.clone();
        let handle = tokio::spawn(suspend_watchdog(
            last_seen.clone(),
            streams,
            closed_tx,
            IDLE,
            POLL,
            move || n.load(Ordering::Relaxed),
        ));
        (last_seen, now, closed_rx, handle)
    }

    #[test]
    fn wall_clock_stale_needs_more_than_the_timeout() {
        // Exactly at the boundary is not yet stale (`>`), one milli past it is.
        assert!(!wall_clock_stale(1_000, 1_000 + 45_000, IDLE));
        assert!(wall_clock_stale(1_000, 1_000 + 45_001, IDLE));
        assert!(!wall_clock_stale(1_000, 1_000, IDLE));
    }

    /// An NTP correction stepping the clock backwards must not be read as a dead link.
    #[test]
    fn wall_clock_stale_ignores_a_backwards_clock_step() {
        assert!(!wall_clock_stale(5_000_000, 1_000, IDLE));
        assert!(!wall_clock_stale(u64::MAX, 0, IDLE));
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_leaves_a_link_that_keeps_receiving_frames_alone() {
        let (last_seen, now, closed_rx, handle) = spawn_watchdog(1_000, 1_000);
        // Hours of wall clock pass, but frames keep arriving, so `last_seen` tracks it.
        for _ in 0..10 {
            tokio::time::sleep(POLL * 3).await;
            let t = now.fetch_add(600_000, Ordering::Relaxed) + 600_000;
            last_seen.store(t, Ordering::Relaxed);
        }
        assert!(
            !*closed_rx.borrow(),
            "a link still receiving frames must never be declared dead"
        );
        // Without this the test would also pass against a watchdog that panicked or returned on
        // its first tick — "never closed" is only meaningful while it is still watching.
        assert!(
            !handle.is_finished(),
            "watchdog must still be running, not dead"
        );
        handle.abort();
    }

    /// The bug this exists for: the phone slept past the peer's idle timeout, so the peer tore
    /// the session down. Monotonic timers learned nothing (they were frozen too) — only the wall
    /// clock shows the gap.
    #[tokio::test(start_paused = true)]
    async fn watchdog_closes_a_link_that_died_while_suspended() {
        let (_last_seen, now, mut closed_rx, _handle) = spawn_watchdog(1_000, 1_000);
        // One hour of suspend: wall clock leaps, `last_seen` cannot move — no frame arrived.
        now.store(1_000 + 3_600_000, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(5), closed_rx.wait_for(|v| *v))
            .await
            .expect("watchdog must declare the link dead on the first tick after wake")
            .unwrap();
    }

    /// Whoever notices the death first wins; the watchdog must not outlive a session the reader
    /// already tore down. Covers both orderings, including a close that lands before the
    /// watchdog is ever polled — where there is no `changed()` edge left to observe.
    #[tokio::test(start_paused = true)]
    async fn watchdog_exits_when_another_task_closes_the_session() {
        for close_before_first_poll in [false, true] {
            let last_seen = Arc::new(AtomicU64::new(1_000));
            let (closed_tx, _closed_rx) = watch::channel(false);
            let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
            let observer = closed_tx.clone();
            if close_before_first_poll {
                observer.send(true).unwrap();
            }
            let handle = tokio::spawn(suspend_watchdog(
                last_seen,
                streams,
                closed_tx,
                IDLE,
                POLL,
                || 1_000, // clock frozen: only the close can end this task
            ));
            if !close_before_first_poll {
                tokio::task::yield_now().await;
                observer.send(true).unwrap(); // the reader hit an I/O error
            }
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .unwrap_or_else(|_| {
                    panic!("watchdog must exit once the session is closed (close_before_first_poll={close_before_first_poll})")
                })
                .unwrap();
        }
    }

    #[tokio::test]
    async fn keepalive_trips_closed_on_silent_peer() {
        // Peer advertises CAP_KEEPALIVE in its HELLO, then goes silent forever. The
        // idle-read timeout must fire `closed()` so the supervisor can reconnect —
        // without keepalive the reader would block on read_frame() indefinitely.
        let reader = ScriptedThenSilent {
            frames: vec![hello_frame(hello_ka())].into(),
        };
        let cfg = KeepaliveConfig {
            interval: std::time::Duration::from_millis(20),
            idle_timeout: std::time::Duration::from_millis(80),
        };
        let mux = Mux::start_with_keepalive(
            reader,
            RecordingWriter {
                sent: Arc::new(Mutex::new(Vec::new())),
            },
            hello_ka(),
            Role::Client,
            cfg,
        )
        .await
        .unwrap();

        let mut closed = mux.closed_receiver();
        tokio::time::timeout(std::time::Duration::from_secs(1), closed.wait_for(|v| *v))
            .await
            .expect("idle keepalive timeout must fire closed() on a silent peer")
            .unwrap();
    }

    #[tokio::test]
    async fn no_keepalive_cap_keeps_silent_peer_open() {
        // Backward compatibility: if the cap is NOT negotiated (peer HELLO without it),
        // a silent-but-idle tunnel must NOT trip closed() — no spurious idle timeout.
        let reader = ScriptedThenSilent {
            frames: vec![hello_frame(hello())].into(),
        };
        let cfg = KeepaliveConfig {
            interval: std::time::Duration::from_millis(20),
            idle_timeout: std::time::Duration::from_millis(50),
        };
        let mux = Mux::start_with_keepalive(
            reader,
            RecordingWriter {
                sent: Arc::new(Mutex::new(Vec::new())),
            },
            hello_ka(), // we advertise it, peer does not → not negotiated
            Role::Client,
            cfg,
        )
        .await
        .unwrap();

        let mut closed = mux.closed_receiver();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                closed.wait_for(|v| *v)
            )
            .await
            .is_err(),
            "without the keepalive cap, an idle tunnel must stay open"
        );
    }

    #[tokio::test]
    async fn ping_is_answered_with_pong() {
        // A received Ping must be echoed as a Pong so the peer can confirm our liveness.
        let reader = ScriptedThenSilent {
            frames: vec![
                hello_frame(hello_ka()),
                Frame {
                    stream_id: 0,
                    ftype: FrameType::Ping as u8,
                    payload: Bytes::new(),
                },
            ]
            .into(),
        };
        let sent = Arc::new(Mutex::new(Vec::new()));
        let cfg = KeepaliveConfig {
            // Long timers so neither our own ping nor the idle timeout interfere.
            interval: std::time::Duration::from_secs(30),
            idle_timeout: std::time::Duration::from_secs(30),
        };
        let _mux = Mux::start_with_keepalive(
            reader,
            RecordingWriter { sent: sent.clone() },
            hello_ka(),
            Role::Client,
            cfg,
        )
        .await
        .unwrap();

        // Poll until a Pong shows up in the recorded writes.
        let saw_pong = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if sent
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|f| base_type(f.ftype) == FrameType::Pong as u8)
                {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or(false);
        assert!(saw_pong, "a received Ping must be answered with a Pong");
    }

    #[tokio::test]
    async fn keepalive_emits_periodic_pings() {
        // With the cap negotiated, the mux must proactively send Ping frames so the
        // peer keeps seeing traffic on an otherwise idle tunnel.
        let reader = ScriptedThenSilent {
            frames: vec![hello_frame(hello_ka())].into(),
        };
        let sent = Arc::new(Mutex::new(Vec::new()));
        let cfg = KeepaliveConfig {
            interval: std::time::Duration::from_millis(20),
            idle_timeout: std::time::Duration::from_secs(30), // don't let idle kill it first
        };
        let _mux = Mux::start_with_keepalive(
            reader,
            RecordingWriter { sent: sent.clone() },
            hello_ka(),
            Role::Client,
            cfg,
        )
        .await
        .unwrap();

        let saw_ping = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if sent
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|f| base_type(f.ftype) == FrameType::Ping as u8)
                {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or(false);
        assert!(saw_ping, "keepalive must emit periodic Ping frames");
    }

    #[tokio::test]
    async fn aborts_when_peer_opens_too_many_streams() {
        use crate::frame::{Frame, FrameType};
        use crate::transport::{FrameRead, FrameWrite};
        use core::future::Future;

        // Reader: HELLO, then an unbounded stream of OPEN frames with fresh ids
        // (never closed), then pends forever. A correct mux must abort the
        // session once the concurrent-stream cap is exceeded rather than grow
        // its stream map without bound. (L3)
        struct FloodReader {
            next: u32,
        }
        impl FrameRead for FloodReader {
            fn read_frame(&mut self) -> impl Future<Output = crate::Result<Frame>> + Send {
                let id = self.next;
                self.next += 1;
                async move {
                    if id == 0 {
                        Ok(Frame {
                            stream_id: 0,
                            ftype: FrameType::Hello as u8,
                            payload: Bytes::from(hello().encode()),
                        })
                    } else if id <= (MAX_CONCURRENT_PEER_STREAMS as u32 + 1) {
                        Ok(Frame {
                            stream_id: id,
                            ftype: FrameType::Open as u8,
                            payload: Bytes::from_static(b"echo:0"),
                        })
                    } else {
                        std::future::pending::<()>().await;
                        unreachable!()
                    }
                }
            }
        }
        struct SinkWriter;
        impl FrameWrite for SinkWriter {
            async fn write_frame(&mut self, _frame: &Frame) -> crate::Result<()> {
                Ok(())
            }
        }

        let mut mux = Mux::start(FloodReader { next: 0 }, SinkWriter, hello(), Role::Server)
            .await
            .unwrap();

        // Drain accepted streams (dropping them, so the map keeps growing) until
        // the session is torn down.
        let mut closed = mux.closed_receiver();
        let drain = tokio::spawn(async move { while mux.accept().await.is_ok() {} });

        tokio::time::timeout(std::time::Duration::from_secs(5), closed.wait_for(|v| *v))
            .await
            .expect("session must abort once the peer exceeds the stream cap")
            .unwrap();
        drain.abort();
    }

    #[tokio::test]
    async fn slow_stream_does_not_block_another_with_flow_control() {
        // A stalled stream (its consumer never reads) must NOT head-of-line-block another stream.
        // The peer pushes 200 frames on stream A — far past the old 64-deep per-stream channel —
        // then one frame on stream B. With the shared reader no longer blocking on a slow stream,
        // B's frame is delivered even though A is never drained. (Pre-fix, the reader would block
        // on A's full channel and B.recv() would hang.)
        let mut frames: std::collections::VecDeque<Frame> = std::collections::VecDeque::new();
        frames.push_back(hello_frame(hello_fc()));
        frames.push_back(Frame {
            stream_id: 1,
            ftype: FrameType::Open as u8,
            payload: Bytes::from_static(b"echo:a"),
        });
        frames.push_back(Frame {
            stream_id: 3,
            ftype: FrameType::Open as u8,
            payload: Bytes::from_static(b"echo:b"),
        });
        for _ in 0..200 {
            frames.push_back(Frame {
                stream_id: 1,
                ftype: FrameType::Data as u8,
                payload: Bytes::from(vec![0u8; 100]),
            });
        }
        frames.push_back(Frame {
            stream_id: 3,
            ftype: FrameType::Data as u8,
            payload: Bytes::from_static(b"hello-b"),
        });

        let reader = ScriptedThenSilent { frames };
        let mut mux = Mux::start(
            reader,
            RecordingWriter {
                sent: Arc::new(Mutex::new(Vec::new())),
            },
            hello_fc(),
            Role::Server,
        )
        .await
        .unwrap();

        let a = mux.accept().await.unwrap(); // stream A: id 1, intentionally never drained
        let mut b = mux.accept().await.unwrap(); // stream B: id 3
        assert_eq!(a.target, "echo:a");
        assert_eq!(b.target, "echo:b");

        let got = tokio::time::timeout(Duration::from_secs(1), b.recv())
            .await
            .expect("stream B must not be head-of-line-blocked by the stalled stream A")
            .unwrap();
        assert_eq!(got.as_ref(), b"hello-b");
    }

    #[tokio::test]
    async fn flow_control_allows_transfer_larger_than_window() {
        // Send more than one window's worth of bytes through a real session. This only completes
        // if the receiver credits the sender (`WindowUpdate`) as it drains — otherwise the sender
        // blocks at INIT_WINDOW and the transfer deadlocks.
        const TOTAL: usize = 1024 * 1024; // 1 MiB ≫ INIT_WINDOW (256 KiB)

        let server = generate_keypair().unwrap();
        let server_pub = server.public.clone();
        let server_priv = server.private.clone();
        let (c_io, s_io) = tokio::io::duplex(64 * 1024);

        let srv = tokio::spawn(async move {
            let sess = Session::accept(s_io, &server_priv, PROTOCOL_MAJOR)
                .await
                .unwrap();
            let (r, w) = sess.into_halves();
            let mut mux = Mux::start(r, w, hello_fc(), Role::Server).await.unwrap();
            let mut stream = mux.accept().await.unwrap();
            let mut got = 0usize;
            while got < TOTAL {
                match stream.recv().await {
                    Ok(b) if !b.is_empty() => got += b.len(),
                    _ => break,
                }
            }
            got
        });

        let client = generate_keypair().unwrap();
        let sess = Session::connect(c_io, &server_pub, &client.private, PROTOCOL_MAJOR)
            .await
            .unwrap();
        let (r, w) = sess.into_halves();
        let mut mux = Mux::start(r, w, hello_fc(), Role::Client).await.unwrap();
        let s = mux.open("sink:0").await.unwrap();
        let chunk = Bytes::from(vec![7u8; 32 * 1024]);
        let mut sent = 0usize;
        while sent < TOTAL {
            s.send(chunk.clone()).await.unwrap();
            sent += chunk.len();
        }

        let got = tokio::time::timeout(Duration::from_secs(5), srv)
            .await
            .expect("transfer larger than the window must not deadlock")
            .unwrap();
        assert_eq!(got, TOTAL);
    }

    #[tokio::test]
    async fn open_data_close_one_stream() {
        let server = generate_keypair().unwrap();
        let server_pub = server.public.clone();
        let server_priv = server.private.clone();
        let (c_io, s_io) = tokio::io::duplex(16384);

        // server: accept first inbound stream, echo until close
        let srv = tokio::spawn(async move {
            let sess = Session::accept(s_io, &server_priv, PROTOCOL_MAJOR)
                .await
                .unwrap();
            let (r, w) = sess.into_halves();
            let mut mux = Mux::start(r, w, hello(), Role::Server).await.unwrap();
            let mut stream = mux.accept().await.unwrap();
            assert_eq!(stream.target, "echo:0");
            let data = stream.recv().await.unwrap();
            stream.send(data).await.unwrap();
            stream.close().await.unwrap();
        });

        let client = generate_keypair().unwrap();
        let sess = Session::connect(c_io, &server_pub, &client.private, PROTOCOL_MAJOR)
            .await
            .unwrap();
        let (r, w) = sess.into_halves();
        let mut mux = Mux::start(r, w, hello(), Role::Client).await.unwrap();
        let mut s = mux.open("echo:0").await.unwrap();
        s.send(Bytes::from_static(b"ping")).await.unwrap();
        let echoed = s.recv().await.unwrap();
        assert_eq!(echoed.as_ref(), b"ping");
        srv.await.unwrap();
    }
}
