//! Stream multiplexer over one Session. OPEN carries the target as UTF-8 in its payload.
use crate::error::{Error, Result};
use crate::frame::{Frame, FrameType, MAX_FRAME_PAYLOAD, base_type, is_critical};
use crate::transport::{FrameRead, FrameWrite};
use crate::version::{CAP_KEEPALIVE, Hello, Negotiated, negotiate};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Upper bound on concurrently-open peer-initiated streams. A peer that exceeds
/// it is aborting the session via resource exhaustion, so we tear the session
/// down rather than grow the stream map without bound. (L3)
const MAX_CONCURRENT_PEER_STREAMS: usize = 1024;

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
    Open(u32, String, mpsc::Sender<Bytes>),
    /// Write an arbitrary frame (DATA, CLOSE, …).
    Write(Frame),
}

/// A logical stream inside a [`Mux`].
pub struct Stream {
    /// The target string carried in the OPEN frame, with any scheme prefix stripped.
    pub target: String,
    /// Whether this stream carries TCP byte-stream data or UDP datagrams.
    pub kind: StreamKind,
    id: u32,
    tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Bytes>,
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

    /// Receive the next payload chunk from the peer.
    pub async fn recv(&mut self) -> Result<Bytes> {
        self.rx.recv().await.ok_or(Error::Closed)
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

/// Shared map of active streams: stream_id → data sender.
type Streams = Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>;

/// Multiplexer: owns the background reader/writer tasks for one [`Session`].
pub struct Mux {
    cmd_tx: mpsc::Sender<Command>,
    incoming: mpsc::Receiver<Stream>,
    next_id: u32,
    pub negotiated: Negotiated,
    closed_rx: watch::Receiver<bool>,
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
                        Command::Open(id, target, data_tx) => {
                            w_streams.lock().unwrap().insert(id, data_tx);
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
                            if base_type(f.ftype) == FrameType::Close as u8 {
                                w_streams.lock().unwrap().remove(&f.stream_id);
                            }
                            if writer.write_frame(&f).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = w_closed.send(true);
            });
        }

        let keepalive_on = negotiated.capabilities & CAP_KEEPALIVE != 0;

        // --- reader task: dispatches inbound frames to per-stream senders ---
        {
            let r_streams = streams.clone();
            let r_cmd_tx = cmd_tx.clone();
            let r_closed = closed_tx.clone();
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
                        // Receipt already reset the idle timer above; nothing else to do.
                        continue;
                    } else if bt == FrameType::Open as u8 {
                        let (data_tx, data_rx) = mpsc::channel::<Bytes>(64);
                        {
                            let mut map = r_streams.lock().unwrap();
                            if map.len() >= MAX_CONCURRENT_PEER_STREAMS {
                                break; // peer opened too many concurrent streams → abort (L3)
                            }
                            map.insert(f.stream_id, data_tx);
                        }
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
                        let stream = Stream {
                            target,
                            kind,
                            id: f.stream_id,
                            tx: r_cmd_tx.clone(),
                            rx: data_rx,
                        };
                        if inc_tx.send(stream).await.is_err() {
                            break;
                        }
                    } else if bt == FrameType::Data as u8 || bt == FrameType::Datagram as u8 {
                        // DATA (stream) and DATAGRAM (one packet) both route to the per-stream
                        // channel. Clone the sender out of the map BEFORE awaiting the send
                        // so we never hold the Mutex guard across an .await.
                        let tx = r_streams.lock().unwrap().get(&f.stream_id).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(f.payload).await;
                        }
                    } else if bt == FrameType::Close as u8 {
                        r_streams.lock().unwrap().remove(&f.stream_id);
                    } else if is_critical(f.ftype) {
                        break; // unknown critical frame → abort session
                    }
                    // unknown non-critical frame → silently ignore (continue)
                }
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
            tokio::spawn(async move {
                loop {
                    if *ka_closed.borrow() {
                        break; // connection already closed
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {
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
                        }
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

        let next_id = if role == Role::Client { 1 } else { 2 };
        Ok(Mux {
            cmd_tx,
            incoming,
            next_id,
            negotiated,
            closed_rx,
        })
    }

    /// Open a new outgoing stream to `target`.
    /// Clients get odd ids, servers get even ids.
    pub async fn open(&mut self, target: &str) -> Result<Stream> {
        let id = self.next_id;
        self.next_id += 2;
        let (data_tx, data_rx) = mpsc::channel::<Bytes>(64);
        self.cmd_tx
            .send(Command::Open(id, target.to_string(), data_tx))
            .await
            .map_err(|_| Error::Closed)?;
        Ok(Stream {
            target: target.to_string(),
            kind: StreamKind::Tcp,
            id,
            tx: self.cmd_tx.clone(),
            rx: data_rx,
        })
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
        let (data_tx, data_rx) = mpsc::channel::<Bytes>(64);
        self.cmd_tx
            .send(Command::Open(id, format!("udp:{target}"), data_tx))
            .await
            .map_err(|_| Error::Closed)?;
        Ok(Stream {
            target: target.to_string(),
            kind: StreamKind::Udp,
            id,
            tx: self.cmd_tx.clone(),
            rx: data_rx,
        })
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
            self.sent.lock().unwrap().push(frame.clone());
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
