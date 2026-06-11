//! Stream multiplexer over one Session. OPEN carries the target as UTF-8 in its payload.
use crate::error::{Error, Result};
use crate::frame::{Frame, FrameType, MAX_PLAINTEXT, base_type, is_critical};
use crate::transport::{FrameRead, FrameWrite};
use crate::version::{Hello, Negotiated, negotiate};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};

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
    Open(u32, String, mpsc::Sender<Vec<u8>>),
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
    rx: mpsc::Receiver<Vec<u8>>,
}

impl Stream {
    /// Send payload bytes. TCP streams chunk into `Data` frames; UDP streams send the
    /// whole datagram in one `Datagram` frame (oversized datagrams are rejected).
    ///
    /// Each plaintext frame = 5-byte header + payload. Cap the payload so the encoded
    /// frame fits any transport's per-record overhead: Noise adds a 16-byte tag, the
    /// TLS app-data path adds a 1-byte inner-type + 16-byte tag (the larger). Leaving
    /// 6 bytes (header 5 + the extra inner-type byte) below MAX_PLAINTEXT is safe for both.
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        match self.kind {
            StreamKind::Tcp => {
                for chunk in data.chunks(MAX_PLAINTEXT - 6) {
                    self.tx
                        .send(Command::Write(Frame {
                            stream_id: self.id,
                            ftype: FrameType::Data as u8,
                            payload: chunk.to_vec(),
                        }))
                        .await
                        .map_err(|_| Error::Closed)?;
                }
                Ok(())
            }
            StreamKind::Udp => {
                if data.len() > MAX_PLAINTEXT - 6 {
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
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.rx.recv().await.ok_or(Error::Closed)
    }

    /// Send a CLOSE frame and remove the stream from the registry.
    pub async fn close(&self) -> Result<()> {
        self.tx
            .send(Command::Write(Frame {
                stream_id: self.id,
                ftype: FrameType::Close as u8,
                payload: vec![],
            }))
            .await
            .map_err(|_| Error::Closed)
    }
}

/// Shared map of active streams: stream_id → data sender.
type Streams = Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>;

/// Multiplexer: owns the background reader/writer tasks for one [`Session`].
pub struct Mux {
    cmd_tx: mpsc::Sender<Command>,
    incoming: mpsc::Receiver<Stream>,
    next_id: u32,
    pub negotiated: Negotiated,
    closed_rx: watch::Receiver<bool>,
}

impl Mux {
    /// Start the mux over a completed session:
    /// 1. Exchange HELLO frames (write own, then read peer's) — deadlock-free on
    ///    full-duplex because both sides write before reading.
    /// 2. Spawn a writer task and a reader task.
    pub async fn start<R, W>(
        mut reader: R,
        mut writer: W,
        local_hello: Hello,
        role: Role,
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
                payload: local_hello.encode(),
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
                                    payload: target.into_bytes(),
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

        // --- reader task: dispatches inbound frames to per-stream senders ---
        {
            let r_streams = streams.clone();
            let r_cmd_tx = cmd_tx.clone();
            let r_closed = closed_tx;
            tokio::spawn(async move {
                loop {
                    let f = match reader.read_frame().await {
                        Ok(f) => f,
                        Err(_) => break,
                    };
                    let bt = base_type(f.ftype);
                    if bt == FrameType::Open as u8 {
                        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
                        r_streams.lock().unwrap().insert(f.stream_id, data_tx);
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
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
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
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
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
        s.send(b"\x00\x01\x02".to_vec()).await.unwrap();
        let echoed = s.recv().await.unwrap();
        assert_eq!(echoed, b"\x00\x01\x02");
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
                            payload: hello().encode(),
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
        s.send(b"ping".to_vec()).await.unwrap();
        let echoed = s.recv().await.unwrap();
        assert_eq!(echoed, b"ping");
        srv.await.unwrap();
    }
}
