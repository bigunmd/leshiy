//! Async, AEAD-sealed frame transport over a single connection.
use crate::error::{Error, Result};
use crate::frame::{Frame, MAX_PLAINTEXT};
use crate::handshake::{build_initiator, build_responder};
use snow::TransportState;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

/// Wall-clock bound on the Noise handshake (both `connect` and `accept`). A peer that opens the
/// socket and then stalls — never sending msg1, or dribbling it — must not pin the task forever
/// (a slowloris / connection-holding DoS). The whole handshake is expected to complete in a few
/// round-trips, so this is generous while still bounding a hostile or dead peer.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Wire framing of a sealed frame: [u16 BE ciphertext-len][ciphertext].
async fn read_sealed<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_sealed<W: AsyncWrite + Unpin>(w: &mut W, ct: &[u8]) -> Result<()> {
    let len = u16::try_from(ct.len()).map_err(|_| Error::FrameTooLarge(ct.len()))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(ct).await?;
    w.flush().await?;
    Ok(())
}

pub struct Session<S: AsyncRead + AsyncWrite> {
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    transport: Arc<Mutex<TransportState>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    /// Initiator side: performs the IK handshake (writes msg1, reads msg2), then
    /// enters transport mode.  Returns `Err` on any crypto or I/O failure so the
    /// caller can drop the connection without distinguishing the cause.
    pub async fn connect(io: S, server_pub: &[u8], client_priv: &[u8], major: u16) -> Result<Self> {
        let mut hs = build_initiator(server_pub, client_priv, major)?;
        let (mut reader, mut writer) = tokio::io::split(io);

        // Bound the whole handshake so a stalled/hostile peer can't pin this task forever.
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            // msg1: initiator → responder
            let mut buf = vec![0u8; 1024];
            let n = hs.write_message(&[], &mut buf)?;
            write_sealed(&mut writer, &buf[..n]).await?;

            // msg2: responder → initiator
            let msg2 = read_sealed(&mut reader).await?;
            let mut tmp = vec![0u8; 1024];
            hs.read_message(&msg2, &mut tmp)?;
            Ok::<_, Error>(hs.into_transport_mode()?)
        })
        .await
        .map_err(|_| Error::Timeout)?
        .map(|transport| Self {
            reader,
            writer,
            transport: Arc::new(Mutex::new(transport)),
        })
    }

    /// Responder side: reads msg1, writes msg2, enters transport mode.
    /// On a wrong key or wrong major version the `read_message` call fails,
    /// propagating `Err` so the caller can drop silently (anti-probe).
    pub async fn accept(io: S, server_priv: &[u8], major: u16) -> Result<Self> {
        let mut hs = build_responder(server_priv, major)?;
        let (mut reader, mut writer) = tokio::io::split(io);

        // Bound the whole handshake: after a valid connect a peer that stalls before sending msg1
        // (or dribbles it) must be dropped, not held indefinitely (anti-probe / anti-DoS).
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            // msg1: initiator → responder (may fail on wrong key / major)
            let msg1 = read_sealed(&mut reader).await?;
            let mut tmp = vec![0u8; 1024];
            hs.read_message(&msg1, &mut tmp)?;

            // msg2: responder → initiator
            let mut buf = vec![0u8; 1024];
            let n = hs.write_message(&[], &mut buf)?;
            write_sealed(&mut writer, &buf[..n]).await?;
            Ok::<_, Error>(hs.into_transport_mode()?)
        })
        .await
        .map_err(|_| Error::Timeout)?
        .map(|transport| Self {
            reader,
            writer,
            transport: Arc::new(Mutex::new(transport)),
        })
    }

    /// Seal a frame and send it.  The Mutex is held only around the synchronous
    /// snow crypto call — never across an `.await`.
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        let pt = frame.encode();
        if pt.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge(pt.len()));
        }
        let mut ct = vec![0u8; pt.len() + 16];
        let n = { self.transport.lock().unwrap().write_message(&pt, &mut ct)? };
        write_sealed(&mut self.writer, &ct[..n]).await
    }

    /// Receive a sealed frame and open it.  The Mutex is held only around the
    /// synchronous snow crypto call — never across an `.await`.
    pub async fn read_frame(&mut self) -> Result<Frame> {
        let ct = read_sealed(&mut self.reader).await?;
        let mut pt = vec![0u8; ct.len()];
        let n = { self.transport.lock().unwrap().read_message(&ct, &mut pt)? };
        Frame::decode(&pt[..n])
    }

    /// Split into independently-owned read/write halves sharing the cipher state,
    /// for concurrent reader/writer tasks used by the mux.
    pub fn into_halves(self) -> (SessionReader<S>, SessionWriter<S>) {
        let t = self.transport;
        (
            SessionReader {
                reader: self.reader,
                transport: t.clone(),
            },
            SessionWriter {
                writer: self.writer,
                transport: t,
            },
        )
    }
}

/// Owned read half produced by [`Session::into_halves`].
pub struct SessionReader<S: AsyncRead + AsyncWrite> {
    reader: ReadHalf<S>,
    transport: Arc<Mutex<TransportState>>,
}

/// Owned write half produced by [`Session::into_halves`].
pub struct SessionWriter<S: AsyncRead + AsyncWrite> {
    writer: WriteHalf<S>,
    transport: Arc<Mutex<TransportState>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SessionReader<S> {
    pub async fn recv_frame(&mut self) -> Result<Frame> {
        let ct = read_sealed(&mut self.reader).await?;
        let mut pt = vec![0u8; ct.len()];
        let n = { self.transport.lock().unwrap().read_message(&ct, &mut pt)? };
        Frame::decode(&pt[..n])
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SessionWriter<S> {
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        let pt = frame.encode();
        if pt.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge(pt.len()));
        }
        let mut ct = vec![0u8; pt.len() + 16];
        let n = { self.transport.lock().unwrap().write_message(&pt, &mut ct)? };
        write_sealed(&mut self.writer, &ct[..n]).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> crate::transport::FrameRead for SessionReader<S> {
    fn read_frame(&mut self) -> impl core::future::Future<Output = Result<Frame>> + Send {
        self.recv_frame()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> crate::transport::FrameWrite for SessionWriter<S> {
    fn write_frame(
        &mut self,
        frame: &Frame,
    ) -> impl core::future::Future<Output = Result<()>> + Send {
        self.send_frame(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Frame, FrameType};
    use crate::handshake::{PROTOCOL_MAJOR, generate_keypair};

    #[tokio::test]
    async fn session_roundtrips_a_frame() {
        let server = generate_keypair().unwrap();
        let server_pub = server.public.clone();
        let (c_io, s_io) = tokio::io::duplex(8192);

        let server_priv = server.private.clone();
        let srv = tokio::spawn(async move {
            let mut sess = Session::accept(s_io, &server_priv, PROTOCOL_MAJOR)
                .await
                .unwrap();
            let f = sess.read_frame().await.unwrap();
            assert_eq!(f.payload.as_ref(), b"hi");
            sess.write_frame(&Frame {
                stream_id: f.stream_id,
                ftype: FrameType::Data as u8,
                payload: bytes::Bytes::from_static(b"yo"),
            })
            .await
            .unwrap();
        });

        let client = generate_keypair().unwrap();
        let mut sess = Session::connect(c_io, &server_pub, &client.private, PROTOCOL_MAJOR)
            .await
            .unwrap();
        sess.write_frame(&Frame {
            stream_id: 1,
            ftype: FrameType::Data as u8,
            payload: bytes::Bytes::from_static(b"hi"),
        })
        .await
        .unwrap();
        let reply = sess.read_frame().await.unwrap();
        assert_eq!(reply.payload.as_ref(), b"yo");
        srv.await.unwrap();
    }

    /// A peer that opens the connection but never sends msg1 must be dropped by the handshake
    /// deadline, not held forever. `start_paused` auto-advances virtual time while the accept task
    /// is idle, so the 10s timeout fires instantly instead of blocking the test.
    #[tokio::test(start_paused = true)]
    async fn accept_times_out_on_a_stalled_peer() {
        let server = generate_keypair().unwrap();
        // Keep the client end alive but silent, so the server's read pends (not EOF).
        let (_c_io, s_io) = tokio::io::duplex(8192);
        let res = Session::accept(s_io, &server.private, PROTOCOL_MAJOR).await;
        assert!(matches!(res, Err(Error::Timeout)));
    }

    #[tokio::test]
    async fn wrong_server_key_fails_client() {
        let server = generate_keypair().unwrap();
        let wrong = generate_keypair().unwrap();
        let (c_io, s_io) = tokio::io::duplex(8192);
        let sp = server.private.clone();
        tokio::spawn(async move {
            let _ = Session::accept(s_io, &sp, PROTOCOL_MAJOR).await;
        });
        let client = generate_keypair().unwrap();
        // client targets the WRONG public key
        let res = Session::connect(c_io, &wrong.public, &client.private, PROTOCOL_MAJOR).await;
        assert!(res.is_err());
    }
}
