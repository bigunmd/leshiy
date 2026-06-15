//! Bidirectional copy between a local client socket and a `ProxyStream`, counting
//! bytes in each direction for live speed display.
use crate::error::Result;
use crate::stats::ByteCounters;
use crate::stream::ProxyStream;
use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read-buffer size: refilled per read, handed downstream as a zero-copy `Bytes`.
const READ_CHUNK: usize = 16384;

/// Pump bytes between `client` and `stream` until either side ends, tallying
/// upload (client→tunnel) and download (tunnel→client) bytes into `counters`.
pub async fn pump<C, S>(client: C, stream: &mut S, counters: Arc<ByteCounters>) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: ProxyStream + ?Sized,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    // Reused read buffer: `read_buf` fills its spare capacity, `split().freeze()`
    // hands the bytes downstream zero-copy, and the allocation is reclaimed once
    // the frozen chunk is consumed by the tunnel.
    let mut rbuf = BytesMut::with_capacity(READ_CHUNK);
    loop {
        tokio::select! {
            inbound = stream.recv() => {
                match inbound {
                    Ok(b) if !b.is_empty() => {
                        counters.add_down(b.len() as u64);
                        cw.write_all(&b).await?;
                    }
                    _ => break, // empty chunk or error => EOF
                }
            }
            res = cr.read_buf(&mut rbuf) => {
                let n = res?;
                if n == 0 {
                    break; // client closed
                }
                let chunk = rbuf.split().freeze();
                counters.add_up(chunk.len() as u64);
                stream.send(chunk).await?;
                rbuf.reserve(READ_CHUNK);
            }
        }
    }
    let _ = stream.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ClientError;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Fake stream: returns queued download chunks then errors; records uploads.
    /// `recv_pends` makes `recv` hang forever once the queue empties (so the upload
    /// direction can be tested in isolation without the recv arm ever firing).
    struct FakeStream {
        incoming: VecDeque<bytes::Bytes>,
        recv_pends: bool,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl ProxyStream for FakeStream {
        async fn send(&mut self, data: bytes::Bytes) -> Result<()> {
            self.sent.lock().unwrap().extend_from_slice(&data);
            Ok(())
        }
        async fn recv(&mut self) -> Result<bytes::Bytes> {
            if let Some(chunk) = self.incoming.pop_front() {
                Ok(chunk)
            } else if self.recv_pends {
                std::future::pending::<()>().await;
                unreachable!()
            } else {
                Err(ClientError::ConnectFailed)
            }
        }
        async fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn pump_counts_upload() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut fake = FakeStream {
            incoming: VecDeque::new(),
            recv_pends: true, // recv never fires; isolate the upload path
            sent: sent.clone(),
        };
        let counters = Arc::new(ByteCounters::new());

        // Write 5 bytes client→tunnel, then close the write half to end the loop.
        let writer = tokio::spawn(async move {
            peer.write_all(b"hello").await.unwrap();
            peer.shutdown().await.unwrap();
        });

        pump(client, &mut fake, counters.clone()).await.unwrap();
        writer.await.unwrap();

        assert_eq!(counters.totals().0, 5, "upload bytes");
        assert_eq!(&*sent.lock().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn pump_counts_download() {
        // Keep the peer end alive (never writes/closes) so the client-read arm pends.
        let (client, _peer_keepalive) = tokio::io::duplex(1024);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut incoming = VecDeque::new();
        incoming.push_back(bytes::Bytes::from_static(b"world!!")); // 7 bytes
        let mut fake = FakeStream {
            incoming,
            recv_pends: false, // after the one chunk, recv errors => EOF
            sent: sent.clone(),
        };
        let counters = Arc::new(ByteCounters::new());

        pump(client, &mut fake, counters.clone()).await.unwrap();

        assert_eq!(counters.totals().1, 7, "download bytes");
    }
}
