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
    // Each direction owns at most one chunk and keeps its send alive while the
    // reverse direction progresses. Only whole-relay termination cancels a send.
    let result = {
        let upload = async {
            let mut rbuf = BytesMut::with_capacity(READ_CHUNK);
            loop {
                if cr.read_buf(&mut rbuf).await? == 0 {
                    return Ok(());
                }
                let chunk = rbuf.split().freeze();
                counters.add_up(chunk.len() as u64);
                stream.send(chunk).await?;
                rbuf.reserve(READ_CHUNK);
            }
        };
        let download = async {
            loop {
                match stream.recv().await {
                    Ok(b) if !b.is_empty() => {
                        counters.add_down(b.len() as u64);
                        cw.write_all(&b).await?;
                    }
                    _ => return Ok(()),
                }
            }
        };
        tokio::select! {
            result = upload => result,
            result = download => result,
        }
    };
    let _ = stream.close().await;
    result
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
        incoming: Mutex<VecDeque<bytes::Bytes>>,
        recv_pends: bool,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl ProxyStream for FakeStream {
        async fn send(&self, data: bytes::Bytes) -> Result<()> {
            self.sent.lock().unwrap().extend_from_slice(&data);
            Ok(())
        }
        async fn recv(&self) -> Result<bytes::Bytes> {
            if let Some(chunk) = { self.incoming.lock().unwrap().pop_front() } {
                Ok(chunk)
            } else if self.recv_pends {
                std::future::pending::<()>().await;
                unreachable!()
            } else {
                Err(ClientError::ConnectFailed)
            }
        }
        async fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    struct BlockedSend {
        sending: tokio::sync::Notify,
        release: Arc<tokio::sync::Notify>,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl ProxyStream for BlockedSend {
        async fn send(&self, data: bytes::Bytes) -> Result<()> {
            // A partial write before blocking catches accidental cancellation/retry.
            self.sent.lock().unwrap().extend_from_slice(&data[..1]);
            self.sending.notify_one();
            self.release.notified().await;
            self.sent.lock().unwrap().extend_from_slice(&data[1..]);
            Ok(())
        }
        async fn recv(&self) -> Result<bytes::Bytes> {
            self.sending.notified().await;
            Ok(bytes::Bytes::from_static(b"reply"))
        }
        async fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn blocked_upload_does_not_block_download() {
        let (client, mut peer) = tokio::io::duplex(64);
        let release = Arc::new(tokio::sync::Notify::new());
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut stream = BlockedSend {
            sending: tokio::sync::Notify::new(),
            release: release.clone(),
            sent: sent.clone(),
        };
        let counters = Arc::new(ByteCounters::new());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let peer = async {
                peer.write_all(b"request").await.unwrap();
                let mut reply = [0; 5];
                peer.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"reply");
                assert_eq!(&*sent.lock().unwrap(), b"r");
                release.notify_one();
                peer.shutdown().await.unwrap();
            };
            let (result, ()) = tokio::join!(pump(client, &mut stream, counters.clone()), peer);
            result.unwrap();
        })
        .await
        .expect("blocked upload prevented reverse progress");
        assert_eq!(counters.totals(), (7, 5));
        assert_eq!(&*sent.lock().unwrap(), b"request");
    }

    #[tokio::test]
    async fn blocked_download_does_not_block_upload() {
        // The download chunk exceeds the entire local socket capacity. Do not drain
        // it until the upload has crossed the tunnel boundary.
        let (client, mut peer) = tokio::io::duplex(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut fake = FakeStream {
            incoming: Mutex::new(VecDeque::from([bytes::Bytes::from_static(
                b"download larger than socket",
            )])),
            recv_pends: true,
            sent: sent.clone(),
        };
        let counters = Arc::new(ByteCounters::new());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let peer_work = async {
                while counters.totals().1 == 0 {
                    tokio::task::yield_now().await;
                }
                peer.write_all(b"request").await.unwrap();
                while sent.lock().unwrap().is_empty() {
                    tokio::task::yield_now().await;
                }
                assert_eq!(&*sent.lock().unwrap(), b"request");
                let mut data = [0; 27];
                peer.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"download larger than socket");
                peer.shutdown().await.unwrap();
            };
            let (result, ()) = tokio::join!(pump(client, &mut fake, counters.clone()), peer_work);
            result.unwrap();
        })
        .await
        .expect("blocked download prevented reverse progress");
        assert_eq!(counters.totals(), (7, 27));
    }

    #[tokio::test]
    async fn pump_counts_upload() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut fake = FakeStream {
            incoming: Mutex::new(VecDeque::new()),
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
            incoming: Mutex::new(incoming),
            recv_pends: false, // after the one chunk, recv errors => EOF
            sent: sent.clone(),
        };
        let counters = Arc::new(ByteCounters::new());

        pump(client, &mut fake, counters.clone()).await.unwrap();

        assert_eq!(counters.totals().1, 7, "download bytes");
    }
}
