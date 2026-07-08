//! HTTP/3 datagram plumbing for CONNECT-UDP (RFC 9298 over RFC 9297).
//!
//! HTTP datagrams ride QUIC DATAGRAM frames framed as `[Quarter Stream ID varint][payload]`
//! (RFC 9297 §2.1), where the quarter-stream-id ties the datagram to its CONNECT-UDP request
//! stream. We use [`h3_datagram::datagram::Datagram`] purely for that framing and quinn's
//! connection-level datagram API for I/O — this avoids borrowing the `h3::Connection` (which the
//! driver task owns) just to send/receive datagrams. The payload is the raw UDP datagram (both
//! ends are ours; we omit RFC 9298's context-id, which would otherwise be a leading `0` varint).
use bytes::{Buf, Bytes};
use h3::quic::StreamId;
use h3_datagram::datagram::Datagram;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

/// Per-connection demux table: quarter-stream-id (the raw request `StreamId` as `u64`) → the
/// channel feeding that association's inbound datagrams. Registered by each CONNECT-UDP handler.
pub(crate) type DatagramRegistry = Arc<Mutex<HashMap<u64, mpsc::Sender<Bytes>>>>;

/// A fresh, empty demux table for one QUIC connection.
pub(crate) fn new_registry() -> DatagramRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Frame `payload` as an HTTP datagram for `stream_id` and return the wire bytes for
/// `quinn::Connection::send_datagram`.
pub(crate) fn encode(stream_id: StreamId, payload: Bytes) -> Bytes {
    let mut enc = Datagram::new(stream_id, payload).encode();
    enc.copy_to_bytes(enc.remaining())
}

/// Read connection-level QUIC datagrams forever, decode the HTTP-datagram framing, and dispatch
/// each payload to the registered association by stream id. A datagram for an unknown/closed
/// stream is dropped. Exits when the connection closes.
pub(crate) async fn demux_loop(conn: quinn::Connection, registry: DatagramRegistry) {
    loop {
        let raw = match conn.read_datagram().await {
            Ok(b) => b,
            Err(_) => break, // connection closed
        };
        let Ok(dg) = Datagram::decode(raw) else {
            continue; // malformed quarter-stream-id
        };
        let key = dg.stream_id().into_inner();
        let payload = dg.into_payload();
        // Look up the association; drop the datagram if none (unknown/closed stream).
        let tx = {
            let map = registry.lock().await;
            map.get(&key).cloned()
        };
        if let Some(tx) = tx {
            // Best-effort: a full channel means the consumer is slow — dropping is correct for UDP.
            let _ = tx.try_send(payload);
        }
    }
}

/// Register an association's inbound channel; returns the receiver the relay reads from. Bounded so
/// a stalled association can't grow unboundedly (excess inbound datagrams are dropped, UDP-style).
pub(crate) async fn register(
    registry: &DatagramRegistry,
    stream_id: StreamId,
) -> mpsc::Receiver<Bytes> {
    let (tx, rx) = mpsc::channel(256);
    registry.lock().await.insert(stream_id.into_inner(), tx);
    rx
}

/// Remove an association from the demux table (on teardown).
pub(crate) async fn deregister(registry: &DatagramRegistry, stream_id: StreamId) {
    registry.lock().await.remove(&stream_id.into_inner());
}
