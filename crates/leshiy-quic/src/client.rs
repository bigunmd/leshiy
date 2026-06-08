//! QUIC client: HTTP/3 CONNECT per SOCKS5 connection (Task 2 — stub for Task 1).
//!
//! The full implementation (h3 client, per-connection CONNECT) is Task 2.
//! This stub compiles cleanly after codec.rs is removed.
use crate::{QuicError, Result};
use std::net::SocketAddr;

pub async fn run_quic_client(
    _server_addr: SocketAddr,
    _server_name: &str,
    _socks_addr: SocketAddr,
    _short_id: [u8; 8],
    _insecure_skip_verify: bool,
) -> Result<()> {
    Err(QuicError::Conn(
        "HTTP/3 client not yet implemented (Task 2)".into(),
    ))
}
