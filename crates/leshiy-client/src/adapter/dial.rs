//! `RealTransport`: dials a `leshiy://` URI to a live tunnel, with QUIC-first
//! auto-fallback ported from the CLI client.
use crate::adapter::quic::QuicTunnel;
use crate::adapter::reality::RealityTunnel;
use crate::error::{ClientError, Result};
use crate::settings::TransportPref;
use crate::transport::{Transport, Tunnel};
use async_trait::async_trait;
use leshiy_quic::client::{QuicConn, connect_quic};
use leshiy_quic::endpoint::CertVerification;
use leshiy_reality::client::connect_reality;
use leshiy_reality::config::{QuicEndpoint, RealityUri};
use std::time::Duration;

const HEAD_START: Duration = Duration::from_millis(200);
const QUIC_TIMEOUT: Duration = Duration::from_secs(3);
const REALITY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The production transport: dials real REALITY/QUIC connections.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealTransport;

#[async_trait]
impl Transport for RealTransport {
    async fn dial(&self, uri: &str, pref: TransportPref) -> Result<Box<dyn Tunnel>> {
        let parsed = RealityUri::parse(uri).map_err(|_| ClientError::ConnectFailed)?;
        match pref {
            TransportPref::Tcp => dial_reality(&parsed).await,
            TransportPref::Quic => dial_quic(&parsed).await,
            TransportPref::Auto => dial_auto(&parsed).await,
        }
    }
}

async fn dial_reality(parsed: &RealityUri) -> Result<Box<dyn Tunnel>> {
    // Bound the connect+handshake so an explicit `Tcp`-pref dial against a server that
    // accepts the TCP connection but then stalls (a common DPI/blackhole behavior) can't
    // hang the supervisor forever — it fails, and the backoff schedules a retry. The
    // `Auto` path already wraps REALITY in this timeout; do the same for the direct path.
    let conn = tokio::time::timeout(
        REALITY_CONNECT_TIMEOUT,
        connect_reality(&parsed.server_addr, parsed.client.clone()),
    )
    .await
    .map_err(|_| ClientError::ConnectFailed)? // elapsed
    .map_err(|_| ClientError::ConnectFailed)?; // connect/handshake error
    Ok(Box::new(RealityTunnel { conn }))
}

async fn dial_quic(parsed: &RealityUri) -> Result<Box<dyn Tunnel>> {
    let q = parsed.quic.clone().ok_or(ClientError::ConnectFailed)?;
    let conn = connect_quic_from(&q, parsed.client.short_id).await?;
    Ok(Box::new(QuicTunnel { conn }))
}

async fn dial_auto(parsed: &RealityUri) -> Result<Box<dyn Tunnel>> {
    let Some(q) = parsed.quic.clone() else {
        return dial_reality(parsed).await;
    };
    // Pre-warm REALITY after a head start; prefer QUIC.
    let raddr = parsed.server_addr.clone();
    let rcfg = parsed.client.clone();
    let reality = tokio::spawn(async move {
        tokio::time::sleep(HEAD_START).await;
        tokio::time::timeout(REALITY_CONNECT_TIMEOUT, connect_reality(&raddr, rcfg)).await
    });

    let short_id = parsed.client.short_id;
    match tokio::time::timeout(QUIC_TIMEOUT, connect_quic_from(&q, short_id)).await {
        Ok(Ok(conn)) => {
            reality.abort();
            Ok(Box::new(QuicTunnel { conn }))
        }
        _ => match reality.await {
            Ok(Ok(Ok(conn))) => Ok(Box::new(RealityTunnel { conn })),
            _ => Err(ClientError::ConnectFailed),
        },
    }
}

async fn connect_quic_from(q: &QuicEndpoint, short_id: [u8; 8]) -> Result<QuicConn> {
    // M2: never silently fall back to public-CA validation. The QUIC transport's
    // only strong server binding is the cert pin (qcert=); without it, anyone who
    // can present a publicly-trusted cert for the SNI could terminate the tunnel.
    // Refuse the unpinned QUIC path so dial() falls back to the pinned REALITY
    // transport instead of downgrading.
    let Some(pin) = q.cert_sha256 else {
        // No qcert= pin → skip QUIC entirely; dial() falls back to REALITY.
        return Err(ClientError::ConnectFailed);
    };
    let verification = CertVerification::Pinned(pin);
    let addr = tokio::net::lookup_host(&q.addr)
        .await
        .map_err(|_| ClientError::ConnectFailed)?
        .next()
        .ok_or(ClientError::ConnectFailed)?;
    connect_quic(addr, &q.sni, short_id, verification)
        .await
        .map_err(|_| ClientError::ConnectFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quic_without_pin_is_refused() {
        // No qcert= pin must NOT silently downgrade to public-CA validation (M2):
        // connect_quic_from returns an error so dial() falls back to REALITY.
        let q = QuicEndpoint {
            addr: "127.0.0.1:1".into(),
            sni: "example.com".into(),
            cert_sha256: None,
        };
        assert!(connect_quic_from(&q, [0u8; 8]).await.is_err());
    }
}
