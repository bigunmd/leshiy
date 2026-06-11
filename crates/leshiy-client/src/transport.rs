//! Dialing seams. `Transport::dial` produces a live `Tunnel`; the supervisor shell
//! (Plan 3) is generic over `Transport`, so it can be driven by a mock in tests and
//! by the real REALITY/QUIC adapters in production.
use crate::error::Result;
use crate::settings::TransportPref;
use crate::stream::{DatagramFlow, ProxyStream};
use async_trait::async_trait;

/// A live tunnel to one server, capable of opening per-target streams.
#[async_trait]
pub trait Tunnel: Send + Sync {
    /// Open a new proxied stream to `target` ("host:port").
    async fn open(&self, target: &str) -> Result<Box<dyn ProxyStream>>;
    /// Open a UDP datagram association to `target` ("host:port").
    /// Default: unsupported — transports without datagram support (e.g. QUIC for now)
    /// inherit this and return `ConnectFailed`.
    async fn open_datagram(&self, _target: &str) -> Result<Box<dyn DatagramFlow>> {
        Err(crate::error::ClientError::ConnectFailed)
    }
    /// Resolves when the tunnel has dropped (the connection died). The supervisor
    /// `select!`s on this to trigger reconnect. Implementations without a usable
    /// close signal may never resolve.
    async fn closed(&self);
}

/// Dials a `leshiy://` URI and returns a live tunnel, or `ClientError::ConnectFailed`.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn dial(&self, uri: &str, pref: TransportPref) -> Result<Box<dyn Tunnel>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ClientError;

    struct DeadTunnel;
    #[async_trait]
    impl Tunnel for DeadTunnel {
        async fn open(&self, _target: &str) -> Result<Box<dyn ProxyStream>> {
            Err(ClientError::ConnectFailed)
        }
        async fn closed(&self) {
            // resolves immediately => "already dropped"
        }
    }

    struct OkOnce;
    #[async_trait]
    impl Transport for OkOnce {
        async fn dial(&self, _uri: &str, _pref: TransportPref) -> Result<Box<dyn Tunnel>> {
            Ok(Box::new(DeadTunnel))
        }
    }

    #[tokio::test]
    async fn transport_dials_a_tunnel() {
        let t = OkOnce;
        let tunnel = t.dial("leshiy://x", TransportPref::Auto).await.unwrap();
        // closed() resolves (DeadTunnel is already down).
        tunnel.closed().await;
        // open() surfaces the generic failure.
        assert!(matches!(
            tunnel.open("example.com:443").await,
            Err(ClientError::ConnectFailed)
        ));
    }
}
