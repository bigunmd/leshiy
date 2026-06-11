//! Pre-session network discovery: the original default gateway, captured *before* any
//! routing change, so the server-IP exception can point at it.
use net_route::Handle;
use std::net::IpAddr;

/// The current IPv4 default gateway. Reads the live routing table; call this before
/// installing the tunnel's override routes.
pub async fn default_gateway_v4() -> std::io::Result<IpAddr> {
    let handle = Handle::new()?;
    for r in handle.list().await? {
        if r.prefix == 0
            && r.destination.is_ipv4()
            && let Some(gw) = r.gateway
            && gw.is_ipv4()
        {
            return Ok(gw);
        }
    }
    Err(std::io::Error::other("no IPv4 default gateway found"))
}
