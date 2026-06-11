//! Userspace TCP/IP netstack construction. Isolated here so a future `netstack-smoltcp`
//! backend can replace `ipstack` without touching the engine's flow handling.
use ipstack::{IpStack, IpStackConfig};
use tun::AsyncDevice;

/// Build the userspace TCP/IP stack over the TUN device. `ipstack` reads/writes raw IP
/// packets on the device (which implements tokio `AsyncRead`/`AsyncWrite`) and yields
/// per-flow TCP/UDP streams from `IpStack::accept`.
pub fn build(device: AsyncDevice, mtu: u16) -> std::io::Result<IpStack> {
    let mut cfg = IpStackConfig::default();
    cfg.mtu(mtu)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(IpStack::new(cfg, device))
}
