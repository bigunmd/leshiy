#![forbid(unsafe_code)]
//! TUN-based full-tunnel engine: device → userspace netstack → leshiy `Tunnel`.
//!
//! VPN mode treats the TUN device as a new traffic *source* feeding the existing tunnel.
//! `ipstack` terminates per-flow TCP/UDP from raw IP packets; each flow is bridged to a
//! mux `Stream` (TCP) or datagram association (UDP). This crate performs privileged
//! operations (TUN creation, routing, DNS) but holds no privilege of its own — the
//! process must already be root / `CAP_NET_ADMIN` (the CLI) or be handed the device by
//! the privileged helper (the GUI, a later phase).

pub mod discover;
pub mod engine;
pub mod netstack;
pub mod route_plan;
pub mod sys;

pub use engine::{TunConfig, TunEngine};
pub use route_plan::RoutePlan;
