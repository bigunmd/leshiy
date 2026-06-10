//! Minimal runnable client: dial a `leshiy://` URI and serve a local SOCKS5 proxy,
//! printing connection state and live throughput.
//!
//! Usage: `cargo run -p leshiy-client --example connect -- <leshiy://…> [socks_addr]`
//! (Default socks_addr 127.0.0.1:1080. No system proxy is set — point your app/browser
//! at the SOCKS5 port. Ctrl-C to quit.)
use leshiy_client::adapter::RealTransport;
use leshiy_client::{NoopProxy, SupervisorConfig, TransportPref, spawn_supervisor};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let uri = args
        .next()
        .expect("usage: connect <leshiy://…> [socks_addr=127.0.0.1:1080]");
    let socks = args.next().unwrap_or_else(|| "127.0.0.1:1080".to_string());
    let socks_addr: std::net::SocketAddr = socks.parse().expect("invalid socks addr");

    let cfg = SupervisorConfig {
        socks_addr,
        pref: TransportPref::Auto,
        ..SupervisorConfig::default()
    };
    println!("leshiy: SOCKS5 proxy on {socks_addr}; connecting…");

    let handle = spawn_supervisor(RealTransport, NoopProxy, cfg);
    let mut state_rx = handle.subscribe_state();
    let mut stats_rx = handle.subscribe_stats();
    handle.connect(uri);

    loop {
        tokio::select! {
            r = state_rx.changed() => {
                if r.is_err() { break; }
                println!("[state] {:?}", *state_rx.borrow());
            }
            r = stats_rx.changed() => {
                if r.is_err() { break; }
                let s = *stats_rx.borrow();
                println!(
                    "[stats] down {} B/s  up {} B/s  (total down {} up {})",
                    s.down_bps, s.up_bps, s.total_down, s.total_up
                );
            }
        }
    }
}
