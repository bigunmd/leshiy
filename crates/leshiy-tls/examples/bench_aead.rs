//! AEAD throughput micro-benchmark for the REALITY data-plane suites (Phase 2).
//!
//! Measures `aead_seal` + `aead_open` over a representative record size for each
//! TLS 1.3 suite, on whatever target it is built for. Use it to confirm the ARMv8
//! hardware-AES win on a real arm64 device:
//!
//!   # software (default): build WITHOUT the .cargo/config cfgs
//!   cargo run --release --example bench_aead -p leshiy-tls --target aarch64-linux-android
//!   # hardware: the workspace .cargo/config.toml enables --cfg aes_armv8 for aarch64,
//!   # so a normal cross-build already includes it — compare against a build that
//!   # removes those cfgs.
//!
//! AES-128/256-GCM should jump several-fold on devices with crypto extensions;
//! ChaCha20-Poly1305 is the software baseline either way.
use leshiy_tls::tls13::suite::CipherSuite;
use std::time::Instant;

fn bench(suite: CipherSuite, record_len: usize, iters: usize) {
    let key = vec![0x42u8; suite.key_len()];
    let nonce = [0x24u8; 12];
    let aad = [0x16u8, 0x03, 0x03, 0x04, 0x00];
    let pt = vec![0x5au8; record_len];

    // Warm up (one-time key schedule etc.).
    let ct = suite.aead_seal(&key, &nonce, &aad, &pt).expect("seal");
    let _ = suite.aead_open(&key, &nonce, &aad, &ct).expect("open");

    let t0 = Instant::now();
    for _ in 0..iters {
        let ct = suite.aead_seal(&key, &nonce, &aad, &pt).expect("seal");
        let pt2 = suite.aead_open(&key, &nonce, &aad, &ct).expect("open");
        std::hint::black_box(&pt2);
    }
    let elapsed = t0.elapsed();
    // Each iter does one seal + one open over record_len bytes.
    let bytes = (iters as u64) * (record_len as u64) * 2;
    let mbps = (bytes as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("{suite:?}: {mbps:8.1} MiB/s  ({iters} iters x {record_len} B, seal+open)");
}

fn main() {
    const RECORD: usize = 1400; // typical MTU-sized record
    const ITERS: usize = 200_000;
    println!("AEAD seal+open throughput ({RECORD} B records):");
    bench(CipherSuite::Aes128GcmSha256, RECORD, ITERS);
    bench(CipherSuite::Aes256GcmSha384, RECORD, ITERS);
    bench(CipherSuite::ChaCha20Poly1305Sha256, RECORD, ITERS);
}
