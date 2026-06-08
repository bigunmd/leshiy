#![forbid(unsafe_code)]
//! Pure-Rust TLS 1.3 ClientHello fingerprinting + record plumbing for Leshiy's
//! REALITY-style camouflage. No TLS key schedule here (see M1.2+).

pub mod client_hello;
pub mod error;
pub mod fingerprint;
pub mod ja;
pub mod record;
pub mod server_hello;
pub mod tls13;

pub use error::{Result, TlsError};
pub use ja::{ClientHelloFields, MlKemClientShare, extract_client_hello_fields};
