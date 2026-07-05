#![forbid(unsafe_code)]
//! Remote leshiy server provisioning: SSH transport, Docker orchestration,
//! an encrypted server vault, and a progress-emitting provisioning engine.

pub mod docker;
pub mod engine;
pub mod error;
pub mod ssh;
mod ssh_russh;
pub mod vault;

pub use error::{Error, Result};
pub use ssh_russh::RusshTransport;

#[cfg(test)]
mod smoke {
    #[test]
    fn crate_builds() {
        assert_eq!(2 + 2, 4);
    }
}
