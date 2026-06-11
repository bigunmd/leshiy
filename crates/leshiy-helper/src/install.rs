//! Installation surface: the canonical control-socket path and an existence probe the
//! unprivileged caller (CLI + Phase 5 GUI) uses to decide whether the privileged helper
//! is installed — *without* elevating. The privileged self-install/uninstall lives in the
//! daemon binary's `install`/`uninstall` subcommands (Task 4.7b); this module is the
//! read-only side the GUI calls via `leshiy_helper::is_installed()`.
use std::path::{Path, PathBuf};

/// The canonical control-socket path the helper binds and the caller connects to.
/// The systemd unit and `install` subcommand both use this.
pub fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/leshiy/helper.sock")
}

/// True if the helper appears installed: the default control socket exists. The GUI calls
/// this (no-arg) to gate the lazy install dialog. Path-parameterized for testability.
pub fn is_installed() -> bool {
    socket_present(&default_socket_path())
}

/// Pure existence check on a given socket path (the testable core of `is_installed`).
fn socket_present(p: &Path) -> bool {
    p.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_is_the_canonical_run_path() {
        assert_eq!(
            default_socket_path(),
            std::path::PathBuf::from("/run/leshiy/helper.sock")
        );
    }

    #[test]
    fn socket_present_is_false_for_missing_and_true_after_create() {
        let dir = std::env::temp_dir().join(format!("leshiy-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(format!(
            "probe-{}.sock",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(
            !socket_present(&p),
            "missing path must read as not-installed"
        );
        std::fs::write(&p, b"").unwrap();
        assert!(
            socket_present(&p),
            "an existing path must read as installed"
        );
        let _ = std::fs::remove_file(&p);
    }
}
