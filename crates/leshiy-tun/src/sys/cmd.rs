//! Small `unsafe`-free helpers for the macOS/Windows backends: run a privileged
//! command and map a non-zero exit to an `io::Error`, plus pure argument builders
//! (unit-tested) so command construction is verifiable without invoking anything.
//!
//! The runner functions (`run`/`run_capture`) are compiled only for the real macOS /
//! Windows targets where the backends use them; the pure argument-builders also compile
//! under `test`, so they (and their unit tests) run on the Linux host via `cargo test`.

/// Run `program args...`, mapping spawn failure or a non-zero exit to `io::Error`.
/// Best-effort callers (teardown) ignore the `Result`; setup callers propagate it.
// `allow(dead_code)`: the Windows backend starts consuming this in Task 3.7; until then
// the cross-target check would flag it unused. Remove the allow once it has a caller.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[allow(dead_code)]
pub fn run(program: &str, args: &[&str]) -> std::io::Result<()> {
    let out = std::process::Command::new(program).args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Run a command and return its captured stdout as a `String` (trimmed).
/// Used to read state we must restore later (e.g. the current DNS servers).
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[allow(dead_code)]
pub fn run_capture(program: &str, args: &[&str]) -> std::io::Result<String> {
    let out = std::process::Command::new(program).args(args).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(std::io::Error::other(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}
