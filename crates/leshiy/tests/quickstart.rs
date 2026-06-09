// Drives the `leshiy quickstart` binary non-interactively and checks it writes a
// config and prints a machine-readable summary line the installer can parse.
use std::process::Command;

#[test]
fn quickstart_writes_config_and_emits_summary() {
    let dir = std::env::temp_dir().join(format!("leshiy-qs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("server.toml");
    let bin = env!("CARGO_BIN_EXE_leshiy");
    let output = Command::new(bin)
        .args([
            "quickstart",
            "--host",
            "203.0.113.5:443",
            "--dest",
            "www.microsoft.com:443",
            "--out",
            out.to_str().unwrap(),
            "--no-probe",
            "--summary-json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("a JSON summary line");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert!(v["uri"].as_str().unwrap().starts_with("leshiy://"));
    assert_eq!(v["listen"].as_str().unwrap(), "0.0.0.0:443");
    assert!(out.exists());
    std::fs::remove_dir_all(&dir).ok();
}
