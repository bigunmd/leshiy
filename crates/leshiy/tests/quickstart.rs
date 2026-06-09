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

#[test]
fn quickstart_entry_role_wires_connector_from_exit_uri() {
    let bin = env!("CARGO_BIN_EXE_leshiy");
    let dir = std::env::temp_dir().join(format!("leshiy-conn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. Stand up an EXIT (quic required) and capture its share URI from the JSON summary.
    let exit_out = dir.join("exit.toml");
    let out = std::process::Command::new(bin)
        .args([
            "quickstart",
            "--role",
            "exit",
            "--host",
            "198.51.100.7:443",
            "--dest",
            "www.cloudflare.com:443",
            "--quic-listen",
            "198.51.100.7:443",
            "--out",
            exit_out.to_str().unwrap(),
            "--no-probe",
            "--summary-json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "exit stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let exit_uri = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .find(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .and_then(|v| v["uri"].as_str().map(String::from))
        .expect("exit uri");

    // 2. Stand up an ENTRY pointing at that exit URI; its config must carry connector=.
    let entry_out = dir.join("entry.toml");
    let out2 = std::process::Command::new(bin)
        .args([
            "quickstart",
            "--role",
            "entry",
            "--host",
            "203.0.113.9:443",
            "--dest",
            "www.microsoft.com:443",
            "--exit-uri",
            &exit_uri,
            "--out",
            entry_out.to_str().unwrap(),
            "--no-probe",
        ])
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "entry stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let cfg = std::fs::read_to_string(&entry_out).unwrap();
    assert!(
        cfg.contains("connector ="),
        "entry config must set connector:\n{cfg}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn quickstart_exit_role_requires_quic() {
    let bin = env!("CARGO_BIN_EXE_leshiy");
    let dir = std::env::temp_dir().join(format!("leshiy-exitq-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = std::process::Command::new(bin)
        .args([
            "quickstart",
            "--role",
            "exit",
            "--host",
            "198.51.100.7:443",
            "--dest",
            "www.cloudflare.com:443",
            "--out",
            dir.join("x.toml").to_str().unwrap(),
            "--no-probe",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "exit role without --quic-listen must fail"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("quic"),
        "error should mention quic requirement"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn quickstart_entry_role_requires_exit_uri() {
    let bin = env!("CARGO_BIN_EXE_leshiy");
    let dir = std::env::temp_dir().join(format!("leshiy-entq-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = std::process::Command::new(bin)
        .args([
            "quickstart",
            "--role",
            "entry",
            "--host",
            "203.0.113.9:443",
            "--dest",
            "www.microsoft.com:443",
            "--out",
            dir.join("x.toml").to_str().unwrap(),
            "--no-probe",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "entry role without --exit-uri must fail"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("exit-uri"),
        "error should mention --exit-uri requirement"
    );
    std::fs::remove_dir_all(&dir).ok();
}
