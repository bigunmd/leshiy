//! Pure builders for the shell commands the engine runs over SSH. No I/O here,
//! so every command shape is unit-tested.

/// Probe whether docker is on PATH. Prints `yes`/`no`.
pub fn detect_docker_cmd() -> &'static str {
    "command -v docker >/dev/null 2>&1 && echo yes || echo no"
}

/// Install Docker by sniffing the available package manager.
pub fn install_docker_cmd() -> &'static str {
    "set -e; \
     if command -v apt-get >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y docker.io; \
     elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y docker; \
     elif command -v yum >/dev/null 2>&1; then sudo yum install -y docker; \
     elif command -v zypper >/dev/null 2>&1; then sudo zypper install -y docker; \
     elif command -v pacman >/dev/null 2>&1; then sudo pacman -Sy --noconfirm docker; \
     else echo 'no supported package manager' >&2; exit 1; fi; \
     sudo systemctl enable --now docker"
}

pub fn pull_cmd(image_ref: &str) -> String {
    format!("sudo docker pull {image_ref}")
}

/// `docker run` for the leshiy server. REALITY is TCP; QUIC (if any) is UDP.
pub fn run_cmd(
    container: &str,
    image_ref: &str,
    reality_port: u16,
    quic_port: Option<u16>,
) -> String {
    let mut s = format!(
        "sudo docker run -d --name {container} --restart=unless-stopped \
         --cap-add=NET_ADMIN -p {reality_port}:{reality_port}"
    );
    if let Some(q) = quic_port {
        s.push_str(&format!(" -p {q}:{q}/udp"));
    }
    s.push_str(&format!(" {image_ref}"));
    s
}

pub fn ps_names_cmd() -> &'static str {
    "sudo docker ps --format '{{.Names}}'"
}

pub fn exec_user_add_cmd(container: &str, extra_args: &str) -> String {
    format!(
        "sudo docker exec {container} leshiy user add --config /etc/leshiy/server.toml {extra_args}"
    )
}

pub fn exec_user_list_json_cmd(container: &str) -> String {
    format!("sudo docker exec {container} leshiy user list --json --config /etc/leshiy/server.toml")
}

pub fn exec_user_rm_cmd(container: &str, short_id: &str) -> String {
    format!(
        "sudo docker exec {container} leshiy user rm {short_id} --config /etc/leshiy/server.toml"
    )
}

pub fn parse_ps_names(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_and_run_shape() {
        assert_eq!(
            pull_cmd("ghcr.io/x/leshiy:1.4.0"),
            "sudo docker pull ghcr.io/x/leshiy:1.4.0"
        );
        let run = run_cmd("leshiy", "img:1", 443, Some(8443));
        assert!(run.contains("--name leshiy"));
        assert!(run.contains("--restart=unless-stopped"));
        assert!(run.contains("--cap-add=NET_ADMIN"));
        assert!(run.contains("-p 443:443"));
        assert!(run.contains("-p 8443:8443/udp"));
        assert!(run.contains("img:1"));
    }

    #[test]
    fn run_without_quic_has_no_udp_port() {
        let run = run_cmd("leshiy", "img:1", 443, None);
        assert!(!run.contains("/udp"));
    }

    #[test]
    fn parse_ps_extracts_names() {
        assert_eq!(parse_ps_names("leshiy\nother\n\n"), vec!["leshiy", "other"]);
        assert!(parse_ps_names("").is_empty());
    }

    #[test]
    fn exec_user_add_targets_container() {
        let c = exec_user_add_cmd("leshiy", "--label self");
        assert_eq!(
            c,
            "sudo docker exec leshiy leshiy user add --config /etc/leshiy/server.toml --label self"
        );
    }

    #[test]
    fn user_list_json_and_rm_shapes() {
        assert_eq!(
            exec_user_list_json_cmd("leshiy"),
            "sudo docker exec leshiy leshiy user list --json --config /etc/leshiy/server.toml"
        );
        assert_eq!(
            exec_user_rm_cmd("leshiy", "0102030400000000"),
            "sudo docker exec leshiy leshiy user rm 0102030400000000 --config /etc/leshiy/server.toml"
        );
    }
}
