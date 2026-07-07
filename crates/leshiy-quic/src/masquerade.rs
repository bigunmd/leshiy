//! Web masquerade served to probers / unauthorized clients (the anti-probe cover).

/// The cover response that unauthorised or unrecognised clients receive.
#[derive(Clone)]
pub enum Masquerade {
    /// Serve this HTML as 200 for "/" and a 404 for other paths. Simple, but a single canned
    /// page is trivially distinguishable from the real site the SNI/cert claim to be.
    Page(String),
    /// Reverse-proxy the unauthorized request to a real HTTP backend (`host:port`) the operator
    /// runs as the cover, and relay its response — a credible site instead of a stub. Mirrors how
    /// the REALITY TCP path borrows a genuine `dest`. Falls back to a 502 page if the origin is
    /// unreachable.
    Reverse(String),
}

impl Default for Masquerade {
    fn default() -> Self {
        Masquerade::Page(
            "<!doctype html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"
                .to_string(),
        )
    }
}

/// A response fetched from a reverse-proxy origin: HTTP status + raw body bytes.
pub(crate) struct OriginResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Fetch `method path` from an HTTP/1.1 origin (`host:port`) over plain TCP, mirroring the
/// prober's method and path. Uses `Connection: close` so the body is delimited by EOF (no
/// chunked/keep-alive parsing needed). Returns the origin's status + body, or `None` on any error
/// (caller then serves a 502) — best-effort, never panics.
pub(crate) async fn fetch_origin(origin: &str, method: &str, path: &str) -> Option<OriginResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Bound the origin dial+read so a slow/hostile backend can't pin the prober handler.
    const ORIGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let host = origin.rsplit_once(':').map(|(h, _)| h).unwrap_or(origin);
    let path = if path.is_empty() { "/" } else { path };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    let work = async {
        let mut sock = tokio::net::TcpStream::connect(origin).await.ok()?;
        sock.write_all(req.as_bytes()).await.ok()?;
        sock.flush().await.ok()?;
        let mut raw = Vec::new();
        sock.read_to_end(&mut raw).await.ok()?;
        parse_http_response(&raw)
    };
    tokio::time::timeout(ORIGIN_TIMEOUT, work)
        .await
        .ok()
        .flatten()
}

/// Parse a raw HTTP/1.1 response into (status, body). Returns `None` if the status line or the
/// header/body delimiter is missing/malformed.
fn parse_http_response(raw: &[u8]) -> Option<OriginResponse> {
    // Split headers from body on the first CRLFCRLF.
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = &raw[..sep];
    let body = raw.get(sep + 4..).unwrap_or(&[]).to_vec();
    // Status line: "HTTP/1.1 200 OK" — take the second whitespace-separated token.
    let first_line = head.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(first_line).ok()?;
    let status = line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    Some(OriginResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>hi</h1>";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"<h1>hi</h1>");
    }

    #[test]
    fn rejects_response_without_header_delimiter() {
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nno end").is_none());
    }

    #[test]
    fn parses_non_200_status() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\nnope";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"nope");
    }
}
