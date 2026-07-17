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

/// A response fetched from a reverse-proxy origin: HTTP status, an allowlist of forwarded
/// headers, and the raw body bytes.
pub(crate) struct OriginResponse {
    pub status: u16,
    /// Allowlisted response headers to forward to the client, so the masqueraded H3 response
    /// carries the same content-type/caching metadata a genuine H3 fetch of the origin would —
    /// closing a fidelity gap that a prober could otherwise use to distinguish the cover (M8).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Response headers safe to forward verbatim from the origin. Lowercased for case-insensitive
/// matching. Deliberately excludes hop-by-hop / framing headers (`content-length`,
/// `transfer-encoding`, `connection`, `set-cookie`, …) which h3 sets itself or which would leak
/// origin state.
const FORWARDED_HEADERS: &[&str] = &[
    "content-type",
    "cache-control",
    "last-modified",
    "etag",
    "content-language",
    "vary",
    "expires",
];

/// Maximum origin body buffered in memory. A prober repeatedly requesting a large backend
/// resource must not be able to OOM the server; anything larger is truncated (M6).
const MAX_ORIGIN_BODY: u64 = 2 * 1024 * 1024;

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
        // Cap the buffered body so a large backend resource can't be used to exhaust memory (M6).
        let mut raw = Vec::new();
        (&mut sock)
            .take(MAX_ORIGIN_BODY)
            .read_to_end(&mut raw)
            .await
            .ok()?;
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
    let mut lines = head.split(|&b| b == b'\n');
    let first_line = lines.next()?;
    let line = std::str::from_utf8(first_line).ok()?;
    let status = line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    // Collect allowlisted headers (each "Name: value", trailing CR trimmed) to forward (M8).
    let mut headers = Vec::new();
    for raw_line in lines {
        let Ok(l) = std::str::from_utf8(raw_line) else {
            continue;
        };
        let l = l.trim_end_matches(['\r', '\n']);
        if let Some((name, value)) = l.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            if FORWARDED_HEADERS.contains(&name.as_str()) {
                headers.push((name, value.trim().to_string()));
            }
        }
    }
    Some(OriginResponse {
        status,
        headers,
        body,
    })
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

    /// M8: allowlisted response headers are captured (lowercased) for forwarding, while
    /// framing/hop-by-hop headers are dropped.
    #[test]
    fn captures_allowlisted_headers_only() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 9\r\nCache-Control: max-age=60\r\nSet-Cookie: sid=secret\r\nConnection: close\r\n\r\n<h1>hi</h1>";
        let r = parse_http_response(raw).unwrap();
        assert!(
            r.headers
                .contains(&("content-type".into(), "text/html; charset=utf-8".into()))
        );
        assert!(
            r.headers
                .contains(&("cache-control".into(), "max-age=60".into()))
        );
        // Framing / stateful headers must NOT be forwarded.
        assert!(r.headers.iter().all(|(n, _)| n != "content-length"));
        assert!(r.headers.iter().all(|(n, _)| n != "set-cookie"));
        assert!(r.headers.iter().all(|(n, _)| n != "connection"));
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
