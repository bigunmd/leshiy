//! `leshiy quickstart`: wizard orchestration on top of `server::init`.
//! Domain logic only (no host mutation) — emits a machine-readable summary the
//! installer consumes.

/// Render a URI as a terminal QR code (UTF-8 half-block string).
// Consumed by the quickstart subcommand wired up in a later task.
#[allow(dead_code)]
pub fn qr_string(uri: &str) -> String {
    use qrcode::QrCode;
    use qrcode::render::unicode;
    let code = QrCode::new(uri.as_bytes()).expect("uri always encodable as QR");
    code.render::<unicode::Dense1x2>().quiet_zone(true).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_renders_nonempty_block_art() {
        let s = qr_string("leshiy://abc@203.0.113.5:443?sni=www.microsoft.com&sid=00");
        assert!(s.contains('█') || s.contains('▀') || s.contains('▄'));
        assert!(s.lines().count() > 10);
    }
}
