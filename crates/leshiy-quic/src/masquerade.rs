//! Web masquerade served to probers / unauthorized clients (the anti-probe cover).

/// The cover response that unauthorised or unrecognised clients receive.
#[derive(Clone)]
pub enum Masquerade {
    /// Serve this HTML as 200 for "/" and a 404 for other paths.
    Page(String),
}

impl Default for Masquerade {
    fn default() -> Self {
        Masquerade::Page(
            "<!doctype html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"
                .to_string(),
        )
    }
}
