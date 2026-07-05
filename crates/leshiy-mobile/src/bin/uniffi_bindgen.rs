//! Foreign-language binding generator, pinned to this crate's uniffi version.
//! Usage: `cargo run -p leshiy-mobile --bin uniffi-bindgen -- generate \
//!   --library <path/to/libleshiy_mobile.so> --language kotlin --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main()
}
