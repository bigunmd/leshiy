//! Human-facing CLI styling. THE rule: stdout = machine data, stderr = decoration.
//! Color is emitted only when stderr is a TTY and NO_COLOR is unset; all colored output
//! goes to stderr so stdout stays byte-for-byte parseable by scripts.

// Temporary: these helpers gain their callers in later CLI-polish tasks; this
// blanket allow is removed in the final cleanup task once every helper is used.
#![allow(dead_code)]

use anstyle::{AnsiColor, Style};
use std::io::IsTerminal;

const S_OK: Style = AnsiColor::Green.on_default().bold();
const S_ERR: Style = AnsiColor::Red.on_default().bold();
const S_WARN: Style = AnsiColor::Yellow.on_default();
const S_ID: Style = AnsiColor::Cyan.on_default().bold();
const S_VAL: Style = AnsiColor::Cyan.on_default();
const S_LABEL: Style = Style::new().dimmed();

/// True when stderr should carry ANSI color: a terminal, and `NO_COLOR` unset/empty.
pub fn color_stderr() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

/// Wrap `s` in `style`'s ANSI codes when `color`, else return it unchanged.
pub fn paint(s: &str, style: Style, color: bool) -> String {
    if color {
        format!("{}{s}{}", style.render(), style.render_reset())
    } else {
        s.to_string()
    }
}

pub fn id(s: &str) -> String {
    paint(s, S_ID, color_stderr())
}

pub fn value(s: &str) -> String {
    paint(s, S_VAL, color_stderr())
}

pub fn url(s: &str) -> String {
    paint(s, S_VAL, color_stderr())
}

pub fn label(s: &str) -> String {
    paint(s, S_LABEL, color_stderr())
}

/// A bold section heading.
pub fn heading(text: &str) -> String {
    paint(text, Style::new().bold(), color_stderr())
}

/// A `  <dim label, width 10> <value>` row (for show/created summaries).
pub fn field(label_text: &str, value_text: &str) -> String {
    format!(
        "  {} {}",
        paint(&format!("{label_text:<10}"), S_LABEL, color_stderr()),
        value_text
    )
}

/// Print a line to stderr (decoration channel). Color decision is made upstream by
/// `color_stderr()` and passed to `paint()`; callers provide plain strings when color
/// is off, ANSI strings when on. `anstream::eprintln!` is the stderr writer.
pub fn eline(s: &str) {
    anstream::eprintln!("{s}");
}

pub fn ok(msg: &str) {
    eline(&format!(
        "{} {msg}",
        paint("\u{2713}", S_OK, color_stderr())
    ));
}

pub fn warn(msg: &str) {
    eline(&format!(
        "{} {msg}",
        paint("warning:", S_WARN, color_stderr())
    ));
}

pub fn error(msg: &str) {
    eline(&format!("{} {msg}", paint("error:", S_ERR, color_stderr())));
}

pub fn hint(msg: &str) {
    eline(&paint(&format!("  {msg}"), S_LABEL, color_stderr()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paint_is_plain_when_color_off() {
        assert_eq!(paint("hello", S_OK, false), "hello");
    }

    #[test]
    fn paint_wraps_in_ansi_when_color_on() {
        let out = paint("hello", S_OK, true);
        assert!(out.contains("hello"));
        assert!(out.contains('\u{1b}'), "expected an ESC byte when color on");
        assert!(out.starts_with('\u{1b}') && out.ends_with("\u{1b}[0m"));
    }

    #[test]
    fn accents_are_plain_under_non_tty_tests() {
        // `cargo test` runs with a non-terminal stderr, so accents must be plain.
        assert_eq!(id("abcd"), "abcd");
        assert_eq!(value("10GB"), "10GB");
    }

    #[test]
    fn field_is_plain_and_padded_under_tests() {
        assert_eq!(field("sni", "www.x.com"), "  sni        www.x.com");
    }
}
