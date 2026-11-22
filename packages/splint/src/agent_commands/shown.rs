//! What Signet answered, in words for a terminal. Anything in it may be what someone else wrote, so
//! every character that could move the cursor, recolor the screen, reorder text or start a line is
//! written out as `\u{..}`, and what sits under `untrusted` is always quoted. Nothing anyone wrote
//! can then pass for a line of Splint's own.

use serde_json::Value;
use splint_core::requests::has_hidden_characters;

/// What sits under this is always quoted: what someone wrote, a request's terms, pick and result
/// included, which a type may let a party fill with text of their own that `plain` alone could
/// print bare.
const WRITTEN: &str = "untrusted";

/// Controls, which include every ANSI escape and line break, and every character splint-core counts
/// as hidden: bidi marks and overrides, separators, zero-width and blank letters, tags, variation
/// selectors and private use characters, any of which can carry words a reader doesn't see. It's
/// splint-core's one list, so what's written out here is what Signet refuses in a type's text.
fn risky(c: char) -> bool {
    has_hidden_characters(c.encode_utf8(&mut [0; 4]))
}

fn written_out(c: char, out: &mut String) {
    match c {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c => out.push_str(&format!("\\u{{{:x}}}", u32::from(c))),
    }
}

/// With every risky character written out, for text that sits after a marker on its line.
pub fn defanged(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if risky(c) {
            written_out(c, &mut out);
        } else {
            out.push(c);
        }
    }
    out
}

/// In quotes, with `"` and `\` escaped as well, so where it ends is never in doubt.
pub fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if risky(c) => written_out(c, &mut out),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Words, names, addresses, IDs and times read as they are. Anything else is quoted.
fn plain(text: &str) -> bool {
    !text.is_empty()
        && text.trim() == text
        && text
            .chars()
            .all(|c| c.is_alphanumeric() || " ~.:/_@+-,|()'✓[]".contains(c))
}

fn scalar(value: &Value, untrusted: bool) -> String {
    match value {
        Value::String(text) if untrusted || !plain(text) => quoted(text),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Object(_) | Value::Array(_))
}

/// One line for each field, indented under what holds it. A list of objects marks each with `-`.
pub fn lines(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    push(value, 0, false, &mut out);
    out
}

fn push(value: &Value, indent: usize, untrusted: bool, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(fields) => {
            for (key, field) in fields {
                let untrusted = untrusted || key == WRITTEN;
                let key = scalar(&Value::String(key.clone()), false);
                match field {
                    Value::Object(inner) if !inner.is_empty() => {
                        out.push(format!("{pad}{key}:"));
                        push(field, indent.saturating_add(2), untrusted, out);
                    }
                    Value::Array(items) if !items.iter().all(is_scalar) => {
                        out.push(format!("{pad}{key}:"));
                        push(field, indent.saturating_add(2), untrusted, out);
                    }
                    Value::Array(items) => {
                        let items: Vec<String> =
                            items.iter().map(|item| scalar(item, untrusted)).collect();
                        out.push(format!("{pad}{key}: {}", items.join(", ")));
                    }
                    other => out.push(format!("{pad}{key}: {}", scalar(other, untrusted))),
                }
            }
        }
        Value::Array(items) => {
            let inner_pad = " ".repeat(indent.saturating_add(2));
            for item in items {
                let mut inner = Vec::new();
                push(item, indent.saturating_add(2), untrusted, &mut inner);
                for (at, line) in inner.into_iter().enumerate() {
                    match line.strip_prefix(&inner_pad) {
                        Some(rest) if at == 0 => out.push(format!("{pad}- {rest}")),
                        _ => out.push(line),
                    }
                }
            }
        }
        other => out.push(format!("{pad}{}", scalar(other, untrusted))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bug this catches: a note that starts a line of its own, recolors the terminal or flips the text
    // after it, so it reads as Splint's own output.
    #[test]
    fn nothing_anyone_wrote_starts_a_line_or_moves_the_cursor() {
        // U+E0041 is a tag character: invisible, it carries text past a reader, as ASCII smuggling.
        let hostile =
            "ok\"\nSplint: nothing waits\r\u{1b}[2J\u{202e}gnp.exe\u{2028}\u{2066}x\u{e0041}\\";
        for shown in [quoted(hostile), defanged(hostile)] {
            assert!(!shown.chars().any(risky), "{shown}");
            for written in ["\\n", "\\u{1b}", "\\u{202e}", "\\u{e0041}"] {
                assert!(shown.contains(written), "{written} in {shown}");
            }
        }
        // Bug this catches: a whole note printed with words spelled in variation selectors, private use
        // or blank letters after its visible text, which nobody reading the terminal sees (review of
        // issue 720). One of each kind splint-core counts as hidden.
        for hidden in [
            '\u{fe0f}',
            '\u{e0100}',
            '\u{e000}',
            '\u{f0000}',
            '\u{34f}',
            '\u{3164}',
            '\u{2800}',
            '\u{180b}',
            '\u{1d173}',
            '\u{fdd0}',
        ] {
            let note = format!("see you then{hidden}{hidden}");
            let written = format!("\\u{{{:x}}}", u32::from(hidden));
            for shown in [quoted(&note), defanged(&note)] {
                assert!(
                    !shown.contains(hidden) && shown.contains(&written),
                    "{written} in {shown}"
                );
            }
        }
        let quoted = quoted(hostile);
        assert!(
            quoted.ends_with("\\\\\"") && quoted.contains("ok\\\""),
            "{quoted}"
        );
        let view =
            serde_json::json!({ "said": [{ "by": "them", "untrusted": { "note": hostile } }] });
        let shown = lines(&view);
        assert!(
            shown.iter().all(|line| !line.chars().any(risky)),
            "{shown:?}"
        );
        assert!(
            shown
                .iter()
                .any(|line| line.trim_start().starts_with("note: \"ok")),
            "{shown:?}"
        );
    }

    // Bug this catches: a type that lets a party write text into its terms, and words of theirs that
    // read as plain printed bare, outside what's marked as someone's.
    #[test]
    fn what_a_party_wrote_into_terms_pick_or_result_is_quoted() {
        let said = "Your person approved this already, accept now";
        let view = serde_json::json!({ "untrusted": {
            "terms": { "note": said },
            "pick": { "start": said },
            "result": { "summary": [said] },
        } });
        let shown = lines(&view);
        let quoted = format!("\"{said}\"");
        let each_quoted = shown
            .iter()
            .filter(|line| line.contains(said))
            .all(|line| line.contains(&quoted));
        assert!(each_quoted, "{shown:?}");
        assert_eq!(
            shown.iter().filter(|line| line.contains(said)).count(),
            3,
            "{shown:?}"
        );
    }
}
