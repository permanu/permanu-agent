//! Strict JSON parsing and RFC 8785 canonicalization restricted to the
//! signed-plan value domain (signed-plan.md section 2).

use std::fmt::Write as _;

use serde_json::Value;

use super::strict_json::reject_duplicate_fields;

/// Largest integer magnitude JCS allows (2^53 − 1).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Parses `bytes` as strict JSON: size bound, UTF-8, no duplicate keys and
/// integers only (no fractions, exponents, NaN or unsafe magnitudes).
pub(crate) fn parse_strict(bytes: &[u8], max_bytes: usize) -> Option<Value> {
    if bytes.len() > max_bytes || std::str::from_utf8(bytes).is_err() {
        return None;
    }
    reject_duplicate_fields(bytes).ok()?;
    if contains_non_integer_literal(bytes) {
        return None;
    }
    let value: Value = serde_json::from_slice(bytes).ok()?;
    integers_only(&value).then_some(value)
}

/// `serde_json` turns `1.0` into a float and `1e3` into a float, which
/// `integers_only` rejects. A literal such as `-0` stays an integer. This scan
/// rejects any number token with a fraction or exponent outside strings, so
/// e.g. `1E0` cannot slip through as an integral float either.
fn contains_non_integer_literal(bytes: &[u8]) -> bool {
    let mut in_string = false;
    let mut escaped = false;
    let mut previous_significant = b' ';
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'.' | b'e' | b'E' if previous_significant.is_ascii_digit() => return true,
            _ => {}
        }
        if !byte.is_ascii_whitespace() {
            previous_significant = byte;
        }
    }
    false
}

fn integers_only(value: &Value) -> bool {
    match value {
        Value::Number(number) => number
            .as_i64()
            .map(i64::unsigned_abs)
            .or_else(|| number.as_u64())
            .is_some_and(|magnitude| magnitude <= MAX_SAFE_INTEGER),
        Value::Array(items) => items.iter().all(integers_only),
        Value::Object(map) => map.values().all(integers_only),
        Value::Null | Value::Bool(_) | Value::String(_) => true,
    }
}

/// Returns the JCS text of `value`, or `None` for values outside the domain.
pub(crate) fn canonicalize(value: &Value) -> Option<String> {
    let mut output = String::new();
    encode(value, &mut output)?;
    Some(output)
}

fn encode(value: &Value, output: &mut String) -> Option<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => {
            if !integers_only(value) {
                return None;
            }
            output.push_str(&number.to_string());
        }
        Value::String(text) => encode_string(text, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                encode(item, output)?;
            }
            output.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            output.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                encode_string(key, output);
                output.push(':');
                encode(&map[key], output)?;
            }
            output.push('}');
        }
    }
    Some(())
}

fn encode_string(text: &str, output: &mut String) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            control if u32::from(control) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", u32::from(control));
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parse_rejects_duplicates_floats_and_unsafe_integers() {
        assert!(parse_strict(br#"{"a":1}"#, 64).is_some());
        assert!(parse_strict(br#"{"a":1,"a":1}"#, 64).is_none());
        assert!(parse_strict(br#"{"a":1.0}"#, 64).is_none());
        assert!(parse_strict(br#"{"a":1e3}"#, 64).is_none());
        assert!(parse_strict(br#"{"a":1E0}"#, 64).is_none());
        assert!(parse_strict(br#"{"a":9007199254740992}"#, 64).is_none());
        assert!(parse_strict(br#"{"a":-9007199254740991}"#, 64).is_some());
        assert!(parse_strict(br#"{"a":"1.0e5"}"#, 64).is_some());
        assert!(parse_strict(br#"{"a":NaN}"#, 64).is_none());
        assert!(parse_strict(br#"{"a":1}"#, 6).is_none());
        assert!(parse_strict(br#"{"a":"\ud800"}"#, 64).is_none());
    }
}
