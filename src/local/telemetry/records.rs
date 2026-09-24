//! Record encodings inside segments (agent-owned, store version 1) and the
//! log record parsing of agent-protocol.md 9.4: level, trace ids and JSON
//! fields, after redaction.

use std::collections::HashMap;

use prost::Message;
use serde_json::Value;

use super::redaction;
use crate::proto::agent::v2::LogLevel;

/// `logs`: a `LogRecord` (cursor empty).
pub const TAG_LOG: u8 = 1;
/// `traces`: a `Span`.
pub const TAG_SPAN: u8 = 1;
/// `traces`: a settled trace's `TraceSummary` (cursor empty).
pub const TAG_TRACE_SUMMARY: u8 = 2;
/// `metrics`: a [`MetricSample`].
pub const TAG_METRIC: u8 = 1;

/// One stored 60 s Dwaar rollup (`analytics`, tag 1): the fields of
/// `AnalyticsRow` (so an `AnalyticsRow` decoder still reads it) plus the
/// ids of the service whose route host it counts (D-060, D-063 #9; empty
/// for a host no service owns).
#[derive(Clone, PartialEq, prost::Message)]
pub struct StoredAnalyticsRow {
    #[prost(message, optional, tag = "1")]
    pub bucket_start: Option<prost_types::Timestamp>,
    #[prost(message, repeated, tag = "2")]
    pub dimensions: Vec<crate::proto::agent::v2::AnalyticsDimensionValue>,
    #[prost(message, repeated, tag = "3")]
    pub values: Vec<crate::proto::agent::v2::AnalyticsMeasureValue>,
    #[prost(string, tag = "16")]
    pub service_id: String,
    #[prost(string, tag = "17")]
    pub project_id: String,
    #[prost(string, tag = "18")]
    pub environment_id: String,
}

/// 9.4: lines longer than 16 KiB are split.
pub const MAX_LINE_BYTES: usize = 16 * 1024;
/// 9.4: JSON lines keep ≤ 32 top-level scalar fields, values ≤ 1 KiB.
const MAX_FIELDS: usize = 32;
const MAX_FIELD_BYTES: usize = 1024;

/// One metric point as stored.
#[derive(Clone, PartialEq, prost::Message)]
pub struct MetricSample {
    #[prost(string, tag = "1")]
    pub name: String,
    /// `MetricDescriptor.Kind`.
    #[prost(int32, tag = "2")]
    pub kind: i32,
    /// `MetricSource`.
    #[prost(int32, tag = "3")]
    pub source: i32,
    #[prost(string, tag = "4")]
    pub unit: String,
    #[prost(btree_map = "string, string", tag = "5")]
    pub labels: std::collections::BTreeMap<String, String>,
    /// Gauge or counter value; histogram sum.
    #[prost(double, tag = "6")]
    pub value: f64,
    /// Histogram explicit bounds and bucket counts (`bounds.len() + 1`).
    #[prost(double, repeated, tag = "7")]
    pub bounds: Vec<f64>,
    #[prost(uint64, repeated, tag = "8")]
    pub counts: Vec<u64>,
    #[prost(string, tag = "9")]
    pub description: String,
    /// Counter and histogram values are cumulative (else delta).
    #[prost(bool, tag = "10")]
    pub cumulative: bool,
}

pub fn encode<M: Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

/// Truncates to at most `max` bytes on a char boundary.
pub fn truncate(text: &mut String, max: usize) {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

/// 9.4: splits a line into pieces of at most 16 KiB (on char boundaries).
pub fn split_line(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while rest.len() > MAX_LINE_BYTES {
        let mut end = MAX_LINE_BYTES;
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        out.push(&rest[..end]);
        rest = &rest[end..];
    }
    out.push(rest);
    out
}

fn level_name(name: &str) -> Option<LogLevel> {
    Some(match name.to_ascii_lowercase().as_str() {
        "trace" | "trc" => LogLevel::Trace,
        "debug" | "dbg" => LogLevel::Debug,
        "info" | "inf" | "notice" | "information" => LogLevel::Info,
        "warn" | "warning" | "wrn" => LogLevel::Warn,
        "error" | "err" | "eror" => LogLevel::Error,
        "fatal" | "critical" | "crit" | "panic" | "emerg" | "alert" | "ftl" => LogLevel::Fatal,
        _ => return None,
    })
}

/// OTel severity numbers (1-24).
pub fn level_of_severity(number: i64) -> LogLevel {
    match number {
        1..=4 => LogLevel::Trace,
        5..=8 => LogLevel::Debug,
        9..=12 => LogLevel::Info,
        13..=16 => LogLevel::Warn,
        17..=20 => LogLevel::Error,
        21..=24 => LogLevel::Fatal,
        _ => LogLevel::Unspecified,
    }
}

fn level_value(value: &Value) -> Option<LogLevel> {
    match value {
        Value::String(name) => level_name(name).or_else(|| {
            name.parse::<i64>()
                .ok()
                .map(level_of_severity)
                .filter(|l| *l != LogLevel::Unspecified)
        }),
        Value::Number(n) => n
            .as_i64()
            .map(level_of_severity)
            .filter(|l| *l != LogLevel::Unspecified),
        _ => None,
    }
}

fn hex_id(value: Option<&Value>, len: usize) -> Option<String> {
    let text = value?.as_str()?;
    (text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then(|| text.to_owned())
}

/// What 9.4 derives from one (already redacted) line.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parsed {
    pub level: LogLevel,
    pub trace_id: String,
    pub span_id: String,
    pub fields: HashMap<String, String>,
    /// A field value changed by rule 8.
    pub redacted: bool,
}

/// Level, in order: a JSON object line's `level`/`severity`/`lvl`/
/// `levelname` (names or OTel severity numbers), a logfmt `level=`, a
/// leading `[LEVEL]` or `LEVEL:` token; otherwise `UNSPECIFIED`. JSON lines
/// also give trace and span ids and their top-level scalars as `fields`
/// (rule 8 applied, ≤ 32 fields, values truncated to 1 KiB after redaction).
pub fn parse_line(line: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let trimmed = line.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(trimmed) {
            parsed.level = ["level", "severity", "lvl", "levelname"]
                .iter()
                .find_map(|k| map.get(*k).and_then(level_value))
                .unwrap_or(LogLevel::Unspecified);
            parsed.trace_id =
                hex_id(map.get("trace_id").or(map.get("traceId")), 32).unwrap_or_default();
            parsed.span_id =
                hex_id(map.get("span_id").or(map.get("spanId")), 16).unwrap_or_default();
            for (key, value) in &map {
                if parsed.fields.len() == MAX_FIELDS {
                    break;
                }
                let mut text = match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => continue,
                };
                let mut key = key.clone();
                truncate(&mut key, 256);
                parsed.redacted |= redaction::redact_entry(&key, &mut text);
                truncate(&mut text, MAX_FIELD_BYTES);
                parsed.fields.insert(key, text);
            }
            return parsed;
        }
    }
    parsed.level = logfmt_level(line)
        .or_else(|| leading_level(trimmed))
        .unwrap_or(LogLevel::Unspecified);
    parsed
}

fn logfmt_level(line: &str) -> Option<LogLevel> {
    line.split_ascii_whitespace().find_map(|token| {
        let value = token.strip_prefix("level=")?;
        level_name(value.trim_matches('"'))
    })
}

fn leading_level(line: &str) -> Option<LogLevel> {
    if let Some(rest) = line.strip_prefix('[') {
        let (name, _) = rest.split_once(']')?;
        return level_name(name.trim());
    }
    let token = line.split_ascii_whitespace().next()?;
    level_name(token.strip_suffix(':')?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_follow_the_contract_order() {
        let cases = [
            (r#"{"level":"warn","msg":"x"}"#, LogLevel::Warn),
            (r#"{"severity":17}"#, LogLevel::Error),
            (r#"{"lvl":"DEBUG"}"#, LogLevel::Debug),
            (r#"{"levelname":"CRITICAL"}"#, LogLevel::Fatal),
            ("time=1 level=info msg=hi", LogLevel::Info),
            ("[ERROR] boom", LogLevel::Error),
            ("WARN: disk", LogLevel::Warn),
            ("plain line on stderr", LogLevel::Unspecified),
            ("{not json", LogLevel::Unspecified),
        ];
        for (line, want) in cases {
            assert_eq!(parse_line(line).level, want, "{line}");
        }
    }

    #[test]
    fn json_lines_give_ids_and_redacted_fields() {
        let line = r#"{"level":"info","traceId":"0123456789abcdef0123456789abcdef","span_id":"0123456789abcdef","password":"hunter2","user":"alice","n":3,"nested":{"a":1},"bad_trace":"XYZ"}"#;
        let p = parse_line(line);
        assert_eq!(p.trace_id, "0123456789abcdef0123456789abcdef");
        assert_eq!(p.span_id, "0123456789abcdef");
        assert_eq!(p.fields["password"], "[REDACTED]");
        assert_eq!(p.fields["user"], "alice");
        assert_eq!(p.fields["n"], "3");
        assert!(!p.fields.contains_key("nested"));
        assert!(p.redacted);
        let upper = parse_line(r#"{"trace_id":"0123456789ABCDEF0123456789ABCDEF"}"#);
        assert_eq!(upper.trace_id, "");
    }

    #[test]
    fn long_lines_split_at_16_kib_on_char_boundaries() {
        let line = "é".repeat(MAX_LINE_BYTES);
        let parts = split_line(&line);
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|p| p.len() <= MAX_LINE_BYTES));
        assert_eq!(parts.concat(), line);
        assert_eq!(split_line("short"), vec!["short"]);
    }

    #[test]
    fn metric_samples_round_trip() {
        let mut s = MetricSample {
            name: "host.cpu.percent".into(),
            value: 12.5,
            ..Default::default()
        };
        s.labels.insert("cpu".into(), "all".into());
        let bytes = encode(&s);
        assert_eq!(MetricSample::decode(bytes.as_slice()).unwrap(), s);
    }
}
