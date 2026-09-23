//! `redaction-v1` (agent-protocol.md 9.6), normative: runs before every
//! write to the telemetry store and before every M1-path `QueryLogs` return.
//!
//! Best-effort and pattern-based (signed-plan.md R11): the agent never holds
//! secret values, so it cannot redact by value. Rules 1-7 run in order on a
//! string, each a global replace; rule 8 replaces the whole value of a map
//! entry whose key is wholly `K` or one of the listed OTel/HTTP keys.
//!
//! The patterns are RE2 syntax with ASCII classes; they are compiled as byte
//! regexes with Unicode off, which matches RE2 (and the reference, Python
//! `re.ASCII`): `\b`, `\s` and `(?i)` are ASCII-only. Every match starts and
//! ends next to an ASCII byte, so replacing never splits a UTF-8 sequence.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::bytes::{Regex, RegexBuilder};

/// `GetTelemetryUsageResponse.redaction_rules_version`.
pub const RULES_VERSION: &str = "redaction-v1";
pub const REPLACEMENT: &str = "[REDACTED]";
/// Rule 1 across stream lines: at most 200 lines from `BEGIN` through `END`.
pub const PEM_STREAM_MAX_LINES: u32 = 200;

/// `K`, the key pattern, as section 9.6 prints it (without the leading
/// `(?i)`, which is scoped where `K` sits inside a larger pattern).
const K_BODY: &str = r"\b(?:[a-z0-9]+[_.-])*(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|authorization|auth[_-]?token|session[_-]?(?:id|token)|cookie|database[_-]?url|dsn|conn(?:ection)?[_-]?string)(?:[_.-][a-z0-9]+)*\b";

/// Rule 2, in section 9.6 order.
const TOKEN_FORMATS: [&str; 15] = [
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
    r"\bglpat-[A-Za-z0-9_-]{20,}\b",
    r"\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b",
    r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+",
    r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
    r"\bwhsec_[A-Za-z0-9]{16,}\b",
    r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b",
    r"\bAIza[0-9A-Za-z_-]{35}\b",
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b",
    r"\bnpm_[A-Za-z0-9]{36}\b",
    r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
];

/// Rule 8: keys whose whole value is always replaced.
const STRUCTURED_KEYS: [&str; 7] = [
    "http.request.header.authorization",
    "http.request.header.proxy-authorization",
    "http.request.header.cookie",
    "http.request.header.x-api-key",
    "http.response.header.set-cookie",
    "db.connection_string",
    "url.userinfo",
];

struct Rules {
    pem: Regex,
    pem_begin: Regex,
    pem_end: Regex,
    tokens: Vec<Regex>,
    url_userinfo: Regex,
    auth_scheme: Regex,
    json_member: Regex,
    assignment: Regex,
    cli_flag: Regex,
    key_whole: Regex,
}

fn compile(pattern: &str) -> Regex {
    // The patterns are constants; a failure is a programming error caught
    // by every test in this module.
    RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(16 * 1024 * 1024)
        .build()
        .unwrap_or_else(|err| panic!("redaction-v1 pattern does not compile: {err}"))
}

static RULES: LazyLock<Rules> = LazyLock::new(|| {
    let k = format!("(?i:{K_BODY})");
    Rules {
        pem: compile(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        ),
        pem_begin: compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        pem_end: compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----"),
        tokens: TOKEN_FORMATS.iter().map(|p| compile(p)).collect(),
        url_userinfo: compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/?#@:]*:[^\s/?#@]*@"),
        auth_scheme: compile(r"(?i)\b(bearer|basic|digest)\s+[A-Za-z0-9._~+/=-]{8,}"),
        json_member: compile(&format!(
            r#"("{k}"\s*:\s*)("(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*|true|false)"#
        )),
        assignment: compile(&format!(
            r#"({k})(\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&"'<>]+)"#
        )),
        cli_flag: compile(&format!(r"(?i)(--?{k})(=|\s+)(\S+)")),
        key_whole: compile(&format!(r"\A(?:{k})\z")),
    }
});

fn replace<'a>(text: Cow<'a, [u8]>, regex: &Regex, with: &[u8]) -> Cow<'a, [u8]> {
    match regex.replace_all(&text, with) {
        Cow::Borrowed(_) => text,
        Cow::Owned(changed) => Cow::Owned(changed),
    }
}

/// Rules 1-7 on one string. `Cow::Borrowed` when nothing matched.
pub fn redact(input: &str) -> Cow<'_, str> {
    let rules = &*RULES;
    let mut text: Cow<'_, [u8]> = Cow::Borrowed(input.as_bytes());
    text = replace(text, &rules.pem, REPLACEMENT.as_bytes());
    for token in &rules.tokens {
        text = replace(text, token, REPLACEMENT.as_bytes());
    }
    text = replace(text, &rules.url_userinfo, b"${1}[REDACTED]@");
    text = replace(text, &rules.auth_scheme, b"${1} [REDACTED]");
    text = replace(text, &rules.json_member, b"${1}\"[REDACTED]\"");
    text = replace(text, &rules.assignment, b"${1}${2}[REDACTED]");
    text = replace(text, &rules.cli_flag, b"${1}${2}[REDACTED]");
    match text {
        Cow::Owned(bytes) if bytes != input.as_bytes() => {
            Cow::Owned(match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
            })
        }
        // Unchanged, or replaced by identical text (already redacted).
        _ => Cow::Borrowed(input),
    }
}

/// Rules 1-7 in place; true when the string changed.
pub fn redact_in_place(value: &mut String) -> bool {
    match redact(value) {
        Cow::Borrowed(_) => false,
        Cow::Owned(changed) => {
            *value = changed;
            true
        }
    }
}

/// Rule 8: true when a map entry with this key loses its whole value.
pub fn is_secret_key(key: &str) -> bool {
    STRUCTURED_KEYS.contains(&key) || RULES.key_whole.is_match(key.as_bytes())
}

/// Rule 8 on one entry; true when the value changed.
pub fn redact_entry(key: &str, value: &mut String) -> bool {
    if is_secret_key(key) {
        if value == REPLACEMENT {
            return false;
        }
        *value = REPLACEMENT.to_owned();
        return true;
    }
    redact_in_place(value)
}

/// Rule 8 on a map (fields, attributes, headers); true when any changed.
#[cfg(test)]
pub fn redact_map<S: std::hash::BuildHasher>(
    map: &mut std::collections::HashMap<String, String, S>,
) -> bool {
    let mut changed = false;
    for (key, value) in map.iter_mut() {
        changed |= redact_entry(key, value);
    }
    changed
}

/// Rule 1 across the lines of one container stream (`stdout` or `stderr`
/// of one container): the `BEGIN` line and every following line up to the
/// `END` line (200 lines at most) become `[REDACTED]`; every other line
/// gets rules 1-7 on its own.
#[derive(Debug, Default, Clone)]
pub struct PemStream {
    left: u32,
}

impl PemStream {
    /// The redacted line and whether it changed.
    pub fn line(&mut self, line: &str) -> (String, bool) {
        let rules = &*RULES;
        let bytes = line.as_bytes();
        if self.left == 0 && rules.pem_begin.is_match(bytes) && !rules.pem_end.is_match(bytes) {
            self.left = PEM_STREAM_MAX_LINES;
        }
        if self.left > 0 {
            self.left = if rules.pem_end.is_match(bytes) {
                0
            } else {
                self.left - 1
            };
            return (REPLACEMENT.to_owned(), line != REPLACEMENT);
        }
        match redact(line) {
            Cow::Borrowed(same) => (same.to_owned(), false),
            Cow::Owned(changed) => (changed, true),
        }
    }

    /// True while inside a key block.
    #[cfg(test)]
    pub fn open(&self) -> bool {
        self.left > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;

    fn cases() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/redaction/cases.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// Every vendored contract vector (contracts-v1.1.1) passes: output and
    /// the `redacted` flag.
    #[test]
    fn redaction_v1_vectors_pass() {
        let doc = cases();
        assert_eq!(doc["version"], RULES_VERSION);
        assert_eq!(doc["replacement"], REPLACEMENT);
        let cases = doc["cases"].as_array().unwrap();
        assert!(cases.len() >= 50);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let want_redacted = case["redacted"].as_bool().unwrap();
            match case["kind"].as_str().unwrap() {
                "string" => {
                    let input = case["input"].as_str().unwrap();
                    let mut value = input.to_owned();
                    let changed = redact_in_place(&mut value);
                    assert_eq!(value, case["expected"].as_str().unwrap(), "{name}");
                    assert_eq!(changed, want_redacted, "{name}");
                }
                "fields" => {
                    let mut map: HashMap<String, String> =
                        serde_json::from_value(case["input"].clone()).unwrap();
                    let want: HashMap<String, String> =
                        serde_json::from_value(case["expected"].clone()).unwrap();
                    let changed = redact_map(&mut map);
                    assert_eq!(map, want, "{name}");
                    assert_eq!(changed, want_redacted, "{name}");
                }
                "stream" => {
                    let mut stream = PemStream::default();
                    let mut changed = false;
                    let out: Vec<String> = case["input"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|line| {
                            let (text, c) = stream.line(line.as_str().unwrap());
                            changed |= c;
                            text
                        })
                        .collect();
                    let want: Vec<String> =
                        serde_json::from_value(case["expected"].clone()).unwrap();
                    assert_eq!(out, want, "{name}");
                    assert_eq!(changed, want_redacted, "{name}");
                }
                other => panic!("{name}: unknown kind {other}"),
            }
        }
    }

    /// K and the rule 2 formats are the ones section 9.6 prints, checked
    /// against the docs checkout when it sits next to this repo.
    #[test]
    fn patterns_match_the_contract_text() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let Some(contract) = [manifest.join("../docs"), manifest.join("../../docs")]
            .into_iter()
            .map(|d| d.join("contracts/agent-protocol.md"))
            .find(|p| p.exists())
        else {
            eprintln!("skipped: docs checkout not found");
            return;
        };
        let text = std::fs::read_to_string(contract).unwrap();
        let section = &text[text.find("### 9.6 ").unwrap()..text.find("### 9.7 ").unwrap()];
        let k_line = section.lines().find(|l| l.starts_with("`K` = `")).unwrap();
        assert_eq!(
            k_line,
            format!("`K` = `(?i){K_BODY}`"),
            "K differs from agent-protocol.md 9.6"
        );
        let row = section.lines().find(|l| l.starts_with("| 2 |")).unwrap();
        let cell = row.split(" | ").nth(2).unwrap();
        let formats: Vec<String> = cell
            .split(" · ")
            .map(|p| {
                p.trim()
                    .trim_end_matches(" (JWT)")
                    .trim_matches('`')
                    .replace("\\|", "|")
            })
            .collect();
        assert_eq!(formats, TOKEN_FORMATS.map(str::to_owned).to_vec());
    }

    #[test]
    fn untouched_text_is_borrowed_and_utf8_survives() {
        assert!(matches!(redact("plain line é ✓"), Cow::Borrowed(_)));
        assert_eq!(
            redact("clé password=sécret ✓ ok"),
            "clé password=[REDACTED] ✓ ok"
        );
    }

    #[test]
    fn pem_stream_caps_at_200_lines() {
        let mut stream = PemStream::default();
        assert_eq!(
            stream
                .line(&format!("-----BEGIN RSA {} KEY-----", "PRIVATE"))
                .0,
            REPLACEMENT
        );
        for _ in 0..199 {
            assert_eq!(stream.line("AAAA").0, REPLACEMENT);
        }
        assert!(!stream.open());
        assert_eq!(stream.line("after").0, "after");
    }
}
