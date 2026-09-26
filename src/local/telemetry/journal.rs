//! Host units on the runner's log stream (agent-protocol.md 9.4 "Host
//! units", signed-plan.md 14.3; contracts v1.1.2, D-060): the allowlist,
//! journald priorities, and the Dwaar access-log records that feed the
//! `http` store and the 60 s `analytics` rollups (9.1, 9.6).
//!
//! Only `dwaar.service`, `permanu-runner@*.service`,
//! `permanu-buildkitd@*.service` and `docker.service` are accepted; any
//! other unit is dropped and counted (AGENTS.md: no broad host collection).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::proto::agent::v2::{
    AnalyticsDimension, AnalyticsDimensionValue, AnalyticsMeasure, AnalyticsMeasureValue,
    AnalyticsRow, LogLevel, LogSourceType,
};

/// What an allowlisted unit's lines are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    /// `dwaar.service`: `DWAAR` records in the `http` store.
    Dwaar,
    /// `docker.service`, `permanu-runner@*.service`: `HOST` records.
    Host,
    /// `permanu-buildkitd@<project_id>.service`: that project's `BUILD`.
    Build { project_id: String },
}

fn instance_ok(instance: &str) -> bool {
    (1..=128).contains(&instance.len())
        && instance
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// The allowlist of section 9.4, or `None` for any other unit.
pub fn classify(unit: &str) -> Option<Unit> {
    match unit {
        "dwaar.service" => return Some(Unit::Dwaar),
        "docker.service" => return Some(Unit::Host),
        _ => {}
    }
    let instance = |prefix: &str| {
        unit.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(".service"))
            .filter(|i| instance_ok(i))
    };
    if instance("permanu-runner@").is_some() {
        return Some(Unit::Host);
    }
    instance("permanu-buildkitd@")
        .filter(|project| super::store::valid_id(project))
        .map(|project| Unit::Build {
            project_id: project.to_owned(),
        })
}

/// A journald cursor as the agent keeps it (opaque, bounded, printable).
pub fn cursor_ok(cursor: &str) -> bool {
    (1..=512).contains(&cursor.len()) && cursor.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// journald priority (0 emerg … 7 debug) to a log level.
pub fn level_of(priority: i64) -> LogLevel {
    match priority {
        0..=2 => LogLevel::Fatal,
        3 => LogLevel::Error,
        4 => LogLevel::Warn,
        5 | 6 => LogLevel::Info,
        7 => LogLevel::Debug,
        _ => LogLevel::Unspecified,
    }
}

pub fn source_type_of(unit: &Unit) -> LogSourceType {
    match unit {
        Unit::Dwaar => LogSourceType::Dwaar,
        Unit::Host => LogSourceType::Host,
        Unit::Build { .. } => LogSourceType::Build,
    }
}

/// Request and response headers that are never stored (9.6 "HTTP").
const DROPPED_FIELDS: &[&str] = &[
    "authorization",
    "proxy_authorization",
    "proxy-authorization",
    "cookie",
    "set_cookie",
    "set-cookie",
];

pub fn drop_header_fields(fields: &mut HashMap<String, String>) {
    fields.retain(|name, _| !DROPPED_FIELDS.contains(&name.to_ascii_lowercase().as_str()));
    // 9.6: the client address is stored truncated to /24 or /48 whatever
    // the proxy wrote; anything that is not an address is dropped.
    if let Some(ip) = fields.remove("client_ip") {
        if let Some(truncated) = truncate_ip(&ip) {
            fields.insert("client_ip".to_owned(), truncated);
        }
    }
}

/// An address truncated to its /24 (IPv4) or /48 (IPv6) network.
pub fn truncate_ip(text: &str) -> Option<String> {
    match text.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            Some(std::net::Ipv4Addr::new(a, b, c, 0).to_string())
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0).to_string())
        }
    }
}

/// One Dwaar access-log line (its JSON request log), as far as the
/// rollups need it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Access {
    pub host: String,
    /// The request path (the `dwaar.*` `route_path` template's input).
    pub path: String,
    pub method: String,
    pub status: u16,
    pub response_time_us: u64,
    pub bytes_sent: u64,
    pub client_ip: String,
    pub user_agent: String,
    pub is_bot: bool,
    /// `Referer` or `referrer`, as written. Empty when the line has neither.
    pub referrer: String,
    /// `country` as written. Empty when the line has none.
    pub country: String,
}

/// Parses a Dwaar request-log line; `None` for any other Dwaar output.
pub fn access_of(line: &str) -> Option<Access> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    let host = value["host"].as_str()?;
    let status = u16::try_from(value["status"].as_u64()?).ok()?;
    value["request_id"].as_str()?;
    let host = host
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(host, |(name, _)| name)
        .to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let path: String = value["path"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .take(2_048)
        .collect();
    Some(Access {
        host,
        path,
        method: value["method"].as_str().unwrap_or_default().to_owned(),
        status,
        response_time_us: value["response_time_us"].as_u64().unwrap_or_default(),
        bytes_sent: value["bytes_sent"].as_u64().unwrap_or_default(),
        client_ip: value["client_ip"].as_str().unwrap_or_default().to_owned(),
        user_agent: value["user_agent"].as_str().unwrap_or_default().to_owned(),
        is_bot: value["is_bot"].as_bool().unwrap_or(false),
        referrer: value["referer"]
            .as_str()
            .or_else(|| value["referrer"].as_str())
            .unwrap_or_default()
            .to_owned(),
        country: value["country"].as_str().unwrap_or_default().to_owned(),
    })
}

/// Referrer domain (`REFERRER`): `direct` when absent, `internal` when it is
/// this route host, `unknown` when it is not a host.
fn referrer_domain(referrer: &str, host: &str) -> String {
    let trimmed = referrer.trim();
    if trimmed.is_empty() {
        return "direct".to_owned();
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let name = authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .map(|(name, _)| name)
        .unwrap_or(authority);
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return "unknown".to_owned();
    }
    if name == host {
        "internal".to_owned()
    } else {
        name
    }
}

/// ISO 3166-1 alpha-2, or `XX` when the line has none.
fn country_code(country: &str) -> String {
    let country = country.trim();
    if country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        country.to_ascii_uppercase()
    } else {
        "XX".to_owned()
    }
}

/// `mobile`, `desktop`, `tablet`, `bot` or `unknown`.
fn device_class(user_agent: &str, is_bot: bool) -> &'static str {
    let ua = user_agent.to_ascii_lowercase();
    if is_bot || ua.contains("bot") || ua.contains("spider") || ua.contains("crawler") {
        "bot"
    } else if ua.contains("ipad") || ua.contains("tablet") {
        "tablet"
    } else if ua.contains("mobile") || ua.contains("iphone") || ua.contains("android") {
        "mobile"
    } else if ua.is_empty() {
        "unknown"
    } else {
        "desktop"
    }
}

#[derive(Debug, Default)]
struct Minute {
    requests: u64,
    page_views: u64,
    bots: u64,
    errors: u64,
    bytes: u64,
    visitors: HashSet<[u8; 16]>,
    latencies_ms: Vec<f64>,
}

/// One closed-minute series: the route host plus the dimensions
/// `QueryAnalytics` groups by (`PATH`, `REFERRER`, `COUNTRY`, `DEVICE`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SeriesKey {
    minute: i64,
    host: String,
    path: String,
    referrer: String,
    country: String,
    device: String,
}

/// Per-minute Dwaar rollups (analytics, 9.1): one `AnalyticsRow` per route
/// host and per path, referrer domain, country and device, for each closed
/// minute. `DOMAIN` stays the first dimension (attribution reads it). Unique
/// visitors use a daily salted hash of address and user agent; the salt
/// lives only in memory and changes at 00:00 UTC (9.6).
pub struct Rollups {
    minutes: BTreeMap<SeriesKey, Minute>,
    salt: [u8; 32],
    salt_day: i64,
}

/// Latency samples kept per series (percentiles are over these).
const MAX_SAMPLES: usize = 10_000;
/// Series per minute; more are dropped from the rollup (not from `http`).
const MAX_HOSTS: usize = 1_000;

/// A random salt; all zero only if the OS RNG fails, which then only
/// weakens the visitor hash (it is never stored or sent).
fn fresh_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    if getrandom::getrandom(&mut salt).is_err() {
        tracing::warn!("no randomness for the analytics salt");
    }
    salt
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

impl Default for Rollups {
    fn default() -> Self {
        Self::new()
    }
}

impl Rollups {
    pub fn new() -> Self {
        Self {
            minutes: BTreeMap::new(),
            salt: fresh_salt(),
            salt_day: i64::MIN,
        }
    }

    /// Adds one request at `sec` (Unix seconds).
    pub fn add(&mut self, sec: i64, access: &Access) {
        let day = sec.div_euclid(86_400);
        if day != self.salt_day {
            self.salt = fresh_salt();
            self.salt_day = day;
        }
        let minute = sec - sec.rem_euclid(60);
        let key = SeriesKey {
            minute,
            host: access.host.clone(),
            path: super::dwaar_metrics::route_path(&access.path),
            referrer: referrer_domain(&access.referrer, &access.host),
            country: country_code(&access.country),
            device: device_class(&access.user_agent, access.is_bot).to_owned(),
        };
        let series = self
            .minutes
            .keys()
            .filter(|existing| existing.minute == minute)
            .count();
        if series >= MAX_HOSTS && !self.minutes.contains_key(&key) {
            return;
        }
        let entry = self.minutes.entry(key).or_default();
        entry.requests += 1;
        entry.bytes += access.bytes_sent;
        if access.is_bot {
            entry.bots += 1;
        }
        if access.status >= 500 {
            entry.errors += 1;
        }
        if !access.is_bot && access.method.eq_ignore_ascii_case("GET") && access.status < 400 {
            entry.page_views += 1;
        }
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(access.client_ip.as_bytes());
        hasher.update([0]);
        hasher.update(access.user_agent.as_bytes());
        let mut visitor = [0u8; 16];
        visitor.copy_from_slice(&hasher.finalize()[..16]);
        entry.visitors.insert(visitor);
        if entry.latencies_ms.len() < MAX_SAMPLES {
            entry
                .latencies_ms
                .push(access.response_time_us as f64 / 1_000.0);
        }
    }

    /// Removes and returns the rows of every minute that closed before
    /// `now_sec` (a minute closes 60 s after it starts).
    pub fn closed(&mut self, now_sec: i64) -> Vec<AnalyticsRow> {
        let open_from = now_sec - now_sec.rem_euclid(60);
        let closed: Vec<SeriesKey> = self
            .minutes
            .keys()
            .filter(|key| key.minute < open_from)
            .cloned()
            .collect();
        closed
            .into_iter()
            .filter_map(|key| {
                let minute = self.minutes.remove(&key)?;
                Some(row_of(key, minute))
            })
            .collect()
    }
}

fn dimension(dimension: AnalyticsDimension, value: String) -> AnalyticsDimensionValue {
    AnalyticsDimensionValue {
        dimension: dimension as i32,
        value,
    }
}

fn row_of(key: SeriesKey, mut minute: Minute) -> AnalyticsRow {
    minute.latencies_ms.sort_by(f64::total_cmp);
    let measure = |measure: AnalyticsMeasure, value: f64| AnalyticsMeasureValue {
        measure: measure as i32,
        value,
    };
    let requests = minute.requests as f64;
    AnalyticsRow {
        bucket_start: Some(prost_types::Timestamp {
            seconds: key.minute,
            nanos: 0,
        }),
        dimensions: vec![
            dimension(AnalyticsDimension::Domain, key.host),
            dimension(AnalyticsDimension::Path, key.path),
            dimension(AnalyticsDimension::Referrer, key.referrer),
            dimension(AnalyticsDimension::Country, key.country),
            dimension(AnalyticsDimension::Device, key.device),
        ],
        values: vec![
            measure(AnalyticsMeasure::Requests, requests),
            measure(AnalyticsMeasure::PageViews, minute.page_views as f64),
            measure(
                AnalyticsMeasure::UniqueVisitors,
                minute.visitors.len() as f64,
            ),
            measure(AnalyticsMeasure::BytesSent, minute.bytes as f64),
            measure(
                AnalyticsMeasure::LatencyP50Ms,
                percentile(&minute.latencies_ms, 0.50),
            ),
            measure(
                AnalyticsMeasure::LatencyP95Ms,
                percentile(&minute.latencies_ms, 0.95),
            ),
            measure(
                AnalyticsMeasure::LatencyP99Ms,
                percentile(&minute.latencies_ms, 0.99),
            ),
            measure(
                AnalyticsMeasure::ErrorRate,
                if requests > 0.0 {
                    minute.errors as f64 / requests
                } else {
                    0.0
                },
            ),
            measure(AnalyticsMeasure::BotRequests, minute.bots as f64),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_allowlisted_units_are_accepted() {
        assert_eq!(classify("dwaar.service"), Some(Unit::Dwaar));
        assert_eq!(classify("docker.service"), Some(Unit::Host));
        assert_eq!(classify("permanu-runner@7-1000.service"), Some(Unit::Host));
        assert_eq!(
            classify("permanu-buildkitd@01a0cdb5-3500-70b1-8000-000000000001.service"),
            Some(Unit::Build {
                project_id: "01a0cdb5-3500-70b1-8000-000000000001".to_owned()
            })
        );
        for other in [
            "sshd.service",
            "permanu-runner@.service",
            "permanu-buildkitd@../x.service",
            "dwaar.service.d",
            "permanu-agent.service",
            "",
        ] {
            assert_eq!(classify(other), None, "{other}");
        }
    }

    #[test]
    fn priorities_map_to_levels() {
        assert_eq!(level_of(0), LogLevel::Fatal);
        assert_eq!(level_of(3), LogLevel::Error);
        assert_eq!(level_of(4), LogLevel::Warn);
        assert_eq!(level_of(6), LogLevel::Info);
        assert_eq!(level_of(7), LogLevel::Debug);
        assert_eq!(level_of(9), LogLevel::Unspecified);
    }

    #[test]
    fn rollups_close_per_minute_and_host() {
        let access = |host: &str, status: u16, ms: u64, bot: bool, ip: &str| Access {
            host: host.to_owned(),
            method: "GET".to_owned(),
            status,
            response_time_us: ms * 1_000,
            bytes_sent: 100,
            client_ip: ip.to_owned(),
            user_agent: "ua".to_owned(),
            is_bot: bot,
            ..Default::default()
        };
        let mut rollups = Rollups::new();
        let t = 1_790_000_040 + 40; // 40 s into a minute
        rollups.add(t, &access("a.example.com", 200, 10, false, "203.0.113.0"));
        rollups.add(
            t + 5,
            &access("a.example.com", 503, 30, false, "203.0.113.0"),
        );
        rollups.add(
            t + 6,
            &access("a.example.com", 200, 20, true, "198.51.100.0"),
        );
        rollups.add(
            t + 7,
            &access("b.example.com", 200, 5, false, "203.0.113.0"),
        );
        assert!(rollups.closed(t + 10).is_empty(), "still open");
        let rows = rollups.closed(t + 30);
        // The bot request is its own device series; the host's requests still
        // add up across those series.
        assert_eq!(rows.len(), 3, "{rows:?}");
        fn dim(row: &AnalyticsRow, dimension: AnalyticsDimension) -> &str {
            row.dimensions
                .iter()
                .find(|d| d.dimension == dimension as i32)
                .unwrap()
                .value
                .as_str()
        }
        let value = |row: &AnalyticsRow, m: AnalyticsMeasure| {
            row.values
                .iter()
                .find(|v| v.measure == m as i32)
                .unwrap()
                .value
        };
        let a: Vec<_> = rows
            .iter()
            .filter(|row| dim(row, AnalyticsDimension::Domain) == "a.example.com")
            .collect();
        assert_eq!(a.len(), 2, "{rows:?}");
        assert!(a.iter().all(|row| {
            row.bucket_start.unwrap().seconds == t - 40
                && dim(row, AnalyticsDimension::Path) == "/"
                && dim(row, AnalyticsDimension::Referrer) == "direct"
                && dim(row, AnalyticsDimension::Country) == "XX"
        }));
        let sum =
            |measure: AnalyticsMeasure| -> f64 { a.iter().map(|row| value(row, measure)).sum() };
        assert_eq!(sum(AnalyticsMeasure::Requests), 3.0);
        assert_eq!(sum(AnalyticsMeasure::PageViews), 1.0);
        assert_eq!(sum(AnalyticsMeasure::UniqueVisitors), 2.0);
        assert_eq!(sum(AnalyticsMeasure::BotRequests), 1.0);
        assert_eq!(sum(AnalyticsMeasure::BytesSent), 300.0);
        let desktop = a
            .iter()
            .find(|row| dim(row, AnalyticsDimension::Device) == "desktop")
            .unwrap();
        assert_eq!(value(desktop, AnalyticsMeasure::Requests), 2.0);
        assert_eq!(value(desktop, AnalyticsMeasure::LatencyP50Ms), 10.0);
        assert_eq!(value(desktop, AnalyticsMeasure::LatencyP99Ms), 30.0);
        assert!((value(desktop, AnalyticsMeasure::ErrorRate) - 0.5).abs() < 1e-9);
        let bot = a
            .iter()
            .find(|row| dim(row, AnalyticsDimension::Device) == "bot")
            .unwrap();
        assert_eq!(value(bot, AnalyticsMeasure::Requests), 1.0);
        assert_eq!(value(bot, AnalyticsMeasure::LatencyP50Ms), 20.0);
        assert!(rows
            .iter()
            .any(|row| dim(row, AnalyticsDimension::Domain) == "b.example.com"));
        assert!(rollups.closed(t + 30).is_empty());
    }

    #[test]
    fn access_lines_parse_and_other_output_does_not() {
        let line = r#"{"timestamp":"2026-09-23T10:00:00Z","request_id":"r1","method":"GET","path":"/","host":"A.example.com:443","status":200,"response_time_us":1500,"client_ip":"203.0.113.0","bytes_sent":10,"bytes_received":0,"http_version":"HTTP/2","is_bot":false}"#;
        let access = access_of(line).unwrap();
        assert_eq!(access.host, "a.example.com");
        assert_eq!(access.status, 200);
        assert_eq!(access_of("INFO dwaar started"), None);
        assert_eq!(access_of(r#"{"level":"info","msg":"x"}"#), None);
        let mut fields: HashMap<String, String> = [
            ("Authorization".to_owned(), "x".to_owned()),
            ("host".to_owned(), "a".to_owned()),
            ("client_ip".to_owned(), "203.0.113.77".to_owned()),
        ]
        .into_iter()
        .collect();
        drop_header_fields(&mut fields);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields["client_ip"], "203.0.113.0");
        assert_eq!(
            truncate_ip("2001:db8:1:2::5").as_deref(),
            Some("2001:db8:1::")
        );
        assert_eq!(truncate_ip("not-an-ip"), None);
    }
}
