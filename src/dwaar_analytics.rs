#![allow(dead_code)]

use std::{collections::HashMap, sync::Mutex};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::proto::agent::v1::{
    AnalyticsSnapshot, CountryCount, DeviceCount, LatencyBucket, PageCount, ReferrerCount,
    StatusClassCount, UtmCount,
};

const MAX_LOG_LINE_BYTES: usize = 64 * 1024;
const MAX_LABEL_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 160;
const MAX_ERROR_SAMPLE_BYTES: usize = 160;
const LATENCY_BUCKETS_MS: [&str; 10] = [
    "10", "50", "100", "250", "500", "1000", "2500", "5000", "10000", "+Inf",
];

#[derive(Clone, Debug)]
pub struct DwaarAnalyticsConfig {
    pub max_domains: usize,
    pub max_top_pages: usize,
    pub max_top_referrers: usize,
    pub max_top_countries: usize,
    pub max_top_user_agents: usize,
    pub max_error_signals: usize,
    pub unique_visitor_bits: usize,
}

impl Default for DwaarAnalyticsConfig {
    fn default() -> Self {
        Self {
            max_domains: 64,
            max_top_pages: 100,
            max_top_referrers: 50,
            max_top_countries: 25,
            max_top_user_agents: 20,
            max_error_signals: 20,
            unique_visitor_bits: 4096,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NamedCount {
    pub value: String,
    pub count: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ErrorBodySignal {
    pub fingerprint: String,
    pub sample: String,
    pub count: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DomainAnalyticsSnapshot {
    pub domain: String,
    pub page_views_1m: u64,
    pub page_views_60m: u64,
    pub unique_visitors: u64,
    pub human_views: u64,
    pub bot_views: u64,
    pub bytes_sent: u64,
    pub status_classes: Vec<NamedCount>,
    pub top_pages: Vec<NamedCount>,
    pub referrers: Vec<NamedCount>,
    pub countries: Vec<NamedCount>,
    pub devices: Vec<NamedCount>,
    pub top_user_agents: Vec<NamedCount>,
    pub utm_sources: Vec<NamedCount>,
    pub utm_mediums: Vec<NamedCount>,
    pub utm_campaigns: Vec<NamedCount>,
    pub utm_terms: Vec<NamedCount>,
    pub utm_contents: Vec<NamedCount>,
    pub cache_statuses: Vec<NamedCount>,
    pub compression_algorithms: Vec<NamedCount>,
    pub response_latency_buckets: Vec<NamedCount>,
    pub upstream_latency_buckets: Vec<NamedCount>,
    pub error_body_signals: Vec<ErrorBodySignal>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DwaarAnalyticsDiagnostics {
    pub malformed_lines: u64,
    pub dropped_domains: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DwaarAnalyticsDrain {
    pub snapshots: Vec<DomainAnalyticsSnapshot>,
    pub diagnostics: DwaarAnalyticsDiagnostics,
}

#[derive(Debug)]
pub struct DwaarAnalyticsCollector {
    inner: Mutex<CollectorInner>,
    config: DwaarAnalyticsConfig,
}

#[derive(Debug, Default)]
struct CollectorInner {
    domains: HashMap<String, DomainBucket>,
    diagnostics: DwaarAnalyticsDiagnostics,
}

#[derive(Debug)]
struct DomainBucket {
    page_views: u64,
    human_views: u64,
    bot_views: u64,
    bytes_sent: u64,
    status_classes: [u64; 5],
    response_latency_buckets: [u64; 10],
    upstream_latency_buckets: [u64; 10],
    unique_bits: Vec<u64>,
    unique_bit_count: usize,
    timestamp: String,
    pages: BoundedCounter,
    referrers: BoundedCounter,
    countries: BoundedCounter,
    devices: BoundedCounter,
    user_agents: BoundedCounter,
    utm_sources: BoundedCounter,
    utm_mediums: BoundedCounter,
    utm_campaigns: BoundedCounter,
    utm_terms: BoundedCounter,
    utm_contents: BoundedCounter,
    cache_statuses: BoundedCounter,
    compression_algorithms: BoundedCounter,
    error_signals: BoundedErrorSignals,
}

impl DomainBucket {
    fn new(config: &DwaarAnalyticsConfig) -> Self {
        let bit_words = config.unique_visitor_bits.div_ceil(64).max(1);
        Self {
            page_views: 0,
            human_views: 0,
            bot_views: 0,
            bytes_sent: 0,
            status_classes: [0; 5],
            response_latency_buckets: [0; 10],
            upstream_latency_buckets: [0; 10],
            unique_bits: vec![0; bit_words],
            unique_bit_count: 0,
            timestamp: String::new(),
            pages: BoundedCounter::new(config.max_top_pages),
            referrers: BoundedCounter::new(config.max_top_referrers),
            countries: BoundedCounter::new(config.max_top_countries),
            devices: BoundedCounter::new(5),
            user_agents: BoundedCounter::new(config.max_top_user_agents),
            utm_sources: BoundedCounter::new(50),
            utm_mediums: BoundedCounter::new(20),
            utm_campaigns: BoundedCounter::new(50),
            utm_terms: BoundedCounter::new(25),
            utm_contents: BoundedCounter::new(25),
            cache_statuses: BoundedCounter::new(8),
            compression_algorithms: BoundedCounter::new(8),
            error_signals: BoundedErrorSignals::new(config.max_error_signals),
        }
    }

    fn record(&mut self, entry: AccessLogEntry) {
        self.page_views = self.page_views.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(entry.bytes_sent);
        self.timestamp = entry.timestamp;
        if entry.is_bot {
            self.bot_views = self.bot_views.saturating_add(1);
        } else {
            self.human_views = self.human_views.saturating_add(1);
        }
        self.mark_unique(&entry.visitor_fingerprint);
        self.pages.add(entry.path);
        self.referrers.add(entry.referrer);
        self.countries.add(entry.country);
        self.devices.add(entry.device);
        self.user_agents.add(entry.user_agent_family);
        for (key, value) in entry.utm {
            match key.as_str() {
                "utm_source" => self.utm_sources.add(value),
                "utm_medium" => self.utm_mediums.add(value),
                "utm_campaign" => self.utm_campaigns.add(value),
                "utm_term" => self.utm_terms.add(value),
                "utm_content" => self.utm_contents.add(value),
                _ => {}
            }
        }
        self.cache_statuses.add(entry.cache_status);
        self.compression_algorithms.add(entry.compression);
        if let Some(idx) = status_class_index(entry.status) {
            self.status_classes[idx] = self.status_classes[idx].saturating_add(1);
        }
        self.response_latency_buckets[latency_bucket_index(entry.response_time_ms)] += 1;
        if entry.upstream_response_time_ms > 0.0 {
            self.upstream_latency_buckets[latency_bucket_index(entry.upstream_response_time_ms)] +=
                1;
        }
        if entry.status >= 500 || !entry.upstream_error_body.is_empty() {
            self.error_signals
                .add(entry.status, &entry.upstream_error_body);
        }
    }

    fn mark_unique(&mut self, fingerprint: &[u8]) {
        if fingerprint.is_empty() || self.unique_bits.is_empty() {
            return;
        }
        let bit_count = self.unique_bits.len() * 64;
        let mut first_eight = [0_u8; 8];
        first_eight.copy_from_slice(&fingerprint[..8]);
        let bit = u64::from_le_bytes(first_eight) as usize % bit_count;
        let word = bit / 64;
        let mask = 1_u64 << (bit % 64);
        if self.unique_bits[word] & mask == 0 {
            self.unique_bits[word] |= mask;
            self.unique_bit_count += 1;
        }
    }

    fn unique_estimate(&self) -> u64 {
        let m = (self.unique_bits.len() * 64) as f64;
        let set = self.unique_bit_count as f64;
        if set <= 1.0 {
            return set as u64;
        }
        let zeros = (m - set).max(1.0);
        (m * (m / zeros).ln()).round().max(set) as u64
    }

    fn snapshot(&self, domain: String) -> DomainAnalyticsSnapshot {
        DomainAnalyticsSnapshot {
            domain,
            page_views_1m: self.page_views,
            page_views_60m: self.page_views,
            unique_visitors: self.unique_estimate(),
            human_views: self.human_views,
            bot_views: self.bot_views,
            bytes_sent: self.bytes_sent,
            status_classes: status_class_counts(self.status_classes),
            top_pages: self.pages.top(),
            referrers: self.referrers.top(),
            countries: self.countries.top(),
            devices: self.devices.top(),
            top_user_agents: self.user_agents.top(),
            utm_sources: self.utm_sources.top(),
            utm_mediums: self.utm_mediums.top(),
            utm_campaigns: self.utm_campaigns.top(),
            utm_terms: self.utm_terms.top(),
            utm_contents: self.utm_contents.top(),
            cache_statuses: self.cache_statuses.top(),
            compression_algorithms: self.compression_algorithms.top(),
            response_latency_buckets: latency_counts(self.response_latency_buckets),
            upstream_latency_buckets: latency_counts(self.upstream_latency_buckets),
            error_body_signals: self.error_signals.top(),
        }
    }
}

impl DwaarAnalyticsCollector {
    pub fn new(config: DwaarAnalyticsConfig) -> Self {
        Self {
            inner: Mutex::new(CollectorInner::default()),
            config: DwaarAnalyticsConfig {
                max_domains: config.max_domains.max(1),
                max_top_pages: config.max_top_pages.max(1),
                max_top_referrers: config.max_top_referrers.max(1),
                max_top_countries: config.max_top_countries.max(1),
                max_top_user_agents: config.max_top_user_agents.max(1),
                max_error_signals: config.max_error_signals.max(1),
                unique_visitor_bits: config.unique_visitor_bits.max(64),
            },
        }
    }

    pub fn record_line(&self, line: &[u8]) {
        if line.is_empty() || line.len() > MAX_LOG_LINE_BYTES {
            self.record_malformed();
            return;
        }
        let Ok(entry) = parse_access_log_line(line) else {
            self.record_malformed();
            return;
        };
        if entry.domain.is_empty() {
            self.record_malformed();
            return;
        }

        let mut inner = self
            .inner
            .lock()
            .expect("dwaar analytics collector poisoned");
        if !inner.domains.contains_key(&entry.domain)
            && inner.domains.len() >= self.config.max_domains
        {
            inner.diagnostics.dropped_domains = inner.diagnostics.dropped_domains.saturating_add(1);
            return;
        }
        inner
            .domains
            .entry(entry.domain.clone())
            .or_insert_with(|| DomainBucket::new(&self.config))
            .record(entry);
    }

    pub fn snapshot(&self) -> DwaarAnalyticsDrain {
        let inner = self
            .inner
            .lock()
            .expect("dwaar analytics collector poisoned");
        drain_from_inner(&inner)
    }

    pub fn collect_and_reset(&self) -> DwaarAnalyticsDrain {
        let mut inner = self
            .inner
            .lock()
            .expect("dwaar analytics collector poisoned");
        let old = std::mem::take(&mut *inner);
        drain_from_inner(&old)
    }

    pub fn collect_and_reset_proto(&self) -> Vec<AnalyticsSnapshot> {
        self.collect_and_reset()
            .snapshots
            .into_iter()
            .map(Into::into)
            .collect()
    }

    fn record_malformed(&self) {
        let mut inner = self
            .inner
            .lock()
            .expect("dwaar analytics collector poisoned");
        inner.diagnostics.malformed_lines = inner.diagnostics.malformed_lines.saturating_add(1);
    }
}

impl From<DomainAnalyticsSnapshot> for AnalyticsSnapshot {
    fn from(value: DomainAnalyticsSnapshot) -> Self {
        #[allow(deprecated)]
        Self {
            domain: value.domain,
            unique_visitors: value.unique_visitors as i64,
            total_pageviews: value.page_views_60m as i64,
            bytes_sent: value.bytes_sent as i64,
            timestamp: String::new(),
            status_1xx: count_for(&value.status_classes, "1xx") as i64,
            status_2xx: count_for(&value.status_classes, "2xx") as i64,
            status_3xx: count_for(&value.status_classes, "3xx") as i64,
            status_4xx: count_for(&value.status_classes, "4xx") as i64,
            status_5xx: count_for(&value.status_classes, "5xx") as i64,
            lcp_p75: 0.0,
            cls_p75: 0.0,
            inp_p75: 0.0,
            top_pages: value
                .top_pages
                .into_iter()
                .map(|item| PageCount {
                    path: item.value,
                    count: item.count as i64,
                })
                .collect(),
            referrers: value
                .referrers
                .into_iter()
                .map(|item| ReferrerCount {
                    domain: item.value,
                    count: item.count as i64,
                })
                .collect(),
            countries: value
                .countries
                .into_iter()
                .map(|item| CountryCount {
                    code: item.value,
                    count: item.count as i64,
                })
                .collect(),
            page_views_1m: value.page_views_1m as i64,
            page_views_60m: value.page_views_60m as i64,
            bot_views: value.bot_views as i64,
            human_views: value.human_views as i64,
            devices: value
                .devices
                .into_iter()
                .map(|item| DeviceCount {
                    device: item.value,
                    count: item.count as i64,
                })
                .collect(),
            utm_sources: value.utm_sources.into_iter().map(utm_count).collect(),
            utm_mediums: value.utm_mediums.into_iter().map(utm_count).collect(),
            utm_campaigns: value.utm_campaigns.into_iter().map(utm_count).collect(),
            status_classes: value
                .status_classes
                .into_iter()
                .map(|item| StatusClassCount {
                    class: item.value,
                    count: item.count as i64,
                })
                .collect(),
            utm_terms: value.utm_terms.into_iter().map(utm_count).collect(),
            utm_contents: value.utm_contents.into_iter().map(utm_count).collect(),
            response_latency_buckets: value
                .response_latency_buckets
                .into_iter()
                .map(|item| LatencyBucket {
                    le: item.value,
                    count: item.count,
                })
                .collect(),
        }
    }
}

fn utm_count(item: NamedCount) -> UtmCount {
    UtmCount {
        value: item.value,
        count: item.count as i64,
    }
}

fn drain_from_inner(inner: &CollectorInner) -> DwaarAnalyticsDrain {
    let mut snapshots = Vec::with_capacity(inner.domains.len());
    for (domain, bucket) in &inner.domains {
        snapshots.push(bucket.snapshot(domain.clone()));
    }
    snapshots.sort_by(|a, b| a.domain.cmp(&b.domain));
    DwaarAnalyticsDrain {
        snapshots,
        diagnostics: inner.diagnostics.clone(),
    }
}

#[derive(Debug, Deserialize)]
struct RawAccessLog {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    status: i64,
    #[serde(default)]
    response_time_us: i64,
    #[serde(default)]
    client_ip: String,
    #[serde(default)]
    user_agent: String,
    #[serde(default, alias = "referer")]
    referrer: String,
    #[serde(default)]
    bytes_sent: i64,
    #[serde(default)]
    is_bot: bool,
    #[serde(default)]
    country: String,
    #[serde(default)]
    cache_status: String,
    #[serde(default)]
    compression: String,
    #[serde(default)]
    upstream_response_time_us: i64,
    #[serde(default)]
    upstream_error_body: String,
}

struct AccessLogEntry {
    timestamp: String,
    domain: String,
    path: String,
    status: i64,
    response_time_ms: f64,
    upstream_response_time_ms: f64,
    bytes_sent: u64,
    is_bot: bool,
    country: String,
    referrer: String,
    device: String,
    user_agent_family: String,
    cache_status: String,
    compression: String,
    upstream_error_body: String,
    utm: Vec<(String, String)>,
    visitor_fingerprint: Vec<u8>,
}

fn parse_access_log_line(line: &[u8]) -> Result<AccessLogEntry, serde_json::Error> {
    let raw: RawAccessLog = serde_json::from_slice(line)?;
    let domain = normalize_domain(&raw.host);
    let query = query_from_path_or_field(&raw.path, &raw.query);
    let user_agent_family = user_agent_family(&raw.user_agent, raw.is_bot);
    Ok(AccessLogEntry {
        timestamp: truncate_bytes(raw.timestamp.trim(), 64),
        domain: domain.clone(),
        path: normalize_path(&raw.path),
        status: raw.status,
        response_time_ms: raw.response_time_us.max(0) as f64 / 1000.0,
        upstream_response_time_ms: raw.upstream_response_time_us.max(0) as f64 / 1000.0,
        bytes_sent: raw.bytes_sent.max(0) as u64,
        is_bot: raw.is_bot || user_agent_family == "Bot",
        country: normalize_country(&raw.country),
        referrer: normalize_referrer(&raw.referrer, &domain),
        device: device_class(&raw.user_agent, raw.is_bot),
        user_agent_family,
        cache_status: normalize_optional_label(&raw.cache_status, "unknown"),
        compression: normalize_optional_label(&raw.compression, "none"),
        upstream_error_body: raw.upstream_error_body,
        utm: parse_utm_values(&query),
        visitor_fingerprint: visitor_fingerprint(&domain, &raw.client_ip, &raw.user_agent),
    })
}

#[derive(Debug)]
struct BoundedCounter {
    cap: usize,
    counts: HashMap<String, u64>,
}

impl BoundedCounter {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            counts: HashMap::new(),
        }
    }

    fn add(&mut self, value: String) {
        if value.is_empty() {
            return;
        }
        if let Some(count) = self.counts.get_mut(&value) {
            *count = count.saturating_add(1);
            return;
        }
        if self.counts.len() < self.cap {
            self.counts.insert(value, 1);
            return;
        }
        let Some(coldest) = self
            .counts
            .iter()
            .min_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        self.counts.remove(&coldest);
        self.counts.insert(value, 1);
    }

    fn top(&self) -> Vec<NamedCount> {
        let mut out = Vec::with_capacity(self.counts.len());
        for (value, count) in &self.counts {
            out.push(NamedCount {
                value: value.clone(),
                count: *count,
            });
        }
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
        out
    }
}

#[derive(Debug)]
struct BoundedErrorSignals {
    cap: usize,
    signals: HashMap<String, ErrorBodySignal>,
}

impl BoundedErrorSignals {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            signals: HashMap::new(),
        }
    }

    fn add(&mut self, status: i64, body: &str) {
        let fingerprint = error_fingerprint(status, body);
        let sample = redact_error_sample(body);
        if let Some(signal) = self.signals.get_mut(&fingerprint) {
            signal.count = signal.count.saturating_add(1);
            return;
        }
        if self.signals.len() >= self.cap {
            let Some(coldest) = self
                .signals
                .iter()
                .min_by_key(|(_, signal)| signal.count)
                .map(|(key, _)| key.clone())
            else {
                return;
            };
            self.signals.remove(&coldest);
        }
        self.signals.insert(
            fingerprint.clone(),
            ErrorBodySignal {
                fingerprint,
                sample,
                count: 1,
            },
        );
    }

    fn top(&self) -> Vec<ErrorBodySignal> {
        let mut out: Vec<_> = self.signals.values().cloned().collect();
        out.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
        });
        out
    }
}

fn normalize_domain(host: &str) -> String {
    let host = host
        .trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if host.len() > 253
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return String::new();
    }
    host
}

fn normalize_path(path: &str) -> String {
    let path = path.split_once('?').map(|(path, _)| path).unwrap_or(path);
    let path = if path.is_empty() { "/" } else { path };
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            parts.push(String::new());
            continue;
        }
        let normalized = if is_identifier_segment(part) {
            "{id}".to_string()
        } else {
            sanitize_path_segment(part)
        };
        parts.push(normalized);
    }
    let mut out = parts.join("/");
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    truncate_bytes(&out, MAX_PATH_BYTES)
}

fn is_identifier_segment(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit())
        || is_uuid_like(value)
        || (value.len() >= 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || value.len() > 48
}

fn is_uuid_like(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    for (idx, byte) in value.bytes().enumerate() {
        match idx {
            8 | 13 | 18 | 23 if byte == b'-' => {}
            8 | 13 | 18 | 23 => return false,
            _ if byte.is_ascii_hexdigit() => {}
            _ => return false,
        }
    }
    true
}

fn sanitize_path_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'%') {
            out.push(byte as char);
        } else {
            out.push('-');
        }
        if out.len() >= 48 {
            break;
        }
    }
    out
}

fn query_from_path_or_field(path: &str, query: &str) -> String {
    if !query.is_empty() {
        return query.to_string();
    }
    path.split_once('?')
        .map(|(_, query)| query.to_string())
        .unwrap_or_default()
}

fn parse_utm_values(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split(['&', ';']) {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if !matches!(
            key.as_str(),
            "utm_source" | "utm_medium" | "utm_campaign" | "utm_term" | "utm_content"
        ) {
            continue;
        }
        let value = normalize_label_value(value, &key);
        if !value.is_empty() {
            out.push((key, value));
        }
    }
    out
}

fn normalize_label_value(value: &str, key: &str) -> String {
    let value = value.replace('+', " ");
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return String::new();
    }
    if is_sensitive_label(key, &value) {
        return "[redacted]".to_string();
    }
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' ' | b'~') {
            out.push(byte as char);
        } else {
            out.push('-');
        }
        if out.len() >= MAX_LABEL_BYTES {
            break;
        }
    }
    out.trim().to_string()
}

fn is_sensitive_label(key: &str, value: &str) -> bool {
    key.contains("token")
        || key.contains("secret")
        || key.contains("password")
        || key.contains("key")
        || value.contains('@')
        || value.contains("bearer ")
        || value.contains("token=")
        || value.contains("password=")
        || value.contains("secret=")
}

fn normalize_country(country: &str) -> String {
    let country = country.trim().to_ascii_uppercase();
    if country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        country
    } else {
        "XX".to_string()
    }
}

fn normalize_referrer(referrer: &str, domain: &str) -> String {
    let trimmed = referrer.trim();
    if trimmed.is_empty() {
        return "direct".to_string();
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = normalize_domain(authority);
    if host.is_empty() {
        "unknown".to_string()
    } else if host == domain {
        "internal".to_string()
    } else {
        host
    }
}

fn device_class(user_agent: &str, is_bot: bool) -> String {
    let ua = user_agent.to_ascii_lowercase();
    if is_bot || ua.contains("bot") || ua.contains("spider") || ua.contains("crawler") {
        "bot".to_string()
    } else if ua.contains("ipad") || ua.contains("tablet") {
        "tablet".to_string()
    } else if ua.contains("mobile") || ua.contains("iphone") || ua.contains("android") {
        "mobile".to_string()
    } else if ua.is_empty() {
        "unknown".to_string()
    } else {
        "desktop".to_string()
    }
}

fn user_agent_family(user_agent: &str, is_bot: bool) -> String {
    let ua = user_agent.to_ascii_lowercase();
    if is_bot || ua.contains("bot") || ua.contains("spider") || ua.contains("crawler") {
        "Bot".to_string()
    } else if ua.contains("edg/") {
        "Edge".to_string()
    } else if ua.contains("firefox/") {
        "Firefox".to_string()
    } else if ua.contains("chrome/") || ua.contains("crios/") {
        "Chrome".to_string()
    } else if ua.contains("safari/") {
        "Safari".to_string()
    } else if ua.contains("curl/") {
        "curl".to_string()
    } else if ua.is_empty() {
        "Unknown".to_string()
    } else {
        "Other".to_string()
    }
}

fn normalize_optional_label(value: &str, default: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return default.to_string();
    }
    normalize_label_value(value, "")
}

fn visitor_fingerprint(domain: &str, client_ip: &str, user_agent: &str) -> Vec<u8> {
    if client_ip.trim().is_empty() && user_agent.trim().is_empty() {
        return Vec::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"|");
    hasher.update(client_ip.trim().as_bytes());
    hasher.update(b"|");
    hasher.update(user_agent.trim().as_bytes());
    hasher.finalize().to_vec()
}

fn status_class_index(status: i64) -> Option<usize> {
    match status {
        100..=199 => Some(0),
        200..=299 => Some(1),
        300..=399 => Some(2),
        400..=499 => Some(3),
        500..=599 => Some(4),
        _ => None,
    }
}

fn status_class_counts(counts: [u64; 5]) -> Vec<NamedCount> {
    ["1xx", "2xx", "3xx", "4xx", "5xx"]
        .into_iter()
        .zip(counts)
        .map(|(value, count)| NamedCount {
            value: value.to_string(),
            count,
        })
        .collect()
}

fn latency_bucket_index(ms: f64) -> usize {
    for (idx, le) in LATENCY_BUCKETS_MS.iter().enumerate() {
        if *le == "+Inf" {
            return idx;
        }
        if ms <= le.parse::<f64>().unwrap_or(f64::MAX) {
            return idx;
        }
    }
    LATENCY_BUCKETS_MS.len() - 1
}

fn latency_counts(counts: [u64; 10]) -> Vec<NamedCount> {
    LATENCY_BUCKETS_MS
        .into_iter()
        .zip(counts)
        .map(|(value, count)| NamedCount {
            value: value.to_string(),
            count,
        })
        .collect()
}

fn count_for(items: &[NamedCount], value: &str) -> u64 {
    items
        .iter()
        .find(|item| item.value == value)
        .map(|item| item.count)
        .unwrap_or(0)
}

fn error_fingerprint(status: i64, body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(status.to_string());
    hasher.update(b"|");
    hasher.update(body.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn redact_error_sample(body: &str) -> String {
    if body.trim().is_empty() {
        return "empty_error_body".to_string();
    }
    let capped = truncate_bytes(body, 256);
    let mut out = Vec::new();
    let mut redact_next = false;
    for token in capped.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if redact_next
            || token_contains_secret_marker(&lower)
            || token.contains('@')
            || looks_like_secret_token(token)
        {
            out.push("[redacted]".to_string());
            redact_next = lower == "bearer" || lower.ends_with(':');
            continue;
        }
        redact_next = lower == "bearer" || lower == "authorization:" || lower == "authorization";
        out.push(truncate_bytes(token, 40));
    }
    let joined = out.join(" ");
    truncate_bytes(&joined, MAX_ERROR_SAMPLE_BYTES)
}

fn token_contains_secret_marker(token: &str) -> bool {
    token.contains("authorization")
        || token.contains("password")
        || token.contains("passwd")
        || token.contains("secret")
        || token.contains("token")
        || token.contains("api_key")
        || token.contains("apikey")
}

fn looks_like_secret_token(token: &str) -> bool {
    token.len() >= 20
        && token
            .bytes()
            .filter(|byte| byte.is_ascii_alphanumeric())
            .count()
            >= 16
}

fn truncate_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = 0;
    for (idx, _) in value.char_indices() {
        if idx > max_bytes {
            break;
        }
        end = idx;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(domain: &str, path: &str) -> String {
        format!(
            r#"{{
                "timestamp":"2026-05-11T10:00:00Z",
                "request_id":"req-1",
                "method":"GET",
                "host":"{domain}",
                "path":"{path}",
                "query":"utm_source=Newsletter&utm_medium=Email&utm_campaign=Launch&utm_term=May&utm_content=Hero",
                "status":200,
                "response_time_us":12500,
                "client_ip":"203.0.113.10",
                "user_agent":"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
                "referer":"https://Google.com/search?q=secret@example.com",
                "bytes_sent":42,
                "is_bot":false,
                "country":"us",
                "cache_status":"HIT",
                "compression":"br",
                "upstream_response_time_us":9000
            }}"#
        )
    }

    #[test]
    fn parses_access_log_into_privacy_safe_analytics() {
        let collector = DwaarAnalyticsCollector::new(DwaarAnalyticsConfig::default());
        collector.record_line(
            line(
                "Example.COM",
                "/users/123/orders/550e8400-e29b-41d4-a716-446655440000?x=1",
            )
            .as_bytes(),
        );

        let drain = collector.snapshot();
        assert_eq!(drain.snapshots.len(), 1);
        let snap = &drain.snapshots[0];
        assert_eq!(snap.domain, "example.com");
        assert_eq!(snap.page_views_1m, 1);
        assert_eq!(snap.unique_visitors, 1);
        assert_eq!(snap.top_pages[0].value, "/users/{id}/orders/{id}");
        assert_eq!(snap.referrers[0].value, "google.com");
        assert_eq!(snap.countries[0].value, "US");
        assert_eq!(snap.devices[0].value, "mobile");
        assert_eq!(snap.top_user_agents[0].value, "Safari");
        assert_eq!(snap.utm_sources[0].value, "newsletter");
        assert_eq!(snap.utm_mediums[0].value, "email");
        assert_eq!(snap.utm_campaigns[0].value, "launch");
        assert_eq!(snap.utm_terms[0].value, "may");
        assert_eq!(snap.utm_contents[0].value, "hero");
        assert_eq!(snap.cache_statuses[0].value, "hit");
        assert_eq!(snap.compression_algorithms[0].value, "br");
        assert_eq!(snap.status_classes[1].value, "2xx");
        assert_eq!(snap.status_classes[1].count, 1);
    }

    #[test]
    fn bounds_high_cardinality_domains_and_top_values() {
        let collector = DwaarAnalyticsCollector::new(DwaarAnalyticsConfig {
            max_domains: 2,
            max_top_pages: 3,
            max_top_referrers: 2,
            max_top_countries: 2,
            max_top_user_agents: 2,
            max_error_signals: 2,
            unique_visitor_bits: 128,
        });

        for i in 0..20 {
            collector
                .record_line(line(&format!("d{i}.example.com"), &format!("/item/{i}")).as_bytes());
        }

        let drain = collector.snapshot();
        assert!(drain.snapshots.len() <= 2);
        assert!(drain.diagnostics.dropped_domains > 0);
        for snap in &drain.snapshots {
            assert!(snap.top_pages.len() <= 3);
            assert!(snap.referrers.len() <= 2);
            assert!(snap.countries.len() <= 2);
            assert!(snap.top_user_agents.len() <= 2);
        }
    }

    #[test]
    fn redacts_error_body_signals_and_never_stores_raw_secret_values() {
        let collector = DwaarAnalyticsCollector::new(DwaarAnalyticsConfig::default());
        collector.record_line(
            br#"{
                "host":"api.example.com",
                "path":"/login",
                "status":502,
                "response_time_us":2000,
                "client_ip":"198.51.100.2",
                "user_agent":"curl/8.0",
                "upstream_error_body":"panic for jane@example.com Authorization: Bearer secret-token-123 password=hunter2"
            }"#,
        );

        let drain = collector.snapshot();
        let signal = &drain.snapshots[0].error_body_signals[0];
        assert!(!signal.fingerprint.is_empty());
        assert!(!signal.sample.contains("jane@example.com"));
        assert!(!signal.sample.contains("secret-token-123"));
        assert!(!signal.sample.contains("hunter2"));
        assert!(signal.sample.contains("[redacted]"));
    }

    #[test]
    fn converts_supported_fields_to_existing_proto_and_resets() {
        let collector = DwaarAnalyticsCollector::new(DwaarAnalyticsConfig::default());
        collector.record_line(line("example.com", "/pricing").as_bytes());

        let protos = collector.collect_and_reset_proto();
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0].domain, "example.com");
        assert_eq!(protos[0].page_views_1m, 1);
        assert_eq!(protos[0].page_views_60m, 1);
        assert_eq!(protos[0].top_pages[0].path, "/pricing");
        assert_eq!(protos[0].referrers[0].domain, "google.com");
        assert_eq!(protos[0].countries[0].code, "US");
        assert_eq!(protos[0].devices[0].device, "mobile");
        assert_eq!(protos[0].utm_sources[0].value, "newsletter");
        assert_eq!(protos[0].utm_mediums[0].value, "email");
        assert_eq!(protos[0].utm_campaigns[0].value, "launch");
        assert_eq!(protos[0].utm_terms[0].value, "may");
        assert_eq!(protos[0].utm_contents[0].value, "hero");
        assert_eq!(protos[0].status_classes[1].class, "2xx");
        assert_eq!(protos[0].response_latency_buckets.len(), 10);

        assert!(collector.collect_and_reset().snapshots.is_empty());
    }
}
