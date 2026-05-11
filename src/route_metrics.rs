use std::{
    cmp::Ordering,
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
    sync::watch,
};
use tracing::warn;

use crate::{dwaar_analytics::DwaarAnalyticsCollector, proto::agent::v1::RouteMetrics};

const DEFAULT_DWAAR_ACCESS_LOG: &str = "/var/log/dwaar/access.log";
const DEFAULT_MAX_ROUTES: usize = 256;
const DEFAULT_MAX_LATENCY_SAMPLES: usize = 10_000;
const MAX_LOG_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RouteKey {
    domain: String,
    path: String,
}

#[derive(Debug)]
struct RouteBucket {
    request_count: i64,
    status_2xx: i64,
    status_3xx: i64,
    status_4xx: i64,
    status_5xx: i64,
    bytes_sent: i64,
    latencies: Vec<f64>,
    bot_requests: i64,
    cache_hits: i64,
    cache_misses: i64,
}

#[derive(Debug, Default)]
struct RouteAggregatorInner {
    buckets: HashMap<RouteKey, RouteBucket>,
    routes_evicted: i64,
    malformed_lines: i64,
}

#[derive(Debug)]
pub struct RouteAggregator {
    inner: Mutex<RouteAggregatorInner>,
    max_routes: usize,
    max_latency_samples: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RouteMetricSnapshot {
    pub domain: String,
    pub path: String,
    pub request_count: i64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub status_2xx: i64,
    pub status_3xx: i64,
    pub status_4xx: i64,
    pub status_5xx: i64,
    pub bytes_sent: i64,
    pub bot_requests: i64,
    pub cache_hits: i64,
    pub cache_misses: i64,
}

#[derive(Debug, Deserialize)]
struct ProxyLogRaw {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    status: i64,
    #[serde(default)]
    response_time_us: i64,
    #[serde(default)]
    bytes_sent: i64,
    #[serde(default)]
    is_bot: bool,
    #[serde(default)]
    cache_status: String,
}

impl Default for RouteAggregator {
    fn default() -> Self {
        Self::new(
            env_usize("DEPLOY_AGENT_MAX_ROUTES", DEFAULT_MAX_ROUTES),
            env_usize(
                "DEPLOY_AGENT_MAX_LATENCY_SAMPLES",
                DEFAULT_MAX_LATENCY_SAMPLES,
            ),
        )
    }
}

impl RouteAggregator {
    pub fn new(max_routes: usize, max_latency_samples: usize) -> Self {
        Self {
            inner: Mutex::new(RouteAggregatorInner::default()),
            max_routes: max_routes.max(1),
            max_latency_samples: max_latency_samples.max(1),
        }
    }

    pub fn record_line(&self, line: &[u8]) {
        if line.len() > MAX_LOG_LINE_BYTES {
            self.record_malformed();
            return;
        }
        match parse_proxy_log_line(line) {
            Ok(entry) => self.record(entry),
            Err(_) => self.record_malformed(),
        }
    }

    fn record(&self, entry: ProxyLogEntry) {
        if entry.domain.is_empty() {
            self.record_malformed();
            return;
        }

        let mut inner = self.inner.lock().expect("route aggregator poisoned");
        let key = RouteKey {
            domain: entry.domain,
            path: entry.path,
        };
        if !inner.buckets.contains_key(&key) && inner.buckets.len() >= self.max_routes {
            evict_coldest_route(&mut inner);
        }
        let bucket = inner.buckets.entry(key).or_insert_with(|| RouteBucket {
            request_count: 0,
            status_2xx: 0,
            status_3xx: 0,
            status_4xx: 0,
            status_5xx: 0,
            bytes_sent: 0,
            latencies: Vec::with_capacity(128.min(self.max_latency_samples)),
            bot_requests: 0,
            cache_hits: 0,
            cache_misses: 0,
        });

        bucket.request_count += 1;
        bucket.bytes_sent = bucket.bytes_sent.saturating_add(entry.bytes_sent);
        if bucket.latencies.len() < self.max_latency_samples {
            bucket.latencies.push(entry.duration_ms);
        }
        if entry.is_bot {
            bucket.bot_requests += 1;
        }
        match entry.cache_status.as_str() {
            "HIT" => bucket.cache_hits += 1,
            "MISS" => bucket.cache_misses += 1,
            _ => {}
        }
        match entry.status {
            200..=299 => bucket.status_2xx += 1,
            300..=399 => bucket.status_3xx += 1,
            400..=499 => bucket.status_4xx += 1,
            500..=599 => bucket.status_5xx += 1,
            _ => {}
        }
    }

    fn record_malformed(&self) {
        let mut inner = self.inner.lock().expect("route aggregator poisoned");
        inner.malformed_lines += 1;
    }

    pub fn snapshot(&self, host: Option<&str>) -> Vec<RouteMetricSnapshot> {
        let inner = self.inner.lock().expect("route aggregator poisoned");
        snapshots_from_buckets(&inner.buckets, host)
    }

    pub fn collect_and_reset_proto(&self) -> Vec<RouteMetrics> {
        let snapshots = {
            let mut inner = self.inner.lock().expect("route aggregator poisoned");
            if inner.routes_evicted > 0 || inner.malformed_lines > 0 {
                warn!(
                    routes_evicted = inner.routes_evicted,
                    malformed_lines = inner.malformed_lines,
                    "route aggregator interval diagnostics"
                );
            }
            let old = std::mem::take(&mut inner.buckets);
            inner.routes_evicted = 0;
            inner.malformed_lines = 0;
            snapshots_from_buckets(&old, None)
        };
        snapshots.into_iter().map(Into::into).collect()
    }
}

impl From<RouteMetricSnapshot> for RouteMetrics {
    fn from(value: RouteMetricSnapshot) -> Self {
        Self {
            domain: value.domain,
            path: value.path,
            request_count: value.request_count,
            latency_p50_ms: value.latency_p50_ms,
            latency_p95_ms: value.latency_p95_ms,
            latency_p99_ms: value.latency_p99_ms,
            status_2xx: value.status_2xx,
            status_3xx: value.status_3xx,
            status_4xx: value.status_4xx,
            status_5xx: value.status_5xx,
            bytes_sent: value.bytes_sent,
            bot_requests: value.bot_requests,
            cache_hits: value.cache_hits,
            cache_misses: value.cache_misses,
        }
    }
}

pub async fn run_access_log_tailer(
    aggregator: Arc<RouteAggregator>,
    analytics: Arc<DwaarAnalyticsCollector>,
    mut shutdown: watch::Receiver<bool>,
) {
    let log_path = env::var("DWAAR_ACCESS_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DWAAR_ACCESS_LOG));
    if let Err(err) = ensure_log_file(&log_path) {
        warn!(path = %log_path.display(), error = ?err, "could not prepare Dwaar access log");
    }

    loop {
        if *shutdown.borrow() {
            return;
        }
        match tail_once(
            &log_path,
            aggregator.clone(),
            analytics.clone(),
            shutdown.clone(),
        )
        .await
        {
            Ok(()) => return,
            Err(err) => {
                warn!(path = %log_path.display(), error = ?err, "Dwaar access log tailer restarting")
            }
        }
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}

async fn tail_once(
    path: &Path,
    aggregator: Arc<RouteAggregator>,
    analytics: Arc<DwaarAnalyticsCollector>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let initial = file
        .metadata()
        .await
        .with_context(|| format!("stat {}", path.display()))?;
    let mut reader = BufReader::new(file);
    reader.seek(std::io::SeekFrom::End(0)).await?;
    let mut line = Vec::with_capacity(1024);

    loop {
        line.clear();
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            read = reader.read_until(b'\n', &mut line) => {
                let read = read.context("read Dwaar access log")?;
                if read == 0 {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    if rotated(path, &initial).await? {
                        anyhow::bail!("log rotated, reopening");
                    }
                    continue;
                }
                trim_newline(&mut line);
                aggregator.record_line(&line);
                analytics.record_line(&line);
            }
        }
    }
}

async fn rotated(path: &Path, initial: &fs::Metadata) -> Result<bool> {
    let current = tokio::fs::metadata(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(current.ino() != initial.ino() || current.dev() != initial.dev())
    }
    #[cfg(not(unix))]
    {
        Ok(current.len() < initial.len())
    }
}

fn ensure_log_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    OpenOptionsExtCompat::create_append(path)?;
    Ok(())
}

struct OpenOptionsExtCompat;

impl OpenOptionsExtCompat {
    fn create_append(path: &Path) -> Result<()> {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        drop(file);
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct ProxyLogEntry {
    domain: String,
    path: String,
    status: i64,
    duration_ms: f64,
    bytes_sent: i64,
    is_bot: bool,
    cache_status: String,
}

fn parse_proxy_log_line(line: &[u8]) -> Result<ProxyLogEntry> {
    let raw: ProxyLogRaw = serde_json::from_slice(line).context("parse proxy log")?;
    Ok(ProxyLogEntry {
        domain: raw.host,
        path: normalize_path(strip_query(&raw.path)),
        status: raw.status,
        duration_ms: raw.response_time_us as f64 / 1000.0,
        bytes_sent: raw.bytes_sent.max(0),
        is_bot: raw.is_bot,
        cache_status: raw.cache_status,
    })
}

fn strip_query(path: &str) -> &str {
    path.split_once('?').map(|(path, _)| path).unwrap_or(path)
}

fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            parts.push(String::new());
        } else if is_uuid_like(part) || part.bytes().all(|byte| byte.is_ascii_digit()) {
            parts.push("{id}".to_string());
        } else {
            parts.push(part.to_string());
        }
    }
    parts.join("/")
}

fn is_uuid_like(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    for (idx, byte) in value.bytes().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if byte != b'-' {
                    return false;
                }
            }
            _ if !byte.is_ascii_hexdigit() => return false,
            _ => {}
        }
    }
    true
}

fn evict_coldest_route(inner: &mut RouteAggregatorInner) {
    let Some(coldest) = inner
        .buckets
        .iter()
        .min_by_key(|(_, bucket)| bucket.request_count)
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    inner.buckets.remove(&coldest);
    inner.routes_evicted += 1;
}

fn snapshots_from_buckets(
    buckets: &HashMap<RouteKey, RouteBucket>,
    host: Option<&str>,
) -> Vec<RouteMetricSnapshot> {
    let mut results = Vec::with_capacity(buckets.len());
    for (key, bucket) in buckets {
        if host
            .filter(|host| !host.eq_ignore_ascii_case(&key.domain))
            .is_some()
        {
            continue;
        }
        let mut latencies = bucket.latencies.clone();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        results.push(RouteMetricSnapshot {
            domain: key.domain.clone(),
            path: key.path.clone(),
            request_count: bucket.request_count,
            latency_p50_ms: percentile_from_sorted(&latencies, 50.0),
            latency_p95_ms: percentile_from_sorted(&latencies, 95.0),
            latency_p99_ms: percentile_from_sorted(&latencies, 99.0),
            status_2xx: bucket.status_2xx,
            status_3xx: bucket.status_3xx,
            status_4xx: bucket.status_4xx,
            status_5xx: bucket.status_5xx,
            bytes_sent: bucket.bytes_sent,
            bot_requests: bucket.bot_requests,
            cache_hits: bucket.cache_hits,
            cache_misses: bucket.cache_misses,
        });
    }
    results.sort_by(|a, b| a.domain.cmp(&b.domain).then(a.path.cmp(&b.path)));
    results
}

fn percentile_from_sorted(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let mut idx = ((pct / 100.0) * sorted.len() as f64).ceil() as isize - 1;
    if idx < 0 {
        idx = 0;
    }
    sorted[idx as usize]
}

fn trim_newline(line: &mut Vec<u8>) {
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_log_line_and_normalizes_path() {
        let line = br#"{"host":"example.com","path":"/users/123/orders/550e8400-e29b-41d4-a716-446655440000?x=1","status":200,"response_time_us":12500,"bytes_sent":42,"is_bot":true,"cache_status":"HIT"}"#;
        let entry = parse_proxy_log_line(line).expect("parse line");
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.path, "/users/{id}/orders/{id}");
        assert_eq!(entry.duration_ms, 12.5);
        assert!(entry.is_bot);
    }

    #[test]
    fn aggregates_status_latency_and_cache_counters() {
        let agg = RouteAggregator::new(256, 10_000);
        agg.record_line(br#"{"host":"example.com","path":"/","status":200,"response_time_us":1000,"bytes_sent":10,"cache_status":"HIT"}"#);
        agg.record_line(br#"{"host":"example.com","path":"/","status":503,"response_time_us":9000,"bytes_sent":20,"cache_status":"MISS"}"#);
        agg.record_line(br#"{"host":"other.com","path":"/","status":404,"response_time_us":5000,"bytes_sent":30}"#);

        let all = agg.snapshot(None);
        assert_eq!(all.len(), 2);
        let filtered = agg.snapshot(Some("EXAMPLE.com"));
        assert_eq!(filtered.len(), 1);
        let route = &filtered[0];
        assert_eq!(route.request_count, 2);
        assert_eq!(route.status_2xx, 1);
        assert_eq!(route.status_5xx, 1);
        assert_eq!(route.bytes_sent, 30);
        assert_eq!(route.cache_hits, 1);
        assert_eq!(route.cache_misses, 1);
        assert_eq!(route.latency_p50_ms, 1.0);
        assert_eq!(route.latency_p95_ms, 9.0);
    }

    #[test]
    fn collect_and_reset_drains_buckets() {
        let agg = RouteAggregator::new(256, 10_000);
        agg.record_line(br#"{"host":"example.com","path":"/","status":200,"response_time_us":1000,"bytes_sent":10}"#);

        let first = agg.collect_and_reset_proto();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].domain, "example.com");
        assert!(agg.collect_and_reset_proto().is_empty());
    }

    #[test]
    fn route_cap_evicts_coldest_bucket() {
        let agg = RouteAggregator::new(1, 10_000);
        agg.record_line(br#"{"host":"a.com","path":"/a","status":200}"#);
        agg.record_line(br#"{"host":"b.com","path":"/b","status":200}"#);

        let snapshot = agg.snapshot(None);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].domain, "b.com");
    }

    #[test]
    fn latency_sample_cap_bounds_memory() {
        let agg = RouteAggregator::new(256, 1);
        agg.record_line(
            br#"{"host":"example.com","path":"/","status":200,"response_time_us":1000}"#,
        );
        agg.record_line(
            br#"{"host":"example.com","path":"/","status":200,"response_time_us":9000}"#,
        );
        let snapshot = agg.snapshot(None);
        assert_eq!(snapshot[0].request_count, 2);
        assert_eq!(snapshot[0].latency_p95_ms, 1.0);
    }
}
