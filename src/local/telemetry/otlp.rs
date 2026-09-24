//! OTLP processing (agent-protocol.md 9.5, D-053): converts OTLP spans,
//! logs and metrics into stored records, redacting every attribute, event,
//! status message and log body first (9.6), and settles traces.
//!
//! - Attribution is declared, not proven: `project_id`, `environment_id`,
//!   `service_id` and `deployment_id` come from the `permanu.*` resource
//!   attributes; the producer is `otlp:<project_id>` or `otlp:unattributed`.
//! - Limits (section 7): ≤ 10,000 items per request; attribute values
//!   ≤ 4 KiB, ≤ 128 attributes and ≤ 128 events per span; ≤ 10,000 spans per
//!   trace (then `Trace.truncated`); ≤ 10,000 active metric series, ≤ 32
//!   labels, label values ≤ 256 B; 5,000 records/s per project (9.2).
//! - A trace settles 10 s after its last span arrived, or 5 s after its
//!   root span ended; its summary record then makes it visible to
//!   `SearchTraces`. `GetTrace` reads spans, settled or not.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{metric, number_data_point};

use super::ingest::timestamp_of;
use super::records::{
    encode, level_of_severity, truncate, MetricSample, TAG_LOG, TAG_METRIC, TAG_SPAN,
    TAG_TRACE_SUMMARY,
};
use super::redaction;
use super::store::{valid_id, Kind, Producer};
use super::{Buckets, Submitted, Telemetry};
use crate::proto::agent::v2::{
    metric_descriptor, LogLevel, LogRecord, LogSourceType, MetricSource, Span, SpanEvent,
    SpanStatusCode, TraceSummary,
};

pub const MAX_ITEMS: usize = 10_000;
const MAX_ATTR_BYTES: usize = 4 * 1024;
const MAX_ATTRS: usize = 128;
const MAX_EVENTS: usize = 128;
pub const MAX_TRACE_SPANS: u32 = 10_000;
const MAX_SERIES: usize = 10_000;
const MAX_LABELS: usize = 32;
const MAX_LABEL_BYTES: usize = 256;
const PROJECT_RATE: f64 = 5_000.0;
const SETTLE_AFTER_LAST: Duration = Duration::from_secs(10);
const SETTLE_AFTER_ROOT: Duration = Duration::from_secs(5);
const SERIES_IDLE: Duration = Duration::from_secs(15 * 60);
const MAX_PENDING: usize = 100_000;
const MAX_BOUNDS: usize = 100_000;

/// The stored summary of a settled trace (`TAG_TRACE_SUMMARY`): the proto
/// summary plus the span names `SearchTraces` filters on.
#[derive(Clone, PartialEq, prost::Message)]
pub struct StoredSummary {
    #[prost(message, optional, tag = "1")]
    pub summary: Option<TraceSummary>,
    #[prost(string, repeated, tag = "2")]
    pub span_names: Vec<String>,
}

#[derive(Default)]
struct Pending {
    last_arrival: Option<Instant>,
    root_ended: Option<Instant>,
    spans: u32,
    errors: u32,
    services: BTreeSet<String>,
    names: BTreeSet<String>,
    min_start: i64,
    max_end: i64,
    root: Option<Span>,
    producer: Option<Producer>,
    truncated: bool,
}

/// Trace settling state plus the bounds `GetTrace` uses to narrow its scan.
#[derive(Default)]
pub struct Traces {
    pending: HashMap<String, Pending>,
    /// trace id -> (min start, max end, truncated) of recent traces.
    bounds: HashMap<String, (i64, i64, bool)>,
    bounds_order: std::collections::VecDeque<String>,
}

/// OTLP-side state shared by the receivers.
#[derive(Default)]
pub struct OtlpState {
    traces: Mutex<Traces>,
    projects: Mutex<Buckets>,
    series: Mutex<HashMap<u64, Instant>>,
}

/// Result of one export: items accepted and rejected.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub accepted: u64,
    pub rejected: u64,
}

/// A request over the limits (HTTP 429 / gRPC `RESOURCE_EXHAUSTED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooMany(pub &'static str);

fn nanos(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// OTLP attribute values rendered as strings (arrays and maps as JSON).
pub fn any_to_string(value: Option<&AnyValue>) -> String {
    match value.and_then(|v| v.value.as_ref()) {
        None => String::new(),
        Some(any_value::Value::StringValue(s)) => s.clone(),
        Some(any_value::Value::BoolValue(b)) => b.to_string(),
        Some(any_value::Value::IntValue(i)) => i.to_string(),
        Some(any_value::Value::DoubleValue(d)) => d.to_string(),
        Some(any_value::Value::BytesValue(b)) => hex::encode(b),
        Some(any_value::Value::StringValueStrindex(_)) => String::new(),
        Some(other) => any_to_json(other).to_string(),
    }
}

fn any_to_json(value: &any_value::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        any_value::Value::StringValue(s) => J::String(s.clone()),
        any_value::Value::BoolValue(b) => J::Bool(*b),
        any_value::Value::IntValue(i) => J::from(*i),
        any_value::Value::DoubleValue(d) => J::from(*d),
        any_value::Value::BytesValue(b) => J::String(hex::encode(b)),
        any_value::Value::ArrayValue(a) => J::Array(
            a.values
                .iter()
                .filter_map(|v| v.value.as_ref().map(any_to_json))
                .collect(),
        ),
        any_value::Value::KvlistValue(kv) => J::Object(
            kv.values
                .iter()
                .map(|kv| {
                    (
                        kv.key.clone(),
                        kv.value
                            .as_ref()
                            .and_then(|v| v.value.as_ref())
                            .map_or(J::Null, any_to_json),
                    )
                })
                .collect(),
        ),
        any_value::Value::StringValueStrindex(_) => J::Null,
    }
}

/// Attributes as a redacted, bounded map; true when redaction changed any.
fn attributes(list: &[KeyValue]) -> (HashMap<String, String>, bool) {
    let mut out = HashMap::new();
    let mut redacted = false;
    for kv in list.iter().take(MAX_ATTRS) {
        let mut key = kv.key.clone();
        truncate(&mut key, 256);
        let mut value = any_to_string(kv.value.as_ref());
        redacted |= redaction::redact_entry(&key, &mut value);
        truncate(&mut value, MAX_ATTR_BYTES);
        out.insert(key, value);
    }
    (out, redacted)
}

/// `permanu.*` identity of a resource (declared).
#[derive(Debug, Default, Clone)]
struct Identity {
    project_id: String,
    environment_id: String,
    environment: String,
    service_id: String,
    deployment_id: String,
    service_name: String,
}

impl Identity {
    fn of(resource: &HashMap<String, String>) -> Self {
        let get = |k: &str| resource.get(k).cloned().unwrap_or_default();
        Self {
            project_id: get("permanu.project_id"),
            environment_id: get("permanu.environment_id"),
            environment: get("permanu.environment"),
            service_id: get("permanu.service_id"),
            deployment_id: get("permanu.deployment_id"),
            service_name: get("service.name"),
        }
    }

    fn producer(&self) -> Producer {
        if valid_id(&self.project_id) {
            Producer::Otlp(self.project_id.clone())
        } else {
            Producer::OtlpUnattributed
        }
    }
}

fn hex_id(bytes: &[u8], len: usize) -> Option<String> {
    (bytes.len() == len && bytes.iter().any(|b| *b != 0)).then(|| hex::encode(bytes))
}

impl OtlpState {
    /// 5,000 records/s per project (its containers and OTLP together are
    /// bounded separately; this is the OTLP share, 9.2).
    fn allow(&self, producer: &Producer, n: usize) -> bool {
        let key = producer.dir_name();
        let mut buckets = self.projects.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        (0..n).all(|_| buckets.take(&key, PROJECT_RATE, PROJECT_RATE, now))
    }

    pub fn traces(
        &self,
        telemetry: &Telemetry,
        request: ExportTraceServiceRequest,
    ) -> Result<Outcome, TooMany> {
        let count: usize = request
            .resource_spans
            .iter()
            .flat_map(|r| r.scope_spans.iter())
            .map(|s| s.spans.len())
            .sum();
        if count > MAX_ITEMS {
            return Err(TooMany("more than 10000 spans in one request"));
        }
        let mut outcome = Outcome::default();
        for resource_spans in request.resource_spans {
            let (resource, _) = attributes(
                resource_spans
                    .resource
                    .as_ref()
                    .map_or(&[][..], |r| r.attributes.as_slice()),
            );
            let identity = Identity::of(&resource);
            let producer = identity.producer();
            let spans: Vec<_> = resource_spans
                .scope_spans
                .into_iter()
                .flat_map(|s| s.spans)
                .collect();
            if !self.allow(&producer, spans.len()) {
                telemetry.count_dropped(Kind::Traces, spans.len() as u64);
                return Err(TooMany("project span rate exceeded"));
            }
            for otlp in spans {
                let (Some(trace_id), Some(span_id)) =
                    (hex_id(&otlp.trace_id, 16), hex_id(&otlp.span_id, 8))
                else {
                    outcome.rejected += 1;
                    continue;
                };
                let (attrs, mut redacted) = attributes(&otlp.attributes);
                let mut name = otlp.name.clone();
                redacted |= redaction::redact_in_place(&mut name);
                truncate(&mut name, MAX_ATTR_BYTES);
                let mut events = Vec::new();
                for event in otlp.events.iter().take(MAX_EVENTS) {
                    let (ea, r) = attributes(&event.attributes);
                    redacted |= r;
                    let mut ename = event.name.clone();
                    redacted |= redaction::redact_in_place(&mut ename);
                    truncate(&mut ename, MAX_ATTR_BYTES);
                    events.push(SpanEvent {
                        name: ename,
                        time: Some(timestamp_of(nanos(event.time_unix_nano))),
                        attributes: ea,
                    });
                }
                let status = otlp.status.clone().unwrap_or_default();
                let mut status_message = status.message.clone();
                redacted |= redaction::redact_in_place(&mut status_message);
                truncate(&mut status_message, MAX_ATTR_BYTES);
                let start = nanos(otlp.start_time_unix_nano);
                let end = nanos(otlp.end_time_unix_nano).max(start);
                let span = Span {
                    trace_id: trace_id.clone(),
                    span_id,
                    parent_span_id: hex_id(&otlp.parent_span_id, 8).unwrap_or_default(),
                    name,
                    kind: otlp.kind.clamp(0, 5),
                    service_name: identity.service_name.clone(),
                    start_time: Some(timestamp_of(start)),
                    duration: Some(prost_types::Duration {
                        seconds: (end - start) / 1_000_000_000,
                        nanos: ((end - start) % 1_000_000_000) as i32,
                    }),
                    status: status.code.clamp(0, 2),
                    status_message,
                    attributes: attrs,
                    resource_attributes: resource.clone(),
                    events,
                };
                if !self.admit_span(&span, &producer, start, end) {
                    telemetry.count_dropped(Kind::Traces, 1);
                    outcome.rejected += 1;
                    continue;
                }
                match telemetry.submit(
                    Kind::Traces,
                    producer.clone(),
                    start,
                    TAG_SPAN,
                    encode(&span),
                    redacted,
                ) {
                    Submitted::Queued => outcome.accepted += 1,
                    Submitted::Dropped => outcome.rejected += 1,
                }
            }
        }
        Ok(outcome)
    }

    /// Tracks the span for settling; false when its trace is full.
    fn admit_span(&self, span: &Span, producer: &Producer, start: i64, end: i64) -> bool {
        let mut traces = self.traces.lock().unwrap_or_else(|p| p.into_inner());
        if traces.pending.len() >= MAX_PENDING && !traces.pending.contains_key(&span.trace_id) {
            return false;
        }
        let entry = traces
            .pending
            .entry(span.trace_id.clone())
            .or_insert_with(|| Pending {
                min_start: i64::MAX,
                max_end: i64::MIN,
                ..Default::default()
            });
        if entry.spans >= MAX_TRACE_SPANS {
            entry.truncated = true;
            return false;
        }
        let now = Instant::now();
        entry.spans += 1;
        entry.last_arrival = Some(now);
        if span.status == SpanStatusCode::Error as i32 {
            entry.errors += 1;
        }
        if !span.service_name.is_empty() {
            entry.services.insert(span.service_name.clone());
        }
        if entry.names.len() < 1_000 {
            entry.names.insert(span.name.clone());
        }
        entry.min_start = entry.min_start.min(start);
        entry.max_end = entry.max_end.max(end);
        if span.parent_span_id.is_empty() {
            entry.root = Some(span.clone());
            entry.root_ended = Some(now);
        }
        if entry.producer.is_none() {
            entry.producer = Some(producer.clone());
        }
        let bounds = (entry.min_start, entry.max_end, entry.truncated);
        let id = span.trace_id.clone();
        if traces.bounds.insert(id.clone(), bounds).is_none() {
            traces.bounds_order.push_back(id);
            if traces.bounds_order.len() > MAX_BOUNDS {
                if let Some(old) = traces.bounds_order.pop_front() {
                    traces.bounds.remove(&old);
                }
            }
        }
        true
    }

    /// Writes summaries of traces that settled by `now` (every second).
    pub fn settle(&self, telemetry: &Telemetry, now: Instant, force: bool) -> usize {
        let settled: Vec<(String, Pending)> = {
            let mut traces = self.traces.lock().unwrap_or_else(|p| p.into_inner());
            let ids: Vec<String> = traces
                .pending
                .iter()
                .filter(|(_, p)| {
                    force
                        || p.last_arrival.is_some_and(|at| {
                            now.saturating_duration_since(at) >= SETTLE_AFTER_LAST
                        })
                        || p.root_ended.is_some_and(|at| {
                            now.saturating_duration_since(at) >= SETTLE_AFTER_ROOT
                        })
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| traces.pending.remove(&id).map(|p| (id, p)))
                .collect()
        };
        let n = settled.len();
        for (trace_id, p) in settled {
            let root = p.root.clone().unwrap_or_default();
            let res = &root.resource_attributes;
            let get = |k: &str| res.get(k).cloned().unwrap_or_default();
            let http_status = root
                .attributes
                .get("http.response.status_code")
                .or(root.attributes.get("http.status_code"))
                .and_then(|v| v.parse().ok())
                .unwrap_or_default();
            let duration = match (&root.duration, p.root.is_some()) {
                (Some(d), true) => *d,
                _ => {
                    let d = (p.max_end - p.min_start).max(0);
                    prost_types::Duration {
                        seconds: d / 1_000_000_000,
                        nanos: (d % 1_000_000_000) as i32,
                    }
                }
            };
            let summary = TraceSummary {
                trace_id,
                root_service: root.service_name.clone(),
                root_span_name: root.name.clone(),
                start_time: Some(timestamp_of(p.min_start)),
                duration: Some(duration),
                span_count: p.spans,
                error_span_count: p.errors,
                services: p.services.into_iter().collect(),
                http_status,
                deployment_id: get("permanu.deployment_id"),
                cursor: String::new(),
                project_id: get("permanu.project_id"),
                environment_id: get("permanu.environment_id"),
                service_id: get("permanu.service_id"),
            };
            let stored = StoredSummary {
                summary: Some(summary),
                span_names: p.names.into_iter().collect(),
            };
            telemetry.submit(
                Kind::Traces,
                p.producer.unwrap_or(Producer::OtlpUnattributed),
                p.min_start,
                TAG_TRACE_SUMMARY,
                encode(&stored),
                false,
            );
        }
        n
    }

    pub fn trace_bounds(&self, trace_id: &str) -> Option<(i64, i64, bool)> {
        let traces = self.traces.lock().unwrap_or_else(|p| p.into_inner());
        traces
            .pending
            .get(trace_id)
            .map(|p| (p.min_start, p.max_end, p.truncated))
            .or_else(|| traces.bounds.get(trace_id).copied())
    }

    pub fn logs(
        &self,
        telemetry: &Telemetry,
        request: ExportLogsServiceRequest,
    ) -> Result<Outcome, TooMany> {
        let count: usize = request
            .resource_logs
            .iter()
            .flat_map(|r| r.scope_logs.iter())
            .map(|s| s.log_records.len())
            .sum();
        if count > MAX_ITEMS {
            return Err(TooMany("more than 10000 log records in one request"));
        }
        let mut outcome = Outcome::default();
        for resource_logs in request.resource_logs {
            let (resource, _) = attributes(
                resource_logs
                    .resource
                    .as_ref()
                    .map_or(&[][..], |r| r.attributes.as_slice()),
            );
            let identity = Identity::of(&resource);
            let producer = identity.producer();
            let logs: Vec<_> = resource_logs
                .scope_logs
                .into_iter()
                .flat_map(|s| s.log_records)
                .collect();
            if !self.allow(&producer, logs.len()) {
                telemetry.count_dropped(Kind::Logs, logs.len() as u64);
                return Err(TooMany("project log rate exceeded"));
            }
            for otlp in logs {
                let (mut fields, mut redacted) = attributes(&otlp.attributes);
                fields.truncate_to(32);
                fields.insert("permanu.attribution".to_owned(), "declared".to_owned());
                let mut message = any_to_string(otlp.body.as_ref());
                let mut pem = redaction::PemStream::default();
                let mut out = Vec::new();
                for piece in super::records::split_line(&message) {
                    let (text, r) = pem.line(piece);
                    redacted |= r;
                    out.push(text);
                }
                message = out.join("\n");
                let level = match level_of_severity(i64::from(otlp.severity_number)) {
                    LogLevel::Unspecified => super::records::parse_line(&otlp.severity_text).level,
                    level => level,
                };
                let ts = match otlp.time_unix_nano {
                    0 => nanos(otlp.observed_time_unix_nano),
                    t => nanos(t),
                };
                let record = LogRecord {
                    timestamp: Some(timestamp_of(ts)),
                    level: level as i32,
                    message,
                    source_type: LogSourceType::App as i32,
                    source: format!("app:{}", identity.service_name),
                    project_id: identity.project_id.clone(),
                    service_id: identity.service_id.clone(),
                    deployment_id: identity.deployment_id.clone(),
                    trace_id: hex_id(&otlp.trace_id, 16).unwrap_or_default(),
                    span_id: hex_id(&otlp.span_id, 8).unwrap_or_default(),
                    fields,
                    redacted,
                    environment_id: identity.environment_id.clone(),
                    environment: identity.environment.clone(),
                    ingest: "otlp".to_owned(),
                    ..Default::default()
                };
                match telemetry.submit(
                    Kind::Logs,
                    producer.clone(),
                    ts,
                    TAG_LOG,
                    encode(&record),
                    redacted,
                ) {
                    Submitted::Queued => outcome.accepted += 1,
                    Submitted::Dropped => outcome.rejected += 1,
                }
            }
        }
        Ok(outcome)
    }

    /// Series admission: ≤ 10,000 active series per server.
    fn admit_series(&self, sample: &MetricSample) -> bool {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        sample.name.hash(&mut hasher);
        sample.labels.hash(&mut hasher);
        let key = hasher.finish();
        let now = Instant::now();
        let mut series = self.series.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(seen) = series.get_mut(&key) {
            *seen = now;
            return true;
        }
        if series.len() >= MAX_SERIES {
            series.retain(|_, at| now.saturating_duration_since(*at) < SERIES_IDLE);
            if series.len() >= MAX_SERIES {
                return false;
            }
        }
        series.insert(key, now);
        true
    }

    /// Stores one metric sample (OTLP or the agent's own), with the series
    /// and label limits.
    pub fn metric(
        &self,
        telemetry: &Telemetry,
        producer: Producer,
        ts: i64,
        mut sample: MetricSample,
    ) -> bool {
        truncate(&mut sample.name, 256);
        if sample.labels.len() > MAX_LABELS {
            let keep: Vec<String> = sample.labels.keys().take(MAX_LABELS).cloned().collect();
            sample.labels.retain(|k, _| keep.contains(k));
        }
        for value in sample.labels.values_mut() {
            truncate(value, MAX_LABEL_BYTES);
        }
        if !self.admit_series(&sample) {
            telemetry.count_dropped(Kind::Metrics, 1);
            return false;
        }
        telemetry.submit(
            Kind::Metrics,
            producer,
            ts,
            TAG_METRIC,
            encode(&sample),
            false,
        ) == Submitted::Queued
    }

    pub fn metrics(
        &self,
        telemetry: &Telemetry,
        request: ExportMetricsServiceRequest,
    ) -> Result<Outcome, TooMany> {
        let count: usize = request
            .resource_metrics
            .iter()
            .flat_map(|r| r.scope_metrics.iter())
            .flat_map(|s| s.metrics.iter())
            .map(|m| match &m.data {
                Some(metric::Data::Gauge(g)) => g.data_points.len(),
                Some(metric::Data::Sum(s)) => s.data_points.len(),
                Some(metric::Data::Histogram(h)) => h.data_points.len(),
                Some(metric::Data::ExponentialHistogram(h)) => h.data_points.len(),
                Some(metric::Data::Summary(s)) => s.data_points.len(),
                None => 0,
            })
            .sum();
        if count > MAX_ITEMS {
            return Err(TooMany("more than 10000 data points in one request"));
        }
        let mut outcome = Outcome::default();
        for resource_metrics in request.resource_metrics {
            let (resource, _) = attributes(
                resource_metrics
                    .resource
                    .as_ref()
                    .map_or(&[][..], |r| r.attributes.as_slice()),
            );
            let identity = Identity::of(&resource);
            let producer = identity.producer();
            let base: Vec<(String, String)> = [
                ("service", &identity.service_name),
                ("project_id", &identity.project_id),
                ("environment_id", &identity.environment_id),
                ("service_id", &identity.service_id),
                ("deployment_id", &identity.deployment_id),
            ]
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.to_owned(), v.clone()))
            .collect();
            let metrics: Vec<_> = resource_metrics
                .scope_metrics
                .into_iter()
                .flat_map(|s| s.metrics)
                .collect();
            for m in metrics {
                let mut description = m.description.clone();
                redaction::redact_in_place(&mut description);
                truncate(&mut description, 1024);
                let make = |attrs: &[KeyValue], kind: metric_descriptor::Kind, cumulative: bool| {
                    let (labels, _) = attributes(attrs);
                    let mut all: std::collections::BTreeMap<String, String> =
                        labels.into_iter().collect();
                    all.extend(base.iter().cloned());
                    MetricSample {
                        name: m.name.clone(),
                        kind: kind as i32,
                        source: MetricSource::App as i32,
                        unit: m.unit.clone(),
                        labels: all,
                        description: description.clone(),
                        cumulative,
                        ..Default::default()
                    }
                };
                let mut points: Vec<(i64, MetricSample)> = Vec::new();
                match m.data {
                    Some(metric::Data::Gauge(g)) => {
                        for p in g.data_points {
                            let mut s = make(&p.attributes, metric_descriptor::Kind::Gauge, false);
                            s.value = number(&p.value);
                            points.push((nanos(p.time_unix_nano), s));
                        }
                    }
                    Some(metric::Data::Sum(sum)) => {
                        let cumulative = sum.aggregation_temporality == 2;
                        let kind = if sum.is_monotonic {
                            metric_descriptor::Kind::Counter
                        } else {
                            metric_descriptor::Kind::Gauge
                        };
                        for p in sum.data_points {
                            let mut s = make(&p.attributes, kind, cumulative);
                            s.value = number(&p.value);
                            points.push((nanos(p.time_unix_nano), s));
                        }
                    }
                    Some(metric::Data::Histogram(h)) => {
                        let cumulative = h.aggregation_temporality == 2;
                        for p in h.data_points {
                            if p.bucket_counts.len() != p.explicit_bounds.len() + 1
                                || p.bucket_counts.len() > 256
                            {
                                outcome.rejected += 1;
                                continue;
                            }
                            let mut s = make(
                                &p.attributes,
                                metric_descriptor::Kind::Histogram,
                                cumulative,
                            );
                            s.value = p.sum.unwrap_or_default();
                            s.bounds = p.explicit_bounds.clone();
                            s.counts = p.bucket_counts.clone();
                            points.push((nanos(p.time_unix_nano), s));
                        }
                    }
                    // Exponential histograms and summaries are not stored.
                    Some(_) | None => {}
                }
                if !self.allow(&producer, points.len()) {
                    telemetry.count_dropped(Kind::Metrics, points.len() as u64);
                    return Err(TooMany("project metric rate exceeded"));
                }
                for (ts, sample) in points {
                    if self.metric(telemetry, producer.clone(), ts, sample) {
                        outcome.accepted += 1;
                    } else {
                        outcome.rejected += 1;
                    }
                }
            }
        }
        Ok(outcome)
    }
}

fn number(value: &Option<number_data_point::Value>) -> f64 {
    match value {
        Some(number_data_point::Value::AsDouble(d)) => *d,
        Some(number_data_point::Value::AsInt(i)) => *i as f64,
        None => 0.0,
    }
}

trait TruncateMap {
    fn truncate_to(&mut self, n: usize);
}

impl TruncateMap for HashMap<String, String> {
    fn truncate_to(&mut self, n: usize) {
        if self.len() > n {
            let mut keys: Vec<String> = self.keys().cloned().collect();
            keys.sort();
            for k in keys.into_iter().skip(n) {
                self.remove(&k);
            }
        }
    }
}

/// Runs the settle loop (every second) for as long as `telemetry` lives.
pub fn spawn_settler(
    state: Arc<OtlpState>,
    telemetry: std::sync::Weak<Telemetry>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let Some(t) = telemetry.upgrade() else {
                return;
            };
            state.settle(&t, Instant::now(), false);
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::local::telemetry::store::ScanSpec;
    use crate::local::telemetry::test_support;
    use crate::signed_plan::test_support::temp_dir;
    use opentelemetry_proto::tonic::common::v1::KeyValue;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord as OtlpLog, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::metrics::v1::{
        Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint, ResourceMetrics,
        ScopeMetrics,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{
        span, status, ResourceSpans, ScopeSpans, Span as OtlpSpan, Status,
    };
    use prost::Message;

    pub fn kv(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(value.into())),
            }),
            ..Default::default()
        }
    }

    pub fn resource(project: &str) -> Option<Resource> {
        Some(Resource {
            attributes: vec![
                kv("service.name", "api"),
                kv("permanu.project_id", project),
                kv("permanu.environment_id", "e1"),
                kv("permanu.service_id", "s1"),
                kv("permanu.deployment_id", "d1"),
            ],
            ..Default::default()
        })
    }

    /// A recent time (one hour ago, fixed for the process). The store drops
    /// records older than their retention (traces: 3 days), so a fixed date
    /// makes these fixtures fail once it is that old.
    pub fn t0() -> u64 {
        static T0: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *T0.get_or_init(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after 1970")
                .as_secs();
            (now - 3_600) * 1_000_000_000
        })
    }

    pub fn otlp_span(trace: u8, id: u8, parent: u8, name: &str, error: bool) -> OtlpSpan {
        OtlpSpan {
            trace_id: vec![trace; 16],
            span_id: vec![id; 8],
            parent_span_id: if parent == 0 { vec![] } else { vec![parent; 8] },
            name: name.into(),
            kind: span::SpanKind::Server as i32,
            start_time_unix_nano: t0() + u64::from(id) * 1_000,
            end_time_unix_nano: t0() + 5_000_000,
            attributes: vec![
                kv("http.request.header.authorization", "Bearer abc"),
                kv("http.route", "/users"),
            ],
            status: Some(Status {
                message: if error {
                    "db password=hunter2 failed".into()
                } else {
                    String::new()
                },
                code: if error {
                    status::StatusCode::Error as i32
                } else {
                    0
                },
            }),
            ..Default::default()
        }
    }

    pub fn trace_request(project: &str, spans: Vec<OtlpSpan>) -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: resource(project),
                scope_spans: vec![ScopeSpans {
                    spans,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
    }

    #[tokio::test]
    async fn spans_are_redacted_attributed_and_settled() {
        let dir = temp_dir("otlp-spans");
        let t = test_support::open(dir.join("telemetry"));
        let state = OtlpState::default();
        let outcome = state
            .traces(
                &t,
                trace_request(
                    "p1",
                    vec![
                        otlp_span(1, 1, 0, "GET /users", false),
                        otlp_span(1, 2, 1, "db token=xyz", true),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(
            outcome,
            Outcome {
                accepted: 2,
                rejected: 0
            }
        );
        assert_eq!(state.settle(&t, Instant::now(), false), 0);
        assert_eq!(
            state.settle(&t, Instant::now() + Duration::from_secs(6), false),
            1
        );
        t.sync().await;
        let records: Vec<_> = t
            .snapshot(Kind::Traces)
            .scan(ScanSpec::default())
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert!(records
            .iter()
            .all(|r| r.producer == Producer::Otlp("p1".into())));
        let child = Span::decode(records[1].payload.as_slice()).unwrap();
        assert_eq!(child.name, "db token=[REDACTED]");
        assert_eq!(child.status_message, "db password=[REDACTED] failed");
        assert_eq!(
            child.attributes["http.request.header.authorization"],
            "[REDACTED]"
        );
        assert_eq!(child.parent_span_id, "0101010101010101");
        assert_eq!(child.trace_id, "01".repeat(16));
        let summary = StoredSummary::decode(records[2].payload.as_slice()).unwrap();
        let s = summary.summary.unwrap();
        assert_eq!(s.span_count, 2);
        assert_eq!(s.error_span_count, 1);
        assert_eq!(s.root_span_name, "GET /users");
        assert_eq!(s.root_service, "api");
        assert_eq!(s.project_id, "p1");
        assert_eq!(s.deployment_id, "d1");
        assert_eq!(
            summary.span_names,
            vec!["GET /users", "db token=[REDACTED]"]
        );
        assert_eq!(t.usage().kinds[1].0.counters.redacted_total, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn unattributed_and_oversized_requests() {
        let dir = temp_dir("otlp-limits");
        let t = test_support::open(dir.join("telemetry"));
        let state = OtlpState::default();
        state
            .traces(
                &t,
                trace_request("../bad", vec![otlp_span(2, 1, 0, "x", false)]),
            )
            .unwrap();
        state.settle(&t, Instant::now(), true);
        t.sync().await;
        let r = t
            .snapshot(Kind::Traces)
            .scan(ScanSpec::default())
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(r.producer, Producer::OtlpUnattributed);
        let many: Vec<OtlpSpan> = (0..10_001)
            .map(|_| otlp_span(3, 1, 0, "x", false))
            .collect();
        assert!(state.traces(&t, trace_request("p1", many)).is_err());
        // A span with a malformed id is rejected, not stored.
        let mut bad = otlp_span(4, 1, 0, "x", false);
        bad.span_id = vec![1; 3];
        assert_eq!(
            state
                .traces(&t, trace_request("p1", vec![bad]))
                .unwrap()
                .rejected,
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn logs_and_metrics_are_stored() {
        let dir = temp_dir("otlp-logs");
        let t = test_support::open(dir.join("telemetry"));
        let state = OtlpState::default();
        let logs = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: resource("p1"),
                scope_logs: vec![ScopeLogs {
                    log_records: vec![OtlpLog {
                        time_unix_nano: t0(),
                        severity_number: 17,
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "login api_key=sk-FAKEFAKEFAKEFAKEFAKEFAKE".into(),
                            )),
                        }),
                        attributes: vec![kv("user.password", "x"), kv("user", "bob")],
                        trace_id: vec![9; 16],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        assert_eq!(state.logs(&t, logs).unwrap().accepted, 1);
        let metrics = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: resource("p1"),
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![
                        Metric {
                            name: "queue.depth".into(),
                            unit: "1".into(),
                            data: Some(metric::Data::Gauge(Gauge {
                                data_points: vec![NumberDataPoint {
                                    time_unix_nano: t0(),
                                    value: Some(number_data_point::Value::AsInt(7)),
                                    attributes: vec![kv("queue", "mail")],
                                    ..Default::default()
                                }],
                            })),
                            ..Default::default()
                        },
                        Metric {
                            name: "http.server.duration".into(),
                            unit: "ms".into(),
                            data: Some(metric::Data::Histogram(Histogram {
                                data_points: vec![HistogramDataPoint {
                                    time_unix_nano: t0(),
                                    bucket_counts: vec![1, 2, 3],
                                    explicit_bounds: vec![10.0, 100.0],
                                    sum: Some(500.0),
                                    ..Default::default()
                                }],
                                aggregation_temporality: 1,
                            })),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        assert_eq!(state.metrics(&t, metrics).unwrap().accepted, 2);
        t.sync().await;
        let log = t
            .snapshot(Kind::Logs)
            .scan(ScanSpec::default())
            .next()
            .unwrap()
            .unwrap();
        let log = LogRecord::decode(log.payload.as_slice()).unwrap();
        assert_eq!(log.message, "login api_key=[REDACTED]");
        assert_eq!(log.level, LogLevel::Error as i32);
        assert_eq!(log.fields["user.password"], "[REDACTED]");
        assert_eq!(log.fields["permanu.attribution"], "declared");
        assert_eq!(log.ingest, "otlp");
        assert_eq!(log.trace_id, "09".repeat(16));
        assert!(log.redacted);
        let samples: Vec<MetricSample> = t
            .snapshot(Kind::Metrics)
            .scan(ScanSpec::default())
            .map(|r| MetricSample::decode(r.unwrap().payload.as_slice()).unwrap())
            .collect();
        assert_eq!(samples[0].value, 7.0);
        assert_eq!(samples[0].labels["queue"], "mail");
        assert_eq!(samples[0].labels["project_id"], "p1");
        assert_eq!(samples[1].counts, vec![1, 2, 3]);
        assert_eq!(samples[1].kind, metric_descriptor::Kind::Histogram as i32);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
