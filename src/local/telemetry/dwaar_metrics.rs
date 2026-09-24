//! Built-in `dwaar.*` per-route metrics (agent-protocol.md 9.5; QA_M2 run 2
//! X1): the agent derives them from Dwaar's access lines.
//!
//! | Name | Kind | Label keys |
//! |---|---|---|
//! | `dwaar.request.duration` | histogram, `ms` | `project_id`, `environment_id`, `service_id`, `server_id`, `route`, `route_path`, `status_class` |
//! | `dwaar.requests` | counter, `1` | same |
//! | `dwaar.requests.5xx` | counter, `1` | the same without `status_class` |
//!
//! Every series carries every key with a non-empty value, so only records
//! whose route host belongs to a service (`routes_map`, D-063 #9) count.
//! `route` is the route host; `route_path` the request path as a template
//! (contracts v1.1.5, D-063 #12) with at most 200 templates per service per
//! metrics retention period, any further one `other`. Counters and the
//! histogram are cumulative since the agent started; a series is emitted
//! when it changed, at most once per [`EMIT_EVERY`].

use std::collections::{BTreeMap, HashMap, HashSet};

use super::journal::Access;
use super::records::MetricSample;
use super::routes::RouteOwner;
use crate::proto::agent::v2::{metric_descriptor, MetricSource};

pub const REQUESTS: &str = "dwaar.requests";
pub const REQUESTS_5XX: &str = "dwaar.requests.5xx";
pub const DURATION: &str = "dwaar.request.duration";
/// Series are emitted at most this often (seconds), like the other built-in
/// metrics.
pub const EMIT_EVERY: i64 = 10;
/// agent-protocol.md 9.5: distinct `route_path` templates per service.
pub const MAX_TEMPLATES_PER_SERVICE: usize = 200;
/// The template of every path past the per-service cap; never changes.
pub const OTHER: &str = "other";
/// The template set is reset once per metrics retention period (the
/// default 15 days, agent-protocol.md 9.2).
const TEMPLATE_PERIOD_SECS: i64 = 15 * 86_400;
/// Services whose templates are tracked; past it every path is `other`.
const MAX_SERVICES: usize = 10_000;
/// Label sets kept; past it new series are not started (memory bound).
const MAX_SERIES: usize = 20_000;
/// A segment longer than this becomes `:id`.
const MAX_LITERAL_SEGMENT: usize = 32;
/// A segment of at least this many hex characters becomes `:id`.
const MIN_HEX_ID: usize = 16;
/// Path segments kept; deeper ones become one `*`.
const MAX_SEGMENTS: usize = 5;
/// `dwaar.request.duration` bucket bounds (ms).
pub const BOUNDS_MS: [f64; 11] = [
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0,
];

type Labels = BTreeMap<String, String>;

fn uuid_shaped(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn id_segment(segment: &str) -> bool {
    segment.bytes().all(|b| b.is_ascii_digit())
        || uuid_shaped(segment)
        || (segment.len() >= MIN_HEX_ID && segment.bytes().all(|b| b.is_ascii_hexdigit()))
        || segment.chars().count() > MAX_LITERAL_SEGMENT
}

/// The `route_path` template of a request path (agent-protocol.md 9.5).
pub fn route_path(path: &str) -> String {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    let segments: Vec<&str> = path[..end].split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return "/".to_owned();
    }
    let mut out = String::new();
    for segment in segments.iter().take(MAX_SEGMENTS) {
        out.push('/');
        if id_segment(segment) {
            out.push_str(":id");
        } else {
            out.push_str(&segment.to_lowercase());
        }
    }
    if segments.len() > MAX_SEGMENTS {
        out.push_str("/*");
    }
    out
}

fn status_class(status: u16) -> Option<&'static str> {
    match status {
        100..=199 => Some("1xx"),
        200..=299 => Some("2xx"),
        300..=399 => Some("3xx"),
        400..=499 => Some("4xx"),
        500..=599 => Some("5xx"),
        _ => None,
    }
}

#[derive(Debug, Default)]
struct Series {
    count: u64,
    sum_ms: f64,
    buckets: Vec<u64>,
    dirty: bool,
}

/// The cumulative `dwaar.*` series of this agent.
#[derive(Debug, Default)]
pub struct DwaarMetrics {
    requests: HashMap<Labels, Series>,
    errors: HashMap<Labels, Series>,
    templates: HashMap<String, HashSet<String>>,
    period_start: Option<i64>,
    last_emit: Option<i64>,
}

impl DwaarMetrics {
    /// The template of `path` for `service_id`, with the per-service cap.
    fn template(&mut self, sec: i64, service_id: &str, path: &str) -> String {
        let start = *self.period_start.get_or_insert(sec);
        if sec - start >= TEMPLATE_PERIOD_SECS {
            self.templates.clear();
            self.period_start = Some(sec);
        }
        let template = route_path(path);
        if !self.templates.contains_key(service_id) && self.templates.len() >= MAX_SERVICES {
            return OTHER.to_owned();
        }
        let known = self.templates.entry(service_id.to_owned()).or_default();
        if known.contains(&template) {
            return template;
        }
        if known.len() >= MAX_TEMPLATES_PER_SERVICE {
            return OTHER.to_owned();
        }
        known.insert(template.clone());
        template
    }

    /// Counts one access line of a route host owned by `owner`.
    pub fn record(&mut self, sec: i64, access: &Access, owner: &RouteOwner, server_id: &str) {
        let Some(class) = status_class(access.status) else {
            return;
        };
        if owner.service_id.is_empty()
            || owner.project_id.is_empty()
            || owner.environment_id.is_empty()
            || server_id.is_empty()
            || access.host.is_empty()
        {
            return;
        }
        let route_path = self.template(sec, &owner.service_id, &access.path);
        let mut labels: Labels = [
            ("project_id", owner.project_id.as_str()),
            ("environment_id", owner.environment_id.as_str()),
            ("service_id", owner.service_id.as_str()),
            ("server_id", server_id),
            ("route", access.host.as_str()),
            ("route_path", route_path.as_str()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let ms = access.response_time_us as f64 / 1_000.0;
        if class == "5xx" {
            if let Some(series) = series_of(&mut self.errors, &labels) {
                series.count += 1;
                series.dirty = true;
            }
        }
        labels.insert("status_class".to_owned(), class.to_owned());
        if let Some(series) = series_of(&mut self.requests, &labels) {
            series.count += 1;
            series.sum_ms += ms;
            if series.buckets.is_empty() {
                series.buckets = vec![0; BOUNDS_MS.len() + 1];
            }
            let slot = BOUNDS_MS
                .iter()
                .position(|bound| ms <= *bound)
                .unwrap_or(BOUNDS_MS.len());
            series.buckets[slot] += 1;
            series.dirty = true;
        }
    }

    /// The changed series as samples, at most once per [`EMIT_EVERY`]
    /// (`force` ignores the interval).
    pub fn take_samples(&mut self, now_sec: i64, force: bool) -> Vec<MetricSample> {
        if !force && self.last_emit.is_some_and(|at| now_sec - at < EMIT_EVERY) {
            return Vec::new();
        }
        self.last_emit = Some(now_sec);
        let mut out = Vec::new();
        for (labels, series) in self.requests.iter_mut().filter(|(_, s)| s.dirty) {
            series.dirty = false;
            out.push(sample(
                REQUESTS,
                metric_descriptor::Kind::Counter,
                "1",
                labels,
                series.count as f64,
            ));
            let mut histogram = sample(
                DURATION,
                metric_descriptor::Kind::Histogram,
                "ms",
                labels,
                series.sum_ms,
            );
            histogram.bounds = BOUNDS_MS.to_vec();
            histogram.counts.clone_from(&series.buckets);
            out.push(histogram);
        }
        for (labels, series) in self.errors.iter_mut().filter(|(_, s)| s.dirty) {
            series.dirty = false;
            out.push(sample(
                REQUESTS_5XX,
                metric_descriptor::Kind::Counter,
                "1",
                labels,
                series.count as f64,
            ));
        }
        out.sort_by(|a, b| (&a.name, &a.labels).cmp(&(&b.name, &b.labels)));
        out
    }
}

fn series_of<'a>(map: &'a mut HashMap<Labels, Series>, labels: &Labels) -> Option<&'a mut Series> {
    if !map.contains_key(labels) && map.len() >= MAX_SERIES {
        return None;
    }
    Some(map.entry(labels.clone()).or_default())
}

fn sample(
    name: &str,
    kind: metric_descriptor::Kind,
    unit: &str,
    labels: &Labels,
    value: f64,
) -> MetricSample {
    MetricSample {
        name: name.to_owned(),
        kind: kind as i32,
        source: MetricSource::Proxy as i32,
        unit: unit.to_owned(),
        labels: labels.clone(),
        value,
        cumulative: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVC: &str = "01a0cdb5-3500-70c1-8000-000000000001";
    const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";
    const ENV: &str = "01a0cdb5-3500-70b2-8000-000000000001";
    const SERVER: &str = "01a0cdb5-3500-70a1-8000-000000000001";

    fn owner() -> RouteOwner {
        RouteOwner {
            service_id: SVC.into(),
            project_id: PROJECT.into(),
            environment_id: ENV.into(),
            source: "default".into(),
        }
    }

    fn access(path: &str, status: u16, us: u64) -> Access {
        Access {
            host: "web-production-shop.11-22-0-10.sslip.io".into(),
            path: path.into(),
            method: "GET".into(),
            status,
            response_time_us: us,
            ..Default::default()
        }
    }

    /// agent-protocol.md 9.5 (D-063 #12) examples.
    #[test]
    fn paths_become_the_contract_templates() {
        assert_eq!(
            route_path("/api/users/42/orders?x=1"),
            "/api/users/:id/orders"
        );
        assert_eq!(route_path("/api//users/"), "/api/users");
        assert_eq!(route_path("/a/b/c/d/e/f/g"), "/a/b/c/d/e/*");
        assert_eq!(route_path("/"), "/");
        assert_eq!(route_path(""), "/");
        assert_eq!(route_path("/?q=1#top"), "/");
        assert_eq!(route_path("/Hooks/ABC"), "/hooks/abc");
        assert_eq!(
            route_path("/o/01A0CDB5-3500-70C1-8000-000000000001"),
            "/o/:id"
        );
        assert_eq!(route_path("/b/0123456789abcdef"), "/b/:id");
        assert_eq!(route_path("/b/0123456789abcde"), "/b/0123456789abcde");
        assert_eq!(route_path(&format!("/x/{}", "g".repeat(33))), "/x/:id");
        assert_eq!(
            route_path(&format!("/x/{}", "g".repeat(32))),
            format!("/x/{}", "g".repeat(32))
        );
    }

    #[test]
    fn a_service_keeps_200_templates_then_other() {
        let mut m = DwaarMetrics::default();
        for n in 0..MAX_TEMPLATES_PER_SERVICE {
            assert_eq!(m.template(0, SVC, &format!("/p{n}")), format!("/p{n}"));
        }
        assert_eq!(m.template(1, SVC, "/new"), OTHER);
        assert_eq!(m.template(1, SVC, "/p7"), "/p7");
        assert_eq!(m.template(1, "another", "/new"), "/new");
        // A new retention period starts over.
        assert_eq!(m.template(TEMPLATE_PERIOD_SECS, SVC, "/new"), "/new");
    }

    #[test]
    fn requests_errors_and_durations_are_cumulative_series() {
        let mut m = DwaarMetrics::default();
        m.record(0, &access("/api/users/1", 200, 3_000), &owner(), SERVER);
        m.record(1, &access("/api/users/2", 200, 30_000), &owner(), SERVER);
        m.record(2, &access("/api/users/3", 502, 700_000), &owner(), SERVER);
        // No service: no series (every label must be non-empty).
        m.record(2, &access("/", 200, 1), &RouteOwner::default(), SERVER);
        m.record(2, &access("/", 200, 1), &owner(), "");
        let samples = m.take_samples(5, false);
        let names: Vec<&str> = samples.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [DURATION, DURATION, REQUESTS, REQUESTS, REQUESTS_5XX]
        );
        let ok = samples
            .iter()
            .find(|s| s.name == REQUESTS && s.labels["status_class"] == "2xx")
            .unwrap();
        assert_eq!(ok.value, 2.0);
        assert!(ok.cumulative);
        assert_eq!(ok.source, MetricSource::Proxy as i32);
        let keys: Vec<&str> = ok.labels.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "environment_id",
                "project_id",
                "route",
                "route_path",
                "server_id",
                "service_id",
                "status_class"
            ]
        );
        assert_eq!(ok.labels["route_path"], "/api/users/:id");
        assert_eq!(
            ok.labels["route"],
            "web-production-shop.11-22-0-10.sslip.io"
        );
        assert!(ok.labels.values().all(|v| !v.is_empty()));
        let duration = samples
            .iter()
            .find(|s| s.name == DURATION && s.labels["status_class"] == "2xx")
            .unwrap();
        assert_eq!(duration.unit, "ms");
        assert_eq!(duration.bounds, BOUNDS_MS.to_vec());
        assert_eq!(duration.counts.iter().sum::<u64>(), 2);
        assert_eq!(duration.counts[0], 1); // 3 ms ≤ 5
        assert_eq!(duration.counts[3], 1); // 30 ms ≤ 50
        assert!((duration.value - 33.0).abs() < 1e-9);
        let errors = samples.iter().find(|s| s.name == REQUESTS_5XX).unwrap();
        assert_eq!(errors.value, 1.0);
        assert!(!errors.labels.contains_key("status_class"));
        // Nothing changed: nothing emitted; within 10 s nothing either.
        assert!(m.take_samples(20, false).is_empty());
        m.record(21, &access("/api/users/4", 200, 1_000), &owner(), SERVER);
        assert!(m.take_samples(25, false).is_empty());
        let later = m.take_samples(31, false);
        assert_eq!(later.len(), 2);
        assert_eq!(
            later.iter().find(|s| s.name == REQUESTS).unwrap().value,
            3.0
        );
    }
}
