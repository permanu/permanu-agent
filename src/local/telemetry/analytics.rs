//! `QueryAnalytics` over the `analytics` rollups (agent-protocol.md 9.7,
//! contracts v1.1.2 D-060; QA_M2 run 2 X1).
//!
//! The agent writes one row per route host per closed minute
//! ([`StoredAnalyticsRow`]), under the service of that host from the
//! runner's `routes_map` (D-063 #9). A query filters by `service_ids` and
//! route hosts (`domains`; both empty = every route on the server), sums the
//! minutes into buckets (`bucket` 0 = one bucket for the range, otherwise a
//! multiple of 60 s), groups by at most 2 dimensions and keeps the top
//! `limit` rows per bucket by the first measure.
//!
//! The rollups record only the route host, so `DOMAIN` is the one dimension
//! a row can be grouped by; a query grouped by any other dimension (or with
//! a `path_prefix` other than `/`) matches no row rather than failing.
//! Summing minutes makes `UNIQUE_VISITORS` an upper bound (a visitor of two
//! minutes counts twice), latency percentiles are request-weighted means of
//! the minutes' percentiles, and `ERROR_RATE` is 5xx over all requests.
//! `exclude_bots` removes `BOT_REQUESTS` from `REQUESTS` (page views never
//! count bots).

use std::collections::{BTreeMap, HashSet};

use prost::Message;
use tonic::Status;

use super::ingest::TAG_ANALYTICS_ROW;
use super::records::StoredAnalyticsRow;
use super::store::{ScanSpec, Snapshot};
use crate::proto::agent::v2::{
    AnalyticsDimension, AnalyticsDimensionValue, AnalyticsMeasure, AnalyticsMeasureValue,
    AnalyticsQuery, AnalyticsRow,
};
use crate::signed_plan::text;

const NANOS: i64 = 1_000_000_000;
const MINUTE: i64 = 60;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 500;
const MAX_GROUP_BY: usize = 2;
const MAX_FILTER: usize = 256;
/// Buckets of one answer (a range over this many buckets is refused).
const MAX_BUCKETS: i64 = 11_000;

fn invalid(message: &str) -> Status {
    Status::invalid_argument(message)
}

/// A checked `AnalyticsQuery`.
#[derive(Debug, Clone)]
pub struct AnalyticsPlan {
    pub from_sec: i64,
    pub to_sec: i64,
    /// Seconds; 0 = one bucket for the range.
    pub bucket: i64,
    group_by: Vec<AnalyticsDimension>,
    measures: Vec<AnalyticsMeasure>,
    services: HashSet<String>,
    domains: HashSet<String>,
    exclude_bots: bool,
    limit: usize,
    /// A `path_prefix` the rollups cannot answer: no row matches.
    unanswerable: bool,
    pub follow: bool,
}

/// Checks a query; `now_sec` ends a range without an end.
pub fn plan(query: &AnalyticsQuery, now_sec: i64) -> Result<AnalyticsPlan, Status> {
    let range = query.range.clone().unwrap_or_default();
    let to_sec = range.end.as_ref().map_or(now_sec, |t| t.seconds);
    let from_sec = range.start.as_ref().map_or(to_sec - 3_600, |t| t.seconds);
    if from_sec >= to_sec {
        return Err(invalid("range is empty"));
    }
    let bucket = match query.bucket.as_ref() {
        None => 0,
        Some(d) if d.nanos != 0 => return Err(invalid("bucket is a multiple of 60 s")),
        Some(d) if d.seconds == 0 => 0,
        Some(d) if d.seconds < MINUTE || d.seconds % MINUTE != 0 => {
            return Err(invalid("bucket is a multiple of 60 s"))
        }
        Some(d) => d.seconds,
    };
    if bucket > 0 && (to_sec - from_sec) / bucket > MAX_BUCKETS {
        return Err(invalid("range / bucket exceeds 11000 buckets"));
    }
    if query.follow && bucket == 0 {
        return Err(invalid("follow needs a bucket"));
    }
    if query.group_by.len() > MAX_GROUP_BY {
        return Err(invalid("group_by has at most 2 dimensions"));
    }
    let mut group_by = Vec::new();
    for dimension in &query.group_by {
        match AnalyticsDimension::try_from(*dimension) {
            Ok(AnalyticsDimension::Unspecified) | Err(_) => {
                return Err(invalid("unknown group_by dimension"))
            }
            Ok(dimension) if group_by.contains(&dimension) => {
                return Err(invalid("group_by repeats a dimension"))
            }
            Ok(dimension) => group_by.push(dimension),
        }
    }
    let mut measures = Vec::new();
    for measure in &query.measures {
        match AnalyticsMeasure::try_from(*measure) {
            Ok(AnalyticsMeasure::Unspecified) | Err(_) => return Err(invalid("unknown measure")),
            Ok(measure) if !measures.contains(&measure) => measures.push(measure),
            Ok(_) => {}
        }
    }
    if measures.is_empty() {
        measures = vec![
            AnalyticsMeasure::Requests,
            AnalyticsMeasure::PageViews,
            AnalyticsMeasure::UniqueVisitors,
        ];
    }
    let limit = match query.limit as usize {
        0 => DEFAULT_LIMIT,
        n if n > MAX_LIMIT => return Err(invalid("limit is at most 500")),
        n => n,
    };
    if query.service_ids.len() > MAX_FILTER || query.domains.len() > MAX_FILTER {
        return Err(invalid("at most 256 service_ids and domains"));
    }
    if !query.service_ids.iter().all(|id| text::uuid7(id)) {
        return Err(invalid("service_ids are UUIDv7"));
    }
    let domains: HashSet<String> = query
        .domains
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();
    if !domains
        .iter()
        .all(|d| (1..=253).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_graphic()))
    {
        return Err(invalid("domains are route hosts"));
    }
    if query.path_prefix.len() > 1_024 {
        return Err(invalid("path_prefix is at most 1024 bytes"));
    }
    Ok(AnalyticsPlan {
        from_sec,
        to_sec,
        bucket,
        group_by,
        measures,
        services: query.service_ids.iter().cloned().collect(),
        domains,
        exclude_bots: query.exclude_bots,
        limit,
        unanswerable: !matches!(query.path_prefix.as_str(), "" | "/"),
        follow: query.follow,
    })
}

/// The sums of one group in one bucket.
#[derive(Debug, Default, Clone)]
struct Sums {
    requests: f64,
    page_views: f64,
    visitors: f64,
    bytes: f64,
    bots: f64,
    errors: f64,
    /// Request-weighted latency percentile sums (p50, p95, p99).
    latency: [f64; 3],
}

fn measure_of(row: &StoredAnalyticsRow, measure: AnalyticsMeasure) -> f64 {
    row.values
        .iter()
        .find(|v| v.measure == measure as i32)
        .map_or(0.0, |v| v.value)
        .max(0.0)
}

impl Sums {
    fn add(&mut self, row: &StoredAnalyticsRow) {
        let requests = measure_of(row, AnalyticsMeasure::Requests);
        self.requests += requests;
        self.page_views += measure_of(row, AnalyticsMeasure::PageViews);
        self.visitors += measure_of(row, AnalyticsMeasure::UniqueVisitors);
        self.bytes += measure_of(row, AnalyticsMeasure::BytesSent);
        self.bots += measure_of(row, AnalyticsMeasure::BotRequests);
        self.errors += measure_of(row, AnalyticsMeasure::ErrorRate) * requests;
        for (slot, measure) in [
            AnalyticsMeasure::LatencyP50Ms,
            AnalyticsMeasure::LatencyP95Ms,
            AnalyticsMeasure::LatencyP99Ms,
        ]
        .into_iter()
        .enumerate()
        {
            self.latency[slot] += measure_of(row, measure) * requests;
        }
    }

    /// `None` for a measure the rollups do not record.
    fn value(&self, measure: AnalyticsMeasure, exclude_bots: bool) -> Option<f64> {
        let weighted = |slot: usize| {
            if self.requests > 0.0 {
                self.latency[slot] / self.requests
            } else {
                0.0
            }
        };
        Some(match measure {
            AnalyticsMeasure::Requests if exclude_bots => (self.requests - self.bots).max(0.0),
            AnalyticsMeasure::Requests => self.requests,
            AnalyticsMeasure::PageViews => self.page_views,
            AnalyticsMeasure::UniqueVisitors => self.visitors,
            AnalyticsMeasure::BytesSent => self.bytes,
            AnalyticsMeasure::BotRequests => self.bots,
            AnalyticsMeasure::ErrorRate if self.requests > 0.0 => self.errors / self.requests,
            AnalyticsMeasure::ErrorRate => 0.0,
            AnalyticsMeasure::LatencyP50Ms => weighted(0),
            AnalyticsMeasure::LatencyP95Ms => weighted(1),
            AnalyticsMeasure::LatencyP99Ms => weighted(2),
            _ => return None,
        })
    }
}

/// The group key of a row: the value of each `group_by` dimension, `None`
/// when the row does not record one of them.
fn group_key(row: &StoredAnalyticsRow, group_by: &[AnalyticsDimension]) -> Option<Vec<String>> {
    group_by
        .iter()
        .map(|dimension| {
            row.dimensions
                .iter()
                .find(|d| d.dimension == *dimension as i32)
                .map(|d| d.value.clone())
        })
        .collect()
}

fn host_of(row: &StoredAnalyticsRow) -> String {
    row.dimensions
        .iter()
        .find(|d| d.dimension == AnalyticsDimension::Domain as i32)
        .map(|d| d.value.clone())
        .unwrap_or_default()
}

/// The rows of the minutes in `[from_sec, to_sec)`, bucketed from
/// `plan.from_sec`.
pub fn evaluate(
    snapshot: &Snapshot,
    plan: &AnalyticsPlan,
    from_sec: i64,
    to_sec: i64,
) -> Result<Vec<AnalyticsRow>, Status> {
    if plan.unanswerable {
        return Ok(Vec::new());
    }
    let spec = ScanSpec {
        from_ts: from_sec.saturating_mul(NANOS),
        to_ts: to_sec.saturating_mul(NANOS).saturating_sub(1),
        producers: None,
        ..Default::default()
    };
    let mut buckets: BTreeMap<i64, BTreeMap<Vec<String>, Sums>> = BTreeMap::new();
    for record in snapshot.scan(spec) {
        let record = record.map_err(|e| Status::internal(format!("telemetry read failed: {e}")))?;
        if record.tag != TAG_ANALYTICS_ROW {
            continue;
        }
        let Ok(row) = StoredAnalyticsRow::decode(record.payload.as_slice()) else {
            continue;
        };
        let minute = row
            .bucket_start
            .map_or(record.ts_nanos / NANOS, |t| t.seconds);
        if minute < from_sec || minute >= to_sec {
            continue;
        }
        if !plan.services.is_empty() && !plan.services.contains(&row.service_id) {
            continue;
        }
        if !plan.domains.is_empty() && !plan.domains.contains(&host_of(&row)) {
            continue;
        }
        let Some(key) = group_key(&row, &plan.group_by) else {
            continue;
        };
        let bucket = if plan.bucket == 0 {
            plan.from_sec
        } else {
            plan.from_sec + (minute - plan.from_sec).div_euclid(plan.bucket) * plan.bucket
        };
        buckets
            .entry(bucket)
            .or_default()
            .entry(key)
            .or_default()
            .add(&row);
    }
    let mut out = Vec::new();
    for (bucket, groups) in buckets {
        let mut rows: Vec<(f64, AnalyticsRow)> = groups
            .into_iter()
            .map(|(key, sums)| {
                let values: Vec<AnalyticsMeasureValue> = plan
                    .measures
                    .iter()
                    .filter_map(|m| {
                        sums.value(*m, plan.exclude_bots)
                            .map(|value| AnalyticsMeasureValue {
                                measure: *m as i32,
                                value,
                            })
                    })
                    .collect();
                let first = values.first().map_or(0.0, |v| v.value);
                let row = AnalyticsRow {
                    bucket_start: Some(prost_types::Timestamp {
                        seconds: bucket,
                        nanos: 0,
                    }),
                    dimensions: plan
                        .group_by
                        .iter()
                        .zip(key)
                        .map(|(dimension, value)| AnalyticsDimensionValue {
                            dimension: *dimension as i32,
                            value,
                        })
                        .collect(),
                    values,
                };
                (first, row)
            })
            .collect();
        rows.sort_by(|a, b| b.0.total_cmp(&a.0));
        out.extend(rows.into_iter().take(plan.limit).map(|(_, row)| row));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_defaults_to_the_last_hour_and_the_three_measures() {
        let plan = plan(&AnalyticsQuery::default(), 10_000).unwrap();
        assert_eq!(
            (plan.from_sec, plan.to_sec, plan.bucket),
            (6_400, 10_000, 0)
        );
        assert_eq!(
            plan.measures,
            [
                AnalyticsMeasure::Requests,
                AnalyticsMeasure::PageViews,
                AnalyticsMeasure::UniqueVisitors
            ]
        );
        assert_eq!(plan.limit, 50);
        let follow = AnalyticsQuery {
            follow: true,
            ..Default::default()
        };
        assert!(super::plan(&follow, 10_000).is_err());
        let prefix = AnalyticsQuery {
            path_prefix: "/api".into(),
            ..Default::default()
        };
        assert!(super::plan(&prefix, 10_000).unwrap().unanswerable);
    }
}
