//! `TelemetryService` served from the store (agent-protocol.md 6, 7, 9.7):
//! `QueryLogs` (history and `follow`, which tails the store), `SearchTraces`,
//! `GetTrace`, `QueryMetrics`, `ListMetrics` and `GetTelemetryUsage`.
//!
//! History phases scan segment files on the blocking pool: at most 16 run
//! at once per agent (others wait up to 5 s, then `RATE_LIMITED`) and each
//! stops after 30 s with `TRUNCATED` (`message = "deadline"`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::Stream;
use prost::Message;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tonic::{Code, Status};

use super::records::{MetricSample, TAG_LOG, TAG_METRIC, TAG_SPAN, TAG_TRACE_SUMMARY};
use super::store::{Cursor, Direction, Kind, Producer, RawRecord, ScanSpec, Snapshot};
use super::Telemetry;
use crate::local::status_with_reason;
use crate::proto::agent::v2::{
    attribute_filter, label_matcher, log_query_response, metric_descriptor, metric_query_response,
    stream_status, trace_search_response, ErrorReason, GetTelemetryUsageResponse,
    ListMetricsRequest, ListMetricsResponse, LogBatch, LogQuery, LogQueryResponse, LogRecord,
    MetricAggregation, MetricDescriptor, MetricPoint, MetricQuery, MetricQueryResponse,
    MetricSeries, MetricSeriesBatch, PageInfo, QueryDirection, RetentionPolicy, Scope, Span,
    SpanStatusCode, StreamStatus, TelemetryKind, TelemetryUsage, Trace, TraceSearch,
    TraceSearchResponse, TraceSummary, TraceSummaryBatch,
};

const NANOS: i64 = 1_000_000_000;
const DEFAULT_LOG_LIMIT: u32 = 1_000;
const MAX_LOG_RECORDS: u32 = 10_000;
const MAX_REGEX_BYTES: usize = 512;
const MAX_CONTAINS_BYTES: usize = 4 * 1024;
const BATCH_RECORDS: usize = 500;
const BATCH_BYTES: usize = 1024 * 1024;
const FOLLOW_PER_SECOND: u64 = 2_000;
pub const KEEPALIVE: Duration = Duration::from_secs(15);
/// 9.7 / section 7: history phases.
pub const HISTORY_SLOTS: usize = 16;
const HISTORY_WAIT: Duration = Duration::from_secs(5);
const HISTORY_DEADLINE: Duration = Duration::from_secs(30);
const DEFAULT_TRACE_LIMIT: u32 = 100;
const MAX_TRACE_LIMIT: u32 = 1_000;
const MAX_TRACE_SPANS: usize = 10_000;
const MAX_TRACE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_SERIES: u32 = 100;
const MAX_SERIES: u32 = 500;
const MAX_POINTS: usize = 11_000;
const RAW_WINDOW_NANOS: i64 = 48 * 3600 * NANOS;
const ROLLUP_STEP_NANOS: i64 = 300 * NANOS;
const LATENESS: Duration = Duration::from_secs(10);
const LIST_CACHE: Duration = Duration::from_secs(30);

pub type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// `ListMetrics` descriptors and when they were read.
type MetricsCache = (Instant, Vec<MetricDescriptor>);

/// Shared state of the store-backed service.
#[derive(Clone)]
pub struct StoreQueries {
    pub telemetry: Arc<Telemetry>,
    history: Arc<Semaphore>,
    pub keepalive: Duration,
    metrics_cache: Arc<Mutex<Option<MetricsCache>>>,
}

fn invalid(message: &str) -> Status {
    Status::invalid_argument(message)
}

fn cursor_expired() -> Status {
    status_with_reason(
        Code::OutOfRange,
        "cursor or range start is in evicted data",
        ErrorReason::CursorExpired,
    )
}

fn nanos_of(ts: &prost_types::Timestamp) -> i64 {
    ts.seconds
        .saturating_mul(NANOS)
        .saturating_add(i64::from(ts.nanos))
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or_default()
}

fn ts_of(nanos: i64) -> prost_types::Timestamp {
    super::ingest::timestamp_of(nanos)
}

fn duration_nanos(d: &prost_types::Duration) -> i64 {
    d.seconds
        .saturating_mul(NANOS)
        .saturating_add(i64::from(d.nanos))
}

fn status_frame(
    kind: stream_status::Kind,
    cursor: &str,
    message: &str,
    dropped: u64,
) -> StreamStatus {
    StreamStatus {
        kind: kind as i32,
        dropped,
        cursor: cursor.to_owned(),
        message: message.to_owned(),
    }
}

fn field(filter: &str, value: &str) -> bool {
    filter.is_empty() || filter == value
}

/// Everything a history scan needs to stop: a record limit and a deadline.
struct Collected<T> {
    items: Vec<(T, String, u64)>,
    truncated: bool,
    deadline: bool,
}

fn collect<T>(
    snapshot: &Snapshot,
    spec: ScanSpec,
    limit: usize,
    deadline: Instant,
    mut keep: impl FnMut(&RawRecord) -> Option<T>,
) -> Result<Collected<T>, Status> {
    let kind = snapshot.kind();
    let mut out = Collected {
        items: Vec::new(),
        truncated: false,
        deadline: false,
    };
    for (n, record) in snapshot.scan(spec).enumerate() {
        let record = record.map_err(|e| Status::internal(format!("telemetry read failed: {e}")))?;
        if n % 1024 == 0 && Instant::now() >= deadline {
            out.deadline = true;
            break;
        }
        if let Some(item) = keep(&record) {
            if out.items.len() == limit {
                out.truncated = true;
                break;
            }
            out.items.push((item, record.cursor(kind), record.seq));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- logs

struct LogFilter {
    scope: Scope,
    sources: Vec<i32>,
    contains: Option<String>,
    case_insensitive: bool,
    regex: Option<regex::Regex>,
    levels: Vec<i32>,
    trace_id: String,
    container: String,
    run_id: String,
}

impl LogFilter {
    fn matches(&self, r: &LogRecord) -> bool {
        let s = &self.scope;
        let scope_ok = field(&s.project_id, &r.project_id)
            && field(&s.service_id, &r.service_id)
            && field(&s.deployment_id, &r.deployment_id)
            && field(&s.app_id, &r.app_id)
            && field(&s.environment, &r.environment)
            && field(&s.environment_id, &r.environment_id);
        if !scope_ok {
            return false;
        }
        if !self.sources.is_empty() && !self.sources.contains(&r.source_type) {
            return false;
        }
        if !self.levels.is_empty() && !self.levels.contains(&r.level) {
            return false;
        }
        if !field(&self.trace_id, &r.trace_id) || !field(&self.run_id, &r.run_id) {
            return false;
        }
        if !self.container.is_empty()
            && r.container_name != self.container
            && !(r.container_id.starts_with(&self.container) && self.container.len() >= 4)
        {
            return false;
        }
        if let Some(needle) = &self.contains {
            let hit = if self.case_insensitive {
                r.message.to_lowercase().contains(needle)
            } else {
                r.message.contains(needle)
            };
            if !hit {
                return false;
            }
        }
        self.regex.as_ref().is_none_or(|re| re.is_match(&r.message))
    }

    /// Producers that can hold matching records.
    fn producers(&self) -> Option<Vec<Producer>> {
        let project = &self.scope.project_id;
        if project.is_empty() || !super::store::valid_id(project) {
            return None;
        }
        Some(vec![
            Producer::System,
            Producer::Project(project.clone()),
            Producer::Otlp(project.clone()),
        ])
    }
}

struct LogPlan {
    filter: LogFilter,
    from_ts: i64,
    to_ts: i64,
    start_given: bool,
    tail: u32,
    limit: u32,
    follow: bool,
    backward: bool,
    cursor: Option<Cursor>,
}

fn log_plan(query: &LogQuery) -> Result<LogPlan, Status> {
    let backward = query.direction == QueryDirection::Backward as i32;
    if query.follow && backward {
        return Err(invalid("follow requires FORWARD"));
    }
    if query.tail > MAX_LOG_RECORDS || query.limit > MAX_LOG_RECORDS {
        return Err(invalid("tail and limit are at most 10000"));
    }
    if query.contains.len() > MAX_CONTAINS_BYTES {
        return Err(invalid("contains is too long"));
    }
    if query.levels.iter().any(|l| !(0..=6).contains(l))
        || query.source_types.iter().any(|t| !(1..=9).contains(t))
    {
        return Err(invalid("unknown level or source type"));
    }
    let regex = if query.regex.is_empty() {
        None
    } else {
        if query.regex.len() > MAX_REGEX_BYTES {
            return Err(invalid("regex is longer than 512 bytes"));
        }
        Some(
            regex::RegexBuilder::new(&query.regex)
                .case_insensitive(query.case_insensitive)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
                .map_err(|_| invalid("regex does not compile"))?,
        )
    };
    let cursor = if query.cursor.is_empty() {
        None
    } else {
        let cursor = Cursor::decode(&query.cursor).ok_or_else(|| invalid("invalid cursor"))?;
        if cursor.kind != Kind::Logs {
            return Err(invalid("invalid cursor"));
        }
        Some(cursor)
    };
    let range = query.range.unwrap_or_default();
    Ok(LogPlan {
        filter: LogFilter {
            scope: query.scope.clone().unwrap_or_default(),
            sources: query.source_types.clone(),
            contains: (!query.contains.is_empty()).then(|| {
                if query.case_insensitive {
                    query.contains.to_lowercase()
                } else {
                    query.contains.clone()
                }
            }),
            case_insensitive: query.case_insensitive,
            regex,
            levels: query.levels.clone(),
            trace_id: query.trace_id.clone(),
            container: query.container.clone(),
            run_id: query.run_id.clone(),
        },
        from_ts: range.start.as_ref().map_or(i64::MIN, nanos_of),
        to_ts: range.end.as_ref().map_or(i64::MAX, nanos_of),
        start_given: range.start.is_some(),
        tail: query.tail,
        limit: match query.limit {
            0 => DEFAULT_LOG_LIMIT,
            n => n,
        },
        follow: query.follow,
        backward,
        cursor,
    })
}

fn decode_log(record: &RawRecord, filter: &LogFilter) -> Option<LogRecord> {
    if record.tag != TAG_LOG {
        return None;
    }
    let log = LogRecord::decode(record.payload.as_slice()).ok()?;
    filter.matches(&log).then_some(log)
}

fn with_cursor(mut record: LogRecord, cursor: String) -> LogRecord {
    record.cursor = cursor;
    record
}

async fn send_logs(
    tx: &mpsc::Sender<Result<LogQueryResponse, Status>>,
    records: Vec<LogRecord>,
) -> bool {
    let mut records = records.into_iter().peekable();
    while records.peek().is_some() {
        let mut batch = Vec::new();
        let mut bytes = 0;
        while let Some(record) = records.next_if(|r| {
            batch.len() < BATCH_RECORDS
                && (batch.is_empty() || bytes + r.encoded_len() <= BATCH_BYTES)
        }) {
            bytes += record.encoded_len();
            batch.push(record);
        }
        let frame = LogQueryResponse {
            frame: Some(log_query_response::Frame::Batch(LogBatch {
                records: batch,
            })),
        };
        if tx.send(Ok(frame)).await.is_err() {
            return false;
        }
    }
    true
}

async fn send_log_status(
    tx: &mpsc::Sender<Result<LogQueryResponse, Status>>,
    status: StreamStatus,
) -> bool {
    tx.send(Ok(LogQueryResponse {
        frame: Some(log_query_response::Frame::Status(status)),
    }))
    .await
    .is_ok()
}

impl StoreQueries {
    pub fn new(telemetry: Arc<Telemetry>) -> Self {
        Self {
            telemetry,
            history: Arc::new(Semaphore::new(HISTORY_SLOTS)),
            keepalive: KEEPALIVE,
            metrics_cache: Arc::new(Mutex::new(None)),
        }
    }

    async fn history_slot(&self) -> Result<OwnedSemaphorePermit, Status> {
        match tokio::time::timeout(HISTORY_WAIT, self.history.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            _ => Err(status_with_reason(
                Code::ResourceExhausted,
                "too many concurrent telemetry queries",
                ErrorReason::RateLimited,
            )),
        }
    }

    fn check_cursor(
        &self,
        cursor: Option<&Cursor>,
        kind: Kind,
        start: Option<i64>,
    ) -> Result<(), Status> {
        match cursor {
            Some(cursor) if !self.telemetry.cursor_live(cursor) => Err(cursor_expired()),
            None if start.is_some_and(|s| self.telemetry.evicted_at(kind, s)) => {
                Err(cursor_expired())
            }
            _ => Ok(()),
        }
    }

    // ------------------------------------------------------------- logs

    pub async fn query_logs(&self, query: LogQuery) -> Result<BoxStream<LogQueryResponse>, Status> {
        let plan = log_plan(&query)?;
        self.check_cursor(
            plan.cursor.as_ref(),
            Kind::Logs,
            plan.start_given.then_some(plan.from_ts),
        )?;
        let permit = self.history_slot().await?;
        let (tx, rx) = mpsc::channel(16);
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(status) = this.run_logs(plan, permit, &tx).await {
                let _ = tx.send(Err(status)).await;
            }
        });
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn run_logs(
        &self,
        plan: LogPlan,
        permit: OwnedSemaphorePermit,
        tx: &mpsc::Sender<Result<LogQueryResponse, Status>>,
    ) -> Result<(), Status> {
        let plan = Arc::new(plan);
        let mut watch = self.telemetry.watch(Kind::Logs);
        watch.borrow_and_update();
        let snapshot = self.telemetry.snapshot(Kind::Logs);
        let deadline = Instant::now() + HISTORY_DEADLINE;
        let history = {
            let plan = plan.clone();
            tokio::task::spawn_blocking(move || -> Result<(Vec<LogRecord>, bool, bool), Status> {
                let base = ScanSpec {
                    from_ts: plan.from_ts,
                    to_ts: plan.to_ts,
                    producers: plan.filter.producers(),
                    ..Default::default()
                };
                let keep = |r: &RawRecord| decode_log(r, &plan.filter);
                let tail_mode = plan.tail > 0 && plan.cursor.is_none();
                let (spec, limit) = if plan.backward || tail_mode {
                    (
                        ScanSpec {
                            direction: Direction::Backward,
                            before_seq: plan.cursor.as_ref().map(|c| c.seq),
                            ..base
                        },
                        if tail_mode && !plan.backward {
                            plan.tail.min(plan.limit)
                        } else {
                            plan.limit
                        },
                    )
                } else {
                    (
                        ScanSpec {
                            after_seq: plan.cursor.as_ref().map(|c| c.seq),
                            ..base
                        },
                        plan.limit,
                    )
                };
                let got = collect(&snapshot, spec, limit as usize, deadline, keep)?;
                let mut records: Vec<LogRecord> = got
                    .items
                    .into_iter()
                    .map(|(r, cursor, _)| with_cursor(r, cursor))
                    .collect();
                if tail_mode && !plan.backward {
                    records.reverse();
                    // A tail that reached its count is complete, not
                    // truncated: it asked for the last N.
                    return Ok((records, false, got.deadline));
                }
                Ok((records, got.truncated, got.deadline))
            })
            .await
            .map_err(|_| Status::internal("telemetry query failed"))??
        };
        drop(permit);
        let (records, truncated, deadline_hit) = history;
        let mut last_cursor = records
            .last()
            .map(|r| r.cursor.clone())
            .or_else(|| plan.cursor.as_ref().map(Cursor::encode))
            .unwrap_or_default();
        // Follow continues after the newest delivered record (or the
        // store's head when history was empty).
        let mut after = records
            .iter()
            .filter_map(|r| Cursor::decode(&r.cursor).map(|c| c.seq))
            .max()
            .or(plan.cursor.as_ref().map(|c| c.seq))
            .unwrap_or_else(|| *watch.borrow());
        if !send_logs(tx, records).await {
            return Ok(());
        }
        if deadline_hit {
            send_log_status(
                tx,
                status_frame(stream_status::Kind::Truncated, &last_cursor, "deadline", 0),
            )
            .await;
        } else if truncated {
            send_log_status(
                tx,
                status_frame(stream_status::Kind::Truncated, &last_cursor, "limit", 0),
            )
            .await;
        }
        if !plan.follow {
            send_log_status(
                tx,
                status_frame(stream_status::Kind::End, &last_cursor, "", 0),
            )
            .await;
            return Ok(());
        }
        if !send_log_status(
            tx,
            status_frame(stream_status::Kind::CaughtUp, &last_cursor, "", 0),
        )
        .await
        {
            return Ok(());
        }
        let mut window = (Instant::now(), 0u64);
        let mut dropped = 0u64;
        loop {
            let changed = tokio::select! {
                changed = watch.changed() => changed.is_ok(),
                _ = tokio::time::sleep(self.keepalive) => false,
                _ = tx.closed() => return Ok(()),
            };
            if !changed {
                let frame = if dropped > 0 {
                    status_frame(
                        stream_status::Kind::Dropped,
                        &last_cursor,
                        "",
                        std::mem::take(&mut dropped),
                    )
                } else {
                    status_frame(stream_status::Kind::Keepalive, &last_cursor, "", 0)
                };
                if !send_log_status(tx, frame).await {
                    return Ok(());
                }
                continue;
            }
            let snapshot = self.telemetry.snapshot(Kind::Logs);
            let plan2 = plan.clone();
            let got = tokio::task::spawn_blocking(move || {
                let spec = ScanSpec {
                    after_seq: Some(after),
                    from_ts: plan2.from_ts,
                    to_ts: plan2.to_ts,
                    producers: plan2.filter.producers(),
                    ..Default::default()
                };
                collect(
                    &snapshot,
                    spec,
                    usize::MAX,
                    Instant::now() + HISTORY_DEADLINE,
                    |r| decode_log(r, &plan2.filter),
                )
            })
            .await
            .map_err(|_| Status::internal("telemetry query failed"))??;
            // Everything up to the store head at this point was scanned.
            let items = got.items;
            after = after.max(*watch.borrow_and_update());
            let mut out = Vec::new();
            for (record, cursor, seq) in items {
                after = after.max(seq);
                if window.0.elapsed() >= Duration::from_secs(1) {
                    window = (Instant::now(), 0);
                }
                if window.1 >= FOLLOW_PER_SECOND {
                    dropped += 1;
                    continue;
                }
                window.1 += 1;
                last_cursor = cursor.clone();
                out.push(with_cursor(record, cursor));
            }
            if !send_logs(tx, out).await {
                return Ok(());
            }
            if dropped > 0
                && !send_log_status(
                    tx,
                    status_frame(
                        stream_status::Kind::Dropped,
                        &last_cursor,
                        "",
                        std::mem::take(&mut dropped),
                    ),
                )
                .await
            {
                return Ok(());
            }
        }
    }

    // ----------------------------------------------------------- traces

    pub async fn search_traces(
        &self,
        search: TraceSearch,
    ) -> Result<BoxStream<TraceSearchResponse>, Status> {
        let limit = match search.limit {
            0 => DEFAULT_TRACE_LIMIT,
            n if n > MAX_TRACE_LIMIT => return Err(invalid("limit is at most 1000")),
            n => n,
        } as usize;
        let mut attr_res = Vec::new();
        for filter in &search.attributes {
            if filter.op == attribute_filter::Op::Regex as i32 {
                if filter.value.len() > MAX_REGEX_BYTES {
                    return Err(invalid("regex is longer than 512 bytes"));
                }
                attr_res.push(Some(
                    regex::RegexBuilder::new(&filter.value)
                        .size_limit(1 << 20)
                        .build()
                        .map_err(|_| invalid("regex does not compile"))?,
                ));
            } else {
                attr_res.push(None);
            }
        }
        let cursor = if search.cursor.is_empty() {
            None
        } else {
            let c = Cursor::decode(&search.cursor).ok_or_else(|| invalid("invalid cursor"))?;
            if c.kind != Kind::Traces {
                return Err(invalid("invalid cursor"));
            }
            Some(c)
        };
        let range = search.range.unwrap_or_default();
        let now = now_nanos();
        let to_ts = range.end.as_ref().map_or(i64::MAX, nanos_of);
        let from_ts = range.start.as_ref().map_or(now - 3600 * NANOS, nanos_of);
        self.check_cursor(
            cursor.as_ref(),
            Kind::Traces,
            range.start.as_ref().map(nanos_of),
        )?;
        let permit = self.history_slot().await?;
        let (tx, rx) = mpsc::channel(16);
        let this = self.clone();
        let search = Arc::new((search, attr_res));
        tokio::spawn(async move {
            let result: Result<(), Status> = async {
                let mut watch = this.telemetry.watch(Kind::Traces);
                watch.borrow_and_update();
                let snapshot = this.telemetry.snapshot(Kind::Traces);
                let deadline = Instant::now() + HISTORY_DEADLINE;
                let this2 = this.clone();
                let s2 = search.clone();
                let (found, truncated, deadline_hit) =
                    tokio::task::spawn_blocking(move || -> Result<_, Status> {
                        // Summaries are written when a trace settles; newest
                        // first is descending ingest order.
                        let spec = ScanSpec {
                            direction: Direction::Backward,
                            before_seq: cursor.as_ref().map(|c| c.seq),
                            ..Default::default()
                        };
                        let got = collect(&snapshot, spec, limit, deadline, |r| {
                            summary_match(&this2, r, &s2, from_ts, to_ts)
                        })?;
                        Ok((got.items, got.truncated, got.deadline))
                    })
                    .await
                    .map_err(|_| Status::internal("telemetry query failed"))??;
                drop(permit);
                let mut last_cursor = found.last().map(|(_, c, _)| c.clone()).unwrap_or_default();
                let mut after = *watch.borrow();
                let traces: Vec<TraceSummary> = found
                    .into_iter()
                    .map(|(mut t, c, _)| {
                        t.cursor = c;
                        t
                    })
                    .collect();
                let send = |traces: Vec<TraceSummary>| {
                    let tx = tx.clone();
                    async move {
                        for chunk in traces.chunks(BATCH_RECORDS) {
                            let frame = TraceSearchResponse {
                                frame: Some(trace_search_response::Frame::Batch(
                                    TraceSummaryBatch {
                                        traces: chunk.to_vec(),
                                    },
                                )),
                            };
                            if tx.send(Ok(frame)).await.is_err() {
                                return false;
                            }
                        }
                        true
                    }
                };
                let status = |kind, cursor: &str, message: &str| TraceSearchResponse {
                    frame: Some(trace_search_response::Frame::Status(status_frame(
                        kind, cursor, message, 0,
                    ))),
                };
                if !traces.is_empty() && !send(traces).await {
                    return Ok(());
                }
                if deadline_hit {
                    let _ = tx
                        .send(Ok(status(
                            stream_status::Kind::Truncated,
                            &last_cursor,
                            "deadline",
                        )))
                        .await;
                } else if truncated {
                    let _ = tx
                        .send(Ok(status(
                            stream_status::Kind::Truncated,
                            &last_cursor,
                            "limit",
                        )))
                        .await;
                }
                if !search.0.follow {
                    let _ = tx
                        .send(Ok(status(stream_status::Kind::End, &last_cursor, "")))
                        .await;
                    return Ok(());
                }
                if tx
                    .send(Ok(status(stream_status::Kind::CaughtUp, &last_cursor, "")))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                loop {
                    let changed = tokio::select! {
                        c = watch.changed() => c.is_ok(),
                        _ = tokio::time::sleep(this.keepalive) => false,
                        _ = tx.closed() => return Ok(()),
                    };
                    if !changed {
                        if tx
                            .send(Ok(status(stream_status::Kind::Keepalive, &last_cursor, "")))
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                        continue;
                    }
                    let snapshot = this.telemetry.snapshot(Kind::Traces);
                    let this2 = this.clone();
                    let s2 = search.clone();
                    let got = tokio::task::spawn_blocking(move || {
                        let spec = ScanSpec {
                            after_seq: Some(after),
                            ..Default::default()
                        };
                        collect(
                            &snapshot,
                            spec,
                            MAX_TRACE_LIMIT as usize,
                            Instant::now() + HISTORY_DEADLINE,
                            |r| summary_match(&this2, r, &s2, i64::MIN, i64::MAX),
                        )
                    })
                    .await
                    .map_err(|_| Status::internal("telemetry query failed"))??;
                    after = after.max(*watch.borrow());
                    let traces: Vec<TraceSummary> = got
                        .items
                        .into_iter()
                        .map(|(mut t, c, _)| {
                            last_cursor = c.clone();
                            t.cursor = c;
                            t
                        })
                        .collect();
                    if !traces.is_empty() && !send(traces).await {
                        return Ok(());
                    }
                }
            }
            .await;
            if let Err(status) = result {
                let _ = tx.send(Err(status)).await;
            }
        });
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    /// Every stored span of the trace, parents before children, capped.
    pub fn get_trace_blocking(&self, trace_id: &str) -> Result<Trace, Status> {
        if trace_id.len() != 32
            || !trace_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(invalid("trace_id is 32 lowercase hex"));
        }
        let (from_ts, to_ts) = self
            .telemetry
            .trace_bounds(trace_id)
            .unwrap_or((i64::MIN, i64::MAX));
        let snapshot = self.telemetry.snapshot(Kind::Traces);
        let spec = ScanSpec {
            from_ts,
            to_ts,
            ..Default::default()
        };
        let mut spans = Vec::new();
        let mut truncated = false;
        let mut bytes = 0usize;
        for record in snapshot.scan(spec) {
            let record =
                record.map_err(|e| Status::internal(format!("telemetry read failed: {e}")))?;
            if record.tag != TAG_SPAN {
                continue;
            }
            let Ok(span) = Span::decode(record.payload.as_slice()) else {
                continue;
            };
            if span.trace_id != trace_id {
                continue;
            }
            if spans.len() == MAX_TRACE_SPANS || bytes + record.payload.len() > MAX_TRACE_BYTES {
                truncated = true;
                break;
            }
            bytes += record.payload.len();
            spans.push(span);
        }
        if spans.is_empty() {
            return Err(Status::not_found("unknown or evicted trace"));
        }
        Ok(Trace {
            trace_id: trace_id.to_owned(),
            spans: parents_first(spans),
            truncated: truncated || self.telemetry.trace_truncated(trace_id),
        })
    }

    pub async fn get_trace(&self, trace_id: String) -> Result<Trace, Status> {
        let _permit = self.history_slot().await?;
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.get_trace_blocking(&trace_id))
            .await
            .map_err(|_| Status::internal("telemetry query failed"))?
    }

    // ---------------------------------------------------------- metrics

    pub async fn query_metrics(
        &self,
        query: MetricQuery,
    ) -> Result<BoxStream<MetricQueryResponse>, Status> {
        let plan = Arc::new(metric_plan(&query, now_nanos())?);
        let permit = self.history_slot().await?;
        let (tx, rx) = mpsc::channel(16);
        let this = self.clone();
        tokio::spawn(async move {
            let result: Result<(), Status> = async {
                let snapshot = this.telemetry.snapshot(Kind::Metrics);
                let p2 = plan.clone();
                let (series, truncated) = tokio::task::spawn_blocking(move || {
                    evaluate(&snapshot, &p2, p2.from_ts, p2.to_ts)
                })
                .await
                .map_err(|_| Status::internal("telemetry query failed"))??;
                drop(permit);
                let status = |kind, message: &str| MetricQueryResponse {
                    frame: Some(metric_query_response::Frame::Status(status_frame(
                        kind, "", message, 0,
                    ))),
                };
                let batch = |series: Vec<MetricSeries>| MetricQueryResponse {
                    frame: Some(metric_query_response::Frame::Batch(MetricSeriesBatch {
                        series,
                    })),
                };
                for chunk in series.chunks(50) {
                    if tx.send(Ok(batch(chunk.to_vec()))).await.is_err() {
                        return Ok(());
                    }
                }
                if truncated {
                    let _ = tx
                        .send(Ok(status(stream_status::Kind::Truncated, "max_series")))
                        .await;
                }
                if !plan.follow {
                    let _ = tx.send(Ok(status(stream_status::Kind::End, ""))).await;
                    return Ok(());
                }
                if tx
                    .send(Ok(status(stream_status::Kind::CaughtUp, "")))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                // Each step once it has closed plus 10 s of lateness.
                let mut next = plan.to_ts.min(now_nanos()).div_euclid(plan.step) * plan.step;
                loop {
                    let due = next + plan.step + LATENESS.as_nanos() as i64;
                    let wait = Duration::from_nanos((due - now_nanos()).max(0) as u64);
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = tx.closed() => return Ok(()),
                    }
                    let snapshot = this.telemetry.snapshot(Kind::Metrics);
                    let p2 = plan.clone();
                    let from = next;
                    let (series, _) = tokio::task::spawn_blocking(move || {
                        evaluate(&snapshot, &p2, from, from + p2.step - 1)
                    })
                    .await
                    .map_err(|_| Status::internal("telemetry query failed"))??;
                    next += plan.step;
                    let frame = if series.is_empty() {
                        status(stream_status::Kind::Keepalive, "")
                    } else {
                        batch(series)
                    };
                    if tx.send(Ok(frame)).await.is_err() {
                        return Ok(());
                    }
                }
            }
            .await;
            if let Err(status) = result {
                let _ = tx.send(Err(status)).await;
            }
        });
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    pub async fn list_metrics(
        &self,
        request: ListMetricsRequest,
    ) -> Result<ListMetricsResponse, Status> {
        let cached = self
            .metrics_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|(at, _)| at.elapsed() < LIST_CACHE)
            .map(|(_, d)| d.clone());
        let all = match cached {
            Some(all) => all,
            None => {
                let _permit = self.history_slot().await?;
                let snapshot = self.telemetry.snapshot(Kind::Metrics);
                let all = tokio::task::spawn_blocking(move || descriptors(&snapshot))
                    .await
                    .map_err(|_| Status::internal("telemetry query failed"))??;
                *self.metrics_cache.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some((Instant::now(), all.clone()));
                all
            }
        };
        let page = request.page.unwrap_or_default();
        let size = match page.page_size {
            0 => 50,
            n => n.min(500) as usize,
        };
        let offset = if page.page_token.is_empty() {
            0
        } else {
            page.page_token
                .parse::<usize>()
                .map_err(|_| invalid("invalid page_token"))?
        };
        let matching: Vec<MetricDescriptor> = all
            .into_iter()
            .filter(|d| request.source == 0 || d.source == request.source)
            .filter(|d| d.name.starts_with(&request.name_prefix))
            .collect();
        if offset > matching.len() {
            return Err(invalid("invalid page_token"));
        }
        let end = (offset + size).min(matching.len());
        Ok(ListMetricsResponse {
            metrics: matching[offset..end].to_vec(),
            page: Some(PageInfo {
                next_page_token: if end < matching.len() {
                    end.to_string()
                } else {
                    String::new()
                },
            }),
        })
    }

    // ------------------------------------------------------------ usage

    pub fn usage(&self) -> GetTelemetryUsageResponse {
        let report = self.telemetry.usage();
        let kinds = report
            .kinds
            .into_iter()
            .map(|(u, rate)| TelemetryUsage {
                kind: telemetry_kind(u.kind) as i32,
                retention: Some(RetentionPolicy {
                    max_bytes: u.retention.max_bytes,
                    max_age_days: u.retention.max_age_days,
                }),
                bytes_used: u.bytes_used,
                records: u.records,
                oldest: u.oldest_nanos.map(ts_of),
                newest: u.newest_nanos.map(ts_of),
                dropped_total: u.counters.dropped_total,
                evicted_total: u.counters.evicted_total,
                ingest_per_second: rate,
                evicted_bytes_total: u.counters.evicted_bytes_total,
                redacted_total: u.counters.redacted_total,
                retention_is_default: u.retention == u.kind.default_retention(),
            })
            .collect();
        GetTelemetryUsageResponse {
            kinds,
            disk_free_bytes: report.disk_free_bytes,
            retention_plan_digest_hex: String::new(),
            ingest_paused: report.ingest_paused,
            redaction_rules_version: super::redaction::RULES_VERSION.to_owned(),
        }
    }
}

pub fn telemetry_kind(kind: Kind) -> TelemetryKind {
    match kind {
        Kind::Logs => TelemetryKind::Logs,
        Kind::Traces => TelemetryKind::Traces,
        Kind::Metrics => TelemetryKind::Metrics,
        Kind::Analytics => TelemetryKind::Analytics,
        Kind::Http => TelemetryKind::Http,
    }
}

fn summary_match(
    this: &StoreQueries,
    record: &RawRecord,
    search: &(TraceSearch, Vec<Option<regex::Regex>>),
    from_ts: i64,
    to_ts: i64,
) -> Option<TraceSummary> {
    if record.tag != TAG_TRACE_SUMMARY {
        return None;
    }
    let stored = super::otlp::StoredSummary::decode(record.payload.as_slice()).ok()?;
    let summary = stored.summary?;
    let (s, attr_res) = search;
    let start = summary.start_time.as_ref().map_or(0, nanos_of);
    if start < from_ts || start > to_ts {
        return None;
    }
    let scope = s.scope.clone().unwrap_or_default();
    let scope_ok = field(&scope.project_id, &summary.project_id)
        && field(&scope.environment_id, &summary.environment_id)
        && field(&scope.service_id, &summary.service_id)
        && field(&scope.deployment_id, &summary.deployment_id);
    if !scope_ok {
        return None;
    }
    if !s.service_name.is_empty() && !summary.services.contains(&s.service_name) {
        return None;
    }
    if !s.span_name.is_empty() && !stored.span_names.contains(&s.span_name) {
        return None;
    }
    let duration = summary.duration.as_ref().map_or(0, duration_nanos);
    if s.min_duration
        .as_ref()
        .is_some_and(|d| duration < duration_nanos(d))
        || s.max_duration
            .as_ref()
            .is_some_and(|d| duration > duration_nanos(d))
    {
        return None;
    }
    if s.status == SpanStatusCode::Error as i32 && summary.error_span_count == 0 {
        return None;
    }
    if !s.attributes.is_empty() {
        let trace = this.get_trace_blocking(&summary.trace_id).ok()?;
        let all_match = s.attributes.iter().zip(attr_res).all(|(filter, re)| {
            trace.spans.iter().any(|span| {
                let value = span
                    .attributes
                    .get(&filter.key)
                    .or_else(|| span.resource_attributes.get(&filter.key));
                match attribute_filter::Op::try_from(filter.op).unwrap_or_default() {
                    attribute_filter::Op::Exists => value.is_some(),
                    attribute_filter::Op::Neq => value.is_some_and(|v| *v != filter.value),
                    attribute_filter::Op::Regex => {
                        value.is_some_and(|v| re.as_ref().is_some_and(|re| re.is_match(v)))
                    }
                    _ => value.is_some_and(|v| *v == filter.value),
                }
            })
        });
        if !all_match {
            return None;
        }
    }
    Some(summary)
}

/// Parents before children (roots first, then breadth-first by start time).
fn parents_first(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        let at = a.start_time.as_ref().map_or(0, nanos_of);
        let bt = b.start_time.as_ref().map_or(0, nanos_of);
        at.cmp(&bt).then_with(|| a.span_id.cmp(&b.span_id))
    });
    let ids: HashSet<String> = spans.iter().map(|s| s.span_id.clone()).collect();
    let mut children: HashMap<String, Vec<usize>> = HashMap::new();
    let mut queue = std::collections::VecDeque::new();
    for (i, span) in spans.iter().enumerate() {
        if span.parent_span_id.is_empty()
            || !ids.contains(&span.parent_span_id)
            || span.parent_span_id == span.span_id
        {
            queue.push_back(i);
        } else {
            children
                .entry(span.parent_span_id.clone())
                .or_default()
                .push(i);
        }
    }
    let mut order = Vec::with_capacity(spans.len());
    let mut seen = vec![false; spans.len()];
    while let Some(i) = queue.pop_front() {
        if seen[i] {
            continue;
        }
        seen[i] = true;
        order.push(i);
        if let Some(kids) = children.get(&spans[i].span_id) {
            queue.extend(kids.iter().copied());
        }
    }
    // Cycles: whatever is left, in start order.
    order.extend((0..spans.len()).filter(|i| !seen[*i]));
    let mut slots: Vec<Option<Span>> = spans.into_iter().map(Some).collect();
    order.into_iter().filter_map(|i| slots[i].take()).collect()
}

// --------------------------------------------------------------- metrics

struct MetricPlan {
    name: String,
    matchers: Vec<(String, label_matcher::Op, String, Option<regex::Regex>)>,
    from_ts: i64,
    to_ts: i64,
    step: i64,
    aggregation: MetricAggregation,
    group_by: Vec<String>,
    follow: bool,
    max_series: usize,
}

fn metric_plan(query: &MetricQuery, now: i64) -> Result<MetricPlan, Status> {
    if query.name.is_empty() || query.name.len() > 256 {
        return Err(invalid("name is required"));
    }
    let max_series = match query.max_series {
        0 => DEFAULT_SERIES,
        n if n > MAX_SERIES => return Err(invalid("max_series is at most 500")),
        n => n,
    } as usize;
    let range = query.range.unwrap_or_default();
    let to_ts = range.end.as_ref().map_or(now, nanos_of);
    let from_ts = range.start.as_ref().map_or(to_ts - 3600 * NANOS, nanos_of);
    if from_ts >= to_ts {
        return Err(invalid("range is empty"));
    }
    let span = to_ts - from_ts;
    let mut step = match query.step.as_ref().map(duration_nanos).unwrap_or(0) {
        s if s <= 0 => (span / 300).max(10 * NANOS),
        s => s.max(10 * NANOS),
    };
    step = step.div_euclid(10 * NANOS) * 10 * NANOS
        + if step % (10 * NANOS) == 0 {
            0
        } else {
            10 * NANOS
        };
    if from_ts < now - RAW_WINDOW_NANOS {
        step = step.max(ROLLUP_STEP_NANOS);
    }
    if span / step > MAX_POINTS as i64 {
        return Err(invalid("range / step exceeds 11000 points"));
    }
    let aggregation = MetricAggregation::try_from(query.aggregation)
        .map_err(|_| invalid("unknown aggregation"))?;
    let mut matchers = Vec::new();
    for m in &query.matchers {
        let op = label_matcher::Op::try_from(m.op).map_err(|_| invalid("unknown matcher op"))?;
        let re = match op {
            label_matcher::Op::Regex | label_matcher::Op::NotRegex => {
                if m.value.len() > MAX_REGEX_BYTES {
                    return Err(invalid("regex is longer than 512 bytes"));
                }
                Some(
                    regex::RegexBuilder::new(&format!("^(?:{})$", m.value))
                        .size_limit(1 << 20)
                        .build()
                        .map_err(|_| invalid("regex does not compile"))?,
                )
            }
            _ => None,
        };
        matchers.push((m.name.clone(), op, m.value.clone(), re));
    }
    Ok(MetricPlan {
        name: query.name.clone(),
        matchers,
        from_ts,
        to_ts,
        step,
        aggregation,
        group_by: query.group_by.clone(),
        follow: query.follow,
        max_series,
    })
}

impl MetricPlan {
    fn matches(&self, sample: &MetricSample) -> bool {
        sample.name == self.name
            && self.matchers.iter().all(|(name, op, value, re)| {
                let v = sample.labels.get(name).map_or("", String::as_str);
                match op {
                    label_matcher::Op::Neq => v != value,
                    label_matcher::Op::Regex => re.as_ref().is_some_and(|re| re.is_match(v)),
                    label_matcher::Op::NotRegex => re.as_ref().is_some_and(|re| !re.is_match(v)),
                    _ => v == value,
                }
            })
    }
}

/// Samples of one raw series inside one step window.
#[derive(Default)]
struct Window {
    values: Vec<(i64, f64)>,
    hist: Vec<(i64, Vec<u64>)>,
}

type Labels = BTreeMap<String, String>;

/// Evaluates a metric query over `[from, to]`: raw series grouped by the
/// kept labels, one point per step window.
fn evaluate(
    snapshot: &Snapshot,
    plan: &MetricPlan,
    from: i64,
    to: i64,
) -> Result<(Vec<MetricSeries>, bool), Status> {
    // Rates need the last point before the window.
    let lookback = if plan.aggregation == MetricAggregation::Rate {
        plan.step
    } else {
        0
    };
    let spec = ScanSpec {
        from_ts: from.saturating_sub(lookback),
        to_ts: to,
        producers: None,
        ..Default::default()
    };
    // raw series -> step start -> window
    let mut raw: BTreeMap<Labels, BTreeMap<i64, Window>> = BTreeMap::new();
    let mut prev: BTreeMap<Labels, (i64, f64)> = BTreeMap::new();
    let mut kind = 0;
    let mut unit = String::new();
    let mut bounds: Vec<f64> = Vec::new();
    let mut cumulative = true;
    for record in snapshot.scan(spec) {
        let record = record.map_err(|e| Status::internal(format!("telemetry read failed: {e}")))?;
        if record.tag != TAG_METRIC {
            continue;
        }
        let Ok(sample) = MetricSample::decode(record.payload.as_slice()) else {
            continue;
        };
        if !plan.matches(&sample) {
            continue;
        }
        kind = sample.kind;
        unit.clone_from(&sample.unit);
        cumulative = sample.cumulative;
        if !sample.bounds.is_empty() {
            bounds.clone_from(&sample.bounds);
        }
        let ts = record.ts_nanos;
        if ts < from {
            prev.insert(sample.labels.clone(), (ts, sample.value));
            continue;
        }
        let bucket = from + (ts - from).div_euclid(plan.step) * plan.step;
        let w = raw
            .entry(sample.labels.clone())
            .or_default()
            .entry(bucket)
            .or_default();
        w.values.push((ts, sample.value));
        if !sample.counts.is_empty() {
            w.hist.push((ts, sample.counts.clone()));
        }
    }
    let histogram = kind == metric_descriptor::Kind::Histogram as i32;
    if matches!(
        plan.aggregation,
        MetricAggregation::P50 | MetricAggregation::P95 | MetricAggregation::P99
    ) && !raw.is_empty()
        && !histogram
    {
        return Err(invalid("percentiles are for histograms only"));
    }
    // Per raw series, one value per window (rate/percentile inputs).
    let mut groups: BTreeMap<Labels, BTreeMap<i64, Vec<f64>>> = BTreeMap::new();
    let mut hist_groups: BTreeMap<Labels, BTreeMap<i64, Vec<u64>>> = BTreeMap::new();
    for (labels, windows) in raw {
        let key: Labels = if plan.group_by.is_empty() {
            labels.clone()
        } else {
            labels
                .iter()
                .filter(|(k, _)| plan.group_by.contains(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut last = prev.get(&labels).copied();
        let mut last_hist: Option<Vec<u64>> = None;
        for (bucket, mut w) in windows {
            w.values.sort_by_key(|(ts, _)| *ts);
            let values: Vec<f64> = match plan.aggregation {
                MetricAggregation::Rate => {
                    let mut increase = 0.0;
                    for &(ts, v) in &w.values {
                        if let Some((_, pv)) = last {
                            increase += if v >= pv { v - pv } else { v };
                        }
                        last = Some((ts, v));
                    }
                    vec![increase / (plan.step as f64 / NANOS as f64)]
                }
                MetricAggregation::Unspecified => {
                    w.values.last().map(|(_, v)| vec![*v]).unwrap_or_default()
                }
                _ => w.values.iter().map(|(_, v)| *v).collect(),
            };
            groups
                .entry(key.clone())
                .or_default()
                .entry(bucket)
                .or_default()
                .extend(values);
            if histogram {
                w.hist.sort_by_key(|(ts, _)| *ts);
                let mut sum: Vec<u64> = Vec::new();
                for (_, counts) in &w.hist {
                    let delta: Vec<u64> = if cumulative {
                        match &last_hist {
                            Some(prev)
                                if prev.len() == counts.len()
                                    && counts.iter().zip(prev).all(|(c, p)| c >= p) =>
                            {
                                counts.iter().zip(prev).map(|(c, p)| c - p).collect()
                            }
                            _ => counts.clone(),
                        }
                    } else {
                        counts.clone()
                    };
                    last_hist = Some(counts.clone());
                    if sum.len() < delta.len() {
                        sum.resize(delta.len(), 0);
                    }
                    for (s, d) in sum.iter_mut().zip(&delta) {
                        *s += d;
                    }
                }
                let slot = hist_groups
                    .entry(key.clone())
                    .or_default()
                    .entry(bucket)
                    .or_default();
                if slot.len() < sum.len() {
                    slot.resize(sum.len(), 0);
                }
                for (s, d) in slot.iter_mut().zip(&sum) {
                    *s += d;
                }
            }
        }
    }
    let truncated = groups.len() > plan.max_series;
    let mut out = Vec::new();
    for (labels, windows) in groups.into_iter().take(plan.max_series) {
        let mut points = Vec::new();
        for (bucket, values) in windows {
            let value = match plan.aggregation {
                MetricAggregation::P50 | MetricAggregation::P95 | MetricAggregation::P99 => {
                    let q = match plan.aggregation {
                        MetricAggregation::P50 => 0.5,
                        MetricAggregation::P95 => 0.95,
                        _ => 0.99,
                    };
                    let counts = hist_groups
                        .get(&labels)
                        .and_then(|w| w.get(&bucket))
                        .cloned()
                        .unwrap_or_default();
                    match quantile(&bounds, &counts, q) {
                        Some(v) => v,
                        None => continue,
                    }
                }
                _ => match aggregate(plan.aggregation, &values) {
                    Some(v) => v,
                    None => continue,
                },
            };
            points.push(MetricPoint {
                timestamp: Some(ts_of(bucket)),
                value,
            });
            if points.len() == MAX_POINTS {
                break;
            }
        }
        out.push(MetricSeries {
            name: plan.name.clone(),
            labels: labels.into_iter().collect(),
            unit: unit.clone(),
            points,
        });
    }
    Ok((out, truncated))
}

fn aggregate(aggregation: MetricAggregation, values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(match aggregation {
        MetricAggregation::Avg => values.iter().sum::<f64>() / values.len() as f64,
        MetricAggregation::Min => values.iter().copied().fold(f64::INFINITY, f64::min),
        MetricAggregation::Max => values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        MetricAggregation::Unspecified => *values.last()?,
        // SUM, and RATE (per-series rates add up).
        _ => values.iter().sum(),
    })
}

/// Linear interpolation inside the bucket that holds quantile `q`.
fn quantile(bounds: &[f64], counts: &[u64], q: f64) -> Option<f64> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let rank = q * total as f64;
    let mut seen = 0f64;
    for (i, &c) in counts.iter().enumerate() {
        let next = seen + c as f64;
        if next >= rank && c > 0 {
            let lower = if i == 0 {
                0.0
            } else {
                bounds.get(i - 1).copied().unwrap_or(0.0)
            };
            let upper = bounds.get(i).copied().unwrap_or(lower);
            let fraction = (rank - seen) / c as f64;
            return Some(lower + (upper - lower) * fraction);
        }
        seen = next;
    }
    bounds.last().copied()
}

fn descriptors(snapshot: &Snapshot) -> Result<Vec<MetricDescriptor>, Status> {
    let mut map: BTreeMap<String, (MetricDescriptor, BTreeSet<String>)> = BTreeMap::new();
    for record in snapshot.scan(ScanSpec::default()) {
        let record = record.map_err(|e| Status::internal(format!("telemetry read failed: {e}")))?;
        if record.tag != TAG_METRIC {
            continue;
        }
        let Ok(sample) = MetricSample::decode(record.payload.as_slice()) else {
            continue;
        };
        let entry = map.entry(sample.name.clone()).or_insert_with(|| {
            (
                MetricDescriptor {
                    name: sample.name.clone(),
                    ..Default::default()
                },
                BTreeSet::new(),
            )
        });
        entry.0.kind = sample.kind;
        entry.0.source = sample.source;
        entry.0.unit.clone_from(&sample.unit);
        if !sample.description.is_empty() {
            entry.0.description.clone_from(&sample.description);
        }
        entry.1.extend(sample.labels.keys().cloned());
    }
    Ok(map
        .into_values()
        .map(|(mut d, keys)| {
            d.label_keys = keys.into_iter().collect();
            d
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_steps_follow_the_contract() {
        let now = 1_790_000_000 * NANOS;
        let q = |range_secs: i64, step: i64| MetricQuery {
            name: "m".into(),
            range: Some(crate::proto::agent::v2::TimeRange {
                start: Some(ts_of(now - range_secs * NANOS)),
                end: Some(ts_of(now)),
            }),
            step: Some(prost_types::Duration {
                seconds: step,
                nanos: 0,
            }),
            ..Default::default()
        };
        // 1 h / 300 = 12 s, rounded up to a multiple of 10 s.
        assert_eq!(metric_plan(&q(3600, 0), now).unwrap().step, 20 * NANOS);
        assert_eq!(metric_plan(&q(600, 0), now).unwrap().step, 10 * NANOS);
        assert_eq!(metric_plan(&q(600, 3), now).unwrap().step, 10 * NANOS);
        // Older than 48 h: at least 5 minutes.
        assert_eq!(
            metric_plan(&q(3 * 86_400, 60), now).unwrap().step,
            300 * NANOS
        );
        assert!(metric_plan(&MetricQuery::default(), now).is_err());
    }

    #[test]
    fn quantiles_interpolate_inside_buckets() {
        let bounds = [10.0, 20.0, 50.0];
        let counts = [0, 10, 0, 0];
        assert_eq!(quantile(&bounds, &counts, 0.5), Some(15.0));
        assert_eq!(quantile(&bounds, &[0, 0, 0, 0], 0.5), None);
    }

    #[test]
    fn spans_come_parents_first() {
        let span = |id: &str, parent: &str, start: i64| Span {
            span_id: id.into(),
            parent_span_id: parent.into(),
            start_time: Some(ts_of(start)),
            ..Default::default()
        };
        let ordered = parents_first(vec![span("c", "b", 1), span("b", "a", 3), span("a", "", 5)]);
        let ids: Vec<&str> = ordered.iter().map(|s| s.span_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }
}
