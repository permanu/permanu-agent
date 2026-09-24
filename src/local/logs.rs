//! `TelemetryService.QueryLogs` for servers in M1 (D-036, signed-plan.md
//! 14.3, capability `logs.containers.v1`): the app and service sources come
//! from the runner's read-only container ops, never from Docker directly
//! (the agent has no Docker socket, D-030) and never over SSH.
//!
//! - `list_containers` with the query's scope as label filters picks the
//!   containers; a `container` filter is resolved with `inspect_container`
//!   (a Docker id, short id or name, Permanu-labelled only).
//! - History is each container's `container_logs` tail, merged by timestamp;
//!   `follow` then streams `container_logs_follow` per container, re-listing
//!   on every keepalive so a new release's containers join the stream.
//! - Every message is redacted (AGENTS.md) before it leaves the agent; the
//!   runner redacts nothing.
//! - Cursors are `v1.<unix nanos>.<container id>.<ordinal>`; a resumed query
//!   returns only records after (FORWARD) or before (BACKWARD) the cursor.
//!
//! - `APP` is the `web`, `worker`, `static` and `cron` containers and
//!   `SERVICE` the `database` and `bucket` ones, by the runner's
//!   `service_kind` (D-045); a container started before v1.0.5 has no kind
//!   and is served as `APP`. A scope's environment matches by name (the
//!   `permanu.environment` label, matched here) or id (a runner filter).
//!
//! M1 limits: records carry no level or trace id, so a query that filters on
//! either matches nothing; every source other than `APP` and `SERVICE` is
//! `CAPABILITY_MISSING` until the M2 telemetry store.

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use tokio::sync::mpsc;
use tonic::{Code, Request, Response, Status};
use tracing::warn;

use super::runner::{self, ContainerFilter, RunnerContainer, RunnerFailure};
use super::telemetry::query::StoreQueries;
use super::telemetry::{redaction, Telemetry};
use super::{capability_missing, log_peer, status_with_reason};
use crate::proto::agent::v2::{
    log_query_response::Frame, stream_status, telemetry_service_server::TelemetryService,
    AnalyticsQuery, AnalyticsQueryResponse, ErrorReason, GetTelemetryUsageRequest,
    GetTelemetryUsageResponse, GetTraceRequest, ListMetricsRequest, ListMetricsResponse, LogBatch,
    LogQuery, LogQueryResponse, LogRecord, LogSourceType, MetricQuery, MetricQueryResponse,
    QueryDirection, StreamStatus, Trace, TraceSearch, TraceSearchResponse,
};

/// `LogQuery.limit` default and cap; `tail` cap (telemetry.proto).
const DEFAULT_LIMIT: u32 = 1_000;
const MAX_RECORDS: u32 = 10_000;
/// Containers one query reads; more are reported as `TRUNCATED`.
const MAX_CONTAINERS: usize = 50;
/// Containers one follow streams at once (each is one runner connection).
const MAX_FOLLOWED: usize = 20;
/// agent-protocol.md section 7: a batch holds at most 500 records or 1 MiB.
const BATCH_RECORDS: usize = 500;
const BATCH_BYTES: usize = 1024 * 1024;
/// agent-protocol.md section 7: follow delivers at most 2,000 records/s per
/// stream; the excess is dropped and reported as `DROPPED`.
const FOLLOW_RECORDS_PER_SECOND: u64 = 2_000;
/// Concurrent QueryLogs streams per agent (each holds runner connections).
const MAX_STREAMS: usize = 16;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_REGEX_BYTES: usize = 512;
const MAX_CONTAINS_BYTES: usize = 4 * 1024;
/// Follow keepalive (common.proto `KIND_KEEPALIVE`).
const KEEPALIVE: Duration = Duration::from_secs(15);

type LogStream = Pin<Box<dyn Stream<Item = Result<LogQueryResponse, Status>> + Send>>;

#[derive(Clone)]
pub struct TelemetrySvc {
    runner: Arc<dyn runner::Runner>,
    /// v2.1.0 (`telemetry.v1`): every RPC is served from the store; `None`
    /// keeps the M1 runner-backed `QueryLogs` (D-036).
    store: Option<StoreQueries>,
    streams: Arc<tokio::sync::Semaphore>,
    /// Follow keepalive and re-list period (`KEEPALIVE`; shorter in tests).
    keepalive: Duration,
}

impl TelemetrySvc {
    pub fn new(runner: Arc<dyn runner::Runner>) -> Self {
        Self {
            runner,
            store: None,
            streams: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS)),
            keepalive: KEEPALIVE,
        }
    }

    /// Serves every RPC from the telemetry store (`telemetry.v1`).
    pub fn with_store(runner: Arc<dyn runner::Runner>, telemetry: Arc<Telemetry>) -> Self {
        Self {
            store: Some(StoreQueries::new(telemetry)),
            ..Self::new(runner)
        }
    }
}

/// A record's position: unix nanos, container id, ordinal among that
/// container's lines with the same timestamp.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    nanos: i128,
    container_id: String,
    ordinal: u32,
}

impl Key {
    fn cursor(&self) -> String {
        format!("v1.{}.{}.{}", self.nanos, self.container_id, self.ordinal)
    }

    fn parse(cursor: &str) -> Option<Self> {
        let mut parts = cursor.split('.');
        let (Some("v1"), Some(nanos), Some(id), Some(ordinal), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        let valid_id = !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        valid_id.then_some(())?;
        Some(Self {
            nanos: nanos.parse().ok()?,
            container_id: id.to_owned(),
            ordinal: ordinal.parse().ok()?,
        })
    }
}

/// A validated `LogQuery`.
struct Plan {
    filter: ContainerFilter,
    /// Environment name (`permanu.environment`); empty matches all.
    environment: String,
    /// Which of `APP` and `SERVICE` the query wants.
    app: bool,
    service: bool,
    deployment_id: String,
    container: Option<String>,
    contains: Option<String>,
    case_insensitive: bool,
    regex: Option<regex::Regex>,
    start: Option<i128>,
    end: Option<i128>,
    tail: u32,
    limit: u32,
    follow: bool,
    backward: bool,
    cursor: Option<Key>,
    /// `levels` or `trace_id` set: records have neither in M1.
    matches_nothing: bool,
}

fn invalid(message: &str) -> Status {
    Status::invalid_argument(message)
}

fn plan_of(query: &LogQuery) -> Result<Plan, Status> {
    let served = [LogSourceType::App as i32, LogSourceType::Service as i32];
    if query.source_types.iter().any(|t| !served.contains(t)) {
        return Err(status_with_reason(
            Code::Unimplemented,
            "only APP and SERVICE logs are served before the telemetry store",
            ErrorReason::CapabilityMissing,
        ));
    }
    if !query.run_id.is_empty() {
        return Err(status_with_reason(
            Code::Unimplemented,
            "run_id needs the telemetry store",
            ErrorReason::CapabilityMissing,
        ));
    }
    let scope = query.scope.clone().unwrap_or_default();
    if !scope.app_id.is_empty() {
        return Err(invalid(
            "QueryLogs scopes by project, environment and service",
        ));
    }
    let backward = query.direction == QueryDirection::Backward as i32;
    if query.follow && backward {
        return Err(invalid("follow requires FORWARD"));
    }
    if query.tail > MAX_RECORDS || query.limit > MAX_RECORDS {
        return Err(invalid("tail and limit are at most 10000"));
    }
    if query.contains.len() > MAX_CONTAINS_BYTES {
        return Err(invalid("contains is too long"));
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
    let range = query.range.unwrap_or_default();
    let nanos = |t: Option<prost_types::Timestamp>| {
        t.map(|t| i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos))
    };
    let cursor = if query.cursor.is_empty() {
        None
    } else {
        Some(Key::parse(&query.cursor).ok_or_else(|| invalid("invalid cursor"))?)
    };
    Ok(Plan {
        filter: ContainerFilter {
            project_id: scope.project_id,
            environment_id: scope.environment_id,
            service_id: scope.service_id,
        },
        environment: scope.environment,
        app: query.source_types.is_empty() || query.source_types.contains(&served[0]),
        service: query.source_types.is_empty() || query.source_types.contains(&served[1]),
        deployment_id: scope.deployment_id,
        container: (!query.container.is_empty()).then(|| query.container.clone()),
        contains: (!query.contains.is_empty()).then(|| {
            if query.case_insensitive {
                query.contains.to_lowercase()
            } else {
                query.contains.clone()
            }
        }),
        case_insensitive: query.case_insensitive,
        regex,
        start: nanos(range.start),
        end: nanos(range.end),
        tail: query.tail,
        limit: match query.limit {
            0 => DEFAULT_LIMIT,
            n => n,
        },
        follow: query.follow,
        backward,
        cursor,
        matches_nothing: !query.levels.is_empty() || !query.trace_id.is_empty(),
    })
}

/// `2026-09-23T10:00:00.123456789Z message` (`docker logs --timestamps`):
/// unix nanos and the message; a line without a timestamp keeps it whole.
fn split_line(line: &str) -> (Option<i128>, &str) {
    let (stamp, message) = line.split_once(' ').unwrap_or((line, ""));
    match parse_nanos(stamp) {
        Some(nanos) => (Some(nanos), message),
        None => (None, line),
    }
}

pub(crate) fn parse_nanos(stamp: &str) -> Option<i128> {
    let body = stamp.strip_suffix('Z')?;
    let (seconds, fraction) = match body.split_once('.') {
        Some((seconds, fraction)) => (seconds, fraction),
        None => (body, ""),
    };
    if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole = crate::signed_plan::text::timestamp(&format!("{seconds}Z"))?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<9}").parse::<i128>().ok()?
    };
    Some(i128::from(whole) * 1_000_000_000 + nanos)
}

/// RFC 3339 seconds for the runner's `since` (floor).
fn since_of(nanos: i128) -> String {
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000)).unwrap_or(0);
    crate::signed_plan::text::format_timestamp(seconds.max(0))
}

impl Plan {
    fn text_matches(&self, message: &str) -> bool {
        if self.matches_nothing {
            return false;
        }
        if let Some(needle) = &self.contains {
            let found = if self.case_insensitive {
                message.to_lowercase().contains(needle.as_str())
            } else {
                message.contains(needle.as_str())
            };
            if !found {
                return false;
            }
        }
        self.regex.as_ref().is_none_or(|re| re.is_match(message))
    }

    fn in_range(&self, key: &Key) -> bool {
        if self.start.is_some_and(|start| key.nanos < start)
            || self.end.is_some_and(|end| key.nanos >= end)
        {
            return false;
        }
        match &self.cursor {
            Some(cursor) if self.backward => key < cursor,
            Some(cursor) => key > cursor,
            None => true,
        }
    }

    /// `since` for the runner: the cursor's second, else the range start.
    fn since(&self) -> Option<String> {
        match &self.cursor {
            Some(cursor) if !self.backward => Some(since_of(cursor.nanos)),
            _ => self.start.map(since_of),
        }
    }

    /// Lines to ask each container for.
    fn per_container_tail(&self) -> u32 {
        if self.tail > 0 && self.cursor.is_none() {
            self.tail
        } else {
            self.limit
        }
        .clamp(1, runner::MAX_LOG_TAIL)
    }

    fn wanted(&self, container: &RunnerContainer) -> bool {
        let source_wanted = match source_type_of(container) {
            LogSourceType::Service => self.service,
            _ => self.app,
        };
        source_wanted
            && (self.deployment_id.is_empty() || container.deployment_id == self.deployment_id)
            && (self.environment.is_empty() || container.environment == self.environment)
    }
}

/// One container's lines as records, with keys, in timestamp order.
fn records_of(
    container: &RunnerContainer,
    lines: impl IntoIterator<Item = (&'static str, String)>,
) -> Vec<(Key, LogRecord)> {
    let mut parsed: Vec<(i128, &'static str, String)> = lines
        .into_iter()
        .map(|(stream, line)| {
            let (nanos, message) = split_line(&line);
            (nanos.unwrap_or(0), stream, message.to_owned())
        })
        .collect();
    parsed.sort_by_key(|(nanos, _, _)| *nanos);
    let mut out = Vec::with_capacity(parsed.len());
    let mut previous: Option<(i128, u32)> = None;
    for (nanos, stream, message) in parsed {
        let ordinal = match previous {
            Some((at, ordinal)) if at == nanos => ordinal + 1,
            _ => 0,
        };
        previous = Some((nanos, ordinal));
        let key = Key {
            nanos,
            container_id: container.id.clone(),
            ordinal,
        };
        out.push((key.clone(), record(container, &key, stream, &message)));
    }
    out
}

/// D-045: managed services (`database`, `bucket`) are `SERVICE`; every
/// other kind, and a container with no kind (before v1.0.5), is `APP`.
fn source_type_of(container: &RunnerContainer) -> LogSourceType {
    match container.service_kind.as_str() {
        "database" | "bucket" => LogSourceType::Service,
        _ => LogSourceType::App,
    }
}

fn record(container: &RunnerContainer, key: &Key, stream: &str, message: &str) -> LogRecord {
    let mut end = message.len().min(MAX_MESSAGE_BYTES);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let message = &message[..end];
    // redaction-v1 (agent-protocol.md 9.6) before every M1-path return.
    let redacted = redaction::redact(message);
    let was_redacted = matches!(redacted, std::borrow::Cow::Owned(_));
    let seconds = i64::try_from(key.nanos.div_euclid(1_000_000_000)).unwrap_or(0);
    let nanos = i32::try_from(key.nanos.rem_euclid(1_000_000_000)).unwrap_or(0);
    let source_type = source_type_of(container);
    let mut fields = HashMap::new();
    for (name, value) in [
        ("environment", &container.environment),
        ("environment_id", &container.environment_id),
        ("service_kind", &container.service_kind),
    ] {
        if !value.is_empty() {
            fields.insert(name.to_owned(), value.clone());
        }
    }
    if !container.spec_digest_hex.is_empty() {
        fields.insert(
            "spec_digest_hex".to_owned(),
            container.spec_digest_hex.clone(),
        );
    }
    LogRecord {
        cursor: key.cursor(),
        timestamp: Some(prost_types::Timestamp { seconds, nanos }),
        message: redacted.into_owned(),
        source_type: source_type as i32,
        source: match source_type {
            LogSourceType::Service => format!("service:{}", container.name),
            _ => format!("app:{}", container.name),
        },
        container_id: container.id.clone(),
        container_name: container.name.clone(),
        image: container.image.clone(),
        project_id: container.project_id.clone(),
        service_id: container.service_id.clone(),
        deployment_id: container.deployment_id.clone(),
        stream: stream.to_owned(),
        fields,
        redacted: was_redacted,
        ..Default::default()
    }
}

fn unavailable(failure: &RunnerFailure) -> Status {
    Status::unavailable(format!(
        "container logs unavailable ({}): {}",
        failure.code, failure.message
    ))
}

fn status(kind: stream_status::Kind, cursor: &str, message: &str) -> LogQueryResponse {
    LogQueryResponse {
        frame: Some(Frame::Status(StreamStatus {
            kind: kind as i32,
            dropped: 0,
            cursor: cursor.to_owned(),
            message: message.to_owned(),
        })),
    }
}

async fn send_batches(
    tx: &mpsc::Sender<Result<LogQueryResponse, Status>>,
    records: Vec<LogRecord>,
) -> bool {
    let mut records = records.into_iter().peekable();
    while records.peek().is_some() {
        let mut batch = Vec::new();
        let mut bytes = 0;
        while let Some(record) = records.next_if(|r| {
            batch.len() < BATCH_RECORDS
                && (batch.is_empty() || bytes + r.message.len() + 512 <= BATCH_BYTES)
        }) {
            bytes += record.message.len() + 512;
            batch.push(record);
        }
        let frame = LogQueryResponse {
            frame: Some(Frame::Batch(LogBatch { records: batch })),
        };
        if tx.send(Ok(frame)).await.is_err() {
            return false;
        }
    }
    true
}

impl TelemetrySvc {
    /// The containers the query reads (at most `MAX_CONTAINERS`) and whether
    /// more matched.
    async fn containers(&self, plan: &Plan) -> Result<(Vec<RunnerContainer>, bool), Status> {
        let resolved = match &plan.container {
            Some(name) => match runner::inspect_container(self.runner.as_ref(), name).await {
                Ok(container) => Some(container["id"].as_str().unwrap_or_default().to_owned()),
                Err(failure) if failure.code == "not_found" => return Ok((Vec::new(), false)),
                Err(failure) => return Err(unavailable(&failure)),
            },
            None => None,
        };
        let mut containers = runner::list_containers(self.runner.as_ref(), &plan.filter)
            .await
            .map_err(|failure| unavailable(&failure))?;
        containers.retain(|c| {
            plan.wanted(c)
                && resolved
                    .as_ref()
                    .is_none_or(|id| !id.is_empty() && c.id == *id)
        });
        containers.sort_by(|a, b| a.id.cmp(&b.id));
        let truncated = containers.len() > MAX_CONTAINERS;
        containers.truncate(MAX_CONTAINERS);
        Ok((containers, truncated))
    }

    /// History: every container's tail, filtered, merged and cut to the
    /// query's size. Returns the records in delivery order, whether it was
    /// truncated, and the last key per container (for follow).
    async fn history(
        &self,
        plan: &Plan,
        containers: &[RunnerContainer],
    ) -> (Vec<(Key, LogRecord)>, bool, BTreeMap<String, Key>) {
        let tail = plan.per_container_tail();
        let since = plan.since();
        let mut all = Vec::new();
        let mut truncated = false;
        for container in containers {
            match runner::container_logs(
                self.runner.as_ref(),
                &container.id,
                tail,
                since.as_deref(),
            )
            .await
            {
                Ok(lines) => {
                    // A full tail may hide older lines.
                    truncated |= lines.len() >= tail as usize && plan.tail == 0;
                    all.extend(records_of(
                        container,
                        lines.into_iter().map(|l| (l.stream, l.line)),
                    ));
                }
                Err(failure) if failure.code == "not_found" => {}
                Err(failure) => {
                    warn!(container = %container.id, code = %failure.code, "container_logs failed");
                    truncated = true;
                }
            }
        }
        let mut last = BTreeMap::new();
        for (key, _) in &all {
            let entry = last.entry(key.container_id.clone()).or_insert(key.clone());
            if key > entry {
                *entry = key.clone();
            }
        }
        all.retain(|(key, record)| plan.in_range(key) && plan.text_matches(&record.message));
        all.sort_by(|a, b| a.0.cmp(&b.0));
        let tail_query = plan.tail > 0 && plan.cursor.is_none();
        let wanted = if tail_query { plan.tail } else { plan.limit } as usize;
        if all.len() > wanted {
            // A tail asks for the last lines only; a limit was cut short.
            truncated |= !tail_query;
            if plan.backward || tail_query {
                all.drain(..all.len() - wanted);
            } else {
                all.truncate(wanted);
            }
        }
        if plan.backward {
            all.reverse();
        }
        (all, truncated, last)
    }

    async fn run_with(
        &self,
        plan: Plan,
        containers: Vec<RunnerContainer>,
        more_containers: bool,
        tx: mpsc::Sender<Result<LogQueryResponse, Status>>,
    ) -> Result<(), Status> {
        let (records, truncated, mut last) = self.history(&plan, &containers).await;
        let mut cursor = records
            .last()
            .map(|(key, _)| key.cursor())
            .or_else(|| plan.cursor.as_ref().map(Key::cursor))
            .unwrap_or_default();
        if !send_batches(&tx, records.into_iter().map(|(_, r)| r).collect()).await {
            return Ok(());
        }
        if truncated || more_containers {
            let _ = tx
                .send(Ok(status(
                    stream_status::Kind::Truncated,
                    &cursor,
                    "the query limit or a server cap was reached",
                )))
                .await;
        }
        if !plan.follow {
            let _ = tx
                .send(Ok(status(stream_status::Kind::End, &cursor, "")))
                .await;
            return Ok(());
        }
        if tx
            .send(Ok(status(stream_status::Kind::CaughtUp, &cursor, "")))
            .await
            .is_err()
        {
            return Ok(());
        }
        self.follow(plan, containers, &mut last, &mut cursor, tx)
            .await;
        Ok(())
    }

    /// Streams live lines until the client goes away. A follow connection
    /// that ends while its container still runs (a transient runner or
    /// Docker error) is reopened at the next keepalive from the last
    /// delivered line, whose re-sent duplicates are skipped (AGENTS.md).
    async fn follow(
        &self,
        plan: Plan,
        containers: Vec<RunnerContainer>,
        last: &mut BTreeMap<String, Key>,
        cursor: &mut String,
        tx: mpsc::Sender<Result<LogQueryResponse, Status>>,
    ) {
        let (lines_tx, mut lines_rx) = mpsc::channel::<(RunnerContainer, String, String)>(256);
        let mut followed: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        let open = |container: RunnerContainer,
                    since: Option<String>,
                    followed: &mut HashMap<String, tokio::task::JoinHandle<()>>|
         -> bool {
            if followed.len() >= MAX_FOLLOWED || followed.contains_key(&container.id) {
                return false;
            }
            let runner = self.runner.clone();
            let lines_tx = lines_tx.clone();
            let id = container.id.clone();
            let task = tokio::spawn(async move {
                let Ok(mut lines) =
                    runner::container_logs_follow(runner.as_ref(), &container.id, since.as_deref())
                        .await
                else {
                    return;
                };
                while let Ok(Some(line)) = lines.next().await {
                    if line["type"] != "progress" {
                        break;
                    }
                    let stream = match line["stream"].as_str() {
                        Some("stderr") => "stderr",
                        _ => "stdout",
                    };
                    let text = line["line"].as_str().unwrap_or_default().to_owned();
                    if lines_tx
                        .send((container.clone(), stream.to_owned(), text))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            followed.insert(id, task);
            true
        };
        let now_since = since_of(
            i128::from(super::execution::Clock::now(&super::execution::SystemClock))
                * 1_000_000_000,
        );
        // Where each container's follow starts when nothing of it was
        // delivered yet: now for those of the query, the whole log (None)
        // for containers that appear later.
        let mut first_since: HashMap<String, Option<String>> = HashMap::new();
        for container in containers.into_iter().filter(|c| c.state == "running") {
            let since = last
                .get(&container.id)
                .map(|key| since_of(key.nanos))
                .unwrap_or_else(|| now_since.clone());
            first_since.insert(container.id.clone(), Some(since.clone()));
            open(container, Some(since), &mut followed);
        }
        // Per container: the newest delivered nanos and how many lines at
        // exactly that time were delivered (a follow `since` re-sends them);
        // `replayed` counts the re-sent ones skipped on the current
        // connection.
        let mut seen: HashMap<String, (i128, u32)> = last
            .iter()
            .map(|(id, key)| (id.clone(), (key.nanos, key.ordinal + 1)))
            .collect();
        let mut replayed: HashMap<String, u32> = HashMap::new();
        let mut keepalive = tokio::time::interval(self.keepalive);
        keepalive.tick().await;
        let mut window = tokio::time::Instant::now();
        let (mut sent_in_window, mut dropped) = (0_u64, 0_u64);
        loop {
            tokio::select! {
                // The client went away: close every follow connection now.
                () = tx.closed() => break,
                line = lines_rx.recv() => {
                    let Some((container, stream, text)) = line else { break };
                    let (nanos, message) = split_line(&text);
                    let nanos = nanos.unwrap_or(0);
                    let (newest, count) = seen.get(&container.id).copied().unwrap_or((i128::MIN, 0));
                    if nanos < newest {
                        continue;
                    }
                    if nanos == newest {
                        let skipped = replayed.entry(container.id.clone()).or_insert(0);
                        if *skipped < count {
                            *skipped += 1;
                            continue;
                        }
                    }
                    let ordinal = if nanos == newest { count } else { 0 };
                    seen.insert(container.id.clone(), (nanos, ordinal + 1));
                    replayed.insert(container.id.clone(), ordinal + 1);
                    let key = Key { nanos, container_id: container.id.clone(), ordinal };
                    if !plan.in_range(&key) || !plan.text_matches(message) {
                        continue;
                    }
                    if window.elapsed() >= Duration::from_secs(1) {
                        window = tokio::time::Instant::now();
                        sent_in_window = 0;
                        if dropped > 0 {
                            let mut frame = status(stream_status::Kind::Dropped, cursor, "follow rate limit");
                            if let Some(Frame::Status(status)) = frame.frame.as_mut() {
                                status.dropped = dropped;
                            }
                            dropped = 0;
                            if tx.send(Ok(frame)).await.is_err() {
                                break;
                            }
                        }
                    }
                    if sent_in_window >= FOLLOW_RECORDS_PER_SECOND {
                        dropped += 1;
                        continue;
                    }
                    sent_in_window += 1;
                    *cursor = key.cursor();
                    let record = record(&container, &key, &stream, message);
                    if !send_batches(&tx, vec![record]).await {
                        break;
                    }
                }
                _ = keepalive.tick() => {
                    if tx.send(Ok(status(stream_status::Kind::Keepalive, cursor, ""))).await.is_err() {
                        break;
                    }
                    followed.retain(|_, task| !task.is_finished());
                    if let Ok((current, _)) = self.containers(&plan).await {
                        for container in current.into_iter().filter(|c| c.state == "running") {
                            if followed.contains_key(&container.id) {
                                continue;
                            }
                            let id = container.id.clone();
                            let since = match seen.get(&id) {
                                Some((nanos, _)) => Some(since_of(*nanos)),
                                None => first_since.entry(id.clone()).or_insert(None).clone(),
                            };
                            if open(container, since, &mut followed) {
                                replayed.insert(id, 0);
                            }
                        }
                    }
                }
            }
        }
        for (_, task) in followed {
            task.abort();
        }
    }
}

#[tonic::async_trait]
impl TelemetryService for TelemetrySvc {
    type QueryLogsStream = LogStream;
    type SearchTracesStream =
        Pin<Box<dyn Stream<Item = Result<TraceSearchResponse, Status>> + Send>>;
    type QueryMetricsStream =
        Pin<Box<dyn Stream<Item = Result<MetricQueryResponse, Status>> + Send>>;
    type QueryAnalyticsStream =
        Pin<Box<dyn Stream<Item = Result<AnalyticsQueryResponse, Status>> + Send>>;

    async fn query_logs(
        &self,
        request: Request<LogQuery>,
    ) -> Result<Response<Self::QueryLogsStream>, Status> {
        log_peer(&request, "QueryLogs");
        if let Some(store) = &self.store {
            return store
                .query_logs(request.into_inner())
                .await
                .map(Response::new);
        }
        let plan = plan_of(request.get_ref())?;
        let permit = self.streams.clone().try_acquire_owned().map_err(|_| {
            status_with_reason(
                Code::ResourceExhausted,
                "too many concurrent log queries",
                ErrorReason::LimitExceeded,
            )
        })?;
        let (tx, rx) = mpsc::channel(16);
        let svc = self.clone();
        // The first answer (containers) is awaited so a runner failure is the
        // RPC's status, not a broken stream.
        let (containers, more) = svc.containers(&plan).await?;
        tokio::spawn(async move {
            let _permit = permit;
            let result = svc.run_with(plan, containers, more, tx.clone()).await;
            if let Err(status) = result {
                let _ = tx.send(Err(status)).await;
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn search_traces(
        &self,
        request: Request<TraceSearch>,
    ) -> Result<Response<Self::SearchTracesStream>, Status> {
        log_peer(&request, "SearchTraces");
        let store = self.store.as_ref().ok_or_else(capability_missing)?;
        store
            .search_traces(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn get_trace(
        &self,
        request: Request<GetTraceRequest>,
    ) -> Result<Response<Trace>, Status> {
        log_peer(&request, "GetTrace");
        let store = self.store.as_ref().ok_or_else(capability_missing)?;
        store
            .get_trace(request.into_inner().trace_id)
            .await
            .map(Response::new)
    }

    async fn query_metrics(
        &self,
        request: Request<MetricQuery>,
    ) -> Result<Response<Self::QueryMetricsStream>, Status> {
        log_peer(&request, "QueryMetrics");
        let store = self.store.as_ref().ok_or_else(capability_missing)?;
        store
            .query_metrics(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn list_metrics(
        &self,
        request: Request<ListMetricsRequest>,
    ) -> Result<Response<ListMetricsResponse>, Status> {
        log_peer(&request, "ListMetrics");
        let store = self.store.as_ref().ok_or_else(capability_missing)?;
        store
            .list_metrics(request.into_inner())
            .await
            .map(Response::new)
    }

    /// The 60 s Dwaar rollups, each under the service of its route host
    /// (`routes_map`, D-063 #9; capability `analytics.v1`).
    async fn query_analytics(
        &self,
        request: Request<AnalyticsQuery>,
    ) -> Result<Response<Self::QueryAnalyticsStream>, Status> {
        log_peer(&request, "QueryAnalytics");
        let store = self.store.as_ref().ok_or_else(capability_missing)?;
        store
            .query_analytics(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn get_telemetry_usage(
        &self,
        request: Request<GetTelemetryUsageRequest>,
    ) -> Result<Response<GetTelemetryUsageResponse>, Status> {
        log_peer(&request, "GetTelemetryUsage");
        let store = self.store.as_ref().ok_or_else(capability_missing)?;
        Ok(Response::new(store.usage()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_harness::Harness;
    use super::*;
    use crate::proto::agent::v2::{
        telemetry_service_client::TelemetryServiceClient, LogLevel, Scope,
    };
    use serde_json::json;

    const S1: &str = "01a0cdb5-3500-70c1-8000-000000000001";
    const S2: &str = "01a0cdb5-3500-70c1-8000-000000000002";

    fn container(id: &str, name: &str, service: &str, state: &str) -> serde_json::Value {
        let kind = if name.starts_with("db") {
            "database"
        } else {
            "web"
        };
        json!({"id": id, "name": name, "image": "ghcr.io/acme/web@sha256:ab",
               "state": state, "status": "Up", "created_at": "2026-09-23T09:00:00Z",
               "project_id": "p1", "environment": "production", "environment_id": "e1",
               "service_id": service, "service_kind": kind,
               "deployment_id": format!("d-{id}"), "spec_digest_hex": "cd"})
    }

    async fn harness(name: &str) -> Harness {
        let h = Harness::start(name, None).await;
        *h.runner.containers.lock().unwrap() = vec![
            container("c1", "web-1", S1, "running"),
            container("c2", "db-1", S2, "running"),
            container("c3", "old-1", S1, "exited"),
        ];
        h.runner.logs.lock().unwrap().insert(
            "c1".to_owned(),
            (
                vec![
                    "2026-09-23T10:00:01.000000001Z started token=abc".to_owned(),
                    "2026-09-23T10:00:03Z ready".to_owned(),
                ],
                vec!["2026-09-23T10:00:02Z warn".to_owned()],
            ),
        );
        h.runner.logs.lock().unwrap().insert(
            "c2".to_owned(),
            (vec!["2026-09-23T10:00:00Z db up".to_owned()], Vec::new()),
        );
        h
    }

    fn query(service: &str) -> LogQuery {
        LogQuery {
            scope: Some(Scope {
                service_id: service.to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Records and status kinds of a finished (non-follow) query.
    async fn run(h: &Harness, q: LogQuery) -> Result<(Vec<LogRecord>, Vec<StreamStatus>), Status> {
        let mut stream = TelemetryServiceClient::new(h.channel.clone())
            .query_logs(q)
            .await?
            .into_inner();
        let (mut records, mut statuses) = (Vec::new(), Vec::new());
        while let Some(frame) = stream.message().await? {
            match frame.frame {
                Some(Frame::Batch(batch)) => records.extend(batch.records),
                Some(Frame::Status(status)) => statuses.push(status),
                None => {}
            }
        }
        Ok((records, statuses))
    }

    fn messages(records: &[LogRecord]) -> Vec<&str> {
        records.iter().map(|r| r.message.as_str()).collect()
    }

    #[tokio::test]
    async fn query_logs_merges_the_runner_tail_and_redacts() {
        let h = harness("logs-tail").await;
        let (records, statuses) = run(&h, query(S1)).await.unwrap();
        // c1 and the stopped c3 (no logs) of service S1, never c2.
        assert_eq!(
            messages(&records),
            vec!["started token=[REDACTED]", "warn", "ready"]
        );
        assert!(records[0].redacted);
        assert!(!records[1].redacted);
        let warn = &records[1];
        assert_eq!(warn.stream, "stderr");
        assert_eq!(warn.container_id, "c1");
        assert_eq!(warn.container_name, "web-1");
        assert_eq!(warn.deployment_id, "d-c1");
        assert_eq!(warn.service_id, S1);
        assert_eq!(warn.source_type, LogSourceType::App as i32);
        assert_eq!(records[0].timestamp.unwrap().nanos, 1);
        let last = statuses.last().unwrap();
        assert_eq!(last.kind, stream_status::Kind::End as i32);
        assert_eq!(last.cursor, records[2].cursor);
        let requests = h.runner.requests.lock().unwrap().clone();
        assert_eq!(
            requests[0],
            json!({"op": "list_containers", "payload": {"service_id": S1}})
        );
        assert!(requests.iter().any(|r| r
            == &json!({"op": "container_logs", "payload": {"container_id": "c1", "tail": 1000}})));
        h.stop().await;
    }

    #[tokio::test]
    async fn tail_filters_cursor_and_direction() {
        let h = harness("logs-filter").await;
        let tail = run(
            &h,
            LogQuery {
                tail: 2,
                ..query(S1)
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(messages(&tail), vec!["warn", "ready"]);

        let contains = LogQuery {
            contains: "READY".to_owned(),
            case_insensitive: true,
            ..query(S1)
        };
        assert_eq!(messages(&run(&h, contains).await.unwrap().0), vec!["ready"]);
        let regex = LogQuery {
            regex: "^wa.n$".to_owned(),
            ..query(S1)
        };
        assert_eq!(messages(&run(&h, regex).await.unwrap().0), vec!["warn"]);
        let levels = LogQuery {
            levels: vec![LogLevel::Error as i32],
            ..query(S1)
        };
        assert!(run(&h, levels).await.unwrap().0.is_empty());

        let all = run(&h, query(S1)).await.unwrap().0;
        let resumed = LogQuery {
            cursor: all[0].cursor.clone(),
            ..query(S1)
        };
        assert_eq!(
            messages(&run(&h, resumed).await.unwrap().0),
            vec!["warn", "ready"]
        );
        let backward = LogQuery {
            direction: QueryDirection::Backward as i32,
            limit: 2,
            ..query(S1)
        };
        let (records, statuses) = run(&h, backward).await.unwrap();
        assert_eq!(messages(&records), vec!["ready", "warn"]);
        assert!(statuses
            .iter()
            .any(|s| s.kind == stream_status::Kind::Truncated as i32));
        h.stop().await;
    }

    #[tokio::test]
    async fn a_container_filter_is_resolved_by_inspect_container() {
        let h = harness("logs-container").await;
        let by_name = LogQuery {
            container: "db-1".to_owned(),
            ..Default::default()
        };
        assert_eq!(messages(&run(&h, by_name).await.unwrap().0), vec!["db up"]);
        assert!(h
            .runner
            .requests
            .lock()
            .unwrap()
            .contains(&json!({"op": "inspect_container", "payload": {"container_id": "db-1"}})));
        let unknown = LogQuery {
            container: "nope".to_owned(),
            ..Default::default()
        };
        let (records, statuses) = run(&h, unknown).await.unwrap();
        assert!(records.is_empty());
        assert_eq!(
            statuses.last().unwrap().kind,
            stream_status::Kind::End as i32
        );
        h.stop().await;
    }

    fn sources(source_types: &[LogSourceType]) -> LogQuery {
        LogQuery {
            source_types: source_types.iter().map(|t| *t as i32).collect(),
            ..Default::default()
        }
    }

    /// D-045: `APP` is web, worker, static and cron containers, `SERVICE` is
    /// database and bucket, from the runner's `service_kind`; a container
    /// started before v1.0.5 (no kind) stays `APP`.
    #[tokio::test]
    async fn source_types_split_app_and_service_by_service_kind() {
        let h = harness("logs-kinds").await;
        let mut legacy = container("c4", "legacy-1", S1, "running");
        legacy["service_kind"] = serde_json::Value::Null;
        legacy["environment"] = serde_json::Value::Null;
        h.runner.containers.lock().unwrap().push(legacy);
        h.runner.logs.lock().unwrap().insert(
            "c4".to_owned(),
            (vec!["2026-09-23T10:00:05Z legacy".to_owned()], Vec::new()),
        );

        let (records, _) = run(&h, sources(&[LogSourceType::Service])).await.unwrap();
        assert_eq!(messages(&records), vec!["db up"]);
        assert_eq!(records[0].source_type, LogSourceType::Service as i32);
        assert_eq!(records[0].source, "service:db-1");
        assert_eq!(records[0].fields["service_kind"], "database");
        assert_eq!(records[0].fields["environment"], "production");

        let (records, _) = run(&h, sources(&[LogSourceType::App])).await.unwrap();
        assert_eq!(
            messages(&records),
            vec!["started token=[REDACTED]", "warn", "ready", "legacy"]
        );
        assert!(records
            .iter()
            .all(|r| r.source_type == LogSourceType::App as i32 && r.source.starts_with("app:")));

        let both = [LogSourceType::App, LogSourceType::Service];
        for query in [sources(&both), LogQuery::default()] {
            let (records, _) = run(&h, query).await.unwrap();
            assert_eq!(records.len(), 5);
            assert_eq!(records[0].message, "db up");
            assert_eq!(records[0].source_type, LogSourceType::Service as i32);
        }
        h.stop().await;
    }

    /// D-045: a scope names its environment by name (the
    /// `permanu.environment` label), by id (a runner label filter) or both.
    #[tokio::test]
    async fn an_environment_scope_matches_by_name_or_id() {
        let h = harness("logs-env").await;
        let mut staging = container("c5", "web-staging", S1, "running");
        staging["environment"] = json!("staging");
        staging["environment_id"] = json!("e2");
        h.runner.containers.lock().unwrap().push(staging);
        h.runner.logs.lock().unwrap().insert(
            "c5".to_owned(),
            (
                vec!["2026-09-23T10:00:06Z staging up".to_owned()],
                Vec::new(),
            ),
        );
        let scoped = |environment: &str, environment_id: &str| LogQuery {
            scope: Some(Scope {
                environment: environment.to_owned(),
                environment_id: environment_id.to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let by_name = run(&h, scoped("staging", "")).await.unwrap().0;
        assert_eq!(messages(&by_name), vec!["staging up"]);
        // The runner filters labels by id only; a name is matched here.
        assert_eq!(
            h.runner.requests.lock().unwrap().last().cloned(),
            Some(json!({"op": "container_logs", "payload": {"container_id": "c5", "tail": 1000}}))
        );
        assert!(h
            .runner
            .requests
            .lock()
            .unwrap()
            .contains(&json!({"op": "list_containers", "payload": {}})));

        let by_id = run(&h, scoped("", "e2")).await.unwrap().0;
        assert_eq!(messages(&by_id), vec!["staging up"]);
        assert!(h
            .runner
            .requests
            .lock()
            .unwrap()
            .contains(&json!({"op": "list_containers", "payload": {"environment_id": "e2"}})));

        let production = run(&h, scoped("production", "")).await.unwrap().0;
        assert_eq!(production.len(), 4);
        assert!(production
            .iter()
            .all(|r| r.fields["environment"] == "production"));

        assert!(run(&h, scoped("staging", "e2")).await.unwrap().0.len() == 1);
        assert!(run(&h, scoped("production", "e2"))
            .await
            .unwrap()
            .0
            .is_empty());
        assert!(run(&h, scoped("preview", "")).await.unwrap().0.is_empty());
        h.stop().await;
    }

    #[tokio::test]
    async fn unsupported_queries_are_refused() {
        let h = harness("logs-refuse").await;
        let dwaar = LogQuery {
            source_types: vec![LogSourceType::Dwaar as i32],
            ..query(S1)
        };
        let status = run(&h, dwaar).await.unwrap_err();
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(
            status
                .metadata()
                .get(super::super::ERROR_REASON_HEADER)
                .unwrap(),
            "ERROR_REASON_CAPABILITY_MISSING"
        );
        for bad in [
            LogQuery {
                follow: true,
                direction: QueryDirection::Backward as i32,
                ..query(S1)
            },
            LogQuery {
                cursor: "garbage".to_owned(),
                ..query(S1)
            },
            LogQuery {
                regex: "(".to_owned(),
                ..query(S1)
            },
            LogQuery {
                tail: 10_001,
                ..query(S1)
            },
        ] {
            assert_eq!(
                run(&h, bad).await.unwrap_err().code(),
                Code::InvalidArgument
            );
        }
        h.stop().await;
    }

    #[tokio::test]
    async fn follow_streams_live_lines_after_the_history() {
        let h = harness("logs-follow").await;
        h.runner.follow_lines.lock().unwrap().insert(
            "c1".to_owned(),
            vec![
                // Re-sent by `since` (already delivered in the history).
                "2026-09-23T10:00:03Z ready".to_owned(),
                "2026-09-23T10:00:04Z live".to_owned(),
            ],
        );
        let mut stream = TelemetryServiceClient::new(h.channel.clone())
            .query_logs(LogQuery {
                tail: 1,
                follow: true,
                ..query(S1)
            })
            .await
            .unwrap()
            .into_inner();
        let mut seen = Vec::new();
        while seen.len() < 3 {
            match stream.message().await.unwrap().unwrap().frame {
                Some(Frame::Batch(batch)) => {
                    seen.extend(batch.records.into_iter().map(|r| r.message))
                }
                Some(Frame::Status(status)) => seen.push(format!("status:{}", status.kind)),
                None => {}
            }
        }
        assert_eq!(
            seen,
            vec![
                "ready".to_owned(),
                format!("status:{}", stream_status::Kind::CaughtUp as i32),
                "live".to_owned()
            ]
        );
        drop(stream);
        let follows = h
            .runner
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["op"] == "container_logs_follow")
            .cloned()
            .collect::<Vec<_>>();
        assert!(follows.contains(&json!({"op": "container_logs_follow",
            "payload": {"container_id": "c1", "since": "2026-09-23T10:00:03Z"}})));
        h.stop().await;
    }

    // AGENTS.md: a transient follow failure must not stop tailing the
    // container; the reopened stream skips what was already delivered.
    #[tokio::test]
    async fn a_broken_follow_resumes_without_duplicates() {
        let h = harness("logs-resume").await;
        h.runner
            .follow_breaks
            .store(true, std::sync::atomic::Ordering::SeqCst);
        h.runner
            .follow_lines
            .lock()
            .unwrap()
            .insert("c1".to_owned(), vec!["2026-09-23T10:00:04Z one".to_owned()]);
        let svc = TelemetrySvc {
            keepalive: Duration::from_millis(100),
            ..TelemetrySvc::new(h.core.runner.clone())
        };
        let mut stream = svc
            .query_logs(Request::new(LogQuery {
                tail: 1,
                follow: true,
                ..query(S1)
            }))
            .await
            .unwrap()
            .into_inner();
        async fn batch_messages(stream: &mut LogStream) -> Vec<String> {
            use futures::StreamExt;
            let frame = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .expect("frame in time")
                .unwrap()
                .unwrap();
            match frame.frame {
                Some(Frame::Batch(batch)) => batch.records.into_iter().map(|r| r.message).collect(),
                _ => Vec::new(),
            }
        }
        let mut records = Vec::new();
        while records.len() < 2 {
            records.extend(batch_messages(&mut stream).await);
        }
        // The next connection re-sends "one" (same second) plus a new line.
        h.runner.follow_lines.lock().unwrap().insert(
            "c1".to_owned(),
            vec![
                "2026-09-23T10:00:04Z one".to_owned(),
                "2026-09-23T10:00:05Z two".to_owned(),
            ],
        );
        while records.len() < 3 {
            records.extend(batch_messages(&mut stream).await);
        }
        assert_eq!(records, vec!["ready", "one", "two"]);
        drop(stream);
        let follows: Vec<_> = h
            .runner
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["op"] == "container_logs_follow")
            .map(|r| r["payload"]["since"].clone())
            .collect();
        assert!(follows.len() >= 2, "{follows:?}");
        assert_eq!(follows[1], json!("2026-09-23T10:00:04Z"));
        h.stop().await;
    }

    #[tokio::test]
    async fn concurrent_queries_are_bounded() {
        let h = harness("logs-limit").await;
        let svc = TelemetrySvc::new(h.core.runner.clone());
        let _all = svc
            .streams
            .clone()
            .acquire_many_owned(MAX_STREAMS as u32)
            .await
            .unwrap();
        let Err(status) = svc.query_logs(Request::new(query(S1))).await else {
            panic!("a query past the stream limit must be refused");
        };
        assert_eq!(status.code(), Code::ResourceExhausted);
        drop(_all);
        assert!(svc.query_logs(Request::new(query(S1))).await.is_ok());
        h.stop().await;
    }

    #[tokio::test]
    async fn list_containers_reads_the_runner() {
        use super::super::facts::{HostProbe, SystemProbe};
        let h = harness("logs-list").await;
        let probe = SystemProbe {
            server_id: "srv".to_owned(),
            ssh_host_key_dir: h.dir.clone(),
            runner: h.core.runner.clone(),
        };
        let running = probe.containers(false).await.unwrap();
        let ids: Vec<_> = running.iter().map(|c| c.container_id.as_str()).collect();
        assert_eq!(ids, vec!["c1", "c2"]);
        assert_eq!(probe.containers(true).await.unwrap().len(), 3);
        assert_eq!(running[0].server_id, "srv");
        // D-045: environment and service_kind come from the runner's labels.
        assert_eq!(running[0].environment, "production");
        assert_eq!(running[0].service_kind, "web");
        assert_eq!(running[1].service_kind, "database");
        h.stop().await;
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        let key = Key {
            nanos: 1_790_000_000_123_456_789,
            container_id: "c1".to_owned(),
            ordinal: 2,
        };
        assert_eq!(Key::parse(&key.cursor()), Some(key));
        for bad in [
            "",
            "v2.1.c.0",
            "v1.x.c.0",
            "v1.1.c.0.9",
            "v1.1.c/d.0",
            "v1.1..0",
        ] {
            assert_eq!(Key::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn docker_timestamps_parse_to_nanos() {
        let (nanos, message) = split_line("2026-09-23T10:00:00.5Z hello world");
        let base = i128::from(crate::signed_plan::text::timestamp("2026-09-23T10:00:00Z").unwrap());
        assert_eq!(nanos, Some(base * 1_000_000_000 + 500_000_000));
        assert_eq!(message, "hello world");
        assert_eq!(
            split_line("2026-09-23T10:00:00.000000001Z x").0,
            Some(base * 1_000_000_000 + 1)
        );
        assert_eq!(split_line("no timestamp here"), (None, "no timestamp here"));
        assert_eq!(since_of(base * 1_000_000_000 + 999), "2026-09-23T10:00:00Z");
    }
}
