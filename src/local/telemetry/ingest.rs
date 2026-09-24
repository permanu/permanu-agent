//! Container log ingestion (agent-protocol.md 9.4, D-054): one connection to
//! the runner's unbound, read-only `logs_follow_stream` (signed-plan.md
//! 14.3), always open, reconnecting with backoff 1 s doubling to 30 s.
//!
//! Each `progress` line becomes a `LogRecord` of producer
//! `project:<project_id>`: identity from the line's `permanu.*` labels and
//! the runner's `list_containers` (name, image, environment, kind), never
//! from the text; redaction-v1 (rule 1 across the lines of each container
//! stream) before it is queued; level, trace ids and JSON fields parsed from
//! the redacted text. Limits: 1,000 lines/s per container (burst 5,000),
//! 5,000 per project and 20,000 per agent; excess is dropped, counted and
//! reported by one `AGENT` record per container per 10 s.
//!
//! Resume (contracts v1.1.2, D-060): `checkpoint.json` keeps, per
//! container, the last stored second, the `(stream, SHA-256 of line)`
//! hashes stored in it and the line's Docker cursor, and per allowlisted
//! unit its journald cursor. On reconnect the agent sends each source its
//! cursor (`resume`, at most 1,000) and the last second it saw as `since`
//! (for sources without one), and drops container lines at or before a
//! checkpoint that it already stored (Docker `--since` is inclusive), so a
//! reconnect neither loses nor duplicates lines.
//!
//! Container lines carry their identity (`container_name`, `image`,
//! `environment`, `service_kind`, v1.1.2); a cron run's lines carry
//! `cron_id` and `cron_run_id` (v1.1.3, D-061) and are stored as `CRON`
//! under the agent's `CronRun`. Host-unit lines (`source: "system"`) go to
//! [`super::journal`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use super::journal::{self, Rollups, Unit};
use super::records::{self, encode, TAG_LOG};
use super::redaction::PemStream;
use super::store::{valid_id, Kind, Producer};
use super::{Bucket, Buckets, Telemetry};
use crate::local::logs::parse_nanos;
use crate::local::runner::{self, ContainerFilter, Runner, RunnerContainer};
use crate::proto::agent::v2::{LogLevel, LogRecord, LogSourceType};

pub const OP: &str = "logs_follow_stream";
const CONTAINER_RATE: f64 = 1_000.0;
const CONTAINER_BURST: f64 = 5_000.0;
const PROJECT_RATE: f64 = 5_000.0;
const AGENT_RATE: f64 = 20_000.0;
const NOTICE_EVERY: Duration = Duration::from_secs(10);
const CHECKPOINT_EVERY: Duration = Duration::from_secs(5);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// Resume entries sent on reconnect (signed-plan.md 14.3).
const MAX_RESUME: usize = 1_000;
/// `AnalyticsRow` records in the `analytics` store.
pub const TAG_ANALYTICS_ROW: u8 = 1;
/// Checkpoints older than the log retention are forgotten.
const CHECKPOINT_MAX_AGE_SECS: i64 = 7 * 86_400;
const NANOS: i64 = 1_000_000_000;

#[derive(Debug, Default, Clone)]
struct Check {
    sec: i64,
    hashes: HashSet<String>,
    /// The Docker cursor (RFC 3339, nanoseconds) of the last stored line.
    cursor: Option<String>,
}

/// Maps a cron line's runner `run_id` (`cron_run_id`) to the agent's
/// `CronRun.id` (agent-protocol.md 9.4, contracts v1.1.3).
pub trait CronRuns: Send + Sync {
    fn cron_run(&self, runner_run_id: &str, cron_id: &str) -> Option<String>;
}

fn docker_cursor_ok(cursor: &str) -> bool {
    (1..=64).contains(&cursor.len()) && parse_nanos(cursor).is_some()
}

struct Drops {
    count: u64,
    last_notice: Option<Instant>,
    project_id: String,
}

pub struct LogIngest {
    telemetry: Arc<Telemetry>,
    runner: Arc<dyn Runner>,
    identities: HashMap<String, RunnerContainer>,
    refreshed_at: Option<Instant>,
    checks: HashMap<String, Check>,
    pem: HashMap<(String, String), PemStream>,
    containers: Buckets,
    projects: Buckets,
    agent: Bucket,
    drops: HashMap<String, Drops>,
    host: String,
    /// Journald cursor per allowlisted unit.
    units: HashMap<String, String>,
    /// The latest second any line carried (`since` on reconnect).
    last_sec: Option<i64>,
    rollups: Rollups,
    cron_runs: Option<Arc<dyn CronRuns>>,
    /// Route host → service (D-063 #9) for Dwaar records.
    routes: Option<Arc<super::routes::RoutesMap>>,
    /// The `dwaar.*` series (agent-protocol.md 9.5, QA_M2 X1).
    dwaar: super::dwaar_metrics::DwaarMetrics,
    /// This server's id (`""` before the bootstrap), for `dwaar.*` labels.
    server_id: Option<ServerIdFn>,
    /// The last id read and when.
    server_id_cache: (String, Option<Instant>),
}

/// Reads this server's id (the trust store's `server_id`).
pub type ServerIdFn = Arc<dyn Fn() -> String + Send + Sync>;

/// How long a read server id is reused.
const SERVER_ID_EVERY: Duration = Duration::from_secs(60);

fn valid_container_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn line_hash(stream: &str, line: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(stream.as_bytes());
    hasher.update([0]);
    hasher.update(line.as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or_default()
}

pub fn timestamp_of(nanos: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: nanos.div_euclid(NANOS),
        nanos: nanos.rem_euclid(NANOS) as i32,
    }
}

/// D-045: `database` and `bucket` are `SERVICE`, every other kind `APP`.
fn source_type_of(kind: &str) -> LogSourceType {
    match kind {
        "database" | "bucket" => LogSourceType::Service,
        _ => LogSourceType::App,
    }
}

impl LogIngest {
    pub fn new(telemetry: Arc<Telemetry>, runner: Arc<dyn Runner>, host: String) -> Self {
        let mut ingest = Self {
            telemetry,
            runner,
            identities: HashMap::new(),
            refreshed_at: None,
            checks: HashMap::new(),
            pem: HashMap::new(),
            containers: Buckets::default(),
            projects: Buckets::default(),
            agent: Bucket::new(AGENT_RATE, AGENT_RATE),
            drops: HashMap::new(),
            host,
            units: HashMap::new(),
            last_sec: None,
            rollups: Rollups::new(),
            cron_runs: None,
            routes: None,
            dwaar: super::dwaar_metrics::DwaarMetrics::default(),
            server_id: None,
            server_id_cache: (String::new(), None),
        };
        ingest.load_checkpoint();
        ingest
    }

    /// Files Dwaar records under the service of their route host (D-063 #9).
    pub fn with_routes(mut self, routes: Arc<super::routes::RoutesMap>) -> Self {
        self.routes = Some(routes);
        self
    }

    /// Labels the `dwaar.*` series with this server's id.
    pub fn with_server_id(mut self, server_id: ServerIdFn) -> Self {
        self.server_id = Some(server_id);
        self
    }

    /// This server's id, re-read at most every [`SERVER_ID_EVERY`] (and
    /// while still empty).
    fn server_id(&mut self, now: Instant) -> String {
        let Some(read) = &self.server_id else {
            return String::new();
        };
        let (id, at) = &self.server_id_cache;
        if id.is_empty() || at.is_none_or(|at| now.duration_since(at) >= SERVER_ID_EVERY) {
            self.server_id_cache = (read(), Some(now));
        }
        self.server_id_cache.0.clone()
    }

    /// Files cron lines under their `CronRun` (v1.1.3, D-061).
    pub fn with_cron_runs(mut self, cron_runs: Arc<dyn CronRuns>) -> Self {
        self.cron_runs = Some(cron_runs);
        self
    }

    fn load_checkpoint(&mut self) {
        let value = self.telemetry.read_checkpoint();
        let Some(logs) = value["logs"].as_object() else {
            return;
        };
        for (id, entry) in logs.iter().take(10_000) {
            if !valid_container_id(id) {
                continue;
            }
            let Some(sec) = entry["sec"].as_i64() else {
                continue;
            };
            let hashes = entry["hashes"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|h| h.as_str())
                        .filter(|h| h.len() == 32)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let cursor = entry["cursor"]
                .as_str()
                .filter(|c| docker_cursor_ok(c))
                .map(str::to_owned);
            self.checks.insert(
                id.clone(),
                Check {
                    sec,
                    hashes,
                    cursor,
                },
            );
        }
        if let Some(units) = value["units"].as_object() {
            for (unit, cursor) in units.iter().take(MAX_RESUME) {
                if let Some(cursor) = cursor.as_str().filter(|c| journal::cursor_ok(c)) {
                    if journal::classify(unit).is_some() {
                        self.units.insert(unit.clone(), cursor.to_owned());
                    }
                }
            }
        }
        self.last_sec = value["since_sec"]
            .as_i64()
            .or_else(|| self.checks.values().map(|c| c.sec).max());
    }

    /// Writes `checkpoint.json` (every 5 s and on reconnect).
    pub fn save_checkpoint(&mut self) {
        let oldest = now_nanos() / NANOS - CHECKPOINT_MAX_AGE_SECS;
        self.checks.retain(|_, c| c.sec >= oldest);
        let logs: serde_json::Map<String, Value> = self
            .checks
            .iter()
            .map(|(id, c)| {
                let mut hashes: Vec<&String> = c.hashes.iter().collect();
                hashes.sort();
                let mut entry = json!({"sec": c.sec, "hashes": hashes});
                if let Some(cursor) = &c.cursor {
                    entry["cursor"] = json!(cursor);
                }
                (id.clone(), entry)
            })
            .collect();
        let mut checkpoint = json!({"version": 1, "logs": logs, "units": self.units});
        if let Some(sec) = self.last_sec {
            checkpoint["since_sec"] = json!(sec);
        }
        self.telemetry.write_checkpoint(&checkpoint);
    }

    /// The `since` of the next connection: the last second the stream
    /// delivered, for sources that have no resume entry.
    pub fn since(&self) -> Option<String> {
        self.last_sec
            .map(crate::signed_plan::text::format_timestamp)
    }

    /// The `resume` entries of the next connection: the newest containers'
    /// Docker cursors, then the units' journald cursors (at most 1,000).
    fn resume(&self) -> Vec<Value> {
        let mut containers: Vec<(&String, &Check)> = self
            .checks
            .iter()
            .filter(|(_, c)| c.cursor.is_some())
            .collect();
        containers.sort_by(|a, b| b.1.sec.cmp(&a.1.sec).then(a.0.cmp(b.0)));
        containers.truncate(MAX_RESUME);
        containers.sort_by(|a, b| a.0.cmp(b.0));
        let mut units: Vec<(&String, &String)> = self.units.iter().collect();
        units.sort();
        containers
            .into_iter()
            .map(|(id, c)| json!({"container_id": id, "cursor": c.cursor}))
            .chain(
                units
                    .into_iter()
                    .map(|(unit, cursor)| json!({"unit": unit, "cursor": cursor})),
            )
            .take(MAX_RESUME)
            .collect()
    }

    async fn refresh(&mut self, force: bool) {
        let due = self
            .refreshed_at
            .is_none_or(|at| at.elapsed() >= REFRESH_EVERY);
        if !force && !due {
            return;
        }
        self.refreshed_at = Some(Instant::now());
        match runner::list_containers(self.runner.as_ref(), &ContainerFilter::default()).await {
            Ok(list) => {
                self.identities = list.into_iter().map(|c| (c.id.clone(), c)).collect();
            }
            Err(failure) => debug!(code = %failure.code, "list_containers failed; identities kept"),
        }
    }

    fn identity(&self, id: &str) -> Option<&RunnerContainer> {
        self.identities.get(id).or_else(|| {
            // The stream may carry a full id where list_containers has a
            // short one, or the reverse.
            self.identities
                .values()
                .find(|c| c.id.starts_with(id) || id.starts_with(&c.id))
        })
    }

    fn drop_line(&mut self, container: &str, project: &str) {
        self.telemetry.count_dropped(Kind::Logs, 1);
        let entry = self
            .drops
            .entry(container.to_owned())
            .or_insert_with(|| Drops {
                count: 0,
                last_notice: None,
                project_id: project.to_owned(),
            });
        entry.count += 1;
    }

    /// One synthetic `AGENT` record per container per 10 s (9.4).
    fn notices(&mut self, now: Instant) {
        let mut out = Vec::new();
        for (container, drops) in &mut self.drops {
            let due = drops
                .last_notice
                .is_none_or(|at| now.saturating_duration_since(at) >= NOTICE_EVERY);
            if drops.count > 0 && due {
                out.push((container.clone(), drops.project_id.clone(), drops.count));
                drops.count = 0;
                drops.last_notice = Some(now);
            }
        }
        for (container, project, count) in out {
            let ts = now_nanos();
            let record = LogRecord {
                timestamp: Some(timestamp_of(ts)),
                level: LogLevel::Warn as i32,
                message: format!("{count} lines dropped"),
                source_type: LogSourceType::Agent as i32,
                source: "agent".to_owned(),
                container_id: container,
                project_id: project,
                host: self.host.clone(),
                ingest: "agent".to_owned(),
                ..Default::default()
            };
            self.telemetry.submit(
                Kind::Logs,
                Producer::System,
                ts,
                TAG_LOG,
                encode(&record),
                false,
            );
        }
    }

    fn saw(&mut self, ts: i64) {
        let sec = ts.div_euclid(NANOS);
        self.last_sec = Some(self.last_sec.map_or(sec, |last| last.max(sec)));
    }

    /// Writes the Dwaar rollups of every minute closed at `now_sec`, each
    /// under the service of its route host (D-060, D-063 #9), and the
    /// changed `dwaar.*` series (at most every 10 s).
    pub fn flush_rollups(&mut self, now_sec: i64) {
        for row in self.rollups.closed(now_sec) {
            let ts = row.bucket_start.map_or(now_sec, |t| t.seconds) * NANOS;
            let owner = row
                .dimensions
                .first()
                .zip(self.routes.as_ref())
                .and_then(|(host, routes)| routes.owner(&host.value))
                .unwrap_or_default();
            let stored = super::records::StoredAnalyticsRow {
                bucket_start: row.bucket_start,
                dimensions: row.dimensions,
                values: row.values,
                service_id: owner.service_id,
                project_id: owner.project_id,
                environment_id: owner.environment_id,
            };
            self.telemetry.submit(
                Kind::Analytics,
                Producer::System,
                ts,
                TAG_ANALYTICS_ROW,
                encode(&stored),
                false,
            );
        }
        for sample in self.dwaar.take_samples(now_sec, false) {
            self.telemetry.otlp_state.metric(
                &self.telemetry,
                Producer::System,
                now_sec * NANOS,
                sample,
            );
        }
    }

    /// A host-unit line (contracts v1.1.2, D-060; agent-protocol.md 9.4):
    /// `system` producer (a `permanu-buildkitd@<project>` line belongs to
    /// that project), `ingest = "journal"`, level from the priority,
    /// `source` = the unit; `dwaar.service` goes to the `http` store and
    /// its access lines to the rollups. Any other unit is dropped.
    fn handle_system(&mut self, line: &Value, now: Instant) {
        let text = |name: &str| line[name].as_str().unwrap_or_default();
        let unit_name = text("unit");
        let (Some(unit), Some(message)) = (journal::classify(unit_name), line["line"].as_str())
        else {
            self.telemetry.count_dropped(Kind::Logs, 1);
            return;
        };
        let cursor = text("cursor");
        if journal::cursor_ok(cursor)
            && (self.units.contains_key(unit_name) || self.units.len() < MAX_RESUME)
        {
            self.units.insert(unit_name.to_owned(), cursor.to_owned());
        }
        let ts = parse_nanos(text("at"))
            .and_then(|n| i64::try_from(n).ok())
            .unwrap_or_else(now_nanos);
        self.saw(ts);
        let kind = if unit == Unit::Dwaar {
            Kind::Http
        } else {
            Kind::Logs
        };
        if !self.agent.take(now) {
            self.telemetry.count_dropped(kind, 1);
            return;
        }
        let mut owner = None;
        if unit == Unit::Dwaar {
            if let Some(access) = journal::access_of(message) {
                self.rollups.add(ts.div_euclid(NANOS), &access);
                owner = self
                    .routes
                    .as_ref()
                    .and_then(|routes| routes.owner(&access.host));
                if let Some(owner) = &owner {
                    let server_id = self.server_id(now);
                    self.dwaar
                        .record(ts.div_euclid(NANOS), &access, owner, &server_id);
                }
            }
        }
        let owner = owner.unwrap_or_default();
        let level = journal::level_of(line["priority"].as_i64().unwrap_or(-1));
        let key = (unit_name.to_owned(), "journal".to_owned());
        let mut pem = self.pem.remove(&key).unwrap_or_default();
        for piece in records::split_line(message) {
            let (redacted_text, mut redacted) = pem.line(piece);
            let mut parsed = records::parse_line(&redacted_text);
            redacted |= parsed.redacted;
            if unit == Unit::Dwaar {
                journal::drop_header_fields(&mut parsed.fields);
            }
            let (source, project_id, producer) = match &unit {
                Unit::Dwaar => (
                    "dwaar".to_owned(),
                    owner.project_id.clone(),
                    Producer::System,
                ),
                Unit::Host => (unit_name.to_owned(), String::new(), Producer::System),
                Unit::Build { project_id } => (
                    unit_name.to_owned(),
                    project_id.clone(),
                    Producer::Project(project_id.clone()),
                ),
            };
            let record = LogRecord {
                timestamp: Some(timestamp_of(ts)),
                level: level as i32,
                message: redacted_text,
                source_type: journal::source_type_of(&unit) as i32,
                source,
                host: self.host.clone(),
                project_id,
                trace_id: parsed.trace_id,
                span_id: parsed.span_id,
                fields: parsed.fields,
                redacted,
                ingest: "journal".to_owned(),
                service_id: owner.service_id.clone(),
                environment_id: owner.environment_id.clone(),
                ..Default::default()
            };
            self.telemetry
                .submit(kind, producer, ts, TAG_LOG, encode(&record), redacted);
        }
        self.pem.insert(key, pem);
        self.flush_rollups(ts.div_euclid(NANOS));
    }

    /// Handles one `progress` line of `logs_follow_stream`.
    pub async fn handle(&mut self, line: &Value, now: Instant) {
        if line["source"] == "system" {
            self.handle_system(line, now);
            return;
        }
        if let Some(event) = line["event"].as_str() {
            let id = line["container_id"].as_str().unwrap_or_default();
            match event {
                "container_started" => self.refresh(true).await,
                "container_stopped" => self.pem.retain(|(c, _), _| c != id),
                _ => {}
            }
            return;
        }
        let text = |name: &str| line[name].as_str().unwrap_or_default();
        let container = text("container_id");
        let project = text("project_id");
        let service = text("service_id");
        let stream = text("stream");
        let Some(message) = line["line"].as_str() else {
            return;
        };
        if !valid_container_id(container) || !matches!(stream, "stdout" | "stderr") {
            self.telemetry.count_dropped(Kind::Logs, 1);
            return;
        }
        // Never streamed without `permanu.service_id`; the project names a
        // directory, so it must be a plain id.
        if service.is_empty() || !valid_id(project) {
            self.telemetry.count_dropped(Kind::Logs, 1);
            return;
        }
        // v1.1.2: the Docker cursor is the line's own time.
        let cursor = line["cursor"].as_str().filter(|c| docker_cursor_ok(c));
        let ts = cursor
            .and_then(parse_nanos)
            .or_else(|| parse_nanos(text("at")))
            .and_then(|n| i64::try_from(n).ok())
            .unwrap_or_else(now_nanos);
        let sec = ts.div_euclid(NANOS);
        let hash = line_hash(stream, message);
        let check = self.checks.entry(container.to_owned()).or_default();
        if sec < check.sec || (sec == check.sec && check.hashes.contains(&hash)) {
            return;
        }
        if sec > check.sec {
            check.sec = sec;
            check.hashes.clear();
        }
        check.hashes.insert(hash);
        if let Some(cursor) = cursor {
            check.cursor = Some(cursor.to_owned());
        }
        self.saw(ts);

        let allowed = self.agent.take(now)
            && self.projects.take(project, PROJECT_RATE, PROJECT_RATE, now)
            && self
                .containers
                .take(container, CONTAINER_RATE, CONTAINER_BURST, now);
        if !allowed {
            let (container, project) = (container.to_owned(), project.to_owned());
            self.drop_line(&container, &project);
            self.notices(now);
            return;
        }
        if self.identity(container).is_none() {
            self.refresh(false).await;
        }
        let mut identity = self.identity(container).cloned().unwrap_or_default();
        // v1.1.2: the line's own identity fields win over the listing.
        for (field, slot) in [
            ("container_name", &mut identity.name),
            ("image", &mut identity.image),
            ("environment", &mut identity.environment),
            ("service_kind", &mut identity.service_kind),
        ] {
            if let Some(value) = line[field]
                .as_str()
                .filter(|v| !v.is_empty() && v.len() <= 256)
            {
                *slot = value.to_owned();
            }
        }
        // v1.1.3 (D-061): a cron run's container.
        let cron = line["cron_run_id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 64)
            .map(|runner_run| {
                let cron_id = text("cron_id");
                let run = self
                    .cron_runs
                    .as_ref()
                    .and_then(|runs| runs.cron_run(runner_run, cron_id));
                (runner_run.to_owned(), cron_id.to_owned(), run)
            });
        let key = (container.to_owned(), stream.to_owned());
        let mut pem = self.pem.remove(&key).unwrap_or_default();
        for piece in records::split_line(message) {
            let (redacted_text, mut redacted) = pem.line(piece);
            let mut parsed = records::parse_line(&redacted_text);
            redacted |= parsed.redacted;
            let kind = identity.service_kind.as_str();
            let source_type = if cron.is_some() {
                LogSourceType::Cron
            } else {
                source_type_of(kind)
            };
            let name = if identity.name.is_empty() {
                container
            } else {
                identity.name.as_str()
            };
            let mut run_id = String::new();
            if let Some((runner_run, cron_id, run)) = &cron {
                parsed.fields.insert("cron_id".to_owned(), cron_id.clone());
                match run {
                    Some(run) => run_id = run.clone(),
                    None => {
                        parsed
                            .fields
                            .insert("cron_run_id".to_owned(), runner_run.clone());
                    }
                }
            }
            let record = LogRecord {
                timestamp: Some(timestamp_of(ts)),
                level: parsed.level as i32,
                message: redacted_text,
                source_type: source_type as i32,
                source: match source_type {
                    LogSourceType::Service => format!("service:{name}"),
                    LogSourceType::Cron => format!("cron:{name}"),
                    _ => format!("app:{name}"),
                },
                container_id: container.to_owned(),
                container_name: identity.name.clone(),
                image: identity.image.clone(),
                host: self.host.clone(),
                project_id: project.to_owned(),
                service_id: service.to_owned(),
                deployment_id: text("deployment_id").to_owned(),
                stream: stream.to_owned(),
                trace_id: parsed.trace_id,
                span_id: parsed.span_id,
                fields: parsed.fields,
                redacted,
                environment_id: text("environment_id").to_owned(),
                environment: identity.environment.clone(),
                service_kind: identity.service_kind.clone(),
                run_id: run_id.clone(),
                ingest: "runner_follow".to_owned(),
                ..Default::default()
            };
            self.telemetry.submit(
                Kind::Logs,
                Producer::Project(project.to_owned()),
                ts,
                TAG_LOG,
                encode(&record),
                redacted,
            );
        }
        self.pem.insert(key, pem);
        self.notices(now);
    }

    /// One connection: reads lines until it ends or fails. True when it
    /// delivered at least one line.
    async fn connect_once(&mut self) -> bool {
        let mut payload = json!({});
        if let Some(since) = self.since() {
            payload["since"] = json!(since);
        }
        let resume = self.resume();
        if !resume.is_empty() {
            payload["resume"] = json!(resume);
        }
        let mut lines = match self
            .runner
            .open(json!({"op": OP, "payload": payload}))
            .await
        {
            Ok(lines) => lines,
            Err(failure) => {
                self.telemetry.set_runner_unreachable(true);
                debug!(code = %failure.code, message = %failure.message, "logs_follow_stream connect failed");
                return false;
            }
        };
        self.telemetry.set_runner_unreachable(false);
        self.refresh(true).await;
        let mut delivered = false;
        let mut save = tokio::time::interval(CHECKPOINT_EVERY);
        save.tick().await;
        loop {
            tokio::select! {
                next = lines.next() => match next {
                    Ok(Some(line)) if line["type"] == "progress" => {
                        delivered = true;
                        self.handle(&line, Instant::now()).await;
                    }
                    Ok(Some(result)) => {
                        warn!(error = %result["error"]["code"], "logs_follow_stream ended");
                        break;
                    }
                    Ok(None) => break,
                    Err(failure) => {
                        debug!(message = %failure.message, "logs_follow_stream broke");
                        break;
                    }
                },
                _ = save.tick() => {
                    self.save_checkpoint();
                    self.notices(Instant::now());
                    self.flush_rollups(now_nanos().div_euclid(NANOS));
                }
            }
        }
        self.save_checkpoint();
        delivered
    }

    /// Runs forever: reconnect with backoff 1 s doubling to 30 s.
    pub async fn run(mut self) {
        let mut backoff = BACKOFF_MIN;
        loop {
            if self.connect_once().await {
                backoff = BACKOFF_MIN;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::local::runner::{EventLines, RunnerFailure};
    use crate::local::telemetry::store::ScanSpec;
    use crate::local::telemetry::test_support;
    use crate::signed_plan::test_support::temp_dir;
    use prost::Message;
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt;

    /// A runner that answers `list_containers` and streams scripted
    /// `logs_follow_stream` connections (each a list of lines, then either
    /// an open wait or a break).
    pub struct ScriptRunner {
        pub containers: Mutex<Vec<Value>>,
        pub connections: Mutex<Vec<Vec<Value>>>,
        pub requests: Mutex<Vec<Value>>,
    }

    impl ScriptRunner {
        pub fn new(containers: Vec<Value>) -> Arc<Self> {
            Arc::new(Self {
                containers: Mutex::new(containers),
                connections: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    #[tonic::async_trait]
    impl Runner for ScriptRunner {
        async fn exchange(&self, request: Value, _: Duration) -> Result<Value, RunnerFailure> {
            self.requests.lock().unwrap().push(request.clone());
            match request["op"].as_str() {
                Some("list_containers") => Ok(
                    json!({"type": "result", "ok": true, "containers": *self.containers.lock().unwrap()}),
                ),
                _ => Err(RunnerFailure::transport("unknown op")),
            }
        }

        async fn open(&self, request: Value) -> Result<EventLines, RunnerFailure> {
            self.requests.lock().unwrap().push(request.clone());
            let script = {
                let mut all = self.connections.lock().unwrap();
                if all.is_empty() {
                    return Err(RunnerFailure::transport("cannot reach the runner"));
                }
                all.remove(0)
            };
            let (agent, runner) = tokio::io::duplex(1 << 20);
            let (r_read, mut r_write) = tokio::io::split(runner);
            let (a_read, a_write) = tokio::io::split(agent);
            tokio::spawn(async move {
                let _keep = r_read;
                for line in script {
                    let mut out = serde_json::to_vec(&line).unwrap();
                    out.push(b'\n');
                    if r_write.write_all(&out).await.is_err() {
                        return;
                    }
                }
                // Break the connection: a transient failure.
            });
            EventLines::start(Box::new(a_read), Box::new(a_write), &request).await
        }
    }

    pub fn container(id: &str, kind: &str) -> Value {
        json!({"id": id, "name": format!("{id}-name"), "image": "img@sha256:ab", "state": "running",
               "status": "Up", "created_at": "2026-09-23T09:00:00Z", "project_id": "p1",
               "environment": "production", "environment_id": "e1", "service_id": "s1",
               "service_kind": kind, "deployment_id": "d1", "spec_digest_hex": "cd"})
    }

    pub fn log(container: &str, at: &str, stream: &str, line: &str) -> Value {
        json!({"type": "progress", "op": OP, "at": at, "container_id": container,
               "project_id": "p1", "environment_id": "e1", "service_id": "s1",
               "deployment_id": "d1", "stream": stream, "line": line})
    }

    /// A FAKE PEM armour line, built at run time so secret scanners do not
    /// flag the test source.
    fn pem_marker(which: &str) -> String {
        format!("-----{which} {} KEY-----", "PRIVATE")
    }

    fn stored(t: &Telemetry) -> Vec<LogRecord> {
        t.snapshot(Kind::Logs)
            .scan(ScanSpec::default())
            .map(|r| LogRecord::decode(r.unwrap().payload.as_slice()).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn lines_are_redacted_labelled_and_stored() {
        let dir = temp_dir("ingest-basic");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(vec![container("c1", "web"), container("c2", "database")]);
        let mut ingest = LogIngest::new(t.clone(), runner.clone(), "host-1".into());
        let now = Instant::now();
        for line in [
            log(
                "c1",
                "2026-09-23T10:00:01.5Z",
                "stdout",
                r#"{"level":"error","msg":"db","password":"x"}"#,
            ),
            log("c1", "2026-09-23T10:00:02Z", "stderr", &pem_marker("BEGIN")),
            log("c1", "2026-09-23T10:00:02Z", "stderr", "MIIFAKE"),
            log("c1", "2026-09-23T10:00:02Z", "stderr", &pem_marker("END")),
            log("c1", "2026-09-23T10:00:02Z", "stdout", "token=abc ok"),
            log("c2", "2026-09-23T10:00:03Z", "stdout", "[WARN] slow"),
            // No service id: never stored.
            json!({"type": "progress", "op": OP, "at": "2026-09-23T10:00:03Z", "container_id": "c9",
                   "project_id": "p1", "stream": "stdout", "line": "x"}),
            // A project id that is not a plain id.
            json!({"type": "progress", "op": OP, "at": "2026-09-23T10:00:03Z", "container_id": "c9",
                   "project_id": "../etc", "service_id": "s", "stream": "stdout", "line": "x"}),
        ] {
            ingest.handle(&line, now).await;
        }
        t.sync().await;
        let records = stored(&t);
        let messages: Vec<&str> = records.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(
            messages,
            vec![
                r#"{"level":"error","msg":"db","password":"[REDACTED]"}"#,
                "[REDACTED]",
                "[REDACTED]",
                "[REDACTED]",
                "token=[REDACTED] ok",
                "[WARN] slow"
            ]
        );
        let first = &records[0];
        assert_eq!(first.level, LogLevel::Error as i32);
        assert_eq!(first.fields["password"], "[REDACTED]");
        assert!(first.redacted);
        assert_eq!(first.container_name, "c1-name");
        assert_eq!(first.image, "img@sha256:ab");
        assert_eq!(first.environment, "production");
        assert_eq!(first.environment_id, "e1");
        assert_eq!(first.service_kind, "web");
        assert_eq!(first.source_type, LogSourceType::App as i32);
        assert_eq!(first.ingest, "runner_follow");
        assert_eq!(first.timestamp.unwrap().nanos, 500_000_000);
        assert_eq!(records[5].source_type, LogSourceType::Service as i32);
        assert_eq!(records[5].level, LogLevel::Warn as i32);
        let usage = t.usage();
        assert_eq!(usage.kinds[0].0.counters.redacted_total, 5);
        assert_eq!(usage.kinds[0].0.counters.dropped_total, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn per_container_limits_drop_and_report() {
        let dir = temp_dir("ingest-limit");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(vec![container("c1", "web")]);
        let mut ingest = LogIngest::new(t.clone(), runner, "h".into());
        let now = Instant::now();
        for i in 0..5_010 {
            ingest
                .handle(
                    &log("c1", "2026-09-23T10:00:01Z", "stdout", &format!("line {i}")),
                    now,
                )
                .await;
        }
        // The next report is due 10 s after the first one.
        ingest.notices(now + Duration::from_secs(5));
        ingest.notices(now + Duration::from_secs(11));
        t.sync().await;
        let records = stored(&t);
        // Burst 5,000 stored; the first drop is reported at once, the
        // other 9 in the next report.
        assert_eq!(records.len(), 5_002);
        let notices: Vec<&LogRecord> = records
            .iter()
            .filter(|r| r.source_type == LogSourceType::Agent as i32)
            .collect();
        assert_eq!(notices.len(), 2);
        assert_eq!(notices[0].message, "1 lines dropped");
        assert_eq!(notices[1].message, "9 lines dropped");
        assert_eq!(notices[1].container_id, "c1");
        assert_eq!(notices[1].project_id, "p1");
        assert_eq!(t.usage().kinds[0].0.counters.dropped_total, 10);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn reconnect_resumes_from_the_checkpoint_without_duplicates() {
        let dir = temp_dir("ingest-resume");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(vec![container("c1", "web")]);
        runner.connections.lock().unwrap().extend([
            vec![
                log("c1", "2026-09-23T10:00:01Z", "stdout", "a"),
                log("c1", "2026-09-23T10:00:02Z", "stdout", "b"),
            ],
            // The runner replays from `since` (10:00:01): a and b again,
            // then new lines, one in the same second as b.
            vec![
                log("c1", "2026-09-23T10:00:01Z", "stdout", "a"),
                log("c1", "2026-09-23T10:00:02Z", "stdout", "b"),
                log("c1", "2026-09-23T10:00:02Z", "stdout", "b2"),
                log("c1", "2026-09-23T10:00:03Z", "stdout", "c"),
            ],
        ]);
        let mut ingest = LogIngest::new(t.clone(), runner.clone(), "h".into());
        assert!(ingest.connect_once().await);
        // A fresh ingest (agent restart) reads checkpoint.json.
        let mut ingest = LogIngest::new(t.clone(), runner.clone(), "h".into());
        assert_eq!(ingest.since().as_deref(), Some("2026-09-23T10:00:02Z"));
        assert!(ingest.connect_once().await);
        t.sync().await;
        let messages: Vec<String> = stored(&t).into_iter().map(|r| r.message).collect();
        assert_eq!(messages, vec!["a", "b", "b2", "c"]);
        let requests = runner.requests.lock().unwrap().clone();
        let opens: Vec<&Value> = requests.iter().filter(|r| r["op"] == OP).collect();
        assert_eq!(opens[0]["payload"], json!({}));
        assert_eq!(
            opens[1]["payload"],
            json!({"since": "2026-09-23T10:00:02Z"})
        );
        // No connection: the runner is unreachable.
        assert!(!ingest.connect_once().await);
        assert!(t.degraded_reasons().contains(&"runner_unreachable"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// v1.1.2 container line: identity fields and the Docker cursor.
    fn line_v2(container: &str, cursor: &str, line: &str) -> Value {
        json!({"type": "progress", "op": OP, "at": "2026-09-23T10:00:09Z", "source": "container",
               "container_id": container, "container_name": format!("{container}-live"),
               "image": "ghcr.io/acme/web@sha256:ef", "project_id": "p1",
               "environment": "staging", "environment_id": "e1", "service_id": "s1",
               "service_kind": "worker", "deployment_id": "d1", "stream": "stdout",
               "cursor": cursor, "line": line})
    }

    fn system(unit: &str, priority: i64, cursor: &str, line: &str) -> Value {
        json!({"type": "progress", "op": OP, "at": "2026-09-23T10:00:05Z", "source": "system",
               "unit": unit, "priority": priority, "cursor": cursor, "line": line})
    }

    fn stored_kind<M: Message + Default>(t: &Telemetry, kind: Kind) -> Vec<M> {
        t.snapshot(kind)
            .scan(ScanSpec::default())
            .map(|r| M::decode(r.unwrap().payload.as_slice()).unwrap())
            .collect()
    }

    /// contracts v1.1.2 (D-060): per-source resume points; a reconnect
    /// resumes each container from its Docker cursor and each unit from
    /// its journald cursor.
    #[tokio::test]
    async fn reconnect_sends_each_source_its_cursor() {
        let dir = temp_dir("ingest-cursors");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(Vec::new());
        runner.connections.lock().unwrap().extend([
            vec![
                line_v2("c1", "2026-09-23T10:00:01.000000001Z", "a"),
                line_v2("c1", "2026-09-23T10:00:02.500000000Z", "b"),
                line_v2("c2", "2026-09-23T10:00:03.000000000Z", "x"),
                system("docker.service", 6, "s=1;i=5", "pulled"),
            ],
            vec![
                // Docker `--since` is inclusive: b comes again.
                line_v2("c1", "2026-09-23T10:00:02.500000000Z", "b"),
                line_v2("c1", "2026-09-23T10:00:04.000000000Z", "c"),
            ],
        ]);
        let mut ingest = LogIngest::new(t.clone(), runner.clone(), "h".into());
        assert!(ingest.connect_once().await);
        let mut ingest = LogIngest::new(t.clone(), runner.clone(), "h".into());
        assert!(ingest.connect_once().await);
        t.sync().await;
        let messages: Vec<String> = stored(&t).into_iter().map(|r| r.message).collect();
        assert_eq!(messages, vec!["a", "b", "x", "pulled", "c"]);
        let requests = runner.requests.lock().unwrap().clone();
        let opens: Vec<&Value> = requests.iter().filter(|r| r["op"] == OP).collect();
        assert_eq!(opens[0]["payload"], json!({}));
        assert_eq!(
            opens[1]["payload"],
            json!({"since": "2026-09-23T10:00:05Z", "resume": [
                {"container_id": "c1", "cursor": "2026-09-23T10:00:02.500000000Z"},
                {"container_id": "c2", "cursor": "2026-09-23T10:00:03.000000000Z"},
                {"unit": "docker.service", "cursor": "s=1;i=5"}]})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// v1.1.2: identity comes from the line itself (no `list_containers`
    /// entry needed), the time from the Docker cursor; v1.1.3 (D-061): a
    /// cron run's line is `CRON` under its `CronRun`.
    #[tokio::test]
    async fn line_fields_and_cron_runs_are_stored() {
        struct Runs;
        impl CronRuns for Runs {
            fn cron_run(&self, runner_run_id: &str, cron_id: &str) -> Option<String> {
                (runner_run_id == "rr-1" && cron_id == "cr-1").then(|| "cronrun-1".to_owned())
            }
        }
        let dir = temp_dir("ingest-fields");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(Vec::new());
        let mut ingest =
            LogIngest::new(t.clone(), runner, "h".into()).with_cron_runs(Arc::new(Runs));
        let now = Instant::now();
        ingest
            .handle(
                &line_v2("c1", "2026-09-23T10:00:01.250000000Z", "hello"),
                now,
            )
            .await;
        let mut cron = line_v2("c9", "2026-09-23T10:00:02Z", "tick");
        cron["cron_id"] = json!("cr-1");
        cron["cron_run_id"] = json!("rr-1");
        cron["service_kind"] = json!("cron");
        ingest.handle(&cron, now).await;
        let mut unknown = line_v2("c9", "2026-09-23T10:00:03Z", "tock");
        unknown["cron_id"] = json!("cr-1");
        unknown["cron_run_id"] = json!("rr-2");
        ingest.handle(&unknown, now).await;
        t.sync().await;
        let records = stored(&t);
        let first = &records[0];
        assert_eq!(first.container_name, "c1-live");
        assert_eq!(first.image, "ghcr.io/acme/web@sha256:ef");
        assert_eq!(first.environment, "staging");
        assert_eq!(first.service_kind, "worker");
        assert_eq!(first.source_type, LogSourceType::App as i32);
        assert_eq!(first.timestamp.unwrap().nanos, 250_000_000);
        assert_eq!(first.timestamp.unwrap().seconds % 60, 1);
        let cron = &records[1];
        assert_eq!(cron.source_type, LogSourceType::Cron as i32);
        assert_eq!(cron.run_id, "cronrun-1");
        assert_eq!(cron.fields["cron_id"], "cr-1");
        let unknown = &records[2];
        assert_eq!(unknown.source_type, LogSourceType::Cron as i32);
        assert_eq!(unknown.run_id, "");
        assert_eq!(unknown.fields["cron_run_id"], "rr-2");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// contracts v1.1.2 (D-060, agent-protocol.md 9.4): allowlisted units
    /// only; `HOST` and `BUILD` in `logs`, Dwaar in `http` plus its 60 s
    /// rollups in `analytics`.
    #[tokio::test]
    async fn system_units_feed_their_stores() {
        use crate::proto::agent::v2::AnalyticsRow;
        let project = "01a0cdb5-3500-70b1-8000-000000000001";
        let dir = temp_dir("ingest-units");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(Vec::new());
        let mut ingest = LogIngest::new(t.clone(), runner, "host-1".into());
        let now = Instant::now();
        let access = r#"{"timestamp":"2026-09-23T10:00:05Z","request_id":"r1","method":"GET","path":"/a","query":"token=abc","host":"app.example.com","status":200,"response_time_us":1500,"client_ip":"203.0.113.0","bytes_sent":10,"bytes_received":0,"http_version":"HTTP/2","is_bot":false,"authorization":"Bearer x"}"#;
        for line in [
            system("docker.service", 3, "s=1;i=1", "error pulling"),
            system("permanu-runner@4-1.service", 6, "s=1;i=2", "bound"),
            system(
                &format!("permanu-buildkitd@{project}.service"),
                6,
                "s=1;i=3",
                "solve",
            ),
            system("sshd.service", 6, "s=1;i=4", "Accepted password"),
            system("dwaar.service", 6, "s=1;i=5", access),
            system("dwaar.service", 4, "s=1;i=6", "WARN upstream slow"),
        ] {
            ingest.handle(&line, now).await;
        }
        ingest.flush_rollups(timestamp("2026-09-23T10:01:30Z"));
        t.sync().await;
        let logs = stored(&t);
        assert_eq!(logs.len(), 3, "{logs:?}");
        assert_eq!(logs[0].source_type, LogSourceType::Host as i32);
        assert_eq!(logs[0].source, "docker.service");
        assert_eq!(logs[0].level, LogLevel::Error as i32);
        assert_eq!(logs[0].ingest, "journal");
        assert_eq!(logs[0].project_id, "");
        assert_eq!(logs[0].host, "host-1");
        assert_eq!(logs[1].source, "permanu-runner@4-1.service");
        assert_eq!(logs[2].source_type, LogSourceType::Build as i32);
        assert_eq!(logs[2].project_id, project);
        assert!(!logs.iter().any(|r| r.message.contains("Accepted")));
        assert_eq!(t.usage().kinds[0].0.counters.dropped_total, 1);
        let http: Vec<LogRecord> = stored_kind(&t, Kind::Http);
        assert_eq!(http.len(), 2);
        assert_eq!(http[0].source_type, LogSourceType::Dwaar as i32);
        assert_eq!(http[0].source, "dwaar");
        assert_eq!(http[0].fields["host"], "app.example.com");
        assert_eq!(http[0].fields["status"], "200");
        assert!(!http[0].fields.contains_key("authorization"));
        assert!(!http[0].message.contains("abc"), "{}", http[0].message);
        assert_eq!(http[1].level, LogLevel::Warn as i32);
        let rows: Vec<AnalyticsRow> = stored_kind(&t, Kind::Analytics);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dimensions[0].value, "app.example.com");
        assert_eq!(rows[0].values[0].value, 1.0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// contracts v1.1.5 (D-063 #9): a Dwaar `http` record takes the ids of
    /// the service whose route host it matched (`routes_map`); a host the map
    /// does not name keeps none.
    #[tokio::test]
    async fn dwaar_records_are_attributed_by_route_host() {
        let dir = temp_dir("ingest-routes");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(Vec::new());
        let routes = Arc::new(super::super::routes::RoutesMap::default());
        routes.replace(
            super::super::routes::parse_routes(&json!({"routes": [{"host": "app.example.com",
                "service_id": "01a0cdb5-3500-70c1-8000-000000000001",
                "project_id": "01a0cdb5-3500-70b1-8000-000000000001",
                "environment_id": "01a0cdb5-3500-70b2-8000-000000000001",
                "source": "custom"}]}))
            .unwrap(),
        );
        let mut ingest =
            LogIngest::new(t.clone(), runner, "host-1".into()).with_routes(routes.clone());
        let access = |host: &str| {
            format!(
                r#"{{"timestamp":"2026-09-23T10:00:05Z","request_id":"r1","method":"GET","path":"/","host":"{host}","status":200,"response_time_us":1500,"client_ip":"203.0.113.0","bytes_sent":10}}"#
            )
        };
        let now = Instant::now();
        for (i, host) in ["App.example.com:443", "other.example.com"]
            .iter()
            .enumerate()
        {
            let line = system("dwaar.service", 6, &format!("s=1;i={i}"), &access(host));
            ingest.handle(&line, now).await;
        }
        t.sync().await;
        let http: Vec<LogRecord> = stored_kind(&t, Kind::Http);
        assert_eq!(http.len(), 2);
        assert_eq!(http[0].service_id, "01a0cdb5-3500-70c1-8000-000000000001");
        assert_eq!(http[0].project_id, "01a0cdb5-3500-70b1-8000-000000000001");
        assert_eq!(
            http[0].environment_id,
            "01a0cdb5-3500-70b2-8000-000000000001"
        );
        assert_eq!(http[1].service_id, "");
        assert_eq!(http[1].project_id, "");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// QA_M2 X1 (agent-protocol.md 9.5): Dwaar access lines of a route host
    /// that belongs to a service feed the `dwaar.*` series, and the 60 s
    /// rollups carry that service's ids for `QueryAnalytics`.
    #[tokio::test]
    async fn dwaar_lines_feed_the_route_metrics_and_attributed_rollups() {
        use super::super::records::{MetricSample, StoredAnalyticsRow, TAG_METRIC};
        const SVC: &str = "01a0cdb5-3500-70c1-8000-000000000001";
        const SERVER: &str = "01a0cdb5-3500-70a1-8000-000000000001";
        let dir = temp_dir("ingest-dwaar-metrics");
        let t = test_support::open(dir.join("telemetry"));
        let runner = ScriptRunner::new(Vec::new());
        let routes = Arc::new(super::super::routes::RoutesMap::default());
        routes.replace(
            super::super::routes::parse_routes(&json!({"routes": [{"host": "app.example.com",
                "service_id": SVC,
                "project_id": "01a0cdb5-3500-70b1-8000-000000000001",
                "environment_id": "01a0cdb5-3500-70b2-8000-000000000001",
                "source": "default"}]}))
            .unwrap(),
        );
        let mut ingest = LogIngest::new(t.clone(), runner, "host-1".into())
            .with_routes(routes)
            .with_server_id(Arc::new(|| SERVER.to_owned()));
        let access = |host: &str, path: &str, status: u16| {
            format!(
                r#"{{"timestamp":"2026-09-23T10:00:05Z","request_id":"r1","method":"GET","path":"{path}","host":"{host}","status":{status},"response_time_us":2500,"client_ip":"203.0.113.0","bytes_sent":10,"route":"{host}","route_path":"/ignored"}}"#
            )
        };
        let now = Instant::now();
        for (i, (host, path, status)) in [
            ("app.example.com", "/hooks/42", 200),
            ("app.example.com", "/hooks/43", 503),
            ("hooks.example.com", "/hooks/44", 200),
        ]
        .iter()
        .enumerate()
        {
            let mut line = system(
                "dwaar.service",
                6,
                &format!("s=1;i={i}"),
                &access(host, path, *status),
            );
            line["at"] = json!("2026-09-23T10:00:05Z");
            ingest.handle(&line, now).await;
        }
        ingest.flush_rollups(timestamp("2026-09-23T10:01:30Z"));
        t.sync().await;
        let samples: Vec<MetricSample> = t
            .snapshot(Kind::Metrics)
            .scan(ScanSpec::default())
            .filter_map(Result::ok)
            .filter(|r| r.tag == TAG_METRIC)
            .filter_map(|r| MetricSample::decode(r.payload.as_slice()).ok())
            .collect();
        let requests: Vec<&MetricSample> = samples
            .iter()
            .filter(|s| s.name == "dwaar.requests")
            .collect();
        assert_eq!(requests.len(), 2, "{samples:?}");
        assert!(requests.iter().all(|s| s.labels["service_id"] == SVC
            && s.labels["server_id"] == SERVER
            && s.labels["route"] == "app.example.com"
            && s.labels["route_path"] == "/hooks/:id"));
        assert_eq!(
            samples
                .iter()
                .filter(|s| s.name == "dwaar.requests.5xx")
                .count(),
            1
        );
        assert_eq!(
            samples
                .iter()
                .filter(|s| s.name == "dwaar.request.duration")
                .count(),
            2
        );
        let rows: Vec<StoredAnalyticsRow> = stored_kind(&t, Kind::Analytics);
        assert_eq!(rows.len(), 2);
        let app = rows
            .iter()
            .find(|r| r.dimensions[0].value == "app.example.com")
            .unwrap();
        assert_eq!(app.service_id, SVC);
        assert_eq!(app.environment_id, "01a0cdb5-3500-70b2-8000-000000000001");
        let other = rows
            .iter()
            .find(|r| r.dimensions[0].value == "hooks.example.com")
            .unwrap();
        assert_eq!(other.service_id, "");
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn timestamp(text: &str) -> i64 {
        crate::signed_plan::text::timestamp(text).unwrap()
    }
}
