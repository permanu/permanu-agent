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
//! Resume: `checkpoint.json` keeps, per container, the last stored second
//! and the `(stream, SHA-256 of line)` hashes stored in it; on reconnect
//! the agent passes the earliest of those seconds as `since` and drops
//! lines at or before a container's checkpoint that it already stored, so a
//! reconnect neither loses nor duplicates lines.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

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
/// Checkpoints older than the log retention are forgotten.
const CHECKPOINT_MAX_AGE_SECS: i64 = 7 * 86_400;
const NANOS: i64 = 1_000_000_000;

#[derive(Debug, Default, Clone)]
struct Check {
    sec: i64,
    hashes: HashSet<String>,
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
}

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
        };
        ingest.load_checkpoint();
        ingest
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
            self.checks.insert(id.clone(), Check { sec, hashes });
        }
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
                (id.clone(), json!({"sec": c.sec, "hashes": hashes}))
            })
            .collect();
        self.telemetry
            .write_checkpoint(&json!({"version": 1, "logs": logs}));
    }

    /// The `since` of the next connection: the earliest checkpoint second.
    pub fn since(&self) -> Option<String> {
        self.checks
            .values()
            .map(|c| c.sec)
            .min()
            .map(crate::signed_plan::text::format_timestamp)
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

    /// Handles one `progress` line of `logs_follow_stream`.
    pub async fn handle(&mut self, line: &Value, now: Instant) {
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
        let ts = parse_nanos(text("at"))
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
        let identity = self.identity(container).cloned().unwrap_or_default();
        let key = (container.to_owned(), stream.to_owned());
        let mut pem = self.pem.remove(&key).unwrap_or_default();
        for piece in records::split_line(message) {
            let (redacted_text, mut redacted) = pem.line(piece);
            let parsed = records::parse_line(&redacted_text);
            redacted |= parsed.redacted;
            let kind = identity.service_kind.as_str();
            let source_type = source_type_of(kind);
            let name = if identity.name.is_empty() {
                container
            } else {
                identity.name.as_str()
            };
            let record = LogRecord {
                timestamp: Some(timestamp_of(ts)),
                level: parsed.level as i32,
                message: redacted_text,
                source_type: source_type as i32,
                source: match source_type {
                    LogSourceType::Service => format!("service:{name}"),
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
                run_id: String::new(),
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
}
