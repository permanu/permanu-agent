//! The agent's client for `permanu-runner` (signed-plan.md sections 14.1 to
//! 14.8, D-025, D-030, D-038).
//!
//! - Production reaches the root runner through the socket-activated unit
//!   `permanu-runner.socket` (`/run/permanu/runner.sock`, `root:permanu-agent
//!   0660`); each connection is one root `permanu-runner serve` instance.
//!   Development builds (`dev-paths`) may run `<program> rpc` over stdio.
//! - Wire protocol (section 14.8): one request line `{"op", "plan"?,
//!   "payload"}` per exchange; the answer is zero or more `{"type":
//!   "progress", ...}` lines and exactly one `{"type": "result", "ok", ...}`
//!   line, which is the last. Any other `type`, a second `result` or a
//!   connection that closes before the `result` is a failed op
//!   (`E_INTERNAL` here); the consumed log stays authoritative for what ran.
//! - Bound requests name only `{plan_id, plan_digest_hex, action_index}` and
//!   carry `payload: {}` (D-025); the runner takes every executable parameter
//!   from the agent's admission row (D-022). `bootstrap_trust` is the one
//!   unbound mutating op and carries only the `server.add` envelope text.
//! - The read-only container ops (section 14.3, D-036) take their pinned
//!   payloads; `container_logs_follow` streams `progress` lines until the
//!   agent closes the connection or the container stops.

use std::path::PathBuf;
#[cfg(feature = "dev-paths")]
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::UnixStream;
#[cfg(feature = "dev-paths")]
use tokio::process::Command;

use crate::signed_plan::PlanCode;

pub const DEFAULT_RUNNER_SOCKET: &str = "/run/permanu/runner.sock";
/// A response line: 4 MiB covers a `container_logs` tail result.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Section 14.8: a request line is at most 256 KiB.
const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Lines read for one non-streaming exchange.
const MAX_LINES: usize = 4_096;
const MAX_MESSAGE_CHARS: usize = 256;
/// Progress lines kept per op; later ones are dropped.
const MAX_PROGRESS_LINES: usize = 256;
/// How long the caller waits, after the `result`, for the runner to close
/// the connection; a line in that time is a second result (section 14.8).
const DRAIN: Duration = Duration::from_millis(500);
pub const BIND_TIMEOUT: Duration = Duration::from_secs(30);
/// Read-only container ops (`list_containers`, `inspect_container`,
/// `container_logs`).
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The message of a call that hit its timeout.
pub const TIMED_OUT: &str = "runner timed out";

/// The admitted action a bound op names (signed-plan.md 14.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRef {
    pub plan_id: String,
    pub plan_digest_hex: String,
    pub action_index: u32,
}

impl PlanRef {
    fn json(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "plan_digest_hex": self.plan_digest_hex,
            "action_index": self.action_index,
        })
    }
}

/// A successful bind: the row's kind and the runner's consumption time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub kind: String,
    pub consumed_at: String,
    pub execution_deadline: String,
}

/// A refused or failed runner call. `code` is the runner's own code (a
/// section 6.1/14 code, or an op failure code such as `health_failed`);
/// transport and protocol failures use `E_INTERNAL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerFailure {
    pub code: String,
    pub message: String,
    pub consumed_at: Option<String>,
    /// `error.failure_code` of a failed service step (section 14.8).
    pub failure_code: Option<String>,
}

impl RunnerFailure {
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            code: PlanCode::Internal.as_str().to_owned(),
            message: message.into(),
            consumed_at: None,
            failure_code: None,
        }
    }

    /// The contract code, or `Internal` for codes outside it.
    pub fn plan_code(&self) -> PlanCode {
        PlanCode::parse(&self.code).unwrap_or(PlanCode::Internal)
    }
}

/// A completed op: the runner's progress messages, in order, and its
/// `result` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpDone {
    pub progress: Vec<String>,
    pub result: Value,
}

/// One request/response exchange with the runner.
#[tonic::async_trait]
pub trait Runner: Send + Sync {
    /// Sends `request` and returns its `result` line with the progress
    /// messages before it under `"progress"`.
    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value, RunnerFailure>;

    /// Sends `request` and hands back its event lines as they arrive
    /// (`container_logs_follow`). Dropping the stream closes the connection.
    async fn open(&self, request: Value) -> Result<EventLines, RunnerFailure>;
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_MESSAGE_CHARS).collect()
}

fn failure_of(result: &Value) -> RunnerFailure {
    let error = &result["error"];
    RunnerFailure {
        code: error["code"]
            .as_str()
            .filter(|code| !code.is_empty() && code.len() <= 64)
            .unwrap_or(PlanCode::Internal.as_str())
            .to_owned(),
        // The runner's messages are fixed text; bound them anyway.
        message: bounded(
            error["message"]
                .as_str()
                .unwrap_or("runner refused the request"),
        ),
        consumed_at: error["consumed_at"]
            .as_str()
            .or(result["consumed_at"].as_str())
            .map(bounded),
        failure_code: error["failure_code"]
            .as_str()
            .filter(|code| !code.is_empty() && code.len() <= 32)
            .map(str::to_owned),
    }
}

fn ok_or_failure(result: Value) -> Result<Value, RunnerFailure> {
    if result["ok"] == true {
        Ok(result)
    } else {
        Err(failure_of(&result))
    }
}

/// `bind_plan` (section 14.2) in the section 14.8 form.
pub async fn bind_plan(runner: &dyn Runner, plan: &PlanRef) -> Result<Bound, RunnerFailure> {
    let request = json!({"op": "bind_plan", "plan": plan.json(), "payload": {}});
    let result = ok_or_failure(runner.exchange(request, BIND_TIMEOUT).await?)?;
    let field = |name: &str| result[name].as_str().map(bounded).unwrap_or_default();
    Ok(Bound {
        kind: field("kind"),
        consumed_at: field("consumed_at"),
        execution_deadline: field("execution_deadline"),
    })
}

/// A bound op with payload `{}` (sections 14.3, 14.6).
pub async fn run_op(
    runner: &dyn Runner,
    op: &str,
    plan: &PlanRef,
    timeout: Duration,
) -> Result<OpDone, RunnerFailure> {
    let request = json!({"op": op, "plan": plan.json(), "payload": {}});
    let mut result = ok_or_failure(runner.exchange(request, timeout).await?)?;
    let progress = match result.as_object_mut().and_then(|m| m.remove("progress")) {
        Some(Value::Array(lines)) => lines
            .iter()
            .filter_map(|line| line.as_str().map(bounded))
            .collect(),
        _ => Vec::new(),
    };
    Ok(OpDone { progress, result })
}

/// A schedule binding (section 14.9): the admitted definition action a
/// scheduled run executes under, its fire time and attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleRef {
    pub plan: PlanRef,
    pub scheduled_for: String,
    pub attempt: u32,
}

/// A schedule-bound op (`run_cron`, `backup_run`, `backup_verify`,
/// `backup_prune`; section 14.8 v1.0.7): `schedule` in place of `plan`,
/// payload `{}`. Returns the `result` line of an accepted run (its
/// `outcome` says how the run ended); a refusal is the runner's code.
pub async fn run_scheduled(
    runner: &dyn Runner,
    op: &str,
    schedule: &ScheduleRef,
    timeout: Duration,
) -> Result<Value, RunnerFailure> {
    let mut binding = schedule.plan.json();
    binding["scheduled_for"] = json!(schedule.scheduled_for);
    binding["attempt"] = json!(schedule.attempt);
    let request = json!({"op": op, "schedule": binding, "payload": {}});
    ok_or_failure(runner.exchange(request, timeout).await?)
}

/// One `notify_channel` call (section 14.3, fixed-purpose op): the runner
/// posts `text` (and `payload_json` for a `webhook` channel) to the
/// credential of the admitted channel. The agent never sees the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub channel_id: String,
    pub text: String,
    pub event_id: String,
    pub payload_json: Option<String>,
}

/// What `notify_channel` answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotifyResult {
    pub delivered: bool,
    pub status_code: i32,
    pub target_display: String,
    pub error: String,
}

/// `notify_channel` waits for the runner's 10 s post plus margin.
pub const NOTIFY_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn notify_channel(
    runner: &dyn Runner,
    notification: &Notification,
) -> Result<NotifyResult, RunnerFailure> {
    let mut payload = json!({
        "channel_id": notification.channel_id,
        "text": notification.text,
        "event_id": notification.event_id,
    });
    if let Some(body) = &notification.payload_json {
        payload["payload_json"] = json!(body);
    }
    let request = json!({"op": "notify_channel", "payload": payload});
    let result = ok_or_failure(runner.exchange(request, NOTIFY_TIMEOUT).await?)?;
    Ok(NotifyResult {
        delivered: result["delivered"] == true,
        status_code: result["status_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
            .unwrap_or_default(),
        target_display: result["target_display"]
            .as_str()
            .map(bounded)
            .unwrap_or_default(),
        error: result["error"].as_str().map(bounded).unwrap_or_default(),
    })
}

/// `bootstrap_trust` (section 14.4, v1.0.2): unbound, accepted by the runner
/// only while trusted-keys.json is absent. The runner runs section 7.3 step 3
/// itself, including the time window, before it writes the file.
pub async fn bootstrap_trust(runner: &dyn Runner, envelope: &str) -> Result<(), RunnerFailure> {
    let request = json!({"op": "bootstrap_trust", "payload": {"signed_plan": envelope}});
    ok_or_failure(runner.exchange(request, BIND_TIMEOUT).await?).map(|_| ())
}

/// A Permanu container as `list_containers` reports it (section 14.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunnerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub created_at: String,
    pub project_id: String,
    /// v1.0.5 (D-045): the `permanu.environment` label (the signed
    /// environment name); empty for a container started before v1.0.5.
    pub environment: String,
    pub environment_id: String,
    pub service_id: String,
    /// v1.0.5 (D-045): the `permanu.service_kind` label (the signed
    /// `ServiceSpec.service_kind`); empty before v1.0.5.
    pub service_kind: String,
    pub deployment_id: String,
    pub spec_digest_hex: String,
}

/// Label filters of `list_containers`; empty fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerFilter {
    pub project_id: String,
    pub environment_id: String,
    pub service_id: String,
}

/// Section 14.3: at most 1000 containers per answer.
const MAX_CONTAINERS: usize = 1_000;

/// `list_containers` (section 14.3): unbound and read-only.
pub async fn list_containers(
    runner: &dyn Runner,
    filter: &ContainerFilter,
) -> Result<Vec<RunnerContainer>, RunnerFailure> {
    let mut payload = serde_json::Map::new();
    for (name, value) in [
        ("project_id", &filter.project_id),
        ("environment_id", &filter.environment_id),
        ("service_id", &filter.service_id),
    ] {
        if !value.is_empty() {
            payload.insert(name.to_owned(), json!(value));
        }
    }
    let request = json!({"op": "list_containers", "payload": payload});
    let result = ok_or_failure(runner.exchange(request, READ_TIMEOUT).await?)?;
    let items = result["containers"]
        .as_array()
        .ok_or_else(|| RunnerFailure::transport("list_containers returned no containers"))?;
    let text = |item: &Value, name: &str| item[name].as_str().map(bounded).unwrap_or_default();
    Ok(items
        .iter()
        .take(MAX_CONTAINERS)
        .filter(|item| item["id"].as_str().is_some_and(|id| !id.is_empty()))
        .map(|item| RunnerContainer {
            id: text(item, "id"),
            name: text(item, "name"),
            image: text(item, "image"),
            state: text(item, "state"),
            status: text(item, "status"),
            created_at: text(item, "created_at"),
            project_id: text(item, "project_id"),
            environment: text(item, "environment"),
            environment_id: text(item, "environment_id"),
            service_id: text(item, "service_id"),
            service_kind: text(item, "service_kind"),
            deployment_id: text(item, "deployment_id"),
            spec_digest_hex: text(item, "spec_digest_hex"),
        })
        .collect())
}

/// `inspect_container` (section 14.3): the `container` object.
pub async fn inspect_container(
    runner: &dyn Runner,
    container_id: &str,
) -> Result<Value, RunnerFailure> {
    let request = json!({"op": "inspect_container", "payload": {"container_id": container_id}});
    let mut result = ok_or_failure(runner.exchange(request, READ_TIMEOUT).await?)?;
    match result.get_mut("container").map(Value::take) {
        Some(container @ Value::Object(_)) => Ok(container),
        _ => Err(RunnerFailure::transport(
            "inspect_container returned no container",
        )),
    }
}

/// One timestamped line of `container_logs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub stream: &'static str,
    pub line: String,
}

/// Section 14.3: `tail` is 1–10000.
pub const MAX_LOG_TAIL: u32 = 10_000;

/// `container_logs` (section 14.3): the tail, stdout lines then stderr
/// lines, each prefixed with its RFC 3339 timestamp.
pub async fn container_logs(
    runner: &dyn Runner,
    container_id: &str,
    tail: u32,
    since: Option<&str>,
) -> Result<Vec<LogLine>, RunnerFailure> {
    let mut payload = json!({"container_id": container_id, "tail": tail.clamp(1, MAX_LOG_TAIL)});
    if let Some(since) = since {
        payload["since"] = json!(since);
    }
    let request = json!({"op": "container_logs", "payload": payload});
    let result = ok_or_failure(runner.exchange(request, READ_TIMEOUT).await?)?;
    let mut lines = Vec::new();
    for stream in ["stdout", "stderr"] {
        for line in result[stream].as_array().map_or(&[][..], Vec::as_slice) {
            if let Some(text) = line.as_str() {
                lines.push(LogLine {
                    stream,
                    line: text.to_owned(),
                });
            }
        }
    }
    Ok(lines)
}

/// `container_logs_follow` (section 14.3): `progress` lines with `stream`
/// and `line` until the caller drops the stream or the container stops.
pub async fn container_logs_follow(
    runner: &dyn Runner,
    container_id: &str,
    since: Option<&str>,
) -> Result<EventLines, RunnerFailure> {
    let mut payload = json!({"container_id": container_id});
    if let Some(since) = since {
        payload["since"] = json!(since);
    }
    runner
        .open(json!({"op": "container_logs_follow", "payload": payload}))
        .await
}

pub(crate) type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub(crate) type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// The event lines of one request (section 14.8), validated one by one.
pub struct EventLines {
    reader: BufReader<BoxRead>,
    writer: Option<BoxWrite>,
    op: String,
    finished: bool,
    /// Keeps a stdio runner alive for as long as the stream is.
    #[cfg(feature = "dev-paths")]
    _child: Option<tokio::process::Child>,
}

impl EventLines {
    pub(crate) async fn start(
        reader: BoxRead,
        mut writer: BoxWrite,
        request: &Value,
    ) -> Result<Self, RunnerFailure> {
        let mut line =
            serde_json::to_vec(request).map_err(|_| RunnerFailure::transport("encode"))?;
        if line.len() > MAX_REQUEST_BYTES {
            return Err(RunnerFailure::transport("request line too long"));
        }
        line.push(b'\n');
        writer
            .write_all(&line)
            .await
            .map_err(|_| RunnerFailure::transport("write to runner failed"))?;
        writer
            .flush()
            .await
            .map_err(|_| RunnerFailure::transport("write to runner failed"))?;
        Ok(Self {
            reader: BufReader::new(reader),
            writer: Some(writer),
            op: request["op"].as_str().unwrap_or_default().to_owned(),
            finished: false,
            #[cfg(feature = "dev-paths")]
            _child: None,
        })
    }

    /// One raw line; `None` at end of stream.
    async fn raw_line(&mut self) -> Result<Option<Value>, RunnerFailure> {
        let mut raw = Vec::new();
        let read = (&mut self.reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut raw)
            .await
            .map_err(|_| RunnerFailure::transport("read from runner failed"))?;
        if read == 0 {
            return Ok(None);
        }
        if raw.len() > MAX_LINE_BYTES || raw.last() != Some(&b'\n') {
            return Err(RunnerFailure::transport("runner line too long or torn"));
        }
        let value: Value = serde_json::from_slice(&raw)
            .map_err(|_| RunnerFailure::transport("runner returned invalid JSON"))?;
        Ok(Some(value))
    }

    /// The next event line: `progress` or the one `result`, after which it
    /// returns `None`. Anything else fails the op (section 14.8).
    pub async fn next(&mut self) -> Result<Option<Value>, RunnerFailure> {
        if self.finished {
            return Ok(None);
        }
        let Some(line) = self.raw_line().await? else {
            return Err(RunnerFailure::transport("runner closed without a result"));
        };
        if line
            .get("op")
            .is_some_and(|op| op.as_str() != Some(self.op.as_str()))
        {
            return Err(RunnerFailure::transport("runner answered another op"));
        }
        match line["type"].as_str() {
            Some("progress") => Ok(Some(line)),
            Some("result") if line["ok"].is_boolean() => {
                self.finished = true;
                Ok(Some(line))
            }
            Some("result") => Err(RunnerFailure::transport("runner result without ok")),
            _ => Err(RunnerFailure::transport("runner returned an unknown line")),
        }
    }

    /// After the `result`: closes the request side and checks that nothing
    /// else follows before the runner closes (exactly one `result`).
    async fn drain(&mut self) -> Result<(), RunnerFailure> {
        if let Some(mut writer) = self.writer.take() {
            let _ = writer.shutdown().await;
        }
        match tokio::time::timeout(DRAIN, self.raw_line()).await {
            Ok(Ok(Some(_))) => Err(RunnerFailure::transport(
                "runner sent a line after its result",
            )),
            // End of stream, a read error or a runner slow to close: the
            // one result stands.
            _ => Ok(()),
        }
    }

    /// Reads the whole answer of a non-streaming request.
    async fn answer(mut self) -> Result<Value, RunnerFailure> {
        let mut progress = Vec::new();
        for _ in 0..MAX_LINES {
            let Some(line) = self.next().await? else {
                break;
            };
            if line["type"] == "result" {
                self.drain().await?;
                let mut result = line;
                result["progress"] = json!(progress);
                return Ok(result);
            }
            let text = line["message"].as_str().unwrap_or_default();
            if !text.is_empty() && progress.len() < MAX_PROGRESS_LINES {
                progress.push(bounded(text));
            }
        }
        Err(RunnerFailure::transport("runner sent too many lines"))
    }
}

/// The root runner behind `permanu-runner.socket` (production, D-030).
#[derive(Debug, Clone)]
pub struct SocketRunner {
    pub path: PathBuf,
}

impl SocketRunner {
    async fn connect(&self, request: &Value) -> Result<EventLines, RunnerFailure> {
        let stream = UnixStream::connect(&self.path)
            .await
            .map_err(|e| RunnerFailure::transport(format!("cannot reach the runner: {e}")))?;
        let (reader, writer) = stream.into_split();
        EventLines::start(Box::new(reader), Box::new(writer), request).await
    }
}

#[tonic::async_trait]
impl Runner for SocketRunner {
    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value, RunnerFailure> {
        let run = async { self.connect(&request).await?.answer().await };
        tokio::time::timeout(timeout, run)
            .await
            .map_err(|_| RunnerFailure::transport(TIMED_OUT))?
    }

    async fn open(&self, request: Value) -> Result<EventLines, RunnerFailure> {
        tokio::time::timeout(READ_TIMEOUT, self.connect(&request))
            .await
            .map_err(|_| RunnerFailure::transport(TIMED_OUT))?
    }
}

/// Runs `<program> rpc` once per request (development builds only).
#[cfg(feature = "dev-paths")]
#[derive(Debug, Clone)]
pub struct StdioRunner {
    pub program: PathBuf,
}

#[cfg(feature = "dev-paths")]
impl StdioRunner {
    async fn spawn(&self, request: &Value) -> Result<EventLines, RunnerFailure> {
        let mut child = Command::new(&self.program)
            .arg("rpc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| RunnerFailure::transport(format!("cannot start the runner: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| RunnerFailure::transport("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RunnerFailure::transport("no stdout"))?;
        let mut lines = EventLines::start(Box::new(stdout), Box::new(stdin), request).await?;
        lines._child = Some(child);
        Ok(lines)
    }
}

#[cfg(feature = "dev-paths")]
#[tonic::async_trait]
impl Runner for StdioRunner {
    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value, RunnerFailure> {
        let run = async { self.spawn(&request).await?.answer().await };
        tokio::time::timeout(timeout, run)
            .await
            .map_err(|_| RunnerFailure::transport(TIMED_OUT))?
    }

    async fn open(&self, request: Value) -> Result<EventLines, RunnerFailure> {
        self.spawn(&request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> PlanRef {
        PlanRef {
            plan_id: "01a0cdb5-3500-7001-8000-000000000001".to_owned(),
            plan_digest_hex: "a".repeat(64),
            action_index: 2,
        }
    }

    /// A socket runner that answers the next connection with fixed bytes
    /// and hands back the request line it read.
    async fn scripted(
        name: &str,
        answer: &'static str,
    ) -> (
        SocketRunner,
        tokio::task::JoinHandle<Value>,
        std::path::PathBuf,
    ) {
        let dir = crate::signed_plan::test_support::temp_dir(name);
        let path = dir.join("runner.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut line = String::new();
            let mut reader = BufReader::new(reader);
            reader.read_line(&mut line).await.unwrap();
            writer.write_all(answer.as_bytes()).await.unwrap();
            // The scripted answer is all this runner says.
            writer.shutdown().await.unwrap();
            let mut rest = String::new();
            let _ = reader.read_line(&mut rest).await;
            serde_json::from_str(&line).unwrap()
        });
        (SocketRunner { path }, server, dir)
    }

    #[tokio::test]
    async fn bind_sends_the_pinned_request_and_reads_the_result_line() {
        let (runner, server, dir) = scripted(
            "rn-bind",
            "{\"type\":\"result\",\"op\":\"bind_plan\",\"ok\":true,\"kind\":\"deploy\",\
             \"consumed_at\":\"c\",\"execution_deadline\":\"e\"}\n",
        )
        .await;
        let bound = bind_plan(&runner, &plan()).await.unwrap();
        assert_eq!(bound.kind, "deploy");
        assert_eq!(bound.consumed_at, "c");
        assert_eq!(bound.execution_deadline, "e");
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "bind_plan", "plan": {"plan_id": plan().plan_id,
                   "plan_digest_hex": plan().plan_digest_hex, "action_index": 2},
                   "payload": {}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn schedule_bound_ops_carry_the_schedule_in_place_of_the_plan() {
        let (runner, server, dir) = scripted(
            "rn-sched",
            "{\"type\":\"result\",\"op\":\"run_cron\",\"ok\":true,\"outcome\":\"succeeded\"}\n",
        )
        .await;
        let schedule = ScheduleRef {
            plan: plan(),
            scheduled_for: "2026-09-23T10:15:00Z".to_owned(),
            attempt: 2,
        };
        let done = run_scheduled(&runner, "run_cron", &schedule, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(done["outcome"], "succeeded");
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "run_cron", "schedule": {"plan_id": plan().plan_id,
                   "plan_digest_hex": plan().plan_digest_hex, "action_index": 2,
                   "scheduled_for": "2026-09-23T10:15:00Z", "attempt": 2},
                   "payload": {}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn notify_channel_sends_only_the_fixed_payload() {
        let (runner, server, dir) = scripted(
            "rn-notify",
            "{\"type\":\"result\",\"op\":\"notify_channel\",\"ok\":true,\"delivered\":true,\
             \"status_code\":200,\"target_display\":\"hooks.slack.com/services/T0\\u2026\"}\n",
        )
        .await;
        let sent = notify_channel(
            &runner,
            &Notification {
                channel_id: "c1".to_owned(),
                text: "[WARNING] disk".to_owned(),
                event_id: "e1".to_owned(),
                payload_json: None,
            },
        )
        .await
        .unwrap();
        assert!(sent.delivered);
        assert_eq!(sent.status_code, 200);
        assert_eq!(sent.target_display, "hooks.slack.com/services/T0\u{2026}");
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "notify_channel", "payload": {"channel_id": "c1",
                   "text": "[WARNING] disk", "event_id": "e1"}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn bind_failures_carry_the_runner_code() {
        let (runner, _server, dir) = scripted(
            "rn-bindf",
            "{\"type\":\"result\",\"op\":\"bind_plan\",\"ok\":false,\"error\":\
             {\"code\":\"E_PLAN_CONSUMED\",\"message\":\"m\",\"consumed_at\":\"t\"}}\n",
        )
        .await;
        let failure = bind_plan(&runner, &plan()).await.unwrap_err();
        assert_eq!(failure.plan_code(), PlanCode::PlanConsumed);
        assert_eq!(failure.consumed_at.as_deref(), Some("t"));
        std::fs::remove_dir_all(dir).unwrap();

        let (runner, _server, dir) = scripted(
            "rn-bindu",
            "{\"type\":\"result\",\"ok\":false,\"error\":{\"code\":\"E_WHAT\"}}\n",
        )
        .await;
        assert_eq!(
            bind_plan(&runner, &plan()).await.unwrap_err().plan_code(),
            PlanCode::Internal
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn ops_collect_progress_then_one_result() {
        let (runner, server, dir) = scripted(
            "rn-op",
            "{\"type\":\"progress\",\"op\":\"prepare_release\",\"at\":\"x\",\"message\":\"pulling image\"}\n\
             {\"type\":\"progress\",\"op\":\"prepare_release\",\"at\":\"x\"}\n\
             {\"type\":\"result\",\"op\":\"prepare_release\",\"ok\":true,\"state\":\"candidate\"}\n",
        )
        .await;
        let done = run_op(&runner, "prepare_release", &plan(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(done.progress, vec!["pulling image"]);
        assert_eq!(done.result["state"], "candidate");
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "prepare_release", "payload": {}, "plan": {
                "plan_id": plan().plan_id, "plan_digest_hex": plan().plan_digest_hex,
                "action_index": 2}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_failed_op_carries_its_failure_code() {
        let (runner, _server, dir) = scripted(
            "rn-opf",
            "{\"type\":\"result\",\"op\":\"activate_release\",\"ok\":false,\"error\":\
             {\"code\":\"health_failed\",\"message\":\"public check failed\",\
             \"failure_code\":\"public_health\"}}\n",
        )
        .await;
        let failure = run_op(&runner, "activate_release", &plan(), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(failure.code, "health_failed");
        assert_eq!(failure.message, "public check failed");
        assert_eq!(failure.failure_code.as_deref(), Some("public_health"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    // Section 14.8: a second result, an unknown type, a result without ok
    // and a connection that closes early are failed ops, never successes.
    #[tokio::test]
    async fn protocol_violations_fail_the_op() {
        for (name, answer) in [
            (
                "rn-two",
                "{\"type\":\"result\",\"op\":\"restart_release\",\"ok\":true}\n\
                 {\"type\":\"result\",\"op\":\"restart_release\",\"ok\":true}\n",
            ),
            (
                "rn-kind",
                "{\"kind\":\"result\",\"result\":{\"success\":true}}\n",
            ),
            ("rn-flat", "{\"ok\":true}\n"),
            (
                "rn-nook",
                "{\"type\":\"result\",\"op\":\"restart_release\"}\n",
            ),
            (
                "rn-early",
                "{\"type\":\"progress\",\"op\":\"restart_release\",\"at\":\"x\"}\n",
            ),
            (
                "rn-otherop",
                "{\"type\":\"result\",\"op\":\"prepare_release\",\"ok\":true}\n",
            ),
            ("rn-torn", "{\"type\":\"result\",\"ok\":true}"),
        ] {
            let (runner, _server, dir) = scripted(name, answer).await;
            let failure = run_op(&runner, "restart_release", &plan(), Duration::from_secs(5))
                .await
                .unwrap_err();
            assert_eq!(failure.plan_code(), PlanCode::Internal, "{name}");
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn bootstrap_trust_carries_only_the_envelope_text() {
        let (runner, server, dir) = scripted(
            "rn-boot",
            "{\"type\":\"result\",\"op\":\"bootstrap_trust\",\"ok\":true}\n",
        )
        .await;
        bootstrap_trust(&runner, "{\"plan\":{}}").await.unwrap();
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "bootstrap_trust", "payload": {"signed_plan": "{\"plan\":{}}"}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn list_containers_sends_only_the_set_filters() {
        let (runner, server, dir) = scripted(
            "rn-list",
            "{\"type\":\"result\",\"op\":\"list_containers\",\"ok\":true,\"containers\":[\
             {\"id\":\"c1\",\"name\":\"web-1\",\"image\":\"i\",\"state\":\"running\",\
             \"status\":\"Up\",\"created_at\":\"t\",\"project_id\":\"p\",\
             \"environment_id\":\"e\",\"service_id\":\"s\",\"deployment_id\":\"d\",\
             \"spec_digest_hex\":\"h\"},{\"name\":\"no-id\"}]}\n",
        )
        .await;
        let containers = list_containers(
            &runner,
            &ContainerFilter {
                service_id: "s".to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].deployment_id, "d");
        assert_eq!(containers[0].name, "web-1");
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "list_containers", "payload": {"service_id": "s"}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn container_logs_reads_both_streams() {
        let (runner, server, dir) = scripted(
            "rn-logs",
            "{\"type\":\"result\",\"op\":\"container_logs\",\"ok\":true,\
             \"stdout\":[\"2026-09-23T10:00:00Z a\"],\"stderr\":[\"2026-09-23T10:00:01Z b\"]}\n",
        )
        .await;
        let lines = container_logs(&runner, "c1", 50_000, Some("2026-09-23T09:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            lines,
            vec![
                LogLine {
                    stream: "stdout",
                    line: "2026-09-23T10:00:00Z a".to_owned()
                },
                LogLine {
                    stream: "stderr",
                    line: "2026-09-23T10:00:01Z b".to_owned()
                }
            ]
        );
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "container_logs", "payload": {"container_id": "c1",
                   "tail": 10_000, "since": "2026-09-23T09:00:00Z"}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn inspect_and_follow_use_their_payloads() {
        let (runner, server, dir) = scripted(
            "rn-insp",
            "{\"type\":\"result\",\"op\":\"inspect_container\",\"ok\":true,\
             \"container\":{\"id\":\"c1\",\"restart_count\":2}}\n",
        )
        .await;
        let container = inspect_container(&runner, "c1").await.unwrap();
        assert_eq!(container["restart_count"], 2);
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "inspect_container", "payload": {"container_id": "c1"}})
        );
        std::fs::remove_dir_all(dir).unwrap();

        let (runner, server, dir) = scripted(
            "rn-follow",
            "{\"type\":\"progress\",\"op\":\"container_logs_follow\",\"at\":\"t\",\
             \"stream\":\"stdout\",\"line\":\"2026-09-23T10:00:00Z hi\"}\n\
             {\"type\":\"result\",\"op\":\"container_logs_follow\",\"ok\":true}\n",
        )
        .await;
        let mut lines = container_logs_follow(&runner, "c1", None).await.unwrap();
        let first = lines.next().await.unwrap().unwrap();
        assert_eq!(first["line"], "2026-09-23T10:00:00Z hi");
        let last = lines.next().await.unwrap().unwrap();
        assert_eq!(last["type"], "result");
        assert_eq!(lines.next().await.unwrap(), None);
        drop(lines);
        assert_eq!(
            server.await.unwrap(),
            json!({"op": "container_logs_follow", "payload": {"container_id": "c1"}})
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn nobody_listening_is_a_transport_failure() {
        let runner = SocketRunner {
            path: std::path::PathBuf::from("/nonexistent/permanu/runner.sock"),
        };
        assert_eq!(
            run_op(&runner, "restart_release", &plan(), Duration::from_secs(5))
                .await
                .unwrap_err()
                .plan_code(),
            PlanCode::Internal
        );
    }

    #[cfg(feature = "dev-paths")]
    #[tokio::test]
    async fn stdio_runner_speaks_the_same_protocol() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::signed_plan::test_support::temp_dir("runner-stdio");
        let script = dir.join("runner");
        let capture = dir.join("request");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n[ \"$1\" = rpc ] || exit 64\nIFS= read -r line\nprintf '%s' \"$line\" > {}\n\
                 printf '%s\\n' '{{\"type\":\"result\",\"op\":\"bind_plan\",\"ok\":true,\"kind\":\"deploy\",\"consumed_at\":\"2026-09-23T10:00:09Z\"}}'\n",
                capture.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let runner = StdioRunner { program: script };
        let bound = bind_plan(&runner, &plan()).await.unwrap();
        assert_eq!(bound.consumed_at, "2026-09-23T10:00:09Z");
        let sent: Value = serde_json::from_slice(&std::fs::read(&capture).unwrap()).unwrap();
        assert_eq!(sent["plan"]["action_index"], 2);
        assert_eq!(sent["payload"], json!({}));
        let missing = StdioRunner {
            program: dir.join("absent"),
        };
        assert_eq!(
            bind_plan(&missing, &plan()).await.unwrap_err().plan_code(),
            PlanCode::Internal
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
