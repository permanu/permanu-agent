//! The agent's client for `permanu-runner` (signed-plan.md sections 14.1 to
//! 14.6, D-025, D-030): newline-delimited JSON, one request line out, response
//! lines back until a terminal one.
//!
//! - Production reaches the root runner through the socket-activated unit
//!   `permanu-runner.socket` (`/run/permanu/runner.sock`, `root:permanu-agent
//!   0660`); each connection is one root `permanu-runner serve` instance.
//! - Tests and development may run `<program> rpc` over stdio instead.
//! - Requests name only `{plan_id, plan_digest_hex, action_index}` and carry
//!   `payload: {}` (D-025); the runner takes every executable parameter from
//!   the agent's admission row (D-022). `bootstrap_trust` is the one unbound
//!   mutating op and carries only the `server.add` envelope text.
//! - A terminal response is either `{"ok": true | false, "error"?: {code,
//!   message}}` (the `bind_plan` shape of section 14.2) or the runner's event
//!   stream, whose `{"kind": "result", "result": {success, error}}` line ends
//!   it; `progress` lines before it become step log lines.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::UnixStream;
use tokio::process::Command;

use crate::signed_plan::PlanCode;

pub const DEFAULT_RUNNER_SOCKET: &str = "/run/permanu/runner.sock";
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 4_096;
const MAX_MESSAGE_CHARS: usize = 256;
/// Progress lines kept per op; later ones are dropped.
const MAX_PROGRESS_LINES: usize = 256;
pub const BIND_TIMEOUT: Duration = Duration::from_secs(30);
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
/// transport failures use `E_INTERNAL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerFailure {
    pub code: String,
    pub message: String,
    pub consumed_at: Option<String>,
}

impl RunnerFailure {
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            code: PlanCode::Internal.as_str().to_owned(),
            message: message.into(),
            consumed_at: None,
        }
    }

    /// The contract code, or `Internal` for codes outside it.
    pub fn plan_code(&self) -> PlanCode {
        PlanCode::parse(&self.code).unwrap_or(PlanCode::Internal)
    }
}

/// A completed op: the runner's progress messages, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpDone {
    pub progress: Vec<String>,
}

/// One request/response exchange with the runner.
#[tonic::async_trait]
pub trait Runner: Send + Sync {
    /// Sends `request` and returns the terminal response, normalised to
    /// `{"ok": bool, "error"?: {...}, "progress": [..], ...}`.
    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value, RunnerFailure>;
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_MESSAGE_CHARS).collect()
}

fn failure_of(response: &Value) -> RunnerFailure {
    let error = &response["error"];
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
                .or(error["safe_message"].as_str())
                .unwrap_or("runner refused the request"),
        ),
        consumed_at: error["consumed_at"].as_str().map(str::to_owned),
    }
}

/// `bind_plan` (section 14.2).
pub async fn bind_plan(runner: &dyn Runner, plan: &PlanRef) -> Result<Bound, RunnerFailure> {
    let mut request = plan.json();
    request["op"] = json!("bind_plan");
    let response = runner.exchange(request, BIND_TIMEOUT).await?;
    if response["ok"] != true {
        return Err(failure_of(&response));
    }
    let field = |name: &str| response[name].as_str().unwrap_or_default().to_owned();
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
    let response = runner.exchange(request, timeout).await?;
    if response["ok"] != true {
        return Err(failure_of(&response));
    }
    Ok(OpDone {
        progress: response["progress"]
            .as_array()
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|l| l.as_str().map(bounded))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// `bootstrap_trust` (section 14.4, v1.0.2): unbound, accepted by the runner
/// only while trusted-keys.json is absent. The runner runs section 7.3 step 3
/// itself, including the time window, before it writes the file.
pub async fn bootstrap_trust(runner: &dyn Runner, envelope: &str) -> Result<(), RunnerFailure> {
    let request = json!({"op": "bootstrap_trust", "payload": {"signed_plan": envelope}});
    let response = runner.exchange(request, BIND_TIMEOUT).await?;
    if response["ok"] == true {
        Ok(())
    } else {
        Err(failure_of(&response))
    }
}

/// Normalises one response line. `None`: a non-terminal progress line.
fn terminal(line: &Value, progress: &mut Vec<String>) -> Result<Option<Value>, RunnerFailure> {
    if line.get("ok").is_some_and(Value::is_boolean) {
        let mut done = line.clone();
        done["progress"] = json!(progress);
        return Ok(Some(done));
    }
    match line["kind"].as_str() {
        Some("progress") => {
            let text = line["safe_message"]
                .as_str()
                .or(line["stage"].as_str())
                .unwrap_or_default();
            if !text.is_empty() && progress.len() < MAX_PROGRESS_LINES {
                progress.push(bounded(text));
            }
            Ok(None)
        }
        Some("result") => {
            let result = &line["result"];
            let ok = result["success"] == true;
            let mut done = json!({"ok": ok, "progress": progress});
            if !ok {
                done["error"] = json!({
                    "code": result["error"]["code"].as_str().unwrap_or_default(),
                    "message": result["error"]["safe_message"].as_str().unwrap_or_default(),
                });
            }
            Ok(Some(done))
        }
        _ => Err(RunnerFailure::transport("runner returned an unknown line")),
    }
}

/// Writes one request line and reads until a terminal line.
async fn converse<R, W>(reader: R, mut writer: W, request: &Value) -> Result<Value, RunnerFailure>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(request).map_err(|_| RunnerFailure::transport("encode"))?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .await
        .map_err(|_| RunnerFailure::transport("write to runner failed"))?;
    writer
        .flush()
        .await
        .map_err(|_| RunnerFailure::transport("write to runner failed"))?;
    let mut reader = BufReader::new(reader);
    let mut progress = Vec::new();
    for _ in 0..MAX_LINES {
        let mut raw = Vec::new();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut raw)
            .await
            .map_err(|_| RunnerFailure::transport("read from runner failed"))?;
        if read == 0 {
            return Err(RunnerFailure::transport("runner closed without a result"));
        }
        if raw.len() > MAX_LINE_BYTES || raw.last() != Some(&b'\n') {
            return Err(RunnerFailure::transport("runner line too long or torn"));
        }
        let value: Value = serde_json::from_slice(&raw)
            .map_err(|_| RunnerFailure::transport("runner returned invalid JSON"))?;
        if let Some(done) = terminal(&value, &mut progress)? {
            return Ok(done);
        }
    }
    Err(RunnerFailure::transport("runner sent too many lines"))
}

/// The root runner behind `permanu-runner.socket` (production, D-030).
#[derive(Debug, Clone)]
pub struct SocketRunner {
    pub path: PathBuf,
}

#[tonic::async_trait]
impl Runner for SocketRunner {
    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value, RunnerFailure> {
        let run = async {
            let stream = UnixStream::connect(&self.path)
                .await
                .map_err(|e| RunnerFailure::transport(format!("cannot reach the runner: {e}")))?;
            let (reader, writer) = stream.into_split();
            converse(reader, writer, &request).await
        };
        tokio::time::timeout(timeout, run)
            .await
            .map_err(|_| RunnerFailure::transport(TIMED_OUT))?
    }
}

/// Runs `<program> rpc` once per request (tests and development).
#[derive(Debug, Clone)]
pub struct StdioRunner {
    pub program: PathBuf,
}

#[tonic::async_trait]
impl Runner for StdioRunner {
    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value, RunnerFailure> {
        let mut child = Command::new(&self.program)
            .arg("rpc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| RunnerFailure::transport(format!("cannot start the runner: {e}")))?;
        let run = async {
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| RunnerFailure::transport("no stdin"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| RunnerFailure::transport("no stdout"))?;
            let done = converse(stdout, stdin, &request).await;
            let _ = child.wait().await;
            done
        };
        tokio::time::timeout(timeout, run)
            .await
            .map_err(|_| RunnerFailure::transport(TIMED_OUT))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn plan() -> PlanRef {
        PlanRef {
            plan_id: "01a0cdb5-3500-7001-8000-000000000001".to_owned(),
            plan_digest_hex: "a".repeat(64),
            action_index: 2,
        }
    }

    /// A runner that answers every request with fixed lines and records it.
    struct Canned {
        lines: Vec<Value>,
        seen: std::sync::Mutex<Vec<Value>>,
    }

    #[tonic::async_trait]
    impl Runner for Canned {
        async fn exchange(&self, request: Value, _: Duration) -> Result<Value, RunnerFailure> {
            self.seen.lock().unwrap().push(request);
            let mut progress = Vec::new();
            for line in &self.lines {
                if let Some(done) = terminal(line, &mut progress)? {
                    return Ok(done);
                }
            }
            Err(RunnerFailure::transport("no result"))
        }
    }

    fn canned(lines: Vec<Value>) -> Canned {
        Canned {
            lines,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn bind_parses_success_and_every_failure_shape() {
        let ok = canned(vec![json!({"ok": true, "kind": "deploy",
            "consumed_at": "c", "execution_deadline": "e"})]);
        let bound = bind_plan(&ok, &plan()).await.unwrap();
        assert_eq!(bound.kind, "deploy");
        assert_eq!(bound.consumed_at, "c");
        assert_eq!(
            ok.seen.lock().unwrap()[0],
            json!({"op": "bind_plan", "plan_id": plan().plan_id,
                   "plan_digest_hex": plan().plan_digest_hex, "action_index": 2})
        );
        let consumed = canned(vec![json!({"ok": false, "error": {
            "code": "E_PLAN_CONSUMED", "message": "m", "consumed_at": "t"}})]);
        let failure = bind_plan(&consumed, &plan()).await.unwrap_err();
        assert_eq!(failure.plan_code(), PlanCode::PlanConsumed);
        assert_eq!(failure.consumed_at.as_deref(), Some("t"));
        let trust = canned(vec![
            json!({"ok": false, "error": {"code": "trust_store_invalid", "message": "m"}}),
        ]);
        assert_eq!(
            bind_plan(&trust, &plan()).await.unwrap_err().plan_code(),
            PlanCode::TrustStoreInvalid
        );
        let unknown = canned(vec![json!({"ok": false, "error": {"code": "E_WHAT"}})]);
        assert_eq!(
            bind_plan(&unknown, &plan()).await.unwrap_err().plan_code(),
            PlanCode::Internal
        );
        let garbage = canned(vec![json!({"hello": 1})]);
        assert_eq!(
            bind_plan(&garbage, &plan()).await.unwrap_err().plan_code(),
            PlanCode::Internal
        );
    }

    #[tokio::test]
    async fn ops_send_an_empty_payload_and_read_either_response_shape() {
        let stream = canned(vec![
            json!({"kind": "progress", "stage": "pull", "safe_message": "Pulling image"}),
            json!({"kind": "progress", "stage": "start"}),
            json!({"kind": "result", "result": {"success": true, "final_state": "candidate"}}),
        ]);
        let done = run_op(&stream, "prepare_release", &plan(), Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(done.progress, vec!["Pulling image", "start"]);
        assert_eq!(
            stream.seen.lock().unwrap()[0],
            json!({"op": "prepare_release", "payload": {}, "plan": {
                "plan_id": plan().plan_id, "plan_digest_hex": plan().plan_digest_hex,
                "action_index": 2}})
        );
        let failed = canned(vec![json!({"kind": "result", "result": {
            "success": false, "final_state": "failed",
            "error": {"code": "health_failed", "safe_message": "candidate unhealthy",
                      "retryable": false}}})]);
        let failure = run_op(&failed, "verify_health", &plan(), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.code, "health_failed");
        assert_eq!(failure.message, "candidate unhealthy");
        let short = canned(vec![json!({"ok": false, "error": {"code": "E_PLAN_ARGS"}})]);
        assert_eq!(
            run_op(&short, "activate_release", &plan(), Duration::from_secs(1))
                .await
                .unwrap_err()
                .plan_code(),
            PlanCode::PlanArgs
        );
    }

    #[tokio::test]
    async fn bootstrap_trust_carries_only_the_envelope() {
        let ok = canned(vec![json!({"ok": true})]);
        bootstrap_trust(&ok, "{\"plan\":{}}").await.unwrap();
        assert_eq!(
            ok.seen.lock().unwrap()[0],
            json!({"op": "bootstrap_trust", "payload": {"signed_plan": "{\"plan\":{}}"}})
        );
    }

    #[tokio::test]
    async fn socket_runner_speaks_ndjson_per_connection() {
        let dir = crate::signed_plan::test_support::temp_dir("runner-sock");
        let path = dir.join("runner.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut line = String::new();
            BufReader::new(reader).read_line(&mut line).await.unwrap();
            writer
                .write_all(b"{\"kind\":\"progress\",\"stage\":\"x\"}\n{\"ok\":true}\n")
                .await
                .unwrap();
            line
        });
        let runner = SocketRunner { path: path.clone() };
        let done = run_op(&runner, "restart_release", &plan(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(done.progress, vec!["x"]);
        let sent: Value = serde_json::from_str(&server.await.unwrap()).unwrap();
        assert_eq!(sent["op"], "restart_release");
        assert_eq!(sent["payload"], json!({}));
        // Nobody listening: a transport failure, never a success.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            run_op(&runner, "restart_release", &plan(), Duration::from_secs(5))
                .await
                .unwrap_err()
                .plan_code(),
            PlanCode::Internal
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stdio_runner_sends_exactly_the_three_fields() {
        let dir = crate::signed_plan::test_support::temp_dir("runner-stdio");
        let script = dir.join("runner");
        let capture = dir.join("request");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n[ \"$1\" = rpc ] || exit 64\nIFS= read -r line\nprintf '%s' \"$line\" > {}\n\
                 printf '%s\\n' '{{\"ok\":true,\"kind\":\"deploy\",\"consumed_at\":\"2026-09-23T10:00:09Z\",\"execution_deadline\":\"x\"}}'\n",
                capture.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let runner = StdioRunner { program: script };
        let bound = bind_plan(&runner, &plan()).await.unwrap();
        assert_eq!(bound.consumed_at, "2026-09-23T10:00:09Z");
        let sent: Value = serde_json::from_slice(&std::fs::read(&capture).unwrap()).unwrap();
        assert_eq!(
            sent,
            json!({"op":"bind_plan","plan_id":plan().plan_id,
                   "plan_digest_hex":plan().plan_digest_hex,"action_index":2})
        );
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
