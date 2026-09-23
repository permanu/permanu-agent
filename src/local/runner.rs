//! `permanu-runner` `bind_plan` over the runner's stdio RPC (signed-plan.md
//! section 14.2): one JSON line in, one JSON line out. The request names only
//! `{plan_id, plan_digest_hex, action_index}`; the runner takes everything
//! executable from the agent's admission row (D-022).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::signed_plan::PlanCode;

pub const DEFAULT_RUNNER_PATH: &str = "/usr/local/libexec/permanu-runner";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A successful bind: the row's kind and the runner's consumption time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub kind: String,
    pub consumed_at: String,
    pub execution_deadline: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindFailure {
    /// The runner's code; `Internal` for transport failures.
    pub code: PlanCode,
    pub message: String,
    pub consumed_at: Option<String>,
}

#[tonic::async_trait]
pub trait Runner: Send + Sync {
    async fn bind_plan(
        &self,
        plan_id: &str,
        plan_digest_hex: &str,
        action_index: u32,
    ) -> Result<Bound, BindFailure>;
}

/// Runs `<program> rpc` once per bind.
#[derive(Debug, Clone)]
pub struct StdioRunner {
    pub program: PathBuf,
    pub timeout: Duration,
}

impl StdioRunner {
    pub fn new(program: PathBuf) -> Self {
        Self {
            program,
            timeout: Duration::from_secs(30),
        }
    }
}

fn transport(message: impl Into<String>) -> BindFailure {
    BindFailure {
        code: PlanCode::Internal,
        message: message.into(),
        consumed_at: None,
    }
}

/// Parses one `bind_plan` response line.
pub fn parse_bind_response(line: &[u8]) -> Result<Bound, BindFailure> {
    let value: Value =
        serde_json::from_slice(line).map_err(|_| transport("runner returned invalid JSON"))?;
    if value["ok"] == true {
        let field = |name: &str| value[name].as_str().unwrap_or_default().to_owned();
        return Ok(Bound {
            kind: field("kind"),
            consumed_at: field("consumed_at"),
            execution_deadline: field("execution_deadline"),
        });
    }
    let error = &value["error"];
    let code = error["code"]
        .as_str()
        .and_then(PlanCode::parse)
        .unwrap_or(PlanCode::Internal);
    Err(BindFailure {
        code,
        // The runner's message is fixed text; bound it anyway.
        message: error["message"]
            .as_str()
            .unwrap_or("runner refused the binding")
            .chars()
            .take(256)
            .collect(),
        consumed_at: error["consumed_at"].as_str().map(str::to_owned),
    })
}

#[tonic::async_trait]
impl Runner for StdioRunner {
    async fn bind_plan(
        &self,
        plan_id: &str,
        plan_digest_hex: &str,
        action_index: u32,
    ) -> Result<Bound, BindFailure> {
        let request = json!({
            "op": "bind_plan",
            "plan_id": plan_id,
            "plan_digest_hex": plan_digest_hex,
            "action_index": action_index,
        });
        let mut line = serde_json::to_vec(&request).map_err(|_| transport("encode"))?;
        line.push(b'\n');
        let mut child = Command::new(&self.program)
            .arg("rpc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| transport(format!("cannot start the runner: {e}")))?;
        let run = async {
            let mut stdin = child.stdin.take().ok_or_else(|| transport("no stdin"))?;
            stdin
                .write_all(&line)
                .await
                .map_err(|_| transport("write to runner failed"))?;
            drop(stdin);
            let stdout = child.stdout.take().ok_or_else(|| transport("no stdout"))?;
            let mut reader = BufReader::new(stdout.take(MAX_RESPONSE_BYTES as u64));
            let mut response = Vec::new();
            reader
                .read_until(b'\n', &mut response)
                .await
                .map_err(|_| transport("read from runner failed"))?;
            let _ = child.wait().await;
            if response.is_empty() {
                return Err(transport("runner returned nothing"));
            }
            parse_bind_response(&response)
        };
        tokio::time::timeout(self.timeout, run)
            .await
            .map_err(|_| transport("runner timed out"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn parses_success_and_every_failure_shape() {
        let ok = parse_bind_response(
            br#"{"ok":true,"plan_id":"p","plan_digest_hex":"d","action_index":0,"kind":"deploy","admitted_at":"a","execution_deadline":"e","consumed_at":"c"}"#,
        )
        .unwrap();
        assert_eq!(ok.kind, "deploy");
        assert_eq!(ok.consumed_at, "c");
        let consumed = parse_bind_response(
            br#"{"ok":false,"error":{"code":"E_PLAN_CONSUMED","message":"m","consumed_at":"t"}}"#,
        )
        .unwrap_err();
        assert_eq!(consumed.code, PlanCode::PlanConsumed);
        assert_eq!(consumed.consumed_at.as_deref(), Some("t"));
        let trust = parse_bind_response(
            br#"{"ok":false,"error":{"code":"trust_store_invalid","message":"m"}}"#,
        )
        .unwrap_err();
        assert_eq!(trust.code, PlanCode::TrustStoreInvalid);
        assert_eq!(
            parse_bind_response(br#"{"ok":false,"error":{"code":"E_WHAT"}}"#)
                .unwrap_err()
                .code,
            PlanCode::Internal
        );
        assert_eq!(
            parse_bind_response(b"garbage").unwrap_err().code,
            PlanCode::Internal
        );
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
        let runner = StdioRunner::new(script);
        let digest = "a".repeat(64);
        let bound = runner
            .bind_plan("01a0cdb5-3500-7001-8000-000000000001", &digest, 2)
            .await
            .unwrap();
        assert_eq!(bound.consumed_at, "2026-09-23T10:00:09Z");
        let sent: Value = serde_json::from_slice(&std::fs::read(&capture).unwrap()).unwrap();
        assert_eq!(
            sent,
            json!({"op":"bind_plan","plan_id":"01a0cdb5-3500-7001-8000-000000000001","plan_digest_hex":digest,"action_index":2})
        );
        let missing = StdioRunner::new(dir.join("absent"));
        assert_eq!(
            missing.bind_plan("p", "d", 0).await.unwrap_err().code,
            PlanCode::Internal
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
