//! `ShellService.Shell` (agent-protocol.md 4 "Shell"; signed-plan.md 3.2
//! `shell.open`, 14.8 "Shell stream").
//!
//! The only interactive exec path in local mode. The first client frame
//! must be `ShellOpen` whose signed plan's only action is `shell.open`; the
//! agent admits it (owner, fresh Touch ID: section 6.1 decides), binds the
//! action and opens the runner's bound `shell_open` op, which picks the
//! container itself (or a host login shell of `permanu-shell`). Nothing in
//! the stream names a container or a command.
//!
//! Relaying: `stdin` → `shell_input` (base64), `resize` → `shell_resize`,
//! `INT`/`QUIT` → the terminal's control byte, `close_stdin` → EOT, any
//! other signal or the end of the client stream → `shell_close`. Runner
//! `stdout` lines come back as `stdout` frames of at most 32 KiB. The
//! session ends at the signed `ttl_seconds` (or the runner's
//! `session_deadline`, whichever is first) or after 15 minutes without
//! input or output; the runner's `result` line ends the action and the
//! stream closes with one `ShellExit`. Only the open and close are audited
//! (operation step logs); input and output never are.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures::Stream;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::Instant;
use tonic::{Request, Response, Status, Streaming};
use tracing::{info, warn};

use super::change::{ChangeSvc, Limit};
use super::errors::plan_status;
use super::execution::ChangeCore;
use super::runner::{BoxWrite, EventLines, PlanRef};
use super::status_with_reason;
use crate::proto::agent::v2::shell_service_server::ShellService;
use crate::proto::agent::v2::{
    shell_client_frame, shell_server_frame, ErrorReason, ShellClientFrame, ShellExit, ShellOpened,
    ShellServerFrame, TerminalSize,
};
use crate::signed_plan::text::timestamp;
use crate::signed_plan::PlanCode;

/// agent-protocol.md 4: a session ends after 15 minutes idle.
pub const IDLE: Duration = Duration::from_secs(15 * 60);
/// The largest `stdin` / `stdout` frame (shell.proto).
const MAX_FRAME: usize = 32 * 1024;
/// After `shell_close`, how long the runner has to send its `result`.
const CLOSE_GRACE: Duration = Duration::from_secs(15);
/// signed-plan.md 14.8: terminal sizes the runner accepts.
const MAX_TERMINAL: u32 = 1_000;
/// agent-protocol.md 7 (contracts v1.1.7, D-065 #9): concurrent shells
/// (service and host) per agent.
pub const MAX_SHELLS: usize = 4;

/// The agent's shell slots ([`MAX_SHELLS`]).
pub fn slots() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_SHELLS))
}

/// agent-protocol.md 7 (contracts v1.1.10, D-068 #6): the refusal of a 5th
/// concurrent shell (the agent's or the runner's `E_SHELL_LIMIT`) names its
/// limit; the engine puts it in `data.detail`.
pub const SHELL_LIMIT_MESSAGE: &str = "at most 4 concurrent shells";

fn limit_exceeded(message: &str) -> Status {
    status_with_reason(
        tonic::Code::ResourceExhausted,
        message,
        ErrorReason::LimitExceeded,
    )
}

type ShellStream = Pin<Box<dyn Stream<Item = Result<ShellServerFrame, Status>> + Send>>;

pub struct ShellSvc {
    pub core: Arc<ChangeCore>,
    /// [`IDLE`] outside tests.
    pub idle: Duration,
    /// One permit per open session ([`slots`]).
    pub slots: Arc<Semaphore>,
}

fn out(frame: shell_server_frame::Frame) -> Result<ShellServerFrame, Status> {
    Ok(ShellServerFrame { frame: Some(frame) })
}

/// The plan's actions are exactly one `shell.open` (checked before
/// admission, like `CancelOperation`); its params.
fn shell_params(envelope: &[u8]) -> Option<Value> {
    let parsed: Value = serde_json::from_slice(envelope).ok()?;
    let actions = parsed["plan"]["actions"].as_array()?;
    match actions.as_slice() {
        [action] if action["kind"] == "shell.open" => Some(action["params"].clone()),
        _ => None,
    }
}

fn resize_line(size: &TerminalSize) -> Option<Value> {
    let ok = |n: u32| (1..=MAX_TERMINAL).contains(&n);
    (ok(size.cols) && ok(size.rows))
        .then(|| json!({"op": "shell_resize", "cols": size.cols, "rows": size.rows}))
}

fn input_line(data: &[u8]) -> Value {
    json!({"op": "shell_input", "data_b64": STANDARD.encode(data)})
}

async fn send_line(writer: &mut BoxWrite, line: &Value) -> bool {
    let mut bytes = line.to_string().into_bytes();
    bytes.push(b'\n');
    writer.write_all(&bytes).await.is_ok() && writer.flush().await.is_ok()
}

#[tonic::async_trait]
impl ShellService for ShellSvc {
    type ShellStream = ShellStream;

    async fn shell(
        &self,
        request: Request<Streaming<ShellClientFrame>>,
    ) -> Result<Response<Self::ShellStream>, Status> {
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("the first frame must be ShellOpen"))?;
        let Some(shell_client_frame::Frame::Open(open)) = first.frame else {
            return Err(Status::invalid_argument(
                "the first frame must be ShellOpen",
            ));
        };
        // D-065 #9: the 5th concurrent shell is refused before admission.
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| limit_exceeded(SHELL_LIMIT_MESSAGE))?;
        let plan = open.plan.ok_or_else(|| plan_status(PlanCode::Parse))?;
        let params = shell_params(&plan.envelope_json)
            .ok_or_else(|| plan_status(PlanCode::ExecPrecondition))?;
        let change = ChangeSvc {
            core: self.core.clone(),
        };
        // D-067 #9: a host shell open (service_id null) is outside the
        // plan submission limit and has its own hourly one.
        let limit = if params["service_id"].is_null() {
            Limit::HostShell
        } else {
            Limit::Submissions
        };
        let admitted = change.admit_limited(Some(plan), limit).await?;
        if admitted.deduplicated {
            // One signed shell.open opens one session.
            return Err(plan_status(PlanCode::ExecPrecondition));
        }
        let (record, action) = self
            .core
            .bind_shell(&admitted.plan_id)
            .await
            .map_err(Status::failed_precondition)?;
        let plan_ref = PlanRef {
            plan_id: record.plan_id.clone(),
            plan_digest_hex: record.plan_digest_hex.clone(),
            action_index: action.action_index,
        };
        let request = json!({"op": "shell_open", "plan": plan_ref.json(), "payload": {}});
        let mut lines = match self.core.runner.open(request).await {
            Ok(lines) => lines,
            Err(failure) => {
                self.core.reconcile_once().await;
                return Err(Status::unavailable(format!(
                    "the runner did not open the shell: {}",
                    failure.message
                )));
            }
        };
        let ready = match lines.next().await {
            Ok(Some(line)) if line["type"] == "progress" && line["ready"] == true => line,
            Ok(Some(line)) => {
                self.core.reconcile_once().await;
                let code = line["error"]["code"].as_str().unwrap_or("E_INTERNAL");
                if code == PlanCode::ShellLimit.as_str() {
                    // A session from before an agent restart holds a slot.
                    warn!("the runner refused the shell: E_SHELL_LIMIT");
                    return Err(limit_exceeded(SHELL_LIMIT_MESSAGE));
                }
                return Err(Status::failed_precondition(format!(
                    "the runner refused the shell ({code})"
                )));
            }
            _ => {
                self.core.reconcile_once().await;
                return Err(Status::unavailable("the runner closed the shell"));
            }
        };
        let Some(mut writer) = lines.take_writer() else {
            return Err(Status::internal("runner connection has no request side"));
        };
        let now = self.core.now();
        let ttl = params["ttl_seconds"].as_i64().unwrap_or(1).clamp(1, 900);
        let deadline_at = ready["session_deadline"]
            .as_str()
            .and_then(timestamp)
            .map_or(now + ttl, |runner| runner.min(now + ttl));
        let remaining = u64::try_from(deadline_at - now).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(remaining);
        let service_id = params["service_id"].as_str().unwrap_or_default().to_owned();
        let opened = ShellOpened {
            session_id: record.operation_id.clone(),
            plan_digest_hex: record.plan_digest_hex.clone(),
            expires_at: Some(prost_types::Timestamp {
                seconds: deadline_at,
                nanos: 0,
            }),
            recorded: false,
            service_id: service_id.clone(),
            container_name: ready["container_name"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take(128)
                .collect(),
        };
        let target = if service_id.is_empty() {
            "the host".to_owned()
        } else {
            format!("service {service_id}")
        };
        self.core
            .shell_log(&record, &action, &format!("shell opened on {target}"));
        info!(plan_id = %record.plan_id, %target, "shell session opened");
        if let Some(line) = open.size.as_ref().and_then(resize_line) {
            let _ = send_line(&mut writer, &line).await;
        }
        let (tx, rx) = mpsc::channel(32);
        let _ = tx
            .send(out(shell_server_frame::Frame::Opened(opened)))
            .await;
        let core = self.core.clone();
        let idle = self.idle;
        tokio::spawn(async move {
            let _slot = slot;
            let exit = pump(lines, writer, inbound, &tx, deadline, idle).await;
            core.shell_log(&record, &action, &format!("shell closed: {}", exit.reason));
            info!(plan_id = %record.plan_id, reason = %exit.reason, "shell session closed");
            let _ = tx.send(out(shell_server_frame::Frame::Exit(exit))).await;
            core.reconcile_once().await;
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

/// Relays one session until the runner's `result` (or its loss).
async fn pump(
    mut lines: EventLines,
    mut writer: BoxWrite,
    mut inbound: Streaming<ShellClientFrame>,
    tx: &mpsc::Sender<Result<ShellServerFrame, Status>>,
    deadline: Instant,
    idle: Duration,
) -> ShellExit {
    let mut reason: Option<&'static str> = None;
    let mut client_open = true;
    let mut closing: Option<Instant> = None;
    let mut last_activity = Instant::now();
    loop {
        let idle_at = last_activity + idle;
        let close_by = closing.unwrap_or(deadline);
        tokio::select! {
            line = lines.next() => {
                match line {
                    Ok(Some(line)) if line["type"] == "result" => {
                        let ended = line["ended"].as_str().unwrap_or_default();
                        let default = if line["ok"] != true {
                            "error"
                        } else if ended == "deadline" {
                            "expired"
                        } else {
                            "exited"
                        };
                        return ShellExit {
                            reason: reason.unwrap_or(default).to_owned(),
                            ..exit_of(&line)
                        };
                    }
                    Ok(Some(line)) => {
                        let Some(data) = line["data_b64"].as_str().and_then(|d| STANDARD.decode(d).ok()) else {
                            continue;
                        };
                        last_activity = Instant::now();
                        for chunk in data.chunks(MAX_FRAME) {
                            if tx.send(out(shell_server_frame::Frame::Stdout(chunk.to_vec()))).await.is_err() {
                                // The client went away: close the session.
                                client_open = false;
                                if closing.is_none() {
                                    reason = Some("client_closed");
                                    closing = Some(Instant::now() + CLOSE_GRACE);
                                    let _ = send_line(&mut writer, &json!({"op": "shell_close"})).await;
                                }
                                break;
                            }
                        }
                    }
                    Ok(None) | Err(_) => {
                        warn!("shell session: the runner connection ended without a result");
                        return ShellExit {
                            exit_code: 0,
                            signal: String::new(),
                            reason: reason.unwrap_or("error").to_owned(),
                        };
                    }
                }
            }
            frame = inbound.message(), if client_open => {
                let line = match frame {
                    Ok(Some(ShellClientFrame { frame: Some(frame) })) => {
                        last_activity = Instant::now();
                        match frame {
                            shell_client_frame::Frame::Stdin(data) if data.len() <= MAX_FRAME => {
                                Some(input_line(&data))
                            }
                            shell_client_frame::Frame::Resize(size) => resize_line(&size),
                            shell_client_frame::Frame::Signal(signal) => match signal.as_str() {
                                "INT" => Some(input_line(b"\x03")),
                                "QUIT" => Some(input_line(b"\x1c")),
                                _ => {
                                    reason.get_or_insert("client_closed");
                                    None
                                }
                            },
                            shell_client_frame::Frame::CloseStdin(true) => Some(input_line(b"\x04")),
                            shell_client_frame::Frame::CloseStdin(false) => None,
                            // A second open or an oversize frame ends it.
                            _ => {
                                reason.get_or_insert("error");
                                None
                            }
                        }
                    }
                    Ok(Some(_)) => None,
                    Ok(None) | Err(_) => {
                        client_open = false;
                        reason.get_or_insert("client_closed");
                        None
                    }
                };
                if let Some(line) = line {
                    if !send_line(&mut writer, &line).await {
                        reason.get_or_insert("error");
                    }
                }
                if reason.is_some() && closing.is_none() {
                    closing = Some(Instant::now() + CLOSE_GRACE);
                    let _ = send_line(&mut writer, &json!({"op": "shell_close"})).await;
                }
            }
            () = tokio::time::sleep_until(close_by) => {
                if closing.is_some() {
                    // The runner never answered the close.
                    return ShellExit {
                        exit_code: 0,
                        signal: String::new(),
                        reason: reason.unwrap_or("error").to_owned(),
                    };
                }
                reason = Some("expired");
                closing = Some(Instant::now() + CLOSE_GRACE);
                let _ = send_line(&mut writer, &json!({"op": "shell_close"})).await;
            }
            () = tokio::time::sleep_until(idle_at), if closing.is_none() => {
                reason = Some("idle_timeout");
                closing = Some(Instant::now() + CLOSE_GRACE);
                let _ = send_line(&mut writer, &json!({"op": "shell_close"})).await;
            }
        }
    }
}

/// v1.0.15 (D-065 #3): the `exit_code` and `signal` of the runner's
/// `shell_open` result line; null or absent is 0 and "".
fn exit_of(line: &Value) -> ShellExit {
    ShellExit {
        exit_code: line["exit_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
            .unwrap_or_default(),
        signal: line["signal"]
            .as_str()
            .filter(|name| {
                name.len() <= 16
                    && name.starts_with("SIG")
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            })
            .unwrap_or_default()
            .to_owned(),
        reason: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_takes_the_runners_code_and_signal() {
        let exit = exit_of(&json!({"exit_code": 3, "signal": null}));
        assert_eq!((exit.exit_code, exit.signal.as_str()), (3, ""));
        let exit = exit_of(&json!({"exit_code": null, "signal": "SIGKILL"}));
        assert_eq!((exit.exit_code, exit.signal.as_str()), (0, "SIGKILL"));
        let exit = exit_of(&json!({"signal": "rm -rf"}));
        assert_eq!(exit.signal, "");
        let exit = exit_of(&json!({"exit_code": 1_u64 << 40}));
        assert_eq!(exit.exit_code, 0);
    }

    #[test]
    fn only_a_single_shell_open_plan_opens_a_shell() {
        let plan = |actions: Value| json!({"plan": {"actions": actions}}).to_string();
        let one = plan(
            json!([{"kind": "shell.open", "params": {"service_id": null, "ttl_seconds": 60}}]),
        );
        assert_eq!(
            shell_params(one.as_bytes()).unwrap()["ttl_seconds"],
            json!(60)
        );
        let two = plan(
            json!([{"kind": "shell.open", "params": {}}, {"kind": "shell.open", "params": {}}]),
        );
        assert!(shell_params(two.as_bytes()).is_none());
        let deploy = plan(json!([{"kind": "deploy", "params": {}}]));
        assert!(shell_params(deploy.as_bytes()).is_none());
        assert!(shell_params(b"not json").is_none());
    }

    #[test]
    fn terminal_sizes_outside_the_runner_bounds_are_not_sent() {
        assert_eq!(
            resize_line(&TerminalSize { cols: 80, rows: 24 }),
            Some(json!({"op": "shell_resize", "cols": 80, "rows": 24}))
        );
        assert!(resize_line(&TerminalSize { cols: 0, rows: 24 }).is_none());
        assert!(resize_line(&TerminalSize {
            cols: 80,
            rows: 1_001
        })
        .is_none());
        assert_eq!(
            input_line(b"ls\n"),
            json!({"op": "shell_input", "data_b64": "bHMK"})
        );
    }
}
