//! A contained local-mode server for tests: temp trust file, admission store,
//! public age recipient, fake host probe, a settable clock and a fake runner
//! that speaks the pinned runner wire protocol on a unix socket
//! (signed-plan.md 14.1 to 14.8): strict `{op, plan?, payload}` requests,
//! `progress` lines and exactly one `result` line; `bind_plan`, bound ops
//! with payload `{}`, `bootstrap_trust`, `update_trusted_keys`,
//! `cancel_execution` and the read-only container ops, with its own consumed
//! log.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tonic::transport::{Channel, Endpoint};
use tonic::Status;

use super::execution::{ChangeCore, ChangeCoreParts, Clock, Timing};
use super::facts::HostProbe;
use super::runner::SocketRunner;
use super::{age_recipient, events::EventBus, socket, AgentIdentity, LocalServer};
use crate::admissions::{AdmissionStore, StoreConfig};
use crate::config::AgentMode;
use crate::proto::agent::v2::{Container, ServerFacts};
use crate::signed_plan::test_support::{temp_dir, vector};
use crate::signed_plan::text::{format_timestamp, timestamp};
use crate::signed_plan::trust::{TrustChange, TrustMode, TrustPaths};
use crate::signed_plan::verify::verify_bootstrap;
use crate::signed_plan::PlanCode;

pub const VECTOR_NOW: &str = "2026-09-23T10:05:00Z";

/// `container_logs` lines of one container: (stdout, stderr).
pub type StdoutStderr = (Vec<String>, Vec<String>);

/// HMAC-SHA256 (RFC 2104) in hex, as git providers sign webhooks.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.iter().map(|b| b ^ byte).collect::<Vec<u8>>();
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    hex::encode(
        Sha256::new()
            .chain_update(pad(0x5c))
            .chain_update(inner)
            .finalize(),
    )
}

/// `(environment, PERMANU_WEBHOOK_SECRET)` of one project.
pub type EnvironmentSecrets = Vec<(String, Vec<u8>)>;

pub struct FakeProbe {
    pub host_keys: Vec<String>,
}

#[tonic::async_trait]
impl HostProbe for FakeProbe {
    async fn server_facts(&self) -> ServerFacts {
        ServerFacts {
            hostname: "fake-host".to_string(),
            arch: "arm64".to_string(),
            memory_total_bytes: 42,
            ..Default::default()
        }
    }

    async fn containers(&self, include_stopped: bool) -> Result<Vec<Container>, Status> {
        let mut all = vec![
            container("c3", "web-3", "p1", "s1", "running"),
            container("c1", "web-1", "p1", "s1", "running"),
            container("c2", "web-2", "p1", "s1", "running"),
            container("c4", "db-1", "p2", "s2", "running"),
        ];
        if include_stopped {
            all.push(container("c5", "old-1", "p1", "s1", "exited"));
        }
        Ok(all)
    }

    fn ssh_host_key_digests_hex(&self) -> Vec<String> {
        self.host_keys.clone()
    }

    fn ntp_synchronized(&self) -> bool {
        true
    }

    fn timezone(&self) -> String {
        "Etc/UTC".to_string()
    }
}

fn container(id: &str, name: &str, project: &str, service: &str, state: &str) -> Container {
    Container {
        container_id: id.to_string(),
        name: name.to_string(),
        project_id: project.to_string(),
        service_id: service.to_string(),
        environment: "production".to_string(),
        state: state.to_string(),
        ..Default::default()
    }
}

pub struct FixedClock(pub AtomicI64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// What the fake runner does for one op name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpBehavior {
    Succeed,
    /// Fails with this runner code.
    Fail(&'static str),
    /// Fails with this runner code and `error.failure_code`.
    FailCode(&'static str, &'static str),
    /// Never answers until a `cancel_execution` releases it.
    Hang,
}

/// A fake `permanu-runner serve` on a unix socket. It keeps its own consumed
/// log (section 14.5) and, like the real runner, appends a `result` line when
/// an action's final op completes (unless `write_results` is off).
pub struct FakeRunner {
    pub log: PathBuf,
    pub admissions_db: PathBuf,
    pub trust: TrustPaths,
    pub host_keys: Vec<String>,
    pub age_recipient: String,
    /// What `cancel_execution` reports for a prepared, unactivated deploy
    /// candidate it cleans up (D-044): `done` or `failed`.
    pub cancel_cleanup: Mutex<&'static str>,
    /// Every request, in arrival order.
    pub requests: Mutex<Vec<Value>>,
    pub fail_bind_with: Mutex<Option<PlanCode>>,
    pub behaviors: Mutex<HashMap<String, OpBehavior>>,
    pub write_results: AtomicBool,
    /// Permanu containers `list_containers` reports (section 14.3 shape).
    pub containers: Mutex<Vec<Value>>,
    /// `container_logs` answers per container id: (stdout, stderr).
    pub logs: Mutex<HashMap<String, StdoutStderr>>,
    /// Lines `container_logs_follow` streams before it waits for the close.
    pub follow_lines: Mutex<HashMap<String, Vec<String>>>,
    /// Drop the follow connection after its lines, without a `result` (a
    /// transient failure the agent must recover from).
    pub follow_breaks: AtomicBool,
    /// Close the `cancel_execution` connection after the consumed-log lines
    /// are written, without its wire `result` (v1.0.6, section 14.6).
    pub drop_cancel_result: AtomicBool,
    /// `PERMANU_WEBHOOK_SECRET` per project: `(environment, secret)`.
    pub webhook_secrets: Mutex<HashMap<String, EnvironmentSecrets>>,
    /// The next `build_image` answers, in order (success when empty).
    pub build_answers: Mutex<Vec<Value>>,
    /// Every session line of `shell_open` sessions, in arrival order.
    pub shell_session_lines: Mutex<Vec<Value>>,
    /// `shell_open` refuses with `E_SHELL_LIMIT` (all 4 slot locks taken,
    /// signed-plan.md 14.8, v1.0.15).
    pub shell_limit: AtomicBool,
    /// Runs inside every `build_image` (a test's side effect mid-build).
    #[allow(clippy::type_complexity)]
    pub on_build: Mutex<Option<Box<dyn Fn() + Send>>>,
    /// The image digest a successful `build_image` reports.
    pub build_image_digest: Mutex<String>,
    /// Extra fields of a bound op's successful wire `result`, per op (for
    /// example `activate_release`'s `reader_status`, v1.0.17).
    pub op_extra: Mutex<HashMap<String, Value>>,
    /// What the read-only `diagnose` op answers (section 14.3).
    pub diagnose_answer: Mutex<Value>,
    /// Actions a `cancel_execution` closed (v1.0.6, D-048).
    closed: Mutex<HashSet<(String, u32)>>,
    consumed: Mutex<HashSet<(String, u32)>>,
    ops: Mutex<HashMap<(String, u32), Vec<String>>>,
    finished: Mutex<HashSet<(String, u32)>>,
    /// Actions whose `result` line is `succeeded` (v1.0.18, D-068: the one
    /// state in which a closed `deploy` still accepts `prune_releases`).
    succeeded: Mutex<HashSet<(String, u32)>>,
    release: tokio::sync::Notify,
    seq: AtomicU64,
    clock: Arc<FixedClock>,
}

fn refuse(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message}})
}

/// Section 14.8 request check: exactly `op`, `payload` (an object) and, for
/// `bind_plan` and bound ops only, `plan`.
fn request_shape_ok(request: &Value) -> bool {
    let Some(map) = request.as_object() else {
        return false;
    };
    let unbound = matches!(
        request["op"].as_str(),
        Some(
            "bootstrap_trust"
                | "list_containers"
                | "inspect_container"
                | "container_logs"
                | "container_logs_follow"
                | "webhook_verify"
                | "build_image"
                | "diagnose"
        )
    );
    map.keys()
        .all(|key| matches!(key.as_str(), "op" | "plan" | "payload"))
        && request["op"].is_string()
        && request["payload"].is_object()
        && (unbound != map.contains_key("plan"))
}

impl FakeRunner {
    /// `(plan_id, plan_digest_hex, action_index)` of every `bind_plan`.
    pub fn binds(&self) -> Vec<(String, String, u32)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["op"] == "bind_plan")
            .map(|r| {
                (
                    r["plan"]["plan_id"].as_str().unwrap().to_owned(),
                    r["plan"]["plan_digest_hex"].as_str().unwrap().to_owned(),
                    r["plan"]["action_index"].as_u64().unwrap() as u32,
                )
            })
            .collect()
    }

    /// `(op, action_index)` of every bound op for one plan.
    /// The action indexes of `plan_id` the runner bound (`bind_plan`).
    pub fn consumed_for(&self, plan_id: &str) -> Vec<u32> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["plan"]["plan_id"] == plan_id && r["op"] == "bind_plan")
            .map(|r| r["plan"]["action_index"].as_u64().unwrap() as u32)
            .collect()
    }

    pub fn ops_for(&self, plan_id: &str) -> Vec<(String, u32)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["plan"]["plan_id"] == plan_id && r["op"] != "bind_plan")
            .map(|r| {
                (
                    r["op"].as_str().unwrap().to_owned(),
                    r["plan"]["action_index"].as_u64().unwrap() as u32,
                )
            })
            .collect()
    }

    pub fn behave(&self, op: &str, behavior: OpBehavior) {
        self.behaviors
            .lock()
            .unwrap()
            .insert(op.to_owned(), behavior);
    }

    fn append(&self, event: &str, plan_id: &str, digest: &str, index: u32, extra: Value) {
        use std::io::Write;
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let mut line = json!({
            "v": 1, "seq": seq, "at": format_timestamp(self.clock.now()), "event": event,
            "plan_id": plan_id, "plan_digest_hex": digest, "action_index": index,
        });
        if let Value::Object(fields) = extra {
            for (name, value) in fields {
                line[name] = value;
            }
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        writeln!(file, "{line}").unwrap();
        fs::set_permissions(&self.log, fs::Permissions::from_mode(0o640)).unwrap();
    }

    /// The runner finishing an action (its `result` line), once.
    pub fn result(&self, plan_id: &str, digest: &str, index: u32, outcome: &str) {
        self.result_with(plan_id, digest, index, json!({"outcome": outcome}));
    }

    /// A `result` line with extra fields; false when the action had one.
    fn result_with(&self, plan_id: &str, digest: &str, index: u32, fields: Value) -> bool {
        let first = self
            .finished
            .lock()
            .unwrap()
            .insert((plan_id.to_owned(), index));
        if first {
            if fields["outcome"] == "succeeded" {
                self.succeeded
                    .lock()
                    .unwrap()
                    .insert((plan_id.to_owned(), index));
            }
            self.append("result", plan_id, digest, index, fields);
        }
        first
    }

    /// `cancel_execution` (sections 14.3, 14.6, v1.0.5 D-044, v1.0.6
    /// D-048): first closes every unfinished action of the target (a
    /// `cancel_execution` op line under it; not one whose `activate_release`
    /// started), then per closed action cleans up a deploy's prepared,
    /// unactivated candidate and writes its one `cancelled` result; returns
    /// the wire `cancelled` list.
    fn cancel_target(&self, target: &str) -> Vec<Value> {
        let Some((digest, plan, count)) = self.admitted(target) else {
            return Vec::new();
        };
        let ops_of = |index: u32| {
            self.ops
                .lock()
                .unwrap()
                .get(&(target.to_owned(), index))
                .cloned()
                .unwrap_or_default()
        };
        let mut closing = Vec::new();
        for index in 0..count as u32 {
            let key = (target.to_owned(), index);
            if self.finished.lock().unwrap().contains(&key)
                || ops_of(index).iter().any(|o| o == "activate_release")
            {
                continue;
            }
            self.append(
                "op",
                target,
                &digest,
                index,
                json!({"op": "cancel_execution"}),
            );
            self.closed.lock().unwrap().insert(key);
            closing.push(index);
        }
        let mut cancelled = Vec::new();
        for index in closing {
            let action = &plan["actions"][index as usize];
            let ops = ops_of(index);
            let prepared = ops.iter().any(|o| o == "prepare_release");
            let cleanup = if action["kind"] == "deploy" && prepared {
                self.append(
                    "op",
                    target,
                    &digest,
                    index,
                    json!({"op": "cleanup_candidate"}),
                );
                *self.cancel_cleanup.lock().unwrap()
            } else {
                "none"
            };
            if self.result_with(
                target,
                &digest,
                index,
                json!({"outcome": "cancelled", "cleanup": cleanup}),
            ) {
                cancelled.push(json!({"action_index": index,
                    "deployment_id": action["params"]["deployment_id"], "cleanup": cleanup}));
            }
        }
        cancelled
    }

    /// Reads the admitted plan, as the real runner does (read-only).
    fn admitted(&self, plan_id: &str) -> Option<(String, Value, usize)> {
        let conn = rusqlite::Connection::open_with_flags(
            &self.admissions_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()?;
        let (digest, text): (String, String) = conn
            .query_row(
                "SELECT plan_digest_hex, signed_plan_json FROM admissions WHERE plan_id = ?1",
                [plan_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok()?;
        let envelope: Value = serde_json::from_str(&text).ok()?;
        let count = envelope["plan"]["actions"].as_array()?.len();
        Some((digest, envelope["plan"].clone(), count))
    }

    async fn handle(&self, request: Value) -> Value {
        self.requests.lock().unwrap().push(request.clone());
        if !request_shape_ok(&request) {
            return refuse("E_PARSE", "request is not {op, plan?, payload}");
        }
        match request["op"].as_str().unwrap_or_default() {
            "bind_plan" => self.bind(&request),
            "bootstrap_trust" => self.bootstrap(&request),
            "list_containers" => self.list(&request["payload"]),
            "inspect_container" => self.inspect(&request["payload"]),
            "container_logs" => self.container_logs(&request["payload"]),
            "webhook_verify" => self.webhook_verify(&request["payload"]),
            "build_image" => self.build_image(&request["payload"]),
            "diagnose" => self.diagnose_answer.lock().unwrap().clone(),
            op => self.bound_op(op, &request).await,
        }
    }

    fn known_container(&self, payload: &Value) -> Option<Value> {
        let id = payload["container_id"].as_str()?;
        self.containers
            .lock()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id || c["name"] == id)
            .cloned()
    }

    fn list(&self, payload: &Value) -> Value {
        let matches = |c: &Value| {
            ["project_id", "environment_id", "service_id"]
                .iter()
                .all(|field| payload.get(*field).is_none_or(|want| c[*field] == *want))
        };
        let containers: Vec<Value> = self
            .containers
            .lock()
            .unwrap()
            .iter()
            .filter(|c| matches(c))
            .cloned()
            .collect();
        json!({"ok": true, "containers": containers})
    }

    fn inspect(&self, payload: &Value) -> Value {
        match self.known_container(payload) {
            Some(c) => json!({"ok": true, "container": {
                "id": c["id"], "name": c["name"], "image": c["image"],
                "created_at": c["created_at"], "restart_count": 1,
                "state": {"status": c["state"], "running": c["state"] == "running",
                          "restarting": false, "exit_code": 0,
                          "started_at": "2026-09-23T10:00:00Z", "finished_at": null,
                          "health": "healthy"},
                "labels": {}, "networks": [], "mounts": []}}),
            None => refuse("not_found", "no such Permanu container"),
        }
    }

    fn container_logs(&self, payload: &Value) -> Value {
        let Some(c) = self.known_container(payload) else {
            return refuse("not_found", "no such Permanu container");
        };
        let tail = payload["tail"].as_u64().unwrap_or(0) as usize;
        if !(1..=10_000).contains(&tail) {
            return refuse("invalid_request", "tail out of range");
        }
        let id = c["id"].as_str().unwrap_or_default();
        let (stdout, stderr) = self
            .logs
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default();
        let last = |lines: Vec<String>| lines[lines.len().saturating_sub(tail)..].to_vec();
        json!({"ok": true, "stdout": last(stdout), "stderr": last(stderr)})
    }

    /// A consumed-log line that names no action (v1.0.7+ events).
    fn append_other(&self, event: &str, fields: Value) {
        use std::io::Write;
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let mut line = json!({"v": 1, "seq": seq, "at": format_timestamp(self.clock.now()),
                              "event": event});
        if let Value::Object(fields) = fields {
            for (name, value) in fields {
                line[name] = value;
            }
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        writeln!(file, "{line}").unwrap();
        fs::set_permissions(&self.log, fs::Permissions::from_mode(0o640)).unwrap();
    }

    /// `webhook_verify` (signed-plan.md 14.3): GitHub/Gitea HMAC-SHA256 or
    /// the GitLab token against each environment's secret; a verified push
    /// gets a `delivery` line.
    fn webhook_verify(&self, payload: &Value) -> Value {
        use base64::Engine as _;
        use sha2::Digest as _;
        let keys: Vec<&str> = payload
            .as_object()
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        if keys != ["body_b64", "project_id", "provider", "signature"] {
            return refuse("invalid_request", "payload keys");
        }
        let project = payload["project_id"].as_str().unwrap_or_default();
        let provider = payload["provider"].as_str().unwrap_or_default();
        let signature = payload["signature"].as_str().unwrap_or_default();
        let Ok(body) = base64::engine::general_purpose::STANDARD
            .decode(payload["body_b64"].as_str().unwrap_or_default())
        else {
            return refuse("invalid_request", "body");
        };
        let secrets = self
            .webhook_secrets
            .lock()
            .unwrap()
            .get(project)
            .cloned()
            .unwrap_or_default();
        if secrets.is_empty() {
            return refuse("not_found", "no webhook secret");
        }
        let digest = hex::encode(sha2::Sha256::digest(&body));
        let mut matched: Vec<String> = secrets
            .iter()
            .filter(|(_, secret)| match provider {
                "gitlab" => signature.as_bytes() == secret.as_slice(),
                "github" => signature
                    .strip_prefix("sha256=")
                    .is_some_and(|mac| mac == hmac_sha256_hex(secret, &body)),
                _ => signature == hmac_sha256_hex(secret, &body),
            })
            .map(|(env, _)| env.clone())
            .collect();
        matched.sort();
        if matched.is_empty() {
            return json!({"ok": true, "verified": false, "environments": [], "event": null,
                          "body_digest_hex": digest});
        }
        let Ok(push) = serde_json::from_slice::<Value>(&body) else {
            return refuse("invalid_request", "body is not JSON");
        };
        if push["after"].is_null() {
            return json!({"ok": true, "verified": true, "environments": matched,
                          "event": "ping", "body_digest_hex": digest});
        }
        let repo = push["repository"]["html_url"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches("https://")
            .to_lowercase();
        let fields = json!({"repo": repo, "ref": push["ref"], "commit_sha": push["after"],
                            "commit_time": push["head_commit"]["timestamp"]});
        let mut line = fields.clone();
        line["body_digest_hex"] = json!(digest);
        line["project_id"] = json!(project);
        line["provider"] = json!(provider);
        line["environments"] = json!(matched);
        self.append_other("delivery", line);
        let mut result = json!({"ok": true, "verified": true, "environments": matched,
                                "event": "push", "body_digest_hex": digest});
        for (name, value) in fields.as_object().unwrap() {
            result[name] = value.clone();
        }
        result
    }

    /// `build_image` (signed-plan.md 14.10) with its pinned payload.
    fn build_image(&self, payload: &Value) -> Value {
        let keys: Vec<&str> = payload
            .as_object()
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        if keys
            != [
                "body_digest_hex",
                "commit_sha",
                "delivery_id",
                "rule_digest_hex",
                "rule_id",
                "service_id",
            ]
        {
            return refuse("E_PARSE", "build_image payload");
        }
        if let Some(hook) = self.on_build.lock().unwrap().as_ref() {
            hook();
        }
        let queued = {
            let mut answers = self.build_answers.lock().unwrap();
            (!answers.is_empty()).then(|| answers.remove(0))
        };
        if let Some(answer) = queued {
            return answer;
        }
        let build_id =
            crate::admissions::new_uuid7(u64::try_from(self.clock.now()).unwrap_or(0) * 1_000);
        let image = self.build_image_digest.lock().unwrap().clone();
        let mut line = payload.clone();
        line["build_id"] = json!(build_id);
        self.append_other("build_started", line.clone());
        line["image_digest_hex"] = json!(image);
        line["outcome"] = json!("succeeded");
        self.append_other("build", line);
        json!({"ok": true, "build_id": build_id, "image_digest_hex": image,
               "progress": ["#1 building"]})
    }

    fn bind(&self, request: &Value) -> Value {
        if let Some(code) = *self.fail_bind_with.lock().unwrap() {
            return refuse(code.as_str(), "refused");
        }
        if request["payload"] != json!({}) {
            return refuse("E_PARSE", "bind_plan payload must be {}");
        }
        let plan_id = request["plan"]["plan_id"].as_str().unwrap_or_default();
        let digest = request["plan"]["plan_digest_hex"]
            .as_str()
            .unwrap_or_default();
        let index = request["plan"]["action_index"].as_u64().unwrap_or_default() as u32;
        if self
            .closed
            .lock()
            .unwrap()
            .contains(&(plan_id.to_owned(), index))
        {
            return refuse("E_PLAN_CONSUMED", "closed by cancel_execution");
        }
        if !self
            .consumed
            .lock()
            .unwrap()
            .insert((plan_id.to_owned(), index))
        {
            return refuse("E_PLAN_CONSUMED", "already consumed");
        }
        self.append("consumed", plan_id, digest, index, json!({}));
        json!({"ok": true, "plan_id": plan_id, "plan_digest_hex": digest, "action_index": index,
               "kind": "", "consumed_at": format_timestamp(self.clock.now()),
               "execution_deadline": ""})
    }

    fn bootstrap(&self, request: &Value) -> Value {
        let text = request["payload"]["signed_plan"]
            .as_str()
            .unwrap_or_default();
        match verify_bootstrap(
            text.as_bytes(),
            &self.host_keys,
            &self.age_recipient,
            self.clock.now(),
        ) {
            Ok(plan) => match self.trust.write_change(&TrustChange::Bootstrap {
                server_id: &plan.server_id,
                owner_key: &plan.owner_key,
            }) {
                Ok(_) => json!({"ok": true}),
                Err(_) => refuse("E_INTERNAL", "trust write failed"),
            },
            Err(code) => refuse(code.as_str(), "bootstrap refused"),
        }
    }

    async fn bound_op(&self, op: &str, request: &Value) -> Value {
        let plan_id = request["plan"]["plan_id"].as_str().unwrap_or_default();
        let digest = request["plan"]["plan_digest_hex"]
            .as_str()
            .unwrap_or_default();
        let index = request["plan"]["action_index"].as_u64().unwrap_or_default() as u32;
        if request["payload"] != json!({}) {
            return refuse("E_PLAN_ARGS", "payload must be {}");
        }
        let key = (plan_id.to_owned(), index);
        if !self.consumed.lock().unwrap().contains(&key) {
            return refuse("E_PLAN_NOT_ADMITTED", "not bound");
        }
        if self.closed.lock().unwrap().contains(&key) {
            return refuse("E_PLAN_CONSUMED", "closed by cancel_execution");
        }
        // v1.0.18 (D-068): `prune_releases` is the one op a closed action
        // accepts, and only after a `succeeded` result.
        let prune_after_success =
            op == "prune_releases" && self.succeeded.lock().unwrap().contains(&key);
        if self.finished.lock().unwrap().contains(&key) && !prune_after_success {
            return refuse("E_PLAN_WINDOW", "action finished");
        }
        self.append("op", plan_id, digest, index, json!({"op": op}));
        let prepared = {
            let mut ops = self.ops.lock().unwrap();
            let list = ops.entry(key.clone()).or_default();
            list.push(op.to_owned());
            list.iter().any(|o| o == "prepare_release")
        };
        let behavior = self
            .behaviors
            .lock()
            .unwrap()
            .get(op)
            .copied()
            .unwrap_or(OpBehavior::Succeed);
        match behavior {
            OpBehavior::Hang => {
                self.release.notified().await;
                return refuse("E_PLAN_WINDOW", "stopped by cancel_execution");
            }
            OpBehavior::Fail(code) => {
                return refuse(code, &format!("{op} failed"));
            }
            OpBehavior::FailCode(code, failure_code) => {
                return json!({"ok": false, "error": {"code": code,
                    "message": format!("{op} failed"), "failure_code": failure_code}});
            }
            OpBehavior::Succeed => {}
        }
        match op {
            "update_trusted_keys" => {
                let Some((_, plan, _)) = self.admitted(plan_id) else {
                    return refuse("E_PLAN_NOT_ADMITTED", "no row");
                };
                let action = &plan["actions"][index as usize];
                let change = if action["kind"] == "key.add" {
                    TrustChange::AddKey(&action["params"]["entry"])
                } else {
                    TrustChange::Revoke(&action["params"]["revocation"])
                };
                if self.trust.write_change(&change).is_err() {
                    return refuse("E_EXEC_PRECONDITION", "trust write refused");
                }
            }
            // v1.0.9 (D-058): nothing interruptible runs in these tests.
            "cancel_running" => return json!({"ok": true, "stopped": []}),
            "cancel_execution" => {
                let Some((_, plan, _)) = self.admitted(plan_id) else {
                    return refuse("E_PLAN_NOT_ADMITTED", "no row");
                };
                let target = plan["actions"][index as usize]["params"]["plan_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let cancelled = self.cancel_target(&target);
                self.release.notify_waiters();
                if self.write_results.load(Ordering::SeqCst) {
                    self.result(plan_id, digest, index, "succeeded");
                }
                return json!({"ok": true, "cancelled": cancelled});
            }
            _ => {}
        }
        if self.write_results.load(Ordering::SeqCst) {
            let outcome = match op {
                "activate_release"
                | "restart_release"
                | "update_trusted_keys"
                | "install_artifact"
                | "set_webhook_route"
                | "cancel_execution" => Some("succeeded"),
                "rollback_release" if prepared => Some("rolled_back"),
                "rollback_release" => Some("succeeded"),
                "cleanup_candidate" => Some("failed"),
                _ => None,
            };
            if let Some(outcome) = outcome {
                self.result(plan_id, digest, index, outcome);
            }
        }
        let mut answer = json!({"ok": true});
        if let Some(Value::Object(extra)) = self.op_extra.lock().unwrap().get(op) {
            for (key, value) in extra {
                answer[key] = value.clone();
            }
        }
        answer
    }

    pub fn shell_lines(&self) -> Vec<Value> {
        self.shell_session_lines.lock().unwrap().clone()
    }

    /// `shell_open` (signed-plan.md 14.8 "Shell stream") with an echo
    /// session: every `shell_input` comes back as `stdout`; `shell_close` or
    /// the connection's end closes it with the action's `result`.
    async fn shell_session(
        &self,
        request: &Value,
        lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
    ) {
        use base64::Engine as _;
        self.requests.lock().unwrap().push(request.clone());
        let plan_id = request["plan"]["plan_id"].as_str().unwrap_or_default();
        let digest = request["plan"]["plan_digest_hex"]
            .as_str()
            .unwrap_or_default();
        let index = request["plan"]["action_index"].as_u64().unwrap_or_default() as u32;
        let key = (plan_id.to_owned(), index);
        let at = format_timestamp(self.clock.now());
        if !self.consumed.lock().unwrap().contains(&key) {
            let out = json!({"type": "result", "op": "shell_open", "ok": false,
                "error": {"code": "E_PLAN_NOT_ADMITTED", "message": "not bound"}});
            let _ = writer.write_all(format!("{out}\n").as_bytes()).await;
            return;
        }
        self.append("op", plan_id, digest, index, json!({"op": "shell_open"}));
        if self.shell_limit.load(Ordering::SeqCst) {
            self.result_with(plan_id, digest, index, json!({"outcome": "failed"}));
            let out = json!({"type": "result", "op": "shell_open", "ok": false,
                "plan_id": plan_id, "plan_digest_hex": digest, "action_index": index,
                "outcome": "failed", "exit_code": null, "signal": null,
                "error": {"code": "E_SHELL_LIMIT", "message": "4 shells are open"}});
            let _ = writer.write_all(format!("{out}\n").as_bytes()).await;
            return;
        }
        let ttl = self
            .admitted(plan_id)
            .and_then(|(_, plan, _)| {
                plan["actions"][index as usize]["params"]["ttl_seconds"].as_i64()
            })
            .unwrap_or(1);
        let ready = json!({"type": "progress", "op": "shell_open", "at": at, "ready": true,
            "session_deadline": format_timestamp(self.clock.now() + ttl)});
        if writer
            .write_all(format!("{ready}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
        let mut ended = "connection";
        // v1.0.15 (D-065 #3): the result carries `exit_code` and `signal`.
        let mut exit_code = Value::Null;
        let mut signal = Value::Null;
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                ended = "invalid_request";
                break;
            };
            self.shell_session_lines.lock().unwrap().push(value.clone());
            match value["op"].as_str() {
                Some("shell_input") => {
                    let data = value["data_b64"].as_str().unwrap_or_default();
                    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(data) else {
                        ended = "invalid_request";
                        break;
                    };
                    // `exit <n>` ends the echo shell by itself with status n.
                    if let Some(code) = std::str::from_utf8(&decoded)
                        .ok()
                        .and_then(|text| text.trim().strip_prefix("exit "))
                        .and_then(|n| n.parse::<i64>().ok())
                    {
                        ended = "exited";
                        exit_code = json!(code);
                        break;
                    }
                    let out = json!({"type": "progress", "op": "shell_open", "at": at,
                        "stream": "stdout", "data_b64": data});
                    if writer
                        .write_all(format!("{out}\n").as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Some("shell_resize") => {}
                Some("shell_close") => {
                    ended = "closed";
                    signal = json!("SIGHUP");
                    break;
                }
                _ => {
                    ended = "invalid_request";
                    break;
                }
            }
        }
        let success = ended != "invalid_request";
        let outcome = if success { "succeeded" } else { "failed" };
        self.result_with(plan_id, digest, index, json!({"outcome": outcome}));
        let mut out = json!({"type": "result", "op": "shell_open", "ok": success,
            "plan_id": plan_id, "plan_digest_hex": digest, "action_index": index,
            "outcome": outcome, "ended": ended, "exit_code": exit_code, "signal": signal});
        if !success {
            out["error"] = json!({"code": "E_SHELL_PROTOCOL", "message": "only shell lines"});
        }
        let _ = writer.write_all(format!("{out}\n").as_bytes()).await;
    }

    /// Serves one connection like `permanu-runner serve`: one request line
    /// at a time, answered with `progress` lines and exactly one `result`
    /// line (section 14.8); a request that is not JSON gets one `E_PARSE`
    /// result and the connection closes.
    async fn serve_connection(self: Arc<Self>, stream: UnixStream) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let at = format_timestamp(self.clock.now());
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(request) = serde_json::from_str::<Value>(&line) else {
                let _ = writer
                    .write_all(b"{\"type\":\"result\",\"ok\":false,\"error\":{\"code\":\"E_PARSE\",\"message\":\"not JSON\"}}\n")
                    .await;
                return;
            };
            let op = request["op"].as_str().unwrap_or_default().to_owned();
            if op == "shell_open" && request_shape_ok(&request) {
                self.shell_session(&request, &mut lines, &mut writer).await;
                return;
            }
            if op == "container_logs_follow" && request_shape_ok(&request) {
                self.requests.lock().unwrap().push(request.clone());
                let id = request["payload"]["container_id"]
                    .as_str()
                    .unwrap_or_default();
                let follow = self.follow_lines.lock().unwrap().get(id).cloned();
                let Some(follow) = follow else {
                    let out = json!({"type": "result", "op": op, "ok": false,
                        "error": {"code": "not_found", "message": "no such container"}});
                    let _ = writer.write_all(format!("{out}\n").as_bytes()).await;
                    continue;
                };
                for line in follow {
                    let out = json!({"type": "progress", "op": op, "at": at,
                                     "stream": "stdout", "line": line});
                    if writer
                        .write_all(format!("{out}\n").as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                if self.follow_breaks.load(Ordering::SeqCst) {
                    return;
                }
                // Streams until the agent closes the connection.
                let _ = lines.next_line().await;
                return;
            }
            let response = self.handle(request).await;
            if op == "cancel_execution" && self.drop_cancel_result.load(Ordering::SeqCst) {
                return;
            }
            if response["ok"] == true && !op.is_empty() {
                let progress = json!({"type": "progress", "op": op, "at": at,
                                      "message": "working"});
                let _ = writer.write_all(format!("{progress}\n").as_bytes()).await;
            }
            let mut result = response;
            result["type"] = json!("result");
            if !op.is_empty() {
                result["op"] = json!(op);
            }
            let mut out = serde_json::to_vec(&result).unwrap();
            out.push(b'\n');
            if writer.write_all(&out).await.is_err() {
                return;
            }
        }
    }
}

pub struct Options {
    pub trust: Option<String>,
    pub host_keys: Vec<String>,
    /// Whether the store is created as after a store loss (quarantine).
    pub store_lost: bool,
    pub start_timeout: Duration,
    /// The age recipient bootstrap compares with; `None` = the bootstrap
    /// vectors' own (`policy-cases.json` `bootstrap_cases[].age_recipient`,
    /// D-045).
    pub age_recipient: Option<String>,
    /// Open a telemetry store under the test dir (`telemetry.v1`).
    pub telemetry: bool,
    /// Serve the schedulers (`cron.v1`, `backups.v1`, `alerts.v1`).
    pub schedulers: bool,
    /// Serve the webhook path (`webhooks.v1`) with a short finish poll.
    pub webhooks: bool,
    /// Serve artifact staging (`artifacts.v1`) under the test dir, trusting
    /// the TEST release keys.
    pub artifacts: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            trust: None,
            host_keys: vec!["ab".repeat(32)],
            store_lost: false,
            start_timeout: Duration::from_secs(300),
            age_recipient: None,
            telemetry: false,
            schedulers: false,
            webhooks: false,
            artifacts: false,
        }
    }
}

pub struct Harness {
    pub dir: PathBuf,
    pub channel: Channel,
    pub core: Arc<ChangeCore>,
    pub runner: Arc<FakeRunner>,
    pub clock: Arc<FixedClock>,
    pub trust_file: PathBuf,
    pub age_recipient: String,
    pub telemetry: Option<Arc<crate::local::telemetry::Telemetry>>,
    pub presence: Arc<crate::local::presence::Presence>,
    pub hooks: Option<Arc<crate::local::hooks::Hooks>>,
    pub artifacts: Option<Arc<crate::local::artifacts::Artifacts>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    runner_task: tokio::task::JoinHandle<()>,
}

impl Harness {
    pub async fn start(name: &str, trusted_keys: Option<&str>) -> Self {
        Self::with(
            name,
            Options {
                trust: trusted_keys.map(str::to_owned),
                ..Default::default()
            },
        )
        .await
    }

    pub async fn with(name: &str, options: Options) -> Self {
        let dir = temp_dir(name);
        let trust_file = dir.join("etc/trusted-keys.json");
        fs::create_dir_all(trust_file.parent().unwrap()).unwrap();
        if let Some(raw) = &options.trust {
            fs::write(&trust_file, raw).unwrap();
            fs::set_permissions(&trust_file, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let trust = TrustPaths {
            file: trust_file.clone(),
            lock: dir.join("run/trust.lock"),
            // SAFETY: geteuid has no preconditions.
            owner_uid: unsafe { libc::geteuid() },
            mode: TrustMode::Test,
        };
        let clock = Arc::new(FixedClock(AtomicI64::new(timestamp(VECTOR_NOW).unwrap())));
        let admissions_db = dir.join("agent/admissions.db");
        let (store, _) = AdmissionStore::open(
            &StoreConfig {
                path: admissions_db.clone(),
                owner: None,
            },
            options.store_lost,
            clock.now(),
        )
        .unwrap();
        // The installer's public recipient file (D-027, D-037); no identity
        // here.
        fs::create_dir_all(dir.join("etc/age")).unwrap();
        fs::set_permissions(dir.join("etc/age"), fs::Permissions::from_mode(0o755)).unwrap();
        let recipient_file = dir.join("etc/age/recipient");
        fs::write(
            &recipient_file,
            format!("{}\n", age::x25519::Identity::generate().to_public()),
        )
        .unwrap();
        fs::set_permissions(&recipient_file, fs::Permissions::from_mode(0o644)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let age_recipient =
            age_recipient::read_recipient(&recipient_file, unsafe { libc::geteuid() }).unwrap();
        // The recipient the bootstrap check compares with (D-045). The
        // vectors sign the fingerprint of a placeholder that is not valid
        // bech32, so it cannot live in the recipient file Hello reads.
        let bootstrap_recipient = options.age_recipient.clone().unwrap_or_else(|| {
            vector("policy-cases")["bootstrap_cases"][0]["age_recipient"]
                .as_str()
                .unwrap()
                .to_owned()
        });
        fs::create_dir_all(dir.join("runner")).unwrap();
        fs::create_dir_all(dir.join("run")).unwrap();
        let runner = Arc::new(FakeRunner {
            log: dir.join("runner/consumed.log"),
            admissions_db,
            trust: trust.clone(),
            host_keys: options.host_keys.clone(),
            age_recipient: bootstrap_recipient.clone(),
            cancel_cleanup: Mutex::new("done"),
            requests: Mutex::new(Vec::new()),
            fail_bind_with: Mutex::new(None),
            behaviors: Mutex::new(HashMap::new()),
            write_results: AtomicBool::new(true),
            containers: Mutex::new(Vec::new()),
            logs: Mutex::new(HashMap::new()),
            follow_lines: Mutex::new(HashMap::new()),
            follow_breaks: AtomicBool::new(false),
            drop_cancel_result: AtomicBool::new(false),
            webhook_secrets: Mutex::new(HashMap::new()),
            build_answers: Mutex::new(Vec::new()),
            on_build: Mutex::new(None),
            shell_session_lines: Mutex::new(Vec::new()),
            shell_limit: AtomicBool::new(false),
            build_image_digest: Mutex::new("e".repeat(64)),
            op_extra: Mutex::new(HashMap::new()),
            diagnose_answer: Mutex::new(
                json!({"ok": true, "op": "diagnose", "buildkit_apparmor": "loaded", "otlp_nft": "absent"}),
            ),
            closed: Mutex::new(HashSet::new()),
            consumed: Mutex::new(HashSet::new()),
            ops: Mutex::new(HashMap::new()),
            finished: Mutex::new(HashSet::new()),
            succeeded: Mutex::new(HashSet::new()),
            release: tokio::sync::Notify::new(),
            seq: AtomicU64::new(0),
            clock: clock.clone(),
        });
        let runner_socket = dir.join("run/runner.sock");
        let listener = UnixListener::bind(&runner_socket).unwrap();
        let serving = runner.clone();
        let runner_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serving.clone().serve_connection(stream));
            }
        });
        let probe: Arc<dyn HostProbe> = Arc::new(FakeProbe {
            host_keys: options.host_keys,
        });
        let core = ChangeCore::new(ChangeCoreParts {
            store: Arc::new(store),
            trust: trust.clone(),
            probe: probe.clone(),
            runner: Arc::new(SocketRunner {
                path: runner_socket,
            }),
            events: EventBus::new(),
            clock: clock.clone(),
            consumed_log: dir.join("runner/consumed.log"),
            // SAFETY: geteuid has no preconditions.
            consumed_log_owner: unsafe { libc::geteuid() },
            age_recipient: bootstrap_recipient,
            timing: Timing {
                start_timeout: options.start_timeout,
                op_timeout: Duration::from_secs(30),
            },
        });
        let telemetry = options
            .telemetry
            .then(|| crate::local::telemetry::test_support::open(dir.join("telemetry")));
        let socket_path = dir.join("run").join("agent.sock");
        let listener = socket::bind(&socket_path, None).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let presence = crate::local::presence::Presence::new(clock.clone());
        let hooks = options.webhooks.then(|| {
            crate::local::hooks::Hooks::new(
                crate::local::hooks::HookDeps {
                    store: core.store.clone(),
                    ops: Arc::new(crate::local::sched::ops_store::OpsStore::in_memory()),
                    core: core.clone(),
                    events: core.events.clone(),
                    clock: clock.clone(),
                    logs: crate::local::sched::AgentLogs {
                        telemetry: telemetry.clone(),
                        host: "test".to_owned(),
                    },
                    presence: Some(presence.clone()),
                    alerts: None,
                },
                crate::local::hooks::HookTiming {
                    finish_poll: Duration::from_millis(20),
                    finish_wait: Duration::from_secs(20),
                    build_timeout: Duration::from_secs(20),
                },
            )
        });
        let artifacts = options.artifacts.then(|| {
            fs::create_dir_all(dir.join("staging")).unwrap();
            crate::local::artifacts::Artifacts::new(crate::local::artifacts::ArtifactDeps {
                root: dir.join("staging"),
                release_keys: dir.join("etc/release-keys.json"),
                // SAFETY: geteuid has no preconditions.
                release_keys_owner: unsafe { libc::geteuid() },
                ops: Arc::new(crate::local::sched::ops_store::OpsStore::in_memory()),
                probe: probe.clone(),
                clock: clock.clone(),
                mode: crate::local::artifacts::ReleaseMode {
                    trust_test_keys: true,
                },
            })
        });
        if let Some(artifacts) = &artifacts {
            let _ = core.staging.set(artifacts.clone());
        }
        let server = LocalServer {
            probe,
            identity: AgentIdentity {
                version: "test-1".to_string(),
                binary_digest_hex: "cd".repeat(32),
                mode: AgentMode::Local,
                started_at: SystemTime::now(),
            },
            trust,
            age_recipient: age_recipient.clone(),
            core: core.clone(),
            telemetry: telemetry.clone(),
            schedulers: options.schedulers.then(|| {
                crate::local::sched::Schedulers::new(
                    crate::local::sched::Deps {
                        store: core.store.clone(),
                        ops: Arc::new(crate::local::sched::ops_store::OpsStore::in_memory()),
                        runner: core.runner.clone(),
                        events: core.events.clone(),
                        clock: clock.clone(),
                        logs: crate::local::sched::AgentLogs {
                            telemetry: telemetry.clone(),
                            host: "test".to_owned(),
                        },
                        server_id: crate::local::sched::ServerId::Fixed(String::new()),
                        consumed_log: Some(crate::local::sched::ConsumedLogRef {
                            path: dir.join("runner/consumed.log"),
                            // SAFETY: geteuid has no preconditions.
                            owner_uid: unsafe { libc::geteuid() },
                        }),
                    },
                    age_recipient.clone(),
                    Arc::new(crate::local::sched::alerts::NoSource),
                )
            }),
            presence: presence.clone(),
            hooks: hooks.clone(),
            artifacts: artifacts.clone(),
        };
        let task = tokio::spawn(async move {
            server
                .serve(listener, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        let channel = connect(&socket_path).await;
        Self {
            dir,
            channel,
            core,
            runner,
            clock,
            trust_file,
            age_recipient,
            telemetry,
            presence,
            hooks,
            artifacts,
            shutdown: Some(tx),
            task,
            runner_task,
        }
    }

    pub async fn stop(mut self) {
        drop(self.channel);
        let _ = self.shutdown.take().unwrap().send(());
        self.task.await.unwrap();
        self.runner_task.abort();
        fs::remove_dir_all(&self.dir).unwrap();
    }
}

pub async fn connect(path: &Path) -> Channel {
    let path = path.to_path_buf();
    Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap()
}
