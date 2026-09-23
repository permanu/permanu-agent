//! A contained local-mode server for tests: temp trust file, admission store,
//! public age recipient, fake host probe, a settable clock and a fake runner
//! that speaks the runner protocol on a unix socket (signed-plan.md 14.1 to
//! 14.6): `bind_plan`, bound ops with payload `{}`, `bootstrap_trust`,
//! `update_trusted_keys` and `cancel_execution`, with its own consumed log.

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
use crate::signed_plan::test_support::temp_dir;
use crate::signed_plan::text::{format_timestamp, timestamp};
use crate::signed_plan::trust::{TrustChange, TrustMode, TrustPaths};
use crate::signed_plan::verify::verify_bootstrap;
use crate::signed_plan::PlanCode;

pub const VECTOR_NOW: &str = "2026-09-23T10:05:00Z";

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
    /// Fails with this runner code (event-stream `result` shape).
    Fail(&'static str),
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
    /// Every request, in arrival order.
    pub requests: Mutex<Vec<Value>>,
    pub fail_bind_with: Mutex<Option<PlanCode>>,
    pub behaviors: Mutex<HashMap<String, OpBehavior>>,
    pub write_results: AtomicBool,
    consumed: Mutex<HashSet<(String, u32)>>,
    ops: Mutex<HashMap<(String, u32), Vec<String>>>,
    finished: Mutex<HashSet<(String, u32)>>,
    release: tokio::sync::Notify,
    seq: AtomicU64,
    clock: Arc<FixedClock>,
}

fn refuse(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message}})
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
                    r["plan_id"].as_str().unwrap().to_owned(),
                    r["plan_digest_hex"].as_str().unwrap().to_owned(),
                    r["action_index"].as_u64().unwrap() as u32,
                )
            })
            .collect()
    }

    /// `(op, action_index)` of every bound op for one plan.
    pub fn ops_for(&self, plan_id: &str) -> Vec<(String, u32)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["plan"]["plan_id"] == plan_id)
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
        if self
            .finished
            .lock()
            .unwrap()
            .insert((plan_id.to_owned(), index))
        {
            self.append(
                "result",
                plan_id,
                digest,
                index,
                json!({"outcome": outcome}),
            );
        }
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
        match request["op"].as_str().unwrap_or_default() {
            "bind_plan" => self.bind(&request),
            "bootstrap_trust" => self.bootstrap(&request),
            op => self.bound_op(op, &request).await,
        }
    }

    fn bind(&self, request: &Value) -> Value {
        if let Some(code) = *self.fail_bind_with.lock().unwrap() {
            return refuse(code.as_str(), "refused");
        }
        let plan_id = request["plan_id"].as_str().unwrap_or_default();
        let digest = request["plan_digest_hex"].as_str().unwrap_or_default();
        let index = request["action_index"].as_u64().unwrap_or_default() as u32;
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
        match verify_bootstrap(text.as_bytes(), &self.host_keys, self.clock.now()) {
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
        if self.finished.lock().unwrap().contains(&key) {
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
                return json!({"kind": "result", "result": {"success": false,
                    "final_state": "failed",
                    "error": {"code": code, "safe_message": format!("{op} failed"),
                              "retryable": false}}});
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
            "cancel_execution" => {
                let Some((_, plan, _)) = self.admitted(plan_id) else {
                    return refuse("E_PLAN_NOT_ADMITTED", "no row");
                };
                let target = plan["actions"][index as usize]["params"]["plan_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if let Some((target_digest, _, count)) = self.admitted(&target) {
                    for victim in 0..count as u32 {
                        self.result(&target, &target_digest, victim, "cancelled");
                    }
                }
                self.release.notify_waiters();
            }
            _ => {}
        }
        if self.write_results.load(Ordering::SeqCst) {
            let outcome = match op {
                "activate_release"
                | "restart_release"
                | "update_trusted_keys"
                | "install_artifact"
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
        json!({"ok": true})
    }

    /// Serves one connection: newline-delimited requests, one answer each.
    async fn serve_connection(self: Arc<Self>, stream: UnixStream) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(request) = serde_json::from_str::<Value>(&line) else {
                return;
            };
            let response = self.handle(request).await;
            if request_is_progress_worthy(&response) {
                let _ = writer
                    .write_all(b"{\"kind\":\"progress\",\"stage\":\"work\",\"safe_message\":\"working\"}\n")
                    .await;
            }
            let mut out = serde_json::to_vec(&response).unwrap();
            out.push(b'\n');
            if writer.write_all(&out).await.is_err() {
                return;
            }
        }
    }
}

fn request_is_progress_worthy(response: &Value) -> bool {
    response == &json!({"ok": true})
}

pub struct Options {
    pub trust: Option<String>,
    pub host_keys: Vec<String>,
    /// Whether the store is created as after a store loss (quarantine).
    pub store_lost: bool,
    pub start_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            trust: None,
            host_keys: vec!["ab".repeat(32)],
            store_lost: false,
            start_timeout: Duration::from_secs(300),
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
        // The installer's public recipient file (D-027); no identity here.
        let recipient_file = dir.join("agent/age-recipient");
        fs::write(
            &recipient_file,
            format!("{}\n", age::x25519::Identity::generate().to_public()),
        )
        .unwrap();
        fs::set_permissions(&recipient_file, fs::Permissions::from_mode(0o644)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let age_recipient =
            age_recipient::read_recipient(&recipient_file, unsafe { libc::geteuid() }).unwrap();
        fs::create_dir_all(dir.join("runner")).unwrap();
        fs::create_dir_all(dir.join("run")).unwrap();
        let runner = Arc::new(FakeRunner {
            log: dir.join("runner/consumed.log"),
            admissions_db,
            trust: trust.clone(),
            host_keys: options.host_keys.clone(),
            requests: Mutex::new(Vec::new()),
            fail_bind_with: Mutex::new(None),
            behaviors: Mutex::new(HashMap::new()),
            write_results: AtomicBool::new(true),
            consumed: Mutex::new(HashSet::new()),
            ops: Mutex::new(HashMap::new()),
            finished: Mutex::new(HashSet::new()),
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
            timing: Timing {
                start_timeout: options.start_timeout,
                op_timeout: Duration::from_secs(30),
            },
        });
        let socket_path = dir.join("run").join("agent.sock");
        let listener = socket::bind(&socket_path, None).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
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
