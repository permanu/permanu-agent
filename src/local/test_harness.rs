//! A contained local-mode server for tests: temp trust file, admission store,
//! age identity, fake host probe, fake runner and a settable clock.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Status;

use super::execution::{ChangeCore, ChangeCoreParts, Clock};
use super::facts::HostProbe;
use super::runner::{BindFailure, Bound, Runner};
use super::{age_identity, events::EventBus, socket, AgentIdentity, LocalServer};
use crate::admissions::{AdmissionStore, StoreConfig};
use crate::config::AgentMode;
use crate::proto::agent::v2::{Container, ServerFacts};
use crate::signed_plan::test_support::temp_dir;
use crate::signed_plan::text::{format_timestamp, timestamp};
use crate::signed_plan::trust::{TrustMode, TrustPaths};
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

/// Behaves like `permanu-runner bind_plan`: appends a fsynced `consumed`
/// line to the consumed log, or fails with a configured code.
pub struct FakeRunner {
    pub log: PathBuf,
    pub calls: Mutex<Vec<(String, String, u32)>>,
    pub fail_with: Mutex<Option<PlanCode>>,
    seq: AtomicU64,
    clock: Arc<FixedClock>,
}

impl FakeRunner {
    fn append(&self, event: &str, plan_id: &str, digest: &str, index: u32, outcome: Option<&str>) {
        use std::io::Write;
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let mut line = serde_json::json!({
            "v": 1, "seq": seq, "at": format_timestamp(self.clock.now()), "event": event,
            "plan_id": plan_id, "plan_digest_hex": digest, "action_index": index,
        });
        if let Some(outcome) = outcome {
            line["outcome"] = serde_json::Value::String(outcome.to_owned());
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        writeln!(file, "{line}").unwrap();
        fs::set_permissions(&self.log, fs::Permissions::from_mode(0o640)).unwrap();
    }

    /// The runner finishing an action (its `result` line).
    pub fn result(&self, plan_id: &str, digest: &str, index: u32, outcome: &str) {
        self.append("result", plan_id, digest, index, Some(outcome));
    }
}

#[tonic::async_trait]
impl Runner for FakeRunner {
    async fn bind_plan(
        &self,
        plan_id: &str,
        plan_digest_hex: &str,
        action_index: u32,
    ) -> Result<Bound, BindFailure> {
        self.calls.lock().unwrap().push((
            plan_id.to_owned(),
            plan_digest_hex.to_owned(),
            action_index,
        ));
        if let Some(code) = *self.fail_with.lock().unwrap() {
            return Err(BindFailure {
                code,
                message: "refused".to_owned(),
                consumed_at: None,
            });
        }
        self.append("consumed", plan_id, plan_digest_hex, action_index, None);
        Ok(Bound {
            kind: String::new(),
            consumed_at: format_timestamp(self.clock.now()),
            execution_deadline: String::new(),
        })
    }
}

pub struct Options {
    pub trust: Option<String>,
    pub host_keys: Vec<String>,
    /// Whether the store is created as after a store loss (quarantine).
    pub store_lost: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            trust: None,
            host_keys: vec!["ab".repeat(32)],
            store_lost: false,
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
        let (store, _) = AdmissionStore::open(
            &StoreConfig {
                path: dir.join("agent/admissions.db"),
                owner: None,
            },
            options.store_lost,
            clock.now(),
        )
        .unwrap();
        let age_recipient =
            age_identity::load_or_generate(&dir.join("agent/age-identity"), None).unwrap();
        fs::create_dir_all(dir.join("runner")).unwrap();
        let runner = Arc::new(FakeRunner {
            log: dir.join("runner/consumed.log"),
            calls: Mutex::new(Vec::new()),
            fail_with: Mutex::new(None),
            seq: AtomicU64::new(0),
            clock: clock.clone(),
        });
        let probe: Arc<dyn HostProbe> = Arc::new(FakeProbe {
            host_keys: options.host_keys,
        });
        let core = ChangeCore::new(ChangeCoreParts {
            store: Arc::new(store),
            trust: trust.clone(),
            probe: probe.clone(),
            runner: runner.clone(),
            events: EventBus::new(),
            clock: clock.clone(),
            consumed_log: dir.join("runner/consumed.log"),
            // SAFETY: geteuid has no preconditions.
            consumed_log_owner: unsafe { libc::geteuid() },
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
        }
    }

    pub async fn stop(mut self) {
        drop(self.channel);
        let _ = self.shutdown.take().unwrap().send(());
        self.task.await.unwrap();
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
