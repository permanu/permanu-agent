//! A scripted runner and fixtures for the scheduler tests.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use super::ops_store::OpsStore;
use super::{AgentLogs, AlertSink, BuiltinEvent, Deps};
use crate::admissions::AdmissionStore;
use crate::local::events::EventBus;
use crate::local::execution::Clock;
use crate::local::runner::{EventLines, Runner, RunnerFailure};

pub const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";
pub const ENV_ID: &str = "01a0cdb5-3500-70b2-8000-000000000001";
pub const WEB: &str = "01a0cdb5-3500-70c1-8000-000000000001";
pub const PG: &str = "01a0cdb5-3500-70d1-8000-000000000001";
pub const CRON: &str = "01a0cdb5-3500-70d2-8000-000000000001";

pub fn production() -> (&'static str, &'static str, &'static str) {
    (PROJECT, "production", ENV_ID)
}

pub fn at(text: &str) -> i64 {
    crate::signed_plan::text::timestamp(text).unwrap()
}

/// A settable clock.
#[derive(Debug)]
pub struct TestClock(pub AtomicI64);

impl TestClock {
    pub fn new(text: &str) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(at(text))))
    }

    pub fn set(&self, text: &str) {
        self.0.store(at(text), Ordering::SeqCst);
    }

    pub fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Answers per op, in order; the last answer repeats. Records every
/// request.
#[derive(Default)]
pub struct FakeRunner {
    pub requests: Mutex<Vec<Value>>,
    answers: Mutex<HashMap<String, VecDeque<Value>>>,
    /// Ops that wait for [`FakeRunner::release`] before answering.
    held: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
}

impl FakeRunner {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Queues the `result` line fields for `op` (`ok` defaults to true).
    pub fn answer(&self, op: &str, result: Value) {
        self.answers
            .lock()
            .unwrap()
            .entry(op.to_owned())
            .or_default()
            .push_back(result);
    }

    /// Replaces every queued answer of `op`.
    pub fn only(&self, op: &str, result: Value) {
        self.answers
            .lock()
            .unwrap()
            .insert(op.to_owned(), VecDeque::from([result]));
    }

    /// Makes `op` wait until released.
    pub fn hold(&self, op: &str) {
        self.held
            .lock()
            .unwrap()
            .insert(op.to_owned(), Arc::new(tokio::sync::Semaphore::new(0)));
    }

    pub fn release(&self, op: &str, n: usize) {
        if let Some(gate) = self.held.lock().unwrap().get(op) {
            gate.add_permits(n);
        }
    }

    pub fn ops(&self, op: &str) -> Vec<Value> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["op"] == op)
            .cloned()
            .collect()
    }
}

#[tonic::async_trait]
impl Runner for FakeRunner {
    async fn exchange(&self, request: Value, _: Duration) -> Result<Value, RunnerFailure> {
        let op = request["op"].as_str().unwrap_or_default().to_owned();
        self.requests.lock().unwrap().push(request);
        let gate = self.held.lock().unwrap().get(&op).cloned();
        if let Some(gate) = gate {
            gate.acquire().await.unwrap().forget();
        }
        let mut answers = self.answers.lock().unwrap();
        let queue = answers.entry(op.clone()).or_default();
        let mut result = if queue.len() > 1 {
            queue.pop_front().unwrap()
        } else {
            queue.front().cloned().unwrap_or_else(|| json!({}))
        };
        if result.get("ok").is_none() {
            result["ok"] = json!(true);
        }
        result["type"] = json!("result");
        result["op"] = json!(op);
        Ok(result)
    }

    async fn open(&self, _: Value) -> Result<EventLines, RunnerFailure> {
        Err(RunnerFailure::transport("not scripted"))
    }
}

/// Collects built-in events.
#[derive(Default)]
pub struct Sink(pub Mutex<Vec<BuiltinEvent>>);

impl AlertSink for Sink {
    fn builtin(&self, event: BuiltinEvent) {
        self.0.lock().unwrap().push(event);
    }
}

pub struct Fixture {
    pub dir: std::path::PathBuf,
    pub store: Arc<AdmissionStore>,
    pub runner: Arc<FakeRunner>,
    pub clock: Arc<TestClock>,
    pub deps: Deps,
    pub sink: Arc<Sink>,
}

impl Fixture {
    pub fn new(name: &str, now: &str) -> Self {
        let (dir, store) = crate::admissions::definitions::tests::open(name);
        let store = Arc::new(store);
        let runner = FakeRunner::new();
        let clock = TestClock::new(now);
        let deps = Deps {
            store: store.clone(),
            ops: Arc::new(OpsStore::in_memory()),
            runner: runner.clone(),
            events: EventBus::new(),
            clock: clock.clone(),
            logs: AgentLogs::default(),
            server_id: super::ServerId::Fixed("01a0cdb5-3500-70a1-8000-000000000001".to_owned()),
            consumed_log: Some(super::ConsumedLogRef {
                path: dir.join("consumed.log"),
                // SAFETY: geteuid has no preconditions.
                owner_uid: unsafe { libc::geteuid() },
            }),
        };
        Self {
            dir,
            store,
            runner,
            clock,
            deps,
            sink: Arc::new(Sink::default()),
        }
    }

    /// Records an admitted plan (`outcome` `succeeded` = in force).
    /// Admitted (and, with an outcome, applied) at the clock's now.
    pub fn record(&self, seq: i64, actions: &[Value], outcome: &str) -> String {
        crate::admissions::definitions::tests::record_at(
            &self.store,
            seq,
            production(),
            actions,
            outcome,
            &crate::signed_plan::text::format_timestamp(self.clock.now()),
        )
    }

    /// Appends one line to the runner's consumed log (mode 0640, like the
    /// runner's).
    pub fn append_consumed(&self, line: &Value) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let path = self.dir.join("consumed.log");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{line}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    /// Ends every action of `plan_id` now.
    pub fn finish(&self, plan_id: &str, outcome: &str) {
        crate::admissions::definitions::tests::finish(
            &self.store,
            plan_id,
            outcome,
            &crate::signed_plan::text::format_timestamp(self.clock.now()),
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
