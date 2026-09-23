//! Admission orchestration and agent-driven execution for local mode.
//!
//! - `submit` runs the bootstrap (section 7.3) when trusted-keys.json is
//!   absent, then the ordered verification and the single-transaction admit.
//!   The trust file itself is written by the runner (`bootstrap_trust`,
//!   D-030): the agent is not root.
//! - The executor (section 14.6, D-025) walks the admitted actions in order:
//!   `bind_plan`, then the kind's op sequence with payload `{}` on the
//!   runner socket. A deploy's start phase is bounded by the start timeout
//!   (D-033); a failed health check or timeout rolls back to the previous
//!   release, or cleans the candidate up when there is none. Kinds the agent
//!   applies itself (`server.add`, `rule.*`, `service.elevate`) are never
//!   bound; kinds this server does not implement fail `not_implemented`.
//! - Every step is an `OperationStep` with a name from the section 14.6
//!   vocabulary, streamed through `WatchOperation`, plus `DeployStatusEvent`s.
//! - Reconciliation reads the runner's consumed log (section 14.5). A runner
//!   `result` line wins over an outcome the executor recorded first.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use prost::Message;
use serde_json::Value;
use tokio::sync::broadcast;
use tracing::{info, warn};

use super::errors::reason_for;
use super::events::EventBus;
use super::facts::HostProbe;
use super::runner::{self, PlanRef, Runner, RunnerFailure};
use crate::admissions::{
    read_consumed_log, ActionRecord, Admission, AdmissionRecord, AdmissionStore, AdmitInput,
    ReconcileEffect, INPUT_KINDS,
};
use crate::proto::agent::v2::{
    deploy_status_event::Phase, event, operation_event, DeployStatusEvent, EventKind, Operation,
    OperationEvent, OperationState, OperationStep, Scope, StepLog, TrustChangedEvent,
};
use crate::signed_plan::jcs::parse_strict;
use crate::signed_plan::text::timestamp as parse_ts;
use crate::signed_plan::trust::{TrustPaths, TrustState, TrustStore};
use crate::signed_plan::verify::{verify_bootstrap, Submitter, MAX_SIGNED_PLAN_BYTES};
use crate::signed_plan::PlanCode;

/// Seconds since the Unix epoch; injectable for tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}

/// agent-protocol.md section 7: 10 submissions per minute.
const SUBMISSIONS_PER_MINUTE: usize = 10;
const MAX_SEALED_SECRETS: usize = 64;
/// D-033: a deploy's start phase fails `start` after this many seconds.
pub const DEFAULT_START_TIMEOUT_SECONDS: u64 = 300;

/// Execution time bounds.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// The start phase (`prepare_release` until healthy, `restart_release`).
    pub start_timeout: Duration,
    /// Every other op.
    pub op_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            start_timeout: Duration::from_secs(DEFAULT_START_TIMEOUT_SECONDS),
            op_timeout: Duration::from_secs(600),
        }
    }
}

/// How the executor runs one action kind (section 14.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exec {
    /// Applied by the agent; never bound.
    Agent,
    /// `bind_plan` only; the composed deploy/restart applies it.
    Input,
    /// `prepare_release` → `verify_health` → `activate_release`, with the
    /// failure path.
    Deploy,
    /// `bind_plan`, then these ops in order.
    Ops(&'static [&'static str]),
    NotImplemented,
}

fn exec_of(kind: &str, params: &Value) -> Exec {
    match kind {
        "server.add" | "rule.create" | "rule.revoke" | "service.elevate" => Exec::Agent,
        "deploy" => Exec::Deploy,
        "rollback" => Exec::Ops(&["rollback_release"]),
        "restart" => Exec::Ops(&["restart_release"]),
        "operation.cancel" => Exec::Ops(&["cancel_execution"]),
        "agent.update" => Exec::Ops(&["install_artifact"]),
        "component.update" if matches!(params["component"].as_str(), Some("dwaar" | "runner")) => {
            Exec::Ops(&["install_artifact"])
        }
        "key.add" | "key.revoke" => Exec::Ops(&["update_trusted_keys"]),
        kind if INPUT_KINDS.contains(&kind) => Exec::Input,
        _ => Exec::NotImplemented,
    }
}

/// `failure_code` of a failed op (section 14.6 table).
fn failure_code_of(kind: &str, op: &str) -> &'static str {
    match (kind, op) {
        (_, "prepare_release") => "prepare",
        (_, "verify_health") => "candidate_health",
        (_, "activate_release") => "activate",
        ("deploy", "rollback_release") => "recovery",
        (_, "restart_release" | "rollback_release") => "start",
        _ => "",
    }
}

/// `failure_code_of`, except that a start-phase op that ran out of time
/// fails `start` (D-033).
fn op_failure_code(kind: &str, op: &str, failure: &RunnerFailure) -> &'static str {
    let start_phase = matches!(op, "prepare_release" | "verify_health" | "restart_release");
    if start_phase && failure.message == runner::TIMED_OUT {
        "start"
    } else {
        failure_code_of(kind, op)
    }
}

/// The result of one action.
#[derive(Debug, Clone)]
struct Outcome {
    outcome: &'static str,
    failure_code: String,
    error: String,
}

impl Outcome {
    fn succeeded() -> Self {
        Self {
            outcome: "succeeded",
            failure_code: String::new(),
            error: String::new(),
        }
    }

    fn with(outcome: &'static str, failure_code: &str, error: impl Into<String>) -> Self {
        Self {
            outcome,
            failure_code: failure_code.to_owned(),
            error: error.into(),
        }
    }
}

/// A submission as it arrives over gRPC.
#[derive(Debug, Clone, Default)]
pub struct Submission {
    pub envelope: Vec<u8>,
    pub specs: Vec<Vec<u8>>,
    pub sealed_secrets: Vec<Vec<u8>>,
}

pub struct ChangeCore {
    pub store: Arc<AdmissionStore>,
    pub trust: TrustPaths,
    pub probe: Arc<dyn HostProbe>,
    pub runner: Arc<dyn Runner>,
    pub events: EventBus,
    pub clock: Arc<dyn Clock>,
    pub consumed_log: PathBuf,
    pub consumed_log_owner: u32,
    timing: Timing,
    operations: broadcast::Sender<OperationEvent>,
    execution: tokio::sync::Mutex<()>,
    bootstrap: tokio::sync::Mutex<()>,
    submissions: Mutex<VecDeque<Instant>>,
    /// Plans an admitted `operation.cancel` stopped (checked before every
    /// step of their executor).
    cancelled: Mutex<HashSet<String>>,
    /// Plans with an executor running (one per plan).
    running: Mutex<HashSet<String>>,
    /// (failure_code, error) the executor saw for an action, for the final
    /// step when the runner's `result` line ends it.
    failures: Mutex<HashMap<(String, u32), (String, String)>>,
}

pub struct ChangeCoreParts {
    pub store: Arc<AdmissionStore>,
    pub trust: TrustPaths,
    pub probe: Arc<dyn HostProbe>,
    pub runner: Arc<dyn Runner>,
    pub events: EventBus,
    pub clock: Arc<dyn Clock>,
    pub consumed_log: PathBuf,
    pub consumed_log_owner: u32,
    pub timing: Timing,
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, PlanCode> + Send + 'static,
) -> Result<T, PlanCode> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or(Err(PlanCode::Internal))
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

/// The runner's failure as a step error: reason, code and message.
fn describe(failure: &RunnerFailure) -> String {
    let reason = reason_for(failure.plan_code());
    format!(
        "{} ({}): {}",
        reason.as_str_name(),
        failure.code,
        failure.message
    )
}

impl ChangeCore {
    pub fn new(parts: ChangeCoreParts) -> Arc<Self> {
        Arc::new(Self {
            store: parts.store,
            trust: parts.trust,
            probe: parts.probe,
            runner: parts.runner,
            events: parts.events,
            clock: parts.clock,
            consumed_log: parts.consumed_log,
            consumed_log_owner: parts.consumed_log_owner,
            timing: parts.timing,
            operations: broadcast::channel(1_024).0,
            execution: tokio::sync::Mutex::new(()),
            bootstrap: tokio::sync::Mutex::new(()),
            submissions: Mutex::new(VecDeque::new()),
            cancelled: Mutex::new(HashSet::new()),
            running: Mutex::new(HashSet::new()),
            failures: Mutex::new(HashMap::new()),
        })
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// agent-protocol.md section 7: false once 10 submissions arrived in the
    /// last minute.
    pub fn allow_submission(&self) -> bool {
        let mut recent = locked(&self.submissions);
        let now = Instant::now();
        while recent
            .front()
            .is_some_and(|at| now.duration_since(*at) > Duration::from_secs(60))
        {
            recent.pop_front();
        }
        if recent.len() >= SUBMISSIONS_PER_MINUTE {
            return false;
        }
        recent.push_back(now);
        true
    }

    pub fn subscribe_operations(&self) -> broadcast::Receiver<OperationEvent> {
        self.operations.subscribe()
    }

    /// Loads the trust store, running the bootstrap first when the file is
    /// absent and the submission is a valid `server.add` for this host.
    async fn trust_for(&self, envelope: &[u8]) -> Result<TrustStore, PlanCode> {
        match self.trust.load() {
            TrustState::Valid(store) => return Ok(*store),
            TrustState::Invalid { .. } => return Err(PlanCode::TrustStoreInvalid),
            TrustState::Absent => {}
        }
        let _guard = self.bootstrap.lock().await;
        match self.trust.load() {
            TrustState::Valid(store) => return Ok(*store),
            TrustState::Invalid { .. } => return Err(PlanCode::TrustStoreInvalid),
            TrustState::Absent => {}
        }
        self.store.check_quarantine(self.now())?;
        // Section 7.3 step 3 including the time window (D-033): an expired
        // or foreign server.add never reaches the runner.
        let bootstrap =
            verify_bootstrap(envelope, &self.probe.ssh_host_key_digests_hex(), self.now())?;
        info!(server_id = %bootstrap.server_id, "server.add bootstrap verified; asking the runner to write trusted-keys.json");
        let text = std::str::from_utf8(envelope).map_err(|_| PlanCode::Parse)?;
        // The runner (root) re-runs the checks and writes the file (D-030).
        runner::bootstrap_trust(self.runner.as_ref(), text)
            .await
            .map_err(|failure| {
                warn!(code = %failure.code, message = %failure.message, "runner refused bootstrap_trust");
                failure.plan_code()
            })?;
        let TrustState::Valid(store) = self.trust.load() else {
            warn!("trusted-keys.json is not valid after bootstrap_trust");
            return Err(PlanCode::Internal);
        };
        info!(server_id = %store.server_id, "trusted-keys.json written by the runner's bootstrap_trust");
        self.trust_changed("server.add", &store.server_id);
        Ok(*store)
    }

    /// Verifies and admits one submission (section 6.1). New admissions are
    /// queued for execution.
    pub async fn submit(
        self: &Arc<Self>,
        submission: Submission,
        submitter: Submitter,
    ) -> Result<Admission, PlanCode> {
        let specs = spec_texts(&submission.specs)?;
        if submission.sealed_secrets.len() > MAX_SEALED_SECRETS {
            return Err(PlanCode::ExecPrecondition);
        }
        if submission.envelope.len() > MAX_SIGNED_PLAN_BYTES {
            return Err(PlanCode::Parse);
        }
        let trust = self.trust_for(&submission.envelope).await?;
        let store = self.store.clone();
        let now = self.now();
        let admission = blocking(move || {
            store.admit(
                &trust,
                &AdmitInput {
                    envelope: &submission.envelope,
                    specs: &specs,
                    sealed_secrets: &submission.sealed_secrets,
                    submitter,
                    now,
                },
            )
        })
        .await?;
        if !admission.deduplicated {
            info!(
                plan_id = %admission.plan_id,
                operation_id = %admission.operation_id,
                deployments = ?admission.deployment_ids,
                "plan admitted"
            );
            self.announce_admission(&admission.plan_id);
            let core = self.clone();
            let plan_id = admission.plan_id.clone();
            tokio::spawn(async move { core.execute(&plan_id).await });
        }
        Ok(admission)
    }

    /// Verification without admission (`VerifySignedPlan`): the plan and its
    /// digest, or the first failed check.
    pub async fn verify(
        &self,
        submission: Submission,
    ) -> Result<(Value, String, Vec<String>), PlanCode> {
        use crate::signed_plan::verify::{parse_envelope, plan_digest_hex, Verdict};
        let specs = spec_texts(&submission.specs)?;
        let trust = match self.trust.load() {
            TrustState::Valid(store) => *store,
            TrustState::Invalid { .. } => return Err(PlanCode::TrustStoreInvalid),
            TrustState::Absent => {
                let bootstrap = verify_bootstrap(
                    &submission.envelope,
                    &self.probe.ssh_host_key_digests_hex(),
                    self.now(),
                )?;
                let (plan, _) = parse_envelope(&submission.envelope)?;
                let digest = plan_digest_hex(&plan)?;
                let signer = bootstrap.owner_key["key_id"].as_str().unwrap_or_default();
                return Ok((plan, digest, vec![signer.to_owned()]));
            }
        };
        let store = self.store.clone();
        let now = self.now();
        let envelope = submission.envelope.clone();
        let verdict = blocking(move || {
            store.verify_only(
                &trust,
                &AdmitInput {
                    envelope: &submission.envelope,
                    specs: &specs,
                    sealed_secrets: &submission.sealed_secrets,
                    submitter: Submitter::Client,
                    now,
                },
            )
        })
        .await?;
        match verdict {
            Verdict::Admit(verified) => {
                let signers = verified.signer_key_ids();
                Ok((verified.plan, verified.digest_hex, signers))
            }
            Verdict::Deduped { .. } => {
                let (plan, _) = parse_envelope(&envelope)?;
                let digest = plan_digest_hex(&plan)?;
                Ok((plan, digest, Vec::new()))
            }
        }
    }

    fn trust_changed(&self, change: &str, subject: &str) {
        let (fingerprint, generation) = match self.trust.load() {
            TrustState::Valid(store) => (store.fingerprint_digest_hex(), store.generation()),
            _ => (String::new(), 0),
        };
        self.events.publish(
            EventKind::TrustChanged,
            Scope::default(),
            event::Payload::TrustChanged(TrustChangedEvent {
                fingerprint_digest_hex: fingerprint,
                generation,
                change: change.to_owned(),
                subject_id: subject.to_owned(),
            }),
        );
    }

    pub fn store_recreated(&self) {
        self.trust_changed("store_recreated", "");
    }

    // ---------------------------------------------------------------- events

    fn record(&self, operation_id: &str, payload: operation_event::Event) {
        let now = self.now();
        let mut built = None;
        let result = self.store.append_operation_event(operation_id, now, |seq| {
            let event = OperationEvent {
                operation_id: operation_id.to_owned(),
                seq,
                timestamp: Some(unix_timestamp(now)),
                event: Some(payload),
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(event.encode_to_vec());
            built = Some(event);
            encoded
        });
        match result {
            Ok(_) => {
                if let Some(event) = built {
                    let _ = self.operations.send(event);
                }
            }
            Err(err) => warn!(error = %err, "operation event not recorded"),
        }
    }

    /// The step's position in its operation: the first step with the same
    /// `(action_index, name)`, else the next one.
    fn step_index(&self, operation_id: &str, action_index: u32, name: &str) -> u32 {
        let steps = self.recorded_steps(operation_id);
        steps
            .iter()
            .position(|s| s.action_index == action_index && s.name == name)
            .unwrap_or(steps.len()) as u32
    }

    /// Appends one `OperationStep` (section 14.6 vocabulary).
    fn step(
        &self,
        record: &AdmissionRecord,
        action: Option<&ActionRecord>,
        name: &str,
        state: OperationState,
        error: &str,
        failure_code: &str,
    ) {
        let action_index = action.map_or(0, |a| a.action_index);
        let now = Some(unix_timestamp(self.now()));
        let step = OperationStep {
            index: self.step_index(&record.operation_id, action_index, name),
            name: name.to_owned(),
            action: action.map(|a| a.kind.clone()).unwrap_or_default(),
            state: state as i32,
            started_at: now,
            finished_at: matches!(
                state,
                OperationState::Succeeded
                    | OperationState::Failed
                    | OperationState::Cancelled
                    | OperationState::RolledBack
            )
            .then_some(now)
            .flatten(),
            error: error.to_owned(),
            action_index,
            deployment_id: action
                .and_then(|a| a.deployment_id.clone())
                .unwrap_or_default(),
            failure_code: failure_code.to_owned(),
        };
        self.record(&record.operation_id, operation_event::Event::Step(step));
    }

    fn log_line(&self, record: &AdmissionRecord, action: &ActionRecord, name: &str, line: &str) {
        let index = self.step_index(&record.operation_id, action.action_index, name);
        self.record(
            &record.operation_id,
            operation_event::Event::Log(StepLog {
                step_index: index,
                stream: "agent".to_owned(),
                line: line.to_owned(),
            }),
        );
    }

    fn deploy_status(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        phase: Phase,
        message: &str,
        failure_code: &str,
    ) {
        let Some(deployment_id) = action.deployment_id.clone() else {
            return;
        };
        let params = &plan["actions"][action.action_index as usize]["params"];
        let service_id = params["service_id"].as_str().unwrap_or_default().to_owned();
        self.events.publish(
            EventKind::DeployStatus,
            Scope {
                project_id: record.project_id.clone(),
                service_id: service_id.clone(),
                deployment_id: deployment_id.clone(),
                environment: record.environment.clone(),
                environment_id: record.environment_id.clone(),
                ..Default::default()
            },
            event::Payload::Deploy(DeployStatusEvent {
                deployment_id,
                project_id: record.project_id.clone(),
                service_id,
                commit_sha: params["commit_sha"].as_str().unwrap_or_default().to_owned(),
                phase: phase as i32,
                message: message.to_owned(),
                operation_id: record.operation_id.clone(),
                environment_id: record.environment_id.clone(),
                failure_code: if matches!(phase, Phase::Failed | Phase::RolledBack) {
                    failure_code.to_owned()
                } else {
                    String::new()
                },
            }),
        );
    }

    fn finished(&self, record: &AdmissionRecord) {
        let Ok(Some(fresh)) = self.store.admission(&record.plan_id) else {
            return;
        };
        let operation = self.operation(&fresh);
        self.events.publish(
            EventKind::Operation,
            Scope {
                project_id: fresh.project_id.clone(),
                environment: fresh.environment.clone(),
                environment_id: fresh.environment_id.clone(),
                ..Default::default()
            },
            event::Payload::Operation(operation.clone()),
        );
        self.record(
            &fresh.operation_id,
            operation_event::Event::Finished(operation),
        );
    }

    fn announce_admission(&self, plan_id: &str) {
        let Ok(Some(record)) = self.store.admission(plan_id) else {
            return;
        };
        let plan = plan_of(&record);
        self.step(&record, None, "admitted", OperationState::Succeeded, "", "");
        for action in self.store.actions(plan_id).unwrap_or_default() {
            self.step(
                &record,
                Some(&action),
                "queued",
                OperationState::Queued,
                "",
                "",
            );
            self.deploy_status(&record, &plan, &action, Phase::Queued, "admitted", "");
        }
    }

    /// The final step of one action and its deploy status.
    fn final_step(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        outcome: &str,
    ) {
        let (failure_code, error) = locked(&self.failures)
            .get(&(record.plan_id.clone(), action.action_index))
            .cloned()
            .unwrap_or_default();
        let (state, phase, message) = match outcome {
            "succeeded" => (OperationState::Succeeded, Phase::Live, ""),
            "rolled_back" => (OperationState::RolledBack, Phase::RolledBack, ""),
            "cancelled" => (OperationState::Cancelled, Phase::Cancelled, ""),
            "expired" => (
                OperationState::Failed,
                Phase::Failed,
                "execution window expired",
            ),
            _ => (OperationState::Failed, Phase::Failed, ""),
        };
        let message = if error.is_empty() { message } else { &error };
        let code = match outcome {
            "failed" | "rolled_back" => failure_code.as_str(),
            _ => "",
        };
        self.step(record, Some(action), outcome, state, message, code);
        self.deploy_status(record, plan, action, phase, message, code);
    }

    // ------------------------------------------------------------- execution

    fn is_cancelled(&self, plan_id: &str) -> bool {
        locked(&self.cancelled).contains(plan_id)
    }

    /// `op` lines already in the consumed log for each action of the plan
    /// (resume after a restart, section 14.6).
    async fn logged_ops(&self, record: &AdmissionRecord) -> HashMap<u32, Vec<String>> {
        let path = self.consumed_log.clone();
        let owner = self.consumed_log_owner;
        let Ok(read) = tokio::task::spawn_blocking(move || read_consumed_log(&path, owner)).await
        else {
            return HashMap::new();
        };
        let mut ops: HashMap<u32, Vec<String>> = HashMap::new();
        for line in read.lines {
            if line.event == "op"
                && line.plan_id == record.plan_id
                && line.plan_digest_hex == record.plan_digest_hex
            {
                if let Some(op) = line.op {
                    ops.entry(line.action_index).or_default().push(op);
                }
            }
        }
        ops
    }

    /// Executes the unfinished actions of one admission in order (section
    /// 14.6). Plans run one at a time, except a cancel, which must be able to
    /// stop a running plan.
    pub async fn execute(self: &Arc<Self>, plan_id: &str) {
        if !locked(&self.running).insert(plan_id.to_owned()) {
            return;
        }
        self.execute_inner(plan_id).await;
        locked(&self.running).remove(plan_id);
    }

    async fn execute_inner(self: &Arc<Self>, plan_id: &str) {
        let Ok(Some(record)) = self.store.admission(plan_id) else {
            return;
        };
        let cancel_only = record.action_kinds == ["operation.cancel"];
        let _serial = if cancel_only {
            None
        } else {
            Some(self.execution.lock().await)
        };
        let Ok(Some(record)) = self.store.admission(plan_id) else {
            return;
        };
        if record.finished_at.is_some() {
            return;
        }
        let plan = plan_of(&record);
        let done_ops = self.logged_ops(&record).await;
        let mut failed = false;
        for action in self.store.actions(plan_id).unwrap_or_default() {
            if self.is_cancelled(plan_id) {
                break;
            }
            if action.finished_at.is_some() {
                failed |= action.outcome != "succeeded";
                continue;
            }
            let window_open = crate::admissions::execution_deadline(&record.admitted_at)
                .is_some_and(|deadline| self.now() <= deadline);
            if !window_open {
                if action.consumed_at.is_none() {
                    self.complete(
                        &record,
                        &plan,
                        &action,
                        Outcome::with("expired", "", "execution window ended"),
                    )
                    .await;
                }
                continue;
            }
            if failed {
                if action.consumed_at.is_none() {
                    self.complete(
                        &record,
                        &plan,
                        &action,
                        Outcome::with("failed", "", "not run: an earlier action failed"),
                    )
                    .await;
                }
                continue;
            }
            let params = &plan["actions"][action.action_index as usize]["params"];
            let done = done_ops
                .get(&action.action_index)
                .cloned()
                .unwrap_or_default();
            let outcome = match exec_of(&action.kind, params) {
                Exec::Agent => Some(self.apply_agent_action(&action, params)),
                Exec::NotImplemented => Some(Outcome::with(
                    "failed",
                    "",
                    format!(
                        "not_implemented: {} is not executed on this server",
                        action.kind
                    ),
                )),
                Exec::Input => self.bind(&record, &action).await.err(),
                Exec::Deploy => Some(match self.bind(&record, &action).await {
                    Ok(()) => self.run_deploy(&record, &plan, &action, &done).await,
                    Err(outcome) => outcome,
                }),
                Exec::Ops(ops) => Some(match self.bind(&record, &action).await {
                    Ok(()) => self.run_ops(&record, &plan, &action, ops, &done).await,
                    Err(outcome) => outcome,
                }),
            };
            if let Some(outcome) = outcome {
                if self.is_cancelled(plan_id) {
                    break;
                }
                failed |= outcome.outcome != "succeeded";
                self.complete(&record, &plan, &action, outcome).await;
            }
        }
        // Input actions take the composed action's outcome (D-028) when the
        // runner has not written their result.
        self.reconcile_once().await;
        if self.is_cancelled(plan_id) {
            return;
        }
        let composed = if failed { "failed" } else { "succeeded" };
        for action in self.store.actions(plan_id).unwrap_or_default() {
            if action.finished_at.is_none()
                && action.consumed_at.is_some()
                && INPUT_KINDS.contains(&action.kind.as_str())
            {
                self.complete(&record, &plan, &action, Outcome::with(composed, "", ""))
                    .await;
            }
        }
    }

    /// Records an action's outcome unless the runner's `result` line already
    /// did, then emits its final step.
    async fn complete(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        outcome: Outcome,
    ) {
        locked(&self.failures).insert(
            (record.plan_id.clone(), action.action_index),
            (outcome.failure_code.clone(), outcome.error.clone()),
        );
        // The runner's result line wins (section 14.5).
        self.reconcile_once().await;
        match self.store.finish_action(
            &record.plan_id,
            action.action_index,
            outcome.outcome,
            self.now(),
        ) {
            Ok(true) => {}
            Ok(false) => return,
            Err(err) => {
                warn!(error = %err, "could not record the action outcome");
                return;
            }
        }
        self.final_step(record, plan, action, outcome.outcome);
        if let Ok(Some(fresh)) = self.store.admission(&record.plan_id) {
            if fresh.finished_at.is_some() {
                self.finished(&fresh);
            }
        }
    }

    /// `bind_plan` (section 14.2). An action already consumed (resume) or a
    /// bind whose response was lost (`E_PLAN_CONSUMED`) continues with its
    /// ops.
    async fn bind(&self, record: &AdmissionRecord, action: &ActionRecord) -> Result<(), Outcome> {
        if action.consumed_at.is_some() {
            return Ok(());
        }
        let plan_ref = plan_ref(record, action);
        match runner::bind_plan(self.runner.as_ref(), &plan_ref).await {
            Ok(bound) => {
                self.step(
                    record,
                    Some(action),
                    "bound",
                    OperationState::Succeeded,
                    "",
                    "",
                );
                self.log_line(
                    record,
                    action,
                    "bound",
                    &format!("bound to the runner at {}", bound.consumed_at),
                );
                Ok(())
            }
            Err(failure) if failure.plan_code() == PlanCode::PlanConsumed => {
                self.step(
                    record,
                    Some(action),
                    "bound",
                    OperationState::Succeeded,
                    "",
                    "",
                );
                self.log_line(record, action, "bound", "already bound to the runner");
                Ok(())
            }
            Err(failure) => {
                let message = describe(&failure);
                warn!(plan_id = %record.plan_id, action = action.action_index, %message, "runner bind failed");
                Err(Outcome::with("failed", "", message))
            }
        }
    }

    /// One bound op with its steps and deploy status.
    async fn op(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        op: &str,
        timeout: Duration,
    ) -> Result<(), RunnerFailure> {
        let auto_rollback = action.kind == "deploy";
        let phase = match op {
            "prepare_release" | "restart_release" => Some(Phase::Starting),
            "verify_health" | "activate_release" => Some(Phase::HealthChecking),
            "rollback_release" if auto_rollback => Some(Phase::RollingBack),
            "rollback_release" => Some(Phase::Starting),
            _ => None,
        };
        self.step(record, Some(action), op, OperationState::Running, "", "");
        if let Some(phase) = phase {
            self.deploy_status(record, plan, action, phase, op, "");
        }
        let result =
            runner::run_op(self.runner.as_ref(), op, &plan_ref(record, action), timeout).await;
        match &result {
            Ok(done) => {
                for line in &done.progress {
                    self.log_line(record, action, op, line);
                }
                self.step(record, Some(action), op, OperationState::Succeeded, "", "");
            }
            Err(failure) => {
                if !self.is_cancelled(&record.plan_id) {
                    self.step(
                        record,
                        Some(action),
                        op,
                        OperationState::Failed,
                        &describe(failure),
                        op_failure_code(&action.kind, op, failure),
                    );
                }
            }
        }
        result.map(|_| ())
    }

    /// A fixed op sequence (every kind but `deploy`).
    async fn run_ops(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        ops: &[&str],
        done: &[String],
    ) -> Outcome {
        let params = &plan["actions"][action.action_index as usize]["params"];
        if action.kind == "operation.cancel" {
            return self.run_cancel(record, plan, action, params, done).await;
        }
        for op in ops {
            if done.iter().any(|d| d == op) {
                continue;
            }
            let timeout = if *op == "restart_release" {
                self.timing.start_timeout
            } else {
                self.timing.op_timeout
            };
            if let Err(failure) = self.op(record, plan, action, op, timeout).await {
                return Outcome::with(
                    "failed",
                    op_failure_code(&action.kind, op, &failure),
                    describe(&failure),
                );
            }
        }
        if matches!(action.kind.as_str(), "key.add" | "key.revoke") {
            let subject = if action.kind == "key.add" {
                params["entry"]["key_id"].as_str()
            } else {
                params["revocation"]["key_id"].as_str()
            };
            self.trust_changed(&action.kind, subject.unwrap_or_default());
        }
        Outcome::succeeded()
    }

    /// `operation.cancel` (section 6.2): the named plan stops before its next
    /// step; the runner's `cancel_execution` ends its unfinished actions
    /// `cancelled`. The flag is set first so the plan's executor cannot start
    /// another step while the cancel is in flight.
    async fn run_cancel(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        params: &Value,
        done: &[String],
    ) -> Outcome {
        let target = params["plan_id"].as_str().unwrap_or_default().to_owned();
        let newly = locked(&self.cancelled).insert(target.clone());
        if !done.iter().any(|d| d == "cancel_execution") {
            if let Err(failure) = self
                .op(
                    record,
                    plan,
                    action,
                    "cancel_execution",
                    self.timing.op_timeout,
                )
                .await
            {
                if newly {
                    locked(&self.cancelled).remove(&target);
                }
                return Outcome::with("failed", "", describe(&failure));
            }
        }
        self.reconcile_once().await;
        if let Ok(Some(cancelled)) = self.store.admission(&target) {
            let cancelled_plan = plan_of(&cancelled);
            for victim in self.store.actions(&target).unwrap_or_default() {
                if victim.finished_at.is_none() {
                    self.complete(
                        &cancelled,
                        &cancelled_plan,
                        &victim,
                        Outcome::with("cancelled", "", "cancelled by an admitted operation.cancel"),
                    )
                    .await;
                }
            }
        }
        info!(canceller = %record.plan_id, target = %target, "operation cancelled");
        Outcome::succeeded()
    }

    /// `deploy`: the start phase (`prepare_release`, `verify_health`) within
    /// the start timeout, then `activate_release`; on failure
    /// `rollback_release` when the service has an earlier release, else
    /// `cleanup_candidate` (section 14.6).
    async fn run_deploy(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        done: &[String],
    ) -> Outcome {
        let ran = |op: &str| done.iter().any(|d| d == op);
        if ran("rollback_release") || ran("cleanup_candidate") {
            // The failure path already ran before a restart; its result line
            // (or the window) ends the action.
            return Outcome::with("failed", "", "failure path already ran");
        }
        let current = Mutex::new("prepare_release");
        let start = async {
            for op in ["prepare_release", "verify_health"] {
                if ran(op) {
                    continue;
                }
                *locked(&current) = op;
                if let Err(failure) = self
                    .op(record, plan, action, op, self.timing.start_timeout)
                    .await
                {
                    return Err((op_failure_code("deploy", op, &failure), describe(&failure)));
                }
                if self.is_cancelled(&record.plan_id) {
                    return Ok(());
                }
            }
            Ok(())
        };
        let failure = match tokio::time::timeout(self.timing.start_timeout, start).await {
            Ok(Ok(())) => None,
            Ok(Err(failure)) => Some(failure),
            Err(_) => {
                let op = *locked(&current);
                let message = format!(
                    "start phase exceeded start_timeout_seconds = {}",
                    self.timing.start_timeout.as_secs()
                );
                self.step(
                    record,
                    Some(action),
                    op,
                    OperationState::Failed,
                    &message,
                    "start",
                );
                Some(("start", message))
            }
        };
        if self.is_cancelled(&record.plan_id) {
            return Outcome::with("cancelled", "", "");
        }
        let (code, message) = match failure {
            Some(failure) => failure,
            None if ran("activate_release") => return Outcome::succeeded(),
            None => match self
                .op(
                    record,
                    plan,
                    action,
                    "activate_release",
                    self.timing.op_timeout,
                )
                .await
            {
                Ok(()) => return Outcome::succeeded(),
                Err(failure) => ("activate", describe(&failure)),
            },
        };
        if self.is_cancelled(&record.plan_id) {
            return Outcome::with("cancelled", "", "");
        }
        let service_id = plan["actions"][action.action_index as usize]["params"]["service_id"]
            .as_str()
            .unwrap_or_default();
        let previous = self
            .store
            .has_previous_release(record, service_id)
            .unwrap_or(false);
        if previous {
            match self
                .op(
                    record,
                    plan,
                    action,
                    "rollback_release",
                    self.timing.op_timeout,
                )
                .await
            {
                Ok(()) => Outcome::with("rolled_back", code, message),
                Err(failure) => Outcome::with("failed", "recovery", describe(&failure)),
            }
        } else {
            if let Err(failure) = self
                .op(
                    record,
                    plan,
                    action,
                    "cleanup_candidate",
                    self.timing.op_timeout,
                )
                .await
            {
                warn!(plan_id = %record.plan_id, error = %describe(&failure), "cleanup_candidate failed");
            }
            Outcome::with("failed", code, message)
        }
    }

    /// Kinds the agent applies itself (section 14.6): the admission
    /// transaction already wrote rules; `server.add` adopted the server id
    /// at bootstrap; `service.elevate` only authorizes the named spec.
    fn apply_agent_action(&self, action: &ActionRecord, params: &Value) -> Outcome {
        if matches!(action.kind.as_str(), "rule.create" | "rule.revoke") {
            let subject = params["rule"]["id"]
                .as_str()
                .or(params["rule_id"].as_str())
                .unwrap_or_default();
            self.trust_changed(&action.kind, subject);
        }
        Outcome::succeeded()
    }

    // -------------------------------------------------------- reconciliation

    /// One pass over the consumed log plus the execution-window sweep.
    pub async fn reconcile_once(&self) {
        let path = self.consumed_log.clone();
        let owner = self.consumed_log_owner;
        let Ok(read) = tokio::task::spawn_blocking(move || read_consumed_log(&path, owner)).await
        else {
            return;
        };
        let now = self.now();
        let effects = match self.store.reconcile(&read, now) {
            Ok(effects) => effects,
            Err(err) => {
                warn!(error = %err, "consumed log reconciliation failed");
                return;
            }
        };
        for effect in effects {
            self.apply_effect(effect);
        }
        match self.store.expire_windows(now) {
            Ok(expired) => {
                for plan_id in expired {
                    if let Ok(Some(record)) = self.store.admission(&plan_id) {
                        let plan = plan_of(&record);
                        for action in self.store.actions(&plan_id).unwrap_or_default() {
                            if action.outcome == "expired" {
                                self.final_step(&record, &plan, &action, "expired");
                            }
                        }
                        self.finished(&record);
                    }
                }
            }
            Err(err) => warn!(error = %err, "execution window sweep failed"),
        }
    }

    fn action_context(
        &self,
        plan_id: &str,
        index: u32,
    ) -> Option<(AdmissionRecord, Value, ActionRecord)> {
        let record = self.store.admission(plan_id).ok()??;
        let action = self
            .store
            .actions(plan_id)
            .ok()?
            .into_iter()
            .find(|a| a.action_index == index)?;
        let plan = plan_of(&record);
        Some((record, plan, action))
    }

    fn apply_effect(&self, effect: ReconcileEffect) {
        match effect {
            // The executor announces `bound` itself.
            ReconcileEffect::Consumed { .. } => {}
            ReconcileEffect::ActionFinished {
                plan_id,
                action_index,
                outcome,
            } => {
                if let Some((record, plan, action)) = self.action_context(&plan_id, action_index) {
                    self.final_step(&record, &plan, &action, &outcome);
                }
            }
            ReconcileEffect::AdmissionFinished { plan_id, .. } => {
                if let Ok(Some(record)) = self.store.admission(&plan_id) {
                    self.finished(&record);
                }
            }
            ReconcileEffect::Unexplained { detail } => {
                warn!(%detail, "consumed log line not explained by an admission");
                self.trust_changed("file_changed", "");
            }
        }
    }

    /// Reconciles, resumes unfinished admissions, then polls every 2 s.
    pub fn spawn_background(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let core = self.clone();
        tokio::spawn(async move {
            core.reconcile_once().await;
            for record in core.store.open_admissions().unwrap_or_default() {
                core.execute(&record.plan_id).await;
            }
            let mut ticks: u64 = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                core.reconcile_once().await;
                ticks += 1;
                if ticks.is_multiple_of(1_800) {
                    let _ = core.store.prune_operation_events(core.now());
                }
            }
        })
    }

    // ------------------------------------------------------------ operations

    /// Every step recorded for an operation, the latest state of each
    /// `(action_index, name)`, in order of first appearance.
    fn recorded_steps(&self, operation_id: &str) -> Vec<OperationStep> {
        let mut steps: Vec<OperationStep> = Vec::new();
        for (_, text) in self
            .store
            .operation_events_after(operation_id, 0)
            .unwrap_or_default()
        {
            let Some(OperationEvent {
                event: Some(operation_event::Event::Step(step)),
                ..
            }) = decode_event(&text)
            else {
                continue;
            };
            match steps
                .iter_mut()
                .find(|s| s.action_index == step.action_index && s.name == step.name)
            {
                Some(existing) => {
                    let started_at = existing.started_at;
                    *existing = step;
                    existing.started_at = started_at;
                }
                None => steps.push(step),
            }
        }
        steps
    }

    pub fn operation(&self, record: &AdmissionRecord) -> Operation {
        let actions = self.store.actions(&record.plan_id).unwrap_or_default();
        let steps = self.recorded_steps(&record.operation_id);
        let state = match record.outcome.as_str() {
            "succeeded" => OperationState::Succeeded,
            "failed" | "expired" => OperationState::Failed,
            "cancelled" => OperationState::Cancelled,
            "rolled_back" => OperationState::RolledBack,
            _ if actions
                .iter()
                .any(|a| a.consumed_at.is_some() || a.finished_at.is_some()) =>
            {
                OperationState::Running
            }
            _ => OperationState::Queued,
        };
        let error = steps
            .iter()
            .rev()
            .find(|s| !s.error.is_empty())
            .map(|s| s.error.clone())
            .unwrap_or_default();
        Operation {
            id: record.operation_id.clone(),
            plan_digest_hex: record.plan_digest_hex.clone(),
            actions: record.action_kinds.clone(),
            state: state as i32,
            submitted_at: ts(&record.admitted_at),
            started_at: actions
                .iter()
                .filter_map(|a| a.consumed_at.as_deref().or(a.finished_at.as_deref()))
                .min()
                .and_then(ts),
            finished_at: record.finished_at.as_deref().and_then(ts),
            authorized_key_ids: record.signer_key_ids.clone(),
            standing_rule_id: record.rule_id.clone().unwrap_or_default(),
            steps,
            error,
            initiator: if record.submitter == "agent_webhook" {
                "webhook".to_owned()
            } else {
                "engine".to_owned()
            },
            plan_id: record.plan_id.clone(),
        }
    }
}

pub fn decode_event(text: &str) -> Option<OperationEvent> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()?;
    OperationEvent::decode(bytes.as_slice()).ok()
}

fn plan_ref(record: &AdmissionRecord, action: &ActionRecord) -> PlanRef {
    PlanRef {
        plan_id: record.plan_id.clone(),
        plan_digest_hex: record.plan_digest_hex.clone(),
        action_index: action.action_index,
    }
}

fn spec_texts(specs: &[Vec<u8>]) -> Result<Vec<String>, PlanCode> {
    if specs.len() > crate::signed_plan::verify::MAX_SPECS {
        return Err(PlanCode::SpecMismatch);
    }
    specs
        .iter()
        .map(|bytes| String::from_utf8(bytes.clone()).map_err(|_| PlanCode::SpecMismatch))
        .collect()
}

fn plan_of(record: &AdmissionRecord) -> Value {
    parse_strict(record.signed_plan_json.as_bytes(), MAX_SIGNED_PLAN_BYTES)
        .map(|envelope| envelope["plan"].clone())
        .unwrap_or(Value::Null)
}

fn ts(text: &str) -> Option<prost_types::Timestamp> {
    parse_ts(text).map(unix_timestamp)
}

fn unix_timestamp(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_kind_has_its_contract_op_sequence() {
        let none = Value::Null;
        assert_eq!(exec_of("deploy", &none), Exec::Deploy);
        assert_eq!(exec_of("rollback", &none), Exec::Ops(&["rollback_release"]));
        assert_eq!(exec_of("restart", &none), Exec::Ops(&["restart_release"]));
        assert_eq!(
            exec_of("operation.cancel", &none),
            Exec::Ops(&["cancel_execution"])
        );
        assert_eq!(
            exec_of("agent.update", &none),
            Exec::Ops(&["install_artifact"])
        );
        assert_eq!(
            exec_of("component.update", &json!({"component": "dwaar"})),
            Exec::Ops(&["install_artifact"])
        );
        assert_eq!(
            exec_of("component.update", &json!({"component": "os_packages"})),
            Exec::NotImplemented
        );
        for kind in ["key.add", "key.revoke"] {
            assert_eq!(exec_of(kind, &none), Exec::Ops(&["update_trusted_keys"]));
        }
        for kind in INPUT_KINDS {
            assert_eq!(exec_of(kind, &none), Exec::Input, "{kind}");
        }
        for kind in [
            "server.add",
            "rule.create",
            "rule.revoke",
            "service.elevate",
        ] {
            assert_eq!(exec_of(kind, &none), Exec::Agent, "{kind}");
        }
        for kind in ["scale", "cron.run", "backup.verify", "alert.silence"] {
            assert_eq!(exec_of(kind, &none), Exec::NotImplemented, "{kind}");
        }
    }

    #[test]
    fn failure_codes_follow_the_step_table() {
        assert_eq!(failure_code_of("deploy", "prepare_release"), "prepare");
        assert_eq!(
            failure_code_of("deploy", "verify_health"),
            "candidate_health"
        );
        assert_eq!(failure_code_of("deploy", "activate_release"), "activate");
        assert_eq!(failure_code_of("deploy", "rollback_release"), "recovery");
        assert_eq!(failure_code_of("rollback", "rollback_release"), "start");
        assert_eq!(failure_code_of("restart", "restart_release"), "start");
        assert_eq!(failure_code_of("key.add", "update_trusted_keys"), "");
    }

    #[test]
    fn the_default_start_timeout_is_300_seconds() {
        assert_eq!(Timing::default().start_timeout, Duration::from_secs(300));
    }
}
