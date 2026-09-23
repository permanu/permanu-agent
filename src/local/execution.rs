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
    deploy_status_event::Phase, event, operation_event, DeployStatusEvent, ErrorReason, EventKind,
    Operation, OperationEvent, OperationState, OperationStep, Scope, StepLog, TrustChangedEvent,
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
/// Cancelled actions logged from one `cancel_execution` result (a plan
/// holds at most 64 actions).
const MAX_LOGGED_CANCELLED: usize = 64;

/// A runner-supplied id that is safe to echo into a step log.
fn text_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

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
    /// v1.0.7 definition kinds: `bind_plan` alone; the runner records the
    /// definition (`consumed`, then `result succeeded`) and the schedulers
    /// apply it once that result is reconciled (section 14.6).
    Definition,
    NotImplemented,
}

/// Section 14.6 definition kinds (v1.0.7, v1.0.9).
const DEFINITION_KINDS: &[&str] = &[
    "cron.create",
    "cron.update",
    "cron.delete",
    "cron.pause",
    "cron.resume",
    "backup.policy.set",
    "backup.policy.delete",
    "backup.destination.set",
    "backup.destination.delete",
    "recovery_recipient.set",
    "env.protection.set",
    "repo.credential.set",
    "repo.credential.delete",
];

/// Why an `alert.rule.*` action cannot be applied (its signed `spec` is
/// not a valid `AlertRule`), if so.
fn alert_spec_error(kind: &str, params: &Value) -> Option<String> {
    if !matches!(kind, "alert.rule.create" | "alert.rule.update") {
        return None;
    }
    let text = |name: &str| params[name].as_str().unwrap_or_default();
    super::sched::alert_spec::parse(text("alert_rule_id"), text("name"), text("spec")).err()
}

fn exec_of(kind: &str, params: &Value) -> Exec {
    match kind {
        "server.add" | "rule.create" | "rule.revoke" | "service.elevate" => Exec::Agent,
        "deploy" => Exec::Deploy,
        "rollback" => Exec::Ops(&["rollback_release"]),
        "restart" => Exec::Ops(&["restart_release"]),
        "operation.cancel" => Exec::Ops(&["cancel_execution"]),
        // v1.0.4 (D-040): agent.update runs its own op; install_artifact
        // serves component.update only.
        "agent.update" => Exec::Ops(&["update_agent"]),
        "component.update"
            if matches!(
                params["component"].as_str(),
                Some("dwaar" | "runner" | "permanu-env")
            ) =>
        {
            Exec::Ops(&["install_artifact"])
        }
        // v1.0.7 (D-051): release keys through the same trust-file op.
        "key.add" | "key.revoke" | "release_key.add" | "release_key.revoke" => {
            Exec::Ops(&["update_trusted_keys"])
        }
        // v1.0.7 plan-bound cron and backup ops (section 14.6).
        "cron.run" => Exec::Ops(&["run_cron"]),
        "backup.run" => Exec::Ops(&["backup_run"]),
        "backup.verify" => Exec::Ops(&["backup_verify"]),
        "backup.delete" => Exec::Ops(&["backup_delete"]),
        "restore" => Exec::Ops(&["restore_backup"]),
        kind if kind.starts_with("alert.") => Exec::Agent,
        kind if DEFINITION_KINDS.contains(&kind) => Exec::Definition,
        kind if INPUT_KINDS.contains(&kind) => Exec::Input,
        _ => Exec::NotImplemented,
    }
}

/// D-046 (contracts v1.0.5): until the M2 artifact trust root lands,
/// `agent.update` and `component.update` for `runner` or `permanu-env` are
/// not supported; the engine never builds them and the runner fails them
/// closed. The agent refuses them before admission as well, so a signed
/// update that cannot succeed never consumes a nonce or advances the head.
/// Returns the refused action's description, if any. The envelope is not
/// verified here: this can only refuse, never admit.
pub fn not_supported_yet(envelope: &[u8]) -> Option<String> {
    if envelope.len() > MAX_SIGNED_PLAN_BYTES {
        return None;
    }
    let parsed: Value = serde_json::from_slice(envelope).ok()?;
    parsed["plan"]["actions"]
        .as_array()?
        .iter()
        .find_map(|action| match action["kind"].as_str()? {
            "agent.update" => Some("agent.update".to_owned()),
            "component.update" => match action["params"]["component"].as_str()? {
                component @ ("runner" | "permanu-env") => {
                    Some(format!("component.update({component})"))
                }
                _ => None,
            },
            _ => None,
        })
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

/// Engine API `DeployFailureCode` values a runner may name in
/// `error.failure_code` (section 14.8).
const DEPLOY_FAILURE_CODES: &[&str] = &[
    "build",
    "prepare",
    "start",
    "candidate_health",
    "activate",
    "public_health",
    "recovery",
];

/// A start-phase op that ran out of time (D-033).
fn timed_out(op: &str, failure: &RunnerFailure) -> bool {
    matches!(op, "prepare_release" | "verify_health" | "restart_release")
        && failure.message == runner::TIMED_OUT
}

/// The `failure_code` of a failed op: `start` on a start-phase timeout,
/// else the runner's own `error.failure_code` for a service step (for
/// example `public_health` after the switch), else the section 14.6 table.
fn op_failure_code(kind: &str, op: &str, failure: &RunnerFailure) -> String {
    let table = failure_code_of(kind, op);
    if timed_out(op, failure) {
        return "start".to_owned();
    }
    match failure.failure_code.as_deref() {
        Some(code) if !table.is_empty() && DEPLOY_FAILURE_CODES.contains(&code) => code.to_owned(),
        _ => table.to_owned(),
    }
}

/// The result of one action.
#[derive(Debug, Clone)]
struct Outcome {
    outcome: &'static str,
    failure_code: String,
    error: String,
    /// The runner (or section 6.1) code of the failure, v2.0.6
    /// `OperationStep.error_code`.
    error_code: String,
    /// The deploy reached `activate_release`, past the point of no return:
    /// a cancel does not close it (v1.0.6, D-048), so it ends through its
    /// own ops.
    activated: bool,
}

impl Outcome {
    fn succeeded() -> Self {
        Self::with("succeeded", "", "")
    }

    fn with(outcome: &'static str, failure_code: &str, error: impl Into<String>) -> Self {
        Self {
            outcome,
            failure_code: failure_code.to_owned(),
            error: error.into(),
            error_code: String::new(),
            activated: false,
        }
    }

    /// A failed runner call: its described message and exact code.
    fn runner(outcome: &'static str, failure_code: &str, failure: &RunnerFailure) -> Self {
        Self {
            error_code: failure.code.clone(),
            ..Self::with(outcome, failure_code, describe(failure))
        }
    }

    fn activated(mut self) -> Self {
        self.activated = true;
        self
    }
}

/// A failed start phase of a deploy (`prepare_release`, `verify_health`).
struct StartFailure {
    failure_code: String,
    message: String,
    error_code: String,
    /// An earlier release may be restored (not a failed prepare).
    restorable: bool,
    /// The runner refused `prepare_release` with a contract code before it
    /// created anything (F-23: a refused input fold): no recovery runs.
    refused: bool,
}

/// v2.0.6: the `ErrorReason` for a step's `error_code`; a code outside the
/// agent-protocol.md section 5 table is `INTERNAL`.
fn reason_of_code(error_code: &str) -> ErrorReason {
    if error_code.is_empty() {
        return ErrorReason::Unspecified;
    }
    reason_for(PlanCode::parse(error_code).unwrap_or(PlanCode::Internal))
}

/// A runner refusal with a signed-plan or runner binding code (sections
/// 6.1, 14.2-14.4, 14.7): the runner stopped at its checks, before the op
/// changed anything on the server.
fn refused_by_check(failure: &RunnerFailure) -> bool {
    PlanCode::parse(&failure.code).is_some_and(|code| code != PlanCode::Internal)
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
    /// `AgentInfo.age_recipient` (empty when unreadable): a bootstrap
    /// `server.add` must sign its fingerprint (v1.0.5, D-045).
    pub age_recipient: String,
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
    /// (failure_code, error, error_code) the executor saw for an action,
    /// for the final step when the runner's `result` line ends it.
    failures: Mutex<HashMap<(String, u32), Failure>>,
    /// Plans whose operation the executor ends itself (a cancel, v1.0.6
    /// D-048): the reconciler records their result lines but leaves their
    /// final steps and `finished` to the executor; the value lists the
    /// actions it skipped.
    held: Mutex<HashMap<String, Vec<u32>>>,
    /// One reconciliation pass at a time, so a pass that returns has
    /// emitted every event of the lines it read.
    reconciling: tokio::sync::Mutex<()>,
}

/// (failure_code, error, error_code) of an action.
type Failure = (String, String, String);

pub struct ChangeCoreParts {
    pub store: Arc<AdmissionStore>,
    pub trust: TrustPaths,
    pub probe: Arc<dyn HostProbe>,
    pub runner: Arc<dyn Runner>,
    pub events: EventBus,
    pub clock: Arc<dyn Clock>,
    pub consumed_log: PathBuf,
    pub consumed_log_owner: u32,
    pub age_recipient: String,
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
            age_recipient: parts.age_recipient,
            timing: parts.timing,
            operations: broadcast::channel(1_024).0,
            execution: tokio::sync::Mutex::new(()),
            bootstrap: tokio::sync::Mutex::new(()),
            submissions: Mutex::new(VecDeque::new()),
            cancelled: Mutex::new(HashSet::new()),
            running: Mutex::new(HashSet::new()),
            failures: Mutex::new(HashMap::new()),
            held: Mutex::new(HashMap::new()),
            reconciling: tokio::sync::Mutex::new(()),
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
        let bootstrap = verify_bootstrap(
            envelope,
            &self.probe.ssh_host_key_digests_hex(),
            &self.age_recipient,
            self.now(),
        )?;
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
                    &self.age_recipient,
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
        self.step_coded(record, action, name, state, error, failure_code, "");
    }

    /// `step` with the failure's runner code and its reason (v2.0.6).
    #[allow(clippy::too_many_arguments)]
    fn step_coded(
        &self,
        record: &AdmissionRecord,
        action: Option<&ActionRecord>,
        name: &str,
        state: OperationState,
        error: &str,
        failure_code: &str,
        error_code: &str,
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
            error_code: error_code.to_owned(),
            error_reason: reason_of_code(error_code) as i32,
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

    /// v1.0.5 (D-044, section 14.6): the `cleanup_candidate` step of a
    /// cancelled deploy whose prepared candidate `cancel_execution` cleaned
    /// up. It carries no failure code (the deployment ends `cancelled`); a
    /// cleanup that could not finish names the leftover candidate in the
    /// step error.
    fn cancel_cleanup_step(&self, record: &AdmissionRecord, action: &ActionRecord, cleanup: &str) {
        let deployment_id = action.deployment_id.clone().unwrap_or_default();
        match cleanup {
            "done" => {
                self.step(
                    record,
                    Some(action),
                    "cleanup_candidate",
                    OperationState::Succeeded,
                    "",
                    "",
                );
                self.log_line(
                    record,
                    action,
                    "cleanup_candidate",
                    &format!("cancelled candidate {deployment_id} removed with its secrets"),
                );
            }
            "failed" => {
                let error = format!(
                    "the cancel could not clean up candidate {deployment_id}: its containers or \
                     /run/permanu/secrets/{deployment_id}/ may remain on the server"
                );
                warn!(plan_id = %record.plan_id, %deployment_id, "cancel cleanup failed");
                self.step(
                    record,
                    Some(action),
                    "cleanup_candidate",
                    OperationState::Failed,
                    &error,
                    "",
                );
            }
            _ => {}
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
        let (failure_code, error, error_code) = locked(&self.failures)
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
        let (code, error_code) = match outcome {
            "failed" | "rolled_back" => (failure_code.as_str(), error_code.as_str()),
            _ => ("", ""),
        };
        self.step_coded(
            record,
            Some(action),
            outcome,
            state,
            message,
            code,
            error_code,
        );
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
        // A hold the executor did not end through `complete` (it stopped
        // early) must not keep the operation from finishing.
        if self.release_held(plan_id) {
            if let Ok(Some(record)) = self.store.admission(plan_id) {
                if record.finished_at.is_some() {
                    self.finished(&record);
                }
            }
        }
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
            if action.kind != "operation.cancel" && done.iter().any(|d| d == "cancel_execution") {
                // v1.0.6 (D-048): a cancel closed this action; it has no next
                // op and its one `cancelled` result line ends it.
                locked(&self.cancelled).insert(plan_id.to_owned());
                break;
            }
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
                Exec::Input | Exec::Definition => self.bind(&record, &action).await.err(),
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
                if self.is_cancelled(plan_id) && !outcome.activated {
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
            (
                outcome.failure_code.clone(),
                outcome.error.clone(),
                outcome.error_code.clone(),
            ),
        );
        // The runner's result line wins (section 14.5).
        self.reconcile_once().await;
        let recorded = match self.store.finish_action(
            &record.plan_id,
            action.action_index,
            outcome.outcome,
            self.now(),
        ) {
            Ok(recorded) => recorded,
            Err(err) => {
                warn!(error = %err, "could not record the action outcome");
                false
            }
        };
        if recorded {
            self.final_step(record, plan, action, outcome.outcome);
        }
        let held = self.release_held(&record.plan_id);
        if !recorded && !held {
            return;
        }
        if let Ok(Some(fresh)) = self.store.admission(&record.plan_id) {
            if fresh.finished_at.is_some() {
                self.finished(&fresh);
            }
        }
    }

    /// Ends the hold on a plan: the final steps of the result lines the
    /// reconciler recorded for it come now, from the executor (v1.0.6,
    /// D-048). False when the plan was not held.
    fn release_held(&self, plan_id: &str) -> bool {
        let Some(skipped) = locked(&self.held).remove(plan_id) else {
            return false;
        };
        for index in skipped {
            if let Some((record, plan, action)) = self.action_context(plan_id, index) {
                self.final_step(&record, &plan, &action, &action.outcome);
            }
        }
        true
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
                let outcome = Outcome::runner("failed", "", &failure);
                warn!(plan_id = %record.plan_id, action = action.action_index, message = %outcome.error, "runner bind failed");
                Err(outcome)
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
        self.op_result(record, plan, action, op, timeout)
            .await
            .map(|_| ())
    }

    /// `op`, returning the runner's `result` line.
    async fn op_result(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        op: &str,
        timeout: Duration,
    ) -> Result<Value, RunnerFailure> {
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
                    self.step_coded(
                        record,
                        Some(action),
                        op,
                        OperationState::Failed,
                        &describe(failure),
                        &op_failure_code(&action.kind, op, failure),
                        &failure.code,
                    );
                }
            }
        }
        result.map(|done| done.result)
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
            return self.run_cancel(record, action, params, done).await;
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
                return Outcome::runner(
                    "failed",
                    &op_failure_code(&action.kind, op, &failure),
                    &failure,
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
    /// step; the runner's `cancel_execution` closes its unfinished actions
    /// and ends each `cancelled` with its cleanup in the one `result` line
    /// (v1.0.6, D-048). The flag is set first so the plan's executor cannot
    /// start another step while the cancel is in flight.
    ///
    /// Event order (signed-plan.md 14.6): the cancelled plan's cleanup and
    /// final steps and its `finished` (from the consumed log), then this
    /// step's list of cancelled actions and its completion; the caller's
    /// `complete` emits this operation's `finished` last. This plan is held
    /// so the reconciler cannot finish it first from the runner's `result`
    /// line for the cancel action.
    async fn run_cancel(
        &self,
        record: &AdmissionRecord,
        action: &ActionRecord,
        params: &Value,
        done: &[String],
    ) -> Outcome {
        let target = params["plan_id"].as_str().unwrap_or_default().to_owned();
        let newly = locked(&self.cancelled).insert(target.clone());
        locked(&self.held)
            .entry(record.plan_id.clone())
            .or_default();
        let mut wire = None;
        if !done.iter().any(|d| d == "cancel_execution") {
            self.step(
                record,
                Some(action),
                "cancel_execution",
                OperationState::Running,
                "",
                "",
            );
            match runner::run_op(
                self.runner.as_ref(),
                "cancel_execution",
                &plan_ref(record, action),
                self.timing.op_timeout,
            )
            .await
            {
                Ok(result) => {
                    for line in &result.progress {
                        self.log_line(record, action, "cancel_execution", line);
                    }
                    wire = Some(result.result);
                }
                Err(failure) => {
                    self.reconcile_once().await;
                    if !self.runner_succeeded(record, action) {
                        if newly {
                            locked(&self.cancelled).remove(&target);
                        }
                        self.step_coded(
                            record,
                            Some(action),
                            "cancel_execution",
                            OperationState::Failed,
                            &describe(&failure),
                            "",
                            &failure.code,
                        );
                        return Outcome::runner("failed", "", &failure);
                    }
                    // The runner wrote the cancel's result line, so every
                    // line of the cancel is in the consumed log (14.8).
                    warn!(canceller = %record.plan_id, error = %failure.message, "cancel_execution result lost; the consumed log has it");
                }
            }
        }
        self.reconcile_once().await;
        let mut listed = Vec::new();
        if let Ok(Some(cancelled)) = self.store.admission(&target) {
            let cancelled_plan = plan_of(&cancelled);
            let ops = self.logged_ops(&cancelled).await;
            for victim in self.store.actions(&target).unwrap_or_default() {
                // An action whose activate_release started is not closed by
                // the cancel; its own ops end it (D-048).
                let activated = ops
                    .get(&victim.action_index)
                    .is_some_and(|ops| ops.iter().any(|op| op == "activate_release"));
                if victim.finished_at.is_none() && !activated {
                    self.complete(
                        &cancelled,
                        &cancelled_plan,
                        &victim,
                        Outcome::with("cancelled", "", "cancelled by an admitted operation.cancel"),
                    )
                    .await;
                }
            }
            listed = self.cancelled_in_log(&cancelled).await;
        }
        let list = wire
            .as_ref()
            .and_then(|result| result["cancelled"].as_array().cloned())
            .unwrap_or(listed);
        self.log_cancelled(record, action, &list);
        self.step(
            record,
            Some(action),
            "cancel_execution",
            OperationState::Succeeded,
            "",
            "",
        );
        info!(canceller = %record.plan_id, target = %target, "operation cancelled");
        Outcome::succeeded()
    }

    /// Whether the runner's `result` line ended this action `succeeded`.
    fn runner_succeeded(&self, record: &AdmissionRecord, action: &ActionRecord) -> bool {
        self.store
            .actions(&record.plan_id)
            .unwrap_or_default()
            .iter()
            .any(|a| {
                a.action_index == action.action_index
                    && a.finished_at.is_some()
                    && a.outcome == "succeeded"
            })
    }

    /// The wire `cancelled` list rebuilt from the consumed log's `cancelled`
    /// result lines of the cancelled plan (v1.0.6, section 14.6), in
    /// `action_index` order.
    async fn cancelled_in_log(&self, cancelled: &AdmissionRecord) -> Vec<Value> {
        let path = self.consumed_log.clone();
        let owner = self.consumed_log_owner;
        let Ok(read) = tokio::task::spawn_blocking(move || read_consumed_log(&path, owner)).await
        else {
            return Vec::new();
        };
        let actions = self.store.actions(&cancelled.plan_id).unwrap_or_default();
        let mut entries: Vec<(u32, Value)> = read
            .lines
            .iter()
            .filter(|line| {
                line.event == "result"
                    && line.plan_id == cancelled.plan_id
                    && line.plan_digest_hex == cancelled.plan_digest_hex
                    && line.outcome.as_deref() == Some("cancelled")
            })
            .map(|line| {
                let deployment_id = actions
                    .iter()
                    .find(|a| a.action_index == line.action_index)
                    .and_then(|a| a.deployment_id.clone());
                (
                    line.action_index,
                    serde_json::json!({
                        "action_index": line.action_index,
                        "deployment_id": deployment_id,
                        "cleanup": line.cleanup.as_deref().unwrap_or("none"),
                    }),
                )
            })
            .collect();
        entries.sort_by_key(|(index, _)| *index);
        entries.dedup_by_key(|(index, _)| *index);
        entries.into_iter().map(|(_, entry)| entry).collect()
    }

    /// The cancelled list `{action_index, deployment_id, cleanup}` (v1.0.5,
    /// D-044) as step logs on the cancel's step. The cancelled plan's own
    /// steps come from the consumed log, which is authoritative (14.5).
    fn log_cancelled(&self, record: &AdmissionRecord, action: &ActionRecord, cancelled: &[Value]) {
        for entry in cancelled.iter().take(MAX_LOGGED_CANCELLED) {
            let index = entry["action_index"].as_u64().unwrap_or_default();
            let cleanup = entry["cleanup"]
                .as_str()
                .filter(|c| matches!(*c, "done" | "failed" | "none"))
                .unwrap_or("unknown");
            let line = match entry["deployment_id"].as_str().filter(|id| text_id(id)) {
                Some(deployment_id) => format!(
                    "cancelled action {index} (deployment {deployment_id}): cleanup {cleanup}"
                ),
                None => format!("cancelled action {index}: cleanup {cleanup}"),
            };
            self.log_line(record, action, "cancel_execution", &line);
        }
    }

    /// `deploy`: the start phase (`prepare_release`, `verify_health`) within
    /// the start timeout, then `activate_release`. Failure paths (section
    /// 14.6, D-038): a failed `prepare_release` → `cleanup_candidate`; a
    /// failed `verify_health`, the start timeout or a failed
    /// `activate_release` → `rollback_release` when the service has an
    /// earlier release, else `cleanup_candidate`. A failed recovery op ends
    /// the action `failed` with failure code `recovery`.
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
                    let prepare = op == "prepare_release" && !timed_out(op, &failure);
                    return Err(StartFailure {
                        failure_code: op_failure_code("deploy", op, &failure),
                        message: describe(&failure),
                        error_code: failure.code.clone(),
                        restorable: !prepare,
                        refused: prepare && refused_by_check(&failure),
                    });
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
                Some(StartFailure {
                    failure_code: "start".to_owned(),
                    message,
                    error_code: String::new(),
                    restorable: true,
                    refused: false,
                })
            }
        };
        if self.is_cancelled(&record.plan_id) {
            return Outcome::with("cancelled", "", "");
        }
        let (failure, activated) = match failure {
            // F-23: the runner refused prepare_release at its checks (for
            // example a refused input fold, E_SCOPE_MISMATCH), so there is
            // no candidate to clean up; the deploy fails `prepare` with the
            // runner's reason, not `recovery`.
            Some(failure) if failure.refused => {
                return Outcome {
                    error_code: failure.error_code,
                    ..Outcome::with("failed", &failure.failure_code, failure.message)
                };
            }
            Some(failure) => (failure, false),
            None if ran("activate_release") => return Outcome::succeeded().activated(),
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
                Ok(()) => return Outcome::succeeded().activated(),
                Err(failure) => (
                    StartFailure {
                        failure_code: op_failure_code("deploy", "activate_release", &failure),
                        message: describe(&failure),
                        error_code: failure.code.clone(),
                        restorable: true,
                        refused: false,
                    },
                    true,
                ),
            },
        };
        // A cancel closes an action only before its activate_release
        // (D-048); after it, the recovery still runs.
        if !activated && self.is_cancelled(&record.plan_id) {
            return Outcome::with("cancelled", "", "");
        }
        let service_id = plan["actions"][action.action_index as usize]["params"]["service_id"]
            .as_str()
            .unwrap_or_default();
        let previous = failure.restorable
            && self
                .store
                .has_previous_release(record, service_id)
                .unwrap_or(false);
        let (recovery, outcome) = if previous {
            ("rollback_release", "rolled_back")
        } else {
            ("cleanup_candidate", "failed")
        };
        // The recovery op's own `result` line can end the action before the
        // executor does; its final step must still carry the failed step's
        // code.
        locked(&self.failures).insert(
            (record.plan_id.clone(), action.action_index),
            (
                failure.failure_code.clone(),
                failure.message.clone(),
                failure.error_code.clone(),
            ),
        );
        let ended = match self
            .op(record, plan, action, recovery, self.timing.op_timeout)
            .await
        {
            Ok(()) => Outcome {
                error_code: failure.error_code,
                ..Outcome::with(outcome, &failure.failure_code, failure.message)
            },
            Err(recovery_failure) => {
                warn!(plan_id = %record.plan_id, op = recovery, error = %describe(&recovery_failure), "recovery op failed");
                Outcome::runner("failed", "recovery", &recovery_failure)
            }
        };
        if activated {
            ended.activated()
        } else {
            ended
        }
    }

    /// Kinds the agent applies itself (section 14.6): the admission
    /// transaction already wrote rules; `server.add` adopted the server id
    /// at bootstrap; `service.elevate` only authorizes the named spec.
    fn apply_agent_action(&self, action: &ActionRecord, params: &Value) -> Outcome {
        if let Some(error) = alert_spec_error(&action.kind, params) {
            return Outcome::with("failed", "", format!("invalid alert rule spec: {error}"));
        }
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
        let _pass = self.reconciling.lock().await;
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
                cleanup,
            } => {
                if let Some(skipped) = locked(&self.held).get_mut(&plan_id) {
                    skipped.push(action_index);
                    return;
                }
                if let Some((record, plan, action)) = self.action_context(&plan_id, action_index) {
                    if let Some(cleanup) = cleanup {
                        self.cancel_cleanup_step(&record, &action, &cleanup);
                    }
                    self.final_step(&record, &plan, &action, &outcome);
                }
            }
            ReconcileEffect::AdmissionFinished { plan_id, .. } => {
                if locked(&self.held).contains_key(&plan_id) {
                    return;
                }
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
        // A held plan (v1.0.6, D-048) is still running until its executor
        // emits the last events and `finished`, even when the runner's
        // result line already ended it in the store.
        let held = locked(&self.held).contains_key(&record.plan_id);
        let state = match record.outcome.as_str() {
            _ if held => OperationState::Running,
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
        // The step that ended the operation: the last one with an error
        // (v2.0.6: its code and reason too).
        let ending = steps.iter().rev().find(|s| !s.error.is_empty());
        let error = ending.map(|s| s.error.clone()).unwrap_or_default();
        let error_code = ending.map(|s| s.error_code.clone()).unwrap_or_default();
        let error_reason = ending.map_or(ErrorReason::Unspecified as i32, |s| s.error_reason);
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
            finished_at: record.finished_at.as_deref().filter(|_| !held).and_then(ts),
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
            error_code,
            error_reason,
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
        // v1.0.4 (D-040): agent.update has its own op.
        assert_eq!(exec_of("agent.update", &none), Exec::Ops(&["update_agent"]));
        for component in ["dwaar", "runner", "permanu-env"] {
            assert_eq!(
                exec_of("component.update", &json!({"component": component})),
                Exec::Ops(&["install_artifact"]),
                "{component}"
            );
        }
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
        // v1.0.7 definition kinds: bind_plan alone; the runner records them.
        for kind in [
            "cron.create",
            "cron.update",
            "cron.delete",
            "cron.pause",
            "cron.resume",
            "backup.policy.set",
            "backup.policy.delete",
            "backup.destination.set",
            "backup.destination.delete",
            "recovery_recipient.set",
            "env.protection.set",
            "repo.credential.set",
            "repo.credential.delete",
        ] {
            assert_eq!(exec_of(kind, &none), Exec::Definition, "{kind}");
        }
        for (kind, op) in [
            ("cron.run", "run_cron"),
            ("backup.run", "backup_run"),
            ("backup.verify", "backup_verify"),
            ("backup.delete", "backup_delete"),
            ("restore", "restore_backup"),
            ("release_key.add", "update_trusted_keys"),
            ("release_key.revoke", "update_trusted_keys"),
        ] {
            let Exec::Ops(ops) = exec_of(kind, &none) else {
                panic!("{kind} runs ops");
            };
            assert_eq!(ops, [op], "{kind}");
        }
        for kind in [
            "alert.rule.create",
            "alert.rule.update",
            "alert.rule.delete",
            "alert.silence",
            "alert.channel.create",
            "alert.channel.update",
            "alert.channel.delete",
        ] {
            assert_eq!(exec_of(kind, &none), Exec::Agent, "{kind}");
        }
        for kind in ["scale", "telemetry.retention.set", "db.upgrade"] {
            assert_eq!(exec_of(kind, &none), Exec::NotImplemented, "{kind}");
        }
    }

    #[test]
    fn alert_rules_with_an_invalid_spec_are_not_applied() {
        let valid = serde_json::json!({"alert_rule_id": "r", "name": "n",
            "spec": "{\"event\": {\"kind\": \"KIND_CRON_FAILED\"}, \"enabled\": true}"});
        assert_eq!(alert_spec_error("alert.rule.create", &valid), None);
        let invalid = serde_json::json!({"alert_rule_id": "r", "name": "n", "spec": "{}"});
        assert!(alert_spec_error("alert.rule.update", &invalid).is_some());
        assert_eq!(alert_spec_error("alert.silence", &invalid), None);
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
