//! Admission orchestration and execution for local mode.
//!
//! - `submit` runs the bootstrap (section 7.3) when trusted-keys.json is
//!   absent, then the ordered verification and the single-transaction admit.
//! - Execution walks the admitted actions in order. Agent-side kinds (trust
//!   and rule changes, `server.add`, `service.elevate`, `operation.cancel`)
//!   run here; every other action is bound to the runner with `bind_plan`
//!   (section 14.2), which consumes it once in the runner's own log.
//! - Reconciliation reads the runner's consumed log (section 14.5) and turns
//!   its lines into action results, `DeployStatusEvent`s and operation events.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use prost::Message;
use serde_json::Value;
use tokio::sync::broadcast;
use tracing::{info, warn};

use super::errors::reason_for;
use super::events::EventBus;
use super::facts::HostProbe;
use super::runner::Runner;
use crate::admissions::{
    read_consumed_log, ActionRecord, Admission, AdmissionRecord, AdmissionStore, AdmitInput,
    ReconcileEffect,
};
use crate::proto::agent::v2::{
    deploy_status_event::Phase, event, operation_event, DeployStatusEvent, EventKind, Operation,
    OperationEvent, OperationState, OperationStep, Scope, StepLog, TrustChangedEvent,
};
use crate::signed_plan::jcs::parse_strict;
use crate::signed_plan::text::timestamp as parse_ts;
use crate::signed_plan::trust::{TrustChange, TrustPaths, TrustState, TrustStore};
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

/// Kinds the agent executes itself; every other kind is bound to the runner.
const AGENT_KINDS: &[&str] = &[
    "server.add",
    "key.add",
    "key.revoke",
    "rule.create",
    "rule.revoke",
    "service.elevate",
    "operation.cancel",
];
/// agent-protocol.md section 7: 10 submissions per minute.
const SUBMISSIONS_PER_MINUTE: usize = 10;
const MAX_SEALED_SECRETS: usize = 64;

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
    operations: broadcast::Sender<OperationEvent>,
    execution: tokio::sync::Mutex<()>,
    bootstrap: tokio::sync::Mutex<()>,
    submissions: std::sync::Mutex<VecDeque<Instant>>,
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
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, PlanCode> + Send + 'static,
) -> Result<T, PlanCode> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or(Err(PlanCode::Internal))
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
            operations: broadcast::channel(1_024).0,
            execution: tokio::sync::Mutex::new(()),
            bootstrap: tokio::sync::Mutex::new(()),
            submissions: std::sync::Mutex::new(VecDeque::new()),
        })
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// agent-protocol.md section 7: false once 10 submissions arrived in the
    /// last minute.
    pub fn allow_submission(&self) -> bool {
        let mut recent = self.submissions.lock().unwrap_or_else(|p| p.into_inner());
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
        let bootstrap = verify_bootstrap(envelope, &self.probe.ssh_host_key_digests_hex())?;
        // An expired or not-yet-valid server.add never writes the trust file;
        // admission would refuse it at step 7 anyway.
        let (plan, _) = crate::signed_plan::verify::parse_envelope(envelope)?;
        crate::signed_plan::verify::check_time(&plan, self.now())?;
        let paths = self.trust.clone();
        let store = blocking(move || {
            paths
                .write_change(&TrustChange::Bootstrap {
                    server_id: &bootstrap.server_id,
                    owner_key: &bootstrap.owner_key,
                })
                .map_err(|err| {
                    warn!(error = %err, "trusted-keys bootstrap write failed");
                    PlanCode::Internal
                })
        })
        .await?;
        info!(server_id = %store.server_id, "trusted-keys.json written by server.add bootstrap");
        self.trust_changed("server.add", &store.server_id);
        Ok(store)
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
                let bootstrap =
                    verify_bootstrap(&submission.envelope, &self.probe.ssh_host_key_digests_hex())?;
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

    fn step_event(&self, record: &AdmissionRecord, action: &ActionRecord, error: &str) {
        let mut step = step_of(action);
        step.error = error.to_owned();
        self.record(&record.operation_id, operation_event::Event::Step(step));
    }

    fn log_line(&self, record: &AdmissionRecord, index: u32, line: &str) {
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
        for action in self.store.actions(plan_id).unwrap_or_default() {
            self.step_event(&record, &action, "");
            self.deploy_status(&record, &plan, &action, Phase::Queued, "admitted");
        }
    }

    // ------------------------------------------------------------- execution

    /// Executes the unfinished, unconsumed actions of one admission in order.
    pub async fn execute(self: &Arc<Self>, plan_id: &str) {
        let _serial = self.execution.lock().await;
        let Ok(Some(record)) = self.store.admission(plan_id) else {
            return;
        };
        if record.finished_at.is_some() {
            return;
        }
        let plan = plan_of(&record);
        let actions = self.store.actions(plan_id).unwrap_or_default();
        let mut failed = false;
        for action in actions {
            if action.finished_at.is_some() || action.consumed_at.is_some() {
                continue;
            }
            let window_open = crate::admissions::execution_deadline(&record.admitted_at)
                .is_some_and(|deadline| self.now() <= deadline);
            if failed || !window_open {
                let outcome = if failed { "cancelled" } else { "expired" };
                self.finish_action(&record, &plan, &action, outcome, "not run");
                continue;
            }
            let kind = action.kind.as_str();
            if AGENT_KINDS.contains(&kind) {
                let params = &plan["actions"][action.action_index as usize]["params"];
                match self.execute_agent_action(&record, kind, params).await {
                    Ok(()) => self.finish_action(&record, &plan, &action, "succeeded", ""),
                    Err(message) => {
                        failed = true;
                        self.finish_action(&record, &plan, &action, "failed", &message);
                    }
                }
                continue;
            }
            match self
                .runner
                .bind_plan(
                    &record.plan_id,
                    &record.plan_digest_hex,
                    action.action_index,
                )
                .await
            {
                Ok(bound) => {
                    self.log_line(
                        &record,
                        action.action_index,
                        &format!("bound to the runner at {}", bound.consumed_at),
                    );
                    self.reconcile_once().await;
                }
                Err(failure) if failure.code == PlanCode::PlanConsumed => {
                    self.log_line(&record, action.action_index, "already bound to the runner");
                    self.reconcile_once().await;
                }
                Err(failure) => {
                    failed = true;
                    let reason = reason_for(failure.code);
                    let message = format!(
                        "{} ({}): {}",
                        reason.as_str_name(),
                        failure.code.as_str(),
                        failure.message
                    );
                    warn!(plan_id, action = action.action_index, %message, "runner bind failed");
                    self.finish_action(&record, &plan, &action, "failed", &message);
                }
            }
        }
    }

    fn finish_action(
        &self,
        record: &AdmissionRecord,
        plan: &Value,
        action: &ActionRecord,
        outcome: &str,
        error: &str,
    ) {
        match self.store.finish_unconsumed_action(
            &record.plan_id,
            action.action_index,
            outcome,
            self.now(),
        ) {
            Ok(true) => {}
            Ok(false) => return,
            Err(err) => {
                warn!(error = %err, "could not record the action outcome");
                return;
            }
        }
        let mut finished = action.clone();
        finished.outcome = outcome.to_owned();
        finished.finished_at = Some(crate::signed_plan::text::format_timestamp(self.now()));
        self.step_event(record, &finished, error);
        let phase = phase_for_outcome(outcome);
        self.deploy_status(record, plan, &finished, phase, error);
        if let Ok(Some(fresh)) = self.store.admission(&record.plan_id) {
            if fresh.finished_at.is_some() {
                self.finished(&fresh);
            }
        }
    }

    async fn execute_agent_action(
        self: &Arc<Self>,
        record: &AdmissionRecord,
        kind: &str,
        params: &Value,
    ) -> Result<(), String> {
        match kind {
            "key.add" | "key.revoke" => {
                let paths = self.trust.clone();
                let owned = params.clone();
                let kind_owned = kind.to_owned();
                let written = tokio::task::spawn_blocking(move || {
                    let change = if kind_owned == "key.add" {
                        TrustChange::AddKey(&owned["entry"])
                    } else {
                        TrustChange::Revoke(&owned["revocation"])
                    };
                    paths.write_change(&change).map(|_| ())
                })
                .await
                .map_err(|_| "trust write task failed".to_owned())?;
                written.map_err(|err| format!("EXEC_PRECONDITION: {err}"))?;
                let subject = if kind == "key.add" {
                    params["entry"]["key_id"].as_str()
                } else {
                    params["revocation"]["key_id"].as_str()
                };
                self.trust_changed(kind, subject.unwrap_or_default());
                Ok(())
            }
            "rule.create" | "rule.revoke" => {
                // Written in the admission transaction (section 6.1 step 13).
                let subject = params["rule"]["id"]
                    .as_str()
                    .or(params["rule_id"].as_str())
                    .unwrap_or_default();
                self.trust_changed(kind, subject);
                Ok(())
            }
            "operation.cancel" => {
                let target = params["plan_id"].as_str().unwrap_or_default();
                self.cancel_plan(record, target);
                Ok(())
            }
            // server.add adopted the server id at bootstrap; service.elevate
            // only authorizes the named spec.
            _ => Ok(()),
        }
    }

    /// Stops the named plan before its next step: every action the runner has
    /// not consumed is finished as `cancelled`, so `bind_plan` refuses it.
    fn cancel_plan(&self, canceller: &AdmissionRecord, target_plan_id: &str) {
        let Ok(Some(target)) = self.store.admission(target_plan_id) else {
            return;
        };
        let plan = plan_of(&target);
        for action in self.store.actions(target_plan_id).unwrap_or_default() {
            if action.finished_at.is_none() && action.consumed_at.is_none() {
                self.finish_action(
                    &target,
                    &plan,
                    &action,
                    "cancelled",
                    "cancelled by an admitted operation.cancel",
                );
            } else if action.finished_at.is_none() {
                self.log_line(
                    &target,
                    action.action_index,
                    "already bound to the runner; it finishes this step",
                );
            }
        }
        info!(canceller = %canceller.plan_id, target = target_plan_id, "operation cancelled");
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
                                self.step_event(&record, &action, "execution window ended");
                                self.deploy_status(
                                    &record,
                                    &plan,
                                    &action,
                                    Phase::Failed,
                                    "execution window ended",
                                );
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
            ReconcileEffect::Consumed {
                plan_id,
                action_index,
            } => {
                if let Some((record, plan, action)) = self.action_context(&plan_id, action_index) {
                    self.step_event(&record, &action, "");
                    self.deploy_status(&record, &plan, &action, Phase::Starting, "bound");
                }
            }
            ReconcileEffect::ActionFinished {
                plan_id,
                action_index,
                outcome,
            } => {
                if let Some((record, plan, action)) = self.action_context(&plan_id, action_index) {
                    self.step_event(&record, &action, "");
                    self.deploy_status(&record, &plan, &action, phase_for_outcome(&outcome), "");
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

    pub fn operation(&self, record: &AdmissionRecord) -> Operation {
        let actions = self.store.actions(&record.plan_id).unwrap_or_default();
        let steps: Vec<OperationStep> = actions.iter().map(step_of).collect();
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
        let error = self
            .store
            .operation_events_after(&record.operation_id, 0)
            .unwrap_or_default()
            .into_iter()
            .rev()
            .filter_map(|(_, text)| decode_event(&text))
            .find_map(|event| match event.event {
                Some(operation_event::Event::Step(step)) if !step.error.is_empty() => {
                    Some(step.error)
                }
                _ => None,
            })
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

fn state_for_outcome(outcome: &str) -> OperationState {
    match outcome {
        "succeeded" => OperationState::Succeeded,
        "failed" | "expired" => OperationState::Failed,
        "cancelled" => OperationState::Cancelled,
        "rolled_back" => OperationState::RolledBack,
        _ => OperationState::Queued,
    }
}

fn phase_for_outcome(outcome: &str) -> Phase {
    match outcome {
        "succeeded" => Phase::Live,
        "rolled_back" => Phase::RolledBack,
        "cancelled" => Phase::Cancelled,
        _ => Phase::Failed,
    }
}

fn step_of(action: &ActionRecord) -> OperationStep {
    let state = if action.finished_at.is_some() {
        state_for_outcome(&action.outcome)
    } else if action.consumed_at.is_some() {
        OperationState::Running
    } else {
        OperationState::Queued
    };
    OperationStep {
        index: action.action_index,
        name: action.kind.clone(),
        action: action.kind.clone(),
        state: state as i32,
        started_at: action.consumed_at.as_deref().and_then(ts),
        finished_at: action.finished_at.as_deref().and_then(ts),
        error: String::new(),
        action_index: action.action_index,
    }
}
