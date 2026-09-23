//! The backup scheduler (`backups.v1`, agent-protocol.md 10.2;
//! signed-plan.md 3.8, 14.9).
//!
//! - A policy is the latest recorded `backup.policy.set` of its resource
//!   until a recorded `backup.policy.delete`; destinations and the recovery
//!   recipient are the recorded `backup.destination.*` and
//!   `recovery_recipient.set`. The agent never sees a credential.
//! - At each fire time of `schedule` it runs `backup_run` with a schedule
//!   binding (up to 3 attempts per fire time), then `backup_prune` under the
//!   same binding after a successful scheduled backup. At each fire time of
//!   `verify_schedule` it runs `backup_verify` (one attempt) against the
//!   newest backup. One run per policy at a time (a fire time that finds one
//!   running is only logged), one `backup_run` per server at a time (others
//!   wait in order).
//! - After downtime a policy runs once when its latest missed fire time is
//!   at most 3600 s old (the runner's schedule window); an older one is
//!   recorded as a failed, missed run and reported.
//! - Manual `backup.run` / `backup.verify` plans are executed by the plan
//!   executor; their runs are recorded from the admissions.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::tz::TimeZone;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tracing::warn;

use super::cron::backoff;
use super::cron_expr::{timezone, CronExpr};
use super::ops_store::{Listing, RecordKind};
use super::DOWNTIME_SECONDS;
use super::{new_id, parse_rfc, pts, rfc, scope_of, AlertSink, BuiltinEvent, Deps, LogIdentity};
use crate::admissions::definitions::AdmittedAction;
use crate::local::runner::{self, PlanRef, RunnerFailure, ScheduleRef};
use crate::proto::agent::v2::{
    backup_destination, backup_run, backup_source, event, event_condition, BackupArtifact,
    BackupDestination, BackupPolicy, BackupRetention, BackupRun, BackupRunStatus, BackupSource,
    EventKind, LogLevel, LogSourceType, RestoreVerification, RestoreVerificationStatus,
    VerificationCheck,
};

pub const BACKUP_KINDS: &[&str] = &[
    "backup.policy.set",
    "backup.policy.delete",
    "backup.destination.set",
    "backup.destination.delete",
    "recovery_recipient.set",
];
const MANUAL_KINDS: &[&str] = &["backup.run", "backup.verify"];
/// `backup_run` attempts per fire time (signed-plan.md 14.9 check 7).
pub const RUN_ATTEMPTS: u32 = 3;
/// Section 10.2: run 6 h, verify 2 h.
const RUN_TIMEOUT: Duration = Duration::from_secs(6 * 3_600 + 300);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(2 * 3_600 + 300);
const PRUNE_TIMEOUT: Duration = Duration::from_secs(3_600);
/// The runner's schedule window (check 6).
pub const LATE_START_SECONDS: i64 = 3_600;
const CHECKPOINT_KEY: &str = "backup_checkpoint";
/// `server_local` root (signed-plan.md 3.8).
pub const LOCAL_ROOT: &str = "/var/lib/permanu/backups";

/// A recorded backup policy.
#[derive(Debug, Clone)]
pub struct PolicyDef {
    pub resource_id: String,
    pub scope: (String, String, String),
    pub schedule_text: String,
    pub schedule: Option<CronExpr>,
    pub timezone_name: String,
    pub timezone: Option<TimeZone>,
    pub keep: (u32, u32, u32),
    pub verify_text: String,
    pub verify: Option<CronExpr>,
    pub destination_ref: String,
    pub plan: PlanRef,
    pub active_from: i64,
}

/// A recorded destination (no credential, only its ciphertext digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationDef {
    pub destination_ref: String,
    pub kind: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub credential_digest: String,
    pub plan_digest_hex: String,
}

/// Everything the recorded backup definitions say.
#[derive(Debug, Clone, Default)]
pub struct Definitions {
    pub policies: BTreeMap<String, PolicyDef>,
    pub destinations: BTreeMap<String, DestinationDef>,
    pub recovery_recipient: Option<String>,
}

fn applied_at(action: &AdmittedAction) -> i64 {
    action
        .finished_at
        .as_deref()
        .and_then(parse_rfc)
        .or_else(|| parse_rfc(&action.admitted_at))
        .unwrap_or_default()
}

fn text(params: &Value, name: &str) -> String {
    params[name].as_str().unwrap_or_default().to_owned()
}

fn keep(params: &Value, name: &str) -> u32 {
    params[name]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or_default()
}

/// The recorded definitions, oldest first.
pub fn load(actions: &[AdmittedAction]) -> Definitions {
    let mut defs = Definitions::default();
    for action in actions.iter().rev().filter(|a| a.succeeded()) {
        let params = &action.params;
        match action.kind.as_str() {
            "backup.policy.set" => {
                let resource = text(params, "resource_id");
                let schedule_text = text(params, "schedule");
                let timezone_name = text(params, "timezone");
                let verify_text = text(params, "verify_schedule");
                defs.policies.insert(
                    resource.clone(),
                    PolicyDef {
                        resource_id: resource,
                        scope: action.scope.clone(),
                        schedule: CronExpr::parse(&schedule_text),
                        schedule_text,
                        timezone: timezone(&timezone_name),
                        timezone_name,
                        keep: (
                            keep(params, "keep_daily"),
                            keep(params, "keep_weekly"),
                            keep(params, "keep_monthly"),
                        ),
                        verify: CronExpr::parse(&verify_text),
                        verify_text,
                        destination_ref: text(params, "destination_ref"),
                        plan: PlanRef {
                            plan_id: action.plan_id.clone(),
                            plan_digest_hex: action.plan_digest_hex.clone(),
                            action_index: u32::try_from(action.action_index).unwrap_or(u32::MAX),
                        },
                        active_from: applied_at(action),
                    },
                );
            }
            "backup.policy.delete" => {
                defs.policies
                    .remove(params["resource_id"].as_str().unwrap_or_default());
            }
            "backup.destination.set" => {
                let reference = text(params, "destination_ref");
                defs.destinations.insert(
                    reference.clone(),
                    DestinationDef {
                        destination_ref: reference,
                        kind: text(params, "destination_kind"),
                        endpoint: text(params, "endpoint"),
                        region: text(params, "region"),
                        bucket: text(params, "bucket"),
                        prefix: text(params, "prefix"),
                        credential_digest: text(params, "credential_ciphertext_digest_hex"),
                        plan_digest_hex: action.plan_digest_hex.clone(),
                    },
                );
            }
            "backup.destination.delete" => {
                defs.destinations
                    .remove(params["destination_ref"].as_str().unwrap_or_default());
            }
            "recovery_recipient.set" => {
                defs.recovery_recipient = params["recipient"].as_str().map(str::to_owned);
            }
            _ => {}
        }
    }
    defs
}

/// Hex SHA-256 of a recipient string (the manifest's fingerprints).
pub fn fingerprint(recipient: &str) -> String {
    hex::encode(Sha256::digest(recipient.as_bytes()))
}

/// The object key below the destination's prefix (signed-plan.md 3.8).
pub fn object_key(prefix: &str, server_id: &str, resource_id: &str, backup_id: &str) -> String {
    let key = format!("permanu/v1/{server_id}/{resource_id}/{backup_id}.age");
    if prefix.is_empty() {
        key
    } else {
        format!("{prefix}/{key}")
    }
}

/// Where an artifact lives, credentials stripped.
pub fn location(
    dest: &DestinationDef,
    server_id: &str,
    resource_id: &str,
    backup_id: &str,
) -> String {
    let key = object_key(&dest.prefix, server_id, resource_id, backup_id);
    match dest.kind.as_str() {
        "server_local" => format!("{LOCAL_ROOT}/{key}"),
        "sftp" => format!("{}/{key}", dest.endpoint),
        kind => format!("{kind}://{}/{key}", dest.bucket),
    }
}

pub fn destination_kind(kind: &str) -> backup_destination::Kind {
    match kind {
        "server_local" => backup_destination::Kind::Local,
        "s3" => backup_destination::Kind::S3,
        "r2" => backup_destination::Kind::R2,
        "b2" => backup_destination::Kind::B2,
        "sftp" => backup_destination::Kind::Sftp,
        _ => backup_destination::Kind::Unspecified,
    }
}

impl DestinationDef {
    pub fn proto(&self) -> BackupDestination {
        BackupDestination {
            kind: destination_kind(&self.kind) as i32,
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            credential_ref: String::new(),
            id: self.destination_ref.clone(),
            name: self.destination_ref.clone(),
            credential_ciphertext_digest_hex: self.credential_digest.clone(),
            plan_digest_hex: self.plan_digest_hex.clone(),
        }
    }
}

impl PolicyDef {
    fn identity(&self, run_id: &str) -> LogIdentity {
        LogIdentity {
            source: format!("backup:{}", self.resource_id),
            project_id: self.scope.0.clone(),
            environment: self.scope.1.clone(),
            environment_id: self.scope.2.clone(),
            service_id: self.resource_id.clone(),
            run_id: run_id.to_owned(),
        }
    }

    fn fire_times(
        expr: Option<&CronExpr>,
        tz: Option<&TimeZone>,
        from: i64,
        to: i64,
    ) -> (Vec<i64>, u32) {
        match (expr, tz) {
            (Some(expr), Some(tz)) => expr.fire_times(tz, from, to, 64, 100_000),
            _ => (Vec::new(), 0),
        }
    }
}

/// A `backup_run` attempt waiting for the server slot or a retry.
#[derive(Debug, Clone)]
struct Pending {
    resource_id: String,
    run: BackupRun,
    scheduled_for: i64,
    retry_at: Option<i64>,
}

#[derive(Default)]
struct State {
    defs: Definitions,
    /// Policies with a backup chain in progress (running, waiting, retry).
    busy: HashSet<String>,
    verifying: HashSet<String>,
    server_busy: bool,
    queue: VecDeque<Pending>,
    retries: Vec<Pending>,
}

pub struct BackupScheduler {
    deps: Deps,
    alerts: Arc<dyn AlertSink>,
    /// The server's own age recipient (`/etc/permanu/age/recipient`).
    server_recipient: String,
    state: Mutex<State>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl BackupScheduler {
    pub fn new(deps: Deps, alerts: Arc<dyn AlertSink>, server_recipient: String) -> Arc<Self> {
        let scheduler = Arc::new(Self {
            deps,
            alerts,
            server_recipient,
            state: Mutex::new(State::default()),
            tasks: Mutex::new(Vec::new()),
        });
        scheduler.recover();
        scheduler
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now(&self) -> i64 {
        self.deps.clock.now()
    }

    fn recover(&self) {
        let now = self.now();
        let running = [
            BackupRunStatus::Pending as i32,
            BackupRunStatus::Dumping as i32,
            BackupRunStatus::Encrypting as i32,
            BackupRunStatus::Uploading as i32,
        ];
        for row in self.deps.ops.list(
            RecordKind::BackupRun,
            &Listing {
                statuses: &running,
                limit: 10_000,
                ..Default::default()
            },
        ) {
            let Some(mut run) = row.decode::<BackupRun>() else {
                continue;
            };
            if run.trigger == backup_run::Trigger::Manual as i32 {
                continue;
            }
            run.status = BackupRunStatus::Failed as i32;
            run.error = "interrupted: the agent restarted during this run".to_owned();
            run.finished_at = Some(pts(now));
            self.save_run(&run, &row.slot);
        }
        let running = [RestoreVerificationStatus::Running as i32];
        for row in self.deps.ops.list(
            RecordKind::Verification,
            &Listing {
                statuses: &running,
                limit: 10_000,
                ..Default::default()
            },
        ) {
            let Some(mut verification) = row.decode::<RestoreVerification>() else {
                continue;
            };
            if verification.trigger == backup_run::Trigger::Manual as i32 {
                continue;
            }
            verification.status = RestoreVerificationStatus::Failed as i32;
            verification.error = "interrupted: the agent restarted during this run".to_owned();
            verification.finished_at = Some(pts(now));
            self.save_verification(&verification, &row.slot);
        }
    }

    /// The recorded definitions (reads the store).
    pub fn definitions(&self) -> Definitions {
        self.reload();
        self.state().defs.clone()
    }

    fn reload(&self) {
        match self.deps.store.admitted_actions(BACKUP_KINDS) {
            Ok(actions) => self.state().defs = load(&actions),
            Err(err) => warn!(error = %err, "backup definitions unreadable; keeping the last set"),
        }
    }

    fn save_run(&self, run: &BackupRun, slot: &str) {
        let at = run.started_at.map_or_else(|| self.now(), |t| t.seconds);
        if let Err(err) = self.deps.ops.put(
            RecordKind::BackupRun,
            &run.id,
            &run.policy_id,
            slot,
            run.status,
            at,
            run,
        ) {
            warn!(error = %err, "backup run not recorded");
        }
    }

    fn save_verification(&self, verification: &RestoreVerification, slot: &str) {
        let at = verification
            .started_at
            .map_or_else(|| self.now(), |t| t.seconds);
        if let Err(err) = self.deps.ops.put(
            RecordKind::Verification,
            &verification.id,
            &verification.policy_id,
            slot,
            verification.status,
            at,
            verification,
        ) {
            warn!(error = %err, "restore verification not recorded");
        }
    }

    fn scope_for(&self, resource_id: &str) -> crate::proto::agent::v2::Scope {
        self.state()
            .defs
            .policies
            .get(resource_id)
            .map(|p| scope_of(&p.scope, resource_id))
            .unwrap_or_default()
    }

    fn record_run(&self, run: &BackupRun, slot: &str) {
        self.save_run(run, slot);
        self.deps.events.publish(
            EventKind::BackupRun,
            self.scope_for(&run.policy_id),
            event::Payload::BackupRun(run.clone()),
        );
    }

    fn record_verification(&self, verification: &RestoreVerification, slot: &str) {
        self.save_verification(verification, slot);
        self.deps.events.publish(
            EventKind::RestoreVerification,
            self.scope_for(&verification.policy_id),
            event::Payload::RestoreVerification(verification.clone()),
        );
    }

    fn log(&self, policy: &PolicyDef, run_id: &str, level: LogLevel, message: &str) {
        self.deps.logs.write(
            LogSourceType::Backup,
            level,
            message,
            &policy.identity(run_id),
        );
    }

    fn report(
        &self,
        policy: &PolicyDef,
        kind: event_condition::Kind,
        occurred: bool,
        summary: &str,
    ) {
        self.alerts.builtin(BuiltinEvent {
            kind,
            scope: scope_of(&policy.scope, &policy.resource_id),
            source: "backup",
            subject_id: policy.resource_id.clone(),
            occurred,
            standalone: false,
            channel_ids: Vec::new(),
            summary: summary.to_owned(),
        });
    }

    /// One scheduler pass at the clock's now.
    pub fn tick(self: &Arc<Self>) {
        let now = self.now();
        self.reload();
        let checkpoint = self
            .deps
            .ops
            .meta(CHECKPOINT_KEY)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(now);
        let from = checkpoint.min(now);
        let downtime = now - checkpoint > DOWNTIME_SECONDS;
        let policies: Vec<PolicyDef> = self.state().defs.policies.values().cloned().collect();
        for policy in &policies {
            let from = from.max(policy.active_from);
            let (times, _) = PolicyDef::fire_times(
                policy.schedule.as_ref(),
                policy.timezone.as_ref(),
                from,
                now,
            );
            let (verify_times, _) =
                PolicyDef::fire_times(policy.verify.as_ref(), policy.timezone.as_ref(), from, now);
            if downtime {
                self.after_downtime(policy, &times, now);
                if let Some(&latest) = verify_times.last() {
                    if now - latest <= LATE_START_SECONDS {
                        self.start_verify(policy, latest);
                    }
                }
            } else {
                for at in times {
                    self.start_backup(policy, at);
                }
                for at in verify_times {
                    self.start_verify(policy, at);
                }
            }
        }
        self.retries_due(now);
        self.reconcile_manual(now);
        self.deps.ops.set_meta(CHECKPOINT_KEY, &now.to_string());
    }

    fn after_downtime(self: &Arc<Self>, policy: &PolicyDef, times: &[i64], now: i64) {
        let Some(&latest) = times.last() else {
            return;
        };
        if now - latest <= LATE_START_SECONDS {
            self.start_backup(policy, latest);
            return;
        }
        let slot = rfc(latest);
        if self
            .deps
            .ops
            .has_slot(RecordKind::BackupRun, &policy.resource_id, &slot)
        {
            return;
        }
        let run = BackupRun {
            id: new_id(now),
            policy_id: policy.resource_id.clone(),
            status: BackupRunStatus::Failed as i32,
            trigger: backup_run::Trigger::Schedule as i32,
            started_at: Some(pts(latest)),
            finished_at: Some(pts(now)),
            error: format!(
                "missed: the agent was not running at {} scheduled time(s), the last at {slot}",
                times.len()
            ),
            ..Default::default()
        };
        self.record_run(&run, &slot);
        self.log(policy, &run.id, LogLevel::Warn, &run.error);
        self.report(
            policy,
            event_condition::Kind::BackupFailed,
            true,
            &run.error,
        );
    }

    fn start_backup(self: &Arc<Self>, policy: &PolicyDef, scheduled_for: i64) {
        let slot = rfc(scheduled_for);
        if self
            .deps
            .ops
            .has_slot(RecordKind::BackupRun, &policy.resource_id, &slot)
        {
            return;
        }
        let now = self.now();
        let mut state = self.state();
        if !state.busy.insert(policy.resource_id.clone()) {
            drop(state);
            self.log(
                policy,
                "",
                LogLevel::Info,
                &format!("scheduled backup at {slot} skipped: a run of this policy is in progress"),
            );
            return;
        }
        let run = BackupRun {
            id: new_id(now),
            policy_id: policy.resource_id.clone(),
            status: BackupRunStatus::Pending as i32,
            trigger: backup_run::Trigger::Schedule as i32,
            ..Default::default()
        };
        state.queue.push_back(Pending {
            resource_id: policy.resource_id.clone(),
            run: run.clone(),
            scheduled_for,
            retry_at: None,
        });
        drop(state);
        self.record_run(&run, &slot);
        self.next_backup();
    }

    /// Starts the next waiting backup when the server has none running.
    fn next_backup(self: &Arc<Self>) {
        let pending = {
            let mut state = self.state();
            if state.server_busy {
                return;
            }
            let Some(pending) = state.queue.pop_front() else {
                return;
            };
            state.server_busy = true;
            pending
        };
        let policy = self
            .state()
            .defs
            .policies
            .get(&pending.resource_id)
            .cloned();
        let Some(policy) = policy else {
            // Deleted while waiting.
            let mut run = pending.run;
            run.status = BackupRunStatus::Cancelled as i32;
            run.error = "the policy was deleted before the run started".to_owned();
            run.finished_at = Some(pts(self.now()));
            self.record_run(&run, &rfc(pending.scheduled_for));
            {
                let mut state = self.state();
                state.server_busy = false;
                state.busy.remove(&pending.resource_id);
            }
            return self.next_backup();
        };
        let attempt = self.attempt_of(&pending);
        let mut run = pending.run.clone();
        run.status = BackupRunStatus::Dumping as i32;
        run.started_at = Some(pts(self.now()));
        let slot = rfc(pending.scheduled_for);
        self.record_run(&run, &slot);
        self.log(
            &policy,
            &run.id,
            LogLevel::Info,
            &format!("backup started: attempt {attempt} for {slot}"),
        );
        let schedule = ScheduleRef {
            plan: policy.plan.clone(),
            scheduled_for: slot.clone(),
            attempt,
        };
        let this = self.clone();
        let task = tokio::spawn(async move {
            let result = runner::run_scheduled(
                this.deps.runner.as_ref(),
                "backup_run",
                &schedule,
                RUN_TIMEOUT,
            )
            .await;
            this.finish_backup(&policy, pending, run, attempt, result)
                .await;
        });
        self.tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(task);
    }

    /// Attempts of one fire time are counted from its records.
    fn attempt_of(&self, pending: &Pending) -> u32 {
        let slot = rfc(pending.scheduled_for);
        let earlier = self
            .deps
            .ops
            .list(
                RecordKind::BackupRun,
                &Listing {
                    subject: Some(&pending.resource_id),
                    limit: 20,
                    ..Default::default()
                },
            )
            .into_iter()
            .filter(|row| row.slot == slot && row.id != pending.run.id)
            .count();
        u32::try_from(earlier).unwrap_or(u32::MAX).saturating_add(1)
    }

    async fn finish_backup(
        self: &Arc<Self>,
        policy: &PolicyDef,
        pending: Pending,
        mut run: BackupRun,
        attempt: u32,
        result: Result<Value, RunnerFailure>,
    ) {
        let now = self.now();
        let slot = rfc(pending.scheduled_for);
        let (retryable, backup_id) = self.apply_backup_result(policy, &mut run, &result, now);
        run.finished_at = Some(pts(now));
        self.record_run(&run, &slot);
        let still_defined = self.state().defs.policies.contains_key(&policy.resource_id);
        let retry = retryable && still_defined && attempt < RUN_ATTEMPTS;
        let mut message = format!(
            "backup {}: attempt {attempt}",
            if run.status == BackupRunStatus::Succeeded as i32 {
                "succeeded"
            } else {
                "failed"
            }
        );
        if !run.error.is_empty() {
            message.push_str(&format!(": {}", run.error));
        }
        if retry {
            message.push_str(&format!(", retry in {} s", backoff(attempt)));
        }
        let level = if run.status == BackupRunStatus::Succeeded as i32 {
            LogLevel::Info
        } else {
            LogLevel::Error
        };
        self.log(policy, &run.id, level, &message);
        {
            let mut state = self.state();
            state.server_busy = false;
            if retry {
                state.retries.push(Pending {
                    resource_id: pending.resource_id.clone(),
                    run: BackupRun {
                        id: new_id(now),
                        policy_id: policy.resource_id.clone(),
                        status: BackupRunStatus::Pending as i32,
                        trigger: backup_run::Trigger::Schedule as i32,
                        ..Default::default()
                    },
                    scheduled_for: pending.scheduled_for,
                    retry_at: Some(now + backoff(attempt)),
                });
            } else {
                state.busy.remove(&pending.resource_id);
            }
        }
        if run.status == BackupRunStatus::Succeeded as i32 {
            self.report(
                policy,
                event_condition::Kind::BackupFailed,
                false,
                "succeeded",
            );
            if let Some(backup_id) = backup_id {
                self.prune(policy, pending.scheduled_for, &backup_id).await;
            }
        } else if !retry {
            self.report(
                policy,
                event_condition::Kind::BackupFailed,
                true,
                &format!("backup failed after {attempt} attempt(s): {}", run.error),
            );
        }
        self.next_backup();
    }

    /// Returns (retryable, backup id of a succeeded run).
    fn apply_backup_result(
        &self,
        policy: &PolicyDef,
        run: &mut BackupRun,
        result: &Result<Value, RunnerFailure>,
        now: i64,
    ) -> (bool, Option<String>) {
        match result {
            Ok(answer) => match answer["outcome"].as_str().unwrap_or("succeeded") {
                "succeeded" => {
                    let backup_id = answer["backup_id"].as_str().unwrap_or_default().to_owned();
                    run.status = BackupRunStatus::Succeeded as i32;
                    run.artifact_id = backup_id.clone();
                    run.content_digest_hex = answer["backup_digest_hex"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    run.size_bytes = answer["size_bytes"].as_u64().unwrap_or_default();
                    if crate::signed_plan::text::uuid7(&backup_id) {
                        self.record_artifact(policy, run, &backup_id, now);
                        (false, Some(backup_id))
                    } else {
                        (false, None)
                    }
                }
                outcome @ ("failed" | "timeout") => {
                    run.status = BackupRunStatus::Failed as i32;
                    run.error = answer["error"]
                        .as_str()
                        .map(|e| e.chars().take(256).collect())
                        .unwrap_or_else(|| outcome.to_owned());
                    (true, None)
                }
                "cancelled" => {
                    run.status = BackupRunStatus::Cancelled as i32;
                    (false, None)
                }
                other => {
                    run.status = BackupRunStatus::Failed as i32;
                    run.error = format!(
                        "unknown outcome {}",
                        other.chars().take(32).collect::<String>()
                    );
                    (false, None)
                }
            },
            Err(failure) => {
                run.status = BackupRunStatus::Failed as i32;
                run.error = format!("{}: {}", failure.code, failure.message);
                (false, None)
            }
        }
    }

    fn record_artifact(&self, policy: &PolicyDef, run: &BackupRun, backup_id: &str, now: i64) {
        let defs = self.state().defs.clone();
        let location = defs
            .destinations
            .get(&policy.destination_ref)
            .map(|dest| location(dest, &self.deps.server_id, &policy.resource_id, backup_id))
            .unwrap_or_default();
        let mut recipients = vec![fingerprint(&self.server_recipient)];
        if let Some(recovery) = &defs.recovery_recipient {
            recipients.push(fingerprint(recovery));
        }
        let artifact = BackupArtifact {
            id: backup_id.to_owned(),
            policy_id: policy.resource_id.clone(),
            run_id: run.id.clone(),
            location,
            size_bytes: run.size_bytes,
            content_digest_hex: run.content_digest_hex.clone(),
            encrypted: true,
            age_recipients: recipients,
            created_at: Some(pts(now)),
            expires_at: None,
            last_verification: RestoreVerificationStatus::Unspecified as i32,
        };
        self.put_artifact(&artifact);
    }

    fn put_artifact(&self, artifact: &BackupArtifact) {
        let at = artifact.created_at.map_or(0, |t| t.seconds);
        if let Err(err) = self.deps.ops.put(
            RecordKind::Artifact,
            &artifact.id,
            &artifact.policy_id,
            "",
            artifact.last_verification,
            at,
            artifact,
        ) {
            warn!(error = %err, "backup artifact not recorded");
        }
    }

    /// `backup_prune` under the backup's schedule binding (section 3.8).
    async fn prune(self: &Arc<Self>, policy: &PolicyDef, scheduled_for: i64, backup_id: &str) {
        let schedule = ScheduleRef {
            plan: policy.plan.clone(),
            scheduled_for: rfc(scheduled_for),
            attempt: 1,
        };
        match runner::run_scheduled(
            self.deps.runner.as_ref(),
            "backup_prune",
            &schedule,
            PRUNE_TIMEOUT,
        )
        .await
        {
            Ok(answer) => {
                let now = self.now();
                let deleted: Vec<String> = answer["deleted"]
                    .as_array()
                    .map(|ids| {
                        ids.iter()
                            .filter_map(Value::as_str)
                            .filter(|id| *id != backup_id)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                for id in &deleted {
                    if let Some(mut artifact) = self
                        .deps
                        .ops
                        .get(RecordKind::Artifact, id)
                        .and_then(|row| row.decode::<BackupArtifact>())
                        .filter(|a| a.policy_id == policy.resource_id)
                    {
                        artifact.expires_at = Some(pts(now));
                        self.put_artifact(&artifact);
                    }
                }
                self.log(
                    policy,
                    "",
                    LogLevel::Info,
                    &format!("backup prune removed {} artifact(s)", deleted.len()),
                );
            }
            Err(failure) => self.log(
                policy,
                "",
                LogLevel::Error,
                &format!("backup prune failed: {}: {}", failure.code, failure.message),
            ),
        }
    }

    fn start_verify(self: &Arc<Self>, policy: &PolicyDef, scheduled_for: i64) {
        let slot = rfc(scheduled_for);
        if self
            .deps
            .ops
            .has_slot(RecordKind::Verification, &policy.resource_id, &slot)
            || !self.state().verifying.insert(policy.resource_id.clone())
        {
            return;
        }
        let now = self.now();
        let verification = RestoreVerification {
            id: new_id(now),
            policy_id: policy.resource_id.clone(),
            status: RestoreVerificationStatus::Running as i32,
            started_at: Some(pts(now)),
            trigger: backup_run::Trigger::Schedule as i32,
            ..Default::default()
        };
        self.record_verification(&verification, &slot);
        self.log(
            policy,
            &verification.id,
            LogLevel::Info,
            &format!("verify-restore started for {slot}"),
        );
        let schedule = ScheduleRef {
            plan: policy.plan.clone(),
            scheduled_for: slot.clone(),
            attempt: 1,
        };
        let this = self.clone();
        let policy = policy.clone();
        let task = tokio::spawn(async move {
            let result = runner::run_scheduled(
                this.deps.runner.as_ref(),
                "backup_verify",
                &schedule,
                VERIFY_TIMEOUT,
            )
            .await;
            this.finish_verify(&policy, verification, &slot, result);
        });
        self.tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(task);
    }

    fn finish_verify(
        &self,
        policy: &PolicyDef,
        mut verification: RestoreVerification,
        slot: &str,
        result: Result<Value, RunnerFailure>,
    ) {
        let now = self.now();
        apply_verify_result(&mut verification, &result);
        verification.finished_at = Some(pts(now));
        self.record_verification(&verification, slot);
        self.state().verifying.remove(&policy.resource_id);
        if let Some(mut artifact) = self
            .deps
            .ops
            .get(RecordKind::Artifact, &verification.artifact_id)
            .and_then(|row| row.decode::<BackupArtifact>())
        {
            artifact.last_verification = verification.status;
            self.put_artifact(&artifact);
        }
        let passed = verification.status == RestoreVerificationStatus::Passed as i32;
        let message = if passed {
            "verify-restore passed".to_owned()
        } else {
            format!("verify-restore failed: {}", verification.error)
        };
        self.log(
            policy,
            &verification.id,
            if passed {
                LogLevel::Info
            } else {
                LogLevel::Error
            },
            &message,
        );
        self.report(
            policy,
            event_condition::Kind::RestoreVerificationFailed,
            !passed,
            &message,
        );
    }

    fn retries_due(self: &Arc<Self>, now: i64) {
        let due: Vec<Pending> = {
            let mut state = self.state();
            let (due, later): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut state.retries)
                .into_iter()
                .partition(|p| p.retry_at.is_some_and(|at| at <= now));
            state.retries = later;
            due
        };
        for mut pending in due {
            pending.retry_at = None;
            let slot = rfc(pending.scheduled_for);
            self.record_run(&pending.run, &slot);
            self.state().queue.push_back(pending);
        }
        self.next_backup();
    }

    /// Records manual `backup.run` / `backup.verify` plans (the executor
    /// runs them) and settles them when their action ends.
    fn reconcile_manual(&self, now: i64) {
        let Ok(actions) = self.deps.store.admitted_actions(MANUAL_KINDS) else {
            return;
        };
        let recent = actions
            .into_iter()
            .filter(|a| parse_rfc(&a.admitted_at).is_some_and(|at| at >= now - 7_200));
        for action in recent {
            let resource = action.params["resource_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let slot = format!("manual:{}:{}", action.plan_id, action.action_index);
            let started = parse_rfc(&action.admitted_at).map(pts);
            let finished = action.finished_at.as_deref().and_then(parse_rfc).map(pts);
            if action.kind == "backup.run" {
                let existing = self.manual_row(RecordKind::BackupRun, &resource, &slot);
                let mut run = match existing.and_then(|row| row.decode::<BackupRun>()) {
                    Some(run) if run.finished_at.is_some() => continue,
                    Some(run) => run,
                    None => BackupRun {
                        id: new_id(now),
                        policy_id: resource.clone(),
                        status: BackupRunStatus::Pending as i32,
                        trigger: backup_run::Trigger::Manual as i32,
                        started_at: started,
                        operation_id: action.operation_id.clone(),
                        ..Default::default()
                    },
                };
                run.status = match action.outcome.as_str() {
                    "" => BackupRunStatus::Dumping,
                    "succeeded" => BackupRunStatus::Succeeded,
                    "cancelled" => BackupRunStatus::Cancelled,
                    _ => BackupRunStatus::Failed,
                } as i32;
                if !action.outcome.is_empty() {
                    run.finished_at = finished.or(Some(pts(now)));
                }
                self.record_run(&run, &slot);
            } else {
                let existing = self.manual_row(RecordKind::Verification, &resource, &slot);
                let mut verification =
                    match existing.and_then(|row| row.decode::<RestoreVerification>()) {
                        Some(v) if v.finished_at.is_some() => continue,
                        Some(v) => v,
                        None => RestoreVerification {
                            id: new_id(now),
                            policy_id: resource.clone(),
                            artifact_id: action.params["backup_id"]
                                .as_str()
                                .unwrap_or_default()
                                .to_owned(),
                            status: RestoreVerificationStatus::Running as i32,
                            started_at: started,
                            trigger: backup_run::Trigger::Manual as i32,
                            operation_id: action.operation_id.clone(),
                            ..Default::default()
                        },
                    };
                verification.status = match action.outcome.as_str() {
                    "" => RestoreVerificationStatus::Running,
                    "succeeded" => RestoreVerificationStatus::Passed,
                    _ => RestoreVerificationStatus::Failed,
                } as i32;
                if !action.outcome.is_empty() {
                    verification.finished_at = finished.or(Some(pts(now)));
                }
                self.record_verification(&verification, &slot);
            }
        }
    }

    fn manual_row(
        &self,
        kind: RecordKind,
        resource: &str,
        slot: &str,
    ) -> Option<super::ops_store::Row> {
        self.deps
            .ops
            .list(
                kind,
                &Listing {
                    subject: Some(resource),
                    limit: 100,
                    ..Default::default()
                },
            )
            .into_iter()
            .find(|row| row.slot == slot)
    }

    /// The `BackupPolicy` view (section 10.2).
    pub fn policy_proto(&self, policy: &PolicyDef, defs: &Definitions) -> BackupPolicy {
        let now = self.now();
        let latest = |kind| {
            self.deps
                .ops
                .list(
                    kind,
                    &Listing {
                        subject: Some(&policy.resource_id),
                        limit: 1,
                        ..Default::default()
                    },
                )
                .into_iter()
                .next()
        };
        let mut recipients = vec![fingerprint(&self.server_recipient)];
        if let Some(recovery) = &defs.recovery_recipient {
            recipients.push(fingerprint(recovery));
        }
        BackupPolicy {
            id: policy.resource_id.clone(),
            name: policy.resource_id.clone(),
            scope: Some(scope_of(&policy.scope, &policy.resource_id)),
            source: Some(BackupSource {
                kind: backup_source::Kind::Postgres as i32,
                service_id: policy.resource_id.clone(),
                ..Default::default()
            }),
            destination: defs
                .destinations
                .get(&policy.destination_ref)
                .map(DestinationDef::proto),
            schedule: policy.schedule_text.clone(),
            timezone: policy.timezone_name.clone(),
            retention: Some(BackupRetention {
                keep_daily: policy.keep.0,
                keep_weekly: policy.keep.1,
                keep_monthly: policy.keep.2,
            }),
            age_recipients: recipients,
            verify_schedule: policy.verify_text.clone(),
            enabled: true,
            channel_ids: Vec::new(),
            next_run_at: match (&policy.schedule, &policy.timezone) {
                (Some(schedule), Some(tz)) => schedule
                    .next_after(tz, now.max(policy.active_from))
                    .map(pts),
                _ => None,
            },
            last_run: latest(RecordKind::BackupRun).and_then(|row| row.decode()),
            last_verification: latest(RecordKind::Verification).and_then(|row| row.decode()),
            plan_digest_hex: policy.plan.plan_digest_hex.clone(),
            timeout_seconds: 6 * 3_600,
            destination_id: policy.destination_ref.clone(),
        }
    }

    #[cfg(test)]
    pub async fn settle(&self) {
        loop {
            let tasks: Vec<JoinHandle<()>> =
                std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|p| p.into_inner()));
            if tasks.is_empty() {
                return;
            }
            for task in tasks {
                let _ = task.await;
            }
        }
    }

    pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(super::TICK_SECONDS));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                this.tick();
                this.tasks
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .retain(|task| !task.is_finished());
            }
        })
    }
}

fn apply_verify_result(
    verification: &mut RestoreVerification,
    result: &Result<Value, RunnerFailure>,
) {
    match result {
        Ok(answer) => {
            if let Some(id) = answer["backup_id"].as_str() {
                verification.artifact_id = id.chars().take(64).collect();
            }
            verification.checks = verify_checks(&answer["checks"]);
            let passed = answer["outcome"].as_str().unwrap_or("succeeded") == "succeeded"
                && verification.checks.iter().all(|c| c.passed);
            verification.status = if passed {
                RestoreVerificationStatus::Passed
            } else {
                RestoreVerificationStatus::Failed
            } as i32;
            if !passed {
                verification.error = verification
                    .checks
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                if verification.error.is_empty() {
                    verification.error = answer["outcome"].as_str().unwrap_or("failed").to_owned();
                }
            }
        }
        Err(failure) => {
            verification.status = RestoreVerificationStatus::Failed as i32;
            verification.error = format!("{}: {}", failure.code, failure.message);
        }
    }
}

/// `backup_verify` checks: the runner's object of booleans
/// (`{"plaintext_digest": true, …}`, jobs::backup) or a list of
/// `{name, passed, detail}`; at most 32.
fn verify_checks(checks: &Value) -> Vec<VerificationCheck> {
    let check = |name: &str, passed: bool, detail: &str| VerificationCheck {
        name: name.chars().take(128).collect(),
        passed,
        detail: detail.chars().take(256).collect(),
    };
    if let Some(map) = checks.as_object() {
        return map
            .iter()
            .take(32)
            .map(|(name, passed)| check(name, *passed == true, ""))
            .collect();
    }
    checks
        .as_array()
        .map(|checks| {
            checks
                .iter()
                .take(32)
                .map(|c| {
                    check(
                        c["name"].as_str().unwrap_or_default(),
                        c["passed"] == true,
                        c["detail"].as_str().unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
