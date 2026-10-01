//! The cron scheduler (`cron.v1`, agent-protocol.md 10.1; signed-plan.md
//! 14.9).
//!
//! - A job is the latest recorded `cron.create`/`cron.update` of its
//!   `cron_id` (the runner wrote its `result succeeded`), until a recorded
//!   `cron.delete`; the latest recorded `cron.pause`/`cron.resume` says
//!   whether it is enabled. A resumed or changed job fires only after the
//!   change took effect (a paused period is never caught up).
//! - Each attempt is `run_cron` with a schedule binding: the definition
//!   action, the fire time and the attempt. Retries after `FAILED` or
//!   `TIMED_OUT` wait 10 s × 2^(attempt−1), capped at 600 s, and reuse the
//!   fire time. A scheduled attempt and its retries are one chain.
//! - Overlap: `skip` records `SKIPPED_OVERLAP` while a chain is active,
//!   `queue` keeps at most one chain `PENDING`, `allow` runs at most 4 per
//!   job. At most 8 cron containers run per server; later chains wait
//!   `PENDING` in start order.
//! - Missed runs: after downtime (a gap over 120 s since the checkpoint) the
//!   latest fire time within 120 s of now runs late and every other fire
//!   time in the gap becomes one `MISSED` run. A fire time that already has
//!   a run is never started again (backward clock jumps).
//! - Manual runs (`cron.run`, `RunCronJobNow`) are executed by the plan
//!   executor (`run_cron` with a plan binding); the scheduler records them
//!   and counts them for overlap.
//! - Heartbeat: a chain that ends `FAILED`/`TIMED_OUT` after its last retry,
//!   or a `MISSED` record, reports `CRON_FAILED`/`CRON_MISSED` (opening an
//!   alert of its own with `heartbeat_alert`); the next `SUCCEEDED` chain
//!   resolves it.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::tz::TimeZone;
use serde_json::Value;
use tokio::task::JoinHandle;
use tracing::warn;

use super::cron_expr::{timezone, CronExpr};
use super::ops_store::{Listing, RecordKind};
use super::{
    new_id, parse_rfc, pts, rfc, scope_of, AlertSink, BuiltinEvent, Deps, LogIdentity,
    DOWNTIME_SECONDS,
};
use crate::admissions::definitions::AdmittedAction;
use crate::local::runner::{self, PlanRef, RunnerFailure, ScheduleRef};
use crate::proto::agent::v2::{
    event, event_condition, CronJob, CronRun, CronRunStatus, CronTrigger, EventKind, LogLevel,
    LogSourceType, OverlapPolicy,
};

pub const CRON_KINDS: &[&str] = &[
    "cron.create",
    "cron.update",
    "cron.delete",
    "cron.pause",
    "cron.resume",
    "cron.run",
];
/// agent-protocol.md 10.1 (the 256-job limit is an admission check,
/// `definitions::MAX_CRON_JOBS`).
pub const MAX_RUNNING: usize = 8;
pub const MAX_ALLOWED_CHAINS: usize = 4;
const CHECKPOINT_KEY: &str = "cron_checkpoint";
/// The runner kills at `timeout_seconds` plus 10 s; the call waits longer.
const CALL_MARGIN_SECONDS: u64 = 60;
/// Missed fire times are counted up to this many.
const MISSED_COUNT_LIMIT: u32 = 100_000;
/// How long a run whose answer was lost waits for its `run_result`:
/// `cancel_running` stops the run within 30 s, then writes it (14.3).
#[cfg(not(test))]
const LOST_RESULT_WAIT: Duration = Duration::from_secs(40);
#[cfg(test)]
const LOST_RESULT_WAIT: Duration = Duration::from_millis(400);
const LOST_RESULT_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlap {
    Skip,
    Queue,
    Allow,
}

impl Overlap {
    fn parse(text: &str) -> Self {
        match text {
            "queue" => Self::Queue,
            "allow" => Self::Allow,
            _ => Self::Skip,
        }
    }

    pub fn proto(self) -> OverlapPolicy {
        match self {
            Self::Skip => OverlapPolicy::Skip,
            Self::Queue => OverlapPolicy::Queue,
            Self::Allow => OverlapPolicy::Allow,
        }
    }
}

/// A job as its recorded definition says.
#[derive(Debug, Clone)]
pub struct JobDef {
    pub cron_id: String,
    pub name: String,
    pub scope: (String, String, String),
    pub service_id: String,
    pub schedule_text: String,
    pub schedule: Option<CronExpr>,
    pub timezone_name: String,
    pub timezone: Option<TimeZone>,
    pub command: Vec<String>,
    pub timeout_seconds: u32,
    pub retries: u32,
    pub overlap: Overlap,
    pub heartbeat_alert: bool,
    pub plan: PlanRef,
    pub enabled: bool,
    /// Fire times after this only (the definition or resume took effect).
    pub active_from: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl JobDef {
    fn identity(&self, run_id: &str) -> LogIdentity {
        LogIdentity {
            source: format!(
                "cron:{}",
                if self.name.is_empty() {
                    &self.cron_id
                } else {
                    &self.name
                }
            ),
            project_id: self.scope.0.clone(),
            environment: self.scope.1.clone(),
            environment_id: self.scope.2.clone(),
            service_id: self.service_id.clone(),
            run_id: run_id.to_owned(),
        }
    }

    pub fn next_fire(&self, after: i64) -> Option<i64> {
        let (schedule, tz) = (self.schedule.as_ref()?, self.timezone.as_ref()?);
        schedule.next_after(tz, after.max(self.active_from))
    }
}

fn applied_at(action: &AdmittedAction) -> i64 {
    action
        .finished_at
        .as_deref()
        .and_then(parse_rfc)
        .or_else(|| parse_rfc(&action.admitted_at))
        .unwrap_or_default()
}

fn plan_ref(action: &AdmittedAction) -> PlanRef {
    PlanRef {
        plan_id: action.plan_id.clone(),
        plan_digest_hex: action.plan_digest_hex.clone(),
        action_index: u32::try_from(action.action_index).unwrap_or(u32::MAX),
    }
}

/// The jobs in force: recorded definitions only, oldest first.
pub fn load_jobs(actions: &[AdmittedAction]) -> BTreeMap<String, JobDef> {
    let mut jobs: BTreeMap<String, JobDef> = BTreeMap::new();
    for action in actions.iter().rev().filter(|a| a.succeeded()) {
        let params = &action.params;
        let Some(cron_id) = params["cron_id"].as_str() else {
            continue;
        };
        let at = applied_at(action);
        match action.kind.as_str() {
            "cron.create" | "cron.update" => {
                let previous = jobs.get(cron_id);
                if previous.is_some_and(|job| job.scope != action.scope) {
                    // Admission refuses this (scope binding); never trust it.
                    continue;
                }
                let text = |name: &str| params[name].as_str().unwrap_or_default().to_owned();
                let number = |name: &str| {
                    params[name]
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .unwrap_or_default()
                };
                let schedule_text = text("schedule");
                let timezone_name = text("timezone");
                jobs.insert(
                    cron_id.to_owned(),
                    JobDef {
                        cron_id: cron_id.to_owned(),
                        name: text("name"),
                        scope: action.scope.clone(),
                        service_id: text("service_id"),
                        schedule: CronExpr::parse(&schedule_text),
                        schedule_text,
                        timezone: timezone(&timezone_name),
                        timezone_name,
                        command: params["command"]
                            .as_array()
                            .map(|argv| {
                                argv.iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default(),
                        timeout_seconds: number("timeout_seconds"),
                        retries: number("retries"),
                        overlap: Overlap::parse(params["overlap"].as_str().unwrap_or_default()),
                        heartbeat_alert: params["heartbeat_alert"] == true,
                        plan: plan_ref(action),
                        enabled: previous.is_none_or(|job| job.enabled),
                        active_from: at,
                        created_at: previous.map_or(at, |job| job.created_at),
                        updated_at: at,
                    },
                );
            }
            "cron.delete" => {
                jobs.remove(cron_id);
            }
            "cron.pause" => {
                if let Some(job) = jobs.get_mut(cron_id) {
                    job.enabled = false;
                    job.updated_at = at;
                }
            }
            "cron.resume" => {
                if let Some(job) = jobs.get_mut(cron_id) {
                    job.enabled = true;
                    job.active_from = job.active_from.max(at);
                    job.updated_at = at;
                }
            }
            _ => {}
        }
    }
    jobs
}

/// Section 10.1 retry backoff: 10 s × 2^(attempt−1), at most 600 s.
pub fn backoff(attempt: u32) -> i64 {
    let exponent = attempt.saturating_sub(1).min(10);
    (10i64 << exponent).min(600)
}

/// An active chain: running, waiting for a retry, or waiting to start.
#[derive(Debug, Clone)]
struct Chain {
    cron_id: String,
    /// The current attempt's run.
    run: CronRun,
    /// A retry waits until this time.
    retry_at: Option<i64>,
    /// Waiting for a container slot (server limit) or the job (queue).
    waiting: bool,
}

#[derive(Default)]
struct State {
    jobs: BTreeMap<String, JobDef>,
    chains: HashMap<String, Chain>,
    running: usize,
    recovering: HashSet<String>,
    /// Chains waiting for a container slot, in start order.
    slots: VecDeque<String>,
    /// `queue` jobs: the one chain waiting for the active one to end.
    queued: HashMap<String, String>,
    /// Jobs whose failure or miss is reported and not yet resolved.
    failing: HashSet<String>,
}

pub struct CronScheduler {
    deps: Deps,
    alerts: Arc<dyn AlertSink>,
    state: Mutex<State>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl CronScheduler {
    pub fn new(deps: Deps, alerts: Arc<dyn AlertSink>) -> Arc<Self> {
        let scheduler = Arc::new(Self {
            deps,
            alerts,
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

    fn run_authority(&self, run: &CronRun) -> Option<PlanRef> {
        if let Some(intent) = self
            .deps
            .ops
            .scheduled_intent(RecordKind::CronRun, &run.id)
            .ok()?
        {
            return (intent.plan.plan_id == run.plan_id).then_some(intent.plan);
        }
        // Legacy and manual rows retain their original plan identity. Resolve
        // one exact recorded action for this cron, never the current definition.
        let actions = self
            .deps
            .store
            .admitted_actions(&["cron.create", "cron.update", "cron.run"])
            .ok()?;
        let mut matching = actions.into_iter().filter(|action| {
            action.plan_id == run.plan_id && action.params["cron_id"] == run.cron_id
        });
        let action = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        Some(plan_ref(&action))
    }

    fn original_job(&self, run: &CronRun) -> Option<JobDef> {
        let authority = self.run_authority(run)?;
        let actions = self
            .deps
            .store
            .admitted_actions(&["cron.create", "cron.update"])
            .ok()?;
        let action = actions
            .into_iter()
            .find(|action| plan_ref(action) == authority)?;
        load_jobs(&[action]).remove(&run.cron_id)
    }

    /// Reconcile interrupted runs from trusted consumed-log terminal evidence.
    /// Unknown outcomes retain their slot and count against overlap limits.
    fn recover(&self) {
        let statuses = [CronRunStatus::Running as i32, CronRunStatus::Pending as i32];
        let rows = self.deps.ops.list(
            RecordKind::CronRun,
            &Listing {
                statuses: &statuses,
                limit: 10_000,
                ..Default::default()
            },
        );
        let now = self.now();
        for row in rows {
            let Some(mut run) = row.decode::<CronRun>() else {
                continue;
            };
            if run.trigger == CronTrigger::Manual as i32 {
                // Manual runs are reconciled from their admission.
                continue;
            }
            {
                let state = self.state();
                if state.chains.contains_key(&run.id) && !state.recovering.contains(&run.id) {
                    continue;
                }
            }
            let result = self.deps.consumed_log.as_ref().and_then(|consumed| {
                let id = super::find_runner_run_id(
                    &consumed.run_lines("run_cron"),
                    &self.run_authority(&run)?,
                    run.scheduled_for.map(|t| t.seconds),
                    run.attempt,
                )?;
                run.runner_run_id = id.clone();
                crate::admissions::run_results(&consumed.path, consumed.owner_uid, "run_cron")
                    .into_iter()
                    .rev()
                    .find(|line| line["run_id"] == id)
            });
            if let Some(answer) = result {
                apply_result(&mut run, &Ok(answer));
                run.finished_at = Some(pts(now));
                if !self.save(&run, &row.slot) {
                    continue;
                }
                let mut state = self.state();
                if state.recovering.remove(&run.id) {
                    state.running = state.running.saturating_sub(1);
                }
                state.chains.remove(&run.id);
            } else {
                run.error = "Execution outcome requires reconciliation after restart".to_owned();
                if !self.save(&run, &row.slot) {
                    continue;
                }
                let mut state = self.state();
                if state.recovering.insert(run.id.clone()) {
                    state.running += 1;
                }
                state.chains.insert(
                    run.id.clone(),
                    Chain {
                        cron_id: run.cron_id.clone(),
                        run,
                        retry_at: None,
                        waiting: false,
                    },
                );
            }
        }
    }

    /// The jobs in force (reads the store).
    pub fn jobs(&self) -> BTreeMap<String, JobDef> {
        self.reload();
        self.state().jobs.clone()
    }

    fn reload(&self) -> bool {
        match self.deps.store.admitted_actions(CRON_KINDS) {
            Ok(actions) => {
                let jobs = load_jobs(&actions);
                let mut state = self.state();
                state.jobs = jobs;
                true
            }
            Err(err) => {
                warn!(error = %err, "cron definitions unreadable; refusing scheduled work");
                false
            }
        }
    }

    fn save(&self, run: &CronRun, slot: &str) -> bool {
        let at = run
            .scheduled_for
            .as_ref()
            .or(run.started_at.as_ref())
            .map_or_else(|| self.now(), |t| t.seconds);
        if let Err(err) = self.deps.ops.put(
            RecordKind::CronRun,
            &run.id,
            &run.cron_id,
            slot,
            run.status,
            at,
            run,
        ) {
            warn!(error = %err, "cron run not recorded");
            return false;
        }
        true
    }

    fn publish(&self, job: Option<&JobDef>, run: &CronRun) {
        let scope = job
            .map(|job| scope_of(&job.scope, &job.service_id))
            .unwrap_or_default();
        self.deps.events.publish(
            EventKind::CronRun,
            scope,
            event::Payload::CronRun(run.clone()),
        );
    }

    fn log(&self, job: &JobDef, run: &CronRun, level: LogLevel, message: &str) {
        self.deps
            .logs
            .write(LogSourceType::Cron, level, message, &job.identity(&run.id));
    }

    /// Records a run (and its event) in one step.
    fn record(&self, job: Option<&JobDef>, run: &CronRun) -> bool {
        let slot = run
            .scheduled_for
            .as_ref()
            .map(|t| rfc(t.seconds))
            .unwrap_or_default();
        if !self.save(run, &slot) {
            return false;
        }
        self.publish(job, run);
        true
    }

    /// One scheduler pass at the clock's now (every 10 s).
    pub fn tick(self: &Arc<Self>) {
        let now = self.now();
        let writes_before = self.deps.ops.failure_generation();
        if !self.reload() {
            return;
        }
        self.recover();
        if writes_before != self.deps.ops.failure_generation() {
            return;
        }
        let Ok(checkpoint) = self.deps.ops.try_meta(CHECKPOINT_KEY) else {
            return;
        };
        let checkpoint = match checkpoint {
            None => now,
            Some(value) => match value.parse::<i64>() {
                Ok(checkpoint) => checkpoint,
                Err(_) => {
                    tracing::error!("scheduler checkpoint is invalid; refusing execution");
                    return;
                }
            },
        };
        let from = checkpoint.min(now);
        let downtime = now - checkpoint > DOWNTIME_SECONDS;
        let jobs: Vec<JobDef> = self.state().jobs.values().cloned().collect();
        for job in &jobs {
            if job.enabled {
                self.fire_due(job, from, now, downtime);
            }
        }
        self.retries_due(now);
        self.reconcile_manual(now);
        self.note_runner_ids();
        if writes_before != self.deps.ops.failure_generation() {
            return;
        }
        if let Err(err) = self.deps.ops.try_set_meta(CHECKPOINT_KEY, &now.to_string()) {
            warn!(error = %err, "cron checkpoint not recorded");
        }
    }

    /// contracts v1.1.5 (D-063 #10): a running attempt takes the runner's
    /// `run_id` from its consumed-log `run` line, so the engine can cancel
    /// that one run (`cron.runs.cancel`) before it ends.
    fn note_runner_ids(&self) {
        let missing: Vec<(String, CronRun)> = self
            .state()
            .chains
            .iter()
            .filter(|(_, chain)| {
                chain.run.status == CronRunStatus::Running as i32
                    && chain.run.runner_run_id.is_empty()
                    && !chain.run.plan_id.is_empty()
            })
            .map(|(id, chain)| (id.clone(), chain.run.clone()))
            .collect();
        let Some(consumed) = self.deps.consumed_log.as_ref() else {
            return;
        };
        if missing.is_empty() {
            return;
        }
        let lines = consumed.run_lines("run_cron");
        for (chain_id, mut run) in missing {
            let scheduled_for = run.scheduled_for.map(|t| t.seconds);
            let Some(authority) = self.run_authority(&run) else {
                continue;
            };
            let Some(id) =
                super::find_runner_run_id(&lines, &authority, scheduled_for, run.attempt)
            else {
                continue;
            };
            run.runner_run_id = id;
            self.update_chain_run(&chain_id, &run);
            let slot = if run.trigger == CronTrigger::Manual as i32 {
                format!("manual:{}", run.plan_id)
            } else {
                scheduled_for.map(rfc).unwrap_or_default()
            };
            self.save(&run, &slot);
            let job = self.state().jobs.get(&run.cron_id).cloned();
            self.publish(job.as_ref(), &run);
        }
    }

    fn fire_due(self: &Arc<Self>, job: &JobDef, from: i64, now: i64, downtime: bool) {
        let (Some(schedule), Some(tz)) = (&job.schedule, &job.timezone) else {
            return;
        };
        let from = from.max(job.active_from);
        if !downtime {
            // A late tick (under 120 s): every fire time starts, in order.
            let (times, _) = schedule.fire_times(tz, from, now, 16, 16);
            for at in times {
                self.start_scheduled(job, at, now);
            }
            return;
        }
        let (first, count) = schedule.fire_times(tz, from, now, 1, MISSED_COUNT_LIMIT);
        let Some(&first) = first.first() else {
            return;
        };
        let latest = latest_before(schedule, tz, first, now);
        let runs_late = now - latest <= DOWNTIME_SECONDS;
        let missed = if runs_late { count - 1 } else { count };
        if missed > 0
            && !self
                .deps
                .ops
                .has_slot(RecordKind::CronRun, &job.cron_id, &rfc(first))
        {
            self.record_missed(job, first, missed, now);
        }
        if runs_late {
            self.start_scheduled(job, latest, now);
        }
    }

    fn record_missed(&self, job: &JobDef, scheduled_for: i64, count: u32, now: i64) {
        let run = CronRun {
            id: new_id(now),
            cron_id: job.cron_id.clone(),
            attempt: 1,
            trigger: CronTrigger::Schedule as i32,
            status: CronRunStatus::Missed as i32,
            scheduled_for: Some(pts(scheduled_for)),
            finished_at: Some(pts(now)),
            missed_count: count,
            plan_id: job.plan.plan_id.clone(),
            error: format!("the agent was not running at {count} scheduled time(s)"),
            ..Default::default()
        };
        self.record(Some(job), &run);
        self.log(
            job,
            &run,
            LogLevel::Warn,
            &format!(
                "cron job missed {count} scheduled run(s) from {}",
                rfc(scheduled_for)
            ),
        );
        self.report(job, event_condition::Kind::CronMissed, true, &run.error);
    }

    fn report(&self, job: &JobDef, kind: event_condition::Kind, occurred: bool, summary: &str) {
        let mut state = self.state();
        let was_failing = state.failing.contains(&job.cron_id);
        if occurred {
            state.failing.insert(job.cron_id.clone());
        } else if was_failing {
            state.failing.remove(&job.cron_id);
        } else {
            return;
        }
        drop(state);
        let kinds = if occurred {
            vec![kind]
        } else {
            vec![
                event_condition::Kind::CronFailed,
                event_condition::Kind::CronMissed,
            ]
        };
        for kind in kinds {
            self.alerts.builtin(BuiltinEvent {
                kind,
                scope: scope_of(&job.scope, &job.service_id),
                source: "cron_heartbeat",
                subject_id: job.cron_id.clone(),
                occurred,
                standalone: job.heartbeat_alert,
                channel_ids: Vec::new(),
                summary: summary.to_owned(),
            });
        }
    }

    /// Active chains of a job (running, waiting for a retry or a slot);
    /// `queue`d chains waiting for the job are not counted.
    fn active_chains(state: &State, cron_id: &str) -> usize {
        let queued = state.queued.get(cron_id);
        state
            .chains
            .iter()
            .filter(|(id, chain)| chain.cron_id == cron_id && Some(*id) != queued)
            .count()
    }

    fn start_scheduled(self: &Arc<Self>, job: &JobDef, scheduled_for: i64, now: i64) {
        if self
            .deps
            .ops
            .has_slot(RecordKind::CronRun, &job.cron_id, &rfc(scheduled_for))
        {
            return;
        }
        let run = CronRun {
            id: new_id(now),
            cron_id: job.cron_id.clone(),
            attempt: 1,
            trigger: CronTrigger::Schedule as i32,
            status: CronRunStatus::Pending as i32,
            scheduled_for: Some(pts(scheduled_for)),
            plan_id: job.plan.plan_id.clone(),
            ..Default::default()
        };
        match self.deps.ops.claim_scheduled(
            RecordKind::CronRun,
            &run.id,
            &run.cron_id,
            run.status,
            scheduled_for,
            &run,
            &ScheduleRef {
                plan: job.plan.clone(),
                scheduled_for: rfc(scheduled_for),
                attempt: run.attempt,
            },
        ) {
            Ok(true) => self.start_chain(job, run, now),
            Ok(false) => {}
            Err(err) => warn!(error = %err, "cron slot not committed; execution deferred"),
        }
    }

    /// The overlap policy (section 10.1) decides whether the chain starts,
    /// waits or is skipped.
    fn start_chain(self: &Arc<Self>, job: &JobDef, mut run: CronRun, now: i64) {
        if !self.record(Some(job), &run) {
            return;
        }
        let mut state = self.state();
        let active = Self::active_chains(&state, &job.cron_id);
        let skip = match job.overlap {
            Overlap::Skip => active > 0,
            Overlap::Queue => active > 0 && state.queued.contains_key(&job.cron_id),
            Overlap::Allow => active >= MAX_ALLOWED_CHAINS,
        };
        if skip {
            drop(state);
            run.status = CronRunStatus::SkippedOverlap as i32;
            run.finished_at = Some(pts(now));
            run.error = "overlap: a run of this job is still active".to_owned();
            self.record(Some(job), &run);
            self.log(
                job,
                &run,
                LogLevel::Info,
                "cron run skipped: a run of this job is still active",
            );
            return;
        }
        let chain_id = run.id.clone();
        state.chains.insert(
            chain_id.clone(),
            Chain {
                cron_id: job.cron_id.clone(),
                run: run.clone(),
                retry_at: None,
                waiting: true,
            },
        );
        if job.overlap == Overlap::Queue && active > 0 {
            state.queued.insert(job.cron_id.clone(), chain_id);
            drop(state);
            self.record(Some(job), &run);
            return;
        }
        state.slots.push_back(chain_id);
        drop(state);
        self.record(Some(job), &run);
        self.fill_slots();
    }

    /// Starts waiting chains while fewer than 8 cron containers run.
    fn fill_slots(self: &Arc<Self>) {
        loop {
            let mut state = self.state();
            if state.running >= MAX_RUNNING {
                return;
            }
            let Some(chain_id) = state.slots.pop_front() else {
                return;
            };
            let Some(cron_id) = state.chains.get(&chain_id).map(|c| c.cron_id.clone()) else {
                continue;
            };
            let Some(_) = state.jobs.get(&cron_id) else {
                // Deleted while waiting: the chain ends without running.
                let mut run = state
                    .chains
                    .get(&chain_id)
                    .map(|c| c.run.clone())
                    .unwrap_or_default();
                drop(state);
                run.status = CronRunStatus::Cancelled as i32;
                run.error = "the job was deleted before the run started".to_owned();
                run.finished_at = Some(pts(self.now()));
                if !self.record(None, &run) {
                    self.state().slots.push_front(chain_id);
                    return;
                }
                self.state().chains.remove(&chain_id);
                continue;
            };
            let Some(chain) = state.chains.get_mut(&chain_id) else {
                continue;
            };
            if !chain.waiting {
                continue;
            }
            let run = chain.run.clone();
            drop(state);
            let Some(job) = self.original_job(&run) else {
                self.state().slots.push_front(chain_id);
                return;
            };
            let mut state = self.state();
            if state.running >= MAX_RUNNING || !state.jobs.contains_key(&cron_id) {
                state.slots.push_front(chain_id);
                return;
            }
            let Some(chain) = state.chains.get_mut(&chain_id) else {
                continue;
            };
            if !chain.waiting {
                continue;
            }
            chain.waiting = false;
            state.running += 1;
            drop(state);
            self.launch(job, chain_id, run);
        }
    }

    fn launch(self: &Arc<Self>, job: JobDef, chain_id: String, mut run: CronRun) {
        let now = self.now();
        run.status = CronRunStatus::Running as i32;
        run.started_at = Some(pts(now));
        let schedule = ScheduleRef {
            plan: job.plan.clone(),
            scheduled_for: run
                .scheduled_for
                .as_ref()
                .map(|t| rfc(t.seconds))
                .unwrap_or_default(),
            attempt: run.attempt,
        };
        let persisted = self.deps.ops.put_scheduled_record(
            RecordKind::CronRun,
            &run.id,
            &run.cron_id,
            run.status,
            run.scheduled_for.as_ref().map_or(now, |t| t.seconds),
            &run,
            &schedule,
        );
        if persisted.is_err() {
            let mut state = self.state();
            state.running = state.running.saturating_sub(1);
            if let Some(chain) = state.chains.get_mut(&chain_id) {
                chain.waiting = true;
            }
            state.slots.push_front(chain_id);
            return;
        }
        self.publish(Some(&job), &run);
        self.update_chain_run(&chain_id, &run);
        self.log(
            &job,
            &run,
            LogLevel::Info,
            &format!(
                "cron run started: attempt {} for {}",
                run.attempt,
                run.scheduled_for
                    .as_ref()
                    .map(|t| rfc(t.seconds))
                    .unwrap_or_default()
            ),
        );
        let this = self.clone();
        let schedule = ScheduleRef {
            plan: job.plan.clone(),
            scheduled_for: run
                .scheduled_for
                .as_ref()
                .map(|t| rfc(t.seconds))
                .unwrap_or_default(),
            attempt: run.attempt,
        };
        let timeout =
            Duration::from_secs(u64::from(job.timeout_seconds) + 10 + CALL_MARGIN_SECONDS);
        let task = tokio::spawn(async move {
            let result =
                runner::run_scheduled(this.deps.runner.as_ref(), "run_cron", &schedule, timeout)
                    .await;
            let result = match result {
                Err(failure) => this.lost_answer(&run, failure).await,
                answered => answered,
            };
            this.finish(&job, &chain_id, run, result);
        });
        self.tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(task);
    }

    fn update_chain_run(&self, chain_id: &str, run: &CronRun) {
        if let Some(chain) = self.state().chains.get_mut(chain_id) {
            chain.run = run.clone();
        }
    }

    fn finish(
        self: &Arc<Self>,
        job: &JobDef,
        chain_id: &str,
        mut run: CronRun,
        result: Result<Value, RunnerFailure>,
    ) {
        let now = self.now();
        if run.runner_run_id.is_empty() {
            // Learned from the `run` line while the attempt was in flight.
            if let Some(chain) = self.state().chains.get(chain_id) {
                run.runner_run_id = chain.run.runner_run_id.clone();
            }
        }
        let retryable = apply_result(&mut run, &result);
        run.finished_at = Some(pts(now));
        let still_defined = self.state().jobs.contains_key(&job.cron_id);
        let retry = retryable && still_defined && run.attempt <= job.retries;
        if retry {
            run.next_retry_at = Some(pts(now + backoff(run.attempt)));
        }
        if !self.record(Some(job), &run) {
            self.state().recovering.insert(chain_id.to_owned());
            return;
        }
        {
            let mut state = self.state();
            state.running = state.running.saturating_sub(1);
            if retry {
                if let Some(chain) = state.chains.get_mut(chain_id) {
                    chain.retry_at = Some(now + backoff(run.attempt));
                    chain.run = run.clone();
                }
            }
        }
        let status = CronRunStatus::try_from(run.status).unwrap_or(CronRunStatus::Failed);
        let level = if status == CronRunStatus::Succeeded {
            LogLevel::Info
        } else {
            LogLevel::Error
        };
        let mut message = format!("cron run {}: attempt {}", status_word(status), run.attempt);
        if run.exit_code != 0 {
            message.push_str(&format!(", exit code {}", run.exit_code));
        }
        if !run.error.is_empty() {
            message.push_str(&format!(": {}", run.error));
        }
        if retry {
            message.push_str(&format!(", retry in {} s", backoff(run.attempt)));
        }
        self.log(job, &run, level, &message);
        if !retry {
            self.end_chain(job, chain_id, &run);
        }
        self.fill_slots();
    }

    fn end_chain(self: &Arc<Self>, job: &JobDef, chain_id: &str, run: &CronRun) {
        {
            let mut state = self.state();
            state.chains.remove(chain_id);
            if Self::active_chains(&state, &job.cron_id) == 0 {
                if let Some(next) = state.queued.remove(&job.cron_id) {
                    state.slots.push_back(next);
                }
            }
        }
        match CronRunStatus::try_from(run.status) {
            Ok(CronRunStatus::Succeeded) => {
                self.report(job, event_condition::Kind::CronFailed, false, "succeeded");
            }
            Ok(CronRunStatus::Failed | CronRunStatus::TimedOut) => {
                let summary = if run.error.is_empty() {
                    format!("cron job failed after {} attempt(s)", run.attempt)
                } else {
                    format!(
                        "cron job failed after {} attempt(s): {}",
                        run.attempt, run.error
                    )
                };
                self.report(job, event_condition::Kind::CronFailed, true, &summary);
            }
            _ => {}
        }
    }

    fn retries_due(self: &Arc<Self>, now: i64) {
        let due: Vec<(String, Chain)> = {
            let state = self.state();
            state
                .chains
                .iter()
                .filter(|(_, chain)| chain.retry_at.is_some_and(|at| at <= now))
                .map(|(id, chain)| (id.clone(), chain.clone()))
                .collect()
        };
        for (chain_id, chain) in due {
            let job = self.state().jobs.get(&chain.cron_id).cloned();
            let Some(_) = job.filter(|job| job.enabled) else {
                // Deleted or paused: no retry follows (section 10.1).
                self.state().chains.remove(&chain_id);
                continue;
            };
            let Some(job) = self.original_job(&chain.run) else {
                continue;
            };
            let run = CronRun {
                id: new_id(now),
                cron_id: job.cron_id.clone(),
                attempt: chain.run.attempt + 1,
                trigger: CronTrigger::Retry as i32,
                status: CronRunStatus::Pending as i32,
                scheduled_for: chain.run.scheduled_for,
                plan_id: job.plan.plan_id.clone(),
                ..Default::default()
            };
            if !self.record(Some(&job), &run) {
                continue;
            }
            {
                let mut state = self.state();
                if let Some(chain) = state.chains.get_mut(&chain_id) {
                    chain.retry_at = None;
                    chain.waiting = true;
                    chain.run = run.clone();
                }
                state.slots.push_back(chain_id);
            }
            self.record(Some(&job), &run);
        }
        self.fill_slots();
    }

    /// Records the manual runs (`cron.run` admissions) and settles them
    /// when their action ends.
    fn reconcile_manual(self: &Arc<Self>, now: i64) {
        let Ok(actions) = self.deps.store.admitted_actions(&["cron.run"]) else {
            return;
        };
        let jobs = self.state().jobs.clone();
        // A persisted unfinished manual run survives any downtime. The age
        // window only bounds creating history for admissions without a row.
        let statuses = [CronRunStatus::Running as i32, CronRunStatus::Pending as i32];
        let mut unfinished: HashMap<_, _> = self
            .deps
            .ops
            .list(
                RecordKind::CronRun,
                &Listing {
                    statuses: &statuses,
                    limit: 10_000,
                    ..Default::default()
                },
            )
            .into_iter()
            .filter(|row| {
                row.decode::<CronRun>()
                    .is_some_and(|run| run.trigger == CronTrigger::Manual as i32)
            })
            .map(|row| ((row.subject.clone(), row.slot.clone()), row))
            .collect();
        for action in actions {
            let cron_id = action.params["cron_id"].as_str().unwrap_or_default();
            let slot = format!("manual:{}", action.plan_id);
            let recorded = unfinished.remove(&(cron_id.to_owned(), slot.clone()));
            let recent = parse_rfc(&action.admitted_at).is_some_and(|at| at >= now - 7_200);
            if recorded.is_none() && !recent {
                continue;
            }
            let existing = recorded.or_else(|| {
                self.deps
                    .ops
                    .list(
                        RecordKind::CronRun,
                        &Listing {
                            subject: Some(cron_id),
                            limit: 50,
                            ..Default::default()
                        },
                    )
                    .into_iter()
                    .find(|row| row.slot == slot)
            });
            let mut run = match existing {
                Some(row) => match row.decode::<CronRun>() {
                    Some(run) if !is_final(run.status) => run,
                    _ => continue,
                },
                // Submitted through SubmitSignedPlan, or before a restart.
                None => manual_run(&action, now),
            };
            let job = jobs.get(cron_id);
            if action.outcome.is_empty() {
                if run.status == CronRunStatus::Pending as i32 {
                    run.status = CronRunStatus::Running as i32;
                    run.started_at = Some(pts(now));
                    if !self.save(&run, &slot) {
                        continue;
                    }
                    self.publish(job, &run);
                }
                self.state().chains.entry(run.id.clone()).or_insert(Chain {
                    cron_id: cron_id.to_owned(),
                    run: run.clone(),
                    retry_at: None,
                    waiting: false,
                });
                continue;
            }
            run.status = match action.outcome.as_str() {
                "succeeded" => CronRunStatus::Succeeded,
                "cancelled" => CronRunStatus::Cancelled,
                _ => CronRunStatus::Failed,
            } as i32;
            // The runner's run_result line of this action carries the exit
            // code, output size, container and a `timeout` outcome
            // (signed-plan.md 14.8), as its answer does for a scheduled run.
            if action.outcome != "cancelled" {
                if let Some(line) = self.manual_result(&action) {
                    apply_result(&mut run, &Ok(line));
                }
            }
            run.finished_at = Some(pts(action
                .finished_at
                .as_deref()
                .and_then(parse_rfc)
                .unwrap_or(now)));
            if !self.save(&run, &slot) {
                continue;
            }
            self.publish(job, &run);
            self.state().chains.remove(&run.id);
            if let Some(job) = job {
                self.end_chain(job, &run.id.clone(), &run);
            }
        }
        self.fill_slots();
    }

    /// The runner's `run_result` line of a plan-bound `run_cron` action,
    /// read with the consumed-log trust checks.
    fn manual_result(&self, action: &AdmittedAction) -> Option<Value> {
        let consumed = self.deps.consumed_log.as_ref()?;
        crate::admissions::run_results(&consumed.path, consumed.owner_uid, "run_cron")
            .into_iter()
            .rev()
            .find(|line| {
                line["plan_id"] == action.plan_id.as_str()
                    && line["plan_digest_hex"] == action.plan_digest_hex.as_str()
                    && line["action_index"].as_u64() == u64::try_from(action.action_index).ok()
            })
    }

    /// A scheduled run whose `run_cron` call ended without a `result` line:
    /// `cancel_running` stops the runner process that holds the run, then
    /// writes the run's `run_result` (signed-plan.md 14.3), which is its end.
    /// Waits up to [`LOST_RESULT_WAIT`] for that line of the attempt the
    /// runner started (read with the consumed-log trust checks); a run the
    /// runner never started, or no line in time, keeps the failure.
    async fn lost_answer(
        &self,
        run: &CronRun,
        failure: RunnerFailure,
    ) -> Result<Value, RunnerFailure> {
        let Some(consumed) = self.deps.consumed_log.clone() else {
            return Err(failure);
        };
        let scheduled_for = run.scheduled_for.as_ref().map(|t| t.seconds);
        let deadline = tokio::time::Instant::now() + LOST_RESULT_WAIT;
        loop {
            let lines = consumed.run_lines("run_cron");
            let Some(authority) = self.run_authority(run) else {
                return Err(failure);
            };
            let Some(run_id) =
                super::find_runner_run_id(&lines, &authority, scheduled_for, run.attempt)
            else {
                return Err(failure);
            };
            let result =
                crate::admissions::run_results(&consumed.path, consumed.owner_uid, "run_cron")
                    .into_iter()
                    .rev()
                    .find(|line| line["run_id"] == run_id.as_str());
            if let Some(line) = result {
                return Ok(line);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failure);
            }
            tokio::time::sleep(LOST_RESULT_POLL).await;
        }
    }

    /// `RunCronJobNow` (section 10.1): the overlap policy applies to manual
    /// chains too. A manual chain cannot wait (the plan executes at
    /// admission), so `queue` behaves like `skip` while a chain is active.
    pub fn manual_allowed(&self, cron_id: &str) -> Result<(), &'static str> {
        self.reload();
        let state = self.state();
        let Some(job) = state.jobs.get(cron_id) else {
            return Err("unknown cron job");
        };
        let active = Self::active_chains(&state, cron_id);
        let limit = match job.overlap {
            Overlap::Allow => MAX_ALLOWED_CHAINS,
            Overlap::Skip | Overlap::Queue => 1,
        };
        if active >= limit {
            return Err("overlap: a run of this job is still active");
        }
        Ok(())
    }

    /// Records the manual run of an admitted `cron.run` plan and counts it
    /// as an active chain until its action ends.
    pub fn record_manual(&self, cron_id: &str, plan_id: &str, operation_id: &str) -> CronRun {
        let now = self.now();
        let slot = format!("manual:{plan_id}");
        if let Some(run) = self
            .deps
            .ops
            .list(
                RecordKind::CronRun,
                &Listing {
                    subject: Some(cron_id),
                    limit: 50,
                    ..Default::default()
                },
            )
            .into_iter()
            .find(|row| row.slot == slot)
            .and_then(|row| row.decode::<CronRun>())
        {
            return run;
        }
        let run = CronRun {
            id: new_id(now),
            cron_id: cron_id.to_owned(),
            attempt: 1,
            trigger: CronTrigger::Manual as i32,
            status: CronRunStatus::Running as i32,
            started_at: Some(pts(now)),
            operation_id: operation_id.to_owned(),
            plan_id: plan_id.to_owned(),
            ..Default::default()
        };
        self.save(&run, &slot);
        let job = self.state().jobs.get(cron_id).cloned();
        self.publish(job.as_ref(), &run);
        self.state().chains.insert(
            run.id.clone(),
            Chain {
                cron_id: cron_id.to_owned(),
                run: run.clone(),
                retry_at: None,
                waiting: false,
            },
        );
        run
    }

    /// A skipped manual request is recorded too.
    pub fn record_skipped_manual(&self, cron_id: &str, reason: &str) -> CronRun {
        let now = self.now();
        let run = CronRun {
            id: new_id(now),
            cron_id: cron_id.to_owned(),
            attempt: 1,
            trigger: CronTrigger::Manual as i32,
            status: CronRunStatus::SkippedOverlap as i32,
            started_at: Some(pts(now)),
            finished_at: Some(pts(now)),
            error: reason.to_owned(),
            ..Default::default()
        };
        self.save(&run, "");
        let job = self.state().jobs.get(cron_id).cloned();
        self.publish(job.as_ref(), &run);
        run
    }

    /// The `CronJob` view of a job (section 10.1).
    pub fn job_proto(&self, job: &JobDef) -> CronJob {
        let now = self.now();
        let last_run = self
            .deps
            .ops
            .list(
                RecordKind::CronRun,
                &Listing {
                    subject: Some(&job.cron_id),
                    limit: 1,
                    ..Default::default()
                },
            )
            .first()
            .and_then(|row| row.decode::<CronRun>());
        CronJob {
            id: job.cron_id.clone(),
            name: job.name.clone(),
            scope: Some(scope_of(&job.scope, &job.service_id)),
            schedule: job.schedule_text.clone(),
            timezone: job.timezone_name.clone(),
            overlap: job.overlap.proto() as i32,
            enabled: job.enabled,
            next_run_at: job.enabled.then(|| job.next_fire(now)).flatten().map(pts),
            last_run,
            created_at: Some(pts(job.created_at)),
            updated_at: Some(pts(job.updated_at)),
            plan_digest_hex: job.plan.plan_digest_hex.clone(),
            retries: job.retries,
            heartbeat_alert: job.heartbeat_alert,
            service_id: job.service_id.clone(),
            command: job.command.clone(),
            timeout_seconds: job.timeout_seconds,
        }
    }

    /// Waits for every started run task (tests and shutdown).
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

    /// Waits for the oldest started run task only.
    #[cfg(test)]
    pub async fn settle_one(&self) {
        let task = {
            let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
            (!tasks.is_empty()).then(|| tasks.remove(0))
        };
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    /// Ticks every 10 s until the task is aborted.
    pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(super::TICK_SECONDS));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                this.tick();
                this.deps.ops.prune(this.now());
                this.tasks
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .retain(|task| !task.is_finished());
            }
        })
    }
}

/// The last fire time at or before `now`, starting from `first`.
fn latest_before(schedule: &CronExpr, tz: &TimeZone, first: i64, now: i64) -> i64 {
    let mut latest = first;
    while let Some(next) = schedule.next_after(tz, latest) {
        if next > now {
            break;
        }
        latest = next;
    }
    latest
}

fn manual_run(action: &AdmittedAction, now: i64) -> CronRun {
    CronRun {
        id: new_id(now),
        cron_id: action.params["cron_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        attempt: 1,
        trigger: CronTrigger::Manual as i32,
        status: CronRunStatus::Pending as i32,
        started_at: parse_rfc(&action.admitted_at).map(pts),
        operation_id: action.operation_id.clone(),
        plan_id: action.plan_id.clone(),
        ..Default::default()
    }
}

fn is_final(status: i32) -> bool {
    !matches!(
        CronRunStatus::try_from(status),
        Ok(CronRunStatus::Pending | CronRunStatus::Running)
    )
}

fn status_word(status: CronRunStatus) -> &'static str {
    match status {
        CronRunStatus::Succeeded => "succeeded",
        CronRunStatus::Failed => "failed",
        CronRunStatus::TimedOut => "timed out",
        CronRunStatus::Cancelled => "cancelled",
        CronRunStatus::SkippedOverlap => "skipped",
        CronRunStatus::Missed => "missed",
        _ => "ended",
    }
}

/// Applies a `run_cron` answer to the run. Returns whether a retry may
/// follow: only a run the runner accepted and that ended `failed` or
/// `timeout` (signed-plan.md 14.9 check 7 refuses any other retry).
fn apply_result(run: &mut CronRun, result: &Result<Value, RunnerFailure>) -> bool {
    match result {
        Ok(answer) => {
            if let Some(id) = super::runner_run_id_of(answer) {
                run.runner_run_id = id;
            }
            run.exit_code = answer["exit_code"]
                .as_i64()
                .and_then(|code| i32::try_from(code).ok())
                .unwrap_or_default();
            run.output_bytes = answer["output_bytes"].as_u64().unwrap_or_default();
            if let Some(name) = answer["container_name"].as_str() {
                run.container_name = name.chars().take(128).collect();
            }
            let (status, retryable) = match answer["outcome"].as_str().unwrap_or("succeeded") {
                "succeeded" => (CronRunStatus::Succeeded, false),
                "failed" => (CronRunStatus::Failed, true),
                "timeout" => (CronRunStatus::TimedOut, true),
                "cancelled" => (CronRunStatus::Cancelled, false),
                "skipped" => (CronRunStatus::SkippedOverlap, false),
                _ => (CronRunStatus::Failed, false),
            };
            run.status = status as i32;
            retryable
        }
        Err(failure) => {
            run.status = CronRunStatus::Failed as i32;
            run.error = format!("{}: {}", failure.code, failure.message);
            false
        }
    }
}

#[cfg(test)]
mod tests;
