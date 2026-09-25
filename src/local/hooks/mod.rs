//! Webhook intake and on-server builds (agent-protocol.md 11,
//! `webhooks.v1`, D-050, D-056, D-057).
//!
//! - Intake (11.1): Dwaar forwards `POST /hooks/<project_id>` to
//!   `127.0.0.1:7461` ([`listener`]); the agent caps the body at 1 MiB,
//!   applies the pre-authentication budget, and hands the raw delivery to
//!   the runner's `webhook_verify`, which holds the per-environment secrets
//!   (the agent never does, D-027) and parses the verified push itself.
//!   Unauthenticated deliveries leave only a digest in
//!   `rejected_deliveries`; verified ones count against the deploy budget,
//!   are deduplicated by body digest and recorded in `deliveries`.
//! - Match and build (11.1 step 8, 11.2): rules of the delivery's project
//!   whose repo, branch patterns and environment match, one build at a time
//!   through the runner's `build_image` (the signed recipe, the runner's own
//!   `delivery` line); then the rule plan ([`plan`]) is admitted through
//!   the agent's webhook path (`submitter = agent_webhook`) and executed.
//! - Nothing from the webhook body or the agent chooses what is built or
//!   deployed: the runner re-checks the rule, its own evidence and the
//!   recipe, and `prepare_release` accepts only its own build's image.

pub mod intake;
pub mod limits;
pub mod listener;
pub mod pipeline;
pub mod plan;
pub mod rpc;

#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::json;
use tokio::task::JoinHandle;

use super::events::EventBus;
use super::execution::{ChangeCore, Clock};
use super::presence::{AwayEvent, Presence};
use super::sched::ops_store::{OpsStore, RecordKind};
use super::sched::{pts, AgentLogs, AlertSink};
use crate::admissions::AdmissionStore;
use crate::proto::agent::v2::{
    event, EventKind, Scope, ServerBuild, ServerBuildStatus, WebhookDelivery, WebhookDeliveryStatus,
};

/// agent-protocol.md 2 (v2.1.0).
pub const CAPABILITY_WEBHOOKS: &str = "webhooks.v1";
/// agent-protocol.md 11.1 step 1.
pub const LISTEN_ADDR: &str = "127.0.0.1:7461";
/// Webhook body cap (agent-protocol.md 7, signed-plan.md 3.5 step 1).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// A verified delivery no rule consumed stays `PENDING` this long (11.1).
pub const PENDING_TTL_SECONDS: i64 = 7 * 86_400;
/// A delivery older than this never backs a plan (`STALE`).
pub const STALE_SECONDS: i64 = 900;
/// One build at a time per server, at most 32 queued (11.2).
pub const MAX_QUEUED_BUILDS: usize = 32;
/// `build_image` runs at most 30 min; the agent waits a little longer.
pub const BUILD_TIMEOUT: Duration = Duration::from_secs(1_800 + 60);
/// agent-protocol.md 8 (D-066 #5): how often the agent asks the runner's
/// `diagnose` check `buildkit_apparmor`.
pub const BUILDKIT_CHECK_EVERY: Duration = Duration::from_secs(60);
const BUILDKIT_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything the webhook path needs.
#[derive(Clone)]
pub struct HookDeps {
    pub store: Arc<AdmissionStore>,
    pub ops: Arc<OpsStore>,
    pub core: Arc<ChangeCore>,
    pub events: EventBus,
    pub clock: Arc<dyn Clock>,
    pub logs: AgentLogs,
    pub presence: Option<Arc<Presence>>,
    /// Built-in `WEBHOOK_BUILD_FAILED` events (the alert evaluator).
    pub alerts: Option<Arc<dyn AlertSink>>,
}

/// Tunables (tests shorten them).
#[derive(Debug, Clone, Copy)]
pub struct HookTiming {
    /// How often a rule plan's admission is checked until it finishes.
    pub finish_poll: Duration,
    /// How long the agent follows a rule plan's execution.
    pub finish_wait: Duration,
    pub build_timeout: Duration,
}

impl Default for HookTiming {
    fn default() -> Self {
        Self {
            finish_poll: Duration::from_secs(2),
            finish_wait: Duration::from_secs(
                u64::try_from(crate::admissions::EXECUTION_WINDOW_SECONDS).unwrap_or(3_600) + 300,
            ),
            build_timeout: BUILD_TIMEOUT,
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    /// When each duplicate arrived (last 24 h).
    duplicates: VecDeque<i64>,
    unknown_project: u64,
    oversize: u64,
    rate_limited: u64,
}

/// The webhook path, shared by the listener, the pipeline and the RPCs.
pub struct Hooks {
    pub deps: HookDeps,
    pub timing: HookTiming,
    pre_auth: limits::Budget,
    deploys: limits::Budget,
    counters: Mutex<Counters>,
    /// The single build slot (FIFO) and the builds waiting for it.
    build_slot: tokio::sync::Semaphore,
    waiting: AtomicUsize,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Tests only: verified deliveries wait here instead of being matched.
    hold: AtomicBool,
    held: Mutex<Vec<String>>,
    /// Whether `buildkitd` looked usable at the last build (status).
    buildkit_ok: AtomicBool,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks").finish()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

impl Hooks {
    pub fn new(deps: HookDeps, timing: HookTiming) -> Arc<Self> {
        Arc::new(Self {
            deps,
            timing,
            pre_auth: limits::Budget::pre_auth(),
            deploys: limits::Budget::deploy(),
            counters: Mutex::new(Counters::default()),
            build_slot: tokio::sync::Semaphore::new(1),
            waiting: AtomicUsize::new(0),
            tasks: Mutex::new(Vec::new()),
            hold: AtomicBool::new(false),
            held: Mutex::new(Vec::new()),
            buildkit_ok: AtomicBool::new(true),
        })
    }

    pub fn now(&self) -> i64 {
        self.deps.clock.now()
    }

    fn away(&self, event: AwayEvent) {
        if let Some(presence) = &self.deps.presence {
            presence.record(event);
        }
    }

    /// Builds waiting for the build slot (`builds_queued`).
    pub fn builds_queued(&self) -> u32 {
        u32::try_from(self.waiting.load(std::sync::atomic::Ordering::SeqCst)).unwrap_or(u32::MAX)
    }

    /// Whether on-server builds look possible (`server_builds_enabled`):
    /// false while the runner's `diagnose` check `buildkit_apparmor` reads
    /// `absent`, or after a build failed with `buildkit_unavailable`.
    pub fn server_builds_enabled(&self) -> bool {
        self.buildkit_ok.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// agent-protocol.md 8 (contracts v1.1.8/v1.1.9, D-066 #5, D-067 #6):
    /// asks the runner's read-only `diagnose` for `buildkit_apparmor`;
    /// `loaded` enables server builds, `absent` disables them (degraded
    /// reason `buildkit_unavailable`). A refusal or a malformed answer (an
    /// older runner) leaves the state as it is.
    pub async fn check_buildkit(&self) {
        let request = json!({"op": "diagnose", "payload": {"checks": ["buildkit_apparmor"]}});
        let answer = self
            .deps
            .core
            .runner
            .exchange(request, BUILDKIT_CHECK_TIMEOUT)
            .await;
        let loaded = match answer {
            Ok(result) if result["ok"] == true => match result["buildkit_apparmor"].as_str() {
                Some("loaded") => true,
                Some("absent") => false,
                _ => return,
            },
            Ok(_) | Err(_) => return,
        };
        let was = self
            .buildkit_ok
            .swap(loaded, std::sync::atomic::Ordering::SeqCst);
        if was != loaded {
            if loaded {
                tracing::info!("buildkit_apparmor loaded: server builds enabled");
            } else {
                tracing::warn!(
                    "buildkit_apparmor absent: server builds need AppArmor with the \
                     permanu-buildkitd profile loaded (buildkit_unavailable)"
                );
            }
        }
    }

    /// Runs [`Self::check_buildkit`] at start and every 60 s.
    pub fn spawn_buildkit_watch(self: &Arc<Self>) -> JoinHandle<()> {
        let hooks = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(BUILDKIT_CHECK_EVERY);
            loop {
                tick.tick().await;
                hooks.check_buildkit().await;
            }
        })
    }

    /// `WebhookQueueStatus.webhook_host` (v2.1.3, D-061): the latest
    /// `webhook.host.set` whose action succeeded on this server; `""` before
    /// one.
    pub fn webhook_host(&self) -> String {
        self.deps
            .store
            .admitted_actions(&["webhook.host.set"])
            .unwrap_or_default()
            .into_iter()
            .find(|action| action.succeeded())
            .and_then(|action| action.params["webhook_host"].as_str().map(str::to_owned))
            .unwrap_or_default()
    }

    /// `WebhookQueueStatus.pending`.
    pub fn pending(&self) -> u32 {
        self.deps.ops.count(
            RecordKind::WebhookDelivery,
            &[WebhookDeliveryStatus::Pending as i32],
            None,
        )
    }

    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(task);
        let mut tasks = locked(&self.tasks);
        tasks.retain(|t| !t.is_finished());
        tasks.push(handle);
    }

    /// Waits for every started pipeline task (tests and shutdown).
    #[cfg(test)]
    pub async fn settle(&self) {
        loop {
            let tasks: Vec<JoinHandle<()>> = std::mem::take(&mut *locked(&self.tasks));
            if tasks.is_empty() {
                return;
            }
            for task in tasks {
                let _ = task.await;
            }
        }
    }

    /// Tests: park verified deliveries until [`Hooks::release`].
    #[cfg(test)]
    pub fn hold(&self, hold: bool) {
        self.hold.store(hold, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub fn release(self: &Arc<Self>) {
        self.hold(false);
        for id in std::mem::take(&mut *locked(&self.held)) {
            let hooks = self.clone();
            self.spawn(async move { hooks.process(&id).await });
        }
    }

    /// Queues a verified delivery for matching.
    fn enqueue(self: &Arc<Self>, delivery_id: String) {
        if self.hold.load(std::sync::atomic::Ordering::SeqCst) {
            locked(&self.held).push(delivery_id);
            return;
        }
        let hooks = self.clone();
        self.spawn(async move { hooks.process(&delivery_id).await });
    }

    /// Stores a delivery record and emits `WEBHOOK_RECEIVED`.
    fn put_delivery(&self, delivery: &WebhookDelivery) {
        let at = delivery.received_at.as_ref().map_or(0, |t| t.seconds);
        if let Err(err) = self.deps.ops.put(
            RecordKind::WebhookDelivery,
            &delivery.id,
            &delivery.project_id,
            "",
            delivery.status,
            at,
            delivery,
        ) {
            tracing::warn!(error = %err, "webhook delivery record not stored");
        }
        self.deps.events.publish(
            EventKind::WebhookReceived,
            Scope {
                project_id: delivery.project_id.clone(),
                ..Default::default()
            },
            event::Payload::Webhook(delivery.clone()),
        );
    }

    pub fn delivery(&self, delivery_id: &str) -> Option<WebhookDelivery> {
        self.deps
            .ops
            .get(RecordKind::WebhookDelivery, delivery_id)
            .and_then(|row| row.decode())
    }

    /// Updates a stored delivery's status (and the `deliveries` row).
    fn set_status(
        &self,
        delivery_id: &str,
        status: WebhookDeliveryStatus,
        reason: &str,
        update: impl FnOnce(&mut WebhookDelivery),
    ) {
        let Some(mut delivery) = self.delivery(delivery_id) else {
            return;
        };
        delivery.status = status as i32;
        if !reason.is_empty() {
            delivery.status_reason = reason.to_owned();
        }
        if matches!(
            status,
            WebhookDeliveryStatus::Deployed
                | WebhookDeliveryStatus::Failed
                | WebhookDeliveryStatus::Ignored
                | WebhookDeliveryStatus::Stale
                | WebhookDeliveryStatus::Expired
        ) {
            delivery.processed_at = Some(pts(self.now()));
        }
        update(&mut delivery);
        let row_status = match status {
            WebhookDeliveryStatus::Pending => "pending",
            WebhookDeliveryStatus::Building => "building",
            WebhookDeliveryStatus::Deployed => "deployed",
            WebhookDeliveryStatus::Ignored => "ignored",
            WebhookDeliveryStatus::Stale => "stale",
            WebhookDeliveryStatus::Expired => "expired",
            _ => "failed",
        };
        if let Err(err) = self.deps.store.set_delivery_status(delivery_id, row_status) {
            tracing::warn!(error = %err, "deliveries row not updated");
        }
        self.put_delivery(&delivery);
    }

    pub fn build(&self, build_id: &str) -> Option<ServerBuild> {
        self.deps
            .ops
            .get(RecordKind::ServerBuild, build_id)
            .and_then(|row| row.decode())
    }

    /// Stores a server build record and emits `SERVER_BUILD`.
    fn put_build(&self, build: &ServerBuild) {
        let at = build.started_at.as_ref().map_or(0, |t| t.seconds);
        if let Err(err) = self.deps.ops.put(
            RecordKind::ServerBuild,
            &build.id,
            &build.project_id,
            "",
            build.status,
            at,
            build,
        ) {
            tracing::warn!(error = %err, "server build record not stored");
        }
        if build.status == ServerBuildStatus::Failed as i32 {
            self.away(AwayEvent::ServerBuildFailed);
        }
        self.deps.events.publish(
            EventKind::ServerBuild,
            Scope {
                project_id: build.project_id.clone(),
                environment_id: build.environment_id.clone(),
                service_id: build.service_id.clone(),
                deployment_id: build.deployment_id.clone(),
                ..Default::default()
            },
            event::Payload::ServerBuild(build.clone()),
        );
    }

    /// `duplicates_24h` (the last 24 hours).
    pub fn duplicates_24h(&self) -> u32 {
        let now = self.now();
        let mut counters = locked(&self.counters);
        while counters
            .duplicates
            .front()
            .is_some_and(|at| now - at >= 86_400)
        {
            counters.duplicates.pop_front();
        }
        u32::try_from(counters.duplicates.len()).unwrap_or(u32::MAX)
    }

    /// Counts a body over 1 MiB (answered 413 before it was read).
    pub fn count_oversize(&self) {
        locked(&self.counters).oversize += 1;
    }

    #[cfg(test)]
    pub fn counters(&self) -> (u64, u64, u64) {
        let counters = locked(&self.counters);
        (
            counters.unknown_project,
            counters.oversize,
            counters.rate_limited,
        )
    }

    /// Expires pending deliveries past their TTL (11.1 step 9) and prunes
    /// old rows; runs every minute.
    pub fn sweep(&self) {
        let now = self.now();
        match self.deps.store.expire_deliveries(now) {
            Ok(expired) => {
                for id in expired {
                    self.set_status(&id, WebhookDeliveryStatus::Expired, "expired", |_| {});
                }
            }
            Err(err) => tracing::warn!(error = %err, "delivery expiry failed"),
        }
    }

    /// v1.1.4 (D-062): re-matches pending deliveries whenever the executor
    /// applies an admitted `rule.create` (its `TrustChanged` event). After a
    /// missed event every active rule is re-matched (idempotent: only
    /// `PENDING` deliveries are touched).
    pub fn spawn_rule_watch(self: &Arc<Self>) -> JoinHandle<()> {
        let hooks = self.clone();
        let mut live = self.deps.events.live();
        tokio::spawn(async move {
            loop {
                match live.recv().await {
                    Ok(event) => {
                        if let Some(event::Payload::TrustChanged(change)) = &event.payload {
                            if change.change == "rule.create" {
                                hooks.rule_admitted(&change.subject_id);
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let now = hooks.now();
                        for rule in hooks.deps.store.rules(false, now).unwrap_or_default() {
                            hooks.rule_admitted(&rule.rule_id);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        })
    }

    /// The sweeper loop.
    pub fn spawn_sweeper(self: &Arc<Self>) -> JoinHandle<()> {
        let hooks = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                hooks.sweep();
            }
        })
    }
}
