//! Rule matching, on-server builds and rule deploys (agent-protocol.md 11.1
//! step 8, 11.2; signed-plan.md 3.5 steps 4–7, 14.10).
//!
//! For a verified push the agent picks the rules that match it (project,
//! repo, branch pattern, one of the delivery's environments, active, in
//! window, this server in scope, not protected, under the hourly limit),
//! skips a commit that is not newer than what the service runs (`IGNORED`),
//! builds each service of the rule on the server through the runner's
//! `build_image` (one build at a time, FIFO, at most 32 waiting), and
//! admits the rule plan through its own webhook path. The delivery ends
//! `DEPLOYED` or `FAILED`; a delivery no rule matched stays `PENDING`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde_json::{json, Value};

use super::plan::{build_rule_plan, RulePlanInput, ServiceBuild};
use super::{Hooks, MAX_QUEUED_BUILDS, STALE_SECONDS};
use crate::admissions::webhooks::DeliveryRow;
use crate::local::execution::Submission;
use crate::local::presence::AwayEvent;
use crate::local::sched::ops_store::{Listing, RecordKind};
use crate::local::sched::{new_id, pts, BuiltinEvent, LogIdentity};
use crate::proto::agent::v2::{
    event_condition, LogLevel, LogSourceType, Scope, ServerBuild, ServerBuildStatus,
    WebhookDeliveryStatus,
};
use crate::signed_plan::crypto::{hex, prefixed_digest, RULE_PREFIX};
use crate::signed_plan::jcs::{canonicalize, parse_strict};
use crate::signed_plan::text::timestamp;
use crate::signed_plan::trust::TrustState;
use crate::signed_plan::verify::Submitter;
use crate::signed_plan::PlanCode;

/// `ServerBuild.failure_reason` values (agent-protocol.md 11.2).
const FAILURE_REASONS: &[&str] = &[
    "source_fetch",
    "recipe_missing",
    "build",
    "timeout",
    "cache_full",
    "buildkit_unavailable",
    "build_queue_full",
];

/// An admitted, active rule as the pipeline uses it.
#[derive(Debug, Clone)]
pub struct ActiveRule {
    pub rule: Value,
    pub rule_digest_hex: String,
    pub created_plan_id: String,
}

fn ref_matches(r#ref: &str, pattern: &str) -> bool {
    r#ref == pattern
        || pattern.strip_suffix('*').is_some_and(|prefix| {
            pattern.ends_with("/*") && r#ref.starts_with(prefix) && r#ref.len() > prefix.len()
        })
}

fn contains(set: &Value, value: &str) -> bool {
    set.as_array()
        .is_some_and(|items| items.iter().any(|item| item == value))
}

/// signed-plan.md 6.1 step 12 (v1.0.11, D-061): a rule plan may be
/// admitted within 900 s of the delivery, or when the runner's build of the
/// commit started within 900 s of it and ended at most 900 s ago.
fn still_fresh(received: i64, started: Option<i64>, built: Option<i64>, now: i64) -> bool {
    now - received <= STALE_SECONDS
        || matches!((started, built), (Some(started), Some(built))
            if started - received <= STALE_SECONDS && now - built <= STALE_SECONDS)
}

/// How one rule ended for a delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleEnd {
    Deployed,
    Ignored(String),
    Stale,
    Failed(String),
}

/// A failed build: the reason (`ServerBuild.failure_reason`) and error.
struct BuildFailure {
    reason: String,
    error: String,
}

impl Hooks {
    /// The admitted rules a delivery matches (section 11.1 step 8), with
    /// the reason of the first rule a protected scope held back.
    fn matching_rules(&self, delivery: &DeliveryRow, project_id: &str) -> (Vec<ActiveRule>, bool) {
        let now = self.now();
        let (server_id, compromised) = match self.deps.core.trust.load() {
            TrustState::Valid(store) => (store.server_id.clone(), store.compromised.clone()),
            _ => return (Vec::new(), false),
        };
        let rules = match self.deps.store.rules(false, now) {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!(error = %err, "rules unavailable");
                return (Vec::new(), false);
            }
        };
        let mut matched = Vec::new();
        let mut protected = false;
        for info in rules {
            let Some(rule) = parse_strict(info.rule_jcs.as_bytes(), 64 * 1024) else {
                continue;
            };
            // The stored digest must be the rule's own (section 3.4).
            let digest = canonicalize(&rule).map(|text| hex(&prefixed_digest(RULE_PREFIX, &text)));
            if digest.as_deref() != Some(info.rule_digest_hex.as_str())
                || compromised.contains(&info.created_by_key_id)
            {
                continue;
            }
            let scope = &rule["scope"];
            let window = match (
                rule["not_before"].as_str().and_then(timestamp),
                rule["expires_at"].as_str().and_then(timestamp),
            ) {
                (Some(start), Some(end)) => start <= now && now <= end,
                _ => false,
            };
            let environment = scope["environment"].as_str().unwrap_or_default();
            let limit = rule["limits"]["max_invocations_per_hour"]
                .as_u64()
                .unwrap_or(0);
            let matches = rule["trigger"] == "git.push"
                && contains(&rule["allowed_kinds"], "deploy")
                && scope["project_id"] == project_id
                && scope["repo"] == delivery.repo.as_str()
                && contains(&scope["server_ids"], &server_id)
                && scope["branch_patterns"].as_array().is_some_and(|patterns| {
                    patterns
                        .iter()
                        .any(|p| ref_matches(&delivery.r#ref, p.as_str().unwrap_or_default()))
                })
                // contracts v1.1.0: a staging secret never triggers a
                // production rule.
                && delivery.environments.iter().any(|env| env == environment)
                && window
                && u64::from(info.invocations_last_hour) < limit;
            if !matches {
                continue;
            }
            if self
                .deps
                .store
                .scope_protected(project_id, environment)
                .unwrap_or(true)
            {
                protected = true;
                continue;
            }
            matched.push(ActiveRule {
                rule,
                rule_digest_hex: info.rule_digest_hex,
                created_plan_id: info.created_plan_id,
            });
        }
        (matched, protected)
    }

    /// Section 3.5 step 4: the pushed commit must differ from what each
    /// service runs on that ref and must not be older.
    fn commit_is_newer(&self, delivery: &DeliveryRow, services: &[String]) -> bool {
        let pushed = timestamp(&delivery.commit_time);
        services.iter().all(|service| {
            match self.deps.store.deployed_commit_on(service, &delivery.r#ref) {
                Ok(Some((sha, time))) => {
                    sha != delivery.commit_sha
                        && match (pushed, timestamp(&time)) {
                            (Some(pushed), Some(deployed)) => pushed >= deployed,
                            _ => false,
                        }
                }
                Ok(None) => true,
                Err(_) => false,
            }
        })
    }

    /// Matches a verified delivery and runs its rules.
    pub async fn process(self: &Arc<Self>, delivery_id: &str) {
        self.process_for(delivery_id, None).await;
    }

    /// Matches a verified delivery against every active rule, or (v1.1.4,
    /// D-062 re-match) against `only_rule` alone.
    async fn process_for(self: &Arc<Self>, delivery_id: &str, only_rule: Option<&str>) {
        let Ok(Some(delivery)) = self.deps.store.delivery_row(delivery_id) else {
            return;
        };
        if delivery.status != "pending"
            || timestamp(&delivery.expires_at).is_some_and(|expires| expires <= self.now())
        {
            return;
        }
        let Some(record) = self.delivery(delivery_id) else {
            return;
        };
        let received = timestamp(&delivery.received_at).unwrap_or(0);
        if self.now() - received > STALE_SECONDS {
            self.set_status(
                delivery_id,
                WebhookDeliveryStatus::Stale,
                "received more than 15 minutes ago",
                |_| {},
            );
            return;
        }
        let (mut rules, protected) = self.matching_rules(&delivery, &record.project_id);
        if let Some(only) = only_rule {
            rules.retain(|rule| rule.rule["id"] == only);
        }
        if rules.is_empty() {
            if protected {
                self.set_status(
                    delivery_id,
                    WebhookDeliveryStatus::Ignored,
                    "environment protected",
                    |_| {},
                );
            }
            // Otherwise it waits PENDING for the engine until it expires.
            return;
        }
        let mut ends = Vec::new();
        for rule in rules {
            let end = self.run_rule(&delivery, &record.project_id, &rule).await;
            ends.push(end);
        }
        let (status, reason) = if ends.contains(&RuleEnd::Deployed) {
            (WebhookDeliveryStatus::Deployed, String::new())
        } else if let Some(RuleEnd::Failed(reason)) =
            ends.iter().find(|e| matches!(e, RuleEnd::Failed(_)))
        {
            (WebhookDeliveryStatus::Failed, reason.clone())
        } else if ends.contains(&RuleEnd::Stale) {
            (
                WebhookDeliveryStatus::Stale,
                "received more than 15 minutes ago".to_owned(),
            )
        } else {
            let reason = ends
                .iter()
                .find_map(|e| match e {
                    RuleEnd::Ignored(reason) => Some(reason.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            (WebhookDeliveryStatus::Ignored, reason)
        };
        self.set_status(delivery_id, status, &reason, |_| {});
    }

    /// v1.1.4 (D-062, agent-protocol.md 11.1 step 9): once a `rule.create`
    /// is admitted, every unexpired `PENDING` delivery of the rule's project
    /// is re-matched against that rule, oldest `received_at` first; the
    /// evidence window still applies (an old one becomes `STALE`).
    pub fn rule_admitted(self: &Arc<Self>, rule_id: &str) {
        let Ok(rules) = self.deps.store.rules(false, self.now()) else {
            return;
        };
        let Some(project) = rules
            .iter()
            .find(|r| r.rule_id == rule_id)
            .and_then(|r| parse_strict(r.rule_jcs.as_bytes(), 64 * 1024))
            .and_then(|rule| rule["scope"]["project_id"].as_str().map(str::to_owned))
        else {
            return;
        };
        let mut pending: Vec<(i64, String)> = self
            .deps
            .ops
            .list(
                RecordKind::WebhookDelivery,
                &Listing {
                    subject: Some(&project),
                    statuses: &[WebhookDeliveryStatus::Pending as i32],
                    ascending: true,
                    limit: 10_000,
                    ..Default::default()
                },
            )
            .into_iter()
            .map(|row| (row.at, row.id))
            .collect();
        pending.sort();
        if pending.is_empty() {
            return;
        }
        let hooks = self.clone();
        let rule_id = rule_id.to_owned();
        self.spawn(async move {
            for (_, delivery_id) in pending {
                hooks.process_for(&delivery_id, Some(&rule_id)).await;
            }
        });
    }

    /// Builds and deploys one rule for a delivery.
    async fn run_rule(
        self: &Arc<Self>,
        delivery: &DeliveryRow,
        project_id: &str,
        rule: &ActiveRule,
    ) -> RuleEnd {
        let rule_id = rule.rule["id"].as_str().unwrap_or_default().to_owned();
        let mut services: Vec<String> = rule.rule["scope"]["service_ids"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        services.sort();
        services.dedup();
        if !self.commit_is_newer(delivery, &services) {
            return RuleEnd::Ignored("commit is not newer than the deployed one".to_owned());
        }
        let environment_id = match self
            .deps
            .store
            .admission_signed_scope(&rule.created_plan_id)
        {
            Ok(Some((_, _, environment_id))) => environment_id,
            _ => return RuleEnd::Failed("rule admission missing".to_owned()),
        };
        self.set_status(
            &delivery.delivery_id,
            WebhookDeliveryStatus::Building,
            "",
            |d| {
                d.standing_rule_id = rule_id.clone();
                d.attempts += 1;
            },
        );
        let platform = format!("linux/{}", self.deps.core.probe.server_facts().await.arch);
        // One ServerBuild per service, queued in order.
        let mut builds: Vec<ServerBuild> = services
            .iter()
            .map(|service| ServerBuild {
                id: new_id(self.now()),
                delivery_id: delivery.delivery_id.clone(),
                project_id: project_id.to_owned(),
                service_id: service.clone(),
                commit_sha: delivery.commit_sha.clone(),
                r#ref: delivery.r#ref.clone(),
                status: ServerBuildStatus::Queued as i32,
                started_at: Some(pts(self.now())),
                standing_rule_id: rule_id.clone(),
                platform: platform.clone(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .collect();
        for build in &builds {
            self.put_build(build);
        }
        let mut built = Vec::new();
        for index in 0..builds.len() {
            let service = services[index].clone();
            let last_spec = match self.deps.store.last_spec(&service) {
                Ok(Some(spec)) => spec,
                _ => {
                    self.fail_builds(
                        &mut builds[index..],
                        &BuildFailure {
                            reason: "recipe_missing".to_owned(),
                            error: "no admitted spec for the service".to_owned(),
                        },
                    );
                    return RuleEnd::Failed("recipe_missing".to_owned());
                }
            };
            match self
                .build_one(&mut builds[index], rule, delivery, &service)
                .await
            {
                Ok(image) => built.push(ServiceBuild {
                    service_id: service,
                    last_spec,
                    image_digest_hex: image,
                }),
                Err(failure) => {
                    self.fail_builds(&mut builds[index..], &failure);
                    let reason = if failure.reason.is_empty() {
                        failure.error
                    } else {
                        failure.reason
                    };
                    return RuleEnd::Failed(reason);
                }
            }
        }
        self.deploy(delivery, rule, &environment_id, &built, &mut builds)
            .await
    }

    /// Ends the remaining builds of a rule as failed.
    fn fail_builds(&self, builds: &mut [ServerBuild], failure: &BuildFailure) {
        for build in builds.iter_mut() {
            build.status = ServerBuildStatus::Failed as i32;
            build.failure_reason = failure.reason.clone();
            build.error = failure.error.clone();
            build.finished_at = Some(pts(self.now()));
            self.put_build(build);
        }
        if let Some(alerts) = &self.deps.alerts {
            let first = &builds[0];
            alerts.builtin(BuiltinEvent {
                kind: event_condition::Kind::WebhookBuildFailed,
                scope: Scope {
                    project_id: first.project_id.clone(),
                    environment_id: first.environment_id.clone(),
                    service_id: first.service_id.clone(),
                    ..Default::default()
                },
                source: "webhook",
                subject_id: first.standing_rule_id.clone(),
                occurred: true,
                standalone: false,
                channel_ids: Vec::new(),
                summary: format!("server build failed: {}", failure.reason),
            });
        }
    }

    /// Waits for the build slot and runs `build_image` for one service.
    async fn build_one(
        &self,
        build: &mut ServerBuild,
        rule: &ActiveRule,
        delivery: &DeliveryRow,
        service_id: &str,
    ) -> Result<String, BuildFailure> {
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= MAX_QUEUED_BUILDS {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(BuildFailure {
                reason: "build_queue_full".to_owned(),
                error: "32 builds are already queued".to_owned(),
            });
        }
        let permit = self.build_slot.acquire().await;
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        let Ok(_permit) = permit else {
            return Err(BuildFailure {
                reason: "buildkit_unavailable".to_owned(),
                error: "build slot closed".to_owned(),
            });
        };
        build.status = ServerBuildStatus::Building as i32;
        build.started_at = Some(pts(self.now()));
        self.put_build(build);
        let request = json!({"op": "build_image", "payload": {
            "rule_id": rule.rule["id"],
            "rule_digest_hex": rule.rule_digest_hex,
            "service_id": service_id,
            "commit_sha": delivery.commit_sha,
            "delivery_id": delivery.delivery_id,
            "body_digest_hex": delivery.body_digest_hex,
        }});
        let identity = LogIdentity {
            source: "build".to_owned(),
            project_id: build.project_id.clone(),
            environment: rule.rule["scope"]["environment"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            environment_id: build.environment_id.clone(),
            service_id: service_id.to_owned(),
            run_id: build.id.clone(),
        };
        let answer = self
            .deps
            .core
            .runner
            .exchange(request, self.timing.build_timeout)
            .await;
        let result = match answer {
            Ok(result) => result,
            Err(failure) => {
                let timeout = failure.message == crate::local::runner::TIMED_OUT;
                return Err(BuildFailure {
                    reason: if timeout {
                        "timeout"
                    } else {
                        "buildkit_unavailable"
                    }
                    .to_owned(),
                    error: failure.message,
                });
            }
        };
        for line in result["progress"].as_array().into_iter().flatten() {
            if let Some(text) = line.as_str() {
                self.deps
                    .logs
                    .write(LogSourceType::Build, LogLevel::Info, text, &identity);
            }
        }
        if result["ok"] != true {
            let error = &result["error"];
            let code = error["code"].as_str().unwrap_or("E_INTERNAL");
            let reason = error["failure_reason"]
                .as_str()
                .filter(|r| FAILURE_REASONS.contains(r))
                .unwrap_or_default()
                .to_owned();
            if reason == "buildkit_unavailable" {
                self.buildkit_ok.store(false, Ordering::SeqCst);
            }
            let message: String = error["message"]
                .as_str()
                .unwrap_or("build refused")
                .chars()
                .take(256)
                .collect();
            // agent-protocol.md 5.1: E_BUILD_FAILED is BUILD_FAILED (44).
            let reason_name = if code == "E_BUILD_FAILED" {
                crate::proto::agent::v2::ErrorReason::BuildFailed
            } else {
                crate::local::errors::reason_for(
                    PlanCode::parse(code).unwrap_or(PlanCode::Internal),
                )
            };
            let error = format!("{} ({code}): {message}", reason_name.as_str_name());
            self.deps
                .logs
                .write(LogSourceType::Build, LogLevel::Error, &error, &identity);
            return Err(BuildFailure { reason, error });
        }
        self.buildkit_ok.store(true, Ordering::SeqCst);
        let image = result["image_digest_hex"]
            .as_str()
            .filter(|d| crate::signed_plan::text::hex64(d))
            .map(str::to_owned);
        let runner_build = result["build_id"].as_str().unwrap_or_default().to_owned();
        let Some(image) = image else {
            return Err(BuildFailure {
                reason: "build".to_owned(),
                error: "the runner returned no image digest".to_owned(),
            });
        };
        let build_id = if crate::signed_plan::text::uuid7(&runner_build) {
            runner_build
        } else {
            build.id.clone()
        };
        // v1.0.11 (D-061): the build's start and end are the runner's
        // `build_started` and `build` lines, which anchor the evidence window.
        let (started_at, built_at) = self.runner_build_times(&build_id).await;
        if let Some(started) = started_at {
            self.deps.store.note_build_started(&build_id, started);
        }
        if let Err(err) = self.deps.store.record_build(
            &build_id,
            service_id,
            &delivery.commit_sha,
            &image,
            &delivery.delivery_id,
            built_at.unwrap_or_else(|| self.now()),
        ) {
            return Err(BuildFailure {
                reason: String::new(),
                error: format!("build not recorded: {err}"),
            });
        }
        build.image_digest_hex = image.clone();
        build.runner_build_id = if build_id == build.id {
            String::new()
        } else {
            build_id.clone()
        };
        build.status = ServerBuildStatus::Deploying as i32;
        self.put_build(build);
        Ok(image)
    }

    /// The `at` of the runner's `build_started` and `build` lines of
    /// `build_id` (Unix seconds), from its consumed log.
    async fn runner_build_times(&self, build_id: &str) -> (Option<i64>, Option<i64>) {
        let path = self.deps.core.consumed_log.clone();
        let owner = self.deps.core.consumed_log_owner;
        let wanted = build_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let at = |event: &str| {
                crate::admissions::event_lines(&path, owner, event)
                    .iter()
                    .rev()
                    .find(|line| line["build_id"] == wanted.as_str())
                    .and_then(|line| line["at"].as_str().and_then(timestamp))
            };
            (at("build_started"), at("build"))
        })
        .await
        .unwrap_or((None, None))
    }

    /// Builds, admits and follows the rule plan.
    async fn deploy(
        self: &Arc<Self>,
        delivery: &DeliveryRow,
        rule: &ActiveRule,
        environment_id: &str,
        built: &[ServiceBuild],
        builds: &mut [ServerBuild],
    ) -> RuleEnd {
        let now = self.now();
        let received = timestamp(&delivery.received_at).unwrap_or(0);
        let fail = |this: &Self, builds: &mut [ServerBuild], status, error: String| {
            for build in builds.iter_mut() {
                build.status = status as i32;
                build.error = error.clone();
                build.finished_at = Some(pts(this.now()));
                this.put_build(build);
            }
        };
        let windows: Vec<(Option<i64>, Option<i64>)> = built
            .iter()
            .map(|b| {
                self.deps
                    .store
                    .build_window_of(&b.service_id, &delivery.commit_sha)
            })
            .collect();
        if !windows
            .iter()
            .all(|(started, built_at)| still_fresh(received, *started, *built_at, now))
        {
            fail(
                self,
                builds,
                ServerBuildStatus::Failed,
                "delivery went stale during the build".to_owned(),
            );
            return RuleEnd::Stale;
        }
        let server_id = match self.deps.core.trust.load() {
            TrustState::Valid(store) => store.server_id.clone(),
            _ => return RuleEnd::Failed("trust store unavailable".to_owned()),
        };
        let scope = &rule.rule["scope"];
        let head = match self.deps.store.head(
            scope["project_id"].as_str().unwrap_or_default(),
            scope["environment"].as_str().unwrap_or_default(),
        ) {
            Ok(head) => head.head_digest_hex,
            Err(_) => return RuleEnd::Failed("state head unavailable".to_owned()),
        };
        let Some(plan) = build_rule_plan(&RulePlanInput {
            rule: &rule.rule,
            rule_digest_hex: &rule.rule_digest_hex,
            environment_id,
            server_id: &server_id,
            head: &head,
            delivery,
            services: built,
            now,
        }) else {
            return RuleEnd::Failed("rule plan not built".to_owned());
        };
        let submitted = self
            .deps
            .core
            .submit(
                Submission {
                    envelope: plan.envelope.clone(),
                    specs: plan.specs.clone(),
                    sealed_secrets: Vec::new(),
                },
                Submitter::AgentWebhook,
            )
            .await;
        let admission = match submitted {
            Ok(admission) => admission,
            Err(code) => {
                let reason = crate::local::errors::reason_for(code);
                let error = format!("{} ({})", reason.as_str_name(), code.as_str());
                fail(self, builds, ServerBuildStatus::Failed, error.clone());
                let stale = code == PlanCode::RuleEvidence && self.now() - received > STALE_SECONDS;
                return if stale {
                    RuleEnd::Stale
                } else {
                    RuleEnd::Failed(error)
                };
            }
        };
        self.away(AwayEvent::RuleDeploy);
        tracing::info!(
            plan_id = %plan.plan_id,
            delivery_id = %delivery.delivery_id,
            "rule plan admitted"
        );
        for build in builds.iter_mut() {
            build.operation_id = admission.operation_id.clone();
            build.deployment_id = plan
                .deployments
                .iter()
                .find(|(service, _)| *service == build.service_id)
                .map(|(_, id)| id.clone())
                .unwrap_or_default();
            self.put_build(build);
        }
        let plan_id = admission.plan_id.clone();
        let operation_id = admission.operation_id.clone();
        self.set_status(
            &delivery.delivery_id,
            WebhookDeliveryStatus::Building,
            "",
            |d| {
                d.operation_id = operation_id.clone();
                d.consumed = true;
                if !d.consumed_by_plan_ids.contains(&plan_id) {
                    d.consumed_by_plan_ids.push(plan_id.clone());
                }
                let rule_id = rule.rule["id"].as_str().unwrap_or_default().to_owned();
                if !d.consumed_by_rule_ids.contains(&rule_id) {
                    d.consumed_by_rule_ids.push(rule_id);
                }
            },
        );
        let outcome = self.wait_finished(&admission.plan_id).await;
        let (status, end) = match outcome.as_deref() {
            Some("succeeded") => (ServerBuildStatus::Succeeded, RuleEnd::Deployed),
            Some("rolled_back") => (
                ServerBuildStatus::RolledBack,
                RuleEnd::Failed("rolled_back".to_owned()),
            ),
            Some("cancelled") => (
                ServerBuildStatus::Cancelled,
                RuleEnd::Failed("cancelled".to_owned()),
            ),
            Some(other) => (ServerBuildStatus::Failed, RuleEnd::Failed(other.to_owned())),
            None => (
                ServerBuildStatus::Failed,
                RuleEnd::Failed("deploy did not finish".to_owned()),
            ),
        };
        for build in builds.iter_mut() {
            build.status = status as i32;
            build.finished_at = Some(pts(self.now()));
            if let RuleEnd::Failed(error) = &end {
                build.error = error.clone();
            }
            self.put_build(build);
        }
        end
    }

    /// Polls the admission until it finished; its outcome.
    async fn wait_finished(&self, plan_id: &str) -> Option<String> {
        let deadline = tokio::time::Instant::now() + self.timing.finish_wait;
        loop {
            if let Ok(Some(record)) = self.deps.store.admission(plan_id) {
                if record.finished_at.is_some() {
                    return Some(record.outcome);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(self.timing.finish_poll).await;
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::ref_matches;

    #[test]
    fn a_long_build_stays_fresh_when_it_started_in_time() {
        use super::still_fresh;
        let received = 1_000;
        assert!(still_fresh(received, None, None, received + 900));
        assert!(!still_fresh(received, None, None, received + 901));
        // A 25-minute build that started 60 s after the delivery.
        let (started, built) = (received + 60, received + 60 + 1_500);
        assert!(still_fresh(
            received,
            Some(started),
            Some(built),
            built + 10
        ));
        assert!(still_fresh(
            received,
            Some(started),
            Some(built),
            built + 900
        ));
        assert!(!still_fresh(
            received,
            Some(started),
            Some(built),
            built + 901
        ));
        // Started too late.
        assert!(!still_fresh(
            received,
            Some(received + 901),
            Some(received + 1_000),
            received + 1_000
        ));
    }

    #[test]
    fn branch_patterns_are_exact_or_a_prefix_with_one_more_character() {
        assert!(ref_matches("refs/heads/main", "refs/heads/main"));
        assert!(!ref_matches("refs/heads/main2", "refs/heads/main"));
        assert!(ref_matches("refs/heads/release/1", "refs/heads/release/*"));
        assert!(!ref_matches("refs/heads/release/", "refs/heads/release/*"));
        assert!(!ref_matches("refs/heads/releasex", "refs/heads/release/*"));
    }
}
