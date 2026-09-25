//! Webhook intake to rule deploy against the fake runner (agent-protocol.md
//! 11; signed-plan.md 3.5, 14.3, 14.10): forged HMAC, replay, stale,
//! oversize, revoked rule, unknown project, other-environment secret,
//! protected scope, build failure, budgets, the listener and the RPCs.

use std::sync::Arc;

use hyper::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::intake::HookRequest;
use super::Hooks;
use crate::admissions::definitions::tests::{record, ENV_ID, PROJECT};
use crate::admissions::webhooks::seed;
use crate::local::test_harness::{hmac_sha256_hex, Harness, Options};
use crate::proto::agent::v2::{
    webhook_service_client::WebhookServiceClient, GetWebhookQueueStatusRequest,
    ListServerBuildsRequest, ListWebhookDeliveriesRequest, ServerBuildStatus,
    WebhookDeliveryStatus,
};
use crate::signed_plan::test_support::vector;

const SERVICE: &str = "01a0cdb5-3500-70c1-8000-000000000001";
const SECRET: &[u8] = b"production-webhook-secret";
const STAGING_SECRET: &[u8] = b"staging-webhook-secret";
const COMMIT: &str = "4f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39";

struct Fixture {
    h: Harness,
    hooks: Arc<Hooks>,
    rule_plan: String,
}

fn context() -> Value {
    vector("policy-cases")["context"].clone()
}

/// A server with the vector trust file, the rule "auto-deploy main to
/// production" admitted, the service's last admitted spec and the
/// production webhook secret held by the runner.
async fn fixture(name: &str) -> Fixture {
    let f = fixture_without_rule(name).await;
    let rule_plan = admit_rule(&f.h);
    Fixture { rule_plan, ..f }
}

/// Records the vector rule's `rule.create` admission (seq 1) and its row.
fn admit_rule(h: &Harness) -> String {
    let store = h.core.store.clone();
    let context = context();
    let rule = &context["rules"][0];
    let rule_plan = record(
        &store,
        1,
        (PROJECT, "production", ENV_ID),
        &[json!({"kind": "rule.create", "params": {"rule": rule["rule"]}})],
        "succeeded",
    );
    seed::rule(
        &store,
        &rule["rule"],
        rule["rule_digest_hex"].as_str().unwrap(),
        rule["created_by_key_id"].as_str().unwrap(),
        &rule_plan,
    );
    rule_plan
}

/// [`fixture`] before its rule is admitted.
async fn fixture_without_rule(name: &str) -> Fixture {
    let trust = serde_json::to_string(&vector("trusted-keys")).unwrap();
    let h = Harness::with(
        name,
        Options {
            trust: Some(trust),
            webhooks: true,
            ..Default::default()
        },
    )
    .await;
    let store = h.core.store.clone();
    let context = context();
    let scope = (PROJECT, "production", ENV_ID);
    let spec_plan = record(
        &store,
        2,
        scope,
        &[json!({"kind": "deploy", "params": {"service_id": SERVICE}})],
        "succeeded",
    );
    seed::spec(&store, &context["admitted_specs"][SERVICE], &spec_plan);
    h.runner.webhook_secrets.lock().unwrap().insert(
        PROJECT.to_owned(),
        vec![("production".to_owned(), SECRET.to_vec())],
    );
    let hooks = h.hooks.clone().unwrap();
    Fixture {
        h,
        hooks,
        rule_plan: String::new(),
    }
}

fn push_body(r#ref: &str, commit: &str) -> Vec<u8> {
    json!({"ref": r#ref, "after": commit,
           "repository": {"html_url": "https://github.com/acme/web"},
           "head_commit": {"timestamp": "2026-09-23T10:04:00Z"}})
    .to_string()
    .into_bytes()
}

fn github(body: &[u8], secret: &[u8], ip: &str) -> HookRequest {
    let mut headers = HeaderMap::new();
    headers.insert("x-github-event", HeaderValue::from_static("push"));
    headers.insert(
        "x-hub-signature-256",
        HeaderValue::from_str(&format!("sha256={}", hmac_sha256_hex(secret, body))).unwrap(),
    );
    headers.insert("x-github-delivery", HeaderValue::from_static("gh-1"));
    headers.insert("x-real-ip", HeaderValue::from_str(ip).unwrap());
    HookRequest {
        method: "POST".to_owned(),
        path: format!("/hooks/{PROJECT}"),
        headers,
        body: body.to_vec(),
    }
}

fn build_requests(h: &Harness) -> Vec<Value> {
    h.runner
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["op"] == "build_image")
        .cloned()
        .collect()
}

fn rejected_rows(h: &Harness) -> Vec<(String, u64, String, String)> {
    let conn = rusqlite::Connection::open(h.dir.join("agent/admissions.db")).unwrap();
    let mut statement = conn
        .prepare("SELECT body_digest_hex, body_bytes, project_id, reason FROM rejected_deliveries")
        .unwrap();
    statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn only_delivery(hooks: &Hooks) -> crate::proto::agent::v2::WebhookDelivery {
    let rows = hooks.deps.ops.list(
        crate::local::sched::ops_store::RecordKind::WebhookDelivery,
        &Default::default(),
    );
    assert_eq!(rows.len(), 1, "one delivery recorded");
    hooks.delivery(&rows[0].id).unwrap()
}

#[tokio::test]
async fn a_verified_push_builds_on_the_server_and_admits_the_rule_plan() {
    let f = fixture("hooks-deploy").await;
    let body = push_body("refs/heads/main", COMMIT);
    let answer = f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    assert_eq!(answer.status, 202);
    f.hooks.settle().await;

    let delivery = only_delivery(&f.hooks);
    assert_eq!(
        delivery.status,
        WebhookDeliveryStatus::Deployed as i32,
        "{delivery:?}"
    );
    assert_eq!(delivery.delivery_ref, "gh-1");
    assert_eq!(delivery.environments, vec!["production"]);
    assert_eq!(
        delivery.standing_rule_id,
        "01a0cdb5-3500-70f1-8000-000000000001"
    );
    assert!(delivery.consumed);

    // The runner built exactly the pinned payload, never from the body.
    let builds = build_requests(&f.h);
    assert_eq!(builds.len(), 1);
    let payload = &builds[0]["payload"];
    assert_eq!(payload["service_id"], SERVICE);
    assert_eq!(payload["commit_sha"], COMMIT);
    assert_eq!(payload["delivery_id"], delivery.id.as_str());
    assert_eq!(
        payload["body_digest_hex"],
        delivery.body_digest_hex.as_str()
    );
    assert_eq!(
        payload["rule_digest_hex"],
        context()["rules"][0]["rule_digest_hex"]
    );

    // The rule plan: admitted through the webhook path, author rule,
    // environment id copied from the rule's admission, image = the build.
    let record =
        f.h.core
            .store
            .admission_by_operation(&delivery.operation_id)
            .unwrap()
            .unwrap();
    assert_eq!(record.submitter, "agent_webhook");
    assert_eq!(record.author_kind, "rule");
    assert_eq!(record.environment_id, ENV_ID);
    assert_eq!(record.outcome, "succeeded");
    let envelope: Value = serde_json::from_str(&record.signed_plan_json).unwrap();
    let plan = &envelope["plan"];
    assert_eq!(
        plan["invocation"]["evidence"]["delivery_id"],
        delivery.id.as_str()
    );
    assert_ne!(plan["id"], f.rule_plan.as_str());
    let spec = f.h.core.store.last_spec(SERVICE).unwrap().unwrap();
    assert_eq!(spec.spec["image_digest_hex"], "e".repeat(64));
    let ops = f.h.runner.ops_for(plan["id"].as_str().unwrap());
    assert!(
        ops.iter().any(|(op, _)| op == "activate_release"),
        "{ops:?}"
    );

    let server_builds = f.hooks.deps.ops.list(
        crate::local::sched::ops_store::RecordKind::ServerBuild,
        &Default::default(),
    );
    assert_eq!(server_builds.len(), 1);
    let build = f.hooks.build(&server_builds[0].id).unwrap();
    assert_eq!(build.status, ServerBuildStatus::Succeeded as i32);
    assert_eq!(build.image_digest_hex, "e".repeat(64));
    assert_eq!(build.platform, "linux/arm64");
    // v2.1.3 (D-061): the runner's build id beside the agent-minted id.
    let runner_log = std::fs::read_to_string(&f.h.runner.log).unwrap();
    let build_line = runner_log
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|l| l["event"] == "build")
        .unwrap();
    assert_eq!(
        build.runner_build_id,
        build_line["build_id"].as_str().unwrap()
    );
    assert_ne!(build.runner_build_id, build.id);
    assert_eq!(build.environment_id, ENV_ID);
    assert_eq!(
        build.deployment_id,
        plan["actions"][0]["params"]["deployment_id"]
            .as_str()
            .unwrap()
    );
    f.h.stop().await;
}

#[tokio::test]
async fn a_forged_signature_is_401_and_only_its_digest_is_kept() {
    let f = fixture("hooks-forged").await;
    let body = push_body("refs/heads/main", COMMIT);
    let answer = f
        .hooks
        .intake(github(&body, b"not-the-secret", "203.0.113.9"))
        .await;
    assert_eq!(answer.status, 401);
    f.hooks.settle().await;
    let rows = rejected_rows(&f.h);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, body.len() as u64);
    assert_eq!(rows[0].2, PROJECT);
    assert_eq!(rows[0].3, "signature");
    assert!(build_requests(&f.h).is_empty());
    let mut client = WebhookServiceClient::new(f.h.channel.clone());
    let status = client
        .get_webhook_queue_status(GetWebhookQueueStatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.rejected_24h, 1);
    assert_eq!(status.pending, 0);
    // A missing signature header is the same 401.
    let mut unsigned = github(&body, SECRET, "203.0.113.9");
    unsigned.headers.remove("x-hub-signature-256");
    assert_eq!(f.hooks.intake(unsigned).await.status, 401);
    assert_eq!(rejected_rows(&f.h)[1].3, "malformed");
    f.h.stop().await;
}

#[tokio::test]
async fn an_unknown_project_gets_the_same_401_and_leaves_no_row() {
    let f = fixture("hooks-unknown").await;
    let body = push_body("refs/heads/main", COMMIT);
    let mut request = github(&body, SECRET, "203.0.113.9");
    request.path = "/hooks/01a0cdb5-3500-70b1-8000-0000000000ff".to_owned();
    let answer = f.hooks.intake(request).await;
    assert_eq!(
        answer,
        super::intake::HookResponse {
            status: 401,
            body: "unauthorized\n"
        }
    );
    assert!(rejected_rows(&f.h).is_empty());
    assert_eq!(f.hooks.counters().0, 1);
    f.h.stop().await;
}

#[tokio::test]
async fn a_replayed_delivery_is_a_duplicate_and_builds_nothing_twice() {
    let f = fixture("hooks-replay").await;
    let body = push_body("refs/heads/main", COMMIT);
    assert_eq!(
        f.hooks
            .intake(github(&body, SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.hooks.settle().await;
    let replay = f.hooks.intake(github(&body, SECRET, "198.51.100.7")).await;
    assert_eq!((replay.status, replay.body), (200, "duplicate\n"));
    f.hooks.settle().await;
    assert_eq!(build_requests(&f.h).len(), 1);
    assert_eq!(f.hooks.duplicates_24h(), 1);
    only_delivery(&f.hooks);
    f.h.stop().await;
}

#[tokio::test]
async fn a_delivery_matched_after_15_minutes_is_stale() {
    let f = fixture("hooks-stale").await;
    f.hooks.hold(true);
    let body = push_body("refs/heads/main", COMMIT);
    assert_eq!(
        f.hooks
            .intake(github(&body, SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.h.clock
        .0
        .fetch_add(901, std::sync::atomic::Ordering::SeqCst);
    f.hooks.release();
    f.hooks.settle().await;
    let delivery = only_delivery(&f.hooks);
    assert_eq!(delivery.status, WebhookDeliveryStatus::Stale as i32);
    assert!(build_requests(&f.h).is_empty());
    f.h.stop().await;
}

#[tokio::test]
async fn an_oversize_body_is_413_and_never_verified() {
    let f = fixture("hooks-oversize").await;
    let body = vec![b'x'; super::MAX_BODY_BYTES + 1];
    let answer = f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    assert_eq!(answer.status, 413);
    assert_eq!(f.hooks.counters().1, 1);
    assert!(!f
        .h
        .runner
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["op"] == "webhook_verify"));
    f.h.stop().await;
}

#[tokio::test]
async fn a_revoked_rule_never_builds_and_the_delivery_waits_pending() {
    let f = fixture("hooks-revoked").await;
    seed::revoke_rule(
        &f.h.core.store,
        "01a0cdb5-3500-70f1-8000-000000000001",
        "2026-09-23T10:01:00Z",
    );
    let body = push_body("refs/heads/main", COMMIT);
    assert_eq!(
        f.hooks
            .intake(github(&body, SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.hooks.settle().await;
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Pending as i32
    );
    assert!(build_requests(&f.h).is_empty());
    // Seven days later it expires.
    f.h.clock.0.fetch_add(
        super::PENDING_TTL_SECONDS,
        std::sync::atomic::Ordering::SeqCst,
    );
    f.hooks.sweep();
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Expired as i32
    );
    f.h.stop().await;
}

#[tokio::test]
async fn a_staging_secret_never_triggers_the_production_rule() {
    let f = fixture("hooks-staging").await;
    f.h.runner.webhook_secrets.lock().unwrap().insert(
        PROJECT.to_owned(),
        vec![
            ("production".to_owned(), SECRET.to_vec()),
            ("staging".to_owned(), STAGING_SECRET.to_vec()),
        ],
    );
    let body = push_body("refs/heads/main", COMMIT);
    assert_eq!(
        f.hooks
            .intake(github(&body, STAGING_SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.hooks.settle().await;
    let delivery = only_delivery(&f.hooks);
    assert_eq!(delivery.environments, vec!["staging"]);
    assert_eq!(delivery.status, WebhookDeliveryStatus::Pending as i32);
    assert!(build_requests(&f.h).is_empty());
    f.h.stop().await;
}

#[tokio::test]
async fn an_older_or_same_commit_is_ignored() {
    let f = fixture("hooks-older").await;
    seed::deployed_commit(
        &f.h.core.store,
        SERVICE,
        "refs/heads/main",
        COMMIT,
        "2026-09-23T10:04:00Z",
        &f.rule_plan,
    );
    let body = push_body("refs/heads/main", COMMIT);
    f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    f.hooks.settle().await;
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Ignored as i32
    );
    assert!(build_requests(&f.h).is_empty());
    f.h.stop().await;
}

#[tokio::test]
async fn a_failed_build_fails_the_delivery_and_admits_nothing() {
    let f = fixture("hooks-build-failed").await;
    f.h.runner
        .build_answers
        .lock()
        .unwrap()
        .push(json!({"ok": false, "error": {
        "code": "E_BUILD_FAILED", "message": "build failed", "failure_reason": "source_fetch"}}));
    let body = push_body("refs/heads/main", COMMIT);
    f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    f.hooks.settle().await;
    let delivery = only_delivery(&f.hooks);
    assert_eq!(delivery.status, WebhookDeliveryStatus::Failed as i32);
    assert_eq!(delivery.status_reason, "source_fetch");
    let mut client = WebhookServiceClient::new(f.h.channel.clone());
    let builds = client
        .list_server_builds(ListServerBuildsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .builds;
    assert_eq!(builds.len(), 1);
    assert_eq!(builds[0].status, ServerBuildStatus::Failed as i32);
    assert_eq!(builds[0].failure_reason, "source_fetch");
    assert!(builds[0].error.contains("ERROR_REASON_BUILD_FAILED"));
    // No rule plan was admitted.
    assert!(f.h.core.store.admissions_after(2, 10).unwrap().is_empty());
    f.h.stop().await;
}

/// contracts v1.1.9 (D-067 #6, QA_M2 run 4 B1): a build the runner refused
/// for want of AppArmor reports `buildkit_unavailable` on the build, the
/// delivery and the agent status.
#[tokio::test]
async fn a_build_without_apparmor_reports_buildkit_unavailable() {
    let f = fixture("hooks-build-apparmor").await;
    f.h.runner
        .build_answers
        .lock()
        .unwrap()
        .push(json!({"ok": false, "error": {
        "code": "E_BUILD_FAILED", "message": "the permanu-buildkitd AppArmor profile is not loaded",
        "failure_reason": "buildkit_unavailable"}}));
    let body = push_body("refs/heads/main", COMMIT);
    f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    f.hooks.settle().await;
    let delivery = only_delivery(&f.hooks);
    assert_eq!(delivery.status, WebhookDeliveryStatus::Failed as i32);
    assert_eq!(delivery.status_reason, "buildkit_unavailable");
    let mut client = WebhookServiceClient::new(f.h.channel.clone());
    let builds = client
        .list_server_builds(ListServerBuildsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .builds;
    assert_eq!(builds[0].failure_reason, "buildkit_unavailable");
    assert!(!f.hooks.server_builds_enabled());
    f.h.stop().await;
}

fn status_of(hooks: &Arc<Hooks>) -> crate::proto::agent::v2::AgentStatus {
    let mut status = crate::proto::agent::v2::AgentStatus::default();
    crate::local::status::StatusSources {
        hooks: Some(hooks.clone()),
        ..Default::default()
    }
    .fill(&mut status, 0);
    status
}

/// contracts v1.1.8/v1.1.9 (D-066 #5, D-067 #6): the runner's `diagnose`
/// check `buildkit_apparmor` decides `server_builds_enabled` and the
/// degraded reason `buildkit_unavailable`; a refused or malformed answer
/// (an older runner) changes nothing.
#[tokio::test]
async fn the_buildkit_apparmor_check_drives_the_build_status() {
    let f = fixture("hooks-buildkit-diagnose").await;
    let answer = |value: Value| *f.h.runner.diagnose_answer.lock().unwrap() = value;
    answer(json!({"ok": true, "op": "diagnose", "buildkit_apparmor": "absent"}));
    f.hooks.check_buildkit().await;
    assert!(!f.hooks.server_builds_enabled());
    let status = status_of(&f.hooks);
    assert!(!status.server_builds_enabled);
    assert_eq!(status.degraded_reasons, vec!["buildkit_unavailable"]);
    for refused in [
        json!({"ok": false, "error": {"code": "invalid_request", "message": "unknown check"}}),
        json!({"ok": true, "op": "diagnose"}),
    ] {
        answer(refused);
        f.hooks.check_buildkit().await;
        assert!(!f.hooks.server_builds_enabled());
    }
    answer(json!({"ok": true, "op": "diagnose", "buildkit_apparmor": "loaded"}));
    f.hooks.check_buildkit().await;
    let status = status_of(&f.hooks);
    assert!(status.server_builds_enabled);
    assert!(status.degraded_reasons.is_empty(), "{status:?}");
    let diagnose: Vec<Value> =
        f.h.runner
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["op"] == "diagnose")
            .cloned()
            .collect();
    assert_eq!(diagnose.len(), 4);
    assert!(diagnose
        .iter()
        .all(|r| *r == json!({"op": "diagnose", "payload": {"checks": ["buildkit_apparmor"]}})));
    f.h.stop().await;
}

/// contracts v1.1.11 (D-069): `diagnose` check `account_ids` adds or removes
/// degraded reason `account_ids`. A refusal or a missing field (an older
/// runner) leaves the previous reason unchanged.
#[tokio::test]
async fn the_account_ids_check_drives_the_degraded_reason() {
    let f = fixture("hooks-account-ids").await;
    let answer = |value: Value| *f.h.runner.diagnose_answer.lock().unwrap() = value;
    answer(json!({"ok": false, "error": {"code": "invalid_request", "message": "unknown check"}}));
    f.hooks.check_account_ids().await;
    assert!(status_of(&f.hooks).degraded_reasons.is_empty());
    answer(json!({"ok": true, "op": "diagnose"}));
    f.hooks.check_account_ids().await;
    assert!(
        status_of(&f.hooks).degraded_reasons.is_empty(),
        "an older runner omits account_ids"
    );
    answer(json!({"ok": true, "op": "diagnose", "account_ids": "migrate"}));
    f.hooks.check_account_ids().await;
    assert_eq!(status_of(&f.hooks).degraded_reasons, vec!["account_ids"]);
    answer(json!({"ok": false, "error": {"code": "E_INTERNAL", "message": "runner down"}}));
    f.hooks.check_account_ids().await;
    assert_eq!(
        status_of(&f.hooks).degraded_reasons,
        vec!["account_ids"],
        "a refusal keeps the previous reason"
    );
    answer(json!({"ok": true, "op": "diagnose", "account_ids": "fixed"}));
    f.hooks.check_account_ids().await;
    assert!(status_of(&f.hooks).degraded_reasons.is_empty());
    let diagnose: Vec<Value> =
        f.h.runner
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["op"] == "diagnose")
            .cloned()
            .collect();
    assert_eq!(diagnose.len(), 5);
    assert!(diagnose
        .iter()
        .all(|r| *r == json!({"op": "diagnose", "payload": {"checks": ["account_ids"]}})));
    f.h.stop().await;
}

/// D-064 #7: a build an admitted `operation.cancel` stopped (runner
/// `E_CANCELLED`) ends `CANCELLED` with `failure_reason` `cancelled` and
/// the reason CANCELLED, never a failure.
#[tokio::test]
async fn a_cancelled_build_ends_cancelled_not_failed() {
    let f = fixture("hooks-build-cancelled").await;
    f.h.runner
        .build_answers
        .lock()
        .unwrap()
        .push(json!({"ok": false, "error": {
        "code": "E_CANCELLED", "message": "cancelled by operation.cancel"}}));
    let body = push_body("refs/heads/main", COMMIT);
    f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    f.hooks.settle().await;
    let delivery = only_delivery(&f.hooks);
    assert_eq!(delivery.status, WebhookDeliveryStatus::Failed as i32);
    assert_eq!(delivery.status_reason, "cancelled");
    let mut client = WebhookServiceClient::new(f.h.channel.clone());
    let builds = client
        .list_server_builds(ListServerBuildsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .builds;
    assert_eq!(builds.len(), 1);
    assert_eq!(builds[0].status, ServerBuildStatus::Cancelled as i32);
    assert_eq!(builds[0].failure_reason, "cancelled");
    assert!(
        builds[0].error.contains("ERROR_REASON_CANCELLED"),
        "{}",
        builds[0].error
    );
    assert!(f.h.core.store.admissions_after(2, 10).unwrap().is_empty());
    f.h.stop().await;
}

/// A deploy that cannot start after a successful build (here the trust
/// store vanished mid-build) ends every build `FAILED`, never left
/// `BUILDING`/`DEPLOYING`, and fails the delivery.
#[tokio::test]
async fn a_deploy_that_cannot_start_fails_its_builds() {
    let f = fixture("hooks-deploy-early-fail").await;
    let trust_file = f.h.dir.join("etc/trusted-keys.json");
    *f.h.runner.on_build.lock().unwrap() = Some(Box::new(move || {
        let _ = std::fs::remove_file(&trust_file);
    }));
    let body = push_body("refs/heads/main", COMMIT);
    f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    f.hooks.settle().await;
    let delivery = only_delivery(&f.hooks);
    assert_eq!(delivery.status, WebhookDeliveryStatus::Failed as i32);
    assert_eq!(delivery.status_reason, "trust store unavailable");
    let mut client = WebhookServiceClient::new(f.h.channel.clone());
    let builds = client
        .list_server_builds(ListServerBuildsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .builds;
    assert_eq!(builds.len(), 1);
    assert_eq!(builds[0].status, ServerBuildStatus::Failed as i32);
    assert_eq!(builds[0].error, "trust store unavailable");
    assert!(builds[0].finished_at.is_some());
    f.h.stop().await;
}

/// Two paths processing one delivery at once (intake and a re-match) build
/// and deploy it once: the move out of `pending` is an atomic claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_processing_builds_a_delivery_once() {
    let f = fixture("hooks-claim-once").await;
    f.hooks.hold(true);
    let body = push_body("refs/heads/main", COMMIT);
    f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    let id = only_delivery(&f.hooks).id;
    let start = Arc::new(tokio::sync::Barrier::new(8));
    let paths: Vec<_> = (0..8)
        .map(|_| {
            let (hooks, id, start) = (f.hooks.clone(), id.clone(), start.clone());
            tokio::spawn(async move {
                start.wait().await;
                hooks.process(&id).await;
            })
        })
        .collect();
    for path in paths {
        path.await.unwrap();
    }
    f.hooks.release();
    f.hooks.settle().await;
    assert_eq!(build_requests(&f.h).len(), 1);
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Deployed as i32
    );
    f.h.stop().await;
}

#[tokio::test]
async fn a_protected_environment_ignores_the_push() {
    let f = fixture("hooks-protected").await;
    record(
        &f.h.core.store,
        3,
        (PROJECT, "production", ENV_ID),
        &[json!({"kind": "env.protection.set", "params": {"protected": true}})],
        "succeeded",
    );
    let body = push_body("refs/heads/main", COMMIT);
    f.hooks.intake(github(&body, SECRET, "203.0.113.9")).await;
    f.hooks.settle().await;
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Ignored as i32
    );
    assert!(build_requests(&f.h).is_empty());
    f.h.stop().await;
}

#[tokio::test]
async fn a_non_push_event_is_ignored() {
    let f = fixture("hooks-ping").await;
    let body = json!({"zen": "hi"}).to_string().into_bytes();
    assert_eq!(
        f.hooks
            .intake(github(&body, SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.hooks.settle().await;
    let delivery = only_delivery(&f.hooks);
    assert_eq!(delivery.status, WebhookDeliveryStatus::Ignored as i32);
    assert_eq!(delivery.event, "ping");
    f.h.stop().await;
}

#[tokio::test]
async fn the_pre_auth_budget_is_per_source_and_before_verification() {
    let f = fixture("hooks-budget").await;
    let body = push_body("refs/heads/main", COMMIT);
    for _ in 0..30 {
        let answer = f
            .hooks
            .intake(github(&body, b"forged", "203.0.113.9"))
            .await;
        assert_eq!(answer.status, 401);
    }
    let limited = f
        .hooks
        .intake(github(&body, b"forged", "203.0.113.9"))
        .await;
    assert_eq!(limited.status, 429);
    // A genuine push from another address still gets through.
    let genuine = f.hooks.intake(github(&body, SECRET, "198.51.100.7")).await;
    assert_eq!(genuine.status, 202);
    f.hooks.settle().await;
    let verifies =
        f.h.runner
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["op"] == "webhook_verify")
            .count();
    assert_eq!(verifies, 31);
    f.h.stop().await;
}

#[tokio::test]
async fn deliveries_list_newest_first_and_after_an_id() {
    let f = fixture("hooks-list").await;
    f.hooks.hold(true);
    for commit in ["1".repeat(40), "2".repeat(40), "3".repeat(40)] {
        let body = push_body("refs/heads/main", &commit);
        assert_eq!(
            f.hooks
                .intake(github(&body, SECRET, "203.0.113.9"))
                .await
                .status,
            202
        );
    }
    let mut client = WebhookServiceClient::new(f.h.channel.clone());
    let all = client
        .list_webhook_deliveries(ListWebhookDeliveriesRequest {
            project_id: PROJECT.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .deliveries;
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].commit_sha, "3".repeat(40));
    let mut ids: Vec<String> = all.iter().map(|d| d.id.clone()).collect();
    ids.sort();
    let after = client
        .list_webhook_deliveries(ListWebhookDeliveriesRequest {
            after_delivery_id: ids[0].clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .deliveries;
    assert_eq!(
        after.iter().map(|d| d.id.clone()).collect::<Vec<_>>(),
        ids[1..].to_vec()
    );
    let status = client
        .get_webhook_queue_status(GetWebhookQueueStatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.pending, 3);
    assert!(status.server_builds_enabled);
    f.h.stop().await;
}

/// The listener: loopback HTTP/1, 413 from Content-Length before the body
/// is read, 404 elsewhere, and a verified push answered 202.
#[tokio::test]
async fn the_listener_serves_only_hooks_and_caps_the_body() {
    let f = fixture("hooks-listener").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = super::listener::serve(f.hooks.clone(), listener);
    let send = |raw: Vec<u8>| async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(&raw).await.unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    };
    let big = format!(
        "POST /hooks/{PROJECT} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        super::MAX_BODY_BYTES + 1
    );
    assert!(send(big.into_bytes()).await.starts_with("HTTP/1.1 413"));
    let other = "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    assert!(send(other.as_bytes().to_vec())
        .await
        .starts_with("HTTP/1.1 404"));
    let body = push_body("refs/heads/main", COMMIT);
    let mac = hmac_sha256_hex(SECRET, &body);
    let mut raw = format!(
        "POST /hooks/{PROJECT}?x=1 HTTP/1.1\r\nHost: x\r\nX-GitHub-Event: push\r\n\
         X-Hub-Signature-256: sha256={mac}\r\nX-Real-IP: 203.0.113.9\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(&body);
    assert!(send(raw).await.starts_with("HTTP/1.1 202"));
    f.hooks.settle().await;
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Deployed as i32
    );
    task.abort();
    f.h.stop().await;
}

/// agent-protocol.md 12: an engine Hello opens a session; the status
/// carries presence, the away summary and the webhook fields; a push
/// while the engine is away counts in the summary.
#[tokio::test]
async fn hello_reports_presence_away_summary_and_webhook_fields() {
    use crate::proto::agent::v2::{info_service_client::InfoServiceClient, HelloRequest};
    let f = fixture("hooks-status").await;
    let hello = |engine_id: &str| HelloRequest {
        client_name: "permanu-engine".to_owned(),
        protocol_versions: vec!["2.1".to_owned()],
        engine_id: engine_id.to_owned(),
        ..Default::default()
    };
    let mut info = InfoServiceClient::new(f.h.channel.clone());
    let first = info.hello(hello("")).await.unwrap().into_inner();
    assert!(first.capabilities.contains(&"webhooks.v1".to_owned()));
    let status = first.status.unwrap();
    assert!(!status.engine_online);
    assert!(status.server_builds_enabled);

    let online = info
        .hello(hello("01a0cdb5-3500-7e01-8000-000000000001"))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert!(online.engine_online);
    assert_eq!(online.engine_id, "01a0cdb5-3500-7e01-8000-000000000001");
    assert!(online.engine_last_seen_at.is_some());

    // 90 s of silence: the engine is away; a push is deployed meanwhile.
    f.h.clock
        .0
        .fetch_add(91, std::sync::atomic::Ordering::SeqCst);
    f.h.presence.tick();
    assert!(!f.h.presence.view().engine_online);
    let body = push_body("refs/heads/main", COMMIT);
    assert_eq!(
        f.hooks
            .intake(github(&body, SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.hooks.settle().await;
    let back = info
        .hello(hello("01a0cdb5-3500-7e01-8000-000000000001"))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert!(back.engine_online);
    let away = back.away.unwrap();
    assert!(away.since.is_some() && away.until.is_some());
    assert_eq!(away.webhook_deliveries, 1);
    assert_eq!(away.rule_deploys, 1);
    assert_eq!(back.webhook_pending, 0);
    f.h.stop().await;
}

/// v1.1.4 (D-062, agent-protocol.md 11.1 step 9): a push verified before
/// its rule was admitted waits `PENDING`; admitting the `rule.create`
/// re-matches it against the new rule and it deploys.
#[tokio::test]
async fn a_pending_push_is_rematched_once_its_rule_is_admitted() {
    use crate::proto::agent::v2::{event, EventKind, Scope, TrustChangedEvent};
    let f = fixture_without_rule("hooks-rematch").await;
    let watch = f.hooks.spawn_rule_watch();
    let body = push_body("refs/heads/main", COMMIT);
    assert_eq!(
        f.hooks
            .intake(github(&body, SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.hooks.settle().await;
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Pending as i32
    );
    assert!(build_requests(&f.h).is_empty());
    admit_rule(&f.h);
    // What the executor publishes when it applies the rule.create.
    f.h.core.events.publish(
        EventKind::TrustChanged,
        Scope::default(),
        event::Payload::TrustChanged(TrustChangedEvent {
            change: "rule.create".to_owned(),
            subject_id: "01a0cdb5-3500-70f1-8000-000000000001".to_owned(),
            ..Default::default()
        }),
    );
    let mut status = 0;
    for _ in 0..300 {
        f.hooks.settle().await;
        status = only_delivery(&f.hooks).status;
        if status == WebhookDeliveryStatus::Deployed as i32 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(status, WebhookDeliveryStatus::Deployed as i32);
    assert_eq!(build_requests(&f.h).len(), 1);
    watch.abort();
    f.h.stop().await;
}

/// The 900 s evidence window still applies to a re-matched push.
#[tokio::test]
async fn a_rematched_push_older_than_the_window_is_stale() {
    let f = fixture_without_rule("hooks-rematch-stale").await;
    let body = push_body("refs/heads/main", COMMIT);
    assert_eq!(
        f.hooks
            .intake(github(&body, SECRET, "203.0.113.9"))
            .await
            .status,
        202
    );
    f.hooks.settle().await;
    f.h.clock
        .0
        .fetch_add(901, std::sync::atomic::Ordering::SeqCst);
    admit_rule(&f.h);
    f.hooks
        .rule_admitted("01a0cdb5-3500-70f1-8000-000000000001");
    f.hooks.settle().await;
    assert_eq!(
        only_delivery(&f.hooks).status,
        WebhookDeliveryStatus::Stale as i32
    );
    assert!(build_requests(&f.h).is_empty());
    f.h.stop().await;
}

/// v2.1.3 (D-061): `WebhookQueueStatus.webhook_host` is the latest
/// succeeded `webhook.host.set`.
#[tokio::test]
async fn the_queue_status_reports_the_recorded_webhook_host() {
    let f = fixture("hooks-webhook-host").await;
    let status = || async {
        WebhookServiceClient::new(f.h.channel.clone())
            .get_webhook_queue_status(GetWebhookQueueStatusRequest::default())
            .await
            .unwrap()
            .into_inner()
    };
    assert_eq!(status().await.webhook_host, "");
    let host = |h: &str| json!({"kind": "webhook.host.set", "params": {"webhook_host": h}});
    record(
        &f.h.core.store,
        3,
        ("", "", ""),
        &[host("hooks.a.example.com")],
        "succeeded",
    );
    record(
        &f.h.core.store,
        4,
        ("", "", ""),
        &[host("hooks.b.example.com")],
        "failed",
    );
    assert_eq!(status().await.webhook_host, "hooks.a.example.com");
    record(
        &f.h.core.store,
        5,
        ("", "", ""),
        &[host("hooks.c.example.com")],
        "succeeded",
    );
    assert_eq!(status().await.webhook_host, "hooks.c.example.com");
    f.h.stop().await;
}

/// v1.1.3 (D-061, agent-protocol.md 11.1 "Body cap"): the agent never relies
/// on Dwaar's cap. A body that ends before its `Content-Length`, or a
/// chunked body cut before its last chunk (what Dwaar forwards when it cuts
/// an oversize chunked body), is 400 and never reaches `webhook_verify`; a
/// chunked body over 1 MiB is 413 and counted.
#[tokio::test]
async fn truncated_bodies_are_400_and_never_verified() {
    let f = fixture("hooks-truncated").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = super::listener::serve(f.hooks.clone(), listener);
    let send_half = |raw: Vec<u8>| async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(&raw).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    };
    let body = push_body("refs/heads/main", COMMIT);
    let mac = hmac_sha256_hex(SECRET, &body);
    let head = |framing: &str| {
        format!(
            "POST /hooks/{PROJECT} HTTP/1.1\r\nHost: x\r\nX-GitHub-Event: push\r\n\
             X-Hub-Signature-256: sha256={mac}\r\nX-Real-IP: 203.0.113.9\r\n{framing}\r\n\r\n"
        )
    };
    let mut short = head(&format!("Content-Length: {}", body.len() + 10)).into_bytes();
    short.extend_from_slice(&body);
    assert!(send_half(short).await.starts_with("HTTP/1.1 400"));
    let mut cut = head("Transfer-Encoding: chunked").into_bytes();
    cut.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
    cut.extend_from_slice(&body);
    cut.extend_from_slice(b"\r\n");
    assert!(send_half(cut).await.starts_with("HTTP/1.1 400"));
    let mut big = head("Transfer-Encoding: chunked").into_bytes();
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..17 {
        big.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        big.extend_from_slice(&chunk);
        big.extend_from_slice(b"\r\n");
    }
    big.extend_from_slice(b"0\r\n\r\n");
    assert!(send_half(big).await.starts_with("HTTP/1.1 413"));
    assert_eq!(f.hooks.counters().1, 1);
    assert!(!f
        .h
        .runner
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["op"] == "webhook_verify"));
    task.abort();
    f.h.stop().await;
}
