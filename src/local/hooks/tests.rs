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
    let rule = &context["rules"][0];
    let scope = (PROJECT, "production", ENV_ID);
    let rule_plan = record(
        &store,
        1,
        scope,
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
        rule_plan,
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
