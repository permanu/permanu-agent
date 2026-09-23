use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use super::super::test_support::{Fixture, CRON, PROJECT};
use super::*;
use crate::proto::agent::v2::event_condition::Kind as Cond;

const RULE: &str = "01a0cdb5-3500-70e1-8000-000000000001";
const CHANNEL: &str = "01a0cdb5-3500-70e2-8000-000000000001";

#[derive(Default)]
struct FakeSource {
    values: Mutex<Vec<f64>>,
    logs: AtomicU64,
    dropped: AtomicU64,
}

#[tonic::async_trait]
impl AlertSource for FakeSource {
    async fn metric(&self, _: &MetricCondition, _: i64) -> Vec<f64> {
        self.values.lock().unwrap().clone()
    }
    async fn log_count(&self, _: &LogCondition, _: i64) -> u64 {
        self.logs.load(Ordering::SeqCst)
    }
    fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }
}

fn rule(spec: serde_json::Value) -> serde_json::Value {
    json!({"kind": "alert.rule.create", "params": {"alert_rule_id": RULE, "name": "CPU high",
        "spec": spec.to_string()}})
}

fn channel(kind: &str) -> serde_json::Value {
    json!({"kind": "alert.channel.create", "params": {"channel_id": CHANNEL, "name": "ops",
        "channel_kind": kind, "credential_ciphertext_digest_hex": "cd".repeat(32)}})
}

fn cpu_rule(for_duration: &str) -> serde_json::Value {
    rule(
        json!({"metric": {"metric": "host.cpu.percent", "op": "COMPARISON_OP_GT",
        "threshold": 90, "window": "60s", "forDuration": for_duration},
        "channelIds": [CHANNEL], "notifyOnResolve": true, "enabled": true,
        "repeatInterval": "3600s"}),
    )
}

fn evaluator(f: &Fixture, source: Arc<FakeSource>) -> Arc<AlertEvaluator> {
    f.runner.answer(
        "notify_channel",
        json!({"delivered": true, "status_code": 200, "target_display": "hooks.slack.com/services/T0…"}),
    );
    AlertEvaluator::with_retry_delays(f.deps.clone(), source, vec![Duration::ZERO; 3])
}

async fn eval_at(f: &Fixture, e: &Arc<AlertEvaluator>, now: &str) {
    f.clock.set(now);
    e.evaluate().await;
    e.settle().await;
}

fn texts(f: &Fixture) -> Vec<String> {
    f.runner
        .ops("notify_channel")
        .iter()
        .map(|r| r["payload"]["text"].as_str().unwrap().to_owned())
        .collect()
}

fn state_of(e: &AlertEvaluator) -> i32 {
    e.rules()[0].state
}

#[tokio::test]
async fn a_metric_rule_goes_pending_firing_and_resolved_with_notifications() {
    let f = Fixture::new("alerts-metric", "2026-09-23T10:00:00Z");
    f.record(1, &[channel("slack"), cpu_rule("60s")], "succeeded");
    let source = Arc::new(FakeSource::default());
    let e = evaluator(&f, source.clone());
    *source.values.lock().unwrap() = vec![50.0, 95.0];
    eval_at(&f, &e, "2026-09-23T10:00:00Z").await;
    assert_eq!(state_of(&e), AlertState::Pending as i32);
    assert!(texts(&f).is_empty());
    eval_at(&f, &e, "2026-09-23T10:00:30Z").await;
    assert_eq!(state_of(&e), AlertState::Pending as i32);
    eval_at(&f, &e, "2026-09-23T10:01:00Z").await;
    assert_eq!(state_of(&e), AlertState::Firing as i32);
    let sent = f.runner.ops("notify_channel");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["payload"]["channel_id"], CHANNEL);
    assert!(
        sent[0]["payload"].get("payload_json").is_none(),
        "slack gets text only"
    );
    assert!(texts(&f)[0].starts_with("[WARNING] CPU high: CPU high: value 95"));
    // Still firing: no repeat before the interval.
    eval_at(&f, &e, "2026-09-23T10:01:30Z").await;
    assert_eq!(texts(&f).len(), 1);
    // Two false evaluations resolve it.
    *source.values.lock().unwrap() = vec![10.0];
    eval_at(&f, &e, "2026-09-23T10:02:00Z").await;
    assert_eq!(state_of(&e), AlertState::Firing as i32);
    eval_at(&f, &e, "2026-09-23T10:02:30Z").await;
    assert_eq!(state_of(&e), AlertState::Ok as i32);
    assert!(texts(&f)[1].starts_with("[RESOLVED] CPU high"));
    let history = e.history(None, 10);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].state, AlertState::Resolved as i32);
    assert_eq!(history[0].deliveries.len(), 2);
    assert!(history[0].deliveries.iter().all(|d| d.ok));
    assert_eq!(
        e.channels()[0].target_display,
        "hooks.slack.com/services/T0…"
    );
}

#[tokio::test]
async fn repeats_follow_the_interval_and_silences_hold_notifications() {
    let f = Fixture::new("alerts-repeat", "2026-09-23T10:00:00Z");
    f.record(1, &[channel("slack"), cpu_rule("0s")], "succeeded");
    let source = Arc::new(FakeSource::default());
    let e = evaluator(&f, source.clone());
    *source.values.lock().unwrap() = vec![99.0];
    eval_at(&f, &e, "2026-09-23T10:00:00Z").await;
    assert_eq!(texts(&f).len(), 1);
    eval_at(&f, &e, "2026-09-23T11:00:00Z").await;
    assert_eq!(texts(&f).len(), 2, "repeat after 3600 s");
    f.record(
        2,
        &[
            json!({"kind": "alert.silence", "params": {"alert_rule_id": RULE,
                 "until": "2026-09-23T13:00:00Z"}}),
        ],
        "succeeded",
    );
    eval_at(&f, &e, "2026-09-23T12:00:00Z").await;
    assert_eq!(texts(&f).len(), 2, "muted");
    assert_eq!(state_of(&e), AlertState::Muted as i32);
    eval_at(&f, &e, "2026-09-23T13:00:00Z").await;
    assert_eq!(texts(&f).len(), 3, "still firing when the silence ends");
}

#[tokio::test]
async fn no_data_and_absent() {
    let f = Fixture::new("alerts-nodata", "2026-09-23T10:00:00Z");
    f.record(1, &[cpu_rule("0s")], "succeeded");
    let source = Arc::new(FakeSource::default());
    let e = evaluator(&f, source);
    for now in ["10:00:00", "10:00:30", "10:01:00"] {
        eval_at(&f, &e, &format!("2026-09-23T{now}Z")).await;
    }
    assert_eq!(state_of(&e), AlertState::NoData as i32);
    assert!(e.rules()[0].last_value.is_nan());

    let g = Fixture::new("alerts-absent", "2026-09-23T10:00:00Z");
    g.record(
        1,
        &[rule(
            json!({"metric": {"metric": "app.heartbeat", "op": "COMPARISON_OP_ABSENT"},
                       "enabled": true}),
        )],
        "succeeded",
    );
    let e = evaluator(&g, Arc::new(FakeSource::default()));
    eval_at(&g, &e, "2026-09-23T10:00:00Z").await;
    assert_eq!(state_of(&e), AlertState::Firing as i32);
}

#[tokio::test]
async fn heartbeat_alerts_are_their_own_event_sent_to_matching_rule_channels() {
    let f = Fixture::new("alerts-heartbeat", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[
            channel("webhook"),
            rule(json!({"event": {"kind": "KIND_CRON_FAILED",
                        "scope": {"projectId": PROJECT}}, "channelIds": [CHANNEL],
                        "enabled": true})),
        ],
        "succeeded",
    );
    let e = evaluator(&f, Arc::new(FakeSource::default()));
    let heartbeat = |occurred: bool| BuiltinEvent {
        kind: Cond::CronFailed,
        scope: Scope {
            project_id: PROJECT.to_owned(),
            environment: "production".to_owned(),
            ..Default::default()
        },
        source: "cron_heartbeat",
        subject_id: CRON.to_owned(),
        occurred,
        standalone: true,
        channel_ids: Vec::new(),
        summary: "cron job failed after 3 attempt(s): token=hunter2hunter2".to_owned(),
    };
    e.builtin(heartbeat(true));
    e.builtin(heartbeat(true));
    e.settle().await;
    let sent = f.runner.ops("notify_channel");
    assert_eq!(sent.len(), 1, "one episode");
    let body: serde_json::Value =
        serde_json::from_str(sent[0]["payload"]["payload_json"].as_str().unwrap()).unwrap();
    assert_eq!(body["type"], "alert");
    assert_eq!(body["event"]["source"], "cron_heartbeat");
    assert_eq!(body["event"]["subjectId"], CRON);
    assert!(
        !sent[0]["payload"]["text"]
            .as_str()
            .unwrap()
            .contains("hunter2"),
        "redacted"
    );
    let history = e.history(None, 10);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].rule_id, "");
    assert_eq!(history[0].severity, AlertSeverity::Warning as i32);
    assert_eq!(
        state_of(&e),
        AlertState::Ok as i32,
        "the rule itself does not fire"
    );
    e.builtin(heartbeat(false));
    e.settle().await;
    assert_eq!(e.history(None, 10)[0].state, AlertState::Resolved as i32);
    assert_eq!(f.runner.ops("notify_channel").len(), 2);
}

#[tokio::test]
async fn event_rules_fire_on_built_in_events_and_resolve_on_their_counterpart() {
    let f = Fixture::new("alerts-event", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[
            channel("discord"),
            rule(
                json!({"event": {"kind": "KIND_BACKUP_FAILED"}, "channelIds": [CHANNEL],
                        "enabled": true}),
            ),
        ],
        "succeeded",
    );
    let e = evaluator(&f, Arc::new(FakeSource::default()));
    let backup = |occurred| BuiltinEvent {
        kind: Cond::BackupFailed,
        scope: Scope::default(),
        source: "backup",
        subject_id: "pg".to_owned(),
        occurred,
        standalone: false,
        channel_ids: Vec::new(),
        summary: "backup failed".to_owned(),
    };
    e.builtin(backup(true));
    e.settle().await;
    assert_eq!(state_of(&e), AlertState::Firing as i32);
    e.builtin(backup(false));
    e.settle().await;
    assert_eq!(state_of(&e), AlertState::Ok as i32);
    assert_eq!(e.history(None, 10)[0].source, "rule");
    // Other kinds do not match.
    e.builtin(BuiltinEvent {
        kind: Cond::CronMissed,
        ..backup(true)
    });
    e.settle().await;
    assert_eq!(state_of(&e), AlertState::Ok as i32);
}

#[tokio::test]
async fn telemetry_dropping_is_built_in() {
    let f = Fixture::new("alerts-dropping", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[rule(
            json!({"event": {"kind": "KIND_TELEMETRY_DROPPING"}, "enabled": true}),
        )],
        "succeeded",
    );
    let source = Arc::new(FakeSource::default());
    let e = evaluator(&f, source.clone());
    eval_at(&f, &e, "2026-09-23T10:00:00Z").await;
    assert_eq!(state_of(&e), AlertState::Ok as i32);
    source.dropped.store(5, Ordering::SeqCst);
    eval_at(&f, &e, "2026-09-23T10:00:30Z").await;
    assert_eq!(state_of(&e), AlertState::Firing as i32);
    eval_at(&f, &e, "2026-09-23T10:03:00Z").await;
    assert_eq!(state_of(&e), AlertState::Firing as i32);
    eval_at(&f, &e, "2026-09-23T10:05:30Z").await;
    assert_eq!(state_of(&e), AlertState::Ok as i32);
}

#[tokio::test]
async fn failed_sends_retry_three_times_on_retryable_statuses() {
    let f = Fixture::new("alerts-retry", "2026-09-23T10:00:00Z");
    f.record(1, &[channel("slack"), cpu_rule("0s")], "succeeded");
    let source = Arc::new(FakeSource::default());
    let e = evaluator(&f, source.clone());
    f.runner.only(
        "notify_channel",
        json!({"delivered": false, "status_code": 503}),
    );
    f.runner.answer(
        "notify_channel",
        json!({"delivered": false, "status_code": 429}),
    );
    f.runner.answer(
        "notify_channel",
        json!({"delivered": true, "status_code": 200}),
    );
    *source.values.lock().unwrap() = vec![99.0];
    eval_at(&f, &e, "2026-09-23T10:00:00Z").await;
    assert_eq!(f.runner.ops("notify_channel").len(), 3);
    let delivery = &e.history(None, 1)[0].deliveries[0];
    assert!(delivery.ok);
    assert_eq!(delivery.attempts, 3);
    // A 4xx other than 408/429 is final.
    f.runner.only(
        "notify_channel",
        json!({"delivered": false, "status_code": 404}),
    );
    eval_at(&f, &e, "2026-09-23T11:00:00Z").await;
    assert_eq!(f.runner.ops("notify_channel").len(), 4);
}

#[tokio::test]
async fn channel_tests_are_rate_limited_and_need_a_recorded_channel() {
    let f = Fixture::new("alerts-test", "2026-09-23T10:00:00Z");
    f.record(1, &[channel("slack")], "succeeded");
    let e = evaluator(&f, Arc::new(FakeSource::default()));
    assert_eq!(e.test_channel("nope").await, Err(TestRefusal::NotFound));
    let result = e.test_channel(CHANNEL).await.unwrap();
    assert!(result.ok);
    assert_eq!(result.http_status, 200);
    assert_eq!(e.test_channel(CHANNEL).await, Err(TestRefusal::RateLimited));
    f.clock.advance(10);
    assert!(e.test_channel(CHANNEL).await.is_ok());
    assert_eq!(
        f.runner.ops("notify_channel")[0]["payload"]["text"],
        "Permanu test notification: this channel works."
    );
}

#[tokio::test]
async fn more_than_thirty_sends_a_minute_are_coalesced() {
    let f = Fixture::new("alerts-coalesce", "2026-09-23T10:00:00Z");
    f.record(1, &[channel("slack")], "succeeded");
    let e = evaluator(&f, Arc::new(FakeSource::default()));
    for n in 0..35 {
        e.builtin(BuiltinEvent {
            kind: Cond::CronFailed,
            scope: Scope::default(),
            source: "cron_heartbeat",
            subject_id: format!("job-{n}"),
            occurred: true,
            standalone: true,
            channel_ids: vec![CHANNEL.to_owned()],
            summary: "failed".to_owned(),
        });
    }
    e.settle().await;
    assert_eq!(f.runner.ops("notify_channel").len(), 30);
    f.clock.advance(60);
    e.builtin(BuiltinEvent {
        kind: Cond::CronFailed,
        scope: Scope::default(),
        source: "cron_heartbeat",
        subject_id: "job-last".to_owned(),
        occurred: true,
        standalone: true,
        channel_ids: vec![CHANNEL.to_owned()],
        summary: "failed".to_owned(),
    });
    e.settle().await;
    let last = texts(&f).pop().unwrap();
    assert!(last.contains("(+5 more alerts)"), "{last}");
}
