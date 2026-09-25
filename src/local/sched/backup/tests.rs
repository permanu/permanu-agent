use serde_json::{json, Value};

use super::super::test_support::{Fixture, PG};
use super::*;
use crate::proto::agent::v2::event_condition::Kind as Cond;

const RECOVERY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
const SERVER_RECIPIENT: &str = "age1server";
const BACKUP_A: &str = "01a0cdb5-3500-7e01-8000-000000000001";
const BACKUP_B: &str = "01a0cdb5-3500-7e01-8000-000000000002";

fn policy(resource: &str, schedule: &str, verify: Value) -> Value {
    json!({"kind": "backup.policy.set", "params": {"resource_id": resource,
        "schedule": schedule, "timezone": "UTC", "keep_daily": 7, "keep_weekly": 4,
        "keep_monthly": 6, "verify_schedule": verify, "destination_ref": "local"}})
}

fn destination() -> Value {
    json!({"kind": "backup.destination.set", "params": {"destination_ref": "local",
        "destination_kind": "server_local", "endpoint": null, "region": null, "bucket": null,
        "prefix": "", "credential_ciphertext_digest_hex": null}})
}

fn recovery() -> Value {
    json!({"kind": "recovery_recipient.set", "params": {"recipient": RECOVERY}})
}

fn scheduler(f: &Fixture) -> Arc<BackupScheduler> {
    f.record(100, &[destination(), recovery()], "succeeded");
    BackupScheduler::new(f.deps.clone(), f.sink.clone(), SERVER_RECIPIENT.to_owned())
}

async fn tick_at(f: &Fixture, s: &Arc<BackupScheduler>, now: &str) {
    f.clock.set(now);
    s.tick();
    s.settle().await;
}

fn backup_runs(f: &Fixture) -> Vec<BackupRun> {
    f.deps
        .ops
        .list(
            RecordKind::BackupRun,
            &Listing {
                limit: 100,
                ascending: true,
                ..Default::default()
            },
        )
        .iter()
        .filter_map(|row| row.decode())
        .collect()
}

#[tokio::test]
async fn a_scheduled_backup_records_its_artifact_then_prunes_under_the_same_binding() {
    let f = Fixture::new("backup-run", "2026-09-23T02:00:00Z");
    let plan = f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T02:59:55Z").await;
    f.runner.answer(
        "backup_run",
        json!({"outcome": "succeeded", "backup_id": BACKUP_B,
               "backup_digest_hex": "ab".repeat(32), "size_bytes": 1234}),
    );
    f.runner
        .answer("backup_prune", json!({"deleted": [BACKUP_A]}));
    // An older artifact of this policy that prune removes.
    s.put_artifact(&BackupArtifact {
        id: BACKUP_A.to_owned(),
        policy_id: PG.to_owned(),
        created_at: Some(pts(1)),
        ..Default::default()
    });
    tick_at(&f, &s, "2026-09-23T03:00:05Z").await;
    let schedule = json!({"plan_id": plan, "plan_digest_hex": format!("{:064x}", 1),
        "action_index": 0, "scheduled_for": "2026-09-23T03:00:00Z", "attempt": 1});
    assert_eq!(
        f.runner.ops("backup_run"),
        [json!({"op": "backup_run", "schedule": schedule, "payload": {}})]
    );
    assert_eq!(
        f.runner.ops("backup_prune"),
        [json!({"op": "backup_prune", "schedule": schedule, "payload": {}})]
    );
    let runs = backup_runs(&f);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, BackupRunStatus::Succeeded as i32);
    assert_eq!(runs[0].artifact_id, BACKUP_B);
    assert_eq!(runs[0].content_digest_hex, "ab".repeat(32));
    let artifact: BackupArtifact = f
        .deps
        .ops
        .get(RecordKind::Artifact, BACKUP_B)
        .unwrap()
        .decode()
        .unwrap();
    assert_eq!(
        artifact.location,
        format!(
            "/var/lib/permanu/backups/permanu/v1/{}/{PG}/{BACKUP_B}.age",
            f.deps.server_id.get()
        )
    );
    assert_eq!(
        artifact.age_recipients,
        [fingerprint(SERVER_RECIPIENT), fingerprint(RECOVERY)]
    );
    assert!(artifact.expires_at.is_none());
    let pruned: BackupArtifact = f
        .deps
        .ops
        .get(RecordKind::Artifact, BACKUP_A)
        .unwrap()
        .decode()
        .unwrap();
    assert!(pruned.expires_at.is_some());
    let defs = s.definitions();
    let proto = s.policy_proto(&defs.policies[PG], &defs);
    assert_eq!(
        proto.destination.unwrap().kind,
        backup_destination::Kind::Local as i32
    );
    assert_eq!(proto.age_recipients.len(), 2);
    assert_eq!(
        proto.last_run.unwrap().status,
        BackupRunStatus::Succeeded as i32
    );
    assert_eq!(
        proto.next_run_at.unwrap().seconds,
        super::super::test_support::at("2026-09-24T03:00:00Z")
    );
}

/// The installer starts the agent before `server.add` bootstraps it, so the
/// schedulers must take the server id from the trust store when they use
/// it: a backup recorded after the bootstrap names the server in its
/// location (else the engine cannot attribute it and never lists it).
#[tokio::test]
async fn backups_after_the_bootstrap_name_the_server_in_their_location() {
    use crate::signed_plan::trust::{TrustMode, TrustPaths};
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new("backup-late-trust", "2026-09-23T02:00:00Z");
    let trust = TrustPaths {
        file: f.dir.join("trusted-keys.json"),
        lock: f.dir.join("trust.lock"),
        // SAFETY: geteuid has no preconditions.
        owner_uid: unsafe { libc::geteuid() },
        mode: TrustMode::Test,
    };
    f.deps.server_id = super::super::ServerId::Trust(trust.clone());
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T02:59:55Z").await;
    // server.add after the agent started.
    let document =
        crate::signed_plan::test_support::vector("policy-cases")["context"]["trusted_keys"].clone();
    std::fs::write(&trust.file, serde_json::to_vec(&document).unwrap()).unwrap();
    std::fs::set_permissions(&trust.file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let server = document["server_id"].as_str().unwrap().to_owned();
    f.runner.answer(
        "backup_run",
        json!({"outcome": "succeeded", "backup_id": BACKUP_B,
               "backup_digest_hex": "ab".repeat(32), "size_bytes": 1234}),
    );
    f.runner.answer("backup_prune", json!({"deleted": []}));
    tick_at(&f, &s, "2026-09-23T03:00:05Z").await;
    let artifact: BackupArtifact = f
        .deps
        .ops
        .get(RecordKind::Artifact, BACKUP_B)
        .unwrap()
        .decode()
        .unwrap();
    assert_eq!(
        artifact.location,
        format!("/var/lib/permanu/backups/permanu/v1/{server}/{PG}/{BACKUP_B}.age")
    );
}

/// A manual `backup.run` is run by the plan executor; the runner writes the
/// backup's id, digest and size only on its `run_result` line (section 14.5),
/// so the artifact comes from that line, and only a succeeded line of the
/// same action counts.
#[tokio::test]
async fn a_manual_backup_records_its_artifact_from_the_runners_run_result_line() {
    let f = Fixture::new("backup-manual", "2026-09-23T02:00:00Z");
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    let plan = f.record(
        2,
        &[json!({"kind": "backup.run", "params": {"resource_id": PG}})],
        "succeeded",
    );
    let line = |index: u32, outcome: &str, backup: &str| {
        json!({"v": 1, "seq": 1, "at": "2026-09-23T02:00:01Z", "event": "run_result",
               "plan_id": plan, "plan_digest_hex": format!("{:064x}", 2), "action_index": index,
               "op": "backup_run", "scheduled_for": null, "attempt": 1, "outcome": outcome,
               "backup_id": backup, "backup_digest_hex": "cd".repeat(32), "size_bytes": 4321,
               "resource_id": PG, "destination_ref": "local", "trigger": "manual"})
    };
    f.append_consumed(&line(1, "succeeded", BACKUP_A));
    f.append_consumed(&line(0, "failed", BACKUP_A));
    f.append_consumed(&line(0, "succeeded", BACKUP_B));
    tick_at(&f, &s, "2026-09-23T02:00:05Z").await;
    let runs = backup_runs(&f);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, BackupRunStatus::Succeeded as i32);
    assert_eq!(runs[0].artifact_id, BACKUP_B);
    assert_eq!(runs[0].content_digest_hex, "cd".repeat(32));
    assert_eq!(runs[0].size_bytes, 4321);
    let artifact: BackupArtifact = f
        .deps
        .ops
        .get(RecordKind::Artifact, BACKUP_B)
        .expect("the manual backup's artifact")
        .decode()
        .unwrap();
    assert_eq!(
        artifact.location,
        format!(
            "/var/lib/permanu/backups/permanu/v1/{}/{PG}/{BACKUP_B}.age",
            f.deps.server_id.get()
        )
    );
    assert_eq!(artifact.size_bytes, 4321);
    assert!(f.deps.ops.get(RecordKind::Artifact, BACKUP_A).is_none());
}

/// The real runner's answers (jobs::bound::finish): a failed run is
/// `ok: false` with `run_outcome`, and verify `checks` is an object of
/// booleans.
#[tokio::test]
async fn runner_shaped_answers_retry_a_failed_backup_and_read_verify_checks() {
    let f = Fixture::new("backup-runner-shape", "2026-09-23T02:00:00Z");
    f.record(
        1,
        &[policy(PG, "0 3 * * *", json!("0 4 * * *"))],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T02:59:55Z").await;
    f.runner.answer(
        "backup_run",
        json!({"ok": false, "outcome": null, "run_outcome": "failed",
               "error": {"code": "runtime_failed", "message": "pg_dump failed"}}),
    );
    f.runner.answer(
        "backup_run",
        json!({"ok": true, "outcome": null, "run_outcome": "succeeded", "backup_id": BACKUP_B,
               "backup_digest_hex": "ab".repeat(32), "size_bytes": 1234}),
    );
    f.runner.answer(
        "backup_prune",
        json!({"outcome": null, "run_outcome": "succeeded", "deleted": []}),
    );
    tick_at(&f, &s, "2026-09-23T03:00:05Z").await;
    tick_at(&f, &s, "2026-09-23T03:00:15Z").await;
    let runs = backup_runs(&f);
    assert_eq!(
        f.runner.ops("backup_run").len(),
        2,
        "a failed backup is retried"
    );
    assert_eq!(runs[0].status, BackupRunStatus::Failed as i32);
    assert_eq!(runs[0].error, "runtime_failed: pg_dump failed");
    assert_eq!(runs[1].status, BackupRunStatus::Succeeded as i32);

    f.runner.answer(
        "backup_verify",
        json!({"ok": true, "outcome": null, "run_outcome": "succeeded", "backup_id": BACKUP_B,
               "checks": {"archive_readable": true, "plaintext_digest": true,
                          "restore_completed": true, "tables_present": true}}),
    );
    tick_at(&f, &s, "2026-09-23T03:59:55Z").await;
    tick_at(&f, &s, "2026-09-23T04:00:05Z").await;
    assert_eq!(f.runner.ops("backup_verify").len(), 1);
    let verifications: Vec<RestoreVerification> = f
        .deps
        .ops
        .list(
            RecordKind::Verification,
            &Listing {
                limit: 10,
                ..Default::default()
            },
        )
        .iter()
        .filter_map(|row| row.decode())
        .collect();
    assert_eq!(verifications.len(), 1);
    assert_eq!(
        verifications[0].status,
        RestoreVerificationStatus::Passed as i32
    );
    let names: Vec<&str> = verifications[0]
        .checks
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "archive_readable",
            "plaintext_digest",
            "restore_completed",
            "tables_present"
        ]
    );
    assert!(verifications[0].checks.iter().all(|c| c.passed));
}

const RUNNER_RUN: &str = "01a0cdb5-3500-70e1-8000-000000000021";

/// contracts v1.1.5 (D-063 #10): a running backup learns the runner's
/// `run_id` from its `run` line; a cancelled one ends `CANCELLED` with its
/// id, no retry and no failure report.
#[tokio::test]
async fn a_cancelled_backup_keeps_its_runner_id_and_is_not_retried() {
    let f = Fixture::new("backup-cancel-one", "2026-09-23T02:00:00Z");
    let plan = f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T02:59:55Z").await;
    f.runner.hold("backup_run");
    f.runner.answer(
        "backup_run",
        json!({"ok": false, "outcome": null, "run_outcome": "cancelled", "run_id": RUNNER_RUN,
               "error": {"code": "E_CANCELLED", "message": "cancelled"}}),
    );
    f.clock.set("2026-09-23T03:00:05Z");
    s.tick();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    f.append_consumed(
        &json!({"v": 1, "seq": 1, "at": "2026-09-23T03:00:06Z", "event": "run",
        "plan_id": plan, "plan_digest_hex": format!("{:064x}", 1), "action_index": 0,
        "op": "backup_run", "scheduled_for": "2026-09-23T03:00:00Z", "attempt": 1,
        "run_id": RUNNER_RUN}),
    );
    f.clock.set("2026-09-23T03:00:15Z");
    s.tick();
    let running = backup_runs(&f);
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].status, BackupRunStatus::Dumping as i32);
    assert_eq!(running[0].runner_run_id, RUNNER_RUN);
    f.runner.release("backup_run", 1);
    s.settle().await;
    tick_at(&f, &s, "2026-09-23T03:01:00Z").await;
    tick_at(&f, &s, "2026-09-23T03:05:00Z").await;
    let runs = backup_runs(&f);
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0].status, BackupRunStatus::Cancelled as i32);
    assert_eq!(runs[0].runner_run_id, RUNNER_RUN);
    assert_eq!(f.runner.ops("backup_run").len(), 1);
    assert!(f.sink.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_backups_get_three_attempts_then_report() {
    let f = Fixture::new("backup-retry", "2026-09-23T02:00:00Z");
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T02:59:55Z").await;
    f.runner.answer(
        "backup_run",
        json!({"outcome": "failed", "error": "pg_dump exited 1"}),
    );
    tick_at(&f, &s, "2026-09-23T03:00:05Z").await;
    tick_at(&f, &s, "2026-09-23T03:00:15Z").await;
    tick_at(&f, &s, "2026-09-23T03:00:35Z").await;
    tick_at(&f, &s, "2026-09-23T03:05:00Z").await;
    let attempts: Vec<Value> = f
        .runner
        .ops("backup_run")
        .iter()
        .map(|r| r["schedule"]["attempt"].clone())
        .collect();
    assert_eq!(attempts, [json!(1), json!(2), json!(3)]);
    assert!(f.runner.ops("backup_prune").is_empty());
    let events = f.sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, Cond::BackupFailed);
    assert!(events[0].occurred);
    assert!(backup_runs(&f)
        .iter()
        .all(|r| r.status == BackupRunStatus::Failed as i32));
}

#[tokio::test]
async fn verify_restore_runs_on_its_own_schedule_and_reports_failures() {
    let f = Fixture::new("backup-verify", "2026-09-27T03:00:00Z");
    f.record(
        1,
        &[policy(PG, "0 3 * * *", json!("0 4 * * 0"))],
        "succeeded",
    );
    let s = scheduler(&f);
    s.put_artifact(&BackupArtifact {
        id: BACKUP_A.to_owned(),
        policy_id: PG.to_owned(),
        ..Default::default()
    });
    tick_at(&f, &s, "2026-09-27T03:59:55Z").await;
    f.runner.answer(
        "backup_verify",
        json!({"outcome": "failed", "backup_id": BACKUP_A, "checks": [
            {"name": "plaintext_digest", "passed": true},
            {"name": "tables_present", "passed": false, "detail": "no user tables"}]}),
    );
    tick_at(&f, &s, "2026-09-27T04:00:05Z").await;
    let sent = f.runner.ops("backup_verify");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["schedule"]["scheduled_for"], "2026-09-27T04:00:00Z");
    let verifications: Vec<RestoreVerification> = f
        .deps
        .ops
        .list(
            RecordKind::Verification,
            &Listing {
                limit: 10,
                ..Default::default()
            },
        )
        .iter()
        .filter_map(|row| row.decode())
        .collect();
    assert_eq!(verifications.len(), 1);
    assert_eq!(
        verifications[0].status,
        RestoreVerificationStatus::Failed as i32
    );
    assert_eq!(verifications[0].error, "tables_present");
    assert_eq!(verifications[0].checks.len(), 2);
    let artifact: BackupArtifact = f
        .deps
        .ops
        .get(RecordKind::Artifact, BACKUP_A)
        .unwrap()
        .decode()
        .unwrap();
    assert_eq!(
        artifact.last_verification,
        RestoreVerificationStatus::Failed as i32
    );
    let events = f.sink.0.lock().unwrap().clone();
    assert_eq!(events[0].kind, Cond::RestoreVerificationFailed);
    assert!(events[0].occurred);
}

#[tokio::test]
async fn one_backup_runs_per_server_at_a_time() {
    let f = Fixture::new("backup-serial", "2026-09-23T02:00:00Z");
    let other = "01a0cdb5-3500-70d1-8000-000000000002";
    f.record(
        1,
        &[
            policy(PG, "0 3 * * *", Value::Null),
            policy(other, "0 3 * * *", Value::Null),
        ],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T02:59:55Z").await;
    f.runner.hold("backup_run");
    f.runner
        .answer("backup_run", json!({"outcome": "succeeded"}));
    f.clock.set("2026-09-23T03:00:05Z");
    s.tick();
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert_eq!(f.runner.ops("backup_run").len(), 1);
    f.runner.release("backup_run", 10);
    s.settle().await;
    assert_eq!(f.runner.ops("backup_run").len(), 2);
}

#[tokio::test]
async fn after_downtime_a_recent_fire_time_runs_once_and_an_old_one_is_reported() {
    let f = Fixture::new("backup-downtime", "2026-09-23T00:00:00Z");
    f.record(1, &[policy(PG, "0 5 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    f.runner
        .answer("backup_run", json!({"outcome": "succeeded"}));
    tick_at(&f, &s, "2026-09-23T00:00:05Z").await;
    // Down until 05:30: 05:00 is 30 min old and runs once.
    tick_at(&f, &s, "2026-09-23T05:30:00Z").await;
    let sent = f.runner.ops("backup_run");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["schedule"]["scheduled_for"], "2026-09-23T05:00:00Z");
    // Down again past the one-hour window of the next fire time.
    tick_at(&f, &s, "2026-09-24T07:30:00Z").await;
    assert_eq!(f.runner.ops("backup_run").len(), 1);
    let runs = backup_runs(&f);
    let missed = runs.last().unwrap();
    // proto v2.1.3 (contracts v1.1.3, D-061): its own status.
    assert_eq!(missed.status, BackupRunStatus::Missed as i32);
    assert!(missed.error.starts_with("missed:"));
    assert!(f
        .sink
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.kind == Cond::BackupFailed && e.occurred));
}

#[tokio::test]
async fn manual_backups_are_recorded_from_their_admission() {
    let f = Fixture::new("backup-manual", "2026-09-23T10:00:00Z");
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    let plan = f.record(
        2,
        &[json!({"kind": "backup.run", "params": {"resource_id": PG}})],
        "",
    );
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    let runs = backup_runs(&f);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].trigger, backup_run::Trigger::Manual as i32);
    assert_eq!(runs[0].status, BackupRunStatus::Dumping as i32);
    f.finish(&plan, "succeeded");
    tick_at(&f, &s, "2026-09-23T10:00:25Z").await;
    let runs = backup_runs(&f);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, BackupRunStatus::Succeeded as i32);
    assert_eq!(
        runs[0].operation_id, plan,
        "the fixture uses the plan id as operation id"
    );
}

/// agent-protocol.md 10.3 (contracts v1.1.5, D-063): `backup_failed` is "a
/// failed or MISSED backup run", manual runs included: a failed manual run
/// reports it once, and the next succeeded manual run resolves it (QA M2
/// run 2: a manual backup to an unwritable destination notified nothing).
#[tokio::test]
async fn a_failed_manual_backup_reports_backup_failed_once() {
    let f = Fixture::new("backup-manual-failed", "2026-09-23T10:00:00Z");
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    let failed = f.record(
        2,
        &[json!({"kind": "backup.run", "params": {"resource_id": PG}})],
        "",
    );
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    f.finish(&failed, "failed");
    tick_at(&f, &s, "2026-09-23T10:00:25Z").await;
    tick_at(&f, &s, "2026-09-23T10:00:45Z").await;
    let occurred = |f: &Fixture, occurred: bool| {
        f.sink
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.kind == Cond::BackupFailed && e.occurred == occurred)
            .cloned()
            .collect::<Vec<_>>()
    };
    let reported = occurred(&f, true);
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(reported[0].subject_id, PG);
    assert_eq!(reported[0].source, "backup");
    assert_eq!(backup_runs(&f)[0].status, BackupRunStatus::Failed as i32);
    let succeeded = f.record(
        3,
        &[json!({"kind": "backup.run", "params": {"resource_id": PG}})],
        "",
    );
    tick_at(&f, &s, "2026-09-23T10:01:05Z").await;
    f.finish(&succeeded, "succeeded");
    tick_at(&f, &s, "2026-09-23T10:01:25Z").await;
    assert_eq!(occurred(&f, false).len(), 1);
    assert_eq!(occurred(&f, true).len(), 1);
}

#[test]
fn locations_follow_the_section_3_8_layout() {
    let dest = DestinationDef {
        destination_ref: "d".to_owned(),
        kind: "r2".to_owned(),
        endpoint: "https://acct.r2.cloudflarestorage.com".to_owned(),
        region: String::new(),
        bucket: "backups".to_owned(),
        prefix: "team/a".to_owned(),
        credential_digest: String::new(),
        plan_digest_hex: String::new(),
    };
    assert_eq!(
        location(&dest, "srv", "res", "bid"),
        "r2://backups/team/a/permanu/v1/srv/res/bid.age"
    );
}

const CHANNEL_A: &str = "01a0cdb5-3500-7c01-8000-000000000001";
const CHANNEL_B: &str = "01a0cdb5-3500-7c01-8000-000000000002";

/// contracts v1.1.3 (D-061): `BackupPolicy.channel_ids` comes only from the
/// signed `backup.policy.set`, and a missed run notifies those channels.
#[tokio::test]
async fn signed_channels_are_listed_and_notified_on_a_missed_run() {
    let f = Fixture::new("backup-channels", "2026-09-23T00:00:00Z");
    let mut signed = policy(PG, "0 5 * * *", Value::Null);
    signed["params"]["channel_ids"] = json!([CHANNEL_A, CHANNEL_B]);
    signed["params"]["db_credentials_ref"] =
        json!({"user": "DB_USER", "password": "DB_PASSWORD", "database": "DB_NAME"});
    f.record(1, &[signed], "succeeded");
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T00:00:05Z").await;
    let defs = s.definitions();
    let listed = s.policy_proto(&defs.policies[PG], &defs);
    assert_eq!(listed.channel_ids, vec![CHANNEL_A, CHANNEL_B]);
    tick_at(&f, &s, "2026-09-23T07:30:00Z").await;
    let events = f.sink.0.lock().unwrap().clone();
    let missed = events
        .iter()
        .find(|e| e.kind == Cond::BackupFailed && e.occurred)
        .expect("a missed run is reported");
    assert_eq!(missed.channel_ids, vec![CHANNEL_A, CHANNEL_B]);
    assert!(missed.standalone, "the policy's own channels are notified");
}

fn verify_line(plan: &str, checks: Value, verified_at: Value) -> Value {
    json!({"v": 1, "seq": 1, "at": "2026-09-23T10:00:30Z", "event": "run_result",
           "plan_id": plan, "plan_digest_hex": format!("{:064x}", 2), "action_index": 0,
           "op": "backup_verify", "scheduled_for": null, "attempt": 1, "run_id": "rr-v",
           "outcome": "succeeded", "backup_id": BACKUP_A, "backup_digest_hex": "ab".repeat(32),
           "resource_id": PG, "checks": checks, "verified_at": verified_at})
}

/// contracts v1.1.4 (D-062): a plan-bound `backup.verify` sets the
/// artifact's `last_verification` from the runner's `run_result` line of
/// that backup, exactly as a scheduled verify does.
#[tokio::test]
async fn a_manual_verify_sets_the_artifacts_last_verification() {
    for (checks, verified_at, want) in [
        (
            json!({"plaintext_digest": true, "archive_readable": true,
                   "restore_completed": true, "tables_present": true}),
            json!("2026-09-23T10:00:29Z"),
            RestoreVerificationStatus::Passed,
        ),
        (
            json!({"plaintext_digest": true, "archive_readable": true,
                   "restore_completed": true, "tables_present": false}),
            Value::Null,
            RestoreVerificationStatus::Failed,
        ),
    ] {
        let f = Fixture::new("backup-manual-verify", "2026-09-23T10:00:00Z");
        f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
        let s = scheduler(&f);
        s.put_artifact(&BackupArtifact {
            id: BACKUP_A.to_owned(),
            policy_id: PG.to_owned(),
            created_at: Some(pts(1)),
            ..Default::default()
        });
        let plan = f.record(
            2,
            &[json!({"kind": "backup.verify", "params": {"resource_id": PG, "backup_id": BACKUP_A}})],
            "succeeded",
        );
        f.append_consumed(&verify_line(&plan, checks, verified_at));
        tick_at(&f, &s, "2026-09-23T10:01:00Z").await;
        let artifact: BackupArtifact = f
            .deps
            .ops
            .get(RecordKind::Artifact, BACKUP_A)
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(artifact.last_verification, want as i32);
        let verification: RestoreVerification = f
            .deps
            .ops
            .list(
                RecordKind::Verification,
                &Listing {
                    limit: 5,
                    ..Default::default()
                },
            )
            .first()
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(verification.status, want as i32);
        assert_eq!(verification.trigger, backup_run::Trigger::Manual as i32);
        assert_eq!(verification.checks.len(), 4);
    }
}

/// contracts v1.1.3 (D-061): a plan-bound `backup.run` whose `run_result`
/// trigger is `pre_deploy` (or `pre_restore`) is `TRIGGER_PRE_CHANGE`.
#[tokio::test]
async fn a_pre_deploy_backup_is_a_pre_change_run() {
    let f = Fixture::new("backup-pre-deploy", "2026-09-23T02:00:00Z");
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    let plan = f.record(
        2,
        &[json!({"kind": "backup.run", "params": {"resource_id": PG}})],
        "succeeded",
    );
    f.append_consumed(&json!({"v": 1, "seq": 1, "at": "2026-09-23T02:00:01Z",
        "event": "run_result", "plan_id": plan, "plan_digest_hex": format!("{:064x}", 2),
        "action_index": 0, "op": "backup_run", "scheduled_for": null, "attempt": 1,
        "run_id": "rr-b", "outcome": "succeeded", "backup_id": BACKUP_B,
        "backup_digest_hex": "cd".repeat(32), "size_bytes": 1, "resource_id": PG,
        "destination_ref": "local", "trigger": "pre_deploy",
        "created_at": "2026-09-23T02:00:01Z", "verified_at": null}));
    tick_at(&f, &s, "2026-09-23T02:00:05Z").await;
    let runs = backup_runs(&f);
    assert_eq!(runs[0].trigger, backup_run::Trigger::PreChange as i32);
}

fn verifications(f: &Fixture) -> Vec<RestoreVerification> {
    f.deps
        .ops
        .list(
            RecordKind::Verification,
            &Listing {
                limit: 10,
                ..Default::default()
            },
        )
        .iter()
        .filter_map(|row| row.decode())
        .collect()
}

const VERIFY_RUN: &str = "01a0cdb5-3500-70e1-8000-000000000031";

/// contracts v1.1.6 (D-064 #8): a running scheduled verification learns the
/// runner's `run_id` from its `run` line; one a cancel stopped keeps it,
/// raises no failure and leaves `last_verification` as it was.
#[tokio::test]
async fn a_cancelled_verification_keeps_its_runner_id_and_is_not_a_failure() {
    let f = Fixture::new("backup-verify-cancel", "2026-09-27T03:00:00Z");
    let plan = f.record(
        1,
        &[policy(PG, "0 3 * * *", json!("0 4 * * 0"))],
        "succeeded",
    );
    let s = scheduler(&f);
    s.put_artifact(&BackupArtifact {
        id: BACKUP_A.to_owned(),
        policy_id: PG.to_owned(),
        last_verification: RestoreVerificationStatus::Passed as i32,
        ..Default::default()
    });
    tick_at(&f, &s, "2026-09-27T03:59:55Z").await;
    f.runner.hold("backup_verify");
    f.runner.answer(
        "backup_verify",
        json!({"ok": false, "outcome": null, "run_outcome": "cancelled", "run_id": VERIFY_RUN,
               "error": {"code": "E_CANCELLED", "message": "cancelled"}}),
    );
    f.clock.set("2026-09-27T04:00:05Z");
    s.tick();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    f.append_consumed(
        &json!({"v": 1, "seq": 1, "at": "2026-09-27T04:00:06Z", "event": "run",
        "plan_id": plan, "plan_digest_hex": format!("{:064x}", 1), "action_index": 0,
        "op": "backup_verify", "scheduled_for": "2026-09-27T04:00:00Z", "attempt": 1,
        "run_id": VERIFY_RUN}),
    );
    f.clock.set("2026-09-27T04:00:15Z");
    s.tick();
    let running = verifications(&f);
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].status, RestoreVerificationStatus::Running as i32);
    assert_eq!(running[0].runner_run_id, VERIFY_RUN);
    f.runner.release("backup_verify", 1);
    s.settle().await;
    let ended = verifications(&f);
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].runner_run_id, VERIFY_RUN);
    // proto v2.1.8 (D-066 #4).
    assert_eq!(ended[0].status, RestoreVerificationStatus::Cancelled as i32);
    assert_eq!(ended[0].error, "cancelled");
    assert!(ended[0].finished_at.is_some());
    let artifact: BackupArtifact = f
        .deps
        .ops
        .get(RecordKind::Artifact, BACKUP_A)
        .unwrap()
        .decode()
        .unwrap();
    assert_eq!(
        artifact.last_verification,
        RestoreVerificationStatus::Passed as i32
    );
    assert!(f.sink.0.lock().unwrap().is_empty());
}

/// contracts v1.1.8 (D-066 #4): a plan-bound verification an
/// `operation.cancel` stopped ends `CANCELLED` and leaves the artifact's
/// `last_verification` as it was.
#[tokio::test]
async fn a_cancelled_manual_verification_is_cancelled_and_keeps_last_verification() {
    for with_line in [true, false] {
        let f = Fixture::new("backup-manual-verify-cancel", "2026-09-23T10:00:00Z");
        f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
        let s = scheduler(&f);
        s.put_artifact(&BackupArtifact {
            id: BACKUP_A.to_owned(),
            policy_id: PG.to_owned(),
            created_at: Some(pts(1)),
            last_verification: RestoreVerificationStatus::Passed as i32,
            ..Default::default()
        });
        let plan = f.record(
            2,
            &[json!({"kind": "backup.verify", "params": {"resource_id": PG, "backup_id": BACKUP_A}})],
            "cancelled",
        );
        if with_line {
            let mut line = verify_line(&plan, Value::Null, Value::Null);
            line["outcome"] = json!("cancelled");
            f.append_consumed(&line);
        }
        tick_at(&f, &s, "2026-09-23T10:01:00Z").await;
        let ended = verifications(&f);
        assert_eq!(ended.len(), 1, "with_line {with_line}");
        assert_eq!(
            ended[0].status,
            RestoreVerificationStatus::Cancelled as i32,
            "with_line {with_line}"
        );
        assert_eq!(ended[0].error, "cancelled");
        let artifact: BackupArtifact = f
            .deps
            .ops
            .get(RecordKind::Artifact, BACKUP_A)
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(
            artifact.last_verification,
            RestoreVerificationStatus::Passed as i32,
            "with_line {with_line}"
        );
    }
}

/// contracts v1.1.6 (D-064 #8): a plan-bound verification takes the
/// runner's `run_id` of its action from the `run` line while it runs.
#[tokio::test]
async fn a_manual_verification_learns_its_runner_run_id() {
    let f = Fixture::new("backup-manual-verify-id", "2026-09-23T10:00:00Z");
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    let plan = f.record(
        2,
        &[json!({"kind": "backup.verify", "params": {"resource_id": PG, "backup_id": BACKUP_A}})],
        "",
    );
    f.append_consumed(
        &json!({"v": 1, "seq": 1, "at": "2026-09-23T10:00:01Z", "event": "run",
        "plan_id": plan, "plan_digest_hex": format!("{:064x}", 2), "action_index": 0,
        "op": "backup_verify", "scheduled_for": null, "attempt": 1, "run_id": VERIFY_RUN}),
    );
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    let running = verifications(&f);
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].status, RestoreVerificationStatus::Running as i32);
    assert_eq!(running[0].runner_run_id, VERIFY_RUN);
}

/// v2.1.9 (D-067 #8): a verification of an empty database passes and
/// carries the runner's note `no tables`; other answers carry no note.
#[test]
fn a_verified_empty_database_carries_the_no_tables_note() {
    let checks = json!({"plaintext_digest": true, "archive_readable": true,
        "restore_completed": true, "tables_present": true});
    let mut empty = RestoreVerification::default();
    apply_verify_result(
        &mut empty,
        &Ok(json!({"outcome": "succeeded", "checks": checks, "note": "no tables"})),
    );
    assert_eq!(empty.status, RestoreVerificationStatus::Passed as i32);
    assert_eq!(empty.note, "no tables");
    let mut full = RestoreVerification::default();
    apply_verify_result(
        &mut full,
        &Ok(json!({"outcome": "succeeded", "checks": checks, "note": null})),
    );
    assert_eq!(full.note, "");
    let mut long = RestoreVerification::default();
    apply_verify_result(
        &mut long,
        &Ok(json!({"outcome": "succeeded", "checks": checks, "note": "x".repeat(500)})),
    );
    assert_eq!(long.note.len(), 128);
}

/// contracts v1.1.10 (D-068 #6): the note comes from the runner's result of
/// every verification, scheduled (the wire `result`) or plan-bound (the
/// consumed log's `run_result` line), and is kept on the recorded
/// verification the engine maps into `Backup.verify_note`.
#[tokio::test]
async fn every_verification_records_the_runners_note() {
    let checks = json!({"plaintext_digest": true, "archive_readable": true,
        "restore_completed": true, "tables_present": true});

    let f = Fixture::new("backup-verify-note-sched", "2026-09-27T03:00:00Z");
    f.record(
        1,
        &[policy(PG, "0 3 * * *", json!("0 4 * * 0"))],
        "succeeded",
    );
    let s = scheduler(&f);
    s.put_artifact(&BackupArtifact {
        id: BACKUP_A.to_owned(),
        policy_id: PG.to_owned(),
        ..Default::default()
    });
    tick_at(&f, &s, "2026-09-27T03:59:55Z").await;
    f.runner.answer(
        "backup_verify",
        json!({"outcome": null, "run_outcome": "succeeded", "backup_id": BACKUP_A,
               "checks": checks, "verified_at": "2026-09-27T04:00:04Z", "note": "no tables"}),
    );
    tick_at(&f, &s, "2026-09-27T04:00:05Z").await;
    let scheduled = verifications(&f);
    assert_eq!(scheduled.len(), 1);
    assert_eq!(
        scheduled[0].status,
        RestoreVerificationStatus::Passed as i32
    );
    assert_eq!(scheduled[0].note, "no tables");

    let f = Fixture::new("backup-verify-note-plan", "2026-09-23T10:00:00Z");
    f.record(1, &[policy(PG, "0 3 * * *", Value::Null)], "succeeded");
    let s = scheduler(&f);
    s.put_artifact(&BackupArtifact {
        id: BACKUP_A.to_owned(),
        policy_id: PG.to_owned(),
        created_at: Some(pts(1)),
        ..Default::default()
    });
    let plan = f.record(
        2,
        &[json!({"kind": "backup.verify", "params": {"resource_id": PG, "backup_id": BACKUP_A}})],
        "succeeded",
    );
    let mut line = verify_line(&plan, checks, json!("2026-09-23T10:00:29Z"));
    line["note"] = json!("no tables");
    f.append_consumed(&line);
    tick_at(&f, &s, "2026-09-23T10:01:00Z").await;
    let manual = verifications(&f);
    assert_eq!(manual.len(), 1);
    assert_eq!(manual[0].status, RestoreVerificationStatus::Passed as i32);
    assert_eq!(manual[0].note, "no tables");
}
