use serde_json::{json, Value};

use super::super::test_support::{at, Fixture, CRON, WEB};
use super::*;
use crate::proto::agent::v2::event_condition::Kind as EventKindCond;

fn cron(kind: &str, schedule: &str, overlap: &str, retries: u32) -> Value {
    json!({"kind": kind, "params": {"cron_id": CRON, "service_id": WEB, "name": "nightly",
        "schedule": schedule, "timezone": "UTC", "command": ["bin/task"],
        "timeout_seconds": 60, "retries": retries, "overlap": overlap,
        "heartbeat_alert": true}})
}

fn id_only(kind: &str) -> Value {
    json!({"kind": kind, "params": {"cron_id": CRON}})
}

fn scheduler(f: &Fixture) -> Arc<CronScheduler> {
    CronScheduler::new(f.deps.clone(), f.sink.clone())
}

fn runs(f: &Fixture) -> Vec<CronRun> {
    let mut runs: Vec<CronRun> = f
        .deps
        .ops
        .list(
            RecordKind::CronRun,
            &Listing {
                limit: 1_000,
                ascending: true,
                ..Default::default()
            },
        )
        .iter()
        .filter_map(|row| row.decode())
        .collect();
    runs.sort_by_key(|r| (r.scheduled_for.map(|t| t.seconds), r.attempt));
    runs
}

fn statuses(f: &Fixture) -> Vec<(String, u32, i32)> {
    runs(f)
        .iter()
        .map(|r| {
            (
                r.scheduled_for.map(|t| rfc(t.seconds)).unwrap_or_default(),
                r.attempt,
                r.status,
            )
        })
        .collect()
}

async fn tick_at(f: &Fixture, s: &Arc<CronScheduler>, now: &str) {
    f.clock.set(now);
    s.tick();
    s.settle().await;
}

#[tokio::test]
async fn a_recorded_job_runs_at_its_fire_time_with_a_schedule_binding() {
    let f = Fixture::new("cron-fires", "2026-09-23T10:00:00Z");
    let plan_id = f.record(
        1,
        &[cron("cron.create", "*/15 * * * *", "skip", 0)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    tick_at(&f, &s, "2026-09-23T10:14:55Z").await;
    assert!(f.runner.ops("run_cron").is_empty());
    f.runner.answer(
        "run_cron",
        json!({"outcome": "succeeded", "exit_code": 0, "container_name": "c1"}),
    );
    tick_at(&f, &s, "2026-09-23T10:15:05Z").await;
    let sent = f.runner.ops("run_cron");
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0],
        json!({"op": "run_cron", "schedule": {"plan_id": plan_id,
            "plan_digest_hex": format!("{:064x}", 1), "action_index": 0,
            "scheduled_for": "2026-09-23T10:15:00Z", "attempt": 1}, "payload": {}})
    );
    let recorded = runs(&f);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].status, CronRunStatus::Succeeded as i32);
    assert_eq!(recorded[0].trigger, CronTrigger::Schedule as i32);
    assert_eq!(recorded[0].container_name, "c1");
    assert_eq!(recorded[0].plan_id, plan_id);
    // The same fire time never runs twice.
    tick_at(&f, &s, "2026-09-23T10:15:15Z").await;
    assert_eq!(f.runner.ops("run_cron").len(), 1);
    let job = s.jobs().remove(CRON).unwrap();
    let proto = s.job_proto(&job);
    assert_eq!(
        proto.next_run_at.unwrap().seconds,
        at("2026-09-23T10:30:00Z")
    );
    assert_eq!(proto.name, "nightly");
    assert_eq!(proto.overlap, OverlapPolicy::Skip as i32);
    assert_eq!(
        proto.last_run.unwrap().status,
        CronRunStatus::Succeeded as i32
    );
}

#[tokio::test]
async fn unrecorded_paused_and_deleted_jobs_never_run() {
    let f = Fixture::new("cron-unrecorded", "2026-09-23T10:00:00Z");
    // Admitted but not recorded by the runner yet.
    f.record(1, &[cron("cron.create", "* * * * *", "skip", 0)], "");
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    tick_at(&f, &s, "2026-09-23T10:01:05Z").await;
    assert!(f.runner.ops("run_cron").is_empty());
    assert!(s.jobs().is_empty());

    let g = Fixture::new("cron-paused", "2026-09-23T10:00:00Z");
    g.record(
        1,
        &[cron("cron.create", "* * * * *", "skip", 0)],
        "succeeded",
    );
    g.record(2, &[id_only("cron.pause")], "succeeded");
    let s = scheduler(&g);
    tick_at(&g, &s, "2026-09-23T10:00:05Z").await;
    tick_at(&g, &s, "2026-09-23T10:01:05Z").await;
    assert!(g.runner.ops("run_cron").is_empty());
    assert!(!s.jobs()[CRON].enabled);
    // A pause admitted after a resume that is not recorded yet keeps it
    // paused; the recorded resume starts it again, from now.
    g.record(3, &[id_only("cron.resume")], "succeeded");
    tick_at(&g, &s, "2026-09-23T10:02:05Z").await;
    assert!(s.jobs()[CRON].enabled);
    g.record(4, &[id_only("cron.delete")], "succeeded");
    tick_at(&g, &s, "2026-09-23T10:03:05Z").await;
    assert!(s.jobs().is_empty());
}

#[tokio::test]
async fn failed_attempts_retry_with_backoff_then_raise_the_heartbeat() {
    let f = Fixture::new("cron-retry", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "0 * * * *", "skip", 2)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:59:55Z").await;
    f.runner
        .answer("run_cron", json!({"outcome": "failed", "exit_code": 3}));
    tick_at(&f, &s, "2026-09-23T11:00:05Z").await;
    // Attempt 1 failed: a retry waits 10 s.
    tick_at(&f, &s, "2026-09-23T11:00:10Z").await;
    assert_eq!(f.runner.ops("run_cron").len(), 1);
    tick_at(&f, &s, "2026-09-23T11:00:15Z").await;
    assert_eq!(f.runner.ops("run_cron").len(), 2);
    // Attempt 2 failed: 20 s.
    tick_at(&f, &s, "2026-09-23T11:00:30Z").await;
    assert_eq!(f.runner.ops("run_cron").len(), 2);
    tick_at(&f, &s, "2026-09-23T11:00:35Z").await;
    let sent = f.runner.ops("run_cron");
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[2]["schedule"]["attempt"], 3);
    assert_eq!(sent[2]["schedule"]["scheduled_for"], "2026-09-23T11:00:00Z");
    let all = runs(&f);
    assert_eq!(
        all.iter()
            .map(|r| (r.attempt, r.trigger))
            .collect::<Vec<_>>(),
        [
            (1, CronTrigger::Schedule as i32),
            (2, CronTrigger::Retry as i32),
            (3, CronTrigger::Retry as i32)
        ]
    );
    assert_eq!(all[0].exit_code, 3);
    assert!(all[0].next_retry_at.is_some());
    assert!(
        all[2].next_retry_at.is_none(),
        "the last attempt schedules nothing"
    );
    let events = f.sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKindCond::CronFailed);
    assert!(events[0].occurred && events[0].standalone);
    assert_eq!(events[0].subject_id, CRON);
    // The next succeeded chain resolves it.
    f.runner.only("run_cron", json!({"outcome": "succeeded"}));
    tick_at(&f, &s, "2026-09-23T12:00:05Z").await;
    let events = f.sink.0.lock().unwrap().clone();
    assert!(events[1..].iter().all(|e| !e.occurred));
    assert_eq!(events.len(), 3, "CRON_FAILED and CRON_MISSED resolve");
}

/// The real runner answers a failed schedule-bound run with `ok: false`,
/// `outcome: null` and the run's own `run_outcome` (jobs::bound::finish).
#[tokio::test]
async fn a_runner_shaped_failed_run_retries_and_keeps_its_exit_code() {
    let f = Fixture::new("cron-runner-shape", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "0 * * * *", "skip", 1)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:59:55Z").await;
    f.runner.answer(
        "run_cron",
        json!({"ok": false, "outcome": null, "run_outcome": "failed", "exit_code": 3,
               "error": {"code": "runtime_failed", "message": "the cron command failed"}}),
    );
    f.runner.answer(
        "run_cron",
        json!({"ok": false, "outcome": null, "run_outcome": "timeout",
               "error": {"code": "deadline_exceeded", "message": "the cron run passed its timeout"}}),
    );
    tick_at(&f, &s, "2026-09-23T11:00:05Z").await;
    tick_at(&f, &s, "2026-09-23T11:00:15Z").await;
    let sent = f.runner.ops("run_cron");
    assert_eq!(sent.len(), 2, "a failed run is retried");
    assert_eq!(sent[1]["schedule"]["attempt"], 2);
    let all = runs(&f);
    assert_eq!(all[0].status, CronRunStatus::Failed as i32);
    assert_eq!(all[0].exit_code, 3);
    assert_eq!(all[1].status, CronRunStatus::TimedOut as i32);
}

#[tokio::test]
async fn a_refused_run_is_not_retried() {
    let f = Fixture::new("cron-refused", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "0 * * * *", "skip", 3)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:59:55Z").await;
    f.runner.answer(
        "run_cron",
        json!({"ok": false, "error": {"code": "E_SCHEDULE_SUPERSEDED", "message": "m"}}),
    );
    tick_at(&f, &s, "2026-09-23T11:00:05Z").await;
    tick_at(&f, &s, "2026-09-23T11:05:00Z").await;
    assert_eq!(f.runner.ops("run_cron").len(), 1);
    let all = runs(&f);
    assert_eq!(all[0].status, CronRunStatus::Failed as i32);
    assert_eq!(all[0].error, "E_SCHEDULE_SUPERSEDED: m");
}

async fn spin() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn overlap_skip_queue_and_allow() {
    use CronRunStatus::{Pending, Running, SkippedOverlap};
    for (overlap, started, expect) in [
        ("skip", 1, [Running, SkippedOverlap, SkippedOverlap]),
        ("queue", 1, [Running, Pending, SkippedOverlap]),
        ("allow", 3, [Running, Running, Running]),
    ] {
        let f = Fixture::new(&format!("cron-overlap-{overlap}"), "2026-09-23T10:00:00Z");
        f.record(
            1,
            &[cron("cron.create", "* * * * *", overlap, 0)],
            "succeeded",
        );
        let s = scheduler(&f);
        f.runner.hold("run_cron");
        f.runner.answer("run_cron", json!({"outcome": "succeeded"}));
        for now in [
            "2026-09-23T10:00:05Z",
            "2026-09-23T10:01:05Z",
            "2026-09-23T10:02:05Z",
            "2026-09-23T10:03:05Z",
        ] {
            f.clock.set(now);
            s.tick();
            spin().await;
        }
        let got: Vec<i32> = runs(&f).iter().map(|r| r.status).collect();
        assert_eq!(got, expect.map(|s| s as i32), "{overlap}");
        assert_eq!(f.runner.ops("run_cron").len(), started, "{overlap}");
        if overlap == "queue" {
            // The queued chain starts when the active one ends.
            f.runner.release("run_cron", 1);
            s.settle_one().await;
            spin().await;
            assert_eq!(f.runner.ops("run_cron").len(), 2);
        }
        f.runner.release("run_cron", 10);
        s.settle().await;
    }
}

#[tokio::test]
async fn downtime_records_one_missed_run_and_runs_the_latest_late() {
    let f = Fixture::new("cron-missed", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "*/15 * * * *", "skip", 0)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    f.runner.answer("run_cron", json!({"outcome": "succeeded"}));
    // Down from 10:00:05 to 12:00:30: 10:15 … 11:45 missed, 12:00 runs late.
    tick_at(&f, &s, "2026-09-23T12:00:30Z").await;
    let all = runs(&f);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].status, CronRunStatus::Missed as i32);
    assert_eq!(all[0].missed_count, 7);
    assert_eq!(
        rfc(all[0].scheduled_for.unwrap().seconds),
        "2026-09-23T10:15:00Z"
    );
    assert_eq!(all[1].status, CronRunStatus::Succeeded as i32);
    assert_eq!(
        rfc(all[1].scheduled_for.unwrap().seconds),
        "2026-09-23T12:00:00Z"
    );
    let events = f.sink.0.lock().unwrap().clone();
    assert_eq!(events[0].kind, EventKindCond::CronMissed);
    // Down past the latest fire time + 120 s: nothing runs late.
    tick_at(&f, &s, "2026-09-23T12:18:00Z").await;
    let all = runs(&f);
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].status, CronRunStatus::Missed as i32);
    assert_eq!(all[2].missed_count, 1);
    assert_eq!(f.runner.ops("run_cron").len(), 1);
}

#[tokio::test]
async fn a_backward_clock_jump_never_reruns_a_fire_time() {
    let f = Fixture::new("cron-backward", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "*/15 * * * *", "skip", 0)],
        "succeeded",
    );
    let s = scheduler(&f);
    f.runner.answer("run_cron", json!({"outcome": "succeeded"}));
    tick_at(&f, &s, "2026-09-23T10:14:58Z").await;
    tick_at(&f, &s, "2026-09-23T10:15:05Z").await;
    tick_at(&f, &s, "2026-09-23T10:10:00Z").await;
    tick_at(&f, &s, "2026-09-23T10:14:58Z").await;
    tick_at(&f, &s, "2026-09-23T10:15:06Z").await;
    assert_eq!(f.runner.ops("run_cron").len(), 1);
}

#[tokio::test]
async fn jobs_fire_in_their_own_timezone() {
    let f = Fixture::new("cron-tz", "2026-09-23T12:00:00Z");
    let mut job = cron("cron.create", "0 9 * * *", "skip", 0);
    job["params"]["timezone"] = json!("America/New_York");
    f.record(1, &[job], "succeeded");
    let s = scheduler(&f);
    f.runner.answer("run_cron", json!({"outcome": "succeeded"}));
    tick_at(&f, &s, "2026-09-23T12:59:55Z").await;
    assert!(f.runner.ops("run_cron").is_empty());
    tick_at(&f, &s, "2026-09-23T13:00:05Z").await;
    assert_eq!(
        f.runner.ops("run_cron")[0]["schedule"]["scheduled_for"],
        "2026-09-23T13:00:00Z"
    );
    assert_eq!(statuses(&f).len(), 1);
}

#[tokio::test]
async fn at_most_eight_cron_containers_run_per_server() {
    let f = Fixture::new("cron-slots", "2026-09-23T10:00:00Z");
    let actions: Vec<Value> = (0..10)
        .map(|n| {
            let mut job = cron("cron.create", "* * * * *", "skip", 0);
            job["params"]["cron_id"] = json!(format!("01a0cdb5-3500-70d2-8000-00000000010{n}"));
            job
        })
        .collect();
    f.record(1, &actions, "succeeded");
    let s = scheduler(&f);
    f.runner.hold("run_cron");
    f.runner.answer("run_cron", json!({"outcome": "succeeded"}));
    f.clock.set("2026-09-23T10:00:05Z");
    s.tick();
    f.clock.set("2026-09-23T10:01:05Z");
    s.tick();
    spin().await;
    assert_eq!(f.runner.ops("run_cron").len(), 8);
    let pending = runs(&f)
        .iter()
        .filter(|r| r.status == CronRunStatus::Pending as i32)
        .count();
    assert_eq!(pending, 2);
    f.runner.release("run_cron", 100);
    s.settle().await;
    assert_eq!(f.runner.ops("run_cron").len(), 10);
}

#[tokio::test]
async fn manual_runs_follow_their_admission_and_count_for_overlap() {
    let f = Fixture::new("cron-manual", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "0 0 1 1 *", "skip", 0)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    assert!(s.manual_allowed(CRON).is_ok());
    let plan = f.record(2, &[id_only("cron.run")], "");
    let run = s.record_manual(CRON, &plan, "op-1");
    assert_eq!(run.trigger, CronTrigger::Manual as i32);
    assert_eq!(
        s.manual_allowed(CRON),
        Err("overlap: a run of this job is still active")
    );
    tick_at(&f, &s, "2026-09-23T10:00:15Z").await;
    assert_eq!(runs(&f).len(), 1, "no second record for the same plan");
    f.finish(&plan, "failed");
    tick_at(&f, &s, "2026-09-23T10:00:25Z").await;
    let all = runs(&f);
    assert_eq!(all[0].status, CronRunStatus::Failed as i32);
    assert_eq!(all[0].operation_id, "op-1");
    assert!(s.manual_allowed(CRON).is_ok());
    assert_eq!(s.manual_allowed("other"), Err("unknown cron job"));
}

/// A manual run (`cron.run`, plan-bound `run_cron`) takes its exit code,
/// output size, container and `timeout` outcome from the runner's
/// `run_result` line of that action (signed-plan.md 14.8), as a scheduled
/// run takes them from the runner's answer: a failed `exit 3` must not read
/// as exit code 0.
#[tokio::test]
async fn a_manual_run_keeps_the_runners_exit_code_and_outcome() {
    let f = Fixture::new("cron-manual-result", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "0 0 1 1 *", "skip", 0)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    let result = |seq: i64, plan: &str, outcome: &str, fields: Value| {
        let mut line = json!({"v": 1, "seq": seq, "at": "2026-09-23T10:00:07Z",
            "event": "run_result", "plan_id": plan, "plan_digest_hex": format!("{seq:064x}"),
            "action_index": 0, "op": "run_cron", "scheduled_for": null, "attempt": 1,
            "run_id": format!("rr-{seq}"), "outcome": outcome, "output_bytes": 14,
            "container_name": format!("permanu-run-{seq}")});
        for (key, value) in fields.as_object().unwrap() {
            line[key] = value.clone();
        }
        line
    };
    let failed = f.record(2, &[id_only("cron.run")], "");
    s.record_manual(CRON, &failed, "op-2");
    f.append_consumed(&result(2, &failed, "failed", json!({"exit_code": 3})));
    f.finish(&failed, "failed");
    tick_at(&f, &s, "2026-09-23T10:00:15Z").await;
    let timed_out = f.record(3, &[id_only("cron.run")], "");
    s.record_manual(CRON, &timed_out, "op-3");
    f.append_consumed(&result(3, &timed_out, "timeout", json!({})));
    f.finish(&timed_out, "failed");
    tick_at(&f, &s, "2026-09-23T10:00:25Z").await;
    let all = runs(&f);
    let by_plan = |plan: &str| all.iter().find(|run| run.plan_id == plan).cloned().unwrap();
    let run = by_plan(&failed);
    assert_eq!(run.status, CronRunStatus::Failed as i32);
    assert_eq!(run.exit_code, 3);
    assert_eq!(run.output_bytes, 14);
    assert_eq!(run.container_name, "permanu-run-2");
    let run = by_plan(&timed_out);
    assert_eq!(run.status, CronRunStatus::TimedOut as i32);
}

/// contracts v1.1.5 (D-063 #3, agent-protocol.md 10.1): a manual run is a
/// single attempt, whatever the job's `retries`; its failure ends the chain
/// (and reports `CRON_FAILED`) with no retry.
#[tokio::test]
async fn a_failed_manual_run_is_never_retried() {
    let f = Fixture::new("cron-manual-once", "2026-09-23T10:00:00Z");
    f.record(
        1,
        &[cron("cron.create", "0 0 1 1 *", "skip", 3)],
        "succeeded",
    );
    let s = scheduler(&f);
    tick_at(&f, &s, "2026-09-23T10:00:05Z").await;
    let manual = f.record(2, &[id_only("cron.run")], "");
    s.record_manual(CRON, &manual, "op-2");
    f.append_consumed(&json!({"v": 1, "seq": 2, "at": "2026-09-23T10:00:07Z",
        "event": "run_result", "plan_id": manual, "plan_digest_hex": format!("{:064x}", 2),
        "action_index": 0, "op": "run_cron", "scheduled_for": null, "attempt": 1,
        "run_id": "rr-2", "outcome": "failed", "exit_code": 1}));
    f.finish(&manual, "failed");
    for now in [
        "2026-09-23T10:00:15Z",
        "2026-09-23T10:00:40Z",
        "2026-09-23T10:02:00Z",
        "2026-09-23T10:15:00Z",
    ] {
        tick_at(&f, &s, now).await;
    }
    let all = runs(&f);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0].status, CronRunStatus::Failed as i32);
    assert!(all[0].next_retry_at.is_none());
    assert!(f.runner.ops("run_cron").is_empty());
    // The chain ended: a new manual run is allowed at once.
    assert!(s.manual_allowed(CRON).is_ok());
    assert!(f
        .sink
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.kind == EventKindCond::CronFailed && e.occurred));
}

#[test]
fn backoff_doubles_from_ten_seconds_up_to_ten_minutes() {
    assert_eq!(
        (1..=8).map(backoff).collect::<Vec<_>>(),
        [10, 20, 40, 80, 160, 320, 600, 600]
    );
}

/// contracts v1.1.3 (D-061, agent-protocol.md 9.4): a cron line's
/// `cron_run_id` (the runner's `run_id`) resolves through the runner's
/// `run` line to the agent's `CronRun` of that plan, fire time and attempt.
#[test]
fn runner_run_ids_resolve_to_cron_runs() {
    use crate::local::telemetry::ingest::CronRuns;
    let f = Fixture::new("cron-run-ids", "2026-09-23T10:00:00Z");
    let definition = "01a0cdb5-3500-7001-8000-0000000000d1";
    let manual_plan = "01a0cdb5-3500-7001-8000-0000000000d2";
    let fire = at("2026-09-23T09:00:00Z");
    let put = |run: &CronRun| {
        f.deps
            .ops
            .put(
                RecordKind::CronRun,
                &run.id,
                &run.cron_id,
                "",
                run.status,
                0,
                run,
            )
            .unwrap();
    };
    for (id, attempt) in [("run-a1", 1), ("run-a2", 2)] {
        put(&CronRun {
            id: id.to_owned(),
            cron_id: CRON.to_owned(),
            attempt,
            scheduled_for: Some(pts(fire)),
            plan_id: definition.to_owned(),
            ..Default::default()
        });
    }
    put(&CronRun {
        id: "run-manual".to_owned(),
        cron_id: CRON.to_owned(),
        attempt: 1,
        plan_id: manual_plan.to_owned(),
        ..Default::default()
    });
    let run_line = |seq: u64, plan: &str, scheduled_for: Value, attempt: u32, run_id: &str| {
        json!({"v": 1, "seq": seq, "at": "2026-09-23T09:00:01Z", "event": "run",
               "plan_id": plan, "plan_digest_hex": "ab".repeat(32), "action_index": 0,
               "op": "run_cron", "scheduled_for": scheduled_for, "attempt": attempt,
               "run_id": run_id})
    };
    f.append_consumed(&run_line(
        1,
        definition,
        json!("2026-09-23T09:00:00Z"),
        2,
        "rr-sched",
    ));
    f.append_consumed(&run_line(2, manual_plan, Value::Null, 1, "rr-manual"));
    let index = super::super::CronRunIndex::from_parts(
        f.deps.ops.clone(),
        f.deps.consumed_log.clone().unwrap(),
    );
    assert_eq!(index.cron_run("rr-sched", CRON).as_deref(), Some("run-a2"));
    assert_eq!(
        index.cron_run("rr-manual", CRON).as_deref(),
        Some("run-manual")
    );
    assert_eq!(index.cron_run("rr-sched", "other-cron"), None);
    assert_eq!(index.cron_run("rr-unknown", CRON), None);
}
