use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use rusqlite::params;
use serde_json::Value;

use super::*;
use crate::signed_plan::test_support::{plan_vector, temp_dir, test_trust, TestSigner, SERVER_A};
use crate::signed_plan::text::timestamp;
use crate::signed_plan::verify::Submitter;
use crate::signed_plan::PlanCode;

const NOW: &str = "2026-09-23T10:05:00Z";
const USER_DEPLOY_HEAD_BEFORE: &str =
    "4a98af3eeae054bf7585746ce20fa5907ec9c079ee1b049a7d01146d1c92ebfb";
const USER_DEPLOY_HEAD_AFTER: &str =
    "46621faca524ff37eeb468903e0fb7faf0bfb27520fbb8b7521d9e7e7f05f766";
const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";

fn now() -> i64 {
    timestamp(NOW).unwrap()
}

fn config(dir: &Path) -> StoreConfig {
    StoreConfig {
        path: dir.join("agent/admissions.db"),
        owner: None,
    }
}

impl AdmissionStore {
    fn raw(&self, sql: &str) {
        self.lock().execute_batch(sql).unwrap();
    }

    fn count(&self, table: &str) -> i64 {
        self.lock()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
}

/// Seeds the production head of the vector context through a prior admission.
fn seed_head(store: &AdmissionStore, head: &str) {
    store.raw(&format!(
        "INSERT INTO admissions (plan_id, plan_digest_hex, signed_plan_json, submitter, \
         operation_id, admitted_at, finished_at, outcome, admission_seq, nonce, author_kind, \
         signer_key_ids, action_kinds, project_id, environment, head_before_hex, head_after_hex, \
         rule_id, delivery_id, expires_at) VALUES ('01a0cdb5-3500-7001-8000-0000000000aa', \
         '{0}', '{{}}', 'client', '01a0cdb5-3500-7001-8000-0000000000ab', '2026-09-23T09:00:00Z', \
         '2026-09-23T09:01:00Z', 'succeeded', 1, 'seed-nonce', 'user', '[]', '[\"deploy\"]', \
         '{PROJECT}', 'production', '{0}', '{head}', NULL, NULL, '2026-09-23T09:10:00Z'); \
         INSERT INTO heads VALUES ('{PROJECT}', 'production', '{head}', \
         '01a0cdb5-3500-7001-8000-0000000000aa', '2026-09-23T09:00:00Z');",
        "0".repeat(64)
    ));
}

fn user_deploy() -> (String, Vec<String>) {
    let case = plan_vector("user-deploy");
    let envelope = serde_json::to_string(&case["signed_plan"]).unwrap();
    let specs = case["specs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["jcs"].as_str().unwrap().to_owned())
        .collect();
    (envelope, specs)
}

fn input<'a>(envelope: &'a str, specs: &'a [String], now: i64) -> AdmitInput<'a> {
    AdmitInput {
        envelope: envelope.as_bytes(),
        specs,
        sealed_secrets: &[],
        submitter: Submitter::Client,
        now,
    }
}

#[test]
fn creates_the_normative_schema_with_wal_modes_and_version() {
    let dir = temp_dir("store-create");
    let (store, report) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    assert!(report.created && !report.recreated);
    assert_eq!(report.quarantine_ends_at, None);
    let conn = store.lock();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1);
    for table in [
        "meta",
        "seen",
        "admissions",
        "admission_actions",
        "specs",
        "heads",
        "rules",
        "rule_invocations",
        "deliveries",
        "rejected_deliveries",
        "delivery_consumptions",
        "builds",
        "sealed_secrets",
        "consumed_reconciliation",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "{table}");
    }
    // The column names the runner reads (section 6.4, marked R).
    conn.query_row(
        "SELECT plan_id, plan_digest_hex, signed_plan_json, submitter, admitted_at, finished_at, \
         outcome FROM admissions LIMIT 0",
        [],
        |_| Ok(()),
    )
    .ok();
    drop(conn);
    // A write so the WAL files exist.
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", store.path().display());
        store.secure_files().unwrap();
        let mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o640, "{path}");
    }
    let dir_mode = fs::metadata(dir.join("agent")).unwrap().mode() & 0o777;
    assert_eq!(dir_mode, 0o750);
    drop(store);
    // WAL files persist after the last connection closes.
    assert!(dir.join("agent/admissions.db-wal").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reopening_keeps_state_and_refuses_a_newer_schema() {
    let dir = temp_dir("store-reopen");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    drop(store);
    let (store, report) = AdmissionStore::open(&config(&dir), true, now()).unwrap();
    assert!(!report.created && !report.recreated);
    assert_eq!(store.count("admissions"), 1);
    store.raw("PRAGMA user_version = 9");
    drop(store);
    assert!(matches!(
        AdmissionStore::open(&config(&dir), true, now()),
        Err(StoreError::TooNew(9))
    ));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn store_loss_quarantines_for_twenty_minutes() {
    let dir = temp_dir("store-loss");
    let (store, report) = AdmissionStore::open(&config(&dir), true, now()).unwrap();
    assert!(report.recreated);
    assert_eq!(report.quarantine_ends_at, Some(now() + QUARANTINE_SECONDS));
    let trust = test_trust();
    let (envelope, specs) = user_deploy();
    assert_eq!(
        store
            .admit(&trust, &input(&envelope, &specs, now()))
            .unwrap_err(),
        PlanCode::StoreQuarantined
    );
    assert_eq!(store.count("seen"), 0);
    assert!(store.check_quarantine(now() + QUARANTINE_SECONDS).is_ok());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn corrupt_store_is_moved_aside_and_recreated_in_quarantine() {
    let dir = temp_dir("store-corrupt");
    fs::create_dir_all(dir.join("agent")).unwrap();
    fs::write(
        dir.join("agent/admissions.db"),
        b"not a database at all, sorry",
    )
    .unwrap();
    let (store, report) = AdmissionStore::open(&config(&dir), true, now()).unwrap();
    let aside = report.moved_aside.unwrap();
    assert!(aside
        .to_string_lossy()
        .ends_with("admissions.db.corrupt-2026-09-23T100500Z"));
    assert!(aside.exists());
    assert!(report.recreated);
    assert_eq!(store.count("admissions"), 0);
    assert!(store.quarantine_ends_at().unwrap().is_some());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn symlinked_store_is_never_opened() {
    let dir = temp_dir("store-link");
    fs::create_dir_all(dir.join("agent")).unwrap();
    fs::write(dir.join("elsewhere.db"), b"").unwrap();
    std::os::unix::fs::symlink(dir.join("elsewhere.db"), dir.join("agent/admissions.db")).unwrap();
    let (_store, report) = AdmissionStore::open(&config(&dir), true, now()).unwrap();
    assert!(report.moved_aside.is_some());
    assert!(!fs::symlink_metadata(dir.join("agent/admissions.db"))
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn admits_the_user_deploy_vector_advances_the_head_and_dedupes() {
    let dir = temp_dir("store-admit");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let trust = test_trust();
    let (envelope, specs) = user_deploy();
    let admission = store
        .admit(&trust, &input(&envelope, &specs, now()))
        .unwrap();
    assert!(!admission.deduplicated);
    assert_eq!(
        admission.plan_digest_hex,
        "4a40f4aecabddaaa268c0ef56f33622650edadf111b017715a2c5d1550ec70e2"
    );
    assert_eq!(admission.admitted_at, NOW);
    assert_eq!(admission.deployment_ids.len(), 1);
    assert!(crate::signed_plan::text::uuid7(
        admission.deployment_ids[0].as_deref().unwrap()
    ));
    assert!(crate::signed_plan::text::uuid7(&admission.operation_id));
    let head = store.head(PROJECT, "production").unwrap();
    assert_eq!(head.head_digest_hex, USER_DEPLOY_HEAD_AFTER);
    assert_eq!(head.last_plan_id, admission.plan_id);
    assert_eq!(store.count("seen"), 1);
    assert_eq!(store.count("specs"), 1);
    assert_eq!(store.count("admission_actions"), 1);
    let record = store.admission(&admission.plan_id).unwrap().unwrap();
    assert_eq!(record.signed_plan_json, envelope);
    assert_eq!(record.submitter, "client");
    assert_eq!(record.outcome, "");
    assert_eq!(record.finished_at, None);
    assert_eq!(record.head_after_hex, USER_DEPLOY_HEAD_AFTER);
    assert_eq!(record.signer_key_ids, vec!["dYLNItf797wK7n5moGt2cw"]);
    assert_eq!(record.admission_seq, 2);

    // Idempotent resubmission: same plan id and operation id, nothing new.
    let again = store
        .admit(&trust, &input(&envelope, &specs, now() + 30))
        .unwrap();
    assert!(again.deduplicated);
    assert_eq!(again.operation_id, admission.operation_id);
    assert_eq!(again.admitted_at, NOW);
    assert_eq!(store.count("admissions"), 2);
    assert_eq!(
        store.head(PROJECT, "production").unwrap().head_digest_hex,
        USER_DEPLOY_HEAD_AFTER
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_checks_write_nothing() {
    let dir = temp_dir("store-reject");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    // Genesis head: the vector names 4a98…, so step 9 fails.
    let trust = test_trust();
    let (envelope, specs) = user_deploy();
    assert_eq!(
        store
            .admit(&trust, &input(&envelope, &specs, now()))
            .unwrap_err(),
        PlanCode::BaseMismatch
    );
    assert_eq!(store.count("seen"), 0);
    assert_eq!(store.count("admissions"), 0);
    // Expired: step 7.
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    assert_eq!(
        store
            .admit(&trust, &input(&envelope, &specs, now() + 3_600))
            .unwrap_err(),
        PlanCode::Expired
    );
    // Missing spec: step 3s.
    assert_eq!(
        store
            .admit(&trust, &input(&envelope, &[], now()))
            .unwrap_err(),
        PlanCode::SpecMismatch
    );
    // A rule plan never comes from a client (step 5).
    let mut plan: Value = serde_json::from_str(&envelope).unwrap();
    plan["plan"]["author"]["kind"] = Value::String("rule".to_owned());
    let text = plan.to_string();
    assert_eq!(
        store
            .admit(&trust, &input(&text, &specs, now()))
            .unwrap_err(),
        PlanCode::Author
    );
    assert_eq!(store.count("seen"), 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sealed_secrets_must_match_the_signed_digests() {
    let dir = temp_dir("store-sealed");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    let trust = test_trust();
    let case = plan_vector("agent-draft-secret-set");
    let envelope = serde_json::to_string(&case["signed_plan"]).unwrap();
    let head = case["plan"]["base"]["heads"][SERVER_A].as_str().unwrap();
    if head != "0".repeat(64) {
        seed_head(&store, head);
    }
    // No ciphertext supplied for the signed digest.
    assert_eq!(
        store
            .admit(&trust, &input(&envelope, &[], now()))
            .unwrap_err(),
        PlanCode::ExecPrecondition
    );
    // A ciphertext whose digest the plan does not sign.
    let wrong = vec![b"age-encryption.org/v1\n-> X25519 abc\n".to_vec()];
    let mut with_wrong = input(&envelope, &[], now());
    with_wrong.sealed_secrets = &wrong;
    assert_eq!(
        store.admit(&trust, &with_wrong).unwrap_err(),
        PlanCode::ExecPrecondition
    );
    assert_eq!(store.count("seen"), 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn list_order_and_cursor_are_durable() {
    let dir = temp_dir("store-list");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let trust = test_trust();
    let (envelope, specs) = user_deploy();
    store
        .admit(&trust, &input(&envelope, &specs, now()))
        .unwrap();
    let first = store.admissions_after(0, 1).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].admission_seq, 1);
    let rest = store.admissions_after(first[0].admission_seq, 10).unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].action_kinds, vec!["deploy"]);
    assert!(store.admissions_after(2, 10).unwrap().is_empty());
    fs::remove_dir_all(dir).unwrap();
}

fn write_log(path: &Path, lines: &[String], torn: bool) {
    let mut text = lines.join("\n");
    text.push('\n');
    if torn {
        text.push_str("{\"v\":1,\"seq\":");
    }
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
}

fn line(seq: u64, event: &str, plan_id: &str, digest: &str, outcome: Option<&str>) -> String {
    let mut value = serde_json::json!({
        "v": 1, "seq": seq, "at": "2026-09-23T10:06:00Z", "event": event,
        "plan_id": plan_id, "plan_digest_hex": digest, "action_index": 0
    });
    if let Some(outcome) = outcome {
        value["outcome"] = Value::String(outcome.to_owned());
    }
    value.to_string()
}

#[test]
fn reconciles_the_consumed_log_into_actions_and_outcome() {
    let dir = temp_dir("store-reconcile");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let trust = test_trust();
    let (envelope, specs) = user_deploy();
    let admission = store
        .admit(&trust, &input(&envelope, &specs, now()))
        .unwrap();
    let (id, digest) = (&admission.plan_id, &admission.plan_digest_hex);
    let log = dir.join("consumed.log");
    let uid = unsafe { libc::geteuid() };
    write_log(&log, &[line(1, "consumed", id, digest, None)], true);
    let effects = store
        .reconcile(&read_consumed_log(&log, uid), now())
        .unwrap();
    assert_eq!(
        effects,
        vec![ReconcileEffect::Consumed {
            plan_id: id.clone(),
            action_index: 0
        }]
    );
    assert!(store.actions(id).unwrap()[0].consumed_at.is_some());

    write_log(
        &log,
        &[
            line(1, "consumed", id, digest, None),
            line(2, "op", id, digest, None),
            line(3, "result", id, digest, Some("succeeded")),
            line(
                5,
                "consumed",
                "01a0cdb5-3500-7001-8000-0000000000ff",
                digest,
                None,
            ),
        ],
        false,
    );
    let effects = store
        .reconcile(&read_consumed_log(&log, uid), now())
        .unwrap();
    assert!(effects.contains(&ReconcileEffect::AdmissionFinished {
        plan_id: id.clone(),
        outcome: "succeeded".to_owned()
    }));
    // The unknown plan and the seq gap are both reported.
    let unexplained = effects
        .iter()
        .filter(|e| matches!(e, ReconcileEffect::Unexplained { .. }))
        .count();
    assert_eq!(unexplained, 2);
    let record = store.admission(id).unwrap().unwrap();
    assert_eq!(record.outcome, "succeeded");
    assert_eq!(record.finished_at.as_deref(), Some("2026-09-23T10:06:00Z"));
    // Re-reading applies nothing twice.
    assert!(store
        .reconcile(&read_consumed_log(&log, uid), now())
        .unwrap()
        .is_empty());

    // A log with a foreign owner or loose mode is not trusted.
    fs::set_permissions(&log, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(!read_consumed_log(&log, uid).problems.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

/// v1.0.5 (D-044): a cancelled action's `result` line carries `cleanup`,
/// and readers ignore fields they do not know (section 14.5).
#[test]
fn a_cancelled_result_carries_its_cleanup_and_unknown_fields_are_ignored() {
    let dir = temp_dir("store-cleanup");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let (envelope, specs) = user_deploy();
    let admission = store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    let (id, digest) = (&admission.plan_id, &admission.plan_digest_hex);
    let log = dir.join("consumed.log");
    let uid = unsafe { libc::geteuid() };
    let mut cleanup = serde_json::from_str::<Value>(&line(3, "op", id, digest, None)).unwrap();
    cleanup["op"] = Value::String("cleanup_candidate".to_owned());
    cleanup["future_field"] = Value::Bool(true);
    let mut cancelled =
        serde_json::from_str::<Value>(&line(4, "result", id, digest, Some("cancelled"))).unwrap();
    cancelled["cleanup"] = Value::String("done".to_owned());
    write_log(
        &log,
        &[
            line(1, "consumed", id, digest, None),
            line(2, "op", id, digest, None),
            cleanup.to_string(),
            cancelled.to_string(),
        ],
        false,
    );
    let read = read_consumed_log(&log, uid);
    assert!(read.problems.is_empty(), "{:?}", read.problems);
    assert_eq!(read.lines[3].cleanup.as_deref(), Some("done"));
    let effects = store.reconcile(&read, now()).unwrap();
    assert!(effects.contains(&ReconcileEffect::ActionFinished {
        plan_id: id.clone(),
        action_index: 0,
        outcome: "cancelled".to_owned(),
        cleanup: Some("done".to_owned()),
    }));
    assert!(!effects
        .iter()
        .any(|e| matches!(e, ReconcileEffect::Unexplained { .. })));
    assert_eq!(store.admission(id).unwrap().unwrap().outcome, "cancelled");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn window_expiry_marks_unconsumed_actions() {
    let dir = temp_dir("store-expire");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let trust = test_trust();
    let (envelope, specs) = user_deploy();
    let admission = store
        .admit(&trust, &input(&envelope, &specs, now()))
        .unwrap();
    assert!(store.expire_windows(now() + 60).unwrap().is_empty());
    let expired = store
        .expire_windows(now() + EXECUTION_WINDOW_SECONDS + 1)
        .unwrap();
    assert_eq!(expired, vec![admission.plan_id.clone()]);
    let record = store.admission(&admission.plan_id).unwrap().unwrap();
    assert_eq!(record.outcome, "expired");
    assert_eq!(
        store.actions(&admission.plan_id).unwrap()[0].outcome,
        "expired"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn uuid7_is_well_formed_and_time_ordered() {
    let a = new_uuid7(1_758_621_600_000);
    let b = new_uuid7(1_758_621_600_001);
    assert!(crate::signed_plan::text::uuid7(&a), "{a}");
    assert!(a[..13] < b[..13]);
}

/// The runner's read-only queries (`permanu-runner`
/// `signed_plan/admissions.rs`, feat/ws3-verify) run unchanged on this store.
#[test]
fn runner_read_queries_work_on_the_agent_store() {
    let dir = temp_dir("store-runner");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let trust = test_trust();
    let (envelope, specs) = user_deploy();
    let admission = store
        .admit(&trust, &input(&envelope, &specs, now()))
        .unwrap();
    drop(store);
    let conn = rusqlite::Connection::open_with_flags(
        dir.join("agent/admissions.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    conn.pragma_update(None, "query_only", true).unwrap();
    let (digest, json, submitter, admitted_at, finished, outcome): (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT plan_digest_hex, signed_plan_json, submitter, admitted_at, finished_at, \
             outcome FROM admissions WHERE plan_id = ?1",
            params![admission.plan_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(digest, admission.plan_digest_hex);
    assert_eq!(json, envelope);
    assert_eq!(submitter, "client");
    assert_eq!(admitted_at, NOW);
    assert_eq!((finished, outcome.as_deref()), (None, Some("")));
    let (consumed, finished): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT consumed_at, finished_at FROM admission_actions \
             WHERE plan_id = ?1 AND action_index = ?2",
            params![admission.plan_id, 0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((consumed, finished), (None, None));
    let spec: String = conn
        .query_row(
            "SELECT spec_jcs FROM specs WHERE spec_digest_hex = ?1",
            params!["20c40e231982e19a4b9138d298861d23925519b97333562870a3b9f238b279f5"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(spec, specs[0]);
    conn.prepare(
        "SELECT rule, rule_digest_hex, created_by_key_id, revoked_at FROM rules \
         WHERE rule_digest_hex = ?1",
    )
    .unwrap();
    fs::remove_dir_all(dir).unwrap();
}

const ENVIRONMENT_ID: &str = "01a0cdb5-3500-70b2-8000-000000000001";
const WEB: &str = "01a0cdb5-3500-70c1-8000-000000000001";

#[test]
fn a_v1_store_migrates_through_the_v1_0_2_columns_to_version_three() {
    let dir = temp_dir("store-v1");
    let path = dir.join("agent/admissions.db");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V1_AGENT).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO meta (id, store_created_at, schema_version) VALUES (1, ?1, 1)",
            params![NOW],
        )
        .unwrap();
    }
    let (store, report) = AdmissionStore::open(&config(&dir), true, now()).unwrap();
    assert!(!report.created && !report.recreated);
    let conn = store.lock();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
    let schema: i64 = conn
        .query_row("SELECT schema_version FROM meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(schema, 3);
    // Every v1.0.2 column the runner reads exists with its default.
    conn.query_row("SELECT environment_id FROM admissions LIMIT 0", [], |_| {
        Ok(())
    })
    .ok();
    conn.execute_batch(
        "SELECT action_index, project_id, environment, service_id, name FROM sealed_secrets",
    )
    .unwrap();
    drop(conn);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_new_store_records_schema_version_three() {
    let dir = temp_dir("store-v3-new");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    let schema: i64 = store
        .lock()
        .query_row("SELECT schema_version FROM meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(schema, 3);
    fs::remove_dir_all(dir).unwrap();
}

/// signed-plan.md 6.4 (v1.0.8 DDL, migration stated in v1.0.10, D-060).
#[test]
fn a_v2_store_migrates_deliveries_and_gains_rejected_deliveries() {
    let dir = temp_dir("store-v2-to-v3");
    let path = dir.join("agent/admissions.db");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let recent = crate::signed_plan::text::format_timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 3_600,
    );
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V1_AGENT).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        conn.execute(
            "INSERT INTO meta (id, store_created_at, schema_version) VALUES (1, ?1, 2)",
            params![NOW],
        )
        .unwrap();
        seed_raw_admission(&conn, "01a0cdb5-3500-7001-8000-0000000000a1");
        for (id, digest, received, status) in [
            ("d-old", "11", "2020-01-01T00:00:00Z", "verified"),
            ("d-new", "22", recent.as_str(), "verified"),
            ("d-stale", "33", recent.as_str(), "stale"),
            ("d-ignored", "44", recent.as_str(), "ignored"),
        ] {
            conn.execute(
                "INSERT INTO deliveries VALUES (?1, 'github', ?2, 'github.com/acme/web', \
                 'refs/heads/main', ?3, '2020-01-01T00:00:00Z', ?4, ?5)",
                params![id, digest.repeat(32), "ab".repeat(20), received, status],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO delivery_consumptions VALUES ('d-new', 'rule-1', \
             '01a0cdb5-3500-7001-8000-0000000000a1', ?1)",
            params![NOW],
        )
        .unwrap();
    }
    let (store, report) = AdmissionStore::open(&config(&dir), true, now()).unwrap();
    assert!(!report.created);
    let conn = store.lock();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
    let schema: i64 = conn
        .query_row("SELECT schema_version FROM meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(schema, 3);
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1, "foreign keys are back on after the rebuild");
    let rows: Vec<(String, String, String, String, String)> = conn
        .prepare(
            "SELECT delivery_id, status, event, environments, expires_at FROM deliveries \
             ORDER BY delivery_id",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let status: Vec<(&str, &str)> = rows.iter().map(|r| (r.0.as_str(), r.1.as_str())).collect();
    assert_eq!(
        status,
        [
            ("d-ignored", "ignored"),
            ("d-new", "pending"),
            ("d-old", "expired"),
            ("d-stale", "stale")
        ]
    );
    assert!(rows.iter().all(|r| r.2 == "push" && r.3 == "[]"));
    assert_eq!(rows[2].4, "2020-01-08T00:00:00Z", "received_at + 7 days");
    // The consumption still references the rebuilt table.
    let violations: i64 = conn
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0);
    assert!(conn
        .execute(
            "INSERT INTO delivery_consumptions VALUES ('missing', 'rule-2', \
             '01a0cdb5-3500-7001-8000-0000000000a1', ?1)",
            params![NOW],
        )
        .is_err());
    conn.execute(
        "INSERT INTO rejected_deliveries VALUES (?1, 10, ?2, 'github', ?3, 'signature')",
        params!["cd".repeat(32), PROJECT, NOW],
    )
    .unwrap();
    assert!(conn
        .execute(
            "INSERT INTO deliveries (delivery_id, provider, body_digest_hex, repo, ref, commit_sha, \
             commit_time, received_at, expires_at, status) VALUES ('d-gitea', 'gitea', ?1, 'r', \
             'refs/heads/main', ?2, ?3, ?3, ?3, 'verified')",
            params!["ef".repeat(32), "ab".repeat(20), NOW],
        )
        .is_err(),
        "verified is no longer a status"
    );
    drop(conn);
    fs::remove_dir_all(dir).unwrap();
}

/// A dangling reference found by `foreign_key_check` rolls the migration
/// back: the store stays at version 2 and the open fails.
#[test]
fn a_v3_migration_with_a_dangling_reference_rolls_back() {
    let dir = temp_dir("store-v3-rollback");
    let path = dir.join("agent/admissions.db");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V1_AGENT).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        conn.execute(
            "INSERT INTO meta (id, store_created_at, schema_version) VALUES (1, ?1, 2)",
            params![NOW],
        )
        .unwrap();
        // A dangling row, as a store written without foreign keys could hold.
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute(
            "INSERT INTO delivery_consumptions VALUES ('nowhere', 'rule-1', 'no-plan', ?1)",
            params![NOW],
        )
        .unwrap();
    }
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    assert!(migrate(&mut conn).is_err());
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 2);
    let rejected: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'rejected_deliveries'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rejected, 0);
    drop(conn);
    fs::remove_dir_all(dir).unwrap();
}

fn seed_raw_admission(conn: &rusqlite::Connection, plan_id: &str) {
    conn.execute(
        "INSERT INTO admissions (plan_id, plan_digest_hex, signed_plan_json, submitter, \
         operation_id, admitted_at, admission_seq, nonce, author_kind, signer_key_ids, \
         action_kinds, head_before_hex, head_after_hex, expires_at) VALUES (?1, ?2, '{}', \
         'client', ?1, ?3, 1, ?1, 'user', '[]', '[]', ?2, ?2, ?3)",
        params![plan_id, "0".repeat(64), NOW],
    )
    .unwrap();
}

#[test]
fn admission_records_environment_id_and_deployment_ids() {
    let dir = temp_dir("store-envid");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let (envelope, specs) = user_deploy();
    let admission = store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    let record = store.admission(&admission.plan_id).unwrap().unwrap();
    assert_eq!(record.environment_id, ENVIRONMENT_ID);
    let stored: (String, Option<String>) = store
        .lock()
        .query_row(
            "SELECT a.environment_id, x.deployment_id FROM admissions a \
             JOIN admission_actions x ON x.plan_id = a.plan_id WHERE a.plan_id = ?1",
            params![admission.plan_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored.0, ENVIRONMENT_ID);
    assert_eq!(stored.1, admission.deployment_ids[0]);
    fs::remove_dir_all(dir).unwrap();
}

/// The user-deploy vector re-signed with `actions` in place of its own.
fn signed_with_actions(signer: &TestSigner, tail: &str, actions: Value) -> String {
    let mut plan = plan_vector("user-deploy")["plan"].clone();
    plan["id"] = Value::String(format!("01a0cdb5-3500-7001-8000-{tail}"));
    plan["nonce"] = Value::String(format!("{tail}AAAAAAAAAA"));
    plan["actions"] = actions;
    signer.envelope(&plan)
}

fn deploy_action() -> Value {
    plan_vector("user-deploy")["plan"]["actions"][0].clone()
}

#[test]
fn input_actions_must_be_composed_with_a_later_deploy() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let dir = temp_dir("store-compose");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let trust = test_trust();
    let (_, specs) = user_deploy();
    let env_set = serde_json::json!({"kind": "env.set", "params": {
        "service_id": WEB, "set": {"LOG_LEVEL": "debug"}, "unset": []}});
    // Alone, and before-only compositions, are refused (D-028).
    for (tail, actions, supplied) in [
        ("0000000000c1", serde_json::json!([env_set]), &[][..]),
        (
            "0000000000c2",
            serde_json::json!([deploy_action(), env_set]),
            &specs[..],
        ),
    ] {
        let envelope = signed_with_actions(&owner, tail, actions);
        assert_eq!(
            store
                .admit(&trust, &input(&envelope, supplied, now()))
                .unwrap_err(),
            PlanCode::ExecPrecondition,
            "{tail}"
        );
    }
    assert_eq!(store.count("seen"), 0);
    let envelope = signed_with_actions(
        &owner,
        "0000000000c3",
        serde_json::json!([env_set, deploy_action()]),
    );
    store
        .admit(&trust, &input(&envelope, &specs, now()))
        .unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sealed_secret_rows_carry_their_action_and_scope() {
    use sha2::{Digest, Sha256};
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let dir = temp_dir("store-sealed-scope");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let (_, specs) = user_deploy();
    let ciphertext = b"age-encryption.org/v1\n-> X25519 test\n".to_vec();
    let digest = hex::encode(Sha256::digest(&ciphertext));
    let envelope = signed_with_actions(
        &owner,
        "0000000000c4",
        serde_json::json!([
            {"kind": "secret.set", "params": {
                "service_id": WEB, "name": "API_KEY", "ciphertext_digest_hex": digest}},
            deploy_action()
        ]),
    );
    let sealed = vec![ciphertext.clone()];
    let mut with_secret = input(&envelope, &specs, now());
    with_secret.sealed_secrets = &sealed;
    let admission = store.admit(&test_trust(), &with_secret).unwrap();
    let row: (String, Vec<u8>, i64, String, String, String, String) = store
        .lock()
        .query_row(
            "SELECT plan_id, ciphertext, action_index, project_id, environment, service_id, \
             name FROM sealed_secrets WHERE ciphertext_digest_hex = ?1",
            params![digest],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        row,
        (
            admission.plan_id,
            ciphertext,
            0,
            PROJECT.to_owned(),
            "production".to_owned(),
            WEB.to_owned(),
            "API_KEY".to_owned()
        )
    );
    fs::remove_dir_all(dir).unwrap();
}

fn vector_admission(name: &str) -> (String, Vec<String>) {
    let case = plan_vector(name);
    let envelope = serde_json::to_string(&case["signed_plan"]).unwrap();
    let specs = case["specs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["jcs"].as_str().unwrap().to_owned())
        .collect();
    (envelope, specs)
}

fn stored_deployment_ids(store: &AdmissionStore, plan_id: &str) -> Vec<Option<String>> {
    store
        .lock()
        .prepare(
            "SELECT deployment_id FROM admission_actions WHERE plan_id = ?1 \
             ORDER BY action_index",
        )
        .unwrap()
        .query_map(params![plan_id], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

// D-035 (contracts v1.0.3): the agent copies the signed deploy.deployment_id
// into admission_actions.deployment_id and never mints one.
#[test]
fn a_deploy_admission_copies_the_signed_deployment_id() {
    let dir = temp_dir("store-depid");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let (envelope, specs) = user_deploy();
    let signed = plan_vector("user-deploy")["plan"]["actions"][0]["params"]["deployment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let admission = store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    assert_eq!(admission.deployment_ids, vec![Some(signed.clone())]);
    assert_eq!(
        stored_deployment_ids(&store, &admission.plan_id),
        vec![Some(signed)]
    );
    fs::remove_dir_all(dir).unwrap();
}

// D-035: a rollback's row names the release it returns to.
#[test]
fn a_rollback_admission_records_its_target_deployment_id() {
    let dir = temp_dir("store-rbid");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let (envelope, specs) = vector_admission("user-rollback");
    let admission = store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    let target = "01a0cdb5-3500-70c7-8000-000000000001".to_owned();
    assert_eq!(admission.deployment_ids, vec![Some(target.clone())]);
    assert_eq!(
        stored_deployment_ids(&store, &admission.plan_id),
        vec![Some(target)]
    );
    fs::remove_dir_all(dir).unwrap();
}

// D-035: restart rows keep deployment_id NULL; the legacy alias
// to_release_id names the rollback target the same way.
#[test]
fn restart_rows_have_no_deployment_id_and_the_legacy_alias_is_copied() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let dir = temp_dir("store-rstid");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let (_, specs) = vector_admission("user-rollback");
    let rollback = plan_vector("user-rollback")["plan"]["actions"][0].clone();
    let mut legacy = rollback.clone();
    let target = legacy["params"]
        .as_object_mut()
        .unwrap()
        .remove("to_deployment_id")
        .unwrap();
    legacy["params"]["to_release_id"] = target.clone();
    let mut restart = rollback;
    restart["kind"] = Value::String("restart".to_owned());
    restart["params"]
        .as_object_mut()
        .unwrap()
        .remove("to_deployment_id");
    let envelope = signed_with_actions(&owner, "0000000000d1", serde_json::json!([legacy]));
    let admission = store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    assert_eq!(
        admission.deployment_ids,
        vec![Some(target.as_str().unwrap().to_owned())]
    );
    // The rollback made SPEC_BASE the current spec, so a restart of it is
    // admissible.
    let mut plan = plan_vector("user-deploy")["plan"].clone();
    plan["id"] = Value::String("01a0cdb5-3500-7001-8000-0000000000d2".to_owned());
    plan["nonce"] = Value::String("0000000000d2AAAAAAAAAA".to_owned());
    plan["actions"] = serde_json::json!([restart]);
    plan["base"]["heads"][SERVER_A] =
        Value::String(store.head(PROJECT, "production").unwrap().head_digest_hex);
    let envelope = owner.envelope(&plan);
    let admission = store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    assert_eq!(admission.deployment_ids, vec![None]);
    assert_eq!(
        stored_deployment_ids(&store, &admission.plan_id),
        vec![None]
    );
    fs::remove_dir_all(dir).unwrap();
}

// D-035: a deploy whose deployment_id already names an admitted action on
// this server is refused after step 12 and writes nothing.
#[test]
fn a_deployment_id_already_admitted_is_refused() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let dir = temp_dir("store-depdup");
    let (store, _) = AdmissionStore::open(&config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    let (envelope, specs) = user_deploy();
    store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    let mut plan = plan_vector("user-deploy")["plan"].clone();
    plan["id"] = Value::String("01a0cdb5-3500-7001-8000-0000000000d3".to_owned());
    plan["nonce"] = Value::String("0000000000d3AAAAAAAAAA".to_owned());
    plan["base"]["heads"][SERVER_A] = Value::String(USER_DEPLOY_HEAD_AFTER.to_owned());
    let envelope = owner.envelope(&plan);
    let seen = store.count("seen");
    assert_eq!(
        store
            .admit(&test_trust(), &input(&envelope, &specs, now()))
            .unwrap_err(),
        PlanCode::ExecPrecondition
    );
    assert_eq!(store.count("seen"), seen);
    // A fresh id is admitted.
    plan["actions"][0]["params"]["deployment_id"] =
        Value::String("01a0cdb5-3500-70c7-8000-0000000000d3".to_owned());
    let envelope = owner.envelope(&plan);
    store
        .admit(&test_trust(), &input(&envelope, &specs, now()))
        .unwrap();
    fs::remove_dir_all(dir).unwrap();
}

fn egid() -> u32 {
    // SAFETY: getegid has no preconditions.
    unsafe { libc::getegid() }
}

fn owned_config(dir: &Path) -> StoreConfig {
    StoreConfig {
        path: dir.join("agent/admissions.db"),
        owner: Some(StoreOwner {
            // SAFETY: geteuid has no preconditions.
            uid: unsafe { libc::geteuid() },
            gid: egid(),
        }),
    }
}

// Section 6.3 (v1.0.3, QA_M1 F-16): the store and its -wal/-shm are 0640 in
// the store group, in a 2750 (setgid) directory of that group.
#[test]
fn an_owned_store_uses_the_store_group_and_a_setgid_directory() {
    let dir = temp_dir("store-owned");
    let (store, _) = AdmissionStore::open(&owned_config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    store.secure_files().unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", store.path().display());
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o640, "{path}");
        assert_eq!(meta.gid(), egid(), "{path}");
    }
    let meta = fs::metadata(dir.join("agent")).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o2750);
    assert_eq!(meta.gid(), egid());
    fs::remove_dir_all(dir).unwrap();
}

// Section 6.3: at start the agent repairs a wrong mode before it serves.
#[test]
fn reopening_repairs_the_store_and_directory_modes() {
    let dir = temp_dir("store-repair");
    let (store, _) = AdmissionStore::open(&owned_config(&dir), false, now()).unwrap();
    seed_head(&store, USER_DEPLOY_HEAD_BEFORE);
    drop(store);
    fs::set_permissions(
        dir.join("agent/admissions.db"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::set_permissions(
        dir.join("agent/admissions.db-wal"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    fs::set_permissions(dir.join("agent"), fs::Permissions::from_mode(0o755)).unwrap();
    let (_store, report) = AdmissionStore::open(&owned_config(&dir), true, now()).unwrap();
    assert!(!report.recreated);
    for suffix in ["", "-wal"] {
        let path = format!("{}{suffix}", dir.join("agent/admissions.db").display());
        assert_eq!(
            fs::metadata(&path).unwrap().mode() & 0o7777,
            0o640,
            "{path}"
        );
    }
    assert_eq!(
        fs::metadata(dir.join("agent")).unwrap().mode() & 0o7777,
        0o2750
    );
    fs::remove_dir_all(dir).unwrap();
}
