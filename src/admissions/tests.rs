use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use rusqlite::params;
use serde_json::Value;

use super::*;
use crate::signed_plan::test_support::{plan_vector, temp_dir, test_trust, SERVER_A};
use crate::signed_plan::text::timestamp;
use crate::signed_plan::verify::Submitter;
use crate::signed_plan::PlanCode;

const NOW: &str = "2026-09-23T10:05:00Z";
const USER_DEPLOY_HEAD_BEFORE: &str =
    "4a98af3eeae054bf7585746ce20fa5907ec9c079ee1b049a7d01146d1c92ebfb";
const USER_DEPLOY_HEAD_AFTER: &str =
    "873dbc34b38acb2f1a812871b9aa71c18c207c204f3aa370f1be16c5a9ebc3f4";
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
    assert_eq!(version, 1);
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
        "3ad6585581ed4f9e1b9355acf258c3d76971dafda5fd461109ea04274946414c"
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
            params!["f9e2f5ba422e79750428675b3191f942f6d85747981184a232a08b369e4da410"],
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
