use crate::proto::agent::v2::SignedPlan;
use futures::StreamExt;
use serde_json::json;
use std::time::Duration;

use super::super::backup::BackupScheduler;
use super::super::test_support::{Fixture, PG};
use super::*;
use crate::proto::agent::v2::backup_run;

const BACKUP: &str = "01a0cdb5-3500-7e01-8000-000000000001";

#[test]
fn run_now_needs_exactly_one_cron_run_of_the_job() {
    let cron = "01a0cdb5-3500-70d2-8000-000000000001";
    let plan = |actions: serde_json::Value| {
        serde_json::to_vec(&json!({"plan": {"actions": actions}, "signatures": []})).unwrap()
    };
    let run = json!({"kind": "cron.run", "params": {"cron_id": cron}});
    assert!(run_now_matches(&plan(json!([run])), cron));
    assert!(!run_now_matches(&plan(json!([run, run])), cron));
    assert!(!run_now_matches(
        &plan(json!([run])),
        "01a0cdb5-3500-70d2-8000-000000000002"
    ));
    assert!(!run_now_matches(
        &plan(json!([{"kind": "cron.pause", "params": {"cron_id": cron}}])),
        cron
    ));
    assert!(!run_now_matches(b"not json", cron));
}

#[test]
fn local_artifacts_never_leave_the_backup_root() {
    let root = Path::new("/srv/root");
    assert_eq!(
        local_path(root, "/var/lib/permanu/backups/permanu/v1/s/r/b.age"),
        Some(PathBuf::from("/srv/root/permanu/v1/s/r/b.age"))
    );
    for bad in [
        "/var/lib/permanu/backups/../etc/shadow.age",
        "/var/lib/permanu/backups/a/./b.age",
        "/var/lib/permanu/backupsX/b.age",
        "/var/lib/permanu/backups/b.manifest.json",
        "r2://bucket/permanu/v1/s/r/b.age",
        "/var/lib/permanu/backups//etc/b.age",
    ] {
        assert_eq!(local_path(root, bad), None, "{bad}");
    }
}

fn artifact(location: &str) -> BackupArtifact {
    BackupArtifact {
        id: BACKUP.to_owned(),
        policy_id: PG.to_owned(),
        location: location.to_owned(),
        content_digest_hex: "ef".repeat(32),
        created_at: Some(prost_types::Timestamp {
            seconds: 1,
            nanos: 0,
        }),
        ..Default::default()
    }
}

fn backup_svc(f: &Fixture, root: PathBuf) -> BackupSvc {
    let backups = BackupScheduler::new(f.deps.clone(), f.sink.clone(), "age1server".to_owned());
    BackupSvc {
        backups,
        ops: f.deps.ops.clone(),
        local_root: root,
        downloads: Arc::new(Semaphore::new(1)),
    }
}

#[tokio::test]
async fn read_backup_artifact_streams_local_ciphertext_in_frames() {
    let f = Fixture::new("rpc-read", "2026-09-23T10:00:00Z");
    let root = f.dir.join("backups");
    let file = root.join(format!("permanu/v1/s/{PG}/{BACKUP}.age"));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let bytes: Vec<u8> = (0..(CHUNK_BYTES + 10)).map(|n| (n % 251) as u8).collect();
    std::fs::write(&file, &bytes).unwrap();
    let svc = backup_svc(&f, root.clone());
    let location = format!("{LOCAL_ROOT}/permanu/v1/s/{PG}/{BACKUP}.age");
    f.deps
        .ops
        .put(
            RecordKind::Artifact,
            BACKUP,
            PG,
            "",
            0,
            1,
            &artifact(&location),
        )
        .unwrap();
    let stream = svc
        .read_backup_artifact(Request::new(ReadBackupArtifactRequest {
            artifact_id: BACKUP.to_owned(),
            offset: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    let frames: Vec<BackupArtifactChunk> = stream.map(|f| f.unwrap()).collect().await;
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].data.len(), CHUNK_BYTES);
    assert!(!frames[0].last && frames[1].last);
    assert_eq!(frames[1].offset, CHUNK_BYTES as u64);
    assert_eq!(frames[1].content_digest_hex, "ef".repeat(32));
    let joined: Vec<u8> = frames.iter().flat_map(|f| f.data.clone()).collect();
    assert_eq!(joined, bytes);
    // Resume from an offset.
    let resumed: Vec<BackupArtifactChunk> = svc
        .read_backup_artifact(Request::new(ReadBackupArtifactRequest {
            artifact_id: BACKUP.to_owned(),
            offset: CHUNK_BYTES as u64,
        }))
        .await
        .unwrap()
        .into_inner()
        .map(|f| f.unwrap())
        .collect()
        .await;
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].data.len(), 10);
}

#[tokio::test]
async fn remote_symlinked_and_concurrent_reads_are_refused() {
    let f = Fixture::new("rpc-read-refused", "2026-09-23T10:00:00Z");
    let root = f.dir.join("backups");
    std::fs::create_dir_all(root.join("permanu")).unwrap();
    let svc = backup_svc(&f, root.clone());
    async fn read(svc: &BackupSvc) -> Result<Response<BoxStream<BackupArtifactChunk>>, Status> {
        svc.read_backup_artifact(Request::new(ReadBackupArtifactRequest {
            artifact_id: BACKUP.to_owned(),
            offset: 0,
        }))
        .await
    }
    f.deps
        .ops
        .put(
            RecordKind::Artifact,
            BACKUP,
            PG,
            "",
            0,
            1,
            &artifact("r2://b/permanu/v1/s/r/x.age"),
        )
        .unwrap();
    assert_eq!(
        read(&svc).await.err().unwrap().code(),
        Code::FailedPrecondition
    );
    // A symlink planted in the root is never followed.
    std::os::unix::fs::symlink("/etc/hosts", root.join("permanu/link.age")).unwrap();
    f.deps
        .ops
        .put(
            RecordKind::Artifact,
            BACKUP,
            PG,
            "",
            0,
            1,
            &artifact(&format!("{LOCAL_ROOT}/permanu/link.age")),
        )
        .unwrap();
    assert!(read(&svc).await.is_err());
    // One download at a time.
    std::fs::write(root.join("permanu/real.age"), b"x").unwrap();
    f.deps
        .ops
        .put(
            RecordKind::Artifact,
            BACKUP,
            PG,
            "",
            0,
            1,
            &artifact(&format!("{LOCAL_ROOT}/permanu/real.age")),
        )
        .unwrap();
    let held = svc.downloads.clone().try_acquire_owned().unwrap();
    assert_eq!(
        read(&svc).await.err().unwrap().code(),
        Code::ResourceExhausted
    );
    drop(held);
    assert!(read(&svc).await.is_ok());
}

#[tokio::test]
async fn backup_lists_page_newest_first() {
    let f = Fixture::new("rpc-pages", "2026-09-23T10:00:00Z");
    let svc = backup_svc(&f, f.dir.clone());
    for n in 0..5 {
        let run = BackupRun {
            id: format!("01a0cdb5-3500-7e02-8000-00000000000{n}"),
            policy_id: PG.to_owned(),
            trigger: backup_run::Trigger::Manual as i32,
            ..Default::default()
        };
        f.deps
            .ops
            .put(RecordKind::BackupRun, &run.id, PG, "", 0, n, &run)
            .unwrap();
    }
    let page = |token: &str| ListBackupRunsRequest {
        policy_id: PG.to_owned(),
        page: Some(PageRequest {
            page_size: 2,
            page_token: token.to_owned(),
        }),
        ..Default::default()
    };
    let first = svc
        .list_backup_runs(Request::new(page("")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.runs.len(), 2);
    assert!(first.runs[0].id.ends_with('4'));
    let token = first.page.unwrap().next_page_token;
    let second = svc
        .list_backup_runs(Request::new(page(&token)))
        .await
        .unwrap()
        .into_inner();
    assert!(second.runs[0].id.ends_with('2'));
    let third = svc
        .list_backup_runs(Request::new(page(&second.page.unwrap().next_page_token)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(third.runs.len(), 1);
    assert_eq!(third.page.unwrap().next_page_token, "");
    assert!(svc
        .list_backup_runs(Request::new(page("bogus")))
        .await
        .is_err());
}

#[tokio::test]
async fn database_read_failure_is_internal_instead_of_not_found() {
    let f = Fixture::new("rpc-corrupt", "2026-09-23T10:00:00Z");
    let path = f.dir.join("rpc-ops.db");
    let ops = Arc::new(OpsStore::open(&path, None).unwrap());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("DROP TABLE records").unwrap();
    let mut svc = backup_svc(&f, f.dir.join("backups"));
    svc.ops = ops;
    let error = svc
        .get_backup_run(Request::new(GetBackupRunRequest {
            run_id: BACKUP.to_owned(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Internal);
}

// Exercise the real signed admission path, rather than only envelope shape.
async fn manual_rpc_fixture(
    name: &str,
) -> (
    crate::local::test_harness::Harness,
    Arc<ScheduleSvc>,
    SignedPlan,
) {
    use super::super::test_support::{production, CRON};
    use crate::signed_plan::test_support::{plan_vector, vector, TestSigner, SERVER_A};
    let owner = TestSigner::load("owner").expect("checked-in test signing key");
    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = crate::local::test_harness::Harness::start(name, Some(&trust)).await;
    let create = plan_vector("deployer-cron-create")["plan"]["actions"][0].clone();
    crate::admissions::definitions::tests::record_at(
        &h.core.store,
        1,
        production(),
        &[create],
        "succeeded",
        "2026-09-23T10:00:00Z",
    );
    let ops = Arc::new(OpsStore::in_memory());
    let deps = super::super::Deps {
        store: h.core.store.clone(),
        ops: ops.clone(),
        runner: h.core.runner.clone(),
        events: h.core.events.clone(),
        clock: h.core.clock.clone(),
        logs: Default::default(),
        server_id: super::super::ServerId::Fixed(SERVER_A.to_owned()),
        consumed_log: None,
    };
    let cron = CronScheduler::new(deps, Arc::new(super::super::test_support::Sink::default()));
    assert!(h.core.cron.set(cron.clone()).is_ok());
    let svc = Arc::new(ScheduleSvc {
        cron,
        ops,
        change: ChangeSvc {
            core: h.core.clone(),
        },
        telemetry: None,
    });
    let mut plan = plan_vector("deployer-cron-create")["plan"].clone();
    plan["id"] = json!("01a0cdb5-3500-7001-8000-000000000099");
    plan["base"]["heads"][SERVER_A] = json!(crate::signed_plan::verify::GENESIS_HEAD);
    plan["service_ids"] = json!([]);
    plan["actions"] = json!([{"kind":"cron.run", "params":{"cron_id":CRON}}]);
    let signed = SignedPlan {
        envelope_json: owner.envelope(&plan).into_bytes(),
        ..Default::default()
    };
    (h, svc, signed)
}

fn manual_request(plan: SignedPlan) -> Request<RunCronJobNowRequest> {
    Request::new(RunCronJobNowRequest {
        cron_id: super::super::test_support::CRON.to_owned(),
        plan: Some(plan),
    })
}

#[tokio::test]
async fn run_now_fresh_signed_plan_succeeds_and_retry_keeps_original_operation_and_run() {
    let (h, svc, plan) = manual_rpc_fixture("rpc-manual-fresh").await;
    let first = svc
        .run_cron_job_now(manual_request(plan.clone()))
        .await
        .unwrap()
        .into_inner();
    let operation = first.operation.as_ref().unwrap();
    assert!(!operation.deduplicated);
    assert_eq!(operation.plan_id, "01a0cdb5-3500-7001-8000-000000000099");
    for _ in 0..200 {
        h.core.reconcile_once().await;
        let admission = h.core.store.admission(&operation.plan_id).unwrap().unwrap();
        if h.core.operation(&admission).state
            == crate::proto::agent::v2::OperationState::Succeeded as i32
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let admission = h.core.store.admission(&operation.plan_id).unwrap().unwrap();
    assert_eq!(
        h.core.operation(&admission).state,
        crate::proto::agent::v2::OperationState::Succeeded as i32
    );
    let retry = svc
        .run_cron_job_now(manual_request(plan))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retry.run_id, first.run_id);
    let retried = retry.operation.unwrap();
    assert!(retried.deduplicated);
    assert_eq!(retried.operation_id, operation.operation_id);
    assert_eq!(retried.plan_id, operation.plan_id);
    assert_eq!(
        h.runner
            .ops_for(&operation.plan_id)
            .iter()
            .filter(|(op, _)| op == "run_cron")
            .count(),
        1
    );
    svc.cron.tick();
    let run: CronRun = svc
        .ops
        .try_get(RecordKind::CronRun, &first.run_id)
        .unwrap()
        .unwrap()
        .decode()
        .unwrap();
    assert_eq!(run.operation_id, operation.operation_id);
    assert_eq!(
        run.status,
        crate::proto::agent::v2::CronRunStatus::Succeeded as i32
    );
    h.stop().await;
}

#[tokio::test]
async fn run_now_caller_cancellation_retains_owned_admission_and_retry_identity() {
    let (h, svc, plan) = manual_rpc_fixture("rpc-manual-cancel").await;
    // Hold the durable admission write while the outer RPC is cancelled.
    let blocker = rusqlite::Connection::open(h.dir.join("agent/admissions.db")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let task_svc = svc.clone();
    let task_plan = plan.clone();
    let caller =
        tokio::spawn(async move { task_svc.run_cron_job_now(manual_request(task_plan)).await });
    for _ in 0..200 {
        if !svc.ops.manual_reservations().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(svc.ops.manual_reservations().unwrap().len(), 1);
    assert!(!caller.is_finished());
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    blocker.execute_batch("COMMIT").unwrap();
    let id = "01a0cdb5-3500-7001-8000-000000000099";
    for _ in 0..200 {
        if h.core.store.admission(id).unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let original = h
        .core
        .store
        .admission(id)
        .unwrap()
        .expect("owned task still admits after caller disappears");
    let retry = svc
        .run_cron_job_now(manual_request(plan))
        .await
        .unwrap()
        .into_inner();
    assert!(retry.operation.as_ref().unwrap().deduplicated);
    assert_eq!(retry.operation.unwrap().operation_id, original.operation_id);
    assert!(!retry.run_id.is_empty());
    h.stop().await;
}
