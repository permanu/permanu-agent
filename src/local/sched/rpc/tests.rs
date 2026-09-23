use futures::StreamExt;
use serde_json::json;

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
