//! `StateService.GetStateSnapshot` (agent-protocol.md 3; contracts v1.1.10,
//! D-068 #5, proto v2.1.10). An agent that advertises `database.reader.v1`
//! serves it for a project, environment or service scope: every service in
//! the scope with its last admitted spec and the release it runs, and for a
//! managed PostgreSQL service `ServiceState.db_reader`, the reader record of
//! its running release. That record is the `reader_status`/`reader_reason`
//! of the consumed-log `result` line that activated the release
//! (signed-plan.md 14.8) or the latest `EnsureReader` answer for it,
//! whichever is newer; `MISSING` when the release has none. The engine reads
//! it after every healthy deploy of such a service (Engine API
//! `Deployment.db_reader`).
//!
//! The running release is the `permanu.deployment_id` of the service's
//! running containers (the runner's read-only `list_containers`), so a
//! rollback reports the release it went back to. `deployments` is every
//! in-flight deployment in the scope plus the latest finished one per
//! service. `health` is the latest Docker health of each of those
//! services' containers. `ServiceState.commit_sha` is the commit of the
//! running release's deployment when the admitted plan carried one.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tonic::Status;

use super::database::ReaderRecords;
use super::events::EventBus;
use super::execution::Clock;
use super::runner::{self, ContainerFilter, Runner, RunnerContainer};
use crate::admissions::webhooks::ServiceSpecRow;
use crate::admissions::{AdmissionStore, StoredDeployment};
use crate::proto::agent::v2::deploy_status_event::Phase;
use crate::proto::agent::v2::health_event::Status as HealthStatus;
use crate::proto::agent::v2::{
    db_reader_status, DbReaderStatus, DeploymentState, HealthEvent, Scope, ServiceState,
    StateSnapshot,
};
use crate::signed_plan::text;

/// This server's id (`""` before the bootstrap).
pub type ServerIdFn = Arc<dyn Fn() -> String + Send + Sync>;

/// A reader record of one release: the result line that activated it.
#[derive(Debug, Clone, PartialEq)]
pub struct Activation {
    pub deployment_id: String,
    pub status: DbReaderStatus,
}

/// Everything `GetStateSnapshot` reads.
pub struct Snapshots {
    pub store: Arc<AdmissionStore>,
    pub runner: Arc<dyn Runner>,
    pub events: EventBus,
    pub readers: Arc<ReaderRecords>,
    pub clock: Arc<dyn Clock>,
    pub consumed_log: PathBuf,
    pub consumed_log_owner: u32,
    pub server_id: ServerIdFn,
}

impl Snapshots {
    pub async fn snapshot(&self, scope: Scope) -> Result<StateSnapshot, Status> {
        if !scope.deployment_id.is_empty() || !scope.app_id.is_empty() {
            return Err(Status::invalid_argument(
                "GetStateSnapshot takes a project, environment or service scope",
            ));
        }
        // Taken first: every event after it replays from this token.
        let resume_token = self.events.resume_token();
        let rows = self
            .store
            .service_specs_in(
                &scope.project_id,
                &scope.environment,
                &scope.environment_id,
                &scope.service_id,
            )
            .map_err(|_| Status::internal("the admission store could not be read"))?;
        let containers = if rows.is_empty() {
            Vec::new()
        } else {
            let filter = ContainerFilter {
                project_id: scope.project_id.clone(),
                environment_id: scope.environment_id.clone(),
                service_id: scope.service_id.clone(),
            };
            runner::list_containers(self.runner.as_ref(), &filter)
                .await
                .map_err(|failure| {
                    tracing::warn!(code = %failure.code, "list_containers failed for a state snapshot");
                    Status::unavailable("the runner did not list the containers")
                })?
        };
        let activations = if rows.iter().any(|row| is_managed_postgres(&row.spec)) {
            self.activations().await
        } else {
            Vec::new()
        };
        let mut services: Vec<ServiceState> = rows
            .iter()
            .map(|row| {
                service_state(
                    row,
                    &containers,
                    &activations,
                    self.readers.get(&row.service_id),
                )
            })
            .collect();
        let stored = self
            .store
            .deployments_in(
                &scope.project_id,
                &scope.environment,
                &scope.environment_id,
                &scope.service_id,
            )
            .map_err(|_| Status::internal("the admission store could not be read"))?;
        let deployments = chosen_deployments(stored);
        for service in &mut services {
            service.health = service_health(&service.service_id, &containers);
            if let Some(commit) = deployments
                .iter()
                .find(|row| row.deployment_id == service.release_id && !row.commit_sha.is_empty())
            {
                service.commit_sha.clone_from(&commit.commit_sha);
            }
        }
        let health = health_events(&services, &containers);
        Ok(StateSnapshot {
            server_id: (self.server_id)(),
            taken_at: Some(prost_types::Timestamp {
                seconds: self.clock.now(),
                nanos: 0,
            }),
            resume_token,
            services,
            deployments,
            health,
        })
    }

    /// The reader records of the consumed log's `result` lines, each under
    /// the deployment its (admitted) deploy action prepared.
    async fn activations(&self) -> Vec<Activation> {
        let path = self.consumed_log.clone();
        let owner = self.consumed_log_owner;
        let lines = tokio::task::spawn_blocking(move || {
            crate::admissions::event_lines(&path, owner, "result")
        })
        .await
        .unwrap_or_default();
        let mut deployments: HashMap<(String, u32), Option<String>> = HashMap::new();
        let mut found = Vec::new();
        for line in lines {
            let Some(status) = reader_record(&line) else {
                continue;
            };
            let (Some(plan_id), Some(digest), Some(index)) = (
                line["plan_id"].as_str(),
                line["plan_digest_hex"].as_str(),
                line["action_index"]
                    .as_u64()
                    .and_then(|i| u32::try_from(i).ok()),
            ) else {
                continue;
            };
            let deployment = deployments
                .entry((plan_id.to_owned(), index))
                .or_insert_with(|| self.deployment_of(plan_id, digest, index))
                .clone();
            if let Some(deployment_id) = deployment {
                found.push(Activation {
                    deployment_id,
                    status,
                });
            }
        }
        found
    }

    /// The deployment id of an admitted action (the digest must match).
    fn deployment_of(&self, plan_id: &str, digest: &str, index: u32) -> Option<String> {
        let record = self.store.admission(plan_id).ok()??;
        if record.plan_digest_hex != digest {
            return None;
        }
        self.store
            .actions(plan_id)
            .ok()?
            .into_iter()
            .find(|action| action.action_index == index && action.kind == "deploy")?
            .deployment_id
    }
}

/// The reader record of a `result` line (`reader_status` `ready` or
/// `failed`, signed-plan.md 14.8), stamped with the line's time.
pub fn reader_record(line: &Value) -> Option<DbReaderStatus> {
    use db_reader_status::Status as S;
    let (status, reason) = match line["reader_status"].as_str()? {
        "ready" => (S::Ready, String::new()),
        "failed" => (
            S::Failed,
            line["reader_reason"]
                .as_str()
                .filter(|r| r.len() <= 128 && r.bytes().all(|b| b.is_ascii_graphic()))
                .unwrap_or_default()
                .to_owned(),
        ),
        _ => return None,
    };
    let seconds = line["at"].as_str().and_then(text::timestamp)?;
    Some(DbReaderStatus {
        status: status as i32,
        reason,
        deployment_id: String::new(),
        checked_at: Some(prost_types::Timestamp { seconds, nanos: 0 }),
    })
}

/// A `database` service whose image is PostgreSQL (signed-plan.md 14.3:
/// the services the runner provisions a reader for).
pub fn is_managed_postgres(spec: &Value) -> bool {
    let image = spec["image_repository"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let name = image.rsplit('/').next().unwrap_or_default();
    spec["service_kind"] == "database"
        && ["postgres", "postgis", "timescaledb"]
            .iter()
            .any(|known| name.contains(known))
}

/// The release a service runs: the `permanu.deployment_id` of its newest
/// running container, with the number of running and healthy containers of
/// that release. `("", 0, 0)` when none runs.
pub fn running_release(service_id: &str, containers: &[RunnerContainer]) -> (String, u32, u32) {
    let running: Vec<&RunnerContainer> = containers
        .iter()
        .filter(|c| c.service_id == service_id && c.state == "running")
        .filter(|c| !c.deployment_id.is_empty())
        .collect();
    let Some(newest) = running
        .iter()
        .max_by(|a, b| a.created_at.cmp(&b.created_at))
    else {
        return (String::new(), 0, 0);
    };
    let release: Vec<&&RunnerContainer> = running
        .iter()
        .filter(|c| c.deployment_id == newest.deployment_id)
        .collect();
    let healthy = release
        .iter()
        .filter(|c| !c.status.contains("unhealthy") && !c.status.contains("health: starting"))
        .count();
    (
        newest.deployment_id.clone(),
        u32::try_from(release.len()).unwrap_or(u32::MAX),
        u32::try_from(healthy).unwrap_or(u32::MAX),
    )
}

/// The reader record of `release`: the newer of its activation's and the
/// latest `EnsureReader` answer for it; `MISSING` when it has none.
pub fn reader_of(
    release: &str,
    activations: &[Activation],
    ensured: Option<DbReaderStatus>,
) -> DbReaderStatus {
    let seconds = |status: &DbReaderStatus| status.checked_at.as_ref().map_or(0, |t| t.seconds);
    let activated = activations
        .iter()
        .filter(|a| !release.is_empty() && a.deployment_id == release)
        .map(|a| a.status.clone())
        .max_by_key(|s| seconds(s));
    let ensured = ensured.filter(|s| !release.is_empty() && s.deployment_id == release);
    let newest = match (activated, ensured) {
        (Some(a), Some(e)) => Some(if seconds(&e) >= seconds(&a) { e } else { a }),
        (a, e) => a.or(e),
    };
    match newest {
        Some(status) => DbReaderStatus {
            deployment_id: release.to_owned(),
            ..status
        },
        None => DbReaderStatus {
            status: db_reader_status::Status::Missing as i32,
            deployment_id: release.to_owned(),
            ..Default::default()
        },
    }
}

/// One service's state; `db_reader` only for a managed PostgreSQL service.
pub fn service_state(
    row: &ServiceSpecRow,
    containers: &[RunnerContainer],
    activations: &[Activation],
    ensured: Option<DbReaderStatus>,
) -> ServiceState {
    let (release_id, running, healthy) = running_release(&row.service_id, containers);
    let db_reader =
        is_managed_postgres(&row.spec).then(|| reader_of(&release_id, activations, ensured));
    ServiceState {
        service_id: row.service_id.clone(),
        project_id: row.project_id.clone(),
        environment: row.environment.clone(),
        environment_id: row.environment_id.clone(),
        spec_digest_hex: row.spec_digest_hex.clone(),
        release_id,
        replicas_desired: row.spec["replicas"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or_default(),
        replicas_healthy: healthy.min(running),
        db_reader,
        ..Default::default()
    }
}

/// In-flight deployments, plus the latest finished one of each service.
fn chosen_deployments(rows: Vec<StoredDeployment>) -> Vec<DeploymentState> {
    let mut inflight = Vec::new();
    let mut latest: HashMap<String, StoredDeployment> = HashMap::new();
    for row in rows {
        if row.finished_at.is_none() {
            inflight.push(row);
            continue;
        }
        match latest.get(&row.service_id) {
            Some(kept) if !later_finish(&row, kept) => {}
            _ => {
                latest.insert(row.service_id.clone(), row);
            }
        }
    }
    let mut chosen = inflight;
    chosen.extend(latest.into_values());
    chosen.sort_by(|a, b| {
        a.service_id
            .cmp(&b.service_id)
            .then(a.deployment_id.cmp(&b.deployment_id))
    });
    chosen.iter().map(deployment_state).collect()
}

fn later_finish(row: &StoredDeployment, kept: &StoredDeployment) -> bool {
    (row.finished_at.as_deref(), row.admission_seq)
        > (kept.finished_at.as_deref(), kept.admission_seq)
}

fn deployment_state(row: &StoredDeployment) -> DeploymentState {
    let phase = match row.outcome.as_str() {
        "succeeded" => Phase::Live,
        "rolled_back" => Phase::RolledBack,
        "cancelled" => Phase::Cancelled,
        "failed" | "expired" => Phase::Failed,
        _ if row.consumed_at.is_some() => Phase::Starting,
        _ => Phase::Queued,
    };
    let started = row.consumed_at.as_deref().unwrap_or(&row.admitted_at);
    DeploymentState {
        deployment_id: row.deployment_id.clone(),
        project_id: row.project_id.clone(),
        service_id: row.service_id.clone(),
        plan_id: row.plan_id.clone(),
        operation_id: row.operation_id.clone(),
        phase: phase as i32,
        commit_sha: row.commit_sha.clone(),
        spec_digest_hex: row.spec_digest_hex.clone(),
        started_at: stamp(started),
        finished_at: row.finished_at.as_deref().and_then(stamp),
    }
}

fn stamp(text: &str) -> Option<prost_types::Timestamp> {
    text::timestamp(text).map(|seconds| prost_types::Timestamp { seconds, nanos: 0 })
}

/// Docker's health token in a container status, if it has one.
fn docker_health(status: &str) -> Option<HealthStatus> {
    let status = status.to_ascii_lowercase();
    if status.contains("unhealthy") {
        Some(HealthStatus::Unhealthy)
    } else if status.contains("health: starting") {
        Some(HealthStatus::Starting)
    } else if status.contains("(healthy)") {
        Some(HealthStatus::Healthy)
    } else {
        None
    }
}

fn service_health(service_id: &str, containers: &[RunnerContainer]) -> i32 {
    containers
        .iter()
        .filter(|container| container.service_id == service_id)
        .filter_map(|container| {
            docker_health(&container.status).map(|status| (container.created_at.as_str(), status))
        })
        .max_by_key(|(created, _)| *created)
        .map(|(_, status)| status as i32)
        .unwrap_or_default()
}

/// One event per container that reports Docker health. The check id is the
/// container id, so the latest status of that container is the check.
fn health_events(services: &[ServiceState], containers: &[RunnerContainer]) -> Vec<HealthEvent> {
    let mut events = Vec::new();
    for container in containers {
        let Some(service) = services
            .iter()
            .find(|s| s.service_id == container.service_id)
        else {
            continue;
        };
        let Some(status) = docker_health(&container.status) else {
            continue;
        };
        if container.id.is_empty() {
            continue;
        }
        let project_id = if container.project_id.is_empty() {
            service.project_id.clone()
        } else {
            container.project_id.clone()
        };
        events.push(HealthEvent {
            check_id: container.id.clone(),
            project_id,
            service_id: container.service_id.clone(),
            container_name: container.name.trim_start_matches('/').to_owned(),
            status: status as i32,
            ..Default::default()
        });
    }
    events.sort_by(|a, b| a.check_id.cmp(&b.check_id));
    events
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::admissions::definitions::tests::{
        open, record, record_at, set_deployment, ENV_ID, PROJECT,
    };
    use crate::admissions::webhooks::seed;
    use crate::local::runner::{EventLines, RunnerFailure};
    use crate::proto::agent::v2::deploy_status_event::Phase;
    use crate::proto::agent::v2::health_event::Status as Health;

    const DB: &str = "01a0cdb5-3500-70c1-8000-0000000000d1";
    const WEB: &str = "01a0cdb5-3500-70c1-8000-0000000000e1";
    const OLD: &str = "01a0cdb5-3500-70c7-8000-000000000001";
    const NEW: &str = "01a0cdb5-3500-70c7-8000-000000000002";

    fn db_spec() -> Value {
        json!({"service_id": DB, "service_kind": "database", "replicas": 1,
               "image_repository": "docker.io/library/postgres"})
    }

    fn container(service: &str, deployment: &str, state: &str, created: &str) -> RunnerContainer {
        RunnerContainer {
            id: format!("{deployment}-{state}"),
            service_id: service.to_owned(),
            deployment_id: deployment.to_owned(),
            state: state.to_owned(),
            status: "Up 1 minute (healthy)".to_owned(),
            created_at: created.to_owned(),
            ..Default::default()
        }
    }

    fn status(state: db_reader_status::Status, reason: &str, at: i64) -> DbReaderStatus {
        DbReaderStatus {
            status: state as i32,
            reason: reason.to_owned(),
            deployment_id: String::new(),
            checked_at: Some(prost_types::Timestamp {
                seconds: at,
                nanos: 0,
            }),
        }
    }

    #[test]
    fn postgres_images_are_managed_postgres_databases() {
        assert!(is_managed_postgres(&db_spec()));
        assert!(is_managed_postgres(
            &json!({"service_kind": "database", "image_repository": "postgis/postgis"})
        ));
        assert!(!is_managed_postgres(
            &json!({"service_kind": "database", "image_repository": "docker.io/library/mysql"})
        ));
        assert!(!is_managed_postgres(
            &json!({"service_kind": "web", "image_repository": "acme/postgres-admin"})
        ));
    }

    /// The running release is the newest running container's deployment; a
    /// stopped previous release does not count.
    #[test]
    fn the_running_release_is_the_newest_running_containers() {
        let containers = [
            container(DB, OLD, "exited", "2026-09-25T10:00:00Z"),
            container(DB, NEW, "running", "2026-09-25T11:00:00Z"),
            container(WEB, OLD, "running", "2026-09-25T12:00:00Z"),
        ];
        assert_eq!(running_release(DB, &containers), (NEW.to_owned(), 1, 1));
        assert_eq!(running_release("x", &containers), (String::new(), 0, 0));
    }

    /// D-068 #5: the newer of the activation's record and the latest
    /// EnsureReader answer of the running release; MISSING without one.
    #[test]
    fn the_reader_record_is_the_newer_of_activation_and_repair() {
        use db_reader_status::Status as S;
        let activations = [
            Activation {
                deployment_id: OLD.to_owned(),
                status: status(S::Ready, "", 100),
            },
            Activation {
                deployment_id: NEW.to_owned(),
                status: status(S::Failed, "auth_failed", 200),
            },
        ];
        let failed = reader_of(NEW, &activations, None);
        assert_eq!(failed.status, S::Failed as i32);
        assert_eq!(failed.reason, "auth_failed");
        assert_eq!(failed.deployment_id, NEW);
        let repaired = DbReaderStatus {
            deployment_id: NEW.to_owned(),
            ..status(S::Ready, "", 300)
        };
        let ready = reader_of(NEW, &activations, Some(repaired.clone()));
        assert_eq!(ready.status, S::Ready as i32);
        // An older repair does not hide a newer activation.
        let stale = DbReaderStatus {
            deployment_id: NEW.to_owned(),
            ..status(S::Ready, "", 150)
        };
        assert_eq!(
            reader_of(NEW, &activations, Some(stale)).status,
            S::Failed as i32
        );
        // A repair of another release is not this release's record.
        let other = DbReaderStatus {
            deployment_id: OLD.to_owned(),
            ..status(S::Ready, "", 300)
        };
        let rolled_back = reader_of(OLD, &activations, Some(other));
        assert_eq!(rolled_back.status, S::Ready as i32);
        assert_eq!(rolled_back.checked_at.unwrap().seconds, 300);
        let missing = reader_of(
            "01a0cdb5-3500-70c7-8000-000000000009",
            &activations,
            Some(repaired),
        );
        assert_eq!(missing.status, S::Missing as i32);
        assert!(missing.checked_at.is_none());
        assert_eq!(reader_of("", &[], None).status, S::Missing as i32);
    }

    #[test]
    fn result_lines_carry_the_reader_record() {
        use db_reader_status::Status as S;
        let failed = reader_record(&json!({"at": "2026-09-25T10:00:00Z",
            "reader_status": "failed", "reader_reason": "not_ready"}))
        .unwrap();
        assert_eq!(failed.status, S::Failed as i32);
        assert_eq!(failed.reason, "not_ready");
        assert!(failed.checked_at.is_some());
        assert!(
            reader_record(&json!({"at": "2026-09-25T10:00:00Z", "outcome": "succeeded"})).is_none()
        );
        assert!(
            reader_record(&json!({"at": "2026-09-25T10:00:00Z", "reader_status": "missing"}))
                .is_none()
        );
    }

    struct Containers(Vec<Value>);

    #[tonic::async_trait]
    impl Runner for Containers {
        async fn exchange(&self, request: Value, _: Duration) -> Result<Value, RunnerFailure> {
            assert_eq!(request["op"], "list_containers");
            Ok(json!({"type": "result", "ok": true, "containers": self.0}))
        }

        async fn open(&self, _: Value) -> Result<EventLines, RunnerFailure> {
            Err(RunnerFailure::transport("unused"))
        }
    }

    struct Fixed;

    impl Clock for Fixed {
        fn now(&self) -> i64 {
            1_790_000_000
        }
    }

    /// D-068 #5: GetStateSnapshot serves every service of the scope with
    /// `db_reader` for the managed PostgreSQL one, from the consumed-log
    /// `result` line that activated its running release.
    #[tokio::test]
    async fn the_snapshot_serves_the_reader_record_of_the_running_release() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = open("snapshot-reader");
        let deploy = |deployment: &str| json!({"kind": "deploy", "params": {"service_id": DB, "deployment_id": deployment}});
        let old = record(
            &store,
            1,
            (PROJECT, "production", ENV_ID),
            &[deploy(OLD)],
            "succeeded",
        );
        let new = record(
            &store,
            2,
            (PROJECT, "production", ENV_ID),
            &[deploy(NEW)],
            "succeeded",
        );
        set_deployment(&store, &old, OLD);
        set_deployment(&store, &new, NEW);
        seed::spec(&store, &db_spec(), &new);
        seed::spec(
            &store,
            &json!({"service_id": WEB, "service_kind": "web", "replicas": 2}),
            &new,
        );
        let log = dir.join("consumed.log");
        let mut file = std::fs::File::create(&log).unwrap();
        for (seq, plan, digest, reader) in [
            (
                1,
                &old,
                1,
                json!({"reader_status": "ready", "reader_reason": null}),
            ),
            (
                2,
                &new,
                2,
                json!({"reader_status": "failed", "reader_reason": "auth_failed"}),
            ),
        ] {
            let mut line = json!({"v": 1, "seq": seq, "at": "2026-09-25T10:00:00Z",
                "event": "result", "plan_id": plan, "plan_digest_hex": format!("{digest:064x}"),
                "action_index": 0, "outcome": "succeeded"});
            for (key, value) in reader.as_object().unwrap() {
                line[key] = value.clone();
            }
            writeln!(file, "{line}").unwrap();
        }
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o640)).unwrap();
        let runner = Containers(vec![
            json!({"id": "c1", "service_id": DB, "deployment_id": NEW, "state": "running",
                   "status": "Up 2 minutes (healthy)", "created_at": "2026-09-25T10:00:00Z"}),
            json!({"id": "c0", "service_id": DB, "deployment_id": OLD, "state": "exited",
                   "status": "Exited (0)", "created_at": "2026-09-25T09:00:00Z"}),
        ]);
        let events = EventBus::new();
        let snapshots = Snapshots {
            store: Arc::new(store),
            runner: Arc::new(runner),
            events: events.clone(),
            readers: Arc::default(),
            clock: Arc::new(Fixed),
            consumed_log: log,
            // SAFETY: geteuid has no preconditions.
            consumed_log_owner: unsafe { libc::geteuid() },
            server_id: Arc::new(|| "server-a".to_owned()),
        };
        let snapshot = snapshots
            .snapshot(Scope {
                project_id: PROJECT.to_owned(),
                service_id: DB.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(snapshot.server_id, "server-a");
        assert_eq!(snapshot.resume_token, events.resume_token());
        assert_eq!(snapshot.services.len(), 1);
        let db = &snapshot.services[0];
        assert_eq!(db.service_id, DB);
        assert_eq!(db.release_id, NEW);
        assert_eq!(db.replicas_desired, 1);
        assert_eq!(db.replicas_healthy, 1);
        let reader = db.db_reader.as_ref().unwrap();
        assert_eq!(reader.status, db_reader_status::Status::Failed as i32);
        assert_eq!(reader.reason, "auth_failed");
        assert_eq!(reader.deployment_id, NEW);

        let whole = snapshots.snapshot(Scope::default()).await.unwrap();
        assert_eq!(whole.services.len(), 2);
        let web = whole.services.iter().find(|s| s.service_id == WEB).unwrap();
        assert!(web.db_reader.is_none());
        assert_eq!(web.replicas_desired, 2);
        assert!(snapshots
            .snapshot(Scope {
                deployment_id: NEW.to_owned(),
                ..Default::default()
            })
            .await
            .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// In-flight deployments and the latest finished one per service, plus
    /// the container health of those services. Services stay in the snapshot.
    #[tokio::test]
    async fn the_snapshot_includes_the_deployment_and_the_health() {
        let (dir, store) = open("snapshot-deploy-health");
        let commit = "a".repeat(40);
        let digest = "b".repeat(64);
        let deploy = |deployment: &str| {
            json!({"kind": "deploy", "params": {
                "service_id": WEB, "deployment_id": deployment,
                "commit_sha": commit, "spec_digest_hex": digest,
            }})
        };
        let old = record_at(
            &store,
            1,
            (PROJECT, "production", ENV_ID),
            &[deploy(OLD)],
            "succeeded",
            "2026-09-25T09:00:00Z",
        );
        let live = record_at(
            &store,
            2,
            (PROJECT, "production", ENV_ID),
            &[deploy(NEW)],
            "succeeded",
            "2026-09-25T11:00:00Z",
        );
        let flight_id = "01a0cdb5-3500-70c7-8000-000000000003";
        let flight = record_at(
            &store,
            3,
            (PROJECT, "production", ENV_ID),
            &[deploy(flight_id)],
            "",
            "2026-09-25T12:00:00Z",
        );
        let foreign_id = "01a0cdb5-3500-70c7-8000-000000000099";
        let foreign = record_at(
            &store,
            4,
            ("01a0cdb5-3500-70b1-8000-000000000099", "production", ENV_ID),
            &[deploy(foreign_id)],
            "succeeded",
            "2026-09-25T12:30:00Z",
        );
        set_deployment(&store, &old, OLD);
        set_deployment(&store, &live, NEW);
        set_deployment(&store, &flight, flight_id);
        set_deployment(&store, &foreign, foreign_id);
        seed::spec(
            &store,
            &json!({"service_id": WEB, "service_kind": "web", "replicas": 2}),
            &live,
        );
        let runner = Containers(vec![json!({
            "id": "c-web", "name": "web-1", "service_id": WEB, "project_id": PROJECT,
            "deployment_id": NEW, "state": "running",
            "status": "Up 2 minutes (healthy)", "created_at": "2026-09-25T11:00:00Z",
        })]);
        let snapshots = Snapshots {
            store: Arc::new(store),
            runner: Arc::new(runner),
            events: EventBus::new(),
            readers: Arc::default(),
            clock: Arc::new(Fixed),
            consumed_log: dir.join("consumed.log"),
            consumed_log_owner: 0,
            server_id: Arc::new(|| "server-a".to_owned()),
        };
        let snapshot = snapshots
            .snapshot(Scope {
                project_id: PROJECT.to_owned(),
                service_id: WEB.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(snapshot.services.len(), 1);
        assert_eq!(snapshot.services[0].service_id, WEB);
        assert_eq!(snapshot.services[0].release_id, NEW);
        assert_eq!(snapshot.services[0].commit_sha, commit);
        assert_eq!(snapshot.services[0].health, Health::Healthy as i32);
        let mut ids: Vec<_> = snapshot
            .deployments
            .iter()
            .map(|row| row.deployment_id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![NEW, flight_id]);
        let finished = snapshot
            .deployments
            .iter()
            .find(|row| row.deployment_id == NEW)
            .unwrap();
        assert_eq!(finished.project_id, PROJECT);
        assert_eq!(finished.service_id, WEB);
        assert_eq!(finished.plan_id, live);
        assert_eq!(finished.operation_id, live);
        assert_eq!(finished.phase, Phase::Live as i32);
        assert_eq!(finished.commit_sha, commit);
        assert_eq!(finished.spec_digest_hex, digest);
        let at = crate::signed_plan::text::timestamp("2026-09-25T11:00:00Z").unwrap();
        assert_eq!(finished.started_at.unwrap().seconds, at);
        assert_eq!(finished.finished_at.unwrap().seconds, at);
        let queued = snapshot
            .deployments
            .iter()
            .find(|row| row.deployment_id == flight_id)
            .unwrap();
        assert_eq!(queued.phase, Phase::Queued as i32);
        assert_eq!(queued.plan_id, flight);
        assert!(queued.finished_at.is_none());
        assert_eq!(snapshot.health.len(), 1);
        let health = &snapshot.health[0];
        assert_eq!(health.check_id, "c-web");
        assert_eq!(health.project_id, PROJECT);
        assert_eq!(health.service_id, WEB);
        assert_eq!(health.container_name, "web-1");
        assert_eq!(health.status, Health::Healthy as i32);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
