//! `ScheduleService`, `BackupService` and `AlertService` (proto v2.1.2,
//! capabilities `cron.v1`, `backups.v1`, `alerts.v1`). Reads are unsigned;
//! every change is a signed plan (`ChangeService.SubmitSignedPlan`), except
//! `RunCronJobNow` (its own `cron.run` plan through the same admission) and
//! `TestNotificationChannel` (a fixed text through `notify_channel`).

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};

use super::alerts::{AlertEvaluator, TestRefusal};
use super::backup::{BackupScheduler, LOCAL_ROOT};
use super::cron::CronScheduler;
use super::ops_store::{Listing, OpsStore, RecordKind, Row};
use crate::local::change::ChangeSvc;
use crate::local::telemetry::query::StoreQueries;
use crate::local::telemetry::Telemetry;
use crate::local::{capability_missing, log_peer, status_with_reason};
use crate::proto::agent::v2::{
    alert_events_response, alert_service_server::AlertService,
    backup_service_server::BackupService, schedule_service_server::ScheduleService, AlertEvent,
    AlertEventBatch, AlertEventsResponse, AlertRule, BackupArtifact, BackupArtifactChunk,
    BackupPolicy, BackupRun, CronJob, CronRun, ErrorReason, GetAlertRuleRequest,
    GetBackupPolicyRequest, GetBackupRunRequest, GetCronJobRequest, GetCronRunRequest,
    ListAlertEventsRequest, ListAlertRulesRequest, ListAlertRulesResponse,
    ListBackupArtifactsRequest, ListBackupArtifactsResponse, ListBackupDestinationsRequest,
    ListBackupDestinationsResponse, ListBackupPoliciesRequest, ListBackupPoliciesResponse,
    ListBackupRunsRequest, ListBackupRunsResponse, ListCronJobsRequest, ListCronJobsResponse,
    ListCronRunsRequest, ListCronRunsResponse, ListNotificationChannelsRequest,
    ListNotificationChannelsResponse, ListRestoreVerificationsRequest,
    ListRestoreVerificationsResponse, LogQuery, LogQueryResponse, LogSourceType, PageInfo,
    PageRequest, ReadBackupArtifactRequest, RestoreVerification, RunCronJobNowRequest,
    RunCronJobNowResponse, Scope, StreamCronRunLogsRequest, StreamStatus,
    TestNotificationChannelRequest, TestNotificationChannelResponse, TimeRange,
};
use crate::signed_plan::text;

const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 500;
/// `ReadBackupArtifact` frames (proto: at most 1 MiB).
const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_ALERT_EVENTS: usize = 2_000;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

pub(crate) fn page_size(page: Option<&PageRequest>) -> usize {
    match page.map_or(0, |p| p.page_size as usize) {
        0 => DEFAULT_PAGE,
        n => n.min(MAX_PAGE),
    }
}

/// Newest-first pages over `ops.db`: the token is the last record's seq.
fn before_token(page: Option<&PageRequest>) -> Result<Option<i64>, Status> {
    let token = page.map_or("", |p| p.page_token.as_str());
    if token.is_empty() {
        return Ok(None);
    }
    token
        .strip_prefix('s')
        .and_then(|n| n.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .map(Some)
        .ok_or_else(|| Status::invalid_argument("invalid page_token"))
}

/// Offset pages over definitions.
fn offset_token(page: Option<&PageRequest>) -> Result<usize, Status> {
    let token = page.map_or("", |p| p.page_token.as_str());
    if token.is_empty() {
        return Ok(0);
    }
    token
        .strip_prefix('o')
        .and_then(|n| n.parse::<usize>().ok())
        .ok_or_else(|| Status::invalid_argument("invalid page_token"))
}

fn offset_page<T>(items: Vec<T>, page: Option<&PageRequest>) -> Result<(Vec<T>, PageInfo), Status> {
    let start = offset_token(page)?;
    let size = page_size(page);
    let total = items.len();
    let items: Vec<T> = items.into_iter().skip(start).take(size).collect();
    let next = if start + size < total {
        format!("o{}", start + size)
    } else {
        String::new()
    };
    Ok((
        items,
        PageInfo {
            next_page_token: next,
        },
    ))
}

fn range_of(range: Option<&TimeRange>) -> (Option<i64>, Option<i64>) {
    let range = range.cloned().unwrap_or_default();
    (range.start.map(|t| t.seconds), range.end.map(|t| t.seconds))
}

/// Lists one page of `kind` newest first and decodes it.
pub(crate) fn seq_page<M: prost::Message + Default>(
    ops: &OpsStore,
    kind: RecordKind,
    subject: Option<&str>,
    statuses: &[i32],
    range: Option<&TimeRange>,
    page: Option<&PageRequest>,
    keep: impl Fn(&M) -> bool,
) -> Result<(Vec<M>, PageInfo), Status> {
    let size = page_size(page);
    let (from, to) = range_of(range);
    let mut before = before_token(page)?;
    let mut out = Vec::new();
    let mut last_seq = None;
    // Filtering after decode may need more than one read.
    'pages: loop {
        let rows: Vec<Row> = ops.list(
            kind,
            &Listing {
                subject,
                statuses,
                from,
                to,
                before,
                limit: size * 2 + 1,
                ..Default::default()
            },
        );
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            before = Some(row.seq);
            if let Some(message) = row.decode::<M>().filter(|m| keep(m)) {
                if out.len() == size {
                    break 'pages;
                }
                out.push(message);
                last_seq = Some(row.seq);
            }
        }
        if rows.len() < size * 2 + 1 {
            last_seq = None;
            break;
        }
    }
    let next = match (out.len() == size, last_seq) {
        (true, Some(seq)) => format!("s{seq}"),
        _ => String::new(),
    };
    Ok((
        out,
        PageInfo {
            next_page_token: next,
        },
    ))
}

/// Every field a scope filter sets must match.
fn scope_matches(filter: Option<&Scope>, scope: Option<&Scope>) -> bool {
    let (Some(filter), Some(scope)) = (filter, scope) else {
        return true;
    };
    let same = |a: &str, b: &str| a.is_empty() || a == b;
    same(&filter.project_id, &scope.project_id)
        && same(&filter.environment, &scope.environment)
        && same(&filter.environment_id, &scope.environment_id)
        && same(&filter.service_id, &scope.service_id)
}

fn id_arg(id: &str, name: &str) -> Result<(), Status> {
    if text::uuid7(id) {
        Ok(())
    } else {
        Err(Status::invalid_argument(format!("{name} must be a UUIDv7")))
    }
}

// ------------------------------------------------------------ schedules

pub struct ScheduleSvc {
    pub cron: Arc<CronScheduler>,
    pub ops: Arc<OpsStore>,
    pub change: ChangeSvc,
    pub telemetry: Option<Arc<Telemetry>>,
}

/// `RunCronJobNow` requires a plan whose only action is `cron.run` of
/// exactly this job (proto: otherwise FAILED_PRECONDITION +
/// EXEC_PRECONDITION and nothing runs). The envelope is verified by the
/// admission; this only refuses.
fn run_now_matches(envelope: &[u8], cron_id: &str) -> bool {
    let Ok(parsed) = serde_json::from_slice::<Value>(envelope) else {
        return false;
    };
    let actions = parsed["plan"]["actions"].as_array();
    actions.is_some_and(|actions| {
        actions.len() == 1
            && actions[0]["kind"] == "cron.run"
            && actions[0]["params"]["cron_id"] == cron_id
    })
}

#[tonic::async_trait]
impl ScheduleService for ScheduleSvc {
    async fn list_cron_jobs(
        &self,
        request: Request<ListCronJobsRequest>,
    ) -> Result<Response<ListCronJobsResponse>, Status> {
        let request = request.into_inner();
        let jobs: Vec<CronJob> = self
            .cron
            .jobs()
            .values()
            .map(|job| self.cron.job_proto(job))
            .filter(|job| scope_matches(request.scope.as_ref(), job.scope.as_ref()))
            .collect();
        let (jobs, page) = offset_page(jobs, request.page.as_ref())?;
        Ok(Response::new(ListCronJobsResponse {
            jobs,
            page: Some(page),
        }))
    }

    async fn get_cron_job(
        &self,
        request: Request<GetCronJobRequest>,
    ) -> Result<Response<CronJob>, Status> {
        let cron_id = request.into_inner().cron_id;
        id_arg(&cron_id, "cron_id")?;
        let jobs = self.cron.jobs();
        let job = jobs
            .get(&cron_id)
            .ok_or_else(|| Status::not_found("unknown cron job"))?;
        Ok(Response::new(self.cron.job_proto(job)))
    }

    async fn list_cron_runs(
        &self,
        request: Request<ListCronRunsRequest>,
    ) -> Result<Response<ListCronRunsResponse>, Status> {
        let request = request.into_inner();
        let subject = (!request.cron_id.is_empty()).then_some(request.cron_id.as_str());
        let (runs, page) = seq_page::<CronRun>(
            &self.ops,
            RecordKind::CronRun,
            subject,
            &request.statuses,
            request.range.as_ref(),
            request.page.as_ref(),
            |_| true,
        )?;
        Ok(Response::new(ListCronRunsResponse {
            runs,
            page: Some(page),
        }))
    }

    async fn get_cron_run(
        &self,
        request: Request<GetCronRunRequest>,
    ) -> Result<Response<CronRun>, Status> {
        let run_id = request.into_inner().run_id;
        id_arg(&run_id, "run_id")?;
        self.ops
            .get(RecordKind::CronRun, &run_id)
            .and_then(|row| row.decode())
            .map(Response::new)
            .ok_or_else(|| Status::not_found("unknown cron run"))
    }

    async fn run_cron_job_now(
        &self,
        request: Request<RunCronJobNowRequest>,
    ) -> Result<Response<RunCronJobNowResponse>, Status> {
        log_peer(&request, "RunCronJobNow");
        let request = request.into_inner();
        let refused = |message: &str| {
            status_with_reason(
                Code::FailedPrecondition,
                message,
                ErrorReason::ExecPrecondition,
            )
        };
        id_arg(&request.cron_id, "cron_id")?;
        let plan = request
            .plan
            .ok_or_else(|| refused("a cron.run plan is required"))?;
        if !run_now_matches(&plan.envelope_json, &request.cron_id) {
            return Err(refused(
                "the plan's only action must be cron.run of this cron_id",
            ));
        }
        match self.cron.manual_allowed(&request.cron_id) {
            Ok(()) => {}
            Err("unknown cron job") => return Err(refused("unknown cron job")),
            Err(reason) => {
                self.cron.record_skipped_manual(&request.cron_id, reason);
                return Err(status_with_reason(
                    Code::FailedPrecondition,
                    reason,
                    ErrorReason::ScheduleRejected,
                ));
            }
        }
        let operation = self.change.submit(Some(plan)).await?;
        let run = self.cron.record_manual(
            &request.cron_id,
            &operation.plan_id,
            &operation.operation_id,
        );
        Ok(Response::new(RunCronJobNowResponse {
            operation: Some(operation),
            run_id: run.id,
        }))
    }

    type StreamCronRunLogsStream = BoxStream<LogQueryResponse>;

    async fn stream_cron_run_logs(
        &self,
        request: Request<StreamCronRunLogsRequest>,
    ) -> Result<Response<Self::StreamCronRunLogsStream>, Status> {
        let request = request.into_inner();
        id_arg(&request.run_id, "run_id")?;
        let Some(telemetry) = &self.telemetry else {
            return Err(capability_missing());
        };
        if self.ops.get(RecordKind::CronRun, &request.run_id).is_none() {
            return Err(Status::not_found("unknown cron run"));
        }
        let stream = StoreQueries::new(telemetry.clone())
            .query_logs(LogQuery {
                run_id: request.run_id,
                follow: request.follow,
                cursor: request.cursor,
                source_types: vec![LogSourceType::Cron as i32],
                limit: 10_000,
                ..Default::default()
            })
            .await?;
        Ok(Response::new(stream))
    }
}

// -------------------------------------------------------------- backups

pub struct BackupSvc {
    pub backups: Arc<BackupScheduler>,
    pub ops: Arc<OpsStore>,
    /// `server_local` root (`/var/lib/permanu/backups`).
    pub local_root: PathBuf,
    /// One concurrent `ReadBackupArtifact` per agent.
    pub downloads: Arc<Semaphore>,
}

impl BackupSvc {
    pub fn new(backups: Arc<BackupScheduler>, ops: Arc<OpsStore>) -> Self {
        Self {
            backups,
            ops,
            local_root: PathBuf::from(LOCAL_ROOT),
            downloads: Arc::new(Semaphore::new(1)),
        }
    }
}

/// The artifact's file below the `server_local` root, or `None` when its
/// location is elsewhere or would leave the root.
fn local_path(root: &Path, location: &str) -> Option<PathBuf> {
    let relative = location.strip_prefix(LOCAL_ROOT)?.strip_prefix('/')?;
    // Raw segments: `Path::components` would hide a `.` segment.
    let plain = relative
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    let relative = Path::new(relative);
    let normal = relative
        .components()
        .all(|c| matches!(c, Component::Normal(_)));
    (plain && normal && relative.extension().is_some_and(|e| e == "age"))
        .then(|| root.join(relative))
}

#[tonic::async_trait]
impl BackupService for BackupSvc {
    async fn list_backup_policies(
        &self,
        request: Request<ListBackupPoliciesRequest>,
    ) -> Result<Response<ListBackupPoliciesResponse>, Status> {
        let request = request.into_inner();
        let defs = self.backups.definitions();
        let policies: Vec<BackupPolicy> = defs
            .policies
            .values()
            .map(|policy| self.backups.policy_proto(policy, &defs))
            .filter(|policy| scope_matches(request.scope.as_ref(), policy.scope.as_ref()))
            .collect();
        let (policies, page) = offset_page(policies, request.page.as_ref())?;
        Ok(Response::new(ListBackupPoliciesResponse {
            policies,
            page: Some(page),
        }))
    }

    async fn get_backup_policy(
        &self,
        request: Request<GetBackupPolicyRequest>,
    ) -> Result<Response<BackupPolicy>, Status> {
        let policy_id = request.into_inner().policy_id;
        id_arg(&policy_id, "policy_id")?;
        let defs = self.backups.definitions();
        let policy = defs
            .policies
            .get(&policy_id)
            .ok_or_else(|| Status::not_found("unknown backup policy"))?;
        Ok(Response::new(self.backups.policy_proto(policy, &defs)))
    }

    async fn list_backup_runs(
        &self,
        request: Request<ListBackupRunsRequest>,
    ) -> Result<Response<ListBackupRunsResponse>, Status> {
        let request = request.into_inner();
        let subject = (!request.policy_id.is_empty()).then_some(request.policy_id.as_str());
        let (runs, page) = seq_page::<BackupRun>(
            &self.ops,
            RecordKind::BackupRun,
            subject,
            &request.statuses,
            request.range.as_ref(),
            request.page.as_ref(),
            |_| true,
        )?;
        Ok(Response::new(ListBackupRunsResponse {
            runs,
            page: Some(page),
        }))
    }

    async fn get_backup_run(
        &self,
        request: Request<GetBackupRunRequest>,
    ) -> Result<Response<BackupRun>, Status> {
        let run_id = request.into_inner().run_id;
        id_arg(&run_id, "run_id")?;
        self.ops
            .get(RecordKind::BackupRun, &run_id)
            .and_then(|row| row.decode())
            .map(Response::new)
            .ok_or_else(|| Status::not_found("unknown backup run"))
    }

    async fn list_restore_verifications(
        &self,
        request: Request<ListRestoreVerificationsRequest>,
    ) -> Result<Response<ListRestoreVerificationsResponse>, Status> {
        let request = request.into_inner();
        let subject = (!request.policy_id.is_empty()).then_some(request.policy_id.as_str());
        let artifact = request.artifact_id.clone();
        let (verifications, page) = seq_page::<RestoreVerification>(
            &self.ops,
            RecordKind::Verification,
            subject,
            &[],
            request.range.as_ref(),
            request.page.as_ref(),
            |v| artifact.is_empty() || v.artifact_id == artifact,
        )?;
        Ok(Response::new(ListRestoreVerificationsResponse {
            verifications,
            page: Some(page),
        }))
    }

    async fn list_backup_artifacts(
        &self,
        request: Request<ListBackupArtifactsRequest>,
    ) -> Result<Response<ListBackupArtifactsResponse>, Status> {
        let request = request.into_inner();
        let subject = (!request.policy_id.is_empty()).then_some(request.policy_id.as_str());
        let (artifacts, page) = seq_page::<BackupArtifact>(
            &self.ops,
            RecordKind::Artifact,
            subject,
            &[],
            request.range.as_ref(),
            request.page.as_ref(),
            |_| true,
        )?;
        Ok(Response::new(ListBackupArtifactsResponse {
            artifacts,
            page: Some(page),
        }))
    }

    async fn list_backup_destinations(
        &self,
        request: Request<ListBackupDestinationsRequest>,
    ) -> Result<Response<ListBackupDestinationsResponse>, Status> {
        let request = request.into_inner();
        let destinations = self
            .backups
            .definitions()
            .destinations
            .values()
            .map(super::backup::DestinationDef::proto)
            .collect();
        let (destinations, page) = offset_page(destinations, request.page.as_ref())?;
        Ok(Response::new(ListBackupDestinationsResponse {
            destinations,
            page: Some(page),
        }))
    }

    type ReadBackupArtifactStream = BoxStream<BackupArtifactChunk>;

    async fn read_backup_artifact(
        &self,
        request: Request<ReadBackupArtifactRequest>,
    ) -> Result<Response<Self::ReadBackupArtifactStream>, Status> {
        log_peer(&request, "ReadBackupArtifact");
        let request = request.into_inner();
        id_arg(&request.artifact_id, "artifact_id")?;
        let artifact: BackupArtifact = self
            .ops
            .get(RecordKind::Artifact, &request.artifact_id)
            .and_then(|row| row.decode())
            .ok_or_else(|| Status::not_found("unknown backup artifact"))?;
        let precondition = |message: &str| {
            status_with_reason(
                Code::FailedPrecondition,
                message,
                ErrorReason::ExecPrecondition,
            )
        };
        let path = local_path(&self.local_root, &artifact.location).ok_or_else(|| {
            precondition("the artifact is not on a server_local destination; the engine fetches it")
        })?;
        let permit = self.downloads.clone().try_acquire_owned().map_err(|_| {
            status_with_reason(
                Code::ResourceExhausted,
                "one backup download at a time",
                ErrorReason::RateLimited,
            )
        })?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| Status::not_found("the artifact file is gone"))?;
        let meta = file
            .metadata()
            .map_err(|_| Status::internal("stat failed"))?;
        let canonical = std::fs::canonicalize(&path).ok();
        let root = std::fs::canonicalize(&self.local_root).ok();
        let inside = matches!((&canonical, &root), (Some(c), Some(r)) if c.starts_with(r));
        if !meta.is_file() || !inside {
            return Err(precondition(
                "the artifact path is not a regular file below the root",
            ));
        }
        let total = meta.len();
        if request.offset > total {
            return Err(Status::out_of_range("offset is past the end"));
        }
        let digest = artifact.content_digest_hex.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut file = tokio::fs::File::from_std(file);
        let offset = request.offset;
        tokio::spawn(async move {
            let _permit = permit;
            if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
                let _ = tx.send(Err(Status::internal("seek failed"))).await;
                return;
            }
            let mut position = offset;
            loop {
                let mut buffer = vec![0u8; CHUNK_BYTES];
                let mut filled = 0;
                while filled < CHUNK_BYTES {
                    match file.read(&mut buffer[filled..]).await {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(_) => {
                            let _ = tx.send(Err(Status::internal("read failed"))).await;
                            return;
                        }
                    }
                }
                buffer.truncate(filled);
                let last = position + filled as u64 >= total;
                let chunk = BackupArtifactChunk {
                    offset: position,
                    data: buffer,
                    total_bytes: total,
                    last,
                    content_digest_hex: if last { digest.clone() } else { String::new() },
                };
                position += filled as u64;
                if tx.send(Ok(chunk)).await.is_err() || last {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

// --------------------------------------------------------------- alerts

pub struct AlertSvc {
    pub alerts: Arc<AlertEvaluator>,
}

#[tonic::async_trait]
impl AlertService for AlertSvc {
    async fn list_alert_rules(
        &self,
        request: Request<ListAlertRulesRequest>,
    ) -> Result<Response<ListAlertRulesResponse>, Status> {
        let request = request.into_inner();
        let rules: Vec<AlertRule> = self
            .alerts
            .rules()
            .into_iter()
            .filter(|rule| request.states.is_empty() || request.states.contains(&rule.state))
            .collect();
        let (rules, page) = offset_page(rules, request.page.as_ref())?;
        Ok(Response::new(ListAlertRulesResponse {
            rules,
            page: Some(page),
        }))
    }

    async fn get_alert_rule(
        &self,
        request: Request<GetAlertRuleRequest>,
    ) -> Result<Response<AlertRule>, Status> {
        let rule_id = request.into_inner().rule_id;
        id_arg(&rule_id, "rule_id")?;
        self.alerts
            .rules()
            .into_iter()
            .find(|rule| rule.id == rule_id)
            .map(Response::new)
            .ok_or_else(|| Status::not_found("unknown alert rule"))
    }

    async fn list_notification_channels(
        &self,
        request: Request<ListNotificationChannelsRequest>,
    ) -> Result<Response<ListNotificationChannelsResponse>, Status> {
        let request = request.into_inner();
        let (channels, page) = offset_page(self.alerts.channels(), request.page.as_ref())?;
        Ok(Response::new(ListNotificationChannelsResponse {
            channels,
            page: Some(page),
        }))
    }

    async fn test_notification_channel(
        &self,
        request: Request<TestNotificationChannelRequest>,
    ) -> Result<Response<TestNotificationChannelResponse>, Status> {
        log_peer(&request, "TestNotificationChannel");
        let channel_id = request.into_inner().channel_id;
        id_arg(&channel_id, "channel_id")?;
        match self.alerts.test_channel(&channel_id).await {
            Ok(result) => Ok(Response::new(TestNotificationChannelResponse {
                result: Some(result),
            })),
            Err(TestRefusal::NotFound) => Err(Status::not_found("unknown notification channel")),
            Err(TestRefusal::RateLimited) => Err(status_with_reason(
                Code::ResourceExhausted,
                "one test per channel per 10 s",
                ErrorReason::RateLimited,
            )),
        }
    }

    type ListAlertEventsStream = BoxStream<AlertEventsResponse>;

    async fn list_alert_events(
        &self,
        request: Request<ListAlertEventsRequest>,
    ) -> Result<Response<Self::ListAlertEventsStream>, Status> {
        let request = request.into_inner();
        let limit = match request.limit as usize {
            0 => 200,
            n => n.min(MAX_ALERT_EVENTS),
        };
        let after = if request.cursor.is_empty() {
            None
        } else {
            Some(
                request
                    .cursor
                    .parse::<i64>()
                    .map_err(|_| Status::invalid_argument("invalid cursor"))?,
            )
        };
        let (from, to) = range_of(request.range.as_ref());
        let keep = move |event: &AlertEvent| {
            (request.rule_id.is_empty() || event.rule_id == request.rule_id)
                && (request.severities.is_empty() || request.severities.contains(&event.severity))
                && from.is_none_or(|from| event.started_at.is_some_and(|t| t.seconds >= from))
                && to.is_none_or(|to| event.started_at.is_some_and(|t| t.seconds <= to))
        };
        let history: Vec<AlertEvent> = self
            .alerts
            .history(after, MAX_ALERT_EVENTS)
            .into_iter()
            .filter(&keep)
            .take(limit)
            .collect();
        let mut live = request.follow.then(|| self.alerts.subscribe());
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let status = |kind| AlertEventsResponse {
            frame: Some(alert_events_response::Frame::Status(StreamStatus {
                kind,
                ..Default::default()
            })),
        };
        tokio::spawn(async move {
            let batch = |events: Vec<AlertEvent>| AlertEventsResponse {
                frame: Some(alert_events_response::Frame::Batch(AlertEventBatch {
                    events,
                })),
            };
            for chunk in history.chunks(100) {
                if tx.send(Ok(batch(chunk.to_vec()))).await.is_err() {
                    return;
                }
            }
            let Some(live) = live.as_mut() else {
                let _ = tx
                    .send(Ok(status(
                        crate::proto::agent::v2::stream_status::Kind::End as i32,
                    )))
                    .await;
                return;
            };
            if tx
                .send(Ok(status(
                    crate::proto::agent::v2::stream_status::Kind::CaughtUp as i32,
                )))
                .await
                .is_err()
            {
                return;
            }
            loop {
                tokio::select! {
                    event = live.recv() => match event {
                        Ok(event) if keep(&event) => {
                            if tx.send(Ok(batch(vec![event]))).await.is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            let dropped = AlertEventsResponse {
                                frame: Some(alert_events_response::Frame::Status(StreamStatus {
                                    kind: crate::proto::agent::v2::stream_status::Kind::Dropped as i32,
                                    dropped: n,
                                    ..Default::default()
                                })),
                            };
                            if tx.send(Ok(dropped)).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    },
                    () = tx.closed() => return,
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

#[cfg(test)]
mod tests;
