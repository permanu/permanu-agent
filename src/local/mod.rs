//! Local mode: agent protocol v2 served on a unix socket (agent-protocol.md).
//!
//! Served: `InfoService` (Hello with trust state and age recipient,
//! GetServerFacts, Ping), `StateService.ListContainers` and
//! `TelemetryService.QueryLogs` (both through the runner's read-only
//! container ops, D-036), `ChangeService` (signed-plan admission,
//! operations, heads, admissions, rules, trusted keys) and
//! `EventService.Subscribe`. Every other v2 RPC answers `UNIMPLEMENTED` with
//! the `ERROR_REASON_CAPABILITY_MISSING` trailer. The only path that changes
//! the host is an admitted signed plan.

pub mod age_recipient;
pub mod artifacts;
pub mod change;
pub mod errors;
pub mod events;
pub mod execution;
pub mod facts;
pub mod hooks;
pub mod logs;
pub mod presence;
pub mod runner;
pub mod sched;
pub mod shell;
pub mod socket;
pub mod status;
pub mod telemetry;

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use futures::{Stream, StreamExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{
    codegen::http,
    metadata::{MetadataMap, MetadataValue},
    transport::Server,
    Code, Request, Response, Status,
};
use tracing::{info, warn};

use crate::{
    admissions::{AdmissionStore, StoreConfig, StoreOwner},
    config::{AgentMode, LocalConfig},
    proto::agent::v2::{
        agent_info, agent_status,
        alert_service_server::AlertServiceServer,
        artifact_service_server::ArtifactServiceServer,
        backup_service_server::BackupServiceServer,
        change_service_server::ChangeServiceServer,
        event_service_server::EventServiceServer,
        info_service_server::{InfoService, InfoServiceServer},
        schedule_service_server::ScheduleServiceServer,
        shell_service_server::ShellServiceServer,
        state_service_server::{StateService, StateServiceServer},
        telemetry_service_server::TelemetryServiceServer,
        trusted_keys_summary::TrustState as TrustStateProto,
        webhook_service_server::WebhookServiceServer,
        AgentInfo, AgentStatus, ClockInfo, Container, ErrorReason, GetServerFactsRequest,
        GetStateSnapshotRequest, HelloRequest, HelloResponse, ListContainersRequest,
        ListContainersResponse, PageInfo, PingRequest, PingResponse, ServerFacts, StateSnapshot,
        TrustedKeysSummary,
    },
    signed_plan::trust::{fingerprint, TrustPaths, TrustState},
};

use facts::{timestamp, HostProbe};

/// agent-protocol.md section 2: v2.1.0 adds RPCs, so `Hello` negotiates
/// `"2.1"` when the client speaks it and `"2.0"` otherwise.
pub const PROTOCOL_VERSION: &str = "2.1";
pub const PROTOCOL_VERSION_2_0: &str = "2.0";
/// v2.1.0 (agent-protocol.md 9, D-053, D-054): the telemetry store, log
/// ingestion, the OTLP receiver and every `TelemetryService` RPC from the
/// store.
pub const CAPABILITY_TELEMETRY: &str = "telemetry.v1";
/// v2.1.2 (contracts v1.1.2, D-060): `QueryAnalytics` from the store with
/// `service_ids` (the rollups carry the service of their route host).
pub const CAPABILITY_ANALYTICS: &str = "analytics.v1";
/// agent-protocol.md section 2 (v2.0.2, D-033): the agent admits signed-plan
/// v1 and drives execution; it serves the section 6.4 store with the v1.0.2
/// columns; and, with a recipient, the runner decrypts sealed secrets.
pub const CAPABILITY_SIGNED_PLANS: &str = "signed_plans.v1";
pub const CAPABILITY_ADMISSIONS: &str = "admissions.v1";
pub const CAPABILITY_AGE: &str = "age.v1";
/// v2.0.3 (D-035): the agent copies signed deployment ids and never mints.
pub const CAPABILITY_DEPLOYMENT_IDS: &str = "deployment_ids.v1";
/// v2.0.3 (D-036): QueryLogs serves APP and SERVICE from the runner's
/// read-only container ops.
pub const CAPABILITY_LOGS_CONTAINERS: &str = "logs.containers.v1";
/// v2.0.5 (D-045): the agent admits v1.0.5 ServiceSpecs (`service_kind`) and
/// `server.add` with `age_recipient_fingerprint`, and fills
/// `Container.environment` and `Container.service_kind`.
pub const CAPABILITY_SERVICE_KIND: &str = "service_kind.v1";
pub const ERROR_REASON_HEADER: &str = "permanu-error-reason";
/// agent-protocol.md section 7.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 500;

/// What the agent says about itself in `AgentInfo`.
#[derive(Clone, Debug)]
pub struct AgentIdentity {
    pub version: String,
    pub binary_digest_hex: String,
    pub mode: AgentMode,
    pub started_at: SystemTime,
}

impl AgentIdentity {
    pub fn current(mode: AgentMode) -> Self {
        Self {
            version: crate::config::agent_version(),
            binary_digest_hex: binary_digest_hex(),
            mode,
            started_at: SystemTime::now(),
        }
    }
}

fn binary_digest_hex() -> String {
    use sha2::{Digest, Sha256};
    std::env::current_exe()
        .and_then(std::fs::read)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .unwrap_or_default()
}

fn mode_proto(mode: AgentMode) -> agent_info::Mode {
    match mode {
        AgentMode::Hosted => agent_info::Mode::Hosted,
        AgentMode::Local => agent_info::Mode::Local,
        AgentMode::Both => agent_info::Mode::Both,
    }
}

/// gRPC status carrying the `permanu-error-reason` trailer.
pub fn status_with_reason(code: Code, message: &str, reason: ErrorReason) -> Status {
    let mut metadata = MetadataMap::new();
    metadata.insert(
        ERROR_REASON_HEADER,
        MetadataValue::from_static(reason.as_str_name()),
    );
    Status::with_metadata(code, message, metadata)
}

pub struct InfoSvc {
    probe: Arc<dyn HostProbe>,
    identity: AgentIdentity,
    trust: TrustPaths,
    age_recipient: String,
    telemetry: Option<Arc<telemetry::Telemetry>>,
    schedulers: bool,
    /// Presence, webhook and scheduler fields of `AgentStatus`.
    sources: status::StatusSources,
    /// `artifacts.v1`: staging and `AgentInfo.release_keys`.
    artifacts: Option<Arc<artifacts::Artifacts>>,
}

/// `AgentStatus` (agent-protocol.md 12.3) from what this agent tracks:
/// health and degraded reasons (telemetry, runner reachability, trust
/// store, clock), the OTLP listeners and the telemetry bytes. Presence,
/// the away summary and scheduler fields stay unset until their
/// surfaces exist.
pub fn build_agent_status(
    telemetry: Option<&telemetry::Telemetry>,
    trust: &TrustState,
    ntp_synchronized: bool,
    now: SystemTime,
) -> AgentStatus {
    let mut reasons: Vec<String> = Vec::new();
    let mut otlp = telemetry::OtlpListen::default();
    let mut bytes = 0;
    if let Some(t) = telemetry {
        reasons.extend(t.degraded_reasons().into_iter().map(str::to_owned));
        otlp = t.otlp();
        bytes = t.usage().kinds.iter().map(|(u, _)| u.bytes_used).sum();
    }
    if matches!(trust, TrustState::Invalid { .. }) {
        reasons.push("trust_store_invalid".to_owned());
    }
    if !ntp_synchronized {
        reasons.push("clock_unsynced".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    AgentStatus {
        health: if reasons.is_empty() {
            agent_status::Health::Ok
        } else {
            agent_status::Health::Degraded
        } as i32,
        degraded_reasons: reasons,
        otlp_grpc_listen: otlp.grpc_listen,
        otlp_http_listen: otlp.http_listen,
        telemetry_bytes_used: bytes,
        computed_at: Some(timestamp(now)),
        ..Default::default()
    }
}

/// `AgentInfo.server_id` and `HelloResponse.trusted_keys` from the trust
/// state (signed-plan.md 7.2, v1.0.1).
fn trust_summary(state: &TrustState) -> (String, TrustedKeysSummary) {
    match state {
        TrustState::Absent => (
            String::new(),
            TrustedKeysSummary {
                state: TrustStateProto::Absent as i32,
                ..Default::default()
            },
        ),
        TrustState::Valid(store) => (
            store.server_id.clone(),
            TrustedKeysSummary {
                fingerprint_digest_hex: store.fingerprint_digest_hex(),
                key_count: store.active_key_count(),
                generation: store.generation(),
                state: TrustStateProto::Valid as i32,
                invalid_reason: String::new(),
            },
        ),
        TrustState::Invalid { reason, document } => (
            document
                .as_ref()
                .and_then(|d| d["server_id"].as_str())
                .filter(|id| crate::signed_plan::text::uuid7(id))
                .unwrap_or_default()
                .to_owned(),
            TrustedKeysSummary {
                fingerprint_digest_hex: document.as_ref().map(fingerprint).unwrap_or_default(),
                state: TrustStateProto::Invalid as i32,
                invalid_reason: reason.clone(),
                ..Default::default()
            },
        ),
    }
}

#[tonic::async_trait]
impl InfoService for InfoSvc {
    async fn hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloResponse>, Status> {
        log_peer(&request, "Hello");
        let connection = presence::connection_of(&request);
        let req = request.into_inner();
        let Some(negotiated) = [PROTOCOL_VERSION, PROTOCOL_VERSION_2_0]
            .into_iter()
            .find(|ours| req.protocol_versions.iter().any(|v| v == ours))
        else {
            return Err(status_with_reason(
                Code::FailedPrecondition,
                &format!(
                    "agent speaks protocol {PROTOCOL_VERSION} and {PROTOCOL_VERSION_2_0} only"
                ),
                ErrorReason::ProtocolVersion,
            ));
        };
        let now = SystemTime::now();
        let trust = self.trust.load();
        if let TrustState::Invalid { reason, .. } = &trust {
            warn!(%reason, "trusted-keys file is invalid; every admission fails");
        }
        let (server_id, trusted_keys) = trust_summary(&trust);
        let estimated_skew = req.client_time.as_ref().map(|client| {
            let agent = timestamp(now);
            let mut seconds = agent.seconds - client.seconds;
            let mut nanos = agent.nanos - client.nanos;
            if seconds > 0 && nanos < 0 {
                seconds -= 1;
                nanos += 1_000_000_000;
            } else if seconds < 0 && nanos > 0 {
                seconds += 1;
                nanos -= 1_000_000_000;
            }
            prost_types::Duration { seconds, nanos }
        });
        let mut session = [0u8; 16];
        getrandom::getrandom(&mut session)
            .map_err(|_| Status::internal("session id generation failed"))?;

        // agent-protocol.md 12.1: an engine Hello opens a session.
        if let (Some(presence), Some(conn)) = (&self.sources.presence, connection) {
            presence.hello(conn, &req.client_name, &req.engine_id);
        }
        let status = (negotiated == PROTOCOL_VERSION).then(|| {
            let mut status = build_agent_status(
                self.telemetry.as_deref(),
                &trust,
                self.probe.ntp_synchronized(),
                now,
            );
            self.sources.fill(&mut status, unix_seconds(now));
            status
        });
        Ok(Response::new(HelloResponse {
            protocol_version: negotiated.to_string(),
            agent: Some(AgentInfo {
                version: self.identity.version.clone(),
                binary_digest_hex: self.identity.binary_digest_hex.clone(),
                protocol_versions: vec![
                    PROTOCOL_VERSION.to_string(),
                    PROTOCOL_VERSION_2_0.to_string(),
                ],
                mode: mode_proto(self.identity.mode) as i32,
                started_at: Some(timestamp(self.identity.started_at)),
                quarantined: false,
                quarantine_reason: String::new(),
                server_id,
                ssh_host_key_digests_hex: self.probe.ssh_host_key_digests_hex(),
                age_recipient: self.age_recipient.clone(),
                release_keys: self.artifacts.as_ref().map(|a| a.summary()),
                recovery_recipient_fingerprint: String::new(),
                bundle_manifest_digest_hex: String::new(),
            }),
            capabilities: capabilities(
                &self.age_recipient,
                self.telemetry.is_some(),
                self.schedulers,
                self.sources.hooks.is_some(),
                self.artifacts.is_some(),
            ),
            server: Some(self.probe.server_facts().await),
            trusted_keys: Some(trusted_keys),
            clock: Some(ClockInfo {
                agent_time: Some(timestamp(now)),
                ntp_synchronized: self.probe.ntp_synchronized(),
                estimated_skew,
                timezone: self.probe.timezone(),
            }),
            session_id: hex::encode(session),
            status,
        }))
    }

    async fn get_server_facts(
        &self,
        request: Request<GetServerFactsRequest>,
    ) -> Result<Response<ServerFacts>, Status> {
        log_peer(&request, "GetServerFacts");
        Ok(Response::new(self.probe.server_facts().await))
    }

    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse {
            client_time: request.into_inner().client_time,
            agent_time: Some(timestamp(SystemTime::now())),
        }))
    }
}

fn unix_seconds(at: SystemTime) -> i64 {
    at.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `HelloResponse.capabilities`: `age.v1` only when a recipient is set,
/// `telemetry.v1` only when the store opened, `cron.v1`, `backups.v1` and
/// `alerts.v1` only while the schedulers run, `webhooks.v1` only with the
/// webhook path and `artifacts.v1` only with the staging directory.
fn capabilities(
    age_recipient: &str,
    telemetry: bool,
    schedulers: bool,
    webhooks: bool,
    artifacts: bool,
) -> Vec<String> {
    let mut ids = vec![
        CAPABILITY_SIGNED_PLANS.to_string(),
        CAPABILITY_ADMISSIONS.to_string(),
        CAPABILITY_DEPLOYMENT_IDS.to_string(),
        CAPABILITY_LOGS_CONTAINERS.to_string(),
        CAPABILITY_SERVICE_KIND.to_string(),
    ];
    if !age_recipient.is_empty() {
        ids.push(CAPABILITY_AGE.to_string());
    }
    if telemetry {
        ids.push(CAPABILITY_TELEMETRY.to_string());
        ids.push(CAPABILITY_ANALYTICS.to_string());
    }
    if schedulers {
        ids.extend(sched::Schedulers::capabilities().map(str::to_owned));
    }
    if webhooks {
        ids.push(hooks::CAPABILITY_WEBHOOKS.to_owned());
    }
    if artifacts {
        ids.push(artifacts::CAPABILITY_ARTIFACTS.to_owned());
    }
    ids
}

pub struct StateSvc {
    probe: Arc<dyn HostProbe>,
}

#[tonic::async_trait]
impl StateService for StateSvc {
    async fn list_containers(
        &self,
        request: Request<ListContainersRequest>,
    ) -> Result<Response<ListContainersResponse>, Status> {
        log_peer(&request, "ListContainers");
        let req = request.into_inner();
        let scope = req.scope.unwrap_or_default();
        if !scope.deployment_id.is_empty() || !scope.app_id.is_empty() {
            return Err(Status::invalid_argument(
                "ListContainers filters by project, environment and service only",
            ));
        }
        let page = req.page.unwrap_or_default();
        let page_size = match page.page_size as usize {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        let offset = if page.page_token.is_empty() {
            0
        } else {
            page.page_token
                .parse::<usize>()
                .map_err(|_| Status::invalid_argument("invalid page_token"))?
        };

        let mut containers: Vec<Container> = self
            .probe
            .containers(req.include_stopped)
            .await?
            .into_iter()
            .filter(|c| {
                matches_field(&scope.project_id, &c.project_id)
                    && matches_field(&scope.service_id, &c.service_id)
                    && matches_field(&scope.environment, &c.environment)
                    && matches_field(&scope.environment_id, &c.environment_id)
            })
            .collect();
        containers.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.container_id.cmp(&b.container_id))
        });
        if offset > containers.len() {
            return Err(Status::invalid_argument("invalid page_token"));
        }
        let end = (offset + page_size).min(containers.len());
        let next_page_token = if end < containers.len() {
            end.to_string()
        } else {
            String::new()
        };
        let items = containers.drain(offset..end).collect();
        Ok(Response::new(ListContainersResponse {
            containers: items,
            page: Some(PageInfo { next_page_token }),
        }))
    }

    async fn get_state_snapshot(
        &self,
        _request: Request<GetStateSnapshotRequest>,
    ) -> Result<Response<StateSnapshot>, Status> {
        Err(capability_missing())
    }
}

fn matches_field(filter: &str, value: &str) -> bool {
    filter.is_empty() || filter == value
}

pub(crate) fn capability_missing() -> Status {
    status_with_reason(
        Code::Unimplemented,
        "not available on this agent",
        ErrorReason::CapabilityMissing,
    )
}

pub(crate) fn log_peer<T>(request: &Request<T>, rpc: &str) {
    let peer = request
        .extensions()
        .get::<presence::ConnectionInfo>()
        .and_then(|info| info.uds.peer_cred);
    if let Some(cred) = peer {
        info!(
            rpc,
            uid = cred.uid(),
            pid = cred.pid().unwrap_or_default(),
            "v2 call"
        );
    }
}

/// Adds the CAPABILITY_MISSING reason to UNIMPLEMENTED responses that lack
/// one (unknown services and methods answered by the router).
fn tag_unimplemented<B>(mut response: http::Response<B>) -> http::Response<B> {
    let headers = response.headers_mut();
    let unimplemented = headers
        .get("grpc-status")
        .is_some_and(|v| v.as_bytes() == b"12");
    if unimplemented && !headers.contains_key(ERROR_REASON_HEADER) {
        headers.insert(
            ERROR_REASON_HEADER,
            http::HeaderValue::from_static(ErrorReason::CapabilityMissing.as_str_name()),
        );
    }
    response
}

/// Everything the local server needs, built once at startup.
pub struct LocalServer {
    pub probe: Arc<dyn HostProbe>,
    pub identity: AgentIdentity,
    pub trust: TrustPaths,
    pub age_recipient: String,
    pub core: Arc<execution::ChangeCore>,
    /// The telemetry store (`telemetry.v1`); `None` serves the M1 paths.
    pub telemetry: Option<Arc<telemetry::Telemetry>>,
    /// Cron, backup and alert schedulers (`cron.v1`, `backups.v1`,
    /// `alerts.v1`); `None` leaves those services unimplemented.
    pub schedulers: Option<sched::Schedulers>,
    /// Engine presence (agent-protocol.md 12.1).
    pub presence: Arc<presence::Presence>,
    /// The webhook path (`webhooks.v1`); `None` leaves it unimplemented.
    pub hooks: Option<Arc<hooks::Hooks>>,
    /// Artifact staging (`artifacts.v1`); `None` leaves it unimplemented.
    pub artifacts: Option<Arc<artifacts::Artifacts>>,
}

impl LocalServer {
    /// The status sources this server fills `AgentStatus` from.
    pub fn sources(&self) -> status::StatusSources {
        status::StatusSources {
            presence: Some(self.presence.clone()),
            hooks: self.hooks.clone(),
            schedulers: self.schedulers.clone(),
        }
    }

    /// Serves until `shutdown` resolves.
    pub async fn serve(
        self,
        listener: UnixListener,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> Result<(), tonic::transport::Error> {
        let sources = self.sources();
        let info_svc = InfoServiceServer::new(InfoSvc {
            probe: self.probe.clone(),
            identity: self.identity,
            trust: self.trust,
            age_recipient: self.age_recipient,
            telemetry: self.telemetry.clone(),
            schedulers: self.schedulers.is_some(),
            sources,
            artifacts: self.artifacts.clone(),
        })
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let state_svc = StateServiceServer::new(StateSvc { probe: self.probe })
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let events = self.core.events.clone();
        let bus = events.clone();
        let shutdown = async move {
            shutdown.await;
            // End open Subscribe/WatchOperation streams so the server drains.
            bus.close();
        };
        let runner = self.core.runner.clone();
        let (schedule_svc, backup_svc, alert_svc) = match self.schedulers {
            Some(s) => (
                Some(
                    ScheduleServiceServer::new(sched::rpc::ScheduleSvc {
                        cron: s.cron.clone(),
                        ops: s.ops.clone(),
                        change: change::ChangeSvc {
                            core: self.core.clone(),
                        },
                        telemetry: self.telemetry.clone(),
                    })
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
                ),
                Some(
                    BackupServiceServer::new(sched::rpc::BackupSvc::new(
                        s.backups.clone(),
                        s.ops.clone(),
                    ))
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
                ),
                Some(
                    AlertServiceServer::new(sched::rpc::AlertSvc { alerts: s.alerts })
                        .max_decoding_message_size(MAX_MESSAGE_BYTES)
                        .max_encoding_message_size(MAX_MESSAGE_BYTES),
                ),
            ),
            None => (None, None, None),
        };
        // agent-protocol.md 4: the only interactive exec path.
        let shell_svc = ShellServiceServer::new(shell::ShellSvc {
            core: self.core.clone(),
            idle: shell::IDLE,
            slots: shell::slots(),
        })
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let change_svc = ChangeServiceServer::new(change::ChangeSvc { core: self.core })
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let webhook_svc = self.hooks.clone().map(|hooks| {
            WebhookServiceServer::new(hooks::rpc::WebhookSvc { hooks })
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES)
        });
        let artifact_svc = self.artifacts.clone().map(|artifacts| {
            ArtifactServiceServer::new(artifacts::ArtifactSvc { artifacts })
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES)
        });
        let event_svc = EventServiceServer::new(events::EventSvc {
            bus: events,
            presence: Some(self.presence.clone()),
        })
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let telemetry = match self.telemetry {
            Some(store) => logs::TelemetrySvc::with_store(runner, store),
            None => logs::TelemetrySvc::new(runner),
        };
        let telemetry_svc = TelemetryServiceServer::new(telemetry)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);

        Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(Duration::from_secs(30)))
            .concurrency_limit_per_connection(32)
            .layer(tower::util::MapResponseLayer::new(tag_unimplemented))
            .layer(presence::PresenceLayer(self.presence.clone()))
            .add_service(info_svc)
            .add_service(state_svc)
            .add_service(change_svc)
            .add_service(shell_svc)
            .add_service(event_svc)
            .add_service(telemetry_svc)
            .add_optional_service(schedule_svc)
            .add_optional_service(backup_svc)
            .add_optional_service(alert_svc)
            .add_optional_service(webhook_svc)
            .add_optional_service(artifact_svc)
            .serve_with_incoming_shutdown(logged_incoming(listener, self.presence), shutdown)
            .await
    }
}

fn logged_incoming(
    listener: UnixListener,
    presence: Arc<presence::Presence>,
) -> impl Stream<Item = std::io::Result<presence::TrackedStream>> + Send {
    UnixListenerStream::new(listener)
        .inspect(|conn: &std::io::Result<UnixStream>| match conn {
            Ok(stream) => match stream.peer_cred() {
                Ok(cred) => info!(
                    uid = cred.uid(),
                    gid = cred.gid(),
                    pid = cred.pid().unwrap_or_default(),
                    "v2 connection"
                ),
                Err(err) => warn!(error = %err, "v2 connection without peer credentials"),
            },
            Err(err) => warn!(error = %err, "v2 accept failed"),
        })
        .map(move |conn| {
            conn.map(|stream| presence::TrackedStream::new(stream, Some(presence.clone())))
        })
}

/// `permanu-agent:permanu-runner` for the store files (D-022, section 6.3).
fn store_owner(cfg: &LocalConfig) -> Option<StoreOwner> {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let owner = store_owner_from(
        euid,
        socket::resolve_user(&cfg.store_user),
        socket::resolve_group(&cfg.store_group),
    );
    if owner.is_none() {
        warn!(
            user = %cfg.store_user,
            group = %cfg.store_group,
            "store group missing; admissions.db keeps the agent's own group"
        );
    }
    owner
}

/// The store group is required: a non-root agent (the server layout, D-030)
/// keeps its own uid and chowns only the group, which it may because it is
/// a supplementary member (F-16); root also sets the `permanu-agent` uid.
fn store_owner_from(
    euid: u32,
    user: std::io::Result<u32>,
    group: std::io::Result<u32>,
) -> Option<StoreOwner> {
    let gid = group.ok()?;
    let uid = match (euid, user) {
        (0, Ok(uid)) => uid,
        (euid, _) => euid,
    };
    Some(StoreOwner { uid, gid })
}

/// Binds the configured socket and serves v2 until `shutdown` resolves.
pub async fn run(
    cfg: LocalConfig,
    mode: AgentMode,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let gid = cfg
        .socket_group
        .as_deref()
        .map(socket::resolve_group)
        .transpose()?;
    let trust = TrustPaths {
        lock: cfg.trust_lock_path.clone(),
        owner_uid: cfg.file_owner_uid,
        ..TrustPaths::production(cfg.trusted_keys_path.clone())
    };
    let trust_state = trust.load();
    let server_id = match &trust_state {
        TrustState::Valid(store) => store.server_id.clone(),
        _ => String::new(),
    };
    let now = execution::Clock::now(&execution::SystemClock);
    let owner = store_owner(&cfg);
    let (store, report) = AdmissionStore::open(
        &StoreConfig {
            path: cfg.admissions_db.clone(),
            owner,
        },
        !matches!(trust_state, TrustState::Absent),
        now,
    )?;
    let age_recipient =
        match age_recipient::read_recipient(&cfg.age_recipient_path, cfg.file_owner_uid) {
            Ok(recipient) => recipient,
            Err(err) => {
                warn!(error = %err, "no age recipient; secrets cannot be sealed for this server");
                String::new()
            }
        };
    let runner: Arc<dyn runner::Runner> = match &cfg.runner_path {
        #[cfg(feature = "dev-paths")]
        Some(program) => Arc::new(runner::StdioRunner {
            program: program.clone(),
        }),
        _ => Arc::new(runner::SocketRunner {
            path: cfg.runner_socket.clone(),
        }),
    };
    let probe: Arc<dyn HostProbe> = Arc::new(facts::SystemProbe {
        server_id,
        ssh_host_key_dir: cfg.ssh_host_key_dir.clone(),
        runner: runner.clone(),
    });
    let core = execution::ChangeCore::new(execution::ChangeCoreParts {
        store: Arc::new(store),
        trust: trust.clone(),
        probe: probe.clone(),
        runner,
        events: events::EventBus::new(),
        clock: Arc::new(execution::SystemClock),
        consumed_log: cfg.consumed_log.clone(),
        consumed_log_owner: cfg.file_owner_uid,
        age_recipient: age_recipient.clone(),
        timing: execution::Timing::default(),
    });
    if report.recreated {
        warn!(
            moved_aside = ?report.moved_aside,
            "admissions.db was lost or corrupt and was recreated; admissions are quarantined for 20 minutes"
        );
        core.store_recreated();
    }
    let background = core.spawn_background();
    let presence = presence::Presence::new(Arc::new(execution::SystemClock));
    let ops = open_ops(&cfg, owner);
    let cron_runs = ops
        .clone()
        .map(|ops| -> Arc<dyn telemetry::ingest::CronRuns> {
            Arc::new(sched::CronRunIndex::from_parts(
                ops,
                sched::ConsumedLogRef {
                    path: core.consumed_log.clone(),
                    owner_uid: core.consumed_log_owner,
                },
            ))
        });
    let (telemetry, mut telemetry_tasks) = start_telemetry(&cfg, &core, cron_runs);
    let schedulers = start_schedulers(
        ops.clone(),
        &core,
        telemetry.clone(),
        &age_recipient,
        &trust,
    );
    let mut scheduler_tasks = schedulers
        .as_ref()
        .map(sched::Schedulers::spawn)
        .unwrap_or_default();
    let hooks = ops.clone().map(|ops| {
        hooks::Hooks::new(
            hooks::HookDeps {
                store: core.store.clone(),
                ops,
                core: core.clone(),
                events: core.events.clone(),
                clock: Arc::new(execution::SystemClock),
                logs: sched::AgentLogs {
                    telemetry: telemetry.clone(),
                    host: hostname(),
                },
                presence: Some(presence.clone()),
                alerts: schedulers
                    .as_ref()
                    .map(|s| -> Arc<dyn sched::AlertSink> { s.alerts.clone() }),
            },
            hooks::HookTiming::default(),
        )
    });
    if let Some(hooks) = &hooks {
        match hooks::listener::bind_and_serve(hooks.clone(), hooks::LISTEN_ADDR).await {
            Ok(task) => scheduler_tasks.push(task),
            Err(err) => warn!(error = %err, "webhook listener not bound"),
        }
        scheduler_tasks.push(hooks.spawn_sweeper());
        scheduler_tasks.push(hooks.spawn_rule_watch());
    }
    let artifacts = ops
        .clone()
        .filter(|_| cfg.staging_root.is_dir())
        .map(|ops| {
            artifacts::Artifacts::new(artifacts::ArtifactDeps {
                root: cfg.staging_root.clone(),
                release_keys: cfg.release_keys_path.clone(),
                release_keys_owner: cfg.file_owner_uid,
                ops,
                probe: probe.clone(),
                clock: Arc::new(execution::SystemClock),
                mode: artifacts::ReleaseMode::production(),
            })
        });
    if let Some(artifacts) = &artifacts {
        let _ = core.staging.set(artifacts.clone());
    }
    let sources = status::StatusSources {
        presence: Some(presence.clone()),
        hooks: hooks.clone(),
        schedulers: schedulers.clone(),
    };
    telemetry_tasks.push(spawn_presence_feed(presence.clone(), core.events.clone()));
    telemetry_tasks.push(spawn_status_events(
        telemetry.clone(),
        core.events.clone(),
        probe.clone(),
        trust.clone(),
        sources,
    ));
    let listener = socket::listen(&cfg.socket_path, gid)?;
    info!(socket = %cfg.socket_path.display(), "serving agent protocol v2");
    let result = LocalServer {
        probe,
        identity: AgentIdentity::current(mode),
        trust,
        age_recipient,
        core,
        telemetry: telemetry.clone(),
        schedulers,
        presence,
        hooks,
        artifacts,
    }
    .serve(listener, shutdown)
    .await;
    background.abort();
    for task in scheduler_tasks {
        task.abort();
    }
    for task in telemetry_tasks {
        task.abort();
    }
    if let Some(telemetry) = telemetry {
        // Store what is queued, then close the open segments.
        telemetry.sync().await;
        telemetry.close();
    }
    result?;
    Ok(())
}

/// Opens `ops.db` next to `admissions.db`. A store that cannot open leaves
/// the schedulers, the webhook path and staging off.
fn open_ops(
    cfg: &LocalConfig,
    owner: Option<StoreOwner>,
) -> Option<Arc<sched::ops_store::OpsStore>> {
    let path = cfg.admissions_db.with_file_name("ops.db");
    match sched::ops_store::OpsStore::open(&path, owner) {
        Ok(ops) => Some(Arc::new(ops)),
        Err(err) => {
            warn!(error = %err, path = %path.display(), "ops.db unavailable; schedulers, webhooks and staging are off");
            None
        }
    }
}

/// Builds the schedulers (agent-protocol.md 10); without `ops.db` they are
/// off (no `cron.v1`, `backups.v1`, `alerts.v1`).
fn start_schedulers(
    ops: Option<Arc<sched::ops_store::OpsStore>>,
    core: &Arc<execution::ChangeCore>,
    telemetry: Option<Arc<telemetry::Telemetry>>,
    age_recipient: &str,
    trust: &TrustPaths,
) -> Option<sched::Schedulers> {
    let ops = ops?;
    let source: Arc<dyn sched::alerts::AlertSource> = match &telemetry {
        Some(store) => Arc::new(sched::source::StoreSource::new(store.clone())),
        None => Arc::new(sched::alerts::NoSource),
    };
    let deps = sched::Deps {
        store: core.store.clone(),
        ops,
        runner: core.runner.clone(),
        events: core.events.clone(),
        clock: Arc::new(execution::SystemClock),
        logs: sched::AgentLogs {
            telemetry,
            host: hostname(),
        },
        // server.add writes the trust store after the agent started.
        server_id: sched::ServerId::Trust(trust.clone()),
        consumed_log: Some(sched::ConsumedLogRef {
            path: core.consumed_log.clone(),
            owner_uid: core.consumed_log_owner,
        }),
    };
    Some(sched::Schedulers::new(
        deps,
        age_recipient.to_owned(),
        source,
    ))
}

/// Opens the telemetry store and starts its producers (agent-protocol.md
/// 9): retention and the disk guard, log ingestion from the runner, the
/// metrics sampler, the OTLP listeners and `AGENT_STATUS` events. A store
/// that cannot open leaves the agent on the M1 paths (no `telemetry.v1`).
fn start_telemetry(
    cfg: &LocalConfig,
    core: &Arc<execution::ChangeCore>,
    cron_runs: Option<Arc<dyn telemetry::ingest::CronRuns>>,
) -> (
    Option<Arc<telemetry::Telemetry>>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    let opened = telemetry::Telemetry::open(telemetry::TelemetryParts {
        options: telemetry::store::StoreOptions::new(cfg.telemetry_root.clone()),
        disk: Arc::new(telemetry::store::StatvfsDisk),
        events: Some(core.events.clone()),
    });
    let store = match opened {
        Ok(store) => store,
        Err(err) => {
            warn!(error = %err, root = %cfg.telemetry_root.display(), "telemetry store unavailable; serving M1 log paths");
            return (None, Vec::new());
        }
    };
    let host = hostname();
    let runner = core.runner.clone();
    let mut tasks = vec![store.spawn_maintenance()];
    // contracts v1.1.5 (D-063 #9): Dwaar records by the service of their
    // route host, from the runner's `routes_map`.
    let routes = Arc::new(telemetry::routes::RoutesMap::default());
    tasks.push(routes.spawn(runner.clone()));
    tasks.push(spawn_routes_nudge(routes.clone(), core.events.clone()));
    // QA_M2 X1: `dwaar.*` series carry this server's id (read from the
    // trust store; `server.add` may write it after the agent started).
    let trust = core.trust.clone();
    let server_id: telemetry::ingest::ServerIdFn = Arc::new(move || match trust.load() {
        crate::signed_plan::trust::TrustState::Valid(store) => store.server_id,
        _ => String::new(),
    });
    let mut ingest = telemetry::ingest::LogIngest::new(store.clone(), runner.clone(), host)
        .with_routes(routes)
        .with_server_id(server_id);
    if let Some(cron_runs) = cron_runs {
        ingest = ingest.with_cron_runs(cron_runs);
    }
    tasks.push(tokio::spawn(ingest.run()));
    tasks.push(tokio::spawn(
        telemetry::metrics::Sampler::new(store.clone(), runner.clone()).run(),
    ));
    let listeners = match cfg.dev_otlp_loopback {
        #[cfg(feature = "dev-paths")]
        Some((grpc_port, http_port)) => {
            telemetry::otlp_server::Listeners::dev_loopback(store.clone(), grpc_port, http_port)
        }
        _ => telemetry::otlp_server::Listeners {
            telemetry: store.clone(),
            net: Arc::new(telemetry::otlp_server::SystemNetwork {
                proc_root: std::path::PathBuf::from("/proc"),
            }),
            firewall: Arc::new(telemetry::otlp_server::RunnerFirewall { runner }),
            gateway_iface: telemetry::otlp_server::GATEWAY_IFACE.to_owned(),
            grpc_port: telemetry::otlp_server::GRPC_PORT,
            http_port: telemetry::otlp_server::HTTP_PORT,
            limits: telemetry::otlp_server::OtlpLimits::default(),
        },
    };
    tasks.push(tokio::spawn(listeners.run()));
    (Some(store), tasks)
}

/// Refreshes the routes map after every finished plan that holds a
/// `domain.*` or `webhook.host.set` action (agent-protocol.md 9.5).
fn spawn_routes_nudge(
    routes: Arc<telemetry::routes::RoutesMap>,
    events: events::EventBus,
) -> tokio::task::JoinHandle<()> {
    let mut live = events.live();
    tokio::spawn(async move {
        loop {
            match live.recv().await {
                Ok(event) => {
                    if let Some(crate::proto::agent::v2::event::Payload::Operation(op)) =
                        &event.payload
                    {
                        if op.finished_at.is_some()
                            && telemetry::routes::changes_routes(&op.actions)
                        {
                            routes.nudge();
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => routes.nudge(),
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most buf.len() bytes into our buffer.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Feeds the away summary from the agent's own events and ends silent
/// engine sessions (agent-protocol.md 12.1, 12.2).
fn spawn_presence_feed(
    presence: Arc<presence::Presence>,
    events: events::EventBus,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut live = events.live();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = tick.tick() => presence.tick(),
                event = live.recv() => match event {
                    Ok(event) => presence.observe(&event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
            }
        }
    })
}

/// Emits `EVENT_KIND_AGENT_STATUS` whenever health, the degraded reasons or
/// engine presence change (checked every 5 s, and at once on a presence
/// flip).
fn spawn_status_events(
    telemetry: Option<Arc<telemetry::Telemetry>>,
    events: events::EventBus,
    probe: Arc<dyn HostProbe>,
    trust: TrustPaths,
    sources: status::StatusSources,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last: Option<(i32, Vec<String>, bool)> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            match &sources.presence {
                Some(presence) => {
                    tokio::select! {
                        _ = tick.tick() => {}
                        () = presence.changed.notified() => {}
                    }
                }
                None => {
                    tick.tick().await;
                }
            }
            let now = SystemTime::now();
            let mut status = build_agent_status(
                telemetry.as_deref(),
                &trust.load(),
                probe.ntp_synchronized(),
                now,
            );
            sources.fill(&mut status, unix_seconds(now));
            let key = (
                status.health,
                status.degraded_reasons.clone(),
                status.engine_online,
            );
            if last.as_ref() != Some(&key) {
                last = Some(key);
                events.publish(
                    crate::proto::agent::v2::EventKind::AgentStatus,
                    crate::proto::agent::v2::Scope::default(),
                    crate::proto::agent::v2::event::Payload::AgentStatus(status),
                );
            }
        }
    })
}

#[cfg(test)]
mod change_tests;
#[cfg(test)]
mod shell_tests;
#[cfg(test)]
pub(crate) mod test_harness;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::agent::v2::{
        info_service_client::InfoServiceClient, state_service_client::StateServiceClient,
        PageRequest, Scope,
    };

    use test_harness::Harness;

    fn hello_request(versions: &[&str]) -> HelloRequest {
        HelloRequest {
            client_name: "permanu-engine".to_string(),
            client_version: "0.0.0-test".to_string(),
            protocol_versions: versions.iter().map(|v| v.to_string()).collect(),
            client_time: Some(timestamp(SystemTime::now())),
            engine_id: String::new(),
        }
    }

    fn reason(status: &Status) -> Option<String> {
        status
            .metadata()
            .get(ERROR_REASON_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    // Section 6.3 (F-16): the non-root agent still puts its store in group
    // permanu-runner (it is a supplementary member); root chowns both.
    #[test]
    fn store_owner_uses_the_store_group_even_when_not_root() {
        let missing = || Err(std::io::Error::other("missing"));
        assert_eq!(
            store_owner_from(1000, Ok(2000), Ok(3000)),
            Some(StoreOwner {
                uid: 1000,
                gid: 3000
            })
        );
        assert_eq!(
            store_owner_from(0, Ok(2000), Ok(3000)),
            Some(StoreOwner {
                uid: 2000,
                gid: 3000
            })
        );
        assert_eq!(store_owner_from(1000, Ok(2000), missing()), None);
        assert_eq!(
            store_owner_from(0, missing(), Ok(3000)),
            Some(StoreOwner { uid: 0, gid: 3000 })
        );
    }

    #[test]
    fn age_capability_needs_a_recipient() {
        assert_eq!(
            capabilities("", false, false, false, false),
            vec![
                "signed_plans.v1",
                "admissions.v1",
                "deployment_ids.v1",
                "logs.containers.v1",
                "service_kind.v1"
            ]
        );
        assert_eq!(
            capabilities("age1xyz", false, false, false, false),
            vec![
                "signed_plans.v1",
                "admissions.v1",
                "deployment_ids.v1",
                "logs.containers.v1",
                "service_kind.v1",
                "age.v1"
            ]
        );
        // telemetry.v1 supersedes logs.containers.v1 for reads; both stay.
        assert_eq!(
            capabilities("", true, false, false, false),
            vec![
                "signed_plans.v1",
                "admissions.v1",
                "deployment_ids.v1",
                "logs.containers.v1",
                "service_kind.v1",
                "telemetry.v1",
                "analytics.v1"
            ]
        );
        let with_schedulers = capabilities("", false, true, false, false);
        assert!(with_schedulers.ends_with(&[
            "cron.v1".to_owned(),
            "backups.v1".to_owned(),
            "alerts.v1".to_owned()
        ]));
    }

    #[tokio::test]
    async fn hello_negotiates_2_1_with_status_and_telemetry() {
        let h = Harness::with(
            "hello21",
            test_harness::Options {
                telemetry: true,
                ..Default::default()
            },
        )
        .await;
        let mut client = InfoServiceClient::new(h.channel.clone());
        let hello = client
            .hello(hello_request(&["2.0", "2.1"]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hello.protocol_version, "2.1");
        assert_eq!(hello.agent.unwrap().protocol_versions, vec!["2.1", "2.0"]);
        assert!(hello.capabilities.contains(&"telemetry.v1".to_owned()));
        let status = hello.status.unwrap();
        // No OTLP listener in tests: degraded with otlp_unbound only.
        assert_eq!(status.health, agent_status::Health::Degraded as i32);
        assert_eq!(status.degraded_reasons, vec!["otlp_unbound"]);
        assert_eq!(status.otlp_grpc_listen, "");
        assert!(status.computed_at.is_some());
        // A 2.0 client gets 2.0 and no status.
        let old = client
            .hello(hello_request(&["2.0"]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(old.protocol_version, "2.0");
        assert!(old.status.is_none());
        h.stop().await;
    }

    #[tokio::test]
    async fn hello_round_trip_over_unix_socket() {
        let trust =
            serde_json::to_string(&crate::signed_plan::test_support::vector("trusted-keys"))
                .unwrap();
        let h = Harness::start("hello", Some(&trust)).await;
        let mut client = InfoServiceClient::new(h.channel.clone());

        let hello = client
            .hello(hello_request(&["2.0"]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hello.protocol_version, "2.0");
        let agent = hello.agent.unwrap();
        assert_eq!(agent.version, "test-1");
        assert_eq!(agent.binary_digest_hex, "cd".repeat(32));
        assert_eq!(agent.protocol_versions, vec!["2.1", "2.0"]);
        assert_eq!(agent.mode, agent_info::Mode::Local as i32);
        assert_eq!(agent.server_id, "01a0cdb5-3500-70a1-8000-000000000001");
        assert_eq!(agent.ssh_host_key_digests_hex, vec!["ab".repeat(32)]);
        assert!(agent.started_at.is_some());
        assert_eq!(hello.server.unwrap().hostname, "fake-host");
        assert_eq!(agent.age_recipient, h.age_recipient);
        assert!(agent.age_recipient.starts_with("age1"));
        let trusted = hello.trusted_keys.unwrap();
        assert_eq!(trusted.state, TrustStateProto::Valid as i32);
        assert_eq!(trusted.invalid_reason, "");
        // Four keys, one revoked directly; generation counts every entry.
        assert_eq!(trusted.key_count, 3);
        assert_eq!(trusted.generation, 5);
        assert_eq!(
            trusted.fingerprint_digest_hex,
            fingerprint(&crate::signed_plan::test_support::vector("trusted-keys"))
        );
        let clock = hello.clock.unwrap();
        assert!(clock.agent_time.is_some());
        assert!(clock.ntp_synchronized);
        assert!(clock.estimated_skew.is_some());
        assert_eq!(clock.timezone, "Etc/UTC");
        assert_eq!(hello.session_id.len(), 32);
        assert_eq!(
            hello.capabilities,
            vec![
                "signed_plans.v1",
                "admissions.v1",
                "deployment_ids.v1",
                "logs.containers.v1",
                "service_kind.v1",
                "age.v1"
            ]
        );

        let facts = client
            .get_server_facts(GetServerFactsRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(facts.memory_total_bytes, 42);

        let sent = timestamp(SystemTime::now());
        let pong = client
            .ping(PingRequest {
                client_time: Some(sent),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(pong.client_time, Some(sent));
        assert!(pong.agent_time.is_some());
        h.stop().await;
    }

    #[tokio::test]
    async fn hello_without_trusted_keys_reports_absent() {
        let h = Harness::start("notrust", None).await;
        let mut client = InfoServiceClient::new(h.channel.clone());
        let hello = client
            .hello(hello_request(&["2.0"]))
            .await
            .unwrap()
            .into_inner();
        let trusted = hello.trusted_keys.unwrap();
        assert_eq!(trusted.state, TrustStateProto::Absent as i32);
        assert_eq!(trusted.fingerprint_digest_hex, "");
        assert_eq!(trusted.key_count, 0);
        assert_eq!(hello.agent.unwrap().server_id, "");
        h.stop().await;
    }

    #[tokio::test]
    async fn hello_reports_an_invalid_trust_file_with_its_reason() {
        let mut file = crate::signed_plan::test_support::vector("trusted-keys");
        file["keys"][1]["label"] = serde_json::Value::String("Tampered".to_owned());
        let h = Harness::start("badtrust", Some(&file.to_string())).await;
        let mut client = InfoServiceClient::new(h.channel.clone());
        let hello = client
            .hello(hello_request(&["2.0"]))
            .await
            .unwrap()
            .into_inner();
        let trusted = hello.trusted_keys.unwrap();
        assert_eq!(trusted.state, TrustStateProto::Invalid as i32);
        assert_eq!(
            trusted.invalid_reason,
            "added_by is not a valid earlier owner signature"
        );
        assert_eq!(trusted.fingerprint_digest_hex, fingerprint(&file));
        assert_eq!(
            hello.agent.unwrap().server_id,
            "01a0cdb5-3500-70a1-8000-000000000001"
        );
        h.stop().await;
    }

    #[tokio::test]
    async fn hello_rejects_unknown_protocol_version() {
        let h = Harness::start("version", None).await;
        let mut client = InfoServiceClient::new(h.channel.clone());
        let status = client.hello(hello_request(&["3.0"])).await.unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(
            reason(&status).as_deref(),
            Some("ERROR_REASON_PROTOCOL_VERSION")
        );
        h.stop().await;
    }

    #[tokio::test]
    async fn list_containers_filters_sorts_and_pages() {
        let h = Harness::start("list", None).await;
        let mut client = StateServiceClient::new(h.channel.clone());

        let first = client
            .list_containers(ListContainersRequest {
                scope: Some(Scope {
                    project_id: "p1".to_string(),
                    ..Default::default()
                }),
                include_stopped: false,
                page: Some(PageRequest {
                    page_size: 2,
                    page_token: String::new(),
                }),
            })
            .await
            .unwrap()
            .into_inner();
        let names: Vec<_> = first.containers.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["web-1", "web-2"]);
        let token = first.page.unwrap().next_page_token;
        assert!(!token.is_empty());

        let second = client
            .list_containers(ListContainersRequest {
                scope: Some(Scope {
                    project_id: "p1".to_string(),
                    ..Default::default()
                }),
                include_stopped: false,
                page: Some(PageRequest {
                    page_size: 2,
                    page_token: token,
                }),
            })
            .await
            .unwrap()
            .into_inner();
        let names: Vec<_> = second.containers.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["web-3"]);
        assert_eq!(second.page.unwrap().next_page_token, "");

        let all = client
            .list_containers(ListContainersRequest {
                include_stopped: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(all.containers.len(), 5);

        let bad = client
            .list_containers(ListContainersRequest {
                page: Some(PageRequest {
                    page_size: 0,
                    page_token: "nope".to_string(),
                }),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(bad.code(), Code::InvalidArgument);
        h.stop().await;
    }

    #[tokio::test]
    async fn scheduler_services_are_served_with_their_capabilities() {
        use crate::local::test_harness::Options;
        use crate::proto::agent::v2::{
            alert_service_client::AlertServiceClient, backup_service_client::BackupServiceClient,
            schedule_service_client::ScheduleServiceClient, GetCronJobRequest,
            ListBackupPoliciesRequest, ListCronJobsRequest, RunCronJobNowRequest,
            TestNotificationChannelRequest,
        };
        let h = Harness::with(
            "sched-wired",
            Options {
                schedulers: true,
                ..Default::default()
            },
        )
        .await;
        let mut info = InfoServiceClient::new(h.channel.clone());
        let hello = info
            .hello(hello_request(&["2.1"]))
            .await
            .unwrap()
            .into_inner();
        for capability in ["cron.v1", "backups.v1", "alerts.v1"] {
            assert!(
                hello.capabilities.contains(&capability.to_owned()),
                "{capability}"
            );
        }
        let mut schedules = ScheduleServiceClient::new(h.channel.clone());
        let jobs = schedules
            .list_cron_jobs(ListCronJobsRequest::default())
            .await
            .unwrap()
            .into_inner();
        assert!(jobs.jobs.is_empty());
        let missing = schedules
            .get_cron_job(GetCronJobRequest {
                cron_id: "01a0cdb5-3500-70d2-8000-000000000001".to_owned(),
            })
            .await
            .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);
        let refused = schedules
            .run_cron_job_now(RunCronJobNowRequest {
                cron_id: "01a0cdb5-3500-70d2-8000-000000000001".to_owned(),
                plan: None,
            })
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::FailedPrecondition);
        assert_eq!(
            reason(&refused).as_deref(),
            Some("ERROR_REASON_EXEC_PRECONDITION")
        );
        let mut backups = BackupServiceClient::new(h.channel.clone());
        assert!(backups
            .list_backup_policies(ListBackupPoliciesRequest::default())
            .await
            .unwrap()
            .into_inner()
            .policies
            .is_empty());
        let mut alerts = AlertServiceClient::new(h.channel.clone());
        let unknown = alerts
            .test_notification_channel(TestNotificationChannelRequest {
                channel_id: "01a0cdb5-3500-70e2-8000-000000000001".to_owned(),
            })
            .await
            .unwrap_err();
        assert_eq!(unknown.code(), Code::NotFound);
        h.stop().await;
    }

    #[tokio::test]
    async fn other_v2_rpcs_are_unimplemented_with_capability_missing() {
        let h = Harness::start("unimpl", None).await;
        use crate::proto::agent::v2::{
            telemetry_service_client::TelemetryServiceClient, ListMetricsRequest,
        };

        let mut state = StateServiceClient::new(h.channel.clone());
        let status = state
            .get_state_snapshot(GetStateSnapshotRequest::default())
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(
            reason(&status).as_deref(),
            Some("ERROR_REASON_CAPABILITY_MISSING")
        );

        let mut telemetry = TelemetryServiceClient::new(h.channel.clone());
        let status = telemetry
            .list_metrics(ListMetricsRequest::default())
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(
            reason(&status).as_deref(),
            Some("ERROR_REASON_CAPABILITY_MISSING")
        );
        h.stop().await;
    }
}
