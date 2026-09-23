//! Local mode: agent protocol v2 served on a unix socket (agent-protocol.md).
//!
//! Served: `InfoService` (Hello with trust state and age recipient,
//! GetServerFacts, Ping), `StateService.ListContainers`, `ChangeService`
//! (signed-plan admission, operations, heads, admissions, rules, trusted
//! keys) and `EventService.Subscribe`. Every other v2 RPC answers
//! `UNIMPLEMENTED` with the `ERROR_REASON_CAPABILITY_MISSING` trailer. The
//! only path that changes the host is an admitted signed plan.

pub mod age_recipient;
pub mod change;
pub mod errors;
pub mod events;
pub mod execution;
pub mod facts;
pub mod runner;
pub mod socket;

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
        agent_info,
        change_service_server::ChangeServiceServer,
        event_service_server::EventServiceServer,
        info_service_server::{InfoService, InfoServiceServer},
        state_service_server::{StateService, StateServiceServer},
        trusted_keys_summary::TrustState as TrustStateProto,
        AgentInfo, ClockInfo, Container, ErrorReason, GetServerFactsRequest,
        GetStateSnapshotRequest, HelloRequest, HelloResponse, ListContainersRequest,
        ListContainersResponse, PageInfo, PingRequest, PingResponse, ServerFacts, StateSnapshot,
        TrustedKeysSummary,
    },
    signed_plan::trust::{fingerprint, TrustPaths, TrustState},
};

use facts::{timestamp, HostProbe};

pub const PROTOCOL_VERSION: &str = "2.0";
/// agent-protocol.md section 2 (v2.0.2, D-033): the agent admits signed-plan
/// v1 and drives execution; it serves the section 6.4 store with the v1.0.2
/// columns; and, with a recipient, the runner decrypts sealed secrets.
pub const CAPABILITY_SIGNED_PLANS: &str = "signed_plans.v1";
pub const CAPABILITY_ADMISSIONS: &str = "admissions.v1";
pub const CAPABILITY_AGE: &str = "age.v1";
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
        let req = request.into_inner();
        if !req.protocol_versions.iter().any(|v| v == PROTOCOL_VERSION) {
            return Err(status_with_reason(
                Code::FailedPrecondition,
                &format!("agent speaks protocol {PROTOCOL_VERSION} only"),
                ErrorReason::ProtocolVersion,
            ));
        }
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

        Ok(Response::new(HelloResponse {
            protocol_version: PROTOCOL_VERSION.to_string(),
            agent: Some(AgentInfo {
                version: self.identity.version.clone(),
                binary_digest_hex: self.identity.binary_digest_hex.clone(),
                protocol_versions: vec![PROTOCOL_VERSION.to_string()],
                mode: mode_proto(self.identity.mode) as i32,
                started_at: Some(timestamp(self.identity.started_at)),
                quarantined: false,
                quarantine_reason: String::new(),
                server_id,
                ssh_host_key_digests_hex: self.probe.ssh_host_key_digests_hex(),
                age_recipient: self.age_recipient.clone(),
            }),
            capabilities: capabilities(&self.age_recipient),
            server: Some(self.probe.server_facts().await),
            trusted_keys: Some(trusted_keys),
            clock: Some(ClockInfo {
                agent_time: Some(timestamp(now)),
                ntp_synchronized: self.probe.ntp_synchronized(),
                estimated_skew,
                timezone: self.probe.timezone(),
            }),
            session_id: hex::encode(session),
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

/// `HelloResponse.capabilities`: `age.v1` only when a recipient is set.
fn capabilities(age_recipient: &str) -> Vec<String> {
    let mut ids = vec![
        CAPABILITY_SIGNED_PLANS.to_string(),
        CAPABILITY_ADMISSIONS.to_string(),
    ];
    if !age_recipient.is_empty() {
        ids.push(CAPABILITY_AGE.to_string());
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

fn capability_missing() -> Status {
    status_with_reason(
        Code::Unimplemented,
        "not available on this agent",
        ErrorReason::CapabilityMissing,
    )
}

pub(crate) fn log_peer<T>(request: &Request<T>, rpc: &str) {
    let peer = request
        .extensions()
        .get::<tonic::transport::server::UdsConnectInfo>()
        .and_then(|info| info.peer_cred);
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
}

impl LocalServer {
    /// Serves until `shutdown` resolves.
    pub async fn serve(
        self,
        listener: UnixListener,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> Result<(), tonic::transport::Error> {
        let info_svc = InfoServiceServer::new(InfoSvc {
            probe: self.probe.clone(),
            identity: self.identity,
            trust: self.trust,
            age_recipient: self.age_recipient,
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
        let change_svc = ChangeServiceServer::new(change::ChangeSvc { core: self.core })
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let event_svc = EventServiceServer::new(events::EventSvc { bus: events })
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);

        Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(Duration::from_secs(30)))
            .concurrency_limit_per_connection(32)
            .layer(tower::util::MapResponseLayer::new(tag_unimplemented))
            .add_service(info_svc)
            .add_service(state_svc)
            .add_service(change_svc)
            .add_service(event_svc)
            .serve_with_incoming_shutdown(logged_incoming(listener), shutdown)
            .await
    }
}

fn logged_incoming(
    listener: UnixListener,
) -> impl Stream<Item = std::io::Result<UnixStream>> + Send {
    UnixListenerStream::new(listener).inspect(|conn| match conn {
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
}

/// `permanu-agent:permanu-runner` when the agent runs as root and both
/// exist (D-022); otherwise the store keeps the process's own ids.
fn store_owner(cfg: &LocalConfig) -> Option<StoreOwner> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let uid = socket::resolve_user(&cfg.store_user);
    let gid = socket::resolve_group(&cfg.store_group);
    match (uid, gid) {
        (Ok(uid), Ok(gid)) => Some(StoreOwner { uid, gid }),
        (uid, gid) => {
            warn!(
                user = %cfg.store_user,
                group = %cfg.store_group,
                user_found = uid.is_ok(),
                group_found = gid.is_ok(),
                "store owner or group missing; admissions.db stays root-owned (the runner, as root, can still read it)"
            );
            gid.ok().map(|gid| StoreOwner { uid: 0, gid })
        }
    }
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
        Some(program) => Arc::new(runner::StdioRunner {
            program: program.clone(),
        }),
        None => Arc::new(runner::SocketRunner {
            path: cfg.runner_socket.clone(),
        }),
    };
    let probe: Arc<dyn HostProbe> = Arc::new(facts::SystemProbe {
        server_id,
        ssh_host_key_dir: cfg.ssh_host_key_dir.clone(),
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
    let listener = socket::bind(&cfg.socket_path, gid)?;
    info!(socket = %cfg.socket_path.display(), "serving agent protocol v2");
    let result = LocalServer {
        probe,
        identity: AgentIdentity::current(mode),
        trust,
        age_recipient,
        core,
    }
    .serve(listener, shutdown)
    .await;
    background.abort();
    result?;
    Ok(())
}

#[cfg(test)]
mod change_tests;
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
        }
    }

    fn reason(status: &Status) -> Option<String> {
        status
            .metadata()
            .get(ERROR_REASON_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    #[test]
    fn age_capability_needs_a_recipient() {
        assert_eq!(capabilities(""), vec!["signed_plans.v1", "admissions.v1"]);
        assert_eq!(
            capabilities("age1xyz"),
            vec!["signed_plans.v1", "admissions.v1", "age.v1"]
        );
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
        assert_eq!(agent.protocol_versions, vec!["2.0".to_string()]);
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
            vec!["signed_plans.v1", "admissions.v1", "age.v1"]
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
