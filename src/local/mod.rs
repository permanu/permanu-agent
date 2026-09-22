//! Local mode: agent protocol v2 served on a unix socket (agent-protocol.md).
//!
//! This slice serves `InfoService` (Hello, GetServerFacts, Ping) and
//! `StateService.ListContainers`. Every other v2 RPC answers `UNIMPLEMENTED`
//! with the `permanu-error-reason: ERROR_REASON_CAPABILITY_MISSING` trailer.
//! Nothing served here mutates the host.

pub mod facts;
pub mod socket;

use std::{
    path::PathBuf,
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
    config::{AgentMode, LocalConfig},
    proto::agent::v2::{
        agent_info,
        info_service_server::{InfoService, InfoServiceServer},
        state_service_server::{StateService, StateServiceServer},
        AgentInfo, ClockInfo, Container, ErrorReason, GetServerFactsRequest,
        GetStateSnapshotRequest, HelloRequest, HelloResponse, ListContainersRequest,
        ListContainersResponse, PageInfo, PingRequest, PingResponse, ServerFacts, StateSnapshot,
        TrustedKeysSummary,
    },
    trusted_keys,
};

use facts::{timestamp, HostProbe};

pub const PROTOCOL_VERSION: &str = "2.0";
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
    trusted_keys_path: PathBuf,
    require_root_owned_trust_file: bool,
}

impl InfoSvc {
    fn trusted_keys(&self) -> Option<trusted_keys::TrustedKeysSummary> {
        match trusted_keys::read_summary(
            &self.trusted_keys_path,
            self.require_root_owned_trust_file,
        ) {
            Ok(summary) => summary,
            Err(err) => {
                warn!(error = %err, "trusted-keys file unreadable; Hello reports no trust set");
                None
            }
        }
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
        let trust = self.trusted_keys();
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
                server_id: trust
                    .as_ref()
                    .map(|t| t.server_id.clone())
                    .unwrap_or_default(),
                ssh_host_key_digests_hex: self.probe.ssh_host_key_digests_hex(),
            }),
            capabilities: Vec::new(),
            server: Some(self.probe.server_facts().await),
            trusted_keys: trust.map(|t| TrustedKeysSummary {
                fingerprint_digest_hex: t.fingerprint_digest_hex,
                key_count: t.key_count,
                generation: t.generation,
            }),
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

fn log_peer<T>(request: &Request<T>, rpc: &str) {
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
    pub trusted_keys_path: PathBuf,
    pub require_root_owned_trust_file: bool,
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
            trusted_keys_path: self.trusted_keys_path,
            require_root_owned_trust_file: self.require_root_owned_trust_file,
        })
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let state_svc = StateServiceServer::new(StateSvc { probe: self.probe })
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);

        Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(Duration::from_secs(30)))
            .concurrency_limit_per_connection(32)
            .layer(tower::util::MapResponseLayer::new(tag_unimplemented))
            .add_service(info_svc)
            .add_service(state_svc)
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
    let listener = socket::bind(&cfg.socket_path, gid)?;
    let server_id = trusted_keys::read_summary(&cfg.trusted_keys_path, true)
        .ok()
        .flatten()
        .map(|s| s.server_id)
        .unwrap_or_default();
    info!(socket = %cfg.socket_path.display(), "serving agent protocol v2");
    LocalServer {
        probe: Arc::new(facts::SystemProbe { server_id }),
        identity: AgentIdentity::current(mode),
        trusted_keys_path: cfg.trusted_keys_path,
        require_root_owned_trust_file: true,
    }
    .serve(listener, shutdown)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::agent::v2::{
        change_service_client::ChangeServiceClient, info_service_client::InfoServiceClient,
        state_service_client::StateServiceClient, GetStateHeadRequest, PageRequest, Scope,
    };
    use hyper_util::rt::TokioIo;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};
    use tonic::transport::{Channel, Endpoint};

    struct FakeProbe;

    #[tonic::async_trait]
    impl HostProbe for FakeProbe {
        async fn server_facts(&self) -> ServerFacts {
            ServerFacts {
                hostname: "fake-host".to_string(),
                arch: "arm64".to_string(),
                memory_total_bytes: 42,
                ..Default::default()
            }
        }

        async fn containers(&self, include_stopped: bool) -> Result<Vec<Container>, Status> {
            let mut all = vec![
                container("c3", "web-3", "p1", "s1", "running"),
                container("c1", "web-1", "p1", "s1", "running"),
                container("c2", "web-2", "p1", "s1", "running"),
                container("c4", "db-1", "p2", "s2", "running"),
            ];
            if include_stopped {
                all.push(container("c5", "old-1", "p1", "s1", "exited"));
            }
            Ok(all)
        }

        fn ssh_host_key_digests_hex(&self) -> Vec<String> {
            vec!["ab".repeat(32)]
        }

        fn ntp_synchronized(&self) -> bool {
            true
        }

        fn timezone(&self) -> String {
            "Etc/UTC".to_string()
        }
    }

    fn container(id: &str, name: &str, project: &str, service: &str, state: &str) -> Container {
        Container {
            container_id: id.to_string(),
            name: name.to_string(),
            project_id: project.to_string(),
            service_id: service.to_string(),
            environment: "production".to_string(),
            state: state.to_string(),
            ..Default::default()
        }
    }

    struct Harness {
        dir: PathBuf,
        channel: Channel,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Harness {
        async fn start(name: &str, trusted_keys: Option<&str>) -> Self {
            let dir = PathBuf::from("/tmp").join(format!(
                "pa-v2-{name}-{}-{}",
                std::process::id(),
                crate::timeutil::now_unix_nanos() % 1_000_000_000
            ));
            fs::create_dir_all(&dir).unwrap();
            let trusted_keys_path = dir.join("trusted-keys.json");
            if let Some(raw) = trusted_keys {
                fs::write(&trusted_keys_path, raw).unwrap();
                fs::set_permissions(&trusted_keys_path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            let socket_path = dir.join("run").join("agent.sock");
            let listener = socket::bind(&socket_path, None).unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let server = LocalServer {
                probe: Arc::new(FakeProbe),
                identity: AgentIdentity {
                    version: "test-1".to_string(),
                    binary_digest_hex: "cd".repeat(32),
                    mode: AgentMode::Local,
                    started_at: SystemTime::now(),
                },
                trusted_keys_path,
                require_root_owned_trust_file: false,
            };
            let task = tokio::spawn(async move {
                server
                    .serve(listener, async {
                        let _ = rx.await;
                    })
                    .await
                    .unwrap();
            });
            let channel = connect(&socket_path).await;
            Self {
                dir,
                channel,
                shutdown: Some(tx),
                task,
            }
        }

        async fn stop(mut self) {
            drop(self.channel);
            let _ = self.shutdown.take().unwrap().send(());
            self.task.await.unwrap();
            fs::remove_dir_all(&self.dir).unwrap();
        }
    }

    async fn connect(path: &Path) -> Channel {
        let path = path.to_path_buf();
        Endpoint::try_from("http://[::]:50051")
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = path.clone();
                async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
            }))
            .await
            .unwrap()
    }

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

    #[tokio::test]
    async fn hello_round_trip_over_unix_socket() {
        let trust = r#"{"version":1,"server_id":"01a0cdb5-3500-70a1-8000-000000000001","keys":[{"key_id":"k1"}],"revocations":[]}"#;
        let h = Harness::start("hello", Some(trust)).await;
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
        let trusted = hello.trusted_keys.unwrap();
        assert_eq!(trusted.key_count, 1);
        assert_eq!(trusted.generation, 1);
        assert_eq!(trusted.fingerprint_digest_hex.len(), 64);
        let clock = hello.clock.unwrap();
        assert!(clock.agent_time.is_some());
        assert!(clock.ntp_synchronized);
        assert!(clock.estimated_skew.is_some());
        assert_eq!(clock.timezone, "Etc/UTC");
        assert_eq!(hello.session_id.len(), 32);
        assert!(hello.capabilities.is_empty());

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
    async fn hello_without_trusted_keys_reports_none() {
        let h = Harness::start("notrust", None).await;
        let mut client = InfoServiceClient::new(h.channel.clone());
        let hello = client
            .hello(hello_request(&["2.0"]))
            .await
            .unwrap()
            .into_inner();
        assert!(hello.trusted_keys.is_none());
        assert_eq!(hello.agent.unwrap().server_id, "");
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

        let mut change = ChangeServiceClient::new(h.channel.clone());
        let status = change
            .get_state_head(GetStateHeadRequest::default())
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
