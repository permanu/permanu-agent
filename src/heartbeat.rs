use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::watch;
use tonic::transport::Channel;
use tracing::{debug, warn};

use crate::{
    agent_crypto::AgentKeypair,
    config::Config,
    container_logs::ContainerIdentityMappings,
    docker_observe,
    dwaar_analytics::DwaarAnalyticsCollector,
    log_forwarder::LogForwarder,
    monitoring::MonitoringState,
    proto::agent::v1::{
        agent_service_client::AgentServiceClient, ContainerMetrics, HeartbeatRequest, ServiceMetric,
    },
    route_metrics::RouteAggregator,
    system,
    timeutil::now_timestamp,
};

const DOCKER_REACHABILITY_TIMEOUT_SECONDS: u64 = 5;
const DOCKER_LIST_TIMEOUT_SECONDS: u64 = 8;
const DOCKER_STATS_TIMEOUT_SECONDS: u64 = 15;
const NODE_VERSION_TIMEOUT_SECONDS: u64 = 2;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    cfg: Arc<Config>,
    client: AgentServiceClient<Channel>,
    agent_keypair: Arc<AgentKeypair>,
    log_forwarder: Arc<LogForwarder>,
    monitoring: Arc<MonitoringState>,
    route_aggregator: Arc<RouteAggregator>,
    analytics_collector: Arc<DwaarAnalyticsCollector>,
    container_identity_mappings: ContainerIdentityMappings,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = cfg.heartbeat_interval;

    loop {
        match send_once(
            cfg.clone(),
            client.clone(),
            agent_keypair.clone(),
            log_forwarder.clone(),
            monitoring.clone(),
            route_aggregator.clone(),
            analytics_collector.clone(),
            container_identity_mappings.clone(),
        )
        .await
        {
            Ok(Some(next_interval)) => interval = next_interval,
            Ok(None) => {}
            Err(err) => warn!(error = ?err, "heartbeat failed"),
        }

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(interval) => {}
        }
        interval = interval.max(Duration::from_secs(5));
    }
}

async fn send_once(
    cfg: Arc<Config>,
    mut client: AgentServiceClient<Channel>,
    agent_keypair: Arc<AgentKeypair>,
    log_forwarder: Arc<LogForwarder>,
    monitoring: Arc<MonitoringState>,
    route_aggregator: Arc<RouteAggregator>,
    analytics_collector: Arc<DwaarAnalyticsCollector>,
    container_identity_mappings: ContainerIdentityMappings,
) -> Result<Option<Duration>> {
    let docker = docker_snapshot().await;
    let mut system_metrics = system::collect_system_metrics();
    system_metrics.docker_version = docker.version;
    let analytics_drain = analytics_collector.collect_and_reset();
    if analytics_drain.diagnostics.malformed_lines > 0
        || analytics_drain.diagnostics.dropped_domains > 0
    {
        warn!(
            malformed_lines = analytics_drain.diagnostics.malformed_lines,
            dropped_domains = analytics_drain.diagnostics.dropped_domains,
            "Dwaar analytics interval diagnostics"
        );
    }

    let mut service_metrics = vec![agent_self_metric(&cfg, &log_forwarder)];
    service_metrics.extend(system::collect_host_mount_metrics());

    let request = HeartbeatRequest {
        agent_version: cfg.version.clone(),
        timestamp: Some(now_timestamp()),
        system: Some(system_metrics),
        containers: docker.containers,
        route_metrics: route_aggregator.collect_and_reset_proto(),
        proxy_metrics: None,
        analytics: analytics_drain
            .snapshots
            .into_iter()
            .map(Into::into)
            .collect(),
        service_metrics,
        slow_queries: Vec::new(),
        health_check_results: monitoring.drain_health_check_results(),
        disk_server_id: cfg.server_id.clone(),
        rebootstrap_key_present: false,
        agent_version_disk: cfg.version.clone(),
        last_rebootstrap_error: String::new(),
        docker_reachable: docker.reachable,
        agent_x25519_pubkey: agent_keypair.public_key().to_vec(),
        agent_checksum: if cfg.report_agent_checksum {
            self_checksum().unwrap_or_default()
        } else {
            String::new()
        },
        agent_quarantined: false,
        quarantine_reason: String::new(),
        buildx_status: String::new(),
        node_version: node_version().await.unwrap_or_default(),
    };

    let request = cfg.attach_auth(tonic::Request::new(request))?;
    let response = client.heartbeat(request).await.context("heartbeat rpc")?;
    let response = response.into_inner();
    container_identity_mappings.update_from_heartbeat(response.app_containers);
    debug!(
        accepted = response.accepted,
        update_available = response.update_available,
        latest_version = %response.latest_version,
        "heartbeat accepted"
    );
    if let Some(config) = response.monitoring_config {
        monitoring.apply_proto_config(config);
    }
    let next_interval = (response.heartbeat_interval_seconds > 0)
        .then(|| Duration::from_secs(response.heartbeat_interval_seconds as u64));
    Ok(next_interval)
}

fn agent_self_metric(cfg: &Config, log_forwarder: &LogForwarder) -> ServiceMetric {
    let mut metric = system::collect_agent_self_metric(&cfg.version);
    let counters = log_forwarder.counters();
    metric
        .gauges
        .insert("agent_log_spool_bytes".to_string(), counters.bytes as f64);
    metric.gauges.insert(
        "agent_log_spool_records".to_string(),
        counters.records as f64,
    );
    metric.gauges.insert(
        "agent_log_spool_segments".to_string(),
        counters.segments as f64,
    );
    metric.gauges.insert(
        "agent_log_spool_dropped_records".to_string(),
        counters.dropped_records as f64,
    );
    metric.gauges.insert(
        "agent_log_spool_dropped_bytes".to_string(),
        counters.dropped_bytes as f64,
    );
    metric
}

struct DockerSnapshot {
    reachable: bool,
    version: String,
    containers: Vec<ContainerMetrics>,
}

async fn docker_snapshot() -> DockerSnapshot {
    let Ok(docker) = docker_observe::docker_client() else {
        return DockerSnapshot {
            reachable: false,
            version: String::new(),
            containers: Vec::new(),
        };
    };

    let reachability = match tokio::time::timeout(
        Duration::from_secs(DOCKER_REACHABILITY_TIMEOUT_SECONDS),
        docker_observe::inspect_docker(&docker),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            warn!("docker reachability check timed out");
            return DockerSnapshot {
                reachable: false,
                version: String::new(),
                containers: Vec::new(),
            };
        }
    };
    if !reachability.reachable {
        return DockerSnapshot {
            reachable: false,
            version: String::new(),
            containers: Vec::new(),
        };
    }

    let filter = docker_observe::NameFilter::default();
    let containers = match tokio::time::timeout(
        Duration::from_secs(DOCKER_LIST_TIMEOUT_SECONDS),
        docker_observe::list_observable_containers(&docker, &filter),
    )
    .await
    {
        Ok(Ok(containers)) => containers,
        Ok(Err(err)) => {
            warn!(error = ?err, "list docker containers failed");
            Vec::new()
        }
        Err(_) => {
            warn!("list docker containers timed out");
            Vec::new()
        }
    };
    let metrics = match tokio::time::timeout(
        Duration::from_secs(DOCKER_STATS_TIMEOUT_SECONDS),
        docker_observe::collect_container_metrics(&docker, &containers),
    )
    .await
    {
        Ok(Ok(metrics)) => metrics,
        Ok(Err(err)) => {
            warn!(error = ?err, "collect docker container metrics failed");
            Vec::new()
        }
        Err(_) => {
            warn!("collect docker container metrics timed out");
            Vec::new()
        }
    };

    DockerSnapshot {
        reachable: true,
        version: reachability.version.unwrap_or_default(),
        containers: metrics.into_iter().map(Into::into).collect(),
    }
}

impl From<docker_observe::ContainerMetrics> for ContainerMetrics {
    fn from(value: docker_observe::ContainerMetrics) -> Self {
        Self {
            container_id: value.container_id,
            name: value.name,
            image: value.image,
            status: value.status,
            cpu_percent: value.cpu_percent,
            memory_used_mb: value.memory_used_mb,
            memory_limit_mb: value.memory_limit_mb,
            network_rx_bytes: value.network_rx_bytes,
            network_tx_bytes: value.network_tx_bytes,
            health_status: value.health_status,
            restart_count: value.restart_count,
            oom_killed: value.oom_killed,
            exit_code: value.exit_code,
            exit_reason: value.exit_reason,
            started_at: value.started_at,
            finished_at: value.finished_at,
            compose_project: value.compose_project,
        }
    }
}

fn self_checksum() -> Result<String> {
    use sha2::{Digest, Sha256};
    let exe = std::env::current_exe().context("current exe")?;
    let bytes = std::fs::read(exe).context("read current exe")?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

async fn node_version() -> Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(NODE_VERSION_TIMEOUT_SECONDS),
        tokio::process::Command::new("node")
            .arg("--version")
            .output(),
    )
    .await
    .context("node --version timed out")?
    .context("run node --version")?;
    if !output.status.success() {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
