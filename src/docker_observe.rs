use bollard::container::LogOutput;
use bollard::errors::Error as BollardError;
use bollard::models::{ContainerInspectResponse, ContainerStatsResponse, ContainerSummary};
use bollard::query_parameters::{
    InspectContainerOptionsBuilder, ListContainersOptionsBuilder, LogsOptionsBuilder,
    StatsOptionsBuilder,
};
use bollard::{Docker, API_DEFAULT_VERSION};
use futures_core::Stream;
use futures_util::{StreamExt, TryStreamExt};
use std::collections::HashMap;

const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const DOCKER_TIMEOUT_SECONDS: u64 = 15;
const BYTES_PER_MEBIBYTE: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameFilter {
    prefixes: Vec<String>,
}

impl NameFilter {
    pub fn new(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            prefixes: prefixes
                .into_iter()
                .map(Into::into)
                .filter(|prefix| !prefix.is_empty())
                .collect(),
        }
    }

    pub fn matches(&self, docker_name: &str) -> bool {
        let normalized = normalize_container_name(docker_name);
        !normalized.is_empty()
            && self
                .prefixes
                .iter()
                .any(|prefix| normalized.starts_with(prefix))
    }
}

impl Default for NameFilter {
    fn default() -> Self {
        Self::new(["deploy-", "dwaar-", "permanu-"])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservableContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub labels: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerReachability {
    pub reachable: bool,
    pub ping: Option<String>,
    pub version: Option<String>,
    pub api_version: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub kernel_version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Stdout,
    Stderr,
    Console,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Console => "console",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerLogLine {
    pub container_id: String,
    pub container_name: String,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContainerMetrics {
    pub container_id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub cpu_percent: f64,
    pub memory_used_mb: i64,
    pub memory_limit_mb: i64,
    pub network_rx_bytes: i64,
    pub network_tx_bytes: i64,
    pub health_status: String,
    pub restart_count: i32,
    pub oom_killed: bool,
    pub exit_code: i32,
    pub exit_reason: String,
    pub started_at: String,
    pub finished_at: String,
    pub compose_project: String,
}

pub fn docker_client() -> Result<Docker, BollardError> {
    Docker::connect_with_socket(DOCKER_SOCKET, DOCKER_TIMEOUT_SECONDS, API_DEFAULT_VERSION)
}

pub async fn inspect_docker(docker: &Docker) -> DockerReachability {
    let ping = match docker.ping().await {
        Ok(ping) => ping,
        Err(err) => {
            return DockerReachability {
                reachable: false,
                ping: None,
                version: None,
                api_version: None,
                os: None,
                arch: None,
                kernel_version: None,
                error: Some(err.to_string()),
            };
        }
    };

    match docker.version().await {
        Ok(version) => DockerReachability {
            reachable: true,
            ping: Some(ping),
            version: version.version,
            api_version: version.api_version,
            os: version.os,
            arch: version.arch,
            kernel_version: version.kernel_version,
            error: None,
        },
        Err(err) => DockerReachability {
            reachable: true,
            ping: Some(ping),
            version: None,
            api_version: None,
            os: None,
            arch: None,
            kernel_version: None,
            error: Some(err.to_string()),
        },
    }
}

pub async fn list_observable_containers(
    docker: &Docker,
    filter: &NameFilter,
) -> Result<Vec<ObservableContainer>, BollardError> {
    let options = ListContainersOptionsBuilder::default().all(true).build();

    let containers = docker.list_containers(Some(options)).await?;
    Ok(containers
        .into_iter()
        .filter_map(|container| observable_from_summary(container, filter))
        .collect())
}

pub async fn stream_container_logs(
    docker: &Docker,
    container: ObservableContainer,
    since_seconds: Option<i64>,
) -> impl Stream<Item = Result<ContainerLogLine, BollardError>> {
    let builder = LogsOptionsBuilder::default()
        .follow(true)
        .stdout(true)
        .stderr(true)
        .timestamps(false);

    let builder = if let Some(since) = since_seconds.and_then(|since| i32::try_from(since).ok()) {
        builder.since(since)
    } else {
        builder
    };

    let container_id = container.id.clone();
    let container_name = container.name.clone();

    docker
        .logs(&container.id, Some(builder.build()))
        .map_ok(move |output| parse_log_output(&container_id, &container_name, output))
}

pub async fn collect_container_metrics(
    docker: &Docker,
    containers: &[ObservableContainer],
) -> Result<Vec<ContainerMetrics>, BollardError> {
    let mut metrics = Vec::with_capacity(containers.len());

    for container in containers {
        let inspect_options = InspectContainerOptionsBuilder::default()
            .size(false)
            .build();
        let inspect = docker
            .inspect_container(&container.id, Some(inspect_options))
            .await?;

        let stats_options = StatsOptionsBuilder::default()
            .stream(false)
            .one_shot(true)
            .build();
        let stats = docker
            .stats(&container.id, Some(stats_options))
            .into_future()
            .await
            .0
            .transpose()?;

        metrics.push(metrics_from_docker(container, inspect, stats));
    }

    Ok(metrics)
}

fn observable_from_summary(
    container: ContainerSummary,
    filter: &NameFilter,
) -> Option<ObservableContainer> {
    let name = container
        .names
        .as_ref()
        .and_then(|names| names.iter().find(|name| filter.matches(name)))
        .map(|name| normalize_container_name(name))?;

    let status = status_from_summary(&container);

    Some(ObservableContainer {
        id: container.id.unwrap_or_default(),
        name,
        image: container.image.unwrap_or_default(),
        status,
        labels: container.labels.unwrap_or_default(),
    })
}

fn parse_log_output(
    container_id: &str,
    container_name: &str,
    output: LogOutput,
) -> ContainerLogLine {
    match output {
        LogOutput::StdOut { message } => {
            log_line(container_id, container_name, LogLevel::Stdout, message)
        }
        LogOutput::StdErr { message } => {
            log_line(container_id, container_name, LogLevel::Stderr, message)
        }
        LogOutput::Console { message } => {
            log_line(container_id, container_name, LogLevel::Console, message)
        }
        LogOutput::StdIn { message } => {
            log_line(container_id, container_name, LogLevel::Console, message)
        }
    }
}

fn log_line(
    container_id: &str,
    container_name: &str,
    level: LogLevel,
    message: impl AsRef<[u8]>,
) -> ContainerLogLine {
    ContainerLogLine {
        container_id: container_id.to_owned(),
        container_name: container_name.to_owned(),
        level,
        message: String::from_utf8_lossy(message.as_ref())
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    }
}

fn metrics_from_docker(
    container: &ObservableContainer,
    inspect: ContainerInspectResponse,
    stats: Option<ContainerStatsResponse>,
) -> ContainerMetrics {
    let state = inspect.state.as_ref();
    let status = state
        .and_then(|state| state.status.as_ref())
        .map(|status| format!("{status:?}").to_lowercase())
        .filter(|status| !status.is_empty())
        .unwrap_or_else(|| container.status.clone());

    ContainerMetrics {
        container_id: inspect.id.unwrap_or_else(|| container.id.clone()),
        name: inspect
            .name
            .map(|name| normalize_container_name(&name))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| container.name.clone()),
        image: inspect.image.unwrap_or_else(|| container.image.clone()),
        status,
        cpu_percent: stats.as_ref().map(cpu_percent).unwrap_or_default(),
        memory_used_mb: stats.as_ref().and_then(memory_used_mb).unwrap_or_default(),
        memory_limit_mb: stats.as_ref().and_then(memory_limit_mb).unwrap_or_default(),
        network_rx_bytes: stats.as_ref().map(network_rx_bytes).unwrap_or_default(),
        network_tx_bytes: stats.as_ref().map(network_tx_bytes).unwrap_or_default(),
        health_status: state
            .and_then(|state| state.health.as_ref())
            .and_then(|health| health.status.as_ref())
            .map(|status| format!("{status:?}").to_lowercase())
            .unwrap_or_default(),
        restart_count: inspect
            .restart_count
            .and_then(|count| i32::try_from(count).ok())
            .unwrap_or_default(),
        oom_killed: state.and_then(|state| state.oom_killed).unwrap_or_default(),
        exit_code: state
            .and_then(|state| state.exit_code)
            .and_then(|code| i32::try_from(code).ok())
            .unwrap_or_default(),
        exit_reason: state
            .and_then(|state| state.error.clone())
            .unwrap_or_default(),
        started_at: state
            .and_then(|state| state.started_at.clone())
            .unwrap_or_default(),
        finished_at: state
            .and_then(|state| state.finished_at.clone())
            .unwrap_or_default(),
        compose_project: container
            .labels
            .get("com.docker.compose.project")
            .cloned()
            .unwrap_or_default(),
    }
}

fn status_from_summary(container: &ContainerSummary) -> String {
    if let Some(state) = &container.state {
        let state = format!("{state:?}").to_lowercase();
        if !state.is_empty() {
            return state;
        }
    }

    container.status.clone().unwrap_or_default()
}

fn cpu_percent(stats: &ContainerStatsResponse) -> f64 {
    let Some(cpu_stats) = &stats.cpu_stats else {
        return 0.0;
    };
    let Some(pre_cpu_stats) = &stats.precpu_stats else {
        return 0.0;
    };
    let Some(cpu_usage) = &cpu_stats.cpu_usage else {
        return 0.0;
    };
    let Some(pre_cpu_usage) = &pre_cpu_stats.cpu_usage else {
        return 0.0;
    };

    let cpu_delta = cpu_usage
        .total_usage
        .unwrap_or_default()
        .saturating_sub(pre_cpu_usage.total_usage.unwrap_or_default());
    let system_delta = cpu_stats
        .system_cpu_usage
        .unwrap_or_default()
        .saturating_sub(pre_cpu_stats.system_cpu_usage.unwrap_or_default());

    if cpu_delta == 0 || system_delta == 0 {
        return 0.0;
    }

    let online_cpus = cpu_stats
        .online_cpus
        .map(f64::from)
        .or_else(|| {
            cpu_usage
                .percpu_usage
                .as_ref()
                .map(|usage| usage.len() as f64)
        })
        .filter(|count| *count > 0.0)
        .unwrap_or(1.0);

    (cpu_delta as f64 / system_delta as f64) * online_cpus * 100.0
}

fn memory_used_mb(stats: &ContainerStatsResponse) -> Option<i64> {
    let memory = stats.memory_stats.as_ref()?;
    let usage = memory.usage?;
    let inactive_file = memory
        .stats
        .as_ref()
        .and_then(|stats| {
            stats
                .get("inactive_file")
                .or_else(|| stats.get("total_inactive_file"))
        })
        .copied()
        .unwrap_or_default();

    bytes_to_mb_i64(usage.saturating_sub(inactive_file))
}

fn memory_limit_mb(stats: &ContainerStatsResponse) -> Option<i64> {
    bytes_to_mb_i64(stats.memory_stats.as_ref()?.limit?)
}

fn network_rx_bytes(stats: &ContainerStatsResponse) -> i64 {
    sum_network(stats, |network| network.rx_bytes)
}

fn network_tx_bytes(stats: &ContainerStatsResponse) -> i64 {
    sum_network(stats, |network| network.tx_bytes)
}

fn sum_network(
    stats: &ContainerStatsResponse,
    read_counter: impl Fn(&bollard::models::ContainerNetworkStats) -> Option<u64>,
) -> i64 {
    stats
        .networks
        .as_ref()
        .into_iter()
        .flat_map(HashMap::values)
        .filter_map(read_counter)
        .try_fold(0_i64, |total, value| {
            i64::try_from(value)
                .ok()
                .and_then(|value| total.checked_add(value))
        })
        .unwrap_or(i64::MAX)
}

fn bytes_to_mb_i64(bytes: u64) -> Option<i64> {
    i64::try_from(bytes / BYTES_PER_MEBIBYTE).ok()
}

fn normalize_container_name(name: &str) -> String {
    name.trim_start_matches('/').trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_filter_matches_normalized_permanu_container_names() {
        let filter = NameFilter::default();

        assert!(filter.matches("/deploy-web-abc123"));
        assert!(filter.matches("dwaar-proxy"));
        assert!(filter.matches("/permanu-agent"));
    }

    #[test]
    fn name_filter_rejects_unrelated_container_names() {
        let filter = NameFilter::default();

        assert!(!filter.matches("/postgres"));
        assert!(!filter.matches("redis"));
        assert!(!filter.matches(""));
    }

    #[test]
    fn name_filter_accepts_custom_prefixes() {
        let filter = NameFilter::new(["worker-", "svc_"]);

        assert!(filter.matches("/worker-indexer"));
        assert!(filter.matches("svc_api"));
        assert!(!filter.matches("deploy-api"));
    }

    #[test]
    fn normalize_container_name_removes_docker_leading_slash() {
        assert_eq!(normalize_container_name("/deploy-api"), "deploy-api");
        assert_eq!(normalize_container_name("deploy-api"), "deploy-api");
    }

    #[test]
    fn bytes_to_mb_uses_binary_mebibytes() {
        assert_eq!(bytes_to_mb_i64(0), Some(0));
        assert_eq!(bytes_to_mb_i64(1_048_576), Some(1));
        assert_eq!(bytes_to_mb_i64(1_572_864), Some(1));
    }

    #[test]
    fn cpu_percent_uses_docker_delta_formula() {
        let stats = ContainerStatsResponse {
            cpu_stats: Some(bollard::models::ContainerCpuStats {
                cpu_usage: Some(bollard::models::ContainerCpuUsage {
                    total_usage: Some(30_000),
                    ..Default::default()
                }),
                system_cpu_usage: Some(200_000),
                online_cpus: Some(2),
                ..Default::default()
            }),
            precpu_stats: Some(bollard::models::ContainerCpuStats {
                cpu_usage: Some(bollard::models::ContainerCpuUsage {
                    total_usage: Some(10_000),
                    ..Default::default()
                }),
                system_cpu_usage: Some(100_000),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(cpu_percent(&stats), 40.0);
    }

    #[test]
    fn cpu_percent_returns_zero_for_missing_baseline() {
        assert_eq!(cpu_percent(&ContainerStatsResponse::default()), 0.0);
    }

    #[test]
    fn memory_used_mb_subtracts_inactive_file_cache() {
        let stats = ContainerStatsResponse {
            memory_stats: Some(bollard::models::ContainerMemoryStats {
                usage: Some(128 * BYTES_PER_MEBIBYTE),
                stats: Some(HashMap::from([(
                    "inactive_file".to_string(),
                    32 * BYTES_PER_MEBIBYTE,
                )])),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(memory_used_mb(&stats), Some(96));
    }

    #[test]
    fn network_counters_are_summed_across_interfaces() {
        let stats = ContainerStatsResponse {
            networks: Some(HashMap::from([
                (
                    "eth0".to_string(),
                    bollard::models::ContainerNetworkStats {
                        rx_bytes: Some(10),
                        tx_bytes: Some(20),
                        ..Default::default()
                    },
                ),
                (
                    "eth1".to_string(),
                    bollard::models::ContainerNetworkStats {
                        rx_bytes: Some(30),
                        tx_bytes: Some(40),
                        ..Default::default()
                    },
                ),
            ])),
            ..Default::default()
        };

        assert_eq!(network_rx_bytes(&stats), 40);
        assert_eq!(network_tx_bytes(&stats), 60);
    }
}
