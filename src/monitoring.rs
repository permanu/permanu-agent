use std::{
    collections::{HashMap, VecDeque},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tokio::{net::TcpStream, process::Command, sync::watch, time::timeout};

use crate::{
    proto::agent::v1::{HealthCheckConfig, HealthCheckResult, MonitoringConfig},
    timeutil::now_unix_nanos,
};

const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const SCHEDULER_TICK: Duration = Duration::from_secs(1);
const MAX_HEALTH_CHECKS: usize = 256;
const MAX_BUFFERED_RESULTS: usize = 4096;

#[derive(Default)]
pub struct MonitoringState {
    inner: Mutex<MonitoringInner>,
}

#[derive(Default)]
struct MonitoringInner {
    config_version: i64,
    health_checks: HashMap<String, CheckState>,
    results: VecDeque<HealthCheckResult>,
    statsd_enabled: bool,
    statsd_port: i32,
}

#[derive(Clone)]
struct CheckState {
    config: HealthCheckConfig,
    last_run: Option<Instant>,
    in_flight: bool,
}

#[derive(Debug, Serialize)]
pub struct MonitoringApplySummary {
    pub config_version: i64,
    pub health_checks: usize,
    pub statsd_enabled: bool,
    pub statsd_port: i32,
}

impl MonitoringState {
    pub fn apply_json_config(&self, payload: &[u8]) -> Result<MonitoringApplySummary> {
        let config: JsonMonitoringConfig = serde_json::from_slice(payload)?;
        Ok(self.apply_proto_config(config.into_proto()))
    }

    pub fn apply_proto_config(&self, config: MonitoringConfig) -> MonitoringApplySummary {
        let mut next_checks = HashMap::new();
        for check in config.health_checks.into_iter().take(MAX_HEALTH_CHECKS) {
            if health_check_supported(&check) && validate_check_target(&check).is_ok() {
                next_checks.insert(
                    check_key(&check),
                    CheckState {
                        config: check,
                        last_run: None,
                        in_flight: false,
                    },
                );
            }
        }

        let mut inner = self.inner.lock().expect("monitoring state poisoned");
        let config_version = config.config_version;
        let statsd_enabled = config.statsd_enabled;
        let statsd_port = config.statsd_port;
        inner.config_version = config_version;
        inner.health_checks = next_checks;
        inner.statsd_enabled = statsd_enabled;
        inner.statsd_port = statsd_port;
        MonitoringApplySummary {
            config_version,
            health_checks: inner.health_checks.len(),
            statsd_enabled,
            statsd_port,
        }
    }

    pub fn drain_health_check_results(&self) -> Vec<HealthCheckResult> {
        let mut inner = self.inner.lock().expect("monitoring state poisoned");
        inner.results.drain(..).collect()
    }

    fn take_due_checks(&self, now: Instant) -> Vec<HealthCheckConfig> {
        let mut inner = self.inner.lock().expect("monitoring state poisoned");
        let mut due = Vec::new();
        for state in inner.health_checks.values_mut() {
            if state.in_flight {
                continue;
            }
            let interval = check_interval(&state.config);
            let should_run = state
                .last_run
                .is_none_or(|last_run| now.duration_since(last_run) >= interval);
            if should_run {
                state.last_run = Some(now);
                state.in_flight = true;
                due.push(state.config.clone());
            }
        }
        due
    }

    fn complete_check(&self, result: HealthCheckResult) {
        let mut inner = self.inner.lock().expect("monitoring state poisoned");
        for state in inner.health_checks.values_mut() {
            if state.config.id == result.check_id {
                state.in_flight = false;
                break;
            }
        }
        if inner.results.len() >= MAX_BUFFERED_RESULTS {
            inner.results.pop_front();
        }
        inner.results.push_back(result);
    }
}

pub async fn run(state: Arc<MonitoringState>, mut shutdown: watch::Receiver<bool>) {
    loop {
        for check in state.take_due_checks(Instant::now()) {
            let state = state.clone();
            tokio::spawn(async move {
                let result = run_health_check(&check).await;
                state.complete_check(result);
            });
        }

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(SCHEDULER_TICK) => {}
        }
    }
}

async fn run_health_check(check: &HealthCheckConfig) -> HealthCheckResult {
    match check.r#type.as_str() {
        "http" => run_http_check(check).await,
        "tcp" => run_tcp_check(check).await,
        "process" => run_process_check(check).await,
        _ => unhealthy_result(check, 0, 0, "unsupported health check type"),
    }
}

async fn run_http_check(check: &HealthCheckConfig) -> HealthCheckResult {
    let start = Instant::now();
    if let Err(err) = validate_check_target(check) {
        return unhealthy_result(
            check,
            start.elapsed().as_millis() as i64,
            0,
            &err.to_string(),
        );
    }

    let timeout_duration = check_timeout(check);
    let max_time = format!("{:.3}", timeout_duration.as_secs_f64());
    let output = timeout(
        timeout_duration + Duration::from_secs(1),
        Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--location",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--max-time",
                &max_time,
                &check.target,
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await;

    let latency_ms = start.elapsed().as_millis() as i64;
    let output = match output {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => return unhealthy_result(check, latency_ms, 0, &err.to_string()),
        Err(_) => return unhealthy_result(check, latency_ms, 0, "request timed out"),
    };
    let status_code = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or_default();
    let expected = if check.expected_status > 0 {
        check.expected_status
    } else {
        200
    };
    if output.status.success() && status_code == expected {
        healthy_result(check, latency_ms, status_code)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = if status_code != expected && status_code > 0 {
            format!("expected {expected}, got {status_code}")
        } else if stderr.trim().is_empty() {
            "request failed".to_string()
        } else {
            stderr.trim().to_string()
        };
        unhealthy_result(check, latency_ms, status_code, &message)
    }
}

async fn run_tcp_check(check: &HealthCheckConfig) -> HealthCheckResult {
    let start = Instant::now();
    if let Err(err) = validate_check_target(check) {
        return unhealthy_result(
            check,
            start.elapsed().as_millis() as i64,
            0,
            &err.to_string(),
        );
    }
    match timeout(check_timeout(check), TcpStream::connect(&check.target)).await {
        Ok(Ok(_stream)) => healthy_result(check, start.elapsed().as_millis() as i64, 0),
        Ok(Err(err)) => unhealthy_result(
            check,
            start.elapsed().as_millis() as i64,
            0,
            &format!("connection failed: {err}"),
        ),
        Err(_) => unhealthy_result(check, start.elapsed().as_millis() as i64, 0, "timed out"),
    }
}

async fn run_process_check(check: &HealthCheckConfig) -> HealthCheckResult {
    let start = Instant::now();
    if let Err(err) = validate_check_target(check) {
        return unhealthy_result(
            check,
            start.elapsed().as_millis() as i64,
            0,
            &err.to_string(),
        );
    }
    let found = tokio::task::spawn_blocking({
        let process_name = check.target.clone();
        move || process_exists(&process_name)
    })
    .await
    .unwrap_or(false);

    let latency_ms = start.elapsed().as_millis() as i64;
    if found {
        healthy_result(check, latency_ms, 0)
    } else {
        unhealthy_result(
            check,
            latency_ms,
            0,
            &format!("process {:?} not found", check.target),
        )
    }
}

fn process_exists(process_name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str() else {
            continue;
        };
        if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let Ok(cmdline) = std::fs::read(cmdline_path) else {
            continue;
        };
        let command = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        if command.contains(process_name) {
            return true;
        }
    }
    false
}

fn healthy_result(
    check: &HealthCheckConfig,
    latency_ms: i64,
    status_code: i32,
) -> HealthCheckResult {
    result(check, "healthy", latency_ms, status_code, "")
}

fn unhealthy_result(
    check: &HealthCheckConfig,
    latency_ms: i64,
    status_code: i32,
    error_message: &str,
) -> HealthCheckResult {
    result(check, "unhealthy", latency_ms, status_code, error_message)
}

fn result(
    check: &HealthCheckConfig,
    status: &str,
    latency_ms: i64,
    status_code: i32,
    error_message: &str,
) -> HealthCheckResult {
    HealthCheckResult {
        check_id: check.id.clone(),
        status: status.to_string(),
        latency_ms,
        status_code,
        error_message: error_message.to_string(),
        app_id: check.app_id.clone(),
        deploy_id: check.deploy_id.clone(),
        timestamp_ns: now_unix_nanos(),
        deploy_timestamp: check.deploy_timestamp.clone(),
        commit_sha: check.commit_sha.clone(),
        prev_deploy_id: check.prev_deploy_id.clone(),
    }
}

fn check_key(check: &HealthCheckConfig) -> String {
    format!("check:{}:{}", check.r#type, check.id)
}

fn check_interval(check: &HealthCheckConfig) -> Duration {
    if check.interval_seconds > 0 {
        Duration::from_secs(check.interval_seconds as u64)
    } else {
        DEFAULT_CHECK_INTERVAL
    }
}

fn check_timeout(check: &HealthCheckConfig) -> Duration {
    if check.timeout_ms > 0 {
        Duration::from_millis(check.timeout_ms as u64)
    } else {
        DEFAULT_CHECK_TIMEOUT
    }
}

fn health_check_supported(check: &HealthCheckConfig) -> bool {
    matches!(check.r#type.as_str(), "http" | "tcp" | "process")
}

fn validate_check_target(check: &HealthCheckConfig) -> Result<()> {
    validate_identifier(&check.id, "id")?;
    validate_no_control(&check.target, "target")?;
    match check.r#type.as_str() {
        "http" => {
            if !(check.target.starts_with("http://") || check.target.starts_with("https://")) {
                anyhow::bail!("http health check target must start with http:// or https://");
            }
        }
        "tcp" => {
            if check.target.trim().is_empty() || !check.target.contains(':') {
                anyhow::bail!("tcp health check target must be host:port");
            }
        }
        "process" => {
            if check.target.trim().is_empty() {
                anyhow::bail!("process health check target is required");
            }
        }
        _ => anyhow::bail!("unsupported health check type {}", check.r#type),
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} is required");
    }
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}

fn validate_no_control(value: &str, label: &str) -> Result<()> {
    if value
        .chars()
        .any(|ch| ch == '\0' || ch == '\r' || ch == '\n')
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}

#[derive(Deserialize)]
struct JsonMonitoringConfig {
    #[serde(default)]
    config_version: i64,
    #[serde(default)]
    system_interval_seconds: i32,
    #[serde(default)]
    container_interval_seconds: i32,
    #[serde(default)]
    service_interval_seconds: i32,
    #[serde(default)]
    slow_query_interval_seconds: i32,
    #[serde(default)]
    health_checks: Vec<JsonHealthCheckConfig>,
    #[serde(default)]
    statsd_enabled: bool,
    #[serde(default)]
    statsd_port: i32,
}

impl JsonMonitoringConfig {
    fn into_proto(self) -> MonitoringConfig {
        MonitoringConfig {
            config_version: self.config_version,
            system_interval_seconds: self.system_interval_seconds,
            container_interval_seconds: self.container_interval_seconds,
            service_interval_seconds: self.service_interval_seconds,
            slow_query_interval_seconds: self.slow_query_interval_seconds,
            health_checks: self
                .health_checks
                .into_iter()
                .map(JsonHealthCheckConfig::into_proto)
                .collect(),
            statsd_enabled: self.statsd_enabled,
            statsd_port: self.statsd_port,
        }
    }
}

#[derive(Deserialize)]
struct JsonHealthCheckConfig {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    interval_seconds: i32,
    #[serde(default)]
    timeout_ms: i32,
    #[serde(default)]
    expected_status: i32,
    #[serde(default)]
    app_id: String,
    #[serde(default)]
    deploy_id: String,
    #[serde(default)]
    deploy_timestamp: String,
    #[serde(default)]
    commit_sha: String,
    #[serde(default)]
    prev_deploy_id: String,
}

impl JsonHealthCheckConfig {
    fn into_proto(self) -> HealthCheckConfig {
        HealthCheckConfig {
            id: self.id,
            name: self.name,
            r#type: self.kind,
            target: self.target,
            interval_seconds: self.interval_seconds,
            timeout_ms: self.timeout_ms,
            expected_status: self.expected_status,
            app_id: self.app_id,
            deploy_id: self.deploy_id,
            deploy_timestamp: self.deploy_timestamp,
            commit_sha: self.commit_sha,
            prev_deploy_id: self.prev_deploy_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn json_config_applies_health_checks_and_statsd() {
        let state = MonitoringState::default();
        let summary = state
            .apply_json_config(
                br#"{
                    "config_version": 7,
                    "statsd_enabled": true,
                    "statsd_port": 8125,
                    "health_checks": [
                        {
                            "id": "tcp-1",
                            "name": "API TCP",
                            "type": "tcp",
                            "target": "127.0.0.1:443",
                            "interval_seconds": 15,
                            "timeout_ms": 500,
                            "app_id": "app-1",
                            "deploy_id": "dep-1"
                        }
                    ]
                }"#,
            )
            .expect("apply config");

        assert_eq!(summary.config_version, 7);
        assert_eq!(summary.health_checks, 1);
        assert!(summary.statsd_enabled);
        assert_eq!(summary.statsd_port, 8125);
    }

    #[test]
    fn drain_health_check_results_empties_buffer() {
        let state = MonitoringState::default();
        state.push_test_result(HealthCheckResult {
            check_id: "check-1".to_string(),
            status: "healthy".to_string(),
            ..Default::default()
        });

        assert_eq!(state.drain_health_check_results().len(), 1);
        assert!(state.drain_health_check_results().is_empty());
    }

    #[tokio::test]
    async fn tcp_check_reports_healthy_for_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let addr = listener.local_addr().expect("local addr");
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = run_tcp_check(&HealthCheckConfig {
            id: "tcp-1".to_string(),
            name: "TCP".to_string(),
            r#type: "tcp".to_string(),
            target: addr.to_string(),
            timeout_ms: 500,
            app_id: "app-1".to_string(),
            deploy_id: "dep-1".to_string(),
            ..Default::default()
        })
        .await;

        assert_eq!(result.check_id, "tcp-1");
        assert_eq!(result.status, "healthy");
        assert_eq!(result.app_id, "app-1");
        assert_eq!(result.deploy_id, "dep-1");
        accept_task.abort();
    }

    impl MonitoringState {
        fn push_test_result(&self, result: HealthCheckResult) {
            let mut inner = self.inner.lock().expect("monitoring state poisoned");
            inner.results.push_back(result);
        }
    }
}
