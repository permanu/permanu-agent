use std::{collections::HashMap, fs, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::watch;
use tracing::warn;

use crate::{
    config::Config,
    container_logs, docker_observe, dwaar_analytics,
    log_forwarder::{agent_log, LogForwarder},
    monitoring, route_metrics, system,
};

#[derive(Debug, Serialize)]
struct ProbeReport {
    duration_seconds: u64,
    samples: usize,
    max_rss_kb: i64,
    max_pss_kb: i64,
    max_private_dirty_kb: i64,
    docker_reachable: bool,
    docker_version: String,
    max_observable_containers: usize,
    max_collected_container_metrics: usize,
    log_spool_bytes: u64,
    log_spool_records: u64,
    log_spool_segments: u64,
    log_spool_dropped_records: u64,
    log_spool_dropped_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct MemorySample {
    rss_kb: i64,
    pss_kb: i64,
    private_dirty_kb: i64,
}

pub fn probe_duration_from_env() -> Option<Duration> {
    std::env::var("PERMANU_AGENT_PROBE_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

pub async fn run(duration: Duration) -> Result<()> {
    let cfg = Config::probe_from_env();
    let forwarder = Arc::new(LogForwarder::open(&cfg)?);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let tail_task = tokio::spawn(container_logs::run(forwarder.clone(), shutdown_rx.clone()));
    let monitoring_state = Arc::new(monitoring::MonitoringState::default());
    let monitoring_task = tokio::spawn(monitoring::run(monitoring_state, shutdown_rx.clone()));
    let route_aggregator = Arc::new(route_metrics::RouteAggregator::default());
    let analytics_collector = Arc::new(dwaar_analytics::DwaarAnalyticsCollector::new(
        dwaar_analytics::DwaarAnalyticsConfig::default(),
    ));
    let route_task = tokio::spawn(route_metrics::run_access_log_tailer(
        route_aggregator,
        analytics_collector,
        shutdown_rx,
    ));

    let docker = docker_observe::docker_client().ok();
    let started = tokio::time::Instant::now();
    let mut samples = Vec::new();
    let mut docker_reachable = false;
    let mut docker_version = String::new();
    let mut max_observable_containers = 0_usize;
    let mut max_collected_container_metrics = 0_usize;

    while started.elapsed() < duration {
        samples.push(memory_sample());
        let _ = system::collect_system_metrics();

        let mut fields = HashMap::new();
        fields.insert("mode".to_string(), "probe".to_string());
        fields.insert(
            "elapsed_seconds".to_string(),
            started.elapsed().as_secs().to_string(),
        );
        forwarder
            .push(agent_log("info", "permanu-agent-rs probe tick", fields))
            .context("enqueue probe log")?;

        if let Some(docker) = &docker {
            let reachability = docker_observe::inspect_docker(docker).await;
            docker_reachable |= reachability.reachable;
            if docker_version.is_empty() {
                docker_version = reachability.version.unwrap_or_default();
            }

            let filter = docker_observe::NameFilter::default();
            match docker_observe::list_observable_containers(docker, &filter).await {
                Ok(containers) => {
                    max_observable_containers = max_observable_containers.max(containers.len());
                    match docker_observe::collect_container_metrics(docker, &containers).await {
                        Ok(metrics) => {
                            max_collected_container_metrics =
                                max_collected_container_metrics.max(metrics.len());
                        }
                        Err(err) => warn!(error = ?err, "probe container metrics failed"),
                    }
                }
                Err(err) => warn!(error = ?err, "probe container list failed"),
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    samples.push(memory_sample());
    let counters = forwarder.counters();
    let report = ProbeReport {
        duration_seconds: duration.as_secs(),
        samples: samples.len(),
        max_rss_kb: samples.iter().map(|s| s.rss_kb).max().unwrap_or_default(),
        max_pss_kb: samples.iter().map(|s| s.pss_kb).max().unwrap_or_default(),
        max_private_dirty_kb: samples
            .iter()
            .map(|s| s.private_dirty_kb)
            .max()
            .unwrap_or_default(),
        docker_reachable,
        docker_version,
        max_observable_containers,
        max_collected_container_metrics,
        log_spool_bytes: counters.bytes,
        log_spool_records: counters.records,
        log_spool_segments: counters.segments,
        log_spool_dropped_records: counters.dropped_records,
        log_spool_dropped_bytes: counters.dropped_bytes,
    };

    let _ = shutdown_tx.send(true);
    tail_task.abort();
    monitoring_task.abort();
    route_task.abort();
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn memory_sample() -> MemorySample {
    let mut sample = MemorySample::default();
    if let Ok(raw) = fs::read_to_string("/proc/self/status") {
        for line in raw.lines() {
            if let Some(value) = parse_status_kb(line, "VmRSS:") {
                sample.rss_kb = value;
            }
        }
    }
    if let Ok(raw) = fs::read_to_string("/proc/self/smaps_rollup") {
        for line in raw.lines() {
            if let Some(value) = parse_status_kb(line, "Pss:") {
                sample.pss_kb = value;
            }
            if let Some(value) = parse_status_kb(line, "Private_Dirty:") {
                sample.private_dirty_kb = value;
            }
        }
    }
    sample
}

fn parse_status_kb(line: &str, key: &str) -> Option<i64> {
    line.strip_prefix(key)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}
