mod agent_crypto;
mod app_lifecycle;
mod backup_lifecycle;
mod command;
mod command_handlers;
mod command_runtime;
mod compose_lifecycle;
mod config;
mod container_logs;
mod control_plane_identity;
mod docker_observe;
mod docksmith;
mod dwaar_admin;
mod dwaar_analytics;
mod dwaar_routes;
mod heartbeat;
mod host_admin;
mod job_deployment;
mod log_forwarder;
mod monitoring;
mod probe;
mod proto;
mod route_metrics;
mod self_update;
mod service_lifecycle;
mod spool;
mod sre_tools;
mod system;
mod systemd;
mod timeutil;

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{config::Config, proto::agent::v1::agent_service_client::AgentServiceClient};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    if let Some(duration) = probe::probe_duration_from_env() {
        return probe::run(duration).await;
    }

    let cfg = Arc::new(Config::from_env()?);
    info!(
        backend = %cfg.backend_grpc_addr,
        server_id = %cfg.server_id,
        version = %cfg.version,
        insecure = cfg.insecure,
        "starting permanu-agent-rs"
    );

    let agent_keypair = Arc::new(agent_crypto::AgentKeypair::load_or_generate_default()?);
    let channel = cfg.connect_channel().await?;
    let client = AgentServiceClient::new(channel)
        .max_decoding_message_size(cfg.max_message_size)
        .max_encoding_message_size(cfg.max_message_size);

    let log_forwarder = Arc::new(log_forwarder::LogForwarder::open(&cfg)?);
    let mut fields = HashMap::new();
    fields.insert("runtime".to_string(), "rust".to_string());
    fields.insert("version".to_string(), cfg.version.clone());
    if let Err(err) = log_forwarder.push(log_forwarder::agent_log(
        "info",
        "permanu-agent-rs starting",
        fields,
    )) {
        error!(error = ?err, "failed to enqueue startup log");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let monitoring_state = Arc::new(monitoring::MonitoringState::default());
    let route_aggregator = Arc::new(route_metrics::RouteAggregator::default());
    let analytics_collector = Arc::new(dwaar_analytics::DwaarAnalyticsCollector::new(
        dwaar_analytics::DwaarAnalyticsConfig::default(),
    ));
    let heartbeat_task = tokio::spawn(heartbeat::run(
        cfg.clone(),
        client.clone(),
        agent_keypair.clone(),
        log_forwarder.clone(),
        monitoring_state.clone(),
        route_aggregator.clone(),
        analytics_collector.clone(),
        shutdown_rx.clone(),
    ));
    let log_task = tokio::spawn(log_forwarder::run(
        cfg.clone(),
        log_forwarder.clone(),
        client.clone(),
        shutdown_rx.clone(),
    ));
    let container_logs_task = tokio::spawn(container_logs::run(
        log_forwarder.clone(),
        shutdown_rx.clone(),
    ));
    systemd::notify_ready();
    let watchdog_task = systemd::spawn_watchdog(shutdown_rx.clone());
    let monitoring_task = tokio::spawn(monitoring::run(
        monitoring_state.clone(),
        shutdown_rx.clone(),
    ));
    let route_metrics_task = tokio::spawn(route_metrics::run_access_log_tailer(
        route_aggregator.clone(),
        analytics_collector.clone(),
        shutdown_rx.clone(),
    ));
    let command_task = tokio::spawn(command::run(
        cfg.clone(),
        client.clone(),
        agent_keypair.clone(),
        monitoring_state.clone(),
        route_aggregator.clone(),
    ));

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            if let Err(err) = signal {
                error!(error = ?err, "failed waiting for shutdown signal");
            }
            info!("shutdown signal received");
        }
        result = command_task => {
            match result {
                Ok(Ok(())) => info!("command stream closed"),
                Ok(Err(err)) => error!(error = ?err, "command stream failed"),
                Err(err) => error!(error = ?err, "command task panicked"),
            }
        }
    }

    let _ = shutdown_tx.send(true);
    heartbeat_task.abort();
    log_task.abort();
    container_logs_task.abort();
    if let Some(task) = watchdog_task {
        task.abort();
    }
    monitoring_task.abort();
    route_metrics_task.abort();
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("permanu_agent_rs=info,info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
