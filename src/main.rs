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

use anyhow::{anyhow, Result};
use serde_json::json;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{config::Config, proto::agent::v1::agent_service_client::AgentServiceClient};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    if let Some(action) = parse_cli_action(std::env::args().skip(1))? {
        return run_cli_action(action).await;
    }

    if let Some(duration) = probe::probe_duration_from_env() {
        return probe::run(duration).await;
    }

    let cfg = Arc::new(Config::from_env()?);
    info!(
        backend = %cfg.backend_grpc_addr,
        server_id = %cfg.server_id,
        version = %cfg.version,
        insecure = cfg.insecure,
        "starting permanu-agent"
    );

    let agent_keypair = Arc::new(agent_crypto::AgentKeypair::load_or_generate_default()?);

    // Notify systemd immediately so the service is considered started even if
    // the backend gRPC is temporarily unreachable.  The reconnect loop below
    // will establish the connection in the background; tasks that need the
    // client won't spawn until it's available.
    systemd::notify_ready();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let watchdog_task = systemd::spawn_watchdog(shutdown_rx.clone());

    let channel = connect_channel_with_retry(&cfg).await;
    let client = AgentServiceClient::new(channel)
        .max_decoding_message_size(cfg.max_message_size)
        .max_encoding_message_size(cfg.max_message_size);

    let log_forwarder = Arc::new(log_forwarder::LogForwarder::open(&cfg)?);
    let mut fields = HashMap::new();
    fields.insert("runtime".to_string(), "rust".to_string());
    fields.insert("version".to_string(), cfg.version.clone());
    if let Err(err) = log_forwarder.push(log_forwarder::agent_log(
        "info",
        "permanu-agent starting",
        fields,
    )) {
        error!(error = ?err, "failed to enqueue startup log");
    }

    let monitoring_state = Arc::new(monitoring::MonitoringState::default());
    let route_aggregator = Arc::new(route_metrics::RouteAggregator::default());
    let container_identity_mappings = container_logs::ContainerIdentityMappings::default();
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
        container_identity_mappings.clone(),
        shutdown_rx.clone(),
    ));
    let log_task = tokio::spawn(log_forwarder::run(
        cfg.clone(),
        log_forwarder.clone(),
        client.clone(),
        shutdown_rx.clone(),
    ));
    let container_logs_task = tokio::spawn(container_logs::run(
        cfg.clone(),
        log_forwarder.clone(),
        container_identity_mappings.clone(),
        shutdown_rx.clone(),
    ));
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
        agent_keypair.clone(),
        log_forwarder.clone(),
        monitoring_state.clone(),
        route_aggregator.clone(),
        shutdown_rx.clone(),
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

async fn connect_channel_with_retry(cfg: &Config) -> tonic::transport::Channel {
    let retry_delay = std::time::Duration::from_secs(5);
    loop {
        match cfg.connect_channel().await {
            Ok(channel) => return channel,
            Err(err) => {
                warn!(
                    error = ?err,
                    retry_in_seconds = retry_delay.as_secs(),
                    "backend gRPC unavailable; retrying"
                );
                tokio::time::sleep(retry_delay).await;
            }
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("permanu_agent=info,info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CliAction {
    Version,
    Doctor { json: bool },
    Help,
}

fn parse_cli_action<I>(args: I) -> Result<Option<CliAction>>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(None);
    };

    match first.as_str() {
        "--version" | "-V" | "version" => Ok(Some(CliAction::Version)),
        "doctor" => parse_doctor_action(args),
        "--help" | "-h" | "help" => Ok(Some(CliAction::Help)),
        other => Err(anyhow!("unsupported permanu-agent argument {other:?}")),
    }
}

fn parse_doctor_action<I>(args: I) -> Result<Option<CliAction>>
where
    I: IntoIterator<Item = String>,
{
    let mut json = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--endpoint" | "--remote" => {
                if args.next().is_none() {
                    return Err(anyhow!("doctor {arg} requires a value"));
                }
            }
            "--help" | "-h" => return Ok(Some(CliAction::Help)),
            other => return Err(anyhow!("unsupported doctor argument {other:?}")),
        }
    }
    Ok(Some(CliAction::Doctor { json }))
}

async fn run_cli_action(action: CliAction) -> Result<()> {
    match action {
        CliAction::Version => {
            println!("{}", config::agent_version());
            Ok(())
        }
        CliAction::Doctor { json } => run_doctor(json).await,
        CliAction::Help => {
            println!("permanu-agent [--version|doctor]");
            Ok(())
        }
    }
}

async fn run_doctor(json_mode: bool) -> Result<()> {
    let checks: &[(&str, &[u8])] = &[
        ("host", br#"{"kind":"agent.host.snapshot"}"#),
        ("metrics", br#"{"kind":"agent.metrics.sample"}"#),
        ("processes", br#"{"kind":"agent.processes.top","limit":10}"#),
        (
            "self",
            br#"{"kind":"agent.permanu.self.status","service":"permanu-agent"}"#,
        ),
    ];
    let mut failed = false;
    let mut json_checks = Vec::with_capacity(checks.len());

    if !json_mode {
        println!("permanu-agent {}", config::agent_version());
    }

    for (name, payload) in checks {
        let result = sre_tools::handle_command(&format!("doctor-{name}"), payload).await;
        let status = result.status.clone();
        let output_text = String::from_utf8_lossy(&result.output).to_string();
        if json_mode {
            let output = serde_json::from_slice::<serde_json::Value>(&result.output)
                .unwrap_or_else(|_| json!({"text": output_text}));
            json_checks.push(json!({
                "name": name,
                "status": status,
                "output": output,
            }));
        } else {
            println!("\n== {name} ==");
            println!("{output_text}");
        }
        if status != "completed" {
            failed = true;
        }
    }

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": config::agent_version(),
                "status": if failed { "degraded" } else { "ok" },
                "checks": json_checks,
            }))?
        );
    }

    if failed {
        Err(anyhow!("one or more doctor checks failed"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_cli_action() {
        let got = parse_cli_action(vec!["--version".to_string()]).unwrap();
        assert_eq!(got, Some(CliAction::Version));
    }

    #[test]
    fn parses_doctor_cli_action() {
        let got = parse_cli_action(vec!["doctor".to_string()]).unwrap();
        assert_eq!(got, Some(CliAction::Doctor { json: false }));
    }

    #[test]
    fn parses_doctor_json_cli_action() {
        let got = parse_cli_action(vec!["doctor".to_string(), "--json".to_string()]).unwrap();
        assert_eq!(got, Some(CliAction::Doctor { json: true }));
    }

    #[test]
    fn no_args_runs_agent() {
        let got = parse_cli_action(Vec::<String>::new()).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn rejects_unknown_cli_action() {
        let err = parse_cli_action(vec!["bogus".to_string()]).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported permanu-agent argument"));
    }
}
