use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result};
use bollard::errors::Error as BollardError;
use futures::future::{AbortHandle, Abortable};
use serde::Serialize;
use serde_json::json;
use tokio::{
    sync::{mpsc, watch, RwLock, Semaphore, TryAcquireError},
    time::Duration,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::{
    agent_crypto::AgentKeypair,
    app_lifecycle, backup_lifecycle,
    command_handlers::{
        parse_agent_logs_lines, parse_cache_purge_path, parse_network_remove_name,
        parse_volume_remove_name,
    },
    command_runtime::{self, CommandAdmission, CommandCancels},
    compose_lifecycle,
    config::Config,
    control_plane_identity::{self, CloudflareTokenOptions, RealSystemCommand},
    docker_observe, docksmith,
    dwaar_admin::{AdminResponse, DwaarAdmin},
    dwaar_routes,
    host_admin::{self, UninstallStep},
    job_deployment,
    monitoring::MonitoringState,
    proto::agent::v1::{
        agent_service_client::AgentServiceClient, Command, CommandAck, CommandResult,
        ListServerRoutesRequest,
    },
    route_metrics::RouteAggregator,
    self_update, service_lifecycle, sre_tools,
    timeutil::{now_timestamp, now_unix_nanos},
};

const COMMAND_TYPE_UPDATE_AGENT: i32 = 4;
const COMMAND_TYPE_DEPLOY: i32 = 1;
const COMMAND_TYPE_RESTART: i32 = 2;
const COMMAND_TYPE_LOGS: i32 = 3;
const COMMAND_TYPE_EXEC: i32 = 5;
const COMMAND_TYPE_SERVICE_CREATE: i32 = 10;
const COMMAND_TYPE_SERVICE_START: i32 = 11;
const COMMAND_TYPE_SERVICE_STOP: i32 = 12;
const COMMAND_TYPE_SERVICE_RESTART: i32 = 13;
const COMMAND_TYPE_SERVICE_DESTROY: i32 = 14;
const COMMAND_TYPE_SERVICE_LOGS: i32 = 15;
const COMMAND_TYPE_WAIT_FOR_HEALTHY: i32 = 16;
const COMMAND_TYPE_BACKUP_CREATE: i32 = 20;
const COMMAND_TYPE_BACKUP_UPLOAD: i32 = 21;
const COMMAND_TYPE_BACKUP_RESTORE: i32 = 22;
const COMMAND_TYPE_BACKUP_CLEANUP: i32 = 23;
const COMMAND_TYPE_BACKUP_DOWNLOAD: i32 = 24;
const COMMAND_TYPE_COMPOSE_UP: i32 = 30;
const COMMAND_TYPE_COMPOSE_DOWN: i32 = 31;
const COMMAND_TYPE_COMPOSE_RESTART: i32 = 32;
const COMMAND_TYPE_COMPOSE_LOGS: i32 = 33;
const COMMAND_TYPE_APP_CLONE: i32 = 40;
const COMMAND_TYPE_APP_BUILD: i32 = 41;
const COMMAND_TYPE_APP_DEPLOY: i32 = 42;
const COMMAND_TYPE_APP_STOP: i32 = 43;
const COMMAND_TYPE_APP_LOGS: i32 = 44;
const COMMAND_TYPE_APP_PROXY_SETUP: i32 = 45;
const COMMAND_TYPE_APP_PROXY_REMOVE: i32 = 46;
const COMMAND_TYPE_APP_CLEANUP: i32 = 47;
const COMMAND_TYPE_ROUTE_ADD: i32 = 50;
const COMMAND_TYPE_ROUTE_REMOVE: i32 = 51;
const COMMAND_TYPE_RUN_HOOKS: i32 = 60;
const COMMAND_TYPE_RUN_RELEASE_HOOK: i32 = 61;
const COMMAND_TYPE_CACHE_PURGE: i32 = 70;
const COMMAND_TYPE_UNINSTALL: i32 = 80;
const COMMAND_TYPE_TCP_PROXY_START: i32 = 81;
const COMMAND_TYPE_TCP_PROXY_STOP: i32 = 82;
const COMMAND_TYPE_TCP_PROXY_UPDATE: i32 = 83;
const COMMAND_TYPE_CERT_ROTATE: i32 = 90;
const COMMAND_TYPE_BACKUP_VERIFY: i32 = 91;
const COMMAND_TYPE_SQL_EXEC: i32 = 92;
const COMMAND_TYPE_CONFIGURE_MONITORING: i32 = 100;
const COMMAND_TYPE_APP_DETECT_FRAMEWORK: i32 = 48;
const COMMAND_TYPE_APP_ROLLBACK: i32 = 49;
const COMMAND_TYPE_ROUTE_LIST: i32 = 110;
const COMMAND_TYPE_CERT_LIST: i32 = 111;
const COMMAND_TYPE_PROXY_TRAFFIC: i32 = 112;
const COMMAND_TYPE_AGENT_LOGS: i32 = 113;
const COMMAND_TYPE_CANCEL_COMMAND: i32 = 99;
const COMMAND_TYPE_AGENT_STATUS: i32 = 114;
const COMMAND_TYPE_AGENT_PING: i32 = 115;
const COMMAND_TYPE_AGENT_RECONNECT: i32 = 116;
const COMMAND_TYPE_DWAAR_RECONCILE: i32 = 117;
const COMMAND_TYPE_NETWORK_REMOVE: i32 = 120;
const COMMAND_TYPE_VOLUME_REMOVE: i32 = 121;
const COMMAND_TYPE_NETWORK_INSPECT: i32 = 122;
const COMMAND_TYPE_RESTART_SELF: i32 = 123;
const COMMAND_TYPE_REENROLL: i32 = 124;
const COMMAND_TYPE_CI_JOB: i32 = 130;
const COMMAND_TYPE_BOOTSTRAP_SECRETS: i32 = 140;
const COMMAND_TYPE_ROTATE_SECRETS: i32 = 141;
const COMMAND_TYPE_ROTATE_AGENT_SECRET: i32 = 142;
const COMMAND_TYPE_HOST_DIAGNOSTIC: i32 = 150;
const COMMAND_TYPE_DWAAR_CONFIG_PATCH: i32 = 151;
const COMMAND_TYPE_SWARM_STACK_DEPLOY: i32 = 160;
const COMMAND_TYPE_SWARM_STACK_REMOVE: i32 = 161;
const COMMAND_TYPE_SWARM_STACK_STATUS: i32 = 162;
const COMMAND_TYPE_SWARM_SERVICE_ROLLBACK: i32 = 163;

const DWAAR_ADMIN_SOCKET: &str = "/run/dwaar/admin.sock";
const DWAAR_APPS_DIR: &str = "/etc/dwaar/apps";
const DWAARFILE_PATH: &str = "/etc/dwaar/Dwaarfile";
const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STATUS_RESPONSE_BYTES: usize = 64 * 1024;
const JOURNALCTL_TIMEOUT_SECONDS: u64 = 10;
const REENROLL_TIMEOUT_SECONDS: u64 = 300;
const COMMAND_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const COMMAND_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

pub async fn run(
    cfg: Arc<Config>,
    agent_keypair: Arc<AgentKeypair>,
    monitoring: Arc<MonitoringState>,
    route_aggregator: Arc<RouteAggregator>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let agent_started = Instant::now();
    let semaphore = Arc::new(Semaphore::new(command_runtime::MAX_CONCURRENT_COMMANDS));
    let cancels = Arc::new(CommandCancels::default());
    let command_ctx = Arc::new(CommandContext {
        cfg: cfg.clone(),
        agent_started,
        cancels: cancels.clone(),
        monitoring,
        route_aggregator,
        agent_keypair,
        internal_apex: Arc::new(RwLock::new(cfg.internal_apex.clone())),
    });

    let mut reconnect_delay = COMMAND_RECONNECT_INITIAL_DELAY;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        let channel = match cfg.connect_channel().await {
            Ok(channel) => channel,
            Err(err) => {
                warn!(
                    error = ?err,
                    retry_in_seconds = reconnect_delay.as_secs(),
                    "command stream backend connect failed"
                );
                if wait_for_reconnect(&mut shutdown, reconnect_delay).await {
                    return Ok(());
                }
                reconnect_delay = next_reconnect_delay(reconnect_delay);
                continue;
            }
        };
        let mut client = AgentServiceClient::new(channel)
            .max_decoding_message_size(cfg.max_message_size)
            .max_encoding_message_size(cfg.max_message_size);
        let (tx, rx) = mpsc::channel::<CommandResult>(128);
        let request = cfg.attach_auth(tonic::Request::new(ReceiverStream::new(rx)))?;
        let mut stream = match client.command_stream(request).await {
            Ok(response) => {
                reconnect_delay = COMMAND_RECONNECT_INITIAL_DELAY;
                response.into_inner()
            }
            Err(err) => {
                warn!(
                    error = ?err,
                    retry_in_seconds = reconnect_delay.as_secs(),
                    "open command stream failed"
                );
                if wait_for_reconnect(&mut shutdown, reconnect_delay).await {
                    return Ok(());
                }
                reconnect_delay = next_reconnect_delay(reconnect_delay);
                continue;
            }
        };

        loop {
            let command = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                    continue;
                }
                message = stream.message() => match message {
                    Ok(Some(command)) => command,
                    Ok(None) => {
                        info!("command stream closed by backend");
                        break;
                    }
                    Err(err) => {
                        warn!(error = ?err, "command stream receive failed");
                        break;
                    }
                }
            };

            let cfg = cfg.clone();
            let tx = tx.clone();
            let ack_client = client.clone();
            let command_ctx = command_ctx.clone();
            if !command_runtime::command_type_is_valid(command.r#type) {
                tokio::spawn(async move {
                    if let Err(err) = ack_and_send_result(
                        cfg,
                        ack_client,
                        tx,
                        &command,
                        invalid_command(&command),
                    )
                    .await
                    {
                        warn!(error = ?err, "invalid command handler failed");
                    }
                });
                continue;
            }

            if command.r#type == COMMAND_TYPE_CANCEL_COMMAND {
                tokio::spawn(async move {
                    if let Err(err) = handle_command(command_ctx, ack_client, tx, command).await {
                        warn!(error = ?err, "cancel command handler failed");
                    }
                });
                continue;
            }

            let permit =
                match command_runtime::admission_for(command.r#type, semaphore.available_permits())
                {
                    CommandAdmission::BypassLimit => None,
                    CommandAdmission::AcquirePermit => {
                        match semaphore.clone().try_acquire_owned() {
                            Ok(permit) => Some(permit),
                            Err(TryAcquireError::NoPermits) => {
                                tokio::spawn(async move {
                                    let result = failed_text(
                                        &command.id,
                                        "agent command capacity exhausted; retry later",
                                    );
                                    if let Err(err) =
                                        ack_and_send_result(cfg, ack_client, tx, &command, result)
                                            .await
                                    {
                                        warn!(error = ?err, "busy command handler failed");
                                    }
                                });
                                continue;
                            }
                            Err(TryAcquireError::Closed) => {
                                return Err(anyhow::anyhow!("command semaphore closed"));
                            }
                        }
                    }
                    CommandAdmission::RejectBusy => {
                        tokio::spawn(async move {
                            let result = failed_text(
                                &command.id,
                                "agent command capacity exhausted; retry later",
                            );
                            if let Err(err) =
                                ack_and_send_result(cfg, ack_client, tx, &command, result).await
                            {
                                warn!(error = ?err, "busy command handler failed");
                            }
                        });
                        continue;
                    }
                };
            let (abort_handle, abort_registration) = AbortHandle::new_pair();
            let command_id = command.id.clone();
            command_ctx.cancels.register(&command_id, abort_handle);
            let abort_tx = tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let command_id_for_cleanup = command_id.clone();
                let cancels = command_ctx.cancels.clone();
                let result = Abortable::new(
                    handle_command(command_ctx, ack_client, tx, command),
                    abort_registration,
                )
                .await;
                cancels.remove(&command_id_for_cleanup);
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => warn!(error = ?err, "command handler failed"),
                    Err(_) => {
                        let _ = abort_tx
                            .send(cancelled_text(&command_id_for_cleanup, "cancelled"))
                            .await;
                    }
                }
            });
        }

        if wait_for_reconnect(&mut shutdown, reconnect_delay).await {
            return Ok(());
        }
        reconnect_delay = next_reconnect_delay(reconnect_delay);
    }
}

async fn wait_for_reconnect(shutdown: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        _ = tokio::time::sleep(delay) => false,
    }
}

fn next_reconnect_delay(current: Duration) -> Duration {
    current.saturating_mul(2).min(COMMAND_RECONNECT_MAX_DELAY)
}

#[derive(Clone)]
struct CommandContext {
    cfg: Arc<Config>,
    agent_started: Instant,
    cancels: Arc<CommandCancels>,
    monitoring: Arc<MonitoringState>,
    route_aggregator: Arc<RouteAggregator>,
    agent_keypair: Arc<AgentKeypair>,
    internal_apex: Arc<RwLock<String>>,
}

async fn handle_command(
    ctx: Arc<CommandContext>,
    mut client: AgentServiceClient<Channel>,
    tx: mpsc::Sender<CommandResult>,
    command: Command,
) -> Result<()> {
    info!(id = %command.id, kind = command.r#type, "received command");

    ack_command_receipt(&ctx.cfg, &mut client, &command.id).await?;

    let result = match command.r#type {
        COMMAND_TYPE_CACHE_PURGE => handle_cache_purge_command(&command.id, &command.payload).await,
        COMMAND_TYPE_DEPLOY | COMMAND_TYPE_RESTART | COMMAND_TYPE_LOGS => failed_text(
            &command.id,
            "unsupported_command_type: legacy DEPLOY/RESTART/LOGS are not implemented by the current Go agent dispatcher either",
        ),
        COMMAND_TYPE_ROUTE_ADD => handle_route_add_command(&command.id, &command.payload).await,
        COMMAND_TYPE_ROUTE_REMOVE => {
            handle_route_remove_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_CONFIGURE_MONITORING => {
            handle_configure_monitoring(&command.id, &command.payload, &ctx.monitoring)
        }
        COMMAND_TYPE_EXEC => {
            service_lifecycle::handle_exec(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_SERVICE_CREATE => {
            service_lifecycle::handle_service_create(&command.id, &command.payload, tx.clone())
                .await
        }
        COMMAND_TYPE_SERVICE_START => {
            service_lifecycle::handle_service_start(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SERVICE_STOP => {
            service_lifecycle::handle_service_stop(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SERVICE_RESTART => {
            service_lifecycle::handle_service_restart(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SERVICE_DESTROY => {
            service_lifecycle::handle_service_destroy(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SERVICE_LOGS => {
            service_lifecycle::handle_service_logs(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_WAIT_FOR_HEALTHY => {
            service_lifecycle::handle_wait_for_healthy(&command.id, &command.payload).await
        }
        COMMAND_TYPE_BACKUP_CREATE => {
            backup_lifecycle::handle_backup_create(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_BACKUP_UPLOAD => {
            backup_lifecycle::handle_backup_upload(&command.id, &command.payload).await
        }
        COMMAND_TYPE_BACKUP_RESTORE => {
            backup_lifecycle::handle_backup_restore(&command.id, &command.payload).await
        }
        COMMAND_TYPE_BACKUP_CLEANUP => {
            backup_lifecycle::handle_backup_cleanup(&command.id, &command.payload).await
        }
        COMMAND_TYPE_BACKUP_DOWNLOAD => {
            backup_lifecycle::handle_backup_download(&command.id, &command.payload, tx.clone())
                .await
        }
        COMMAND_TYPE_COMPOSE_UP => {
            compose_lifecycle::handle_compose_up(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_COMPOSE_DOWN => {
            compose_lifecycle::handle_compose_down(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_COMPOSE_RESTART => {
            compose_lifecycle::handle_compose_restart(&command.id, &command.payload).await
        }
        COMMAND_TYPE_COMPOSE_LOGS => {
            compose_lifecycle::handle_compose_logs(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_APP_CLONE => {
            app_lifecycle::handle_app_clone(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_APP_BUILD => {
            app_lifecycle::handle_app_build(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_APP_DEPLOY => {
            app_lifecycle::handle_app_deploy(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_APP_STOP => {
            app_lifecycle::handle_app_stop(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_APP_LOGS => {
            app_lifecycle::handle_app_logs(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_APP_PROXY_SETUP => {
            handle_app_proxy_setup_command(&command.id, &command.payload, &ctx).await
        }
        COMMAND_TYPE_APP_PROXY_REMOVE => {
            handle_app_proxy_remove_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_APP_CLEANUP => {
            app_lifecycle::handle_app_cleanup(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_APP_DETECT_FRAMEWORK => {
            handle_app_detect_framework_command(&command.id, &ctx.cfg, &command.payload).await
        }
        COMMAND_TYPE_APP_ROLLBACK => {
            app_lifecycle::handle_app_rollback(&command.id, &command.payload, tx.clone()).await
        }
        COMMAND_TYPE_RUN_HOOKS => handle_run_hooks_command(&command.id, &command.payload).await,
        COMMAND_TYPE_RUN_RELEASE_HOOK => {
            handle_run_release_hook_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_UNINSTALL => handle_uninstall_command(&command.id).await,
        COMMAND_TYPE_TCP_PROXY_START | COMMAND_TYPE_TCP_PROXY_UPDATE => {
            handle_tcp_proxy_upsert_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_TCP_PROXY_STOP => {
            handle_tcp_proxy_stop_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_CERT_ROTATE => handle_cert_rotate_command(&command.id, &command.payload).await,
        COMMAND_TYPE_ROUTE_LIST => handle_dwaar_get_command(&command.id, "/routes").await,
        COMMAND_TYPE_CERT_LIST => handle_cert_list_command(&command.id).await,
        COMMAND_TYPE_PROXY_TRAFFIC => {
            handle_proxy_traffic(&command.id, &command.payload, &ctx.route_aggregator)
        }
        COMMAND_TYPE_AGENT_LOGS => handle_agent_logs_command(&command.id, &command.payload).await,
        COMMAND_TYPE_AGENT_PING => completed_json(
            &command.id,
            &AgentPing {
                agent_time_nanos: now_unix_nanos(),
                agent_version: ctx.cfg.version.clone(),
            },
        )?,
        COMMAND_TYPE_AGENT_STATUS => {
            let docker_reachable = docker_reachable().await;
            completed_json(
                &command.id,
                &AgentStatus {
                    agent_version: ctx.cfg.version.clone(),
                    runtime: "rust".to_string(),
                    arch: std::env::consts::ARCH.to_string(),
                    uptime_seconds: ctx.agent_started.elapsed().as_secs() as i64,
                    docker_reachable,
                    server_time_nanos: now_unix_nanos(),
                    rss_bytes: current_rss_bytes(),
                },
            )?
        }
        COMMAND_TYPE_AGENT_RECONNECT | COMMAND_TYPE_RESTART_SELF => {
            let result = queued_json(
                &command.id,
                &RestartQueued {
                    message: "agent restart queued".to_string(),
                    scheduled_in_seconds: 1,
                },
            )?;
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                std::process::exit(0);
            });
            result
        }
        COMMAND_TYPE_CANCEL_COMMAND => {
            handle_cancel_command(&command.id, &command.payload, &ctx.cancels)
        }
        COMMAND_TYPE_BACKUP_VERIFY => {
            backup_lifecycle::handle_backup_verify(&command.id, &command.payload).await
        }
        COMMAND_TYPE_UPDATE_AGENT => {
            self_update::handle_update_agent(
                &command.id,
                &command.payload,
                &ctx.cfg,
                client.clone(),
                tx.clone(),
            )
            .await
        }
        COMMAND_TYPE_DWAAR_RECONCILE => {
            handle_dwaar_reconcile_command(&command.id, &ctx.cfg, &mut client).await
        }
        COMMAND_TYPE_NETWORK_REMOVE => {
            handle_network_remove_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_VOLUME_REMOVE => {
            handle_volume_remove_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_NETWORK_INSPECT => handle_network_inspect_command(&command.id).await,
        COMMAND_TYPE_REENROLL => handle_reenroll_command(&command.id, &command.payload).await,
        COMMAND_TYPE_BOOTSTRAP_SECRETS => {
            handle_bootstrap_secrets_command(&command.id, &command.payload, &ctx).await
        }
        COMMAND_TYPE_ROTATE_SECRETS => {
            handle_rotate_secrets_command(&command.id, &command.payload, &ctx).await
        }
        COMMAND_TYPE_ROTATE_AGENT_SECRET => {
            handle_rotate_agent_secret_command(&command.id, &command.payload, &ctx).await
        }
        COMMAND_TYPE_CI_JOB => handle_ci_job_command(&command.id, &command.payload),
        COMMAND_TYPE_HOST_DIAGNOSTIC => sre_tools::handle_command(&command.id, &command.payload).await,
        COMMAND_TYPE_DWAAR_CONFIG_PATCH => {
            handle_dwaar_config_patch_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SWARM_STACK_DEPLOY => {
            handle_swarm_stack_deploy_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SWARM_STACK_REMOVE => {
            handle_swarm_stack_remove_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SWARM_STACK_STATUS => {
            handle_swarm_stack_status_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SWARM_SERVICE_ROLLBACK => {
            handle_swarm_service_rollback_command(&command.id, &command.payload).await
        }
        COMMAND_TYPE_SQL_EXEC => failed_text(
            &command.id,
            "unsupported_command_type: SQL_EXEC is intentionally disabled on the agent",
        ),
        other => failed_text(
            &command.id,
            &format!(
                "unsupported_command_type: {other} is not implemented in permanu-agent-rs yet"
            ),
        ),
    };

    tx.send(result).await.context("send command result")?;
    Ok(())
}

async fn handle_app_detect_framework_command(
    command_id: &str,
    cfg: &Config,
    payload: &[u8],
) -> CommandResult {
    match docksmith::detect_framework(&cfg.docksmith_bin, cfg.docksmith_timeout, payload).await {
        Ok(output) => completed_bytes(command_id, output),
        Err(err) => failed_text(command_id, &format!("framework detection failed: {err}")),
    }
}

async fn handle_bootstrap_secrets_command(
    command_id: &str,
    payload: &[u8],
    ctx: &CommandContext,
) -> CommandResult {
    let mut system = RealSystemCommand;
    let options = CloudflareTokenOptions::new(
        &ctx.cfg.dwaar_cf_token_path,
        &ctx.cfg.dwaar_cf_token_drop_in_dir,
        &mut system,
    );
    let result = control_plane_identity::handle_bootstrap_secrets_with_decryptor(
        command_id,
        payload,
        options,
        |sealed| decrypt_agent_text(&ctx.agent_keypair, sealed),
    );
    identity_result(command_id, result, ctx).await
}

async fn handle_rotate_secrets_command(
    command_id: &str,
    payload: &[u8],
    ctx: &CommandContext,
) -> CommandResult {
    let mut system = RealSystemCommand;
    let options = CloudflareTokenOptions::new(
        &ctx.cfg.dwaar_cf_token_path,
        &ctx.cfg.dwaar_cf_token_drop_in_dir,
        &mut system,
    );
    let result = control_plane_identity::handle_rotate_secrets_with_decryptor(
        command_id,
        payload,
        options,
        |sealed| decrypt_agent_text(&ctx.agent_keypair, sealed),
    );
    identity_result(command_id, result, ctx).await
}

async fn handle_rotate_agent_secret_command(
    command_id: &str,
    payload: &[u8],
    ctx: &CommandContext,
) -> CommandResult {
    let result = control_plane_identity::handle_rotate_agent_secret_with_decryptor(
        command_id,
        payload,
        &ctx.cfg.agent_env_file,
        &ctx.cfg.server_id,
        |sealed| decrypt_agent_text(&ctx.agent_keypair, sealed),
    );
    identity_result(command_id, result, ctx).await
}

async fn identity_result(
    command_id: &str,
    result: anyhow::Result<control_plane_identity::AgentCommandResult>,
    ctx: &CommandContext,
) -> CommandResult {
    match result {
        Ok(result) => {
            if let Some(apex) = &result.internal_apex {
                *ctx.internal_apex.write().await = apex.clone();
            }
            if let Some(delay) = result.restart_agent_after {
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    std::process::exit(0);
                });
            }
            CommandResult {
                command_id: result.command_id,
                status: result.status.as_str().to_string(),
                output: result.output,
                is_final: result.is_final,
                timestamp: Some(now_timestamp()),
            }
        }
        Err(err) => failed_text(command_id, &err.to_string()),
    }
}

fn decrypt_agent_text(agent_keypair: &AgentKeypair, sealed: &[u8]) -> anyhow::Result<String> {
    let plaintext = agent_keypair.open_from_agent(sealed)?;
    let text = String::from_utf8(plaintext).context("agent_box: plaintext is not UTF-8")?;
    Ok(text.trim().to_string())
}

async fn handle_reenroll_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let parsed = match control_plane_identity::parse_reenroll_payload(payload, command_id) {
        Ok(parsed) => parsed,
        Err(err) => return failed_text(command_id, &format!("reenroll: {err}")),
    };
    let script =
        match control_plane_identity::download_installer_with_curl(&parsed.install_url).await {
            Ok(script) => script,
            Err(err) => return failed_text(command_id, &format!("reenroll download: {err}")),
        };
    let script_path =
        match control_plane_identity::write_reenroll_script(&parsed, &script, std::env::temp_dir())
        {
            Ok(path) => path,
            Err(err) => return failed_text(command_id, &format!("reenroll script: {err}")),
        };
    match control_plane_identity::run_reenroll_script(
        &script_path,
        Duration::from_secs(REENROLL_TIMEOUT_SECONDS),
    )
    .await
    {
        Ok(output) => {
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                std::process::exit(0);
            });
            completed_text(command_id, &output)
        }
        Err(err) => failed_text(command_id, &format!("reenroll installer: {err}")),
    }
}

async fn handle_run_hooks_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let plan = match job_deployment::parse_run_hooks(payload) {
        Ok(plan) => plan,
        Err(err) => return failed_text(command_id, &format!("invalid run hooks payload: {err}")),
    };
    let mut invocations = Vec::with_capacity(plan.commands.len());
    for command in plan.commands {
        let Some((program, args)) = command.argv.split_first() else {
            return failed_text(command_id, "run hooks: empty command");
        };
        invocations.push(job_deployment::CommandInvocation {
            program: program.clone(),
            args: args.to_vec(),
            work_dir: Some(plan.work_dir.clone()),
            env: plan.env.clone(),
            timeout_seconds: plan.timeout_seconds,
        });
    }
    run_job_invocations(command_id, invocations).await
}

async fn handle_run_release_hook_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let invocations = match job_deployment::build_release_hook_invocations(payload) {
        Ok(invocations) => invocations,
        Err(err) => {
            return failed_text(command_id, &format!("invalid release hook payload: {err}"))
        }
    };
    run_job_invocations(command_id, invocations).await
}

async fn run_job_invocations(
    command_id: &str,
    invocations: Vec<job_deployment::CommandInvocation>,
) -> CommandResult {
    let mut output = String::new();
    for invocation in invocations {
        match job_deployment::run_invocation(&invocation).await {
            Ok(process) if process.status_success => {
                if !process.output.is_empty() {
                    output.push_str(&process.output);
                    output.push('\n');
                }
            }
            Ok(process) => {
                return failed_text(
                    command_id,
                    &format!("{} failed: {}", invocation.program, process.output),
                )
            }
            Err(err) => return failed_text(command_id, &err),
        }
    }
    completed_text(command_id, output.trim())
}

fn handle_ci_job_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let result = job_deployment::handle_ci_job(command_id, payload);
    CommandResult {
        command_id: result.command_id,
        status: result.status,
        output: result.output,
        is_final: result.is_final,
        timestamp: Some(now_timestamp()),
    }
}

async fn handle_app_proxy_setup_command(
    command_id: &str,
    payload: &[u8],
    ctx: &CommandContext,
) -> CommandResult {
    let mut setup = match job_deployment::parse_app_proxy_setup(payload) {
        Ok(setup) => setup,
        Err(err) => return failed_text(command_id, &format!("invalid app proxy payload: {err}")),
    };
    if let Ok(docker) = docker_observe::docker_client() {
        if let Ok(Ok(upstream)) = tokio::time::timeout(
            Duration::from_secs(10),
            dwaar_routes::resolve_container_addr(
                &docker,
                &setup.container_name,
                setup.port,
                "deploy-net",
            ),
        )
        .await
        {
            setup.upstream = upstream;
        }
    }
    let path = Path::new(DWAAR_APPS_DIR).join(format!("{}.dwaar", setup.slug));
    if !Path::new(DWAAR_APPS_DIR).is_dir() {
        return failed_text(
            command_id,
            &format!("dwaar apps dir {DWAAR_APPS_DIR} missing"),
        );
    }
    let apex = {
        let apex = ctx.internal_apex.read().await;
        if apex.trim().is_empty() {
            "local".to_string()
        } else {
            apex.clone()
        }
    };
    let content = job_deployment::render_app_proxy_snippet(&setup, &apex);
    if let Err(err) = atomic_write_string(&path, &content, 0o644) {
        return failed_text(command_id, &format!("write app proxy snippet: {err}"));
    }
    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
        return failed_text(command_id, &format!("reload dwaar: {err}"));
    }
    completed_text(command_id, "proxy configured")
}

async fn handle_app_proxy_remove_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let remove = match job_deployment::parse_app_proxy_remove(payload) {
        Ok(remove) => remove,
        Err(err) => return failed_text(command_id, &format!("invalid app proxy payload: {err}")),
    };
    let path = Path::new(DWAAR_APPS_DIR).join(format!("{}.dwaar", remove.slug));
    if let Err(err) = fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return failed_text(command_id, &format!("remove app proxy snippet: {err}"));
        }
    }
    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
        return failed_text(command_id, &format!("reload dwaar: {err}"));
    }
    completed_text(command_id, "proxy removed")
}

async fn ack_and_send_result(
    cfg: Arc<Config>,
    mut client: AgentServiceClient<Channel>,
    tx: mpsc::Sender<CommandResult>,
    command: &Command,
    result: CommandResult,
) -> Result<()> {
    ack_command_receipt(&cfg, &mut client, &command.id).await?;
    tx.send(result).await.context("send command result")
}

async fn ack_command_receipt(
    cfg: &Config,
    client: &mut AgentServiceClient<Channel>,
    command_id: &str,
) -> Result<()> {
    if command_id.is_empty() {
        return Ok(());
    }
    let ack = CommandAck {
        command_id: command_id.to_string(),
        server_id: cfg.server_id.clone(),
        phase: "received".to_string(),
    };
    let request = cfg.attach_auth(tonic::Request::new(ack))?;
    match tokio::time::timeout(Duration::from_secs(3), client.ack_command(request)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => warn!(error = ?err, command_id = %command_id, "command ack failed"),
        Err(err) => warn!(error = ?err, command_id = %command_id, "command ack timed out"),
    }
    Ok(())
}

fn invalid_command(command: &Command) -> CommandResult {
    if command.r#type == 0 {
        return failed_text(
            &command.id,
            "invalid_command_type: COMMAND_TYPE_UNSPECIFIED",
        );
    }
    failed_text(
        &command.id,
        &format!("invalid_command_type: {}", command.r#type),
    )
}

fn handle_cancel_command(
    command_id: &str,
    payload: &[u8],
    cancels: &CommandCancels,
) -> CommandResult {
    let target = match command_runtime::parse_cancel_target(payload) {
        Ok(target) => target,
        Err(err) => return failed_text(command_id, &format!("malformed cancel payload: {err}")),
    };
    if cancels.cancel(&target) {
        completed_text(command_id, &format!("cancelled cmd={target}"))
    } else {
        completed_text(command_id, &format!("no such command cmd={target}"))
    }
}

async fn handle_route_add_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match dwaar_routes::parse_route_add_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let upstream = if dwaar_routes::host_is_literal(&payload.upstream_host) {
        dwaar_routes::literal_upstream(&payload.upstream_host, payload.upstream_port)
    } else {
        let docker = match docker_observe::docker_client() {
            Ok(docker) => docker,
            Err(err) => return failed_text(command_id, &format!("docker client: {err}")),
        };
        match tokio::time::timeout(
            Duration::from_secs(10),
            dwaar_routes::resolve_container_addr(
                &docker,
                &payload.upstream_host,
                payload.upstream_port,
                "deploy-net",
            ),
        )
        .await
        {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(err)) => {
                return failed_text(
                    command_id,
                    &format!(
                        "resolve upstream container {:?}: {err}",
                        payload.upstream_host
                    ),
                )
            }
            Err(_) => {
                return failed_text(
                    command_id,
                    &format!(
                        "resolve upstream container {:?}: timed out",
                        payload.upstream_host
                    ),
                )
            }
        }
    };

    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    if dwaar_routes::route_needs_snippet(&payload.path_prefix, payload.analytics_enabled) {
        if let Err(err) = dwaar_routes::persist_route_snippet(
            &payload.domain,
            &upstream,
            &payload.path_prefix,
            payload.analytics_enabled,
        ) {
            return failed_text(command_id, &format!("write route snippet: {err}"));
        }
        if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
            return failed_text(command_id, &format!("dwaar reload after route add: {err}"));
        }
        return completed_text(
            command_id,
            &format!("route snippet added: {} -> {}", payload.domain, upstream),
        );
    }
    let request = dwaar_routes::create_route_request(&payload.domain, &upstream);
    if let Err(err) = dwaar_routes::post_route(&dwaar, &request).await {
        return failed_text(command_id, &format!("dwaar admin API: {err}"));
    }
    if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
        return failed_text(command_id, &format!("dwaar reload after route add: {err}"));
    }
    if let Err(err) = dwaar_routes::persist_route_file(&payload.domain, &upstream) {
        warn!(domain = %payload.domain, upstream = %upstream, error = ?err, "route file persistence failed");
    }
    completed_text(
        command_id,
        &format!("route added: {} -> {}", payload.domain, upstream),
    )
}

async fn handle_route_remove_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let domain = match dwaar_routes::parse_route_remove_domain(payload) {
        Ok(domain) => domain,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    let removed = match dwaar_routes::delete_route(&dwaar, &domain).await {
        Ok(removed) => removed,
        Err(err) => return failed_text(command_id, &format!("dwaar admin API: {err}")),
    };
    if let Err(err) = dwaar_routes::remove_route_files(&domain) {
        return failed_text(command_id, &format!("remove route files: {err}"));
    }
    if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
        return failed_text(
            command_id,
            &format!("dwaar reload after route remove: {err}"),
        );
    }

    if removed {
        completed_text(command_id, &format!("route removed: {domain}"))
    } else {
        completed_text(command_id, "route not found (already removed)")
    }
}

async fn handle_dwaar_reconcile_command(
    command_id: &str,
    cfg: &Config,
    client: &mut AgentServiceClient<Channel>,
) -> CommandResult {
    let request = match cfg.attach_auth(tonic::Request::new(ListServerRoutesRequest {
        server_id: cfg.server_id.clone(),
    })) {
        Ok(request) => request,
        Err(err) => {
            return failed_text(
                command_id,
                &format!("build ListServerRoutes request: {err}"),
            )
        }
    };

    let response =
        match tokio::time::timeout(Duration::from_secs(15), client.list_server_routes(request))
            .await
        {
            Ok(Ok(response)) => response.into_inner(),
            Ok(Err(err)) => {
                return failed_text(command_id, &format!("ListServerRoutes failed: {err}"))
            }
            Err(_) => return failed_text(command_id, "ListServerRoutes timed out"),
        };

    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    let live_routes = match dwaar_routes::fetch_live_routes(&dwaar).await {
        Ok(routes) => routes,
        Err(err) => return failed_text(command_id, &format!("fetch Dwaar routes: {err}")),
    };
    let live_domains: std::collections::HashSet<String> =
        live_routes.into_iter().map(|route| route.domain).collect();

    let docker = match docker_observe::docker_client() {
        Ok(docker) => docker,
        Err(err) => return failed_text(command_id, &format!("docker client: {err}")),
    };

    let mut summary = dwaar_routes::ReconcileSummary {
        routes_added: 0,
        routes_skipped: 0,
        errors: Vec::new(),
    };

    for route in response.routes {
        if route.domain.is_empty() || route.container_name.is_empty() {
            continue;
        }
        if live_domains.contains(&route.domain)
            && !dwaar_routes::route_needs_snippet(&route.path_prefix, route.analytics_enabled)
        {
            summary.routes_skipped += 1;
            continue;
        }

        let port = u16::try_from(route.port)
            .ok()
            .filter(|port| *port > 0)
            .unwrap_or(3000);
        let upstream = match tokio::time::timeout(
            Duration::from_secs(10),
            dwaar_routes::resolve_route_upstream(&docker, &route.container_name, port),
        )
        .await
        {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(err)) => {
                summary.errors.push(dwaar_routes::ReconcileRouteError {
                    domain: route.domain,
                    app_id: route.app_id,
                    reason: err.to_string(),
                });
                continue;
            }
            Err(_) => {
                summary.errors.push(dwaar_routes::ReconcileRouteError {
                    domain: route.domain,
                    app_id: route.app_id,
                    reason: "resolve container timed out".to_string(),
                });
                continue;
            }
        };

        if dwaar_routes::route_needs_snippet(&route.path_prefix, route.analytics_enabled) {
            match dwaar_routes::persist_route_snippet(
                &route.domain,
                &upstream,
                &route.path_prefix,
                route.analytics_enabled,
            ) {
                Ok(()) => {
                    if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
                        summary.errors.push(dwaar_routes::ReconcileRouteError {
                            domain: route.domain,
                            app_id: route.app_id,
                            reason: format!("dwaar reload after snippet upsert: {err}"),
                        });
                        continue;
                    }
                    summary.routes_added += 1;
                }
                Err(err) => summary.errors.push(dwaar_routes::ReconcileRouteError {
                    domain: route.domain,
                    app_id: route.app_id,
                    reason: format!("write route snippet: {err}"),
                }),
            }
            continue;
        }

        let request = dwaar_routes::create_route_request(&route.domain, &upstream);
        match dwaar_routes::post_route(&dwaar, &request).await {
            Ok(()) => {
                if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
                    summary.errors.push(dwaar_routes::ReconcileRouteError {
                        domain: route.domain,
                        app_id: route.app_id,
                        reason: format!("dwaar reload after route upsert: {err}"),
                    });
                    continue;
                }
                if let Err(err) = dwaar_routes::persist_route_file(&route.domain, &upstream) {
                    warn!(domain = %route.domain, upstream = %upstream, error = ?err, "route file persistence failed");
                }
                summary.routes_added += 1;
            }
            Err(err) => summary.errors.push(dwaar_routes::ReconcileRouteError {
                domain: route.domain,
                app_id: route.app_id,
                reason: err.to_string(),
            }),
        }
    }

    completed_json(command_id, &summary)
        .unwrap_or_else(|err| failed_text(command_id, &format!("marshal summary: {err}")))
}

async fn handle_dwaar_get_command(command_id: &str, path: &str) -> CommandResult {
    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    match dwaar
        .request("GET", path, &[], MAX_INTROSPECTION_RESPONSE_BYTES)
        .await
    {
        Ok(response) => command_result_from_dwaar_response(command_id, response),
        Err(err) => failed_text(command_id, &format!("dwaar admin unreachable: {err}")),
    }
}

async fn handle_cert_list_command(command_id: &str) -> CommandResult {
    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    match dwaar
        .request("GET", "/certs", &[], MAX_INTROSPECTION_RESPONSE_BYTES)
        .await
    {
        Ok(response) if response.status == 404 => completed_json(
            command_id,
            &json!({
                "supported": false,
                "reason": "Dwaar on this server does not expose /certs - upgrade Dwaar to surface cert inventory."
            }),
        )
        .unwrap_or_else(|err| failed_text(command_id, &format!("marshal: {err}"))),
        Ok(response) => command_result_from_dwaar_response(command_id, response),
        Err(err) => failed_text(command_id, &format!("dwaar admin unreachable: {err}")),
    }
}

async fn handle_cache_purge_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let path = match parse_cache_purge_path(payload) {
        Ok(path) => path,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    match dwaar
        .request("PURGE", &path, &[], MAX_STATUS_RESPONSE_BYTES)
        .await
    {
        Ok(response) if matches!(response.status, 200 | 204 | 404) => completed_text(
            command_id,
            &format!(
                "purged {} (status={})",
                path.trim_start_matches("/cache/"),
                response.status
            ),
        ),
        Ok(response) => failed_text(
            command_id,
            &format!(
                "cache purge: dwaar returned {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body).trim()
            ),
        ),
        Err(err) => failed_text(
            command_id,
            &format!("cache purge: dwaar admin socket unreachable: {err}"),
        ),
    }
}

fn handle_configure_monitoring(
    command_id: &str,
    payload: &[u8],
    monitoring: &MonitoringState,
) -> CommandResult {
    match monitoring.apply_json_config(payload) {
        Ok(summary) => completed_json(command_id, &summary)
            .unwrap_or_else(|err| failed_text(command_id, &format!("marshal response: {err}"))),
        Err(err) => failed_text(command_id, &format!("invalid monitoring config: {err}")),
    }
}

fn handle_proxy_traffic(
    command_id: &str,
    payload: &[u8],
    route_aggregator: &RouteAggregator,
) -> CommandResult {
    #[derive(serde::Deserialize)]
    struct ProxyTrafficPayload {
        #[serde(default)]
        host: String,
        #[serde(default)]
        lookback_seconds: i64,
    }

    let request = if payload.is_empty() {
        ProxyTrafficPayload {
            host: String::new(),
            lookback_seconds: 0,
        }
    } else {
        match serde_json::from_slice::<ProxyTrafficPayload>(payload) {
            Ok(payload) => payload,
            Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
        }
    };
    let host = request.host.trim().to_string();
    let routes = route_aggregator.snapshot((!host.is_empty()).then_some(host.as_str()));
    completed_json(
        command_id,
        &json!({
            "host": host,
            "lookback_seconds": request.lookback_seconds,
            "routes": routes,
            "note": "aggregator is reset on each heartbeat; values reflect the current open window, not a fixed lookback"
        }),
    )
    .unwrap_or_else(|err| failed_text(command_id, &format!("marshal: {err}")))
}

async fn handle_agent_logs_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let lines = match parse_agent_logs_lines(payload) {
        Ok(lines) => lines,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let line_count = lines.to_string();

    let output = tokio::time::timeout(
        Duration::from_secs(JOURNALCTL_TIMEOUT_SECONDS),
        tokio::process::Command::new("journalctl")
            .args([
                "-u",
                "permanu-agent",
                "-n",
                &line_count,
                "--no-pager",
                "-o",
                "short-iso",
            ])
            .output(),
    )
    .await;

    match output {
        Ok(Ok(output)) => {
            let mut combined = output.stdout;
            combined.extend_from_slice(&output.stderr);
            completed_bytes(command_id, combined)
        }
        Ok(Err(err)) => failed_text(command_id, &format!("agent logs: journalctl failed: {err}")),
        Err(_) => failed_text(command_id, "agent logs: journalctl timed out"),
    }
}

async fn handle_network_remove_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let name = match parse_network_remove_name(payload) {
        Ok(name) => name,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let docker = match docker_observe::docker_client() {
        Ok(docker) => docker,
        Err(err) => return failed_text(command_id, &format!("docker client: {err}")),
    };
    match tokio::time::timeout(Duration::from_secs(10), docker.remove_network(&name)).await {
        Ok(Ok(())) => completed_text(command_id, "removed"),
        Ok(Err(err)) if docker_not_found(&err) => completed_text(command_id, "not_found"),
        Ok(Err(err)) => failed_text(
            command_id,
            &format!("failed to remove network {name:?}: {err}"),
        ),
        Err(_) => failed_text(
            command_id,
            &format!("failed to remove network {name:?}: timed out"),
        ),
    }
}

async fn handle_volume_remove_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let name = match parse_volume_remove_name(payload) {
        Ok(name) => name,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let docker = match docker_observe::docker_client() {
        Ok(docker) => docker,
        Err(err) => return failed_text(command_id, &format!("docker client: {err}")),
    };
    let remove = docker.remove_volume(
        &name,
        None::<bollard::query_parameters::RemoveVolumeOptions>,
    );
    match tokio::time::timeout(Duration::from_secs(10), remove).await {
        Ok(Ok(())) => completed_text(command_id, "removed"),
        Ok(Err(err)) if docker_not_found(&err) => completed_text(command_id, "not_found"),
        Ok(Err(err)) => failed_text(
            command_id,
            &format!("failed to remove volume {name:?}: {err}"),
        ),
        Err(_) => failed_text(
            command_id,
            &format!("failed to remove volume {name:?}: timed out"),
        ),
    }
}

async fn handle_network_inspect_command(command_id: &str) -> CommandResult {
    let docker = match docker_observe::docker_client() {
        Ok(docker) => docker,
        Err(err) => return failed_text(command_id, &format!("docker client: {err}")),
    };

    let inspect = tokio::time::timeout(
        Duration::from_secs(5),
        docker.inspect_network("deploy-net", None),
    )
    .await;

    let network = match inspect {
        Ok(Ok(network)) => network,
        Ok(Err(err)) => {
            return failed_text(command_id, &format!("NetworkInspect deploy-net: {err}"))
        }
        Err(_) => return failed_text(command_id, "NetworkInspect deploy-net: timed out"),
    };

    let mut containers = Vec::new();
    if let Some(endpoints) = network.containers {
        containers.reserve(endpoints.len());
        for (container_id, endpoint) in endpoints {
            containers.push(NetworkInspectContainer {
                container_id,
                container_name: endpoint
                    .name
                    .unwrap_or_default()
                    .trim_start_matches('/')
                    .to_string(),
                ipv4_address: endpoint.ipv4_address.unwrap_or_default(),
                mac_address: endpoint.mac_address.unwrap_or_default(),
            });
        }
    }

    completed_json(
        command_id,
        &NetworkInspectResult {
            network_id: network.id.unwrap_or_default(),
            network_name: network.name.unwrap_or_default(),
            driver: network.driver.unwrap_or_default(),
            containers,
        },
    )
    .unwrap_or_else(|err| failed_text(command_id, &format!("marshal: {err}")))
}

async fn handle_dwaar_config_patch_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let patch = match host_admin::parse_dwaar_config_patch(payload) {
        Ok(patch) => patch,
        Err(err) => return failed_text(command_id, &format!("invalid dwaar patch payload: {err}")),
    };
    let path = Path::new(DWAARFILE_PATH);
    let current = match fs::read_to_string(path) {
        Ok(current) => current,
        Err(err) => return failed_text(command_id, &format!("read {DWAARFILE_PATH}: {err}")),
    };
    let plan = match host_admin::plan_dwaar_config_patch(&current, &patch) {
        Ok(plan) => plan,
        Err(err) => return failed_text(command_id, &format!("plan dwaar patch: {err}")),
    };
    if let Err(err) = write_backup(path, plan.backup_retention) {
        return failed_text(command_id, &format!("backup {DWAARFILE_PATH}: {err}"));
    }
    if let Err(err) = atomic_write_string(path, &plan.content, 0o644) {
        return failed_text(command_id, &format!("write {DWAARFILE_PATH}: {err}"));
    }
    if let Err(err) = run_spec(&plan.restart).await {
        return failed_text(command_id, &format!("restart dwaar: {err}"));
    }
    if let Err(err) = run_spec(&plan.active_check).await {
        return failed_text(command_id, &format!("dwaar active check: {err}"));
    }
    completed_json(command_id, &plan.result)
        .unwrap_or_else(|err| failed_text(command_id, &format!("marshal: {err}")))
}

async fn handle_tcp_proxy_upsert_command(command_id: &str, payload: &[u8]) -> CommandResult {
    #[derive(serde::Deserialize)]
    struct Payload {
        proxy_id: String,
        port: u16,
        target: String,
        #[serde(default)]
        allowed_ips: Vec<String>,
    }

    let payload = match serde_json::from_slice::<Payload>(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid tcp proxy payload: {err}")),
    };
    let content = match host_admin::build_tcp_proxy_config(
        &payload.proxy_id,
        payload.port,
        &payload.target,
        &payload.allowed_ips,
    ) {
        Ok(content) => content,
        Err(err) => return failed_text(command_id, &format!("tcp proxy config: {err}")),
    };
    let path = match host_admin::tcp_proxy_config_path(&payload.proxy_id) {
        Ok(path) => PathBuf::from(path),
        Err(err) => return failed_text(command_id, &format!("tcp proxy path: {err}")),
    };
    if !Path::new(DWAAR_APPS_DIR).is_dir() {
        return failed_text(
            command_id,
            &format!("dwaar apps dir {DWAAR_APPS_DIR} missing"),
        );
    }
    if let Err(err) = atomic_write_string(&path, &content, 0o644) {
        return failed_text(command_id, &format!("write tcp proxy config: {err}"));
    }
    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
        return failed_text(command_id, &format!("reload dwaar: {err}"));
    }
    completed_json(
        command_id,
        &host_admin::TcpProxyResult {
            proxy_id: payload.proxy_id,
            port: payload.port,
            tls: false,
        },
    )
    .unwrap_or_else(|err| failed_text(command_id, &format!("marshal: {err}")))
}

async fn handle_tcp_proxy_stop_command(command_id: &str, payload: &[u8]) -> CommandResult {
    #[derive(serde::Deserialize)]
    struct Payload {
        proxy_id: String,
    }
    let payload = match serde_json::from_slice::<Payload>(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid tcp proxy payload: {err}")),
    };
    let path = match host_admin::tcp_proxy_config_path(&payload.proxy_id) {
        Ok(path) => PathBuf::from(path),
        Err(err) => return failed_text(command_id, &format!("tcp proxy path: {err}")),
    };
    if let Err(err) = fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return failed_text(command_id, &format!("remove tcp proxy config: {err}"));
        }
    }
    let dwaar = DwaarAdmin::new(DWAAR_ADMIN_SOCKET);
    if let Err(err) = dwaar_routes::reload_dwaar(&dwaar).await {
        return failed_text(command_id, &format!("reload dwaar: {err}"));
    }
    completed_text(command_id, "tcp proxy removed")
}

async fn handle_cert_rotate_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let steps = match host_admin::build_cert_rotate_steps(payload) {
        Ok(steps) => steps,
        Err(err) => return failed_text(command_id, &format!("invalid cert rotate payload: {err}")),
    };
    for step in steps {
        let spec = host_admin::CommandSpec {
            program: step.program,
            args: step.args,
            timeout: step.timeout,
            max_output_bytes: step.max_output_bytes,
        };
        if let Err(err) = run_spec(&spec).await {
            return failed_text(command_id, &format!("cert rotate: {err}"));
        }
    }
    completed_text(command_id, "cert rotated")
}

async fn handle_uninstall_command(command_id: &str) -> CommandResult {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        for step in host_admin::build_uninstall_plan() {
            match step {
                UninstallStep::Command(spec) => {
                    let _ = run_spec(&spec).await;
                }
                UninstallStep::DockerCleanup(spec) => {
                    let args = vec![
                        spec.resource,
                        "prune".to_string(),
                        "--force".to_string(),
                        "--filter".to_string(),
                        "label=permanu.managed=true".to_string(),
                    ];
                    let _ = tokio::time::timeout(
                        spec.timeout,
                        tokio::process::Command::new("docker").args(&args).output(),
                    )
                    .await;
                }
            }
        }
        std::process::exit(0);
    });
    completed_text(command_id, "uninstall started")
}

async fn handle_swarm_stack_deploy_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match job_deployment::parse_swarm_deploy(payload) {
        Ok(payload) => payload,
        Err(err) => {
            return failed_text(command_id, &format!("invalid swarm deploy payload: {err}"))
        }
    };
    let stack_dir = match job_deployment::swarm_stack_dir(&payload.stack_name) {
        Ok(dir) => dir,
        Err(err) => return failed_text(command_id, &err),
    };
    if let Err(err) = materialize_swarm_stack(&stack_dir, &payload) {
        return failed_text(command_id, &format!("materialize swarm stack: {err}"));
    }
    let args = job_deployment::build_swarm_deploy_args(&payload, &stack_dir.to_string_lossy());
    run_simple_command(command_id, "docker", args, Duration::from_secs(300)).await
}

async fn handle_swarm_stack_remove_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let stack = match job_deployment::parse_swarm_remove(payload) {
        Ok(stack) => stack,
        Err(err) => {
            return failed_text(command_id, &format!("invalid swarm remove payload: {err}"))
        }
    };
    let args = match job_deployment::build_swarm_remove_args(&stack) {
        Ok(args) => args,
        Err(err) => return failed_text(command_id, &err),
    };
    run_simple_command(command_id, "docker", args, Duration::from_secs(120)).await
}

async fn handle_swarm_stack_status_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let stack = match job_deployment::parse_swarm_status(payload) {
        Ok(stack) => stack,
        Err(err) => {
            return failed_text(command_id, &format!("invalid swarm status payload: {err}"))
        }
    };
    let (services_args, tasks_args) = match job_deployment::build_swarm_status_args(&stack) {
        Ok(args) => args,
        Err(err) => return failed_text(command_id, &err),
    };
    let services = match run_program(
        "docker",
        services_args,
        Duration::from_secs(30),
        1024 * 1024,
    )
    .await
    {
        Ok(output) => output,
        Err(err) => return failed_text(command_id, &format!("swarm services: {err}")),
    };
    let tasks = match run_program("docker", tasks_args, Duration::from_secs(30), 1024 * 1024).await
    {
        Ok(output) => output,
        Err(err) => return failed_text(command_id, &format!("swarm tasks: {err}")),
    };
    completed_json(
        command_id,
        &json!({
            "stack": stack,
            "services": services,
            "tasks": tasks,
        }),
    )
    .unwrap_or_else(|err| failed_text(command_id, &format!("marshal: {err}")))
}

async fn handle_swarm_service_rollback_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let (stack, service) = match job_deployment::parse_swarm_rollback(payload) {
        Ok(parsed) => parsed,
        Err(err) => {
            return failed_text(
                command_id,
                &format!("invalid swarm rollback payload: {err}"),
            )
        }
    };
    let args = match job_deployment::build_swarm_rollback_args(&stack, &service) {
        Ok(args) => args,
        Err(err) => return failed_text(command_id, &err),
    };
    run_simple_command(command_id, "docker", args, Duration::from_secs(120)).await
}

fn command_result_from_dwaar_response(command_id: &str, response: AdminResponse) -> CommandResult {
    if response.status >= 400 {
        return failed_text(
            command_id,
            &format!(
                "dwaar returned {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body).trim()
            ),
        );
    }
    completed_bytes(command_id, response.body)
}

async fn run_spec(spec: &host_admin::CommandSpec) -> anyhow::Result<String> {
    run_program(
        &spec.program,
        spec.args.clone(),
        spec.timeout,
        spec.max_output_bytes,
    )
    .await
}

async fn run_simple_command(
    command_id: &str,
    program: &str,
    args: Vec<String>,
    timeout: Duration,
) -> CommandResult {
    match run_program(program, args, timeout, 1024 * 1024).await {
        Ok(output) => completed_text(command_id, output.trim()),
        Err(err) => failed_text(command_id, &err.to_string()),
    }
}

async fn run_program(
    program: &str,
    args: Vec<String>,
    timeout_duration: Duration,
    max_output_bytes: usize,
) -> anyhow::Result<String> {
    let output = tokio::time::timeout(
        timeout_duration,
        tokio::process::Command::new(program)
            .args(&args)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await
    .with_context(|| format!("{program} timed out"))?
    .with_context(|| format!("run {program}"))?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    if combined.len() > max_output_bytes {
        combined.truncate(max_output_bytes);
        combined.extend_from_slice(b"\n[output truncated]");
    }
    let text = String::from_utf8_lossy(&combined).trim().to_string();
    if !output.status.success() {
        anyhow::bail!("{} {} failed: {}", program, args.join(" "), text);
    }
    Ok(text)
}

fn materialize_swarm_stack(
    stack_dir: &Path,
    payload: &job_deployment::SwarmDeployPayload,
) -> anyhow::Result<()> {
    fs::create_dir_all(stack_dir).with_context(|| format!("mkdir {}", stack_dir.display()))?;
    atomic_write_string(
        &stack_dir.join("stack.yaml"),
        &payload.compose_content,
        0o644,
    )?;
    for (relative, content) in &payload.extra_files {
        let path = stack_dir.join(relative);
        if !path.starts_with(stack_dir) {
            anyhow::bail!("extra file escapes stack dir: {relative}");
        }
        atomic_write_string(&path, content, 0o644)?;
    }
    Ok(())
}

fn atomic_write_string(path: &Path, content: &str, mode: u32) -> anyhow::Result<()> {
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("path contains traversal: {}", path.display());
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing to write through symlink: {}", path.display());
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    if let Err(err) =
        std::io::Write::write_all(&mut file, content.as_bytes()).and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("write {}", tmp.display()));
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", tmp.display()))?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()));
    }
    Ok(())
}

fn write_backup(path: &Path, retention: usize) -> anyhow::Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    let backup = parent.join(format!(
        "Dwaarfile.bak.{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));
    fs::write(&backup, bytes).with_context(|| format!("write {}", backup.display()))?;
    prune_backups(parent, retention)?;
    Ok(())
}

fn prune_backups(parent: &Path, retention: usize) -> anyhow::Result<()> {
    let mut backups = Vec::new();
    for entry in fs::read_dir(parent).with_context(|| format!("read {}", parent.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("Dwaarfile.bak.") {
            backups.push(entry.path());
        }
    }
    backups.sort();
    while backups.len() > retention {
        let path = backups.remove(0);
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

fn docker_not_found(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

#[derive(Serialize)]
struct AgentPing {
    agent_time_nanos: i64,
    agent_version: String,
}

#[derive(Serialize)]
struct AgentStatus {
    agent_version: String,
    runtime: String,
    arch: String,
    uptime_seconds: i64,
    docker_reachable: bool,
    server_time_nanos: i64,
    rss_bytes: Option<i64>,
}

#[derive(Serialize)]
struct RestartQueued {
    message: String,
    scheduled_in_seconds: i64,
}

#[derive(Serialize)]
struct NetworkInspectContainer {
    container_id: String,
    container_name: String,
    ipv4_address: String,
    mac_address: String,
}

#[derive(Serialize)]
struct NetworkInspectResult {
    network_id: String,
    network_name: String,
    driver: String,
    containers: Vec<NetworkInspectContainer>,
}

fn completed_json(command_id: &str, value: &impl Serialize) -> Result<CommandResult> {
    Ok(CommandResult {
        command_id: command_id.to_string(),
        status: "completed".to_string(),
        output: serde_json::to_vec(value)?,
        is_final: true,
        timestamp: Some(now_timestamp()),
    })
}

fn queued_json(command_id: &str, value: &impl Serialize) -> Result<CommandResult> {
    Ok(CommandResult {
        command_id: command_id.to_string(),
        status: "queued".to_string(),
        output: serde_json::to_vec(value)?,
        is_final: true,
        timestamp: Some(now_timestamp()),
    })
}

fn completed_bytes(command_id: &str, output: Vec<u8>) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".to_string(),
        output,
        is_final: true,
        timestamp: Some(now_timestamp()),
    }
}

fn completed_text(command_id: &str, text: &str) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".to_string(),
        output: text.as_bytes().to_vec(),
        is_final: true,
        timestamp: Some(now_timestamp()),
    }
}

fn failed_text(command_id: &str, text: &str) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "failed".to_string(),
        output: text.as_bytes().to_vec(),
        is_final: true,
        timestamp: Some(now_timestamp()),
    }
}

fn cancelled_text(command_id: &str, text: &str) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "cancelled".to_string(),
        output: text.as_bytes().to_vec(),
        is_final: true,
        timestamp: Some(now_timestamp()),
    }
}

fn current_rss_bytes() -> Option<i64> {
    let raw = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            let kib = value.split_whitespace().next()?.parse::<i64>().ok()?;
            return Some(kib.saturating_mul(1024));
        }
    }
    None
}

async fn docker_reachable() -> bool {
    let Ok(docker) = docker_observe::docker_client() else {
        return false;
    };
    docker_observe::inspect_docker(&docker).await.reachable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_backs_off_until_cap() {
        assert_eq!(
            next_reconnect_delay(COMMAND_RECONNECT_INITIAL_DELAY),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_reconnect_delay(Duration::from_secs(16)),
            Duration::from_secs(30)
        );
        assert_eq!(
            next_reconnect_delay(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
    }
}
