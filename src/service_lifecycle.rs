use std::{collections::HashMap, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
    time::timeout,
};

use crate::{
    log_forwarder::{agent_log, redact_log_message},
    proto::agent::v1::{CommandResult, LogEntry},
    timeutil::now_timestamp,
};

const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DOCKER_OP_TIMEOUT: Duration = Duration::from_secs(30);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(60);
const LOG_STREAM_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const EXEC_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STREAM_LINE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
struct CreateServicePayload {
    container_name: String,
    image: String,
    port: i64,
    internal_port: i64,
    env: HashMap<String, String>,
    volumes: Vec<String>,
    network: String,
    restart_policy: String,
    health_check: String,
    resource_limits: ResourceLimits,
    exposed: bool,
    command: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ResourceLimits {
    #[serde(default)]
    memory: String,
    #[serde(default)]
    cpus: String,
}

#[derive(Clone, Debug)]
struct ContainerNamePayload {
    container_name: String,
    remove_volumes: bool,
}

#[derive(Clone, Debug)]
struct LogsPayload {
    container_name: String,
    tail: i64,
    follow: bool,
}

#[derive(Clone, Debug)]
struct WaitPayload {
    container_name: String,
    condition: String,
}

#[derive(Clone, Debug)]
struct ExecPayload {
    container_name: String,
    command: Vec<String>,
    clone_dir: String,
}

pub async fn handle_service_create(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_create_service_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let _ = send_running(&tx, command_id, "Pulling image and creating container...").await;
    if let Err(err) = run_streamed_docker(
        &["pull".to_string(), payload.image.clone()],
        None,
        IMAGE_PULL_TIMEOUT,
        &tx,
        command_id,
    )
    .await
    {
        return failed_text(command_id, &format!("failed to pull image: {err}"));
    }

    if !payload.network.is_empty() {
        if let Err(err) = ensure_network(&payload.network).await {
            return failed_text(command_id, &format!("failed to ensure network: {err}"));
        }
    }
    for volume in &payload.volumes {
        if let Some(source) = named_volume_source(volume) {
            if let Err(err) =
                run_docker_output(&["volume", "create", &source], DOCKER_OP_TIMEOUT).await
            {
                return failed_text(
                    command_id,
                    &format!("failed to create volume {source}: {err}"),
                );
            }
        }
    }

    let args = docker_create_args(&payload);
    let created = match run_command_output(
        "docker",
        &args,
        None,
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await
    {
        Ok(output) if output.status_success => output,
        Ok(output) => {
            return failed_text(
                command_id,
                &format!("failed to create container: {}", output.combined_string()),
            )
        }
        Err(err) => return failed_text(command_id, &format!("failed to create container: {err}")),
    };
    let container_id = String::from_utf8_lossy(&created.stdout).trim().to_string();
    if container_id.is_empty() {
        return failed_text(command_id, "failed to create container: empty container id");
    }
    if let Err(err) = run_docker_output(&["start", &container_id], DOCKER_OP_TIMEOUT).await {
        return failed_text(command_id, &format!("failed to start container: {err}"));
    }

    let _ = send_running(
        &tx,
        command_id,
        "Container started, waiting for health check...",
    )
    .await;
    if !payload.health_check.is_empty() {
        if let Err(err) = wait_for_container_healthy(&container_id, HEALTH_TIMEOUT).await {
            return failed_text(command_id, &format!("health check failed: {err}"));
        }
    }

    completed_text(command_id, &container_id)
}

pub async fn handle_service_stop(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_container_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let _ = run_docker_output(
        &["update", "--restart=no", &payload.container_name],
        DOCKER_OP_TIMEOUT,
    )
    .await;
    match run_docker_output(
        &["stop", "--time", "30", &payload.container_name],
        DOCKER_OP_TIMEOUT + Duration::from_secs(35),
    )
    .await
    {
        Ok(output) if output.status_success => completed_text(command_id, "stopped"),
        Ok(output) => failed_text(
            command_id,
            &format!("failed to stop: {}", output.combined_string()),
        ),
        Err(err) => failed_text(command_id, &format!("failed to stop: {err}")),
    }
}

pub async fn handle_service_start(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_container_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    match run_docker_output(&["start", &payload.container_name], DOCKER_OP_TIMEOUT).await {
        Ok(output) if output.status_success => {
            let _ = run_docker_output(
                &[
                    "update",
                    "--restart=unless-stopped",
                    &payload.container_name,
                ],
                DOCKER_OP_TIMEOUT,
            )
            .await;
            completed_text(command_id, "started")
        }
        Ok(output) => failed_text(
            command_id,
            &format!("failed to start: {}", output.combined_string()),
        ),
        Err(err) => failed_text(command_id, &format!("failed to start: {err}")),
    }
}

pub async fn handle_service_restart(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_container_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    match run_docker_output(
        &["restart", "--time", "30", &payload.container_name],
        DOCKER_OP_TIMEOUT + Duration::from_secs(35),
    )
    .await
    {
        Ok(output) if output.status_success => completed_text(command_id, "restarted"),
        Ok(output) => failed_text(
            command_id,
            &format!("failed to restart: {}", output.combined_string()),
        ),
        Err(err) => failed_text(command_id, &format!("failed to restart: {err}")),
    }
}

pub async fn handle_service_destroy(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_container_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let mut args = vec!["rm", "-f"];
    if payload.remove_volumes {
        args.push("-v");
    }
    args.push(&payload.container_name);
    match run_docker_output(&args, DOCKER_OP_TIMEOUT).await {
        Ok(output) if output.status_success => completed_text(command_id, "destroyed"),
        Ok(output) => failed_text(
            command_id,
            &format!("failed to destroy: {}", output.combined_string()),
        ),
        Err(err) => failed_text(command_id, &format!("failed to destroy: {err}")),
    }
}

pub async fn handle_service_logs(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_logs_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let mut args = vec![
        "logs".to_string(),
        "--tail".to_string(),
        payload.tail.to_string(),
    ];
    if payload.follow {
        args.push("-f".to_string());
    }
    args.push(payload.container_name);
    match run_streamed_docker(&args, None, LOG_STREAM_TIMEOUT, &tx, command_id).await {
        Ok(()) => completed_text(command_id, "log stream ended"),
        Err(err) => failed_text(command_id, &format!("service logs failed: {err}")),
    }
}

#[allow(dead_code)]
fn service_log_entry_for_forwarding(
    container_name: &str,
    stream: &str,
    line: impl AsRef<str>,
) -> LogEntry {
    let redacted = redact_log_message(line.as_ref());
    let mut fields = HashMap::new();
    fields.insert("source_type".to_string(), "service".to_string());
    fields.insert("container_name".to_string(), container_name.to_string());
    fields.insert("stream".to_string(), stream.to_string());
    fields.insert("ingest_status".to_string(), "stream_scaffold".to_string());
    fields.insert(
        "redaction_status".to_string(),
        if redacted.was_redacted {
            "redacted".to_string()
        } else {
            "none".to_string()
        },
    );

    let level = if stream == "stderr" { "error" } else { "info" };
    let mut entry = agent_log(level, redacted.message, fields);
    entry.source = format!("service:{container_name}");
    entry
}

fn redact_service_stream_line(line: &str) -> String {
    let had_newline = line.ends_with('\n');
    let had_carriage = line.ends_with("\r\n");
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut redacted = redact_log_message(trimmed).message;
    if had_carriage {
        redacted.push_str("\r\n");
    } else if had_newline {
        redacted.push('\n');
    }
    redacted
}

pub async fn handle_wait_for_healthy(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_wait_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let inspect = match inspect_container(&payload.container_name).await {
        Ok(inspect) => inspect,
        Err(err) => {
            return completed_json(
                command_id,
                &WaitResult {
                    healthy: false,
                    running: false,
                    message: format!("container not found: {err}"),
                },
            )
        }
    };
    completed_json(
        command_id,
        &wait_result_from_inspect(&inspect, &payload.condition),
    )
}

pub async fn handle_exec(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_exec_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid exec payload: {err}")),
    };
    if !payload.clone_dir.is_empty() {
        return cleanup_build_dir(command_id, &payload.clone_dir);
    }
    let mut args = vec!["exec".to_string(), payload.container_name];
    args.extend(payload.command);
    match run_streamed_docker(&args, None, EXEC_TIMEOUT, &tx, command_id).await {
        Ok(()) => completed_text(command_id, "exit 0"),
        Err(err) => failed_text(command_id, &err.to_string()),
    }
}

fn parse_create_service_payload(payload: &[u8]) -> Result<CreateServicePayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        image: String,
        #[serde(default)]
        port: i64,
        #[serde(default)]
        internal_port: i64,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default)]
        volumes: Vec<String>,
        #[serde(default)]
        network: String,
        #[serde(default)]
        restart_policy: String,
        #[serde(default)]
        health_check: String,
        #[serde(default)]
        resource_limits: ResourceLimits,
        #[serde(default)]
        exposed: bool,
        #[serde(default)]
        command: Vec<String>,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_docker_resource_name(payload.container_name.trim(), "container_name")?;
    if payload.image.trim().is_empty() {
        anyhow::bail!("image is required");
    }
    validate_no_control(payload.image.trim(), "image")?;
    if !payload.network.trim().is_empty() {
        validate_docker_resource_name(payload.network.trim(), "network")?;
    }
    for key in payload.env.keys() {
        validate_env_key(key)?;
    }
    for volume in &payload.volumes {
        validate_no_control(volume, "volume")?;
    }
    for arg in &payload.command {
        validate_no_nul(arg, "command")?;
    }
    Ok(CreateServicePayload {
        container_name: payload.container_name.trim().to_string(),
        image: payload.image.trim().to_string(),
        port: payload.port,
        internal_port: payload.internal_port,
        env: payload.env,
        volumes: payload.volumes,
        network: payload.network.trim().to_string(),
        restart_policy: payload.restart_policy,
        health_check: payload.health_check,
        resource_limits: payload.resource_limits,
        exposed: payload.exposed,
        command: payload.command,
    })
}

fn parse_container_payload(payload: &[u8]) -> Result<ContainerNamePayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        remove_volumes: bool,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_docker_resource_name(payload.container_name.trim(), "container_name")?;
    Ok(ContainerNamePayload {
        container_name: payload.container_name.trim().to_string(),
        remove_volumes: payload.remove_volumes,
    })
}

fn parse_logs_payload(payload: &[u8]) -> Result<LogsPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        tail: i64,
        #[serde(default)]
        follow: bool,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_docker_resource_name(payload.container_name.trim(), "container_name")?;
    Ok(LogsPayload {
        container_name: payload.container_name.trim().to_string(),
        tail: if payload.tail <= 0 {
            100
        } else {
            payload.tail.min(10_000)
        },
        follow: payload.follow,
    })
}

fn parse_wait_payload(payload: &[u8]) -> Result<WaitPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        condition: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_docker_resource_name(payload.container_name.trim(), "container_name")?;
    if payload.condition != "healthy" && payload.condition != "started" {
        anyhow::bail!("condition must be 'healthy' or 'started'");
    }
    Ok(WaitPayload {
        container_name: payload.container_name.trim().to_string(),
        condition: payload.condition,
    })
}

fn parse_exec_payload(payload: &[u8]) -> Result<ExecPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        command: Vec<String>,
        #[serde(default)]
        clone_dir: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    if payload.clone_dir.trim().is_empty() {
        validate_docker_resource_name(payload.container_name.trim(), "container_name")?;
    } else {
        validate_build_dir(payload.clone_dir.trim())?;
    }
    let command = if payload.command.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        payload.command
    };
    for arg in &command {
        validate_no_nul(arg, "command")?;
    }
    Ok(ExecPayload {
        container_name: payload.container_name.trim().to_string(),
        command,
        clone_dir: payload.clone_dir.trim().to_string(),
    })
}

fn docker_create_args(payload: &CreateServicePayload) -> Vec<String> {
    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        payload.container_name.clone(),
    ];
    if !payload.network.is_empty() {
        args.extend(["--network".to_string(), payload.network.clone()]);
    }
    args.extend([
        "--restart".to_string(),
        restart_policy(&payload.restart_policy).to_string(),
    ]);
    if !payload.resource_limits.memory.trim().is_empty() {
        args.extend([
            "--memory".to_string(),
            payload.resource_limits.memory.trim().to_string(),
        ]);
    }
    if !payload.resource_limits.cpus.trim().is_empty() {
        args.extend([
            "--cpus".to_string(),
            payload.resource_limits.cpus.trim().to_string(),
        ]);
    }
    let internal_port = if payload.internal_port > 0 {
        payload.internal_port
    } else {
        payload.port
    };
    if internal_port > 0 {
        args.extend(["--expose".to_string(), format!("{internal_port}/tcp")]);
        if payload.exposed && payload.port > 0 {
            args.extend([
                "-p".to_string(),
                format!("{}:{internal_port}", payload.port),
            ]);
        }
    }
    for (key, value) in &payload.env {
        args.extend(["-e".to_string(), format!("{key}={value}")]);
    }
    for volume in &payload.volumes {
        args.extend(["-v".to_string(), volume.clone()]);
    }
    if !payload.health_check.is_empty() {
        args.extend([
            "--health-cmd".to_string(),
            payload.health_check.clone(),
            "--health-interval".to_string(),
            "10s".to_string(),
            "--health-timeout".to_string(),
            "5s".to_string(),
            "--health-retries".to_string(),
            "3".to_string(),
        ]);
    }
    args.push(payload.image.clone());
    args.extend(payload.command.iter().cloned());
    args
}

fn restart_policy(input: &str) -> &'static str {
    if input == "no" {
        "no"
    } else {
        "unless-stopped"
    }
}

fn named_volume_source(mount: &str) -> Option<String> {
    let (source, _) = mount.split_once(':')?;
    if source.is_empty()
        || source.starts_with('/')
        || source.starts_with('.')
        || source.starts_with('~')
        || source.contains('\\')
    {
        return None;
    }
    Some(source.to_string())
}

async fn ensure_network(network: &str) -> Result<()> {
    let inspect = run_docker_output(&["network", "inspect", network], DOCKER_OP_TIMEOUT).await;
    if inspect.is_ok_and(|output| output.status_success) {
        return Ok(());
    }
    let output = run_docker_output(
        &["network", "create", "--driver", "bridge", network],
        DOCKER_OP_TIMEOUT,
    )
    .await?;
    if output.status_success {
        Ok(())
    } else {
        anyhow::bail!("{}", output.combined_string())
    }
}

async fn wait_for_container_healthy(container: &str, timeout_duration: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout_duration;
    while tokio::time::Instant::now() < deadline {
        let inspect = inspect_container(container).await?;
        let state = inspect.state.as_ref().context("container has no state")?;
        if state
            .health
            .as_ref()
            .is_some_and(|health| health.status == "healthy")
        {
            return Ok(());
        }
        if state.status == "exited" || !state.running {
            anyhow::bail!("container exited with code {}", state.exit_code);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    anyhow::bail!("health check timed out after {:?}", timeout_duration)
}

async fn inspect_container(container: &str) -> Result<InspectContainer> {
    let output = run_docker_output(&["inspect", container], DOCKER_OP_TIMEOUT).await?;
    if !output.status_success {
        anyhow::bail!("{}", output.combined_string());
    }
    let mut containers: Vec<InspectContainer> = serde_json::from_slice(&output.stdout)?;
    containers.pop().context("empty docker inspect response")
}

fn wait_result_from_inspect(inspect: &InspectContainer, condition: &str) -> WaitResult {
    let Some(state) = inspect.state.as_ref() else {
        return WaitResult {
            healthy: false,
            running: false,
            message: "container has no state".to_string(),
        };
    };
    if condition == "started" {
        return WaitResult {
            healthy: state.running,
            running: state.running,
            message: if state.running {
                "container is running"
            } else {
                "container is not running"
            }
            .to_string(),
        };
    }
    if !state.running {
        return WaitResult {
            healthy: false,
            running: false,
            message: "container is not running".to_string(),
        };
    }
    if let Some(health) = state.health.as_ref() {
        return WaitResult {
            healthy: health.status == "healthy",
            running: true,
            message: format!("healthcheck status: {}", health.status),
        };
    }
    WaitResult {
        healthy: true,
        running: true,
        message: "container is running (no healthcheck)".to_string(),
    }
}

fn cleanup_build_dir(command_id: &str, clone_dir: &str) -> CommandResult {
    if let Err(err) = validate_build_dir(clone_dir) {
        return failed_text(command_id, &err.to_string());
    }
    match std::fs::remove_dir_all(clone_dir) {
        Ok(()) => completed_text(command_id, &format!("removed build dir {clone_dir}")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            completed_text(command_id, &format!("removed build dir {clone_dir}"))
        }
        Err(err) => failed_text(command_id, &format!("failed to remove build dir: {err}")),
    }
}

fn validate_build_dir(path: &str) -> Result<()> {
    if !path.starts_with("/tmp/deploy-build-") {
        anyhow::bail!("refusing to remove {path}: not a deploy build directory");
    }
    Ok(())
}

fn validate_docker_resource_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} is required");
    }
    if value
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n' | b'/' | b'\\' | b'\0'))
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}

fn validate_env_key(value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        anyhow::bail!("invalid env var key {value:?}");
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

fn validate_no_nul(value: &str, label: &str) -> Result<()> {
    if value.contains('\0') {
        anyhow::bail!("{label} contains NUL");
    }
    Ok(())
}

async fn run_docker_output(args: &[&str], timeout_duration: Duration) -> Result<CommandOutput> {
    let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    run_command_output(
        "docker",
        &args,
        None,
        timeout_duration,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await
}

struct CommandOutput {
    status_success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CommandOutput {
    fn combined_string(&self) -> String {
        let mut combined = self.stdout.clone();
        combined.extend_from_slice(&self.stderr);
        String::from_utf8_lossy(&combined).trim().to_string()
    }
}

async fn run_command_output(
    program: &str,
    args: &[String],
    dir: Option<&Path>,
    timeout_duration: Duration,
    max_bytes: usize,
) -> Result<CommandOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let output = timeout(timeout_duration, command.output())
        .await
        .with_context(|| format!("{program} timed out after {}s", timeout_duration.as_secs()))?
        .with_context(|| format!("run {program}"))?;
    let mut stdout = output.stdout;
    let mut stderr = output.stderr;
    if stdout.len() > max_bytes {
        stdout.truncate(max_bytes);
    }
    if stderr.len() > max_bytes {
        stderr.truncate(max_bytes);
    }
    Ok(CommandOutput {
        status_success: output.status.success(),
        stdout,
        stderr,
    })
}

async fn run_streamed_docker(
    args: &[String],
    dir: Option<&Path>,
    timeout_duration: Duration,
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
) -> Result<()> {
    let mut command = Command::new("docker");
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let mut child = command.spawn().context("spawn docker")?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_task = stdout
        .map(|reader| tokio::spawn(stream_reader(reader, tx.clone(), command_id.to_string())));
    let stderr_task = stderr
        .map(|reader| tokio::spawn(stream_reader(reader, tx.clone(), command_id.to_string())));
    let status = match timeout(timeout_duration, child.wait()).await {
        Ok(status) => status.context("wait for docker")?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("docker timed out after {}s", timeout_duration.as_secs());
        }
    };
    let mut tail = Vec::new();
    if let Some(task) = stdout_task {
        tail.extend(task.await.unwrap_or_default());
    }
    if let Some(task) = stderr_task {
        tail.extend(task.await.unwrap_or_default());
    }
    if status.success() {
        Ok(())
    } else if tail.is_empty() {
        anyhow::bail!("docker exited with {status}")
    } else {
        anyhow::bail!("{}", tail.join(" | "))
    }
}

async fn stream_reader<R>(
    reader: R,
    tx: mpsc::Sender<CommandResult>,
    command_id: String,
) -> Vec<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut tail = Vec::new();
    loop {
        line.clear();
        let read = match reader.read_line(&mut line).await {
            Ok(read) => read,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        if line.len() > MAX_STREAM_LINE_BYTES {
            line.truncate(MAX_STREAM_LINE_BYTES);
            line.push_str("...[truncated]\n");
        }
        let redacted_line = redact_service_stream_line(&line);
        if tail.len() == 10 {
            tail.remove(0);
        }
        tail.push(redacted_line.trim().to_string());
        if tx
            .send(CommandResult {
                command_id: command_id.clone(),
                status: "running".to_string(),
                output: redacted_line.as_bytes().to_vec(),
                is_final: false,
                timestamp: Some(now_timestamp()),
            })
            .await
            .is_err()
        {
            break;
        }
    }
    tail
}

async fn send_running(
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
    text: &str,
) -> Result<()> {
    let mut output = text.as_bytes().to_vec();
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    tx.send(CommandResult {
        command_id: command_id.to_string(),
        status: "running".to_string(),
        output,
        is_final: false,
        timestamp: Some(now_timestamp()),
    })
    .await
    .context("send running result")
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

fn completed_json(command_id: &str, value: &impl Serialize) -> CommandResult {
    match serde_json::to_vec(value) {
        Ok(output) => CommandResult {
            command_id: command_id.to_string(),
            status: "completed".to_string(),
            output,
            is_final: true,
            timestamp: Some(now_timestamp()),
        },
        Err(err) => failed_text(command_id, &format!("marshal response: {err}")),
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

#[derive(Debug, Deserialize)]
struct InspectContainer {
    #[serde(rename = "State", default)]
    state: Option<InspectState>,
}

#[derive(Debug, Deserialize)]
struct InspectState {
    #[serde(rename = "Running", default)]
    running: bool,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "ExitCode", default)]
    exit_code: i64,
    #[serde(rename = "Health", default)]
    health: Option<InspectHealth>,
}

#[derive(Debug, Deserialize)]
struct InspectHealth {
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Serialize)]
struct WaitResult {
    healthy: bool,
    running: bool,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_service_requires_container_name() {
        let err = parse_create_service_payload(br#"{"image":"postgres:16"}"#).unwrap_err();

        assert!(err.to_string().contains("container_name is required"));
    }

    #[test]
    fn create_args_include_healthcheck_and_port_binding() {
        let payload = parse_create_service_payload(
            br#"{"container_name":"deploy-service-db-1","image":"postgres:16","port":5432,"internal_port":5432,"exposed":true,"health_check":"pg_isready","network":"deploy-net"}"#,
        )
        .expect("parse service payload");

        let args = docker_create_args(&payload);

        assert!(args.windows(2).any(|pair| pair == ["-p", "5432:5432"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--health-cmd", "pg_isready"]));
    }

    #[test]
    fn service_logs_caps_tail() {
        let payload =
            parse_logs_payload(br#"{"container_name":"deploy-service-db-1","tail":999999}"#)
                .expect("parse logs payload");

        assert_eq!(payload.tail, 10_000);
    }

    #[test]
    fn wait_for_healthy_rejects_invalid_condition() {
        let err =
            parse_wait_payload(br#"{"container_name":"deploy-service-db-1","condition":"ready"}"#)
                .unwrap_err();

        assert!(err
            .to_string()
            .contains("condition must be 'healthy' or 'started'"));
    }

    #[test]
    fn exec_payload_defaults_command_to_shell() {
        let payload =
            parse_exec_payload(br#"{"container_name":"deploy-service-db-1"}"#).expect("parse exec");

        assert_eq!(payload.command, vec!["/bin/sh"]);
    }

    #[test]
    fn service_log_line_converts_to_redacted_log_entry_for_forwarding() {
        let entry = service_log_entry_for_forwarding(
            "deploy-svc-postgres-a1",
            "stderr",
            "Authorization: Bearer raw-token password=hunter2",
        );

        assert_eq!(entry.source, "service:deploy-svc-postgres-a1");
        assert_eq!(entry.level, "error");
        assert!(!entry.message.contains("raw-token"));
        assert!(!entry.message.contains("hunter2"));
        assert_eq!(
            entry.fields.get("source_type").map(String::as_str),
            Some("service")
        );
        assert_eq!(
            entry.fields.get("container_name").map(String::as_str),
            Some("deploy-svc-postgres-a1")
        );
        assert_eq!(
            entry.fields.get("stream").map(String::as_str),
            Some("stderr")
        );
        assert_eq!(
            entry.fields.get("redaction_status").map(String::as_str),
            Some("redacted")
        );
    }

    #[test]
    fn service_stream_line_redacts_secrets_without_changing_newline_shape() {
        let line = redact_service_stream_line("token=raw-secret ok\n");

        assert_eq!(line, "token=[REDACTED] ok\n");
    }
}
