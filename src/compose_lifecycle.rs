use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
    time::timeout,
};
use tracing::warn;

use crate::{proto::agent::v1::CommandResult, timeutil::now_timestamp};

const DEPLOYMENT_BASE_DIR: &str = "/opt/permanu-agent/deployments";
const DOCKER_OP_TIMEOUT: Duration = Duration::from_secs(30);
const COMPOSE_UP_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const COMPOSE_LOG_STREAM_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STREAM_LINE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
struct ComposeUpPayload {
    project_name: String,
    compose_content: String,
    extra_files: HashMap<String, String>,
    restore_backup: bool,
}

#[derive(Clone, Debug)]
struct ComposeDownPayload {
    project_name: String,
    remove_volumes: bool,
    remove_images: bool,
}

#[derive(Clone, Debug)]
struct ComposeProjectPayload {
    project_name: String,
}

#[derive(Clone, Debug)]
struct ComposeLogsPayload {
    project_name: String,
    tail: i64,
    follow: bool,
}

pub async fn handle_compose_up(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_compose_up_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let project_dir = match deployment_project_dir(&payload.project_name) {
        Ok(dir) => dir,
        Err(err) => return failed_text(command_id, &err.to_string()),
    };

    let _ = send_running(&tx, command_id, "ensuring deploy-net network...").await;
    if let Err(err) = ensure_deploy_net().await {
        return failed_text(
            command_id,
            &format!("failed to ensure deploy-net network: {err}"),
        );
    }

    if !payload.compose_content.is_empty() {
        let _ = send_running(&tx, command_id, "writing compose file...").await;
        if project_dir.exists() {
            let backup_dir = backup_dir_for(&project_dir);
            let _ = std::fs::remove_dir_all(&backup_dir);
            if let Err(err) = copy_dir(&project_dir, &backup_dir) {
                return failed_text(
                    command_id,
                    &format!("failed to backup deployment for rollback: {err}"),
                );
            }
        }
        if let Err(err) = write_compose_file(&project_dir, &payload.compose_content) {
            return failed_text(command_id, &format!("failed to write compose file: {err}"));
        }
        if let Err(err) = write_extra_files(&project_dir, &payload.extra_files) {
            return failed_text(command_id, &format!("failed to write extra files: {err}"));
        }
    } else {
        if payload.restore_backup {
            let backup_dir = backup_dir_for(&project_dir);
            if !backup_dir.exists() {
                return failed_text(command_id, "no deployment backup found for rollback");
            }
            let _ = std::fs::remove_dir_all(&project_dir);
            if let Err(err) = std::fs::rename(&backup_dir, &project_dir) {
                return failed_text(
                    command_id,
                    &format!("failed to restore deployment backup: {err}"),
                );
            }
            let _ = send_running(&tx, command_id, "restored previous deployment from backup").await;
        }
        if !project_dir.join("compose.yaml").is_file() {
            return failed_text(
                command_id,
                "no compose file found for project (was it deployed?)",
            );
        }
    }

    let _ = send_running(&tx, command_id, "pulling images...").await;
    if let Err(err) = run_compose_output(&project_dir, &["pull"], DOCKER_OP_TIMEOUT).await {
        warn!(project = %payload.project_name, error = ?err, "compose pull failed, continuing");
        let _ = send_running(
            &tx,
            command_id,
            &format!("pull warning (continuing): {err}"),
        )
        .await;
    }

    let _ = send_running(&tx, command_id, "starting services...").await;
    let up =
        run_compose_with_transient_retry(&project_dir, &["up", "-d", "--remove-orphans"]).await;
    let out = match up {
        Ok(out) => out,
        Err(err) => return failed_text(command_id, &format!("compose up failed: {err}")),
    };

    tokio::spawn(async {
        let _ = run_docker_output(&["image", "prune", "-f"], DOCKER_OP_TIMEOUT).await;
    });

    completed_text(
        command_id,
        &format!("service started: {}\n{}", payload.project_name, out.trim()),
    )
}

pub async fn handle_compose_down(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_compose_down_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let project_dir = match deployment_project_dir(&payload.project_name) {
        Ok(dir) => dir,
        Err(err) => return failed_text(command_id, &err.to_string()),
    };

    let args = compose_down_subcommand_args(&payload);
    let out = match run_compose_output(&project_dir, &args, DOCKER_OP_TIMEOUT).await {
        Ok(out) => out,
        Err(err) => {
            warn!(project = %payload.project_name, error = ?err, "compose down failed, attempting force cleanup");
            force_cleanup_by_project(
                &payload.project_name,
                payload.remove_volumes,
                payload.remove_images,
            )
            .await;
            String::new()
        }
    };

    cleanup_deployment_dir(&payload.project_name);
    let _ = send_running(&tx, command_id, "deployment directory removed").await;
    tokio::spawn(async {
        let _ = run_docker_output(&["image", "prune", "-f"], DOCKER_OP_TIMEOUT).await;
    });

    completed_text(
        command_id,
        &format!("service stopped: {}\n{}", payload.project_name, out.trim()),
    )
}

pub async fn handle_compose_restart(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_compose_project_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let project_dir = match deployment_project_dir(&payload.project_name) {
        Ok(dir) => dir,
        Err(err) => return failed_text(command_id, &err.to_string()),
    };

    match run_compose_output(&project_dir, &["restart"], DOCKER_OP_TIMEOUT).await {
        Ok(out) => completed_text(
            command_id,
            &format!(
                "service restarted: {}\n{}",
                payload.project_name,
                out.trim()
            ),
        ),
        Err(err) => failed_text(command_id, &format!("compose restart failed: {err}")),
    }
}

pub async fn handle_compose_logs(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_compose_logs_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let project_dir = match deployment_project_dir(&payload.project_name) {
        Ok(dir) => dir,
        Err(err) => return failed_text(command_id, &err.to_string()),
    };
    if !project_dir.join("compose.yaml").is_file() {
        return failed_text(
            command_id,
            "no compose file found for project (was it deployed?)",
        );
    }

    let mut sub = vec![
        "logs".to_string(),
        "--tail".to_string(),
        payload.tail.to_string(),
    ];
    if payload.follow {
        sub.push("--follow".to_string());
    }
    let args = compose_args(&project_dir, &sub);
    match run_streamed_docker(
        &args,
        Some(&project_dir),
        COMPOSE_LOG_STREAM_TIMEOUT,
        &tx,
        command_id,
    )
    .await
    {
        Ok(()) => completed_text(command_id, "log stream ended"),
        Err(err) => failed_text(command_id, &format!("compose logs failed: {err}")),
    }
}

fn parse_compose_up_payload(payload: &[u8]) -> Result<ComposeUpPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        project_name: String,
        #[serde(default)]
        compose_content: String,
        #[serde(default)]
        extra_files: HashMap<String, String>,
        #[serde(default)]
        restore_backup: bool,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_project_name(payload.project_name.trim())?;
    Ok(ComposeUpPayload {
        project_name: payload.project_name.trim().to_string(),
        compose_content: payload.compose_content,
        extra_files: payload.extra_files,
        restore_backup: payload.restore_backup,
    })
}

fn parse_compose_down_payload(payload: &[u8]) -> Result<ComposeDownPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        project_name: String,
        #[serde(default)]
        remove_volumes: bool,
        #[serde(default)]
        remove_images: bool,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_project_name(payload.project_name.trim())?;
    Ok(ComposeDownPayload {
        project_name: payload.project_name.trim().to_string(),
        remove_volumes: payload.remove_volumes,
        remove_images: payload.remove_images,
    })
}

fn parse_compose_project_payload(payload: &[u8]) -> Result<ComposeProjectPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        project_name: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_project_name(payload.project_name.trim())?;
    Ok(ComposeProjectPayload {
        project_name: payload.project_name.trim().to_string(),
    })
}

fn parse_compose_logs_payload(payload: &[u8]) -> Result<ComposeLogsPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        project_name: String,
        #[serde(default)]
        tail: i64,
        #[serde(default)]
        follow: bool,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_project_name(payload.project_name.trim())?;
    let tail = if payload.tail <= 0 {
        100
    } else {
        payload.tail.min(10_000)
    };
    Ok(ComposeLogsPayload {
        project_name: payload.project_name.trim().to_string(),
        tail,
        follow: payload.follow,
    })
}

fn deployment_project_dir(project_name: &str) -> Result<PathBuf> {
    validate_project_name(project_name)?;
    let base = PathBuf::from(DEPLOYMENT_BASE_DIR);
    let dir = base.join(project_name);
    if !path_within_root(&dir, &base) {
        anyhow::bail!("deployment dir escapes deployment root");
    }
    Ok(dir)
}

fn deployment_extra_file_path(project_dir: &Path, rel_path: &str) -> Result<PathBuf> {
    if rel_path.is_empty() || rel_path == "." || rel_path == ".." {
        anyhow::bail!("invalid extra file path {rel_path:?}");
    }
    if Path::new(rel_path).is_absolute() || rel_path.contains('\\') {
        anyhow::bail!("invalid extra file path {rel_path:?}");
    }
    let clean = Path::new(rel_path);
    if clean.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        anyhow::bail!("extra file path escapes deployment dir");
    }
    let full = project_dir.join(clean);
    if !path_within_root(&full, project_dir) {
        anyhow::bail!("extra file path escapes deployment dir");
    }
    Ok(full)
}

fn compose_args(project_dir: &Path, subcommand: &[impl AsRef<str>]) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        project_dir
            .join("compose.yaml")
            .to_string_lossy()
            .to_string(),
    ];
    args.extend(subcommand.iter().map(|arg| arg.as_ref().to_string()));
    args
}

fn compose_down_subcommand_args(payload: &ComposeDownPayload) -> Vec<String> {
    let mut args = vec!["down".to_string()];
    if payload.remove_volumes {
        args.push("-v".to_string());
    }
    if payload.remove_images {
        args.extend(["--rmi".to_string(), "all".to_string()]);
    }
    args
}

fn validate_project_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.len() > 128 {
        anyhow::bail!("invalid compose project name {name:?}");
    }
    let mut chars = name.chars();
    if !chars.next().is_some_and(|ch| ch.is_ascii_alphanumeric()) {
        anyhow::bail!("invalid compose project name {name:?}");
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')) {
        anyhow::bail!("invalid compose project name {name:?}");
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        anyhow::bail!("invalid compose project name {name:?}");
    }
    Ok(())
}

fn path_within_root(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn backup_dir_for(project_dir: &Path) -> PathBuf {
    let mut raw = project_dir.as_os_str().to_os_string();
    raw.push(".bak");
    PathBuf::from(raw)
}

fn write_compose_file(project_dir: &Path, compose_content: &str) -> Result<()> {
    std::fs::create_dir_all(project_dir)
        .with_context(|| format!("create {}", project_dir.display()))?;
    let path = project_dir.join("compose.yaml");
    std::fs::write(&path, compose_content).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn write_extra_files(project_dir: &Path, extra_files: &HashMap<String, String>) -> Result<()> {
    for (rel_path, content) in extra_files {
        let full_path = deployment_extra_file_path(project_dir, rel_path)?;
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(&full_path, content)
            .with_context(|| format!("write {}", full_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if rel_path.ends_with(".sh") {
                0o755
            } else {
                0o644
            };
            std::fs::set_permissions(&full_path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            std::fs::create_dir_all(&to)?;
            copy_dir(&from, &to)?;
        } else if file_type.is_file() {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn cleanup_deployment_dir(project_name: &str) {
    if let Ok(dir) = deployment_project_dir(project_name) {
        if let Err(err) = std::fs::remove_dir_all(&dir) {
            warn!(dir = %dir.display(), error = ?err, "failed to cleanup deployment dir");
        }
    }
}

async fn ensure_deploy_net() -> Result<()> {
    let inspect = run_docker_output(&["network", "inspect", "deploy-net"], DOCKER_OP_TIMEOUT).await;
    if inspect.is_ok_and(|output| output.status_success) {
        return Ok(());
    }
    let output = run_docker_output(
        &["network", "create", "--driver", "bridge", "deploy-net"],
        DOCKER_OP_TIMEOUT,
    )
    .await?;
    if output.status_success {
        Ok(())
    } else {
        anyhow::bail!("{}", output.combined_string())
    }
}

async fn run_compose_with_transient_retry(
    project_dir: &Path,
    subcommand: &[&str],
) -> Result<String> {
    let mut last = None;
    for attempt in 1..=3 {
        match run_compose_output(project_dir, subcommand, COMPOSE_UP_TIMEOUT).await {
            Ok(out) => return Ok(out),
            Err(err) if attempt < 3 && is_transient_compose_failure(&err.to_string()) => {
                last = Some(err);
                tokio::time::sleep(Duration::from_secs(attempt * 2)).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("compose up failed")))
}

fn is_transient_compose_failure(text: &str) -> bool {
    text.to_ascii_lowercase()
        .contains("lease does not exist: not found")
}

async fn run_compose_output(
    project_dir: &Path,
    subcommand: &[impl AsRef<str>],
    timeout_duration: Duration,
) -> Result<String> {
    let args = compose_args(project_dir, subcommand);
    let output = run_command_output(
        "docker",
        &args,
        Some(project_dir),
        timeout_duration,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await?;
    if output.status_success {
        Ok(output.combined_string())
    } else {
        anyhow::bail!("{}", output.combined_string())
    }
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

async fn force_cleanup_by_project(project_name: &str, remove_volumes: bool, remove_images: bool) {
    if validate_project_name(project_name).is_err() {
        return;
    }
    let container_ids = docker_lines(&[
        "ps",
        "-a",
        "--filter",
        &format!("label=com.docker.compose.project={project_name}"),
        "--format",
        "{{.ID}}",
    ])
    .await
    .unwrap_or_default();
    if !container_ids.is_empty() {
        let mut args = vec!["rm".to_string(), "-f".to_string()];
        args.extend(container_ids);
        let _ = run_command_output(
            "docker",
            &args,
            None,
            DOCKER_OP_TIMEOUT,
            MAX_COMMAND_OUTPUT_BYTES,
        )
        .await;
    }

    for network in docker_lines(&[
        "network",
        "ls",
        "--filter",
        &format!("name={project_name}"),
        "--format",
        "{{.ID}}",
    ])
    .await
    .unwrap_or_default()
    {
        let _ = run_docker_output(&["network", "rm", &network], DOCKER_OP_TIMEOUT).await;
    }

    if remove_volumes {
        for volume in docker_lines(&[
            "volume",
            "ls",
            "--filter",
            &format!("name={project_name}"),
            "--format",
            "{{.Name}}",
        ])
        .await
        .unwrap_or_default()
        {
            let _ = run_docker_output(&["volume", "rm", "-f", &volume], DOCKER_OP_TIMEOUT).await;
        }
    }

    if remove_images {
        remove_project_images(project_name).await;
    }
}

async fn remove_project_images(project_name: &str) {
    let images = docker_lines(&[
        "ps",
        "-a",
        "--filter",
        &format!("label=com.docker.compose.project={project_name}"),
        "--format",
        "{{.Image}}",
    ])
    .await
    .unwrap_or_default();
    let mut seen = HashSet::new();
    for image in images {
        if image.is_empty() || !seen.insert(image.clone()) {
            continue;
        }
        let _ = run_docker_output(&["image", "rm", "-f", &image], DOCKER_OP_TIMEOUT).await;
    }
}

async fn docker_lines(args: &[&str]) -> Result<Vec<String>> {
    let output = run_docker_output(args, DOCKER_OP_TIMEOUT).await?;
    if !output.status_success {
        anyhow::bail!("{}", output.combined_string());
    }
    Ok(output
        .combined_string()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
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
        if tail.len() == 10 {
            tail.remove(0);
        }
        tail.push(line.trim().to_string());
        if tx
            .send(CommandResult {
                command_id: command_id.clone(),
                status: "running".to_string(),
                output: line.as_bytes().to_vec(),
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

fn failed_text(command_id: &str, text: &str) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "failed".to_string(),
        output: text.as_bytes().to_vec(),
        is_final: true,
        timestamp: Some(now_timestamp()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_name_rejects_path_traversal() {
        let err = deployment_project_dir("../bad").unwrap_err();

        assert!(err.to_string().contains("invalid compose project name"));
    }

    #[test]
    fn project_dir_stays_under_deployment_root() {
        let dir = deployment_project_dir("demo_stack-1").expect("project dir");

        assert_eq!(
            dir,
            std::path::PathBuf::from("/opt/permanu-agent/deployments/demo_stack-1")
        );
    }

    #[test]
    fn extra_file_path_rejects_escape() {
        let dir = std::path::Path::new("/opt/permanu-agent/deployments/demo");
        let err = deployment_extra_file_path(dir, "../secrets.env").unwrap_err();

        assert!(err
            .to_string()
            .contains("extra file path escapes deployment dir"));
    }

    #[test]
    fn compose_args_include_file_before_subcommand() {
        let args = compose_args(
            std::path::Path::new("/opt/permanu-agent/deployments/demo"),
            &["up", "-d"],
        );

        assert_eq!(
            args,
            vec![
                "compose",
                "-f",
                "/opt/permanu-agent/deployments/demo/compose.yaml",
                "up",
                "-d"
            ]
        );
    }

    #[test]
    fn compose_down_args_include_optional_volume_and_image_cleanup() {
        let payload = parse_compose_down_payload(
            br#"{"project_name":"demo","remove_volumes":true,"remove_images":true}"#,
        )
        .expect("parse down payload");

        assert_eq!(
            compose_down_subcommand_args(&payload),
            vec!["down", "-v", "--rmi", "all"]
        );
    }

    #[test]
    fn compose_logs_defaults_and_caps_tail() {
        let payload =
            parse_compose_logs_payload(br#"{"project_name":"demo","tail":999999,"follow":true}"#)
                .expect("parse logs payload");

        assert_eq!(payload.tail, 10_000);
        assert!(payload.follow);
    }
}
