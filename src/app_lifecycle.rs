use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc,
    time::timeout,
};
use tracing::warn;

use crate::{proto::agent::v1::CommandResult, timeutil::now_timestamp};

const CLONE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PULL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DOCKER_OP_TIMEOUT: Duration = Duration::from_secs(30);
const LOG_STREAM_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STREAM_LINE_BYTES: usize = 16 * 1024;
const SECRET_FILES_BASE_DIR: &str = "/var/lib/permanu-agent/secrets";

#[derive(Clone, Debug)]
struct ClonePayload {
    repo_url: String,
    branch: String,
    commit_sha: String,
    github_token: String,
}

#[derive(Clone, Debug)]
struct BuildPayload {
    app_slug: String,
    image_tag: String,
    clone_dir: String,
    dockerfile_path: String,
    dockerfile_content: String,
    dockerfile_source: String,
    cache_args: Vec<String>,
    build_env_vars: HashMap<String, String>,
    no_cache: bool,
}

#[derive(Clone, Debug)]
struct DeployPayload {
    container_name: String,
    image_tag: String,
    port: u16,
    env_vars: HashMap<String, String>,
    network: String,
    skip_pull: bool,
    health_check_only: bool,
    health_check_path: String,
    health_check_status_codes: Vec<u16>,
    memory_mb: i64,
    cpu_cores: f64,
    volumes: Vec<VolumeMount>,
    secret_files: Vec<SecretFileMount>,
    restart_policy: String,
    process_name: String,
    replica_index: i32,
    labels: HashMap<String, String>,
    command: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct VolumeMount {
    #[serde(default)]
    host_path: String,
    #[serde(default)]
    container_path: String,
    #[serde(default)]
    read_only: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct SecretFileMount {
    #[serde(default)]
    mount_path: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DockerfileKind {
    Configured,
    Repo,
    Generated,
}

#[derive(Clone, Debug)]
struct DockerfileStrategy {
    kind: DockerfileKind,
    path: PathBuf,
}

#[derive(Clone, Copy)]
enum StreamSanitizer {
    Git,
    Build,
    Plain,
}

pub async fn handle_app_clone(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_clone_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    if let Err(err) = send_running(
        &tx,
        command_id,
        &format!(
            "Cloning {} (branch: {})...",
            redact_url_credentials(&payload.repo_url),
            payload.branch
        ),
    )
    .await
    {
        return failed_text(command_id, &format!("send clone status: {err}"));
    }

    let clone_dir = match create_temp_clone_dir().await {
        Ok(dir) => dir,
        Err(err) => return failed_text(command_id, &format!("failed to create temp dir: {err}")),
    };
    let clone_dir_str = clone_dir.to_string_lossy().to_string();

    let askpass = if payload.github_token.is_empty() {
        None
    } else {
        match write_askpass_script() {
            Ok(path) => Some(path),
            Err(err) => {
                let _ = tokio::fs::remove_dir_all(&clone_dir).await;
                return failed_text(command_id, &format!("failed to create git askpass: {err}"));
            }
        }
    };

    let envs = clone_git_env(&payload, askpass.as_deref());
    let args = git_clone_args(&payload, &clone_dir_str);
    let clone_result = run_streamed_command(
        StreamCommandSpec {
            program: "git",
            args: &args,
            dir: Some(&std::env::temp_dir()),
            envs: &envs,
            timeout: CLONE_TIMEOUT,
            sanitizer: StreamSanitizer::Git,
        },
        &tx,
        command_id,
    )
    .await;

    if let Err(err) = clone_result {
        if let Some(path) = askpass.as_ref() {
            let _ = std::fs::remove_file(path);
        }
        let _ = tokio::fs::remove_dir_all(&clone_dir).await;
        return failed_text(command_id, &format!("git clone failed: {err}"));
    }

    if !payload.commit_sha.is_empty() {
        if let Err(err) = run_git_quiet(
            &clone_dir,
            &envs,
            &["fetch", "--depth", "1", "origin", &payload.commit_sha],
        )
        .await
        {
            if let Some(path) = askpass.as_ref() {
                let _ = std::fs::remove_file(path);
            }
            let _ = tokio::fs::remove_dir_all(&clone_dir).await;
            return failed_text(
                command_id,
                &format!("git fetch commit {} failed: {err}", payload.commit_sha),
            );
        }
        if let Err(err) = run_git_quiet(&clone_dir, &envs, &["checkout", &payload.commit_sha]).await
        {
            if let Some(path) = askpass.as_ref() {
                let _ = std::fs::remove_file(path);
            }
            let _ = tokio::fs::remove_dir_all(&clone_dir).await;
            return failed_text(
                command_id,
                &format!("git checkout {} failed: {err}", payload.commit_sha),
            );
        }
    }

    if let Some(path) = askpass.as_ref() {
        let _ = std::fs::remove_file(path);
    }

    if let Ok(head) = run_command_output(
        "git",
        &["rev-parse", "HEAD"],
        Some(&clone_dir),
        &envs,
        DOCKER_OP_TIMEOUT,
        128 * 1024,
    )
    .await
    {
        let head = String::from_utf8_lossy(&head.stdout);
        let head = head.trim();
        if !head.is_empty() {
            let _ = send_running(&tx, command_id, &format!("checked out {head}")).await;
        }
    }

    completed_text(command_id, &clone_dir_str)
}

pub async fn handle_app_build(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_build_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let clone_dir = PathBuf::from(&payload.clone_dir);
    if !clone_dir.exists() {
        return failed_text(
            command_id,
            &format!("clone_dir {} not available", payload.clone_dir),
        );
    }

    let _guard = match BuildGuard::acquire(&payload.clone_dir) {
        Ok(guard) => guard,
        Err(err) => return failed_text(command_id, &err.to_string()),
    };

    let strategy = match resolve_dockerfile_strategy(
        &payload.clone_dir,
        &payload.dockerfile_path,
        &payload.dockerfile_content,
        &payload.dockerfile_source,
    ) {
        Ok(strategy) => strategy,
        Err(err) => return failed_text(command_id, &format!("dockerfile: {err}")),
    };

    if strategy.kind == DockerfileKind::Generated {
        if let Err(err) = tokio::fs::write(&strategy.path, payload.dockerfile_content.as_bytes())
            .await
            .with_context(|| format!("write {}", strategy.path.display()))
        {
            return failed_text(command_id, &format!("write generated Dockerfile: {err}"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&strategy.path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&strategy.path, perms);
            }
        }
    }

    let buildx = docker_buildx_available().await;
    if !buildx {
        let _ = send_running(
            &tx,
            command_id,
            "layer cache disabled: docker buildx not available; falling back to docker build",
        )
        .await;
    }

    let args = docker_build_args(&payload, &strategy, buildx);
    let build_env = [("DOCKER_BUILDKIT".to_string(), "1".to_string())];
    let result = run_streamed_command(
        StreamCommandSpec {
            program: "docker",
            args: &args,
            dir: Some(&clone_dir),
            envs: &build_env,
            timeout: BUILD_TIMEOUT,
            sanitizer: StreamSanitizer::Build,
        },
        &tx,
        command_id,
    )
    .await;

    if let Err(err) = result {
        let _ = run_command_output(
            "docker",
            &["builder", "prune", "--filter", "until=1h", "-f"],
            None,
            &[],
            DOCKER_OP_TIMEOUT,
            128 * 1024,
        )
        .await;
        return failed_text(command_id, &format!("docker build failed: {err}"));
    }

    completed_text(
        command_id,
        &format!("Build complete: {}", payload.image_tag),
    )
}

pub async fn handle_app_deploy(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let mut payload = match parse_deploy_payload(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    if payload.health_check_only {
        return match probe_container_health(&payload).await {
            Ok(true) => completed_text(command_id, "healthy"),
            Ok(false) => failed_text(command_id, "health check failed after 60s"),
            Err(err) => failed_text(command_id, &format!("health check failed: {err}")),
        };
    }

    if payload.image_tag.is_empty() {
        return failed_text(command_id, "image_tag is required for deploy");
    }

    if let Err(err) = send_running(
        &tx,
        command_id,
        &format!("ensuring network {}...", payload.network),
    )
    .await
    {
        return failed_text(command_id, &format!("send deploy status: {err}"));
    }
    if let Err(err) = ensure_network(&payload.network).await {
        return failed_text(command_id, &format!("failed to ensure network: {err}"));
    }

    if !payload.skip_pull {
        let _ = send_running(
            &tx,
            command_id,
            &format!("pulling image {}...", payload.image_tag),
        )
        .await;
        let args = ["pull".to_string(), payload.image_tag.clone()];
        if let Err(err) = run_streamed_command(
            StreamCommandSpec {
                program: "docker",
                args: &args,
                dir: None,
                envs: &[],
                timeout: PULL_TIMEOUT,
                sanitizer: StreamSanitizer::Plain,
            },
            &tx,
            command_id,
        )
        .await
        {
            return failed_text(command_id, &format!("image pull failed: {err}"));
        }
    }

    match write_secret_files(&payload.secret_files, &payload.container_name) {
        Ok(mut mounts) => payload.volumes.append(&mut mounts),
        Err(err) => return failed_text(command_id, &format!("secret file write failed: {err}")),
    }

    let args = docker_create_args(&payload);
    let _ = send_running(
        &tx,
        command_id,
        &format!("starting container {}...", payload.container_name),
    )
    .await;
    let created = match run_command_output(
        "docker",
        &args,
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await
    {
        Ok(output) => output,
        Err(err) => return failed_text(command_id, &format!("container create failed: {err}")),
    };
    let container_id = String::from_utf8_lossy(&created.stdout).trim().to_string();
    if container_id.is_empty() {
        return failed_text(command_id, "container create failed: empty container id");
    }

    connect_app_to_service_networks(&container_id, &payload.network, &payload.env_vars).await;

    if let Err(err) = run_command_output(
        "docker",
        &["start", &container_id],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await
    {
        return failed_text(command_id, &format!("container start failed: {err}"));
    }

    completed_text(command_id, &container_id)
}

pub async fn handle_app_stop(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let container = match parse_container_name_payload(payload) {
        Ok(container) => container,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let _ = send_running(
        &tx,
        command_id,
        &format!("stopping container {container}..."),
    )
    .await;
    let _ = run_command_output(
        "docker",
        &["update", "--restart=no", &container],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await;

    if let Err(err) = run_command_output(
        "docker",
        &["stop", "--time", "30", &container],
        None,
        &[],
        DOCKER_OP_TIMEOUT + Duration::from_secs(35),
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await
    {
        return failed_text(command_id, &format!("docker stop failed: {err}"));
    }

    if let Err(err) = run_command_output(
        "docker",
        &["rm", "-f", &container],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await
    {
        warn!(container = %container, error = ?err, "remove container best-effort failed");
    }

    completed_text(command_id, "stopped")
}

pub async fn handle_app_rollback(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let container = match parse_container_name_payload(payload) {
        Ok(container) => container,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };

    let _ = send_running(
        &tx,
        command_id,
        &format!("starting rollback container {container}..."),
    )
    .await;
    let inspect = match inspect_container(&container).await {
        Ok(inspect) => inspect,
        Err(err) => {
            return failed_text(command_id, &format!("rollback container not found: {err}"))
        }
    };
    if inspect.state.as_ref().is_some_and(|state| state.running) {
        return completed_text(command_id, &inspect.id);
    }

    let _ = run_command_output(
        "docker",
        &["update", "--restart=unless-stopped", &container],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await;
    if let Err(err) = run_command_output(
        "docker",
        &["start", &container],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await
    {
        return failed_text(command_id, &format!("rollback start failed: {err}"));
    }

    completed_text(command_id, &inspect.id)
}

pub async fn handle_app_logs(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        tail: i64,
        #[serde(default)]
        follow: bool,
    }

    let payload: Payload = match serde_json::from_slice(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    let container =
        match validate_docker_resource_name(payload.container_name.trim(), "container_name") {
            Ok(()) => payload.container_name.trim().to_string(),
            Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
        };
    let tail = if payload.tail <= 0 {
        100
    } else {
        payload.tail.min(10_000)
    };
    let mut args = vec!["logs".to_string(), "--tail".to_string(), tail.to_string()];
    if payload.follow {
        args.push("-f".to_string());
    }
    args.push(container);

    match run_streamed_command(
        StreamCommandSpec {
            program: "docker",
            args: &args,
            dir: None,
            envs: &[],
            timeout: LOG_STREAM_TIMEOUT,
            sanitizer: StreamSanitizer::Plain,
        },
        &tx,
        command_id,
    )
    .await
    {
        Ok(()) => completed_text(command_id, "log stream ended"),
        Err(err) => failed_text(command_id, &format!("docker logs failed: {err}")),
    }
}

pub async fn handle_app_cleanup(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        app_slug: String,
        #[serde(default)]
        keep_image: String,
        #[serde(default)]
        keep_container: String,
    }

    let payload: Payload = match serde_json::from_slice(payload) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid payload: {err}")),
    };
    if let Err(err) = validate_slug(&payload.app_slug) {
        return failed_text(command_id, &format!("invalid payload: {err}"));
    }

    let container_prefix = format!("deploy-app-{}-", payload.app_slug);
    let _ = send_running(
        &tx,
        command_id,
        &format!("removing containers matching {container_prefix}*..."),
    )
    .await;
    let containers = docker_list_lines(&[
        "ps",
        "-a",
        "--format",
        "{{.Names}}",
        "--filter",
        &format!("name={container_prefix}"),
    ])
    .await
    .unwrap_or_default();

    let mut volumes = HashSet::new();
    let mut removed_containers = 0usize;
    for container in containers {
        if container.is_empty() || container == payload.keep_container {
            continue;
        }
        if let Ok(names) = docker_list_lines(&[
            "inspect",
            "--format",
            "{{range .Mounts}}{{.Name}} {{end}}",
            &container,
        ])
        .await
        {
            volumes.extend(names.into_iter().flat_map(|line| {
                line.split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            }));
        }
        if run_command_output(
            "docker",
            &["rm", "-f", &container],
            None,
            &[],
            DOCKER_OP_TIMEOUT,
            MAX_COMMAND_OUTPUT_BYTES,
        )
        .await
        .is_ok()
        {
            removed_containers += 1;
        }
    }
    let _ = send_running(
        &tx,
        command_id,
        &format!("removed {removed_containers} containers"),
    )
    .await;

    if let Ok(convention_volumes) = docker_list_lines(&[
        "volume",
        "ls",
        "--filter",
        &format!("name=deploy-app-{}", payload.app_slug),
        "-q",
    ])
    .await
    {
        volumes.extend(convention_volumes);
    }

    let images = match docker_list_lines(&[
        "images",
        "--format",
        "{{.Repository}}:{{.Tag}}",
        "--filter",
        &format!("reference=deploy-app-{}:*", payload.app_slug),
    ])
    .await
    {
        Ok(images) => images,
        Err(err) => return failed_text(command_id, &format!("failed to list images: {err}")),
    };
    let mut removed_images = 0usize;
    for image in images {
        if image.is_empty() || image == payload.keep_image || image.ends_with(":<none>") {
            continue;
        }
        if run_command_output(
            "docker",
            &["rmi", &image],
            None,
            &[],
            DOCKER_OP_TIMEOUT,
            MAX_COMMAND_OUTPUT_BYTES,
        )
        .await
        .is_ok()
        {
            removed_images += 1;
        }
    }

    for volume in volumes {
        if validate_docker_resource_name(&volume, "volume").is_err() {
            continue;
        }
        let _ = run_command_output(
            "docker",
            &["volume", "rm", "-f", &volume],
            None,
            &[],
            DOCKER_OP_TIMEOUT,
            MAX_COMMAND_OUTPUT_BYTES,
        )
        .await;
    }

    completed_text(command_id, &format!("removed {removed_images} old images"))
}

fn parse_clone_payload(payload: &[u8]) -> Result<ClonePayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        repo_url: String,
        #[serde(default)]
        branch: String,
        #[serde(default)]
        commit_sha: String,
        #[serde(default)]
        github_token: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_no_control(&payload.repo_url, "repo_url")?;
    let repo_url = payload.repo_url.trim();
    if repo_url.is_empty() {
        anyhow::bail!("repo_url is required");
    }
    let branch = if payload.branch.trim().is_empty() {
        "main"
    } else {
        payload.branch.trim()
    };
    validate_git_atom(branch, "branch")?;
    if !payload.commit_sha.trim().is_empty() {
        validate_git_atom(payload.commit_sha.trim(), "commit_sha")?;
    }
    Ok(ClonePayload {
        repo_url: repo_url.to_string(),
        branch: branch.to_string(),
        commit_sha: payload.commit_sha.trim().to_string(),
        github_token: payload.github_token,
    })
}

fn parse_build_payload(payload: &[u8]) -> Result<BuildPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        app_slug: String,
        #[serde(default)]
        image_tag: String,
        #[serde(default)]
        clone_dir: String,
        #[serde(default)]
        dockerfile_path: String,
        #[serde(default)]
        dockerfile_content: String,
        #[serde(default)]
        dockerfile_source: String,
        #[serde(default)]
        cache_args: Vec<String>,
        #[serde(default)]
        build_env_vars: HashMap<String, String>,
        #[serde(default)]
        no_cache: bool,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    if payload.image_tag.trim().is_empty() {
        anyhow::bail!("image_tag is required");
    }
    if payload.clone_dir.trim().is_empty() {
        anyhow::bail!("clone_dir is required");
    }
    validate_no_control(payload.image_tag.trim(), "image_tag")?;
    validate_abs_path(payload.clone_dir.trim(), "clone_dir")?;
    if !payload.app_slug.trim().is_empty() {
        validate_slug(payload.app_slug.trim())?;
    }
    for key in payload.build_env_vars.keys() {
        validate_env_key(key)?;
    }
    Ok(BuildPayload {
        app_slug: payload.app_slug.trim().to_string(),
        image_tag: payload.image_tag.trim().to_string(),
        clone_dir: payload.clone_dir.trim().to_string(),
        dockerfile_path: payload.dockerfile_path.trim().to_string(),
        dockerfile_content: payload.dockerfile_content,
        dockerfile_source: payload.dockerfile_source.trim().to_string(),
        cache_args: build_cache_args(payload.cache_args, payload.no_cache),
        build_env_vars: payload.build_env_vars,
        no_cache: payload.no_cache,
    })
}

fn parse_deploy_payload(payload: &[u8]) -> Result<DeployPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        image_tag: String,
        #[serde(default)]
        port: u16,
        #[serde(default)]
        env_vars: HashMap<String, String>,
        #[serde(default)]
        network: String,
        #[serde(default)]
        skip_pull: bool,
        #[serde(default)]
        health_check_only: bool,
        #[serde(default)]
        health_check_path: String,
        #[serde(default)]
        health_check_status_codes: Vec<u16>,
        #[serde(default)]
        memory_mb: i64,
        #[serde(default)]
        cpu_cores: f64,
        #[serde(default)]
        volumes: Vec<VolumeMount>,
        #[serde(default)]
        secret_files: Vec<SecretFileMount>,
        #[serde(default)]
        restart_policy: String,
        #[serde(default)]
        process_name: String,
        #[serde(default)]
        replica_index: i32,
        #[serde(default)]
        labels: HashMap<String, String>,
        #[serde(default)]
        override_cmd: String,
        #[serde(default)]
        cron_schedule: String,
        #[serde(default)]
        cron_command: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    validate_docker_resource_name(payload.container_name.trim(), "container_name")?;
    let network = if payload.network.trim().is_empty() {
        "deploy-net"
    } else {
        payload.network.trim()
    };
    validate_docker_resource_name(network, "network")?;
    for key in payload.env_vars.keys() {
        validate_env_key(key)?;
    }
    for label in payload.labels.keys() {
        validate_label_key(label)?;
    }
    let command = container_command(
        &payload.override_cmd,
        &payload.cron_schedule,
        &payload.cron_command,
    )?;
    Ok(DeployPayload {
        container_name: payload.container_name.trim().to_string(),
        image_tag: payload.image_tag.trim().to_string(),
        port: if payload.port == 0 {
            3000
        } else {
            payload.port
        },
        env_vars: payload.env_vars,
        network: network.to_string(),
        skip_pull: payload.skip_pull,
        health_check_only: payload.health_check_only,
        health_check_path: if payload.health_check_path.trim().is_empty() {
            "/".to_string()
        } else {
            payload.health_check_path.trim().to_string()
        },
        health_check_status_codes: payload.health_check_status_codes,
        memory_mb: payload.memory_mb,
        cpu_cores: payload.cpu_cores,
        volumes: payload.volumes,
        secret_files: payload.secret_files,
        restart_policy: payload.restart_policy,
        process_name: payload.process_name,
        replica_index: payload.replica_index,
        labels: payload.labels,
        command,
    })
}

fn container_command(
    override_cmd: &str,
    cron_schedule: &str,
    cron_command: &str,
) -> Result<Vec<String>> {
    let override_cmd = override_cmd.trim();
    let cron_schedule = cron_schedule.trim();
    let cron_command = cron_command.trim();

    if !cron_schedule.is_empty() || !cron_command.is_empty() {
        validate_cron_schedule(cron_schedule)?;
        validate_no_control(cron_command, "cron_command")?;
        return Ok(vec![
            "sh".to_string(),
            "-c".to_string(),
            cron_shell_supervisor(cron_schedule, cron_command),
        ]);
    }

    if override_cmd.is_empty() {
        return Ok(Vec::new());
    }
    validate_no_control(override_cmd, "override_cmd")?;
    Ok(vec![
        "sh".to_string(),
        "-c".to_string(),
        override_cmd.to_string(),
    ])
}

fn validate_cron_schedule(schedule: &str) -> Result<()> {
    validate_no_control(schedule, "cron_schedule")?;
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 {
        anyhow::bail!("cron_schedule must have exactly 5 fields");
    }
    for field in fields {
        if field.is_empty()
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'*' | b',' | b'-' | b'/'))
        {
            anyhow::bail!("cron_schedule contains unsupported field {field:?}");
        }
    }
    Ok(())
}

fn cron_shell_supervisor(schedule: &str, command: &str) -> String {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    format!(
        "match_one() {{ token=\"$1\"; val=\"$2\"; case \"$token\" in \"*\") return 0;; \"*/\"*) step=\"${{token#*/}}\"; [ \"$step\" -gt 0 ] && [ $((val % step)) -eq 0 ];; *-*) start=\"${{token%-*}}\"; end=\"${{token#*-}}\"; [ \"$val\" -ge \"$start\" ] && [ \"$val\" -le \"$end\" ];; *) [ \"$val\" -eq \"$token\" ];; esac; }}\n\
match_field() {{ field=\"$1\"; val=$(expr \"$2\" + 0); oldifs=\"$IFS\"; IFS=,; for token in $field; do if match_one \"$token\" \"$val\"; then IFS=\"$oldifs\"; return 0; fi; done; IFS=\"$oldifs\"; return 1; }}\n\
while true; do set -- $(date '+%M %H %d %m %w'); if match_field '{}' \"$1\" && match_field '{}' \"$2\" && match_field '{}' \"$3\" && match_field '{}' \"$4\" && match_field '{}' \"$5\"; then sh -c {}; fi; sleep 60; done",
        fields[0],
        fields[1],
        fields[2],
        fields[3],
        fields[4],
        shell_single_quote(command)
    )
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn parse_container_name_payload(payload: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let name = payload.container_name.trim();
    validate_docker_resource_name(name, "container_name")?;
    Ok(name.to_string())
}

fn git_clone_args(payload: &ClonePayload, clone_dir: &str) -> Vec<String> {
    vec![
        "clone".to_string(),
        "--depth".to_string(),
        "1".to_string(),
        "--branch".to_string(),
        payload.branch.clone(),
        "--progress".to_string(),
        payload.repo_url.clone(),
        clone_dir.to_string(),
    ]
}

fn docker_build_args(
    payload: &BuildPayload,
    strategy: &DockerfileStrategy,
    buildx: bool,
) -> Vec<String> {
    let mut args = if buildx {
        vec![
            "buildx".to_string(),
            "build".to_string(),
            "-t".to_string(),
            payload.image_tag.clone(),
            "-f".to_string(),
            strategy.path.to_string_lossy().to_string(),
        ]
    } else {
        vec![
            "build".to_string(),
            "-t".to_string(),
            payload.image_tag.clone(),
            "-f".to_string(),
            strategy.path.to_string_lossy().to_string(),
        ]
    };

    if !payload.app_slug.is_empty() {
        args.extend([
            "--label".to_string(),
            format!("deploy-app={}", payload.app_slug),
        ]);
    }
    args.extend(payload.cache_args.iter().cloned());
    for (key, value) in &payload.build_env_vars {
        args.extend(["--build-arg".to_string(), format!("{key}={value}")]);
    }
    if payload.no_cache && !args.iter().any(|arg| arg == "--no-cache") {
        args.push("--no-cache".to_string());
    }
    args.push(payload.clone_dir.clone());
    args
}

fn docker_create_args(payload: &DeployPayload) -> Vec<String> {
    let mut labels = payload.labels.clone();
    if !payload.process_name.is_empty() {
        labels.insert("permanu.process".to_string(), payload.process_name.clone());
        labels.insert(
            "permanu.replica".to_string(),
            payload.replica_index.to_string(),
        );
    }

    let memory_mb = if payload.memory_mb > 0 {
        payload.memory_mb
    } else {
        512
    };
    let cpu_cores = if payload.cpu_cores > 0.0 {
        payload.cpu_cores
    } else {
        1.0
    };

    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        payload.container_name.clone(),
        "--network".to_string(),
        payload.network.clone(),
        "--restart".to_string(),
        restart_policy(&payload.restart_policy).to_string(),
        "--memory".to_string(),
        format!("{memory_mb}m"),
        "--cpus".to_string(),
        cpu_cores.to_string(),
        "--add-host".to_string(),
        "host.docker.internal:host-gateway".to_string(),
        "--log-driver".to_string(),
        "json-file".to_string(),
        "--log-opt".to_string(),
        "max-size=50m".to_string(),
        "--log-opt".to_string(),
        "max-file=3".to_string(),
        "--expose".to_string(),
        format!("{}/tcp", payload.port),
    ];

    for (key, value) in &payload.env_vars {
        args.extend(["-e".to_string(), format!("{key}={value}")]);
    }
    args.extend(["-e".to_string(), format!("PORT={}", payload.port)]);
    for (key, value) in labels {
        args.extend(["--label".to_string(), format!("{key}={value}")]);
    }
    for volume in &payload.volumes {
        if volume.host_path.trim().is_empty() || volume.container_path.trim().is_empty() {
            continue;
        }
        let mut bind = format!("{}:{}", volume.host_path, volume.container_path);
        if volume.read_only {
            bind.push_str(":ro");
        }
        args.extend(["-v".to_string(), bind]);
    }
    args.push(payload.image_tag.clone());
    args.extend(payload.command.iter().cloned());
    args
}

fn resolve_dockerfile_strategy(
    clone_dir: &str,
    dockerfile_path: &str,
    dockerfile_content: &str,
    dockerfile_source: &str,
) -> Result<DockerfileStrategy> {
    validate_abs_path(clone_dir, "clone_dir")?;
    let clone_dir = PathBuf::from(clone_dir);

    if !dockerfile_path.trim().is_empty() {
        let path = safe_child_path(&clone_dir, dockerfile_path.trim(), "dockerfile_path")?;
        if !path.exists() {
            anyhow::bail!("configured Dockerfile does not exist: {}", path.display());
        }
        return Ok(DockerfileStrategy {
            kind: DockerfileKind::Configured,
            path,
        });
    }

    if dockerfile_source == "generated" || !dockerfile_content.is_empty() {
        return Ok(DockerfileStrategy {
            kind: DockerfileKind::Generated,
            path: clone_dir.join("Dockerfile.permanu.generated"),
        });
    }

    for name in ["Dockerfile.production", "Dockerfile.prod", "Dockerfile"] {
        let path = clone_dir.join(name);
        if path.is_file() {
            return Ok(DockerfileStrategy {
                kind: DockerfileKind::Repo,
                path,
            });
        }
    }

    anyhow::bail!("no Dockerfile found and no generated Dockerfile content provided")
}

fn build_cache_args(args: Vec<String>, no_cache: bool) -> Vec<String> {
    if !no_cache {
        return args;
    }
    let mut out = Vec::with_capacity(args.len() + 1);
    let mut has_no_cache = false;
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--cache-from" || arg == "--cache-to" {
            let _ = iter.next();
            continue;
        }
        if arg.starts_with("--cache-from=") || arg.starts_with("--cache-to=") {
            continue;
        }
        if arg == "--no-cache" {
            has_no_cache = true;
        }
        out.push(arg);
    }
    if !has_no_cache {
        out.push("--no-cache".to_string());
    }
    out
}

fn restart_policy(input: &str) -> &'static str {
    match input {
        "always" => "always",
        "on-failure" => "on-failure",
        "no" => "no",
        _ => "unless-stopped",
    }
}

async fn create_temp_clone_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for attempt in 0..100u32 {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = base.join(format!(
            "deploy-build-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match tokio::fs::create_dir(&path).await {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err).with_context(|| format!("mkdir {}", path.display())),
        }
    }
    anyhow::bail!("failed to allocate unique deploy build directory")
}

fn write_askpass_script() -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "pa-askpass-{}-{}.sh",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::write(
        &path,
        "#!/bin/sh\ncase \"$1\" in\n*Username*) printf '%s\\n' x-access-token ;;\n*) printf '%s\\n' \"$GIT_TOKEN\" ;;\nesac\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(path)
}

fn clone_git_env(payload: &ClonePayload, askpass: Option<&Path>) -> Vec<(String, String)> {
    let Some(askpass) = askpass else {
        return Vec::new();
    };
    vec![
        (
            "GIT_ASKPASS".to_string(),
            askpass.to_string_lossy().to_string(),
        ),
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
        ("GCM_INTERACTIVE".to_string(), "never".to_string()),
        ("GIT_TOKEN".to_string(), payload.github_token.clone()),
    ]
}

async fn run_git_quiet(dir: &Path, envs: &[(String, String)], args: &[&str]) -> Result<()> {
    let output =
        run_command_output("git", args, Some(dir), envs, CLONE_TIMEOUT, 256 * 1024).await?;
    if output.status_success {
        Ok(())
    } else {
        anyhow::bail!("{}", sanitize_git_error(&output.combined_string()))
    }
}

async fn docker_buildx_available() -> bool {
    run_command_output(
        "docker",
        &["buildx", "version"],
        None,
        &[],
        Duration::from_secs(5),
        128 * 1024,
    )
    .await
    .is_ok_and(|output| output.status_success)
}

async fn ensure_network(network: &str) -> Result<()> {
    let inspect = run_command_output(
        "docker",
        &["network", "inspect", network],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await;
    if inspect.is_ok_and(|output| output.status_success) {
        return Ok(());
    }
    let output = run_command_output(
        "docker",
        &["network", "create", network],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await?;
    if output.status_success {
        Ok(())
    } else {
        anyhow::bail!("{}", output.combined_string())
    }
}

fn write_secret_files(
    secret_files: &[SecretFileMount],
    container_name: &str,
) -> Result<Vec<VolumeMount>> {
    if secret_files.is_empty() {
        return Ok(Vec::new());
    }
    let app_slug =
        extract_slug_from_container(container_name).unwrap_or_else(|| "unknown".to_string());
    validate_slug(&app_slug)?;
    let app_dir = Path::new(SECRET_FILES_BASE_DIR).join(app_slug);
    std::fs::create_dir_all(&app_dir).with_context(|| format!("mkdir {}", app_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&app_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let mut mounts = Vec::with_capacity(secret_files.len());
    for secret in secret_files {
        validate_abs_path(&secret.mount_path, "secret mount_path")?;
        let file_name = Path::new(&secret.mount_path)
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .context("secret mount_path must include a file name")?;
        validate_no_control(file_name, "secret file name")?;
        if file_name.contains('/') || file_name == "." || file_name == ".." {
            anyhow::bail!("secret file name contains invalid characters");
        }
        let raw = general_purpose::STANDARD
            .decode(&secret.content)
            .context("invalid secret base64")?;
        let host_path = app_dir.join(file_name);
        std::fs::write(&host_path, raw)
            .with_context(|| format!("write secret {}", host_path.display()))?;
        let mode = if secret.mode == 0 { 0o400 } else { secret.mode };
        if mode > 0o777 {
            anyhow::bail!("secret mode must be <= 0777");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(mode))?;
        }
        mounts.push(VolumeMount {
            host_path: host_path.to_string_lossy().to_string(),
            container_path: secret.mount_path.clone(),
            read_only: true,
        });
    }
    Ok(mounts)
}

async fn probe_container_health(payload: &DeployPayload) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    tokio::time::sleep(Duration::from_secs(5)).await;
    while tokio::time::Instant::now() < deadline {
        let inspect = match inspect_container(&payload.container_name).await {
            Ok(inspect) => inspect,
            Err(err) => {
                let ps = docker_ps_by_name(&payload.container_name)
                    .await
                    .unwrap_or_default();
                anyhow::bail!(
                    "inspect failed for {}: {err}; docker ps -a match: {}",
                    payload.container_name,
                    if ps.trim().is_empty() {
                        "<none>"
                    } else {
                        ps.trim()
                    }
                );
            }
        };
        if inspect
            .state
            .as_ref()
            .and_then(|state| state.health.as_ref())
            .is_some_and(|health| health.status == "healthy")
        {
            return Ok(true);
        }
        if inspect.state.as_ref().is_some_and(|state| !state.running) {
            return Ok(false);
        }
        if let Some(ip) = pick_container_ip(&inspect, &payload.network) {
            if let Ok(status) =
                http_probe_status(&ip, payload.port, &payload.health_check_path).await
            {
                if is_healthy_status(status, &payload.health_check_status_codes) {
                    return Ok(true);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(false)
}

async fn http_probe_status(ip: &str, port: u16, path: &str) -> Result<u16> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let mut stream = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((ip, port)),
    )
    .await
    .context("connect timed out")??;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut buf = vec![0u8; 512];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .context("read timed out")??;
    let head = String::from_utf8_lossy(&buf[..n]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .context("invalid HTTP response")?;
    Ok(status)
}

fn is_healthy_status(code: u16, allowlist: &[u16]) -> bool {
    if allowlist.is_empty() {
        return (200..400).contains(&code);
    }
    allowlist.contains(&code)
}

async fn inspect_container(container: &str) -> Result<InspectContainer> {
    let output = run_command_output(
        "docker",
        &["inspect", container],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await?;
    if !output.status_success {
        anyhow::bail!("{}", output.combined_string());
    }
    let mut containers: Vec<InspectContainer> = serde_json::from_slice(&output.stdout)?;
    containers.pop().context("empty docker inspect response")
}

async fn docker_ps_by_name(container: &str) -> Result<String> {
    let filter = format!("name=^/{}$", container);
    let output = run_command_output(
        "docker",
        &[
            "ps",
            "-a",
            "--no-trunc",
            "--filter",
            &filter,
            "--format",
            "{{.ID}} {{.Names}} {{.Status}}",
        ],
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await?;
    Ok(output.combined_string())
}

fn pick_container_ip(inspect: &InspectContainer, preferred_network: &str) -> Option<String> {
    let networks = inspect.network_settings.as_ref()?.networks.as_ref()?;
    if let Some(ip) = networks
        .get(preferred_network)
        .and_then(|network| network.ip_address.as_deref())
        .filter(|ip| !ip.is_empty())
    {
        return Some(ip.to_string());
    }
    networks
        .values()
        .find_map(|network| network.ip_address.as_deref().filter(|ip| !ip.is_empty()))
        .map(ToOwned::to_owned)
}

async fn connect_app_to_service_networks(
    container_id: &str,
    app_network: &str,
    env_vars: &HashMap<String, String>,
) {
    let mut connected = HashSet::from([app_network.to_string()]);
    for value in env_vars.values() {
        let Some(host) = extract_container_host(value) else {
            continue;
        };
        let Ok(inspect) = inspect_container(&host).await else {
            continue;
        };
        let Some(networks) = inspect
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
        else {
            continue;
        };
        for network in networks.keys() {
            if !connected.insert(network.clone()) {
                continue;
            }
            let _ = run_command_output(
                "docker",
                &["network", "connect", network, container_id],
                None,
                &[],
                DOCKER_OP_TIMEOUT,
                MAX_COMMAND_OUTPUT_BYTES,
            )
            .await;
        }
    }
}

fn extract_container_host(value: &str) -> Option<String> {
    let mut host = if let Some(idx) = value.find("://") {
        let mut rest = &value[idx + 3..];
        if let Some(at) = rest.find('@') {
            rest = &rest[at + 1..];
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        rest[..end].to_string()
    } else {
        value.to_string()
    };
    if let Some(idx) = host.rfind(':') {
        host.truncate(idx);
    }
    let host = host.trim();
    if looks_like_container_name(host) {
        Some(host.to_string())
    } else {
        None
    }
}

fn looks_like_container_name(value: &str) -> bool {
    value.len() >= 2
        && value.chars().any(|ch| ch.is_ascii_alphabetic())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

async fn docker_list_lines(args: &[&str]) -> Result<Vec<String>> {
    let output = run_command_output(
        "docker",
        args,
        None,
        &[],
        DOCKER_OP_TIMEOUT,
        MAX_COMMAND_OUTPUT_BYTES,
    )
    .await?;
    if !output.status_success {
        anyhow::bail!("{}", output.combined_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

struct StreamCommandSpec<'a> {
    program: &'a str,
    args: &'a [String],
    dir: Option<&'a Path>,
    envs: &'a [(String, String)],
    timeout: Duration,
    sanitizer: StreamSanitizer,
}

async fn run_streamed_command(
    spec: StreamCommandSpec<'_>,
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
) -> Result<()> {
    let mut command = Command::new(spec.program);
    command
        .args(spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(dir) = spec.dir {
        command.current_dir(dir);
    }
    for (key, value) in spec.envs {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", spec.program))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_task = stdout.map(|reader| {
        tokio::spawn(stream_reader(
            reader,
            tx.clone(),
            command_id.to_string(),
            spec.sanitizer,
        ))
    });
    let stderr_task = stderr.map(|reader| {
        tokio::spawn(stream_reader(
            reader,
            tx.clone(),
            command_id.to_string(),
            spec.sanitizer,
        ))
    });

    let status = match timeout(spec.timeout, child.wait()).await {
        Ok(status) => status.with_context(|| format!("wait for {}", spec.program))?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!(
                "{} timed out after {}s",
                spec.program,
                spec.timeout.as_secs()
            );
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
        return Ok(());
    }
    if tail.is_empty() {
        anyhow::bail!("{} exited with {status}", spec.program);
    }
    anyhow::bail!("{}", tail.join(" | "))
}

async fn stream_reader<R>(
    reader: R,
    tx: mpsc::Sender<CommandResult>,
    command_id: String,
    sanitizer: StreamSanitizer,
) -> Vec<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut tail = VecDeque::with_capacity(10);
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
            line.push_str("...[truncated]");
        }
        let Some(clean) = sanitize_stream_line(&line, sanitizer) else {
            continue;
        };
        if tail.len() == 10 {
            tail.pop_front();
        }
        tail.push_back(clean.clone());
        if tx
            .send(CommandResult {
                command_id: command_id.clone(),
                status: "running".to_string(),
                output: clean.into_bytes(),
                is_final: false,
                timestamp: Some(now_timestamp()),
            })
            .await
            .is_err()
        {
            break;
        }
    }
    tail.into_iter().collect()
}

fn sanitize_stream_line(line: &str, sanitizer: StreamSanitizer) -> Option<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    match sanitizer {
        StreamSanitizer::Git => {
            let line = sanitize_git_output(line);
            if line.is_empty() {
                None
            } else {
                Some(format!("{line}\n"))
            }
        }
        StreamSanitizer::Build => {
            if line.contains("(*service).Write failed")
                || (line.contains("locked for") && line.contains("unavailable"))
            {
                None
            } else {
                Some(format!("{line}\n"))
            }
        }
        StreamSanitizer::Plain => Some(format!("{line}\n")),
    }
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

async fn run_command_output<S: AsRef<std::ffi::OsStr>>(
    program: &str,
    args: &[S],
    dir: Option<&Path>,
    envs: &[(String, String)],
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
    for (key, value) in envs {
        command.env(key, value);
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

struct BuildGuard {
    clone_dir: String,
}

impl BuildGuard {
    fn acquire(clone_dir: &str) -> Result<Self> {
        let locks = build_locks();
        let mut locks = locks.lock().expect("build lock map poisoned");
        if !locks.insert(clone_dir.to_string()) {
            anyhow::bail!("another build is already in flight for {clone_dir}");
        }
        Ok(Self {
            clone_dir: clone_dir.to_string(),
        })
    }
}

impl Drop for BuildGuard {
    fn drop(&mut self) {
        let locks = build_locks();
        let mut locks = locks.lock().expect("build lock map poisoned");
        locks.remove(&self.clone_dir);
    }
}

fn build_locks() -> &'static Mutex<HashSet<String>> {
    static LOCKS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn safe_child_path(base: &Path, raw: &str, label: &str) -> Result<PathBuf> {
    validate_no_control(raw, label)?;
    let raw_path = Path::new(raw);
    if raw_path.is_absolute() {
        let canonical = raw_path
            .canonicalize()
            .with_context(|| format!("{label} does not exist"))?;
        let base = base
            .canonicalize()
            .with_context(|| format!("clone_dir {} does not exist", base.display()))?;
        if canonical.starts_with(&base) {
            return Ok(canonical);
        }
        anyhow::bail!("{label} must stay inside clone_dir");
    }
    if raw_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        anyhow::bail!("{label} must stay inside clone_dir");
    }
    Ok(base.join(raw_path))
}

fn validate_abs_path(value: &str, label: &str) -> Result<()> {
    validate_no_control(value, label)?;
    if !Path::new(value).is_absolute() {
        anyhow::bail!("{label} must be absolute");
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

fn validate_git_atom(value: &str, label: &str) -> Result<()> {
    validate_no_control(value, label)?;
    if value.starts_with('-') {
        anyhow::bail!("{label} cannot start with '-'");
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

fn validate_slug(value: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("app_slug is required");
    }
    if value == "." || value == ".." || value.starts_with('-') {
        anyhow::bail!("app_slug contains invalid characters");
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        anyhow::bail!("app_slug contains invalid characters");
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

fn validate_label_key(value: &str) -> Result<()> {
    if value.is_empty() || value.contains(['\0', '\r', '\n']) {
        anyhow::bail!("invalid docker label key {value:?}");
    }
    Ok(())
}

fn sanitize_git_output(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if lower.contains("authorization:")
        || lower.contains("bearer ")
        || lower.contains("x-access-token:")
        || looks_like_credential_assignment(&lower)
    {
        return String::new();
    }
    line.trim().to_string()
}

fn sanitize_git_error(stderr: &str) -> String {
    let safe: Vec<_> = stderr
        .lines()
        .map(sanitize_git_output)
        .filter(|line| !line.is_empty())
        .collect();
    if safe.is_empty() {
        "(error details redacted for security)".to_string()
    } else {
        safe.join("; ")
    }
}

fn looks_like_credential_assignment(lower: &str) -> bool {
    for key in [
        "access_token",
        "access-token",
        "auth_token",
        "auth-token",
        "git_token",
        "git-token",
        "token",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "client-secret",
    ] {
        if let Some(idx) = lower.find(key) {
            let rest = lower[idx + key.len()..].trim_start();
            if rest.starts_with(':') || rest.starts_with('=') {
                return true;
            }
        }
    }
    false
}

fn redact_url_credentials(url: &str) -> String {
    let Some(scheme_idx) = url.find("://") else {
        return url.to_string();
    };
    let auth_start = scheme_idx + 3;
    let rest = &url[auth_start..];
    let path_start = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..path_start];
    let Some(at_idx) = authority.rfind('@') else {
        return url.to_string();
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..auth_start]);
    out.push_str("***@");
    out.push_str(&rest[at_idx + 1..]);
    out
}

fn extract_slug_from_container(name: &str) -> Option<String> {
    let body = name.strip_prefix("deploy-app-")?;
    let idx = body.rfind('-')?;
    if idx == 0 {
        None
    } else {
        Some(body[..idx].to_string())
    }
}

#[derive(Debug, Deserialize)]
struct InspectContainer {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "State", default)]
    state: Option<InspectState>,
    #[serde(rename = "NetworkSettings", default)]
    network_settings: Option<InspectNetworkSettings>,
}

#[derive(Debug, Deserialize)]
struct InspectState {
    #[serde(rename = "Running", default)]
    running: bool,
    #[serde(rename = "Health", default)]
    health: Option<InspectHealth>,
}

#[derive(Debug, Deserialize)]
struct InspectHealth {
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Debug, Deserialize)]
struct InspectNetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: Option<HashMap<String, InspectNetwork>>,
}

#[derive(Debug, Deserialize)]
struct InspectNetwork {
    #[serde(rename = "IPAddress", default)]
    ip_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_payload_defaults_branch_to_main() {
        let payload = parse_clone_payload(br#"{"repo_url":"https://github.com/acme/app.git"}"#)
            .expect("parse clone payload");

        assert_eq!(payload.branch, "main");
    }

    #[test]
    fn clone_args_do_not_include_github_token() {
        let payload = parse_clone_payload(
            br#"{"repo_url":"https://github.com/acme/app.git","branch":"main","github_token":"ghs_secret"}"#,
        )
        .expect("parse clone payload");

        let args = git_clone_args(&payload, "/tmp/deploy-build-123");
        assert!(!args.iter().any(|arg| arg.contains("ghs_secret")));
    }

    #[test]
    fn clone_payload_rejects_control_chars() {
        let err = parse_clone_payload(b"{\"repo_url\":\"https://github.com/acme/app.git\\n\"}")
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("repo_url contains invalid characters"));
    }

    #[test]
    fn build_payload_requires_image_tag() {
        let err = parse_build_payload(br#"{"clone_dir":"/tmp/deploy-build-123"}"#).unwrap_err();

        assert!(err.to_string().contains("image_tag is required"));
    }

    #[test]
    fn dockerfile_path_cannot_escape_clone_dir() {
        let clone_dir = unique_test_dir("dockerfile-escape");
        std::fs::create_dir_all(&clone_dir).expect("create clone dir");

        let err = resolve_dockerfile_strategy(
            clone_dir.to_str().expect("clone dir"),
            "../Dockerfile",
            "",
            "",
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("dockerfile_path must stay inside clone_dir"));
        let _ = std::fs::remove_dir_all(&clone_dir);
    }

    #[test]
    fn generated_dockerfile_is_materialized_inside_clone_dir() {
        let clone_dir = unique_test_dir("generated-dockerfile");
        std::fs::create_dir_all(&clone_dir).expect("create clone dir");

        let strategy = resolve_dockerfile_strategy(
            clone_dir.to_str().expect("clone dir"),
            "",
            "FROM scratch\n",
            "generated",
        )
        .expect("resolve dockerfile");

        assert_eq!(strategy.kind, DockerfileKind::Generated);
        assert!(strategy.path.starts_with(&clone_dir));
        let _ = std::fs::remove_dir_all(&clone_dir);
    }

    #[test]
    fn build_args_are_separate_docker_argv_entries() {
        let payload = parse_build_payload(
            br#"{"image_tag":"deploy-app-demo:abc","clone_dir":"/tmp/deploy-build-123","build_env_vars":{"NODE_ENV":"production"}}"#,
        )
        .expect("parse build payload");
        let strategy = DockerfileStrategy {
            kind: DockerfileKind::Repo,
            path: std::path::PathBuf::from("/tmp/deploy-build-123/Dockerfile"),
        };

        let args = docker_build_args(&payload, &strategy, true);

        assert!(args
            .windows(2)
            .any(|pair| pair == ["--build-arg", "NODE_ENV=production"]));
    }

    #[test]
    fn deploy_payload_defaults_port_and_network() {
        let payload = parse_deploy_payload(
            br#"{"container_name":"deploy-app-demo-abc","image_tag":"deploy-app-demo:abc"}"#,
        )
        .expect("parse deploy payload");

        assert_eq!(payload.port, 3000);
        assert_eq!(payload.network, "deploy-net");
    }

    #[test]
    fn deploy_payload_adds_worker_command_after_image() {
        let payload = parse_deploy_payload(
            br#"{"container_name":"deploy-app-worker-abc","image_tag":"deploy-app:abc","override_cmd":"bundle exec sidekiq"}"#,
        )
        .expect("parse deploy payload");

        let args = docker_create_args(&payload);
        let image_idx = args
            .iter()
            .position(|arg| arg == "deploy-app:abc")
            .expect("image arg");
        assert_eq!(&args[image_idx + 1..], ["sh", "-c", "bundle exec sidekiq"]);
    }

    #[test]
    fn deploy_payload_wraps_cron_process_without_host_shell() {
        let payload = parse_deploy_payload(
            br#"{"container_name":"deploy-app-cron-abc","image_tag":"deploy-app:abc","cron_schedule":"*/5 * * * *","cron_command":"./bin/scheduler --run"}"#,
        )
        .expect("parse deploy payload");

        assert_eq!(&payload.command[0..2], ["sh", "-c"]);
        assert!(payload.command[2].contains("match_field '*/5'"));
        assert!(payload.command[2].contains("sh -c './bin/scheduler --run'"));
    }

    #[test]
    fn deploy_payload_rejects_malformed_cron_schedule() {
        let err = parse_deploy_payload(
            br#"{"container_name":"deploy-app-cron-abc","image_tag":"deploy-app:abc","cron_schedule":"not a cron","cron_command":"./bin/scheduler"}"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("cron_schedule"));
    }

    #[test]
    fn app_slug_rejects_path_traversal() {
        let err = validate_slug("../demo").unwrap_err();

        assert!(err
            .to_string()
            .contains("app_slug contains invalid characters"));
    }

    #[test]
    fn healthy_status_accepts_allowlist_only_when_present() {
        assert!(is_healthy_status(204, &[]));
        assert!(!is_healthy_status(404, &[]));
        assert!(is_healthy_status(404, &[404]));
        assert!(!is_healthy_status(204, &[404]));
    }

    #[test]
    fn redact_url_credentials_masks_userinfo() {
        assert_eq!(
            redact_url_credentials("https://user:token@example.com/acme/app.git"),
            "https://***@example.com/acme/app.git"
        );
    }

    fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
