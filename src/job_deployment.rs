#![allow(dead_code)]

use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashMap},
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Component, Path, PathBuf},
    process::{Child, Command as StdCommand, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{process::Command, time::timeout};

use crate::{log_forwarder::LogForwarder, proto::agent::v1::LogEntry, timeutil::now_unix_nanos};

const DEFAULT_HOOK_TIMEOUT_SECONDS: u64 = 120;
const DEFAULT_RELEASE_HOOK_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_CI_JOB_TIMEOUT_SECONDS: u64 = 60 * 60;
const DEFAULT_GIT_COMMAND_TIMEOUT_SECONDS: u64 = 10 * 60;
const MAX_CI_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_CI_STEPS: usize = 128;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_COMPOSE_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_ACTION_BUNDLE_FILES: usize = 512;
const MAX_ACTION_BUNDLE_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACTION_BUNDLE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_SWARM_EXTRA_FILES: usize = 64;
const MAX_SWARM_EXTRA_FILE_BYTES: usize = 1024 * 1024;
const MAX_SWARM_STACK_PAYLOAD_BYTES: usize = 5 * 1024 * 1024;
const SWARM_STACK_FILE_NAME: &str = "stack.yaml";
const DEPLOYMENT_BASE_DIR: &str = "/opt/permanu-agent/deployments";
const DEFAULT_CI_WORKSPACE_ROOT: &str = "/var/tmp/permanu-ci";
const CI_WORKSPACE_ROOT_ENV: &str = "PERMANU_CI_ROOT";
const CI_STRICT_ENV_ENV: &str = "PERMANU_CI_STRICT_ENV";
const CI_SHARED_TOOL_CACHE_ROOT_ENV: &str = "PERMANU_CI_SHARED_TOOL_CACHE_ROOT";
const CI_SHARED_TOOL_CACHE_ENV: &str = "PERMANU_CI_SHARED_TOOL_CACHE";
const DEFAULT_CI_ARTIFACTS_ROOT: &str = "/var/lib/permanu-agent/actions-artifacts";
const CI_ARTIFACTS_ROOT_ENV: &str = "PERMANU_ACTIONS_ARTIFACTS_DIR";
const DEFAULT_CI_ACTIONS_CACHE_ROOT: &str = "/var/lib/permanu-agent/actions-cache";
const CI_ACTIONS_CACHE_ROOT_ENV: &str = "PERMANU_ACTIONS_CACHE_DIR";
const CI_ACTIONS_CACHE_MAX_BYTES_ENV: &str = "PERMANU_ACTIONS_CACHE_MAX_BYTES";
const CI_ARTIFACT_RETENTION_DAYS: u64 = 90;
const CI_ARTIFACT_ARCHIVE_FILENAME: &str = ".permanu-artifact.zip";

pub type CancellationSignal = Arc<AtomicBool>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentCommandResult {
    pub command_id: String,
    pub status: String,
    pub output: Vec<u8>,
    pub is_final: bool,
}

impl AgentCommandResult {
    pub fn completed(command_id: &str, message: impl AsRef<str>) -> Self {
        Self {
            command_id: command_id.to_string(),
            status: "completed".to_string(),
            output: message.as_ref().as_bytes().to_vec(),
            is_final: true,
        }
    }

    pub fn failed(command_id: &str, message: impl AsRef<str>) -> Self {
        Self {
            command_id: command_id.to_string(),
            status: "failed".to_string(),
            output: message.as_ref().as_bytes().to_vec(),
            is_final: true,
        }
    }

    pub fn unsupported(command_id: &str, message: impl AsRef<str>) -> Self {
        Self::failed(command_id, message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub work_dir: Option<String>,
    pub env: BTreeMap<String, String>,
    pub host_env: BTreeMap<String, String>,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ParsedCommand {
    pub original: String,
    pub argv: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunHooksPlan {
    pub hook_event: String,
    pub commands: Vec<ParsedCommand>,
    pub block_deploy: bool,
    pub timeout_seconds: u64,
    pub work_dir: String,
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReleaseHookPlan {
    pub image_tag: String,
    pub commands: Vec<ParsedCommand>,
    pub timeout_seconds: u64,
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiJobPlan {
    pub job_db_id: String,
    pub job_id_yaml: String,
    pub run_db_id: String,
    pub timeout_seconds: u64,
    pub clone_dir: String,
    pub container: Option<CiJobContainer>,
    pub services: BTreeMap<String, CiJobService>,
    pub repo_owner: String,
    pub repo_name: String,
    pub repo_clone_token: String,
    pub head_sha: String,
    pub trigger_ref: String,
    pub oidc_token_requests_allowed: bool,
    pub oidc_request_url: String,
    pub oidc_request_token: String,
    pub sandbox_policy: Option<String>,
    pub env: BTreeMap<String, String>,
    pub matrix_values: BTreeMap<String, String>,
    pub secret_keys: Vec<String>,
    action_bundles: Vec<ActionBundle>,
    available_artifacts: Vec<AvailableArtifact>,
    pub steps: Vec<CiStep>,
}

impl CiJobPlan {
    pub fn service_network_name(&self) -> Option<String> {
        if self.services.is_empty() {
            None
        } else {
            Some(service_network_name(&self.job_db_id))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiJobContainer {
    pub image: String,
    pub credentials: Option<CiContainerCredential>,
    pub env: BTreeMap<String, String>,
    pub options: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiContainerCredential {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiJobService {
    pub image: String,
    pub credentials: Option<CiContainerCredential>,
    pub env: BTreeMap<String, String>,
    pub ports: Vec<String>,
    pub volumes: Vec<String>,
    pub options: Vec<String>,
    pub container_name: String,
    pub network_alias: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiStep {
    pub step_db_id: String,
    pub step_index: u32,
    pub name: String,
    pub run: String,
    pub uses: String,
    pub with: BTreeMap<String, String>,
    pub shell: String,
    pub working_dir: String,
    pub env: BTreeMap<String, String>,
    pub continue_on_error: bool,
    pub timeout_minutes: u32,
    pub if_expr: String,
    argv: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CiJobResult {
    conclusion: String,
    failed_step_index: Option<u32>,
    step_statuses: BTreeMap<String, String>,
    step_logs: BTreeMap<String, String>,
    artifacts: Vec<ArtifactEvent>,
    cache_events: Vec<CacheEvent>,
    log: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ArtifactEvent {
    name: String,
    size_bytes: i64,
    content_sha256: String,
    storage_path: String,
    expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CacheEvent {
    scope: String,
    key: String,
    result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_read: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eviction_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_used_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct AvailableArtifact {
    name: String,
    storage_path: String,
    download_url: String,
    provider_url: String,
    size_bytes: i64,
    hash: String,
}

#[derive(Deserialize)]
struct AvailableArtifactPayload {
    #[serde(default)]
    name: String,
    #[serde(default)]
    storage_path: String,
    #[serde(default)]
    download_url: String,
    #[serde(default)]
    provider_url: String,
    #[serde(default)]
    remote_url: String,
    #[serde(default)]
    size_bytes: i64,
    #[serde(default)]
    hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ActionBundle {
    uses: String,
    local_path: String,
    action_filename: String,
    action_yml: String,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ActionBundlePayload {
    #[serde(default)]
    uses: String,
    #[serde(default)]
    local_path: String,
    #[serde(default)]
    action_filename: String,
    #[serde(default)]
    action_yml: String,
    #[serde(default)]
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct CiStepPayload {
    #[serde(default)]
    step_db_id: String,
    #[serde(default)]
    step_index: u32,
    #[serde(default)]
    name: String,
    #[serde(default)]
    run: String,
    #[serde(default)]
    uses: String,
    #[serde(default, rename = "with")]
    with_values: BTreeMap<String, String>,
    #[serde(default)]
    shell: String,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    continue_on_error: bool,
    #[serde(default)]
    timeout_minutes: u32,
    #[serde(default, rename = "if")]
    if_expr: String,
}

#[derive(Deserialize)]
struct CiJobContainerPayload {
    #[serde(default)]
    image: String,
    #[serde(default)]
    credentials: Option<CiContainerCredentialPayload>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    volumes: Vec<String>,
    #[serde(default)]
    options: String,
}

#[derive(Deserialize)]
struct CiContainerCredentialPayload {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct CompositeAction {
    #[serde(default)]
    inputs: BTreeMap<String, CompositeActionInput>,
    runs: CompositeRuns,
}

#[derive(Deserialize)]
struct CompositeActionInput {
    #[serde(default)]
    default: Option<serde_yaml::Value>,
}

#[derive(Deserialize)]
struct CompositeRuns {
    using: String,
    #[serde(default)]
    main: String,
    #[serde(default)]
    pre: String,
    #[serde(default, rename = "pre-if")]
    pre_if: String,
    #[serde(default)]
    post: String,
    #[serde(default, rename = "post-if")]
    post_if: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    entrypoint: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    steps: Vec<CiStepPayload>,
}

struct CommandFiles {
    env: PathBuf,
    output: PathBuf,
    path: PathBuf,
    state: PathBuf,
    summary: PathBuf,
    container_env: PathBuf,
}

struct StepOutcome {
    process: ProcessOutput,
    command_updates: CommandFileUpdates,
    artifacts: Vec<ArtifactEvent>,
    cache_save: Option<ActionsCacheSave>,
}

#[derive(Default)]
struct CommandFileUpdates {
    env: BTreeMap<String, String>,
    path_entries: Vec<String>,
    output: BTreeMap<String, String>,
    summary: String,
}

struct ActionsCacheSave {
    entry: PathBuf,
    scope: String,
    key: String,
    paths: Vec<PathBuf>,
    max_bytes: Option<u64>,
}

impl CiStep {
    pub fn step_id(&self) -> String {
        if self.step_db_id.is_empty() {
            format!("step{}", self.step_index)
        } else {
            self.step_db_id.clone()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SwarmDeployPayload {
    pub stack_name: String,
    pub compose_content: String,
    pub extra_files: BTreeMap<String, String>,
    pub prune: bool,
    pub resolve_image: Option<String>,
    pub detach: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppProxySetup {
    pub slug: String,
    pub container_name: String,
    pub port: u16,
    pub domains: Vec<String>,
    pub upstream: String,
}

impl AppProxySetup {
    pub fn default_route_host(&self, internal_apex: &str) -> String {
        let apex = if internal_apex.trim().is_empty() {
            "local"
        } else {
            internal_apex.trim()
        };
        format!("{}.{}", self.slug, apex)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppProxyRemove {
    pub slug: String,
}

#[derive(Clone, Debug)]
pub struct ProcessOutput {
    pub status_success: bool,
    pub output: String,
    pub exit_code: Option<i32>,
}

pub fn parse_run_hooks(payload: &[u8]) -> Result<RunHooksPlan, String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        hook_event: String,
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        block_deploy: bool,
        #[serde(default)]
        timeout_sec: u64,
        #[serde(default)]
        clone_dir: String,
        #[serde(default)]
        env_vars: BTreeMap<String, String>,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    let hook_event = payload.hook_event.trim();
    if hook_event.is_empty() {
        return Err("hook_event is required".to_string());
    }
    validate_label(hook_event, "hook_event")?;
    validate_env(&payload.env_vars)?;
    let work_dir = normalize_work_dir(&payload.clone_dir)?;
    let commands = parse_commands(&payload.commands)?;

    Ok(RunHooksPlan {
        hook_event: hook_event.to_string(),
        commands,
        block_deploy: payload.block_deploy,
        timeout_seconds: nonzero_or(payload.timeout_sec, DEFAULT_HOOK_TIMEOUT_SECONDS),
        work_dir,
        env: payload.env_vars,
    })
}

pub fn build_release_hook_invocations(payload: &[u8]) -> Result<Vec<CommandInvocation>, String> {
    let plan = parse_release_hook(payload)?;
    let mut invocations = Vec::with_capacity(plan.commands.len());
    for command in plan.commands {
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--network".to_string(),
            "none".to_string(),
        ];
        for (key, value) in &plan.env {
            args.push("--env".to_string());
            args.push(format!("{key}={value}"));
        }
        args.push(plan.image_tag.clone());
        args.extend(command.argv);
        invocations.push(CommandInvocation {
            program: "docker".to_string(),
            args,
            work_dir: None,
            env: BTreeMap::new(),
            host_env: BTreeMap::new(),
            timeout_seconds: plan.timeout_seconds,
        });
    }
    Ok(invocations)
}

pub fn parse_release_hook(payload: &[u8]) -> Result<ReleaseHookPlan, String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        image_tag: String,
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        timeout_sec: u64,
        #[serde(default)]
        env_vars: BTreeMap<String, String>,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    let image_tag = payload.image_tag.trim();
    if image_tag.is_empty() {
        return Err("release hook: image_tag is required".to_string());
    }
    validate_image_reference(image_tag)?;
    validate_env(&payload.env_vars)?;
    let commands = parse_commands(&payload.commands)?;
    if commands.is_empty() {
        return Err("no release commands configured".to_string());
    }
    Ok(ReleaseHookPlan {
        image_tag: image_tag.to_string(),
        commands,
        timeout_seconds: nonzero_or(payload.timeout_sec, DEFAULT_RELEASE_HOOK_TIMEOUT_SECONDS),
        env: payload.env_vars,
    })
}

pub fn parse_ci_job(payload: &[u8]) -> Result<CiJobPlan, String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        job_db_id: String,
        #[serde(default)]
        job_id_yaml: String,
        #[serde(default)]
        run_db_id: String,
        #[serde(default)]
        clone_dir: String,
        #[serde(default)]
        container: Option<CiJobContainerPayload>,
        #[serde(default)]
        services: BTreeMap<String, CiJobContainerPayload>,
        #[serde(default)]
        repo_owner: String,
        #[serde(default)]
        repo_name: String,
        #[serde(default)]
        repo_clone_token: String,
        #[serde(default)]
        head_sha: String,
        #[serde(default)]
        trigger_ref: String,
        #[serde(default)]
        oidc_token_requests_allowed: bool,
        #[serde(default)]
        oidc_request_url: String,
        #[serde(default)]
        oidc_request_token: String,
        #[serde(default)]
        sandbox_policy: String,
        #[serde(default)]
        timeout_seconds: u64,
        #[serde(default)]
        steps: Vec<CiStepPayload>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        matrix_values: BTreeMap<String, String>,
        #[serde(default)]
        secret_keys: Vec<String>,
        #[serde(default)]
        action_bundles: Vec<ActionBundlePayload>,
        #[serde(default)]
        available_artifacts: Vec<AvailableArtifactPayload>,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    let job_db_id = payload.job_db_id.trim();
    if job_db_id.is_empty() {
        return Err("ci job: job_db_id is required".to_string());
    }
    validate_label(job_db_id, "job_db_id")?;
    if !payload.job_id_yaml.trim().is_empty() {
        validate_label(payload.job_id_yaml.trim(), "job_id_yaml")?;
    }
    if !payload.run_db_id.trim().is_empty() {
        validate_label(payload.run_db_id.trim(), "run_db_id")?;
    }
    validate_optional_github_component(&payload.repo_owner, "repo_owner")?;
    validate_optional_github_component(&payload.repo_name, "repo_name")?;
    validate_optional_head_sha(&payload.head_sha)?;
    let sandbox_policy = parse_ci_sandbox_policy(&payload.sandbox_policy)?;
    validate_env(&payload.env)?;
    for key in &payload.secret_keys {
        validate_env_key(key)?;
    }
    let mut action_bundles = Vec::with_capacity(payload.action_bundles.len());
    for bundle in payload.action_bundles {
        action_bundles.push(parse_action_bundle(bundle)?);
    }
    let mut available_artifacts = Vec::with_capacity(payload.available_artifacts.len());
    for artifact in payload.available_artifacts {
        available_artifacts.push(parse_available_artifact(artifact)?);
    }
    if payload.steps.is_empty() {
        return Err("ci job: at least one run step is required".to_string());
    }
    if payload.steps.len() > MAX_CI_STEPS {
        return Err(format!("ci job: steps exceeds {MAX_CI_STEPS}"));
    }
    let container = parse_ci_job_container(payload.container)?;
    let services = parse_ci_job_services(job_db_id, payload.services)?;
    let timeout_seconds = bounded_timeout(
        payload.timeout_seconds,
        DEFAULT_CI_JOB_TIMEOUT_SECONDS,
        "timeout_seconds",
    )?;
    let clone_dir = if payload.clone_dir.trim().is_empty() {
        default_ci_clone_dir(payload.run_db_id.trim(), job_db_id)?
    } else {
        let clone_dir = normalize_work_dir(&payload.clone_dir)?;
        validate_managed_ci_clone_dir(Path::new(&clone_dir))?;
        clone_dir
    };
    let mut steps = Vec::with_capacity(payload.steps.len());
    for step in payload.steps {
        steps.push(parse_ci_step(step)?);
    }
    Ok(CiJobPlan {
        job_db_id: job_db_id.to_string(),
        job_id_yaml: payload.job_id_yaml.trim().to_string(),
        run_db_id: payload.run_db_id.trim().to_string(),
        timeout_seconds,
        clone_dir,
        container,
        services,
        repo_owner: payload.repo_owner.trim().to_string(),
        repo_name: payload.repo_name.trim().to_string(),
        repo_clone_token: payload.repo_clone_token.trim().to_string(),
        head_sha: payload.head_sha.trim().to_string(),
        trigger_ref: payload.trigger_ref.trim().to_string(),
        oidc_token_requests_allowed: payload.oidc_token_requests_allowed,
        oidc_request_url: payload.oidc_request_url.trim().to_string(),
        oidc_request_token: payload.oidc_request_token.trim().to_string(),
        sandbox_policy,
        env: payload.env,
        matrix_values: payload.matrix_values,
        secret_keys: payload.secret_keys,
        action_bundles,
        available_artifacts,
        steps,
    })
}

fn parse_action_bundle(payload: ActionBundlePayload) -> Result<ActionBundle, String> {
    let uses = payload.uses.trim();
    if uses.is_empty() {
        return Err("ci job: action_bundles[].uses is required".to_string());
    }
    let local_path = payload.local_path.trim();
    validate_local_action_ref(local_path)?;
    if !local_path.starts_with("./.permanu/action-bundles/") {
        return Err(
            "ci job: action_bundles[].local_path must stay under ./.permanu/action-bundles"
                .to_string(),
        );
    }
    let action_filename = payload.action_filename.trim();
    if action_filename != "action.yml" && action_filename != "action.yaml" {
        return Err(
            "ci job: action_bundles[].action_filename must be action.yml or action.yaml"
                .to_string(),
        );
    }
    if payload.action_yml.trim().is_empty() {
        return Err("ci job: action_bundles[].action_yml is required".to_string());
    }
    if payload.action_yml.len() > MAX_COMPOSE_CONTENT_BYTES {
        return Err("ci job: action_bundles[].action_yml is too large".to_string());
    }
    if payload.files.len() > MAX_ACTION_BUNDLE_FILES {
        return Err(format!(
            "ci job: action_bundles[].files exceeds {MAX_ACTION_BUNDLE_FILES} files"
        ));
    }
    let mut total_file_bytes = 0usize;
    let mut files = BTreeMap::new();
    for (path, content) in payload.files {
        validate_action_bundle_file_path(&path)?;
        if content.len() > MAX_ACTION_BUNDLE_FILE_BYTES {
            return Err(format!(
                "ci job: action bundle file {path:?} exceeds {MAX_ACTION_BUNDLE_FILE_BYTES} bytes"
            ));
        }
        total_file_bytes = total_file_bytes
            .checked_add(content.len())
            .ok_or_else(|| "ci job: action bundle files are too large".to_string())?;
        if total_file_bytes > MAX_ACTION_BUNDLE_TOTAL_BYTES {
            return Err(format!(
                "ci job: action_bundles[].files exceeds {MAX_ACTION_BUNDLE_TOTAL_BYTES} bytes"
            ));
        }
        if path == action_filename {
            return Err("ci job: action_bundles[].files must not include action.yml".to_string());
        }
        files.insert(path, content);
    }
    Ok(ActionBundle {
        uses: uses.to_string(),
        local_path: local_path.to_string(),
        action_filename: action_filename.to_string(),
        action_yml: payload.action_yml,
        files,
    })
}

fn validate_action_bundle_file_path(path: &str) -> Result<(), String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("ci job: action bundle file path is required".to_string());
    }
    if path.as_bytes().contains(&0) || path.contains('\\') {
        return Err(format!("ci job: invalid action bundle file path {path:?}"));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        return Err(format!(
            "ci job: action bundle file path {path:?} must be relative"
        ));
    }
    for component in parsed.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(format!(
                "ci job: action bundle file path {path:?} must stay inside the action directory"
            ));
        }
    }
    Ok(())
}

fn parse_available_artifact(
    payload: AvailableArtifactPayload,
) -> Result<AvailableArtifact, String> {
    let name = payload.name.trim();
    if name.is_empty() {
        return Err("ci job: available_artifacts[].name is required".to_string());
    }
    validate_artifact_name(name)?;
    let storage_path = payload.storage_path.trim();
    let download_url = payload.download_url.trim();
    let provider_url = if payload.provider_url.trim().is_empty() {
        payload.remote_url.trim()
    } else {
        payload.provider_url.trim()
    };
    if storage_path.is_empty() && download_url.is_empty() && provider_url.is_empty() {
        return Err(
            "ci job: available_artifacts[] requires storage_path, download_url, or provider_url"
                .to_string(),
        );
    }
    if !storage_path.is_empty() {
        validate_artifact_storage_path_fragment(storage_path)?;
    }
    if !download_url.is_empty() {
        validate_control_plane_artifact_download_url(download_url)?;
    }
    Ok(AvailableArtifact {
        name: name.to_string(),
        storage_path: storage_path.to_string(),
        download_url: download_url.to_string(),
        provider_url: provider_url.to_string(),
        size_bytes: payload.size_bytes,
        hash: payload.hash.trim().to_string(),
    })
}

pub fn handle_ci_job(command_id: &str, payload: &[u8]) -> AgentCommandResult {
    handle_ci_job_with_cancellation(command_id, payload, Arc::new(AtomicBool::new(false)))
}

pub fn handle_ci_job_with_cancellation(
    command_id: &str,
    payload: &[u8],
    cancellation: CancellationSignal,
) -> AgentCommandResult {
    handle_ci_job_with_cancellation_and_logs(command_id, payload, cancellation, None)
}

pub fn handle_ci_job_with_cancellation_and_logs(
    command_id: &str,
    payload: &[u8],
    cancellation: CancellationSignal,
    log_forwarder: Option<Arc<LogForwarder>>,
) -> AgentCommandResult {
    match parse_ci_job(payload) {
        Ok(plan) => execute_ci_job(command_id, &plan, &cancellation, log_forwarder),
        Err(err) => ci_job_command_result(
            command_id,
            "failure",
            None,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            format!("invalid CI job payload: {err}"),
        ),
    }
}

fn parse_ci_step(step: CiStepPayload) -> Result<CiStep, String> {
    if !step.step_db_id.trim().is_empty() {
        validate_label(step.step_db_id.trim(), "step_db_id")?;
    }
    let run = step.run.trim();
    let uses = step.uses.trim();
    if run.is_empty() && uses.is_empty() {
        return Err("ci job: run step command is required".to_string());
    }
    if !run.is_empty() && !uses.is_empty() {
        return Err("ci job: a step cannot define both run and uses".to_string());
    }
    if !uses.is_empty() && !is_builtin_ci_action(uses) {
        validate_local_action_ref(uses)?;
    }
    validate_ci_if_expr(&step.if_expr)?;
    if run.len() > 64 * 1024 || run.as_bytes().contains(&0) {
        return Err("ci job: invalid run command".to_string());
    }
    validate_env(&step.env)?;
    validate_ci_working_dir_fragment(&step.working_dir)?;
    let shell = step.shell.trim().to_ascii_lowercase();
    validate_ci_shell(&shell)?;
    let argv = Vec::new();
    if step.timeout_minutes > 24 * 60 {
        return Err("ci job: step timeout_minutes exceeds 1440".to_string());
    }
    Ok(CiStep {
        step_db_id: step.step_db_id.trim().to_string(),
        step_index: step.step_index,
        name: step.name.trim().to_string(),
        run: run.to_string(),
        uses: uses.to_string(),
        with: step.with_values,
        shell,
        working_dir: step.working_dir.trim().to_string(),
        env: step.env,
        continue_on_error: step.continue_on_error,
        timeout_minutes: step.timeout_minutes,
        if_expr: step.if_expr.trim().to_string(),
        argv,
    })
}

fn validate_ci_if_expr(value: &str) -> Result<(), String> {
    let value = normalize_ci_if_expr(value);
    match value.as_str() {
        "" | "true" | "false" | "success()" | "failure()" | "always()" | "cancelled()" => Ok(()),
        expr if parse_starts_with_github_ref(expr).is_some() => Ok(()),
        _ => Err("ci job: unsupported if expression; supported: empty, true, false, success(), failure(), always(), cancelled(), startsWith(github.ref, 'prefix')".to_string()),
    }
}

fn should_run_ci_step(plan: &CiJobPlan, expr: &str, saw_failure: bool) -> bool {
    let expr = normalize_ci_if_expr(expr);
    match expr.as_str() {
        "" | "true" => true,
        "false" => false,
        "success()" => !saw_failure,
        "failure()" => saw_failure,
        "always()" => true,
        "cancelled()" => false,
        expr => parse_starts_with_github_ref(expr)
            .map(|prefix| plan.trigger_ref.starts_with(prefix))
            .unwrap_or(false),
    }
}

fn normalize_ci_if_expr(expr: &str) -> String {
    let trimmed = expr.trim();
    if let Some(inner) = trimmed
        .strip_prefix("${{")
        .and_then(|value| value.strip_suffix("}}"))
    {
        return normalize_ci_if_expr_atom(inner.trim());
    }
    normalize_ci_if_expr_atom(trimmed)
}

fn normalize_ci_if_expr_atom(expr: &str) -> String {
    if matches!(
        expr.to_ascii_lowercase().as_str(),
        "true" | "false" | "success()" | "failure()" | "always()" | "cancelled()"
    ) {
        return expr.to_ascii_lowercase();
    }
    expr.to_string()
}

fn parse_starts_with_github_ref(expr: &str) -> Option<&str> {
    let rest = expr.strip_prefix("startsWith(github.ref,")?.trim();
    let rest = rest.strip_suffix(')')?.trim();
    rest.strip_prefix('\'')?.strip_suffix('\'')
}

fn validate_ci_working_dir_fragment(working_dir: &str) -> Result<(), String> {
    let working_dir = working_dir.trim();
    if working_dir.is_empty() {
        return Ok(());
    }
    if working_dir.as_bytes().contains(&0)
        || working_dir.contains('\n')
        || working_dir.contains('\r')
        || working_dir.contains('\\')
    {
        return Err("invalid working_dir".to_string());
    }
    let path = Path::new(working_dir);
    if path.is_absolute() {
        return Err("working_dir must be relative and stay inside workspace".to_string());
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("working_dir must stay inside workspace".to_string());
        }
    }
    Ok(())
}

fn validate_ci_shell(shell: &str) -> Result<(), String> {
    match shell {
        "" | "sh" | "bash" => Ok(()),
        _ => Err("ci job: shell must be empty, sh, or bash".to_string()),
    }
}

fn parse_ci_job_container(
    payload: Option<CiJobContainerPayload>,
) -> Result<Option<CiJobContainer>, String> {
    let Some(payload) = payload else {
        return Ok(None);
    };
    let image = payload.image.trim();
    if image.is_empty() {
        return Err("ci job: container image is required".to_string());
    }
    validate_image_reference(image)?;
    validate_env(&payload.env)?;
    if !payload.ports.is_empty() {
        return Err("ci job: container ports are not supported yet".to_string());
    }
    if !payload.volumes.is_empty() {
        return Err("ci job: container volumes are not supported yet".to_string());
    }
    if !payload.options.trim().is_empty() {
        return Err("ci job: container options are not supported yet".to_string());
    }
    Ok(Some(CiJobContainer {
        image: image.to_string(),
        credentials: parse_ci_container_credentials(payload.credentials)?,
        env: payload.env,
        options: Vec::new(),
    }))
}

fn parse_ci_container_credentials(
    payload: Option<CiContainerCredentialPayload>,
) -> Result<Option<CiContainerCredential>, String> {
    let Some(payload) = payload else {
        return Ok(None);
    };
    let username = payload.username.trim();
    let password = payload.password.trim();
    if username.is_empty() || password.is_empty() {
        return Err("ci job: container credentials require username and password".to_string());
    }
    for value in [username, password] {
        if value.as_bytes().contains(&0) || value.contains('\n') || value.contains('\r') {
            return Err("ci job: container credentials must be single-line".to_string());
        }
    }
    Ok(Some(CiContainerCredential {
        username: username.to_string(),
        password: password.to_string(),
    }))
}

fn parse_ci_sandbox_policy(value: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    match value {
        "" => Ok(None),
        "untrusted" => Ok(Some(value.to_string())),
        _ => Err("ci job: sandbox_policy must be empty or untrusted".to_string()),
    }
}

fn parse_ci_job_services(
    job_db_id: &str,
    payload: BTreeMap<String, CiJobContainerPayload>,
) -> Result<BTreeMap<String, CiJobService>, String> {
    let mut services = BTreeMap::new();
    let network = service_network_name(job_db_id);
    for (name, service) in payload {
        let service_name = name.trim();
        if service_name.is_empty() {
            return Err("ci job: service name is required".to_string());
        }
        let image = service.image.trim();
        if image.is_empty() {
            return Err(format!("ci job: service {service_name}: image is required"));
        }
        validate_image_reference(image)?;
        validate_env(&service.env)?;
        for port in &service.ports {
            validate_service_port(port)?;
        }
        let network_alias = sanitized_docker_component(service_name);
        let volumes = parse_ci_service_volumes(&network, &network_alias, &service.volumes)
            .map_err(|err| format!("ci job: service {service_name}: {err}"))?;
        let options = parse_ci_service_options(&service.options)
            .map_err(|err| format!("ci job: service {service_name}: {err}"))?;
        services.insert(
            name,
            CiJobService {
                image: image.to_string(),
                credentials: parse_ci_container_credentials(service.credentials)?,
                env: service.env,
                ports: service.ports,
                volumes,
                options,
                container_name: format!("{network}-{network_alias}"),
                network_alias,
            },
        );
    }
    Ok(services)
}

fn validate_service_port(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 32
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b':' | b'/' | b'-'))
    {
        return Err("ci job: invalid service container port".to_string());
    }
    Ok(())
}

fn parse_ci_service_volumes(
    network: &str,
    network_alias: &str,
    volumes: &[String],
) -> Result<Vec<String>, String> {
    let mut parsed = Vec::new();
    for (index, volume) in volumes.iter().enumerate() {
        let volume = volume.trim();
        if volume.is_empty()
            || volume.as_bytes().contains(&0)
            || volume.contains('\n')
            || volume.contains('\r')
        {
            return Err("service volume must be a non-empty single-line value".to_string());
        }
        let parts: Vec<&str> = volume.split(':').collect();
        match parts.as_slice() {
            [target] => {
                validate_ci_service_volume_target(target)?;
                parsed.push(volume.to_string());
            }
            [source, target] | [source, target, "ro"] | [source, target, "rw"] => {
                validate_ci_service_volume_name(source)?;
                validate_ci_service_volume_target(target)?;
                let per_job_source = format!("{network}-{network_alias}-vol-{index}");
                if parts.len() == 3 {
                    parsed.push(format!("{per_job_source}:{target}:{}", parts[2]));
                } else {
                    parsed.push(format!("{per_job_source}:{target}"));
                }
            }
            _ => {
                return Err(
                    "service volume must be /container/path or name:/container/path[:ro|rw]"
                        .to_string(),
                )
            }
        }
    }
    Ok(parsed)
}

fn validate_ci_service_volume_name(source: &str) -> Result<(), String> {
    if source.is_empty()
        || source.starts_with('.')
        || source.contains('/')
        || source.contains('\\')
        || source.contains('~')
        || !source
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(
            "service volume source must be a Docker volume name, not a host path".to_string(),
        );
    }
    Ok(())
}

fn validate_ci_service_volume_target(target: &str) -> Result<(), String> {
    if !target.starts_with('/')
        || target.contains("..")
        || target.contains('\\')
        || target.contains('\0')
        || target.contains('\n')
        || target.contains('\r')
    {
        return Err(
            "service volume target must be an absolute container path without traversal"
                .to_string(),
        );
    }
    Ok(())
}

fn parse_ci_service_options(options: &str) -> Result<Vec<String>, String> {
    let argv = split_ci_service_options(options)?;
    let mut parsed = Vec::new();
    let mut index = 0;
    while index < argv.len() {
        let token = &argv[index];
        let (flag, inline_value) = token
            .split_once('=')
            .map(|(flag, value)| (flag.to_string(), Some(value.to_string())))
            .unwrap_or_else(|| (token.clone(), None));
        if !is_supported_ci_service_health_option(&flag) {
            return Err(format!(
                "unsupported service option {flag:?}; only Docker --health-* flags are supported"
            ));
        }
        let value = if let Some(value) = inline_value {
            value
        } else {
            index += 1;
            argv.get(index)
                .cloned()
                .ok_or_else(|| format!("service option {flag} requires a value"))?
        };
        if value.is_empty()
            || value.as_bytes().contains(&0)
            || value.contains('\n')
            || value.contains('\r')
        {
            return Err(format!("service option {flag} value must be single-line"));
        }
        parsed.extend([flag, value]);
        index += 1;
    }
    Ok(parsed)
}

fn split_ci_service_options(options: &str) -> Result<Vec<String>, String> {
    let trimmed = options.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    reject_shell_syntax(trimmed).map_err(|_| {
        "unsupported shell syntax in service options; only Docker --health-* flags are supported"
            .to_string()
    })?;
    parse_command_argv(trimmed).map_err(|err| err.replace("hook command", "service options"))
}

fn is_supported_ci_service_health_option(flag: &str) -> bool {
    matches!(
        flag,
        "--health-cmd"
            | "--health-interval"
            | "--health-timeout"
            | "--health-start-period"
            | "--health-start-interval"
            | "--health-retries"
            | "--cpus"
            | "--cpu-shares"
            | "--memory"
            | "--memory-reservation"
            | "--memory-swap"
            | "--shm-size"
    )
}

fn service_network_name(job_db_id: &str) -> String {
    format!("permanu-ci-{}", sanitized_docker_component(job_db_id))
}

fn sanitized_docker_component(value: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !output.is_empty() {
            output.push('-');
            last_dash = true;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        "job".to_string()
    } else {
        output
    }
}

fn execute_ci_job(
    command_id: &str,
    plan: &CiJobPlan,
    cancellation: &CancellationSignal,
    log_forwarder: Option<Arc<LogForwarder>>,
) -> AgentCommandResult {
    let mut log = String::new();
    append_capped(
        &mut log,
        &format!("starting CI job {}\n", display_ci_job_name(plan)),
    );
    let job_deadline = Instant::now() + Duration::from_secs(plan.timeout_seconds);
    if cancellation.load(Ordering::SeqCst) {
        return ci_job_command_result(
            command_id,
            "cancelled",
            None,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            "ci job cancelled before checkout",
        );
    }
    if let Err(err) = ensure_ci_checkout(plan, &mut log, job_deadline, cancellation) {
        append_capped(&mut log, &format!("checkout failed: {err}"));
        cleanup_ci_checkout(plan, &mut log);
        return ci_job_command_result(
            command_id,
            "failure",
            None,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            log.trim(),
        );
    }
    if let Err(err) = materialize_action_bundles(plan, &mut log) {
        append_capped(
            &mut log,
            &format!("action bundle materialization failed: {err}"),
        );
        cleanup_ci_checkout(plan, &mut log);
        return ci_job_command_result(
            command_id,
            "failure",
            None,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            log.trim(),
        );
    }
    let service_env = match start_ci_services(plan, &mut log, job_deadline, cancellation) {
        Ok(env) => env,
        Err(err) => {
            append_capped(&mut log, &format!("service startup failed: {err}\n"));
            cleanup_ci_services(plan, &mut log);
            cleanup_ci_checkout(plan, &mut log);
            return ci_job_command_result(
                command_id,
                "failure",
                None,
                BTreeMap::new(),
                BTreeMap::new(),
                Vec::new(),
                Vec::new(),
                log.trim(),
            );
        }
    };
    let mut failed_step_index = None;
    let mut statuses = BTreeMap::new();
    let mut step_logs = BTreeMap::new();
    let mut artifacts = Vec::new();
    let mut cache_events = Vec::new();
    let mut pending_cache_saves = Vec::new();
    let mut runtime_env = service_env;
    let mut saw_failure = false;
    for step in &plan.steps {
        let step_id = step.step_id();
        let label = display_ci_step_name(step);
        if cancellation.load(Ordering::SeqCst) {
            append_capped(&mut log, "ci job cancelled\n");
            statuses.insert(step_id, "cancelled".to_string());
            cleanup_ci_services(plan, &mut log);
            cleanup_ci_checkout(plan, &mut log);
            return ci_job_command_result(
                command_id,
                "cancelled",
                None,
                statuses,
                step_logs,
                artifacts,
                cache_events,
                log.trim(),
            );
        }
        if !should_run_ci_step(plan, &step.if_expr, saw_failure) {
            append_capped(&mut log, &format!("[{label}] skipped\n"));
            statuses.insert(step_id, "skipped".to_string());
            continue;
        }
        let env = merged_ci_env(plan, step, &runtime_env);
        let redactor = SecretRedactor::from_env(&env, &plan.secret_keys);
        append_capped(&mut log, &format!("[{label}] starting\n"));
        let step_started = Instant::now();
        match execute_ci_step(
            plan,
            step,
            &artifacts,
            &env,
            &label,
            &mut log,
            job_deadline,
            cancellation,
            log_forwarder.clone(),
            redactor.clone(),
        ) {
            Ok(outcome) if outcome.process.status_success => {
                apply_command_updates(&mut runtime_env, outcome.command_updates, &plan.clone_dir);
                artifacts.extend(outcome.artifacts);
                if let Some(cache_save) = outcome.cache_save {
                    pending_cache_saves.push(cache_save);
                }
                let output = redactor.redact(&outcome.process.output);
                let step_log = render_enterprise_step_log(
                    plan,
                    step,
                    &env,
                    &output,
                    &outcome.process,
                    step_started.elapsed(),
                    &redactor,
                );
                step_logs.insert(step_id.clone(), step_log);
                append_capped(&mut log, &output);
                if !output.is_empty() {
                    append_capped(&mut log, "\n");
                }
                append_capped(&mut log, &format!("[{label}] completed successfully\n"));
                statuses.insert(step_id, "success".to_string());
            }
            Ok(outcome) => {
                apply_command_updates(&mut runtime_env, outcome.command_updates, &plan.clone_dir);
                artifacts.extend(outcome.artifacts);
                if let Some(cache_save) = outcome.cache_save {
                    pending_cache_saves.push(cache_save);
                }
                let output = redactor.redact(&outcome.process.output);
                let step_log = render_enterprise_step_log(
                    plan,
                    step,
                    &env,
                    &output,
                    &outcome.process,
                    step_started.elapsed(),
                    &redactor,
                );
                step_logs.insert(step_id.clone(), step_log);
                append_capped(&mut log, &output);
                if !output.is_empty() {
                    append_capped(&mut log, "\n");
                }
                append_capped(&mut log, &format!("[{label}] failed\n"));
                statuses.insert(step_id, "failure".to_string());
                saw_failure = true;
                if !step.continue_on_error {
                    failed_step_index = Some(step.step_index);
                    break;
                }
                append_capped(&mut log, &format!("[{label}] continuing on error\n"));
            }
            Err(err) => {
                let output = redactor.redact(&err);
                if !output.trim().is_empty() {
                    step_logs.insert(step_id.clone(), output.trim().to_string());
                }
                if cancellation.load(Ordering::SeqCst) {
                    append_capped(&mut log, &redactor.redact(&format!("[{label}] {err}\n")));
                    statuses.insert(step_id, "cancelled".to_string());
                    cleanup_ci_services(plan, &mut log);
                    cleanup_ci_checkout(plan, &mut log);
                    return ci_job_command_result(
                        command_id,
                        "cancelled",
                        None,
                        statuses,
                        step_logs,
                        artifacts,
                        cache_events,
                        log.trim(),
                    );
                }
                append_capped(&mut log, &redactor.redact(&format!("[{label}] {err}\n")));
                statuses.insert(step_id, "failure".to_string());
                saw_failure = true;
                if !step.continue_on_error {
                    failed_step_index = Some(step.step_index);
                    break;
                }
                append_capped(&mut log, &format!("[{label}] continuing on error\n"));
            }
        }
    }
    append_capped(
        &mut log,
        &format!("step statuses: {}\n", render_step_statuses(&statuses)),
    );
    if failed_step_index.is_none() {
        for cache_save in pending_cache_saves {
            match save_actions_cache_paths(&cache_save.entry, &cache_save) {
                Ok(Some(event)) => cache_events.push(event),
                Ok(None) => {}
                Err(err) => {
                    append_capped(&mut log, &format!("actions/cache save skipped: {err}\n"));
                }
            }
        }
    }
    cleanup_ci_services(plan, &mut log);
    cleanup_ci_checkout(plan, &mut log);
    if let Some(index) = failed_step_index {
        append_capped(&mut log, &format!("ci job failed at step {index}"));
        ci_job_command_result(
            command_id,
            "failure",
            Some(index),
            statuses,
            step_logs,
            artifacts,
            cache_events,
            log.trim(),
        )
    } else {
        append_capped(&mut log, "ci job completed");
        ci_job_command_result(
            command_id,
            "success",
            None,
            statuses,
            step_logs,
            artifacts,
            cache_events,
            log.trim(),
        )
    }
}

fn cleanup_ci_checkout(plan: &CiJobPlan, log: &mut String) {
    match normalize_work_dir(&plan.clone_dir) {
        Ok(path) => {
            let clone_dir = PathBuf::from(path);
            if let Err(err) = validate_managed_ci_clone_dir(&clone_dir) {
                append_capped(log, &format!("checkout cleanup skipped: {err}\n"));
                return;
            }
            if !clone_dir.exists() {
                return;
            }
            if let Err(err) = fs::remove_dir_all(&clone_dir) {
                append_capped(log, &format!("checkout cleanup failed: {err}\n"));
            } else {
                cleanup_empty_ci_workspace_parents(&clone_dir);
            }
        }
        Err(err) => append_capped(log, &format!("checkout cleanup skipped: {err}\n")),
    }
}

fn start_ci_services(
    plan: &CiJobPlan,
    log: &mut String,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
) -> Result<BTreeMap<String, String>, String> {
    let Some(network) = plan.service_network_name() else {
        return Ok(BTreeMap::new());
    };
    let mut runtime_env = BTreeMap::new();
    let credential_session = DockerCredentialSession::for_plan(plan)?;
    run_docker_lifecycle_command_with_env(
        &strings(["network", "create", &network]),
        job_deadline,
        cancellation,
        credential_session.env(),
    )?;
    append_capped(log, &format!("created CI service network {network}\n"));
    for (name, service) in &plan.services {
        if let Some(credentials) = &service.credentials {
            docker_login_for_image(
                &service.image,
                credentials,
                job_deadline,
                cancellation,
                credential_session.env(),
            )
            .map_err(|err| format!("ci job: service {name}: registry login failed: {err}"))?;
            append_capped(
                log,
                &format!("authenticated registry for CI service {name}\n"),
            );
        }
        let mut args = strings([
            "run",
            "--detach",
            "--name",
            &service.container_name,
            "--network",
            &network,
            "--network-alias",
            &service.network_alias,
        ]);
        for (key, value) in &service.env {
            validate_env_key(key)?;
            if value.as_bytes().contains(&0) || value.contains('\n') || value.contains('\r') {
                return Err(format!(
                    "ci job: service {name}: env values must be single-line"
                ));
            }
            args.extend(strings(["--env", &format!("{key}={value}")]));
        }
        for volume in &service.volumes {
            args.extend(strings(["--volume", volume]));
        }
        if plan.container.is_none() {
            for port in &service.ports {
                let publish = host_shell_service_publish_arg(port);
                if publish != *port {
                    append_capped(
                        log,
                        &format!(
                            "service {name} port {port} is not free on this runner; publishing on a dynamic loopback port\n"
                        ),
                    );
                }
                args.extend(strings(["--publish", &publish]));
            }
        }
        args.extend(service.options.clone());
        args.push(service.image.clone());
        run_docker_lifecycle_command_with_env(
            &args,
            job_deadline,
            cancellation,
            credential_session.env(),
        )?;
        append_capped(log, &format!("started CI service {name}\n"));
        wait_for_ci_service_ready(
            service,
            job_deadline,
            cancellation,
            credential_session.env(),
        )?;
        if plan.container.is_none() {
            record_host_shell_service_ports(
                name,
                service,
                &mut runtime_env,
                job_deadline,
                cancellation,
                credential_session.env(),
            )?;
        }
        append_capped(log, &format!("CI service {name} ready\n"));
    }
    Ok(runtime_env)
}

fn host_shell_service_publish_arg(port: &str) -> String {
    let Some((host, container)) = split_service_port(port) else {
        return port.to_string();
    };
    if host_port_is_available(host) {
        return port.to_string();
    }
    format!("127.0.0.1::{container}")
}

fn split_service_port(port: &str) -> Option<(&str, &str)> {
    let mut parts = port.splitn(2, ':');
    let host = parts.next()?.trim();
    let container = parts.next()?.trim();
    if host.is_empty() || container.is_empty() || host.contains('-') {
        return None;
    }
    Some((host, container))
}

fn host_port_is_available(port: &str) -> bool {
    let Ok(port) = port.parse::<u16>() else {
        return true;
    };
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn record_host_shell_service_ports(
    name: &str,
    service: &CiJobService,
    runtime_env: &mut BTreeMap<String, String>,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    docker_env: &BTreeMap<String, String>,
) -> Result<(), String> {
    for port in &service.ports {
        let Some((_, container)) = split_service_port(port) else {
            continue;
        };
        let output = run_docker_command_with_env(
            &strings(["port", &service.container_name, container]),
            remaining_job_timeout(job_deadline)?.min(Duration::from_secs(10)),
            cancellation,
            docker_env,
        )?;
        let Some(host_port) = parse_docker_port_output(&output.output) else {
            continue;
        };
        let service_key = sanitized_env_component(name);
        runtime_env.insert(format!("{service_key}_PORT"), host_port.clone());
        if service_key == "POSTGRES" || container.starts_with("5432") {
            runtime_env.insert("POSTGRES_PORT".to_string(), host_port.clone());
            runtime_env.insert("DB_PORT".to_string(), host_port.clone());
            runtime_env.insert("TEST_DB_PORT".to_string(), host_port);
        }
    }
    Ok(())
}

fn parse_docker_port_output(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let value = line.trim().rsplit_once(':')?.1.trim();
        if value.chars().all(|ch| ch.is_ascii_digit()) {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn sanitized_env_component(value: &str) -> String {
    let mut output = String::new();
    let mut last_underscore = false;
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_uppercase());
            last_underscore = false;
        } else if !last_underscore && !output.is_empty() {
            output.push('_');
            last_underscore = true;
        }
    }
    while output.ends_with('_') {
        output.pop();
    }
    if output.is_empty() {
        "SERVICE".to_string()
    } else {
        output
    }
}

fn wait_for_ci_service_ready(
    service: &CiJobService,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    docker_env: &BTreeMap<String, String>,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let process = run_docker_command_with_env(
            &strings([
                "inspect",
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{if .State.Running}}running{{else}}stopped:{{.State.ExitCode}}{{end}}{{end}}",
                &service.container_name,
            ]),
            remaining_job_timeout(job_deadline)?
                .min(Duration::from_secs(10))
                .min(deadline.saturating_duration_since(Instant::now())),
            cancellation,
            docker_env,
        )?;
        if !process.status_success {
            return Err(format!(
                "inspect CI service {} failed: {}",
                service.network_alias,
                process.output.trim()
            ));
        }
        let status = process.output.trim();
        match status {
            "healthy" | "running" => return Ok(()),
            "unhealthy" => {
                return Err(format!(
                    "CI service {} reported unhealthy",
                    service.network_alias
                ));
            }
            value if value.starts_with("stopped:") => {
                return Err(format!(
                    "CI service {} exited before readiness ({value})",
                    service.network_alias
                ));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "CI service {} was not ready within 60s (last status: {status})",
                service.network_alias
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn cleanup_ci_services(plan: &CiJobPlan, log: &mut String) {
    let Some(network) = plan.service_network_name() else {
        return;
    };
    let credential_session = DockerCredentialSession::for_plan(plan).ok();
    for service in plan.services.values() {
        if let Err(err) = run_docker_best_effort_with_env(
            &strings(["rm", "-fv", &service.container_name]),
            credential_session
                .as_ref()
                .map(DockerCredentialSession::env)
                .unwrap_or(&BTreeMap::new()),
        ) {
            append_capped(
                log,
                &format!(
                    "service cleanup failed for {}: {err}\n",
                    service.container_name
                ),
            );
        }
    }
    if let Err(err) = run_docker_best_effort_with_env(
        &strings(["network", "rm", &network]),
        credential_session
            .as_ref()
            .map(DockerCredentialSession::env)
            .unwrap_or(&BTreeMap::new()),
    ) {
        append_capped(log, &format!("service network cleanup failed: {err}\n"));
    }
}

fn run_docker_lifecycle_command(
    args: &[String],
    job_deadline: Instant,
    cancellation: &CancellationSignal,
) -> Result<(), String> {
    run_docker_lifecycle_command_with_env(args, job_deadline, cancellation, &BTreeMap::new())
}

fn run_docker_lifecycle_command_with_env(
    args: &[String],
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    docker_env: &BTreeMap<String, String>,
) -> Result<(), String> {
    let process = run_docker_command_with_env(
        args,
        remaining_job_timeout(job_deadline)?,
        cancellation,
        docker_env,
    )?;
    if process.status_success {
        Ok(())
    } else if process.output.is_empty() {
        Err("docker exited unsuccessfully".to_string())
    } else {
        Err(process.output)
    }
}

fn docker_login_for_image(
    image: &str,
    credentials: &CiContainerCredential,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    docker_env: &BTreeMap<String, String>,
) -> Result<(), String> {
    let registry = docker_registry_for_image(image);
    let args = strings([
        "login",
        &registry,
        "--username",
        &credentials.username,
        "--password-stdin",
    ]);
    let process = run_docker_command_with_stdin_and_env(
        &args,
        &(credentials.password.clone() + "\n"),
        remaining_job_timeout(job_deadline)?,
        cancellation,
        docker_env,
    )?;
    if process.status_success {
        Ok(())
    } else if process.output.is_empty() {
        Err("docker login exited unsuccessfully".to_string())
    } else {
        Err(process.output)
    }
}

fn docker_registry_for_image(image: &str) -> String {
    let first = image.split('/').next().unwrap_or_default();
    if first.contains('.') || first.contains(':') || first == "localhost" {
        first.to_string()
    } else {
        "docker.io".to_string()
    }
}

fn run_docker_best_effort(args: &[String]) -> Result<(), String> {
    run_docker_best_effort_with_env(args, &BTreeMap::new())
}

fn run_docker_best_effort_with_env(
    args: &[String],
    docker_env: &BTreeMap<String, String>,
) -> Result<(), String> {
    let cancellation = Arc::new(AtomicBool::new(false));
    let process =
        run_docker_command_with_env(args, Duration::from_secs(30), &cancellation, docker_env)?;
    if process.status_success {
        Ok(())
    } else if process.output.is_empty() {
        Err("docker exited unsuccessfully".to_string())
    } else {
        Err(process.output)
    }
}

fn run_docker_command(
    args: &[String],
    timeout: Duration,
    cancellation: &CancellationSignal,
) -> Result<ProcessOutput, String> {
    run_docker_command_with_env(args, timeout, cancellation, &BTreeMap::new())
}

fn run_docker_command_with_env(
    args: &[String],
    timeout: Duration,
    cancellation: &CancellationSignal,
    docker_env: &BTreeMap<String, String>,
) -> Result<ProcessOutput, String> {
    run_docker_command_with_stdin_and_env(args, "", timeout, cancellation, docker_env)
}

fn run_docker_command_with_stdin(
    args: &[String],
    stdin: &str,
    timeout: Duration,
    cancellation: &CancellationSignal,
) -> Result<ProcessOutput, String> {
    run_docker_command_with_stdin_and_env(args, stdin, timeout, cancellation, &BTreeMap::new())
}

fn run_docker_command_with_stdin_and_env(
    args: &[String],
    stdin: &str,
    timeout: Duration,
    cancellation: &CancellationSignal,
    docker_env: &BTreeMap<String, String>,
) -> Result<ProcessOutput, String> {
    let mut command = StdCommand::new("docker");
    command
        .args(args)
        .stdin(if stdin.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if ci_strict_env_enabled() {
        command.env_clear();
    }
    command.envs(docker_cli_host_env());
    command.envs(docker_env);
    prepare_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|err| format!("start docker: {err}"))?;
    if !stdin.is_empty() {
        if let Some(mut child_stdin) = child.stdin.take() {
            child_stdin
                .write_all(stdin.as_bytes())
                .map_err(|err| format!("write docker stdin: {err}"))?;
        }
    }
    wait_for_child_output(&mut child, timeout, cancellation, None)
}

struct DockerCredentialSession {
    path: PathBuf,
    env: BTreeMap<String, String>,
}

impl DockerCredentialSession {
    fn for_plan(plan: &CiJobPlan) -> Result<Self, String> {
        let has_credentials = plan
            .services
            .values()
            .any(|service| service.credentials.is_some());
        if !has_credentials {
            return Ok(Self {
                path: PathBuf::new(),
                env: BTreeMap::new(),
            });
        }
        let path = Path::new("/tmp/permanu-ci/docker-config")
            .join(sanitized_docker_component(&plan.job_db_id));
        if path.exists() {
            fs::remove_dir_all(&path).map_err(|err| {
                format!(
                    "remove stale docker credential helper config {}: {err}",
                    path.display()
                )
            })?;
        }
        fs::create_dir_all(&path).map_err(|err| {
            format!(
                "create docker credential helper config {}: {err}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!(
                "secure docker credential helper config {}: {err}",
                path.display()
            )
        })?;
        let mut env = BTreeMap::new();
        env.insert(
            "DOCKER_CONFIG".to_string(),
            path.to_string_lossy().to_string(),
        );
        Ok(Self { path, env })
    }

    fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }
}

impl Drop for DockerCredentialSession {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn cleanup_empty_ci_workspace_parents(clone_dir: &Path) {
    let root = ci_workspace_root();
    let mut current = clone_dir.parent();
    while let Some(dir) = current {
        if dir == root {
            break;
        }
        if !dir.starts_with(&root) {
            break;
        }
        match fs::remove_dir(dir) {
            Ok(()) => current = dir.parent(),
            Err(_) => break,
        }
    }
}

fn ci_job_command_result(
    command_id: &str,
    conclusion: &str,
    failed_step_index: Option<u32>,
    step_statuses: BTreeMap<String, String>,
    step_logs: BTreeMap<String, String>,
    artifacts: Vec<ArtifactEvent>,
    cache_events: Vec<CacheEvent>,
    log: impl AsRef<str>,
) -> AgentCommandResult {
    let result = CiJobResult {
        conclusion: conclusion.to_string(),
        failed_step_index,
        step_statuses,
        step_logs,
        artifacts,
        cache_events,
        log: log.as_ref().to_string(),
    };
    let output = serde_json::to_vec(&result).unwrap_or_else(|_| log.as_ref().as_bytes().to_vec());
    AgentCommandResult {
        command_id: command_id.to_string(),
        status: if conclusion == "success" {
            "completed".to_string()
        } else {
            "failed".to_string()
        },
        output,
        is_final: true,
    }
}

fn execute_ci_step(
    plan: &CiJobPlan,
    step: &CiStep,
    artifacts: &[ArtifactEvent],
    env: &BTreeMap<String, String>,
    label: &str,
    log: &mut String,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    log_forwarder: Option<Arc<LogForwarder>>,
    redactor: SecretRedactor,
) -> Result<StepOutcome, String> {
    if !step.uses.is_empty() {
        if is_builtin_upload_artifact_action(&step.uses) {
            return upload_artifact_action(plan, step);
        }
        if is_builtin_download_artifact_action(&step.uses) {
            return download_artifact_action(plan, step, artifacts);
        }
        if is_builtin_actions_cache_action(&step.uses) {
            return actions_cache_action(plan, step);
        }
        if is_builtin_cosign_installer_action(&step.uses) {
            return cosign_installer_action(env, job_deadline, cancellation);
        }
        if is_builtin_cosign_sign_blob_action(&step.uses) {
            return cosign_sign_blob_action(plan, step, env, job_deadline, cancellation, redactor);
        }
        if is_builtin_docker_image_action(&step.uses) {
            return docker_image_action(plan, step, env, job_deadline, cancellation, redactor);
        }
        if local_action_uses_docker_runtime(plan, step)? {
            return run_local_docker_action(plan, step, env, job_deadline, cancellation, redactor);
        }
        if local_action_uses_node_runtime(plan, step)? {
            return run_local_javascript_action(
                plan,
                step,
                env,
                job_deadline,
                cancellation,
                redactor,
            );
        }
        return run_local_composite_action(
            plan,
            step,
            env,
            label,
            log,
            job_deadline,
            cancellation,
            log_forwarder,
            redactor,
        );
    }
    run_ci_step(
        plan,
        step,
        env,
        job_deadline,
        cancellation,
        log_forwarder,
        redactor,
    )
}

fn render_enterprise_step_log(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    output: &str,
    process: &ProcessOutput,
    elapsed: Duration,
    redactor: &SecretRedactor,
) -> String {
    let mut log = String::new();
    append_capped(&mut log, &format!("step: {}\n", display_ci_step_name(step)));
    append_capped(&mut log, &format!("job: {}\n", display_ci_job_name(plan)));
    append_capped(
        &mut log,
        &format!("repository: {}\n", github_repository(plan)),
    );
    if !plan.head_sha.is_empty() {
        append_capped(&mut log, &format!("commit: {}\n", plan.head_sha));
    }
    if !plan.trigger_ref.is_empty() {
        append_capped(&mut log, &format!("ref: {}\n", plan.trigger_ref));
    }
    append_capped(
        &mut log,
        &format!(
            "runner: {} {}\n",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    );
    if let Ok(work_dir) = resolve_ci_work_dir(&plan.clone_dir, &step.working_dir) {
        append_capped(
            &mut log,
            &format!(
                "working-directory: {}\n",
                display_relative_to_workspace(plan, &work_dir)
            ),
        );
    }
    if !step.uses.is_empty() {
        append_capped(&mut log, &format!("action: {}\n", step.uses));
    } else {
        append_capped(&mut log, &format!("shell: {}\n", ci_step_shell_name(step)));
        append_capped(
            &mut log,
            &format!("command: {}\n", redactor.redact(step.run.trim())),
        );
    }
    append_capped(
        &mut log,
        &format!(
            "environment: {} keys, {} secret keys masked\n",
            env.len(),
            plan.secret_keys.len()
        ),
    );
    append_capped(&mut log, "--- output ---\n");
    if output.trim().is_empty() {
        append_capped(&mut log, "(no stdout/stderr)\n");
    } else {
        append_capped(&mut log, output.trim());
        append_capped(&mut log, "\n");
    }
    append_capped(&mut log, "--- result ---\n");
    append_capped(
        &mut log,
        &format!(
            "status: {}\n",
            if process.status_success {
                "success"
            } else {
                "failure"
            }
        ),
    );
    append_capped(
        &mut log,
        &format!(
            "exit-code: {}\n",
            process
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
    );
    append_capped(&mut log, &format!("duration-ms: {}\n", elapsed.as_millis()));
    log.trim().to_string()
}

fn ci_step_shell_name(step: &CiStep) -> &str {
    if step.shell.is_empty() {
        "sh"
    } else {
        step.shell.as_str()
    }
}

fn is_builtin_upload_artifact_action(uses: &str) -> bool {
    let uses = uses.trim().to_ascii_lowercase();
    uses == "actions/upload-artifact@v4" || uses.starts_with("actions/upload-artifact@v4.")
}

fn is_builtin_download_artifact_action(uses: &str) -> bool {
    let uses = uses.trim().to_ascii_lowercase();
    uses == "actions/download-artifact@v4" || uses.starts_with("actions/download-artifact@v4.")
}

fn is_builtin_ci_action(uses: &str) -> bool {
    is_builtin_upload_artifact_action(uses)
        || is_builtin_download_artifact_action(uses)
        || is_builtin_actions_cache_action(uses)
        || is_builtin_cosign_installer_action(uses)
        || is_builtin_cosign_sign_blob_action(uses)
        || is_builtin_docker_image_action(uses)
}

fn is_builtin_docker_image_action(uses: &str) -> bool {
    uses.trim().to_ascii_lowercase().starts_with("docker://")
}

fn docker_image_action(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    redactor: SecretRedactor,
) -> Result<StepOutcome, String> {
    let image = step
        .uses
        .trim()
        .strip_prefix("docker://")
        .ok_or_else(|| "docker action must use docker:// image syntax".to_string())?;
    validate_image_reference(image).map_err(|err| format!("docker action image: {err}"))?;
    prepare_ci_env_dirs(&plan.clone_dir)?;
    let command_files = prepare_command_files(&plan.clone_dir, &step.step_id())?;
    let mut action_env = BTreeMap::new();
    append_inherited_action_env(&mut action_env, &plan.clone_dir, env)?;
    append_action_command_file_env(plan, &command_files, &mut action_env)?;
    for (key, value) in &step.with {
        if key == "args" {
            continue;
        }
        let Some(env_key) = composite_input_env_key(&key) else {
            return Err(format!(
                "docker action input {key:?} is not a valid env key"
            ));
        };
        append_container_env(&mut action_env, &plan.clone_dir, &env_key, value)?;
    }
    write_container_env_file(&command_files.container_env, &action_env)?;

    let mut args = strings([
        "run",
        "--rm",
        "--network",
        plan.service_network_name().as_deref().unwrap_or("bridge"),
        "--workdir",
        "/workspace",
        "--volume",
        &format!("{}:/workspace", plan.clone_dir),
        "--env-file",
        command_files
            .container_env
            .to_str()
            .ok_or_else(|| "container env file path is not valid UTF-8".to_string())?,
    ]);
    append_ci_env_volume_args(&mut args, &plan.clone_dir)?;
    args.push(image.to_string());
    if let Some(action_args) = step
        .with
        .get("args")
        .filter(|value| !value.trim().is_empty())
    {
        args.extend(parse_command_argv(action_args)?);
    }
    let process = run_docker_command(&args, step_timeout(step, job_deadline)?, cancellation)?;
    let command_updates = read_command_file_updates(&command_files)?;
    Ok(StepOutcome {
        process: ProcessOutput {
            status_success: process.status_success,
            output: redactor.redact(&process.output),
            exit_code: process.exit_code,
        },
        command_updates,
        artifacts: Vec::new(),
        cache_save: None,
    })
}

fn is_builtin_actions_cache_action(uses: &str) -> bool {
    let uses = uses.trim().to_ascii_lowercase();
    uses == "actions/cache@v3"
        || uses.starts_with("actions/cache@v3.")
        || uses == "actions/cache@v4"
        || uses.starts_with("actions/cache@v4.")
}

fn actions_cache_action(plan: &CiJobPlan, step: &CiStep) -> Result<StepOutcome, String> {
    validate_actions_cache_inputs(step)?;
    let key = required_action_input(step, "key")?;
    let paths = actions_cache_paths(plan, step)?;
    let restore_keys = restore_key_inputs(step);
    let lookup_only = actions_cache_bool_input(step, "lookup-only")?;
    let fail_on_cache_miss = actions_cache_bool_input(step, "fail-on-cache-miss")?;
    let root = actions_cache_root(plan)?;
    let max_bytes = actions_cache_max_bytes(plan)?;
    let scope = actions_cache_scope(plan);
    let scope_dir = root.join(&scope);
    fs::create_dir_all(&scope_dir).map_err(|err| format!("prepare actions/cache: {err}"))?;

    let matched_key = find_actions_cache_entry(&scope_dir, key, &restore_keys);
    let cache_hit = matched_key.as_deref() == Some(key);
    if !lookup_only {
        if let Some(matched) = &matched_key {
            let entry = actions_cache_entry_dir(&scope_dir, matched);
            restore_actions_cache_paths(&entry, &paths)?;
        }
    }
    let cache_save = if !lookup_only && matched_key.as_deref() != Some(key) {
        Some(ActionsCacheSave {
            entry: actions_cache_entry_dir(&scope_dir, key),
            scope,
            key: key.to_string(),
            paths: paths.clone(),
            max_bytes,
        })
    } else {
        None
    };

    let status_success = !fail_on_cache_miss || matched_key.is_some();
    let process_message = if status_success {
        format!("actions/cache {}\n", if cache_hit { "hit" } else { "miss" })
    } else {
        "actions/cache miss: fail-on-cache-miss is enabled\n".to_string()
    };

    let mut output = BTreeMap::new();
    output.insert("cache-hit".to_string(), cache_hit.to_string());
    output.insert("cache_hit".to_string(), cache_hit.to_string());
    output.insert("cache-primary-key".to_string(), key.to_string());
    output.insert("cache_primary_key".to_string(), key.to_string());
    if let Some(matched) = matched_key {
        output.insert("cache_matched_key".to_string(), matched.clone());
        output.insert("cache-matched-key".to_string(), matched);
    }
    Ok(StepOutcome {
        process: ProcessOutput {
            status_success,
            output: process_message,
            exit_code: Some(if status_success { 0 } else { 1 }),
        },
        command_updates: CommandFileUpdates {
            output,
            ..CommandFileUpdates::default()
        },
        artifacts: Vec::new(),
        cache_save,
    })
}

fn validate_actions_cache_inputs(step: &CiStep) -> Result<(), String> {
    for input in step.with.keys() {
        match input.as_str() {
            "key" | "path" | "restore-keys" | "lookup-only" | "fail-on-cache-miss" => {}
            "enableCrossOsArchive" => {
                return Err(format!(
                    "actions/cache input \"{input}\" is not supported by Permanu CI yet because the native cache store is local to the runner OS and does not produce cross-OS-compatible archives"
                ));
            }
            _ => {
                return Err(format!(
                    "actions/cache input \"{input}\" is not supported by Permanu CI"
                ));
            }
        }
    }
    Ok(())
}

fn actions_cache_bool_input(step: &CiStep, key: &str) -> Result<bool, String> {
    let Some(raw) = step.with.get(key) else {
        return Ok(false);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "false" => Ok(false),
        "true" => Ok(true),
        _ => Err(format!(
            "actions/cache input \"{key}\" must be true or false"
        )),
    }
}

fn required_action_input<'a>(step: &'a CiStep, key: &str) -> Result<&'a str, String> {
    let value = step.with.get(key).map(|value| value.trim()).unwrap_or("");
    if value.is_empty()
        || value.as_bytes().contains(&0)
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(format!("actions/cache input \"{key}\" is required"));
    }
    Ok(value)
}

fn actions_cache_paths(plan: &CiJobPlan, step: &CiStep) -> Result<Vec<PathBuf>, String> {
    let raw = required_action_input(step, "path")?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let value = line.trim();
        if value.is_empty() {
            continue;
        }
        out.push(resolve_actions_cache_path(plan, value)?);
    }
    if out.is_empty() {
        return Err("actions/cache input \"path\" is required".to_string());
    }
    Ok(out)
}

fn resolve_actions_cache_path(plan: &CiJobPlan, value: &str) -> Result<PathBuf, String> {
    if value.as_bytes().contains(&0) || value.contains('\r') || value.contains('\\') {
        return Err("actions/cache path is invalid".to_string());
    }
    let workspace = Path::new(&plan.clone_dir);
    let path = if value == "~" {
        workspace.join("home")
    } else if let Some(rest) = value.strip_prefix("~/") {
        workspace.join("home").join(rest)
    } else {
        let path = Path::new(value);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            workspace.join(path)
        }
    };
    let normalized = normalize_workspace_path(&path)?;
    if !normalized.starts_with(workspace) {
        return Err("actions/cache path must stay inside workspace".to_string());
    }
    if fs::symlink_metadata(&normalized)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err("actions/cache path cannot be a symlink".to_string());
    }
    Ok(normalized)
}

fn normalize_workspace_path(path: &Path) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => return Err("actions/cache path is invalid".to_string()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err("actions/cache path must stay inside workspace".to_string());
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    Ok(out)
}

fn restore_key_inputs(step: &CiStep) -> Vec<String> {
    step.with
        .get("restore-keys")
        .map(|value| {
            value
                .lines()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn actions_cache_root(plan: &CiJobPlan) -> Result<PathBuf, String> {
    let root = plan
        .env
        .get(CI_ACTIONS_CACHE_ROOT_ENV)
        .cloned()
        .or_else(|| std::env::var(CI_ACTIONS_CACHE_ROOT_ENV).ok())
        .unwrap_or_else(|| DEFAULT_CI_ACTIONS_CACHE_ROOT.to_string());
    if root.as_bytes().contains(&0) {
        return Err("actions/cache root is invalid".to_string());
    }
    Ok(PathBuf::from(root))
}

fn actions_cache_scope(plan: &CiJobPlan) -> String {
    let value = format!("{}/{}", plan.repo_owner, plan.repo_name);
    hex_sha256(value.as_bytes())
}

fn find_actions_cache_entry(
    scope_dir: &Path,
    key: &str,
    restore_keys: &[String],
) -> Option<String> {
    if actions_cache_entry_dir(scope_dir, key).is_dir() {
        return Some(key.to_string());
    }
    let entries = fs::read_dir(scope_dir).ok()?;
    let mut matches = Vec::new();
    for entry in entries.flatten() {
        let key_path = entry.path().join("key");
        let stored = fs::read_to_string(key_path).ok()?;
        let stored = stored.trim().to_string();
        if restore_keys.iter().any(|prefix| stored.starts_with(prefix)) {
            matches.push(stored);
        }
    }
    matches.sort();
    matches.pop()
}

fn actions_cache_entry_dir(scope_dir: &Path, key: &str) -> PathBuf {
    scope_dir.join(hex_sha256(key.as_bytes()))
}

fn save_actions_cache_paths(
    entry: &Path,
    save: &ActionsCacheSave,
) -> Result<Option<CacheEvent>, String> {
    if entry.exists() {
        return Ok(None);
    }
    fs::create_dir_all(entry.join("paths")).map_err(|err| format!("save actions/cache: {err}"))?;
    fs::write(entry.join("key"), save.key.as_bytes())
        .map_err(|err| format!("save actions/cache: {err}"))?;
    for (index, path) in save.paths.iter().enumerate() {
        if !path.exists() {
            continue;
        }
        copy_cache_path(path, &entry.join("paths").join(index.to_string()))?;
    }
    apply_actions_cache_quota(entry, save)
}

fn restore_actions_cache_paths(entry: &Path, paths: &[PathBuf]) -> Result<(), String> {
    for (index, target) in paths.iter().enumerate() {
        let source = entry.join("paths").join(index.to_string());
        if source.exists() {
            copy_cache_path(&source, target)?;
        }
    }
    Ok(())
}

fn apply_actions_cache_quota(
    entry: &Path,
    save: &ActionsCacheSave,
) -> Result<Option<CacheEvent>, String> {
    let Some(limit) = save.max_bytes else {
        return Ok(None);
    };
    let used = directory_size_bytes(entry)?;
    if used <= limit {
        let (scoped_used, evicted_entries) = enforce_actions_cache_scope_quota(entry, limit)?;
        if evicted_entries > 0 {
            return Ok(Some(CacheEvent {
                scope: save.scope.clone(),
                key: save.key.clone(),
                result: "saved".to_string(),
                bytes_read: None,
                bytes_written: Some(used),
                eviction_reason: Some("quota_exceeded".to_string()),
                quota_decision: Some("evict_lru_entries".to_string()),
                quota_limit_bytes: Some(limit),
                quota_used_bytes: Some(scoped_used),
            }));
        }
        return Ok(Some(CacheEvent {
            scope: save.scope.clone(),
            key: save.key.clone(),
            result: "saved".to_string(),
            bytes_read: None,
            bytes_written: Some(used),
            eviction_reason: None,
            quota_decision: Some("within_quota".to_string()),
            quota_limit_bytes: Some(limit),
            quota_used_bytes: Some(used),
        }));
    }
    fs::remove_dir_all(entry).map_err(|err| format!("evict actions/cache entry: {err}"))?;
    Ok(Some(CacheEvent {
        scope: save.scope.clone(),
        key: save.key.clone(),
        result: "evicted".to_string(),
        bytes_read: None,
        bytes_written: Some(used),
        eviction_reason: Some("quota_exceeded".to_string()),
        quota_decision: Some("evict_saved_entry".to_string()),
        quota_limit_bytes: Some(limit),
        quota_used_bytes: Some(used),
    }))
}

fn enforce_actions_cache_scope_quota(
    saved_entry: &Path,
    limit: u64,
) -> Result<(u64, usize), String> {
    let Some(scope_dir) = saved_entry.parent() else {
        return directory_size_bytes(saved_entry).map(|used| (used, 0));
    };
    let mut entries = actions_cache_quota_entries(scope_dir, saved_entry)?;
    let mut used =
        entries.iter().map(|entry| entry.size).sum::<u64>() + directory_size_bytes(saved_entry)?;
    let mut evicted_entries = 0usize;
    for entry in entries.drain(..) {
        if used <= limit {
            break;
        }
        fs::remove_dir_all(&entry.path)
            .map_err(|err| format!("evict actions/cache entry: {err}"))?;
        used = used.saturating_sub(entry.size);
        evicted_entries += 1;
    }
    Ok((used, evicted_entries))
}

struct ActionsCacheQuotaEntry {
    path: PathBuf,
    size: u64,
    modified_nanos: u128,
}

fn actions_cache_quota_entries(
    scope_dir: &Path,
    saved_entry: &Path,
) -> Result<Vec<ActionsCacheQuotaEntry>, String> {
    let mut entries = Vec::new();
    let read_dir = match fs::read_dir(scope_dir) {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(err) => return Err(format!("read actions/cache scope: {err}")),
    };
    let saved_entry = saved_entry
        .canonicalize()
        .unwrap_or_else(|_| saved_entry.to_path_buf());
    for entry in read_dir {
        let entry = entry.map_err(|err| format!("read actions/cache scope: {err}"))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|err| format!("read actions/cache entry metadata: {err}"))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if canonical == saved_entry {
            continue;
        }
        let size = directory_size_bytes(&path)?;
        let modified_nanos = meta
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        entries.push(ActionsCacheQuotaEntry {
            path,
            size,
            modified_nanos,
        });
    }
    entries.sort_by_key(|entry| (entry.modified_nanos, entry.path.clone()));
    Ok(entries)
}

fn actions_cache_max_bytes(plan: &CiJobPlan) -> Result<Option<u64>, String> {
    let Some(raw) = plan
        .env
        .get(CI_ACTIONS_CACHE_MAX_BYTES_ENV)
        .cloned()
        .or_else(|| std::env::var(CI_ACTIONS_CACHE_MAX_BYTES_ENV).ok())
    else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() || raw == "0" {
        return Ok(None);
    }
    raw.parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{CI_ACTIONS_CACHE_MAX_BYTES_ENV} must be a positive integer"))
}

fn directory_size_bytes(path: &Path) -> Result<u64, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|err| format!("read actions/cache size: {err}"))?;
    if meta.file_type().is_symlink() {
        return Err("actions/cache path cannot be a symlink".to_string());
    }
    if meta.is_file() {
        return Ok(meta.len());
    }
    if meta.is_dir() {
        let mut size = 0_u64;
        for entry in fs::read_dir(path).map_err(|err| format!("read actions/cache dir: {err}"))? {
            let entry = entry.map_err(|err| format!("read actions/cache dir: {err}"))?;
            size = size.saturating_add(directory_size_bytes(&entry.path())?);
        }
        return Ok(size);
    }
    Ok(0)
}

fn copy_cache_path(source: &Path, target: &Path) -> Result<(), String> {
    let meta =
        fs::symlink_metadata(source).map_err(|err| format!("read actions/cache path: {err}"))?;
    if meta.file_type().is_symlink() {
        return Err("actions/cache path cannot be a symlink".to_string());
    }
    if meta.is_file() {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("copy actions/cache: {err}"))?;
        }
        fs::copy(source, target).map_err(|err| format!("copy actions/cache: {err}"))?;
        return Ok(());
    }
    if meta.is_dir() {
        fs::create_dir_all(target).map_err(|err| format!("copy actions/cache: {err}"))?;
        for entry in fs::read_dir(source).map_err(|err| format!("read actions/cache dir: {err}"))? {
            let entry = entry.map_err(|err| format!("read actions/cache dir: {err}"))?;
            copy_cache_path(&entry.path(), &target.join(entry.file_name()))?;
        }
        return Ok(());
    }
    Err("actions/cache path must be a regular file or directory".to_string())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_builtin_cosign_installer_action(uses: &str) -> bool {
    uses.trim()
        .to_ascii_lowercase()
        .starts_with("sigstore/cosign-installer@")
}

fn is_builtin_cosign_sign_blob_action(uses: &str) -> bool {
    let uses = uses.trim().to_ascii_lowercase();
    uses == "permanu/cosign-sign-blob@v1" || uses.starts_with("permanu/cosign-sign-blob@v1.")
}

fn cosign_installer_action(
    env: &BTreeMap<String, String>,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
) -> Result<StepOutcome, String> {
    let cosign = cosign_program(env)?;
    let mut command = StdCommand::new(&cosign);
    command
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_ci_command_env(&mut command, env);
    prepare_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|err| format!("sigstore/cosign-installer BYOS shim could not start {cosign}: {err}; install cosign on the runner or set PERMANU_COSIGN_PATH"))?;
    let process = wait_for_child_output(
        &mut child,
        remaining_job_timeout(job_deadline)?,
        cancellation,
        None,
    )?;
    if !process.status_success {
        let detail = if process.output.is_empty() {
            "cosign version exited unsuccessfully".to_string()
        } else {
            process.output
        };
        return Err(format!(
            "sigstore/cosign-installer BYOS shim requires a working cosign binary: {detail}"
        ));
    }
    Ok(StepOutcome {
        process: ProcessOutput {
            status_success: true,
            output: format!("cosign available via {cosign}"),
            exit_code: Some(0),
        },
        command_updates: CommandFileUpdates::default(),
        artifacts: Vec::new(),
        cache_save: None,
    })
}

fn cosign_sign_blob_action(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    mut redactor: SecretRedactor,
) -> Result<StepOutcome, String> {
    let signing_identity = cosign_signing_identity(step, env)?;
    if let CosignSigningIdentity::Key(key) = &signing_identity {
        redactor.add_secret_value(key);
    }
    let cosign = cosign_program(env)?;
    let targets = cosign_signing_targets(plan, step)?;
    if targets.is_empty() {
        return Err("permanu/cosign-sign-blob@v1 found no files to sign".to_string());
    }

    let mut output = String::new();
    for target in targets {
        let bundle = sidecar_path(&target, "bundle");
        let signature = sidecar_path(&target, "sig");
        let certificate = sidecar_path(&target, "cert");
        let mut command = StdCommand::new(&cosign);
        command.arg("sign-blob");
        if let CosignSigningIdentity::Key(key) = &signing_identity {
            command.arg("--key").arg(key);
        }
        command.arg("--yes").arg("--bundle").arg(&bundle);
        if matches!(&signing_identity, CosignSigningIdentity::Keyless) {
            command
                .arg("--output-signature")
                .arg(&signature)
                .arg("--output-certificate")
                .arg(&certificate);
        }
        command
            .arg(&target)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_ci_command_env(&mut command, env);
        if matches!(&signing_identity, CosignSigningIdentity::Keyless)
            && !has_non_empty_env(env, "SIGSTORE_ID_TOKEN")
        {
            if let Some(token) = env.get("PERMANU_SIGSTORE_ID_TOKEN") {
                command.env("SIGSTORE_ID_TOKEN", token);
            }
        }
        prepare_process_group(&mut command);
        let mut child = command
            .spawn()
            .map_err(|err| format!("start cosign sign-blob: {err}"))?;
        let process = wait_for_child_output(
            &mut child,
            remaining_job_timeout(job_deadline)?,
            cancellation,
            None,
        )?;
        if !process.status_success {
            let detail = if process.output.is_empty() {
                "cosign sign-blob exited unsuccessfully".to_string()
            } else {
                redactor.redact(&process.output)
            };
            return Err(format!(
                "cosign sign-blob failed for {}: {detail}",
                display_relative_to_workspace(plan, &target)
            ));
        }
        if matches!(&signing_identity, CosignSigningIdentity::Key(_)) {
            append_capped(
                &mut output,
                &format!(
                    "signed {} -> {}\n",
                    display_relative_to_workspace(plan, &target),
                    display_relative_to_workspace(plan, &bundle),
                ),
            );
        } else {
            append_capped(
                &mut output,
                &format!(
                    "signed {} -> {}, {}, {}\n",
                    display_relative_to_workspace(plan, &target),
                    display_relative_to_workspace(plan, &bundle),
                    display_relative_to_workspace(plan, &signature),
                    display_relative_to_workspace(plan, &certificate)
                ),
            );
        }
        if !process.output.trim().is_empty() {
            append_capped(&mut output, &redactor.redact(&process.output));
            append_capped(&mut output, "\n");
        }
    }

    Ok(StepOutcome {
        process: ProcessOutput {
            status_success: true,
            output: output.trim().to_string(),
            exit_code: Some(0),
        },
        command_updates: CommandFileUpdates::default(),
        artifacts: Vec::new(),
        cache_save: None,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CosignSigningIdentity {
    Key(String),
    Keyless,
}

fn cosign_signing_identity(
    step: &CiStep,
    env: &BTreeMap<String, String>,
) -> Result<CosignSigningIdentity, String> {
    if let Some(key) = step
        .with
        .get("key")
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(CosignSigningIdentity::Key(validate_cosign_key_ref(key)?));
    }
    for env_key in ["PERMANU_COSIGN_KEY", "COSIGN_KEY"] {
        if let Some(key) = env
            .get(env_key)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            return Ok(CosignSigningIdentity::Key(validate_cosign_key_ref(key)?));
        }
    }
    if has_non_empty_env(env, "SIGSTORE_ID_TOKEN")
        || has_non_empty_env(env, "PERMANU_SIGSTORE_ID_TOKEN")
    {
        return Ok(CosignSigningIdentity::Keyless);
    }
    Err("permanu/cosign-sign-blob@v1 requires key, COSIGN_KEY, PERMANU_COSIGN_KEY, SIGSTORE_ID_TOKEN, or PERMANU_SIGSTORE_ID_TOKEN; key/KMS mode is preferred for enterprise BYOS and Permanu does not mint GitHub Actions OIDC tokens".to_string())
}

fn validate_cosign_key_ref(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.as_bytes().contains(&0)
        || trimmed.contains('\n')
        || trimmed.contains('\r')
    {
        return Err("invalid cosign key reference".to_string());
    }
    Ok(trimmed.to_string())
}

fn has_non_empty_env(env: &BTreeMap<String, String>, key: &str) -> bool {
    env.get(key)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn cosign_program(env: &BTreeMap<String, String>) -> Result<String, String> {
    let value = env
        .get("PERMANU_COSIGN_PATH")
        .map(String::as_str)
        .unwrap_or("cosign")
        .trim();
    if value.is_empty()
        || value.as_bytes().contains(&0)
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err("invalid PERMANU_COSIGN_PATH".to_string());
    }
    Ok(value.to_string())
}

fn cosign_signing_targets(plan: &CiJobPlan, step: &CiStep) -> Result<Vec<PathBuf>, String> {
    let paths = step
        .with
        .get("path")
        .or_else(|| step.with.get("paths"))
        .map(String::as_str)
        .unwrap_or_default();
    let workspace = PathBuf::from(normalize_work_dir(&plan.clone_dir)?);
    validate_managed_ci_clone_dir(&workspace)?;
    let mut targets = Vec::new();
    for raw in paths.lines() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if raw.contains('*') || raw.contains('?') || raw.contains('[') || raw.contains(']') {
            return Err("permanu/cosign-sign-blob@v1 path globs are not supported; provide files or directories".to_string());
        }
        let rel = Path::new(raw);
        if rel.is_absolute() {
            return Err(
                "permanu/cosign-sign-blob@v1 path must be relative to the workspace".to_string(),
            );
        }
        for component in rel.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(
                    "permanu/cosign-sign-blob@v1 path must stay inside the workspace".to_string(),
                );
            }
        }
        let source = workspace.join(rel);
        if source.is_file() {
            if !is_cosign_sidecar_path(&source) {
                targets.push(source);
            }
        } else if source.is_dir() {
            for file in collect_artifact_files(&source)? {
                if !is_cosign_sidecar_path(&file) {
                    targets.push(file);
                }
            }
        }
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn is_cosign_sidecar_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    name.ends_with(".bundle")
        || name.ends_with(".sig")
        || name.ends_with(".cert")
        || name.ends_with(".sigstore.json")
}

fn sidecar_path(target: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}.{}", target.to_string_lossy(), suffix))
}

fn display_relative_to_workspace(plan: &CiJobPlan, path: &Path) -> String {
    let workspace = Path::new(&plan.clone_dir);
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn upload_artifact_action(plan: &CiJobPlan, step: &CiStep) -> Result<StepOutcome, String> {
    validate_upload_artifact_inputs(step)?;
    let artifact_name = step
        .with
        .get("name")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("artifact");
    validate_artifact_name(artifact_name)?;
    let path_value = step
        .with
        .get("path")
        .map(|value| value.as_str())
        .unwrap_or_default();
    let include_hidden = artifact_bool_input(step, "include-hidden-files")?;
    let retention_days = artifact_retention_days(step)?;
    let source_paths = upload_artifact_source_paths(&plan.clone_dir, path_value, include_hidden)?;
    if source_paths.is_empty() {
        let behavior = step
            .with
            .get("if-no-files-found")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "warn".to_string());
        if behavior == "ignore" || behavior == "warn" {
            return Ok(StepOutcome {
                process: ProcessOutput {
                    status_success: true,
                    output: format!("no files found for artifact {artifact_name}"),
                    exit_code: Some(0),
                },
                command_updates: CommandFileUpdates::default(),
                artifacts: Vec::new(),
                cache_save: None,
            });
        }
        return Err(format!("no files found for artifact {artifact_name}"));
    }

    let storage_root = ci_artifacts_root();
    cleanup_stale_ci_artifacts(
        &storage_root,
        Duration::from_secs(CI_ARTIFACT_RETENTION_DAYS * 24 * 60 * 60),
    );
    let run_component = if plan.run_db_id.is_empty() {
        sanitize_file_component(&plan.job_db_id)
    } else {
        sanitize_file_component(&plan.run_db_id)
    };
    let artifact_component = sanitize_file_component(artifact_name);
    let storage_rel = PathBuf::from(&run_component)
        .join(sanitize_file_component(&plan.job_db_id))
        .join(format!("{}-{}", step.step_index, artifact_component));
    let storage_abs = storage_root.join(&storage_rel);
    if storage_abs.exists() {
        fs::remove_dir_all(&storage_abs).map_err(|err| format!("reset artifact dir: {err}"))?;
    }
    fs::create_dir_all(&storage_abs).map_err(|err| format!("create artifact dir: {err}"))?;

    let mut extracted_hasher = Sha256::new();
    let mut file_count = 0usize;
    for source in source_paths {
        let name = source
            .file_name()
            .ok_or_else(|| "artifact source has no file name".to_string())?;
        let destination = storage_abs.join(name);
        copy_artifact_entry(&source, &destination, &mut extracted_hasher)?;
        file_count += 1;
    }
    let compression_level = upload_artifact_compression_level(step)?;
    let archive_path = storage_abs.join(CI_ARTIFACT_ARCHIVE_FILENAME);
    write_artifact_archive(&storage_abs, &archive_path, compression_level)?;
    let (size_bytes, content_sha256) = artifact_archive_metadata(&archive_path)?;

    let event = ArtifactEvent {
        name: artifact_name.to_string(),
        size_bytes,
        content_sha256,
        storage_path: storage_rel.to_string_lossy().to_string(),
        expires_at: retention_days
            .map(|days| format!("retention-days:{days}"))
            .unwrap_or_default(),
    };
    Ok(StepOutcome {
        process: ProcessOutput {
            status_success: true,
            output: format!(
                "uploaded artifact {artifact_name} ({file_count} file entries, {size_bytes} bytes)"
            ),
            exit_code: Some(0),
        },
        command_updates: CommandFileUpdates::default(),
        artifacts: vec![event],
        cache_save: None,
    })
}

fn validate_upload_artifact_inputs(step: &CiStep) -> Result<(), String> {
    for key in step.with.keys() {
        match key.as_str() {
            "name" | "path" | "if-no-files-found" | "retention-days" | "compression-level"
            | "overwrite" | "include-hidden-files" => {}
            _ => {
                return Err(format!(
                    "actions/upload-artifact@v4 input {key:?} is not supported by the native artifact bridge"
                ))
            }
        }
    }
    let behavior = step
        .with
        .get("if-no-files-found")
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "warn".to_string());
    if !matches!(behavior.as_str(), "warn" | "error" | "ignore") {
        return Err(
            "actions/upload-artifact@v4 if-no-files-found must be warn, error, or ignore"
                .to_string(),
        );
    }
    artifact_bool_input(step, "overwrite")?;
    artifact_bool_input(step, "include-hidden-files")?;
    if let Some(value) = step
        .with
        .get("compression-level")
        .filter(|value| !value.trim().is_empty())
    {
        parse_upload_artifact_compression_level(value)?;
    }
    artifact_retention_days(step)?;
    Ok(())
}

fn upload_artifact_compression_level(step: &CiStep) -> Result<u8, String> {
    match step.with.get("compression-level") {
        Some(value) if !value.trim().is_empty() => parse_upload_artifact_compression_level(value),
        _ => Ok(6),
    }
}

fn parse_upload_artifact_compression_level(value: &str) -> Result<u8, String> {
    let level: u8 = value.trim().parse().map_err(|_| {
        "actions/upload-artifact@v4 compression-level must be 0 through 9".to_string()
    })?;
    if level > 9 {
        return Err("actions/upload-artifact@v4 compression-level must be 0 through 9".to_string());
    }
    Ok(level)
}

fn artifact_bool_input(step: &CiStep, key: &str) -> Result<bool, String> {
    let Some(raw) = step.with.get(key) else {
        return Ok(false);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "false" => Ok(false),
        "true" => Ok(true),
        _ => Err(format!(
            "actions/upload-artifact@v4 input {key:?} must be true or false"
        )),
    }
}

fn artifact_retention_days(step: &CiStep) -> Result<Option<u16>, String> {
    let Some(raw) = step.with.get("retention-days") else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let days: u16 = raw.parse().map_err(|_| {
        "actions/upload-artifact@v4 retention-days must be 1 through 90".to_string()
    })?;
    if !(1..=90).contains(&days) {
        return Err("actions/upload-artifact@v4 retention-days must be 1 through 90".to_string());
    }
    Ok(Some(days))
}

fn download_artifact_action(
    plan: &CiJobPlan,
    step: &CiStep,
    artifacts: &[ArtifactEvent],
) -> Result<StepOutcome, String> {
    validate_download_artifact_inputs(step)?;
    let requested_name = step
        .with
        .get("name")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    if let Some(name) = requested_name {
        validate_artifact_name(name)?;
    }
    let requested_pattern = step
        .with
        .get("pattern")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let merge_multiple = download_artifact_bool_input(step, "merge-multiple")?;
    let destination = download_artifact_destination(
        &plan.clone_dir,
        step.with
            .get("path")
            .map(|value| value.as_str())
            .unwrap_or("."),
    )?;
    let selected_same_job: Vec<&ArtifactEvent> = artifacts
        .iter()
        .filter(|artifact| {
            artifact_matches_download_request(&artifact.name, requested_name, requested_pattern)
        })
        .collect();
    let selected_available: Vec<&AvailableArtifact> = if selected_same_job.is_empty() {
        plan.available_artifacts
            .iter()
            .filter(|artifact| {
                artifact_matches_download_request(&artifact.name, requested_name, requested_pattern)
            })
            .collect()
    } else {
        Vec::new()
    };
    if selected_same_job.is_empty() && selected_available.is_empty() {
        return Err(match requested_name {
            Some(name) => {
                format!("artifact {name} was not found in this job or available artifacts")
            }
            None => "no artifacts are available to download in this job or available artifacts"
                .to_string(),
        });
    }
    for artifact in &selected_available {
        if artifact.storage_path.is_empty() && artifact.download_url.is_empty() {
            return Err(format!(
                "artifact {} only has provider_url; download through the control plane is required",
                artifact.name
            ));
        }
    }
    let selected_count = selected_same_job.len() + selected_available.len();
    fs::create_dir_all(&destination).map_err(|err| format!("create download dir: {err}"))?;
    let mut total_bytes = 0i64;
    let mut hasher = Sha256::new();
    let mut seen_targets = BTreeMap::new();
    for artifact in selected_same_job {
        let source = resolve_artifact_storage_path(&artifact.storage_path)?;
        let target = if requested_name.is_some() || merge_multiple {
            destination.clone()
        } else {
            destination.join(sanitize_file_component(&artifact.name))
        };
        if requested_name.is_none() && !merge_multiple {
            let key = target.to_string_lossy().to_string();
            if let Some(existing) = seen_targets.insert(key, artifact.name.clone()) {
                return Err(format!(
                    "download-artifact artifact names {existing:?} and {:?} collide after path sanitization",
                    artifact.name
                ));
            }
        }
        let copied = copy_artifact_entry(&source, &target, &mut hasher)?;
        total_bytes = total_bytes
            .checked_add(copied)
            .ok_or_else(|| "downloaded artifact size overflow".to_string())?;
    }
    for artifact in &selected_available {
        let target = if requested_name.is_some() || merge_multiple {
            destination.clone()
        } else {
            destination.join(sanitize_file_component(&artifact.name))
        };
        if requested_name.is_none() && !merge_multiple {
            let key = target.to_string_lossy().to_string();
            if let Some(existing) = seen_targets.insert(key, artifact.name.clone()) {
                return Err(format!(
                    "download-artifact artifact names {existing:?} and {:?} collide after path sanitization",
                    artifact.name
                ));
            }
        }
        let copied = if artifact.storage_path.is_empty() {
            download_control_plane_artifact(artifact, &target, &mut hasher)?
        } else {
            let source = resolve_artifact_storage_path(&artifact.storage_path)?;
            copy_artifact_entry(&source, &target, &mut hasher)?
        };
        total_bytes = total_bytes
            .checked_add(copied)
            .ok_or_else(|| "downloaded artifact size overflow".to_string())?;
    }
    validate_downloaded_available_artifacts(&selected_available, total_bytes, &hasher)?;
    Ok(StepOutcome {
        process: ProcessOutput {
            status_success: true,
            output: format!(
                "downloaded {} artifact(s), {total_bytes} bytes",
                selected_count
            ),
            exit_code: Some(0),
        },
        command_updates: CommandFileUpdates::default(),
        artifacts: Vec::new(),
        cache_save: None,
    })
}

fn validate_downloaded_available_artifacts(
    artifacts: &[&AvailableArtifact],
    total_bytes: i64,
    hasher: &Sha256,
) -> Result<(), String> {
    if artifacts.len() != 1 {
        return Ok(());
    }
    let artifact = artifacts[0];
    if !artifact.download_url.is_empty() && artifact.storage_path.is_empty() {
        return Ok(());
    }
    if artifact.size_bytes > 0 && artifact.size_bytes != total_bytes {
        return Err(format!(
            "downloaded artifact {} size mismatch: got {total_bytes}, expected {}",
            artifact.name, artifact.size_bytes
        ));
    }
    if !artifact.hash.is_empty() {
        let actual = hex::encode(hasher.clone().finalize());
        if !actual.eq_ignore_ascii_case(&artifact.hash) {
            return Err(format!(
                "downloaded artifact {} checksum mismatch",
                artifact.name
            ));
        }
    }
    Ok(())
}

fn validate_download_artifact_inputs(step: &CiStep) -> Result<(), String> {
    for key in step.with.keys() {
        if key != "name" && key != "path" && key != "pattern" && key != "merge-multiple" {
            return Err(format!(
                "actions/download-artifact@v4 input {key:?} is not supported by the native same-job artifact bridge"
            ));
        }
    }
    if step
        .with
        .get("name")
        .is_some_and(|value| !value.trim().is_empty())
        && step
            .with
            .get("pattern")
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(
            "actions/download-artifact@v4 inputs \"name\" and \"pattern\" cannot both be set"
                .to_string(),
        );
    }
    download_artifact_bool_input(step, "merge-multiple")?;
    Ok(())
}

fn artifact_matches_download_request(
    name: &str,
    requested_name: Option<&str>,
    requested_pattern: Option<&str>,
) -> bool {
    if let Some(requested_name) = requested_name {
        return name == requested_name;
    }
    if let Some(pattern) = requested_pattern {
        return wildcard_match(pattern, name);
    }
    true
}

fn download_artifact_bool_input(step: &CiStep, key: &str) -> Result<bool, String> {
    let Some(raw) = step.with.get(key) else {
        return Ok(false);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "false" => Ok(false),
        "true" => Ok(true),
        _ => Err(format!(
            "actions/download-artifact@v4 input {key:?} must be true or false"
        )),
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    match pattern[0] {
        b'*' => {
            wildcard_match_bytes(&pattern[1..], value)
                || (!value.is_empty() && wildcard_match_bytes(pattern, &value[1..]))
        }
        b'?' => !value.is_empty() && wildcard_match_bytes(&pattern[1..], &value[1..]),
        ch => {
            !value.is_empty() && value[0] == ch && wildcard_match_bytes(&pattern[1..], &value[1..])
        }
    }
}

fn upload_artifact_source_paths(
    clone_dir: &str,
    path_value: &str,
    include_hidden: bool,
) -> Result<Vec<PathBuf>, String> {
    let workspace = PathBuf::from(normalize_work_dir(clone_dir)?);
    validate_managed_ci_clone_dir(&workspace)?;
    let mut out = Vec::new();
    for raw in path_value.lines() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if raw.contains('*') || raw.contains('?') || raw.contains('[') || raw.contains(']') {
            return Err("upload-artifact path globs are not supported yet".to_string());
        }
        let rel = Path::new(raw);
        if rel.is_absolute() {
            return Err("upload-artifact path must be relative to the workspace".to_string());
        }
        for component in rel.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err("upload-artifact path must stay inside the workspace".to_string());
            }
        }
        let source = workspace.join(rel);
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() {
            return Err("upload-artifact path must not contain symlinks".to_string());
        }
        if metadata.is_file() || metadata.is_dir() {
            if include_hidden || !artifact_path_has_hidden_component(&workspace, &source)? {
                out.push(source);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn artifact_path_has_hidden_component(workspace: &Path, source: &Path) -> Result<bool, String> {
    let relative = source
        .strip_prefix(workspace)
        .map_err(|_| "upload-artifact path must stay inside the workspace".to_string())?;
    Ok(relative.components().any(|component| {
        matches!(component, Component::Normal(part) if part.to_string_lossy().starts_with('.'))
    }))
}

fn download_artifact_destination(clone_dir: &str, path_value: &str) -> Result<PathBuf, String> {
    let workspace = PathBuf::from(normalize_work_dir(clone_dir)?);
    validate_managed_ci_clone_dir(&workspace)?;
    let raw = path_value.trim();
    let rel = if raw.is_empty() {
        Path::new(".")
    } else {
        Path::new(raw)
    };
    if rel.is_absolute() {
        return Err("download-artifact path must be relative to the workspace".to_string());
    }
    for component in rel.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            return Err("download-artifact path must stay inside the workspace".to_string());
        }
    }
    Ok(workspace.join(rel))
}

fn resolve_artifact_storage_path(storage_path: &str) -> Result<PathBuf, String> {
    let root = ci_artifacts_root();
    validate_artifact_storage_path_fragment(storage_path)?;
    let source = root.join(storage_path);
    if !source.exists() {
        return Err("artifact storage path does not exist on this runner".to_string());
    }
    Ok(source)
}

fn download_control_plane_artifact(
    artifact: &AvailableArtifact,
    destination: &Path,
    hasher: &mut Sha256,
) -> Result<i64, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "download-artifact destination has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|err| format!("create download parent: {err}"))?;
    let temp = parent.join(format!(
        ".permanu-artifact-{}-{}.download",
        sanitize_file_component(&artifact.name),
        std::process::id()
    ));
    if temp.exists() {
        fs::remove_file(&temp).map_err(|err| format!("remove stale artifact download: {err}"))?;
    }
    let output = StdCommand::new("curl")
        .arg("--fail")
        .arg("--location")
        .arg("--silent")
        .arg("--show-error")
        .arg("--max-time")
        .arg("300")
        .arg("--output")
        .arg(&temp)
        .arg(&artifact.download_url)
        .output()
        .map_err(|err| format!("start control-plane artifact download: {err}"))?;
    if !output.status.success() {
        let _ = fs::remove_file(&temp);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "control-plane artifact download failed for {}: {}",
            artifact.name,
            stderr.trim()
        ));
    }
    validate_control_plane_artifact_archive_bytes(artifact, &temp)?;
    let copied = unpack_zip_artifact(&temp, destination, hasher)
        .or_else(|_| copy_artifact_entry(&temp, destination, hasher));
    let _ = fs::remove_file(&temp);
    copied
}

fn validate_control_plane_artifact_archive_bytes(
    artifact: &AvailableArtifact,
    archive_path: &Path,
) -> Result<(), String> {
    let bytes = fs::read(archive_path).map_err(|err| format!("read artifact download: {err}"))?;
    if artifact.size_bytes > 0 {
        let actual_size =
            i64::try_from(bytes.len()).map_err(|_| "artifact archive is too large".to_string())?;
        if artifact.size_bytes != actual_size {
            return Err(format!(
                "downloaded artifact {} archive size mismatch: got {actual_size}, expected {}",
                artifact.name, artifact.size_bytes
            ));
        }
    }
    if !artifact.hash.is_empty() {
        let actual = hex::encode(Sha256::digest(&bytes));
        if !actual.eq_ignore_ascii_case(&artifact.hash) {
            return Err(format!(
                "downloaded artifact {} archive checksum mismatch",
                artifact.name
            ));
        }
    }
    Ok(())
}

fn validate_control_plane_artifact_download_url(raw: &str) -> Result<(), String> {
    if raw.as_bytes().iter().any(|byte| byte.is_ascii_control()) {
        return Err("artifact download_url contains control characters".to_string());
    }
    if !(raw.starts_with("https://")
        || raw.starts_with("http://127.0.0.1:")
        || raw.starts_with("http://localhost:"))
    {
        return Err("artifact download_url must be a control-plane HTTPS URL".to_string());
    }
    if !raw.contains("/api/artifacts/") || !raw.contains("/download") {
        return Err("artifact download_url must target the control-plane artifact API".to_string());
    }
    Ok(())
}

fn unpack_zip_artifact(
    path: &Path,
    destination: &Path,
    hasher: &mut Sha256,
) -> Result<i64, String> {
    let file = fs::File::open(path).map_err(|err| format!("open artifact download: {err}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|err| format!("open artifact zip: {err}"))?;
    fs::create_dir_all(destination).map_err(|err| format!("create unzip destination: {err}"))?;
    let root = destination
        .canonicalize()
        .map_err(|err| format!("canonicalize unzip destination: {err}"))?;
    let mut total = 0i64;
    for idx in 0..archive.len() {
        let mut entry = archive
            .by_index(idx)
            .map_err(|err| format!("read artifact zip entry: {err}"))?;
        if entry.is_dir() {
            continue;
        }
        let Some(enclosed) = entry.enclosed_name() else {
            return Err("artifact zip entry escapes destination".to_string());
        };
        let target = root.join(enclosed);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create unzip parent: {err}"))?;
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|err| format!("create unzip file: {err}"))?;
        let copied = std::io::copy(&mut entry, &mut output)
            .map_err(|err| format!("write unzip file: {err}"))?;
        output
            .flush()
            .map_err(|err| format!("flush unzip file: {err}"))?;
        let mut input = fs::File::open(&target).map_err(|err| format!("hash unzip file: {err}"))?;
        let mut buf = [0u8; 8192];
        loop {
            let n = input
                .read(&mut buf)
                .map_err(|err| format!("read unzip file: {err}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        total = total
            .checked_add(
                i64::try_from(copied).map_err(|_| "artifact entry is too large".to_string())?,
            )
            .ok_or_else(|| "downloaded artifact size overflow".to_string())?;
    }
    Ok(total)
}

fn validate_artifact_storage_path_fragment(storage_path: &str) -> Result<(), String> {
    let rel = Path::new(storage_path);
    if rel.is_absolute() {
        return Err("artifact storage path must be relative".to_string());
    }
    for component in rel.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("artifact storage path must stay inside artifact root".to_string());
        }
    }
    Ok(())
}

fn validate_artifact_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 128
        || name.as_bytes().contains(&0)
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
    {
        return Err("invalid artifact name".to_string());
    }
    Ok(())
}

pub(crate) fn ci_artifacts_root() -> PathBuf {
    std::env::var(CI_ARTIFACTS_ROOT_ENV)
        .ok()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CI_ARTIFACTS_ROOT))
}

fn cleanup_stale_ci_artifacts(root: &Path, max_age: Duration) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if modified.elapsed().is_ok_and(|age| age > max_age) {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn copy_artifact_entry(
    source: &Path,
    destination: &Path,
    hasher: &mut Sha256,
) -> Result<i64, String> {
    let metadata =
        fs::symlink_metadata(source).map_err(|err| format!("read artifact metadata: {err}"))?;
    if metadata.file_type().is_symlink() {
        return Err("artifact source must not contain symlinks".to_string());
    }
    if metadata.is_file() {
        return copy_artifact_file(source, destination, hasher);
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    fs::create_dir_all(destination).map_err(|err| format!("create artifact subdir: {err}"))?;
    let mut total = 0i64;
    for file in collect_artifact_files(source)? {
        let rel = file
            .strip_prefix(source)
            .map_err(|_| "artifact path escaped source directory".to_string())?;
        let target = destination.join(rel);
        let copied = copy_artifact_file(&file, &target, hasher)?;
        total = total
            .checked_add(copied)
            .ok_or_else(|| "artifact size overflow".to_string())?;
    }
    Ok(total)
}

fn collect_artifact_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|err| format!("read artifact dir: {err}"))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("read artifact entry: {err}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|err| format!("read artifact metadata: {err}"))?;
            if metadata.file_type().is_symlink() {
                return Err("artifact source must not contain symlinks".to_string());
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == CI_ARTIFACT_ARCHIVE_FILENAME)
                {
                    continue;
                }
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn copy_artifact_file(
    source: &Path,
    destination: &Path,
    hasher: &mut Sha256,
) -> Result<i64, String> {
    let metadata =
        fs::symlink_metadata(source).map_err(|err| format!("read artifact metadata: {err}"))?;
    if metadata.file_type().is_symlink() {
        return Err("artifact source must not contain symlinks".to_string());
    }
    if !metadata.is_file() {
        return Err("artifact source is not a file".to_string());
    }
    if let Some(parent) = destination.parent() {
        reject_existing_symlink_component(parent)?;
        fs::create_dir_all(parent).map_err(|err| format!("create artifact parent: {err}"))?;
    }
    reject_existing_symlink_component(destination)?;
    let mut input =
        open_artifact_source_file(source).map_err(|err| format!("open artifact source: {err}"))?;
    let mut output =
        fs::File::create(destination).map_err(|err| format!("create artifact file: {err}"))?;
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0i64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|err| format!("read artifact source: {err}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        std::io::Write::write_all(&mut output, &buffer[..read])
            .map_err(|err| format!("write artifact file: {err}"))?;
        total = total
            .checked_add(read as i64)
            .ok_or_else(|| "artifact size overflow".to_string())?;
    }
    Ok(total)
}

fn write_artifact_archive(
    storage_dir: &Path,
    archive_path: &Path,
    compression_level: u8,
) -> Result<(), String> {
    let file =
        fs::File::create(archive_path).map_err(|err| format!("create artifact archive: {err}"))?;
    let method = if compression_level == 0 {
        zip::CompressionMethod::Stored
    } else {
        zip::CompressionMethod::Deflated
    };
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(method)
        .compression_level((compression_level > 0).then_some(i64::from(compression_level)));
    let mut archive = zip::ZipWriter::new(file);
    for path in collect_artifact_files(storage_dir)? {
        let rel = path
            .strip_prefix(storage_dir)
            .map_err(|_| "artifact archive path escaped storage directory".to_string())?;
        let rel_name = rel
            .to_str()
            .ok_or_else(|| "artifact archive path is not valid UTF-8".to_string())?;
        archive
            .start_file(rel_name.replace('\\', "/"), options)
            .map_err(|err| format!("start artifact archive file: {err}"))?;
        let mut input =
            fs::File::open(&path).map_err(|err| format!("open artifact archive source: {err}"))?;
        std::io::copy(&mut input, &mut archive)
            .map_err(|err| format!("write artifact archive file: {err}"))?;
    }
    let mut output = archive
        .finish()
        .map_err(|err| format!("finish artifact archive: {err}"))?;
    output
        .flush()
        .map_err(|err| format!("flush artifact archive: {err}"))?;
    Ok(())
}

fn artifact_archive_metadata(archive_path: &Path) -> Result<(i64, String), String> {
    let bytes = fs::read(archive_path).map_err(|err| format!("read artifact archive: {err}"))?;
    let size =
        i64::try_from(bytes.len()).map_err(|_| "artifact archive is too large".to_string())?;
    Ok((size, hex::encode(Sha256::digest(&bytes))))
}

fn reject_existing_symlink_component(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("artifact destination must not contain symlinks".to_string());
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("read artifact destination metadata: {err}")),
    }
    Ok(())
}

fn open_artifact_source_file(source: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(source)
}

fn ensure_ci_checkout(
    plan: &CiJobPlan,
    log: &mut String,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
) -> Result<(), String> {
    if plan.repo_owner.is_empty() || plan.repo_name.is_empty() || plan.head_sha.is_empty() {
        return Ok(());
    }
    let clone_dir = PathBuf::from(normalize_work_dir(&plan.clone_dir)?);
    validate_managed_ci_clone_dir(&clone_dir)?;
    if let Some(parent) = clone_dir.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create checkout parent: {err}"))?;
    }
    if clone_dir.exists() {
        fs::remove_dir_all(&clone_dir).map_err(|err| format!("reset checkout dir: {err}"))?;
    }
    let repo_url = format!(
        "https://github.com/{}/{}.git",
        plan.repo_owner, plan.repo_name
    );
    let askpass_path = if plan.repo_clone_token.is_empty() {
        None
    } else {
        Some(write_ci_git_askpass(&clone_dir, &plan.repo_clone_token)?)
    };
    append_capped(
        log,
        &format!(
            "checking out {}/{} at {}\n",
            plan.repo_owner, plan.repo_name, plan.head_sha
        ),
    );
    let result = run_git_command(
        None,
        &[
            "clone",
            "--no-checkout",
            "--filter=blob:none",
            &repo_url,
            path_str(&clone_dir)?,
        ],
        remaining_job_timeout(job_deadline)?,
        cancellation,
        askpass_path.as_deref(),
        &plan.repo_clone_token,
    )
    .and_then(|_| {
        run_git_command(
            Some(&clone_dir),
            &["fetch", "--depth", "1", "origin", &plan.head_sha],
            remaining_job_timeout(job_deadline)?,
            cancellation,
            askpass_path.as_deref(),
            &plan.repo_clone_token,
        )
    })
    .and_then(|_| {
        run_git_command(
            Some(&clone_dir),
            &["checkout", "--detach", &plan.head_sha],
            remaining_job_timeout(job_deadline)?,
            cancellation,
            askpass_path.as_deref(),
            &plan.repo_clone_token,
        )
    });
    if let Some(path) = askpass_path {
        let _ = fs::remove_file(path);
    }
    result
}

fn write_ci_git_askpass(clone_dir: &Path, token: &str) -> Result<PathBuf, String> {
    let parent = clone_dir
        .parent()
        .ok_or_else(|| "checkout parent is missing".to_string())?;
    fs::create_dir_all(parent).map_err(|err| format!("create checkout parent: {err}"))?;
    let path = parent.join(format!(".permanu-git-askpass-{}.sh", std::process::id()));
    let escaped = token.replace('\'', "'\"'\"'");
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s\\n' 'x-access-token' ;;\n  *) printf '%s\\n' '{}' ;;\nesac\n",
        escaped
    );
    fs::write(&path, script).map_err(|err| format!("write git askpass helper: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .map_err(|err| format!("stat git askpass helper: {err}"))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&path, perms)
            .map_err(|err| format!("chmod git askpass helper: {err}"))?;
    }
    Ok(path)
}

fn run_git_command(
    work_dir: Option<&Path>,
    args: &[&str],
    deadline: Duration,
    cancellation: &CancellationSignal,
    askpass_path: Option<&Path>,
    repo_clone_token: &str,
) -> Result<(), String> {
    let mut command = StdCommand::new("git");
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = askpass_path {
        command.env("GIT_ASKPASS", path);
        command.env("GIT_TERMINAL_PROMPT", "0");
        command.env("GITHUB_TOKEN", repo_clone_token);
    }
    if let Some(work_dir) = work_dir {
        command.current_dir(work_dir);
    }
    prepare_process_group(&mut command);
    let mut child = command.spawn().map_err(|err| format!("start git: {err}"))?;
    let process = wait_for_child_output(
        &mut child,
        deadline.min(Duration::from_secs(DEFAULT_GIT_COMMAND_TIMEOUT_SECONDS)),
        cancellation,
        None,
    )?;
    if process.status_success {
        return Ok(());
    }
    if process.output.is_empty() {
        Err("git exited unsuccessfully".to_string())
    } else {
        Err(process.output)
    }
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| "checkout path is not valid UTF-8".to_string())
}

pub fn build_ci_container_invocation(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
) -> Result<CommandInvocation, String> {
    let command_files = CommandFiles {
        env: PathBuf::from("/workspace/.permanu-ci/env"),
        output: PathBuf::from("/workspace/.permanu-ci/output"),
        path: PathBuf::from("/workspace/.permanu-ci/path"),
        state: PathBuf::from("/workspace/.permanu-ci/state"),
        summary: PathBuf::from("/workspace/.permanu-ci/summary"),
        container_env: PathBuf::from("/workspace/.permanu-ci/container-env"),
    };
    build_ci_container_invocation_with_files(plan, step, env, &command_files)
}

fn build_ci_container_invocation_with_files(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    command_files: &CommandFiles,
) -> Result<CommandInvocation, String> {
    let Some(container) = &plan.container else {
        return Err("ci job: container image is required".to_string());
    };
    let container_work_dir = container_work_dir(&step.working_dir)?;
    let timeout_seconds = if step.timeout_minutes > 0 {
        u64::from(step.timeout_minutes) * 60
    } else {
        plan.timeout_seconds
    };
    let env_file_path = command_files
        .container_env
        .to_str()
        .ok_or_else(|| "container env file path is not valid UTF-8".to_string())?;
    let mut args = strings([
        "run",
        "--rm",
        "--network",
        plan.service_network_name().as_deref().unwrap_or("bridge"),
        "--workdir",
        &container_work_dir,
        "--volume",
        &format!("{}:/workspace", plan.clone_dir),
        "--env-file",
        env_file_path,
    ]);
    append_ci_sandbox_args(&mut args, plan.sandbox_policy.as_deref())?;
    let mut invocation_env = BTreeMap::new();
    for (key, value) in &container.env {
        append_container_env(&mut invocation_env, &plan.clone_dir, key, value)?;
    }
    for (key, value) in env {
        append_container_env(&mut invocation_env, &plan.clone_dir, key, value)?;
    }
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "PERMANU_ENV",
        &container_path(&plan.clone_dir, command_files.env.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "PERMANU_OUTPUT",
        &container_path(&plan.clone_dir, command_files.output.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "PERMANU_PATH",
        &container_path(&plan.clone_dir, command_files.path.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "PERMANU_STATE",
        &container_path(&plan.clone_dir, command_files.state.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "PERMANU_STEP_SUMMARY",
        &container_path(&plan.clone_dir, command_files.summary.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "GITHUB_ENV",
        &container_path(&plan.clone_dir, command_files.env.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "GITHUB_OUTPUT",
        &container_path(&plan.clone_dir, command_files.output.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "GITHUB_PATH",
        &container_path(&plan.clone_dir, command_files.path.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "GITHUB_STATE",
        &container_path(&plan.clone_dir, command_files.state.as_path())?,
    )?;
    append_container_env(
        &mut invocation_env,
        &plan.clone_dir,
        "GITHUB_STEP_SUMMARY",
        &container_path(&plan.clone_dir, command_files.summary.as_path())?,
    )?;
    args.extend(strings(["--entrypoint", ci_shell_program(step)]));
    let command_args = ci_shell_args(step);
    args.extend(strings([&container.image]));
    args.extend(command_args);
    Ok(CommandInvocation {
        program: "docker".to_string(),
        args,
        work_dir: Some(plan.clone_dir.clone()),
        env: invocation_env,
        host_env: docker_cli_host_env(),
        timeout_seconds,
    })
}

fn append_ci_sandbox_args(
    args: &mut Vec<String>,
    sandbox_policy: Option<&str>,
) -> Result<(), String> {
    match sandbox_policy.unwrap_or("") {
        "" => Ok(()),
        "untrusted" => {
            args.extend(strings([
                "--security-opt",
                "no-new-privileges",
                "--cap-drop",
                "ALL",
                "--pids-limit",
                "256",
            ]));
            Ok(())
        }
        _ => Err("ci job: unsupported sandbox policy".to_string()),
    }
}

fn append_action_command_file_env(
    plan: &CiJobPlan,
    command_files: &CommandFiles,
    invocation_env: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "PERMANU_ENV",
        &container_path(&plan.clone_dir, command_files.env.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "PERMANU_OUTPUT",
        &container_path(&plan.clone_dir, command_files.output.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "PERMANU_PATH",
        &container_path(&plan.clone_dir, command_files.path.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "PERMANU_STATE",
        &container_path(&plan.clone_dir, command_files.state.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "PERMANU_STEP_SUMMARY",
        &container_path(&plan.clone_dir, command_files.summary.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "GITHUB_ENV",
        &container_path(&plan.clone_dir, command_files.env.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "GITHUB_OUTPUT",
        &container_path(&plan.clone_dir, command_files.output.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "GITHUB_PATH",
        &container_path(&plan.clone_dir, command_files.path.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "GITHUB_STATE",
        &container_path(&plan.clone_dir, command_files.state.as_path())?,
    )?;
    append_container_env(
        invocation_env,
        &plan.clone_dir,
        "GITHUB_STEP_SUMMARY",
        &container_path(&plan.clone_dir, command_files.summary.as_path())?,
    )?;
    Ok(())
}

fn step_timeout(step: &CiStep, job_deadline: Instant) -> Result<Duration, String> {
    let step_budget = if step.timeout_minutes > 0 {
        Duration::from_secs(u64::from(step.timeout_minutes) * 60)
    } else {
        remaining_job_timeout(job_deadline)?
    };
    Ok(step_budget.min(remaining_job_timeout(job_deadline)?))
}

fn docker_cli_host_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for key in ["PATH", "HOME", "TMPDIR", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    env
}

fn write_container_env_file(path: &Path, env: &BTreeMap<String, String>) -> Result<(), String> {
    let mut content = String::new();
    for (key, value) in env {
        validate_env_key(key)?;
        if value.as_bytes().contains(&0) || value.contains('\n') || value.contains('\r') {
            return Err("ci job: container env values must be single-line".to_string());
        }
        content.push_str(key);
        content.push('=');
        content.push_str(value);
        content.push('\n');
    }
    fs::write(path, content.as_bytes())
        .map_err(|err| format!("write container env file: {err}"))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("secure container env file: {err}"))?;
    Ok(())
}

fn append_inherited_action_env(
    invocation_env: &mut BTreeMap<String, String>,
    clone_dir: &str,
    env: &BTreeMap<String, String>,
) -> Result<(), String> {
    for (key, value) in env {
        if validate_env_key(key).is_err() {
            continue;
        }
        append_container_env(invocation_env, clone_dir, key, value)?;
    }
    Ok(())
}

fn append_container_env(
    invocation_env: &mut BTreeMap<String, String>,
    clone_dir: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    validate_env_key(key)?;
    invocation_env.insert(key.to_string(), container_env_value(clone_dir, key, value));
    Ok(())
}

fn container_env_value(clone_dir: &str, key: &str, value: &str) -> String {
    if matches!(key, "GITHUB_WORKSPACE" | "PERMANU_WORKSPACE") {
        return "/workspace".to_string();
    }
    if key == "PATH" {
        return container_path_env(clone_dir, value);
    }
    let path = Path::new(value);
    if path.is_absolute() && path.starts_with(clone_dir) {
        if let Ok(mapped) = container_path(clone_dir, path) {
            return mapped;
        }
    }
    if let Ok(mapped) = ci_env_container_path(clone_dir, path) {
        return mapped;
    }
    value.to_string()
}

fn container_path_env(clone_dir: &str, host_path: &str) -> String {
    const DEFAULT_CONTAINER_PATH: &str =
        "/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let mut entries: Vec<String> = Vec::new();
    for entry in host_path.split(':') {
        if entry.is_empty() {
            continue;
        }
        if entry.starts_with("/workspace") {
            push_unique(&mut entries, entry.to_string());
            continue;
        }
        let path = Path::new(entry);
        if path.is_absolute() && path.starts_with(clone_dir) {
            if let Ok(mapped) = container_path(clone_dir, path) {
                push_unique(&mut entries, mapped);
            }
            continue;
        }
        if let Ok(mapped) = ci_env_container_path(clone_dir, path) {
            push_unique(&mut entries, mapped);
        }
    }
    for entry in DEFAULT_CONTAINER_PATH.split(':') {
        push_unique(&mut entries, entry.to_string());
    }
    entries.join(":")
}

fn push_unique(entries: &mut Vec<String>, value: String) {
    if !entries.iter().any(|entry| entry == &value) {
        entries.push(value);
    }
}

fn ci_env_container_path(clone_dir: &str, path: &Path) -> Result<String, String> {
    for (host, container) in ci_env_mounts(clone_dir)? {
        if path == host {
            return Ok(container.to_string());
        }
        if let Ok(relative) = path.strip_prefix(&host) {
            return Ok(format!("{container}/{}", relative.display()));
        }
    }
    Err("path is not a mounted CI env dir".to_string())
}

fn container_work_dir(working_dir: &str) -> Result<String, String> {
    let working_dir = working_dir.trim();
    if working_dir.is_empty() {
        return Ok("/workspace".to_string());
    }
    if Path::new(working_dir).is_absolute() {
        return Err("ci job: absolute working_dir is not supported for container jobs".to_string());
    }
    if working_dir.as_bytes().contains(&0)
        || working_dir.contains('\n')
        || working_dir.contains('\r')
        || working_dir.contains('\\')
    {
        return Err("invalid working_dir".to_string());
    }
    let mut path = PathBuf::from("/workspace");
    for component in Path::new(working_dir).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => return Err("working_dir must stay inside clone_dir".to_string()),
        }
    }
    Ok(path.to_string_lossy().to_string())
}

fn container_path(clone_dir: &str, path: &Path) -> Result<String, String> {
    if path.starts_with("/workspace") {
        return Ok(path.to_string_lossy().to_string());
    }
    let relative = path
        .strip_prefix(Path::new(clone_dir))
        .map_err(|_| "workflow command file must stay inside clone_dir".to_string())?;
    Ok(format!("/workspace/{}", relative.display()))
}

fn run_ci_step(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    log_forwarder: Option<Arc<LogForwarder>>,
    redactor: SecretRedactor,
) -> Result<StepOutcome, String> {
    let work_dir = resolve_ci_work_dir(&plan.clone_dir, &step.working_dir)?;
    let step_budget = if step.timeout_minutes > 0 {
        Duration::from_secs(u64::from(step.timeout_minutes) * 60)
    } else {
        remaining_job_timeout(job_deadline)?
    };
    let timeout = step_budget.min(remaining_job_timeout(job_deadline)?);
    prepare_ci_env_dirs(&plan.clone_dir)?;
    let command_files = prepare_command_files(&plan.clone_dir, &step.step_id())?;
    let mut container_host_env = BTreeMap::new();
    let (mut command, command_work_dir) = if plan.container.is_some() {
        let invocation = build_ci_container_invocation_with_files(plan, step, env, &command_files)?;
        write_container_env_file(&command_files.container_env, &invocation.env)?;
        let mut command = StdCommand::new(&invocation.program);
        command.args(&invocation.args);
        container_host_env = invocation.host_env;
        let work_dir = invocation
            .work_dir
            .unwrap_or_else(|| plan.clone_dir.clone());
        (command, PathBuf::from(work_dir))
    } else {
        (ci_shell_command(step), work_dir)
    };
    command.current_dir(command_work_dir);
    if plan.container.is_some() {
        if ci_strict_env_enabled() {
            command.env_clear();
        }
        command.envs(&container_host_env);
    } else {
        apply_ci_command_env(&mut command, env);
        command
            .env("PERMANU_ENV", &command_files.env)
            .env("PERMANU_OUTPUT", &command_files.output)
            .env("PERMANU_PATH", &command_files.path)
            .env("PERMANU_STATE", &command_files.state)
            .env("PERMANU_STEP_SUMMARY", &command_files.summary)
            .env("GITHUB_ENV", &command_files.env)
            .env("GITHUB_OUTPUT", &command_files.output)
            .env("GITHUB_PATH", &command_files.path)
            .env("GITHUB_STATE", &command_files.state)
            .env("GITHUB_STEP_SUMMARY", &command_files.summary);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepare_process_group(&mut command);
    let mut child = command.spawn().map_err(|err| {
        if plan.container.is_some() && err.kind() == std::io::ErrorKind::NotFound {
            format!("Docker is unavailable for CI container job: {err}")
        } else {
            format!("start ci step: {err}")
        }
    })?;
    let emitter =
        log_forwarder.map(|forwarder| CiLiveLogEmitter::new(forwarder, plan, step, redactor));
    if let Some(emitter) = &emitter {
        emit_enterprise_step_start(emitter, plan, step, env);
    }
    let started = Instant::now();
    let process = wait_for_child_output(&mut child, timeout, cancellation, emitter.clone())?;
    if let Some(emitter) = &emitter {
        emit_enterprise_step_result(emitter, &process, started.elapsed());
    }
    let command_updates = read_command_file_updates(&command_files)?;
    Ok(StepOutcome {
        process,
        command_updates,
        artifacts: Vec::new(),
        cache_save: None,
    })
}

fn emit_enterprise_step_start(
    emitter: &CiLiveLogEmitter,
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
) {
    emitter.emit_line("system", &format!("step: {}", display_ci_step_name(step)));
    emitter.emit_line("system", &format!("job: {}", display_ci_job_name(plan)));
    emitter.emit_line(
        "system",
        &format!("repository: {}", github_repository(plan)),
    );
    if !plan.head_sha.is_empty() {
        emitter.emit_line("system", &format!("commit: {}", plan.head_sha));
    }
    if !plan.trigger_ref.is_empty() {
        emitter.emit_line("system", &format!("ref: {}", plan.trigger_ref));
    }
    emitter.emit_line(
        "system",
        &format!(
            "runner: {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    );
    if let Ok(work_dir) = resolve_ci_work_dir(&plan.clone_dir, &step.working_dir) {
        emitter.emit_line(
            "system",
            &format!(
                "working-directory: {}",
                display_relative_to_workspace(plan, &work_dir)
            ),
        );
    }
    if !step.uses.is_empty() {
        emitter.emit_line("system", &format!("action: {}", step.uses));
    } else {
        emitter.emit_line("system", &format!("shell: {}", ci_step_shell_name(step)));
        emitter.emit_line("system", &format!("command: {}", step.run.trim()));
    }
    emitter.emit_line(
        "system",
        &format!(
            "environment: {} keys, {} secret keys masked",
            env.len(),
            plan.secret_keys.len()
        ),
    );
    emitter.emit_line("system", "--- output ---");
}

fn emit_enterprise_step_result(
    emitter: &CiLiveLogEmitter,
    process: &ProcessOutput,
    elapsed: Duration,
) {
    emitter.emit_line("system", "--- result ---");
    emitter.emit_line(
        "system",
        &format!(
            "status: {}",
            if process.status_success {
                "success"
            } else {
                "failure"
            }
        ),
    );
    emitter.emit_line(
        "system",
        &format!(
            "exit-code: {}",
            process
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
    );
    emitter.emit_line("system", &format!("duration-ms: {}", elapsed.as_millis()));
}

fn run_local_composite_action(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    label: &str,
    log: &mut String,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    log_forwarder: Option<Arc<LogForwarder>>,
    redactor: SecretRedactor,
) -> Result<StepOutcome, String> {
    let action = load_local_composite_action(&plan.clone_dir, &step.uses)?;
    let mut aggregate_output = String::new();
    let mut aggregate_updates = CommandFileUpdates::default();
    let mut composite_env = env.clone();
    let action_inputs = action_input_values(&action, step);
    apply_composite_inputs(&mut composite_env, &action_inputs);

    for (index, payload) in action.runs.steps.into_iter().enumerate() {
        let mut substep = parse_ci_step(payload)?;
        expand_composite_input_expressions(&mut substep, &action_inputs);
        substep.step_db_id = format!("{}-composite-{index}", step.step_id());
        substep.step_index = step.step_index;
        substep.continue_on_error = step.continue_on_error;
        if substep.name.is_empty() {
            substep.name = format!("step-{index}");
        }
        let sub_label = format!("{label} / {}", display_ci_step_name(&substep));
        append_capped(log, &format!("[{sub_label}] starting\n"));
        let sub_env = merge_step_env(&composite_env, &substep.env);
        let outcome = run_ci_step(
            plan,
            &substep,
            &sub_env,
            job_deadline,
            cancellation,
            log_forwarder.clone(),
            redactor.clone(),
        )?;
        apply_command_updates(&mut composite_env, outcome.command_updates, &plan.clone_dir);
        append_capped(
            &mut aggregate_output,
            &format!("[{sub_label}] {}\n", outcome.process.output),
        );
        if !outcome.process.status_success {
            return Ok(StepOutcome {
                process: ProcessOutput {
                    status_success: false,
                    output: aggregate_output.trim().to_string(),
                    exit_code: outcome.process.exit_code,
                },
                command_updates: aggregate_updates,
                artifacts: Vec::new(),
                cache_save: None,
            });
        }
        append_capped(log, &format!("[{sub_label}] completed successfully\n"));
        aggregate_updates = diff_env_updates(env, &composite_env);
    }

    Ok(StepOutcome {
        process: ProcessOutput {
            status_success: true,
            output: aggregate_output.trim().to_string(),
            exit_code: Some(0),
        },
        command_updates: aggregate_updates,
        artifacts: Vec::new(),
        cache_save: None,
    })
}

fn ci_shell_command(step: &CiStep) -> StdCommand {
    let mut command = StdCommand::new(ci_shell_program(step));
    command.args(ci_shell_args(step));
    command
}

fn ci_shell_program(step: &CiStep) -> &'static str {
    match step.shell.as_str() {
        "bash" => "bash",
        _ => "sh",
    }
}

fn ci_shell_argv(step: &CiStep) -> Vec<String> {
    match step.shell.as_str() {
        "bash" => {
            let mut argv = strings(["bash"]);
            argv.extend(ci_shell_args(step));
            argv
        }
        _ => {
            let mut argv = strings(["sh"]);
            argv.extend(ci_shell_args(step));
            argv
        }
    }
}

fn ci_shell_args(step: &CiStep) -> Vec<String> {
    match step.shell.as_str() {
        "bash" => strings([
            "--noprofile",
            "--norc",
            "-eo",
            "pipefail",
            "-c",
            step.run.as_str(),
        ]),
        _ => strings(["-e", "-c", step.run.as_str()]),
    }
}

fn wait_for_child_output(
    child: &mut Child,
    deadline: Duration,
    cancellation: &CancellationSignal,
    log_emitter: Option<CiLiveLogEmitter>,
) -> Result<ProcessOutput, String> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = stdout.map(|pipe| read_capped_pipe(pipe, "stdout", log_emitter.clone()));
    let stderr_reader = stderr.map(|pipe| read_capped_pipe(pipe, "stderr", log_emitter.clone()));
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait for ci step: {err}"))?
        {
            let output = join_capped_output(stdout_reader, stderr_reader);
            return Ok(ProcessOutput {
                status_success: status.success(),
                output,
                exit_code: status.code(),
            });
        }
        if cancellation.load(Ordering::SeqCst) {
            terminate_child(child);
            let _ = child.wait();
            let output = join_capped_output(stdout_reader, stderr_reader);
            let suffix = if output.is_empty() {
                String::new()
            } else {
                format!(":\n{output}")
            };
            return Err(format!("cancelled{suffix}"));
        }
        if started.elapsed() >= deadline {
            terminate_child(child);
            let _ = child.wait();
            let output = join_capped_output(stdout_reader, stderr_reader);
            let suffix = if output.is_empty() {
                String::new()
            } else {
                format!(":\n{output}")
            };
            return Err(format!("timed out after {}s{suffix}", deadline.as_secs()));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_capped_pipe<R: Read + Send + 'static>(
    mut reader: R,
    stream: &'static str,
    log_emitter: Option<CiLiveLogEmitter>,
) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut truncated = false;
        let mut buf = [0_u8; 8192];
        let mut pending_line = String::new();
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if output.len() < MAX_COMMAND_OUTPUT_BYTES {
                        let remaining = MAX_COMMAND_OUTPUT_BYTES - output.len();
                        output.extend_from_slice(&buf[..n.min(remaining)]);
                    }
                    if output.len() >= MAX_COMMAND_OUTPUT_BYTES {
                        truncated = true;
                    }
                    if let Some(emitter) = &log_emitter {
                        emit_ci_log_chunk(emitter, stream, &mut pending_line, &buf[..n]);
                    }
                }
                Err(_) => break,
            }
        }
        if let Some(emitter) = &log_emitter {
            flush_ci_log_line(emitter, stream, &mut pending_line);
        }
        (output, truncated)
    })
}

fn join_capped_output(
    stdout_reader: Option<thread::JoinHandle<(Vec<u8>, bool)>>,
    stderr_reader: Option<thread::JoinHandle<(Vec<u8>, bool)>>,
) -> String {
    let mut output = Vec::new();
    let mut truncated = false;
    for reader in [stdout_reader, stderr_reader].into_iter().flatten() {
        if let Ok((bytes, was_truncated)) = reader.join() {
            let remaining = MAX_COMMAND_OUTPUT_BYTES.saturating_sub(output.len());
            output.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
            truncated |= was_truncated || bytes.len() > remaining;
        }
    }
    if truncated {
        output.extend_from_slice(b"\n[output truncated]");
    }
    String::from_utf8_lossy(&output).trim().to_string()
}

#[derive(Clone)]
struct CiLiveLogEmitter {
    forwarder: Arc<LogForwarder>,
    run_id: String,
    job_id: String,
    step_id: String,
    sequence: Arc<AtomicU64>,
    redactor: Arc<SecretRedactor>,
}

impl CiLiveLogEmitter {
    fn new(
        forwarder: Arc<LogForwarder>,
        plan: &CiJobPlan,
        step: &CiStep,
        redactor: SecretRedactor,
    ) -> Self {
        Self {
            forwarder,
            run_id: plan.run_db_id.clone(),
            job_id: plan.job_db_id.clone(),
            step_id: step.step_id(),
            sequence: Arc::new(AtomicU64::new(0)),
            redactor: Arc::new(redactor),
        }
    }

    fn emit_line(&self, stream: &str, line: &str) {
        let line = self.redactor.redact(line.trim_end_matches(['\r', '\n']));
        if line.is_empty() {
            return;
        }
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let entry = ci_step_log_entry(
            &self.run_id,
            &self.job_id,
            &self.step_id,
            sequence,
            stream,
            line,
        );
        let _ = self.forwarder.push(entry);
    }
}

fn emit_ci_log_chunk(
    emitter: &CiLiveLogEmitter,
    stream: &str,
    pending_line: &mut String,
    chunk: &[u8],
) {
    pending_line.push_str(&String::from_utf8_lossy(chunk));
    while let Some(newline) = pending_line.find('\n') {
        let line = pending_line[..newline].to_string();
        emitter.emit_line(stream, &line);
        pending_line.replace_range(..=newline, "");
    }
}

fn flush_ci_log_line(emitter: &CiLiveLogEmitter, stream: &str, pending_line: &mut String) {
    if pending_line.is_empty() {
        return;
    }
    emitter.emit_line(stream, pending_line);
    pending_line.clear();
}

fn ci_step_log_entry(
    run_id: &str,
    job_id: &str,
    step_id: &str,
    sequence: u64,
    stream: &str,
    line: String,
) -> LogEntry {
    let mut fields = HashMap::with_capacity(5);
    fields.insert("ci_run_id".to_string(), run_id.to_string());
    fields.insert("ci_job_id".to_string(), job_id.to_string());
    fields.insert("ci_step_id".to_string(), step_id.to_string());
    fields.insert("ci_sequence".to_string(), sequence.to_string());
    fields.insert("ci_stream".to_string(), stream.to_string());
    LogEntry {
        timestamp_ns: now_unix_nanos(),
        source: "ci".to_string(),
        level: if stream == "stderr" { "error" } else { "info" }.to_string(),
        message: line,
        fields,
        app_id: String::new(),
        deployment_id: String::new(),
    }
}

#[cfg(unix)]
fn prepare_process_group(command: &mut StdCommand) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            if setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

#[cfg(not(unix))]
fn prepare_process_group(_command: &mut StdCommand) {}

#[cfg(unix)]
fn terminate_child(child: &mut Child) {
    let pgid = -(child.id() as std::os::raw::c_int);
    unsafe {
        kill(pgid, SIGTERM);
    }
    thread::sleep(Duration::from_secs(5));
    if matches!(child.try_wait(), Ok(None)) {
        unsafe {
            kill(pgid, SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn terminate_child(child: &mut Child) {
    let _ = child.kill();
}

#[cfg(unix)]
const SIGTERM: std::os::raw::c_int = 15;
#[cfg(unix)]
const SIGKILL: std::os::raw::c_int = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn setpgid(pid: std::os::raw::c_int, pgid: std::os::raw::c_int) -> std::os::raw::c_int;
    fn kill(pid: std::os::raw::c_int, sig: std::os::raw::c_int) -> std::os::raw::c_int;
}

fn remaining_job_timeout(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "ci job timed out before starting next operation".to_string())
}

fn resolve_ci_work_dir(clone_dir: &str, working_dir: &str) -> Result<PathBuf, String> {
    let base = PathBuf::from(normalize_work_dir(clone_dir)?);
    validate_managed_ci_clone_dir(&base)?;
    let working_dir = working_dir.trim();
    if working_dir.is_empty() {
        return Ok(base);
    }
    if working_dir.as_bytes().contains(&0)
        || working_dir.contains('\n')
        || working_dir.contains('\r')
        || working_dir.contains('\\')
    {
        return Err("invalid working_dir".to_string());
    }
    let path = Path::new(working_dir);
    if path.is_absolute() {
        return Err("working_dir must be relative and stay inside workspace".to_string());
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("working_dir must stay inside clone_dir".to_string());
        }
    }
    Ok(base.join(path))
}

fn materialize_action_bundles(plan: &CiJobPlan, log: &mut String) -> Result<(), String> {
    if plan.action_bundles.is_empty() {
        return Ok(());
    }
    let clone_dir = PathBuf::from(normalize_work_dir(&plan.clone_dir)?);
    validate_managed_ci_clone_dir(&clone_dir)?;
    for bundle in &plan.action_bundles {
        let action_dir = resolve_local_action_dir(&plan.clone_dir, &bundle.local_path)?;
        if !action_dir.starts_with(&clone_dir) {
            return Err(format!(
                "action bundle {} resolved outside workspace",
                bundle.uses
            ));
        }
        fs::create_dir_all(&action_dir)
            .map_err(|err| format!("create action bundle {}: {err}", bundle.uses))?;
        let action_path = action_dir.join(&bundle.action_filename);
        fs::write(&action_path, &bundle.action_yml)
            .map_err(|err| format!("write action bundle {}: {err}", bundle.uses))?;
        for (relative_path, content) in &bundle.files {
            validate_action_bundle_file_path(relative_path)?;
            let file_path = action_dir.join(relative_path);
            if !file_path.starts_with(&action_dir) {
                return Err(format!(
                    "action bundle file {} for {} resolved outside action directory",
                    relative_path, bundle.uses
                ));
            }
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!("create action bundle file parent {}: {err}", bundle.uses)
                })?;
            }
            fs::write(&file_path, content)
                .map_err(|err| format!("write action bundle file {}: {err}", bundle.uses))?;
        }
        append_capped(
            log,
            &format!(
                "materialized action bundle {} at {}\n",
                bundle.uses, bundle.local_path
            ),
        );
    }
    Ok(())
}

fn load_local_composite_action(clone_dir: &str, uses: &str) -> Result<CompositeAction, String> {
    validate_local_action_ref(uses)?;
    let action = load_local_action_metadata(clone_dir, uses)?;
    if action.runs.using.trim() != "composite" {
        return Err(format!(
            "local action {uses} uses unsupported runs.using {}",
            action.runs.using
        ));
    }
    if action.runs.steps.is_empty() {
        return Err(format!("local composite action {uses} has no steps"));
    }
    if action.runs.steps.len() > MAX_CI_STEPS {
        return Err(format!(
            "local composite action {uses} exceeds {MAX_CI_STEPS} steps"
        ));
    }
    Ok(action)
}

fn load_local_action_metadata(clone_dir: &str, uses: &str) -> Result<CompositeAction, String> {
    validate_local_action_ref(uses)?;
    let action_dir = resolve_local_action_dir(clone_dir, uses)?;
    let action_path = ["action.yml", "action.yaml"]
        .iter()
        .map(|name| action_dir.join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("local action {uses} is missing action.yml"))?;
    let content = fs::read_to_string(&action_path)
        .map_err(|err| format!("read local action {}: {err}", action_path.display()))?;
    let action: CompositeAction =
        serde_yaml::from_str(&content).map_err(|err| format!("parse local action: {err}"))?;
    Ok(action)
}

fn action_input_values(action: &CompositeAction, step: &CiStep) -> BTreeMap<String, String> {
    let mut inputs = BTreeMap::new();
    for (key, spec) in &action.inputs {
        if let Some(default) = &spec.default {
            inputs.insert(key.clone(), action_input_default_to_string(default));
        }
    }
    inputs.extend(step.with.clone());
    inputs
}

fn action_input_default_to_string(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::Null => String::new(),
        serde_yaml::Value::Bool(value) => value.to_string(),
        serde_yaml::Value::Number(value) => value.to_string(),
        serde_yaml::Value::String(value) => value.clone(),
        _ => serde_yaml::to_string(value)
            .unwrap_or_default()
            .trim_end()
            .to_string(),
    }
}

fn github_action_input_env_key(key: &str) -> Option<String> {
    if key.is_empty() || key.as_bytes().contains(&0) || key.contains('\n') || key.contains('\r') {
        return None;
    }
    let mut out = String::from("INPUT_");
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if ch == '-' {
            out.push('-');
        } else if ch == '_' || ch == ' ' {
            out.push('_');
        } else {
            return None;
        }
    }
    Some(out)
}

fn write_node_action_wrapper(
    command_files: &CommandFiles,
    clone_dir: &str,
    phase: &str,
    script: &str,
    inputs: &BTreeMap<String, String>,
) -> Result<String, String> {
    let wrapper_path = command_files
        .container_env
        .parent()
        .ok_or_else(|| "container env file has no parent".to_string())?
        .join(format!("{phase}-action-wrapper.js"));
    let mut input_env = BTreeMap::new();
    for key in inputs.keys() {
        let Some(env_key) = github_action_input_env_key(key) else {
            return Err(format!(
                "JavaScript action input {key:?} is not a valid env key"
            ));
        };
        input_env.insert(env_key, inputs.get(key).cloned().unwrap_or_default());
    }
    let input_json = serde_json::to_string(&input_env)
        .map_err(|err| format!("serialize action input wrapper env: {err}"))?;
    let script_json = serde_json::to_string(script)
        .map_err(|err| format!("serialize action wrapper script: {err}"))?;
    let content = format!(
        "const inputs = {input_json};\nfor (const [key, value] of Object.entries(inputs)) process.env[key] = value;\nrequire({script_json});\n"
    );
    fs::write(&wrapper_path, content).map_err(|err| format!("write action wrapper: {err}"))?;
    container_path(clone_dir, &wrapper_path)
}

fn local_action_uses_node_runtime(plan: &CiJobPlan, step: &CiStep) -> Result<bool, String> {
    if !step.uses.starts_with("./") && step.uses != "." {
        return Ok(false);
    }
    let action = load_local_action_metadata(&plan.clone_dir, &step.uses)?;
    Ok(node_action_image(&action.runs.using).is_some())
}

fn local_action_uses_docker_runtime(plan: &CiJobPlan, step: &CiStep) -> Result<bool, String> {
    if !step.uses.starts_with("./") && step.uses != "." {
        return Ok(false);
    }
    let action = load_local_action_metadata(&plan.clone_dir, &step.uses)?;
    Ok(action.runs.using.trim().eq_ignore_ascii_case("docker"))
}

fn node_action_image(using: &str) -> Option<&'static str> {
    match using.trim().to_ascii_lowercase().as_str() {
        "node12" | "node16" => Some("node:16-bookworm"),
        "node20" => Some("node:20-bookworm"),
        "node24" => Some("node:24-bookworm"),
        _ => None,
    }
}

fn run_local_docker_action(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    redactor: SecretRedactor,
) -> Result<StepOutcome, String> {
    let action = load_local_action_metadata(&plan.clone_dir, &step.uses)?;
    if !action.runs.using.trim().eq_ignore_ascii_case("docker") {
        return Err(format!(
            "local action {} does not use a Docker runtime",
            step.uses
        ));
    }
    let action_dir = resolve_local_action_dir(&plan.clone_dir, &step.uses)?;
    let image_name = action.runs.image.trim();
    if image_name.is_empty() {
        return Err(format!(
            "local Docker action {} is missing runs.image",
            step.uses
        ));
    }
    if image_name.starts_with("docker://") {
        let mut docker_step = step.clone();
        docker_step.uses = image_name.to_string();
        if !action.runs.args.is_empty() && !docker_step.with.contains_key("args") {
            docker_step.with.insert(
                "args".to_string(),
                expand_action_args(&action.runs.args, step)?.join(" "),
            );
        }
        return docker_image_action(
            plan,
            &docker_step,
            env,
            job_deadline,
            cancellation,
            redactor,
        );
    }
    validate_ci_working_dir_fragment(image_name)?;
    let dockerfile = action_dir.join(image_name);
    if !dockerfile.is_file() {
        return Err(format!(
            "local Docker action {} is missing Dockerfile {}",
            step.uses, image_name
        ));
    }
    let tag = format!(
        "permanu-ci-action-{}-{}",
        sanitized_docker_component(&plan.job_db_id),
        sanitize_file_component(&step.step_id()).to_ascii_lowercase()
    );
    let dockerfile_arg = dockerfile
        .to_str()
        .ok_or_else(|| "Docker action Dockerfile path is not valid UTF-8".to_string())?;
    let context_arg = action_dir
        .to_str()
        .ok_or_else(|| "Docker action directory path is not valid UTF-8".to_string())?;
    let build_args = strings([
        "build",
        "--file",
        dockerfile_arg,
        "--tag",
        &tag,
        context_arg,
    ]);
    let build = run_docker_command(&build_args, step_timeout(step, job_deadline)?, cancellation)?;
    if !build.status_success {
        return Ok(StepOutcome {
            process: ProcessOutput {
                status_success: false,
                output: redactor.redact(&build.output),
                exit_code: build.exit_code,
            },
            command_updates: CommandFileUpdates::default(),
            artifacts: Vec::new(),
            cache_save: None,
        });
    }

    prepare_ci_env_dirs(&plan.clone_dir)?;
    let command_files = prepare_command_files(&plan.clone_dir, &step.step_id())?;
    let mut action_env = BTreeMap::new();
    append_inherited_action_env(&mut action_env, &plan.clone_dir, env)?;
    append_action_command_file_env(plan, &command_files, &mut action_env)?;
    for (key, value) in action_input_values(&action, step) {
        if key == "args" {
            continue;
        }
        let Some(env_key) = composite_input_env_key(&key) else {
            return Err(format!(
                "Docker action input {key:?} is not a valid env key"
            ));
        };
        append_container_env(&mut action_env, &plan.clone_dir, &env_key, &value)?;
    }
    write_container_env_file(&command_files.container_env, &action_env)?;
    let mut run_args = strings([
        "run",
        "--rm",
        "--network",
        plan.service_network_name().as_deref().unwrap_or("bridge"),
        "--workdir",
        "/workspace",
        "--volume",
        &format!("{}:/workspace", plan.clone_dir),
        "--env-file",
        command_files
            .container_env
            .to_str()
            .ok_or_else(|| "container env file path is not valid UTF-8".to_string())?,
    ]);
    append_ci_env_volume_args(&mut run_args, &plan.clone_dir)?;
    if !action.runs.entrypoint.trim().is_empty() {
        run_args.push("--entrypoint".to_string());
        run_args.push(action.runs.entrypoint.trim().to_string());
    }
    run_args.push(tag);
    if let Some(args) = step
        .with
        .get("args")
        .filter(|value| !value.trim().is_empty())
    {
        run_args.extend(parse_command_argv(args)?);
    } else {
        run_args.extend(expand_action_args(&action.runs.args, step)?);
    }
    let process = run_docker_command(&run_args, step_timeout(step, job_deadline)?, cancellation)?;
    let command_updates = read_command_file_updates(&command_files)?;
    let output = if build.output.trim().is_empty() {
        process.output
    } else if process.output.trim().is_empty() {
        build.output
    } else {
        format!("{}\n{}", build.output, process.output)
    };
    Ok(StepOutcome {
        process: ProcessOutput {
            status_success: process.status_success,
            output: redactor.redact(&output),
            exit_code: process.exit_code,
        },
        command_updates,
        artifacts: Vec::new(),
        cache_save: None,
    })
}

fn run_local_javascript_action(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
    redactor: SecretRedactor,
) -> Result<StepOutcome, String> {
    let action = load_local_action_metadata(&plan.clone_dir, &step.uses)?;
    let image = node_action_image(&action.runs.using)
        .ok_or_else(|| format!("local action {} does not use a Node runtime", step.uses))?;
    let main = action.runs.main.trim();
    if main.is_empty() {
        return Err(format!(
            "local JavaScript action {} is missing runs.main",
            step.uses
        ));
    }
    prepare_ci_env_dirs(&plan.clone_dir)?;
    let command_files = prepare_command_files(&plan.clone_dir, &step.step_id())?;
    let mut action_env = BTreeMap::new();
    append_inherited_action_env(&mut action_env, &plan.clone_dir, env)?;
    append_action_command_file_env(plan, &command_files, &mut action_env)?;
    let action_inputs = action_input_values(&action, step);
    for (key, value) in &action_inputs {
        let Some(env_key) = composite_input_env_key(&key) else {
            return Err(format!(
                "JavaScript action input {key:?} is not a valid env key"
            ));
        };
        append_container_env(&mut action_env, &plan.clone_dir, &env_key, value)?;
    }
    write_container_env_file(&command_files.container_env, &action_env)?;
    let mut output = Vec::new();
    let mut status_success = true;
    let mut exit_code = Some(0);
    for (phase, script, if_expr) in [
        ("pre", action.runs.pre.trim(), action.runs.pre_if.trim()),
        ("main", main, ""),
        ("post", action.runs.post.trim(), action.runs.post_if.trim()),
    ] {
        if script.is_empty() {
            continue;
        }
        if phase != "main" && !should_run_ci_step(plan, if_expr, !status_success) {
            continue;
        }
        let process = run_node_action_script(
            plan,
            step,
            image,
            script,
            &action_inputs,
            &command_files,
            job_deadline,
            cancellation,
        )?;
        if !process.output.trim().is_empty() {
            output.push(format!("[{phase}] {}", process.output));
        }
        if !process.status_success {
            status_success = false;
            exit_code = process.exit_code;
            if phase != "main" {
                break;
            }
        }
    }
    let command_updates = read_command_file_updates(&command_files)?;
    Ok(StepOutcome {
        process: ProcessOutput {
            status_success,
            output: redactor.redact(output.join("\n").trim()),
            exit_code,
        },
        command_updates,
        artifacts: Vec::new(),
        cache_save: None,
    })
}

fn run_node_action_script(
    plan: &CiJobPlan,
    step: &CiStep,
    image: &str,
    script: &str,
    action_inputs: &BTreeMap<String, String>,
    command_files: &CommandFiles,
    job_deadline: Instant,
    cancellation: &CancellationSignal,
) -> Result<ProcessOutput, String> {
    validate_ci_working_dir_fragment(script)?;
    let action_dir = resolve_local_action_dir(&plan.clone_dir, &step.uses)?;
    let script_path = action_dir.join(script);
    let script_container_path = container_path(&plan.clone_dir, &script_path)?;
    let wrapper_container_path = write_node_action_wrapper(
        command_files,
        &plan.clone_dir,
        &step.step_id(),
        &script_container_path,
        action_inputs,
    )?;
    let env_file_path = command_files
        .container_env
        .to_str()
        .ok_or_else(|| "container env file path is not valid UTF-8".to_string())?;
    let mut args = strings([
        "run",
        "--rm",
        "--network",
        plan.service_network_name().as_deref().unwrap_or("bridge"),
        "--workdir",
        "/workspace",
        "--volume",
        &format!("{}:/workspace", plan.clone_dir),
        "--env-file",
        env_file_path,
    ]);
    append_ci_env_volume_args(&mut args, &plan.clone_dir)?;
    args.extend(strings([image, "node", &wrapper_container_path]));
    run_docker_command(&args, step_timeout(step, job_deadline)?, cancellation)
}

fn expand_action_args(args: &[String], step: &CiStep) -> Result<Vec<String>, String> {
    let mut expanded = Vec::with_capacity(args.len());
    for arg in args {
        let value = expand_action_arg(arg, step)?;
        if !value.trim().is_empty() {
            expanded.push(value);
        }
    }
    Ok(expanded)
}

fn expand_action_arg(arg: &str, step: &CiStep) -> Result<String, String> {
    let mut value = arg.to_string();
    for (key, input) in &step.with {
        if key.as_bytes().contains(&0) || key.contains('\n') || key.contains('\r') {
            return Err(format!("action input {key:?} is not valid"));
        }
        value = value.replace(&format!("${{{{ inputs.{key} }}}}"), input);
        value = value.replace(&format!("${{{{inputs.{key}}}}}"), input);
    }
    if value.contains("${{") {
        return Err(format!(
            "Docker action arg {arg:?} contains an unsupported expression"
        ));
    }
    Ok(value)
}

fn validate_local_action_ref(uses: &str) -> Result<(), String> {
    if !(uses == "." || uses.starts_with("./")) {
        return Err("ci job: only local composite uses steps are supported".to_string());
    }
    if uses.as_bytes().contains(&0)
        || uses.contains('\\')
        || uses.contains('\n')
        || uses.contains('\r')
        || uses.contains('@')
    {
        return Err("ci job: invalid local action reference".to_string());
    }
    let path = Path::new(uses);
    for component in path.components() {
        match component {
            Component::CurDir | Component::Normal(_) => {}
            _ => {
                return Err("ci job: local action reference must stay inside clone_dir".to_string())
            }
        }
    }
    Ok(())
}

fn resolve_local_action_dir(clone_dir: &str, uses: &str) -> Result<PathBuf, String> {
    validate_local_action_ref(uses)?;
    let base = PathBuf::from(normalize_work_dir(clone_dir)?);
    validate_managed_ci_clone_dir(&base)?;
    let rel = uses.strip_prefix("./").unwrap_or(uses);
    if rel.is_empty() || rel == "." {
        return Ok(base);
    }
    Ok(base.join(rel))
}

fn prepare_ci_env_dirs(clone_dir: &str) -> Result<(), String> {
    let root = ci_job_root(clone_dir)?;
    for dir in ["home", "tmp", "runner-temp"] {
        fs::create_dir_all(root.join(dir)).map_err(|err| format!("create ci env dir: {err}"))?;
    }
    for (host, _) in ci_tool_cache_dirs(&root) {
        fs::create_dir_all(host).map_err(|err| format!("create ci tool cache dir: {err}"))?;
    }
    Ok(())
}

fn ci_job_root(clone_dir: &str) -> Result<PathBuf, String> {
    let workspace = PathBuf::from(normalize_work_dir(clone_dir)?);
    validate_managed_ci_clone_dir(&workspace)?;
    workspace
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "ci job: clone_dir has no parent".to_string())
}

fn ci_env_mounts(clone_dir: &str) -> Result<Vec<(PathBuf, &'static str)>, String> {
    let root = ci_job_root(clone_dir)?;
    let mut mounts = vec![
        (root.join("home"), "/permanu-ci/home"),
        (root.join("tmp"), "/permanu-ci/tmp"),
        (root.join("runner-temp"), "/permanu-ci/runner-temp"),
    ];
    mounts.extend(ci_tool_cache_dirs(&root));
    Ok(mounts)
}

fn ci_tool_cache_dirs(job_root: &Path) -> Vec<(PathBuf, &'static str)> {
    let root = if ci_shared_tool_cache_enabled() {
        ci_shared_tool_cache_root()
    } else {
        job_root.to_path_buf()
    };
    vec![
        (
            root.join("runner-tool-cache"),
            "/permanu-ci/runner-tool-cache",
        ),
        (root.join("cargo"), "/permanu-ci/cargo"),
        (root.join("rustup"), "/permanu-ci/rustup"),
    ]
}

fn ci_shared_tool_cache_enabled() -> bool {
    match std::env::var(CI_SHARED_TOOL_CACHE_ENV) {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            !matches!(
                value.as_str(),
                "0" | "false" | "no" | "off" | "job" | "job-local"
            )
        }
        Err(_) => !running_under_rust_test(),
    }
}

fn running_under_rust_test() -> bool {
    if cfg!(test) {
        return true;
    }
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .is_some_and(|name| name.contains("_test") || name.ends_with("-test"))
}

fn ci_shared_tool_cache_root() -> PathBuf {
    std::env::var(CI_SHARED_TOOL_CACHE_ROOT_ENV)
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| ci_workspace_root().join("_tool-cache"))
}

fn append_ci_env_volume_args(args: &mut Vec<String>, clone_dir: &str) -> Result<(), String> {
    for (host, container) in ci_env_mounts(clone_dir)? {
        args.push("--volume".to_string());
        args.push(format!("{}:{container}", host.to_string_lossy()));
    }
    Ok(())
}

fn prepare_command_files(clone_dir: &str, step_id: &str) -> Result<CommandFiles, String> {
    let workspace = PathBuf::from(normalize_work_dir(clone_dir)?);
    validate_managed_ci_clone_dir(&workspace)?;
    let root = workspace
        .join(".permanu-ci")
        .join(sanitize_file_component(step_id));
    fs::create_dir_all(&root).map_err(|err| format!("create workflow command files: {err}"))?;
    let files = CommandFiles {
        env: root.join("env"),
        output: root.join("output"),
        path: root.join("path"),
        state: root.join("state"),
        summary: root.join("summary"),
        container_env: root.join("container-env"),
    };
    for path in [
        &files.env,
        &files.output,
        &files.path,
        &files.state,
        &files.summary,
        &files.container_env,
    ] {
        fs::write(path, b"").map_err(|err| format!("create workflow command file: {err}"))?;
    }
    Ok(files)
}

fn read_command_file_updates(files: &CommandFiles) -> Result<CommandFileUpdates, String> {
    let env = read_key_value_file(&files.env, validate_env_key)?;
    let output = read_key_value_file(&files.output, validate_output_key)?;
    let path_entries = read_line_file(&files.path)?;
    let summary = fs::read_to_string(&files.summary).unwrap_or_default();
    Ok(CommandFileUpdates {
        env,
        path_entries,
        output,
        summary,
    })
}

fn read_key_value_file(
    path: &Path,
    validate_key: fn(&str) -> Result<(), String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some((key, delimiter)) = line.split_once("<<") {
            validate_key(key)?;
            if delimiter.is_empty()
                || delimiter.as_bytes().contains(&0)
                || delimiter.contains('\r')
                || delimiter.contains('\n')
            {
                return Err(format!(
                    "workflow command file {} has invalid multiline delimiter",
                    path.display()
                ));
            }
            let mut value = String::new();
            let mut found_end = false;
            for value_line in lines.by_ref() {
                if value_line == delimiter {
                    found_end = true;
                    break;
                }
                if !value.is_empty() {
                    value.push('\n');
                }
                value.push_str(value_line);
            }
            if !found_end {
                return Err(format!(
                    "workflow command file {} has unterminated multiline value",
                    path.display()
                ));
            }
            values.insert(key.to_string(), value);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "workflow command file {} has invalid line",
                path.display()
            ));
        };
        validate_key(key)?;
        values.insert(key.to_string(), value.to_string());
    }
    Ok(values)
}

fn validate_output_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.as_bytes().contains(&0) || key.contains('\n') || key.contains('\r') {
        return Err(format!("invalid output key {key:?}"));
    }
    if key.starts_with("GITHUB_") || key.starts_with("RUNNER_") {
        return Err(format!("invalid output key {key:?}"));
    }
    Ok(())
}

fn apply_composite_inputs(env: &mut BTreeMap<String, String>, inputs: &BTreeMap<String, String>) {
    for (key, value) in inputs {
        if let Some(env_key) = composite_input_env_key(key) {
            env.insert(env_key, value.clone());
        }
    }
}

fn expand_composite_input_expressions(step: &mut CiStep, inputs: &BTreeMap<String, String>) {
    step.run = expand_input_expressions(&step.run, inputs);
    for value in step.env.values_mut() {
        *value = expand_input_expressions(value, inputs);
    }
}

fn expand_input_expressions(value: &str, inputs: &BTreeMap<String, String>) -> String {
    let mut expanded = value.to_string();
    for (key, input_value) in inputs {
        expanded = expanded.replace(&format!("${{{{ inputs.{key} }}}}"), input_value);
    }
    expanded
}

fn composite_input_env_key(key: &str) -> Option<String> {
    if key.is_empty() || key.as_bytes().contains(&0) || key.contains('\n') || key.contains('\r') {
        return None;
    }
    let mut out = String::from("INPUT_");
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if ch == '-' || ch == '_' || ch == ' ' {
            out.push('_');
        } else {
            return None;
        }
    }
    Some(out)
}

fn read_line_file(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.as_bytes().contains(&0) || line.contains('\n') || line.contains('\r') {
            return Err(format!(
                "workflow path file {} has invalid line",
                path.display()
            ));
        }
        lines.push(line.to_string());
    }
    Ok(lines)
}

fn apply_command_updates(
    env: &mut BTreeMap<String, String>,
    updates: CommandFileUpdates,
    clone_dir: &str,
) {
    for (key, value) in updates.env {
        env.insert(key, value);
    }
    if !updates.path_entries.is_empty() {
        let existing = env
            .get("PATH")
            .cloned()
            .or_else(|| std::env::var("PATH").ok())
            .unwrap_or_default();
        let mapped_entries: Vec<String> = updates
            .path_entries
            .iter()
            .map(|entry| container_workspace_path_to_host(clone_dir, entry))
            .collect();
        let mut next = mapped_entries.join(":");
        if !existing.is_empty() {
            next.push(':');
            next.push_str(&existing);
        }
        env.insert("PATH".to_string(), next);
    }
    for (key, value) in updates.output {
        env.insert(format!("PERMANU_OUTPUT_{key}"), value);
    }
    if !updates.summary.is_empty() {
        env.insert("PERMANU_STEP_SUMMARY".to_string(), updates.summary);
    }
}

fn container_workspace_path_to_host(clone_dir: &str, value: &str) -> String {
    if let Some(suffix) = value.strip_prefix("/workspace") {
        return format!("{clone_dir}{suffix}");
    }
    if let Ok(mounts) = ci_env_mounts(clone_dir) {
        for (host, container) in mounts {
            if value == container {
                return host.to_string_lossy().to_string();
            }
            if let Some(suffix) = value.strip_prefix(&format!("{container}/")) {
                return host.join(suffix).to_string_lossy().to_string();
            }
        }
    }
    value.to_string()
}

fn append_valid_env_entries(
    env: &mut BTreeMap<String, String>,
    entries: &BTreeMap<String, String>,
) {
    for (key, value) in entries {
        if validate_env_key(key).is_ok() {
            env.insert(key.clone(), value.clone());
        }
    }
}

fn merge_step_env(
    base: &BTreeMap<String, String>,
    step_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = base.clone();
    env.extend(step_env.clone());
    env
}

fn diff_env_updates(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> CommandFileUpdates {
    let env = after
        .iter()
        .filter(|(key, value)| before.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    CommandFileUpdates {
        env,
        ..CommandFileUpdates::default()
    }
}

fn sanitize_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn merged_ci_env(
    plan: &CiJobPlan,
    step: &CiStep,
    runtime_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let workspace = PathBuf::from(&plan.clone_dir);
    let strict_env = ci_strict_env_enabled();
    let mut env: BTreeMap<String, String> = if strict_env {
        BTreeMap::new()
    } else {
        std::env::vars().collect()
    };
    env.insert("PATH".to_string(), ci_path());
    env.extend(plan.env.clone());
    append_valid_env_entries(&mut env, &plan.matrix_values);
    env.extend(runtime_env.clone());
    env.extend(step.env.clone());
    if strict_env {
        apply_strict_workspace_env(&mut env, &workspace);
        apply_linux_hosted_toolchain_defaults(&mut env);
    }
    env.insert("GITHUB_WORKSPACE".to_string(), plan.clone_dir.clone());
    env.insert("PERMANU_WORKSPACE".to_string(), plan.clone_dir.clone());
    env.insert("GITHUB_SHA".to_string(), plan.head_sha.clone());
    env.insert("GITHUB_REF".to_string(), plan.trigger_ref.clone());
    env.insert("GITHUB_REPOSITORY".to_string(), github_repository(plan));
    env.insert("GITHUB_JOB".to_string(), display_ci_job_name(plan));
    env.insert("GITHUB_ACTIONS".to_string(), "true".to_string());
    if plan.oidc_token_requests_allowed
        && !plan.oidc_request_url.is_empty()
        && !plan.oidc_request_token.is_empty()
    {
        env.insert(
            "ACTIONS_ID_TOKEN_REQUEST_URL".to_string(),
            plan.oidc_request_url.clone(),
        );
        env.insert(
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN".to_string(),
            plan.oidc_request_token.clone(),
        );
    }
    env.insert("PERMANU_SHA".to_string(), plan.head_sha.clone());
    env.insert("PERMANU_REF".to_string(), plan.trigger_ref.clone());
    env.insert("PERMANU_REPOSITORY".to_string(), github_repository(plan));
    env.insert("PERMANU_JOB".to_string(), display_ci_job_name(plan));
    env.insert("PERMANU_ACTIONS".to_string(), "true".to_string());
    env.insert("CI_JOB_ID".to_string(), plan.job_db_id.clone());
    if !plan.job_id_yaml.is_empty() {
        env.insert("CI_JOB_NAME".to_string(), plan.job_id_yaml.clone());
    }
    env
}

fn ci_strict_env_enabled() -> bool {
    match std::env::var(CI_STRICT_ENV_ENV) {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            !matches!(
                value.as_str(),
                "0" | "false" | "no" | "off" | "legacy" | "legacy-shell"
            )
        }
        Err(_) => true,
    }
}

fn ci_path() -> String {
    std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string())
}

fn apply_ci_command_env(command: &mut StdCommand, env: &BTreeMap<String, String>) {
    if ci_strict_env_enabled() {
        command.env_clear();
    }
    command.envs(env);
}

fn apply_strict_workspace_env(env: &mut BTreeMap<String, String>, workspace: &Path) {
    let root = workspace.parent().unwrap_or(workspace);
    for (key, dir) in [
        ("HOME", "home"),
        ("TMPDIR", "tmp"),
        ("RUNNER_TEMP", "runner-temp"),
    ] {
        env.insert(
            key.to_string(),
            root.join(dir).to_string_lossy().to_string(),
        );
    }
    for (key, path) in [
        (
            "RUNNER_TOOL_CACHE",
            ci_tool_cache_dir_for_env(root, "runner-tool-cache"),
        ),
        ("CARGO_HOME", ci_tool_cache_dir_for_env(root, "cargo")),
        ("RUSTUP_HOME", ci_tool_cache_dir_for_env(root, "rustup")),
    ] {
        env.insert(key.to_string(), path.to_string_lossy().to_string());
    }
}

fn ci_tool_cache_dir_for_env(job_root: &Path, name: &str) -> PathBuf {
    if ci_shared_tool_cache_enabled() {
        ci_shared_tool_cache_root().join(name)
    } else {
        job_root.join(name)
    }
}

fn apply_linux_hosted_toolchain_defaults(env: &mut BTreeMap<String, String>) {
    if cfg!(target_os = "linux") {
        env.entry("CGO_ENABLED".to_string())
            .or_insert_with(|| "1".to_string());
        env.entry("CC".to_string())
            .or_insert_with(|| "gcc".to_string());
        env.entry("CXX".to_string())
            .or_insert_with(|| "g++".to_string());
    }
}

fn github_repository(plan: &CiJobPlan) -> String {
    if plan.repo_owner.is_empty() || plan.repo_name.is_empty() {
        String::new()
    } else {
        format!("{}/{}", plan.repo_owner, plan.repo_name)
    }
}

fn display_ci_job_name(plan: &CiJobPlan) -> String {
    if plan.job_id_yaml.is_empty() {
        plan.job_db_id.clone()
    } else {
        format!("{} ({})", plan.job_id_yaml, plan.job_db_id)
    }
}

fn display_ci_step_name(step: &CiStep) -> String {
    if step.name.is_empty() {
        step.step_id()
    } else {
        step.name.clone()
    }
}

fn render_step_statuses(statuses: &BTreeMap<String, String>) -> String {
    statuses
        .iter()
        .map(|(step, status)| format!("{step}={status}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn append_capped(output: &mut String, text: &str) {
    if output.len() >= MAX_COMMAND_OUTPUT_BYTES {
        return;
    }
    let remaining = MAX_COMMAND_OUTPUT_BYTES - output.len();
    if text.len() <= remaining {
        output.push_str(text);
        return;
    }
    let end = text
        .char_indices()
        .map(|(index, ch)| index + ch.len_utf8())
        .take_while(|index| *index <= remaining)
        .last()
        .unwrap_or(0);
    output.push_str(&text[..end]);
}

#[derive(Clone)]
struct SecretRedactor {
    values: Vec<String>,
    b64_values: Vec<String>,
}

impl SecretRedactor {
    fn from_env(env: &BTreeMap<String, String>, secret_keys: &[String]) -> Self {
        let mut redactor = Self {
            values: Vec::new(),
            b64_values: Vec::new(),
        };
        for key in secret_keys {
            if let Some(value) = env.get(key) {
                redactor.add_secret_value(value);
            }
        }
        for key in [
            "SIGSTORE_ID_TOKEN",
            "PERMANU_SIGSTORE_ID_TOKEN",
            "COSIGN_KEY",
            "PERMANU_COSIGN_KEY",
            "COSIGN_PASSWORD",
        ] {
            if let Some(value) = env.get(key) {
                redactor.add_secret_value(value);
            }
        }
        redactor
    }

    fn add_secret_value(&mut self, value: &str) {
        if value.is_empty() || self.values.iter().any(|existing| existing == value) {
            return;
        }
        self.values.push(value.to_string());
        self.values.sort_by_key(|value| Reverse(value.len()));
        self.b64_values = self
            .values
            .iter()
            .map(|value| general_purpose::STANDARD.encode(value.as_bytes()))
            .collect();
    }

    fn redact(&self, value: &str) -> String {
        let mut redacted = value.to_string();
        for secret in &self.values {
            redacted = redacted.replace(secret, "***");
        }
        for secret in &self.b64_values {
            if !secret.is_empty() {
                redacted = redacted.replace(secret, "***");
            }
        }
        redacted
    }
}

pub fn parse_swarm_deploy(payload: &[u8]) -> Result<SwarmDeployPayload, String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        stack_name: String,
        #[serde(default)]
        compose_content: String,
        #[serde(default)]
        extra_files: BTreeMap<String, String>,
        #[serde(default)]
        prune: bool,
        #[serde(default)]
        resolve_image: String,
        #[serde(default)]
        detach: bool,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    validate_swarm_stack_name(&payload.stack_name)?;
    if payload.compose_content.is_empty() {
        return Err("compose_content is required".to_string());
    }
    validate_resolve_image(&payload.resolve_image)?;
    validate_swarm_payload_size(&payload.compose_content, &payload.extra_files)?;
    validate_swarm_compose_content(&payload.compose_content)?;
    for path in payload.extra_files.keys() {
        validate_extra_file_path(path)?;
    }
    Ok(SwarmDeployPayload {
        stack_name: payload.stack_name,
        compose_content: payload.compose_content,
        extra_files: payload.extra_files,
        prune: payload.prune,
        resolve_image: empty_to_none(payload.resolve_image),
        detach: payload.detach,
    })
}

pub fn build_swarm_deploy_args(payload: &SwarmDeployPayload, stack_dir: &str) -> Vec<String> {
    let mut args = vec![
        "stack".to_string(),
        "deploy".to_string(),
        "--compose-file".to_string(),
        Path::new(stack_dir)
            .join(SWARM_STACK_FILE_NAME)
            .to_string_lossy()
            .to_string(),
    ];
    if payload.prune {
        args.push("--prune".to_string());
    }
    if let Some(resolve_image) = &payload.resolve_image {
        args.push("--resolve-image".to_string());
        args.push(resolve_image.clone());
    }
    if !payload.detach {
        args.push("--detach=false".to_string());
    }
    args.push(payload.stack_name.clone());
    args
}

pub fn parse_swarm_remove(payload: &[u8]) -> Result<String, String> {
    parse_swarm_stack_payload(payload)
}

pub fn parse_swarm_status(payload: &[u8]) -> Result<String, String> {
    parse_swarm_stack_payload(payload)
}

pub fn parse_swarm_rollback(payload: &[u8]) -> Result<(String, String), String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        stack_name: String,
        #[serde(default)]
        service_name: String,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    validate_swarm_stack_name(&payload.stack_name)?;
    if payload.service_name.trim().is_empty() {
        return Err("service_name is required".to_string());
    }
    let _ = swarm_service_name(&payload.stack_name, payload.service_name.trim())?;
    Ok((payload.stack_name, payload.service_name.trim().to_string()))
}

pub fn swarm_stack_dir(stack_name: &str) -> Result<PathBuf, String> {
    validate_swarm_stack_name(stack_name)?;
    let root = Path::new(DEPLOYMENT_BASE_DIR).join("swarm");
    let dir = root.join(stack_name);
    if !dir.starts_with(&root) {
        return Err("swarm stack dir escapes swarm root".to_string());
    }
    Ok(dir)
}

pub fn build_swarm_remove_args(stack_name: &str) -> Result<Vec<String>, String> {
    validate_swarm_stack_name(stack_name)?;
    Ok(strings(["stack", "rm", stack_name]))
}

pub fn build_swarm_status_args(stack_name: &str) -> Result<(Vec<String>, Vec<String>), String> {
    validate_swarm_stack_name(stack_name)?;
    Ok((
        strings(["stack", "services", stack_name, "--format", "{{json .}}"]),
        strings([
            "stack",
            "ps",
            stack_name,
            "--no-trunc",
            "--format",
            "{{json .}}",
        ]),
    ))
}

pub fn build_swarm_rollback_args(
    stack_name: &str,
    service_name: &str,
) -> Result<Vec<String>, String> {
    let service_name = swarm_service_name(stack_name, service_name)?;
    Ok(strings(["service", "rollback", &service_name]))
}

pub fn parse_app_proxy_setup(payload: &[u8]) -> Result<AppProxySetup, String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        slug: String,
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        port: u16,
        #[serde(default)]
        domains: Vec<String>,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    validate_slug(&payload.slug)?;
    validate_docker_name(&payload.container_name, "container_name")?;
    for domain in &payload.domains {
        validate_domain(domain)?;
    }
    let port = if payload.port == 0 {
        3000
    } else {
        payload.port
    };
    Ok(AppProxySetup {
        upstream: format!("{}:{port}", payload.container_name),
        slug: payload.slug,
        container_name: payload.container_name,
        port,
        domains: payload.domains,
    })
}

pub fn parse_app_proxy_remove(payload: &[u8]) -> Result<AppProxyRemove, String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        slug: String,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    validate_slug(&payload.slug)?;
    Ok(AppProxyRemove { slug: payload.slug })
}

pub fn render_app_proxy_snippet(setup: &AppProxySetup, internal_apex: &str) -> String {
    let mut snippet = String::new();
    snippet.push_str(&format!("# App: {}\n", setup.slug));
    snippet.push_str(&format!("{} {{\n", setup.default_route_host(internal_apex)));
    snippet.push_str(&format!("    reverse_proxy {}\n", setup.upstream));
    snippet.push_str("}\n");
    for domain in &setup.domains {
        snippet.push('\n');
        snippet.push_str(&format!("{domain} {{\n"));
        snippet.push_str(&format!("    reverse_proxy {}\n", setup.upstream));
        snippet.push_str("}\n");
    }
    snippet
}

pub async fn run_invocation(invocation: &CommandInvocation) -> Result<ProcessOutput, String> {
    let mut command = Command::new(&invocation.program);
    command
        .args(&invocation.args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(work_dir) = &invocation.work_dir {
        command.current_dir(work_dir);
    }
    for (key, value) in &invocation.env {
        command.env(key, value);
    }
    for (key, value) in &invocation.host_env {
        command.env(key, value);
    }
    let deadline = Duration::from_secs(invocation.timeout_seconds);
    let output = timeout(deadline, command.output())
        .await
        .map_err(|err| format!("{} timed out: {err}", invocation.program))?
        .map_err(|err| format!("run {}: {err}", invocation.program))?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    if combined.len() > MAX_COMMAND_OUTPUT_BYTES {
        combined.truncate(MAX_COMMAND_OUTPUT_BYTES);
        combined.extend_from_slice(b"\n[output truncated]");
    }
    Ok(ProcessOutput {
        status_success: output.status.success(),
        output: String::from_utf8_lossy(&combined).trim().to_string(),
        exit_code: output.status.code(),
    })
}

fn parse_commands(commands: &[String]) -> Result<Vec<ParsedCommand>, String> {
    let mut parsed = Vec::with_capacity(commands.len());
    for command in commands {
        let argv = parse_command_argv(command)?;
        parsed.push(ParsedCommand {
            original: command.clone(),
            argv,
        });
    }
    Ok(parsed)
}

fn parse_command_argv(command: &str) -> Result<Vec<String>, String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err("hook command must not be empty".to_string());
    }
    reject_shell_syntax(trimmed)?;

    let mut argv = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in trimmed.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ch if ch.is_whitespace() => {
                if !current.is_empty() {
                    argv.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if quote.is_some() {
        return Err("unterminated quote in hook command".to_string());
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        argv.push(current);
    }
    if argv.is_empty() {
        return Err("hook command must not be empty".to_string());
    }
    Ok(argv)
}

fn reject_shell_syntax(command: &str) -> Result<(), String> {
    if command
        .chars()
        .any(|ch| matches!(ch, ';' | '|' | '&' | '<' | '>' | '`' | '$' | '\n' | '\r'))
    {
        return Err("unsupported shell syntax in hook command".to_string());
    }
    Ok(())
}

pub fn validate_env(env: &BTreeMap<String, String>) -> Result<(), String> {
    for key in env.keys() {
        validate_env_key(key)?;
    }
    Ok(())
}

fn validate_env_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > 128 {
        return Err(format!("invalid env key {key:?}"));
    }
    let mut chars = key.chars();
    if !chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        return Err(format!("invalid env key {key:?}"));
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return Err(format!("invalid env key {key:?}"));
    }
    Ok(())
}

fn normalize_work_dir(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok("/tmp".to_string());
    }
    if value.as_bytes().contains(&0)
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('\\')
    {
        return Err("invalid clone_dir".to_string());
    }
    Ok(value.to_string())
}

fn default_ci_clone_dir(run_db_id: &str, job_db_id: &str) -> Result<String, String> {
    validate_label(job_db_id, "job_db_id")?;
    let run = if run_db_id.trim().is_empty() {
        "adhoc"
    } else {
        validate_label(run_db_id.trim(), "run_db_id")?;
        run_db_id.trim()
    };
    Ok(ci_workspace_root()
        .join(run)
        .join(job_db_id)
        .join("workspace")
        .to_string_lossy()
        .to_string())
}

fn ci_workspace_root() -> PathBuf {
    std::env::var_os(CI_WORKSPACE_ROOT_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CI_WORKSPACE_ROOT))
}

fn validate_managed_ci_clone_dir(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("checkout clone_dir must be absolute".to_string());
    }
    let root = ci_workspace_root();
    let legacy_root = Path::new("/tmp/permanu-ci");
    if !path.starts_with(&root) && !path.starts_with(legacy_root) {
        return Err(format!(
            "checkout clone_dir must be under {}",
            root.display()
        ));
    }
    Ok(())
}

fn validate_optional_github_component(value: &str, label: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if value == "." || value == ".." || value.len() > 100 {
        return Err(format!("invalid {label}"));
    }
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_optional_head_sha(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid head_sha".to_string());
    }
    Ok(())
}

fn validate_image_reference(value: &str) -> Result<(), String> {
    if value.len() > 512
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'"' | b'\'' | b'\\'))
    {
        return Err("invalid image_tag".to_string());
    }
    Ok(())
}

fn validate_label(value: &str, label: &str) -> Result<(), String> {
    if value.len() > 256
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'/' | b'\\' | b'"' | b'\''))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_swarm_stack_name(value: &str) -> Result<(), String> {
    validate_slug_like(value, "swarm stack name", 64, false)
}

fn validate_slug(value: &str) -> Result<(), String> {
    validate_slug_like(value, "slug", 64, true)
}

fn validate_slug_like(
    value: &str,
    label: &str,
    max_len: usize,
    allow_dot: bool,
) -> Result<(), String> {
    if value.is_empty() || value == "." || value == ".." || value.len() > max_len {
        return Err(format!("invalid {label} {value:?}"));
    }
    let mut chars = value.chars();
    if !chars
        .next()
        .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        return Err(format!("invalid {label} {value:?}"));
    }
    for ch in chars {
        let allowed = ch.is_ascii_lowercase()
            || ch.is_ascii_digit()
            || ch == '_'
            || ch == '-'
            || (allow_dot && ch == '.');
        if !allowed {
            return Err(format!("invalid {label} {value:?}"));
        }
    }
    if value.contains("..") || value.contains('/') || value.contains('\\') {
        return Err(format!("invalid {label} {value:?}"));
    }
    Ok(())
}

fn validate_docker_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'/' | b'\\' | b'"' | b'\'' | b'$' | b'`'))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_domain(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'/' | b'\\' | b'"' | b'\'' | b'$' | b'`'))
    {
        return Err("invalid domain".to_string());
    }
    Ok(())
}

fn validate_resolve_image(value: &str) -> Result<(), String> {
    if value.is_empty() || matches!(value, "always" | "changed" | "never") {
        Ok(())
    } else {
        Err("resolve_image must be one of: always, changed, never".to_string())
    }
}

fn validate_swarm_payload_size(
    compose_content: &str,
    extra_files: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut total = compose_content.len();
    if total > MAX_COMPOSE_CONTENT_BYTES {
        return Err(format!(
            "compose_content exceeds {MAX_COMPOSE_CONTENT_BYTES} bytes"
        ));
    }
    if extra_files.len() > MAX_SWARM_EXTRA_FILES {
        return Err(format!("extra_files exceeds {MAX_SWARM_EXTRA_FILES} files"));
    }
    for (path, content) in extra_files {
        let len = content.len();
        if len > MAX_SWARM_EXTRA_FILE_BYTES {
            return Err(format!(
                "swarm extra file {path} exceeds {MAX_SWARM_EXTRA_FILE_BYTES} bytes"
            ));
        }
        total += len;
        if total > MAX_SWARM_STACK_PAYLOAD_BYTES {
            return Err(format!(
                "swarm stack payload exceeds {MAX_SWARM_STACK_PAYLOAD_BYTES} bytes"
            ));
        }
    }
    Ok(())
}

fn parse_swarm_stack_payload(payload: &[u8]) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        stack_name: String,
    }

    let payload: Payload = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    validate_swarm_stack_name(&payload.stack_name)?;
    Ok(payload.stack_name)
}

pub fn validate_swarm_compose_content(content: &str) -> Result<(), String> {
    validate_compose_content(content, false)
}

pub fn validate_compose_up_content(content: &str) -> Result<(), String> {
    validate_compose_content(content, true)
}

fn validate_compose_content(content: &str, allow_relative_file_mounts: bool) -> Result<(), String> {
    if !content.lines().any(|line| line.trim() == "services:") {
        return Err("swarm stack yaml must declare services".to_string());
    }
    let forbidden = [
        "build",
        "cap_add",
        "cap_drop",
        "cgroup_parent",
        "credential_spec",
        "device_cgroup_rules",
        "devices",
        "env_file",
        "extends",
        "ipc",
        "label_file",
        "network_mode",
        "pid",
        "privileged",
        "security_opt",
        "sysctls",
        "userns_mode",
    ];
    for line in content.lines() {
        let trimmed = line.trim();
        for key in forbidden {
            if trimmed == format!("{key}:") || trimmed.starts_with(&format!("{key}: ")) {
                return Err(format!("swarm stack field {key:?} is not allowed"));
            }
        }
        if compose_line_uses_host_path_volume(trimmed, allow_relative_file_mounts)
            || trimmed == "type: bind"
            || trimmed.starts_with("type: bind ")
        {
            return Err("swarm stack volume uses a host path; use a named volume".to_string());
        }
    }
    Ok(())
}

fn compose_line_uses_host_path_volume(trimmed: &str, allow_relative_file_mounts: bool) -> bool {
    let Some(item) = trimmed.strip_prefix("- ") else {
        return false;
    };
    let Some((source, _target)) = item.split_once(':') else {
        return false;
    };
    source.starts_with('/')
        || source.starts_with("../")
        || (source.starts_with("./") && !allow_relative_file_mounts)
}

fn validate_extra_file_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() || value.contains('\\') {
        return Err(format!("invalid swarm extra file path {value}"));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(format!("invalid swarm extra file path {value}"));
        }
    }
    Ok(())
}

fn swarm_service_name(stack_name: &str, service_name: &str) -> Result<String, String> {
    validate_swarm_stack_name(stack_name)?;
    validate_swarm_stack_name(service_name)?;
    let prefix = format!("{stack_name}_");
    if service_name.starts_with(&prefix) {
        return Ok(service_name.to_string());
    }
    if service_name.contains('_') {
        return Err(format!(
            "swarm service {service_name:?} is outside stack {stack_name:?}"
        ));
    }
    Ok(format!("{prefix}{service_name}"))
}

fn nonzero_or(value: u64, default: u64) -> u64 {
    if value == 0 {
        default
    } else {
        value
    }
}

fn bounded_timeout(value: u64, default: u64, label: &str) -> Result<u64, String> {
    let value = nonzero_or(value, default);
    if value > MAX_CI_TIMEOUT_SECONDS {
        return Err(format!("{label} exceeds {MAX_CI_TIMEOUT_SECONDS}"));
    }
    Ok(value)
}

fn empty_to_none(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn strings<const N: usize>(items: [&str; N]) -> Vec<String> {
    items.into_iter().map(ToOwned::to_owned).collect()
}

#[cfg(test)]
mod ci_service_runtime_tests {
    use super::*;

    #[test]
    fn command_file_outputs_allow_github_action_output_names() {
        let root =
            std::env::temp_dir().join(format!("permanu-command-files-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp command files dir");
        let files = CommandFiles {
            env: root.join("env"),
            output: root.join("output"),
            path: root.join("path"),
            state: root.join("state"),
            summary: root.join("summary"),
            container_env: root.join("container-env"),
        };
        fs::write(&files.env, b"VALID_ENV=value\n").expect("write env");
        fs::write(&files.output, b"node-version=24\ncache-hit=false\n").expect("write output");
        fs::write(&files.path, b"").expect("write path");
        fs::write(&files.summary, b"").expect("write summary");

        let updates = read_command_file_updates(&files).expect("read command files");

        assert_eq!(
            updates.output.get("node-version").map(String::as_str),
            Some("24")
        );
        assert_eq!(
            updates.output.get("cache-hit").map(String::as_str),
            Some("false")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn action_input_values_include_metadata_defaults() {
        let action: CompositeAction = serde_yaml::from_str(
            r#"name: defaults
inputs:
  check-latest:
    default: false
  architecture:
    default: x64
runs:
  using: node20
  main: index.js
"#,
        )
        .expect("parse action metadata");
        let step = CiStep {
            step_db_id: "s1".to_string(),
            step_index: 0,
            name: "setup".to_string(),
            run: String::new(),
            uses: "./action".to_string(),
            with: BTreeMap::from([("architecture".to_string(), "arm64".to_string())]),
            shell: String::new(),
            working_dir: String::new(),
            env: BTreeMap::new(),
            continue_on_error: false,
            timeout_minutes: 0,
            if_expr: String::new(),
            argv: Vec::new(),
        };

        let inputs = action_input_values(&action, &step);

        assert_eq!(
            inputs.get("check-latest").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            inputs.get("architecture").map(String::as_str),
            Some("arm64")
        );
        assert_eq!(
            composite_input_env_key("python-version").as_deref(),
            Some("INPUT_PYTHON_VERSION")
        );
        assert_eq!(
            github_action_input_env_key("python-version").as_deref(),
            Some("INPUT_PYTHON-VERSION")
        );
    }

    #[test]
    fn command_path_updates_map_container_workspace_to_host_checkout() {
        let mut env = BTreeMap::from([("PATH".to_string(), "/usr/bin".to_string())]);
        let updates = CommandFileUpdates {
            path_entries: vec!["/permanu-ci/runner-tool-cache/node/22/bin".to_string()],
            ..CommandFileUpdates::default()
        };

        apply_command_updates(&mut env, updates, "/var/tmp/permanu-ci/run/job/workspace");

        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some("/var/tmp/permanu-ci/run/job/runner-tool-cache/node/22/bin:/usr/bin")
        );
    }

    #[test]
    fn service_volumes_accept_anonymous_and_rewrite_named_to_per_job_volume() {
        let volumes = vec![
            "/var/lib/postgresql/data".to_string(),
            "pgdata:/data:ro".to_string(),
        ];

        let parsed = parse_ci_service_volumes("permanu-ci-job", "postgres", &volumes)
            .expect("parse service volumes");

        assert_eq!(
            parsed,
            vec![
                "/var/lib/postgresql/data".to_string(),
                "permanu-ci-job-postgres-vol-1:/data:ro".to_string()
            ]
        );
    }

    #[test]
    fn service_volumes_reject_host_paths() {
        let err = parse_ci_service_volumes(
            "permanu-ci-job",
            "postgres",
            &["./data:/var/lib/postgresql/data".to_string()],
        )
        .unwrap_err();

        assert!(err.contains("not a host path"), "{err}");
    }

    #[test]
    fn service_options_accept_health_flags_without_shell() {
        let parsed =
            parse_ci_service_options("--health-cmd 'pg_isready -U postgres' --health-retries=5")
                .expect("parse health options");

        assert_eq!(
            parsed,
            vec![
                "--health-cmd".to_string(),
                "pg_isready -U postgres".to_string(),
                "--health-retries".to_string(),
                "5".to_string()
            ]
        );
    }

    #[test]
    fn service_options_reject_non_health_and_shell_syntax() {
        let err = parse_ci_service_options("--privileged").unwrap_err();
        assert!(err.contains("unsupported service option"), "{err}");

        let err = parse_ci_service_options("--health-cmd 'pg_isready || exit 1'").unwrap_err();
        assert!(err.contains("unsupported shell syntax"), "{err}");
    }

    #[test]
    fn swarm_compose_validation_allows_named_volumes_and_urls() {
        let compose = r#"
services:
  postgresql:
    image: postgres:16-alpine
    volumes:
      - postgresql_data:/var/lib/postgresql/data
    environment:
      DATA_SOURCE_NAME: "postgresql://app:secret@postgresql:5432/app?sslmode=disable"
volumes:
  postgresql_data:
"#;

        validate_swarm_compose_content(compose).expect("named volumes and URLs are valid");
    }

    #[test]
    fn swarm_compose_validation_rejects_host_path_volumes() {
        let compose = r#"
services:
  postgresql:
    image: postgres:16-alpine
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
"#;

        let err = validate_swarm_compose_content(compose)
            .expect_err("host path volumes must be rejected");

        assert!(err.contains("host path"), "{err}");
    }

    #[test]
    fn compose_up_validation_allows_relative_extra_file_mounts() {
        let compose = r#"
services:
  postgresql:
    image: postgres:16-alpine
    volumes:
      - postgresql_data:/var/lib/postgresql/data
      - ./init-pg-stat-statements.sql:/docker-entrypoint-initdb.d/01-pg-stat-statements.sql:ro
"#;

        validate_compose_up_content(compose)
            .expect("relative extra-file mounts are valid for compose up");
        assert!(
            validate_swarm_compose_content(compose).is_err(),
            "swarm stack deploy must stay stricter than compose up"
        );
    }

    #[test]
    fn compose_validation_allows_command_items_and_anonymous_container_volumes() {
        let compose = r#"
services:
  worker:
    image: alpine:3.20
    command:
      - /bin/sh
      - -c
      - echo ok
    volumes:
      - /var/lib/postgresql/data
"#;

        validate_swarm_compose_content(compose)
            .expect("command list items and anonymous container volumes are not host binds");
    }
}

#[cfg(test)]
mod ci_cancellation_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn wait_for_child_output_terminates_process_group_on_cancel_signal() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut command = StdCommand::new("sh");
        command
            .args(["-c", "trap 'exit 0' TERM; while true; do sleep 1; done"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        prepare_process_group(&mut command);
        let mut child = command.spawn().expect("spawn cancellable shell");

        cancelled.store(true, Ordering::SeqCst);
        let err = wait_for_child_output(&mut child, Duration::from_secs(30), &cancelled, None)
            .expect_err("cancelled child should return an error");

        assert!(err.contains("cancelled"));
        assert!(child.try_wait().expect("child wait state").is_some());
    }

    #[test]
    fn ci_step_log_entry_carries_step_sequence_and_stream() {
        let entry = ci_step_log_entry(
            "run-1",
            "job-1",
            "22222222-2222-2222-2222-222222222222",
            7,
            "stderr",
            "secret-free line".to_string(),
        );

        assert_eq!(entry.source, "ci");
        assert_eq!(entry.level, "error");
        assert_eq!(entry.message, "secret-free line");
        assert_eq!(
            entry.fields.get("ci_run_id").map(String::as_str),
            Some("run-1")
        );
        assert_eq!(
            entry.fields.get("ci_job_id").map(String::as_str),
            Some("job-1")
        );
        assert_eq!(
            entry.fields.get("ci_step_id").map(String::as_str),
            Some("22222222-2222-2222-2222-222222222222")
        );
        assert_eq!(
            entry.fields.get("ci_sequence").map(String::as_str),
            Some("7")
        );
        assert_eq!(
            entry.fields.get("ci_stream").map(String::as_str),
            Some("stderr")
        );
    }
}
