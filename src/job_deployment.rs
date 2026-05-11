#![allow(dead_code)]

use std::{
    cmp::Reverse,
    collections::BTreeMap,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Child, Command as StdCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use tokio::{process::Command, time::timeout};

const DEFAULT_HOOK_TIMEOUT_SECONDS: u64 = 120;
const DEFAULT_RELEASE_HOOK_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_CI_JOB_TIMEOUT_SECONDS: u64 = 60 * 60;
const MAX_CI_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_CI_STEPS: usize = 128;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_COMPOSE_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_SWARM_EXTRA_FILES: usize = 64;
const MAX_SWARM_EXTRA_FILE_BYTES: usize = 1024 * 1024;
const MAX_SWARM_STACK_PAYLOAD_BYTES: usize = 5 * 1024 * 1024;
const SWARM_STACK_FILE_NAME: &str = "stack.yaml";
const DEPLOYMENT_BASE_DIR: &str = "/opt/permanu-agent/deployments";

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
    pub timeout_seconds: u64,
    pub clone_dir: String,
    pub env: BTreeMap<String, String>,
    pub matrix_values: BTreeMap<String, String>,
    pub secret_keys: Vec<String>,
    pub steps: Vec<CiStep>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiStep {
    pub step_db_id: String,
    pub step_index: u32,
    pub name: String,
    pub run: String,
    pub shell: String,
    pub working_dir: String,
    pub env: BTreeMap<String, String>,
    pub continue_on_error: bool,
    pub timeout_minutes: u32,
    argv: Vec<String>,
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
        clone_dir: String,
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
    validate_env(&payload.env)?;
    validate_env(&payload.matrix_values)?;
    for key in &payload.secret_keys {
        validate_env_key(key)?;
    }
    if payload.steps.is_empty() {
        return Err("ci job: at least one run step is required".to_string());
    }
    if payload.steps.len() > MAX_CI_STEPS {
        return Err(format!("ci job: steps exceeds {MAX_CI_STEPS}"));
    }
    let timeout_seconds = bounded_timeout(
        payload.timeout_seconds,
        DEFAULT_CI_JOB_TIMEOUT_SECONDS,
        "timeout_seconds",
    )?;
    let clone_dir = normalize_work_dir(&payload.clone_dir)?;
    let mut steps = Vec::with_capacity(payload.steps.len());
    for step in payload.steps {
        steps.push(parse_ci_step(step)?);
    }
    Ok(CiJobPlan {
        job_db_id: job_db_id.to_string(),
        job_id_yaml: payload.job_id_yaml.trim().to_string(),
        timeout_seconds,
        clone_dir,
        env: payload.env,
        matrix_values: payload.matrix_values,
        secret_keys: payload.secret_keys,
        steps,
    })
}

pub fn handle_ci_job(command_id: &str, payload: &[u8]) -> AgentCommandResult {
    match parse_ci_job(payload) {
        Ok(plan) => execute_ci_job(command_id, &plan),
        Err(err) => {
            AgentCommandResult::failed(command_id, format!("invalid CI job payload: {err}"))
        }
    }
}

fn parse_ci_step(step: CiStepPayload) -> Result<CiStep, String> {
    if !step.step_db_id.trim().is_empty() {
        validate_label(step.step_db_id.trim(), "step_db_id")?;
    }
    if !step.uses.trim().is_empty() && step.run.trim().is_empty() {
        return Err("ci job: uses steps are not supported by the Rust CI runner".to_string());
    }
    let run = step.run.trim();
    if run.is_empty() {
        return Err("ci job: run step command is required".to_string());
    }
    if run.len() > 64 * 1024 || run.as_bytes().contains(&0) {
        return Err("ci job: invalid run command".to_string());
    }
    validate_env(&step.env)?;
    let shell = step.shell.trim().to_ascii_lowercase();
    validate_ci_shell(&shell)?;
    let argv = if shell.is_empty() {
        parse_command_argv(run)?
    } else {
        Vec::new()
    };
    if step.timeout_minutes > 24 * 60 {
        return Err("ci job: step timeout_minutes exceeds 1440".to_string());
    }
    Ok(CiStep {
        step_db_id: step.step_db_id.trim().to_string(),
        step_index: step.step_index,
        name: step.name.trim().to_string(),
        run: run.to_string(),
        shell,
        working_dir: step.working_dir.trim().to_string(),
        env: step.env,
        continue_on_error: step.continue_on_error,
        timeout_minutes: step.timeout_minutes,
        argv,
    })
}

fn validate_ci_shell(shell: &str) -> Result<(), String> {
    match shell {
        "" | "sh" | "bash" => Ok(()),
        _ => Err("ci job: shell must be empty, sh, or bash".to_string()),
    }
}

fn execute_ci_job(command_id: &str, plan: &CiJobPlan) -> AgentCommandResult {
    let mut log = String::new();
    append_capped(
        &mut log,
        &format!("starting CI job {}\n", display_ci_job_name(plan)),
    );
    let mut failed_step_index = None;
    let mut statuses = BTreeMap::new();
    for step in &plan.steps {
        let step_id = step.step_id();
        let label = display_ci_step_name(step);
        let env = merged_ci_env(plan, step);
        let redactor = SecretRedactor::from_env(&env, &plan.secret_keys);
        append_capped(&mut log, &format!("[{label}] starting\n"));
        match run_ci_step(plan, step, &env) {
            Ok(process) if process.status_success => {
                append_capped(&mut log, &redactor.redact(&process.output));
                if !process.output.is_empty() {
                    append_capped(&mut log, "\n");
                }
                append_capped(&mut log, &format!("[{label}] completed successfully\n"));
                statuses.insert(step_id, "success".to_string());
            }
            Ok(process) => {
                append_capped(&mut log, &redactor.redact(&process.output));
                if !process.output.is_empty() {
                    append_capped(&mut log, "\n");
                }
                append_capped(&mut log, &format!("[{label}] failed\n"));
                statuses.insert(step_id, "failure".to_string());
                if !step.continue_on_error {
                    failed_step_index = Some(step.step_index);
                    break;
                }
                append_capped(&mut log, &format!("[{label}] continuing on error\n"));
            }
            Err(err) => {
                append_capped(&mut log, &redactor.redact(&format!("[{label}] {err}\n")));
                statuses.insert(step_id, "failure".to_string());
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
    if let Some(index) = failed_step_index {
        append_capped(&mut log, &format!("ci job failed at step {index}"));
        AgentCommandResult::failed(command_id, log.trim())
    } else {
        append_capped(&mut log, "ci job completed");
        AgentCommandResult::completed(command_id, log.trim())
    }
}

fn run_ci_step(
    plan: &CiJobPlan,
    step: &CiStep,
    env: &BTreeMap<String, String>,
) -> Result<ProcessOutput, String> {
    let work_dir = resolve_ci_work_dir(&plan.clone_dir, &step.working_dir)?;
    let timeout_seconds = if step.timeout_minutes > 0 {
        u64::from(step.timeout_minutes) * 60
    } else {
        plan.timeout_seconds
    };
    let mut command = if step.shell.is_empty() {
        let Some((program, args)) = step.argv.split_first() else {
            return Err("empty run step command".to_string());
        };
        let mut command = StdCommand::new(program);
        command.args(args);
        command
    } else {
        ci_shell_command(step)
    };
    command
        .current_dir(work_dir)
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepare_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|err| format!("start ci step: {err}"))?;
    wait_for_child_output(&mut child, Duration::from_secs(timeout_seconds))
}

fn ci_shell_command(step: &CiStep) -> StdCommand {
    match step.shell.as_str() {
        "bash" => {
            let mut command = StdCommand::new("bash");
            command.args([
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                "-c",
                step.run.as_str(),
            ]);
            command
        }
        _ => {
            let mut command = StdCommand::new("sh");
            command.args(["-e", "-c", step.run.as_str()]);
            command
        }
    }
}

fn wait_for_child_output(child: &mut Child, deadline: Duration) -> Result<ProcessOutput, String> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = stdout.map(read_capped_pipe);
    let stderr_reader = stderr.map(read_capped_pipe);
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
            });
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
) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut truncated = false;
        let mut buf = [0_u8; 8192];
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
                }
                Err(_) => break,
            }
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
    thread::sleep(Duration::from_millis(100));
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

fn resolve_ci_work_dir(clone_dir: &str, working_dir: &str) -> Result<PathBuf, String> {
    let base = PathBuf::from(normalize_work_dir(clone_dir)?);
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
        return Ok(path.to_path_buf());
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("working_dir must stay inside clone_dir".to_string());
        }
    }
    Ok(base.join(path))
}

fn merged_ci_env(plan: &CiJobPlan, step: &CiStep) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    env.extend(plan.env.clone());
    env.extend(plan.matrix_values.clone());
    env.extend(step.env.clone());
    env.insert("GITHUB_WORKSPACE".to_string(), plan.clone_dir.clone());
    env.insert("CI_JOB_ID".to_string(), plan.job_db_id.clone());
    if !plan.job_id_yaml.is_empty() {
        env.insert("CI_JOB_NAME".to_string(), plan.job_id_yaml.clone());
    }
    env
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

struct SecretRedactor {
    values: Vec<String>,
    b64_values: Vec<String>,
}

impl SecretRedactor {
    fn from_env(env: &BTreeMap<String, String>, secret_keys: &[String]) -> Self {
        let mut values = Vec::new();
        for key in secret_keys {
            if let Some(value) = env.get(key) {
                if !value.is_empty() && !values.contains(value) {
                    values.push(value.clone());
                }
            }
        }
        values.sort_by_key(|value| Reverse(value.len()));
        let b64_values = values
            .iter()
            .map(|value| general_purpose::STANDARD.encode(value.as_bytes()))
            .collect();
        Self { values, b64_values }
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

fn validate_swarm_compose_content(content: &str) -> Result<(), String> {
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
        let without_list_marker = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if without_list_marker.starts_with('/')
            || without_list_marker.starts_with("./")
            || without_list_marker.starts_with("../")
            || without_list_marker.contains(":/")
            || trimmed == "type: bind"
            || trimmed.starts_with("type: bind ")
        {
            return Err("swarm stack volume uses a host path; use a named volume".to_string());
        }
    }
    Ok(())
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
