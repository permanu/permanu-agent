mod log_forwarder {
    use crate::proto::agent::v1::LogEntry;

    pub struct LogForwarder;

    impl LogForwarder {
        pub fn push(&self, _entry: LogEntry) -> Result<(), String> {
            Ok(())
        }
    }
}

mod proto {
    pub mod agent {
        pub mod v1 {
            use std::collections::HashMap;

            #[allow(dead_code)]
            #[derive(Clone, Debug, Default)]
            pub struct LogEntry {
                pub timestamp_ns: i64,
                pub source: String,
                pub level: String,
                pub message: String,
                pub fields: HashMap<String, String>,
                pub app_id: String,
                pub deployment_id: String,
            }
        }
    }
}

mod timeutil {
    pub fn now_unix_nanos() -> i64 {
        1
    }
}

#[path = "../src/job_deployment.rs"]
mod job_deployment;

use std::sync::Mutex;
use std::{collections::BTreeMap, fs, io::Write, net::TcpListener, thread};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use job_deployment::{
    build_ci_container_invocation, build_release_hook_invocations, build_swarm_deploy_args,
    build_swarm_remove_args, build_swarm_rollback_args, build_swarm_status_args,
    parse_app_proxy_remove, parse_app_proxy_setup, parse_ci_job, parse_run_hooks,
    parse_swarm_deploy, parse_swarm_remove, parse_swarm_rollback, parse_swarm_status,
    render_app_proxy_snippet, run_invocation, swarm_stack_dir, AgentCommandResult,
    CommandInvocation,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, original }
    }

    fn remove(key: &'static str) -> Self {
        let original = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

#[test]
fn run_hooks_rejects_shell_metacharacters() {
    let err = parse_run_hooks(
        br#"{"hook_event":"pre_deploy","commands":["echo ok; rm -rf /"],"clone_dir":"/tmp/app","env_vars":{"SAFE_KEY":"value"}}"#,
    )
    .unwrap_err();

    assert!(err.contains("unsupported shell syntax"));
}

#[test]
fn run_hooks_parses_safe_argv_and_env() {
    let plan = parse_run_hooks(
        br#"{"hook_event":"pre_deploy","commands":["bundle exec rake db:migrate"],"clone_dir":"/tmp/app","timeout_sec":30,"env_vars":{"RAILS_ENV":"production"}}"#,
    )
    .expect("parse hooks");

    assert_eq!(plan.hook_event, "pre_deploy");
    assert_eq!(plan.timeout_seconds, 30);
    assert_eq!(plan.work_dir, "/tmp/app");
    assert_eq!(
        plan.commands[0].argv,
        vec!["bundle", "exec", "rake", "db:migrate"]
    );
    assert_eq!(
        plan.env.get("RAILS_ENV").map(String::as_str),
        Some("production")
    );
}

#[test]
fn release_hook_builds_docker_run_without_shell() {
    let invocations = build_release_hook_invocations(
        br#"{"image_tag":"registry.example.com/app:sha","commands":["rails db:migrate"],"timeout_sec":90,"env_vars":{"RAILS_ENV":"production"}}"#,
    )
    .expect("build release hook");

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].program, "docker");
    assert_eq!(
        invocations[0].args,
        vec![
            "run",
            "--rm",
            "--network",
            "none",
            "--env",
            "RAILS_ENV=production",
            "registry.example.com/app:sha",
            "rails",
            "db:migrate"
        ]
    );
    assert_eq!(invocations[0].timeout_seconds, 90);
}

#[test]
fn ci_job_requires_job_db_id() {
    let err = parse_ci_job(br#"{"job_id_yaml":"build"}"#).unwrap_err();
    assert!(err.contains("job_db_id is required"));

    let result =
        job_deployment::handle_ci_job("cmd-2", br#"{"job_db_id":"job-1","timeout_seconds":0}"#);
    assert_eq!(result.status, "failed");
    assert!(String::from_utf8(result.output)
        .unwrap()
        .contains("at least one run step"));
}

#[test]
fn ci_job_parses_run_steps_and_merges_env() {
    let job = parse_ci_job(
        br#"{"job_db_id":"job-1","job_id_yaml":"build","timeout_seconds":5,"env":{"BASE":"job"},"matrix_values":{"TARGET":"linux"},"steps":[{"step_db_id":"s1","step_index":0,"name":"show env","run":"printf ok","env":{"BASE":"step"}}]}"#,
    )
    .expect("parse ci job");

    assert_eq!(job.job_db_id, "job-1");
    assert_eq!(job.job_id_yaml, "build");
    assert_eq!(job.clone_dir, "/var/tmp/permanu-ci/adhoc/job-1/workspace");
    assert_eq!(job.timeout_seconds, 5);
    assert_eq!(job.steps.len(), 1);
    assert_eq!(job.steps[0].step_id(), "s1");
    assert_eq!(job.steps[0].run, "printf ok");
    assert_eq!(job.env.get("BASE").map(String::as_str), Some("job"));
    assert_eq!(
        job.matrix_values.get("TARGET").map(String::as_str),
        Some("linux")
    );
    assert_eq!(
        job.steps[0].env.get("BASE").map(String::as_str),
        Some("step")
    );
}

#[test]
fn ci_job_accepts_github_matrix_keys_that_are_not_env_keys() {
    let result = job_deployment::handle_ci_job(
        "cmd-1",
        br#"{"job_db_id":"job-1","job_id_yaml":"test","run_db_id":"run-1","timeout_seconds":5,"matrix_values":{"go-version":"1.26","TARGET":"linux"},"steps":[{"step_db_id":"s1","step_index":0,"name":"matrix env","shell":"sh","run":"if env | grep '^go-version='; then exit 11; fi\n[ \"$TARGET\" = \"linux\" ] && printf ok"}]}"#,
    );

    let output = String::from_utf8(result.output).expect("utf8 output");
    assert_eq!(result.status, "completed", "{output}");
    assert!(output.contains("ok"), "{output}");
}

#[test]
fn ci_job_defaults_run_steps_to_shell_execution() {
    let workspace = managed_tempfile_like_dir("ci-default-shell");
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"default shell","run":"printf one && printf two"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let log = output["log"].as_str().expect("human log");

    assert_eq!(result.status, "completed", "{output}");
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert!(log.contains("onetwo"), "{log}");
}

#[test]
fn ci_job_accepts_large_marketplace_action_bundle_files() {
    let large_dist = "console.log('setup action');\n".repeat(130_000);
    assert!(
        large_dist.len() > 2 * 1024 * 1024,
        "test fixture must exceed the previous 2 MiB runner limit"
    );
    assert!(
        large_dist.len() < 8 * 1024 * 1024,
        "test fixture must remain below the scheduler and runner limit"
    );

    let payload = serde_json::json!({
        "job_db_id": "job-1",
        "timeout_seconds": 5,
        "action_bundles": [{
            "uses": "actions/setup-python@v5",
            "local_path": "./.permanu/action-bundles/setup-python-v5",
            "action_filename": "action.yml",
            "action_yml": "name: setup-python\nruns:\n  using: node20\n  main: dist/cache-save/index.js\n",
            "files": {
                "dist/cache-save/index.js": large_dist
            }
        }],
        "steps": [{
            "step_db_id": "s1",
            "step_index": 0,
            "name": "setup python",
            "uses": "./.permanu/action-bundles/setup-python-v5"
        }]
    });
    let raw = serde_json::to_vec(&payload).expect("serialize ci payload");

    parse_ci_job(&raw).expect("large action bundle should parse");
}

#[test]
fn ci_job_parses_container_and_builds_fixed_docker_argv() {
    let workspace = managed_tempfile_like_dir("ci-container-plan");
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"container":{{"image":"golang:1.26-bookworm","env":{{"GOFLAGS":"-mod=mod"}}}},"env":{{"BASE":"job"}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"test","shell":"bash","run":"go test ./...","env":{{"STEP":"one"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );
    let job = parse_ci_job(payload.as_bytes()).expect("parse ci job");

    assert_eq!(
        job.container
            .as_ref()
            .map(|container| container.image.as_str()),
        Some("golang:1.26-bookworm")
    );
    let env = BTreeMap::from([
        (
            "PATH".to_string(),
            format!("{}/bin:/usr/bin:/bin", workspace.display()),
        ),
        (
            "GITHUB_WORKSPACE".to_string(),
            workspace.to_string_lossy().to_string(),
        ),
        ("SECRET_TOKEN".to_string(), "super-secret".to_string()),
    ]);
    let invocation =
        build_ci_container_invocation(&job, &job.steps[0], &env).expect("container invocation");

    assert_eq!(invocation.program, "docker");
    assert_eq!(invocation.work_dir.as_deref(), Some(job.clone_dir.as_str()));
    assert_eq!(invocation.timeout_seconds, job.timeout_seconds);
    let volume_arg = format!("{}:/workspace", job.clone_dir);
    let expected_args: Vec<String> = vec![
        "run",
        "--rm",
        "--network",
        "bridge",
        "--workdir",
        "/workspace",
        "--volume",
        volume_arg.as_str(),
        "--env-file",
        "/workspace/.permanu-ci/container-env",
        "--entrypoint",
        "bash",
        "golang:1.26-bookworm",
        "--noprofile",
        "--norc",
        "-eo",
        "pipefail",
        "-c",
        "go test ./...",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(invocation.args, expected_args);
    assert_eq!(
        invocation.env.get("GITHUB_WORKSPACE").map(String::as_str),
        Some("/workspace")
    );
    assert_eq!(
        invocation.env.get("GOFLAGS").map(String::as_str),
        Some("-mod=mod")
    );
    assert_eq!(
        invocation.env.get("SECRET_TOKEN").map(String::as_str),
        Some("super-secret")
    );
    assert!(!invocation.host_env.contains_key("SECRET_TOKEN"));
    assert!(!invocation.host_env.contains_key("DOCKER_HOST"));
    assert!(!invocation.host_env.contains_key("DOCKER_CONTEXT"));
    assert!(!invocation.host_env.contains_key("DOCKER_CONFIG"));
    assert!(!invocation
        .args
        .iter()
        .any(|arg| arg.contains("super-secret")));
    assert_eq!(
        invocation.env.get("PATH").map(String::as_str),
        Some("/workspace/bin:/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    );
}

#[test]
fn ci_job_untrusted_sandbox_policy_hardens_container_argv() {
    let workspace = managed_tempfile_like_dir("ci-untrusted-container-plan");
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"sandbox_policy":"untrusted","container":{{"image":"golang:1.26-bookworm"}},"steps":[{{"step_db_id":"s1","step_index":0,"shell":"bash","run":"go test ./..."}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );
    let job = parse_ci_job(payload.as_bytes()).expect("parse ci job");
    let invocation = build_ci_container_invocation(&job, &job.steps[0], &BTreeMap::new())
        .expect("container invocation");

    assert_eq!(job.sandbox_policy.as_deref(), Some("untrusted"));
    for expected in [
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "256",
    ] {
        assert!(
            invocation.args.iter().any(|arg| arg == expected),
            "missing docker arg {expected:?} in {:?}",
            invocation.args
        );
    }
}

#[test]
fn ci_job_parses_services_and_runs_container_on_job_network() {
    let workspace = managed_tempfile_like_dir("ci-service-plan");
    let payload = format!(
        r#"{{"job_db_id":"job_Prod.1","clone_dir":{},"container":{{"image":"golang:1.26-bookworm"}},"services":{{"Postgres DB":{{"image":"postgres:16","ports":["5432:5432"],"env":{{"POSTGRES_PASSWORD":"postgres"}}}}}},"steps":[{{"step_db_id":"s1","step_index":0,"run":"go test ./..."}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );
    let job = parse_ci_job(payload.as_bytes()).expect("parse ci job with services");

    assert_eq!(job.services.len(), 1);
    let service = job.services.get("Postgres DB").expect("postgres service");
    assert_eq!(service.image, "postgres:16");
    assert_eq!(
        service.env.get("POSTGRES_PASSWORD").map(String::as_str),
        Some("postgres")
    );
    assert_eq!(service.ports, ["5432:5432"]);
    assert_eq!(service.container_name, "permanu-ci-job-prod-1-postgres-db");
    assert_eq!(service.network_alias, "postgres-db");
    assert_eq!(
        job.service_network_name().as_deref(),
        Some("permanu-ci-job-prod-1")
    );

    let invocation = build_ci_container_invocation(&job, &job.steps[0], &BTreeMap::new())
        .expect("container invocation");
    assert_eq!(invocation.args[2], "--network");
    assert_eq!(invocation.args[3], "permanu-ci-job-prod-1");
}

#[test]
fn ci_job_parses_safe_service_resource_options_and_volume_modes() {
    let payload = br#"{"job_db_id":"job-1","container":{"image":"golang:1.26-bookworm"},"services":{"postgres":{"image":"postgres:16","volumes":["pgdata:/var/lib/postgresql/data:ro","scratch:/scratch:rw"],"options":"--health-cmd \"pg_isready -U postgres\" --cpus 1.5 --memory=1g --shm-size 256m"}},"steps":[{"step_db_id":"s1","step_index":0,"run":"go test ./..."}]}"#;
    let job = parse_ci_job(payload).expect("parse ci job");
    let service = job.services.get("postgres").expect("postgres service");

    assert_eq!(
        service.volumes,
        [
            "permanu-ci-job-1-postgres-vol-0:/var/lib/postgresql/data:ro",
            "permanu-ci-job-1-postgres-vol-1:/scratch:rw"
        ]
    );
    assert_eq!(
        service.options,
        [
            "--health-cmd",
            "pg_isready -U postgres",
            "--cpus",
            "1.5",
            "--memory",
            "1g",
            "--shm-size",
            "256m"
        ]
    );
}

#[test]
fn ci_job_rejects_unsupported_container_runtime_shape() {
    for (name, payload, want) in [
        (
            "options",
            br#"{"job_db_id":"job-1","container":{"image":"golang:1.26-bookworm","options":"--network host"},"steps":[{"step_db_id":"s1","step_index":0,"run":"go test ./..."}]}"#.as_slice(),
            "container options are not supported",
        ),
        (
            "ports",
            br#"{"job_db_id":"job-1","container":{"image":"golang:1.26-bookworm","ports":["5432:5432"]},"steps":[{"step_db_id":"s1","step_index":0,"run":"go test ./..."}]}"#.as_slice(),
            "container ports are not supported",
        ),
        (
            "volumes",
            br#"{"job_db_id":"job-1","container":{"image":"golang:1.26-bookworm","volumes":["/tmp:/tmp"]},"steps":[{"step_db_id":"s1","step_index":0,"run":"go test ./..."}]}"#.as_slice(),
            "container volumes are not supported",
        ),
    ] {
        let err = parse_ci_job(payload).unwrap_err();
        assert!(
            err.contains(want),
            "{name}: err = {err:?}, want substring {want:?}"
        );
    }
}

#[test]
fn ci_job_accepts_services_without_job_container_for_host_steps() {
    let payload = br#"{"job_db_id":"job-1","services":{"postgres":{"image":"postgres:16","ports":["5432:5432"],"options":"--health-cmd pg_isready --health-retries 5"}},"steps":[{"step_db_id":"s1","step_index":0,"run":"go test ./..."}]}"#;
    let plan = parse_ci_job(payload).expect("services without job container should parse");
    assert!(plan.container.is_none());
    let service = plan.services.get("postgres").expect("postgres service");
    assert_eq!(service.ports, ["5432:5432"]);
    assert_eq!(service.network_alias, "postgres");
}

#[cfg(unix)]
#[test]
fn ci_job_with_services_sequences_fake_docker_lifecycle_and_cleanup() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-service-runtime");
    let fake_bin = managed_tempfile_like_dir("ci-service-docker-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let payload = format!(
        r#"{{"job_db_id":"job_Prod.1","clone_dir":{},"timeout_seconds":5,"container":{{"image":"alpine:3.20"}},"services":{{"Postgres DB":{{"image":"postgres:16","ports":["5432:5432"],"env":{{"POSTGRES_PASSWORD":"postgres"}}}}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"test","shell":"sh","run":"printf ok"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    let entries: Vec<String> = fs::read_to_string(fake_log)
        .expect("fake docker log")
        .lines()
        .map(ToString::to_string)
        .collect();
    assert_eq!(entries.len(), 6, "{entries:#?}");
    assert_eq!(entries[0], "network create permanu-ci-job-prod-1");
    assert_eq!(
        entries[1],
        "run --detach --name permanu-ci-job-prod-1-postgres-db --network permanu-ci-job-prod-1 --network-alias postgres-db --env POSTGRES_PASSWORD=postgres postgres:16"
    );
    assert!(!entries[1].contains("--publish"));
    assert!(entries[2].starts_with("inspect --format "));
    assert!(entries[3].starts_with("run --rm --network permanu-ci-job-prod-1 --workdir /workspace"));
    assert_eq!(entries[4], "rm -fv permanu-ci-job-prod-1-postgres-db");
    assert_eq!(entries[5], "network rm permanu-ci-job-prod-1");
}

#[cfg(unix)]
#[test]
fn ci_job_with_service_credentials_logs_in_before_starting_service() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-service-credentials");
    let fake_bin = managed_tempfile_like_dir("ci-service-credentials-docker-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"container":{{"image":"alpine:3.20"}},"services":{{"private-db":{{"image":"ghcr.io/acme/postgres:16","credentials":{{"username":"robot","password":"secret-password"}}}}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"test","shell":"sh","run":"printf ok"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let entries = fs::read_to_string(fake_log).expect("fake docker log");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert!(
        entries.contains("login ghcr.io --username robot --password-stdin"),
        "{entries}"
    );
    assert!(
        entries.contains("run --detach --name permanu-ci-job-1-private-db"),
        "{entries}"
    );
    assert!(!entries.contains("secret-password"), "{entries}");
}

#[cfg(unix)]
#[test]
fn ci_job_with_service_credentials_uses_and_removes_isolated_docker_config() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-service-credential-cleanup");
    let fake_bin = managed_tempfile_like_dir("ci-service-credential-cleanup-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker_with_config_logging(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"container":{{"image":"alpine:3.20"}},"services":{{"private-db":{{"image":"ghcr.io/acme/postgres:16","credentials":{{"username":"robot","password":"secret-password"}}}}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"test","shell":"sh","run":"printf ok"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let entries: Vec<String> = fs::read_to_string(fake_log)
        .expect("fake docker log")
        .lines()
        .map(ToString::to_string)
        .collect();

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s1"], "success");
    let login_config = entries
        .iter()
        .find_map(|line| line.strip_prefix("DOCKER_CONFIG login "))
        .expect("login docker config");
    assert!(
        login_config.starts_with("/tmp/permanu-ci/docker-config/"),
        "{login_config}"
    );
    let run_config = entries
        .iter()
        .find_map(|line| line.strip_prefix("DOCKER_CONFIG run "))
        .expect("run docker config");
    assert_eq!(run_config, login_config);
    assert!(
        !std::path::Path::new(login_config).exists(),
        "isolated docker config should be removed after service cleanup"
    );
}

#[cfg(unix)]
#[test]
fn ci_job_executes_docker_image_action_in_ephemeral_container() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-docker-image-action");
    let fake_bin = managed_tempfile_like_dir("ci-docker-action-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"docker action","uses":"docker://alpine:3.20","with":{{"who-to-greet":"permanu","args":"hello world"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let entries = fs::read_to_string(fake_log).expect("fake docker log");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert!(entries.contains("run --rm --network bridge --workdir /workspace"));
    assert!(entries.contains("alpine:3.20 hello world"), "{entries}");
    assert!(output["log"]
        .as_str()
        .expect("human log")
        .contains("fake job output"));
}

#[cfg(unix)]
#[test]
fn ci_job_executes_local_javascript_action_in_ephemeral_node_container() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-local-js-action");
    let action_dir = workspace.join(".github/actions/js");
    fs::create_dir_all(&action_dir).expect("create action dir");
    fs::write(
        action_dir.join("action.yml"),
        r#"name: local-js
runs:
  using: node20
  main: index.js
"#,
    )
    .expect("write action metadata");
    fs::write(action_dir.join("index.js"), "console.log('hello');\n").expect("write action main");

    let fake_bin = managed_tempfile_like_dir("ci-local-js-action-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"local js action","uses":"./.github/actions/js","with":{{"node-version":"24","who-to-greet":"permanu"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let entries = fs::read_to_string(fake_log).expect("fake docker log");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert!(entries.contains("run --rm --network bridge --workdir /workspace"));
    assert!(
        entries.contains("node:20-bookworm node /workspace/.permanu-ci/s1/s1-action-wrapper.js"),
        "{entries}"
    );
    assert!(output["log"]
        .as_str()
        .expect("human log")
        .contains("fake job output"));
}

#[cfg(unix)]
#[test]
fn ci_job_executes_local_javascript_action_pre_main_and_post() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-local-js-action-hooks");
    let action_dir = workspace.join(".github/actions/js-hooks");
    fs::create_dir_all(&action_dir).expect("create action dir");
    fs::write(
        action_dir.join("action.yml"),
        r#"name: local-js-hooks
runs:
  using: node20
  pre: pre.js
  main: index.js
  post: post.js
"#,
    )
    .expect("write action metadata");
    fs::write(action_dir.join("pre.js"), "console.log('pre');\n").expect("write pre");
    fs::write(action_dir.join("index.js"), "console.log('main');\n").expect("write main");
    fs::write(action_dir.join("post.js"), "console.log('post');\n").expect("write post");

    let fake_bin = managed_tempfile_like_dir("ci-local-js-action-hooks-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"local js action","uses":"./.github/actions/js-hooks"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let entries = fs::read_to_string(fake_log).expect("fake docker log");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert!(
        entries.contains("node:20-bookworm node /workspace/.github/actions/js-hooks/pre.js"),
        "{entries}"
    );
    assert!(
        entries.contains("node:20-bookworm node /workspace/.github/actions/js-hooks/index.js"),
        "{entries}"
    );
    assert!(
        entries.contains("node:20-bookworm node /workspace/.github/actions/js-hooks/post.js"),
        "{entries}"
    );
}

#[cfg(unix)]
#[test]
fn ci_job_materializes_bundled_javascript_action_files_before_execution() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-bundled-js-action");
    let fake_bin = managed_tempfile_like_dir("ci-bundled-js-action-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let action_yml = r#"
name: bundled-js
runs:
  using: node20
  main: dist/index.js
"#;
    let files = serde_json::json!({
        "dist/index.js": "console.log('bundled');\n"
    });
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"action_bundles":[{{"uses":"owner/js@v1","local_path":"./.permanu/action-bundles/js123","action_filename":"action.yml","action_yml":{},"files":{}}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"bundled js","uses":"./.permanu/action-bundles/js123"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path"),
        serde_json::to_string(action_yml).expect("json action yaml"),
        files
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let entries = fs::read_to_string(fake_log).expect("fake docker log");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert!(output["log"]
        .as_str()
        .expect("human log")
        .contains("materialized action bundle owner/js@v1"));
    assert!(
        entries.contains(
            "node:20-bookworm node /workspace/.permanu/action-bundles/js123/dist/index.js"
        ),
        "{entries}"
    );
}

#[cfg(unix)]
#[test]
fn ci_job_materializes_and_runs_bundled_docker_action() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-bundled-docker-action");
    let fake_bin = managed_tempfile_like_dir("ci-bundled-docker-action-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "running");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let action_yml = r#"
name: bundled-docker
runs:
  using: docker
  image: Dockerfile
  args:
    - "${{ inputs.name }}"
"#;
    let files = serde_json::json!({
        "Dockerfile": "FROM alpine:3.20\nENTRYPOINT [\"/bin/echo\"]\n"
    });
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"action_bundles":[{{"uses":"owner/docker@v1","local_path":"./.permanu/action-bundles/docker123","action_filename":"action.yml","action_yml":{},"files":{}}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"bundled docker","uses":"./.permanu/action-bundles/docker123","with":{{"name":"permanu"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path"),
        serde_json::to_string(action_yml).expect("json action yaml"),
        files
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let entries = fs::read_to_string(fake_log).expect("fake docker log");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert!(output["log"]
        .as_str()
        .expect("human log")
        .contains("materialized action bundle owner/docker@v1"));
    assert!(
        entries.contains("build --file ") && entries.contains(" --tag permanu-ci-action-job-1-s1 "),
        "{entries}"
    );
    assert!(
        entries.contains("run --rm --network bridge --workdir /workspace")
            && entries.contains("permanu-ci-action-job-1-s1 permanu"),
        "{entries}"
    );
}

#[cfg(unix)]
#[test]
fn ci_job_with_services_reports_unhealthy_readiness_and_cleans_up() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-service-unhealthy");
    let fake_bin = managed_tempfile_like_dir("ci-service-unhealthy-docker-bin");
    let fake_log = fake_bin.join("docker-args.log");
    install_fake_docker(&fake_bin, &fake_log, "unhealthy");
    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }
    let _path = EnvVarGuard::set("PATH", &path_value);
    let payload = format!(
        r#"{{"job_db_id":"job_Prod.1","clone_dir":{},"timeout_seconds":5,"container":{{"image":"alpine:3.20"}},"services":{{"Postgres DB":{{"image":"postgres:16","ports":["5432/tcp"]}}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"test","shell":"sh","run":"printf ok"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);
    let entries = fs::read_to_string(fake_log).expect("fake docker log");

    assert_eq!(result.status, "failed", "{output}");
    assert!(output.contains("reported unhealthy"), "{output}");
    assert!(entries.contains("inspect --format"));
    assert!(entries.contains("rm -fv permanu-ci-job-prod-1-postgres-db"));
    assert!(entries.contains("network rm permanu-ci-job-prod-1"));
}

#[test]
fn ci_job_rejects_unmanaged_clone_dir() {
    let err = parse_ci_job(
        br#"{"job_db_id":"job-1","clone_dir":"/tmp/app","steps":[{"step_db_id":"s1","step_index":0,"run":"printf ok"}]}"#,
    )
    .unwrap_err();

    assert!(err.contains("under /var/tmp/permanu-ci"));
}

#[test]
fn ci_job_rejects_absolute_working_dir() {
    let err = parse_ci_job(
        br#"{"job_db_id":"job-1","steps":[{"step_db_id":"s1","step_index":0,"run":"printf ok","working_dir":"/etc"}]}"#,
    )
    .unwrap_err();

    assert!(err.contains("working_dir must be relative"));
}

#[test]
fn ci_job_rejects_parent_working_dir_escape() {
    let err = parse_ci_job(
        br#"{"job_db_id":"job-1","steps":[{"step_db_id":"s1","step_index":0,"run":"printf ok","working_dir":"subdir/../../outside"}]}"#,
    )
    .unwrap_err();

    assert!(err.contains("working_dir must stay inside workspace"));
}

#[test]
fn ci_job_sets_standard_ci_env_vars_under_managed_workspace() {
    let payload = br#"{"job_db_id":"job-1","job_id_yaml":"build","run_db_id":"run-1","timeout_seconds":5,"steps":[{"step_db_id":"s1","step_index":0,"name":"env","shell":"sh","run":"printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \"$GITHUB_SHA\" \"$GITHUB_REF\" \"$GITHUB_REPOSITORY\" \"$GITHUB_JOB\" \"$GITHUB_ACTIONS\" \"$PERMANU_SHA\" \"$PERMANU_REF\" \"$PERMANU_REPOSITORY\" \"$PERMANU_JOB\" \"$HOME\" \"$RUNNER_TEMP\""}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let log = output["log"].as_str().expect("human log");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert!(log.contains("true"));
    assert!(log.contains("/var/tmp/permanu-ci/run-1/job-1"));
}

#[test]
fn ci_job_sets_actions_oidc_request_env_when_allowed() {
    let payload = br#"{"job_db_id":"job-1","job_id_yaml":"build","run_db_id":"run-1","oidc_token_requests_allowed":true,"oidc_request_url":"https://api.permanu.test/api/ci/oidc/token?","oidc_request_token":"request-token","timeout_seconds":5,"steps":[{"step_db_id":"s1","step_index":0,"name":"oidc env","shell":"sh","run":"printf '%s\n%s\n' \"$ACTIONS_ID_TOKEN_REQUEST_URL\" \"$ACTIONS_ID_TOKEN_REQUEST_TOKEN\""}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let log = output["log"].as_str().expect("human log");

    assert_eq!(result.status, "completed", "{log}");
    assert!(log.contains("https://api.permanu.test/api/ci/oidc/token?"));
    assert!(log.contains("request-token"));
}

#[test]
fn ci_job_does_not_set_actions_oidc_env_when_not_allowed() {
    let payload = br#"{"job_db_id":"job-1","job_id_yaml":"build","run_db_id":"run-1","oidc_request_url":"https://api.permanu.test/api/ci/oidc/token?","oidc_request_token":"request-token","timeout_seconds":5,"steps":[{"step_db_id":"s1","step_index":0,"name":"oidc env","shell":"sh","run":"if [ -n \"${ACTIONS_ID_TOKEN_REQUEST_URL+x}\" ] || [ -n \"${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}\" ]; then exit 19; fi; printf absent"}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let log = output["log"].as_str().expect("human log");

    assert_eq!(result.status, "completed", "{log}");
    assert!(log.contains("absent"));
}

#[test]
fn ci_job_strips_host_env_and_preserves_explicit_ci_env() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let _host_secret = EnvVarGuard::set("PERMANU_TEST_HOST_SECRET", "host-secret-leak");
    let _strict_env = EnvVarGuard::remove("PERMANU_CI_STRICT_ENV");
    let _shared_cache = EnvVarGuard::set("PERMANU_CI_SHARED_TOOL_CACHE", "0");

    let payload = br#"{"job_db_id":"job-1","job_id_yaml":"build","run_db_id":"run-1","timeout_seconds":5,"env":{"EXPLICIT_SECRET":"allowed-secret"},"matrix_values":{"TARGET":"linux"},"secret_keys":["EXPLICIT_SECRET"],"steps":[{"step_db_id":"s1","step_index":0,"name":"isolated env","shell":"sh","run":"if [ -n \"${PERMANU_TEST_HOST_SECRET+x}\" ]; then echo \"leaked=$PERMANU_TEST_HOST_SECRET\"; exit 11; fi\n[ \"$EXPLICIT_SECRET\" = \"allowed-secret\" ] || exit 12\n[ \"$TARGET\" = \"linux\" ] || exit 13\n[ -n \"$PATH\" ] || exit 14\nJOB_ROOT=$(dirname \"$GITHUB_WORKSPACE\")\ncase \"$HOME\" in \"$JOB_ROOT\"/home) ;; *) echo \"bad-home=$HOME\"; exit 15;; esac\ncase \"$TMPDIR\" in \"$JOB_ROOT\"/tmp) ;; *) echo \"bad-tmp=$TMPDIR\"; exit 16;; esac\ncase \"$RUNNER_TEMP\" in \"$JOB_ROOT\"/runner-temp) ;; *) echo \"bad-runner-temp=$RUNNER_TEMP\"; exit 17;; esac\ncase \"$RUNNER_TOOL_CACHE\" in \"$JOB_ROOT\"/runner-tool-cache) ;; *) echo \"bad-tool-cache=$RUNNER_TOOL_CACHE\"; exit 18;; esac\ncase \"$CARGO_HOME\" in \"$JOB_ROOT\"/cargo) ;; *) echo \"bad-cargo=$CARGO_HOME\"; exit 19;; esac\ncase \"$RUSTUP_HOME\" in \"$JOB_ROOT\"/rustup) ;; *) echo \"bad-rustup=$RUSTUP_HOME\"; exit 20;; esac\nif [ \"$(uname -s)\" = \"Linux\" ]; then [ \"${CGO_ENABLED:-}\" = \"1\" ] || exit 21; [ \"${CC:-}\" = \"gcc\" ] || exit 22; fi\nprintf 'explicit=%s target=%s path-ok home=%s' \"$EXPLICIT_SECRET\" \"$TARGET\" \"$HOME\""}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);

    let output = String::from_utf8(result.output).expect("utf8 output");
    assert_eq!(result.status, "completed", "{output}");
    assert!(output.contains("*** target=linux path-ok home="));
    assert!(!output.contains("host-secret-leak"));
    assert!(!output.contains("allowed-secret"));
}

#[test]
fn ci_job_uses_runner_level_tool_caches_without_sharing_home_or_tmp() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let cache_root = managed_tempfile_like_dir("ci-shared-tool-cache-root");
    let _shared_cache = EnvVarGuard::set("PERMANU_CI_SHARED_TOOL_CACHE", "1");
    let _shared_cache_root = EnvVarGuard::set(
        "PERMANU_CI_SHARED_TOOL_CACHE_ROOT",
        cache_root.to_str().expect("utf8 cache root"),
    );

    let payload = br#"{"job_db_id":"job-1","job_id_yaml":"build","run_db_id":"run-1","timeout_seconds":5,"steps":[{"step_db_id":"s1","step_index":0,"name":"shared tool cache","shell":"sh","run":"JOB_ROOT=$(dirname \"$GITHUB_WORKSPACE\")\ncase \"$HOME\" in \"$JOB_ROOT\"/home) ;; *) echo \"bad-home=$HOME\"; exit 11;; esac\ncase \"$TMPDIR\" in \"$JOB_ROOT\"/tmp) ;; *) echo \"bad-tmp=$TMPDIR\"; exit 12;; esac\ncase \"$RUNNER_TEMP\" in \"$JOB_ROOT\"/runner-temp) ;; *) echo \"bad-runner-temp=$RUNNER_TEMP\"; exit 13;; esac\ncase \"$RUNNER_TOOL_CACHE\" in \"$JOB_ROOT\"/runner-tool-cache) echo bad-tool-cache=$RUNNER_TOOL_CACHE; exit 14;; esac\ncase \"$CARGO_HOME\" in \"$JOB_ROOT\"/cargo) echo bad-cargo=$CARGO_HOME; exit 15;; esac\ncase \"$RUSTUP_HOME\" in \"$JOB_ROOT\"/rustup) echo bad-rustup=$RUSTUP_HOME; exit 16;; esac\n[ -d \"$RUNNER_TOOL_CACHE\" ] || exit 17\n[ -d \"$CARGO_HOME\" ] || exit 18\n[ -d \"$RUSTUP_HOME\" ] || exit 19\nprintf 'tool-cache=%s cargo=%s rustup=%s' \"$RUNNER_TOOL_CACHE\" \"$CARGO_HOME\" \"$RUSTUP_HOME\""}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);

    let output = String::from_utf8(result.output).expect("utf8 output");
    assert_eq!(result.status, "completed", "{output}");
    let cache_root_text = cache_root.to_string_lossy();
    assert!(output.contains(&format!("tool-cache={cache_root_text}/runner-tool-cache")));
    assert!(output.contains(&format!("cargo={cache_root_text}/cargo")));
    assert!(output.contains(&format!("rustup={cache_root_text}/rustup")));
}

#[test]
fn ci_job_actions_cache_restores_from_exact_key_and_sets_outputs() {
    let workspace = managed_tempfile_like_dir("ci-cache-hit");
    let cache_root = managed_tempfile_like_dir("ci-cache-root");
    let cache_root_json =
        serde_json::to_string(cache_root.to_str().expect("utf8 cache root")).expect("json root");
    let workspace_json =
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path");

    let save_payload = format!(
        r#"{{"job_db_id":"job-1","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore cache","uses":"actions/cache@v4","with":{{"key":"linux-deps","path":"deps"}}}},{{"step_db_id":"s2","step_index":1,"name":"write","shell":"sh","run":"mkdir -p deps && printf cached > deps/value.txt"}}]}}"#
    );
    let save = job_deployment::handle_ci_job("cmd-save", save_payload.as_bytes());
    assert_eq!(
        save.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&save.output)
    );

    fs::create_dir_all(&workspace).expect("recreate workspace");
    let restore_payload = format!(
        r#"{{"job_db_id":"job-2","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore cache","uses":"actions/cache@v4","with":{{"key":"linux-deps","path":"deps","restore-keys":"linux-"}}}},{{"step_db_id":"s2","step_index":1,"name":"verify","shell":"sh","run":"printf '%s %s %s %s' \"$(cat deps/value.txt)\" \"$PERMANU_OUTPUT_cache_hit\" \"$PERMANU_OUTPUT_cache_primary_key\" \"$PERMANU_OUTPUT_cache_matched_key\""}}]}}"#
    );

    let restore = job_deployment::handle_ci_job("cmd-restore", restore_payload.as_bytes());
    let output = String::from_utf8(restore.output).expect("utf8 output");

    assert_eq!(restore.status, "completed", "{output}");
    assert!(
        output.contains("cached true linux-deps linux-deps"),
        "{output}"
    );
    assert!(!output.contains(cache_root.to_string_lossy().as_ref()));
}

#[test]
fn ci_job_actions_cache_restore_key_sets_primary_and_matched_outputs() {
    let workspace = managed_tempfile_like_dir("ci-cache-prefix");
    let cache_root = managed_tempfile_like_dir("ci-cache-prefix-root");
    let cache_root_json =
        serde_json::to_string(cache_root.to_str().expect("utf8 cache root")).expect("json root");
    let workspace_json =
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path");

    let save_payload = format!(
        r#"{{"job_db_id":"job-1","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore cache","uses":"actions/cache@v4","with":{{"key":"linux-deps-old","path":"deps"}}}},{{"step_db_id":"s2","step_index":1,"name":"write","shell":"sh","run":"mkdir -p deps && printf cached > deps/value.txt"}}]}}"#
    );
    let save = job_deployment::handle_ci_job("cmd-save", save_payload.as_bytes());
    assert_eq!(
        save.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&save.output)
    );

    fs::create_dir_all(&workspace).expect("recreate workspace");
    let restore_payload = format!(
        r#"{{"job_db_id":"job-2","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore cache","uses":"actions/cache@v4","with":{{"key":"linux-deps-new","path":"deps","restore-keys":"linux-deps-"}}}},{{"step_db_id":"s2","step_index":1,"name":"verify","shell":"sh","run":"printf '%s %s %s %s' \"$(cat deps/value.txt)\" \"$PERMANU_OUTPUT_cache_hit\" \"$PERMANU_OUTPUT_cache_primary_key\" \"$PERMANU_OUTPUT_cache_matched_key\""}}]}}"#
    );

    let restore = job_deployment::handle_ci_job("cmd-restore", restore_payload.as_bytes());
    let output = String::from_utf8(restore.output).expect("utf8 output");

    assert_eq!(restore.status, "completed", "{output}");
    assert!(
        output.contains("cached false linux-deps-new linux-deps-old"),
        "{output}"
    );
}

#[test]
fn ci_job_actions_cache_rejects_traversal_and_symlink_paths() {
    let workspace = managed_tempfile_like_dir("ci-cache-guard");
    let outside = managed_tempfile_like_dir("ci-cache-outside");
    fs::write(outside.join("secret.txt"), "secret").expect("write outside");
    #[cfg(unix)]
    let symlink_workspace = managed_tempfile_like_dir("ci-cache-symlink");
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        outside.join("secret.txt"),
        symlink_workspace.join("linked-secret"),
    )
    .expect("create symlink");

    let traversal_payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"bad cache","uses":"actions/cache@v4","with":{{"key":"bad","path":"../outside"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path")
    );
    let traversal = job_deployment::handle_ci_job("cmd-traversal", traversal_payload.as_bytes());
    let traversal_output = String::from_utf8(traversal.output).expect("utf8 output");
    assert_eq!(traversal.status, "failed");
    assert!(traversal_output.contains("cache path must stay inside workspace"));

    #[cfg(unix)]
    {
        let symlink_payload = format!(
            r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"bad cache","uses":"actions/cache@v4","with":{{"key":"bad","path":"linked-secret"}}}}]}}"#,
            serde_json::to_string(symlink_workspace.to_str().expect("utf8 workspace"))
                .expect("json path")
        );
        let symlink = job_deployment::handle_ci_job("cmd-symlink", symlink_payload.as_bytes());
        let symlink_output = String::from_utf8(symlink.output).expect("utf8 output");
        assert_eq!(symlink.status, "failed");
        assert!(symlink_output.contains("cache path cannot be a symlink"));
    }
}

#[test]
fn ci_job_actions_cache_lookup_only_does_not_save_on_miss() {
    let workspace = managed_tempfile_like_dir("ci-cache-unsupported");
    let cache_root = managed_tempfile_like_dir("ci-cache-lookup-root");
    let cache_root_json =
        serde_json::to_string(cache_root.to_str().expect("utf8 cache root")).expect("json root");
    let workspace_json =
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path");
    let payload = format!(
        r#"{{"job_db_id":"job-1","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"lookup only","uses":"actions/cache@v4","with":{{"key":"linux-deps","path":"deps","lookup-only":"true"}}}},{{"step_db_id":"s2","step_index":1,"name":"write","shell":"sh","run":"mkdir -p deps && printf fresh > deps/value.txt"}}]}}"#
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "completed", "{output}");

    fs::create_dir_all(&workspace).expect("recreate workspace");
    let restore_payload = format!(
        r#"{{"job_db_id":"job-2","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore","uses":"actions/cache@v4","with":{{"key":"linux-deps","path":"deps"}}}},{{"step_db_id":"s2","step_index":1,"name":"verify","shell":"sh","run":"test ! -e deps/value.txt && printf '%s %s' \"$PERMANU_OUTPUT_cache_hit\" \"$PERMANU_OUTPUT_cache_primary_key\""}}]}}"#
    );

    let restore = job_deployment::handle_ci_job("cmd-restore", restore_payload.as_bytes());
    let restore_output = String::from_utf8(restore.output).expect("utf8 output");
    assert_eq!(restore.status, "completed", "{restore_output}");
    assert!(
        restore_output.contains("false linux-deps"),
        "{restore_output}"
    );
}

#[test]
fn ci_job_actions_cache_fail_on_cache_miss_fails_step() {
    let workspace = managed_tempfile_like_dir("ci-cache-fail-miss");
    let cache_root = managed_tempfile_like_dir("ci-cache-fail-miss-root");
    let payload = format!(
        r#"{{"job_db_id":"job-1","repo_owner":"permanu","repo_name":"app","clone_dir":{},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore required cache","uses":"actions/cache@v4","with":{{"key":"linux-deps","path":"deps","fail-on-cache-miss":"true"}}}},{{"step_db_id":"s2","step_index":1,"name":"should not run","shell":"sh","run":"printf unexpected"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path"),
        serde_json::to_string(cache_root.to_str().expect("utf8 cache root")).expect("json root")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "failed");
    assert!(output.contains("actions/cache miss"), "{output}");
    assert!(output.contains("fail-on-cache-miss"), "{output}");
    assert!(!output.contains("unexpected"), "{output}");
}

#[test]
fn ci_job_actions_cache_records_quota_eviction_decision() {
    let workspace = managed_tempfile_like_dir("ci-cache-quota");
    let cache_root = managed_tempfile_like_dir("ci-cache-quota-root");
    let cache_root_json =
        serde_json::to_string(cache_root.to_str().expect("utf8 cache root")).expect("json root");
    let workspace_json =
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path");
    let payload = format!(
        r#"{{"job_db_id":"job-1","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json},"PERMANU_ACTIONS_CACHE_MAX_BYTES":"8"}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore cache","uses":"actions/cache@v4","with":{{"key":"linux-deps","path":"deps"}}}},{{"step_db_id":"s2","step_index":1,"name":"write","shell":"sh","run":"mkdir -p deps && printf 'larger-than-quota' > deps/value.txt"}}]}}"#
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8(result.output.clone()).expect("utf8 output");
    assert_eq!(result.status, "completed", "{output}");

    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let cache_events = output["cache_events"].as_array().expect("cache events");
    assert!(cache_events.iter().any(|event| {
        event["result"] == "evicted"
            && event["key"] == "linux-deps"
            && event["eviction_reason"] == "quota_exceeded"
            && event["quota_decision"] == "evict_saved_entry"
            && event["quota_limit_bytes"] == 8
    }));
}

#[test]
fn ci_job_actions_cache_quota_evicts_older_entries_before_new_saved_entry() {
    let workspace = managed_tempfile_like_dir("ci-cache-lru");
    let cache_root = managed_tempfile_like_dir("ci-cache-lru-root");
    let cache_root_json =
        serde_json::to_string(cache_root.to_str().expect("utf8 cache root")).expect("json root");
    let workspace_json =
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path");

    let old_payload = format!(
        r#"{{"job_db_id":"job-1","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json},"PERMANU_ACTIONS_CACHE_MAX_BYTES":"600"}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore old","uses":"actions/cache@v4","with":{{"key":"old-deps","path":"deps"}}}},{{"step_db_id":"s2","step_index":1,"name":"write old","shell":"sh","run":"mkdir -p deps && head -c 320 </dev/zero > deps/value.bin"}}]}}"#
    );
    let old = job_deployment::handle_ci_job("cmd-old", old_payload.as_bytes());
    assert_eq!(
        old.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&old.output)
    );

    fs::create_dir_all(&workspace).expect("recreate workspace");
    let new_payload = format!(
        r#"{{"job_db_id":"job-2","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json},"PERMANU_ACTIONS_CACHE_MAX_BYTES":"600"}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore new","uses":"actions/cache@v4","with":{{"key":"new-deps","path":"deps"}}}},{{"step_db_id":"s2","step_index":1,"name":"write new","shell":"sh","run":"mkdir -p deps && head -c 320 </dev/zero > deps/value.bin"}}]}}"#
    );
    let new = job_deployment::handle_ci_job("cmd-new", new_payload.as_bytes());
    let new_output = String::from_utf8(new.output.clone()).expect("utf8 output");
    assert_eq!(new.status, "completed", "{new_output}");

    let output: Value = serde_json::from_slice(&new.output).expect("json output");
    let cache_events = output["cache_events"].as_array().expect("cache events");
    assert!(cache_events.iter().any(|event| {
        event["result"] == "saved"
            && event["key"] == "new-deps"
            && event["quota_decision"] == "evict_lru_entries"
            && event["eviction_reason"] == "quota_exceeded"
            && event["quota_limit_bytes"] == 600
    }));

    fs::create_dir_all(&workspace).expect("recreate workspace");
    let verify_payload = format!(
        r#"{{"job_db_id":"job-3","job_id_yaml":"build","repo_owner":"permanu","repo_name":"app","clone_dir":{workspace_json},"timeout_seconds":5,"env":{{"PERMANU_ACTIONS_CACHE_DIR":{cache_root_json}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"restore old","uses":"actions/cache@v4","with":{{"key":"old-deps","path":"deps","lookup-only":"true"}}}},{{"step_db_id":"s2","step_index":1,"name":"verify old miss","shell":"sh","run":"printf '%s ' \"$PERMANU_OUTPUT_cache_hit\""}},{{"step_db_id":"s3","step_index":2,"name":"restore new","uses":"actions/cache@v4","with":{{"key":"new-deps","path":"deps","lookup-only":"true"}}}},{{"step_db_id":"s4","step_index":3,"name":"verify new hit","shell":"sh","run":"printf '%s' \"$PERMANU_OUTPUT_cache_hit\""}}]}}"#
    );
    let verify = job_deployment::handle_ci_job("cmd-verify", verify_payload.as_bytes());
    let verify_output = String::from_utf8(verify.output).expect("utf8 output");
    assert_eq!(verify.status, "completed", "{verify_output}");
    let verify_json: Value = serde_json::from_str(&verify_output).expect("json output");
    assert!(
        verify_json["step_logs"]["s2"]
            .as_str()
            .unwrap_or_default()
            .contains("false"),
        "{verify_output}"
    );
    assert!(
        verify_json["step_logs"]["s4"]
            .as_str()
            .unwrap_or_default()
            .contains("true"),
        "{verify_output}"
    );
}

#[test]
fn ci_job_actions_cache_rejects_cross_os_archive_with_precise_diagnostic() {
    let workspace = managed_tempfile_like_dir("ci-cache-cross-os");
    let payload = format!(
        r#"{{"job_db_id":"job-1","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"cross os","uses":"actions/cache@v4","with":{{"key":"linux-deps","path":"deps","enableCrossOsArchive":"true"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 workspace")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "failed");
    assert!(output.contains("enableCrossOsArchive"), "{output}");
    assert!(output.contains("not supported"), "{output}");
}

#[test]
fn ci_job_defaults_checkout_workspace_from_repo_metadata() {
    let job = parse_ci_job(
        br#"{"job_db_id":"00000000-0000-0000-0000-000000000001","job_id_yaml":"build","run_db_id":"00000000-0000-0000-0000-000000000002","repo_owner":"permanu","repo_name":"Dwaar","head_sha":"1111111111111111111111111111111111111111","trigger_ref":"refs/heads/main","steps":[{"step_db_id":"s1","step_index":0,"name":"test","run":"printf ok"}]}"#,
    )
    .expect("parse ci job");

    assert_eq!(job.repo_owner, "permanu");
    assert_eq!(job.repo_name, "Dwaar");
    assert_eq!(job.head_sha, "1111111111111111111111111111111111111111");
    assert_eq!(
        job.clone_dir,
        "/var/tmp/permanu-ci/00000000-0000-0000-0000-000000000002/00000000-0000-0000-0000-000000000001/workspace"
    );
}

#[test]
fn ci_job_executes_explicit_shell_and_redacts_secret_output() {
    let payload = br#"{"job_db_id":"job-1","timeout_seconds":5,"env":{"TOKEN":"s3cr3t-value"},"matrix_values":{"TARGET":"linux"},"secret_keys":["TOKEN"],"steps":[{"step_db_id":"s1","step_index":0,"name":"show env","run":"printf '%s %s' \"$TOKEN\" \"$TARGET\"","shell":"sh"}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "completed");
    assert!(output.contains("*** linux"));
    assert!(!output.contains("s3cr3t-value"));
    assert!(output.contains("[show env] completed successfully"));
}

#[test]
fn ci_job_evaluates_rendered_boolean_and_status_if_expressions() {
    let workspace = managed_tempfile_like_dir("ci-if-expressions");
    let payload = format!(
        r#"{{"job_db_id":"job-1","job_id_yaml":"build","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"rendered true","run":"printf true-ran","if":"True"}},{{"step_db_id":"s2","step_index":1,"name":"rendered false","run":"printf false-ran","if":"False"}},{{"step_db_id":"s3","step_index":2,"name":"soft failure","run":"false","continue_on_error":true}},{{"step_db_id":"s4","step_index":3,"name":"always status","run":"printf always-ran","if":"always()"}},{{"step_db_id":"s5","step_index":4,"name":"cancelled status","run":"printf cancelled-ran","if":"cancelled()"}},{{"step_db_id":"s6","step_index":5,"name":"rendered always","run":"printf rendered-always-ran","if":"${{{{ Always() }}}}"}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");
    let log = output["log"].as_str().expect("human log");

    assert_eq!(result.status, "completed", "{output}");
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert_eq!(output["step_statuses"]["s2"], "skipped");
    assert_eq!(output["step_statuses"]["s3"], "failure");
    assert_eq!(output["step_statuses"]["s4"], "success");
    assert_eq!(output["step_statuses"]["s5"], "skipped");
    assert_eq!(output["step_statuses"]["s6"], "success");
    assert!(log.contains("true-ran"), "{log}");
    assert!(log.contains("always-ran"), "{log}");
    assert!(log.contains("rendered-always-ran"), "{log}");
    assert!(!log.contains("false-ran"), "{log}");
    assert!(!log.contains("cancelled-ran"), "{log}");
}

#[test]
fn ci_job_emits_structured_json_result_with_human_log() {
    let payload = br#"{"job_db_id":"job-1","job_id_yaml":"build","timeout_seconds":5,"steps":[{"step_db_id":"s1","step_index":0,"name":"pass","run":"printf ok"},{"step_db_id":"s2","step_index":1,"name":"allowed failure","run":"false","continue_on_error":true},{"step_db_id":"s3","step_index":2,"name":"hard failure","run":"false"}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(result.status, "failed");
    assert_eq!(output["conclusion"], "failure");
    assert_eq!(output["failed_step_index"], 2);
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert_eq!(output["step_statuses"]["s2"], "failure");
    assert_eq!(output["step_statuses"]["s3"], "failure");
    let log = output["log"].as_str().expect("human log");
    assert!(log.contains("starting CI job build (job-1)"));
    assert!(log.contains("[allowed failure] continuing on error"));
    assert!(log.contains("ci job failed at step 2"));
}

#[test]
fn ci_job_executes_local_composite_action_and_workflow_command_files() {
    let workspace = managed_tempfile_like_dir("ci-composite");
    let action_dir = workspace.join(".permanu/actions/setup");
    fs::create_dir_all(&action_dir).expect("create action dir");
    fs::write(
        action_dir.join("action.yml"),
        r#"
runs:
  using: composite
  steps:
    - name: export value
      shell: sh
      run: |
        echo "COMPOSITE_VALUE=${{ inputs.value }}" >> "$PERMANU_ENV"
        echo "MULTILINE<<EOF" >> "$PERMANU_ENV"
        echo "line-one" >> "$PERMANU_ENV"
        echo "line-two" >> "$PERMANU_ENV"
        echo "EOF" >> "$PERMANU_ENV"
        echo "answer=42" >> "$PERMANU_OUTPUT"
        echo "body<<EOF" >> "$PERMANU_OUTPUT"
        echo "$INPUT_MESSAGE" >> "$PERMANU_OUTPUT"
        echo "EOF" >> "$PERMANU_OUTPUT"
"#,
    )
    .expect("write action");

    let payload = format!(
        r#"{{"job_db_id":"job-1","job_id_yaml":"build","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"setup","uses":"./.permanu/actions/setup","with":{{"value":"from-composite","message":"hello multiline"}}}},{{"step_db_id":"s2","step_index":1,"name":"verify","shell":"sh","run":"printf '%s %s %s %s' \"$COMPOSITE_VALUE\" \"$PERMANU_WORKSPACE\" \"$MULTILINE\" \"$PERMANU_OUTPUT_body\""}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert_eq!(output["step_statuses"]["s2"], "success");
    assert!(output["step_logs"]["s2"]
        .as_str()
        .expect("step log")
        .contains("hello multiline"));
    let log = output["log"].as_str().expect("human log");
    assert!(log.contains("[setup / export value] completed successfully"));
    assert!(log.contains("from-composite"));
    assert!(log.contains("line-one"));
    assert!(log.contains("line-two"));
    assert!(log.contains("hello multiline"));
    assert!(log.contains(workspace.to_str().expect("utf8 path")));
}

#[test]
fn ci_job_materializes_remote_composite_action_bundle_before_execution() {
    let workspace = managed_tempfile_like_dir("ci-remote-composite-bundle");
    let action_yml = r#"
runs:
  using: composite
  steps:
    - name: bundled step
      shell: sh
      run: echo "REMOTE_BUNDLE_VALUE=${{ inputs.value }}" >> "$PERMANU_ENV"
"#;
    let payload = format!(
        r#"{{"job_db_id":"job-1","job_id_yaml":"build","clone_dir":{},"timeout_seconds":5,"action_bundles":[{{"uses":"owner/composite@v1","local_path":"./.permanu/action-bundles/abc123","action_filename":"action.yml","action_yml":{}}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"remote composite","uses":"./.permanu/action-bundles/abc123","with":{{"value":"from-bundle"}}}},{{"step_db_id":"s2","step_index":1,"name":"verify","shell":"sh","run":"printf '%s' \"$REMOTE_BUNDLE_VALUE\""}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path"),
        serde_json::to_string(action_yml).expect("json action yaml")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert_eq!(output["step_statuses"]["s2"], "success");
    assert!(output["step_logs"]["s2"]
        .as_str()
        .expect("step log")
        .contains("from-bundle"));
    let log = output["log"].as_str().expect("human log");
    assert!(log.contains("materialized action bundle owner/composite@v1"));
}

#[test]
fn ci_job_uploads_artifact_events_for_upload_artifact_v4() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-artifact");
    let artifact_store = managed_tempfile_like_dir("ci-artifact-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(workspace.join("dist/dwaar-linux-amd64"), b"release-binary").expect("write artifact");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dwaar-linux-amd64","path":"dist/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert_eq!(output["artifacts"][0]["name"], "dwaar-linux-amd64");
    let storage_path = output["artifacts"][0]["storage_path"]
        .as_str()
        .expect("storage path");
    let archive = fs::read(
        artifact_store
            .join(storage_path)
            .join(".permanu-artifact.zip"),
    )
    .expect("artifact archive");
    assert_eq!(
        output["artifacts"][0]["size_bytes"],
        i64::try_from(archive.len()).expect("archive length")
    );
    assert!(storage_path.contains("run-1/job-1/0-dwaar-linux-amd64"));
    assert!(artifact_store
        .join(storage_path)
        .join("dist")
        .join("dwaar-linux-amd64")
        .is_file());
    assert!(
        !workspace.exists(),
        "CI workspace should be cleaned after upload"
    );
}

#[test]
fn ci_job_downloads_same_job_artifact_for_later_steps() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-artifact");
    let artifact_store = managed_tempfile_like_dir("ci-download-artifact-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(workspace.join("dist/app.tar.gz"), b"release-archive").expect("write artifact");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dist","path":"dist/"}}}},{{"step_db_id":"s2","step_index":1,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"restored"}}}},{{"step_db_id":"s3","step_index":2,"name":"upload restored","uses":"actions/upload-artifact@v4","with":{{"name":"restored","path":"restored/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert_eq!(output["step_statuses"]["s2"], "success");
    assert_eq!(output["step_statuses"]["s3"], "success");
    assert!(output["step_logs"]["s2"]
        .as_str()
        .expect("download step log")
        .contains("downloaded 1 artifact(s)"));

    let restored_storage_path = output["artifacts"][1]["storage_path"]
        .as_str()
        .expect("restored storage path");
    assert_eq!(output["artifacts"][1]["name"], "restored");
    assert!(artifact_store
        .join(restored_storage_path)
        .join("restored")
        .join("dist")
        .join("app.tar.gz")
        .is_file());
}

#[test]
fn ci_job_upload_artifact_honors_retention_and_hidden_file_inputs() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-artifact-hidden");
    let artifact_store = managed_tempfile_like_dir("ci-artifact-hidden-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(workspace.join("dist/.coverage"), b"hidden").expect("write hidden artifact");
    fs::write(workspace.join("dist/app"), b"binary").expect("write artifact");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );
    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dist","path":"dist/.coverage\n dist/app","include-hidden-files":"true","retention-days":"7","compression-level":"0","overwrite":"true"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["artifacts"][0]["expires_at"], "retention-days:7");
    let storage_path = output["artifacts"][0]["storage_path"]
        .as_str()
        .expect("storage path");
    assert!(artifact_store
        .join(storage_path)
        .join(".coverage")
        .is_file());
    assert!(artifact_store.join(storage_path).join("app").is_file());
}

#[test]
fn ci_job_upload_artifact_event_uses_archive_bytes_and_compression_level() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-artifact-archive-bytes");
    let artifact_store = managed_tempfile_like_dir("ci-artifact-archive-bytes-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(workspace.join("dist/app"), b"release-binary").expect("write artifact");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );
    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dist","path":"dist/","compression-level":"0"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    let storage_path = output["artifacts"][0]["storage_path"]
        .as_str()
        .expect("storage path");
    let archive_path = artifact_store
        .join(storage_path)
        .join(".permanu-artifact.zip");
    let archive = fs::read(&archive_path).expect("read artifact archive");
    assert_eq!(
        output["artifacts"][0]["size_bytes"],
        i64::try_from(archive.len()).expect("archive length")
    );
    assert_eq!(
        output["artifacts"][0]["content_sha256"],
        format!("{:x}", Sha256::digest(&archive))
    );
    let archive_file = fs::File::open(&archive_path).expect("open artifact archive");
    let mut zip = zip::ZipArchive::new(archive_file).expect("zip archive");
    let entry = zip.by_name("dist/app").expect("zip entry");
    assert_eq!(entry.compression(), zip::CompressionMethod::Stored);
}

#[test]
fn ci_job_download_artifact_rejects_workspace_escape() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-artifact-escape");
    let artifact_store = managed_tempfile_like_dir("ci-download-artifact-escape-store");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"../outside"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("must stay inside the workspace"),
        "{output}"
    );
}

#[test]
fn ci_job_download_artifact_errors_when_named_artifact_missing() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-artifact-missing");
    let artifact_store = managed_tempfile_like_dir("ci-download-artifact-missing-store");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"downloaded"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("artifact dist was not found in this job"),
        "{output}"
    );
}

#[test]
fn ci_job_downloads_available_artifact_from_same_runner_storage_path() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-available-artifact");
    let artifact_store = managed_tempfile_like_dir("ci-download-available-artifact-store");
    fs::create_dir_all(artifact_store.join("run-1/build-1/0-dist/dist")).expect("create artifact");
    fs::write(
        artifact_store.join("run-1/build-1/0-dist/dist/app.tar.gz"),
        b"release-archive",
    )
    .expect("write artifact");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"test","clone_dir":{},"timeout_seconds":5,"available_artifacts":[{{"name":"dist","storage_path":"run-1/build-1/0-dist"}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"restored"}}}},{{"step_db_id":"s2","step_index":1,"name":"upload restored","uses":"actions/upload-artifact@v4","with":{{"name":"restored","path":"restored/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert!(output["step_logs"]["s1"]
        .as_str()
        .expect("download log")
        .contains("downloaded 1 artifact(s)"));
    let restored_storage_path = output["artifacts"][0]["storage_path"]
        .as_str()
        .expect("restored storage path");
    assert!(artifact_store
        .join(restored_storage_path)
        .join("restored")
        .join("dist")
        .join("app.tar.gz")
        .is_file());
}

#[test]
fn ci_job_download_available_artifact_rejects_sanitized_name_collisions() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-available-collision");
    let artifact_store = managed_tempfile_like_dir("ci-download-available-collision-store");
    fs::create_dir_all(artifact_store.join("run-1/build-a/0-a")).expect("create artifact a");
    fs::create_dir_all(artifact_store.join("run-1/build-b/0-b")).expect("create artifact b");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"test","clone_dir":{},"timeout_seconds":5,"available_artifacts":[{{"name":"foo.bar","storage_path":"run-1/build-a/0-a"}},{{"name":"foo bar","storage_path":"run-1/build-b/0-b"}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"download","uses":"actions/download-artifact@v4","with":{{"path":"downloaded"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("collide after path sanitization"),
        "{output}"
    );
}

#[cfg(unix)]
#[test]
fn ci_job_download_available_artifact_rejects_symlinked_storage_path() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-available-symlink");
    let artifact_store = managed_tempfile_like_dir("ci-download-available-symlink-store");
    let outside = managed_tempfile_like_dir("ci-download-available-symlink-outside");
    fs::write(outside.join("secret.txt"), b"outside-secret").expect("write outside secret");
    fs::create_dir_all(artifact_store.join("run-1/build-1")).expect("create parent");
    std::os::unix::fs::symlink(
        outside.join("secret.txt"),
        artifact_store.join("run-1/build-1/0-dist"),
    )
    .expect("create symlink");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"test","clone_dir":{},"timeout_seconds":5,"available_artifacts":[{{"name":"dist","storage_path":"run-1/build-1/0-dist"}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"restored"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("artifact source must not contain symlinks"),
        "{output}"
    );
    assert!(!workspace.join("restored/secret.txt").exists());
}

#[test]
fn ci_job_download_available_artifact_reports_remote_unsupported() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-available-remote");
    let artifact_store = managed_tempfile_like_dir("ci-download-available-remote-store");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"test","clone_dir":{},"timeout_seconds":5,"available_artifacts":[{{"name":"dist","provider_url":"permanu://artifacts/run-1/dist"}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"restored"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("only has provider_url; download through the control plane is required"),
        "{output}"
    );
}

#[test]
fn ci_job_downloads_available_artifact_from_control_plane_url() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-available-control-plane");
    let artifact_store = managed_tempfile_like_dir("ci-download-available-control-plane-store");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );
    let zip_bytes = control_plane_artifact_zip_bytes();
    let zip_size = i64::try_from(zip_bytes.len()).expect("zip size");
    let zip_hash = format!("{:x}", Sha256::digest(&zip_bytes));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local artifact server");
    let addr = listener.local_addr().expect("local addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept artifact request");
        let mut request = [0u8; 1024];
        let _ = std::io::Read::read(&mut stream, &mut request);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            zip_bytes.len()
        );
        stream.write_all(header.as_bytes()).expect("write header");
        stream.write_all(&zip_bytes).expect("write body");
    });

    let download_url = format!("http://127.0.0.1:{}/api/artifacts/artifact-1/download?expires=9999999999&sig=test&run_id=run-1&job_id=build-1", addr.port());
    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"test","clone_dir":{},"timeout_seconds":5,"available_artifacts":[{{"name":"dist","download_url":{},"size_bytes":{},"hash":{}}}],"steps":[{{"step_db_id":"s1","step_index":0,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"restored"}}}},{{"step_db_id":"s2","step_index":1,"name":"upload restored","uses":"actions/upload-artifact@v4","with":{{"name":"restored","path":"restored/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path"),
        serde_json::to_string(&download_url).expect("json url"),
        zip_size,
        serde_json::to_string(&zip_hash).expect("json hash")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    server.join().expect("artifact server joins");
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert!(artifact_store
        .join(
            output["artifacts"][0]["storage_path"]
                .as_str()
                .expect("storage path")
        )
        .join("restored")
        .join("dist")
        .join("app.tar.gz")
        .is_file());
}

fn control_plane_artifact_zip_bytes() -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("dist/app.tar.gz", options)
            .expect("start zip file");
        zip.write_all(b"release-archive").expect("write zip file");
        zip.finish().expect("finish zip");
    }
    cursor.into_inner()
}

#[cfg(unix)]
#[test]
fn ci_job_download_artifact_rejects_symlinked_destination_file_escape() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-artifact-file-symlink");
    let outside = managed_tempfile_like_dir("ci-download-artifact-file-outside");
    let artifact_store = managed_tempfile_like_dir("ci-download-artifact-file-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::create_dir_all(workspace.join("restored")).expect("create restored");
    fs::write(workspace.join("dist/app.tar.gz"), b"release-archive").expect("write artifact");
    fs::write(outside.join("target.txt"), b"outside-secret").expect("write outside target");
    std::os::unix::fs::symlink(
        outside.join("target.txt"),
        workspace.join("restored/app.tar.gz"),
    )
    .expect("create symlink");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dist","path":"dist/app.tar.gz"}}}},{{"step_db_id":"s2","step_index":1,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"restored"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("destination must not contain symlinks"),
        "{output}"
    );
    assert_eq!(
        fs::read_to_string(outside.join("target.txt")).expect("outside target"),
        "outside-secret"
    );
}

#[cfg(unix)]
#[test]
fn ci_job_download_artifact_rejects_symlinked_destination_directory_escape() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-artifact-dir-symlink");
    let outside = managed_tempfile_like_dir("ci-download-artifact-dir-outside");
    let artifact_store = managed_tempfile_like_dir("ci-download-artifact-dir-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::create_dir_all(workspace.join("restored")).expect("create restored");
    fs::write(workspace.join("dist/app.tar.gz"), b"release-archive").expect("write artifact");
    std::os::unix::fs::symlink(&outside, workspace.join("restored/dist")).expect("create symlink");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dist","path":"dist/"}}}},{{"step_db_id":"s2","step_index":1,"name":"download","uses":"actions/download-artifact@v4","with":{{"name":"dist","path":"restored"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("destination must not contain symlinks"),
        "{output}"
    );
    assert!(
        !outside.join("app.tar.gz").exists(),
        "download must not write through destination directory symlink"
    );
}

#[test]
fn ci_job_download_artifact_supports_pattern_and_merge_multiple() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-artifact-pattern");
    let artifact_store = managed_tempfile_like_dir("ci-download-artifact-pattern-store");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    fs::create_dir_all(workspace.join("dist-a")).expect("create dist a");
    fs::create_dir_all(workspace.join("dist-b")).expect("create dist b");
    fs::write(workspace.join("dist-a/a.txt"), b"a").expect("write artifact a");
    fs::write(workspace.join("dist-b/b.txt"), b"b").expect("write artifact b");

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload a","uses":"actions/upload-artifact@v4","with":{{"name":"dist-a","path":"dist-a/a.txt"}}}},{{"step_db_id":"s2","step_index":1,"name":"upload b","uses":"actions/upload-artifact@v4","with":{{"name":"dist-b","path":"dist-b/b.txt"}}}},{{"step_db_id":"s3","step_index":2,"name":"download","uses":"actions/download-artifact@v4","with":{{"pattern":"dist-*","path":"downloaded","merge-multiple":"true"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["step_statuses"]["s3"], "success");
    assert!(output["step_logs"]["s3"]
        .as_str()
        .expect("download log")
        .contains("downloaded 2 artifact(s)"));
}

#[test]
fn ci_job_download_artifact_rejects_sanitized_name_collisions() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-download-artifact-collision");
    let artifact_store = managed_tempfile_like_dir("ci-download-artifact-collision-store");
    fs::create_dir_all(workspace.join("dist-a")).expect("create dist a");
    fs::create_dir_all(workspace.join("dist-b")).expect("create dist b");
    fs::write(workspace.join("dist-a/app.txt"), b"a").expect("write artifact a");
    fs::write(workspace.join("dist-b/app.txt"), b"b").expect("write artifact b");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload a","uses":"actions/upload-artifact@v4","with":{{"name":"foo.bar","path":"dist-a/"}}}},{{"step_db_id":"s2","step_index":1,"name":"upload b","uses":"actions/upload-artifact@v4","with":{{"name":"foo bar","path":"dist-b/"}}}},{{"step_db_id":"s3","step_index":2,"name":"download all","uses":"actions/download-artifact@v4","with":{{"path":"downloaded"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(
        output.contains("collide after path sanitization"),
        "{output}"
    );
}

#[cfg(unix)]
#[test]
fn ci_job_upload_artifact_rejects_symlinked_file_escape() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-artifact-file-symlink");
    let outside = managed_tempfile_like_dir("ci-artifact-file-outside");
    let artifact_store = managed_tempfile_like_dir("ci-artifact-file-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(outside.join("secret.txt"), b"outside-secret").expect("write outside secret");
    std::os::unix::fs::symlink(
        outside.join("secret.txt"),
        workspace.join("dist/secret.txt"),
    )
    .expect("create symlink");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"leak","path":"dist/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(output.contains("symlink"), "{output}");
}

#[cfg(unix)]
#[test]
fn ci_job_upload_artifact_rejects_symlinked_directory_escape() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-artifact-dir-symlink");
    let outside = managed_tempfile_like_dir("ci-artifact-dir-outside");
    let artifact_store = managed_tempfile_like_dir("ci-artifact-dir-store");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(outside.join("secret.txt"), b"outside-secret").expect("write outside secret");
    std::os::unix::fs::symlink(&outside, workspace.join("dist/outside")).expect("create symlink");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"leak","path":"dist/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8_lossy(&result.output);

    assert_eq!(result.status, "failed", "{output}");
    assert!(output.contains("symlink"), "{output}");
}

#[test]
fn ci_job_native_cosign_sign_blob_requires_key_or_explicit_token() {
    let workspace = managed_tempfile_like_dir("ci-cosign-token-required");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(workspace.join("dist/dwaar-linux-amd64"), b"release-binary").expect("write artifact");

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"steps":[{{"step_db_id":"s1","step_index":0,"name":"sign","uses":"permanu/cosign-sign-blob@v1","with":{{"path":"dist/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "failed");
    assert!(output.contains("key"));
    assert!(output.contains("COSIGN_KEY"));
    assert!(output.contains("PERMANU_COSIGN_KEY"));
    assert!(output.contains("SIGSTORE_ID_TOKEN"));
    assert!(output.contains("PERMANU_SIGSTORE_ID_TOKEN"));
}

#[test]
fn ci_job_native_cosign_sign_blob_creates_bundle_signature_and_certificate_sidecars() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-cosign-sign");
    let artifact_store = managed_tempfile_like_dir("ci-cosign-artifact-store");
    let fake_bin = managed_tempfile_like_dir("ci-cosign-bin");
    let fake_log = fake_bin.join("cosign-args.log");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(workspace.join("dist/dwaar-linux-amd64"), b"release-binary").expect("write artifact");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );
    install_fake_cosign(&fake_bin);

    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }

    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"env":{{"PATH":{},"PERMANU_FAKE_COSIGN_LOG":{},"PERMANU_SIGSTORE_ID_TOKEN":"token-from-runner"}},"secret_keys":["PERMANU_SIGSTORE_ID_TOKEN"],"steps":[{{"step_db_id":"s1","step_index":0,"name":"sign","uses":"permanu/cosign-sign-blob@v1","with":{{"path":"dist/"}}}},{{"step_db_id":"s2","step_index":1,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dwaar-signed","path":"dist/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path"),
        serde_json::to_string(&path_value).expect("json path env"),
        serde_json::to_string(fake_log.to_str().expect("utf8 log path")).expect("json log path")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert_eq!(output["step_statuses"]["s1"], "success");
    assert_eq!(output["step_statuses"]["s2"], "success");
    let sign_log = output["step_logs"]["s1"].as_str().expect("sign step log");
    assert!(sign_log.contains("signed dist/dwaar-linux-amd64"));
    assert!(!sign_log.contains("token-from-runner"));

    let storage_path = output["artifacts"][0]["storage_path"]
        .as_str()
        .expect("storage path");
    let signed_dist = artifact_store.join(storage_path).join("dist");
    assert!(signed_dist.join("dwaar-linux-amd64").is_file());
    assert!(signed_dist.join("dwaar-linux-amd64.bundle").is_file());
    assert!(signed_dist.join("dwaar-linux-amd64.sig").is_file());
    assert!(signed_dist.join("dwaar-linux-amd64.cert").is_file());

    let args_log = fs::read_to_string(fake_log).expect("fake cosign args log");
    assert!(args_log.contains("sign-blob"));
    assert!(args_log.contains("--bundle"));
    assert!(args_log.contains("dwaar-linux-amd64.bundle"));
    assert!(args_log.contains("--output-signature"));
    assert!(args_log.contains("dwaar-linux-amd64.sig"));
    assert!(args_log.contains("--output-certificate"));
    assert!(args_log.contains("dwaar-linux-amd64.cert"));
}

#[test]
fn ci_job_native_cosign_sign_blob_uses_kms_key_and_redacts_signing_secrets() {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let workspace = managed_tempfile_like_dir("ci-cosign-kms-sign");
    let artifact_store = managed_tempfile_like_dir("ci-cosign-kms-artifact-store");
    let fake_bin = managed_tempfile_like_dir("ci-cosign-kms-bin");
    let fake_log = fake_bin.join("cosign-args.log");
    fs::create_dir_all(workspace.join("dist")).expect("create dist");
    fs::write(workspace.join("dist/dwaar-linux-amd64"), b"release-binary").expect("write artifact");
    let _artifact_store_env = EnvVarGuard::set(
        "PERMANU_ACTIONS_ARTIFACTS_DIR",
        artifact_store.to_str().expect("utf8 artifact store"),
    );
    install_fake_cosign(&fake_bin);

    let mut path_value = fake_bin.to_string_lossy().to_string();
    if let Ok(existing_path) = std::env::var("PATH") {
        path_value.push(':');
        path_value.push_str(&existing_path);
    }

    let kms_key = "awskms://arn:aws:kms:us-east-1:111122223333:key/key-token-secret";
    let cosign_password = "cosign-password-secret";
    let payload = format!(
        r#"{{"job_db_id":"job-1","run_db_id":"run-1","job_id_yaml":"release","clone_dir":{},"timeout_seconds":5,"env":{{"PATH":{},"PERMANU_FAKE_COSIGN_LOG":{},"PERMANU_FAKE_COSIGN_ECHO_SECRETS":"1","PERMANU_COSIGN_KEY":{},"COSIGN_PASSWORD":{}}},"steps":[{{"step_db_id":"s1","step_index":0,"name":"kms sign","uses":"permanu/cosign-sign-blob@v1","with":{{"path":"dist/"}}}},{{"step_db_id":"s2","step_index":1,"name":"upload","uses":"actions/upload-artifact@v4","with":{{"name":"dwaar-kms-signed","path":"dist/"}}}}]}}"#,
        serde_json::to_string(workspace.to_str().expect("utf8 path")).expect("json path"),
        serde_json::to_string(&path_value).expect("json path env"),
        serde_json::to_string(fake_log.to_str().expect("utf8 log path")).expect("json log path"),
        serde_json::to_string(kms_key).expect("json key"),
        serde_json::to_string(cosign_password).expect("json password")
    );

    let result = job_deployment::handle_ci_job("cmd-1", payload.as_bytes());
    let output: Value = serde_json::from_slice(&result.output).expect("json output");

    assert_eq!(
        result.status,
        "completed",
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(output["conclusion"], "success");
    assert_eq!(output["step_statuses"]["s2"], "success");
    let sign_log = output["step_logs"]["s1"].as_str().expect("sign step log");
    assert!(sign_log.contains("signed dist/dwaar-linux-amd64"));
    assert!(!sign_log.contains(kms_key));
    assert!(!sign_log.contains(cosign_password));
    assert!(sign_log.contains("***"));
    let storage_path = output["artifacts"][0]["storage_path"]
        .as_str()
        .expect("storage path");
    let signed_dist = artifact_store.join(storage_path).join("dist");
    assert!(signed_dist.join("dwaar-linux-amd64.bundle").is_file());
    assert!(!signed_dist.join("dwaar-linux-amd64.sig").exists());
    assert!(!signed_dist.join("dwaar-linux-amd64.cert").exists());

    let args_log = fs::read_to_string(fake_log).expect("fake cosign args log");
    assert!(args_log.contains("sign-blob --key"));
    assert!(args_log.contains("--bundle"));
    assert!(args_log.contains(kms_key));
    assert!(!args_log.contains("--output-certificate"));
    assert!(!args_log.contains("--output-signature"));
}

#[test]
fn ci_job_rejects_implicit_shell_syntax() {
    let result = job_deployment::handle_ci_job(
        "cmd-1",
        br#"{"job_db_id":"job-1","steps":[{"step_db_id":"s1","step_index":0,"run":"echo ok; rm -rf /"}]}"#,
    );
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "failed");
    assert!(output.contains("unsupported shell syntax"));
}

#[cfg(unix)]
fn install_fake_cosign(fake_bin: &std::path::Path) {
    let script = fake_bin.join("cosign");
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "version" ]; then
  echo "cosign fake"
  exit 0
fi
printf '%s\n' "$*" >> "$PERMANU_FAKE_COSIGN_LOG"
bundle=""
sig=""
cert=""
key=""
target=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    sign-blob|--yes)
      shift
      ;;
    --key)
      key="$2"
      shift 2
      ;;
    --key=*)
      key="${1#--key=}"
      shift
      ;;
    --bundle)
      bundle="$2"
      shift 2
      ;;
    --output-signature)
      sig="$2"
      shift 2
      ;;
    --output-certificate)
      cert="$2"
      shift 2
      ;;
    *)
      target="$1"
      shift
      ;;
  esac
done
if [ -z "$key" ]; then
  test -n "${SIGSTORE_ID_TOKEN:-}"
fi
printf 'bundle for %s' "$target" > "$bundle"
if [ -n "$sig" ]; then
  printf 'signature for %s' "$target" > "$sig"
fi
if [ -n "$cert" ]; then
  printf 'certificate for %s' "$target" > "$cert"
fi
if [ "${PERMANU_FAKE_COSIGN_ECHO_SECRETS:-}" = "1" ]; then
  printf 'fake key=%s envkey=%s password=%s token=%s\n' "$key" "${PERMANU_COSIGN_KEY:-}${COSIGN_KEY:-}" "${COSIGN_PASSWORD:-}" "${SIGSTORE_ID_TOKEN:-}"
fi
echo "fake signed $target"
"#,
    )
    .expect("write fake cosign");
    let mut permissions = fs::metadata(&script)
        .expect("fake cosign metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake cosign");
}

#[cfg(not(unix))]
fn install_fake_cosign(_fake_bin: &std::path::Path) {
    panic!("fake cosign test requires a Unix shell");
}

#[cfg(unix)]
fn install_fake_docker(
    fake_bin: &std::path::Path,
    fake_log: &std::path::Path,
    inspect_status: &str,
) {
    let script = fake_bin.join("docker");
    let fake_log = fake_log.to_str().expect("utf8 fake docker log path");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{fake_log}"
case "${{1:-}}" in
  run)
    if [ "${{2:-}}" = "--detach" ]; then
      printf 'fake-container-id\n'
    else
      printf 'fake job output\n'
    fi
    ;;
  inspect)
    printf '%s\n' "{inspect_status}"
    ;;
  network|rm)
    printf 'ok\n'
    ;;
esac
"#,
        ),
    )
    .expect("write fake docker");
    let mut permissions = fs::metadata(&script)
        .expect("fake docker metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake docker");
}

#[cfg(unix)]
fn install_fake_docker_with_config_logging(
    fake_bin: &std::path::Path,
    fake_log: &std::path::Path,
    inspect_status: &str,
) {
    let script = fake_bin.join("docker");
    let fake_log = fake_log.to_str().expect("utf8 fake docker log path");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
printf '%s %s %s\n' "DOCKER_CONFIG" "${{1:-}}" "${{DOCKER_CONFIG:-}}" >> "{fake_log}"
case "${{1:-}}" in
  login)
    mkdir -p "${{DOCKER_CONFIG:?}}"
    cat > "$DOCKER_CONFIG/config.json"
    printf 'ok\n'
    ;;
  run)
    if [ "${{2:-}}" = "--detach" ]; then
      printf 'fake-container-id\n'
    else
      printf 'fake job output\n'
    fi
    ;;
  inspect)
    printf '%s\n' "{inspect_status}"
    ;;
  network|rm)
    printf 'ok\n'
    ;;
esac
"#,
        ),
    )
    .expect("write fake docker");
    let mut permissions = fs::metadata(&script)
        .expect("fake docker metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake docker");
}

fn managed_tempfile_like_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::path::Path::new("/tmp/permanu-ci/test").join(format!(
        "permanu-agent-rs-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn ci_job_times_out_bounded_command() {
    let result = job_deployment::handle_ci_job(
        "cmd-1",
        br#"{"job_db_id":"job-1","timeout_seconds":1,"steps":[{"step_db_id":"s1","step_index":0,"run":"sleep 5"}]}"#,
    );
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "failed");
    assert!(output.contains("timed out"));
}

#[test]
fn swarm_deploy_rejects_host_path_bind_mounts() {
    let err = parse_swarm_deploy(
        br#"{"stack_name":"permanu-postgres","compose_content":"services:\n  db:\n    image: postgres\n    volumes:\n      - /etc/passwd:/host/passwd\n"}"#,
    )
    .unwrap_err();

    assert!(err.contains("host path"));
}

#[test]
fn swarm_deploy_builds_fixed_docker_stack_argv() {
    let payload = parse_swarm_deploy(
        br#"{"stack_name":"permanu-postgres","compose_content":"services:\n  db:\n    image: postgres\n","prune":true,"resolve_image":"changed","detach":false}"#,
    )
    .expect("parse swarm deploy");
    let args = build_swarm_deploy_args(
        &payload,
        "/opt/permanu-agent/deployments/swarm/permanu-postgres",
    );

    assert_eq!(
        args,
        vec![
            "stack",
            "deploy",
            "--compose-file",
            "/opt/permanu-agent/deployments/swarm/permanu-postgres/stack.yaml",
            "--prune",
            "--resolve-image",
            "changed",
            "--detach=false",
            "permanu-postgres"
        ]
    );
}

#[test]
fn swarm_status_and_rollback_validate_stack_scoped_names() {
    assert_eq!(
        parse_swarm_remove(br#"{"stack_name":"permanu-postgres"}"#).expect("parse remove"),
        "permanu-postgres"
    );
    assert_eq!(
        parse_swarm_status(br#"{"stack_name":"permanu-postgres"}"#).expect("parse status"),
        "permanu-postgres"
    );
    assert_eq!(
        parse_swarm_rollback(br#"{"stack_name":"permanu-postgres","service_name":"haproxy"}"#)
            .expect("parse rollback"),
        ("permanu-postgres".to_string(), "haproxy".to_string())
    );
    assert_eq!(
        swarm_stack_dir("permanu-postgres").expect("stack dir"),
        std::path::PathBuf::from("/opt/permanu-agent/deployments/swarm/permanu-postgres")
    );
    assert_eq!(
        build_swarm_remove_args("permanu-postgres").expect("remove args"),
        vec![
            "stack".to_string(),
            "rm".to_string(),
            "permanu-postgres".to_string()
        ]
    );
    assert_eq!(
        build_swarm_status_args("permanu-postgres").expect("status args"),
        (
            vec![
                "stack".to_string(),
                "services".to_string(),
                "permanu-postgres".to_string(),
                "--format".to_string(),
                "{{json .}}".to_string()
            ],
            vec![
                "stack".to_string(),
                "ps".to_string(),
                "permanu-postgres".to_string(),
                "--no-trunc".to_string(),
                "--format".to_string(),
                "{{json .}}".to_string()
            ]
        )
    );

    assert_eq!(
        build_swarm_rollback_args("permanu-postgres", "haproxy").expect("rollback args"),
        vec!["service", "rollback", "permanu-postgres_haproxy"]
    );

    let err = build_swarm_rollback_args("permanu-postgres", "other_stack_haproxy").unwrap_err();
    assert!(err.contains("outside stack"));
}

#[test]
fn app_proxy_payloads_are_route_wrappers_with_strict_names() {
    let setup = parse_app_proxy_setup(
        br#"{"slug":"api","container_name":"deploy-app-api-abc123","port":3000,"domains":["api.example.com"]}"#,
    )
    .expect("parse app proxy setup");
    assert_eq!(
        setup.default_route_host("internal.example"),
        "api.internal.example"
    );
    assert_eq!(setup.upstream, "deploy-app-api-abc123:3000");
    assert_eq!(
        render_app_proxy_snippet(&setup, "internal.example"),
        "# App: api\napi.internal.example {\n    reverse_proxy deploy-app-api-abc123:3000\n}\n\napi.example.com {\n    reverse_proxy deploy-app-api-abc123:3000\n}\n"
    );

    let remove = parse_app_proxy_remove(br#"{"slug":"api"}"#).expect("parse app proxy remove");
    assert_eq!(remove.slug, "api");

    let err = parse_app_proxy_setup(
        b"{\"slug\":\"api/../../bad\",\"container_name\":\"deploy-app-api\",\"port\":3000,\"domains\":[]}",
    )
    .unwrap_err();
    assert!(err.contains("invalid slug"));
}

#[test]
fn env_keys_are_validated_before_process_plans_are_created() {
    let mut env = BTreeMap::new();
    env.insert("BAD-KEY".to_string(), "value".to_string());

    let err = job_deployment::validate_env(&env).unwrap_err();
    assert!(err.contains("invalid env key"));
}

#[test]
fn command_result_completed_is_command_result_compatible() {
    let result = AgentCommandResult::completed("cmd-1", "ok");
    assert_eq!(result.status, "completed");
    assert!(result.is_final);
}

#[tokio::test]
async fn run_invocation_captures_bounded_output() {
    let output = run_invocation(&CommandInvocation {
        program: "printf".to_string(),
        args: vec!["hello".to_string()],
        work_dir: None,
        env: BTreeMap::new(),
        host_env: BTreeMap::new(),
        timeout_seconds: 5,
    })
    .await
    .expect("run invocation");

    assert!(output.status_success);
    assert_eq!(output.output, "hello");
}
