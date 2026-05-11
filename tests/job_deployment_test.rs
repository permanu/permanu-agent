#[path = "../src/job_deployment.rs"]
mod job_deployment;

use std::collections::BTreeMap;

use job_deployment::{
    build_release_hook_invocations, build_swarm_deploy_args, build_swarm_remove_args,
    build_swarm_rollback_args, build_swarm_status_args, parse_app_proxy_remove,
    parse_app_proxy_setup, parse_ci_job, parse_run_hooks, parse_swarm_deploy, parse_swarm_remove,
    parse_swarm_rollback, parse_swarm_status, render_app_proxy_snippet, run_invocation,
    swarm_stack_dir, AgentCommandResult, CommandInvocation,
};

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
        br#"{"job_db_id":"job-1","job_id_yaml":"build","clone_dir":"/tmp/app","timeout_seconds":5,"env":{"BASE":"job"},"matrix_values":{"TARGET":"linux"},"steps":[{"step_db_id":"s1","step_index":0,"name":"show env","run":"printf ok","env":{"BASE":"step"}}]}"#,
    )
    .expect("parse ci job");

    assert_eq!(job.job_db_id, "job-1");
    assert_eq!(job.job_id_yaml, "build");
    assert_eq!(job.clone_dir, "/tmp/app");
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
fn ci_job_executes_explicit_shell_and_redacts_secret_output() {
    let payload = br#"{"job_db_id":"job-1","clone_dir":"/tmp","timeout_seconds":5,"env":{"TOKEN":"s3cr3t-value"},"matrix_values":{"TARGET":"linux"},"secret_keys":["TOKEN"],"steps":[{"step_db_id":"s1","step_index":0,"name":"show env","run":"printf '%s %s' \"$TOKEN\" \"$TARGET\"","shell":"sh"}]}"#;

    let result = job_deployment::handle_ci_job("cmd-1", payload);
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "completed");
    assert!(output.contains("*** linux"));
    assert!(!output.contains("s3cr3t-value"));
    assert!(output.contains("[show env] completed successfully"));
}

#[test]
fn ci_job_rejects_implicit_shell_syntax() {
    let result = job_deployment::handle_ci_job(
        "cmd-1",
        br#"{"job_db_id":"job-1","clone_dir":"/tmp","steps":[{"step_db_id":"s1","step_index":0,"run":"echo ok; rm -rf /"}]}"#,
    );
    let output = String::from_utf8(result.output).expect("utf8 output");

    assert_eq!(result.status, "failed");
    assert!(output.contains("unsupported shell syntax"));
}

#[test]
fn ci_job_times_out_bounded_command() {
    let result = job_deployment::handle_ci_job(
        "cmd-1",
        br#"{"job_db_id":"job-1","clone_dir":"/tmp","timeout_seconds":1,"steps":[{"step_db_id":"s1","step_index":0,"run":"sleep 5"}]}"#,
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
        timeout_seconds: 5,
    })
    .await
    .expect("run invocation");

    assert!(output.status_success);
    assert_eq!(output.output, "hello");
}
