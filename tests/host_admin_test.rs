#[path = "../src/host_admin.rs"]
mod host_admin;

use host_admin::{
    build_cert_rotate_steps, build_host_diagnostic_plan, build_tcp_proxy_config,
    build_uninstall_plan, parse_dwaar_config_patch, parse_lsof_output, parse_ss_output,
    plan_dwaar_config_patch, tcp_proxy_config_path, HostDiagnosticPlan, UninstallStep,
};

#[test]
fn process_list_uses_fixed_ps_argv_and_caps_limit() {
    let plan =
        build_host_diagnostic_plan(br#"{"kind":"process_list","limit":999,"sort_by":"mem"}"#)
            .expect("build process list plan");

    match plan {
        HostDiagnosticPlan::ProcessList { command, limit } => {
            assert_eq!(limit, 200);
            assert_eq!(command.program, "ps");
            assert_eq!(
                command.args,
                [
                    "-eo",
                    "pid,user,comm,pcpu,pmem,rss",
                    "--sort=-pmem",
                    "--no-headers"
                ]
            );
            assert!(command.timeout.as_secs() <= 30);
            assert!(command.max_output_bytes <= 1024 * 1024);
        }
        other => panic!("unexpected plan: {other:?}"),
    }
}

#[test]
fn journal_tail_requires_allowlisted_unit_and_caps_lines() {
    let err = build_host_diagnostic_plan(br#"{"kind":"journal_tail","unit":"ssh"}"#).unwrap_err();
    assert!(err.to_string().contains("allowlist"));

    let plan = build_host_diagnostic_plan(
        br#"{"kind":"journal_tail","unit":"dwaar","since":"25h","lines":9999}"#,
    )
    .unwrap_err();
    assert!(plan.to_string().contains("since must be"));

    let plan = build_host_diagnostic_plan(
        br#"{"kind":"journal_tail","unit":"dwaar","since":"24h","lines":9999}"#,
    )
    .expect("build journal plan");
    match plan {
        HostDiagnosticPlan::JournalTail {
            command,
            unit,
            since,
            lines,
        } => {
            assert_eq!(unit, "dwaar");
            assert_eq!(since.as_secs(), 24 * 60 * 60);
            assert_eq!(lines, 500);
            assert_eq!(command.program, "journalctl");
            assert_eq!(command.args[0..2], ["-u", "dwaar"]);
            assert!(command.args.contains(&"--no-pager".to_string()));
            assert!(!command.args.iter().any(|arg| arg.contains(';')));
        }
        other => panic!("unexpected plan: {other:?}"),
    }
}

#[test]
fn listener_parsers_extract_address_port_and_process() {
    let ss = r#"LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=42,fd=7))
LISTEN 0 128 [::]:443 [::]:* users:(("dwaar",pid=77,fd=8))"#;
    let entries = parse_ss_output(ss);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].addr, "0.0.0.0");
    assert_eq!(entries[0].port, 5432);
    assert_eq!(entries[0].pid, Some(42));
    assert_eq!(entries[0].command, Some("postgres".to_string()));
    assert_eq!(entries[1].addr, "[::]");
    assert_eq!(entries[1].port, 443);

    let lsof = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
postgres 123 postgres 7u IPv4 1 0t0 TCP 127.0.0.1:5432 (LISTEN)\n";
    let entries = parse_lsof_output(lsof);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].addr, "127.0.0.1");
    assert_eq!(entries[0].port, 5432);
    assert_eq!(entries[0].pid, Some(123));
    assert_eq!(entries[0].command, Some("postgres".to_string()));
}

#[test]
fn dwaar_patch_edits_only_allowlisted_one_line_blocks() {
    let input = "{\n    log_level { info }\n}\n";
    let payload = parse_dwaar_config_patch(
        br#"{"block":"analytics","action":"upsert","value":"endpoint http://localhost:9000"}"#,
    )
    .expect("parse patch");
    let planned = plan_dwaar_config_patch(input, &payload).expect("plan patch");

    assert_eq!(planned.result.prev, "");
    assert_eq!(planned.result.new, "endpoint http://localhost:9000");
    assert!(planned
        .content
        .contains("analytics { endpoint http://localhost:9000 }"));
    assert!(planned.content.find("analytics").unwrap() < planned.content.rfind('}').unwrap());

    let err = parse_dwaar_config_patch(
        b"{\"block\":\"analytics\",\"action\":\"upsert\",\"value\":\"ok\\nadmin off\"}",
    )
    .unwrap_err();
    assert!(err.to_string().contains("single line"));

    let err = parse_dwaar_config_patch(br#"{"block":"tls","action":"remove"}"#).unwrap_err();
    assert!(err.to_string().contains("allowlist"));
}

#[test]
fn tcp_proxy_config_validates_proxy_id_target_and_allowed_ips() {
    let err = tcp_proxy_config_path("../db").unwrap_err();
    assert!(err.to_string().contains("proxy_id"));

    let path = tcp_proxy_config_path("db-primary_1").expect("path");
    assert_eq!(path, "/etc/dwaar/apps/tcp-proxy-db-primary_1.dwaar");

    let config = build_tcp_proxy_config(
        "db-primary_1",
        15432,
        "172.18.0.8:5432",
        &["10.0.0.0/8".to_string(), "0.0.0.0/0".to_string()],
    )
    .expect("build config");
    assert!(config.contains("@allowed remote_ip 10.0.0.0/8"));
    assert!(config.contains("proxy 172.18.0.8:5432"));
    assert!(!config.contains("0.0.0.0/0"));

    let err = build_tcp_proxy_config("db", 15432, "bad target", &[]).unwrap_err();
    assert!(err.to_string().contains("target"));
}

#[test]
fn cert_rotate_builds_fixed_postgres_exec_steps() {
    let steps = build_cert_rotate_steps(
        br#"{"container_name":"deploy-postgres","service_type":"postgresql"}"#,
    )
    .expect("build steps");

    assert_eq!(steps.len(), 4);
    assert_eq!(steps[0].program, "docker");
    assert_eq!(steps[0].args[0..3], ["exec", "deploy-postgres", "openssl"]);
    assert!(steps[0].args.contains(&"/CN=deploy-postgres".to_string()));
    assert_eq!(steps[3].args[0..3], ["exec", "deploy-postgres", "sh"]);
    assert!(steps[3].args[4].contains("pg_ctl reload"));
    assert!(!steps[3].args[4].contains("deploy-postgres"));

    let err =
        build_cert_rotate_steps(br#"{"container_name":"deploy-postgres","service_type":"mysql"}"#)
            .unwrap_err();
    assert!(err.to_string().contains("unsupported service type"));
}

#[test]
fn uninstall_plan_has_fixed_argv_and_no_shell_pipeline() {
    let steps = build_uninstall_plan();
    assert!(steps.iter().any(|step| matches!(
        step,
        UninstallStep::DockerCleanup(cleanup) if cleanup.resource == "container"
    )));
    assert!(steps.iter().any(|step| matches!(
        step,
        UninstallStep::Command(command)
            if command.program == "systemctl" && command.args == ["stop", "permanu-agent"]
    )));
    assert!(steps.iter().any(|step| matches!(
        step,
        UninstallStep::Command(command)
            if command.program == "rm" && command.args == ["-rf", "/opt/permanu-agent"]
    )));

    for step in steps {
        if let UninstallStep::Command(command) = step {
            assert_ne!(command.program, "sh");
            assert_ne!(command.program, "bash");
            assert!(command.timeout.as_secs() <= 30);
            for arg in command.args {
                assert!(!arg.contains('|'), "pipeline leaked into argv: {arg}");
                assert!(
                    !arg.contains("&&"),
                    "shell operator leaked into argv: {arg}"
                );
            }
        }
    }
}
