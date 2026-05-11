#[path = "../src/proto.rs"]
mod proto;
#[allow(dead_code)]
#[path = "../src/sre_tools.rs"]
mod sre_tools;
#[allow(dead_code)]
#[path = "../src/timeutil.rs"]
mod timeutil;

use serde_json::{json, Value};
use sre_tools::{
    parse_proc_net_tcp, parse_ps_rows, parse_request, redact_value, DiagnosticKind, MAX_LIMIT,
};

#[test]
fn payload_validation_accepts_all_supported_kinds_and_caps_limits() {
    let kinds = [
        "agent.host.snapshot",
        "agent.metrics.sample",
        "agent.processes.top",
        "agent.process.inspect",
        "agent.network.listeners",
        "agent.network.connections",
        "agent.dns.check",
        "agent.http.probe",
        "agent.tls.inspect",
        "agent.logs.tail",
        "agent.journal.query",
        "agent.service.status",
        "agent.containers.list",
        "agent.container.inspect",
        "agent.container.logs",
        "agent.file.stat",
        "agent.config.digest",
        "agent.package.inventory",
        "agent.permanu.self.status",
        "agent.command.history",
        "agent.audit.local",
        "agent.resource.alerts",
        "agent.trace.route",
        "agent.safe_probe.tcp",
    ];

    for kind in kinds {
        let request = parse_request(
            json!({
                "kind": kind,
                "limit": 9999,
                "pid": 1,
                "host": "127.0.0.1",
                "port": 443,
                "path": "/etc/dwaar/Dwaarfile",
                "unit": "permanu-agent",
                "container": "permanu-app_1",
                "target": "127.0.0.1",
                "url": "http://127.0.0.1:8080/health"
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap_or_else(|err| panic!("{kind} should validate: {err}"));

        assert_eq!(request.kind.as_str(), kind);
        assert!(request.limit <= MAX_LIMIT);
    }

    let err = parse_request(br#"{"kind":"agent.unknown"}"#).unwrap_err();
    assert!(err.to_string().contains("unsupported kind"));
}

#[test]
fn validation_enforces_read_only_allowlists() {
    let err = parse_request(br#"{"kind":"agent.journal.query","unit":"nginx"}"#).unwrap_err();
    assert!(err.to_string().contains("unit"));

    let err = parse_request(br#"{"kind":"agent.file.stat","path":"/etc/shadow"}"#).unwrap_err();
    assert!(err.to_string().contains("path"));

    let err = parse_request(br#"{"kind":"agent.http.probe","url":"http://169.254.169.254/"}"#)
        .unwrap_err();
    assert!(err.to_string().contains("host"));

    let err = parse_request(br#"{"kind":"agent.tls.inspect","host":"example.com","port":443}"#)
        .unwrap_err();
    assert!(err.to_string().contains("host"));

    let err = parse_request(br#"{"kind":"agent.safe_probe.tcp","host":"example.com","port":22}"#)
        .unwrap_err();
    assert!(err.to_string().contains("port"));
}

#[test]
fn redaction_masks_secret_keys_and_sensitive_values() {
    let redacted = redact_value(json!({
        "token": "abc123",
        "nested": {
            "database_url": "postgres://user:pass@example.com/db",
            "authorization": "Bearer secret",
            "plain": "hello"
        },
        "items": [
            {"api_key": "secret"},
            {"message": "password=my-secret TOKEN=abc"}
        ]
    }));

    assert_eq!(redacted["token"], Value::String("[REDACTED]".to_string()));
    assert_eq!(
        redacted["nested"]["database_url"],
        Value::String("[REDACTED]".to_string())
    );
    assert_eq!(
        redacted["nested"]["authorization"],
        Value::String("[REDACTED]".to_string())
    );
    assert_eq!(
        redacted["nested"]["plain"],
        Value::String("hello".to_string())
    );
    assert_eq!(
        redacted["items"][0]["api_key"],
        Value::String("[REDACTED]".to_string())
    );
    assert_eq!(
        redacted["items"][1]["message"],
        Value::String("password=[REDACTED] TOKEN=[REDACTED]".to_string())
    );
}

#[test]
fn proc_net_tcp_parser_extracts_bounded_socket_rows() {
    let rows = parse_proc_net_tcp(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
           0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1\n\
           1: 00000000:01BB 0200007F:CEA2 01 00000000:00000000 00:00000000 00000000 1000 0 12346 1\n",
        10,
    );

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].local_addr, "127.0.0.1");
    assert_eq!(rows[0].local_port, 8080);
    assert_eq!(rows[0].state, "listen");
    assert_eq!(rows[1].local_port, 443);
    assert_eq!(rows[1].remote_addr, "127.0.0.2");
    assert_eq!(rows[1].state, "established");
}

#[test]
fn ps_parser_skips_bad_rows_and_redacts_commands() {
    let rows = parse_ps_rows(
        "PID USER COMMAND %CPU %MEM RSS\n\
         42 root /usr/bin/app --token abc --mode prod 1.5 2.0 2048\n\
         bad row\n",
        5,
    );

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pid, 42);
    assert_eq!(rows[0].user, "root");
    assert!(rows[0].command.contains("--token [REDACTED]"));
    assert_eq!(rows[0].cpu_percent, 1.5);
    assert_eq!(rows[0].rss_kib, 2048);
}

#[test]
fn diagnostic_kind_round_trips_canonical_strings() {
    let request = parse_request(br#"{"kind":"agent.metrics.sample"}"#).unwrap();
    assert_eq!(request.kind, DiagnosticKind::MetricsSample);
    assert_eq!(request.kind.as_str(), "agent.metrics.sample");
}

#[test]
fn backend_shaped_payloads_validate_without_legacy_field_names() {
    for payload in [
        br#"{"kind":"agent.service.status","service":"docker"}"#.as_slice(),
        br#"{"kind":"agent.logs.tail","source":"permanu-agent","lines":20}"#.as_slice(),
        br#"{"kind":"agent.config.digest","target":"dwaar"}"#.as_slice(),
        br#"{"kind":"agent.dns.check","hostname":"localhost"}"#.as_slice(),
        br#"{"kind":"agent.http.probe","url":"http://127.0.0.1:8080/health","method":"HEAD"}"#
            .as_slice(),
    ] {
        parse_request(payload).unwrap_or_else(|err| panic!("payload should validate: {err}"));
    }
}

#[test]
fn every_agent_tool_accepts_its_mcp_schema_shaped_minimal_payload() {
    let payloads = [
        json!({"kind":"agent.host.snapshot"}),
        json!({"kind":"agent.metrics.sample","metrics":["cpu","memory"],"window":"1m","interval_seconds":5}),
        json!({"kind":"agent.processes.top","limit":10,"sort_by":"io"}),
        json!({"kind":"agent.process.inspect","pid":1,"include":["limits","env_summary"]}),
        json!({"kind":"agent.network.listeners","protocol":"tcp","include_process":true}),
        json!({"kind":"agent.network.connections","protocol":"tcp","state":"established","limit":25}),
        json!({"kind":"agent.dns.check","hostname":"localhost","record_type":"A","resolver":"system"}),
        json!({"kind":"agent.http.probe","url":"https://127.0.0.1:8443/health","method":"HEAD","timeout_seconds":5}),
        json!({"kind":"agent.tls.inspect","host":"127.0.0.1","port":443,"server_name":"localhost"}),
        json!({"kind":"agent.logs.tail","source":"syslog","lines":20,"since":"15m"}),
        json!({"kind":"agent.journal.query","unit":"ssh","priority":"err","since":"15m","lines":20}),
        json!({"kind":"agent.service.status","service":"postgresql","include_logs":true}),
        json!({"kind":"agent.containers.list","runtime":"docker","all":true,"limit":20}),
        json!({"kind":"agent.container.inspect","container":"permanu-app_1","include":["state","networks"]}),
        json!({"kind":"agent.container.logs","container":"permanu-app_1","lines":20,"since":"15m","timestamps":true}),
        json!({"kind":"agent.file.stat","path":"/etc/dwaar/Dwaarfile","hash":true}),
        json!({"kind":"agent.config.digest","target":"systemd","include_hash":true}),
        json!({"kind":"agent.package.inventory","manager":"auto","query":"docker","limit":20}),
        json!({"kind":"agent.permanu.self.status","component":"all","include_version":true}),
        json!({"kind":"agent.command.history","status":"all","limit":20}),
        json!({"kind":"agent.audit.local","source":"permanu","since":"1h","limit":20}),
        json!({"kind":"agent.resource.alerts","severity":"all","resource":"all","limit":20}),
        json!({"kind":"agent.trace.route","host":"127.0.0.1","port":443,"protocol":"tcp","max_hops":16}),
        json!({"kind":"agent.safe_probe.tcp","host":"127.0.0.1","port":443,"timeout_seconds":5}),
    ];

    for payload in payloads {
        parse_request(payload.to_string().as_bytes())
            .unwrap_or_else(|err| panic!("{payload} should validate: {err}"));
    }
}

#[test]
fn legacy_host_diagnostic_kinds_remain_supported() {
    let processes = parse_request(br#"{"kind":"process_list"}"#).unwrap();
    assert_eq!(processes.kind, DiagnosticKind::ProcessesTop);

    let listeners = parse_request(br#"{"kind":"listeners"}"#).unwrap();
    assert_eq!(listeners.kind, DiagnosticKind::NetworkListeners);

    let journal =
        parse_request(br#"{"kind":"journal_tail","unit":"permanu-agent","lines":20}"#).unwrap();
    assert_eq!(journal.kind, DiagnosticKind::JournalQuery);
}
