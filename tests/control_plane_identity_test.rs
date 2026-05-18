#![allow(dead_code)]

#[path = "../src/control_plane_identity.rs"]
mod control_plane_identity;

use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use control_plane_identity::{
    handle_bootstrap_secrets_with_decryptor, handle_rotate_agent_secret_with_decryptor,
    handle_rotate_secrets_with_decryptor, line_contains_credential_token, parse_reenroll_payload,
    rewrite_agent_env_file, sanitise_reenroll_output, validate_install_url, write_reenroll_script,
    CloudflareTokenOptions, CommandStatus, SystemCommand,
};

#[derive(Default)]
struct RecordingCommand {
    calls: Vec<Vec<String>>,
}

impl SystemCommand for RecordingCommand {
    fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        self.calls.push(
            std::iter::once(program.to_string())
                .chain(args.iter().map(|arg| arg.to_string()))
                .collect(),
        );
        Ok(Vec::new())
    }
}

#[test]
fn bootstrap_secrets_applies_token_and_updates_apex_without_leaking_secret() {
    let dir = tempfile_dir("bootstrap");
    let token_path = dir.join("cf-token");
    let drop_in_dir = dir.join("dwaar.service.d");
    let payload =
        br#"{"cf_token_enc":"c2VhbGVk","cf_token_env":"CF_API_TOKEN","internal_apex":"permanu.app"}"#;
    let mut command = RecordingCommand::default();

    let result = handle_bootstrap_secrets_with_decryptor(
        "cmd-bootstrap",
        payload,
        CloudflareTokenOptions::new(&token_path, &drop_in_dir, &mut command),
        |sealed| {
            assert_eq!(sealed, b"sealed");
            Ok("super-secret-cf-token\n".to_string())
        },
    )
    .expect("bootstrap secrets");

    assert_eq!(result.status, CommandStatus::Completed);
    assert_eq!(result.output_text(), "cf_token_applied");
    assert_eq!(result.internal_apex.as_deref(), Some("permanu.app"));
    assert!(!result.output_text().contains("super-secret"));
    assert_eq!(
        fs::read_to_string(&token_path).expect("read token"),
        "super-secret-cf-token"
    );
    assert!(fs::read_to_string(drop_in_dir.join("cf-token.conf"))
        .expect("read drop-in")
        .contains("Environment=DWAAR_CLOUDFLARE_API_TOKEN_FILE="));
    assert!(command
        .calls
        .iter()
        .any(|call| call == &["systemctl", "daemon-reload"]));
    assert!(command
        .calls
        .iter()
        .any(|call| call == &["systemctl", "reload", "dwaar"]));
    assert_secure_mode(&token_path, 0o600);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rotate_secrets_skips_write_and_reload_when_token_is_unchanged() {
    let dir = tempfile_dir("rotate-unchanged");
    let token_path = dir.join("cf-token");
    let drop_in_dir = dir.join("dwaar.service.d");
    fs::create_dir_all(&drop_in_dir).expect("mkdir drop-in");
    fs::write(&token_path, "stable-token").expect("seed token");
    fs::write(
        drop_in_dir.join("cf-token.conf"),
        format!(
            "[Service]\nEnvironment=DWAAR_CLOUDFLARE_API_TOKEN_FILE={}\n",
            token_path.display()
        ),
    )
    .expect("seed drop-in");
    let mut command = RecordingCommand::default();

    let result = handle_rotate_secrets_with_decryptor(
        "cmd-rotate",
        br#"{"cf_token_enc":"cm90YXRlZA==","cf_token_env":"CF_API_TOKEN"}"#,
        CloudflareTokenOptions::new(&token_path, &drop_in_dir, &mut command),
        |_| Ok("stable-token".to_string()),
    )
    .expect("rotate secrets");

    assert_eq!(result.status, CommandStatus::Completed);
    assert_eq!(result.output_text(), "cf_token_unchanged");
    assert!(
        command.calls.is_empty(),
        "unchanged token must not run system commands"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rotate_agent_secret_rewrites_env_and_requests_restart() {
    let dir = tempfile_dir("rotate-agent-secret");
    let env_path = dir.join("permanu-agent.env");
    fs::write(
        &env_path,
        "SERVER_ID=old-server\nAGENT_SECRET=old-secret\nOTHER_VAR=preserved\n",
    )
    .expect("seed env");

    let result = handle_rotate_agent_secret_with_decryptor(
        "cmd-secret",
        br#"{"secret_enc":"bmV3"}"#,
        &env_path,
        "server-123",
        |_| Ok("new-secret-value".to_string()),
    )
    .expect("rotate agent secret");

    assert_eq!(result.status, CommandStatus::Completed);
    assert_eq!(result.output_text(), "agent_secret_rotated");
    assert_eq!(result.restart_agent_after, Some(Duration::from_secs(2)));
    let env = fs::read_to_string(&env_path).expect("read env");
    assert!(env.contains("SERVER_ID=server-123\n"));
    assert!(env.contains("AGENT_SECRET=new-secret-value\n"));
    assert!(env.contains("OTHER_VAR=preserved\n"));
    assert!(!result.output_text().contains("new-secret-value"));
    assert_secure_mode(&env_path, 0o600);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn payload_validation_rejects_injection_and_path_traversal_inputs() {
    let dir = tempfile_dir("validation");
    let env_path = dir.join("permanu-agent.env");

    let env_err = rewrite_agent_env_file(&env_path, "server-1", "secret\nbad").unwrap_err();
    assert!(env_err.to_string().contains("AGENT_SECRET"));

    let reenroll_err = parse_reenroll_payload(
        br#"{"install_url":"https://example.com/install"}"#,
        "../bad",
    )
    .unwrap_err();
    assert!(reenroll_err.to_string().contains("command_id"));

    assert!(validate_install_url("http://example.com/install/token").is_err());
    assert!(validate_install_url("https://example.com/install/token\nx").is_err());
    assert!(validate_install_url("https://example.com/install/token").is_ok());
    assert!(validate_install_url("http://127.0.0.1:8080/install/token").is_ok());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn reenroll_script_is_written_executable_and_output_is_redacted() {
    let dir = tempfile_dir("reenroll");
    let payload = parse_reenroll_payload(
        br#"{"install_url":"https://control.example/install/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"}"#,
        "cmd-reenroll-1",
    )
    .expect("parse reenroll");

    let script_path = write_reenroll_script(&payload, b"#!/bin/sh\nexit 0\n", &dir)
        .expect("write reenroll script");

    assert_eq!(
        script_path.file_name().and_then(|name| name.to_str()),
        Some("permanu-reenroll-cmd-reenroll-1.sh")
    );
    assert_secure_mode(&script_path, 0o700);

    let install_segment = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
    assert!(line_contains_credential_token(&format!(
        "install token {install_segment}"
    )));
    let sanitised = sanitise_reenroll_output(&format!("ok\ninstall token {install_segment}\ndone"));
    assert!(!sanitised.contains(install_segment));
    assert!(sanitised.contains("[redacted"));

    let _ = fs::remove_dir_all(dir);
}

fn tempfile_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permanu-agent-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("mkdir temp");
    dir
}

fn assert_secure_mode(path: &Path, want: u32) {
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, want);
}
