#![allow(dead_code)]

#[path = "control_plane_identity_files.rs"]
mod control_plane_identity_files;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};

#[allow(unused_imports)]
pub use control_plane_identity_files::{
    apply_cloudflare_token, rewrite_agent_env_file, CloudflareApplySummary, CloudflareTokenOptions,
    RealSystemCommand, SystemCommand,
};

use control_plane_identity_files::{
    atomic_write_file, normalise_secret_value, reject_path_with_traversal, reject_symlink,
    token_matches_disk, validate_command_id_for_filename,
};

const DEFAULT_CF_TOKEN_ENV: &str = "CF_API_TOKEN";
const MAX_REENROLL_SCRIPT_BYTES: usize = 10 << 20;
const AGENT_RESTART_DELAY: Duration = Duration::from_secs(2);
const PREVIOUS_SERVER_ID_FILE: &str = "/var/lib/permanu/previous-server-id";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    Completed,
    Failed,
    Error,
    Running,
}

impl CommandStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Error => "error",
            Self::Running => "running",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentCommandResult {
    pub command_id: String,
    pub status: CommandStatus,
    pub output: Vec<u8>,
    pub is_final: bool,
    pub restart_agent_after: Option<Duration>,
    pub internal_apex: Option<String>,
}

impl AgentCommandResult {
    pub fn output_text(&self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReenrollPayload {
    pub install_url: String,
    pub command_id: String,
}

#[derive(Deserialize)]
struct SecretsPayload {
    #[serde(default)]
    cf_token_enc: String,
    #[serde(default)]
    cf_token_env: String,
    #[serde(default)]
    internal_apex: String,
}

#[derive(Deserialize)]
struct RotateAgentSecretPayload {
    #[serde(default)]
    secret_enc: String,
}

#[derive(Deserialize)]
struct RawReenrollPayload {
    #[serde(default)]
    install_url: String,
}

pub fn handle_bootstrap_secrets_with_decryptor<C, F>(
    command_id: &str,
    payload: &[u8],
    options: CloudflareTokenOptions<'_, C>,
    decrypt: F,
) -> Result<AgentCommandResult>
where
    C: SystemCommand + ?Sized,
    F: FnOnce(&[u8]) -> Result<String>,
{
    let parsed = parse_secrets_payload(payload, true)?;
    if parsed.sealed_token.is_empty() {
        return Ok(completed(command_id, "no_cf_token").with_internal_apex(parsed.internal_apex));
    }

    let token = decrypt(&parsed.sealed_token).context("bootstrap_secrets: decrypt")?;
    apply_cloudflare_token(&token, options)?;
    Ok(completed(command_id, "cf_token_applied").with_internal_apex(parsed.internal_apex))
}

pub fn handle_rotate_secrets_with_decryptor<C, F>(
    command_id: &str,
    payload: &[u8],
    options: CloudflareTokenOptions<'_, C>,
    decrypt: F,
) -> Result<AgentCommandResult>
where
    C: SystemCommand + ?Sized,
    F: FnOnce(&[u8]) -> Result<String>,
{
    let parsed = parse_secrets_payload(payload, false)?;
    if parsed.sealed_token.is_empty() {
        return Ok(completed(command_id, "no_cf_token").with_internal_apex(parsed.internal_apex));
    }

    let token = decrypt(&parsed.sealed_token).context("rotate_secrets: decrypt")?;
    let token = normalise_secret_value(&token, "CF token")?;
    if token_matches_disk(&options.token_path, &token)? {
        return Ok(
            completed(command_id, "cf_token_unchanged").with_internal_apex(parsed.internal_apex)
        );
    }

    apply_cloudflare_token(&token, options)?;
    Ok(completed(command_id, "cf_token_rotated").with_internal_apex(parsed.internal_apex))
}

pub fn handle_rotate_agent_secret_with_decryptor<F>(
    command_id: &str,
    payload: &[u8],
    env_path: impl AsRef<Path>,
    server_id: &str,
    decrypt: F,
) -> Result<AgentCommandResult>
where
    F: FnOnce(&[u8]) -> Result<String>,
{
    let payload: RotateAgentSecretPayload =
        serde_json::from_slice(payload).context("rotate_agent_secret: invalid payload")?;
    if payload.secret_enc.trim().is_empty() {
        bail!("rotate_agent_secret: secret_enc is required");
    }
    let sealed = decode_standard_base64(payload.secret_enc.trim(), "secret_enc")?;
    let secret = decrypt(&sealed).context("rotate_agent_secret: decrypt")?;
    rewrite_agent_env_file(env_path, server_id, &secret)?;

    Ok(completed(command_id, "agent_secret_rotated").with_restart(AGENT_RESTART_DELAY))
}

pub fn parse_reenroll_payload(payload: &[u8], command_id: &str) -> Result<ReenrollPayload> {
    let raw: RawReenrollPayload =
        serde_json::from_slice(payload).context("reenroll: invalid payload")?;
    let install_url = raw.install_url.trim();
    if install_url.is_empty() {
        bail!("reenroll: install_url is required");
    }
    validate_install_url(install_url)?;
    validate_command_id_for_filename(command_id)?;
    Ok(ReenrollPayload {
        install_url: install_url.to_string(),
        command_id: command_id.to_string(),
    })
}

/// Persists the current server_id to a well-known file before reenrollment.
/// This allows the new agent instance to carry forward its identity for
/// server relinking when the IP changes between installations.
pub fn persist_previous_server_id(server_id: &str) -> Result<()> {
    if server_id.trim().is_empty() || server_id == "probe" {
        return Ok(());
    }
    let path = Path::new(PREVIOUS_SERVER_ID_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create previous-server-id directory")?;
    }
    atomic_write_file(path, server_id.as_bytes(), 0o644)?;
    Ok(())
}

/// Reads the previously persisted server_id, if any. Returns None if the file
/// doesn't exist or can't be read (non-fatal).
pub fn read_previous_server_id() -> Option<String> {
    let path = Path::new(PREVIOUS_SERVER_ID_FILE);
    match std::fs::read_to_string(path) {
        Ok(id) if !id.trim().is_empty() => Some(id.trim().to_string()),
        Ok(_) | Err(_) => None,
    }
}

/// Appends the previous server_id as a query parameter to the install URL.
/// This allows the control plane to match the new installation to the old
/// server row and relink resources instead of creating an orphan.
pub fn append_previous_server_id_to_url(install_url: &str) -> String {
    let previous_id = match read_previous_server_id() {
        Some(id) => id,
        None => return install_url.to_string(),
    };
    let separator = if install_url.contains('?') { '&' } else { '?' };
    format!("{install_url}{separator}previous_server_id={previous_id}")
}

pub fn validate_install_url(raw: &str) -> Result<()> {
    if raw
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("install_url contains invalid characters");
    }
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| anyhow!("install_url must include a scheme"))?;
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    if host.is_empty() {
        bail!("install_url must include a host");
    }
    match scheme {
        "https" => Ok(()),
        "http" if is_loopback_host(host) => Ok(()),
        _ => bail!("install_url must use https"),
    }
}

pub fn write_reenroll_script(
    payload: &ReenrollPayload,
    script: &[u8],
    temp_dir: impl AsRef<Path>,
) -> Result<PathBuf> {
    if script.len() > MAX_REENROLL_SCRIPT_BYTES {
        bail!("reenroll installer exceeds maximum size");
    }
    validate_command_id_for_filename(&payload.command_id)?;
    let path = temp_dir
        .as_ref()
        .join(format!("permanu-reenroll-{}.sh", payload.command_id));
    reject_symlink(&path)?;
    atomic_write_file(&path, script, 0o700)?;
    Ok(path)
}

pub async fn download_installer_with_curl(install_url: &str) -> Result<Vec<u8>> {
    validate_install_url(install_url)?;
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--max-time",
            "60",
            install_url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn curl")?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("curl stdout unavailable"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = stdout.read(&mut chunk).await.context("read installer")?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > MAX_REENROLL_SCRIPT_BYTES {
            let _ = child.kill().await;
            bail!("reenroll installer exceeds maximum size");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let status = child.wait().await.context("wait curl")?;
    if !status.success() {
        bail!("curl installer download failed with status {status}");
    }
    Ok(buf)
}

pub async fn run_reenroll_script(script_path: &Path, timeout: Duration) -> Result<String> {
    reject_path_with_traversal(script_path)?;
    let child = Command::new("/bin/bash")
        .arg(script_path)
        .env("PERMANU_FORCE_REENROLL", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn reenroll installer")?;

    let run = async {
        let output = child.wait_with_output().await.context("wait installer")?;
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        let text = sanitise_reenroll_output(&String::from_utf8_lossy(&combined));
        if !output.status.success() {
            bail!("reenroll installer failed: {text}");
        }
        Ok(text)
    };
    tokio::time::timeout(timeout, run)
        .await
        .context("reenroll installer timed out")?
}

pub fn sanitise_reenroll_output(raw: &str) -> String {
    raw.lines()
        .map(|line| {
            if line_contains_credential_token(line) {
                "[redacted - line contains credential-like token]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn line_contains_credential_token(line: &str) -> bool {
    let mut run = 0usize;
    for byte in line.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') {
            run += 1;
            if run >= 40 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn parse_secrets_payload(payload: &[u8], _allow_internal_apex: bool) -> Result<ParsedSecrets> {
    let raw: SecretsPayload =
        serde_json::from_slice(payload).context("secrets: invalid payload")?;
    let env = if raw.cf_token_env.trim().is_empty() {
        DEFAULT_CF_TOKEN_ENV.to_string()
    } else {
        raw.cf_token_env.trim().to_string()
    };
    validate_env_var_name(&env)?;
    let internal_apex = if raw.internal_apex.trim().is_empty() {
        None
    } else {
        let apex = raw.internal_apex.trim().to_string();
        validate_internal_apex(&apex)?;
        Some(apex)
    };
    let sealed_token = if raw.cf_token_enc.trim().is_empty() {
        Vec::new()
    } else {
        decode_standard_base64(raw.cf_token_enc.trim(), "cf_token_enc")?
    };
    Ok(ParsedSecrets {
        sealed_token,
        internal_apex,
    })
}

struct ParsedSecrets {
    sealed_token: Vec<u8>,
    internal_apex: Option<String>,
}

fn decode_standard_base64(value: &str, field: &str) -> Result<Vec<u8>> {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("{field} contains invalid characters");
    }
    STANDARD
        .decode(value)
        .with_context(|| format!("{field} is not valid base64"))
}

fn validate_env_var_name(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        bail!("cf_token_env is required");
    };
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        bail!("cf_token_env must start with a letter or underscore");
    }
    if !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        bail!("cf_token_env contains invalid characters");
    }
    if value.len() > 128 {
        bail!("cf_token_env is too long");
    }
    Ok(())
}

fn validate_internal_apex(value: &str) -> Result<()> {
    if value.len() > 253
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'/' | b'\\' | b':' | b'\0'))
    {
        bail!("internal_apex contains invalid characters");
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("internal_apex is not a valid hostname");
        }
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn completed(command_id: &str, text: &str) -> AgentCommandResult {
    AgentCommandResult {
        command_id: command_id.to_string(),
        status: CommandStatus::Completed,
        output: text.as_bytes().to_vec(),
        is_final: true,
        restart_agent_after: None,
        internal_apex: None,
    }
}

impl AgentCommandResult {
    fn with_restart(mut self, delay: Duration) -> Self {
        self.restart_agent_after = Some(delay);
        self
    }

    fn with_internal_apex(mut self, apex: Option<String>) -> Self {
        self.internal_apex = apex;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn run_reenroll_script_sets_force_reenroll_env() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "permanu-reenroll-env-test-{}-{unique}.sh",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"#!/bin/sh
if [ "${PERMANU_FORCE_REENROLL:-}" = "1" ]; then
  echo forced
  exit 0
fi
echo missing-force-flag
exit 23
"#,
        )
        .expect("write test script");

        let result = run_reenroll_script(&path, Duration::from_secs(5)).await;
        let _ = fs::remove_file(&path);

        let output = result.expect("reenroll script should see PERMANU_FORCE_REENROLL=1");
        assert!(output.contains("forced"), "unexpected output: {output}");
    }
}
