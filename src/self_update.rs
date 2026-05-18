use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, read::DecoderReader};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::mpsc,
};
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::{
    config::Config,
    proto::agent::v1::{
        agent_service_client::AgentServiceClient, CommandResult, DownloadAgentBinaryRequest,
    },
    timeutil::now_timestamp,
};

const MAX_AGENT_BINARY_SIZE: u64 = 128 << 20;
const AGENT_BINARY_STREAM_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const RESTART_DELAY: Duration = Duration::from_millis(700);

#[derive(Debug, Deserialize)]
struct UpdatePayload {
    #[serde(default)]
    download_url: String,
    #[serde(default)]
    binary_base64: String,
    #[serde(default)]
    expected_checksum: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    arch: String,
}

#[derive(Debug, Eq, PartialEq)]
struct DownloadedBinary {
    bytes: u64,
    checksum: String,
}

struct TempUpdate {
    path: PathBuf,
    consumed: bool,
}

impl TempUpdate {
    fn new(target_path: &Path) -> Result<Self> {
        let dir = target_path
            .parent()
            .ok_or_else(|| anyhow!("target binary has no parent directory"))?;
        let file_name = target_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("permanu-agent");
        let pid = std::process::id();
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for attempt in 0..100u32 {
            let path = dir.join(format!(".{file_name}.update-{pid}-{seed}-{attempt}.tmp"));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    drop(file);
                    return Ok(Self {
                        path,
                        consumed: false,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err).context("create update tempfile"),
            }
        }
        bail!("could not allocate update tempfile in {}", dir.display())
    }
}

impl Drop for TempUpdate {
    fn drop(&mut self) {
        if !self.consumed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub async fn handle_update_agent(
    command_id: &str,
    payload: &[u8],
    cfg: &Config,
    client: AgentServiceClient<Channel>,
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    match update_agent(command_id, payload, cfg, client, tx).await {
        Ok(result) => result,
        Err(err) => failed_text(command_id, &format!("agent update failed: {err}")),
    }
}

async fn update_agent(
    command_id: &str,
    payload: &[u8],
    cfg: &Config,
    client: AgentServiceClient<Channel>,
    tx: mpsc::Sender<CommandResult>,
) -> Result<CommandResult> {
    let payload = parse_update_payload(payload)?;
    let target_path = resolve_current_binary()?;
    let mut temp = TempUpdate::new(&target_path)?;

    let downloaded = if !payload.binary_base64.is_empty() {
        send_running(
            &tx,
            command_id,
            &format!("decoding inline agent binary {}...", payload.version),
        )
        .await;
        write_base64_to_file(&payload.binary_base64, &temp.path).await?
    } else {
        match stream_agent_binary(cfg, client, &payload, &temp.path).await {
            Ok(downloaded) => downloaded,
            Err(err) if !payload.download_url.is_empty() => {
                warn!(error = ?err, "agent binary stream failed; falling back to download_url");
                send_running(
                    &tx,
                    command_id,
                    &format!("downloading agent {}...", payload.version),
                )
                .await;
                download_binary_with_curl(&payload.download_url, &temp.path).await?
            }
            Err(err) => return Err(err).context("agent binary stream"),
        }
    };

    if downloaded.checksum != payload.expected_checksum {
        bail!(
            "checksum mismatch: got {}, expected {}",
            downloaded.checksum,
            payload.expected_checksum
        );
    }

    send_running(&tx, command_id, "checksum verified, replacing binary...").await;
    install_tmp_binary(&temp.path, &target_path).context("replace binary")?;
    temp.consumed = true;

    info!(
        version = %payload.version,
        checksum = %downloaded.checksum,
        bytes = downloaded.bytes,
        target = %target_path.display(),
        "agent binary replaced"
    );
    schedule_restart();

    Ok(completed_text(
        command_id,
        &format!("updated to {}, restarting", payload.version),
    ))
}

fn parse_update_payload(payload: &[u8]) -> Result<UpdatePayload> {
    let mut payload: UpdatePayload = serde_json::from_slice(payload).context("invalid payload")?;
    payload.expected_checksum = payload.expected_checksum.trim().to_ascii_lowercase();
    validate_expected_checksum(&payload.expected_checksum)?;
    payload.arch = normalize_arch(&payload.arch);
    if payload.binary_base64.is_empty()
        && payload.download_url.is_empty()
        && payload.version.is_empty()
    {
        bail!("version is required for streamed agent update");
    }
    if !payload.download_url.is_empty() {
        validate_download_url(&payload.download_url)?;
    }
    Ok(payload)
}

fn normalize_arch(arch: &str) -> String {
    match arch.trim() {
        "" => match std::env::consts::ARCH {
            "x86_64" => "amd64".to_string(),
            "aarch64" => "arm64".to_string(),
            other => other.to_string(),
        },
        value => value.to_string(),
    }
}

fn validate_expected_checksum(checksum: &str) -> Result<()> {
    if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected_checksum must be a 64-character hex SHA256 digest");
    }
    Ok(())
}

fn validate_download_url(raw: &str) -> Result<()> {
    if raw
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("download_url contains invalid characters");
    }
    let Some(rest) = raw.strip_prefix("https://") else {
        bail!("download_url must use https");
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    if host.is_empty() {
        bail!("download_url must include a host");
    }
    Ok(())
}

fn resolve_current_binary() -> Result<PathBuf> {
    let path = std::env::current_exe().context("resolve executable")?;
    path.canonicalize().context("canonicalize executable")
}

async fn stream_agent_binary(
    cfg: &Config,
    mut client: AgentServiceClient<Channel>,
    payload: &UpdatePayload,
    path: &Path,
) -> Result<DownloadedBinary> {
    if payload.version.trim().is_empty() {
        bail!("version is required for streamed agent update");
    }
    let request = cfg.attach_auth(tonic::Request::new(DownloadAgentBinaryRequest {
        version: payload.version.clone(),
        os: "linux".to_string(),
        arch: payload.arch.clone(),
    }))?;
    let mut stream = tokio::time::timeout(
        AGENT_BINARY_STREAM_TIMEOUT,
        client.download_agent_binary(request),
    )
    .await
    .context("download agent binary timed out")??
    .into_inner();

    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("create {}", path.display()))?;
    let mut expected_seq = 0u32;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut saw_chunk = false;
    let mut stream_total_size = 0i64;

    while let Some(chunk) = stream.message().await.context("receive binary chunk")? {
        if chunk.seq != expected_seq {
            bail!(
                "unexpected agent binary chunk sequence: got {}, want {}",
                chunk.seq,
                expected_seq
            );
        }
        if expected_seq == 0 {
            let stream_checksum = chunk.checksum.trim().to_ascii_lowercase();
            stream_total_size = chunk.total_size;
            if !stream_checksum.is_empty() && stream_checksum != payload.expected_checksum {
                bail!(
                    "stream checksum mismatch: got {}, expected {}",
                    stream_checksum,
                    payload.expected_checksum
                );
            }
            if stream_total_size > MAX_AGENT_BINARY_SIZE as i64 {
                bail!("agent binary exceeds maximum size");
            }
        }
        saw_chunk = true;
        write_chunk_capped(&mut file, &mut hasher, &mut written, &chunk.data).await?;
        expected_seq = expected_seq.saturating_add(1);
    }

    if !saw_chunk {
        bail!("agent binary stream ended without data");
    }
    if stream_total_size > 0 && written != stream_total_size as u64 {
        bail!(
            "stream size mismatch: got {} bytes, expected {}",
            written,
            stream_total_size
        );
    }
    file.sync_all().await.context("fsync streamed binary")?;
    Ok(DownloadedBinary {
        bytes: written,
        checksum: hex::encode(hasher.finalize()),
    })
}

async fn write_base64_to_file(encoded: &str, path: &Path) -> Result<DownloadedBinary> {
    let encoded = encoded.to_string();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut decoder = DecoderReader::new(encoded.as_bytes(), &STANDARD);
        let mut file =
            fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        let downloaded = copy_reader_capped(&mut decoder, &mut file, MAX_AGENT_BINARY_SIZE)
            .context("decode inline binary")?;
        file.sync_all().context("fsync inline binary")?;
        Ok(downloaded)
    })
    .await
    .context("join base64 decode task")?
}

async fn download_binary_with_curl(download_url: &str, path: &Path) -> Result<DownloadedBinary> {
    validate_download_url(download_url)?;
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--max-time",
            "300",
            "--output",
            "-",
            download_url,
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
    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("create {}", path.display()))?;
    let copy = copy_async_reader_capped(&mut stdout, &mut file, MAX_AGENT_BINARY_SIZE).await;
    if copy.is_err() {
        let _ = child.kill().await;
    }
    let downloaded = copy?;
    file.sync_all().await.context("fsync downloaded binary")?;

    let status = tokio::time::timeout(AGENT_BINARY_STREAM_TIMEOUT, child.wait())
        .await
        .context("curl timed out")?
        .context("wait curl")?;
    if !status.success() {
        bail!("curl download failed with status {status}");
    }
    Ok(downloaded)
}

async fn write_chunk_capped(
    file: &mut tokio::fs::File,
    hasher: &mut Sha256,
    written: &mut u64,
    chunk: &[u8],
) -> Result<()> {
    let next = written
        .checked_add(chunk.len() as u64)
        .ok_or_else(|| anyhow!("agent binary exceeds maximum size"))?;
    if next > MAX_AGENT_BINARY_SIZE {
        bail!("agent binary exceeds maximum size");
    }
    if !chunk.is_empty() {
        file.write_all(chunk).await.context("write binary chunk")?;
        hasher.update(chunk);
        *written = next;
    }
    Ok(())
}

fn copy_reader_capped(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
) -> Result<DownloadedBinary> {
    let mut buf = [0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    loop {
        let n = reader.read(&mut buf).context("read binary")?;
        if n == 0 {
            break;
        }
        let next = written
            .checked_add(n as u64)
            .ok_or_else(|| anyhow!("agent binary exceeds maximum size"))?;
        if next > limit {
            bail!("agent binary exceeds maximum size");
        }
        writer.write_all(&buf[..n]).context("write binary")?;
        hasher.update(&buf[..n]);
        written = next;
    }
    Ok(DownloadedBinary {
        bytes: written,
        checksum: hex::encode(hasher.finalize()),
    })
}

async fn copy_async_reader_capped<R>(
    reader: &mut R,
    writer: &mut tokio::fs::File,
    limit: u64,
) -> Result<DownloadedBinary>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    loop {
        let n = reader.read(&mut buf).await.context("read binary")?;
        if n == 0 {
            break;
        }
        let next = written
            .checked_add(n as u64)
            .ok_or_else(|| anyhow!("agent binary exceeds maximum size"))?;
        if next > limit {
            bail!("agent binary exceeds maximum size");
        }
        writer.write_all(&buf[..n]).await.context("write binary")?;
        hasher.update(&buf[..n]);
        written = next;
    }
    Ok(DownloadedBinary {
        bytes: written,
        checksum: hex::encode(hasher.finalize()),
    })
}

fn install_tmp_binary(tmp_path: &Path, target_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp_path, fs::Permissions::from_mode(0o755))
            .context("chmod update binary")?;
    }
    #[cfg(not(unix))]
    {
        let mut perms = fs::metadata(tmp_path)?.permissions();
        perms.set_readonly(false);
        fs::set_permissions(tmp_path, perms).context("chmod update binary")?;
    }
    fs::rename(tmp_path, target_path).with_context(|| {
        format!(
            "atomic rename {} -> {}",
            tmp_path.display(),
            target_path.display()
        )
    })
}

fn schedule_restart() {
    tokio::spawn(async {
        tokio::time::sleep(RESTART_DELAY).await;
        if is_systemd_managed().await {
            if let Err(err) = Command::new("systemctl")
                .args(["restart", "permanu-agent"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                warn!(error = ?err, "systemctl restart failed; exiting for supervisor restart");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        std::process::exit(0);
    });
}

async fn is_systemd_managed() -> bool {
    if std::env::var_os("NOTIFY_SOCKET").is_some() {
        return true;
    }
    let status = tokio::time::timeout(
        Duration::from_secs(2),
        Command::new("systemctl")
            .args(["is-active", "permanu-agent"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await;
    matches!(status, Ok(Ok(status)) if status.success())
}

async fn send_running(tx: &mpsc::Sender<CommandResult>, command_id: &str, message: &str) {
    let _ = tx
        .send(CommandResult {
            command_id: command_id.to_string(),
            status: "running".to_string(),
            output: message.as_bytes().to_vec(),
            is_final: false,
            timestamp: Some(now_timestamp()),
        })
        .await;
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
    fn parse_payload_requires_checksum() {
        let err = parse_update_payload(br#"{"version":"v1"}"#).unwrap_err();
        assert!(err.to_string().contains("expected_checksum"));
    }

    #[test]
    fn parse_payload_defaults_arch_and_normalizes_checksum() {
        let payload = parse_update_payload(
            br#"{"version":"v1","expected_checksum":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .expect("parse payload");
        assert_eq!(
            payload.expected_checksum,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(!payload.arch.is_empty());
    }

    #[test]
    fn validate_download_url_requires_https_host() {
        assert!(validate_download_url("https://example.com/agent").is_ok());
        assert!(validate_download_url("http://example.com/agent").is_err());
        assert!(validate_download_url("https://").is_err());
        assert!(validate_download_url("https://example.com/\nagent").is_err());
    }

    #[test]
    fn copy_reader_capped_hashes_and_rejects_oversize() {
        let mut input = std::io::Cursor::new(b"hello".to_vec());
        let mut output = Vec::new();
        let copied = copy_reader_capped(&mut input, &mut output, 10).expect("copy");
        assert_eq!(copied.bytes, 5);
        assert_eq!(output, b"hello");
        assert_eq!(
            copied.checksum,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        let mut input = std::io::Cursor::new(b"hello".to_vec());
        let err = copy_reader_capped(&mut input, &mut Vec::new(), 4).unwrap_err();
        assert!(err.to_string().contains("maximum size"));
    }

    #[test]
    fn install_tmp_binary_replaces_target_and_marks_executable() {
        let dir = test_dir("self-update-install");
        fs::create_dir_all(&dir).expect("mkdir");
        let target = dir.join("permanu-agent");
        let tmp = dir.join(".permanu-agent.update-test.tmp");
        fs::write(&target, b"old").expect("write target");
        fs::write(&tmp, b"new").expect("write tmp");

        install_tmp_binary(&tmp, &target).expect("install");

        assert_eq!(fs::read(&target).expect("read target"), b"new");
        assert!(!tmp.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    fn test_dir(name: &str) -> PathBuf {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("permanu-agent-{name}-{seed}"))
    }
}
