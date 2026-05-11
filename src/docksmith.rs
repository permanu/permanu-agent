use std::{io, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_DOCKSMITH_STDOUT_BYTES: u64 = 1024 * 1024;
const MAX_DOCKSMITH_STDERR_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectPayload {
    pub clone_dir: String,
}

pub fn parse_detect_payload(payload: &[u8]) -> Result<DetectPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        clone_dir: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let clone_dir = payload.clone_dir.trim();
    if clone_dir.is_empty() {
        anyhow::bail!("clone_dir is required");
    }
    if clone_dir.contains('\0') {
        anyhow::bail!("clone_dir contains NUL");
    }
    if !Path::new(clone_dir).is_absolute() {
        anyhow::bail!("clone_dir must be absolute");
    }
    Ok(DetectPayload {
        clone_dir: clone_dir.to_string(),
    })
}

pub fn docksmith_detect_args(clone_dir: &str) -> Vec<String> {
    vec![
        "--format".to_string(),
        "json".to_string(),
        "--quiet".to_string(),
        "detect".to_string(),
        clone_dir.to_string(),
    ]
}

pub async fn detect_framework(
    docksmith_bin: &str,
    timeout_duration: Duration,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let payload = parse_detect_payload(payload)?;
    let mut command = tokio::process::Command::new(docksmith_bin);
    command
        .args(docksmith_detect_args(&payload.clone_dir))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn docksmith helper {docksmith_bin:?}"))?;

    let stdout = child
        .stdout
        .take()
        .context("docksmith stdout pipe missing")?;
    let stderr = child
        .stderr
        .take()
        .context("docksmith stderr pipe missing")?;
    let stdout_task = tokio::spawn(read_capped(stdout, MAX_DOCKSMITH_STDOUT_BYTES + 1));
    let stderr_task = tokio::spawn(read_capped(stderr, MAX_DOCKSMITH_STDERR_BYTES + 1));

    let status = match tokio::time::timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => return Err(err).context("wait for docksmith helper"),
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("docksmith detect timed out");
        }
    };

    let stdout = stdout_task
        .await
        .context("join docksmith stdout reader")??;
    let stderr = stderr_task
        .await
        .context("join docksmith stderr reader")??;
    if stdout.len() as u64 > MAX_DOCKSMITH_STDOUT_BYTES {
        anyhow::bail!("docksmith stdout exceeded maximum size");
    }
    if stderr.len() as u64 > MAX_DOCKSMITH_STDERR_BYTES {
        anyhow::bail!("docksmith stderr exceeded maximum size");
    }

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        anyhow::bail!("docksmith detect failed: {}", stderr.trim());
    }
    serde_json::from_slice::<serde_json::Value>(&stdout)
        .context("docksmith emitted invalid JSON")?;
    Ok(stdout)
}

async fn read_capped<R>(reader: R, max_bytes: u64) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut reader = reader.take(max_bytes);
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn detect_payload_requires_clone_dir() {
        let err = parse_detect_payload(br#"{}"#).unwrap_err();
        assert!(err.to_string().contains("clone_dir is required"));
    }

    #[test]
    fn detect_payload_rejects_relative_clone_dir() {
        let err = parse_detect_payload(br#"{"clone_dir":"repo"}"#).unwrap_err();
        assert!(err.to_string().contains("clone_dir must be absolute"));
    }

    #[test]
    fn detect_payload_rejects_nul_bytes() {
        let err = parse_detect_payload(b"{\"clone_dir\":\"/tmp/a\\u0000b\"}").unwrap_err();
        assert!(err.to_string().contains("clone_dir contains NUL"));
    }

    #[test]
    fn detect_args_match_docksmith_json_cli() {
        let args = docksmith_detect_args("/tmp/deploy-build-123");
        assert_eq!(
            args,
            vec![
                "--format",
                "json",
                "--quiet",
                "detect",
                "/tmp/deploy-build-123"
            ]
        );
    }

    #[tokio::test]
    async fn detect_framework_uses_json_cli_and_returns_stdout() {
        let dir = unique_test_dir("docksmith-ok");
        fs::create_dir_all(&dir).expect("create temp dir");
        let helper = dir.join("docksmith-helper");
        fs::write(
            &helper,
            "#!/bin/sh\n[ \"$1\" = \"--format\" ] || exit 7\n[ \"$2\" = \"json\" ] || exit 8\n[ \"$3\" = \"--quiet\" ] || exit 9\n[ \"$4\" = \"detect\" ] || exit 10\n[ \"$5\" = \"/tmp/deploy-build-123\" ] || exit 11\nprintf '{\"name\":\"nextjs\",\"port\":3000}'\n",
        )
        .expect("write helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("chmod helper");

        let output = detect_framework(
            helper.to_str().expect("helper path"),
            Duration::from_secs(5),
            br#"{"clone_dir":"/tmp/deploy-build-123"}"#,
        )
        .await
        .expect("detect framework");

        assert_eq!(output, br#"{"name":"nextjs","port":3000}"#);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn detect_framework_rejects_invalid_json_stdout() {
        let dir = unique_test_dir("docksmith-invalid-json");
        fs::create_dir_all(&dir).expect("create temp dir");
        let helper = dir.join("docksmith-helper");
        fs::write(&helper, "#!/bin/sh\nprintf 'not json'\n").expect("write helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("chmod helper");

        let err = detect_framework(
            helper.to_str().expect("helper path"),
            Duration::from_secs(5),
            br#"{"clone_dir":"/tmp/deploy-build-123"}"#,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("docksmith emitted invalid JSON"));
        let _ = fs::remove_dir_all(&dir);
    }

    fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
