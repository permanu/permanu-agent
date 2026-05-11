use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};

const DWAAR_CF_TOKEN_ENV_KEY: &str = "DWAAR_CLOUDFLARE_API_TOKEN_FILE";
const DWAAR_CF_TOKEN_DROP_IN: &str = "cf-token.conf";

pub trait SystemCommand {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Vec<u8>>;
}

pub struct RealSystemCommand;

impl SystemCommand for RealSystemCommand {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        let output = std::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run {program}"))?;
        if !output.status.success() {
            bail!(
                "{program} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }
}

pub struct CloudflareTokenOptions<'a, C: SystemCommand + ?Sized> {
    pub(super) token_path: PathBuf,
    drop_in_dir: PathBuf,
    command: &'a mut C,
}

impl<'a, C: SystemCommand + ?Sized> CloudflareTokenOptions<'a, C> {
    pub fn new(
        token_path: impl AsRef<Path>,
        drop_in_dir: impl AsRef<Path>,
        command: &'a mut C,
    ) -> Self {
        Self {
            token_path: token_path.as_ref().to_path_buf(),
            drop_in_dir: drop_in_dir.as_ref().to_path_buf(),
            command,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CloudflareApplySummary {
    pub token_changed: bool,
    pub drop_in_changed: bool,
}

pub fn apply_cloudflare_token<C: SystemCommand + ?Sized>(
    token_plaintext: &str,
    options: CloudflareTokenOptions<'_, C>,
) -> Result<CloudflareApplySummary> {
    let token = normalise_secret_value(token_plaintext, "CF token")?;
    let token_changed = !token_matches_disk(&options.token_path, &token)?;
    if token_changed {
        atomic_write_file(&options.token_path, token.as_bytes(), 0o600)
            .with_context(|| format!("write {}", options.token_path.display()))?;
        let read_back = fs::read(&options.token_path)
            .with_context(|| format!("read back {}", options.token_path.display()))?;
        if read_back != token.as_bytes() {
            bail!(
                "cf_token: read-back mismatch at {}",
                options.token_path.display()
            );
        }
    }

    let drop_in_changed = ensure_dwaar_cf_token_drop_in(&options.token_path, &options.drop_in_dir)?;
    if token_changed || drop_in_changed {
        options
            .command
            .run("systemctl", &["daemon-reload"])
            .context("cf_token: systemctl daemon-reload")?;
        options
            .command
            .run("systemctl", &["reload", "dwaar"])
            .context("cf_token: systemctl reload dwaar")?;
    }
    verify_dwaar_env(&options.token_path, options.command)?;

    Ok(CloudflareApplySummary {
        token_changed,
        drop_in_changed,
    })
}

pub fn rewrite_agent_env_file(
    path: impl AsRef<Path>,
    server_id: &str,
    agent_secret: &str,
) -> Result<()> {
    validate_env_value("SERVER_ID", server_id)?;
    validate_env_value("AGENT_SECRET", agent_secret)?;
    let path = path.as_ref();
    reject_symlink(path)?;

    let existing = match fs::read_to_string(path) {
        Ok(existing) => existing,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };

    let mut out = String::new();
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SERVER_ID=") || trimmed.starts_with("AGENT_SECRET=") {
            continue;
        }
        if !trimmed.is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str("SERVER_ID=");
    out.push_str(server_id);
    out.push('\n');
    out.push_str("AGENT_SECRET=");
    out.push_str(agent_secret);
    out.push('\n');

    atomic_write_file(path, out.as_bytes(), 0o600)
}

pub(super) fn token_matches_disk(path: &Path, token: &str) -> Result<bool> {
    reject_symlink(path)?;
    match fs::read_to_string(path) {
        Ok(existing) => Ok(existing.trim() == token),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

pub(super) fn atomic_write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    reject_path_with_traversal(path)?;
    reject_symlink(path)?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let temp = unique_temp_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(&temp)
        .with_context(|| format!("create {}", temp.display()))?;
    if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(err).with_context(|| format!("write {}", temp.display()));
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", temp.display()))?;
    }
    if let Err(err) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(err)
            .with_context(|| format!("rename {} -> {}", temp.display(), path.display()));
    }
    Ok(())
}

pub(super) fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("refusing to write through symlink: {}", path.display())
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

pub(super) fn reject_path_with_traversal(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("path contains traversal: {}", path.display());
    }
    Ok(())
}

pub(super) fn normalise_secret_value(value: &str, label: &str) -> Result<String> {
    let value = value.trim().to_string();
    validate_env_value(label, &value)?;
    Ok(value)
}

pub(super) fn validate_env_value(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{label} is required");
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r' || byte.is_ascii_control())
    {
        bail!("{label} contains invalid characters");
    }
    Ok(())
}

pub(super) fn validate_command_id_for_filename(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 {
        bail!("command_id is invalid for filename");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("command_id is invalid for filename");
    }
    Ok(())
}

fn ensure_dwaar_cf_token_drop_in(token_path: &Path, drop_in_dir: &Path) -> Result<bool> {
    reject_path_with_traversal(token_path)?;
    reject_path_with_traversal(drop_in_dir)?;
    let content = format!(
        "[Service]\nEnvironment={DWAAR_CF_TOKEN_ENV_KEY}={}\n",
        token_path.display()
    );
    let drop_in_path = drop_in_dir.join(DWAAR_CF_TOKEN_DROP_IN);
    if let Ok(existing) = fs::read_to_string(&drop_in_path) {
        if existing == content {
            return Ok(false);
        }
    }
    fs::create_dir_all(drop_in_dir).with_context(|| format!("mkdir {}", drop_in_dir.display()))?;
    atomic_write_file(&drop_in_path, content.as_bytes(), 0o644)?;
    Ok(true)
}

fn verify_dwaar_env<C: SystemCommand + ?Sized>(token_path: &Path, command: &mut C) -> Result<()> {
    let pid_output = match command.run("pidof", &["dwaar"]) {
        Ok(output) => output,
        Err(_) => return Ok(()),
    };
    let pid_text = String::from_utf8_lossy(&pid_output);
    let Some(pid) = pid_text.split_whitespace().next() else {
        return Ok(());
    };
    if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("cf_token: pidof dwaar returned invalid pid");
    }
    let environ_path = PathBuf::from(format!("/proc/{pid}/environ"));
    let data = match fs::read(&environ_path) {
        Ok(data) => data,
        Err(_) => return Ok(()),
    };
    let expected = format!("{DWAAR_CF_TOKEN_ENV_KEY}={}", token_path.display());
    if data
        .split(|byte| *byte == 0)
        .any(|entry| entry == expected.as_bytes())
    {
        return Ok(());
    }
    bail!("cf_token: dwaar process env missing {DWAAR_CF_TOKEN_ENV_KEY}");
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_file_name(format!(".{file_name}.tmp-{}-{seed}", std::process::id()))
}
