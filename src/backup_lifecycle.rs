use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::mpsc,
    task,
    time::{timeout, Duration},
};

use crate::{proto::agent::v1::CommandResult, timeutil::now_timestamp};

const BACKUP_DATA_DIR: &str = "/var/lib/permanu-agent/backups";
const AGENT_ARTIFACT_SCHEME: &str = "agent-artifact://";
const DOWNLOAD_CHUNK_SIZE: usize = 64 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const BACKUP_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DOCKER_OP_TIMEOUT: Duration = Duration::from_secs(30);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackupOperation {
    Create,
    Upload,
    Restore,
    Cleanup,
    Verify,
    Download,
}

impl BackupOperation {
    fn as_go_string(self) -> &'static str {
        match self {
            Self::Create => "BACKUP_OPERATION_CREATE",
            Self::Upload => "BACKUP_OPERATION_UPLOAD",
            Self::Restore => "BACKUP_OPERATION_RESTORE",
            Self::Cleanup => "BACKUP_OPERATION_CLEANUP",
            Self::Verify => "BACKUP_OPERATION_VERIFY",
            Self::Download => "BACKUP_OPERATION_DOWNLOAD",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackupEngine {
    Postgres,
    MySql,
    Mongo,
    Redis,
    Unspecified,
}

impl BackupEngine {
    fn as_go_string(self) -> &'static str {
        match self {
            Self::Postgres => "BACKUP_ENGINE_POSTGRES",
            Self::MySql => "BACKUP_ENGINE_MYSQL",
            Self::Mongo => "BACKUP_ENGINE_MONGO",
            Self::Redis => "BACKUP_ENGINE_REDIS",
            Self::Unspecified => "BACKUP_ENGINE_UNSPECIFIED",
        }
    }
}

#[derive(Clone, Debug)]
struct BackupPayload {
    operation: BackupOperation,
    engine: BackupEngine,
    container_name: String,
    backup_id: String,
    storage_path: String,
    image: String,
    s3_endpoint: String,
    s3_bucket: String,
    download_filename: String,
    content_type: String,
}

#[derive(Serialize)]
struct BackupResult {
    operation: &'static str,
    storage_path: String,
    size_bytes: i64,
    storage_tier: String,
    downloaded_bytes: i64,
    verified: bool,
    verify_count: i32,
    restored_engine: String,
}

#[derive(Debug)]
struct PreparedDownload {
    local_path: PathBuf,
    cleanup_path: Option<PathBuf>,
    filename: String,
    size_bytes: i64,
    content_type: String,
}

#[derive(Serialize)]
struct DownloadMetadata {
    filename: String,
    size_bytes: i64,
    content_type: String,
}

pub async fn handle_backup_create(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_backup_payload(payload, BackupOperation::Create) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid backup payload: {err}")),
    };
    let _ = send_running(&tx, command_id, "starting backup worker...").await;
    match create_backup(&payload).await {
        Ok(mut result) => {
            if payload.s3_requested() {
                let _ = send_running(
                    &tx,
                    command_id,
                    "S3 upload is not enabled in permanu-agent yet; keeping local backup.",
                )
                .await;
                result.storage_tier = "local".to_string();
            }
            completed_json(command_id, &result)
        }
        Err(err) => failed_text(command_id, &format!("backup worker error: {err}")),
    }
}

pub async fn handle_backup_upload(command_id: &str, payload: &[u8]) -> CommandResult {
    if let Err(err) = parse_backup_payload(payload, BackupOperation::Upload) {
        return failed_text(command_id, &format!("invalid backup payload: {err}"));
    }
    completed_json(command_id, &empty_result(BackupOperation::Upload))
}

pub async fn handle_backup_restore(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_backup_payload(payload, BackupOperation::Restore) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid backup payload: {err}")),
    };
    match restore_backup(&payload).await {
        Ok(result) => completed_json(command_id, &result),
        Err(err) => failed_text(command_id, &format!("backup worker error: {err}")),
    }
}

pub async fn handle_backup_cleanup(command_id: &str, payload: &[u8]) -> CommandResult {
    if let Err(err) = parse_backup_payload(payload, BackupOperation::Cleanup) {
        return failed_text(command_id, &format!("invalid backup payload: {err}"));
    }
    completed_json(command_id, &empty_result(BackupOperation::Cleanup))
}

pub async fn handle_backup_verify(command_id: &str, payload: &[u8]) -> CommandResult {
    let payload = match parse_backup_payload(payload, BackupOperation::Verify) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid backup payload: {err}")),
    };
    match verify_backup(&payload).await {
        Ok(result) => completed_json(command_id, &result),
        Err(err) => failed_text(command_id, &format!("backup worker error: {err}")),
    }
}

pub async fn handle_backup_download(
    command_id: &str,
    payload: &[u8],
    tx: mpsc::Sender<CommandResult>,
) -> CommandResult {
    let payload = match parse_backup_payload(payload, BackupOperation::Download) {
        Ok(payload) => payload,
        Err(err) => return failed_text(command_id, &format!("invalid backup payload: {err}")),
    };
    match download_backup(&payload, &tx, command_id).await {
        Ok(result) => completed_json(command_id, &result),
        Err(err) => failed_text(command_id, &format!("backup worker error: {err}")),
    }
}

fn parse_backup_payload(payload: &[u8], operation: BackupOperation) -> Result<BackupPayload> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        service_type: String,
        #[serde(default)]
        backup_id: String,
        #[serde(default)]
        storage_path: String,
        #[serde(default)]
        image: String,
        #[serde(default)]
        s3_endpoint: String,
        #[serde(default)]
        s3_bucket: String,
        #[serde(default)]
        download_filename: String,
        #[serde(default)]
        content_type: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    Ok(BackupPayload {
        operation,
        engine: service_type_to_engine(&payload.service_type),
        container_name: payload.container_name.trim().to_string(),
        backup_id: payload.backup_id.trim().to_string(),
        storage_path: payload.storage_path.trim().to_string(),
        image: payload.image.trim().to_string(),
        s3_endpoint: payload.s3_endpoint,
        s3_bucket: payload.s3_bucket,
        download_filename: payload.download_filename.trim().to_string(),
        content_type: payload.content_type.trim().to_string(),
    })
}

impl BackupPayload {
    fn s3_requested(&self) -> bool {
        !self.s3_endpoint.trim().is_empty() && !self.s3_bucket.trim().is_empty()
    }
}

fn service_type_to_engine(service_type: &str) -> BackupEngine {
    match service_type {
        "postgresql" => BackupEngine::Postgres,
        "mysql" => BackupEngine::MySql,
        "mongodb" => BackupEngine::Mongo,
        "redis" => BackupEngine::Redis,
        _ => BackupEngine::Unspecified,
    }
}

fn local_backup_write_path(container_name: &str, backup_id: &str, ext: &str) -> Result<PathBuf> {
    local_backup_write_path_with_root(Path::new(BACKUP_DATA_DIR), container_name, backup_id, ext)
}

fn resolve_local_path(storage_path: &str) -> Result<(PathBuf, u64)> {
    resolve_local_path_with_root(Path::new(BACKUP_DATA_DIR), storage_path)
}

fn local_backup_write_path_with_root(
    root: &Path,
    container_name: &str,
    backup_id: &str,
    ext: &str,
) -> Result<PathBuf> {
    validate_container_name(container_name, "container_name")?;
    validate_backup_id(backup_id)?;
    if ext != ".tar.gz" && ext != ".sql.gz" {
        anyhow::bail!("invalid backup extension {ext:?}");
    }
    let root = canonical_or_absolute(root)?;
    let file_path = root.join(container_name).join(format!("{backup_id}{ext}"));
    if !path_within_root(&file_path, &root) {
        anyhow::bail!("backup path escapes root");
    }
    Ok(file_path)
}

fn resolve_local_path_with_root(root: &Path, storage_path: &str) -> Result<(PathBuf, u64)> {
    let raw_path = storage_path
        .strip_prefix("agent-local://")
        .filter(|path| !path.is_empty())
        .ok_or_else(|| anyhow::anyhow!("invalid storage_path (expected agent-local:// prefix)"))?;
    let root = canonical_or_absolute(root)?;
    let requested = canonical_or_absolute(Path::new(raw_path))?;
    if !path_within_root(&requested, &root) {
        anyhow::bail!(
            "path traversal rejected: {} is outside backup root",
            requested.display()
        );
    }
    let meta = std::fs::metadata(&requested)
        .with_context(|| format!("stat backup file {}", requested.display()))?;
    if meta.is_dir() {
        anyhow::bail!(
            "storage_path resolves to a directory: {}",
            requested.display()
        );
    }
    Ok((requested, meta.len()))
}

async fn create_backup(payload: &BackupPayload) -> Result<BackupResult> {
    validate_container_name(&payload.container_name, "container_name")?;
    validate_backup_id(&payload.backup_id)?;
    match payload.engine {
        BackupEngine::Postgres => {
            create_exec_stream_backup(
                payload,
                ".tar.gz",
                &[
                    "sh",
                    "-c",
                    r#"pg_basebackup -D - -Ft -z -X fetch -U "$POSTGRES_USER" --no-password"#,
                ],
            )
            .await
        }
        BackupEngine::MySql => {
            create_exec_stream_backup(
                payload,
                ".sql.gz",
                &[
                    "sh",
                    "-c",
                    "MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysqldump -u root --all-databases --single-transaction --routines --triggers | gzip",
                ],
            )
            .await
        }
        BackupEngine::Mongo => {
            create_exec_stream_backup(
                payload,
                ".tar.gz",
                &[
                    "sh",
                    "-c",
                    "mongodump --archive --gzip --username=app --password=$MONGO_INITDB_ROOT_PASSWORD --authenticationDatabase=admin",
                ],
            )
            .await
        }
        BackupEngine::Redis => create_redis_backup(payload).await,
        BackupEngine::Unspecified => anyhow::bail!("backup create: unsupported engine"),
    }
}

async fn create_exec_stream_backup(
    payload: &BackupPayload,
    ext: &str,
    exec_args: &[&str],
) -> Result<BackupResult> {
    let out_path = local_backup_write_path(&payload.container_name, &payload.backup_id, ext)?;
    let parent = out_path.parent().context("backup path has no parent")?;
    fs::create_dir_all(parent).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await;
    }
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&out_path)
        .await
        .with_context(|| format!("open output {}", out_path.display()))?;
    let written = match exec_stream_to_file(&payload.container_name, exec_args, file).await {
        Ok(written) => written,
        Err(err) => {
            let _ = fs::remove_file(&out_path).await;
            return Err(err);
        }
    };
    Ok(backup_result(
        payload.operation,
        format!("agent-local://{}", out_path.display()),
        written,
        "local",
    ))
}

async fn create_redis_backup(payload: &BackupPayload) -> Result<BackupResult> {
    let baseline = redis_lastsave(&payload.container_name)
        .await
        .unwrap_or_default();
    run_docker_success(
        &["exec", &payload.container_name, "redis-cli", "BGSAVE"],
        DOCKER_OP_TIMEOUT,
    )
    .await
    .context("backup create redis: BGSAVE")?;
    wait_redis_bgsave(&payload.container_name, &baseline).await?;

    let out_path = local_backup_write_path(&payload.container_name, &payload.backup_id, ".tar.gz")?;
    let parent = out_path.parent().context("backup path has no parent")?;
    fs::create_dir_all(parent).await?;
    let temp_name = format!(
        "{}.tmp",
        out_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("non-utf8 backup file name")?
    );
    let temp_path = out_path.with_file_name(temp_name);
    if fs::try_exists(&out_path).await.unwrap_or(false) {
        anyhow::bail!("backup output already exists: {}", out_path.display());
    }
    let _ = fs::remove_file(&temp_path).await;
    run_docker_success(
        &[
            "cp",
            &format!("{}:/data/dump.rdb", payload.container_name),
            temp_path.to_str().context("non-utf8 backup path")?,
        ],
        BACKUP_TIMEOUT,
    )
    .await
    .context("backup create redis: docker cp dump.rdb")?;
    fs::rename(&temp_path, &out_path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).await;
    }
    let size = fs::metadata(&out_path).await?.len();
    Ok(backup_result(
        payload.operation,
        format!("agent-local://{}", out_path.display()),
        size,
        "local",
    ))
}

async fn restore_backup(payload: &BackupPayload) -> Result<BackupResult> {
    validate_container_name(&payload.container_name, "container_name")?;
    let (local_path, _) = resolve_local_path(&payload.storage_path)?;
    match payload.engine {
        BackupEngine::Postgres => restore_postgres(&payload.container_name, &local_path).await?,
        BackupEngine::MySql => restore_mysql(&payload.container_name, &local_path).await?,
        BackupEngine::Mongo => restore_mongo(&payload.container_name, &local_path).await?,
        BackupEngine::Redis => restore_redis(&payload.container_name, &local_path).await?,
        BackupEngine::Unspecified => anyhow::bail!("backup restore: unsupported engine"),
    }
    let mut result = empty_result(BackupOperation::Restore);
    result.restored_engine = payload.engine.as_go_string().to_string();
    Ok(result)
}

async fn verify_backup(payload: &BackupPayload) -> Result<BackupResult> {
    if payload.storage_path.is_empty() || payload.image.is_empty() {
        anyhow::bail!("backup verify: storage_path and image are required");
    }
    validate_image_ref(&payload.image)?;
    let (local_path, _) = resolve_local_path(&payload.storage_path)?;
    let short_id = backup_short_id(&payload.backup_id);
    let temp_container = format!("deploy-verify-{short_id}");
    let temp_volume = format!("{temp_container}-data");
    let verify_result = match timeout(
        VERIFY_TIMEOUT,
        verify_backup_inner(payload, &local_path, &temp_container, &temp_volume),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("backup verify timed out")),
    };

    let _ = run_docker_success(&["rm", "-f", &temp_container], DOCKER_OP_TIMEOUT).await;
    let _ = run_docker_success(&["volume", "rm", &temp_volume], DOCKER_OP_TIMEOUT).await;

    verify_result
}

async fn verify_backup_inner(
    payload: &BackupPayload,
    local_path: &Path,
    temp_container: &str,
    temp_volume: &str,
) -> Result<BackupResult> {
    create_verify_container(payload, temp_container, temp_volume).await?;
    wait_container_running(temp_container, Duration::from_secs(30)).await?;
    match payload.engine {
        BackupEngine::Postgres => restore_postgres(temp_container, local_path).await?,
        BackupEngine::MySql => restore_mysql(temp_container, local_path).await?,
        BackupEngine::Mongo => restore_mongo(temp_container, local_path).await?,
        BackupEngine::Redis => restore_redis(temp_container, local_path).await?,
        BackupEngine::Unspecified => anyhow::bail!("backup verify: unsupported engine"),
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let count = validate_service(payload.engine, temp_container).await?;
    let mut result = empty_result(BackupOperation::Verify);
    result.verified = true;
    result.verify_count = count;
    Ok(result)
}

async fn create_verify_container(
    payload: &BackupPayload,
    container_name: &str,
    volume_name: &str,
) -> Result<()> {
    let _ = ensure_network("deploy-net").await;
    run_docker_success(&["volume", "create", volume_name], DOCKER_OP_TIMEOUT).await?;
    let (data_path, env_args): (&str, &[&str]) = match payload.engine {
        BackupEngine::Postgres => (
            "/var/lib/postgresql/data",
            &[
                "-e",
                "POSTGRES_PASSWORD=verify_temp",
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
            ],
        ),
        BackupEngine::MySql => (
            "/var/lib/mysql",
            &[
                "-e",
                "MYSQL_ROOT_PASSWORD=verify_temp",
                "-e",
                "MYSQL_ALLOW_EMPTY_PASSWORD=yes",
            ],
        ),
        BackupEngine::Mongo => ("/data/db", &[]),
        BackupEngine::Redis => ("/data", &[]),
        BackupEngine::Unspecified => anyhow::bail!("backup verify: unsupported engine"),
    };
    let volume_mount = format!("{volume_name}:{data_path}");
    let mut args = vec![
        "run",
        "-d",
        "--name",
        container_name,
        "--memory",
        "268435456",
        "--cpus",
        "0.5",
        "-v",
        &volume_mount,
        "--network",
        "deploy-net",
        "--restart",
        "no",
    ];
    args.extend_from_slice(env_args);
    args.push(&payload.image);
    run_docker_success(&args, BACKUP_TIMEOUT).await
}

async fn restore_postgres(container_name: &str, local_path: &Path) -> Result<()> {
    docker_stop(container_name, 30).await?;
    if let Err(err) =
        docker_cp_to_container(container_name, local_path, "/tmp/backup-restore.tar.gz").await
    {
        let _ = docker_start(container_name).await;
        return Err(err);
    }
    docker_start(container_name).await?;
    run_docker_success(
        &[
            "exec",
            container_name,
            "bash",
            "-c",
            "pg_ctl stop -D /var/lib/postgresql/data -m fast 2>/dev/null; rm -rf /var/lib/postgresql/data/* && tar xzf /tmp/backup-restore.tar.gz -C /var/lib/postgresql/data/ && rm -f /tmp/backup-restore.tar.gz",
        ],
        BACKUP_TIMEOUT,
    )
    .await?;
    docker_restart(container_name, 10).await
}

async fn restore_mysql(container_name: &str, local_path: &Path) -> Result<()> {
    docker_stop(container_name, 30).await?;
    if let Err(err) =
        docker_cp_to_container(container_name, local_path, "/tmp/backup-restore.sql.gz").await
    {
        let _ = docker_start(container_name).await;
        return Err(err);
    }
    docker_start(container_name).await?;
    run_docker_success(
        &[
            "exec",
            container_name,
            "sh",
            "-c",
            "gunzip -c /tmp/backup-restore.sql.gz | MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql -u root && rm -f /tmp/backup-restore.sql.gz",
        ],
        BACKUP_TIMEOUT,
    )
    .await
}

async fn restore_mongo(container_name: &str, local_path: &Path) -> Result<()> {
    docker_cp_to_container(container_name, local_path, "/tmp/backup-restore.archive.gz").await?;
    run_docker_success(
        &[
            "exec",
            container_name,
            "sh",
            "-c",
            "mongorestore --archive=/tmp/backup-restore.archive.gz --gzip --drop --username=app --password=$MONGO_INITDB_ROOT_PASSWORD --authenticationDatabase=admin && rm -f /tmp/backup-restore.archive.gz",
        ],
        BACKUP_TIMEOUT,
    )
    .await
}

async fn restore_redis(container_name: &str, local_path: &Path) -> Result<()> {
    docker_stop(container_name, 10).await?;
    if let Err(err) = docker_cp_to_container(container_name, local_path, "/data/dump.rdb").await {
        let _ = docker_start(container_name).await;
        return Err(err);
    }
    docker_start(container_name).await
}

async fn validate_service(engine: BackupEngine, container_name: &str) -> Result<i32> {
    match engine {
        BackupEngine::Postgres => {
            run_docker_success(
                &["exec", container_name, "pg_isready", "-U", "postgres"],
                DOCKER_OP_TIMEOUT,
            )
            .await?;
            let output = run_docker_output(
                &[
                    "exec",
                    container_name,
                    "psql",
                    "-U",
                    "postgres",
                    "-t",
                    "-A",
                    "-c",
                    "SELECT count(*) FROM pg_tables WHERE schemaname='public'",
                ],
                DOCKER_OP_TIMEOUT,
            )
            .await?;
            Ok(parse_count(&output.stdout))
        }
        BackupEngine::MySql => {
            let output = run_docker_output(
                &[
                    "exec",
                    container_name,
                    "mysql",
                    "-uroot",
                    "-N",
                    "-e",
                    "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','mysql','performance_schema','sys')",
                ],
                DOCKER_OP_TIMEOUT,
            )
            .await?;
            Ok(parse_count(&output.stdout))
        }
        BackupEngine::Mongo => {
            run_docker_success(
                &[
                    "exec",
                    container_name,
                    "mongosh",
                    "--eval",
                    "db.adminCommand('ping')",
                    "--quiet",
                ],
                DOCKER_OP_TIMEOUT,
            )
            .await?;
            Ok(0)
        }
        BackupEngine::Redis => {
            run_docker_success(
                &["exec", container_name, "redis-cli", "PING"],
                DOCKER_OP_TIMEOUT,
            )
            .await?;
            let output = run_docker_output(
                &["exec", container_name, "redis-cli", "DBSIZE"],
                DOCKER_OP_TIMEOUT,
            )
            .await?;
            Ok(parse_count(&output.stdout))
        }
        BackupEngine::Unspecified => anyhow::bail!("backup verify: unsupported engine"),
    }
}

async fn download_backup(
    payload: &BackupPayload,
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
) -> Result<BackupResult> {
    let prepared = prepare_download(payload).await?;
    let total = stream_download_with_metadata(&prepared, tx, command_id).await;
    if let Some(cleanup_path) = &prepared.cleanup_path {
        let _ = fs::remove_file(cleanup_path).await;
    }
    let total = total?;
    let mut result = empty_result(BackupOperation::Download);
    result.downloaded_bytes = total;
    Ok(result)
}

async fn prepare_download(payload: &BackupPayload) -> Result<PreparedDownload> {
    if payload.storage_path.starts_with(AGENT_ARTIFACT_SCHEME) {
        return prepare_agent_artifact_download(payload).await;
    }
    let (local_path, size_bytes) = resolve_local_path(&payload.storage_path)?;
    Ok(PreparedDownload {
        filename: download_filename_for_path(&local_path, &payload.download_filename, "backup"),
        content_type: fallback_content_type(&payload.content_type),
        local_path,
        cleanup_path: None,
        size_bytes: i64::try_from(size_bytes).context("download file is too large")?,
    })
}

async fn prepare_agent_artifact_download(payload: &BackupPayload) -> Result<PreparedDownload> {
    prepare_agent_artifact_download_with_root(payload, &crate::job_deployment::ci_artifacts_root())
        .await
}

async fn prepare_agent_artifact_download_with_root(
    payload: &BackupPayload,
    artifact_root: &Path,
) -> Result<PreparedDownload> {
    let local_path = resolve_artifact_path_with_root(artifact_root, &payload.storage_path)?;
    let metadata = std::fs::symlink_metadata(&local_path)
        .with_context(|| format!("read artifact metadata {}", local_path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("artifact download refuses symlinks");
    }
    if metadata.is_file() {
        return Ok(PreparedDownload {
            filename: download_filename_for_path(
                &local_path,
                &payload.download_filename,
                "artifact",
            ),
            content_type: fallback_content_type(&payload.content_type),
            local_path,
            cleanup_path: None,
            size_bytes: i64::try_from(metadata.len()).context("artifact file is too large")?,
        });
    }
    if !metadata.is_dir() {
        anyhow::bail!("artifact path is neither file nor directory");
    }

    let zip_path = unique_temp_zip_path();
    let zip_path_for_task = zip_path.clone();
    let artifact_dir = local_path.clone();
    let size_bytes =
        task::spawn_blocking(move || zip_directory_artifact(&artifact_dir, &zip_path_for_task))
            .await
            .context("zip artifact task")??;
    let base_name = download_filename_for_path(&local_path, &payload.download_filename, "artifact");
    let filename = if base_name.ends_with(".zip") {
        base_name
    } else {
        format!("{base_name}.zip")
    };
    Ok(PreparedDownload {
        local_path: zip_path.clone(),
        cleanup_path: Some(zip_path),
        filename,
        size_bytes,
        content_type: "application/zip".to_string(),
    })
}

fn resolve_artifact_path_with_root(root: &Path, storage_path: &str) -> Result<PathBuf> {
    let raw_path = storage_path
        .strip_prefix(AGENT_ARTIFACT_SCHEME)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("invalid storage_path (expected agent-artifact:// prefix)")
        })?;
    let relative = Path::new(raw_path);
    if relative.is_absolute() {
        anyhow::bail!("artifact storage path must be relative");
    }
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            anyhow::bail!("artifact storage path must stay inside artifact root");
        }
    }
    let root = canonical_or_absolute(root)?;
    let requested = root.join(relative);
    let resolved = std::fs::canonicalize(&requested)
        .with_context(|| format!("resolve artifact path {}", requested.display()))?;
    if !path_within_root(&resolved, &root) {
        anyhow::bail!(
            "path traversal rejected: {} is outside artifact root",
            resolved.display()
        );
    }
    Ok(resolved)
}

async fn stream_download_with_metadata(
    prepared: &PreparedDownload,
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
) -> Result<i64> {
    let metadata = DownloadMetadata {
        filename: prepared.filename.clone(),
        size_bytes: prepared.size_bytes,
        content_type: prepared.content_type.clone(),
    };
    let mut header = serde_json::to_vec(&metadata).context("marshal download metadata")?;
    header.push(b'\n');
    tx.send(CommandResult {
        command_id: command_id.to_string(),
        status: "running".to_string(),
        output: header,
        is_final: false,
        timestamp: Some(now_timestamp()),
    })
    .await
    .context("send download metadata")?;
    stream_download_file(&prepared.local_path, tx, command_id).await
}

async fn stream_download_file(
    local_path: &Path,
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
) -> Result<i64> {
    let mut file = open_download_file(local_path).await?;
    let mut buf = vec![0_u8; DOWNLOAD_CHUNK_SIZE];
    let mut total = 0_i64;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n as i64;
        tx.send(CommandResult {
            command_id: command_id.to_string(),
            status: "running".to_string(),
            output: buf[..n].to_vec(),
            is_final: false,
            timestamp: Some(now_timestamp()),
        })
        .await
        .context("send backup download chunk")?;
    }
    Ok(total)
}

async fn open_download_file(local_path: &Path) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(local_path)
        .await
        .with_context(|| format!("open download file {}", local_path.display()))
}

fn download_filename_for_path(path: &Path, requested: &str, fallback: &str) -> String {
    let fallback_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback);
    sanitize_download_filename(
        if requested.trim().is_empty() {
            fallback_name
        } else {
            requested
        },
        fallback,
    )
}

fn sanitize_download_filename(name: &str, fallback: &str) -> String {
    let safe: String = name
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let safe = safe.trim_matches('.');
    if safe.is_empty() {
        fallback.to_string()
    } else {
        safe.to_string()
    }
}

fn fallback_content_type(content_type: &str) -> String {
    let content_type = content_type.trim();
    if content_type.is_empty()
        || content_type
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n'))
    {
        return "application/octet-stream".to_string();
    }
    content_type.to_string()
}

fn unique_temp_zip_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "permanu-agent-artifact-{}-{nanos}.zip",
        std::process::id()
    ))
}

fn zip_directory_artifact(root: &Path, zip_path: &Path) -> Result<i64> {
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("resolve artifact directory {}", root.display()))?;
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("read artifact directory {}", dir.display()))?
        {
            let entry = entry.context("read artifact directory entry")?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .with_context(|| format!("read artifact metadata {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("artifact archive refuses symlinks");
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();

    let file = create_new_file_no_symlink(zip_path)?;
    let mut archive = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for path in files {
        let rel = path
            .strip_prefix(&root)
            .context("artifact path escaped archive root")?;
        let name = rel
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        if name.is_empty() || name == ".." || name.starts_with("../") {
            anyhow::bail!("artifact path escapes archive root");
        }
        archive
            .start_file(name, options)
            .context("start artifact zip file")?;
        let mut input = open_file_no_symlink(&path)?;
        std::io::copy(&mut input, &mut archive).context("write artifact zip file")?;
    }

    let mut output = archive.finish().context("finish artifact zip")?;
    std::io::Write::flush(&mut output).context("flush artifact zip")?;
    let len = output.metadata().context("stat artifact zip")?.len();
    i64::try_from(len).context("artifact zip is too large")
}

fn open_file_no_symlink(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .with_context(|| format!("open artifact file {}", path.display()))
}

fn create_new_file_no_symlink(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .with_context(|| format!("create artifact zip {}", path.display()))
}

async fn exec_stream_to_file(
    container_name: &str,
    exec_args: &[&str],
    mut file: File,
) -> Result<u64> {
    let mut args = vec!["exec", container_name];
    args.extend_from_slice(exec_args);
    let mut command = Command::new("docker");
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().context("spawn docker exec")?;
    let mut stdout = child.stdout.take().context("docker stdout missing")?;
    let stderr = child.stderr.take();
    let stderr_task =
        stderr.map(|reader| tokio::spawn(read_limited(reader, MAX_COMMAND_OUTPUT_BYTES)));
    let copy = tokio::io::copy(&mut stdout, &mut file);
    let written = match timeout(BACKUP_TIMEOUT, copy).await {
        Ok(result) => result.context("stream docker output to file")?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("docker exec timed out after {}s", BACKUP_TIMEOUT.as_secs());
        }
    };
    file.flush().await?;
    let status = match timeout(DOCKER_OP_TIMEOUT, child.wait()).await {
        Ok(result) => result.context("wait for docker exec")?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("docker exec did not exit cleanly");
        }
    };
    let stderr = match stderr_task {
        Some(task) => task.await.unwrap_or_default(),
        None => Vec::new(),
    };
    if !status.success() {
        anyhow::bail!(
            "docker exec failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    Ok(written)
}

async fn read_limited<R>(mut reader: R, max_bytes: usize) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    while let Ok(read) = reader.read(&mut buf).await {
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(out.len());
        if remaining == 0 {
            continue;
        }
        out.extend_from_slice(&buf[..read.min(remaining)]);
    }
    out
}

async fn redis_lastsave(container_name: &str) -> Result<String> {
    let output = run_docker_output(
        &["exec", container_name, "redis-cli", "LASTSAVE"],
        DOCKER_OP_TIMEOUT,
    )
    .await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn wait_redis_bgsave(container_name: &str, baseline: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5 * 60);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if redis_lastsave(container_name)
            .await
            .is_ok_and(|current| current != baseline)
        {
            return Ok(());
        }
    }
    anyhow::bail!("BGSAVE did not complete within 5 minutes")
}

async fn docker_cp_to_container(
    container_name: &str,
    host_path: &Path,
    container_path: &str,
) -> Result<()> {
    run_docker_success(
        &[
            "cp",
            host_path.to_str().context("non-utf8 backup path")?,
            &format!("{container_name}:{container_path}"),
        ],
        BACKUP_TIMEOUT,
    )
    .await
}

async fn docker_stop(container_name: &str, timeout_seconds: u64) -> Result<()> {
    run_docker_success(
        &["stop", "-t", &timeout_seconds.to_string(), container_name],
        DOCKER_OP_TIMEOUT + Duration::from_secs(timeout_seconds + 5),
    )
    .await
}

async fn docker_start(container_name: &str) -> Result<()> {
    run_docker_success(&["start", container_name], DOCKER_OP_TIMEOUT).await
}

async fn docker_restart(container_name: &str, timeout_seconds: u64) -> Result<()> {
    run_docker_success(
        &[
            "restart",
            "-t",
            &timeout_seconds.to_string(),
            container_name,
        ],
        DOCKER_OP_TIMEOUT + Duration::from_secs(timeout_seconds + 5),
    )
    .await
}

async fn wait_container_running(container_name: &str, timeout_duration: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout_duration;
    while tokio::time::Instant::now() < deadline {
        if run_docker_output(
            &["inspect", "--format", "{{.State.Running}}", container_name],
            DOCKER_OP_TIMEOUT,
        )
        .await
        .is_ok_and(|output| {
            output.status_success && String::from_utf8_lossy(&output.stdout).trim() == "true"
        }) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("container {container_name} not running after {timeout_duration:?}")
}

async fn ensure_network(network: &str) -> Result<()> {
    if run_docker_output(&["network", "inspect", network], DOCKER_OP_TIMEOUT)
        .await
        .is_ok_and(|output| output.status_success)
    {
        return Ok(());
    }
    run_docker_success(
        &["network", "create", "--driver", "bridge", network],
        DOCKER_OP_TIMEOUT,
    )
    .await
}

struct CommandOutput {
    status_success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CommandOutput {
    fn combined_string(&self) -> String {
        let mut combined = self.stdout.clone();
        combined.extend_from_slice(&self.stderr);
        String::from_utf8_lossy(&combined).trim().to_string()
    }
}

async fn run_docker_success(args: &[&str], timeout_duration: Duration) -> Result<()> {
    let output = run_docker_output(args, timeout_duration).await?;
    if output.status_success {
        Ok(())
    } else {
        anyhow::bail!("{}", output.combined_string())
    }
}

async fn run_docker_output(args: &[&str], timeout_duration: Duration) -> Result<CommandOutput> {
    let mut command = Command::new("docker");
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(timeout_duration, command.output())
        .await
        .with_context(|| format!("docker timed out after {}s", timeout_duration.as_secs()))?
        .context("run docker")?;
    let mut stdout = output.stdout;
    let mut stderr = output.stderr;
    stdout.truncate(stdout.len().min(MAX_COMMAND_OUTPUT_BYTES));
    stderr.truncate(stderr.len().min(MAX_COMMAND_OUTPUT_BYTES));
    Ok(CommandOutput {
        status_success: output.status.success(),
        stdout,
        stderr,
    })
}

fn backup_result(
    operation: BackupOperation,
    storage_path: String,
    size_bytes: u64,
    storage_tier: &str,
) -> BackupResult {
    BackupResult {
        operation: operation.as_go_string(),
        storage_path,
        size_bytes: size_bytes as i64,
        storage_tier: storage_tier.to_string(),
        downloaded_bytes: 0,
        verified: false,
        verify_count: 0,
        restored_engine: String::new(),
    }
}

fn empty_result(operation: BackupOperation) -> BackupResult {
    backup_result(operation, String::new(), 0, "")
}

fn backup_short_id(backup_id: &str) -> String {
    if backup_id.len() >= 8 && validate_backup_id(backup_id).is_ok() {
        backup_id[..8].to_string()
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("manual-{now}")
    }
}

fn parse_count(out: &[u8]) -> i32 {
    let text = String::from_utf8_lossy(out);
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with('#') {
            continue;
        }
        if let Ok(value) = line.parse::<i32>() {
            return value;
        }
        if let Some((_, rest)) = line.split_once("keys=") {
            if let Some(value) = rest
                .split(',')
                .next()
                .and_then(|raw| raw.parse::<i32>().ok())
            {
                return value;
            }
        }
    }
    0
}

fn canonical_or_absolute(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    match std::fs::canonicalize(&absolute) {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(clean_path(&absolute)),
        Err(err) => Err(err).with_context(|| format!("resolve {}", absolute.display())),
    }
}

fn clean_path(path: &Path) -> PathBuf {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                cleaned.pop();
            }
            other => cleaned.push(other.as_os_str()),
        }
    }
    cleaned
}

fn path_within_root(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).is_ok()
}

fn validate_container_name(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        anyhow::bail!("{label} is required");
    }
    if bytes.len() > 128 {
        anyhow::bail!("{label} is too long");
    }
    if !bytes[0].is_ascii_alphanumeric() {
        anyhow::bail!("{label} contains invalid characters");
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}

fn validate_backup_id(value: &str) -> Result<()> {
    let segments: Vec<&str> = value.split('-').collect();
    if segments.len() != 5
        || segments.iter().zip([8, 4, 4, 4, 12]).any(|(segment, len)| {
            segment.len() != len || !segment.chars().all(|ch| ch.is_ascii_hexdigit())
        })
    {
        anyhow::bail!("invalid backup id {value:?}");
    }
    Ok(())
}

fn validate_no_control(value: &str, label: &str) -> Result<()> {
    if value
        .chars()
        .any(|ch| ch == '\0' || ch == '\r' || ch == '\n')
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}

fn validate_image_ref(value: &str) -> Result<()> {
    let image = value.trim();
    if image.is_empty() {
        anyhow::bail!("image is required");
    }
    validate_no_control(image, "image")?;
    if image.starts_with('-') || image.chars().any(|ch| ch.is_whitespace()) {
        anyhow::bail!("image contains invalid characters");
    }
    Ok(())
}

async fn send_running(
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
    text: &str,
) -> Result<()> {
    let mut output = text.as_bytes().to_vec();
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    tx.send(CommandResult {
        command_id: command_id.to_string(),
        status: "running".to_string(),
        output,
        is_final: false,
        timestamp: Some(now_timestamp()),
    })
    .await
    .context("send running result")
}

fn completed_json(command_id: &str, value: &impl Serialize) -> CommandResult {
    match serde_json::to_vec(value) {
        Ok(output) => CommandResult {
            command_id: command_id.to_string(),
            status: "completed".to_string(),
            output,
            is_final: true,
            timestamp: Some(now_timestamp()),
        },
        Err(err) => failed_text(command_id, &format!("marshal response: {err}")),
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
    use std::{fs, path::Path};

    const VALID_ID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn service_type_maps_to_backup_engine_names() {
        assert_eq!(
            service_type_to_engine("postgresql").as_go_string(),
            "BACKUP_ENGINE_POSTGRES"
        );
        assert_eq!(
            service_type_to_engine("mysql").as_go_string(),
            "BACKUP_ENGINE_MYSQL"
        );
        assert_eq!(
            service_type_to_engine("mongodb").as_go_string(),
            "BACKUP_ENGINE_MONGO"
        );
        assert_eq!(
            service_type_to_engine("redis").as_go_string(),
            "BACKUP_ENGINE_REDIS"
        );
    }

    #[test]
    fn create_payload_requires_container_and_uuid() {
        let parsed = parse_backup_payload(
            br#"{"service_type":"postgresql","container_name":"deploy-postgresql-abc","backup_id":"11111111-2222-3333-4444-555555555555"}"#,
            BackupOperation::Create,
        )
        .expect("parse backup payload");

        assert_eq!(parsed.engine, BackupEngine::Postgres);
        assert_eq!(parsed.container_name, "deploy-postgresql-abc");
        assert_eq!(parsed.backup_id, VALID_ID);
    }

    #[test]
    fn local_backup_write_path_rejects_traversal() {
        assert!(local_backup_write_path("../evil", VALID_ID, ".tar.gz").is_err());
        assert!(local_backup_write_path("deploy/postgres", VALID_ID, ".tar.gz").is_err());
        assert!(local_backup_write_path("deploy-postgresql-abc", "not-a-uuid", ".tar.gz").is_err());
        assert!(local_backup_write_path("deploy-postgresql-abc", VALID_ID, ".zip").is_err());
    }

    #[test]
    fn local_backup_write_path_uses_backup_root() {
        let path = local_backup_write_path("deploy-postgresql-abc", VALID_ID, ".tar.gz")
            .expect("local path");

        assert!(path.starts_with(Path::new(BACKUP_DATA_DIR)));
        assert!(path.ends_with(format!("deploy-postgresql-abc/{VALID_ID}.tar.gz")));
    }

    #[test]
    fn resolve_local_path_accepts_file_inside_root() {
        let root = tempfile_like_dir("permanu-agent-backup-root");
        let backup_path = root.join("backup.tar.gz");
        fs::write(&backup_path, b"backup-data").expect("write backup");

        let (resolved, size) = resolve_local_path_with_root(
            &root,
            &format!("agent-local://{}", backup_path.display()),
        )
        .expect("resolve local path");

        assert_eq!(resolved.file_name(), backup_path.file_name());
        assert_eq!(size, 11);
    }

    #[test]
    fn resolve_local_path_rejects_missing_scheme() {
        let err = resolve_local_path("/var/lib/permanu-agent/backups/file.tar.gz").unwrap_err();

        assert!(err.to_string().contains("agent-local://"));
    }

    #[test]
    fn resolve_local_path_rejects_directory() {
        let dir = tempfile_like_dir("permanu-agent-backup-dir");
        let storage = format!("agent-local://{}", dir.display());
        let err = resolve_local_path(&storage).unwrap_err();

        assert!(
            err.to_string().contains("outside backup root")
                || err.to_string().contains("directory")
        );
    }

    #[test]
    fn parse_count_handles_database_outputs() {
        assert_eq!(parse_count(b"42\n"), 42);
        assert_eq!(parse_count(b"# Keyspace\ndb0:keys=7,expires=0\n"), 7);
        assert_eq!(parse_count(b"not-a-number\n"), 0);
    }

    #[test]
    fn backup_result_matches_go_json_shape() {
        let result = backup_result(
            BackupOperation::Create,
            "agent-local:///var/lib/permanu-agent/backups/c/b.tar.gz".to_string(),
            123,
            "local",
        );
        let json = serde_json::to_value(&result).expect("marshal result");

        assert_eq!(json["operation"], "BACKUP_OPERATION_CREATE");
        assert_eq!(
            json["storage_path"],
            "agent-local:///var/lib/permanu-agent/backups/c/b.tar.gz"
        );
        assert_eq!(json["size_bytes"], 123);
        assert_eq!(json["downloaded_bytes"], 0);
        assert_eq!(json["verified"], false);
        assert_eq!(json["verify_count"], 0);
        assert_eq!(json["restored_engine"], "");
    }

    #[tokio::test]
    async fn stream_download_file_uses_64k_chunks() {
        let dir = tempfile_like_dir("permanu-agent-download");
        let file_path = dir.join("backup.tar.gz");
        let data = vec![b'x'; DOWNLOAD_CHUNK_SIZE + 3];
        fs::write(&file_path, &data).expect("write backup");
        let (tx, mut rx) = mpsc::channel(4);

        let total = stream_download_file(&file_path, &tx, "cmd-1")
            .await
            .expect("stream file");

        assert_eq!(total, (DOWNLOAD_CHUNK_SIZE + 3) as i64);
        let first = rx.recv().await.expect("first chunk");
        let second = rx.recv().await.expect("second chunk");
        assert_eq!(first.status, "running");
        assert_eq!(first.output.len(), DOWNLOAD_CHUNK_SIZE);
        assert_eq!(second.output.len(), 3);
    }

    #[tokio::test]
    async fn stream_download_with_metadata_sends_header_before_file_chunks() {
        let dir = tempfile_like_dir("permanu-agent-download-metadata");
        let file_path = dir.join("artifact.bin");
        fs::write(&file_path, b"artifact-bytes").expect("write artifact");
        let (tx, mut rx) = mpsc::channel(4);
        let prepared = PreparedDownload {
            local_path: file_path,
            cleanup_path: None,
            filename: "artifact.bin".to_string(),
            size_bytes: 14,
            content_type: "application/octet-stream".to_string(),
        };

        let total = stream_download_with_metadata(&prepared, &tx, "cmd-1")
            .await
            .expect("stream download");

        assert_eq!(total, 14);
        let header = rx.recv().await.expect("metadata header");
        assert_eq!(header.status, "running");
        assert!(!header.is_final);
        assert!(header.output.ends_with(b"\n"));
        let metadata: serde_json::Value =
            serde_json::from_slice(&header.output[..header.output.len() - 1])
                .expect("metadata json");
        assert_eq!(metadata["filename"], "artifact.bin");
        assert_eq!(metadata["size_bytes"], 14);
        let chunk = rx.recv().await.expect("file chunk");
        assert_eq!(chunk.output, b"artifact-bytes");
    }

    #[test]
    fn resolve_artifact_path_rejects_traversal() {
        let root = tempfile_like_dir("permanu-agent-artifact-root");
        let err = resolve_artifact_path_with_root(&root, "agent-artifact://../secret")
            .expect_err("reject traversal");

        assert!(err
            .to_string()
            .contains("artifact storage path must stay inside artifact root"));
    }

    #[tokio::test]
    async fn prepare_agent_artifact_download_zips_directory() {
        let root = tempfile_like_dir("permanu-agent-artifact-zip-root");
        let artifact_dir = root.join("run/job/0-release");
        fs::create_dir_all(artifact_dir.join("dist")).expect("create artifact dir");
        fs::write(artifact_dir.join("dist/app"), b"release-binary").expect("write artifact");
        let payload =
            test_download_payload("agent-artifact://run/job/0-release", "release-bundle", "");

        let prepared = prepare_agent_artifact_download_with_root(&payload, &root)
            .await
            .expect("prepare artifact");

        assert_eq!(prepared.filename, "release-bundle.zip");
        assert_eq!(prepared.content_type, "application/zip");
        assert!(prepared.size_bytes > 0);
        let zip_file = std::fs::File::open(&prepared.local_path).expect("open zip");
        let mut archive = zip::ZipArchive::new(zip_file).expect("zip archive");
        let mut file = archive.by_name("dist/app").expect("zip entry");
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut contents).expect("read zip entry");
        assert_eq!(contents, b"release-binary");
        if let Some(cleanup_path) = prepared.cleanup_path {
            let _ = fs::remove_file(cleanup_path);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepare_agent_artifact_download_rejects_symlink_in_directory() {
        let root = tempfile_like_dir("permanu-agent-artifact-symlink-root");
        let artifact_dir = root.join("run/job/0-release");
        let outside = tempfile_like_dir("permanu-agent-artifact-symlink-outside");
        fs::create_dir_all(&artifact_dir).expect("create artifact dir");
        fs::write(outside.join("secret.txt"), b"secret").expect("write secret");
        std::os::unix::fs::symlink(outside.join("secret.txt"), artifact_dir.join("secret.txt"))
            .expect("symlink secret");
        let payload = test_download_payload("agent-artifact://run/job/0-release", "release", "");

        let err = prepare_agent_artifact_download_with_root(&payload, &root)
            .await
            .expect_err("reject symlink");

        assert!(err.to_string().contains("symlink"), "{err}");
    }

    fn test_download_payload(
        storage_path: &str,
        download_filename: &str,
        content_type: &str,
    ) -> BackupPayload {
        BackupPayload {
            operation: BackupOperation::Download,
            engine: BackupEngine::Unspecified,
            container_name: String::new(),
            backup_id: String::new(),
            storage_path: storage_path.to_string(),
            image: String::new(),
            s3_endpoint: String::new(),
            s3_bucket: String::new(),
            download_filename: download_filename.to_string(),
            content_type: content_type.to_string(),
        }
    }

    fn tempfile_like_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
