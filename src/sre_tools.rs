use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::{net::TcpStream, process::Command, time::timeout};

use crate::{proto::agent::v1::CommandResult, timeutil::now_timestamp};

pub const MAX_LIMIT: usize = 200;
const DEFAULT_LIMIT: usize = 50;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

const JOURNAL_UNITS: &[&str] = &["permanu-agent", "dwaar", "docker", "ssh", "postgresql"];
const SERVICE_UNITS: &[&str] = &["permanu-agent", "dwaar", "docker", "ssh", "postgresql"];
const TCP_PROBE_PORTS: &[u16] = &[80, 443, 5432, 6379, 8080, 8443, 9000, 9090];
const SAFE_BASES: &[&str] = &[
    "/etc/dwaar",
    "/run/dwaar",
    "/var/log/dwaar",
    "/var/lib/permanu",
    "/var/log/permanu",
];
const SAFE_FILES: &[&str] = &[
    "/etc/permanu/permanu-agent.yaml",
    "/etc/dwaar/Dwaarfile",
    "/etc/docker/daemon.json",
    "/etc/systemd/system/permanu-agent.service",
    "/var/log/permanu-agent.log",
    "/var/log/dwaar/dwaar.log",
    "/var/log/dwaar/access.log",
    "/var/log/dwaar/error.log",
    "/var/log/docker.log",
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/messages",
    "/var/log/secure",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticKind {
    HostSnapshot,
    MetricsSample,
    ProcessesTop,
    ProcessInspect,
    NetworkListeners,
    NetworkConnections,
    DnsCheck,
    HttpProbe,
    TlsInspect,
    LogsTail,
    JournalQuery,
    ServiceStatus,
    ContainersList,
    ContainerInspect,
    ContainerLogs,
    FileStat,
    ConfigDigest,
    PackageInventory,
    PermanuSelfStatus,
    CommandHistory,
    AuditLocal,
    ResourceAlerts,
    TraceRoute,
    SafeProbeTcp,
}

impl DiagnosticKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HostSnapshot => "agent.host.snapshot",
            Self::MetricsSample => "agent.metrics.sample",
            Self::ProcessesTop => "agent.processes.top",
            Self::ProcessInspect => "agent.process.inspect",
            Self::NetworkListeners => "agent.network.listeners",
            Self::NetworkConnections => "agent.network.connections",
            Self::DnsCheck => "agent.dns.check",
            Self::HttpProbe => "agent.http.probe",
            Self::TlsInspect => "agent.tls.inspect",
            Self::LogsTail => "agent.logs.tail",
            Self::JournalQuery => "agent.journal.query",
            Self::ServiceStatus => "agent.service.status",
            Self::ContainersList => "agent.containers.list",
            Self::ContainerInspect => "agent.container.inspect",
            Self::ContainerLogs => "agent.container.logs",
            Self::FileStat => "agent.file.stat",
            Self::ConfigDigest => "agent.config.digest",
            Self::PackageInventory => "agent.package.inventory",
            Self::PermanuSelfStatus => "agent.permanu.self.status",
            Self::CommandHistory => "agent.command.history",
            Self::AuditLocal => "agent.audit.local",
            Self::ResourceAlerts => "agent.resource.alerts",
            Self::TraceRoute => "agent.trace.route",
            Self::SafeProbeTcp => "agent.safe_probe.tcp",
        }
    }
}

impl TryFrom<&str> for DiagnosticKind {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        Ok(match value {
            "agent.host.snapshot" => Self::HostSnapshot,
            "agent.metrics.sample" => Self::MetricsSample,
            "agent.processes.top" => Self::ProcessesTop,
            "agent.process.inspect" => Self::ProcessInspect,
            "agent.network.listeners" => Self::NetworkListeners,
            "agent.network.connections" => Self::NetworkConnections,
            "agent.dns.check" => Self::DnsCheck,
            "agent.http.probe" => Self::HttpProbe,
            "agent.tls.inspect" => Self::TlsInspect,
            "agent.logs.tail" => Self::LogsTail,
            "agent.journal.query" => Self::JournalQuery,
            "agent.service.status" => Self::ServiceStatus,
            "agent.containers.list" => Self::ContainersList,
            "agent.container.inspect" => Self::ContainerInspect,
            "agent.container.logs" => Self::ContainerLogs,
            "agent.file.stat" => Self::FileStat,
            "agent.config.digest" => Self::ConfigDigest,
            "agent.package.inventory" => Self::PackageInventory,
            "agent.permanu.self.status" => Self::PermanuSelfStatus,
            "agent.command.history" => Self::CommandHistory,
            "agent.audit.local" => Self::AuditLocal,
            "agent.resource.alerts" => Self::ResourceAlerts,
            "agent.trace.route" => Self::TraceRoute,
            "agent.safe_probe.tcp" => Self::SafeProbeTcp,
            other => anyhow::bail!("unsupported kind {other:?}"),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RawRequest {
    kind: String,
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    sort_by: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    lines: usize,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    container: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticRequest {
    pub kind: DiagnosticKind,
    pub limit: usize,
    pid: Option<u32>,
    sort_by: String,
    host: Option<String>,
    port: Option<u16>,
    path: Option<PathBuf>,
    unit: Option<String>,
    method: String,
    lines: usize,
    since: String,
    container: Option<String>,
    url: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct TcpSocketRow {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub inode: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ProcessRow {
    pub pid: u32,
    pub user: String,
    pub command: String,
    pub cpu_percent: f64,
    pub mem_percent: f64,
    pub rss_kib: u64,
}

#[derive(Clone, Debug)]
struct FixedCommand {
    program: &'static str,
    args: Vec<String>,
    timeout: Duration,
    max_output_bytes: usize,
}

impl FixedCommand {
    fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: MAX_OUTPUT_BYTES,
        }
    }
}

pub fn parse_request(payload: &[u8]) -> Result<DiagnosticRequest> {
    let raw: RawRequest = serde_json::from_slice(payload).context("malformed payload")?;
    let kind = parse_kind(raw.kind.as_str())?;
    let limit = normalized_limit(raw.limit);
    let lines = normalized_limit(raw.lines);
    let target = raw.target.clone();
    let host = raw
        .host
        .or(raw.hostname)
        .or_else(|| host_target(&kind, target.as_deref()))
        .map(normalize_host);
    let path = raw
        .path
        .or_else(|| source_path(&kind, raw.source.as_deref(), target.as_deref()))
        .as_deref()
        .map(validate_safe_path)
        .transpose()?;
    let unit = raw
        .unit
        .or(raw.service)
        .map(|unit| validate_unit(&unit, &kind))
        .transpose()?;
    let method = validate_method(raw.method.as_deref())?;
    let container = raw
        .container
        .map(|container| validate_container_id(&container))
        .transpose()?;
    let port = raw
        .port
        .map(|port| validate_port(port, &kind))
        .transpose()?;
    let url = raw.url.map(|url| validate_probe_url(&url)).transpose()?;
    let sort_by = match raw.sort_by.as_deref().unwrap_or("cpu") {
        "cpu" | "mem" | "io" | "time" => raw.sort_by.unwrap_or_else(|| "cpu".to_string()),
        other => anyhow::bail!("sort_by {other:?} not in allowlist"),
    };

    validate_kind_requirements(RequirementInputs {
        kind: &kind,
        pid: raw.pid,
        host: host.as_deref(),
        port,
        path: path.as_deref(),
        unit: unit.as_deref(),
        container: container.as_deref(),
        url: url.as_deref(),
    })?;
    validate_request_host(&kind, host.as_deref())?;

    Ok(DiagnosticRequest {
        kind,
        limit,
        pid: raw.pid,
        sort_by,
        host,
        port,
        path,
        unit,
        method,
        lines,
        since: validate_since(raw.since.as_deref().unwrap_or("5m"))?,
        container,
        url,
    })
}

fn parse_kind(kind: &str) -> Result<DiagnosticKind> {
    match kind {
        "process_list" => Ok(DiagnosticKind::ProcessesTop),
        "listeners" => Ok(DiagnosticKind::NetworkListeners),
        "journal_tail" => Ok(DiagnosticKind::JournalQuery),
        other => DiagnosticKind::try_from(other),
    }
}

pub async fn handle_command(command_id: &str, payload: &[u8]) -> CommandResult {
    let request = match parse_request(payload) {
        Ok(request) => request,
        Err(err) => {
            return failed_text(
                command_id,
                &format!("invalid SRE diagnostic payload: {err}"),
            )
        }
    };

    match collect(&request).await {
        Ok(data) => completed_json(command_id, request.kind.as_str(), data),
        Err(err) => failed_text(command_id, &format!("{}: {err}", request.kind.as_str())),
    }
}

async fn collect(request: &DiagnosticRequest) -> Result<Value> {
    let value = match request.kind {
        DiagnosticKind::HostSnapshot => host_snapshot()?,
        DiagnosticKind::MetricsSample => metrics_sample()?,
        DiagnosticKind::ProcessesTop => processes_top(request).await?,
        DiagnosticKind::ProcessInspect => process_inspect(require_pid(request)?)?,
        DiagnosticKind::NetworkListeners => network_sockets(true, request.limit)?,
        DiagnosticKind::NetworkConnections => network_sockets(false, request.limit)?,
        DiagnosticKind::DnsCheck => {
            run_json_command(
                request,
                FixedCommand::new("getent", ["hosts", require_host(request)?]),
            )
            .await?
        }
        DiagnosticKind::HttpProbe => http_probe(request).await?,
        DiagnosticKind::TlsInspect => tls_inspect(request).await?,
        DiagnosticKind::LogsTail => logs_tail(request)?,
        DiagnosticKind::JournalQuery => journal_query(request).await?,
        DiagnosticKind::ServiceStatus => service_status(request).await?,
        DiagnosticKind::ContainersList => {
            run_json_command(
                request,
                FixedCommand::new("docker", ["ps", "--no-trunc", "--format", "{{json .}}"]),
            )
            .await?
        }
        DiagnosticKind::ContainerInspect => {
            run_json_command(
                request,
                FixedCommand::new("docker", ["inspect", require_container(request)?]),
            )
            .await?
        }
        DiagnosticKind::ContainerLogs => {
            run_json_command(
                request,
                FixedCommand::new(
                    "docker",
                    [
                        "logs",
                        "--tail",
                        &request.lines.to_string(),
                        require_container(request)?,
                    ],
                ),
            )
            .await?
        }
        DiagnosticKind::FileStat => file_stat(require_path(request)?)?,
        DiagnosticKind::ConfigDigest => config_digest(require_path(request)?)?,
        DiagnosticKind::PackageInventory => package_inventory(request).await?,
        DiagnosticKind::PermanuSelfStatus => permanu_self_status().await?,
        DiagnosticKind::CommandHistory => {
            logs_tail_path(Path::new("/var/log/permanu/commands.log"), request.lines)?
        }
        DiagnosticKind::AuditLocal => {
            logs_tail_path(Path::new("/var/log/permanu/audit.log"), request.lines)?
        }
        DiagnosticKind::ResourceAlerts => local_resource_alerts()?,
        DiagnosticKind::TraceRoute => {
            run_json_command(
                request,
                FixedCommand::new("ip", ["route", "get", require_host(request)?]),
            )
            .await?
        }
        DiagnosticKind::SafeProbeTcp => tcp_probe(request).await?,
    };
    Ok(redact_value(value))
}

pub fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(redact_object(map)),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_value).collect()),
        Value::String(text) => Value::String(redact_text(&text)),
        other => other,
    }
}

fn redact_object(map: Map<String, Value>) -> Map<String, Value> {
    let mut redacted = Map::new();
    for (key, value) in map {
        if is_secret_key(&key) {
            redacted.insert(key, Value::String("[REDACTED]".to_string()));
        } else {
            redacted.insert(key, redact_value(value));
        }
    }
    redacted
}

fn redact_text(text: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut parts = Vec::with_capacity(words.len());
    let mut idx = 0;
    while idx < words.len() {
        let part = words[idx];
        let lower = part.to_ascii_lowercase();
        if lower.starts_with("password=")
            || lower.starts_with("token=")
            || lower.starts_with("secret=")
            || lower.starts_with("api_key=")
        {
            let key = part.split_once('=').map(|(key, _)| key).unwrap_or(part);
            parts.push(format!("{key}=[REDACTED]"));
        } else if matches!(
            lower.as_str(),
            "--token" | "--password" | "--secret" | "--api-key"
        ) {
            parts.push(part.to_string());
            if idx + 1 < words.len() {
                parts.push("[REDACTED]".to_string());
                idx += 1;
            }
        } else if lower == "bearer" && idx + 1 < words.len() {
            parts.push(part.to_string());
            parts.push("[REDACTED]".to_string());
            idx += 1;
        } else {
            parts.push(part.to_string());
        }
        idx += 1;
    }
    parts.join(" ")
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "authorization",
        "database_url",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

pub fn parse_ps_rows(output: &str, limit: usize) -> Vec<ProcessRow> {
    let mut rows = Vec::new();
    for line in output.lines().skip(1) {
        if rows.len() >= limit {
            break;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let Ok(pid) = fields[0].parse::<u32>() else {
            continue;
        };
        let Ok(cpu_percent) = fields[fields.len() - 3].parse::<f64>() else {
            continue;
        };
        let Ok(mem_percent) = fields[fields.len() - 2].parse::<f64>() else {
            continue;
        };
        let Ok(rss_kib) = fields[fields.len() - 1].parse::<u64>() else {
            continue;
        };
        let command = fields[2..fields.len() - 3].join(" ");
        if is_kernel_thread_ps_row(&command, rss_kib) {
            continue;
        }
        rows.push(ProcessRow {
            pid,
            user: fields[1].to_string(),
            command: redact_text(&command),
            cpu_percent,
            mem_percent,
            rss_kib,
        });
    }
    rows
}

fn is_kernel_thread_ps_row(command: &str, rss_kib: u64) -> bool {
    rss_kib == 0 && command.starts_with('[') && command.ends_with(']')
}

pub fn parse_proc_net_tcp(content: &str, limit: usize) -> Vec<TcpSocketRow> {
    let mut rows = Vec::new();
    for line in content.lines().skip(1) {
        if rows.len() >= limit {
            break;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some((local_addr, local_port)) = parse_socket_addr(fields[1]) else {
            continue;
        };
        let Some((remote_addr, remote_port)) = parse_socket_addr(fields[2]) else {
            continue;
        };
        rows.push(TcpSocketRow {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state: tcp_state(fields[3]).to_string(),
            inode: fields[9].to_string(),
        });
    }
    rows
}

async fn run_json_command(request: &DiagnosticRequest, spec: FixedCommand) -> Result<Value> {
    let output = run_fixed_command(&spec).await?;
    Ok(json!({
        "limit": request.limit,
        "program": spec.program,
        "args": spec.args,
        "output": output,
    }))
}

async fn run_fixed_command(spec: &FixedCommand) -> Result<String> {
    let mut command = Command::new(spec.program);
    command.args(spec.args.iter().map(OsStr::new));
    command.kill_on_drop(true);
    let output = timeout(spec.timeout, command.output())
        .await
        .with_context(|| format!("{} timed out", spec.program))?
        .with_context(|| format!("run {}", spec.program))?;
    let mut combined = output.stdout;
    combined.extend(output.stderr);
    if combined.len() > spec.max_output_bytes {
        combined.truncate(spec.max_output_bytes);
    }
    let text = String::from_utf8_lossy(&combined).to_string();
    if !output.status.success() && text.trim().is_empty() {
        anyhow::bail!("{} exited with {}", spec.program, output.status);
    }
    Ok(text)
}

async fn processes_top(request: &DiagnosticRequest) -> Result<Value> {
    let sort = match request.sort_by.as_str() {
        "mem" => "-pmem",
        "time" => "-start_time",
        "io" => "-rss",
        _ => "-pcpu",
    };
    let output = run_fixed_command(&FixedCommand::new(
        "ps",
        [
            "-eo",
            "pid,user,args,pcpu,pmem,rss",
            &format!("--sort={sort}"),
        ],
    ))
    .await?;
    Ok(json!({ "processes": parse_ps_rows(&output, request.limit) }))
}

fn host_snapshot() -> Result<Value> {
    Ok(json!({
        "os_release": read_key_value_file(Path::new("/etc/os-release")).unwrap_or_default(),
        "uptime": read_trimmed(Path::new("/proc/uptime")).unwrap_or_default(),
        "loadavg": read_trimmed(Path::new("/proc/loadavg")).unwrap_or_default(),
        "hostname": read_trimmed(Path::new("/proc/sys/kernel/hostname")).unwrap_or_default(),
        "meminfo": parse_key_value_colon(&read_trimmed(Path::new("/proc/meminfo")).unwrap_or_default()),
    }))
}

fn metrics_sample() -> Result<Value> {
    Ok(json!({
        "stat": read_trimmed(Path::new("/proc/stat")).unwrap_or_default().lines().take(5).collect::<Vec<_>>(),
        "loadavg": read_trimmed(Path::new("/proc/loadavg")).unwrap_or_default(),
        "meminfo": parse_key_value_colon(&read_trimmed(Path::new("/proc/meminfo")).unwrap_or_default()),
        "disk": read_trimmed(Path::new("/proc/diskstats")).unwrap_or_default().lines().take(32).collect::<Vec<_>>(),
    }))
}

fn process_inspect(pid: u32) -> Result<Value> {
    if pid == 0 {
        anyhow::bail!("pid must be positive");
    }
    let base = PathBuf::from(format!("/proc/{pid}"));
    Ok(json!({
        "pid": pid,
        "status": parse_key_value_colon(&read_trimmed(&base.join("status")).unwrap_or_default()),
        "cmdline": redact_text(&read_cmdline(&base.join("cmdline")).unwrap_or_default()),
        "limits": read_trimmed(&base.join("limits")).unwrap_or_default().lines().take(64).collect::<Vec<_>>(),
    }))
}

fn network_sockets(listeners_only: bool, limit: usize) -> Result<Value> {
    let mut rows = parse_proc_net_tcp(&read_trimmed(Path::new("/proc/net/tcp"))?, limit);
    if listeners_only {
        rows.retain(|row| row.state == "listen");
    }
    Ok(json!({ "sockets": rows.into_iter().take(limit).collect::<Vec<_>>() }))
}

async fn http_probe(request: &DiagnosticRequest) -> Result<Value> {
    let url = require_url(request)?;
    if url.starts_with("https://") {
        return run_json_command(
            request,
            FixedCommand::new(
                "curl",
                vec![
                    "-sS".to_string(),
                    "-o".to_string(),
                    "/dev/null".to_string(),
                    "-D".to_string(),
                    "-".to_string(),
                    "-X".to_string(),
                    request.method.clone(),
                    "--max-time".to_string(),
                    "5".to_string(),
                    "--connect-timeout".to_string(),
                    "5".to_string(),
                    url.to_string(),
                ],
            ),
        )
        .await;
    }
    let (host, port, path) = parse_http_url(url)?;
    let start = Instant::now();
    let mut stream = timeout(DEFAULT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .context("connect timed out")?
        .context("connect")?;
    let request_text = format!(
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        request.method
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    timeout(DEFAULT_TIMEOUT, stream.write_all(request_text.as_bytes()))
        .await
        .context("write timed out")??;
    let mut buf = vec![0; 2048];
    let n = timeout(DEFAULT_TIMEOUT, stream.read(&mut buf))
        .await
        .context("read timed out")??;
    let head = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    Ok(json!({"url": url, "status_line": head, "elapsed_ms": start.elapsed().as_millis()}))
}

async fn tls_inspect(request: &DiagnosticRequest) -> Result<Value> {
    let host = require_host(request)?;
    let port = request.port.unwrap_or(443);
    run_json_command(
        request,
        FixedCommand::new(
            "openssl",
            [
                "s_client",
                "-connect",
                &format!("{host}:{port}"),
                "-servername",
                host,
                "-brief",
            ],
        ),
    )
    .await
}

fn logs_tail(request: &DiagnosticRequest) -> Result<Value> {
    logs_tail_path(require_path(request)?, request.lines)
}

fn logs_tail_path(path: &Path, lines: usize) -> Result<Value> {
    if !safe_path(path) {
        anyhow::bail!("path {:?} is not allowlisted", path);
    }
    let text = read_limited(path, MAX_FILE_BYTES)?;
    let mut rows: Vec<&str> = text.lines().rev().take(lines).collect();
    rows.reverse();
    Ok(json!({"path": path, "lines": rows}))
}

async fn journal_query(request: &DiagnosticRequest) -> Result<Value> {
    run_json_command(
        request,
        FixedCommand::new(
            "journalctl",
            [
                "-u",
                require_unit(request)?,
                "--since",
                &request.since,
                "--no-pager",
                "-n",
                &request.lines.to_string(),
                "--output=short-iso",
            ],
        ),
    )
    .await
}

async fn service_status(request: &DiagnosticRequest) -> Result<Value> {
    run_json_command(
        request,
        FixedCommand::new(
            "systemctl",
            [
                "show",
                require_unit(request)?,
                "--no-pager",
                "--property=Id,ActiveState,SubState,LoadState,ExecMainPID,NRestarts",
            ],
        ),
    )
    .await
}

fn file_stat(path: &Path) -> Result<Value> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {:?}", path))?;
    Ok(json!({
        "path": path,
        "is_file": meta.is_file(),
        "is_dir": meta.is_dir(),
        "len": meta.len(),
        "readonly": meta.permissions().readonly(),
    }))
}

fn config_digest(path: &Path) -> Result<Value> {
    let data = read_limited(path, MAX_FILE_BYTES)?;
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    Ok(json!({"path": path, "sha256": format!("{:x}", hasher.finalize()), "bytes": data.len()}))
}

async fn package_inventory(request: &DiagnosticRequest) -> Result<Value> {
    match run_json_command(
        request,
        FixedCommand::new("dpkg-query", ["-W", "-f=${Package} ${Version}\n"]),
    )
    .await
    {
        Ok(value) => Ok(value),
        Err(_) => run_json_command(request, FixedCommand::new("rpm", ["-qa"])).await,
    }
}

async fn permanu_self_status() -> Result<Value> {
    let unit = DiagnosticRequest {
        kind: DiagnosticKind::PermanuSelfStatus,
        limit: DEFAULT_LIMIT,
        pid: None,
        sort_by: "cpu".to_string(),
        host: None,
        port: None,
        path: None,
        unit: Some("permanu-agent".to_string()),
        method: "GET".to_string(),
        lines: DEFAULT_LIMIT,
        since: "5m".to_string(),
        container: None,
        url: None,
    };
    service_status(&unit).await
}

fn local_resource_alerts() -> Result<Value> {
    let meminfo =
        parse_key_value_colon(&read_trimmed(Path::new("/proc/meminfo")).unwrap_or_default());
    let load = read_trimmed(Path::new("/proc/loadavg")).unwrap_or_default();
    Ok(json!({"loadavg": load, "meminfo": meminfo, "alerts": []}))
}

async fn tcp_probe(request: &DiagnosticRequest) -> Result<Value> {
    let host = require_host(request)?;
    let port = require_port(request)?;
    let addr = SocketAddr::new(resolve_safe_ip(host)?, port);
    let start = Instant::now();
    let connected = timeout(DEFAULT_TIMEOUT, TcpStream::connect(addr)).await;
    Ok(json!({
        "host": host,
        "port": port,
        "ok": matches!(connected, Ok(Ok(_))),
        "elapsed_ms": start.elapsed().as_millis(),
    }))
}

fn normalized_limit(value: usize) -> usize {
    if value == 0 {
        DEFAULT_LIMIT
    } else {
        value.min(MAX_LIMIT)
    }
}

fn require_pid(request: &DiagnosticRequest) -> Result<u32> {
    request
        .pid
        .ok_or_else(|| anyhow::anyhow!("pid is required"))
}

fn require_host(request: &DiagnosticRequest) -> Result<&str> {
    request
        .host
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("host is required"))
}

fn require_port(request: &DiagnosticRequest) -> Result<u16> {
    request
        .port
        .ok_or_else(|| anyhow::anyhow!("port is required"))
}

fn require_path(request: &DiagnosticRequest) -> Result<&Path> {
    request
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("path is required"))
}

fn require_unit(request: &DiagnosticRequest) -> Result<&str> {
    request
        .unit
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("unit is required"))
}

fn require_container(request: &DiagnosticRequest) -> Result<&str> {
    request
        .container
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("container is required"))
}

fn require_url(request: &DiagnosticRequest) -> Result<&str> {
    request
        .url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("url is required"))
}

fn host_target(kind: &DiagnosticKind, target: Option<&str>) -> Option<String> {
    match kind {
        DiagnosticKind::DnsCheck
        | DiagnosticKind::TraceRoute
        | DiagnosticKind::TlsInspect
        | DiagnosticKind::SafeProbeTcp => target.map(str::to_string),
        _ => None,
    }
}

fn source_path(
    kind: &DiagnosticKind,
    source: Option<&str>,
    target: Option<&str>,
) -> Option<String> {
    match kind {
        DiagnosticKind::LogsTail => match source {
            Some("permanu-agent") => Some("/var/log/permanu-agent.log".to_string()),
            Some("dwaar") => Some("/var/log/dwaar/dwaar.log".to_string()),
            Some("docker") => Some("/var/log/docker.log".to_string()),
            Some("syslog") => Some("/var/log/syslog".to_string()),
            Some("auth") => Some("/var/log/auth.log".to_string()),
            _ => None,
        },
        DiagnosticKind::ConfigDigest => match target {
            Some("permanu-agent") => Some("/etc/permanu/permanu-agent.yaml".to_string()),
            Some("dwaar") => Some("/etc/dwaar/Dwaarfile".to_string()),
            Some("docker") => Some("/etc/docker/daemon.json".to_string()),
            Some("systemd") => Some("/etc/systemd/system/permanu-agent.service".to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn validate_method(method: Option<&str>) -> Result<String> {
    let method = method.unwrap_or("GET");
    match method {
        "GET" | "HEAD" => Ok(method.to_string()),
        other => anyhow::bail!("method {other:?} not in allowlist"),
    }
}

struct RequirementInputs<'a> {
    kind: &'a DiagnosticKind,
    pid: Option<u32>,
    host: Option<&'a str>,
    port: Option<u16>,
    path: Option<&'a Path>,
    unit: Option<&'a str>,
    container: Option<&'a str>,
    url: Option<&'a str>,
}

fn validate_kind_requirements(input: RequirementInputs<'_>) -> Result<()> {
    match input.kind {
        DiagnosticKind::ProcessInspect if input.pid.is_none() => anyhow::bail!("pid is required"),
        DiagnosticKind::DnsCheck | DiagnosticKind::TraceRoute if input.host.is_none() => {
            anyhow::bail!("host is required")
        }
        DiagnosticKind::SafeProbeTcp if input.host.is_none() || input.port.is_none() => {
            anyhow::bail!("host and port are required")
        }
        DiagnosticKind::HttpProbe if input.url.is_none() => anyhow::bail!("url is required"),
        DiagnosticKind::TlsInspect if input.host.is_none() => anyhow::bail!("host is required"),
        DiagnosticKind::LogsTail | DiagnosticKind::FileStat | DiagnosticKind::ConfigDigest
            if input.path.is_none() =>
        {
            anyhow::bail!("path is required")
        }
        DiagnosticKind::JournalQuery | DiagnosticKind::ServiceStatus if input.unit.is_none() => {
            anyhow::bail!("unit is required")
        }
        DiagnosticKind::ContainerInspect | DiagnosticKind::ContainerLogs
            if input.container.is_none() =>
        {
            anyhow::bail!("container is required")
        }
        _ => {}
    }
    Ok(())
}

fn validate_request_host(kind: &DiagnosticKind, host: Option<&str>) -> Result<()> {
    let Some(host) = host else {
        return Ok(());
    };
    match kind {
        DiagnosticKind::SafeProbeTcp | DiagnosticKind::TlsInspect | DiagnosticKind::TraceRoute => {
            validate_safe_host(host)
        }
        DiagnosticKind::DnsCheck => validate_hostname_arg(host),
        _ => Ok(()),
    }
}

fn validate_unit(unit: &str, kind: &DiagnosticKind) -> Result<String> {
    let allowlist = match kind {
        DiagnosticKind::JournalQuery => JOURNAL_UNITS,
        DiagnosticKind::ServiceStatus => SERVICE_UNITS,
        _ => return Ok(unit.to_string()),
    };
    if !allowlist.contains(&unit) {
        anyhow::bail!("unit {unit:?} not in allowlist");
    }
    Ok(unit.to_string())
}

fn validate_port(port: u16, kind: &DiagnosticKind) -> Result<u16> {
    if matches!(kind, DiagnosticKind::SafeProbeTcp) && !TCP_PROBE_PORTS.contains(&port) {
        anyhow::bail!("port {port} not in allowlist");
    }
    Ok(port)
}

fn validate_container_id(container: &str) -> Result<String> {
    if container.is_empty() || container.len() > 128 {
        anyhow::bail!("container is required");
    }
    if container.starts_with('-') {
        anyhow::bail!("container must not start with '-'");
    }
    if !container
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        anyhow::bail!("container contains invalid characters");
    }
    Ok(container.to_string())
}

fn validate_hostname_arg(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 {
        anyhow::bail!("host is required");
    }
    if host
        .bytes()
        .any(|b| !matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
    {
        anyhow::bail!("host contains invalid characters");
    }
    Ok(())
}

fn validate_probe_url(url: &str) -> Result<String> {
    let (host, port, _) = parse_http_url(url)?;
    validate_safe_host(&host)?;
    if ![80, 443, 8080, 8443, 9000, 9090].contains(&port) {
        anyhow::bail!("port {port} not in allowlist");
    }
    Ok(url.to_string())
}

fn validate_since(value: &str) -> Result<String> {
    if value.len() < 2 || value.len() > 4 {
        anyhow::bail!("since must be a compact duration");
    }
    let (number, unit) = value.split_at(value.len() - 1);
    let amount = number.parse::<u64>().context("since must be numeric")?;
    if amount == 0 || !matches!(unit, "s" | "m" | "h") {
        anyhow::bail!("since unit must be s|m|h");
    }
    if unit == "h" && amount > 24 {
        anyhow::bail!("since must be <=24h");
    }
    Ok(value.to_string())
}

fn validate_safe_path(path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    if !safe_path(&path) {
        anyhow::bail!("path {:?} is not allowlisted", path);
    }
    Ok(path)
}

fn safe_path(path: &Path) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return false;
    }
    SAFE_FILES.iter().any(|file| path == Path::new(file))
        || SAFE_BASES.iter().any(|base| path.starts_with(base))
}

fn normalize_host(host: String) -> String {
    host.trim().trim_matches(['[', ']']).to_string()
}

fn validate_safe_host(host: &str) -> Result<()> {
    let ip = resolve_safe_ip(host)?;
    if !(ip.is_loopback() || is_private_ip(ip)) {
        anyhow::bail!("host {host:?} is not allowlisted");
    }
    Ok(())
}

fn resolve_safe_ip(host: &str) -> Result<IpAddr> {
    if host == "localhost" {
        return Ok(IpAddr::from([127, 0, 0, 1]));
    }
    let ip: IpAddr = host
        .parse()
        .with_context(|| format!("host {host:?} must be an IP or localhost"))?;
    if ip.is_loopback() || is_private_ip(ip) {
        return Ok(ip);
    }
    anyhow::bail!("host {host:?} is not allowlisted")
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else {
        anyhow::bail!("url scheme must be http or https");
    };
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((rest, "/".to_string()));
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().context("invalid port")?),
        None => (authority, if scheme == "https" { 443 } else { 80 }),
    };
    Ok((normalize_host(host.to_string()), port, path))
}

fn parse_socket_addr(value: &str) -> Option<(String, u16)> {
    let (raw_addr, raw_port) = value.split_once(':')?;
    if raw_addr.len() != 8 {
        return None;
    }
    let bytes = (0..4)
        .map(|idx| u8::from_str_radix(&raw_addr[idx * 2..idx * 2 + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    let port = u16::from_str_radix(raw_port, 16).ok()?;
    Some((
        format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]),
        port,
    ))
}

fn tcp_state(raw: &str) -> &'static str {
    match raw {
        "01" => "established",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "04" => "fin_wait1",
        "05" => "fin_wait2",
        "06" => "time_wait",
        "07" => "close",
        "08" => "close_wait",
        "09" => "last_ack",
        "0A" => "listen",
        "0B" => "closing",
        _ => "unknown",
    }
}

fn read_trimmed(path: &Path) -> Result<String> {
    Ok(read_limited(path, MAX_FILE_BYTES)?.trim().to_string())
}

fn read_cmdline(path: &Path) -> Result<String> {
    Ok(read_limited(path, 16 * 1024)?
        .replace('\0', " ")
        .trim()
        .to_string())
}

fn read_limited(path: &Path, max_bytes: u64) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut buf = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn read_key_value_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for line in read_trimmed(path)?.lines() {
        if let Some((key, value)) = line.split_once('=') {
            out.insert(key.to_string(), value.trim_matches('"').to_string());
        }
    }
    Ok(out)
}

fn parse_key_value_colon(content: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            out.insert(key.to_string(), value.trim().to_string());
        }
    }
    out
}

fn completed_json(command_id: &str, kind: &str, data: Value) -> CommandResult {
    let output = serde_json::to_vec(&json!({"kind": kind, "status": "ok", "data": data}))
        .unwrap_or_else(|err| {
            format!(r#"{{"kind":"{kind}","status":"error","error":"marshal: {err}"}}"#).into_bytes()
        });
    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".to_string(),
        output,
        is_final: true,
        timestamp: Some(now_timestamp()),
    }
}

fn failed_text(command_id: &str, text: &str) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "failed".to_string(),
        output: redact_text(text).as_bytes().to_vec(),
        is_final: true,
        timestamp: Some(now_timestamp()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ps_rows_filters_kernel_threads() {
        let output = "\
PID USER COMMAND %CPU %MEM RSS
18 root [rcu_preempt] 0.0 0.0 0
1058 messagebus /usr/bin/dbus-daemon --system 0.0 0.0 5312
";

        let rows = parse_ps_rows(output, 10);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 1058);
        assert_eq!(rows[0].command, "/usr/bin/dbus-daemon --system");
    }

    #[test]
    fn parse_ps_rows_keeps_bracketed_user_process_with_memory() {
        let output = "\
PID USER COMMAND %CPU %MEM RSS
1234 app [worker] 0.1 0.1 2048
";

        let rows = parse_ps_rows(output, 10);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].command, "[worker]");
    }
}
