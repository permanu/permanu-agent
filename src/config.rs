use std::{env, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context, Result};
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request,
};

#[derive(Clone)]
pub struct Config {
    pub backend_grpc_addr: String,
    pub server_id: String,
    pub agent_secret: String,
    pub version: String,
    pub insecure: bool,
    pub heartbeat_interval: Duration,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_message_size: usize,
    pub spool_dir: PathBuf,
    pub log_spool_max_bytes: u64,
    pub log_spool_segment_bytes: u64,
    pub report_agent_checksum: bool,
    pub docksmith_bin: String,
    pub docksmith_timeout: Duration,
    pub agent_env_file: PathBuf,
    pub dwaar_cf_token_path: PathBuf,
    pub dwaar_cf_token_drop_in_dir: PathBuf,
    pub internal_apex: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let backend_grpc_addr = required_env("BACKEND_GRPC_ADDR")?;
        let server_id = required_env("SERVER_ID")?;
        let agent_secret = required_env("AGENT_SECRET")?;
        let version = agent_version();
        let insecure = env::var("AGENT_INSECURE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let heartbeat_interval = env_duration("AGENT_HEARTBEAT_SECONDS", 30);
        let spool_dir = env::var("PERMANU_AGENT_SPOOL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/permanu-agent/spool"));

        Ok(Self {
            backend_grpc_addr,
            server_id,
            agent_secret,
            version,
            insecure,
            heartbeat_interval,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            max_message_size: 30 << 20,
            spool_dir,
            log_spool_max_bytes: env_u64("PERMANU_AGENT_LOG_SPOOL_MAX_BYTES", 256 * 1024 * 1024),
            log_spool_segment_bytes: env_u64(
                "PERMANU_AGENT_LOG_SPOOL_SEGMENT_BYTES",
                4 * 1024 * 1024,
            ),
            report_agent_checksum: env_bool("PERMANU_AGENT_REPORT_CHECKSUM", false),
            docksmith_bin: env::var("PERMANU_DOCKSMITH_BIN")
                .unwrap_or_else(|_| "docksmith".to_string()),
            docksmith_timeout: env_duration("PERMANU_DOCKSMITH_TIMEOUT_SECONDS", 30),
            agent_env_file: env::var("PERMANU_AGENT_ENV_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/permanu-agent.env")),
            dwaar_cf_token_path: env::var("DWAAR_CF_TOKEN_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/dwaar/cf-token")),
            dwaar_cf_token_drop_in_dir: env::var("DWAAR_CF_TOKEN_DROP_IN_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/systemd/system/dwaar.service.d")),
            internal_apex: env::var("INTERNAL_APEX").unwrap_or_default(),
        })
    }

    pub fn probe_from_env() -> Self {
        let version = env::var("AGENT_VERSION")
            .unwrap_or_else(|_| format!("rust-probe-{}-{}", env::consts::OS, env::consts::ARCH));
        let spool_dir = env::var("PERMANU_AGENT_SPOOL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/permanu-agent-probe/spool"));

        Self {
            backend_grpc_addr: "probe.invalid:0".to_string(),
            server_id: "probe".to_string(),
            agent_secret: "probe".to_string(),
            version,
            insecure: true,
            heartbeat_interval: env_duration("AGENT_HEARTBEAT_SECONDS", 30),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            max_message_size: 30 << 20,
            spool_dir,
            log_spool_max_bytes: env_u64("PERMANU_AGENT_LOG_SPOOL_MAX_BYTES", 256 * 1024 * 1024),
            log_spool_segment_bytes: env_u64(
                "PERMANU_AGENT_LOG_SPOOL_SEGMENT_BYTES",
                4 * 1024 * 1024,
            ),
            report_agent_checksum: false,
            docksmith_bin: env::var("PERMANU_DOCKSMITH_BIN")
                .unwrap_or_else(|_| "docksmith".to_string()),
            docksmith_timeout: env_duration("PERMANU_DOCKSMITH_TIMEOUT_SECONDS", 30),
            agent_env_file: PathBuf::from("/tmp/permanu-agent-probe/permanu-agent.env"),
            dwaar_cf_token_path: PathBuf::from("/tmp/permanu-agent-probe/dwaar/cf-token"),
            dwaar_cf_token_drop_in_dir: PathBuf::from(
                "/tmp/permanu-agent-probe/systemd/dwaar.service.d",
            ),
            internal_apex: env::var("INTERNAL_APEX").unwrap_or_default(),
        }
    }

    pub fn endpoint_uri(&self) -> String {
        let scheme = if self.insecure { "http" } else { "https" };
        format!("{scheme}://{}", self.backend_grpc_addr)
    }

    pub async fn connect_channel(&self) -> Result<Channel> {
        let mut endpoint = Endpoint::from_shared(self.endpoint_uri())
            .context("invalid BACKEND_GRPC_ADDR")?
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true);

        if !self.insecure {
            endpoint = endpoint.tls_config(ClientTlsConfig::new())?;
        }

        endpoint.connect().await.context("connect backend gRPC")
    }

    pub fn attach_auth<T>(&self, mut request: Request<T>) -> Result<Request<T>> {
        let bearer = format!("Bearer {}", self.agent_secret);
        let auth = MetadataValue::try_from(bearer).context("build authorization metadata")?;
        let server_id =
            MetadataValue::try_from(self.server_id.clone()).context("build server-id metadata")?;
        request.metadata_mut().insert("authorization", auth);
        request.metadata_mut().insert("server-id", server_id);
        Ok(request)
    }
}

pub fn agent_version() -> String {
    env::var("AGENT_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            option_env!("PERMANU_AGENT_BUILD_VERSION")
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            format!(
                "{}-{}-{}",
                env!("CARGO_PKG_VERSION"),
                env::consts::OS,
                env::consts::ARCH
            )
        })
}

fn required_env(name: &str) -> Result<String> {
    let value =
        env::var(name).with_context(|| format!("{name} environment variable is required"))?;
    if value.trim().is_empty() {
        return Err(anyhow!("{name} environment variable is empty"));
    }
    Ok(value)
}

fn env_duration(name: &str, default_seconds: u64) -> Duration {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default_seconds))
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(default)
}
