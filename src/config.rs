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
    /// S8: once this file exists, mutating v1 commands are refused.
    pub trusted_keys_path: PathBuf,
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
            trusted_keys_path: PathBuf::from(crate::trusted_keys::TRUSTED_KEYS_PATH),
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
            trusted_keys_path: PathBuf::from(crate::trusted_keys::TRUSTED_KEYS_PATH),
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

/// Which protocols the agent serves (agent-protocol.md section 1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentMode {
    /// v1 only: dial out to the hosted control plane (default, unchanged).
    Hosted,
    /// v2 only: serve the local unix socket; no control-plane connection.
    Local,
    /// Both of the above.
    Both,
}

impl AgentMode {
    pub const ENV: &'static str = "PERMANU_AGENT_MODE";

    pub fn from_env() -> Result<Self> {
        Self::parse(env::var(Self::ENV).ok().as_deref())
    }

    pub fn parse(value: Option<&str>) -> Result<Self> {
        let value = value.map(str::trim).unwrap_or_default();
        if value.is_empty() || value.eq_ignore_ascii_case("hosted") {
            Ok(Self::Hosted)
        } else if value.eq_ignore_ascii_case("local") {
            Ok(Self::Local)
        } else if value.eq_ignore_ascii_case("both") {
            Ok(Self::Both)
        } else {
            Err(anyhow!(
                "{} must be hosted, local or both (got {value:?})",
                Self::ENV
            ))
        }
    }

    pub fn runs_hosted(self) -> bool {
        matches!(self, Self::Hosted | Self::Both)
    }

    pub fn serves_local(self) -> bool {
        matches!(self, Self::Local | Self::Both)
    }
}

/// Local-mode (v2 unix socket) settings.
#[derive(Clone, Debug)]
pub struct LocalConfig {
    pub socket_path: PathBuf,
    /// Group that owns the socket (mode 0660). `None` skips the chown; only
    /// tests use that.
    pub socket_group: Option<String>,
    pub trusted_keys_path: PathBuf,
    /// signed-plan.md 6.3: the agent's admission store.
    pub admissions_db: PathBuf,
    /// signed-plan.md 14.5: the runner's consumed log (read-only here).
    pub consumed_log: PathBuf,
    /// `permanu-runner`, run as `<runner_path> rpc` for `bind_plan`.
    pub runner_path: PathBuf,
    /// signed-plan.md 3.2: the agent's age X25519 identity.
    pub age_identity_path: PathBuf,
    /// Owner and group of the store files (D-022).
    pub store_user: String,
    pub store_group: String,
}

pub const DEFAULT_LOCAL_SOCKET_PATH: &str = "/run/permanu/agent.sock";
pub const DEFAULT_LOCAL_SOCKET_GROUP: &str = "permanu";

impl LocalConfig {
    pub fn from_env() -> Self {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let socket_path = lookup("PERMANU_AGENT_SOCKET")
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_LOCAL_SOCKET_PATH.to_string());
        Self {
            socket_path: PathBuf::from(socket_path),
            socket_group: Some(DEFAULT_LOCAL_SOCKET_GROUP.to_string()),
            trusted_keys_path: PathBuf::from(crate::trusted_keys::TRUSTED_KEYS_PATH),
            admissions_db: PathBuf::from(crate::admissions::DEFAULT_ADMISSIONS_DB),
            consumed_log: PathBuf::from("/var/lib/permanu/runner/consumed.log"),
            runner_path: PathBuf::from(
                lookup("PERMANU_RUNNER_PATH")
                    .filter(|v| v.starts_with('/'))
                    .unwrap_or_else(|| crate::local::runner::DEFAULT_RUNNER_PATH.to_string()),
            ),
            age_identity_path: PathBuf::from(crate::local::age_identity::DEFAULT_AGE_IDENTITY_PATH),
            store_user: "permanu-agent".to_string(),
            store_group: "permanu-runner".to_string(),
        }
    }
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    #[test]
    fn mode_defaults_to_hosted() {
        assert_eq!(AgentMode::parse(None).unwrap(), AgentMode::Hosted);
        assert_eq!(AgentMode::parse(Some("  ")).unwrap(), AgentMode::Hosted);
    }

    #[test]
    fn mode_parses_all_values_case_insensitively() {
        assert_eq!(AgentMode::parse(Some("hosted")).unwrap(), AgentMode::Hosted);
        assert_eq!(AgentMode::parse(Some("Local")).unwrap(), AgentMode::Local);
        assert_eq!(AgentMode::parse(Some("BOTH")).unwrap(), AgentMode::Both);
    }

    #[test]
    fn mode_rejects_unknown_values() {
        let err = AgentMode::parse(Some("remote")).unwrap_err();
        assert!(err.to_string().contains("PERMANU_AGENT_MODE"));
    }

    #[test]
    fn mode_flags() {
        assert!(AgentMode::Hosted.runs_hosted() && !AgentMode::Hosted.serves_local());
        assert!(!AgentMode::Local.runs_hosted() && AgentMode::Local.serves_local());
        assert!(AgentMode::Both.runs_hosted() && AgentMode::Both.serves_local());
    }

    #[test]
    fn local_config_defaults_and_overrides() {
        let cfg = LocalConfig::from_lookup(|_| None);
        assert_eq!(cfg.socket_path, PathBuf::from("/run/permanu/agent.sock"));
        assert_eq!(cfg.socket_group.as_deref(), Some("permanu"));
        assert_eq!(
            cfg.trusted_keys_path,
            PathBuf::from("/etc/permanu/trusted-keys.json")
        );
        assert_eq!(
            cfg.admissions_db,
            PathBuf::from("/var/lib/permanu/agent/admissions.db")
        );
        assert_eq!(
            cfg.consumed_log,
            PathBuf::from("/var/lib/permanu/runner/consumed.log")
        );
        assert_eq!(
            cfg.runner_path,
            PathBuf::from("/usr/local/libexec/permanu-runner")
        );
        assert_eq!(
            cfg.age_identity_path,
            PathBuf::from("/var/lib/permanu/agent/age-identity")
        );
        assert_eq!(cfg.store_user, "permanu-agent");
        assert_eq!(cfg.store_group, "permanu-runner");

        let cfg = LocalConfig::from_lookup(|name| match name {
            "PERMANU_AGENT_SOCKET" => Some("/tmp/x.sock".to_string()),
            _ => None,
        });
        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/x.sock"));
    }
}
