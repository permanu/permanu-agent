use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::common::{validate_identifier, CommandSpec, MAX_STATUS_OUTPUT_BYTES};

const DWAAR_APPS_DIR: &str = "/etc/dwaar/apps";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerCleanupSpec {
    pub resource: String,
    pub name_prefix: String,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UninstallStep {
    DockerCleanup(DockerCleanupSpec),
    Command(CommandSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerExecSpec {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct TcpProxyResult {
    pub proxy_id: String,
    pub port: u16,
    pub tls: bool,
}

pub fn tcp_proxy_config_path(proxy_id: &str) -> Result<String> {
    validate_identifier(proxy_id, "proxy_id")?;
    Ok(format!("{DWAAR_APPS_DIR}/tcp-proxy-{proxy_id}.dwaar"))
}

pub fn build_tcp_proxy_config(
    proxy_id: &str,
    port: u16,
    target: &str,
    allowed_ips: &[String],
) -> Result<String> {
    validate_identifier(proxy_id, "proxy_id")?;
    validate_tcp_port(port, "port")?;
    validate_target(target)?;
    let filtered = filter_allowed_ips(allowed_ips)?;

    if filtered.is_empty() {
        return Ok(format!(
            "# tcp-proxy-{proxy_id} (managed by permanu-agent)\n\
layer4 {{\n\
    :{port} {{\n\
        route {{\n\
            proxy {target}\n\
        }}\n\
    }}\n\
}}\n"
        ));
    }

    Ok(format!(
        "# tcp-proxy-{proxy_id} (managed by permanu-agent)\n\
layer4 {{\n\
    :{port} {{\n\
        @allowed remote_ip {}\n\
        route @allowed {{\n\
            proxy {target}\n\
        }}\n\
    }}\n\
}}\n",
        filtered.join(" ")
    ))
}

pub fn build_cert_rotate_steps(payload: &[u8]) -> Result<Vec<DockerExecSpec>> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        container_name: String,
        #[serde(default)]
        service_type: String,
    }

    let payload: Payload =
        serde_json::from_slice(payload).context("invalid cert_rotate payload")?;
    validate_identifier(&payload.container_name, "container_name")?;
    if payload.service_type != "postgresql" {
        anyhow::bail!(
            "unsupported service type for cert rotation: {}",
            payload.service_type
        );
    }

    let container = payload.container_name;
    Ok(vec![
        docker_exec(
            &container,
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-days",
                "365",
                "-nodes",
                "-text",
                "-out",
                "/var/lib/postgresql/data/server.crt",
                "-keyout",
                "/var/lib/postgresql/data/server.key",
                "-subj",
                "/CN=deploy-postgres",
            ],
        ),
        docker_exec(
            &container,
            [
                "chmod",
                "600",
                "/var/lib/postgresql/data/server.key",
                "/var/lib/postgresql/data/server.crt",
            ],
        ),
        docker_exec(
            &container,
            [
                "chown",
                "postgres:postgres",
                "/var/lib/postgresql/data/server.key",
                "/var/lib/postgresql/data/server.crt",
            ],
        ),
        docker_exec(
            &container,
            [
                "sh",
                "-c",
                r#"dir="${PGDATA:-}"; if [ -z "$dir" ]; then if [ -d /var/lib/postgresql/data/pgdata ]; then dir=/var/lib/postgresql/data/pgdata; else dir=/var/lib/postgresql/data; fi; fi; su -c "pg_ctl reload -D '$dir'" postgres"#,
            ],
        ),
    ])
}

pub fn build_uninstall_plan() -> Vec<UninstallStep> {
    let mut steps = vec![
        docker_cleanup("container"),
        docker_cleanup("network"),
        docker_cleanup("volume"),
        UninstallStep::Command(command("docker", ["image", "prune", "-f"])),
        command_step("systemctl", ["stop", "dwaar"]),
        command_step("systemctl", ["disable", "dwaar"]),
        command_step("rm", ["-f", "/etc/systemd/system/dwaar.service"]),
        command_step("rm", ["-f", "/usr/local/bin/dwaar"]),
        command_step("rm", ["-rf", "/etc/dwaar"]),
        command_step("rm", ["-rf", "/var/log/dwaar"]),
        command_step("rm", ["-rf", "/run/dwaar"]),
        command_step("systemctl", ["stop", "pagent"]),
        command_step("systemctl", ["disable", "pagent"]),
        command_step("rm", ["-f", "/etc/systemd/system/pagent.service"]),
        command_step("rm", ["-f", "/etc/pagent.env"]),
        command_step("rm", ["-rf", "/opt/pagent"]),
        command_step("systemctl", ["stop", "permanu-agent"]),
        command_step("systemctl", ["disable", "permanu-agent"]),
        command_step("rm", ["-f", "/etc/systemd/system/permanu-agent.service"]),
        command_step("rm", ["-f", "/etc/permanu-agent.env"]),
        command_step("rm", ["-rf", "/etc/permanu-agent"]),
        command_step("rm", ["-rf", "/var/lib/permanu-agent"]),
        command_step("rm", ["-rf", "/var/log/permanu-agent"]),
        command_step("systemctl", ["daemon-reload"]),
    ];
    steps.push(command_step("rm", ["-rf", "/opt/permanu-agent"]));
    steps
}

fn docker_cleanup(resource: &str) -> UninstallStep {
    UninstallStep::DockerCleanup(DockerCleanupSpec {
        resource: resource.to_string(),
        name_prefix: "deploy-".to_string(),
        timeout: Duration::from_secs(30),
    })
}

fn command_step(program: &str, args: impl IntoIterator<Item = impl Into<String>>) -> UninstallStep {
    UninstallStep::Command(command(program, args))
}

fn command(program: &str, args: impl IntoIterator<Item = impl Into<String>>) -> CommandSpec {
    CommandSpec::new(
        program,
        args,
        Duration::from_secs(30),
        MAX_STATUS_OUTPUT_BYTES,
    )
}

fn docker_exec(
    container: &str,
    args: impl IntoIterator<Item = impl Into<String>>,
) -> DockerExecSpec {
    let mut docker_args = vec!["exec".to_string(), container.to_string()];
    docker_args.extend(args.into_iter().map(Into::into));
    DockerExecSpec {
        program: "docker".to_string(),
        args: docker_args,
        timeout: Duration::from_secs(30),
        max_output_bytes: MAX_STATUS_OUTPUT_BYTES,
    }
}

fn filter_allowed_ips(ips: &[String]) -> Result<Vec<String>> {
    let mut filtered = Vec::new();
    for ip in ips {
        let ip = ip.trim();
        if ip.is_empty() || ip == "0.0.0.0/0" || ip == "::/0" {
            continue;
        }
        validate_cidr_or_ip(ip)?;
        filtered.push(ip.to_string());
    }
    Ok(filtered)
}

fn validate_cidr_or_ip(value: &str) -> Result<()> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let ip = addr
            .parse::<IpAddr>()
            .with_context(|| format!("invalid allowed_ip {value:?}"))?;
        let prefix = prefix
            .parse::<u8>()
            .with_context(|| format!("invalid allowed_ip {value:?}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            anyhow::bail!("invalid allowed_ip {value:?}: prefix too large");
        }
        return Ok(());
    }
    value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid allowed_ip {value:?}"))?;
    Ok(())
}

fn validate_target(target: &str) -> Result<()> {
    if target.bytes().any(|byte| byte <= b' ') {
        anyhow::bail!("target contains invalid whitespace");
    }
    let Some((host, port)) = target.rsplit_once(':') else {
        anyhow::bail!("target must be host:port");
    };
    if host.is_empty() {
        anyhow::bail!("target host is required");
    }
    validate_tcp_port(
        port.parse::<u16>().context("target port must be numeric")?,
        "target port",
    )
}

fn validate_tcp_port(port: u16, label: &str) -> Result<()> {
    if port == 0 {
        anyhow::bail!("{label} is required");
    }
    Ok(())
}
