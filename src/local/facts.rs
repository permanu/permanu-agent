//! Host facts for `InfoService` and containers for `StateService`, read from
//! the local system and Docker. The pure parsers are unit-tested; the probe
//! itself is swapped for a fake in the socket round-trip test.

use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use bollard::{
    models::{
        ContainerSummary, ContainerSummaryHealthStatusEnum, LocalNodeState,
        SwarmInfo as DockerSwarmInfo,
    },
    query_parameters::ListContainersOptionsBuilder,
};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::{
    docker_observe,
    proto::agent::v2::{
        health_event, swarm_info, Container, CpuInfo, DiskInfo, DockerInfo, DwaarInfo, OsInfo,
        ServerFacts, SwarmInfo,
    },
};

/// Docker labels that tie a container to Permanu identities. Containers
/// without `permanu.project_id` or `permanu.service_id` are not listed.
pub const LABEL_PROJECT_ID: &str = "permanu.project_id";
pub const LABEL_ENVIRONMENT: &str = "permanu.environment";
pub const LABEL_ENVIRONMENT_ID: &str = "permanu.environment_id";
pub const LABEL_SERVICE_ID: &str = "permanu.service_id";
pub const LABEL_SPEC_DIGEST: &str = "permanu.spec_digest_hex";

const DWAAR_ADMIN_SOCKET: &str = "/run/dwaar/admin.sock";
const DWAAR_BINARIES: [&str; 2] = ["/usr/local/bin/dwaar", "/usr/bin/dwaar"];
const DOCKER_BINARIES: [&str; 2] = ["/usr/bin/docker", "/usr/local/bin/docker"];
const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Read-only access to the host. Implementations must never mutate it.
#[tonic::async_trait]
pub trait HostProbe: Send + Sync + 'static {
    async fn server_facts(&self) -> ServerFacts;
    /// Permanu-managed containers on this host (unfiltered, unpaged).
    async fn containers(&self, include_stopped: bool) -> Result<Vec<Container>, Status>;
    /// Hex SHA-256 of each SSH host public key blob.
    fn ssh_host_key_digests_hex(&self) -> Vec<String>;
    fn ntp_synchronized(&self) -> bool;
    fn timezone(&self) -> String;
}

/// The real host.
pub struct SystemProbe {
    pub server_id: String,
}

#[tonic::async_trait]
impl HostProbe for SystemProbe {
    async fn server_facts(&self) -> ServerFacts {
        let (os_name, os_version) =
            parse_os_release(&fs::read_to_string("/etc/os-release").unwrap_or_default());
        let (memory_total_bytes, memory_available_bytes) =
            parse_meminfo_bytes(&fs::read_to_string("/proc/meminfo").unwrap_or_default());
        let mounts = parse_mounts(&fs::read_to_string("/proc/mounts").unwrap_or_default());
        ServerFacts {
            hostname: hostname(),
            machine_id: fs::read_to_string("/etc/machine-id")
                .unwrap_or_default()
                .trim()
                .to_string(),
            os: Some(OsInfo {
                name: if os_name.is_empty() {
                    std::env::consts::OS.to_string()
                } else {
                    os_name
                },
                version: os_version,
                kernel: fs::read_to_string("/proc/sys/kernel/osrelease")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            }),
            arch: arch_name(std::env::consts::ARCH).to_string(),
            cpu: Some(CpuInfo {
                model: parse_cpu_model(&fs::read_to_string("/proc/cpuinfo").unwrap_or_default()),
                cores: cpu_cores(),
            }),
            memory_total_bytes,
            memory_available_bytes,
            disks: mounts
                .into_iter()
                .filter_map(|(mount, fs_type)| disk_usage(&mount, fs_type))
                .collect(),
            docker: Some(docker_info().await),
            dwaar: Some(dwaar_info().await),
            boot_time: parse_boot_time(&fs::read_to_string("/proc/stat").unwrap_or_default()),
            probed_at: Some(timestamp(SystemTime::now())),
            ..Default::default()
        }
    }

    async fn containers(&self, include_stopped: bool) -> Result<Vec<Container>, Status> {
        let docker = docker_observe::docker_client()
            .map_err(|err| Status::unavailable(format!("docker unavailable: {err}")))?;
        let options = ListContainersOptionsBuilder::default()
            .all(include_stopped)
            .build();
        let summaries = tokio::time::timeout(PROBE_TIMEOUT, docker.list_containers(Some(options)))
            .await
            .map_err(|_| Status::unavailable("docker list timed out"))?
            .map_err(|err| Status::unavailable(format!("docker list failed: {err}")))?;
        Ok(summaries
            .into_iter()
            .filter_map(|summary| container_from_summary(summary, &self.server_id))
            .collect())
    }

    fn ssh_host_key_digests_hex(&self) -> Vec<String> {
        let mut paths: Vec<_> = fs::read_dir("/etc/ssh")
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("ssh_host_") && n.ends_with("_key.pub"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        paths.sort();
        paths
            .iter()
            .filter_map(|p| fs::read_to_string(p).ok())
            .filter_map(|line| ssh_host_key_digest_hex(&line))
            .collect()
    }

    fn ntp_synchronized(&self) -> bool {
        ntp_synchronized()
    }

    fn timezone(&self) -> String {
        fs::read_link("/etc/localtime")
            .ok()
            .and_then(|target| timezone_from_localtime_target(&target))
            .or_else(|| {
                fs::read_to_string("/etc/timezone")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "UTC".to_string())
    }
}

pub fn timestamp(time: SystemTime) -> Timestamp {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    Timestamp {
        seconds: since.as_secs() as i64,
        nanos: since.subsec_nanos() as i32,
    }
}

/// `ID` and `VERSION_ID` from os-release.
pub fn parse_os_release(raw: &str) -> (String, String) {
    let mut id = String::new();
    let mut version = String::new();
    for line in raw.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = v.trim().trim_matches('"').to_string();
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version = v.trim().trim_matches('"').to_string();
        }
    }
    (id, version)
}

/// `MemTotal` and `MemAvailable` in bytes.
pub fn parse_meminfo_bytes(raw: &str) -> (u64, u64) {
    let field = |name: &str| {
        raw.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kib| kib.parse::<u64>().ok())
            .map(|kib| kib.saturating_mul(1024))
            .unwrap_or_default()
    };
    (field("MemTotal:"), field("MemAvailable:"))
}

pub fn parse_cpu_model(raw: &str) -> String {
    raw.lines()
        .filter(|line| line.starts_with("model name") || line.starts_with("Model"))
        .find_map(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default()
}

pub fn parse_boot_time(raw: &str) -> Option<Timestamp> {
    raw.lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|seconds| Timestamp { seconds, nanos: 0 })
}

/// Real, block-backed filesystems from /proc/mounts, one entry per mount.
pub fn parse_mounts(raw: &str) -> Vec<(String, String)> {
    const REAL: [&str; 6] = ["ext4", "ext3", "xfs", "btrfs", "zfs", "vfat"];
    let mut out: Vec<(String, String)> = Vec::new();
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let (Some(_dev), Some(mount), Some(fs_type)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if !REAL.contains(&fs_type) || mount.starts_with("/var/lib/docker/") {
            continue;
        }
        let mount = mount.replace("\\040", " ");
        if !out.iter().any(|(m, _)| *m == mount) {
            out.push((mount, fs_type.to_string()));
        }
    }
    out
}

pub fn arch_name(rust_arch: &str) -> &str {
    match rust_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// SHA-256 over the decoded key blob of an OpenSSH public key line.
pub fn ssh_host_key_digest_hex(line: &str) -> Option<String> {
    let blob = line.split_whitespace().nth(1)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .ok()?;
    Some(hex::encode(Sha256::digest(bytes)))
}

pub fn timezone_from_localtime_target(target: &Path) -> Option<String> {
    let s = target.to_str()?;
    let (_, tz) = s.split_once("zoneinfo/")?;
    (!tz.is_empty()).then(|| tz.to_string())
}

pub fn swarm_from_docker(swarm: Option<&DockerSwarmInfo>) -> SwarmInfo {
    let Some(swarm) = swarm else {
        return SwarmInfo::default();
    };
    let state = match swarm.local_node_state {
        Some(LocalNodeState::INACTIVE) => swarm_info::State::Inactive,
        Some(LocalNodeState::PENDING) => swarm_info::State::Pending,
        Some(LocalNodeState::ACTIVE) => swarm_info::State::Active,
        Some(LocalNodeState::ERROR) => swarm_info::State::Error,
        Some(LocalNodeState::LOCKED) => swarm_info::State::Locked,
        _ => swarm_info::State::Unspecified,
    };
    let role = if state != swarm_info::State::Active {
        swarm_info::Role::Unspecified
    } else if swarm.control_available == Some(true) {
        swarm_info::Role::Manager
    } else {
        swarm_info::Role::Worker
    };
    SwarmInfo {
        state: state as i32,
        role: role as i32,
        node_id: swarm.node_id.clone().unwrap_or_default(),
        cluster_id: swarm
            .cluster
            .as_ref()
            .and_then(|c| c.id.clone())
            .unwrap_or_default(),
        managers: swarm
            .managers
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0),
        nodes: swarm.nodes.and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
    }
}

/// Maps a Docker container to the v2 `Container`; `None` when it carries no
/// Permanu identity label.
pub fn container_from_summary(summary: ContainerSummary, server_id: &str) -> Option<Container> {
    let labels: HashMap<String, String> = summary.labels.unwrap_or_default();
    let label = |key: &str| labels.get(key).cloned().unwrap_or_default();
    if label(LABEL_PROJECT_ID).is_empty() && label(LABEL_SERVICE_ID).is_empty() {
        return None;
    }
    let image = summary.image.unwrap_or_default();
    let image_digest_hex = image
        .split_once("@sha256:")
        .map(|(_, hex)| hex.to_string())
        .unwrap_or_default();
    let health = match summary.health.and_then(|h| h.status) {
        Some(ContainerSummaryHealthStatusEnum::HEALTHY) => health_event::Status::Healthy,
        Some(ContainerSummaryHealthStatusEnum::UNHEALTHY) => health_event::Status::Unhealthy,
        Some(ContainerSummaryHealthStatusEnum::STARTING) => health_event::Status::Starting,
        _ => health_event::Status::Unknown,
    };
    Some(Container {
        container_id: summary.id.unwrap_or_default(),
        name: summary
            .names
            .and_then(|names| names.into_iter().next())
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_default(),
        server_id: server_id.to_string(),
        project_id: label(LABEL_PROJECT_ID),
        environment: label(LABEL_ENVIRONMENT),
        environment_id: label(LABEL_ENVIRONMENT_ID),
        service_id: label(LABEL_SERVICE_ID),
        spec_digest_hex: label(LABEL_SPEC_DIGEST),
        image,
        image_digest_hex,
        state: summary.state.map(|s| s.to_string()).unwrap_or_default(),
        health: health as i32,
        ..Default::default()
    })
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn cpu_cores() -> u32 {
    // SAFETY: sysconf has no memory-safety preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    u32::try_from(n).unwrap_or(0)
}

fn disk_usage(mount: &str, filesystem: String) -> Option<DiskInfo> {
    let path = CString::new(mount).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: path is NUL-terminated and stat is a valid out-pointer.
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = stat.f_frsize as u64;
    let total = (stat.f_blocks as u64).saturating_mul(frsize);
    let free = (stat.f_bfree as u64).saturating_mul(frsize);
    Some(DiskInfo {
        mount: mount.to_string(),
        filesystem,
        total_bytes: total,
        used_bytes: total.saturating_sub(free),
    })
}

async fn docker_info() -> DockerInfo {
    let installed =
        DOCKER_BINARIES.iter().any(|p| Path::new(p).exists()) || Path::new(DOCKER_SOCKET).exists();
    let Ok(docker) = docker_observe::docker_client() else {
        return DockerInfo {
            installed,
            ..Default::default()
        };
    };
    match tokio::time::timeout(PROBE_TIMEOUT, docker.info()).await {
        Ok(Ok(info)) => DockerInfo {
            installed: true,
            reachable: true,
            version: info.server_version.unwrap_or_default(),
            storage_driver: info.driver.unwrap_or_default(),
            swarm: Some(swarm_from_docker(info.swarm.as_ref())),
        },
        _ => DockerInfo {
            installed,
            ..Default::default()
        },
    }
}

async fn dwaar_info() -> DwaarInfo {
    let binary = DWAAR_BINARIES.iter().find(|p| Path::new(p).exists());
    let admin_socket_reachable = matches!(
        tokio::time::timeout(
            PROBE_TIMEOUT,
            tokio::net::UnixStream::connect(DWAAR_ADMIN_SOCKET)
        )
        .await,
        Ok(Ok(_))
    );
    let version = match binary {
        Some(bin) => {
            let mut cmd = tokio::process::Command::new(bin);
            cmd.arg("--version").kill_on_drop(true);
            match tokio::time::timeout(PROBE_TIMEOUT, cmd.output()).await {
                Ok(Ok(out)) if out.status.success() => {
                    parse_version_output(&String::from_utf8_lossy(&out.stdout))
                }
                _ => String::new(),
            }
        }
        None => String::new(),
    };
    DwaarInfo {
        installed: binary.is_some(),
        running: admin_socket_reachable,
        version,
        admin_socket_reachable,
    }
}

/// Last whitespace-separated token of the first line ("dwaar 1.2.3" -> "1.2.3").
pub fn parse_version_output(raw: &str) -> String {
    raw.lines()
        .next()
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or_default()
        .to_string()
}

#[cfg(target_os = "linux")]
fn ntp_synchronized() -> bool {
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: modes = 0 makes adjtimex read-only; tx is a valid out-pointer.
    let state = unsafe { libc::adjtimex(&mut tx) };
    state >= 0 && state != libc::TIME_ERROR && tx.status & libc::STA_UNSYNC == 0
}

#[cfg(not(target_os = "linux"))]
fn ntp_synchronized() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ClusterInfo, ContainerSummaryHealth, ContainerSummaryStateEnum};

    #[test]
    fn parses_os_release_id_and_version() {
        let raw =
            "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04\"\n";
        assert_eq!(
            parse_os_release(raw),
            ("ubuntu".to_string(), "24.04".to_string())
        );
    }

    #[test]
    fn parses_meminfo_in_bytes() {
        let raw = "MemTotal:        2048 kB\nMemFree:  1 kB\nMemAvailable:    1024 kB\n";
        assert_eq!(parse_meminfo_bytes(raw), (2048 * 1024, 1024 * 1024));
    }

    #[test]
    fn parses_boot_time_and_cpu_model() {
        assert_eq!(
            parse_boot_time("cpu 1 2\nbtime 1700000000\n").map(|t| t.seconds),
            Some(1_700_000_000)
        );
        assert_eq!(
            parse_cpu_model("processor\t: 0\nmodel name\t: AMD EPYC 7B13\n"),
            "AMD EPYC 7B13"
        );
    }

    #[test]
    fn keeps_real_filesystems_only() {
        let raw = "/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\noverlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n/dev/sdb /mnt/data\\040disk xfs rw 0 0\n/dev/sda1 / ext4 rw 0 0\n";
        assert_eq!(
            parse_mounts(raw),
            vec![
                ("/".to_string(), "ext4".to_string()),
                ("/mnt/data disk".to_string(), "xfs".to_string())
            ]
        );
    }

    #[test]
    fn maps_rust_arch_to_go_names() {
        assert_eq!(arch_name("x86_64"), "amd64");
        assert_eq!(arch_name("aarch64"), "arm64");
    }

    #[test]
    fn digests_ssh_host_key_blob() {
        let blob = base64::engine::general_purpose::STANDARD.encode(b"key-blob");
        let line = format!("ssh-ed25519 {blob} root@host\n");
        assert_eq!(
            ssh_host_key_digest_hex(&line).unwrap(),
            hex::encode(Sha256::digest(b"key-blob"))
        );
        assert_eq!(ssh_host_key_digest_hex("garbage"), None);
    }

    #[test]
    fn timezone_from_zoneinfo_link() {
        assert_eq!(
            timezone_from_localtime_target(Path::new("/usr/share/zoneinfo/Europe/Berlin"))
                .as_deref(),
            Some("Europe/Berlin")
        );
        assert_eq!(timezone_from_localtime_target(Path::new("/etc/foo")), None);
    }

    #[test]
    fn maps_swarm_state_and_role() {
        assert_eq!(swarm_from_docker(None), SwarmInfo::default());
        let manager = DockerSwarmInfo {
            node_id: Some("n1".to_string()),
            local_node_state: Some(LocalNodeState::ACTIVE),
            control_available: Some(true),
            managers: Some(1),
            nodes: Some(3),
            cluster: Some(ClusterInfo {
                id: Some("c1".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let got = swarm_from_docker(Some(&manager));
        assert_eq!(got.state, swarm_info::State::Active as i32);
        assert_eq!(got.role, swarm_info::Role::Manager as i32);
        assert_eq!(
            (got.node_id.as_str(), got.cluster_id.as_str()),
            ("n1", "c1")
        );
        assert_eq!((got.managers, got.nodes), (1, 3));

        let inactive = DockerSwarmInfo {
            local_node_state: Some(LocalNodeState::INACTIVE),
            ..Default::default()
        };
        let got = swarm_from_docker(Some(&inactive));
        assert_eq!(got.state, swarm_info::State::Inactive as i32);
        assert_eq!(got.role, swarm_info::Role::Unspecified as i32);
    }

    #[test]
    fn maps_labelled_containers_only() {
        let unlabelled = ContainerSummary {
            id: Some("x".to_string()),
            ..Default::default()
        };
        assert!(container_from_summary(unlabelled, "srv").is_none());

        let labels = HashMap::from([
            (LABEL_PROJECT_ID.to_string(), "p1".to_string()),
            (LABEL_SERVICE_ID.to_string(), "s1".to_string()),
            (LABEL_ENVIRONMENT.to_string(), "production".to_string()),
            (LABEL_SPEC_DIGEST.to_string(), "ab".repeat(32)),
        ]);
        let summary = ContainerSummary {
            id: Some("c1".to_string()),
            names: Some(vec!["/web-1".to_string()]),
            image: Some(format!("ghcr.io/acme/web@sha256:{}", "cd".repeat(32))),
            labels: Some(labels),
            state: Some(ContainerSummaryStateEnum::RUNNING),
            health: Some(ContainerSummaryHealth {
                status: Some(ContainerSummaryHealthStatusEnum::HEALTHY),
                ..Default::default()
            }),
            ..Default::default()
        };
        let got = container_from_summary(summary, "srv").unwrap();
        assert_eq!(got.container_id, "c1");
        assert_eq!(got.name, "web-1");
        assert_eq!(got.server_id, "srv");
        assert_eq!(got.project_id, "p1");
        assert_eq!(got.service_id, "s1");
        assert_eq!(got.environment, "production");
        assert_eq!(got.spec_digest_hex, "ab".repeat(32));
        assert_eq!(got.image_digest_hex, "cd".repeat(32));
        assert_eq!(got.state, "running");
        assert_eq!(got.health, health_event::Status::Healthy as i32);
    }

    #[test]
    fn parses_version_output() {
        assert_eq!(parse_version_output("dwaar 0.4.2\nbuilt ...\n"), "0.4.2");
        assert_eq!(parse_version_output(""), "");
    }
}
