use std::{collections::HashMap, fs, path::Path};

use crate::proto::agent::v1::{ServiceMetric, SystemMetrics};

pub fn collect_system_metrics() -> SystemMetrics {
    let meminfo = parse_meminfo("/proc/meminfo");
    let memory_total_mb = kib_to_mb(meminfo.get("MemTotal").copied().unwrap_or_default());
    let memory_available_mb = kib_to_mb(meminfo.get("MemAvailable").copied().unwrap_or_default());
    let memory_buffers_mb = kib_to_mb(meminfo.get("Buffers").copied().unwrap_or_default());
    let memory_cached_mb = kib_to_mb(
        meminfo.get("Cached").copied().unwrap_or_default()
            + meminfo.get("SReclaimable").copied().unwrap_or_default(),
    );
    let swap_total_mb = kib_to_mb(meminfo.get("SwapTotal").copied().unwrap_or_default());
    let swap_free_mb = kib_to_mb(meminfo.get("SwapFree").copied().unwrap_or_default());
    let memory_used_mb = memory_total_mb.saturating_sub(memory_available_mb);
    let swap_used_mb = swap_total_mb.saturating_sub(swap_free_mb);

    let (load_avg_1, load_avg_5, load_avg_15) = parse_loadavg("/proc/loadavg");
    let (network_rx_bytes, network_tx_bytes) = network_bytes("/proc/net/dev");

    SystemMetrics {
        cpu_percent: 0.0,
        memory_used_mb,
        memory_total_mb,
        disk_used_mb: 0,
        disk_total_mb: 0,
        os_info: os_info(),
        docker_version: String::new(),
        network_rx_bytes,
        network_tx_bytes,
        cpu_model: cpu_model(),
        kernel_version: kernel_version(),
        arch: std::env::consts::ARCH.to_string(),
        machine_id: first_existing_file(&["/etc/machine-id", "/var/lib/dbus/machine-id"])
            .unwrap_or_default(),
        load_avg_1,
        load_avg_5,
        load_avg_15,
        cpu_user_percent: 0.0,
        cpu_system_percent: 0.0,
        cpu_iowait_percent: 0.0,
        cpu_steal_percent: 0.0,
        memory_available_mb,
        memory_buffers_mb,
        memory_cached_mb,
        swap_used_mb,
        swap_total_mb,
        disk_read_bytes: 0,
        disk_write_bytes: 0,
        disk_read_ops: 0,
        disk_write_ops: 0,
        open_file_descriptors: fd_count(),
        process_count: process_count(),
        tcp_established: 0,
        tcp_time_wait: 0,
        tcp_close_wait: 0,
        uptime_seconds: uptime_seconds(),
        public_ipv4: String::new(),
        public_ipv6: String::new(),
        top_processes: Vec::new(),
    }
}

pub fn collect_agent_self_metric(version: &str) -> ServiceMetric {
    let mut gauges = HashMap::new();
    if let Some(rss) = self_rss_bytes() {
        gauges.insert("agent_memory_rss_bytes".to_string(), rss as f64);
    }
    gauges.insert("agent_runtime_threads".to_string(), thread_count() as f64);

    let mut counters = HashMap::new();
    counters.insert("agent_process_start_time_unix".to_string(), 0);

    let mut labels = HashMap::new();
    labels.insert("agent_version".to_string(), version.to_string());

    ServiceMetric {
        container_name: "agent-self".to_string(),
        service_type: "agent_internal".to_string(),
        gauges,
        counters,
    }
}

fn parse_meminfo(path: &str) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    let Ok(raw) = fs::read_to_string(path) else {
        return out;
    };
    for line in raw.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        if let Some(value) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<i64>().ok())
        {
            out.insert(key.to_string(), value);
        }
    }
    out
}

fn parse_loadavg(path: &str) -> (f64, f64, f64) {
    let raw = fs::read_to_string(path).unwrap_or_default();
    let mut parts = raw.split_whitespace().filter_map(|p| p.parse::<f64>().ok());
    (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    )
}

fn network_bytes(path: &str) -> (i64, i64) {
    let raw = fs::read_to_string(path).unwrap_or_default();
    let mut rx = 0_i64;
    let mut tx = 0_i64;
    for line in raw.lines().skip(2) {
        let Some((_, values)) = line.split_once(':') else {
            continue;
        };
        let parts: Vec<&str> = values.split_whitespace().collect();
        if parts.len() >= 16 {
            rx = rx.saturating_add(parts[0].parse::<i64>().unwrap_or_default());
            tx = tx.saturating_add(parts[8].parse::<i64>().unwrap_or_default());
        }
    }
    (rx, tx)
}

fn os_info() -> String {
    let raw = fs::read_to_string("/etc/os-release").unwrap_or_default();
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return value.trim_matches('"').to_string();
        }
    }
    std::env::consts::OS.to_string()
}

fn cpu_model() -> String {
    let raw = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    for line in raw.lines() {
        if let Some((_, value)) = line.split_once(':') {
            if line.starts_with("model name") {
                return value.trim().to_string();
            }
        }
    }
    String::new()
}

fn kernel_version() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn first_existing_file(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|p| fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
}

fn fd_count() -> i64 {
    fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count() as i64)
        .unwrap_or_default()
}

fn process_count() -> i64 {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .chars()
                        .all(|c| c.is_ascii_digit())
                })
                .count() as i64
        })
        .unwrap_or_default()
}

fn uptime_seconds() -> i64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|raw| {
            raw.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .map(|v| v as i64)
        .unwrap_or_default()
}

fn self_rss_bytes() -> Option<i64> {
    let raw = fs::read_to_string("/proc/self/status").ok()?;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            let kib = value.split_whitespace().next()?.parse::<i64>().ok()?;
            return Some(kib.saturating_mul(1024));
        }
    }
    None
}

fn thread_count() -> i64 {
    fs::read_dir("/proc/self/task")
        .map(|entries| entries.count() as i64)
        .unwrap_or(1)
}

fn kib_to_mb(kib: i64) -> i64 {
    kib / 1024
}

#[allow(dead_code)]
fn path_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}
