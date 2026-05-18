use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use crate::proto::agent::v1::{ServiceMetric, SystemMetrics, TopProcess};

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
    let root_disk = filesystem_usage_mb("/");
    let public_ips = collect_host_public_ips();

    SystemMetrics {
        cpu_percent: 0.0,
        memory_used_mb,
        memory_total_mb,
        disk_used_mb: root_disk
            .as_ref()
            .map(|usage| usage.used_mb)
            .unwrap_or_default(),
        disk_total_mb: root_disk
            .as_ref()
            .map(|usage| usage.total_mb)
            .unwrap_or_default(),
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
        public_ipv4: public_ips.ipv4,
        public_ipv6: public_ips.ipv6,
        top_processes: collect_top_processes(30),
        cpu_cores: cpu_core_count(),
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

pub fn collect_host_mount_metrics() -> Vec<ServiceMetric> {
    host_mount_metrics_for_paths(["/", "/tmp"])
}

fn host_mount_metrics_for_paths<const N: usize>(paths: [&str; N]) -> Vec<ServiceMetric> {
    let mut seen = std::collections::HashSet::new();
    let mut metrics = Vec::new();
    for path in paths {
        let Some(usage) = filesystem_usage_mb(path) else {
            continue;
        };
        if !seen.insert(usage.mountpoint.clone()) {
            continue;
        }

        let mut gauges = HashMap::new();
        gauges.insert("used_mb".to_string(), usage.used_mb as f64);
        gauges.insert("total_mb".to_string(), usage.total_mb as f64);
        gauges.insert("available_mb".to_string(), usage.available_mb as f64);
        if usage.total_mb > 0 {
            gauges.insert(
                "used_percent".to_string(),
                (usage.used_mb as f64 / usage.total_mb as f64) * 100.0,
            );
        }

        metrics.push(ServiceMetric {
            container_name: usage.mountpoint,
            service_type: "host_mount".to_string(),
            gauges,
            counters: HashMap::new(),
        });
    }
    metrics
}

#[derive(Clone, Debug)]
struct FilesystemUsage {
    mountpoint: String,
    used_mb: i64,
    total_mb: i64,
    available_mb: i64,
}

fn filesystem_usage_mb(path: &str) -> Option<FilesystemUsage> {
    let mountpoint = canonical_mountpoint(path);
    let c_path = CString::new(mountpoint.as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    let block_size = stat.f_frsize.max(stat.f_bsize) as u128;
    if block_size == 0 || stat.f_blocks == 0 {
        return None;
    }
    let total_bytes = stat.f_blocks as u128 * block_size;
    let available_bytes = stat.f_bavail as u128 * block_size;
    let free_bytes = stat.f_bfree as u128 * block_size;
    let used_bytes = total_bytes.saturating_sub(free_bytes);
    Some(FilesystemUsage {
        mountpoint,
        used_mb: bytes_to_mb(used_bytes),
        total_mb: bytes_to_mb(total_bytes),
        available_mb: bytes_to_mb(available_bytes),
    })
}

fn canonical_mountpoint(path: &str) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .to_string()
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct HostPublicIps {
    ipv4: String,
    ipv6: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostIpCandidate {
    interface: String,
    addr: IpAddr,
}

impl HostIpCandidate {
    fn new(interface: impl Into<String>, addr: IpAddr) -> Self {
        Self {
            interface: interface.into(),
            addr,
        }
    }
}

fn collect_host_public_ips() -> HostPublicIps {
    let candidates = local_ip_candidates();
    select_host_public_ips(&candidates, |name| std::env::var(name).ok())
}

fn select_host_public_ips(
    candidates: &[HostIpCandidate],
    env: impl Fn(&str) -> Option<String>,
) -> HostPublicIps {
    let override_ipv4 = env_public_ipv4("PERMANU_AGENT_PUBLIC_IPV4", &env);
    let override_ipv6 = env_public_ipv6("PERMANU_AGENT_PUBLIC_IPV6", &env);
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|left, right| {
        left.interface
            .cmp(&right.interface)
            .then_with(|| left.addr.to_string().cmp(&right.addr.to_string()))
    });

    let mut selected = HostPublicIps::default();
    match override_ipv4 {
        Some(value) => selected.ipv4 = value.unwrap_or_default(),
        None => {
            for candidate in &sorted {
                if let IpAddr::V4(addr) = candidate.addr {
                    if is_public_ipv4(addr) {
                        selected.ipv4 = addr.to_string();
                        break;
                    }
                }
            }
        }
    }

    match override_ipv6 {
        Some(value) => selected.ipv6 = value.unwrap_or_default(),
        None => {
            for candidate in &sorted {
                if let IpAddr::V6(addr) = candidate.addr {
                    if is_public_ipv6(addr) {
                        selected.ipv6 = addr.to_string();
                        break;
                    }
                }
            }
        }
    }

    selected
}

fn env_public_ipv4(name: &str, env: &impl Fn(&str) -> Option<String>) -> Option<Option<String>> {
    let raw = env(name)?;
    match raw.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) if is_public_ipv4(addr) => Some(Some(addr.to_string())),
        _ => Some(None),
    }
}

fn env_public_ipv6(name: &str, env: &impl Fn(&str) -> Option<String>) -> Option<Option<String>> {
    let raw = env(name)?;
    match raw.trim().parse::<IpAddr>() {
        Ok(IpAddr::V6(addr)) if is_public_ipv6(addr) => Some(Some(addr.to_string())),
        _ => Some(None),
    }
}

fn local_ip_candidates() -> Vec<HostIpCandidate> {
    let mut addrs = Vec::new();
    let mut ifaddr_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut ifaddr_ptr) };
    if rc != 0 || ifaddr_ptr.is_null() {
        return addrs;
    }

    let mut cursor = ifaddr_ptr;
    while !cursor.is_null() {
        let ifaddr = unsafe { &*cursor };
        if !ifaddr.ifa_addr.is_null() {
            let interface = unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) }
                .to_string_lossy()
                .to_string();
            if let Some(addr) = sockaddr_to_ip(ifaddr.ifa_addr) {
                addrs.push(HostIpCandidate::new(interface, addr));
            }
        }
        cursor = ifaddr.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifaddr_ptr) };
    addrs
}

fn sockaddr_to_ip(sockaddr: *const libc::sockaddr) -> Option<IpAddr> {
    let family = unsafe { (*sockaddr).sa_family as libc::c_int };
    match family {
        libc::AF_INET => {
            let sockaddr = unsafe { &*(sockaddr.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sockaddr.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let sockaddr = unsafe { &*(sockaddr.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn is_public_ipv4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    !(octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || octets[0] >= 224
        || octets == [255, 255, 255, 255]
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

fn is_public_ipv6(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();
    !(addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x0100 && segments[1] == 0)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
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

fn cpu_core_count() -> i32 {
    // Prefer sysconf (respects cgroup limits).
    let cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if cores > 0 {
        return cores as i32;
    }
    // Fallback: count "processor" lines in /proc/cpuinfo.
    fs::read_to_string("/proc/cpuinfo")
        .map(|raw| raw.lines().filter(|l| l.starts_with("processor\t")).count() as i32)
        .unwrap_or(0)
}

struct ProcEntry {
    pid: i32,
    name: String,
    user: String,
    cpu_percent: f64,
    memory_kb: i64,
}

#[derive(Debug, PartialEq)]
struct ProcStatSample {
    comm: String,
    total_jiffies: u64,
    start_time_jiffies: u64,
    rss_pages: i64,
}

fn collect_top_processes(limit: usize) -> Vec<TopProcess> {
    let mut procs = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let uptime = uptime_seconds() as f64;
    let ticks_per_second = clock_ticks_per_second();
    let page_size_kb = page_size_kb();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };

        let stat_path = format!("/proc/{pid}/stat");
        let Ok(stat_raw) = fs::read_to_string(&stat_path) else {
            continue;
        };
        let Some(sample) = parse_proc_stat(&stat_raw) else {
            continue;
        };
        if is_kernel_thread(pid, &sample) {
            continue;
        }
        let user = uid_to_user(pid).unwrap_or_else(|| "-".to_string());

        procs.push(ProcEntry {
            pid,
            name: sample.comm,
            user,
            cpu_percent: lifetime_cpu_percent(
                sample.total_jiffies,
                sample.start_time_jiffies,
                uptime,
                ticks_per_second,
            ),
            memory_kb: sample.rss_pages.saturating_mul(page_size_kb),
        });
    }

    // Sort by CPU (descending), take top N.
    procs.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    procs.truncate(limit);

    procs
        .into_iter()
        .map(|p| TopProcess {
            pid: p.pid,
            name: truncate_process_name(&p.name),
            cpu_percent: p.cpu_percent,
            memory_mb: p.memory_kb / 1024,
            user: p.user,
            children: Vec::new(),
        })
        .collect()
}

fn is_kernel_thread(pid: i32, sample: &ProcStatSample) -> bool {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|cmdline| is_kernel_thread_snapshot(sample.rss_pages, &cmdline))
        .unwrap_or(false)
}

fn is_kernel_thread_snapshot(rss_pages: i64, cmdline: &[u8]) -> bool {
    rss_pages == 0 && cmdline.is_empty()
}

fn parse_proc_stat(raw: &str) -> Option<ProcStatSample> {
    let open_paren = raw.find('(')?;
    let close_paren = raw.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let comm = raw[open_paren + 1..close_paren].to_string();
    let fields: Vec<&str> = raw[close_paren + 1..].split_whitespace().collect();
    if fields.len() <= 21 {
        return None;
    }

    let utime = fields.get(11)?.parse::<u64>().ok()?;
    let stime = fields.get(12)?.parse::<u64>().ok()?;
    let start_time_jiffies = fields.get(19)?.parse::<u64>().ok()?;
    let rss_pages = fields.get(21)?.parse::<i64>().ok()?.max(0);

    Some(ProcStatSample {
        comm,
        total_jiffies: utime.saturating_add(stime),
        start_time_jiffies,
        rss_pages,
    })
}

fn lifetime_cpu_percent(
    total_jiffies: u64,
    start_time_jiffies: u64,
    uptime_seconds: f64,
    ticks_per_second: f64,
) -> f64 {
    if ticks_per_second <= 0.0 {
        return 0.0;
    }
    let process_age_seconds = uptime_seconds - (start_time_jiffies as f64 / ticks_per_second);
    if process_age_seconds <= 0.0 {
        return 0.0;
    }
    let cpu_seconds = total_jiffies as f64 / ticks_per_second;
    ((cpu_seconds / process_age_seconds) * 100.0).clamp(0.0, 100.0 * cpu_core_count() as f64)
}

fn clock_ticks_per_second() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as f64
    } else {
        100.0
    }
}

fn page_size_kb() -> i64 {
    let bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if bytes > 0 {
        bytes / 1024
    } else {
        4
    }
}

fn truncate_process_name(name: &str) -> String {
    // Trim very long command names for readability.
    if name.len() > 80 {
        format!("{}…", &name[..77])
    } else {
        name.to_string()
    }
}

fn uid_to_user(pid: i32) -> Option<String> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid = rest.split_whitespace().next()?.parse::<u32>().ok()?;
            // Try to resolve via /etc/passwd.
            if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
                for entry in passwd.lines() {
                    let parts: Vec<&str> = entry.splitn(7, ':').collect();
                    if parts.len() >= 3 && parts[2].parse::<u32>() == Ok(uid) {
                        return Some(parts[0].to_string());
                    }
                }
            }
            return Some(uid.to_string());
        }
    }
    None
}

fn kib_to_mb(kib: i64) -> i64 {
    kib / 1024
}

fn bytes_to_mb(bytes: u128) -> i64 {
    (bytes / 1024 / 1024).min(i64::MAX as u128) as i64
}

#[allow(dead_code)]
fn path_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn public_ip_selection_prefers_global_interface_addresses() {
        let candidates = vec![
            HostIpCandidate::new("lo", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            HostIpCandidate::new("tailscale0", IpAddr::V4(Ipv4Addr::new(100, 64, 1, 2))),
            HostIpCandidate::new("eth0", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            HostIpCandidate::new(
                "eth0",
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888)),
            ),
        ];

        let selected = select_host_public_ips(&candidates, |_| None);

        assert_eq!(selected.ipv4, "8.8.8.8");
        assert_eq!(selected.ipv6, "2001:4860::8888");
    }

    #[test]
    fn public_ip_selection_uses_env_fallback_when_interfaces_are_not_public() {
        let candidates = vec![
            HostIpCandidate::new("eth0", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12))),
            HostIpCandidate::new(
                "tailscale0",
                IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1)),
            ),
        ];

        let selected = select_host_public_ips(&candidates, |name| match name {
            "PERMANU_AGENT_PUBLIC_IPV4" => Some("1.1.1.1".to_string()),
            "PERMANU_AGENT_PUBLIC_IPV6" => Some("2606:4700:4700::1111".to_string()),
            _ => None,
        });

        assert_eq!(selected.ipv4, "1.1.1.1");
        assert_eq!(selected.ipv6, "2606:4700:4700::1111");
    }

    #[test]
    fn public_ip_selection_env_overrides_interface_addresses() {
        let candidates = vec![
            HostIpCandidate::new("eth0", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            HostIpCandidate::new(
                "eth0",
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888)),
            ),
        ];

        let selected = select_host_public_ips(&candidates, |name| match name {
            "PERMANU_AGENT_PUBLIC_IPV4" => Some("1.1.1.1".to_string()),
            "PERMANU_AGENT_PUBLIC_IPV6" => Some("2606:4700:4700::1111".to_string()),
            _ => None,
        });

        assert_eq!(selected.ipv4, "1.1.1.1");
        assert_eq!(selected.ipv6, "2606:4700:4700::1111");
    }

    #[test]
    fn public_ip_selection_rejects_non_public_env_overrides() {
        let candidates = vec![
            HostIpCandidate::new("eth0", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            HostIpCandidate::new(
                "eth0",
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888)),
            ),
        ];

        let selected = select_host_public_ips(&candidates, |name| match name {
            "PERMANU_AGENT_PUBLIC_IPV4" => Some("192.168.1.20".to_string()),
            "PERMANU_AGENT_PUBLIC_IPV6" => Some("fe80::1".to_string()),
            _ => None,
        });

        assert_eq!(selected.ipv4, "");
        assert_eq!(selected.ipv6, "");
    }

    #[test]
    fn parse_proc_stat_reads_rss_pages_from_linux_field_24() {
        let stat = "1234 (dbus-daemon) S 1 2 3 4 5 6 7 8 9 10 120 30 13 14 15 16 17 18 19 2000 123456789 4096 999999 1 2";

        let sample = parse_proc_stat(stat).expect("valid proc stat");

        assert_eq!(
            sample,
            ProcStatSample {
                comm: "dbus-daemon".to_string(),
                total_jiffies: 150,
                start_time_jiffies: 19,
                rss_pages: 123456789,
            }
        );
    }

    #[test]
    fn parse_proc_stat_handles_process_names_with_spaces_and_parentheses() {
        let stat =
            "42 (worker (side car)) R 1 2 3 4 5 6 7 8 9 10 5 7 13 14 15 16 17 18 19 100 123456 64";

        let sample = parse_proc_stat(stat).expect("valid proc stat");

        assert_eq!(sample.comm, "worker (side car)");
        assert_eq!(sample.total_jiffies, 12);
        assert_eq!(sample.start_time_jiffies, 19);
        assert_eq!(sample.rss_pages, 123456);
    }

    #[test]
    fn lifetime_cpu_percent_converts_jiffies_to_bounded_percent() {
        let got = lifetime_cpu_percent(300, 100, 10.0, 100.0);

        assert_eq!(got, 33.33333333333333);
    }

    #[test]
    fn kernel_thread_detection_requires_empty_cmdline_and_zero_rss() {
        assert!(is_kernel_thread_snapshot(0, b""));
        assert!(!is_kernel_thread_snapshot(8, b""));
        assert!(!is_kernel_thread_snapshot(0, b"/usr/bin/dockerd\0"));
    }
}
