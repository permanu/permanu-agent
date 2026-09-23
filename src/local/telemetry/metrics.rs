//! Built-in metrics (agent-protocol.md 9.5): every 10 s the agent samples
//! `host.*` from `/proc` and `container.*` from the cgroup v2 files of
//! Permanu-labelled containers (identities from the runner's
//! `list_containers`, refreshed every 60 s). Samples belong to the `system`
//! producer (9.2). Paths are injectable so tests use fixture trees; on a
//! host without `/proc` (macOS dev) nothing is sampled.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::records::MetricSample;
use super::store::{DiskProbe, Producer, StatvfsDisk};
use super::Telemetry;
use crate::local::runner::{self, ContainerFilter, Runner, RunnerContainer};
use crate::proto::agent::v2::{metric_descriptor, MetricSource};

pub const SAMPLE_EVERY: Duration = Duration::from_secs(10);
const CONTAINERS_EVERY: Duration = Duration::from_secs(60);

pub struct Sampler {
    pub proc_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub disk_path: PathBuf,
    telemetry: Arc<Telemetry>,
    runner: Arc<dyn Runner>,
    containers: Vec<RunnerContainer>,
    listed_at: Option<Instant>,
    prev_cpu: Option<(u64, u64)>,
    prev_container_cpu: HashMap<String, (u64, Instant)>,
}

fn sample(
    name: &str,
    kind: metric_descriptor::Kind,
    source: MetricSource,
    unit: &str,
    value: f64,
) -> MetricSample {
    MetricSample {
        name: name.to_owned(),
        kind: kind as i32,
        source: source as i32,
        unit: unit.to_owned(),
        value,
        cumulative: kind == metric_descriptor::Kind::Counter,
        ..Default::default()
    }
}

fn gauge(name: &str, source: MetricSource, unit: &str, value: f64) -> MetricSample {
    sample(name, metric_descriptor::Kind::Gauge, source, unit, value)
}

fn counter(name: &str, source: MetricSource, unit: &str, value: f64) -> MetricSample {
    sample(name, metric_descriptor::Kind::Counter, source, unit, value)
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// `(total, idle)` jiffies of the `cpu` line of `/proc/stat`.
fn cpu_times(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let values: Vec<u64> = line
        .split_ascii_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if values.len() < 4 {
        return None;
    }
    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    Some((values.iter().take(8).sum(), idle))
}

fn meminfo(text: &str, key: &str) -> Option<f64> {
    let line = text.lines().find(|l| l.starts_with(key))?;
    let kib: f64 = line.split_ascii_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024.0)
}

impl Sampler {
    pub fn new(telemetry: Arc<Telemetry>, runner: Arc<dyn Runner>) -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            disk_path: PathBuf::from("/"),
            telemetry,
            runner,
            containers: Vec::new(),
            listed_at: None,
            prev_cpu: None,
            prev_container_cpu: HashMap::new(),
        }
    }

    /// `host.*` samples (9.5).
    pub fn host(&mut self) -> Vec<MetricSample> {
        let mut out = Vec::new();
        let host = MetricSource::Host;
        if let Some((total, idle)) = read(&self.proc_root.join("stat"))
            .as_deref()
            .and_then(cpu_times)
        {
            if let Some((pt, pi)) = self.prev_cpu {
                let dt = total.saturating_sub(pt);
                if dt > 0 {
                    let busy = dt.saturating_sub(idle.saturating_sub(pi));
                    out.push(gauge(
                        "host.cpu.percent",
                        host,
                        "%",
                        busy as f64 * 100.0 / dt as f64,
                    ));
                }
            }
            self.prev_cpu = Some((total, idle));
        }
        if let Some(mem) = read(&self.proc_root.join("meminfo")) {
            if let (Some(total), Some(avail)) =
                (meminfo(&mem, "MemTotal:"), meminfo(&mem, "MemAvailable:"))
            {
                out.push(gauge("host.memory.total_bytes", host, "By", total));
                out.push(gauge(
                    "host.memory.used_bytes",
                    host,
                    "By",
                    (total - avail).max(0.0),
                ));
            }
        }
        if let Some(load) = read(&self.proc_root.join("loadavg")) {
            let parts: Vec<f64> = load
                .split_ascii_whitespace()
                .take(3)
                .filter_map(|v| v.parse().ok())
                .collect();
            for (name, value) in ["host.load.1", "host.load.5", "host.load.15"]
                .iter()
                .zip(parts)
            {
                out.push(gauge(name, host, "1", value));
            }
        }
        if let Some(net) = read(&self.proc_root.join("net/dev")) {
            for line in net.lines().skip(2) {
                let Some((iface, rest)) = line.split_once(':') else {
                    continue;
                };
                let iface = iface.trim();
                if iface == "lo" || iface.starts_with("veth") {
                    continue;
                }
                let v: Vec<f64> = rest
                    .split_ascii_whitespace()
                    .filter_map(|x| x.parse().ok())
                    .collect();
                if v.len() >= 9 {
                    for (name, value) in [
                        ("host.network.rx_bytes", v[0]),
                        ("host.network.tx_bytes", v[8]),
                    ] {
                        let mut s = counter(name, host, "By", value);
                        s.labels.insert("interface".to_owned(), iface.to_owned());
                        out.push(s);
                    }
                }
            }
        }
        if self.proc_root.join("stat").exists() {
            if let Some((free, total)) = StatvfsDisk.free(&self.disk_path) {
                for (name, value) in [
                    ("host.disk.total_bytes", total as f64),
                    ("host.disk.used_bytes", total.saturating_sub(free) as f64),
                ] {
                    let mut s = gauge(name, host, "By", value);
                    s.labels
                        .insert("mount".to_owned(), self.disk_path.display().to_string());
                    out.push(s);
                }
            }
        }
        out
    }

    fn cgroup_dir(&self, id: &str) -> Option<PathBuf> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        [
            self.cgroup_root
                .join(format!("system.slice/docker-{id}.scope")),
            self.cgroup_root.join("docker").join(id),
        ]
        .into_iter()
        .find(|p| p.is_dir())
    }

    /// `container.*` samples of running Permanu containers (9.5).
    pub fn containers(&mut self, now: Instant) -> Vec<MetricSample> {
        let mut out = Vec::new();
        let source = MetricSource::Container;
        for c in self.containers.iter().filter(|c| c.state == "running") {
            let Some(dir) = self.cgroup_dir(&c.id) else {
                continue;
            };
            let mut labels = BTreeMap::new();
            for (k, v) in [
                ("container", &c.name),
                ("project_id", &c.project_id),
                ("environment_id", &c.environment_id),
                ("service_id", &c.service_id),
                ("deployment_id", &c.deployment_id),
            ] {
                if !v.is_empty() {
                    labels.insert(k.to_owned(), v.clone());
                }
            }
            labels.insert("container_id".to_owned(), c.id.chars().take(12).collect());
            let mut push = |mut s: MetricSample| {
                s.labels = labels.clone();
                out.push(s);
            };
            if let Some(usec) = read(&dir.join("cpu.stat")).and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("usage_usec "))
                    .and_then(|v| v.trim().parse::<u64>().ok())
            }) {
                push(counter(
                    "container.cpu.usage_seconds",
                    source,
                    "s",
                    usec as f64 / 1e6,
                ));
                if let Some((prev, at)) = self.prev_container_cpu.get(&c.id) {
                    let elapsed = now.saturating_duration_since(*at).as_secs_f64();
                    if elapsed > 0.0 && usec >= *prev {
                        let percent = (usec - prev) as f64 / 1e6 / elapsed * 100.0;
                        push(gauge("container.cpu.percent", source, "%", percent));
                    }
                }
                self.prev_container_cpu.insert(c.id.clone(), (usec, now));
            }
            if let Some(used) =
                read(&dir.join("memory.current")).and_then(|v| v.trim().parse::<f64>().ok())
            {
                push(gauge("container.memory.used_bytes", source, "By", used));
            }
            if let Some(limit) =
                read(&dir.join("memory.max")).and_then(|v| v.trim().parse::<f64>().ok())
            {
                push(gauge("container.memory.limit_bytes", source, "By", limit));
            }
        }
        let running: std::collections::HashSet<&str> =
            self.containers.iter().map(|c| c.id.as_str()).collect();
        self.prev_container_cpu
            .retain(|id, _| running.contains(id.as_str()));
        out
    }

    async fn refresh(&mut self) {
        if self
            .listed_at
            .is_some_and(|at| at.elapsed() < CONTAINERS_EVERY)
        {
            return;
        }
        self.listed_at = Some(Instant::now());
        if let Ok(list) =
            runner::list_containers(self.runner.as_ref(), &ContainerFilter::default()).await
        {
            self.containers = list;
        }
    }

    /// One sampling pass: stores every sample under `system`.
    pub async fn tick(&mut self) -> usize {
        self.refresh().await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or_default();
        let mut samples = self.host();
        samples.extend(self.containers(Instant::now()));
        let n = samples.len();
        for s in samples {
            self.telemetry
                .otlp_state
                .metric(&self.telemetry, Producer::System, ts, s);
        }
        n
    }

    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(SAMPLE_EVERY);
        loop {
            tick.tick().await;
            self.tick().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::telemetry::ingest::tests::{container, ScriptRunner};
    use crate::local::telemetry::test_support;
    use crate::signed_plan::test_support::temp_dir;
    use std::fs;

    #[tokio::test]
    async fn host_and_container_samples_from_fixture_trees() {
        let dir = temp_dir("metrics-fixture");
        let proc_root = dir.join("proc");
        fs::create_dir_all(proc_root.join("net")).unwrap();
        fs::write(proc_root.join("stat"), "cpu  100 0 100 800 0 0 0 0 0 0\n").unwrap();
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n",
        )
        .unwrap();
        fs::write(proc_root.join("loadavg"), "0.50 0.25 0.10 1/100 42\n").unwrap();
        fs::write(
            proc_root.join("net/dev"),
            "Inter-|\n face |\n    lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n  eth0: 500 0 0 0 0 0 0 0 700 0 0 0 0 0 0 0\n",
        )
        .unwrap();
        let id = "abcdef0123456789";
        let cg = dir
            .join("cgroup/system.slice")
            .join(format!("docker-{id}.scope"));
        fs::create_dir_all(&cg).unwrap();
        fs::write(cg.join("cpu.stat"), "usage_usec 2000000\nuser_usec 1\n").unwrap();
        fs::write(cg.join("memory.current"), "4096\n").unwrap();
        fs::write(cg.join("memory.max"), "max\n").unwrap();

        let t = test_support::open(dir.join("telemetry"));
        let mut c = container(id, "web");
        c["project_id"] = serde_json::json!("p1");
        let runner = ScriptRunner::new(vec![c]);
        let mut s = Sampler::new(t.clone(), runner);
        s.proc_root = proc_root.clone();
        s.cgroup_root = dir.join("cgroup");
        s.disk_path = dir.clone();
        let first = s.tick().await;
        let names = |v: &[MetricSample]| v.iter().map(|m| m.name.clone()).collect::<Vec<_>>();
        // No CPU time passed since the first pass: no CPU percent yet.
        let host = s.host();
        assert!(!names(&host).contains(&"host.cpu.percent".to_owned()));
        assert!(first >= 9);
        fs::write(proc_root.join("stat"), "cpu  200 0 200 1600 0 0 0 0 0 0\n").unwrap();
        let host = s.host();
        let cpu = host.iter().find(|m| m.name == "host.cpu.percent").unwrap();
        assert_eq!(cpu.value, 20.0);
        let used = host
            .iter()
            .find(|m| m.name == "host.memory.used_bytes")
            .unwrap();
        assert_eq!(used.value, 750.0 * 1024.0);
        let rx = host
            .iter()
            .find(|m| m.name == "host.network.rx_bytes")
            .unwrap();
        assert_eq!(rx.labels["interface"], "eth0");
        assert!(host
            .iter()
            .all(|m| m.labels.get("interface").map(String::as_str) != Some("lo")));

        let later = Instant::now() + Duration::from_secs(10);
        fs::write(cg.join("cpu.stat"), "usage_usec 7000000\n").unwrap();
        let cs = s.containers(later);
        let pct = cs
            .iter()
            .find(|m| m.name == "container.cpu.percent")
            .unwrap();
        assert!((pct.value - 50.0).abs() < 1.0, "{}", pct.value);
        let mem = cs
            .iter()
            .find(|m| m.name == "container.memory.used_bytes")
            .unwrap();
        assert_eq!(mem.value, 4096.0);
        assert_eq!(mem.labels["project_id"], "p1");
        assert_eq!(mem.labels["container"], format!("{id}-name"));
        assert!(cs.iter().all(|m| m.name != "container.memory.limit_bytes"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cgroup_paths_need_hex_ids() {
        assert_eq!(cpu_times("cpu  1 2 3 4 5 6 7 8\n"), Some((36, 9)));
        assert_eq!(cpu_times("nope"), None);
    }
}
