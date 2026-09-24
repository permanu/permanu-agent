//! The server-side telemetry store and its producers (agent-protocol.md 9,
//! capability `telemetry.v1`, D-053, D-054).
//!
//! [`Telemetry`] owns the [`store::Store`] behind one writer task: producers
//! (log ingestion, the OTLP receiver, the metrics sampler) redact first and
//! then [`Telemetry::submit`] records into an in-memory ingest queue of 8 MiB
//! per kind (9.3); overflow and the disk guard drop records and count them,
//! never silently. The writer appends in ingest order and flushes each batch
//! (at least every second, 9.1); a maintenance task enforces retention every
//! 60 s and checks the disk guard every 5 s.

pub mod ingest;
pub mod journal;
pub mod metrics;
pub mod otlp;
pub mod otlp_server;
pub mod query;
pub mod records;
pub mod redaction;
pub mod routes;
pub mod store;

#[cfg(test)]
mod service_tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{mpsc, oneshot, watch};
use tracing::warn;

use crate::proto::agent::v2::{
    event, resource_pressure_event, EventKind, ResourcePressureEvent, Scope,
};

use super::events::EventBus;
use store::{Appended, DiskProbe, Kind, Producer, Store, StoreOptions};

/// `/var/lib/permanu/telemetry` (9.1).
pub const DEFAULT_ROOT: &str = "/var/lib/permanu/telemetry";
/// 9.3: in-memory ingest queue per kind.
pub const QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// 9.3: `telemetry_dropping` stays set this long after the last drop.
const DROPPING_FOR: Duration = Duration::from_secs(60);
const ENFORCE_EVERY: Duration = Duration::from_secs(60);
const DISK_EVERY: Duration = Duration::from_secs(5);
const RATE_EVERY: Duration = Duration::from_secs(10);

enum Item {
    Record {
        kind: Kind,
        producer: Producer,
        ts_nanos: i64,
        tag: u8,
        payload: Vec<u8>,
    },
    Barrier(oneshot::Sender<()>),
}

#[derive(Default)]
struct KindState {
    queued: AtomicUsize,
    dropped: AtomicU64,
    redacted: AtomicU64,
    rate_milli: AtomicU64,
}

/// OTLP listener state for `AgentStatus` (9.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtlpListen {
    pub grpc_listen: String,
    pub http_listen: String,
}

/// Where a record was dropped before the store (for `dropped_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    Queued,
    Dropped,
}

pub struct Telemetry {
    store: Mutex<Store>,
    tx: mpsc::UnboundedSender<Item>,
    kinds: [KindState; 5],
    /// Last stored `ingest_seq` per kind; followers wait on it.
    seqs: [watch::Sender<u64>; 5],
    last_drop: Mutex<Option<Instant>>,
    paused: AtomicBool,
    system_paused: AtomicBool,
    disk: Arc<dyn DiskProbe>,
    otlp: Mutex<OtlpListen>,
    /// OTLP processing state (trace settling, series limits).
    pub otlp_state: Arc<otlp::OtlpState>,
    runner_unreachable: AtomicBool,
    events: Option<EventBus>,
    started: Instant,
    /// OTLP clients cut off by the connection limits (D-063 #17).
    otlp_refused: AtomicU64,
}

/// What the rest of the agent needs to start telemetry.
pub struct TelemetryParts {
    pub options: StoreOptions,
    pub disk: Arc<dyn DiskProbe>,
    pub events: Option<EventBus>,
}

impl Telemetry {
    /// Opens the store and starts the writer. Call [`Telemetry::spawn_maintenance`]
    /// for retention and the disk guard.
    pub fn open(parts: TelemetryParts) -> std::io::Result<Arc<Self>> {
        let store = Store::open(parts.options, SystemTime::now())?;
        let seqs = Kind::ALL.map(|k| watch::channel(store.last_seq(k)).0);
        let (tx, rx) = mpsc::unbounded_channel();
        let telemetry = Arc::new(Self {
            store: Mutex::new(store),
            tx,
            kinds: Default::default(),
            seqs,
            last_drop: Mutex::new(None),
            paused: AtomicBool::new(false),
            system_paused: AtomicBool::new(false),
            disk: parts.disk,
            otlp: Mutex::new(OtlpListen::default()),
            otlp_state: Arc::new(otlp::OtlpState::default()),
            runner_unreachable: AtomicBool::new(false),
            events: parts.events,
            started: Instant::now(),
            otlp_refused: AtomicU64::new(0),
        });
        telemetry.check_disk();
        tokio::spawn(Self::writer(Arc::downgrade(&telemetry), rx));
        otlp::spawn_settler(telemetry.otlp_state.clone(), Arc::downgrade(&telemetry));
        Ok(telemetry)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn writer(this: std::sync::Weak<Self>, mut rx: mpsc::UnboundedReceiver<Item>) {
        while let Some(first) = rx.recv().await {
            let Some(this) = this.upgrade() else {
                return;
            };
            let mut barriers = Vec::new();
            let mut touched = [false; 5];
            {
                let mut store = this.lock();
                let now = SystemTime::now();
                let mut item = Some(first);
                let mut n = 0;
                while let Some(next) = item.take() {
                    match next {
                        Item::Record {
                            kind,
                            producer,
                            ts_nanos,
                            tag,
                            payload,
                        } => {
                            let state = &this.kinds[kind as usize];
                            state.queued.fetch_sub(payload.len(), Ordering::SeqCst);
                            if let Appended::Stored(_) =
                                store.append(kind, &producer, ts_nanos, tag, &payload, now)
                            {
                                touched[kind as usize] = true;
                            } else {
                                this.mark_drop();
                            }
                        }
                        Item::Barrier(done) => barriers.push(done),
                    }
                    n += 1;
                    if n < 4096 {
                        item = rx.try_recv().ok();
                    }
                }
                store.flush();
                for kind in Kind::ALL {
                    if touched[kind as usize] {
                        this.seqs[kind as usize].send_replace(store.last_seq(kind));
                    }
                }
            }
            for done in barriers {
                let _ = done.send(());
            }
        }
    }

    fn mark_drop(&self) {
        *self.last_drop.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
    }

    /// Queues one redacted record. `redacted` counts it in `redacted_total`.
    pub fn submit(
        &self,
        kind: Kind,
        producer: Producer,
        ts_nanos: i64,
        tag: u8,
        payload: Vec<u8>,
        redacted: bool,
    ) -> Submitted {
        let state = &self.kinds[kind as usize];
        let paused = if producer == Producer::System {
            self.system_paused.load(Ordering::SeqCst)
        } else {
            self.paused.load(Ordering::SeqCst)
        };
        let len = payload.len();
        if paused || state.queued.load(Ordering::SeqCst) + len > QUEUE_BYTES {
            state.dropped.fetch_add(1, Ordering::SeqCst);
            self.mark_drop();
            return Submitted::Dropped;
        }
        state.queued.fetch_add(len, Ordering::SeqCst);
        if redacted {
            state.redacted.fetch_add(1, Ordering::SeqCst);
        }
        let sent = self.tx.send(Item::Record {
            kind,
            producer,
            ts_nanos,
            tag,
            payload,
        });
        if sent.is_err() {
            state.queued.fetch_sub(len, Ordering::SeqCst);
            state.dropped.fetch_add(1, Ordering::SeqCst);
            return Submitted::Dropped;
        }
        Submitted::Queued
    }

    /// Counts records dropped by a producer's own limits (9.4 rate limits,
    /// OTLP limits) in `dropped_total`.
    pub fn count_dropped(&self, kind: Kind, n: u64) {
        if n > 0 {
            self.kinds[kind as usize]
                .dropped
                .fetch_add(n, Ordering::SeqCst);
            self.mark_drop();
        }
    }

    /// Counts an OTLP client cut off by the connection limits (D-063 #17).
    pub fn count_otlp_refused(&self) {
        self.otlp_refused.fetch_add(1, Ordering::SeqCst);
    }

    /// OTLP clients cut off by the connection limits since start
    /// (`GetTelemetryUsageResponse.otlp_refused_total`, D-064 #6).
    #[cfg(test)]
    pub fn otlp_connections_refused(&self) -> u64 {
        self.otlp_refused.load(Ordering::SeqCst)
    }

    /// Resolves once everything submitted before it is stored and flushed.
    pub async fn sync(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Item::Barrier(tx)).is_ok() {
            let _ = rx.await;
        }
    }

    /// A read view of `kind` (flushed).
    pub fn snapshot(&self, kind: Kind) -> store::Snapshot {
        self.lock().snapshot(kind, SystemTime::now())
    }

    pub fn cursor_live(&self, cursor: &store::Cursor) -> bool {
        self.lock().cursor_live(cursor)
    }

    pub fn evicted_at(&self, kind: Kind, ts_nanos: i64) -> bool {
        self.lock().evicted_at(kind, ts_nanos)
    }

    /// Changes whenever `kind` stores new records (follow).
    pub fn watch(&self, kind: Kind) -> watch::Receiver<u64> {
        self.seqs[kind as usize].subscribe()
    }

    /// Retention now (tests and the maintenance task).
    pub fn enforce(&self, now: SystemTime) {
        self.lock().enforce(now);
    }

    /// Updates the disk guard and reports transitions (9.3).
    pub fn check_disk(&self) {
        let (before, guard) = {
            let mut store = self.lock();
            let before = store.guard();
            (before, store.check_disk(self.disk.as_ref()))
        };
        self.paused.store(guard.paused, Ordering::SeqCst);
        self.system_paused
            .store(guard.system_paused, Ordering::SeqCst);
        if before.paused != guard.paused {
            if guard.paused {
                warn!(free = guard.free_bytes, "telemetry ingest paused: disk low");
            }
            if let Some(events) = &self.events {
                let used = if guard.total_bytes == 0 {
                    0.0
                } else {
                    1.0 - guard.free_bytes as f64 / guard.total_bytes as f64
                };
                events.publish(
                    EventKind::ResourcePressure,
                    Scope::default(),
                    event::Payload::ResourcePressure(ResourcePressureEvent {
                        resource: resource_pressure_event::Resource::TelemetryStore as i32,
                        target: self.lock().root().display().to_string(),
                        used_ratio: used,
                        threshold: 0.95,
                        resolved: !guard.paused,
                    }),
                );
            }
        }
    }

    fn sample_rates(&self, last: &mut [u64; 5], elapsed: Duration) {
        let usage = self.lock().usage(SystemTime::now());
        for u in usage {
            let i = u.kind as usize;
            let total = u.counters.appended_total;
            let rate = (total.saturating_sub(last[i])) as f64 / elapsed.as_secs_f64().max(0.001);
            last[i] = total;
            self.kinds[i]
                .rate_milli
                .store((rate * 1000.0) as u64, Ordering::SeqCst);
        }
    }

    /// Retention every 60 s, disk guard every 5 s, ingest rates every 10 s.
    pub fn spawn_maintenance(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut disk = tokio::time::interval(DISK_EVERY);
            let mut enforce = tokio::time::interval(ENFORCE_EVERY);
            let mut rates = tokio::time::interval(RATE_EVERY);
            let mut last = [0u64; 5];
            let mut last_at = Instant::now();
            loop {
                tokio::select! {
                    _ = disk.tick() => {
                        let Some(this) = weak.upgrade() else { return };
                        this.check_disk();
                    }
                    _ = enforce.tick() => {
                        let Some(this) = weak.upgrade() else { return };
                        tokio::task::spawn_blocking(move || this.enforce(SystemTime::now()));
                    }
                    _ = rates.tick() => {
                        let Some(this) = weak.upgrade() else { return };
                        this.sample_rates(&mut last, last_at.elapsed());
                        last_at = Instant::now();
                    }
                }
            }
        })
    }

    /// Closes open segments (shutdown).
    pub fn close(&self) {
        let mut store = self.lock();
        store.flush();
        store.close_all();
    }

    pub fn root(&self) -> PathBuf {
        self.lock().root().to_path_buf()
    }

    pub fn gid(&self) -> Option<u32> {
        self.lock().gid()
    }

    pub fn set_otlp(&self, state: OtlpListen) {
        *self.otlp.lock().unwrap_or_else(|p| p.into_inner()) = state;
    }

    pub fn otlp(&self) -> OtlpListen {
        self.otlp.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// `(min start, max end)` of a recent trace, to narrow `GetTrace`.
    pub fn trace_bounds(&self, trace_id: &str) -> Option<(i64, i64)> {
        self.otlp_state
            .trace_bounds(trace_id)
            .map(|(a, b, _)| (a, b))
    }

    /// Whether spans of the trace were dropped over the per-trace cap.
    pub fn trace_truncated(&self, trace_id: &str) -> bool {
        self.otlp_state
            .trace_bounds(trace_id)
            .is_some_and(|(_, _, t)| t)
    }

    pub fn set_runner_unreachable(&self, unreachable: bool) {
        self.runner_unreachable.store(unreachable, Ordering::SeqCst);
    }

    /// `GetTelemetryUsage` (9.2, 9.3).
    pub fn usage(&self) -> TelemetryUsageReport {
        let store = self.lock();
        let guard = store.guard();
        let kinds = store
            .usage(SystemTime::now())
            .into_iter()
            .map(|mut u| {
                let state = &self.kinds[u.kind as usize];
                u.counters.dropped_total += state.dropped.load(Ordering::SeqCst);
                u.counters.redacted_total += state.redacted.load(Ordering::SeqCst);
                let rate = state.rate_milli.load(Ordering::SeqCst) as f64 / 1000.0;
                (u, rate)
            })
            .collect();
        let spool_bytes = self
            .kinds
            .iter()
            .map(|k| k.queued.load(Ordering::SeqCst) as u64)
            .sum();
        TelemetryUsageReport {
            kinds,
            disk_free_bytes: guard.free_bytes,
            ingest_paused: guard.paused,
            spool_bytes,
            otlp_refused_total: self.otlp_refused.load(Ordering::SeqCst),
        }
    }

    /// The telemetry entries of `AgentStatus.degraded_reasons` (12.3).
    pub fn degraded_reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.runner_unreachable.load(Ordering::SeqCst) {
            reasons.push("runner_unreachable");
        }
        let dropping = self
            .last_drop
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|at| at.elapsed() < DROPPING_FOR);
        if dropping {
            reasons.push("telemetry_dropping");
        }
        if self.paused.load(Ordering::SeqCst) {
            reasons.push("telemetry_ingest_paused");
        }
        let reset = self.lock().reset_at.is_some_and(|at| {
            SystemTime::now()
                .duration_since(at)
                .is_ok_and(|age| age < store::RESET_DEGRADED)
        }) && self.started.elapsed() < store::RESET_DEGRADED;
        if reset {
            reasons.push("telemetry_store_reset");
        }
        if self.otlp().grpc_listen.is_empty() {
            reasons.push("otlp_unbound");
        }
        reasons
    }

    /// Reads `checkpoint.json` (9.4), empty when absent or unreadable.
    pub fn read_checkpoint(&self) -> serde_json::Value {
        std::fs::read(self.root().join("checkpoint.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(serde_json::Value::Null)
    }

    /// Rewrites `checkpoint.json` atomically.
    pub fn write_checkpoint(&self, value: &serde_json::Value) {
        let path = self.root().join("checkpoint.json");
        if let Err(err) = store::write_atomic(&path, value.to_string().as_bytes(), self.gid()) {
            warn!(error = %err, "telemetry checkpoint write failed");
        }
    }
}

/// `GetTelemetryUsage` data: usage and ingest rate per kind.
pub struct TelemetryUsageReport {
    pub kinds: Vec<(store::Usage, f64)>,
    pub disk_free_bytes: u64,
    pub ingest_paused: bool,
    /// Bytes accepted into the ingest queues, not yet written (D-063 #13).
    pub spool_bytes: u64,
    /// OTLP connections refused at accept or cut by a limit (D-064 #6).
    pub otlp_refused_total: u64,
}

/// Token bucket (ingest rate limits, 9.4 and 9.5).
#[derive(Debug, Clone)]
pub struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            at: Instant::now(),
        }
    }

    pub fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Buckets keyed by a name, pruned when they grow too many.
#[derive(Debug, Default)]
pub struct Buckets {
    map: HashMap<String, Bucket>,
}

impl Buckets {
    pub fn take(&mut self, key: &str, rate: f64, burst: f64, now: Instant) -> bool {
        if self.map.len() > 10_000 {
            self.map
                .retain(|_, b| now.saturating_duration_since(b.at) < Duration::from_secs(60));
        }
        self.map
            .entry(key.to_owned())
            .or_insert_with(|| Bucket::new(rate, burst))
            .take(now)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::path::Path;

    pub struct Disk(pub Mutex<(u64, u64)>);

    impl DiskProbe for Disk {
        fn free(&self, _: &Path) -> Option<(u64, u64)> {
            Some(*self.0.lock().unwrap())
        }
    }

    pub fn roomy() -> Arc<Disk> {
        Arc::new(Disk(Mutex::new((500 << 30, 1000 << 30))))
    }

    pub fn open(root: PathBuf) -> Arc<Telemetry> {
        Telemetry::open(TelemetryParts {
            options: StoreOptions::new(root),
            disk: roomy(),
            events: None,
        })
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_plan::test_support::temp_dir;

    #[tokio::test]
    async fn submit_queues_writes_and_counts_drops() {
        let dir = temp_dir("tel-facade");
        let disk = Arc::new(test_support::Disk(Mutex::new((500 << 30, 1000 << 30))));
        let t = Telemetry::open(TelemetryParts {
            options: StoreOptions::new(dir.join("telemetry")),
            disk: disk.clone(),
            events: Some(EventBus::new()),
        })
        .unwrap();
        let p = Producer::Project("p1".into());
        let mut seen = t.watch(Kind::Logs);
        assert_eq!(
            t.submit(Kind::Logs, p.clone(), 1, 1, b"one".to_vec(), true),
            Submitted::Queued
        );
        t.sync().await;
        assert_eq!(*seen.borrow_and_update(), 1);
        let report = t.usage();
        assert_eq!(report.kinds[0].0.records, 1);
        assert_eq!(report.kinds[0].0.counters.redacted_total, 1);
        assert!(!t.degraded_reasons().contains(&"telemetry_dropping"));

        // Over the 8 MiB queue: dropped and counted, never silent.
        assert_eq!(
            t.submit(Kind::Logs, p.clone(), 1, 1, vec![0; QUEUE_BYTES + 1], false),
            Submitted::Dropped
        );
        assert_eq!(t.usage().kinds[0].0.counters.dropped_total, 1);
        assert!(t.degraded_reasons().contains(&"telemetry_dropping"));

        // Disk guard: projects paused, system still writes.
        *disk.0.lock().unwrap() = (500 << 20, 1000 << 30);
        t.check_disk();
        assert!(t.usage().ingest_paused);
        assert!(t.degraded_reasons().contains(&"telemetry_ingest_paused"));
        assert_eq!(
            t.submit(Kind::Logs, p, 2, 1, b"x".to_vec(), false),
            Submitted::Dropped
        );
        assert_eq!(
            t.submit(Kind::Logs, Producer::System, 2, 1, b"x".to_vec(), false),
            Submitted::Queued
        );
        t.sync().await;
        assert_eq!(t.usage().kinds[0].0.records, 2);
        assert!(t.degraded_reasons().contains(&"otlp_unbound"));
        t.close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// D-063 #13: `spool_bytes` counts bytes accepted but not yet written.
    #[tokio::test(flavor = "current_thread")]
    async fn usage_reports_spool_bytes_until_written() {
        let dir = temp_dir("tel-spool");
        let t = test_support::open(dir.join("telemetry"));
        assert_eq!(t.usage().spool_bytes, 0);
        let p = Producer::Project("p1".into());
        // The writer cannot run before the next await on this runtime.
        t.submit(Kind::Logs, p.clone(), 1, 1, vec![1; 100], false);
        t.submit(Kind::Traces, p, 1, 1, vec![2; 23], false);
        assert_eq!(t.usage().spool_bytes, 123);
        t.sync().await;
        assert_eq!(t.usage().spool_bytes, 0);
        t.close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// D-064 #6: refused or cut OTLP connections reach
    /// `GetTelemetryUsageResponse.otlp_refused_total`.
    #[tokio::test(flavor = "current_thread")]
    async fn usage_reports_otlp_refused_total() {
        let dir = temp_dir("tel-otlp-refused");
        let t = test_support::open(dir.join("telemetry"));
        assert_eq!(t.usage().otlp_refused_total, 0);
        t.count_otlp_refused();
        t.count_otlp_refused();
        assert_eq!(t.usage().otlp_refused_total, 2);
        let response = query::StoreQueries::new(t.clone()).usage();
        assert_eq!(response.otlp_refused_total, 2);
        t.close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn buckets_refill_at_their_rate() {
        let start = Instant::now();
        let mut b = Bucket::new(10.0, 2.0);
        assert!(b.take(start));
        assert!(b.take(start));
        assert!(!b.take(start));
        assert!(b.take(start + Duration::from_millis(150)));
    }
}
