//! The on-disk telemetry store (agent-protocol.md 9.1 to 9.3).
//!
//! ```text
//! <root>/                     0750
//!   store.json                {"version": 1, "created_at", "redaction_rules_version"}
//!   checkpoint.json           log ingest resume positions (9.4)
//!   <kind>/<producer>/        one directory per producer (9.2)
//!     <first_ingest_seq>.seg  append-only data segment, 0640
//!     <first_ingest_seq>.idx  sparse block index plus a closing summary
//! ```
//!
//! Segment encoding (agent-owned, `store.json.version` 1): frames of
//! `len u32 | ingest_seq u64 | timestamp_nanos i64 | tag u8 | payload`, all
//! little endian, `len` counting everything after itself. The index holds
//! fixed 33-byte entries: a block entry `(1, offset, first_seq, first_ts, 0)`
//! every 64 KiB of data, and on close one summary entry `(2, records,
//! last_seq, min_ts, max_ts)`. A segment without a summary is the open one
//! of a crashed agent: it is scanned (a torn last frame is cut off) and
//! closed on start. Closed segments are never rewritten.
//!
//! Eviction and the disk guard follow 9.2 and 9.3: age every 60 s; above
//! `max_bytes` down to 90%, always from the producer furthest above its
//! fair share (`otlp:*` first while they hold more than half), oldest
//! segment first; `system` only by age or inside its reserved quarter.

use std::collections::{BTreeMap, BinaryHeap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde_json::json;
use tracing::warn;

use super::redaction::RULES_VERSION;

pub const STORE_VERSION: u64 = 1;
pub const SEGMENT_MAX_BYTES: u64 = 32 * 1024 * 1024;
pub const SEGMENT_MAX_AGE: Duration = Duration::from_secs(3600);
const BLOCK_BYTES: u64 = 64 * 1024;
const FRAME_HEADER: usize = 4 + 8 + 8 + 1;
const IDX_ENTRY: usize = 33;
/// A frame larger than this is corrupt (records are ≤ 4 MiB on the wire).
const MAX_FRAME: usize = 8 * 1024 * 1024;
const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;
const DAY_NANOS: i64 = 86_400 * 1_000_000_000;
/// Evicted segment spans remembered for `CURSOR_EXPIRED` on `range.start`.
const EVICTED_SPANS: usize = 4_096;
/// How long `telemetry_store_reset` stays degraded.
pub const RESET_DEGRADED: Duration = Duration::from_secs(24 * 3600);

/// `TelemetryKind`, in proto order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Logs,
    Traces,
    Metrics,
    Analytics,
    Http,
}

impl Kind {
    pub const ALL: [Kind; 5] = [
        Kind::Logs,
        Kind::Traces,
        Kind::Metrics,
        Kind::Analytics,
        Kind::Http,
    ];

    pub fn dir(self) -> &'static str {
        match self {
            Kind::Logs => "logs",
            Kind::Traces => "traces",
            Kind::Metrics => "metrics",
            Kind::Analytics => "analytics",
            Kind::Http => "http",
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    /// D-054 defaults (9.2).
    pub fn default_retention(self) -> Retention {
        let (max_age_days, max_bytes) = match self {
            Kind::Logs => (7, GIB),
            Kind::Traces => (3, 512 * MIB),
            Kind::Metrics => (15, 256 * MIB),
            Kind::Analytics => (30, 256 * MIB),
            Kind::Http => (7, 256 * MIB),
        };
        Retention {
            max_age_days,
            max_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub max_age_days: u32,
    pub max_bytes: u64,
}

/// Who a record belongs to (9.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Producer {
    System,
    Project(String),
    Otlp(String),
    OtlpUnattributed,
}

/// Project ids name directories, so only plain ids are accepted.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Producer {
    pub fn dir_name(&self) -> String {
        match self {
            Producer::System => "system".to_owned(),
            Producer::Project(id) => format!("project:{id}"),
            Producer::Otlp(id) => format!("otlp:{id}"),
            Producer::OtlpUnattributed => "otlp:unattributed".to_owned(),
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "system" => Some(Producer::System),
            "otlp:unattributed" => Some(Producer::OtlpUnattributed),
            _ => {
                if let Some(id) = name.strip_prefix("project:") {
                    valid_id(id).then(|| Producer::Project(id.to_owned()))
                } else if let Some(id) = name.strip_prefix("otlp:") {
                    valid_id(id).then(|| Producer::Otlp(id.to_owned()))
                } else {
                    None
                }
            }
        }
    }

    fn is_otlp(&self) -> bool {
        matches!(self, Producer::Otlp(_) | Producer::OtlpUnattributed)
    }
}

/// One stored record as a query reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecord {
    pub seq: u64,
    pub ts_nanos: i64,
    pub tag: u8,
    pub payload: Vec<u8>,
    pub producer: Producer,
    pub segment: u64,
}

impl RawRecord {
    pub fn cursor(&self, kind: Kind) -> String {
        Cursor {
            kind,
            producer: self.producer.clone(),
            segment: self.segment,
            seq: self.seq,
        }
        .encode()
    }
}

/// Opaque cursor `(kind, segment, ingest_seq)` (9.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub kind: Kind,
    pub producer: Producer,
    pub segment: u64,
    pub seq: u64,
}

impl Cursor {
    pub fn encode(&self) -> String {
        let text = format!(
            "t1|{}|{}|{}|{}",
            self.kind.dir(),
            self.producer.dir_name(),
            self.segment,
            self.seq
        );
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text)
    }

    pub fn decode(cursor: &str) -> Option<Self> {
        if cursor.len() > 256 {
            return None;
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cursor)
            .ok()?;
        let text = String::from_utf8(bytes).ok()?;
        let mut parts = text.split('|');
        let (Some("t1"), Some(kind), Some(producer), Some(segment), Some(seq), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        Some(Self {
            kind: *Kind::ALL.iter().find(|k| k.dir() == kind)?,
            producer: Producer::parse(producer)?,
            segment: segment.parse().ok()?,
            seq: seq.parse().ok()?,
        })
    }
}

/// Free space of the store's filesystem.
pub trait DiskProbe: Send + Sync {
    /// `(free_bytes, total_bytes)`, `None` when unknown.
    fn free(&self, path: &Path) -> Option<(u64, u64)>;
}

pub struct StatvfsDisk;

impl DiskProbe for StatvfsDisk {
    fn free(&self, path: &Path) -> Option<(u64, u64)> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: statvfs writes into the zeroed struct we own and reads a
        // NUL-terminated path.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if rc != 0 {
            return None;
        }
        let frsize = stat.f_frsize as u64;
        Some((
            (stat.f_bavail as u64).saturating_mul(frsize),
            (stat.f_blocks as u64).saturating_mul(frsize),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct StoreOptions {
    pub root: PathBuf,
    pub retention: [Retention; 5],
    pub segment_max_bytes: u64,
    pub segment_max_age: Duration,
    /// Owner group applied to created directories and files (`None` keeps
    /// the process's).
    pub gid: Option<u32>,
}

impl StoreOptions {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            retention: Kind::ALL.map(Kind::default_retention),
            segment_max_bytes: SEGMENT_MAX_BYTES,
            segment_max_age: SEGMENT_MAX_AGE,
            gid: None,
        }
    }
}

#[derive(Debug, Clone)]
struct Segment {
    first_seq: u64,
    last_seq: u64,
    records: u64,
    seg_bytes: u64,
    idx_bytes: u64,
    min_ts: i64,
    max_ts: i64,
    /// `(offset, first_seq)` of each block.
    blocks: Vec<(u64, u64)>,
    closed: bool,
}

impl Segment {
    fn bytes(&self) -> u64 {
        self.seg_bytes + self.idx_bytes
    }
}

struct OpenFiles {
    seg: BufWriter<File>,
    idx: File,
    opened: SystemTime,
    block_fill: u64,
}

#[derive(Default)]
struct ProducerData {
    segments: Vec<Segment>,
    open: Option<OpenFiles>,
}

impl ProducerData {
    fn bytes(&self) -> u64 {
        self.segments.iter().map(Segment::bytes).sum()
    }
}

/// Per-kind counters since agent start (9.3, `TelemetryUsage`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Counters {
    pub dropped_total: u64,
    pub evicted_total: u64,
    pub evicted_bytes_total: u64,
    pub redacted_total: u64,
    pub appended_total: u64,
}

#[derive(Default)]
struct KindData {
    next_seq: u64,
    producers: BTreeMap<Producer, ProducerData>,
    counters: Counters,
    /// `(min_ts, max_ts)` of evicted segments, newest last.
    evicted: VecDeque<(i64, i64)>,
}

/// Usage of one kind (`TelemetryUsage`).
#[derive(Debug, Clone, PartialEq)]
pub struct Usage {
    pub kind: Kind,
    pub retention: Retention,
    pub bytes_used: u64,
    pub records: u64,
    pub oldest_nanos: Option<i64>,
    pub newest_nanos: Option<i64>,
    pub counters: Counters,
}

/// A consistent, read-only view of one producer's segments.
#[derive(Debug, Clone)]
struct SegmentView {
    path: PathBuf,
    first_seq: u64,
    last_seq: u64,
    min_ts: i64,
    max_ts: i64,
    blocks: Vec<(u64, u64)>,
    readable: u64,
}

/// What a scan reads: the segments of each producer, as of the snapshot.
#[derive(Debug, Clone)]
pub struct Snapshot {
    kind: Kind,
    producers: Vec<(Producer, Vec<SegmentView>)>,
    /// Records older than this are filtered out (retention, 9.3).
    pub min_ts: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

/// Scan bounds: records strictly after `after_seq` (forward) or before
/// `before_seq` (backward), with `timestamp` in `[from_ts, to_ts]`.
#[derive(Debug, Clone)]
pub struct ScanSpec {
    pub direction: Direction,
    pub after_seq: Option<u64>,
    pub before_seq: Option<u64>,
    pub from_ts: i64,
    pub to_ts: i64,
    /// Only these producers (`None` = all).
    pub producers: Option<Vec<Producer>>,
}

impl Default for ScanSpec {
    fn default() -> Self {
        Self {
            direction: Direction::Forward,
            after_seq: None,
            before_seq: None,
            from_ts: i64::MIN,
            to_ts: i64::MAX,
            producers: None,
        }
    }
}

/// An append outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    Stored(u64),
    /// Refused by the disk guard.
    Paused,
    /// The write failed (counted as dropped).
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardState {
    /// Ingest paused for every producer but `system`.
    pub paused: bool,
    /// `system` paused too (less than 256 MiB free).
    pub system_paused: bool,
    pub free_bytes: u64,
    pub total_bytes: u64,
}

pub struct Store {
    opts: StoreOptions,
    kinds: [KindData; 5],
    guard: GuardState,
    /// Set when an unknown store version was moved aside.
    pub reset_at: Option<SystemTime>,
}

fn nanos_of(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_nanos()).unwrap_or(i64::MAX),
    }
}

fn mkdir(path: &Path, gid: Option<u32>) -> std::io::Result<()> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
        chgrp(path, gid);
    }
    Ok(())
}

fn chgrp(path: &Path, gid: Option<u32>) {
    if let Some(gid) = gid {
        let _ = std::os::unix::fs::chown(path, None, Some(gid));
    }
}

/// Writes `bytes` to `path` atomically (temp file, fsync, rename), 0640.
pub fn write_atomic(path: &Path, bytes: &[u8], gid: Option<u32>) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o640)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    chgrp(&tmp, gid);
    fs::rename(&tmp, path)
}

fn idx_entry(tag: u8, a: u64, b: u64, c: i64, d: i64) -> [u8; IDX_ENTRY] {
    let mut out = [0u8; IDX_ENTRY];
    out[0] = tag;
    out[1..9].copy_from_slice(&a.to_le_bytes());
    out[9..17].copy_from_slice(&b.to_le_bytes());
    out[17..25].copy_from_slice(&c.to_le_bytes());
    out[25..33].copy_from_slice(&d.to_le_bytes());
    out
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}

fn i64_at(bytes: &[u8], at: usize) -> i64 {
    u64_at(bytes, at) as i64
}

/// Parses frames from `bytes`; stops at the first torn or corrupt frame and
/// returns how many bytes were valid.
fn parse_frames(bytes: &[u8], mut each: impl FnMut(u64, i64, u8, &[u8])) -> usize {
    let mut at = 0usize;
    while bytes.len() - at >= FRAME_HEADER {
        let len =
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize;
        if !(FRAME_HEADER - 4..=MAX_FRAME).contains(&len) || bytes.len() - at - 4 < len {
            break;
        }
        let seq = u64_at(bytes, at + 4);
        let ts = i64_at(bytes, at + 12);
        let tag = bytes[at + 20];
        each(seq, ts, tag, &bytes[at + FRAME_HEADER..at + 4 + len]);
        at += 4 + len;
    }
    at
}

impl Store {
    /// Opens (or creates) the store at `opts.root`. An unknown
    /// `store.json.version` moves the directory aside and starts empty
    /// (9.1, `telemetry_store_reset`).
    pub fn open(opts: StoreOptions, now: SystemTime) -> std::io::Result<Self> {
        let mut reset_at = None;
        let meta_path = opts.root.join("store.json");
        if opts.root.exists() {
            let version = fs::read(&meta_path)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["version"].as_u64());
            let has_data = fs::read_dir(&opts.root)?.next().is_some();
            if version != Some(STORE_VERSION) && (version.is_some() || has_data) {
                let secs = now
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                let name = format!(
                    "{}.{secs}.old",
                    opts.root
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "telemetry".to_owned())
                );
                let aside = opts.root.with_file_name(name);
                warn!(from = %opts.root.display(), to = %aside.display(), "telemetry store version unknown; moved aside");
                fs::rename(&opts.root, &aside)?;
                reset_at = Some(now);
            }
        }
        mkdir(&opts.root, opts.gid)?;
        if !meta_path.exists() {
            let created = crate::signed_plan::text::format_timestamp(
                now.duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or_default(),
            );
            let meta = json!({"version": STORE_VERSION, "created_at": created,
                              "redaction_rules_version": RULES_VERSION});
            write_atomic(&meta_path, meta.to_string().as_bytes(), opts.gid)?;
        }
        let mut store = Self {
            kinds: Default::default(),
            guard: GuardState::default(),
            reset_at,
            opts,
        };
        for kind in Kind::ALL {
            store.load_kind(kind)?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.opts.root
    }

    pub fn gid(&self) -> Option<u32> {
        self.opts.gid
    }

    pub fn retention(&self, kind: Kind) -> Retention {
        self.opts.retention[kind.index()]
    }

    fn producer_dir(&self, kind: Kind, producer: &Producer) -> PathBuf {
        self.opts.root.join(kind.dir()).join(producer.dir_name())
    }

    fn load_kind(&mut self, kind: Kind) -> std::io::Result<()> {
        let dir = self.opts.root.join(kind.dir());
        mkdir(&dir, self.opts.gid)?;
        let mut next_seq = 1u64;
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(producer) = Producer::parse(&name) else {
                continue;
            };
            let mut firsts: Vec<u64> = fs::read_dir(entry.path())?
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .strip_suffix(".seg")
                        .and_then(|n| n.parse::<u64>().ok())
                })
                .collect();
            firsts.sort_unstable();
            let mut data = ProducerData::default();
            for first in firsts {
                match self.load_segment(&entry.path(), first) {
                    Ok(Some(segment)) => {
                        next_seq = next_seq.max(segment.last_seq + 1);
                        data.segments.push(segment);
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(error = %err, segment = first, "telemetry segment unreadable; skipped")
                    }
                }
            }
            if !data.segments.is_empty() {
                self.kinds[kind.index()].producers.insert(producer, data);
            }
        }
        self.kinds[kind.index()].next_seq = next_seq;
        Ok(())
    }

    /// Reads a segment's index; recovers an unclosed one by scanning it.
    fn load_segment(&self, dir: &Path, first: u64) -> std::io::Result<Option<Segment>> {
        let seg_path = dir.join(format!("{first}.seg"));
        let idx_path = dir.join(format!("{first}.idx"));
        let idx = fs::read(&idx_path).unwrap_or_default();
        let mut blocks = Vec::new();
        let mut summary = None;
        for entry in idx.chunks_exact(IDX_ENTRY) {
            match entry[0] {
                1 => blocks.push((u64_at(entry, 1), u64_at(entry, 9))),
                2 => {
                    summary = Some((
                        u64_at(entry, 1),
                        u64_at(entry, 9),
                        i64_at(entry, 17),
                        i64_at(entry, 25),
                    ))
                }
                _ => {}
            }
        }
        let seg_bytes = fs::metadata(&seg_path)?.len();
        if let Some((records, last_seq, min_ts, max_ts)) = summary {
            return Ok(Some(Segment {
                first_seq: first,
                last_seq,
                records,
                seg_bytes,
                idx_bytes: idx.len() as u64,
                min_ts,
                max_ts,
                blocks,
                closed: true,
            }));
        }
        // Crash recovery: scan, cut a torn tail, rebuild and close.
        let bytes = fs::read(&seg_path)?;
        let (mut records, mut last_seq, mut min_ts, mut max_ts) = (0u64, 0u64, i64::MAX, i64::MIN);
        let mut rebuilt = Vec::new();
        let mut offset = 0u64;
        let mut fill = BLOCK_BYTES;
        let valid = parse_frames(&bytes, |seq, ts, _, payload| {
            if fill >= BLOCK_BYTES {
                rebuilt.push((offset, seq));
                fill = 0;
            }
            let size = (FRAME_HEADER + payload.len()) as u64;
            offset += size;
            fill += size;
            records += 1;
            last_seq = seq;
            min_ts = min_ts.min(ts);
            max_ts = max_ts.max(ts);
        });
        if records == 0 {
            let _ = fs::remove_file(&seg_path);
            let _ = fs::remove_file(&idx_path);
            return Ok(None);
        }
        if valid < bytes.len() {
            OpenOptions::new()
                .write(true)
                .open(&seg_path)?
                .set_len(valid as u64)?;
        }
        let mut idx_out = Vec::new();
        for (offset, seq) in &rebuilt {
            idx_out.extend_from_slice(&idx_entry(1, *offset, *seq, 0, 0));
        }
        idx_out.extend_from_slice(&idx_entry(2, records, last_seq, min_ts, max_ts));
        write_atomic(&idx_path, &idx_out, self.opts.gid)?;
        Ok(Some(Segment {
            first_seq: first,
            last_seq,
            records,
            seg_bytes: valid as u64,
            idx_bytes: idx_out.len() as u64,
            min_ts,
            max_ts,
            blocks: rebuilt,
            closed: true,
        }))
    }

    // ------------------------------------------------------------ append

    /// Updates the disk guard (9.3); returns the new state.
    pub fn check_disk(&mut self, disk: &dyn DiskProbe) -> GuardState {
        let Some((free, total)) = disk.free(&self.opts.root) else {
            return self.guard;
        };
        let ratio = |pct: u64| total / 100 * pct;
        let low = free < ratio(5) || free < GIB;
        let high = free > ratio(8) && free > GIB + GIB / 2;
        let mut guard = self.guard;
        if low {
            guard.paused = true;
        } else if high {
            guard.paused = false;
        }
        guard.system_paused = free < 256 * MIB;
        guard.free_bytes = free;
        guard.total_bytes = total;
        self.guard = guard;
        guard
    }

    pub fn guard(&self) -> GuardState {
        self.guard
    }

    /// Appends one record under `producer`.
    pub fn append(
        &mut self,
        kind: Kind,
        producer: &Producer,
        ts_nanos: i64,
        tag: u8,
        payload: &[u8],
        now: SystemTime,
    ) -> Appended {
        let paused = if *producer == Producer::System {
            self.guard.system_paused
        } else {
            self.guard.paused
        };
        if paused {
            self.kinds[kind.index()].counters.dropped_total += 1;
            return Appended::Paused;
        }
        match self.try_append(kind, producer, ts_nanos, tag, payload, now) {
            Ok(seq) => {
                self.kinds[kind.index()].counters.appended_total += 1;
                Appended::Stored(seq)
            }
            Err(err) => {
                warn!(error = %err, kind = kind.dir(), "telemetry append failed");
                self.kinds[kind.index()].counters.dropped_total += 1;
                Appended::Failed
            }
        }
    }

    fn try_append(
        &mut self,
        kind: Kind,
        producer: &Producer,
        ts: i64,
        tag: u8,
        payload: &[u8],
        now: SystemTime,
    ) -> std::io::Result<u64> {
        let frame_len = FRAME_HEADER + payload.len();
        if frame_len - 4 > MAX_FRAME {
            return Err(std::io::Error::other("record too large"));
        }
        let rotate = {
            let data = self.kinds[kind.index()].producers.get(producer);
            match data.and_then(|d| d.open.as_ref().map(|o| (o, d.segments.last()))) {
                Some((open, Some(seg))) => {
                    seg.seg_bytes + frame_len as u64 > self.opts.segment_max_bytes
                        || now
                            .duration_since(open.opened)
                            .is_ok_and(|age| age >= self.opts.segment_max_age)
                }
                _ => false,
            }
        };
        if rotate {
            self.close_open(kind, producer)?;
        }
        let seq = self.kinds[kind.index()].next_seq;
        let has_open = self.kinds[kind.index()]
            .producers
            .get(producer)
            .is_some_and(|d| d.open.is_some());
        if !has_open {
            self.open_segment(kind, producer, seq, now)?;
        }
        let data = self.kinds[kind.index()]
            .producers
            .get_mut(producer)
            .ok_or_else(|| std::io::Error::other("producer vanished"))?;
        let open = data
            .open
            .as_mut()
            .ok_or_else(|| std::io::Error::other("no open segment"))?;
        let segment = data
            .segments
            .last_mut()
            .ok_or_else(|| std::io::Error::other("no segment"))?;
        if open.block_fill >= BLOCK_BYTES || segment.blocks.is_empty() {
            open.idx
                .write_all(&idx_entry(1, segment.seg_bytes, seq, ts, 0))?;
            segment.blocks.push((segment.seg_bytes, seq));
            segment.idx_bytes += IDX_ENTRY as u64;
            open.block_fill = 0;
        }
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&((frame_len - 4) as u32).to_le_bytes());
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&ts.to_le_bytes());
        frame.push(tag);
        frame.extend_from_slice(payload);
        open.seg.write_all(&frame)?;
        open.block_fill += frame_len as u64;
        segment.seg_bytes += frame_len as u64;
        segment.records += 1;
        segment.last_seq = seq;
        segment.min_ts = segment.min_ts.min(ts);
        segment.max_ts = segment.max_ts.max(ts);
        self.kinds[kind.index()].next_seq = seq + 1;
        Ok(seq)
    }

    fn open_segment(
        &mut self,
        kind: Kind,
        producer: &Producer,
        first: u64,
        now: SystemTime,
    ) -> std::io::Result<()> {
        let dir = self.producer_dir(kind, producer);
        mkdir(&dir, self.opts.gid)?;
        let create = |path: PathBuf| -> std::io::Result<File> {
            let file = OpenOptions::new()
                .create_new(true)
                .append(true)
                .mode(0o640)
                .open(&path)?;
            chgrp(&path, self.opts.gid);
            Ok(file)
        };
        let seg = create(dir.join(format!("{first}.seg")))?;
        let idx = create(dir.join(format!("{first}.idx")))?;
        let data = self.kinds[kind.index()]
            .producers
            .entry(producer.clone())
            .or_default();
        data.segments.push(Segment {
            first_seq: first,
            last_seq: first,
            records: 0,
            seg_bytes: 0,
            idx_bytes: 0,
            min_ts: i64::MAX,
            max_ts: i64::MIN,
            blocks: Vec::new(),
            closed: false,
        });
        data.open = Some(OpenFiles {
            seg: BufWriter::with_capacity(256 * 1024, seg),
            idx,
            opened: now,
            block_fill: 0,
        });
        Ok(())
    }

    fn close_open(&mut self, kind: Kind, producer: &Producer) -> std::io::Result<()> {
        let Some(data) = self.kinds[kind.index()].producers.get_mut(producer) else {
            return Ok(());
        };
        let Some(mut open) = data.open.take() else {
            return Ok(());
        };
        let Some(segment) = data.segments.last_mut() else {
            return Ok(());
        };
        open.seg.flush()?;
        open.idx.write_all(&idx_entry(
            2,
            segment.records,
            segment.last_seq,
            segment.min_ts,
            segment.max_ts,
        ))?;
        segment.idx_bytes += IDX_ENTRY as u64;
        segment.closed = true;
        Ok(())
    }

    /// Flushes every open segment (at least every second, 9.1).
    pub fn flush(&mut self) {
        for kind in &mut self.kinds {
            for data in kind.producers.values_mut() {
                if let Some(open) = data.open.as_mut() {
                    if let Err(err) = open.seg.flush() {
                        warn!(error = %err, "telemetry flush failed");
                    }
                }
            }
        }
    }

    /// Closes every open segment (shutdown).
    pub fn close_all(&mut self) {
        for kind in Kind::ALL {
            let producers: Vec<Producer> =
                self.kinds[kind.index()].producers.keys().cloned().collect();
            for producer in producers {
                if let Err(err) = self.close_open(kind, &producer) {
                    warn!(error = %err, "telemetry segment close failed");
                }
            }
        }
    }

    // ---------------------------------------------------------- eviction

    fn delete_oldest(&mut self, kind: Kind, producer: &Producer) -> std::io::Result<bool> {
        let needs_close = self.kinds[kind.index()]
            .producers
            .get(producer)
            .is_some_and(|d| d.segments.first().is_some_and(|s| !s.closed));
        if needs_close {
            self.close_open(kind, producer)?;
        }
        let dir = self.producer_dir(kind, producer);
        let data = &mut self.kinds[kind.index()];
        let Some(pdata) = data.producers.get_mut(producer) else {
            return Ok(false);
        };
        if pdata.segments.is_empty() {
            return Ok(false);
        }
        let segment = pdata.segments.remove(0);
        let _ = fs::remove_file(dir.join(format!("{}.seg", segment.first_seq)));
        let _ = fs::remove_file(dir.join(format!("{}.idx", segment.first_seq)));
        data.counters.evicted_total += segment.records;
        data.counters.evicted_bytes_total += segment.bytes();
        if segment.records > 0 {
            if data.evicted.len() == EVICTED_SPANS {
                data.evicted.pop_front();
            }
            data.evicted.push_back((segment.min_ts, segment.max_ts));
        }
        if pdata.segments.is_empty() {
            data.producers.remove(producer);
            let _ = fs::remove_dir(&dir);
        }
        Ok(true)
    }

    /// Age and size eviction for every kind (9.3); run every 60 s.
    pub fn enforce(&mut self, now: SystemTime) {
        let now_nanos = nanos_of(now);
        for kind in Kind::ALL {
            // Close segments open for longer than their maximum age.
            let stale: Vec<Producer> = self.kinds[kind.index()]
                .producers
                .iter()
                .filter(|(_, d)| {
                    d.open.as_ref().is_some_and(|o| {
                        now.duration_since(o.opened)
                            .is_ok_and(|age| age >= self.opts.segment_max_age)
                    })
                })
                .map(|(p, _)| p.clone())
                .collect();
            for producer in stale {
                let _ = self.close_open(kind, &producer);
            }
            let cutoff =
                now_nanos - i64::from(self.retention(kind).max_age_days).saturating_mul(DAY_NANOS);
            let producers: Vec<Producer> =
                self.kinds[kind.index()].producers.keys().cloned().collect();
            for producer in producers {
                loop {
                    let expired = self.kinds[kind.index()]
                        .producers
                        .get(&producer)
                        .and_then(|d| d.segments.first())
                        .is_some_and(|s| s.closed && s.records > 0 && s.max_ts < cutoff);
                    if !expired || !self.delete_oldest(kind, &producer).unwrap_or(false) {
                        break;
                    }
                }
            }
            self.evict_size(kind);
        }
    }

    fn evict_size(&mut self, kind: Kind) {
        let max = self.retention(kind).max_bytes;
        let total = |s: &Self| -> u64 {
            s.kinds[kind.index()]
                .producers
                .values()
                .map(ProducerData::bytes)
                .sum()
        };
        if total(self) <= max {
            return;
        }
        let target = max / 10 * 9;
        let reserved = max / 4;
        let unreserved = max - reserved;
        while total(self) > target {
            let data = &self.kinds[kind.index()];
            let system = data
                .producers
                .get(&Producer::System)
                .map_or(0, ProducerData::bytes);
            let victim = if system > reserved {
                Some(Producer::System)
            } else {
                let others: Vec<(&Producer, u64)> = data
                    .producers
                    .iter()
                    .filter(|(p, _)| **p != Producer::System)
                    .map(|(p, d)| (p, d.bytes()))
                    .filter(|(_, b)| *b > 0)
                    .collect();
                if others.is_empty() {
                    None
                } else {
                    let share = unreserved / others.len() as u64;
                    let otlp: u64 = others
                        .iter()
                        .filter(|(p, _)| p.is_otlp())
                        .map(|(_, b)| b)
                        .sum();
                    let pool: Vec<&(&Producer, u64)> = if otlp > max / 2 {
                        others.iter().filter(|(p, _)| p.is_otlp()).collect()
                    } else {
                        others.iter().collect()
                    };
                    pool.into_iter()
                        .filter(|(_, b)| *b > share)
                        .max_by_key(|(_, b)| *b - share)
                        .map(|(p, _)| (*p).clone())
                }
            };
            let Some(victim) = victim else {
                break;
            };
            match self.delete_oldest(kind, &victim) {
                Ok(true) => {}
                _ => break,
            }
        }
    }

    // ------------------------------------------------------------- reads

    /// Usage of every kind, in `TelemetryKind` order.
    pub fn usage(&self, now: SystemTime) -> Vec<Usage> {
        let now_nanos = nanos_of(now);
        Kind::ALL
            .iter()
            .map(|&kind| {
                let data = &self.kinds[kind.index()];
                let cutoff = now_nanos
                    - i64::from(self.retention(kind).max_age_days).saturating_mul(DAY_NANOS);
                let segments = data.producers.values().flat_map(|d| d.segments.iter());
                let mut usage = Usage {
                    kind,
                    retention: self.retention(kind),
                    bytes_used: 0,
                    records: 0,
                    oldest_nanos: None,
                    newest_nanos: None,
                    counters: data.counters.clone(),
                };
                for s in segments {
                    usage.bytes_used += s.bytes();
                    usage.records += s.records;
                    if s.records > 0 {
                        let oldest = s.min_ts.max(cutoff);
                        usage.oldest_nanos =
                            Some(usage.oldest_nanos.map_or(oldest, |o| o.min(oldest)));
                        usage.newest_nanos =
                            Some(usage.newest_nanos.map_or(s.max_ts, |n| n.max(s.max_ts)));
                    }
                }
                usage
            })
            .collect()
    }

    /// Bytes of one producer of one kind.
    #[cfg(test)]
    pub fn producer_bytes(&self, kind: Kind, producer: &Producer) -> u64 {
        self.kinds[kind.index()]
            .producers
            .get(producer)
            .map_or(0, ProducerData::bytes)
    }

    pub fn last_seq(&self, kind: Kind) -> u64 {
        self.kinds[kind.index()].next_seq - 1
    }

    /// Whether a cursor's segment is still stored (else `CURSOR_EXPIRED`).
    pub fn cursor_live(&self, cursor: &Cursor) -> bool {
        self.kinds[cursor.kind.index()]
            .producers
            .get(&cursor.producer)
            .is_some_and(|d| {
                d.segments
                    .iter()
                    .any(|s| s.first_seq == cursor.segment && cursor.seq <= s.last_seq)
            })
    }

    /// Whether `ts` falls inside an evicted segment (`range.start` check).
    pub fn evicted_at(&self, kind: Kind, ts: i64) -> bool {
        self.kinds[kind.index()]
            .evicted
            .iter()
            .any(|(min, max)| (*min..=*max).contains(&ts))
    }

    /// Flushes and takes a read view of `kind` (the caller then scans
    /// without holding the store).
    pub fn snapshot(&mut self, kind: Kind, now: SystemTime) -> Snapshot {
        self.flush();
        let cutoff =
            nanos_of(now) - i64::from(self.retention(kind).max_age_days).saturating_mul(DAY_NANOS);
        let producers = self.kinds[kind.index()]
            .producers
            .iter()
            .map(|(producer, data)| {
                let dir = self.producer_dir(kind, producer);
                let views = data
                    .segments
                    .iter()
                    .filter(|s| s.records > 0)
                    .map(|s| SegmentView {
                        path: dir.join(format!("{}.seg", s.first_seq)),
                        first_seq: s.first_seq,
                        last_seq: s.last_seq,
                        min_ts: s.min_ts,
                        max_ts: s.max_ts,
                        blocks: s.blocks.clone(),
                        readable: s.seg_bytes,
                    })
                    .collect();
                (producer.clone(), views)
            })
            .collect();
        Snapshot {
            kind,
            producers,
            min_ts: cutoff,
        }
    }
}

// ------------------------------------------------------------------ scans

/// The segment a reader is in: first seq, blocks, file, readable bytes.
type OpenView = (u64, Vec<(u64, u64)>, File, u64);

struct ProducerReader {
    producer: Producer,
    segments: Vec<SegmentView>,
    direction: Direction,
    /// Next segment index to load (forward: ascending; backward: descending).
    next_segment: usize,
    current: Option<OpenView>,
    next_block: usize,
    buffer: VecDeque<RawRecord>,
    spec: ScanSpec,
    min_ts: i64,
}

impl ProducerReader {
    fn wanted_segment(&self, s: &SegmentView) -> bool {
        s.max_ts >= self.spec.from_ts.max(self.min_ts)
            && s.min_ts <= self.spec.to_ts
            && self.spec.after_seq.is_none_or(|a| s.last_seq > a)
            && self.spec.before_seq.is_none_or(|b| s.first_seq < b)
    }

    fn fill(&mut self) -> std::io::Result<()> {
        while self.buffer.is_empty() {
            if self.current.is_none() {
                let n = self.segments.len();
                let view = loop {
                    if self.next_segment >= n {
                        return Ok(());
                    }
                    let i = match self.direction {
                        Direction::Forward => self.next_segment,
                        Direction::Backward => n - 1 - self.next_segment,
                    };
                    self.next_segment += 1;
                    if self.wanted_segment(&self.segments[i]) {
                        break self.segments[i].clone();
                    }
                };
                let file = match File::open(&view.path) {
                    Ok(f) => f,
                    // Evicted since the snapshot.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                let mut blocks = view.blocks.clone();
                if blocks.is_empty() {
                    blocks.push((0, view.first_seq));
                }
                // Skip blocks wholly before the cursor (forward).
                self.next_block = 0;
                if let (Direction::Forward, Some(after)) = (self.direction, self.spec.after_seq) {
                    let skip = blocks.iter().rposition(|(_, first)| *first <= after + 1);
                    self.next_block = skip.unwrap_or(0);
                }
                self.current = Some((view.first_seq, blocks, file, view.readable));
            }
            let Some((segment, blocks, file, readable)) = self.current.as_mut() else {
                continue;
            };
            let nblocks = blocks.len();
            if self.next_block >= nblocks {
                self.current = None;
                continue;
            }
            let b = match self.direction {
                Direction::Forward => self.next_block,
                Direction::Backward => nblocks - 1 - self.next_block,
            };
            self.next_block += 1;
            let start = blocks[b].0;
            let end = blocks
                .get(b + 1)
                .map_or(*readable, |(o, _)| *o)
                .min(*readable);
            if end <= start {
                continue;
            }
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = vec![0u8; (end - start) as usize];
            file.read_exact(&mut bytes)?;
            let seg_first = *segment;
            let spec = &self.spec;
            let min_ts = self.min_ts;
            let producer = &self.producer;
            let mut out = Vec::new();
            parse_frames(&bytes, |seq, ts, tag, payload| {
                let in_seq = spec.after_seq.is_none_or(|a| seq > a)
                    && spec.before_seq.is_none_or(|b| seq < b);
                if in_seq && ts >= spec.from_ts && ts >= min_ts && ts <= spec.to_ts {
                    out.push(RawRecord {
                        seq,
                        ts_nanos: ts,
                        tag,
                        payload: payload.to_vec(),
                        producer: producer.clone(),
                        segment: seg_first,
                    });
                }
            });
            if self.direction == Direction::Backward {
                out.reverse();
            }
            self.buffer.extend(out);
        }
        Ok(())
    }
}

/// Records of a snapshot in ingest order (or reverse), merged across
/// producers by `ingest_seq`.
pub struct Scan {
    readers: Vec<ProducerReader>,
    heap: BinaryHeap<(i128, usize)>,
    started: bool,
    direction: Direction,
}

impl Snapshot {
    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn scan(&self, spec: ScanSpec) -> Scan {
        let readers = self
            .producers
            .iter()
            .filter(|(p, _)| spec.producers.as_ref().is_none_or(|ps| ps.contains(p)))
            .map(|(producer, segments)| ProducerReader {
                producer: producer.clone(),
                segments: segments.clone(),
                direction: spec.direction,
                next_segment: 0,
                current: None,
                next_block: 0,
                buffer: VecDeque::new(),
                spec: spec.clone(),
                min_ts: self.min_ts,
            })
            .collect();
        Scan {
            readers,
            heap: BinaryHeap::new(),
            started: false,
            direction: spec.direction,
        }
    }
}

impl Scan {
    fn key(&self, seq: u64) -> i128 {
        match self.direction {
            Direction::Forward => -(seq as i128),
            Direction::Backward => seq as i128,
        }
    }

    fn push(&mut self, i: usize) -> std::io::Result<()> {
        self.readers[i].fill()?;
        if let Some(front) = self.readers[i].buffer.front() {
            let key = self.key(front.seq);
            self.heap.push((key, i));
        }
        Ok(())
    }
}

impl Iterator for Scan {
    type Item = std::io::Result<RawRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.started {
            self.started = true;
            for i in 0..self.readers.len() {
                if let Err(e) = self.push(i) {
                    return Some(Err(e));
                }
            }
        }
        let (_, i) = self.heap.pop()?;
        let record = self.readers[i].buffer.pop_front()?;
        if let Err(e) = self.push(i) {
            return Some(Err(e));
        }
        Some(Ok(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_plan::test_support::temp_dir;
    use std::sync::Mutex;

    const T0: i64 = 1_790_000_000 * 1_000_000_000;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_790_000_000 + secs)
    }

    fn store(name: &str, tweak: impl FnOnce(&mut StoreOptions)) -> (Store, PathBuf) {
        let dir = temp_dir(name);
        let mut opts = StoreOptions::new(dir.join("telemetry"));
        tweak(&mut opts);
        (Store::open(opts, at(0)).unwrap(), dir)
    }

    fn all(store: &mut Store, kind: Kind, spec: ScanSpec) -> Vec<(u64, Vec<u8>)> {
        store
            .snapshot(kind, at(0))
            .scan(spec)
            .map(|r| r.unwrap())
            .map(|r| (r.seq, r.payload))
            .collect()
    }

    #[test]
    fn layout_is_the_contract_layout() {
        let (mut s, dir) = store("tel-layout", |_| {});
        let p = Producer::Project("p1".into());
        assert_eq!(
            s.append(Kind::Logs, &p, T0, 1, b"a", at(0)),
            Appended::Stored(1)
        );
        s.flush();
        let root = dir.join("telemetry");
        let meta: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("store.json")).unwrap()).unwrap();
        assert_eq!(meta["version"], 1);
        assert_eq!(meta["redaction_rules_version"], "redaction-v1");
        assert!(meta["created_at"].is_string());
        for kind in ["logs", "http", "traces", "metrics", "analytics"] {
            assert!(root.join(kind).is_dir(), "{kind}");
        }
        let seg = root.join("logs/project:p1/1.seg");
        assert!(seg.exists());
        assert!(root.join("logs/project:p1/1.idx").exists());
        assert_eq!(
            fs::metadata(&seg).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o750
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scans_merge_producers_in_ingest_order_both_ways() {
        let (mut s, dir) = store("tel-merge", |o| o.segment_max_bytes = 200);
        let a = Producer::Project("a".into());
        let b = Producer::System;
        for i in 0..40u8 {
            let p = if i % 3 == 0 { &a } else { &b };
            s.append(Kind::Logs, p, T0 + i64::from(i), 1, &[i; 20], at(0));
        }
        let fwd = all(&mut s, Kind::Logs, ScanSpec::default());
        assert_eq!(
            fwd.iter().map(|r| r.0).collect::<Vec<_>>(),
            (1..=40).collect::<Vec<_>>()
        );
        assert_eq!(fwd[5].1, vec![5; 20]);
        let back = all(
            &mut s,
            Kind::Logs,
            ScanSpec {
                direction: Direction::Backward,
                before_seq: Some(31),
                ..Default::default()
            },
        );
        assert_eq!(
            back.iter().map(|r| r.0).collect::<Vec<_>>(),
            (1..=30).rev().collect::<Vec<_>>()
        );
        let after = all(
            &mut s,
            Kind::Logs,
            ScanSpec {
                after_seq: Some(35),
                ..Default::default()
            },
        );
        assert_eq!(
            after.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![36, 37, 38, 39, 40]
        );
        let ranged = all(
            &mut s,
            Kind::Logs,
            ScanSpec {
                from_ts: T0 + 10,
                to_ts: T0 + 12,
                ..Default::default()
            },
        );
        assert_eq!(
            ranged.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![11, 12, 13]
        );
        let only_a = all(
            &mut s,
            Kind::Logs,
            ScanSpec {
                producers: Some(vec![a.clone()]),
                ..Default::default()
            },
        );
        assert_eq!(only_a.len(), 14);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reopen_keeps_data_and_recovers_a_torn_open_segment() {
        let dir = temp_dir("tel-reopen");
        let opts = StoreOptions::new(dir.join("telemetry"));
        {
            let mut s = Store::open(opts.clone(), at(0)).unwrap();
            for i in 0..5 {
                s.append(Kind::Logs, &Producer::System, T0 + i, 1, b"hello", at(0));
            }
            s.flush();
            // Crash: no close. Tear the last frame.
        }
        let seg = dir.join("telemetry/logs/system/1.seg");
        let len = fs::metadata(&seg).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&seg)
            .unwrap()
            .set_len(len - 3)
            .unwrap();
        let mut s = Store::open(opts.clone(), at(0)).unwrap();
        let records = all(&mut s, Kind::Logs, ScanSpec::default());
        assert_eq!(records.len(), 4);
        // Sequence numbers continue after the recovered segment.
        assert_eq!(
            s.append(Kind::Logs, &Producer::System, T0, 1, b"x", at(0)),
            Appended::Stored(5)
        );
        s.close_all();
        drop(s);
        let mut s = Store::open(opts, at(0)).unwrap();
        assert_eq!(all(&mut s, Kind::Logs, ScanSpec::default()).len(), 5);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_version_moves_the_store_aside() {
        let dir = temp_dir("tel-version");
        let root = dir.join("telemetry");
        fs::create_dir_all(root.join("logs")).unwrap();
        fs::write(root.join("store.json"), r#"{"version": 9}"#).unwrap();
        let s = Store::open(StoreOptions::new(root.clone()), at(0)).unwrap();
        assert_eq!(s.reset_at, Some(at(0)));
        assert!(dir.join("telemetry.1790000000.old/store.json").exists());
        let meta: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("store.json")).unwrap()).unwrap();
        assert_eq!(meta["version"], 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn segments_rotate_by_size_and_age_and_age_eviction_deletes_closed_ones() {
        let (mut s, dir) = store("tel-age", |o| {
            o.segment_max_bytes = 100;
            o.retention[Kind::Traces.index()].max_age_days = 3;
        });
        let p = Producer::Otlp("p1".into());
        let old = T0 - 4 * DAY_NANOS;
        for i in 0..3 {
            s.append(Kind::Traces, &p, old + i, 1, &[0; 40], at(0));
        }
        // Rotated by size: one 61-byte frame per 100-byte segment (.seg + .idx).
        let segs = fs::read_dir(dir.join("telemetry/traces/otlp:p1"))
            .unwrap()
            .count();
        assert_eq!(segs, 6);
        // Age rotation: a segment open for an hour is closed.
        s.append(Kind::Traces, &p, T0, 1, b"new", at(3600 * 2));
        s.enforce(at(3600 * 2));
        let usage = &s.usage(at(3600 * 2))[Kind::Traces.index()];
        assert_eq!(usage.records, 1);
        assert_eq!(usage.counters.evicted_total, 3);
        assert!(usage.counters.evicted_bytes_total > 0);
        assert!(s.evicted_at(Kind::Traces, old + 1));
        assert!(!s.evicted_at(Kind::Traces, T0));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cursors_round_trip_and_expire_with_their_segment() {
        let (mut s, dir) = store("tel-cursor", |o| o.segment_max_bytes = 60);
        let p = Producer::Project("p1".into());
        for i in 0..3 {
            s.append(Kind::Logs, &p, T0 + i, 1, &[1; 30], at(0));
        }
        let first = s
            .snapshot(Kind::Logs, at(0))
            .scan(ScanSpec::default())
            .next()
            .unwrap()
            .unwrap();
        let cursor = Cursor::decode(&first.cursor(Kind::Logs)).unwrap();
        assert_eq!(cursor.seq, 1);
        assert_eq!(cursor.producer, p);
        assert!(s.cursor_live(&cursor));
        assert!(Cursor::decode("garbage").is_none());
        assert!(s.delete_oldest(Kind::Logs, &p).unwrap());
        assert!(!s.cursor_live(&cursor));
        fs::remove_dir_all(dir).unwrap();
    }

    fn fill(s: &mut Store, p: &Producer, n: usize, ts: i64) {
        for _ in 0..n {
            s.append(Kind::Logs, p, ts, 1, &[7; 979], at(0));
        }
    }

    #[test]
    fn size_eviction_takes_the_heaviest_producer_and_spares_fair_shares() {
        // 1,000-byte frames, 2 per segment; logs capped at 40,000 bytes.
        let (mut s, dir) = store("tel-fair", |o| {
            o.segment_max_bytes = 2_000;
            o.retention[Kind::Logs.index()].max_bytes = 40_000;
        });
        let noisy = Producer::Project("noisy".into());
        let quiet = Producer::Project("quiet".into());
        fill(&mut s, &Producer::System, 6, T0);
        fill(&mut s, &quiet, 6, T0);
        fill(&mut s, &noisy, 40, T0);
        s.enforce(at(0));
        let total: u64 = s.usage(at(0))[0].bytes_used;
        assert!(total <= 36_000, "{total}");
        // The quiet project and system are at or below their shares.
        assert_eq!(
            s.producer_bytes(Kind::Logs, &quiet),
            6 * 1000 + 5 * IDX_ENTRY as u64
        );
        assert!(s.producer_bytes(Kind::Logs, &Producer::System) >= 6_000);
        // The noisy one lost its oldest data only.
        let noisy_left = s.producer_bytes(Kind::Logs, &noisy);
        assert!(noisy_left < 40_000 && noisy_left > 10_000);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn otlp_is_evicted_first_above_half_and_system_keeps_its_quarter() {
        let (mut s, dir) = store("tel-otlp", |o| {
            o.segment_max_bytes = 2_000;
            o.retention[Kind::Logs.index()].max_bytes = 40_000;
        });
        let app = Producer::Project("a".into());
        let otlp = Producer::Otlp("a".into());
        fill(&mut s, &app, 14, T0);
        fill(&mut s, &otlp, 30, T0);
        s.enforce(at(0));
        assert!(s.producer_bytes(Kind::Logs, &otlp) <= 21_000);
        assert!(s.producer_bytes(Kind::Logs, &app) >= 14_000);

        // A system producer beyond its quarter loses its oldest data only.
        let (mut s2, dir2) = store("tel-system", |o| {
            o.segment_max_bytes = 2_000;
            o.retention[Kind::Logs.index()].max_bytes = 20_000;
        });
        let project = Producer::Project("b".into());
        fill(&mut s2, &Producer::System, 16, T0);
        fill(&mut s2, &project, 10, T0);
        let before = s2.producer_bytes(Kind::Logs, &project);
        s2.enforce(at(0));
        assert_eq!(s2.producer_bytes(Kind::Logs, &project), before);
        assert!(s2.producer_bytes(Kind::Logs, &Producer::System) < 9_000);
        assert!(s2.usage(at(0))[0].bytes_used <= 18_000);
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(dir2).unwrap();
    }

    struct FakeDisk(Mutex<(u64, u64)>);

    impl DiskProbe for FakeDisk {
        fn free(&self, _: &Path) -> Option<(u64, u64)> {
            Some(*self.0.lock().unwrap())
        }
    }

    #[test]
    fn disk_guard_pauses_everything_but_system_with_hysteresis() {
        let (mut s, dir) = store("tel-guard", |_| {});
        let disk = FakeDisk(Mutex::new((500 * MIB, 100 * GIB)));
        let p = Producer::Project("p".into());
        assert!(s.check_disk(&disk).paused);
        assert_eq!(
            s.append(Kind::Logs, &p, T0, 1, b"x", at(0)),
            Appended::Paused
        );
        assert!(matches!(
            s.append(Kind::Logs, &Producer::System, T0, 1, b"x", at(0)),
            Appended::Stored(_)
        ));
        *disk.0.lock().unwrap() = (100 * MIB, 100 * GIB);
        assert!(s.check_disk(&disk).system_paused);
        assert_eq!(
            s.append(Kind::Logs, &Producer::System, T0, 1, b"x", at(0)),
            Appended::Paused
        );
        // 6% free: still paused (resume needs 8% and 1.5 GiB).
        *disk.0.lock().unwrap() = (6 * GIB, 100 * GIB);
        assert!(s.check_disk(&disk).paused);
        *disk.0.lock().unwrap() = (9 * GIB, 100 * GIB);
        assert!(!s.check_disk(&disk).paused);
        assert!(matches!(
            s.append(Kind::Logs, &p, T0, 1, b"x", at(0)),
            Appended::Stored(_)
        ));
        assert_eq!(s.usage(at(0))[0].counters.dropped_total, 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn producers_parse_only_plain_ids() {
        assert_eq!(
            Producer::parse("project:p-1"),
            Some(Producer::Project("p-1".into()))
        );
        assert_eq!(
            Producer::parse("otlp:unattributed"),
            Some(Producer::OtlpUnattributed)
        );
        assert_eq!(Producer::parse("project:../x"), None);
        assert_eq!(Producer::parse("project:"), None);
        assert!(!valid_id("a/b"));
    }
}
