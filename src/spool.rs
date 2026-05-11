use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const RECORD_HEADER_BYTES: u64 = 8;
const SEGMENT_PREFIX: &str = "segment-";
const SEGMENT_SUFFIX: &str = ".spool";

#[derive(Clone, Debug)]
pub struct SpoolConfig {
    pub dir: PathBuf,
    pub max_bytes: u64,
    pub max_segment_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolRecord {
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpoolAck {
    records: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpoolBatch {
    pub records: Vec<SpoolRecord>,
    pub ack: SpoolAck,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpoolCounters {
    pub bytes: u64,
    pub records: u64,
    pub segments: u64,
    pub dropped_records: u64,
    pub dropped_bytes: u64,
}

#[derive(Debug)]
pub struct DiskSpool {
    config: SpoolConfig,
    state: Mutex<SpoolState>,
}

#[derive(Clone, Debug, Default)]
struct SpoolState {
    segments: Vec<Segment>,
    bytes: u64,
    records: u64,
    next_sequence: u64,
    dropped_records: u64,
    dropped_bytes: u64,
}

#[derive(Clone, Debug)]
struct Segment {
    sequence: u64,
    path: PathBuf,
    bytes: u64,
    records: u64,
}

impl DiskSpool {
    pub fn open(config: SpoolConfig) -> io::Result<Self> {
        if config.max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spool max_bytes must be greater than zero",
            ));
        }

        fs::create_dir_all(&config.dir)?;
        let mut state = load_state(&config.dir)?;
        enforce_budget(&config, &mut state)?;

        Ok(Self {
            config,
            state: Mutex::new(state),
        })
    }

    pub fn append_bytes(&self, payload: &[u8]) -> io::Result<()> {
        let record_bytes = record_disk_bytes(payload)?;
        if record_bytes > self.config.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spool record exceeds max_bytes",
            ));
        }

        let mut state = self.lock_state()?;
        let segment_index = writable_segment_index(&self.config, &mut state, record_bytes)?;
        append_record(&state.segments[segment_index].path, payload)?;

        state.segments[segment_index].bytes += record_bytes;
        state.segments[segment_index].records += 1;
        state.bytes += record_bytes;
        state.records += 1;
        enforce_budget(&self.config, &mut state)
    }

    pub fn read_batch(&self, max_records: usize, max_payload_bytes: u64) -> io::Result<SpoolBatch> {
        if max_records == 0 {
            return Ok(SpoolBatch::default());
        }

        let state = self.lock_state()?;
        let mut records = Vec::new();
        let mut payload_bytes = 0_u64;

        for segment in &state.segments {
            for payload in read_segment_payloads(&segment.path)? {
                let next_bytes = checked_len_u64(payload.len())?;
                if !records.is_empty()
                    && (records.len() >= max_records
                        || payload_bytes + next_bytes > max_payload_bytes)
                {
                    return Ok(SpoolBatch {
                        ack: SpoolAck {
                            records: records.len(),
                        },
                        records,
                    });
                }

                payload_bytes += next_bytes;
                records.push(SpoolRecord { payload });

                if records.len() >= max_records {
                    return Ok(SpoolBatch {
                        ack: SpoolAck {
                            records: records.len(),
                        },
                        records,
                    });
                }
            }
        }

        Ok(SpoolBatch {
            ack: SpoolAck {
                records: records.len(),
            },
            records,
        })
    }

    pub fn ack(&self, ack: SpoolAck) -> io::Result<()> {
        if ack.records == 0 {
            return Ok(());
        }

        let mut state = self.lock_state()?;
        if ack.records as u64 > state.records {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ack exceeds queued record count",
            ));
        }

        let mut remaining = Vec::new();
        let mut skip = ack.records;
        for segment in &state.segments {
            for payload in read_segment_payloads(&segment.path)? {
                if skip > 0 {
                    skip -= 1;
                } else {
                    remaining.push(payload);
                }
            }
        }

        let dropped_records = state.dropped_records;
        let dropped_bytes = state.dropped_bytes;
        clear_segments(&state.segments)?;
        *state = SpoolState {
            dropped_records,
            dropped_bytes,
            ..SpoolState::default()
        };
        rewrite_records(&self.config, &mut state, remaining)
    }

    pub fn counters(&self) -> SpoolCounters {
        match self.state.lock() {
            Ok(state) => SpoolCounters {
                bytes: state.bytes,
                records: state.records,
                segments: state.segments.len() as u64,
                dropped_records: state.dropped_records,
                dropped_bytes: state.dropped_bytes,
            },
            Err(poisoned) => {
                let state = poisoned.into_inner();
                SpoolCounters {
                    bytes: state.bytes,
                    records: state.records,
                    segments: state.segments.len() as u64,
                    dropped_records: state.dropped_records,
                    dropped_bytes: state.dropped_bytes,
                }
            }
        }
    }

    fn lock_state(&self) -> io::Result<std::sync::MutexGuard<'_, SpoolState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("spool state lock poisoned"))
    }
}

fn load_state(dir: &Path) -> io::Result<SpoolState> {
    let mut segments = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(sequence) = parse_segment_sequence(&entry.file_name()) else {
            continue;
        };
        let path = entry.path();
        let (bytes, records) = scan_segment(&path)?;
        segments.push(Segment {
            sequence,
            path,
            bytes,
            records,
        });
    }

    segments.sort_by_key(|segment| segment.sequence);
    let bytes = segments.iter().map(|segment| segment.bytes).sum();
    let records = segments.iter().map(|segment| segment.records).sum();
    let next_sequence = segments
        .last()
        .map(|segment| segment.sequence.saturating_add(1))
        .unwrap_or(0);

    Ok(SpoolState {
        segments,
        bytes,
        records,
        next_sequence,
        dropped_records: 0,
        dropped_bytes: 0,
    })
}

fn parse_segment_sequence(name: &OsStr) -> Option<u64> {
    let name = name.to_str()?;
    let sequence = name
        .strip_prefix(SEGMENT_PREFIX)?
        .strip_suffix(SEGMENT_SUFFIX)?;
    sequence.parse().ok()
}

fn segment_path(dir: &Path, sequence: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{sequence:020}{SEGMENT_SUFFIX}"))
}

fn writable_segment_index(
    config: &SpoolConfig,
    state: &mut SpoolState,
    record_bytes: u64,
) -> io::Result<usize> {
    let segment_limit = config.max_segment_bytes.max(record_bytes);
    if let Some(last) = state.segments.last() {
        if last.bytes + record_bytes <= segment_limit {
            return Ok(state.segments.len() - 1);
        }
    }

    let sequence = state.next_sequence;
    state.next_sequence = state.next_sequence.saturating_add(1);
    let path = segment_path(&config.dir, sequence);
    File::create(&path)?;
    state.segments.push(Segment {
        sequence,
        path,
        bytes: 0,
        records: 0,
    });
    Ok(state.segments.len() - 1)
}

fn append_record(path: &Path, payload: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().append(true).create(true).open(path)?;
    let len = checked_len_u64(payload.len())?;
    file.write_all(&len.to_be_bytes())?;
    file.write_all(payload)?;
    file.sync_data()
}

fn scan_segment(path: &Path) -> io::Result<(u64, u64)> {
    let mut bytes = 0_u64;
    let mut records = 0_u64;
    let mut reader = BufReader::new(File::open(path)?);

    loop {
        let mut header = [0_u8; 8];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
        let len = u64::from_be_bytes(header);
        io::copy(&mut reader.by_ref().take(len), &mut io::sink())?;
        bytes = bytes
            .checked_add(RECORD_HEADER_BYTES + len)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "spool segment size overflow")
            })?;
        records = records.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "spool record count overflow")
        })?;
    }

    Ok((bytes, records))
}

fn read_segment_payloads(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut payloads = Vec::new();
    let mut reader = BufReader::new(File::open(path)?);

    loop {
        let mut header = [0_u8; 8];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
        let len = u64::from_be_bytes(header);
        let payload_len = usize::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "spool record too large for platform",
            )
        })?;
        let mut payload = vec![0_u8; payload_len];
        reader.read_exact(&mut payload)?;
        payloads.push(payload);
    }

    Ok(payloads)
}

fn enforce_budget(config: &SpoolConfig, state: &mut SpoolState) -> io::Result<()> {
    while state.bytes > config.max_bytes {
        let Some(segment) = state.segments.first().cloned() else {
            break;
        };
        fs::remove_file(&segment.path)?;
        state.bytes -= segment.bytes;
        state.records -= segment.records;
        state.dropped_bytes += segment.bytes;
        state.dropped_records += segment.records;
        state.segments.remove(0);
    }
    Ok(())
}

fn clear_segments(segments: &[Segment]) -> io::Result<()> {
    for segment in segments {
        match fs::remove_file(&segment.path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn rewrite_records(
    config: &SpoolConfig,
    state: &mut SpoolState,
    records: Vec<Vec<u8>>,
) -> io::Result<()> {
    for payload in records {
        let record_bytes = record_disk_bytes(&payload)?;
        let index = writable_segment_index(config, state, record_bytes)?;
        write_record_without_sync(&state.segments[index].path, &payload)?;
        state.segments[index].bytes += record_bytes;
        state.segments[index].records += 1;
        state.bytes += record_bytes;
        state.records += 1;
    }

    for segment in &state.segments {
        OpenOptions::new()
            .read(true)
            .open(&segment.path)?
            .sync_data()?;
    }

    Ok(())
}

fn write_record_without_sync(path: &Path, payload: &[u8]) -> io::Result<()> {
    let mut writer = BufWriter::new(OpenOptions::new().append(true).create(true).open(path)?);
    let len = checked_len_u64(payload.len())?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn record_disk_bytes(payload: &[u8]) -> io::Result<u64> {
    let len = checked_len_u64(payload.len())?;
    len.checked_add(RECORD_HEADER_BYTES)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "spool record size overflow"))
}

fn checked_len_u64(len: usize) -> io::Result<u64> {
    u64::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "spool record length overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock moved backwards")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("permanu-spool-{name}-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn appends_bytes_and_reads_fifo_batches() {
        let dir = temp_dir("fifo");
        let spool = DiskSpool::open(SpoolConfig {
            dir: dir.clone(),
            max_bytes: 16 * 1024,
            max_segment_bytes: 64,
        })
        .expect("open spool");

        spool.append_bytes(b"one").expect("append one");
        spool.append_bytes(br#"{"n":2}"#).expect("append json");
        spool.append_bytes(b"three").expect("append three");

        let batch = spool.read_batch(10, 1024).expect("read batch");
        let payloads: Vec<Vec<u8>> = batch.records.iter().map(|r| r.payload.clone()).collect();
        assert_eq!(
            payloads,
            vec![b"one".to_vec(), br#"{"n":2}"#.to_vec(), b"three".to_vec()]
        );
        assert_eq!(spool.counters().records, 3);

        spool.ack(batch.ack).expect("ack batch");
        assert_eq!(spool.read_batch(10, 1024).expect("empty").records.len(), 0);
        assert_eq!(spool.counters().records, 0);

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn drops_oldest_segments_when_over_budget() {
        let dir = temp_dir("budget");
        let spool = DiskSpool::open(SpoolConfig {
            dir: dir.clone(),
            max_bytes: 82,
            max_segment_bytes: 41,
        })
        .expect("open spool");

        for n in 0..6 {
            spool
                .append_bytes(format!("record-{n:02}").as_bytes())
                .expect("append");
        }

        let batch = spool.read_batch(10, 1024).expect("read batch");
        let payloads: Vec<String> = batch
            .records
            .iter()
            .map(|r| String::from_utf8(r.payload.clone()).expect("utf8"))
            .collect();

        assert_eq!(
            payloads,
            vec!["record-02", "record-03", "record-04", "record-05"]
        );
        let counters = spool.counters();
        assert_eq!(counters.records, 4);
        assert_eq!(counters.dropped_records, 2);
        assert!(counters.bytes <= 82);

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn persists_unacked_records_across_reopen() {
        let dir = temp_dir("persist");
        {
            let spool = DiskSpool::open(SpoolConfig {
                dir: dir.clone(),
                max_bytes: 16 * 1024,
                max_segment_bytes: 128,
            })
            .expect("open spool");
            spool.append_bytes(b"kept").expect("append kept");
            let batch = spool.read_batch(1, 1024).expect("read batch");
            assert_eq!(batch.records[0].payload, b"kept");
        }

        let reopened = DiskSpool::open(SpoolConfig {
            dir: dir.clone(),
            max_bytes: 16 * 1024,
            max_segment_bytes: 128,
        })
        .expect("reopen spool");
        let batch = reopened.read_batch(1, 1024).expect("read after reopen");
        assert_eq!(batch.records[0].payload, b"kept");

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn ack_removes_only_consumed_prefix() {
        let dir = temp_dir("partial-ack");
        let spool = DiskSpool::open(SpoolConfig {
            dir: dir.clone(),
            max_bytes: 16 * 1024,
            max_segment_bytes: 128,
        })
        .expect("open spool");

        spool.append_bytes(b"a").expect("append a");
        spool.append_bytes(b"b").expect("append b");
        spool.append_bytes(b"c").expect("append c");

        let first = spool.read_batch(2, 1024).expect("read first");
        spool.ack(first.ack).expect("ack first two");

        let second = spool.read_batch(10, 1024).expect("read remaining");
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].payload, b"c");

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn appends_are_safe_from_multiple_threads() {
        let dir = temp_dir("threads");
        let spool = Arc::new(
            DiskSpool::open(SpoolConfig {
                dir: dir.clone(),
                max_bytes: 64 * 1024,
                max_segment_bytes: 256,
            })
            .expect("open spool"),
        );

        let mut handles = Vec::new();
        for worker in 0..4 {
            let spool = Arc::clone(&spool);
            handles.push(thread::spawn(move || {
                for item in 0..25 {
                    spool
                        .append_bytes(format!("{worker}:{item}").as_bytes())
                        .expect("append");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("join worker");
        }

        assert_eq!(spool.counters().records, 100);

        fs::remove_dir_all(dir).expect("cleanup");
    }
}
