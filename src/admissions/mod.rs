//! `/var/lib/permanu/agent/admissions.db`: the agent's admission store
//! (signed-plan.md sections 6.3, 6.4, 8; D-022). The agent is its only
//! writer; the runner opens it read-only through group `permanu-runner`.
//!
//! - Schema: `schema_v1.sql` is the normative DDL of section 6.4 (v1.0.1),
//!   verbatim; `schema_v1_agent.sql` adds agent-only tables and one trailing
//!   nullable column, as section 6.4 allows; `schema_v2.sql` adds the v1.0.2
//!   columns with `ADD COLUMN` (user_version 2); `schema_v3.sql` adds
//!   `rejected_deliveries` and rebuilds `deliveries` (v1.0.8, user_version 3,
//!   D-060). `PRAGMA user_version` is the migration
//!   cursor; a newer store than this binary knows is refused (fail closed).
//! - Files: database, `-wal` and `-shm` are `0640` with the configured owner
//!   and group (`permanu-agent:permanu-runner`), the directory `2750`
//!   (setgid, so new files inherit the group; v1.0.3, QA_M1 F-16), repaired
//!   at every open; WAL files persist across restarts
//!   (`SQLITE_FCNTL_PERSIST_WAL`) so the runner can always read. Without a
//!   configured owner (development, tests) the directory is `0750`.
//! - Store loss: a missing or corrupt store while trusted-keys.json exists
//!   is moved aside (`admissions.db.corrupt-<ts>`) and recreated with a
//!   1200 s quarantine (section 6.3).

mod admit;
pub mod definitions;
mod query;
mod reconcile;
pub mod webhooks;

#[cfg(test)]
mod tests;

pub use admit::{Admission, AdmitInput, INPUT_KINDS};
pub use query::{execution_deadline, ActionRecord, AdmissionRecord};
pub use reconcile::{event_lines, read_consumed_log, run_results, ReconcileEffect};

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension};

use crate::signed_plan::text::{format_timestamp, timestamp};
use crate::signed_plan::PlanCode;

pub const DEFAULT_ADMISSIONS_DB: &str = "/var/lib/permanu/agent/admissions.db";
/// Section 6.3: max plan lifetime 900 s + 2 × skew 120 s + 60 s margin.
pub const QUARANTINE_SECONDS: i64 = 1_200;
/// Section 6.2: an admitted plan executes within `admitted_at + 60 min`.
pub const EXECUTION_WINDOW_SECONDS: i64 = 3_600;
/// Operation events are kept for 7 days (agent-protocol.md 6).
pub const OPERATION_EVENT_RETENTION_SECONDS: i64 = 7 * 86_400;

const SCHEMA_V1: &str = include_str!("schema_v1.sql");
const SCHEMA_V1_AGENT: &str = include_str!("schema_v1_agent.sql");
const SCHEMA_V2: &str = include_str!("schema_v2.sql");
const SCHEMA_V3: &str = include_str!("schema_v3.sql");

/// One migration step: its SQL, and whether it rebuilds a table (section
/// 6.4 v1.0.8: `foreign_keys` OFF for its duration, then
/// `foreign_key_check`).
struct Migration {
    sql: &'static [&'static str],
    rebuilds: bool,
}

/// Index i migrates user_version i → i + 1.
const MIGRATIONS: &[Migration] = &[
    Migration {
        sql: &[SCHEMA_V1, SCHEMA_V1_AGENT],
        rebuilds: false,
    },
    Migration {
        sql: &[SCHEMA_V2],
        rebuilds: false,
    },
    Migration {
        sql: &[SCHEMA_V3],
        rebuilds: true,
    },
];
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

const FILE_MODE: u32 = 0o640;
const DIR_MODE: u32 = 0o750;
/// Section 6.3 (v1.0.3): `0750` plus setgid for the store group.
const OWNED_DIR_MODE: u32 = 0o2750;

/// Owner and group of the store files (`permanu-agent:permanu-runner`).
/// `None` leaves the creating process's ids (tests, non-root runs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOwner {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub path: PathBuf,
    pub owner: Option<StoreOwner>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("admissions store: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("admissions store: {0}")]
    Io(#[from] std::io::Error),
    #[error("admissions store: {0}")]
    Unsafe(String),
    #[error("admissions store has schema version {0}, newer than this agent ({SCHEMA_VERSION})")]
    TooNew(i64),
}

impl From<StoreError> for PlanCode {
    fn from(_: StoreError) -> Self {
        PlanCode::Internal
    }
}

/// What happened when the store was opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenReport {
    pub created: bool,
    /// Store loss: a store was created while trusted-keys.json existed.
    pub recreated: bool,
    /// Where a corrupt store was moved.
    pub moved_aside: Option<PathBuf>,
    pub quarantine_ends_at: Option<i64>,
}

pub struct AdmissionStore {
    conn: Mutex<Connection>,
    path: PathBuf,
    owner: Option<StoreOwner>,
    /// v1.0.11 (D-061): `build_id` → the `at` of the runner's
    /// `build_started` line (Unix seconds), which anchors the rule-plan
    /// evidence window (section 6.1 step 12). Not in the normative DDL, so
    /// kept in memory; unknown after a restart, which only narrows the
    /// window to the delivery's own 900 s (fail closed).
    build_starts: Mutex<std::collections::BTreeMap<String, i64>>,
}

impl std::fmt::Debug for AdmissionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionStore")
            .field("path", &self.path)
            .finish()
    }
}

impl AdmissionStore {
    /// Opens the store, creating or recreating it as section 6.3 requires.
    /// `trust_present`: whether trusted-keys.json exists (store loss vs. a
    /// fresh server in bootstrap state).
    pub fn open(
        config: &StoreConfig,
        trust_present: bool,
        now: i64,
    ) -> Result<(Self, OpenReport), StoreError> {
        ensure_dir(&config.path, config.owner)?;
        let mut report = OpenReport::default();
        match fs::symlink_metadata(&config.path) {
            Ok(meta) if meta.file_type().is_file() => match open_existing(&config.path) {
                Ok(conn) => {
                    let store = Self::wrap(conn, config);
                    store.secure_files()?;
                    report.quarantine_ends_at = store.quarantine_ends_at()?;
                    return Ok((store, report));
                }
                Err(StoreError::TooNew(version)) => return Err(StoreError::TooNew(version)),
                Err(_) => {
                    report.moved_aside = Some(move_aside(&config.path, now)?);
                    report.recreated = true;
                }
            },
            Ok(_) => {
                // A symlink or special file is never opened (section 6.4).
                report.moved_aside = Some(move_aside(&config.path, now)?);
                report.recreated = true;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                report.recreated = trust_present;
            }
            Err(err) => return Err(err.into()),
        }
        let quarantine = report.recreated.then_some(now + QUARANTINE_SECONDS);
        let conn = create(&config.path, config.owner, now, quarantine)?;
        let store = Self::wrap(conn, config);
        store.secure_files()?;
        report.created = true;
        report.quarantine_ends_at = quarantine;
        Ok((store, report))
    }

    fn wrap(conn: Connection, config: &StoreConfig) -> Self {
        Self {
            conn: Mutex::new(conn),
            path: config.path.clone(),
            owner: config.owner,
            build_starts: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records when the runner started a build (its `build_started` line).
    pub fn note_build_started(&self, build_id: &str, started_at: i64) {
        let mut starts = self
            .build_starts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // Bounded: builds are one at a time; keep the newest 1024.
        while starts.len() >= 1024 {
            let Some(oldest) = starts.keys().next().cloned() else {
                break;
            };
            starts.remove(&oldest);
        }
        starts.insert(build_id.to_owned(), started_at);
    }

    /// `(started_at, built_at)` of the recorded build of a service and
    /// commit (see [`AdmissionStore::note_build_started`]).
    pub fn build_window_of(
        &self,
        service_id: &str,
        commit_sha: &str,
    ) -> (Option<i64>, Option<i64>) {
        let row: Option<(String, String)> = self
            .lock()
            .query_row(
                "SELECT build_id, built_at FROM builds WHERE service_id = ?1 AND commit_sha = ?2",
                rusqlite::params![service_id, commit_sha],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        row.map_or((None, None), |(build_id, built_at)| {
            (
                self.build_starts().get(&build_id).copied(),
                crate::signed_plan::text::timestamp(&built_at),
            )
        })
    }

    fn build_starts(&self) -> std::collections::BTreeMap<String, i64> {
        self.build_starts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// `-wal` and `-shm` get the database's owner and mode (section 6.4).
    fn secure_files(&self) -> Result<(), StoreError> {
        for suffix in ["", "-wal", "-shm"] {
            let mut name = self.path.as_os_str().to_owned();
            name.push(suffix);
            let path = PathBuf::from(name);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_file() => secure_file(&path, self.owner)?,
                Ok(_) => {
                    return Err(StoreError::Unsafe(format!(
                        "{} is not a regular file",
                        path.display()
                    )))
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    /// End of the store-loss quarantine, if one was set.
    pub fn quarantine_ends_at(&self) -> Result<Option<i64>, StoreError> {
        let conn = self.lock();
        let value: Option<String> = conn
            .query_row(
                "SELECT quarantine_ends_at FROM meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        Ok(value.as_deref().and_then(timestamp))
    }
}

fn ensure_dir(path: &Path, owner: Option<StoreOwner>) -> Result<(), StoreError> {
    let dir = path
        .parent()
        .ok_or_else(|| StoreError::Unsafe("store path has no directory".to_owned()))?;
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            return Err(StoreError::Unsafe(format!(
                "{} is not a directory",
                dir.display()
            )))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE)
                .create(dir)?;
        }
        Err(err) => return Err(err.into()),
    }
    match owner {
        Some(owner) => {
            // Group first: setgid is kept only on a directory of a group the
            // (non-root) agent belongs to.
            chown(dir, owner)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(OWNED_DIR_MODE))?;
        }
        None => fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))?,
    }
    Ok(())
}

fn chown(path: &Path, owner: StoreOwner) -> Result<(), StoreError> {
    std::os::unix::fs::lchown(path, Some(owner.uid), Some(owner.gid)).map_err(Into::into)
}

fn secure_file(path: &Path, owner: Option<StoreOwner>) -> Result<(), StoreError> {
    if let Some(owner) = owner {
        chown(path, owner)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))?;
    Ok(())
}

fn move_aside(path: &Path, now: i64) -> Result<PathBuf, StoreError> {
    let stamp = format_timestamp(now).replace(':', "");
    let mut target = path.as_os_str().to_owned();
    target.push(format!(".corrupt-{stamp}"));
    let target = PathBuf::from(target);
    fs::rename(path, &target)?;
    for suffix in ["-wal", "-shm"] {
        let mut from = path.as_os_str().to_owned();
        from.push(suffix);
        let mut to = target.as_os_str().to_owned();
        to.push(suffix);
        match fs::rename(&from, &to) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(target)
}

fn configure(conn: &Connection) -> Result<(), StoreError> {
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::Unsafe(format!("journal_mode is {mode}")));
    }
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    persist_wal(conn)
}

/// `SQLITE_FCNTL_PERSIST_WAL`: keep `-wal`/`-shm` after the last connection
/// closes, so the runner's read-only open never has to create them.
fn persist_wal(conn: &Connection) -> Result<(), StoreError> {
    let mut on: std::os::raw::c_int = 1;
    // SAFETY: the handle is valid for the lifetime of `conn`, "main" is a
    // NUL-terminated database name and the argument is an int as the
    // SQLITE_FCNTL_PERSIST_WAL opcode requires.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            conn.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut on as *mut std::os::raw::c_int).cast(),
        )
    };
    if rc == rusqlite::ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(StoreError::Unsafe(format!(
            "SQLITE_FCNTL_PERSIST_WAL failed ({rc})"
        )))
    }
}

fn user_version(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let version = user_version(conn)?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::TooNew(version));
    }
    for (index, step) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        if step.rebuilds {
            // PRAGMA foreign_keys is a no-op inside a transaction.
            conn.pragma_update(None, "foreign_keys", false)?;
        }
        let applied = apply_migration(conn, step, index as i64 + 1);
        if step.rebuilds {
            conn.pragma_update(None, "foreign_keys", true)?;
        }
        applied?;
    }
    Ok(())
}

fn apply_migration(
    conn: &mut Connection,
    step: &Migration,
    version: i64,
) -> Result<(), StoreError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for sql in step.sql {
        tx.execute_batch(sql)?;
    }
    if step.rebuilds {
        let violations: i64 =
            tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        if violations != 0 {
            // Dropping the transaction rolls back: the store stays at the
            // previous version and the agent reports INTERNAL.
            return Err(StoreError::Unsafe(format!(
                "migration to user_version {version}: {violations} foreign key violations"
            )));
        }
    }
    tx.pragma_update(None, "user_version", version)?;
    tx.commit()?;
    Ok(())
}

fn open_existing(path: &Path) -> Result<Connection, StoreError> {
    let mut conn = Connection::open(path)?;
    let check: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if check != "ok" {
        return Err(StoreError::Unsafe(format!("quick_check: {check}")));
    }
    let version = user_version(&conn)?;
    if version == 0 {
        // Never initialised (crash during creation): treated as lost.
        return Err(StoreError::Unsafe("uninitialised store".to_owned()));
    }
    configure(&conn)?;
    migrate(&mut conn)?;
    let meta: i64 = conn.query_row("SELECT COUNT(*) FROM meta WHERE id = 1", [], |r| r.get(0))?;
    if meta != 1 {
        return Err(StoreError::Unsafe("meta row missing".to_owned()));
    }
    Ok(conn)
}

fn create(
    path: &Path,
    owner: Option<StoreOwner>,
    now: i64,
    quarantine_ends_at: Option<i64>,
) -> Result<Connection, StoreError> {
    // Create the file ourselves so it is 0640 with the right owner before
    // SQLite writes anything; SQLite copies both to `-wal` and `-shm`.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    drop(file);
    secure_file(path, owner)?;
    let mut conn = Connection::open(path)?;
    configure(&conn)?;
    migrate(&mut conn)?;
    conn.execute(
        "INSERT INTO meta (id, store_created_at, schema_version, quarantine_ends_at) \
         VALUES (1, ?1, ?2, ?3)",
        rusqlite::params![
            format_timestamp(now),
            SCHEMA_VERSION,
            quarantine_ends_at.map(format_timestamp)
        ],
    )?;
    Ok(conn)
}

/// A lowercase UUIDv7 (RFC 9562): 48-bit Unix milliseconds, version 7,
/// variant 10, 74 random bits.
pub fn new_uuid7(unix_ms: u64) -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("CSPRNG");
    bytes[..6].copy_from_slice(&unix_ms.to_be_bytes()[2..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
