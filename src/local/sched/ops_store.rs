//! `/var/lib/permanu/agent/ops.db` (agent-protocol.md 10): the schedulers'
//! own state, written only by the agent (`permanu-agent:permanu-runner
//! 0640`, like every file of that directory). Definitions never live here:
//! they come from admitted plans in `admissions.db`. This store keeps run
//! history (cron runs, backup runs, verify-restores, artifacts), alert
//! events and rule state, and the scheduler checkpoints.
//!
//! Records are the protocol messages themselves (prost-encoded), with the
//! few columns the queries filter on. Run history is kept for 90 days or
//! the newest 1,000 records per job or policy, whichever is more.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use prost::Message;
use rusqlite::{params, Connection, OptionalExtension};

use crate::admissions::{StoreError, StoreOwner};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
  seq     INTEGER PRIMARY KEY AUTOINCREMENT,
  kind    TEXT NOT NULL,
  id      TEXT NOT NULL,
  subject TEXT NOT NULL,
  slot    TEXT NOT NULL DEFAULT '',
  status  INTEGER NOT NULL,
  at      INTEGER NOT NULL,
  body    BLOB NOT NULL,
  UNIQUE (kind, id)
);
CREATE INDEX IF NOT EXISTS records_subject ON records (kind, subject, seq);
CREATE INDEX IF NOT EXISTS records_slot ON records (kind, subject, slot);
CREATE TABLE IF NOT EXISTS claimed_slots (
 kind TEXT NOT NULL, subject TEXT NOT NULL, slot TEXT NOT NULL,
 PRIMARY KEY(kind, subject, slot)
);
INSERT OR IGNORE INTO claimed_slots SELECT DISTINCT kind, subject, slot FROM records WHERE slot <> '';

";

/// Run history retention (agent-protocol.md 10).
pub const HISTORY_SECONDS: i64 = 90 * 86_400;
pub const HISTORY_RECORDS: i64 = 1_000;

/// The record families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    CronRun,
    BackupRun,
    Verification,
    Artifact,
    AlertEvent,
    /// agent-protocol.md 11: webhook deliveries (`WebhookDelivery`).
    WebhookDelivery,
    /// agent-protocol.md 11.2: server builds (`ServerBuild`).
    ServerBuild,
    /// agent-protocol.md 13: staged artifact sets (`StagedArtifactSet`).
    StagedSet,
}

impl RecordKind {
    fn name(self) -> &'static str {
        match self {
            Self::CronRun => "cron_run",
            Self::BackupRun => "backup_run",
            Self::Verification => "verification",
            Self::Artifact => "artifact",
            Self::AlertEvent => "alert_event",
            Self::WebhookDelivery => "webhook_delivery",
            Self::ServerBuild => "server_build",
            Self::StagedSet => "staged_set",
        }
    }
}

/// One stored record: the columns plus the encoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub seq: i64,
    pub id: String,
    pub subject: String,
    pub slot: String,
    pub status: i32,
    pub at: i64,
    pub body: Vec<u8>,
}

impl Row {
    pub fn decode<M: Message + Default>(&self) -> Option<M> {
        M::decode(self.body.as_slice()).ok()
    }
}

/// A newest-first (or oldest-first) listing.
#[derive(Debug, Clone, Default)]
pub struct Listing<'a> {
    pub subject: Option<&'a str>,
    pub statuses: &'a [i32],
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// Newest first: records with `seq < before`; oldest first: `seq > after`.
    pub before: Option<i64>,
    pub after: Option<i64>,
    pub ascending: bool,
    pub limit: usize,
}

pub struct OpsStore {
    conn: Mutex<Connection>,
    failure_generation: AtomicU64,
}

impl std::fmt::Debug for OpsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpsStore").finish()
    }
}

impl OpsStore {
    /// Opens (or creates) the store with the admissions store's file modes.
    pub fn open(path: &Path, owner: Option<StoreOwner>) -> Result<Self, StoreError> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.file_type().is_file() {
                return Err(StoreError::Unsafe(format!(
                    "{} is not a regular file",
                    path.display()
                )));
            }
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let file = std::path::PathBuf::from(name);
            if file.exists() {
                use std::os::unix::fs::PermissionsExt;
                if let Some(owner) = owner {
                    std::os::unix::fs::lchown(&file, Some(owner.uid), Some(owner.gid))?;
                }
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640))?;
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
            failure_generation: AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(SCHEMA).expect("schema");
        Self {
            conn: Mutex::new(conn),
            failure_generation: AtomicU64::new(0),
        }
    }

    pub fn failure_generation(&self) -> u64 {
        self.failure_generation.load(Ordering::SeqCst)
    }
    fn checked<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if result.is_err() {
            self.failure_generation.fetch_add(1, Ordering::SeqCst);
        }
        result
    }

    #[cfg(test)]
    pub fn query_only(&self, enabled: bool) {
        self.lock()
            .pragma_update(None, "query_only", enabled)
            .unwrap();
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim<M: Message>(
        &self,
        kind: RecordKind,
        id: &str,
        subject: &str,
        slot: &str,
        status: i32,
        at: i64,
        message: &M,
    ) -> Result<bool, StoreError> {
        self.checked(self.claim_inner(kind, id, subject, slot, status, at, message))
    }

    /// Claims a scheduled fire time and records its initial run atomically.
    /// Claims survive history pruning, so an old clock cannot replay work.
    #[allow(clippy::too_many_arguments)]
    fn claim_inner<M: Message>(
        &self,
        kind: RecordKind,
        id: &str,
        subject: &str,
        slot: &str,
        status: i32,
        at: i64,
        message: &M,
    ) -> Result<bool, StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if tx.execute(
            "INSERT OR IGNORE INTO claimed_slots(kind, subject, slot) VALUES (?1, ?2, ?3)",
            params![kind.name(), subject, slot],
        )? == 0
        {
            return Ok(false);
        }
        tx.execute("INSERT INTO records(kind,id,subject,slot,status,at,body) VALUES (?1,?2,?3,?4,?5,?6,?7)", params![kind.name(),id,subject,slot,status,at,message.encode_to_vec()])?;
        tx.commit()?;
        Ok(true)
    }

    pub fn try_meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .lock()
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }
    pub fn try_set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.lock().execute("INSERT INTO meta(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,value])?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put<M: Message>(
        &self,
        kind: RecordKind,
        id: &str,
        subject: &str,
        slot: &str,
        status: i32,
        at: i64,
        message: &M,
    ) -> Result<i64, StoreError> {
        self.checked(self.put_inner(kind, id, subject, slot, status, at, message))
    }

    /// Inserts or replaces a record by `(kind, id)`; its `seq` (listing
    /// order) is kept on update.
    #[allow(clippy::too_many_arguments)]
    fn put_inner<M: Message>(
        &self,
        kind: RecordKind,
        id: &str,
        subject: &str,
        slot: &str,
        status: i32,
        at: i64,
        message: &M,
    ) -> Result<i64, StoreError> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO records (kind, id, subject, slot, status, at, body) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT (kind, id) DO UPDATE SET subject = excluded.subject, \
             slot = excluded.slot, status = excluded.status, at = excluded.at, \
             body = excluded.body",
            params![
                kind.name(),
                id,
                subject,
                slot,
                status,
                at,
                message.encode_to_vec()
            ],
        )?;
        Ok(conn.query_row(
            "SELECT seq FROM records WHERE kind = ?1 AND id = ?2",
            params![kind.name(), id],
            |r| r.get(0),
        )?)
    }

    pub fn try_get(&self, kind: RecordKind, id: &str) -> Result<Option<Row>, StoreError> {
        Ok(self
            .lock()
            .query_row(
                "SELECT seq,id,subject,slot,status,at,body FROM records WHERE kind=?1 AND id=?2",
                params![kind.name(), id],
                row,
            )
            .optional()?)
    }
    pub fn get(&self, kind: RecordKind, id: &str) -> Option<Row> {
        self.checked(self.try_get(kind, id)).unwrap_or_else(|err| {
            tracing::error!(error=%err,"scheduler record unreadable");
            None
        })
    }

    /// Whether `subject` already has a record in `slot` (a fire time).
    pub fn has_slot(&self, kind: RecordKind, subject: &str, slot: &str) -> bool {
        self.lock()
            .query_row(
                "SELECT COUNT(*) FROM (SELECT kind,subject,slot FROM records UNION ALL SELECT kind,subject,slot FROM claimed_slots) WHERE kind = ?1 AND subject = ?2 AND slot = ?3",
                params![kind.name(), subject, slot],
                |r| r.get::<_, i64>(0),
            )
            .map_or_else(
                |err| {
                    tracing::error!(error=%err,"scheduler slot unreadable; refusing execution");
                    true
                },
                |count| count > 0,
            )
    }

    pub fn list(&self, kind: RecordKind, listing: &Listing<'_>) -> Vec<Row> {
        self.checked(self.try_list(kind, listing))
            .unwrap_or_else(|err| {
                tracing::error!(error=%err,"scheduler history unreadable");
                Vec::new()
            })
    }
    pub fn try_list(
        &self,
        kind: RecordKind,
        listing: &Listing<'_>,
    ) -> Result<Vec<Row>, StoreError> {
        let mut sql = String::from(
            "SELECT seq, id, subject, slot, status, at, body FROM records WHERE kind = ?1",
        );
        let mut values: Vec<rusqlite::types::Value> = vec![kind.name().to_owned().into()];
        let mut bind = |sql: &mut String, clause: &str, value: rusqlite::types::Value| {
            values.push(value);
            sql.push_str(&clause.replace('?', &format!("?{}", values.len())));
        };
        if let Some(subject) = listing.subject {
            bind(&mut sql, " AND subject = ?", subject.to_owned().into());
        }
        if let Some(from) = listing.from {
            bind(&mut sql, " AND at >= ?", from.into());
        }
        if let Some(to) = listing.to {
            bind(&mut sql, " AND at <= ?", to.into());
        }
        if let Some(before) = listing.before {
            bind(&mut sql, " AND seq < ?", before.into());
        }
        if let Some(after) = listing.after {
            bind(&mut sql, " AND seq > ?", after.into());
        }
        if !listing.statuses.is_empty() {
            let list: Vec<String> = listing.statuses.iter().map(i32::to_string).collect();
            sql.push_str(&format!(" AND status IN ({})", list.join(",")));
        }
        sql.push_str(if listing.ascending {
            " ORDER BY seq ASC"
        } else {
            " ORDER BY seq DESC"
        });
        bind(
            &mut sql,
            " LIMIT ?",
            i64::try_from(listing.limit.max(1))
                .unwrap_or(i64::MAX)
                .into(),
        );
        let conn = self.lock();
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(values), row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Records of `kind` with one of `statuses` (all when empty) whose `at`
    /// is at least `from`.
    pub fn count(&self, kind: RecordKind, statuses: &[i32], from: Option<i64>) -> u32 {
        let mut sql = String::from("SELECT COUNT(*) FROM records WHERE kind = ?1 AND at >= ?2");
        if !statuses.is_empty() {
            let list: Vec<String> = statuses.iter().map(i32::to_string).collect();
            sql.push_str(&format!(" AND status IN ({})", list.join(",")));
        }
        self.lock()
            .query_row(&sql, params![kind.name(), from.unwrap_or(i64::MIN)], |r| {
                r.get::<_, i64>(0)
            })
            .map_or(0, |count| u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Drops one record (a staged set that was deleted).
    pub fn remove(&self, kind: RecordKind, id: &str) {
        let _ = self.lock().execute(
            "DELETE FROM records WHERE kind = ?1 AND id = ?2",
            params![kind.name(), id],
        );
    }

    /// Drops run history older than 90 days beyond the newest 1,000 records
    /// of each job or policy. Artifacts and alert events follow the same
    /// rule per policy and rule.
    pub fn prune(&self, now: i64) {
        let _ = self.lock().execute(
            "DELETE FROM records WHERE at < ?1 AND seq NOT IN ( \
               SELECT r.seq FROM records r WHERE r.kind = records.kind \
               AND r.subject = records.subject ORDER BY r.seq DESC LIMIT ?2)",
            params![now - HISTORY_SECONDS, HISTORY_RECORDS],
        );
    }
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        seq: r.get(0)?,
        id: r.get(1)?,
        subject: r.get(2)?,
        slot: r.get(3)?,
        status: r.get(4)?,
        at: r.get(5)?,
        body: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::agent::v2::{CronRun, CronRunStatus};

    fn run(id: &str, cron: &str, status: CronRunStatus) -> CronRun {
        CronRun {
            id: id.to_owned(),
            cron_id: cron.to_owned(),
            status: status as i32,
            ..Default::default()
        }
    }

    #[test]
    fn slot_claim_and_initial_record_commit_together() {
        let store = OpsStore::in_memory();
        let first = run("r1", "c1", CronRunStatus::Pending);
        assert!(store
            .claim(RecordKind::CronRun, "r1", "c1", "slot", 1, 100, &first)
            .unwrap());
        assert!(!store
            .claim(RecordKind::CronRun, "r2", "c1", "slot", 1, 100, &first)
            .unwrap());
        assert!(store.get(RecordKind::CronRun, "r2").is_none());
        store.lock().execute_batch("PRAGMA query_only=ON").unwrap();
        assert!(store
            .claim(RecordKind::CronRun, "r3", "c1", "next", 1, 101, &first)
            .is_err());
        store.lock().execute_batch("PRAGMA query_only=OFF").unwrap();
        assert!(store
            .claim(RecordKind::CronRun, "r3", "c1", "next", 1, 101, &first)
            .unwrap());
    }

    #[test]
    fn records_round_trip_keep_their_order_and_filter() {
        let store = OpsStore::in_memory();
        let kind = RecordKind::CronRun;
        let first = run("r1", "c1", CronRunStatus::Running);
        let seq = store
            .put(kind, "r1", "c1", "2026-09-23T10:00:00Z", 2, 100, &first)
            .unwrap();
        store
            .put(
                kind,
                "r2",
                "c2",
                "",
                3,
                200,
                &run("r2", "c2", CronRunStatus::Succeeded),
            )
            .unwrap();
        // An update keeps the listing position.
        let done = run("r1", "c1", CronRunStatus::Failed);
        assert_eq!(
            store
                .put(kind, "r1", "c1", "2026-09-23T10:00:00Z", 4, 100, &done)
                .unwrap(),
            seq
        );
        let got: CronRun = store.get(kind, "r1").unwrap().decode().unwrap();
        assert_eq!(got.status, CronRunStatus::Failed as i32);
        assert!(store.has_slot(kind, "c1", "2026-09-23T10:00:00Z"));
        assert!(!store.has_slot(kind, "c2", "2026-09-23T10:00:00Z"));
        let newest: Vec<String> = store
            .list(
                kind,
                &Listing {
                    limit: 10,
                    ..Default::default()
                },
            )
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(newest, ["r2", "r1"]);
        let failed = store.list(
            kind,
            &Listing {
                statuses: &[4],
                limit: 10,
                ..Default::default()
            },
        );
        assert_eq!(failed.len(), 1);
        let page = store.list(
            kind,
            &Listing {
                before: Some(failed[0].seq + 1),
                subject: Some("c1"),
                limit: 1,
                ..Default::default()
            },
        );
        assert_eq!(page[0].id, "r1");
        store.try_set_meta("cron_checkpoint", "123").unwrap();
        assert_eq!(
            store.try_meta("cron_checkpoint").unwrap().as_deref(),
            Some("123")
        );
    }

    #[test]
    fn prune_keeps_the_newest_thousand_and_the_last_ninety_days() {
        let store = OpsStore::in_memory();
        let now = 200 * 86_400;
        for n in 0..1_005 {
            let id = format!("r{n}");
            store
                .put(
                    RecordKind::CronRun,
                    &id,
                    "c1",
                    "",
                    3,
                    0,
                    &run(&id, "c1", CronRunStatus::Succeeded),
                )
                .unwrap();
        }
        store
            .put(
                RecordKind::CronRun,
                "recent",
                "c2",
                "",
                3,
                now - 86_400,
                &CronRun::default(),
            )
            .unwrap();
        store
            .put(
                RecordKind::CronRun,
                "old",
                "c2",
                "",
                3,
                0,
                &CronRun::default(),
            )
            .unwrap();
        store.prune(now);
        let listing = Listing {
            subject: Some("c1"),
            limit: 5_000,
            ..Default::default()
        };
        assert_eq!(store.list(RecordKind::CronRun, &listing).len(), 1_000);
        assert!(store.get(RecordKind::CronRun, "r0").is_none());
        assert!(store.get(RecordKind::CronRun, "r1004").is_some());
        // c2 has only two records: both are within the newest 1,000.
        assert!(store.get(RecordKind::CronRun, "old").is_some());
    }
}
