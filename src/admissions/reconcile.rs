//! Reconciliation of the runner's consumed log (signed-plan.md sections 6.4
//! and 14.5, D-022). The log is authoritative: a `consumed` line is never
//! undone. The agent reads `consumed.log.1` then `consumed.log`, skips lines
//! with `seq <= last_seq`, ignores a torn last line, and applies each new
//! line in one transaction together with the cursor.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rusqlite::{params, OptionalExtension, Transaction};
use serde::Deserialize;

use super::{AdmissionStore, StoreError};
use crate::signed_plan::text::format_timestamp;

const MAX_LOG_BYTES: u64 = 33 * 1024 * 1024 + 1024 * 1024;

/// One line of the consumed log (section 14.5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumedLine {
    pub v: u32,
    pub seq: u64,
    pub at: String,
    pub event: String,
    pub plan_id: String,
    pub plan_digest_hex: String,
    pub action_index: u32,
    #[serde(default)]
    pub op: Option<String>,
    #[serde(default)]
    pub release_id: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
}

/// What a reconciliation pass changed, for events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileEffect {
    Consumed {
        plan_id: String,
        action_index: u32,
    },
    ActionFinished {
        plan_id: String,
        action_index: u32,
        outcome: String,
    },
    AdmissionFinished {
        plan_id: String,
        outcome: String,
    },
    /// A line naming a plan or digest the store does not hold, a malformed
    /// line or a `seq` gap: reported as `TrustChangedEvent{file_changed}`.
    Unexplained {
        detail: String,
    },
}

/// The log lines, in file order, plus problems found while reading.
#[derive(Debug, Default)]
pub struct LogRead {
    pub lines: Vec<ConsumedLine>,
    pub problems: Vec<String>,
    pub inode: Option<u64>,
    pub offset: u64,
}

fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// Reads `consumed.log.1` then `consumed.log`. A file that is not a regular
/// file owned by `owner_uid` and not group/world-writable is not trusted.
pub fn read_consumed_log(path: &Path, owner_uid: u32) -> LogRead {
    let mut read = LogRead::default();
    for (index, file) in [rotated(path), path.to_path_buf()].iter().enumerate() {
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(file);
        let mut handle = match opened {
            Ok(handle) => handle,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                read.problems.push(format!("{}: {err}", file.display()));
                continue;
            }
        };
        let Ok(meta) = handle.metadata() else {
            read.problems
                .push(format!("{}: cannot stat", file.display()));
            continue;
        };
        if !meta.file_type().is_file() || meta.uid() != owner_uid || meta.mode() & 0o022 != 0 {
            read.problems.push(format!(
                "{}: unexpected owner, mode or type",
                file.display()
            ));
            continue;
        }
        let mut bytes = Vec::new();
        if handle
            .by_ref()
            .take(MAX_LOG_BYTES)
            .read_to_end(&mut bytes)
            .is_err()
        {
            read.problems
                .push(format!("{}: read failed", file.display()));
            continue;
        }
        // A torn last line (crash before fsync) is ignored: nothing ran.
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        for raw in bytes[..complete].split(|b| *b == b'\n') {
            if raw.is_empty() {
                continue;
            }
            match serde_json::from_slice::<ConsumedLine>(raw) {
                Ok(line)
                    if line.v == 1
                        && matches!(line.event.as_str(), "consumed" | "op" | "result") =>
                {
                    read.lines.push(line);
                }
                _ => read.problems.push("malformed consumed.log line".to_owned()),
            }
        }
        if index == 1 {
            read.inode = Some(meta.ino());
            read.offset = complete as u64;
        }
    }
    read
}

const OUTCOMES: &[&str] = &["succeeded", "failed", "rolled_back", "cancelled", "expired"];

impl AdmissionStore {
    /// Applies the new lines of `read` in one transaction with the cursor.
    pub fn reconcile(&self, read: &LogRead, now: i64) -> Result<Vec<ReconcileEffect>, StoreError> {
        let mut effects: Vec<ReconcileEffect> = read
            .problems
            .iter()
            .map(|detail| ReconcileEffect::Unexplained {
                detail: detail.clone(),
            })
            .collect();
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let mut last_seq: u64 = tx
            .query_row(
                "SELECT last_seq FROM consumed_reconciliation WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map_or(0, |seq| u64::try_from(seq).unwrap_or(0));
        let mut lines: Vec<&ConsumedLine> = read
            .lines
            .iter()
            .filter(|line| line.seq > last_seq)
            .collect();
        lines.sort_by_key(|line| line.seq);
        lines.dedup_by_key(|line| line.seq);
        for line in lines {
            if line.seq != last_seq + 1 {
                effects.push(ReconcileEffect::Unexplained {
                    detail: format!("consumed.log seq gap {} -> {}", last_seq, line.seq),
                });
            }
            last_seq = line.seq;
            apply_line(&tx, line, &mut effects)?;
        }
        tx.execute(
            "INSERT INTO consumed_reconciliation (id, last_seq, log_inode, log_offset, reconciled_at) \
             VALUES (1, ?1, ?2, ?3, ?4) ON CONFLICT (id) DO UPDATE SET last_seq = excluded.last_seq, \
             log_inode = excluded.log_inode, log_offset = excluded.log_offset, \
             reconciled_at = excluded.reconciled_at",
            params![
                last_seq as i64,
                read.inode.map(|i| i as i64),
                read.offset as i64,
                format_timestamp(now)
            ],
        )?;
        tx.commit()?;
        Ok(effects)
    }
}

fn apply_line(
    tx: &Transaction<'_>,
    line: &ConsumedLine,
    effects: &mut Vec<ReconcileEffect>,
) -> Result<(), StoreError> {
    let exists: i64 = tx.query_row(
        "SELECT COUNT(*) FROM admission_actions x JOIN admissions a ON a.plan_id = x.plan_id \
         WHERE x.plan_id = ?1 AND a.plan_digest_hex = ?2 AND x.action_index = ?3",
        params![line.plan_id, line.plan_digest_hex, line.action_index],
        |r| r.get(0),
    )?;
    if exists != 1 {
        effects.push(ReconcileEffect::Unexplained {
            detail: format!("consumed.log seq {} names an unknown admission", line.seq),
        });
        return Ok(());
    }
    match line.event.as_str() {
        "consumed" => {
            let changed = tx.execute(
                "UPDATE admission_actions SET consumed_at = ?1, consumed_seq = ?2 \
                 WHERE plan_id = ?3 AND action_index = ?4 AND consumed_seq IS NULL",
                params![line.at, line.seq as i64, line.plan_id, line.action_index],
            )?;
            if changed == 1 {
                effects.push(ReconcileEffect::Consumed {
                    plan_id: line.plan_id.clone(),
                    action_index: line.action_index,
                });
            }
        }
        "result" => {
            let outcome = line.outcome.as_deref().unwrap_or_default();
            if !OUTCOMES.contains(&outcome) {
                effects.push(ReconcileEffect::Unexplained {
                    detail: format!("consumed.log seq {} has an unknown outcome", line.seq),
                });
                return Ok(());
            }
            // The log wins over anything the agent recorded for the action.
            tx.execute(
                "UPDATE admission_actions SET finished_at = ?1, outcome = ?2, result_seq = ?3 \
                 WHERE plan_id = ?4 AND action_index = ?5",
                params![
                    line.at,
                    outcome,
                    line.seq as i64,
                    line.plan_id,
                    line.action_index
                ],
            )?;
            effects.push(ReconcileEffect::ActionFinished {
                plan_id: line.plan_id.clone(),
                action_index: line.action_index,
                outcome: outcome.to_owned(),
            });
            if let Some(outcome) = finish_admission_if_done(tx, &line.plan_id)? {
                effects.push(ReconcileEffect::AdmissionFinished {
                    plan_id: line.plan_id.clone(),
                    outcome,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

/// When every action has a result, the admission's `finished_at` is the
/// latest action `finished_at` and its outcome `failed` if any failed, else
/// `rolled_back`, `cancelled` or `succeeded` in that precedence (an action
/// the agent expired ranks after `failed`).
pub(super) fn finish_admission_if_done(
    tx: &Transaction<'_>,
    plan_id: &str,
) -> Result<Option<String>, StoreError> {
    let (unfinished, latest): (i64, Option<String>) = tx.query_row(
        "SELECT SUM(finished_at IS NULL), MAX(finished_at) FROM admission_actions \
         WHERE plan_id = ?1",
        params![plan_id],
        |r| Ok((r.get::<_, Option<i64>>(0)?.unwrap_or(1), r.get(1)?)),
    )?;
    if unfinished != 0 {
        return Ok(None);
    }
    let outcomes: Vec<String> = {
        let mut statement =
            tx.prepare("SELECT outcome FROM admission_actions WHERE plan_id = ?1")?;
        let rows = statement
            .query_map(params![plan_id], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let outcome = ["failed", "expired", "rolled_back", "cancelled"]
        .into_iter()
        .find(|o| outcomes.iter().any(|x| x == o))
        .unwrap_or("succeeded")
        .to_owned();
    let changed = tx.execute(
        "UPDATE admissions SET finished_at = ?1, outcome = ?2 \
         WHERE plan_id = ?3 AND finished_at IS NULL",
        params![latest, outcome, plan_id],
    )?;
    Ok((changed == 1).then_some(outcome))
}
