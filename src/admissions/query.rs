//! Read paths (GetStateHead, ListAdmissions, operations, rules) and the
//! agent's own execution-state writes.

use rusqlite::{params, OptionalExtension, Row};

use super::{
    AdmissionStore, StoreError, EXECUTION_WINDOW_SECONDS, OPERATION_EVENT_RETENTION_SECONDS,
};
use crate::signed_plan::text::{format_timestamp, timestamp};
use crate::signed_plan::verify::GENESIS_HEAD;

/// One `admissions` row, as the agent serves it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub plan_id: String,
    pub plan_digest_hex: String,
    pub signed_plan_json: String,
    pub submitter: String,
    pub operation_id: String,
    pub admitted_at: String,
    pub finished_at: Option<String>,
    pub outcome: String,
    pub admission_seq: i64,
    pub nonce: String,
    pub author_kind: String,
    pub signer_key_ids: Vec<String>,
    pub action_kinds: Vec<String>,
    pub project_id: String,
    pub environment: String,
    pub head_after_hex: String,
    pub rule_id: Option<String>,
    pub expires_at: String,
    /// v1.0.2: plan.environment_id ('' for server-level plans).
    pub environment_id: String,
}

/// One `admission_actions` row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionRecord {
    pub action_index: u32,
    pub kind: String,
    pub consumed_at: Option<String>,
    pub finished_at: Option<String>,
    pub outcome: String,
    pub deployment_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleInfo {
    pub rule_id: String,
    pub rule_jcs: String,
    pub rule_digest_hex: String,
    pub created_by_key_id: String,
    pub created_plan_id: String,
    pub installed_at: String,
    pub revoked_at: Option<String>,
    /// An admitted `rule.revoke` whose runner result is not recorded yet.
    pub revoke_pending: bool,
    pub invocations_last_hour: u32,
    pub match_count: u64,
    pub last_matched_at: Option<String>,
}

/// `GetStateHead` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadRecord {
    pub head_digest_hex: String,
    pub last_plan_id: String,
    pub updated_at: Option<String>,
}

const ADMISSION_COLUMNS: &str = "plan_id, plan_digest_hex, signed_plan_json, submitter, \
    operation_id, admitted_at, finished_at, outcome, admission_seq, nonce, author_kind, \
    signer_key_ids, action_kinds, project_id, environment, head_after_hex, rule_id, expires_at, \
    environment_id";

fn admission_from_row(row: &Row<'_>) -> rusqlite::Result<AdmissionRecord> {
    let list = |text: String| serde_json::from_str::<Vec<String>>(&text).unwrap_or_default();
    Ok(AdmissionRecord {
        plan_id: row.get(0)?,
        plan_digest_hex: row.get(1)?,
        signed_plan_json: row.get(2)?,
        submitter: row.get(3)?,
        operation_id: row.get(4)?,
        admitted_at: row.get(5)?,
        finished_at: row.get(6)?,
        outcome: row.get(7)?,
        admission_seq: row.get(8)?,
        nonce: row.get(9)?,
        author_kind: row.get(10)?,
        signer_key_ids: list(row.get(11)?),
        action_kinds: list(row.get(12)?),
        project_id: row.get(13)?,
        environment: row.get(14)?,
        head_after_hex: row.get(15)?,
        rule_id: row.get(16)?,
        expires_at: row.get(17)?,
        environment_id: row.get(18)?,
    })
}

impl AdmissionStore {
    pub fn head(&self, project_id: &str, environment: &str) -> Result<HeadRecord, StoreError> {
        let conn = self.lock();
        let row: Option<(String, String, String)> = conn
            .query_row(
                "SELECT head_digest_hex, plan_id, updated_at FROM heads \
                 WHERE project_id = ?1 AND environment = ?2",
                params![project_id, environment],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(match row {
            Some((head, plan, at)) => HeadRecord {
                head_digest_hex: head,
                last_plan_id: plan,
                updated_at: Some(at),
            },
            None => HeadRecord {
                head_digest_hex: GENESIS_HEAD.to_owned(),
                last_plan_id: String::new(),
                updated_at: None,
            },
        })
    }

    /// Admissions with `admission_seq > after`, ascending, at most `limit`.
    pub fn admissions_after(
        &self,
        after: i64,
        limit: usize,
    ) -> Result<Vec<AdmissionRecord>, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "SELECT {ADMISSION_COLUMNS} FROM admissions WHERE admission_seq > ?1 \
             ORDER BY admission_seq ASC LIMIT ?2"
        ))?;
        let rows = statement
            .query_map(params![after, limit as i64], admission_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Admissions newest first with `admission_seq < before` (0 = newest).
    pub fn admissions_before(
        &self,
        before: i64,
        limit: usize,
    ) -> Result<Vec<AdmissionRecord>, StoreError> {
        let conn = self.lock();
        let bound = if before <= 0 { i64::MAX } else { before };
        let mut statement = conn.prepare(&format!(
            "SELECT {ADMISSION_COLUMNS} FROM admissions WHERE admission_seq < ?1 \
             ORDER BY admission_seq DESC LIMIT ?2"
        ))?;
        let rows = statement
            .query_map(params![bound, limit as i64], admission_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn admission_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionRecord>, StoreError> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                &format!("SELECT {ADMISSION_COLUMNS} FROM admissions WHERE operation_id = ?1"),
                params![operation_id],
                admission_from_row,
            )
            .optional()?)
    }

    pub fn admission(&self, plan_id: &str) -> Result<Option<AdmissionRecord>, StoreError> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                &format!("SELECT {ADMISSION_COLUMNS} FROM admissions WHERE plan_id = ?1"),
                params![plan_id],
                admission_from_row,
            )
            .optional()?)
    }

    pub fn actions(&self, plan_id: &str) -> Result<Vec<ActionRecord>, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT action_index, kind, consumed_at, finished_at, outcome, deployment_id \
             FROM admission_actions WHERE plan_id = ?1 ORDER BY action_index",
        )?;
        let rows = statement
            .query_map(params![plan_id], |r| {
                Ok(ActionRecord {
                    action_index: r.get(0)?,
                    kind: r.get(1)?,
                    consumed_at: r.get(2)?,
                    finished_at: r.get(3)?,
                    outcome: r.get(4)?,
                    deployment_id: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The agent records an action's outcome: one it applied itself, one that
    /// can no longer run, or a bound one whose final op returned before the
    /// runner's `result` line arrived. Never overwrites a result; a later
    /// `result` line wins (section 14.5).
    pub fn finish_action(
        &self,
        plan_id: &str,
        action_index: u32,
        outcome: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE admission_actions SET finished_at = ?1, outcome = ?2 \
             WHERE plan_id = ?3 AND action_index = ?4 AND finished_at IS NULL",
            params![format_timestamp(now), outcome, plan_id, action_index],
        )?;
        if changed == 1 {
            super::reconcile::settle_rule_revoke(
                &tx,
                plan_id,
                action_index,
                outcome,
                &format_timestamp(now),
            )?;
        }
        super::reconcile::finish_admission_if_done(&tx, plan_id)?;
        tx.commit()?;
        Ok(changed == 1)
    }

    /// Whether `service_id` has a release to return to: an earlier admission
    /// of the scope whose `deploy`, `rollback` or `restart` of it succeeded
    /// (signed-plan.md 14.6 failure path).
    pub fn has_previous_release(
        &self,
        record: &AdmissionRecord,
        service_id: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT a.signed_plan_json, x.action_index FROM admission_actions x \
             JOIN admissions a ON a.plan_id = x.plan_id \
             WHERE a.project_id = ?1 AND a.environment = ?2 AND a.admission_seq < ?3 \
             AND x.kind IN ('deploy', 'rollback', 'restart') AND x.outcome = 'succeeded' \
             ORDER BY a.admission_seq DESC",
        )?;
        let mut rows = statement.query(params![
            record.project_id,
            record.environment,
            record.admission_seq
        ])?;
        while let Some(row) = rows.next()? {
            let text: String = row.get(0)?;
            let index: usize = row.get(1)?;
            let envelope: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            if envelope["plan"]["actions"][index]["params"]["service_id"] == service_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Admissions whose execution window ended with actions unconsumed get
    /// `outcome = expired` (section 6.4). Returns their plan ids.
    pub fn expire_windows(&self, now: i64) -> Result<Vec<String>, StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let cutoff = format_timestamp(now - EXECUTION_WINDOW_SECONDS);
        let plan_ids: Vec<String> = {
            let mut statement = tx.prepare(
                "SELECT a.plan_id FROM admissions a WHERE a.finished_at IS NULL \
                 AND a.admitted_at < ?1 AND EXISTS (SELECT 1 FROM admission_actions x \
                 WHERE x.plan_id = a.plan_id AND x.consumed_at IS NULL AND x.finished_at IS NULL)",
            )?;
            let ids = statement
                .query_map(params![cutoff], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids
        };
        let at = format_timestamp(now);
        for plan_id in &plan_ids {
            tx.execute(
                "UPDATE admission_actions SET finished_at = ?1, outcome = 'expired' \
                 WHERE plan_id = ?2 AND consumed_at IS NULL AND finished_at IS NULL",
                params![at, plan_id],
            )?;
            tx.execute(
                "UPDATE admissions SET finished_at = ?1, outcome = 'expired' \
                 WHERE plan_id = ?2 AND finished_at IS NULL",
                params![at, plan_id],
            )?;
        }
        tx.commit()?;
        Ok(plan_ids)
    }

    /// Unfinished admissions (execution resumes after a restart).
    pub fn open_admissions(&self) -> Result<Vec<AdmissionRecord>, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "SELECT {ADMISSION_COLUMNS} FROM admissions WHERE finished_at IS NULL \
             ORDER BY admission_seq ASC"
        ))?;
        let rows = statement
            .query_map([], admission_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn rules(&self, include_revoked: bool, now: i64) -> Result<Vec<RuleInfo>, StoreError> {
        let conn = self.lock();
        let since = format_timestamp(now - 3_600);
        let mut statement = conn.prepare(
            "SELECT r.rule_id, r.rule, r.rule_digest_hex, r.created_by_key_id, \
             r.created_plan_id, a.admitted_at, r.revoked_at, r.revoked_plan_id, \
             (SELECT COUNT(*) FROM rule_invocations i WHERE i.rule_id = r.rule_id \
              AND i.admitted_at > ?1), \
             (SELECT COUNT(*) FROM admissions m WHERE m.rule_id = r.rule_id), \
             (SELECT MAX(m.admitted_at) FROM admissions m WHERE m.rule_id = r.rule_id) \
             FROM rules r JOIN admissions a ON a.plan_id = r.created_plan_id \
             ORDER BY a.admission_seq ASC",
        )?;
        let rows = statement
            .query_map(params![since], |r| {
                Ok(RuleInfo {
                    rule_id: r.get(0)?,
                    rule_jcs: r.get(1)?,
                    rule_digest_hex: r.get(2)?,
                    created_by_key_id: r.get(3)?,
                    created_plan_id: r.get(4)?,
                    installed_at: r.get(5)?,
                    revoked_at: r.get(6)?,
                    revoke_pending: r.get::<_, Option<String>>(7)?.is_some(),
                    invocations_last_hour: r.get(8)?,
                    match_count: r.get(9)?,
                    last_matched_at: r.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        // v1.0.11 (D-061): a rule with an admitted revocation stops
        // triggering before the runner's result records it.
        Ok(rows
            .into_iter()
            .filter(|rule| include_revoked || (rule.revoked_at.is_none() && !rule.revoke_pending))
            .collect())
    }

    /// Appends one encoded operation event; returns its per-operation seq.
    pub fn append_operation_event(
        &self,
        operation_id: &str,
        now: i64,
        encode: impl FnOnce(u64) -> String,
    ) -> Result<u64, StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM operation_events WHERE operation_id = ?1",
            params![operation_id],
            |r| r.get(0),
        )?;
        let seq_u = u64::try_from(seq).unwrap_or(1);
        tx.execute(
            "INSERT INTO operation_events (operation_id, seq, at, event) VALUES (?1, ?2, ?3, ?4)",
            params![operation_id, seq, format_timestamp(now), encode(seq_u)],
        )?;
        tx.commit()?;
        Ok(seq_u)
    }

    pub fn operation_events_after(
        &self,
        operation_id: &str,
        after_seq: u64,
    ) -> Result<Vec<(u64, String)>, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT seq, event FROM operation_events WHERE operation_id = ?1 AND seq > ?2 \
             ORDER BY seq ASC",
        )?;
        let rows = statement
            .query_map(params![operation_id, after_seq as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn prune_operation_events(&self, now: i64) -> Result<usize, StoreError> {
        let conn = self.lock();
        Ok(conn.execute(
            "DELETE FROM operation_events WHERE at < ?1",
            params![format_timestamp(now - OPERATION_EVENT_RETENTION_SECONDS)],
        )?)
    }
}

/// Execution deadline of an admission (section 6.2).
pub fn execution_deadline(admitted_at: &str) -> Option<i64> {
    timestamp(admitted_at).map(|at| at + EXECUTION_WINDOW_SECONDS)
}
