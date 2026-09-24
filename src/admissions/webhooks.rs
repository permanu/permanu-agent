//! Webhook bookkeeping in `admissions.db` (signed-plan.md 3.5 steps 3–5,
//! 6.4; agent-protocol.md 11): verified deliveries, rejected deliveries and
//! the images the runner built for rule deploys. The agent owns these rows;
//! the runner never reads them (its evidence is its own `delivery` and
//! `build` lines, section 14.5).

use rusqlite::{params, ErrorCode, OptionalExtension};
use serde_json::Value;

use super::{AdmissionStore, StoreError};
use crate::signed_plan::jcs::parse_strict;
use crate::signed_plan::text::format_timestamp;

/// A delivery `webhook_verify` verified (section 3.5 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRow {
    pub delivery_id: String,
    pub provider: String,
    pub event: String,
    pub body_digest_hex: String,
    pub repo: String,
    pub r#ref: String,
    pub commit_sha: String,
    pub commit_time: String,
    pub environments: Vec<String>,
    pub received_at: String,
    pub expires_at: String,
    pub status: String,
}

/// Why a delivery was not authenticated (`rejected_deliveries.reason`).
/// `unknown_project` is never written: a project with no webhook secret
/// leaves only a counter (agent-protocol.md 11.1 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Signature,
    Malformed,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Malformed => "malformed",
        }
    }
}

/// A verified delivery is kept 30 days (agent-protocol.md 11.1 step 9)
/// unless an admission or build cites it.
pub const DELIVERY_RETENTION_SECONDS: i64 = 30 * 86_400;
/// `rejected_deliveries` rows are kept 7 days (section 6.4).
pub const REJECTED_RETENTION_SECONDS: i64 = 7 * 86_400;

/// Rows `rejected_deliveries` holds at most (7 days at the pre-auth
/// budget would otherwise be millions).
pub const MAX_REJECTED_ROWS: i64 = 100_000;

/// The rule plan's inputs for one service: its last admitted spec.
#[derive(Debug, Clone, PartialEq)]
pub struct LastSpec {
    pub spec: Value,
    pub spec_digest_hex: String,
}

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryRow> {
    let environments: String = r.get(8)?;
    Ok(DeliveryRow {
        delivery_id: r.get(0)?,
        provider: r.get(1)?,
        event: r.get(2)?,
        body_digest_hex: r.get(3)?,
        repo: r.get(4)?,
        r#ref: r.get(5)?,
        commit_sha: r.get(6)?,
        commit_time: r.get(7)?,
        environments: serde_json::from_str(&environments).unwrap_or_default(),
        received_at: r.get(9)?,
        expires_at: r.get(10)?,
        status: r.get(11)?,
    })
}

const DELIVERY_COLUMNS: &str = "delivery_id, provider, event, body_digest_hex, repo, ref, \
     commit_sha, commit_time, environments, received_at, expires_at, status";

impl AdmissionStore {
    /// Records a verified delivery. `Ok(false)`: a delivery with the same
    /// `body_digest_hex` exists (DUPLICATE, section 3.5 step 3).
    pub fn insert_delivery(&self, row: &DeliveryRow) -> Result<bool, StoreError> {
        let environments = serde_json::to_string(&row.environments)
            .map_err(|err| StoreError::Unsafe(err.to_string()))?;
        let inserted = self.lock().execute(
            &format!("INSERT INTO deliveries ({DELIVERY_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"),
            params![
                row.delivery_id,
                row.provider,
                row.event,
                row.body_digest_hex,
                row.repo,
                row.r#ref,
                row.commit_sha,
                row.commit_time,
                environments,
                row.received_at,
                row.expires_at,
                row.status
            ],
        );
        match inserted {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == ErrorCode::ConstraintViolation =>
            {
                Ok(false)
            }
            Err(err) => Err(err.into()),
        }
    }

    pub fn delivery_row(&self, delivery_id: &str) -> Result<Option<DeliveryRow>, StoreError> {
        Ok(self
            .lock()
            .query_row(
                &format!("SELECT {DELIVERY_COLUMNS} FROM deliveries WHERE delivery_id = ?1"),
                params![delivery_id],
                row_of,
            )
            .optional()?)
    }

    pub fn set_delivery_status(&self, delivery_id: &str, status: &str) -> Result<(), StoreError> {
        self.lock().execute(
            "UPDATE deliveries SET status = ?2 WHERE delivery_id = ?1",
            params![delivery_id, status],
        )?;
        Ok(())
    }

    /// Moves a `pending` delivery to `status` atomically; false when another
    /// path already moved it (or it does not exist). The single gate every
    /// processing path passes, so a delivery is never processed twice.
    pub fn claim_delivery(&self, delivery_id: &str, status: &str) -> Result<bool, StoreError> {
        let claimed = self
            .lock()
            .query_row(
                "UPDATE deliveries SET status = ?2 WHERE delivery_id = ?1 AND status = 'pending' \
                 RETURNING delivery_id",
                params![delivery_id, status],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(claimed.is_some())
    }

    /// Records an unauthenticated delivery: never the body (section 6.4).
    /// At most [`MAX_REJECTED_ROWS`] rows are kept; beyond that only the
    /// caller's counter grows (a flood cannot fill the disk).
    pub fn insert_rejected_delivery(
        &self,
        body_digest_hex: &str,
        body_bytes: u64,
        project_id: &str,
        provider: &str,
        received_at: &str,
        reason: RejectReason,
    ) -> Result<(), StoreError> {
        self.lock().execute(
            "INSERT INTO rejected_deliveries (body_digest_hex, body_bytes, project_id, provider, \
             received_at, reason) SELECT ?1, ?2, ?3, ?4, ?5, ?6 \
             WHERE (SELECT COUNT(*) FROM rejected_deliveries) < ?7",
            params![
                body_digest_hex,
                i64::try_from(body_bytes).unwrap_or(i64::MAX),
                project_id,
                provider,
                received_at,
                reason.as_str(),
                MAX_REJECTED_ROWS
            ],
        )?;
        Ok(())
    }

    /// Rejected deliveries received after `since` (`rejected_24h`).
    pub fn rejected_since(&self, since: i64) -> Result<u32, StoreError> {
        let count: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM rejected_deliveries WHERE received_at > ?1",
            params![format_timestamp(since)],
            |r| r.get(0),
        )?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Section 11.1 step 9: `pending` deliveries past `expires_at` become
    /// `expired`; returns their ids. Also prunes rejected rows after 7
    /// days and delivery rows after 30 days that nothing cites.
    pub fn expire_deliveries(&self, now: i64) -> Result<Vec<String>, StoreError> {
        let conn = self.lock();
        let at = format_timestamp(now);
        // One statement: a delivery claimed meanwhile is never expired.
        let expired = {
            let mut statement = conn.prepare(
                "UPDATE deliveries SET status = 'expired' WHERE status = 'pending' \
                 AND expires_at <= ?1 RETURNING delivery_id",
            )?;
            let ids = statement
                .query_map(params![at], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids
        };
        conn.execute(
            "DELETE FROM rejected_deliveries WHERE received_at <= ?1",
            params![format_timestamp(now - REJECTED_RETENTION_SECONDS)],
        )?;
        conn.execute(
            "DELETE FROM deliveries WHERE received_at <= ?1 \
             AND delivery_id NOT IN (SELECT delivery_id FROM delivery_consumptions) \
             AND delivery_id NOT IN (SELECT delivery_id FROM builds WHERE delivery_id IS NOT NULL) \
             AND delivery_id NOT IN (SELECT delivery_id FROM admissions WHERE delivery_id IS NOT NULL)",
            params![format_timestamp(now - DELIVERY_RETENTION_SECONDS)],
        )?;
        Ok(expired)
    }

    /// Records the image the runner built (section 3.5 step 5); a second
    /// build of the same `(service_id, commit_sha)` keeps the first row.
    pub fn record_build(
        &self,
        build_id: &str,
        service_id: &str,
        commit_sha: &str,
        image_digest_hex: &str,
        delivery_id: &str,
        built_at: i64,
    ) -> Result<(), StoreError> {
        self.lock().execute(
            "INSERT INTO builds (build_id, service_id, commit_sha, image_digest_hex, delivery_id, \
             built_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (service_id, commit_sha) \
             DO UPDATE SET image_digest_hex = excluded.image_digest_hex, \
             build_id = excluded.build_id, delivery_id = excluded.delivery_id, \
             built_at = excluded.built_at",
            params![
                build_id,
                service_id,
                commit_sha,
                image_digest_hex,
                delivery_id,
                format_timestamp(built_at)
            ],
        )?;
        Ok(())
    }

    /// The service's last admitted spec (section 3.7), if any.
    pub fn last_spec(&self, service_id: &str) -> Result<Option<LastSpec>, StoreError> {
        let row: Option<(String, String)> = self
            .lock()
            .query_row(
                "SELECT s.spec_jcs, s.spec_digest_hex FROM service_specs c JOIN specs s \
                 ON s.spec_digest_hex = c.spec_digest_hex WHERE c.service_id = ?1",
                params![service_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(text, digest)| {
            parse_strict(text.as_bytes(), 16 * 1024).map(|spec| LastSpec {
                spec,
                spec_digest_hex: digest,
            })
        }))
    }

    /// `(project_id, environment, environment_id)` of an admission.
    pub fn admission_signed_scope(
        &self,
        plan_id: &str,
    ) -> Result<Option<(String, String, String)>, StoreError> {
        Ok(self
            .lock()
            .query_row(
                "SELECT project_id, environment, environment_id FROM admissions WHERE plan_id = ?1",
                params![plan_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// `(commit_sha, commit_time)` the service last deployed on `ref`.
    pub fn deployed_commit_on(
        &self,
        service_id: &str,
        r#ref: &str,
    ) -> Result<Option<(String, String)>, StoreError> {
        Ok(self
            .lock()
            .query_row(
                "SELECT commit_sha, commit_time FROM deployed_commits \
                 WHERE service_id = ?1 AND ref = ?2",
                params![service_id, r#ref],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Whether `env.protection.set` protects the scope (section 14.10).
    pub fn scope_protected(&self, project_id: &str, environment: &str) -> Result<bool, StoreError> {
        Ok(super::definitions::environment_protected(
            &self.lock(),
            project_id,
            environment,
        )?)
    }
}

/// Test seeding: rows the webhook path reads, written directly.
#[cfg(test)]
pub(crate) mod seed {
    use rusqlite::params;
    use serde_json::Value;

    use super::AdmissionStore;
    use crate::signed_plan::crypto::{hex, prefixed_digest, SPEC_PREFIX};
    use crate::signed_plan::jcs::canonicalize;

    /// A `rules` row created by the admitted plan `plan_id`.
    pub fn rule(store: &AdmissionStore, rule: &Value, digest: &str, creator: &str, plan_id: &str) {
        store
            .lock()
            .execute(
                "INSERT INTO rules (rule, rule_digest_hex, created_by_key_id, created_plan_id, \
                 revoked_at, rule_id, revoked_plan_id) VALUES (?1, ?2, ?3, ?4, NULL, ?5, NULL)",
                params![
                    canonicalize(rule).unwrap(),
                    digest,
                    creator,
                    plan_id,
                    rule["id"].as_str()
                ],
            )
            .unwrap();
    }

    pub fn revoke_rule(store: &AdmissionStore, rule_id: &str, at: &str) {
        store
            .lock()
            .execute(
                "UPDATE rules SET revoked_at = ?2 WHERE rule_id = ?1",
                params![rule_id, at],
            )
            .unwrap();
    }

    /// The service's last admitted spec, admitted by `plan_id`.
    pub fn spec(store: &AdmissionStore, spec: &Value, plan_id: &str) -> String {
        let text = canonicalize(spec).unwrap();
        let digest = hex(&prefixed_digest(SPEC_PREFIX, &text));
        let conn = store.lock();
        conn.execute(
            "INSERT OR IGNORE INTO specs (spec_digest_hex, service_id, spec_jcs, admitted_plan_id, \
             admitted_at) VALUES (?1, ?2, ?3, ?4, '2026-09-23T10:00:00Z')",
            params![digest, spec["service_id"].as_str(), text, plan_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO service_specs (service_id, spec_digest_hex, plan_id, admitted_at) \
             VALUES (?1, ?2, ?3, '2026-09-23T10:00:00Z')",
            params![spec["service_id"].as_str(), digest, plan_id],
        )
        .unwrap();
        digest
    }

    pub fn deployed_commit(
        store: &AdmissionStore,
        service: &str,
        r#ref: &str,
        sha: &str,
        time: &str,
        plan_id: &str,
    ) {
        store
            .lock()
            .execute(
                "INSERT INTO deployed_commits (service_id, ref, commit_sha, commit_time, plan_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![service, r#ref, sha, time, plan_id],
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admissions::definitions::tests::open;
    use crate::signed_plan::text::timestamp;

    fn delivery(id: &str, digest: &str, status: &str) -> DeliveryRow {
        DeliveryRow {
            delivery_id: id.to_owned(),
            provider: "github".to_owned(),
            event: "push".to_owned(),
            body_digest_hex: digest.to_owned(),
            repo: "github.com/acme/web".to_owned(),
            r#ref: "refs/heads/main".to_owned(),
            commit_sha: "4f".repeat(20),
            commit_time: "2026-09-23T09:59:30Z".to_owned(),
            environments: vec!["production".to_owned()],
            received_at: "2026-09-23T10:00:00Z".to_owned(),
            expires_at: "2026-09-30T10:00:00Z".to_owned(),
            status: status.to_owned(),
        }
    }

    #[test]
    fn a_body_digest_is_recorded_once() {
        let (dir, store) = open("hooks-dedupe");
        assert!(store
            .insert_delivery(&delivery("d-1", &"a".repeat(64), "pending"))
            .unwrap());
        assert!(!store
            .insert_delivery(&delivery("d-2", &"a".repeat(64), "pending"))
            .unwrap());
        let row = store.delivery_row("d-1").unwrap().unwrap();
        assert_eq!(row.environments, vec!["production"]);
        assert!(store.delivery_row("d-2").unwrap().is_none());
        store.set_delivery_status("d-1", "building").unwrap();
        assert_eq!(
            store.delivery_row("d-1").unwrap().unwrap().status,
            "building"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Only one caller can move a delivery out of `pending`.
    #[test]
    fn a_pending_delivery_is_claimed_once() {
        let (dir, store) = open("hooks-claim");
        store
            .insert_delivery(&delivery("d-1", &"a".repeat(64), "pending"))
            .unwrap();
        store
            .insert_delivery(&delivery("d-2", &"b".repeat(64), "deployed"))
            .unwrap();
        assert!(store.claim_delivery("d-1", "building").unwrap());
        assert!(!store.claim_delivery("d-1", "building").unwrap());
        assert!(!store.claim_delivery("d-1", "stale").unwrap());
        assert!(!store.claim_delivery("d-2", "building").unwrap());
        assert!(!store.claim_delivery("d-3", "building").unwrap());
        assert_eq!(
            store.delivery_row("d-1").unwrap().unwrap().status,
            "building"
        );
        // A claimed delivery never expires under it.
        let after = timestamp("2026-09-30T10:00:00Z").unwrap();
        assert!(store.expire_deliveries(after).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pending_deliveries_expire_and_old_rows_are_pruned() {
        let (dir, store) = open("hooks-expire");
        store
            .insert_delivery(&delivery("d-1", &"a".repeat(64), "pending"))
            .unwrap();
        store
            .insert_delivery(&delivery("d-2", &"b".repeat(64), "deployed"))
            .unwrap();
        let before = timestamp("2026-09-29T10:00:00Z").unwrap();
        assert!(store.expire_deliveries(before).unwrap().is_empty());
        let after = timestamp("2026-09-30T10:00:00Z").unwrap();
        assert_eq!(store.expire_deliveries(after).unwrap(), vec!["d-1"]);
        assert_eq!(
            store.delivery_row("d-1").unwrap().unwrap().status,
            "expired"
        );
        store
            .insert_rejected_delivery(
                &"c".repeat(64),
                10,
                "p",
                "github",
                "2026-09-23T10:00:00Z",
                RejectReason::Signature,
            )
            .unwrap();
        assert_eq!(
            store
                .rejected_since(timestamp("2026-09-23T09:00:00Z").unwrap())
                .unwrap(),
            1
        );
        // 30 days later both deliveries and the rejected row are gone.
        let month = timestamp("2026-10-24T10:00:00Z").unwrap();
        store.expire_deliveries(month).unwrap();
        assert!(store.delivery_row("d-1").unwrap().is_none());
        assert!(store.delivery_row("d-2").unwrap().is_none());
        assert_eq!(store.rejected_since(0).unwrap(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_build_row_keeps_one_image_per_service_and_commit() {
        let (dir, store) = open("hooks-builds");
        store
            .insert_delivery(&delivery("d-1", &"a".repeat(64), "building"))
            .unwrap();
        let now = timestamp("2026-09-23T10:01:00Z").unwrap();
        store
            .record_build("b-1", "svc", &"4f".repeat(20), &"e".repeat(64), "d-1", now)
            .unwrap();
        store
            .record_build("b-2", "svc", &"4f".repeat(20), &"f".repeat(64), "d-1", now)
            .unwrap();
        let image: String = store
            .lock()
            .query_row(
                "SELECT image_digest_hex FROM builds WHERE service_id = 'svc'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(image, "f".repeat(64));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
