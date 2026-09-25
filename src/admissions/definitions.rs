//! Admitted definition actions read back from `admissions.db` (contracts
//! v1.1.0 scope binding, section 6.1 step 11; agent-protocol.md 10): the
//! scope of a named service or cron job, the backup policies a new policy
//! must not narrow, environment protection, and the cron / backup / alert
//! definitions the schedulers run.
//!
//! Every value comes from the stored signed envelope of an admitted plan,
//! never from a request.

use rusqlite::{params, Connection};
use serde_json::Value;

use std::collections::BTreeSet;

use crate::signed_plan::jcs::parse_strict;
use crate::signed_plan::verify::SignedScope;
use crate::signed_plan::verify::MAX_SIGNED_PLAN_BYTES;
use crate::signed_plan::PlanCode;

/// One action of an admitted plan with its reconciled outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedAction {
    pub plan_id: String,
    pub plan_digest_hex: String,
    pub action_index: usize,
    pub admission_seq: i64,
    pub admitted_at: String,
    pub operation_id: String,
    pub kind: String,
    pub params: Value,
    pub scope: SignedScope,
    /// `''` while not finished, else the consumed-log result.
    pub outcome: String,
    pub finished_at: Option<String>,
}

impl AdmittedAction {
    /// Applied: the runner recorded `result succeeded` for it.
    pub fn succeeded(&self) -> bool {
        self.outcome == "succeeded"
    }

    /// Ended without effect (failed, cancelled, expired or rolled back).
    pub fn void(&self) -> bool {
        !self.outcome.is_empty() && !self.succeeded()
    }
}

/// Every admitted action whose kind is one of `kinds`, newest admission
/// first (and, within one plan, the last action first).
pub fn admitted_actions(
    conn: &Connection,
    kinds: &[&str],
) -> Result<Vec<AdmittedAction>, rusqlite::Error> {
    let mut statement = conn.prepare_cached(
        "SELECT a.plan_id, a.plan_digest_hex, a.admission_seq, a.admitted_at, \
         a.signed_plan_json, a.project_id, a.environment, a.environment_id, \
         x.action_index, x.kind, x.outcome, x.finished_at, a.operation_id \
         FROM admission_actions x JOIN admissions a ON a.plan_id = x.plan_id \
         WHERE x.kind IN (SELECT value FROM json_each(?1)) \
         ORDER BY a.admission_seq DESC, x.action_index DESC",
    )?;
    let wanted = serde_json::to_string(kinds).unwrap_or_else(|_| "[]".to_owned());
    let rows = statement.query_map(params![wanted], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            (
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ),
            r.get::<_, i64>(8)?,
            r.get::<_, String>(9)?,
            r.get::<_, String>(10)?,
            r.get::<_, Option<String>>(11)?,
            r.get::<_, String>(12)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (
            plan_id,
            digest,
            seq,
            admitted_at,
            envelope,
            scope,
            index,
            kind,
            outcome,
            finished,
            operation_id,
        ) = row?;
        let Some(envelope) = parse_strict(envelope.as_bytes(), MAX_SIGNED_PLAN_BYTES) else {
            continue;
        };
        let Ok(action_index) = usize::try_from(index) else {
            continue;
        };
        let action = &envelope["plan"]["actions"][action_index];
        if action["kind"] != kind.as_str() {
            continue;
        }
        out.push(AdmittedAction {
            plan_id,
            plan_digest_hex: digest,
            action_index,
            admission_seq: seq,
            admitted_at,
            operation_id,
            kind,
            params: action["params"].clone(),
            scope,
            outcome,
            finished_at: finished,
        });
    }
    Ok(out)
}

/// The admitted definitions of one object, newest first, down to and
/// including the newest applied one; void actions are skipped. The applied
/// one is what the runner recorded; the newer ones may still apply.
fn current_and_pending(actions: impl IntoIterator<Item = AdmittedAction>) -> Vec<AdmittedAction> {
    let mut out = Vec::new();
    for action in actions {
        if action.void() {
            continue;
        }
        let applied = action.succeeded();
        out.push(action);
        if applied {
            break;
        }
    }
    out
}

/// Scope of the service: the signed scope of an admitted spec of it.
pub fn service_scope(
    conn: &Connection,
    service_id: &str,
) -> Result<Option<SignedScope>, rusqlite::Error> {
    let mut statement = conn.prepare_cached(
        "SELECT a.project_id, a.environment, a.environment_id FROM specs s \
         JOIN admissions a ON a.plan_id = s.admitted_plan_id \
         WHERE s.service_id = ?1 ORDER BY a.admission_seq DESC LIMIT 1",
    )?;
    let mut rows = statement.query(params![service_id])?;
    match rows.next()? {
        Some(row) => Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?))),
        None => Ok(None),
    }
}

/// Scope of a cron job: the signed scope of its admitted `cron.create`.
pub fn cron_scope(
    conn: &Connection,
    cron_id: &str,
) -> Result<Option<SignedScope>, rusqlite::Error> {
    Ok(admitted_actions(conn, &["cron.create"])?
        .into_iter()
        .rev()
        .find(|action| action.params["cron_id"] == cron_id)
        .map(|action| action.scope))
}

/// The `backup.policy.set` params a new policy of `resource_id` is compared
/// with: the applied one and any admitted after it that may still apply.
/// An applied `backup.policy.delete` ends the history.
pub fn backup_policies(
    conn: &Connection,
    resource_id: &str,
) -> Result<Vec<Value>, rusqlite::Error> {
    let history = admitted_actions(conn, &["backup.policy.set", "backup.policy.delete"])?
        .into_iter()
        .filter(|action| action.params["resource_id"] == resource_id);
    Ok(current_and_pending(history)
        .into_iter()
        .filter(|action| action.kind == "backup.policy.set")
        .map(|action| action.params)
        .collect())
}

/// Whether the scope is protected: its applied `env.protection.set`, or one
/// admitted after it, says so (fail closed while a change is pending).
pub fn environment_protected(
    conn: &Connection,
    project_id: &str,
    environment: &str,
) -> Result<bool, rusqlite::Error> {
    let history = admitted_actions(conn, &["env.protection.set"])?
        .into_iter()
        .filter(|action| action.scope.0 == project_id && action.scope.1 == environment);
    Ok(current_and_pending(history)
        .iter()
        .any(|action| action.params["protected"] == true))
}

/// agent-protocol.md 10.1: at most 256 cron jobs per server.
pub const MAX_CRON_JOBS: usize = 256;

/// The cron jobs admitted and not deleted (void actions ignored).
fn current_cron_ids(conn: &Connection) -> Result<BTreeSet<String>, rusqlite::Error> {
    let mut ids = BTreeSet::new();
    for action in admitted_actions(conn, &["cron.create", "cron.delete"])?
        .iter()
        .rev()
        .filter(|a| !a.void())
    {
        let id = action.params["cron_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if action.kind == "cron.create" {
            ids.insert(id);
        } else {
            ids.remove(&id);
        }
    }
    Ok(ids)
}

/// Execution preconditions of the cron and backup kinds (agent-protocol.md
/// 10.1, 10.2; section 6.1 after step 12, `E_EXEC_PRECONDITION`): a named
/// service or resource has an admitted spec here, a named job exists (and a
/// new one does not), at most 256 jobs, and a destination in use by a
/// policy is not deleted.
pub fn definition_preconditions(conn: &Connection, plan: &Value) -> Result<(), PlanCode> {
    let internal = |_: rusqlite::Error| PlanCode::Internal;
    let actions = plan["actions"].as_array().map_or(&[][..], Vec::as_slice);
    let kinds: Vec<&str> = actions.iter().filter_map(|a| a["kind"].as_str()).collect();
    let touches_cron = kinds.iter().any(|k| k.starts_with("cron."));
    let mut jobs = if touches_cron {
        current_cron_ids(conn).map_err(internal)?
    } else {
        BTreeSet::new()
    };
    let has_spec = |id: &Value| -> Result<bool, PlanCode> {
        Ok(service_scope(conn, id.as_str().unwrap_or_default())
            .map_err(internal)?
            .is_some())
    };
    for action in actions {
        let params = &action["params"];
        let cron_id = params["cron_id"].as_str().unwrap_or_default().to_owned();
        match action["kind"].as_str().unwrap_or_default() {
            "cron.create" => {
                if !has_spec(&params["service_id"])?
                    || jobs.contains(&cron_id)
                    || jobs.len() >= MAX_CRON_JOBS
                {
                    return Err(PlanCode::ExecPrecondition);
                }
                jobs.insert(cron_id);
            }
            "cron.update" => {
                if !has_spec(&params["service_id"])? || !jobs.contains(&cron_id) {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            "cron.delete" => {
                if !jobs.remove(&cron_id) {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            "cron.pause" | "cron.resume" | "cron.run" => {
                if !jobs.contains(&cron_id) {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            // v1.0.11 (D-061): a restore may target a service an earlier
            // deploy of this plan creates; the source must exist here.
            "restore" => {
                let target = &params["resource_id"];
                let deployed_here = actions
                    .iter()
                    .take_while(|a| !std::ptr::eq(*a, action))
                    .any(|a| a["kind"] == "deploy" && a["params"]["service_id"] == *target);
                let source = params.get("source_resource_id").unwrap_or(target);
                if !(deployed_here || has_spec(target)?) || !has_spec(source)? {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            "backup.run"
            | "backup.verify"
            | "backup.delete"
            | "backup.policy.set"
            | "backup.policy.delete" => {
                if !has_spec(&params["resource_id"])? {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            "backup.destination.delete" => {
                let reference = &params["destination_ref"];
                let mut policies = std::collections::BTreeMap::new();
                for policy in admitted_actions(conn, &["backup.policy.set", "backup.policy.delete"])
                    .map_err(internal)?
                    .iter()
                    .rev()
                    .filter(|a| !a.void())
                {
                    let resource = policy.params["resource_id"].as_str().unwrap_or_default();
                    if policy.kind == "backup.policy.set" {
                        policies.insert(
                            resource.to_owned(),
                            policy.params["destination_ref"].clone(),
                        );
                    } else {
                        policies.remove(resource);
                    }
                }
                if policies.values().any(|used| used == reference) {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

impl super::AdmissionStore {
    /// Every admitted action of these kinds, newest first (see
    /// [`admitted_actions`]).
    pub fn admitted_actions(
        &self,
        kinds: &[&str],
    ) -> Result<Vec<AdmittedAction>, super::StoreError> {
        Ok(admitted_actions(&self.lock(), kinds)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use rusqlite::params;
    use serde_json::{json, Value};

    use super::super::{AdmissionStore, StoreConfig};
    use super::*;
    use crate::signed_plan::test_support::temp_dir;
    use crate::signed_plan::text::timestamp;

    pub const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";
    pub const ENV_ID: &str = "01a0cdb5-3500-70b2-8000-000000000001";

    pub fn open(name: &str) -> (std::path::PathBuf, AdmissionStore) {
        let dir = temp_dir(name);
        let config = StoreConfig {
            path: dir.join("agent/admissions.db"),
            owner: None,
        };
        let now = timestamp("2026-09-23T10:00:00Z").unwrap();
        let (store, _) = AdmissionStore::open(&config, false, now).unwrap();
        (dir, store)
    }

    /// Records an admitted plan with `actions` in `scope` directly (the
    /// definition readers trust the admission row, never a request).
    pub fn record(
        store: &AdmissionStore,
        seq: i64,
        scope: (&str, &str, &str),
        actions: &[Value],
        outcome: &str,
    ) -> String {
        record_at(store, seq, scope, actions, outcome, "2026-09-23T10:00:00Z")
    }

    /// [`record`] admitted (and, with an outcome, finished) at `at`.
    pub fn record_at(
        store: &AdmissionStore,
        seq: i64,
        scope: (&str, &str, &str),
        actions: &[Value],
        outcome: &str,
        at: &str,
    ) -> String {
        let plan_id = format!("01a0cdb5-3500-7001-8000-{seq:012x}");
        let envelope = json!({"plan": {"id": plan_id, "actions": actions}, "signatures": []});
        let kinds: Vec<&str> = actions.iter().filter_map(|a| a["kind"].as_str()).collect();
        let conn = store.lock();
        conn.execute(
            "INSERT INTO admissions (plan_id, plan_digest_hex, signed_plan_json, submitter, \
             operation_id, admitted_at, admission_seq, nonce, author_kind, signer_key_ids, \
             action_kinds, project_id, environment, environment_id, head_before_hex, \
             head_after_hex, expires_at) VALUES (?1, ?2, ?3, 'client', ?1, \
             ?9, ?4, ?1, 'user', '[]', ?5, ?6, ?7, ?8, ?2, ?2, ?9)",
            params![
                plan_id,
                format!("{seq:064x}"),
                envelope.to_string(),
                seq,
                serde_json::to_string(&kinds).unwrap(),
                scope.0,
                scope.1,
                scope.2,
                at
            ],
        )
        .unwrap();
        for (index, kind) in kinds.iter().enumerate() {
            conn.execute(
                "INSERT INTO admission_actions (plan_id, action_index, kind, outcome, finished_at) \
                 VALUES (?1, ?2, ?3, ?4, CASE WHEN ?4 = '' THEN NULL ELSE ?5 END)",
                params![plan_id, index as i64, kind, outcome, at],
            )
            .unwrap();
        }
        plan_id
    }

    /// Sets the deployment id of every action of an admitted plan (what
    /// admission records for a `deploy`).
    pub fn set_deployment(store: &AdmissionStore, plan_id: &str, deployment_id: &str) {
        store
            .lock()
            .execute(
                "UPDATE admission_actions SET deployment_id = ?2 WHERE plan_id = ?1",
                params![plan_id, deployment_id],
            )
            .unwrap();
    }

    /// Ends every action of an admitted plan with `outcome` (what the
    /// consumed-log reconciliation does).
    pub fn finish(store: &AdmissionStore, plan_id: &str, outcome: &str, at: &str) {
        store
            .lock()
            .execute(
                "UPDATE admission_actions SET outcome = ?2, finished_at = ?3 WHERE plan_id = ?1",
                params![plan_id, outcome, at],
            )
            .unwrap();
    }

    fn seed_spec(store: &AdmissionStore, plan_id: &str, service_id: &str) {
        store
            .lock()
            .execute(
                "INSERT INTO specs (spec_digest_hex, service_id, spec_jcs, admitted_plan_id, \
                 admitted_at) VALUES (?1, ?2, '{}', ?3, '2026-09-23T10:00:00Z')",
                params![format!("{:064x}", 7), service_id, plan_id],
            )
            .unwrap();
    }

    #[test]
    fn cron_and_backup_kinds_need_their_objects() {
        let (dir, store) = open("definitions-preconditions");
        let scope = (PROJECT, "production", ENV_ID);
        let web = "01a0cdb5-3500-70c1-8000-000000000001";
        let cron = "01a0cdb5-3500-70d2-8000-000000000001";
        let deploy = record(
            &store,
            1,
            scope,
            &[json!({"kind": "deploy", "params": {}})],
            "succeeded",
        );
        let plan = |actions: Value| json!({"actions": actions});
        let create = json!({"kind": "cron.create", "params": {"cron_id": cron, "service_id": web}});
        let run = json!({"kind": "cron.run", "params": {"cron_id": cron}});
        let check = |p: &Value| definition_preconditions(&store.lock(), p);
        // No admitted spec of the service yet.
        assert_eq!(
            check(&plan(json!([create]))),
            Err(PlanCode::ExecPrecondition)
        );
        seed_spec(&store, &deploy, web);
        assert_eq!(check(&plan(json!([create]))), Ok(()));
        assert_eq!(
            check(&plan(json!([run]))),
            Err(PlanCode::ExecPrecondition),
            "unknown job"
        );
        assert_eq!(
            check(&plan(json!([create, run]))),
            Ok(()),
            "created by the same plan"
        );
        record(&store, 2, scope, std::slice::from_ref(&create), "succeeded");
        assert_eq!(check(&plan(json!([run]))), Ok(()));
        assert_eq!(
            check(&plan(json!([create]))),
            Err(PlanCode::ExecPrecondition),
            "id taken"
        );
        let delete = json!({"kind": "cron.delete", "params": {"cron_id": cron}});
        record(&store, 3, scope, &[delete], "succeeded");
        assert_eq!(
            check(&plan(json!([run]))),
            Err(PlanCode::ExecPrecondition),
            "deleted"
        );
        let backup =
            |resource: &str| json!({"kind": "backup.run", "params": {"resource_id": resource}});
        assert_eq!(check(&plan(json!([backup(web)]))), Ok(()));
        assert_eq!(
            check(&plan(json!([backup(
                "01a0cdb5-3500-70c1-8000-000000000099"
            )]))),
            Err(PlanCode::ExecPrecondition)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_destination_in_use_is_not_deleted() {
        let (dir, store) = open("definitions-destination");
        let scope = (PROJECT, "production", ENV_ID);
        let res = "01a0cdb5-3500-70d1-8000-000000000001";
        record(&store, 1, scope, &[policy(res, 7, "offsite")], "succeeded");
        let delete = |r: &str| {
            json!({"actions": [{"kind": "backup.destination.delete",
            "params": {"destination_ref": r}}]})
        };
        assert_eq!(
            definition_preconditions(&store.lock(), &delete("offsite")),
            Err(PlanCode::ExecPrecondition)
        );
        assert_eq!(
            definition_preconditions(&store.lock(), &delete("other")),
            Ok(())
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// v1.0.11 (D-061): a restore into a service the same plan deploys
    /// first needs no admitted spec of the target, but its source must have
    /// one here.
    #[test]
    fn a_restore_into_a_new_service_needs_the_source_and_an_earlier_deploy() {
        let (dir, store) = open("definitions-restore-new");
        let scope = (PROJECT, "production", ENV_ID);
        let pg = "01a0cdb5-3500-70c1-8000-000000000011";
        let fresh = "01a0cdb5-3500-70c1-8000-000000000012";
        let backup = "01a0cdb5-3500-70d3-8000-000000000001";
        let deploy_plan = record(
            &store,
            1,
            scope,
            &[json!({"kind": "deploy", "params": {}})],
            "succeeded",
        );
        seed_spec(&store, &deploy_plan, pg);
        let deploy_new = json!({"kind": "deploy", "params": {"service_id": fresh}});
        let restore = |source: &str| {
            json!({"kind": "restore", "params": {"resource_id": fresh, "backup_id": backup,
                "backup_digest_hex": "00".repeat(32), "origin": "server",
                "source_resource_id": source}})
        };
        let check =
            |actions: Value| definition_preconditions(&store.lock(), &json!({"actions": actions}));
        assert_eq!(check(json!([deploy_new.clone(), restore(pg)])), Ok(()));
        assert_eq!(
            check(json!([restore(pg)])),
            Err(PlanCode::ExecPrecondition),
            "no deploy of the target"
        );
        assert_eq!(
            check(json!([deploy_new, restore(fresh)])),
            Err(PlanCode::ExecPrecondition),
            "the source has no spec here"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn policy(resource: &str, keep_daily: i64, destination: &str) -> Value {
        json!({"kind": "backup.policy.set", "params": {"resource_id": resource,
            "schedule": "0 3 * * *", "timezone": "UTC", "keep_daily": keep_daily,
            "keep_weekly": 4, "keep_monthly": 6, "verify_schedule": null,
            "destination_ref": destination}})
    }

    #[test]
    fn backup_policies_are_the_applied_one_and_newer_pending_ones() {
        let (dir, store) = open("definitions-policies");
        let scope = (PROJECT, "production", ENV_ID);
        let res = "01a0cdb5-3500-70d1-8000-000000000001";
        record(&store, 1, scope, &[policy(res, 1, "old")], "succeeded");
        record(&store, 2, scope, &[policy(res, 7, "offsite")], "succeeded");
        record(&store, 3, scope, &[policy(res, 30, "offsite")], "failed");
        record(&store, 4, scope, &[policy(res, 14, "offsite")], "");
        let conn = store.lock();
        let found: Vec<i64> = backup_policies(&conn, res)
            .unwrap()
            .iter()
            .map(|p| p["keep_daily"].as_i64().unwrap())
            .collect();
        assert_eq!(
            found,
            [14, 7],
            "pending newest first, void skipped, stop at applied"
        );
        assert!(backup_policies(&conn, "other").unwrap().is_empty());
        drop(conn);
        let delete = json!({"kind": "backup.policy.delete", "params": {"resource_id": res}});
        record(&store, 5, scope, &[delete], "succeeded");
        assert!(backup_policies(&store.lock(), res).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protection_and_cron_scope_come_from_admitted_actions() {
        let (dir, store) = open("definitions-protection");
        let staging = (PROJECT, "staging", "01a0cdb5-3500-70b2-8000-000000000003");
        let protect = |on: bool| {
            json!({"kind": "env.protection.set",
                   "params": {"environment": "staging", "protected": on}})
        };
        assert!(!environment_protected(&store.lock(), PROJECT, "staging").unwrap());
        record(&store, 1, staging, &[protect(true)], "succeeded");
        assert!(environment_protected(&store.lock(), PROJECT, "staging").unwrap());
        assert!(!environment_protected(&store.lock(), PROJECT, "production").unwrap());
        // An unprotect is only in force once the runner recorded it.
        record(&store, 2, staging, &[protect(false)], "");
        assert!(environment_protected(&store.lock(), PROJECT, "staging").unwrap());
        store
            .lock()
            .execute_batch("UPDATE admission_actions SET outcome = 'succeeded'")
            .unwrap();
        assert!(!environment_protected(&store.lock(), PROJECT, "staging").unwrap());

        let cron = "01a0cdb5-3500-70d2-8000-000000000001";
        let create = json!({"kind": "cron.create", "params": {"cron_id": cron}});
        record(&store, 3, staging, &[create], "succeeded");
        assert_eq!(
            cron_scope(&store.lock(), cron).unwrap(),
            Some((
                PROJECT.to_owned(),
                "staging".to_owned(),
                staging.2.to_owned()
            ))
        );
        assert_eq!(cron_scope(&store.lock(), "other").unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
