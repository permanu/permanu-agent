//! Section 6.1 steps 1–13 against the store, in one `BEGIN IMMEDIATE`
//! transaction: every `PolicyContext` read happens inside the write lock, so
//! the step 13 re-check (nonce/id, head, rule counter, delivery consumption)
//! is the same read, and a failure rolls back every reservation.

use std::collections::BTreeSet;

use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{new_uuid7, AdmissionStore};
use crate::signed_plan::crypto::hex;
use crate::signed_plan::jcs::{canonicalize, parse_strict};
use crate::signed_plan::schema::spec_elevated;
use crate::signed_plan::text::format_timestamp;
use crate::signed_plan::trust::{apply_change, TrustChange, TrustStore};
use crate::signed_plan::verify::{
    next_head, verify_signed_plan, DeliveryRecord, PolicyContext, RuleRecord, Submitter, Verdict,
    VerifiedPlan, GENESIS_HEAD, SKEW_SECONDS,
};
use crate::signed_plan::PlanCode;

const MAX_SEALED_SECRETS: usize = 64;
const MAX_SEALED_SECRET_BYTES: usize = 64 * 1024;
const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";
/// Kinds whose spec becomes the service's last admitted spec (section 3.7).
const LAST_SPEC_KINDS: &[&str] = &["deploy", "rollback", "scale"];

/// One submission.
#[derive(Debug, Clone)]
pub struct AdmitInput<'a> {
    pub envelope: &'a [u8],
    pub specs: &'a [String],
    pub sealed_secrets: &'a [Vec<u8>],
    pub submitter: Submitter,
    pub now: i64,
}

/// The admission (new or deduplicated).
#[derive(Debug, Clone)]
pub struct Admission {
    pub plan_id: String,
    pub plan_digest_hex: String,
    pub operation_id: String,
    pub admitted_at: String,
    pub deduplicated: bool,
    /// deployment id per action index (None for kinds without one).
    pub deployment_ids: Vec<Option<String>>,
}

pub(super) struct TxContext<'a> {
    pub(super) tx: &'a Transaction<'a>,
    pub(super) trust: &'a TrustStore,
    pub(super) now: i64,
}

fn internal(_: rusqlite::Error) -> PlanCode {
    PlanCode::Internal
}

impl PolicyContext for TxContext<'_> {
    fn now(&self) -> i64 {
        self.now
    }

    fn trust(&self) -> &TrustStore {
        self.trust
    }

    fn admission_digest(&self, plan_id: &str) -> Result<Option<String>, PlanCode> {
        self.tx
            .query_row(
                "SELECT plan_digest_hex FROM admissions WHERE plan_id = ?1",
                params![plan_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)
    }

    fn admission_signer_key_ids(
        &self,
        plan_id: &str,
        plan_digest_hex: &str,
    ) -> Result<Option<Vec<String>>, PlanCode> {
        let ids: Option<String> = self
            .tx
            .query_row(
                "SELECT signer_key_ids FROM admissions WHERE plan_id = ?1 \
                 AND plan_digest_hex = ?2",
                params![plan_id, plan_digest_hex],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?;
        ids.map(|text| serde_json::from_str(&text).map_err(|_| PlanCode::Internal))
            .transpose()
    }

    fn seen(&self, nonce: &str, plan_id: &str) -> Result<bool, PlanCode> {
        let count: i64 = self
            .tx
            .query_row(
                "SELECT (SELECT COUNT(*) FROM seen WHERE nonce = ?1 OR plan_id = ?2) + \
                 (SELECT COUNT(*) FROM admissions WHERE nonce = ?1 OR plan_id = ?2)",
                params![nonce, plan_id],
                |r| r.get(0),
            )
            .map_err(internal)?;
        Ok(count > 0)
    }

    fn head(&self, project_id: &str, environment: &str) -> Result<String, PlanCode> {
        Ok(self
            .tx
            .query_row(
                "SELECT head_digest_hex FROM heads WHERE project_id = ?1 AND environment = ?2",
                params![project_id, environment],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?
            .unwrap_or_else(|| GENESIS_HEAD.to_owned()))
    }

    fn rule(&self, rule_id: &str) -> Result<Option<RuleRecord>, PlanCode> {
        let row: Option<(String, String, String, Option<String>)> = self
            .tx
            .query_row(
                "SELECT rule, rule_digest_hex, created_by_key_id, revoked_at FROM rules \
                 WHERE rule_id = ?1",
                params![rule_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(internal)?;
        let Some((text, digest, creator, revoked_at)) = row else {
            return Ok(None);
        };
        let rule = parse_strict(text.as_bytes(), 64 * 1024).ok_or(PlanCode::Internal)?;
        Ok(Some(RuleRecord {
            rule,
            rule_digest_hex: digest,
            created_by_key_id: creator,
            revoked: revoked_at.is_some(),
        }))
    }

    fn rule_invocations_last_hour(&self, rule_id: &str) -> Result<u64, PlanCode> {
        let since = format_timestamp(self.now - 3_600);
        let count: i64 = self
            .tx
            .query_row(
                "SELECT COUNT(*) FROM rule_invocations WHERE rule_id = ?1 AND admitted_at > ?2",
                params![rule_id, since],
                |r| r.get(0),
            )
            .map_err(internal)?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    fn delivery(&self, delivery_id: &str) -> Result<Option<DeliveryRecord>, PlanCode> {
        type Row = (String, String, String, String, String, String, String);
        let row: Option<Row> = self
            .tx
            .query_row(
                "SELECT body_digest_hex, repo, ref, commit_sha, commit_time, received_at, status \
                 FROM deliveries WHERE delivery_id = ?1",
                params![delivery_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(internal)?;
        let Some((body, repo, r#ref, sha, time, received, status)) = row else {
            return Ok(None);
        };
        let mut statement = self
            .tx
            .prepare("SELECT rule_id FROM delivery_consumptions WHERE delivery_id = ?1")
            .map_err(internal)?;
        let consumed = statement
            .query_map(params![delivery_id], |r| r.get::<_, String>(0))
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        Ok(Some(DeliveryRecord {
            body_digest_hex: body,
            repo,
            r#ref,
            commit_sha: sha,
            commit_time: time,
            received_at: received,
            verified: status == "verified",
            consumed_by_rule_ids: consumed,
        }))
    }

    fn last_admitted_spec(&self, service_id: &str) -> Result<Option<Value>, PlanCode> {
        let text: Option<String> = self
            .tx
            .query_row(
                "SELECT s.spec_jcs FROM service_specs c JOIN specs s \
                 ON s.spec_digest_hex = c.spec_digest_hex WHERE c.service_id = ?1",
                params![service_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?;
        text.map(|t| parse_strict(t.as_bytes(), 16 * 1024).ok_or(PlanCode::Internal))
            .transpose()
    }

    fn build_image(&self, service_id: &str, commit_sha: &str) -> Result<Option<String>, PlanCode> {
        self.tx
            .query_row(
                "SELECT image_digest_hex FROM builds WHERE service_id = ?1 AND commit_sha = ?2",
                params![service_id, commit_sha],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)
    }

    fn deployed_commit(
        &self,
        service_id: &str,
        r#ref: &str,
    ) -> Result<Option<(String, String)>, PlanCode> {
        self.tx
            .query_row(
                "SELECT commit_sha, commit_time FROM deployed_commits \
                 WHERE service_id = ?1 AND ref = ?2",
                params![service_id, r#ref],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(internal)
    }
}

impl AdmissionStore {
    /// Refuses admissions during the store-loss quarantine (section 6.3).
    pub fn check_quarantine(&self, now: i64) -> Result<(), PlanCode> {
        match self.quarantine_ends_at().map_err(|_| PlanCode::Internal)? {
            Some(end) if now < end => Err(PlanCode::StoreQuarantined),
            _ => Ok(()),
        }
    }

    /// Section 6.1 steps 1–13. `trust` is the validated trust store.
    pub fn admit(&self, trust: &TrustStore, input: &AdmitInput<'_>) -> Result<Admission, PlanCode> {
        self.check_quarantine(input.now)?;
        let mut conn = self.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal)?;
        let ctx = TxContext {
            tx: &tx,
            trust,
            now: input.now,
        };
        let verdict = verify_signed_plan(input.envelope, input.specs, input.submitter, &ctx)?;
        let verified = match verdict {
            Verdict::Deduped {
                plan_id,
                digest_hex,
            } => {
                let (operation_id, admitted_at): (String, String) = tx
                    .query_row(
                        "SELECT operation_id, admitted_at FROM admissions WHERE plan_id = ?1",
                        params![plan_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(internal)?;
                return Ok(Admission {
                    plan_id,
                    plan_digest_hex: digest_hex,
                    operation_id,
                    admitted_at,
                    deduplicated: true,
                    deployment_ids: Vec::new(),
                });
            }
            Verdict::Admit(verified) => verified,
        };
        let sealed = execution_preconditions(&ctx, &verified, input.sealed_secrets)?;
        let admission = write_admission(&tx, &verified, input, &sealed)?;
        tx.commit().map_err(internal)?;
        Ok(admission)
    }

    /// Steps 1–12 plus the execution preconditions without writing anything
    /// (`VerifySignedPlan`).
    pub fn verify_only(
        &self,
        trust: &TrustStore,
        input: &AdmitInput<'_>,
    ) -> Result<Verdict, PlanCode> {
        self.check_quarantine(input.now)?;
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(internal)?;
        let ctx = TxContext {
            tx: &tx,
            trust,
            now: input.now,
        };
        let verdict = verify_signed_plan(input.envelope, input.specs, input.submitter, &ctx)?;
        if let Verdict::Admit(verified) = &verdict {
            execution_preconditions(&ctx, verified, input.sealed_secrets)?;
        }
        Ok(verdict)
    }
}

/// Implementation-specific checks after step 12 (section 6.1): they fail
/// `E_EXEC_PRECONDITION` and run before anything is written. Returns the
/// sealed secrets by digest.
fn execution_preconditions(
    ctx: &TxContext<'_>,
    verified: &VerifiedPlan,
    sealed_secrets: &[Vec<u8>],
) -> Result<Vec<(String, Vec<u8>)>, PlanCode> {
    let actions = verified.plan["actions"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    // Sealed secrets (section 3.2): exactly one ciphertext per signed digest.
    let wanted: BTreeSet<&str> = actions.iter().filter_map(sealed_digest).collect();
    if sealed_secrets.len() > MAX_SEALED_SECRETS {
        return Err(PlanCode::ExecPrecondition);
    }
    let mut supplied = Vec::new();
    for ciphertext in sealed_secrets {
        if ciphertext.len() > MAX_SEALED_SECRET_BYTES || !ciphertext.starts_with(AGE_HEADER) {
            return Err(PlanCode::ExecPrecondition);
        }
        let digest = hex(&Sha256::digest(ciphertext));
        if supplied.iter().any(|(d, _)| d == &digest) {
            return Err(PlanCode::ExecPrecondition);
        }
        supplied.push((digest, ciphertext.clone()));
    }
    let supplied_set: BTreeSet<&str> = supplied.iter().map(|(d, _)| d.as_str()).collect();
    if supplied_set != wanted {
        return Err(PlanCode::ExecPrecondition);
    }

    check_input_composition(ctx, verified)?;

    let mut trust = ctx.trust.clone();
    for action in actions {
        let params = &action["params"];
        match action["kind"].as_str().unwrap_or_default() {
            // The superset must validate and the lockout guard must hold
            // (section 7.4), checked in plan order.
            "key.add" | "key.revoke" => {
                let change = if action["kind"] == "key.add" {
                    TrustChange::AddKey(&params["entry"])
                } else {
                    TrustChange::Revoke(&params["revocation"])
                };
                let document = apply_change(Some(&trust), &change, trust.mode)
                    .map_err(|_| PlanCode::ExecPrecondition)?;
                trust = crate::signed_plan::trust::validate_trust(&document, trust.mode)
                    .map_err(|_| PlanCode::ExecPrecondition)?;
            }
            "rule.revoke" => {
                let rule = ctx
                    .rule(params["rule_id"].as_str().unwrap_or_default())?
                    .ok_or(PlanCode::ExecPrecondition)?;
                if rule.revoked || rule.rule_digest_hex != params["rule_digest_hex"] {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            "rule.create" => {
                if ctx
                    .rule(params["rule"]["id"].as_str().unwrap_or_default())?
                    .is_some()
                {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            "operation.cancel" => check_cancel(ctx, params)?,
            // v1.0.3 (D-035): an id already admitted on this server names
            // another release; the agent never reuses one.
            "deploy" => {
                let taken: i64 = ctx
                    .tx
                    .query_row(
                        "SELECT COUNT(*) FROM admission_actions WHERE deployment_id = ?1",
                        params![params["deployment_id"].as_str()],
                        |r| r.get(0),
                    )
                    .map_err(internal)?;
                if taken != 0 {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            "restart" => {
                // restart MUST name the service's currently admitted spec.
                let current: Option<String> = ctx
                    .tx
                    .query_row(
                        "SELECT spec_digest_hex FROM service_specs WHERE service_id = ?1",
                        params![params["service_id"].as_str()],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(internal)?;
                if current.as_deref() != params["spec_digest_hex"].as_str() {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            _ => {}
        }
    }
    Ok(supplied)
}

/// Input kinds never execute on their own on a server (section 3.2, D-028).
pub const INPUT_KINDS: &[&str] = &[
    "env.set",
    "secret.set",
    "secret.unset",
    "domain.add",
    "domain.remove",
    "domain.switch",
];

/// D-028: every input action is followed, later in the same plan, by a
/// `deploy` or `restart` of each service it affects. An environment-wide
/// secret affects every service of the scope whose spec (this plan's, else
/// the last admitted one) binds the name as `{kind: secret, ref: name}`; if none does,
/// it is stored and applies at the first deploy that binds it.
fn check_input_composition(ctx: &TxContext<'_>, verified: &VerifiedPlan) -> Result<(), PlanCode> {
    let actions = verified.plan["actions"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    if !actions
        .iter()
        .any(|a| INPUT_KINDS.contains(&a["kind"].as_str().unwrap_or_default()))
    {
        return Ok(());
    }
    let (project, environment) = verified.scope();
    // service_id -> spec, this plan's specs overriding the admitted ones.
    let mut specs: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    {
        let mut statement = ctx
            .tx
            .prepare(
                "SELECT c.service_id, s.spec_jcs FROM service_specs c \
                 JOIN specs s ON s.spec_digest_hex = c.spec_digest_hex \
                 JOIN admissions a ON a.plan_id = c.plan_id \
                 WHERE a.project_id = ?1 AND a.environment = ?2",
            )
            .map_err(internal)?;
        let rows = statement
            .query_map(params![project, environment], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        for (service, text) in rows {
            let spec = parse_strict(text.as_bytes(), 16 * 1024).ok_or(PlanCode::Internal)?;
            specs.insert(service, spec);
        }
    }
    for (spec, _) in verified.specs.values() {
        if let Some(service) = spec["service_id"].as_str() {
            specs.insert(service.to_owned(), spec.clone());
        }
    }
    for (index, action) in actions.iter().enumerate() {
        let kind = action["kind"].as_str().unwrap_or_default();
        if !INPUT_KINDS.contains(&kind) {
            continue;
        }
        let params = &action["params"];
        let affected: Vec<String> = match params["service_id"].as_str() {
            Some(service) => vec![service.to_owned()],
            None => {
                let name = params["name"].as_str().unwrap_or_default();
                specs
                    .iter()
                    .filter(|(_, spec)| {
                        spec["env"].as_object().is_some_and(|env| {
                            env.values()
                                .any(|b| b["kind"] == "secret" && b["ref"] == name)
                        })
                    })
                    .map(|(service, _)| service.clone())
                    .collect()
            }
        };
        for service in affected {
            let composed = actions[index + 1..].iter().any(|later| {
                matches!(later["kind"].as_str(), Some("deploy" | "restart"))
                    && later["params"]["service_id"] == service.as_str()
            });
            if !composed {
                return Err(PlanCode::ExecPrecondition);
            }
        }
    }
    Ok(())
}

/// The ciphertext digest an action signs (section 3.2, "Sealed secrets").
fn sealed_digest(action: &Value) -> Option<&str> {
    match action["kind"].as_str() {
        Some("secret.set") => action["params"]["ciphertext_digest_hex"].as_str(),
        Some("alert.channel.create" | "alert.channel.update") => {
            action["params"]["credential_ciphertext_digest_hex"].as_str()
        }
        _ => None,
    }
}

/// `operation.cancel`: the named admission exists with that digest. The ci
/// rule (a ci key cancels only plans it signed) is step 11 (D-033).
fn check_cancel(ctx: &TxContext<'_>, params: &Value) -> Result<(), PlanCode> {
    let digest: Option<String> = ctx
        .tx
        .query_row(
            "SELECT plan_digest_hex FROM admissions WHERE plan_id = ?1",
            params![params["plan_id"].as_str().unwrap_or_default()],
            |r| r.get(0),
        )
        .optional()
        .map_err(internal)?;
    match digest {
        Some(digest) if params["plan_digest_hex"] == digest.as_str() => Ok(()),
        _ => Err(PlanCode::ExecPrecondition),
    }
}

/// `admission_actions.deployment_id`, copied from the signed plan and never
/// minted (v1.0.3, D-035): a deploy's own id, the release a rollback returns
/// to; `None` for every other kind (restart and scale act on the active
/// release).
fn signed_deployment_id(kind: &str, params: &Value) -> Option<String> {
    match kind {
        "deploy" => params["deployment_id"].as_str().map(str::to_owned),
        "rollback" => crate::signed_plan::schema::rollback_target(params).map(str::to_owned),
        _ => None,
    }
}

fn write_admission(
    tx: &Transaction<'_>,
    verified: &VerifiedPlan,
    input: &AdmitInput<'_>,
    sealed: &[(String, Vec<u8>)],
) -> Result<Admission, PlanCode> {
    let plan = &verified.plan;
    let now = input.now;
    let admitted_at = format_timestamp(now);
    let plan_id = plan["id"].as_str().unwrap_or_default().to_owned();
    let nonce = plan["nonce"].as_str().unwrap_or_default();
    let expires_at = plan["expires_at"].as_str().unwrap_or_default();
    let (project, environment) = verified.scope();
    let unix_ms = u64::try_from(now).unwrap_or(0) * 1_000;
    let operation_id = new_uuid7(unix_ms);
    let envelope_text = std::str::from_utf8(input.envelope)
        .map_err(|_| PlanCode::Parse)?
        .to_owned();

    // Prune expired reservations: step 7 rejects those plans anyway.
    tx.execute(
        "DELETE FROM seen WHERE expires_at < ?1",
        params![format_timestamp(now - SKEW_SECONDS)],
    )
    .map_err(internal)?;
    tx.execute(
        "INSERT INTO seen (nonce, plan_id, plan_digest_hex, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![nonce, plan_id, verified.digest_hex, expires_at],
    )
    .map_err(|_| PlanCode::Replay)?;

    let head_before: String = tx
        .query_row(
            "SELECT head_digest_hex FROM heads WHERE project_id = ?1 AND environment = ?2",
            params![project, environment],
            |r| r.get(0),
        )
        .optional()
        .map_err(internal)?
        .unwrap_or_else(|| GENESIS_HEAD.to_owned());
    let head_after = next_head(&head_before, &verified.digest_hex);
    let seq: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(admission_seq), 0) + 1 FROM admissions",
            [],
            |r| r.get(0),
        )
        .map_err(internal)?;
    let kinds = verified.kinds();
    let invocation = &plan["invocation"];
    let rule_id = invocation["rule_id"].as_str();
    let delivery_id = invocation["evidence"]["delivery_id"].as_str();
    tx.execute(
        "INSERT INTO admissions (plan_id, plan_digest_hex, signed_plan_json, submitter, \
         operation_id, admitted_at, finished_at, outcome, admission_seq, nonce, author_kind, \
         signer_key_ids, action_kinds, project_id, environment, head_before_hex, \
         head_after_hex, rule_id, delivery_id, expires_at, environment_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, '', ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
         ?16, ?17, ?18, ?19)",
        params![
            plan_id,
            verified.digest_hex,
            envelope_text,
            input.submitter.as_str(),
            operation_id,
            admitted_at,
            seq,
            nonce,
            plan["author"]["kind"].as_str().unwrap_or_default(),
            serde_json::to_string(&verified.signer_key_ids()).map_err(|_| PlanCode::Internal)?,
            serde_json::to_string(&kinds).map_err(|_| PlanCode::Internal)?,
            project,
            environment,
            head_before,
            head_after,
            rule_id,
            delivery_id,
            expires_at,
            plan["environment_id"].as_str().unwrap_or_default(),
        ],
    )
    .map_err(|_| PlanCode::Replay)?;

    let mut deployment_ids = Vec::new();
    let actions = plan["actions"].as_array().map_or(&[][..], Vec::as_slice);
    for (index, kind) in kinds.iter().enumerate() {
        let deployment_id = signed_deployment_id(kind, &actions[index]["params"]);
        tx.execute(
            "INSERT INTO admission_actions (plan_id, action_index, kind, deployment_id) \
             VALUES (?1, ?2, ?3, ?4)",
            params![plan_id, index as i64, kind, deployment_id],
        )
        .map_err(internal)?;
        deployment_ids.push(deployment_id);
    }

    for (digest, (spec, text)) in &verified.specs {
        tx.execute(
            "INSERT OR IGNORE INTO specs (spec_digest_hex, service_id, spec_jcs, \
             admitted_plan_id, admitted_at, elevated) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                digest,
                spec["service_id"].as_str().unwrap_or_default(),
                text,
                plan_id,
                admitted_at,
                i64::from(spec_elevated(spec)),
            ],
        )
        .map_err(internal)?;
    }
    for action in plan["actions"].as_array().map_or(&[][..], Vec::as_slice) {
        let kind = action["kind"].as_str().unwrap_or_default();
        let params_value = &action["params"];
        if LAST_SPEC_KINDS.contains(&kind) {
            tx.execute(
                "INSERT INTO service_specs (service_id, spec_digest_hex, plan_id, admitted_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (service_id) DO UPDATE SET \
                 spec_digest_hex = excluded.spec_digest_hex, plan_id = excluded.plan_id, \
                 admitted_at = excluded.admitted_at",
                params![
                    params_value["service_id"].as_str(),
                    params_value["spec_digest_hex"].as_str(),
                    plan_id,
                    admitted_at
                ],
            )
            .map_err(internal)?;
        }
        if kind == "deploy" && !invocation.is_null() {
            let evidence = &invocation["evidence"];
            tx.execute(
                "INSERT INTO deployed_commits (service_id, ref, commit_sha, commit_time, plan_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (service_id, ref) DO UPDATE SET \
                 commit_sha = excluded.commit_sha, commit_time = excluded.commit_time, \
                 plan_id = excluded.plan_id",
                params![
                    params_value["service_id"].as_str(),
                    evidence["ref"].as_str(),
                    evidence["commit_sha"].as_str(),
                    evidence["commit_time"].as_str(),
                    plan_id
                ],
            )
            .map_err(internal)?;
        }
        match kind {
            "rule.create" => {
                let rule = &params_value["rule"];
                let text = canonicalize(rule).ok_or(PlanCode::Parse)?;
                let digest = hex(&crate::signed_plan::crypto::prefixed_digest(
                    crate::signed_plan::crypto::RULE_PREFIX,
                    &text,
                ));
                let creator = verified
                    .signers
                    .iter()
                    .find(|s| s["role"] == "owner" && s["presence"] != "none")
                    .and_then(|s| s["key_id"].as_str())
                    .ok_or(PlanCode::TouchIdRequired)?;
                tx.execute(
                    "INSERT INTO rules (rule, rule_digest_hex, created_by_key_id, \
                     created_plan_id, revoked_at, rule_id, revoked_plan_id) \
                     VALUES (?1, ?2, ?3, ?4, NULL, ?5, NULL)",
                    params![text, digest, creator, plan_id, rule["id"].as_str()],
                )
                .map_err(|_| PlanCode::ExecPrecondition)?;
            }
            "rule.revoke" => {
                let changed = tx
                    .execute(
                        "UPDATE rules SET revoked_at = ?1, revoked_plan_id = ?2 \
                         WHERE rule_id = ?3 AND rule_digest_hex = ?4 AND revoked_at IS NULL",
                        params![
                            admitted_at,
                            plan_id,
                            params_value["rule_id"].as_str(),
                            params_value["rule_digest_hex"].as_str()
                        ],
                    )
                    .map_err(internal)?;
                if changed != 1 {
                    return Err(PlanCode::ExecPrecondition);
                }
            }
            _ => {}
        }
    }

    tx.execute(
        "INSERT INTO heads (project_id, environment, head_digest_hex, plan_id, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (project_id, environment) DO UPDATE SET \
         head_digest_hex = excluded.head_digest_hex, plan_id = excluded.plan_id, \
         updated_at = excluded.updated_at",
        params![project, environment, head_after, plan_id, admitted_at],
    )
    .map_err(internal)?;

    if let (Some(rule_id), Some(delivery_id)) = (rule_id, delivery_id) {
        tx.execute(
            "DELETE FROM rule_invocations WHERE admitted_at <= ?1",
            params![format_timestamp(now - 3_600)],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT INTO rule_invocations (rule_id, plan_id, admitted_at) VALUES (?1, ?2, ?3)",
            params![rule_id, plan_id, admitted_at],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT INTO delivery_consumptions (delivery_id, rule_id, plan_id, consumed_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![delivery_id, rule_id, plan_id, admitted_at],
        )
        .map_err(|_| PlanCode::RuleEvidence)?;
    }

    // v1.0.2 (D-027): stored with the signing action and its scope; only
    // the runner decrypts.
    for (digest, ciphertext) in sealed {
        let (index, action) = plan["actions"]
            .as_array()
            .and_then(|actions| {
                actions
                    .iter()
                    .enumerate()
                    .find(|(_, a)| sealed_digest(a) == Some(digest.as_str()))
            })
            .ok_or(PlanCode::ExecPrecondition)?;
        let secret = action["kind"] == "secret.set";
        let text = |value: &Value| value.as_str().unwrap_or_default().to_owned();
        let (scope_project, scope_environment, service_id, name) = if secret {
            (
                project.clone(),
                environment.clone(),
                text(&action["params"]["service_id"]),
                text(&action["params"]["name"]),
            )
        } else {
            Default::default()
        };
        tx.execute(
            "INSERT OR IGNORE INTO sealed_secrets (ciphertext_digest_hex, plan_id, ciphertext, \
             action_index, project_id, environment, service_id, name) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                digest,
                plan_id,
                ciphertext,
                index as i64,
                scope_project,
                scope_environment,
                service_id,
                name
            ],
        )
        .map_err(internal)?;
    }

    Ok(Admission {
        plan_id,
        plan_digest_hex: verified.digest_hex.clone(),
        operation_id,
        admitted_at,
        deduplicated: false,
        deployment_ids,
    })
}
