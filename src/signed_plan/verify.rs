//! The ordered verification of signed-plan.md section 6.1 (steps 1–12) and
//! the bootstrap of section 7.3. Step 13 (the write) belongs to the store,
//! which runs this inside its `BEGIN IMMEDIATE` transaction so every read of
//! `PolicyContext` is already the in-transaction re-check.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::crypto::{
    b64url_decode, hex, parse_spki_base64, prefixed_digest, PLAN_PREFIX, RULE_PREFIX, SPEC_PREFIX,
};
use super::jcs::{canonicalize, parse_strict};
use super::schema::{check, spec_elevated, validate_plan, SIGNATURE, SPEC, SPEC_KINDS};
use super::text;
use super::trust::TrustStore;
use super::PlanCode;

pub const MAX_SIGNED_PLAN_BYTES: usize = 64 * 1024;
pub const MAX_SPEC_BYTES: usize = 16 * 1024;
pub const MAX_SPECS: usize = 64;
pub const SKEW_SECONDS: i64 = 120;
pub const MAX_LIFETIME_SECONDS: i64 = 900;
pub const WEBHOOK_TTL_SECONDS: i64 = 900;
pub const GENESIS_HEAD: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Always-Touch-ID kinds (section 3.2, D-013, D-016).
pub const TID_KINDS: &[&str] = &[
    "agent.update",
    "component.update",
    "secret.set",
    "secret.unset",
    "restore",
    "server.add",
    "shell.open",
    "rule.create",
    "rule.revoke",
    "key.add",
    "key.revoke",
    "service.elevate",
    "service.delete",
    "environment.delete",
    "project.delete",
    "server.remove",
    // v1.0.19 (D-069): owner, fresh.
    "server.accounts.migrate",
    "volume.delete",
    "bucket.delete",
    "bucket.credentials.rotate",
    "backup.delete",
    // v1.0.7 (D-049, D-051): recovery recipient, backup destination
    // credential, environment protection, release keys.
    "recovery_recipient.set",
    "backup.destination.set",
    "env.protection.set",
    "release_key.add",
    "release_key.revoke",
    // v1.0.9 (D-057): repository credentials.
    "repo.credential.set",
    "repo.credential.delete",
];
/// Kinds only an owner may sign (TID kinds plus the owner-only presence kinds).
const OWNER_ONLY_PRESENCE: &[&str] = &[
    "db.upgrade",
    "backup.policy.delete",
    "backup.destination.delete",
    // v1.0.11 (D-061).
    "webhook.host.set",
];
const CI_KINDS: &[&str] = &["deploy", "rollback", "restart", "operation.cancel"];
/// Rule-eligible kinds (signed-plan.md 3.4). `scale` is contracts v1.2.1 (D-072).
const RULE_ELIGIBLE: &[&str] = &["deploy", "scale"];

fn role_allows(role: &str, kind: &str) -> bool {
    match role {
        "owner" => true,
        "deployer" => !TID_KINDS.contains(&kind) && !OWNER_ONLY_PRESENCE.contains(&kind),
        "ci" => CI_KINDS.contains(&kind),
        _ => false,
    }
}

/// The path a plan arrived on. Never a request field (section 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitter {
    Client,
    AgentWebhook,
}

impl Submitter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::AgentWebhook => "agent_webhook",
        }
    }
}

/// A standing rule as stored by the agent.
#[derive(Debug, Clone)]
pub struct RuleRecord {
    pub rule: Value,
    pub rule_digest_hex: String,
    pub created_by_key_id: String,
    pub revoked: bool,
}

/// A verified webhook delivery (section 3.5 step 3).
#[derive(Debug, Clone)]
pub struct DeliveryRecord {
    pub body_digest_hex: String,
    pub repo: String,
    pub r#ref: String,
    pub commit_sha: String,
    pub commit_time: String,
    pub received_at: String,
    pub verified: bool,
    pub consumed_by_rule_ids: Vec<String>,
    /// v1.0.8: the environments whose webhook secret matched.
    pub environments: Vec<String>,
}

/// The signed scope `(project_id, environment, environment_id)` of an
/// admitted object, `""` for server-level fields (section 6.4).
pub type SignedScope = (String, String, String);

/// The server's own state, read by steps 6r–12. Nothing here comes from the
/// request. Store failures are `PlanCode::Internal` (fail closed).
pub trait PolicyContext {
    fn now(&self) -> i64;
    fn trust(&self) -> &TrustStore;
    /// Digest of the admission with this plan id, if any (step 8).
    fn admission_digest(&self, plan_id: &str) -> Result<Option<String>, PlanCode>;
    /// Signer key ids of the admission with this id and digest, if any
    /// (step 11: a `ci` key may cancel only a plan it signed, D-033).
    fn admission_signer_key_ids(
        &self,
        plan_id: &str,
        plan_digest_hex: &str,
    ) -> Result<Option<Vec<String>>, PlanCode>;
    /// Whether the nonce or plan id is already reserved (step 8).
    fn seen(&self, nonce: &str, plan_id: &str) -> Result<bool, PlanCode>;
    /// Current head of a scope; genesis when none (step 9).
    fn head(&self, project_id: &str, environment: &str) -> Result<String, PlanCode>;
    fn rule(&self, rule_id: &str) -> Result<Option<RuleRecord>, PlanCode>;
    fn rule_invocations_last_hour(&self, rule_id: &str) -> Result<u64, PlanCode>;
    fn delivery(&self, delivery_id: &str) -> Result<Option<DeliveryRecord>, PlanCode>;
    fn last_admitted_spec(&self, service_id: &str) -> Result<Option<Value>, PlanCode>;
    fn build_image(&self, service_id: &str, commit_sha: &str) -> Result<Option<String>, PlanCode>;
    /// v1.0.11 (D-061): when the runner's build of the service and commit
    /// started (its `build_started` line) and ended (its `build` line), in
    /// Unix seconds; `None` for a time this server does not know.
    fn build_window(
        &self,
        service_id: &str,
        commit_sha: &str,
    ) -> Result<(Option<i64>, Option<i64>), PlanCode>;
    /// (commit_sha, commit_time) the service last deployed on `ref`.
    fn deployed_commit(
        &self,
        service_id: &str,
        r#ref: &str,
    ) -> Result<Option<(String, String)>, PlanCode>;
    /// contracts v1.1.0: the signed scope of the admission with this id and
    /// digest (an `operation.cancel` takes the cancelled plan's scope).
    fn admission_scope(
        &self,
        plan_id: &str,
        plan_digest_hex: &str,
    ) -> Result<Option<SignedScope>, PlanCode>;
    /// contracts v1.1.0: the signed scope of an admitted spec of the service.
    fn service_scope(&self, service_id: &str) -> Result<Option<SignedScope>, PlanCode>;
    /// contracts v1.1.0: the signed scope of the job's admitted `cron.create`.
    fn cron_scope(&self, cron_id: &str) -> Result<Option<SignedScope>, PlanCode>;
    /// contracts v1.1.0: the backup policies (`backup.policy.set` params) a
    /// new policy of the resource must not narrow without a fresh owner
    /// signature: the recorded one and any admitted after it.
    fn backup_policies(&self, resource_id: &str) -> Result<Vec<Value>, PlanCode>;
    /// v1.0.7: whether `env.protection.set` protects the scope (recorded, or
    /// admitted and not yet applied).
    fn environment_protected(&self, project_id: &str, environment: &str) -> Result<bool, PlanCode>;
}

/// A plan that passed steps 1–12.
#[derive(Debug, Clone)]
pub struct VerifiedPlan {
    pub plan: Value,
    pub digest_hex: String,
    /// Trusted-key entries of the valid signers, in signature order.
    pub signers: Vec<Value>,
    /// spec_digest_hex → (spec, JCS text).
    pub specs: BTreeMap<String, (Value, String)>,
}

impl VerifiedPlan {
    pub fn kinds(&self) -> Vec<String> {
        self.plan["actions"]
            .as_array()
            .map(|actions| {
                actions
                    .iter()
                    .filter_map(|a| a["kind"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn signer_key_ids(&self) -> Vec<String> {
        self.signers
            .iter()
            .filter_map(|s| s["key_id"].as_str().map(str::to_owned))
            .collect()
    }

    pub fn scope(&self) -> (String, String) {
        (
            self.plan["project_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            self.plan["environment"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    }
}

/// Result of steps 1–12.
#[derive(Debug, Clone)]
pub enum Verdict {
    Admit(Box<VerifiedPlan>),
    /// Step 8 idempotent success: same id and digest already admitted.
    Deduped {
        plan_id: String,
        digest_hex: String,
    },
}

/// Parses one `ServiceSpec` JCS text: strict, schema-valid and byte-canonical.
pub fn parse_spec(spec_text: &str) -> Option<(Value, String)> {
    if spec_text.len() > MAX_SPEC_BYTES {
        return None;
    }
    let spec = parse_strict(spec_text.as_bytes(), MAX_SPEC_BYTES)?;
    if !check(&SPEC, &spec) || canonicalize(&spec)? != spec_text {
        return None;
    }
    let digest = hex(&prefixed_digest(SPEC_PREFIX, spec_text));
    Some((spec, digest))
}

/// Step 3s.
fn bind_specs(plan: &Value, spec_texts: &[String]) -> Option<BTreeMap<String, (Value, String)>> {
    if spec_texts.len() > MAX_SPECS {
        return None;
    }
    let mut specs = BTreeMap::new();
    for spec_text in spec_texts {
        let (spec, digest) = parse_spec(spec_text)?;
        if specs.insert(digest, (spec, spec_text.clone())).is_some() {
            return None;
        }
    }
    let actions = plan["actions"].as_array()?;
    let elevations: BTreeSet<&str> = actions
        .iter()
        .filter(|action| action["kind"] == "service.elevate")
        .filter_map(|action| action["params"]["spec_digest_hex"].as_str())
        .collect();
    let mut wanted = BTreeSet::new();
    for action in actions {
        let kind = action["kind"].as_str()?;
        let params = &action["params"];
        let upgrade_spec = kind == "db.upgrade" && params.get("spec_digest_hex").is_some();
        if !SPEC_KINDS.contains(&kind) && !upgrade_spec {
            continue;
        }
        let digest = params["spec_digest_hex"].as_str()?;
        let (spec, _) = specs.get(digest)?;
        let service = if upgrade_spec {
            &params["resource_id"]
        } else {
            &params["service_id"]
        };
        if spec["service_id"] != *service
            || (kind == "scale" && spec["replicas"] != params["replicas"])
            || (kind != "service.elevate" && spec_elevated(spec) && !elevations.contains(digest))
        {
            return None;
        }
        wanted.insert(digest.to_owned());
    }
    (specs.keys().cloned().collect::<BTreeSet<_>>() == wanted).then_some(specs)
}

/// Steps 1–3: strict envelope parse and schema.
pub fn parse_envelope(text: &[u8]) -> Result<(Value, Vec<Value>), PlanCode> {
    let value = parse_strict(text, MAX_SIGNED_PLAN_BYTES).ok_or(PlanCode::Parse)?;
    let Value::Object(mut map) = value else {
        return Err(PlanCode::Parse);
    };
    if map.len() != 2 || !map.get("plan").is_some_and(Value::is_object) {
        return Err(PlanCode::Parse);
    }
    let signatures = map.remove("signatures").ok_or(PlanCode::Parse)?;
    let plan = map.remove("plan").ok_or(PlanCode::Parse)?;
    if plan.get("version").and_then(Value::as_i64) != Some(1) {
        return Err(PlanCode::Version);
    }
    let Value::Array(signatures) = signatures else {
        return Err(PlanCode::Parse);
    };
    let distinct: BTreeSet<String> = signatures
        .iter()
        .map(|sig| sig["key_id"].to_string())
        .collect();
    if !validate_plan(&plan)
        || signatures.len() > 4
        || !signatures.iter().all(|sig| check(&SIGNATURE, sig))
        || distinct.len() != signatures.len()
    {
        return Err(PlanCode::Parse);
    }
    Ok((plan, signatures))
}

pub fn plan_digest_hex(plan: &Value) -> Result<String, PlanCode> {
    let canonical = canonicalize(plan).ok_or(PlanCode::Parse)?;
    Ok(hex(&prefixed_digest(PLAN_PREFIX, &canonical)))
}

/// Section 3.6: `head' = SHA-256("permanu-state-v1\n" || head || "\n" || digest)`.
pub fn next_head(head_hex: &str, plan_digest_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"permanu-state-v1\n");
    hasher.update(head_hex.as_bytes());
    hasher.update(b"\n");
    hasher.update(plan_digest_hex.as_bytes());
    hex(&hasher.finalize())
}

/// Section 6.1 steps 1–12, in order, stopping at the first failure.
pub fn verify_signed_plan(
    text: &[u8],
    spec_texts: &[String],
    submitter: Submitter,
    ctx: &dyn PolicyContext,
) -> Result<Verdict, PlanCode> {
    let (plan, signatures) = parse_envelope(text)?;
    let specs = bind_specs(&plan, spec_texts).ok_or(PlanCode::SpecMismatch)?;
    let trust = ctx.trust();
    let targets_self = plan["targets"]
        .as_array()
        .is_some_and(|targets| targets.iter().any(|t| t == trust.server_id.as_str()));
    if !targets_self {
        return Err(PlanCode::Target);
    }
    let author = plan["author"]["kind"].as_str().unwrap_or_default();
    let is_rule = author == "rule";
    let has_invocation = !plan["invocation"].is_null();
    let authority_ok = if is_rule {
        signatures.is_empty() && has_invocation && submitter == Submitter::AgentWebhook
    } else {
        !signatures.is_empty() && !has_invocation
    };
    if !authority_ok {
        return Err(PlanCode::Author);
    }
    let canonical = canonicalize(&plan).ok_or(PlanCode::Parse)?;
    let digest = prefixed_digest(PLAN_PREFIX, &canonical);
    let digest_hex = hex(&digest);
    let mut signers = Vec::new();
    for signature in &signatures {
        signers.push(verify_signature(signature, &digest, trust)?);
    }
    let rule = if is_rule {
        Some(verify_rule(&plan["invocation"], trust, ctx)?)
    } else {
        None
    };

    // Step 7.
    let now = ctx.now();
    check_time(&plan, now)?;

    // Step 8.
    let plan_id = plan["id"].as_str().unwrap_or_default();
    if ctx.admission_digest(plan_id)?.as_deref() == Some(digest_hex.as_str()) {
        return Ok(Verdict::Deduped {
            plan_id: plan_id.to_owned(),
            digest_hex,
        });
    }
    let nonce = plan["nonce"].as_str().unwrap_or_default();
    if ctx.seen(nonce, plan_id)? || ctx.admission_digest(plan_id)?.is_some() {
        return Err(PlanCode::Replay);
    }

    // Step 9.
    let project = plan["project_id"].as_str().unwrap_or_default();
    let environment = plan["environment"].as_str().unwrap_or_default();
    if plan["base"]["force"] == true {
        if is_rule || !signers.iter().any(|s| s["role"] == "owner") {
            return Err(PlanCode::ForceForbidden);
        }
    } else {
        let head = ctx.head(project, environment)?;
        if plan["base"]["heads"][trust.server_id.as_str()] != head.as_str() {
            return Err(PlanCode::BaseMismatch);
        }
    }

    // Step 10.
    let kinds: Vec<&str> = plan["actions"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x["kind"].as_str()).collect())
        .unwrap_or_default();
    if (kinds.iter().any(|kind| TID_KINDS.contains(kind)) || policy_narrows(&plan, ctx)?)
        && (is_rule
            || !signers
                .iter()
                .any(|s| s["role"] == "owner" && s["presence"] != "none"))
    {
        return Err(PlanCode::TouchIdRequired);
    }

    // Step 11.
    for kind in &kinds {
        if let Some(record) = &rule {
            let allowed = record.rule["allowed_kinds"]
                .as_array()
                .is_some_and(|k| k.iter().any(|x| x == kind));
            if !allowed || !RULE_ELIGIBLE.contains(kind) {
                return Err(PlanCode::KindForbidden);
            }
            continue;
        }
        let mut allowed: Vec<&Value> = signers
            .iter()
            .filter(|s| role_allows(s["role"].as_str().unwrap_or_default(), kind))
            .collect();
        if *kind == "operation.cancel" {
            // contracts v1.1.0: the cancel plan's signed scope is the
            // cancelled plan's, environment_id included.
            let params = &plan["actions"][0]["params"];
            let cancelled = ctx.admission_scope(
                params["plan_id"].as_str().unwrap_or_default(),
                params["plan_digest_hex"].as_str().unwrap_or_default(),
            )?;
            if cancelled.is_some_and(|scope| scope != signed_scope(&plan)) {
                return Err(PlanCode::ScopeMismatch);
            }
        }
        if *kind == "operation.cancel" && allowed.iter().any(|s| s["role"] == "ci") {
            // A ci key counts only for a cancel of an admitted plan it signed
            // itself (section 6.1 step 11, D-033).
            let params = &plan["actions"][0]["params"];
            let cancelled = ctx.admission_signer_key_ids(
                params["plan_id"].as_str().unwrap_or_default(),
                params["plan_digest_hex"].as_str().unwrap_or_default(),
            )?;
            allowed.retain(|s| {
                s["role"] != "ci"
                    || cancelled.as_ref().is_some_and(|ids| {
                        s["key_id"]
                            .as_str()
                            .is_some_and(|id| ids.iter().any(|x| x == id))
                    })
            });
        }
        if allowed.is_empty() {
            return Err(PlanCode::KindForbidden);
        }
        if !allowed.iter().any(|s| scope_covers(s, &plan)) {
            return Err(PlanCode::KeyScope);
        }
    }

    // contracts v1.1.0: a named service, resource or cron job of another
    // scope. An unknown name is not decided here.
    if rule.is_none() && !names_in_scope(&plan, ctx)? {
        return Err(PlanCode::ScopeMismatch);
    }

    // Step 12.
    if let Some(record) = &rule {
        check_rule(&plan, &record.rule, ctx, now, &specs)?;
    }
    Ok(Verdict::Admit(Box::new(VerifiedPlan {
        plan,
        digest_hex,
        signers,
        specs,
    })))
}

/// Step 7: lifetime, then not-yet-valid, then expired, with 120 s skew.
pub fn check_time(plan: &Value, now: i64) -> Result<(), PlanCode> {
    let created = timestamp(&plan["created_at"])?;
    let expires = timestamp(&plan["expires_at"])?;
    let lifetime = expires - created;
    if !(0 < lifetime && lifetime <= MAX_LIFETIME_SECONDS) {
        return Err(PlanCode::Lifetime);
    }
    if created > now + SKEW_SECONDS {
        return Err(PlanCode::NotYetValid);
    }
    if now > expires + SKEW_SECONDS {
        return Err(PlanCode::Expired);
    }
    Ok(())
}

fn timestamp(value: &Value) -> Result<i64, PlanCode> {
    value
        .as_str()
        .and_then(text::timestamp)
        .ok_or(PlanCode::Parse)
}

fn verify_signature(
    signature: &Value,
    digest: &[u8; 32],
    trust: &TrustStore,
) -> Result<Value, PlanCode> {
    if signature["alg"] != "ES256-raw" {
        return Err(PlanCode::SigAlg);
    }
    let key_id = signature["key_id"].as_str().unwrap_or_default();
    let key = trust
        .keys
        .get(key_id)
        .filter(|_| !trust.is_test_key(key_id))
        .ok_or(PlanCode::KeyUnknown)?;
    if trust.revoked.contains(key_id) {
        return Err(PlanCode::KeyRevoked);
    }
    let raw = signature["sig"]
        .as_str()
        .and_then(b64url_decode)
        .ok_or(PlanCode::Parse)?;
    if key.public_key.verify_prehash(digest, &raw) {
        Ok(key.entry.clone())
    } else {
        Err(PlanCode::SigInvalid)
    }
}

fn verify_rule(
    invocation: &Value,
    trust: &TrustStore,
    ctx: &dyn PolicyContext,
) -> Result<RuleRecord, PlanCode> {
    let rule_id = invocation["rule_id"].as_str().unwrap_or_default();
    let claimed = invocation["rule_digest_hex"].as_str().unwrap_or_default();
    let record = ctx.rule(rule_id)?.ok_or(PlanCode::RuleUnknown)?;
    let recomputed =
        canonicalize(&record.rule).map(|canonical| hex(&prefixed_digest(RULE_PREFIX, &canonical)));
    if record.rule["id"] != rule_id
        || record.rule_digest_hex != claimed
        || recomputed.as_deref() != Some(claimed)
    {
        return Err(PlanCode::RuleUnknown);
    }
    if record.revoked || trust.compromised.contains(&record.created_by_key_id) {
        return Err(PlanCode::RuleRevoked);
    }
    Ok(record)
}

/// Key scope (section 7.2).
fn scope_covers(signer: &Value, plan: &Value) -> bool {
    let scope = &signer["scope"];
    if scope.is_null() {
        return true;
    }
    if plan["project_id"].is_null() {
        return scope["server_level"] == true;
    }
    let contains = |field: &str, value: &Value| {
        scope[field]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == value))
    };
    contains("project_ids", &plan["project_id"]) && contains("environments", &plan["environment"])
}

/// `(project_id, environment, environment_id)` of a plan, `""` for null.
fn signed_scope(plan: &Value) -> SignedScope {
    let field = |name: &str| plan[name].as_str().unwrap_or_default().to_owned();
    (
        field("project_id"),
        field("environment"),
        field("environment_id"),
    )
}

/// Kinds whose service or resource must belong to the plan's scope.
const SERVICE_PARAM_KINDS: &[(&str, &str)] = &[
    ("cron.create", "service_id"),
    ("cron.update", "service_id"),
    ("backup.run", "resource_id"),
    ("backup.verify", "resource_id"),
    ("backup.policy.set", "resource_id"),
    ("backup.policy.delete", "resource_id"),
    ("backup.delete", "resource_id"),
    ("restore", "resource_id"),
];
/// Kinds whose `cron_id` must be a job of the plan's scope.
const CRON_ID_KINDS: &[&str] = &[
    "cron.update",
    "cron.delete",
    "cron.pause",
    "cron.resume",
    "cron.run",
];

fn names_in_scope(plan: &Value, ctx: &dyn PolicyContext) -> Result<bool, PlanCode> {
    let scope = signed_scope(plan);
    for action in plan["actions"].as_array().map_or(&[][..], Vec::as_slice) {
        let kind = action["kind"].as_str().unwrap_or_default();
        let params = &action["params"];
        if let Some((_, field)) = SERVICE_PARAM_KINDS.iter().find(|(k, _)| *k == kind) {
            let id = params[*field].as_str().unwrap_or_default();
            if ctx.service_scope(id)?.is_some_and(|found| found != scope) {
                return Ok(false);
            }
        }
        // v1.0.11 (D-061): the resource whose backup a restore reads.
        if kind == "restore" {
            if let Some(source) = params["source_resource_id"].as_str() {
                if ctx
                    .service_scope(source)?
                    .is_some_and(|found| found != scope)
                {
                    return Ok(false);
                }
            }
        }
        if CRON_ID_KINDS.contains(&kind) {
            let id = params["cron_id"].as_str().unwrap_or_default();
            if ctx.cron_scope(id)?.is_some_and(|found| found != scope) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// contracts v1.1.0: a `backup.policy.set` that lowers a `keep_*` value of,
/// or changes the destination of, a policy of the resource is always-fresh.
fn policy_narrows(plan: &Value, ctx: &dyn PolicyContext) -> Result<bool, PlanCode> {
    for action in plan["actions"].as_array().map_or(&[][..], Vec::as_slice) {
        if action["kind"] != "backup.policy.set" {
            continue;
        }
        let params = &action["params"];
        let resource = params["resource_id"].as_str().unwrap_or_default();
        for current in ctx.backup_policies(resource)? {
            let lower = ["keep_daily", "keep_weekly", "keep_monthly"]
                .iter()
                .any(|keep| {
                    params[*keep].as_i64().unwrap_or(0) < current[*keep].as_i64().unwrap_or(0)
                });
            if lower || params["destination_ref"] != current["destination_ref"] {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn ref_matches(r#ref: &str, pattern: &str) -> bool {
    r#ref == pattern
        || pattern.strip_suffix('*').is_some_and(|prefix| {
            pattern.ends_with("/*") && r#ref.starts_with(prefix) && r#ref.len() > prefix.len()
        })
}

fn string_in(set: &Value, value: &Value) -> bool {
    set.as_array()
        .is_some_and(|items| items.iter().any(|item| item == value))
}

/// Step 12 for rule plans.
fn check_rule(
    plan: &Value,
    rule: &Value,
    ctx: &dyn PolicyContext,
    now: i64,
    specs: &BTreeMap<String, (Value, String)>,
) -> Result<(), PlanCode> {
    let invocation = &plan["invocation"];
    let evidence = &invocation["evidence"];
    let scope = &rule["scope"];
    let not_before = timestamp(&rule["not_before"])?;
    let rule_expires = timestamp(&rule["expires_at"])?;
    if !(not_before <= now && now <= rule_expires) {
        return Err(PlanCode::RuleWindow);
    }
    let targets = plan["targets"].as_array().map_or(&[][..], Vec::as_slice);
    let services = plan["service_ids"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let scope_ok = invocation["trigger"] == rule["trigger"]
        && plan["project_id"] == scope["project_id"]
        && plan["environment"] == scope["environment"]
        && targets.len() == 1
        && targets.iter().all(|t| string_in(&scope["server_ids"], t))
        && services.iter().all(|s| string_in(&scope["service_ids"], s))
        && evidence["repo"] == scope["repo"]
        && scope["branch_patterns"].as_array().is_some_and(|patterns| {
            patterns.iter().any(|p| {
                ref_matches(
                    evidence["ref"].as_str().unwrap_or_default(),
                    p.as_str().unwrap_or_default(),
                )
            })
        });
    let project = plan["project_id"].as_str().unwrap_or_default();
    let environment = plan["environment"].as_str().unwrap_or_default();
    if !scope_ok || ctx.environment_protected(project, environment)? {
        return Err(PlanCode::RuleScope);
    }
    let actions = plan["actions"].as_array().map_or(&[][..], Vec::as_slice);
    let limits = &rule["limits"];
    // A stored rule that lists scale with a null cap is malformed. The
    // replica check below does not run when max_replicas is null, so a scale
    // action would otherwise slip past it (D-072). Same code as over-cap.
    let lists_scale = rule["allowed_kinds"]
        .as_array()
        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "scale"));
    if lists_scale && limits["max_replicas"].is_null() {
        return Err(PlanCode::RuleLimit);
    }
    for action in actions {
        let digest = action["params"]["spec_digest_hex"]
            .as_str()
            .unwrap_or_default();
        let (spec, _) = specs.get(digest).ok_or(PlanCode::RuleSpec)?;
        if let Some(max) = limits["max_replicas"].as_i64() {
            if spec["replicas"].as_i64().unwrap_or(i64::MAX) > max {
                return Err(PlanCode::RuleLimit);
            }
        }
    }
    let rule_id = rule["id"].as_str().unwrap_or_default();
    let max_per_hour = limits["max_invocations_per_hour"].as_i64().unwrap_or(0);
    if i64::try_from(ctx.rule_invocations_last_hour(rule_id)?).unwrap_or(i64::MAX) >= max_per_hour {
        return Err(PlanCode::RuleLimit);
    }
    let delivery_id = evidence["delivery_id"].as_str().unwrap_or_default();
    let delivery = ctx
        .delivery(delivery_id)?
        .filter(|d| d.verified)
        .ok_or(PlanCode::RuleEvidence)?;
    let matches = |field: &str, value: &str| evidence[field] == value;
    if delivery.consumed_by_rule_ids.iter().any(|id| id == rule_id)
        || !delivery.environments.iter().any(|env| env == environment)
        || !matches("body_digest_hex", &delivery.body_digest_hex)
        || !matches("repo", &delivery.repo)
        || !matches("ref", &delivery.r#ref)
        || !matches("commit_sha", &delivery.commit_sha)
        || !matches("commit_time", &delivery.commit_time)
        || !matches("received_at", &delivery.received_at)
    {
        return Err(PlanCode::RuleEvidence);
    }
    let received = timestamp(&evidence["received_at"])?;
    if now < received - SKEW_SECONDS {
        return Err(PlanCode::RuleEvidence);
    }
    let commit_sha = evidence["commit_sha"].as_str().unwrap_or_default();
    // v1.0.11 (D-061): the window is anchored to the runner's build: fresh
    // within 900 s of the delivery, or when the build started within 900 s
    // of it and ended at most 900 s ago.
    if now > received + WEBHOOK_TTL_SECONDS {
        for action in actions {
            // Commit and build freshness apply to deploy only. A scale
            // action has no commit_sha (D-072).
            if action["kind"] != "deploy" {
                continue;
            }
            let service = action["params"]["service_id"].as_str().unwrap_or_default();
            let fresh = match ctx.build_window(service, commit_sha)? {
                (Some(started), Some(built)) => {
                    started <= received + WEBHOOK_TTL_SECONDS && now <= built + WEBHOOK_TTL_SECONDS
                }
                _ => false,
            };
            if !fresh {
                return Err(PlanCode::RuleEvidence);
            }
        }
    }
    let commit_time = timestamp(&evidence["commit_time"])?;
    let r#ref = evidence["ref"].as_str().unwrap_or_default();
    for action in actions {
        if action["kind"] != "deploy" {
            continue;
        }
        let params = &action["params"];
        if params["commit_sha"] != commit_sha {
            return Err(PlanCode::RuleEvidence);
        }
        let service = params["service_id"].as_str().unwrap_or_default();
        if let Some((sha, time)) = ctx.deployed_commit(service, r#ref)? {
            let older = text::timestamp(&time).is_none_or(|deployed| commit_time < deployed);
            if sha == commit_sha || older {
                return Err(PlanCode::RuleEvidence);
            }
        }
    }
    for action in actions {
        if action["kind"] != "deploy" {
            continue;
        }
        let params = &action["params"];
        let service = params["service_id"].as_str().unwrap_or_default();
        let digest = params["spec_digest_hex"].as_str().unwrap_or_default();
        let (spec, _) = specs.get(digest).ok_or(PlanCode::RuleSpec)?;
        let base = ctx.last_admitted_spec(service)?.ok_or(PlanCode::RuleSpec)?;
        let build = ctx
            .build_image(service, commit_sha)?
            .ok_or(PlanCode::RuleSpec)?;
        if spec["image_digest_hex"] != build.as_str() {
            return Err(PlanCode::RuleSpec);
        }
        let mut rebased = spec.clone();
        rebased["image_digest_hex"] = base["image_digest_hex"].clone();
        if rebased != base {
            return Err(PlanCode::RuleSpec);
        }
    }
    for action in actions {
        if action["kind"] != "scale" {
            continue;
        }
        // Autoscale does not raise permissions: only replicas may differ
        // from the admitted spec (D-072).
        let params = &action["params"];
        let service = params["service_id"].as_str().unwrap_or_default();
        let digest = params["spec_digest_hex"].as_str().unwrap_or_default();
        let (spec, _) = specs.get(digest).ok_or(PlanCode::RuleSpec)?;
        let base = ctx.last_admitted_spec(service)?.ok_or(PlanCode::RuleSpec)?;
        let mut rebased = spec.clone();
        rebased["replicas"] = base["replicas"].clone();
        if rebased != base {
            return Err(PlanCode::RuleSpec);
        }
    }
    Ok(())
}

/// A `server.add` plan that passed the section 7.3 bootstrap checks.
#[derive(Debug, Clone)]
pub struct BootstrapPlan {
    pub server_id: String,
    pub owner_key: Value,
}

/// Section 7.3 step 3, applied only while trusted-keys.json is absent,
/// including the step 7 time window (v1.0.2, D-033) so an expired
/// `server.add` never writes trusted-keys.json. `age_recipient` is the
/// server's own recipient string (trailing newline removed); the plan's
/// signed `age_recipient_fingerprint` must be its hex SHA-256 (v1.0.5,
/// D-045). An empty recipient never matches, so a server that cannot read
/// its recipient refuses every bootstrap (fail closed).
pub fn verify_bootstrap(
    text: &[u8],
    host_key_digests: &[String],
    age_recipient: &str,
    now: i64,
) -> Result<BootstrapPlan, PlanCode> {
    let (plan, signatures) = match parse_envelope(text) {
        Ok(parsed) => parsed,
        Err(PlanCode::Version) => return Err(PlanCode::Parse),
        Err(code) => return Err(code),
    };
    let actions = plan["actions"].as_array().map_or(&[][..], Vec::as_slice);
    if actions.len() != 1 || actions[0]["kind"] != "server.add" {
        return Err(PlanCode::Bootstrap);
    }
    let params = &actions[0]["params"];
    let server_id = params["server_id"].as_str().unwrap_or_default();
    if plan["targets"].as_array().map(Vec::as_slice) != Some(&[Value::String(server_id.to_owned())])
    {
        return Err(PlanCode::Bootstrap);
    }
    let owner = &params["owner_key"];
    let host_key = params["ssh_host_key_digest_hex"]
        .as_str()
        .unwrap_or_default();
    if !host_key_digests.iter().any(|d| d == host_key) {
        return Err(PlanCode::Bootstrap);
    }
    if age_recipient.is_empty()
        || params["age_recipient_fingerprint"].as_str()
            != Some(hex(&Sha256::digest(age_recipient.as_bytes())).as_str())
    {
        return Err(PlanCode::Bootstrap);
    }
    if signatures.len() != 1
        || signatures[0]["key_id"] != owner["key_id"]
        || signatures[0]["alg"] != "ES256-raw"
    {
        return Err(PlanCode::Bootstrap);
    }
    if owner["role"] != "owner" || owner["presence"] == "none" || plan["author"]["kind"] != "user" {
        return Err(PlanCode::Bootstrap);
    }
    let key = parse_spki_base64(owner["spki"].as_str().unwrap_or_default())
        .filter(|key| owner["key_id"] == key.key_id.as_str())
        .ok_or(PlanCode::Bootstrap)?;
    let digest = prefixed_digest(PLAN_PREFIX, &canonicalize(&plan).ok_or(PlanCode::Parse)?);
    let raw = signatures[0]["sig"]
        .as_str()
        .and_then(b64url_decode)
        .ok_or(PlanCode::Parse)?;
    if !key.verify_prehash(&digest, &raw) {
        return Err(PlanCode::SigInvalid);
    }
    check_time(&plan, now)?;
    Ok(BootstrapPlan {
        server_id: server_id.to_owned(),
        owner_key: owner.clone(),
    })
}

#[cfg(test)]
mod upgrade_spec_binding_tests {
    use super::*;
    use crate::signed_plan::test_support::{plan_vector, TestSigner};
    use serde_json::json;

    fn fixture() -> (Value, String, String) {
        let vector = plan_vector("user-deploy");
        let spec = vector["specs"][0]["jcs"].as_str().unwrap().to_owned();
        let (parsed, digest) = parse_spec(&spec).unwrap();
        let mut plan = vector["plan"].clone();
        plan["service_ids"] = json!([]);
        plan["actions"] = json!([{"kind":"db.upgrade","params":{"resource_id":parsed["service_id"],"engine":"postgres","from_version":"16","to_version":"17","spec_digest_hex":digest}}]);
        (plan, spec, digest)
    }
    #[test]
    fn upgrade_destination_digest_is_optional_but_schema_checked() {
        let (mut plan, _, _) = fixture();
        let (owner, _) = TestSigner::ephemeral_owner();
        assert!(parse_envelope(owner.envelope(&plan).as_bytes()).is_ok());
        plan["actions"][0]["params"]["spec_digest_hex"] = json!("bad");
        assert!(parse_envelope(owner.envelope(&plan).as_bytes()).is_err());
        plan["actions"][0]["params"]
            .as_object_mut()
            .unwrap()
            .remove("spec_digest_hex");
        assert!(parse_envelope(owner.envelope(&plan).as_bytes()).is_ok());
        assert!(bind_specs(&plan, &[]).is_some());
    }
    #[test]
    fn upgrade_destination_spec_requires_matching_digest_resource_and_no_extra_specs() {
        let (mut plan, spec, digest) = fixture();
        assert!(bind_specs(&plan, std::slice::from_ref(&spec)).is_some());
        assert!(bind_specs(&plan, &[]).is_none());
        plan["actions"][0]["params"]["spec_digest_hex"] = json!("aa".repeat(32));
        assert!(bind_specs(&plan, std::slice::from_ref(&spec)).is_none());
        plan["actions"][0]["params"]["spec_digest_hex"] = json!(digest);
        plan["actions"][0]["params"]["resource_id"] = json!("01a0cdb5-3500-70d1-8000-000000000099");
        assert!(bind_specs(&plan, std::slice::from_ref(&spec)).is_none());
        plan["actions"][0]["params"]
            .as_object_mut()
            .unwrap()
            .remove("spec_digest_hex");
        assert!(bind_specs(&plan, &[spec]).is_none());
    }
    #[test]
    fn upgrade_destination_elevation_needs_matching_elevate_action() {
        let (mut plan, spec, _) = fixture();
        let mut elevated: Value = serde_json::from_str(&spec).unwrap();
        elevated["privileged"] = json!(true);
        let text = canonicalize(&elevated).unwrap();
        let (_, digest) = parse_spec(&text).unwrap();
        plan["actions"][0]["params"]["spec_digest_hex"] = json!(digest);
        assert!(bind_specs(&plan, std::slice::from_ref(&text)).is_none());
        plan["actions"].as_array_mut().unwrap().push(json!({"kind":"service.elevate","params":{"service_id":elevated["service_id"],"spec_digest_hex":digest}}));
        assert!(bind_specs(&plan, &[text]).is_some());
    }
}
