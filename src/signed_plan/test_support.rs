//! Test helpers: the vendored contract vectors (`tests/vectors/signed-plan`,
//! docs tag contracts-v1.0.1), a `PolicyContext` over the vector context, and
//! a TEST signer that loads `keys.json` from the docs checkout. `keys.json`
//! holds public TEST private keys and is never vendored (gitleaks); tests that
//! need it skip when the docs checkout is absent.

use std::path::PathBuf;

use serde_json::Value;

use super::crypto::{b64url_encode, prefixed_digest, PLAN_PREFIX};
use super::jcs::canonicalize;
use super::text;
use super::trust::{validate_trust, TrustMode, TrustStore};
use super::verify::{DeliveryRecord, PolicyContext, RuleRecord, GENESIS_HEAD};
use super::PlanCode;

pub const SERVER_A: &str = "01a0cdb5-3500-70a1-8000-000000000001";

pub fn vector(name: &str) -> Value {
    let text = match name {
        "jcs" => include_str!("../../tests/vectors/signed-plan/jcs.json"),
        "plans" => include_str!("../../tests/vectors/signed-plan/plans.json"),
        "policy-cases" => include_str!("../../tests/vectors/signed-plan/policy-cases.json"),
        "trusted-keys" => include_str!("../../tests/vectors/signed-plan/trusted-keys.json"),
        _ => panic!("unknown vector file {name}"),
    };
    serde_json::from_str(text).expect("vector json")
}

pub fn policy_context() -> Value {
    vector("policy-cases")["context"].clone()
}

pub fn test_trust() -> TrustStore {
    validate_trust(&policy_context()["trusted_keys"], TrustMode::Test).expect("vector trust")
}

pub fn temp_dir(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    // Short: unix socket paths are limited to ~104 bytes on macOS.
    let dir = PathBuf::from("/tmp").join(format!(
        "pa-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// `PolicyContext` over `policy-cases.json › context`.
pub struct VectorContext {
    pub context: Value,
    pub trust: TrustStore,
    pub now: i64,
}

impl VectorContext {
    pub fn new(production: bool) -> Self {
        let context = policy_context();
        let mut trust = test_trust();
        if production {
            trust.mode = TrustMode::Production;
        }
        let now = text::timestamp(context["now"].as_str().unwrap()).unwrap();
        Self {
            context,
            trust,
            now,
        }
    }
}

fn find(items: &Value, predicate: impl Fn(&Value) -> bool) -> Option<&Value> {
    items.as_array()?.iter().find(|item| predicate(item))
}

impl PolicyContext for VectorContext {
    fn now(&self) -> i64 {
        self.now
    }

    fn trust(&self) -> &TrustStore {
        &self.trust
    }

    fn admission_digest(&self, plan_id: &str) -> Result<Option<String>, PlanCode> {
        Ok(
            find(&self.context["admissions"], |a| a["plan_id"] == plan_id)
                .and_then(|a| a["plan_digest_hex"].as_str().map(str::to_owned)),
        )
    }

    fn seen(&self, nonce: &str, plan_id: &str) -> Result<bool, PlanCode> {
        let seen = &self.context["seen"];
        Ok(find(&seen["nonces"], |n| n == nonce).is_some()
            || find(&seen["plan_ids"], |p| p == plan_id).is_some())
    }

    fn head(&self, project_id: &str, environment: &str) -> Result<String, PlanCode> {
        Ok(find(&self.context["heads"], |h| {
            h["project_id"].as_str().unwrap_or_default() == project_id
                && h["environment"].as_str().unwrap_or_default() == environment
        })
        .and_then(|h| h["head_digest_hex"].as_str().map(str::to_owned))
        .unwrap_or_else(|| GENESIS_HEAD.to_owned()))
    }

    fn rule(&self, rule_id: &str) -> Result<Option<RuleRecord>, PlanCode> {
        Ok(
            find(&self.context["rules"], |r| r["rule"]["id"] == rule_id).map(|r| RuleRecord {
                rule: r["rule"].clone(),
                rule_digest_hex: r["rule_digest_hex"].as_str().unwrap().to_owned(),
                created_by_key_id: r["created_by_key_id"].as_str().unwrap().to_owned(),
                revoked: r["revoked"] == true,
            }),
        )
    }

    fn rule_invocations_last_hour(&self, rule_id: &str) -> Result<u64, PlanCode> {
        Ok(self.context["rule_invocations_last_hour"][rule_id]
            .as_u64()
            .unwrap_or(0))
    }

    fn delivery(&self, delivery_id: &str) -> Result<Option<DeliveryRecord>, PlanCode> {
        let field = |d: &Value, name: &str| d[name].as_str().unwrap_or_default().to_owned();
        Ok(find(&self.context["verified_deliveries"], |d| {
            d["delivery_id"] == delivery_id
        })
        .map(|d| DeliveryRecord {
            body_digest_hex: field(d, "body_digest_hex"),
            repo: field(d, "repo"),
            r#ref: field(d, "ref"),
            commit_sha: field(d, "commit_sha"),
            commit_time: field(d, "commit_time"),
            received_at: field(d, "received_at"),
            verified: true,
            consumed_by_rule_ids: d["consumed_by_rule_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap().to_owned())
                .collect(),
        }))
    }

    fn last_admitted_spec(&self, service_id: &str) -> Result<Option<Value>, PlanCode> {
        Ok(self.context["admitted_specs"].get(service_id).cloned())
    }

    fn build_image(&self, service_id: &str, commit_sha: &str) -> Result<Option<String>, PlanCode> {
        Ok(find(&self.context["builds"], |b| {
            b["service_id"] == service_id && b["commit_sha"] == commit_sha
        })
        .and_then(|b| b["image_digest_hex"].as_str().map(str::to_owned)))
    }

    fn deployed_commit(
        &self,
        service_id: &str,
        r#ref: &str,
    ) -> Result<Option<(String, String)>, PlanCode> {
        Ok(find(&self.context["deployed_commits"], |c| {
            c["service_id"] == service_id && c["ref"] == r#ref
        })
        .map(|c| {
            (
                c["commit_sha"].as_str().unwrap().to_owned(),
                c["commit_time"].as_str().unwrap().to_owned(),
            )
        }))
    }
}

pub fn case_specs(case: &Value) -> Vec<String> {
    case["specs"]
        .as_array()
        .expect("specs")
        .iter()
        .map(|spec| spec.as_str().expect("spec text").to_owned())
        .collect()
}

pub fn plan_vector(name: &str) -> Value {
    vector("plans")["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("plan vector {name}"))
        .clone()
}

/// A TEST signing key from the docs checkout's `keys.json`.
pub struct TestSigner {
    pub key_id: String,
    key: p256::ecdsa::SigningKey,
}

fn keys_json_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("PERMANU_DOCS_DIR") {
        return Some(PathBuf::from(dir).join("contracts/vectors/signed-plan/keys.json"));
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [manifest.join("../docs"), manifest.join("../../docs")]
        .into_iter()
        .map(|d| d.join("contracts/vectors/signed-plan/keys.json"))
        .find(|p| p.exists())
}

impl TestSigner {
    /// `None` (test skips) when the docs checkout is not next to this repo.
    pub fn load(name: &str) -> Option<Self> {
        let path = keys_json_path()?;
        let keys: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let entry = keys["keys"]
            .as_array()?
            .iter()
            .find(|k| k["name"] == name)?;
        let scalar = hex::decode(entry["private_scalar_hex_TEST_ONLY"].as_str()?).ok()?;
        let key = p256::ecdsa::SigningKey::from_slice(&scalar).ok()?;
        Some(Self {
            key_id: entry["key_id"].as_str()?.to_owned(),
            key,
        })
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> String {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: p256::ecdsa::Signature = self.key.sign_prehash(digest).expect("sign");
        b64url_encode(&signature.to_bytes())
    }

    /// Signs `plan` and returns the envelope text.
    pub fn envelope(&self, plan: &Value) -> String {
        let digest = prefixed_digest(PLAN_PREFIX, &canonicalize(plan).unwrap());
        serde_json::json!({
            "plan": plan,
            "signatures": [{
                "key_id": self.key_id, "alg": "ES256-raw",
                "sig": self.sign_digest(&digest), "signed_at": plan["created_at"],
            }]
        })
        .to_string()
    }

    /// Signs a key statement (`permanu-key-add-v1` / `permanu-key-revoke-v1`).
    pub fn sign_statement(&self, statement: &Value, prefix: &[u8], field: &str) -> Value {
        let mut unsigned = statement.clone();
        unsigned[field] = Value::Null;
        let digest = prefixed_digest(prefix, &canonicalize(&unsigned).unwrap());
        let mut signed = statement.clone();
        signed[field] =
            serde_json::json!({"key_id": self.key_id, "sig": self.sign_digest(&digest)});
        signed
    }
}
