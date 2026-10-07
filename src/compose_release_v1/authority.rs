//! Actual signature verification against current server trust and an enrolled
//! application policy. No request may supply keys or policy. Registration has
//! no live API yet: constructing this type is NOT proof of signed enrollment.
use super::{generated, schema, AdmissionVerifier, Error};
use crate::signed_plan::{
    crypto, jcs,
    trust::{TrustPaths, TrustState, TrustStore},
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub(crate) struct RegisteredPolicy {
    pub application_id: String,
    pub revision: u64,
    pub spec_digest: String,
    pub policy_digest: String,
    pub target: Value,
    pub repository: String,
    pub git_ref: String,
    pub project_id: String,
    pub environment: String,
    pub verification_config_digest: String,
    pub owner_id: String,
    pub producer_id: String,
    pub owner_key_ids: BTreeSet<String>,
    pub producer_key_ids: BTreeSet<String>,
    pub required_gates: BTreeSet<String>,
    pub max_age_seconds: i64,
}

/// Registry starts empty and therefore fails closed. A future authenticated
/// registration handler must populate it only from an admitted signed action.
/// Revoking registration is represented by removing it, never a request boolean.
#[derive(Default)]
pub(crate) struct Registry(pub(crate) RwLock<Option<RegisteredPolicy>>);

pub(crate) struct EnrolledVerifier {
    pub trust: TrustPaths,
    pub registry: Arc<Registry>,
}

impl AdmissionVerifier for EnrolledVerifier {
    fn verify(&self, envelope: &Value, now: i64) -> Result<(), Error> {
        let guard = self.registry.0.read().map_err(|_| Error::Authority)?;
        let policy = guard.as_ref().ok_or(Error::Authority)?;
        let TrustState::Valid(trust) = self.trust.load() else {
            return Err(Error::Authority);
        };
        verify_registered(envelope, policy, &trust, now)
    }
}

pub(crate) fn verify_registered(
    e: &Value,
    p: &RegisteredPolicy,
    trust: &TrustStore,
    now: i64,
) -> Result<(), Error> {
    // Always perform full shape/digest-link validation, including on recheck.
    let raw = serde_json::to_vec(e).map_err(|_| Error::Parse)?;
    schema::parse(&raw, now)?;
    let r = &e["release"];
    let a = &e["attestation"];
    let o = &e["authorization"];
    if p.revision == 0
        || p.max_age_seconds < 1
        || p.max_age_seconds > 86400
        || p.required_gates.is_empty()
        || p.owner_key_ids.is_empty()
        || p.producer_key_ids.is_empty()
        || !p.owner_key_ids.is_disjoint(&p.producer_key_ids)
        || p.owner_id == p.producer_id
        || p.project_id.is_empty()
        || p.environment.is_empty()
        || p.target["server_id"] != trust.server_id
        || r["application_id"] != p.application_id
        || r["policy_revision"] != p.revision
        || r["spec_digest"] != p.spec_digest
        || r["policy_digest"] != p.policy_digest
        || r["target"] != p.target
        || r["source"]["repository"] != p.repository
        || r["source"]["ref"] != p.git_ref
        || a["verification_config_digest"] != p.verification_config_digest
        || a["producer_id"] != p.producer_id
        || o["owner_id"] != p.owner_id
    {
        return Err(Error::Authority);
    }
    let gates = a["gates"].as_object().ok_or(Error::Authority)?;
    if gates.len() != p.required_gates.len()
        || p.required_gates
            .iter()
            .any(|g| gates.get(g) != Some(&Value::String("success".into())))
    {
        return Err(Error::Authority);
    }
    for auth in [a, o] {
        let issued = auth["issued_at"].as_i64().ok_or(Error::Authority)?;
        let expires = auth["expires_at"].as_i64().ok_or(Error::Authority)?;
        if now
            .checked_sub(issued)
            .filter(|age| *age >= 0 && *age <= p.max_age_seconds)
            .is_none()
            || expires
                .checked_sub(issued)
                .filter(|age| *age > 0 && *age <= p.max_age_seconds)
                .is_none()
        {
            return Err(Error::Authority);
        }
    }
    verify_role(
        e,
        "producer_signature",
        a,
        generated::ATTESTATION_DOMAIN.as_bytes(),
        "ci",
        &p.producer_key_ids,
        p,
        trust,
    )?;
    verify_role(
        e,
        "owner_signature",
        o,
        generated::AUTHORIZATION_DOMAIN.as_bytes(),
        "owner",
        &p.owner_key_ids,
        p,
        trust,
    )
}

pub(super) fn verify_role(
    e: &Value,
    field: &str,
    body: &Value,
    domain: &[u8],
    role: &str,
    allowed: &BTreeSet<String>,
    p: &RegisteredPolicy,
    trust: &TrustStore,
) -> Result<(), Error> {
    let s = &e[field];
    if s["alg"] != "ES256-raw" {
        return Err(Error::Authority);
    }
    let id = s["key_id"].as_str().ok_or(Error::Authority)?;
    if !allowed.contains(id)
        || trust.revoked.contains(id)
        || trust.compromised.contains(id)
        || crate::signed_plan::trust::TEST_KEY_IDS.contains(&id)
    {
        return Err(Error::Authority);
    }
    let k = trust.keys.get(id).ok_or(Error::Authority)?;
    if k.entry["role"] != role || k.public_key.key_id != id || k.entry["alg"] != "ES256-raw" {
        return Err(Error::Authority);
    }
    if role == "owner" {
        if !k.entry["scope"].is_null()
            || !matches!(
                k.entry["presence"].as_str(),
                Some("biometry" | "user_presence")
            )
        {
            return Err(Error::Authority);
        }
    } else {
        let scope = &k.entry["scope"];
        if k.entry["presence"] != "none"
            || scope["server_level"] != false
            || !scope["project_ids"]
                .as_array()
                .is_some_and(|v| v.iter().any(|x| x == &p.project_id))
            || !scope["environments"]
                .as_array()
                .is_some_and(|v| v.iter().any(|x| x == &p.environment))
        {
            return Err(Error::Authority);
        }
    }
    let raw = crypto::b64url_decode(s["sig"].as_str().ok_or(Error::Authority)?)
        .ok_or(Error::Authority)?;
    let canonical = jcs::canonicalize(body).ok_or(Error::Authority)?;
    if !k
        .public_key
        .verify_prehash(&crypto::prefixed_digest(domain, &canonical), &raw)
    {
        return Err(Error::Authority);
    }
    Ok(())
}

#[cfg(test)]
#[path = "authority_tests.rs"]
pub(crate) mod tests;
