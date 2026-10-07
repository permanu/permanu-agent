//! Owner-approved standing authority. No per-release owner signature is needed.
//! The stored rule is supplied by trusted registration state, never the request.
//! Verification does not reserve a release or execute it; the Go coordinator
//! still owns its durable rule lease, release journal, rate limit and host lock.
use super::{
    authority::{verify_role, RegisteredPolicy},
    schema, typed, Error,
};
use crate::signed_plan::{jcs, trust::TrustStore};
use serde::{Deserialize, Serialize};

use std::collections::BTreeSet;

pub const CAPABILITY: &str = "compose-standing-rule-v1";
pub const RULE_DOMAIN: &[u8] = b"permanu-compose-standing-rule-v1\n";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub version: u32,
    pub capability: String,
    pub action: String,
    pub rule_id: String,
    pub revision: u64,
    pub application_id: String,
    pub policy_revision: u64,
    pub spec_digest: String,
    pub policy_digest: String,
    pub repository: String,
    pub r#ref: String,
    pub verification_config_digest: String,
    pub target: typed::Target,
    pub owner_id: String,
    pub producer_id: String,
    pub producer_key_id: String,
    pub producer_key_purpose: String,
    pub backend_services: Vec<String>,
    pub required_gates: Vec<String>,
    pub frontend_targets: Vec<String>,
    pub migrations: String,
    pub max_evidence_age_seconds: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub max_releases_per_hour: u32,
    pub concurrency: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRule {
    pub rule: Rule,
    pub owner_signature: typed::Signature,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingEnvelope {
    pub authority_mode: String,
    pub rule_id: String,
    pub rule_revision: u64,
    pub release: typed::Release,
    pub attestation: typed::Attestation,
    pub producer_signature: typed::Signature,
}
fn parse<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, Error> {
    let v = jcs::parse_strict(raw, 65536).ok_or(Error::Parse)?;
    serde_json::from_value(v).map_err(|_| Error::Parse)
}
fn hash(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn fresh(issued: i64, expires: i64, now: i64, max: i64) -> bool {
    issued > 0
        && issued <= now
        && expires > now
        && max > 0
        && now.checked_sub(issued).is_some_and(|v| v <= max)
        && expires
            .checked_sub(issued)
            .is_some_and(|v| v > 0 && v <= max)
}

pub fn verify_rule(
    raw: &[u8],
    p: &RegisteredPolicy,
    trust: &TrustStore,
    now: i64,
    activation: bool,
) -> Result<SignedRule, Error> {
    let signed: SignedRule = parse(raw)?;
    let r = &signed.rule;
    let gates: BTreeSet<_> = r.required_gates.iter().cloned().collect();
    if p.revision == 0
        || p.owner_id == p.producer_id
        || p.owner_key_ids.is_empty()
        || p.producer_key_ids.is_empty()
        || !p.owner_key_ids.is_disjoint(&p.producer_key_ids)
        || p.required_gates.is_empty()
        || !hash(&p.spec_digest, 64)
        || !hash(&p.policy_digest, 64)
        || !hash(&p.verification_config_digest, 64)
        || p.max_age_seconds < 1
        || p.max_age_seconds > 86400
        || r.version != 1
        || r.capability != CAPABILITY
        || r.action != "compose.rule.activate"
        || !identifier(&r.rule_id)
        || r.revision == 0
        || r.application_id != p.application_id
        || r.policy_revision != p.revision
        || r.spec_digest != p.spec_digest
        || r.policy_digest != p.policy_digest
        || r.repository != p.repository
        || r.r#ref != "refs/heads/main"
        || r.r#ref != p.git_ref
        || r.verification_config_digest != p.verification_config_digest
        || serde_json::to_value(&r.target).map_err(|_| Error::Parse)? != p.target
        || r.target.server_id != trust.server_id
        || r.owner_id != p.owner_id
        || r.producer_id != p.producer_id
        || r.producer_key_purpose != "compose-evidence-v1"
        || !p.producer_key_ids.contains(&r.producer_key_id)
        || r.producer_key_id == signed.owner_signature.key_id
        || r.backend_services != ["server", "worker"]
        || gates != p.required_gates
        || gates.len() != r.required_gates.len()
        || r.frontend_targets != ["authenticated", "public"]
        || r.migrations != "none"
        || r.max_evidence_age_seconds < 1
        || r.max_evidence_age_seconds > p.max_age_seconds
        || r.max_releases_per_hour < 1
        || r.max_releases_per_hour > 60
        || r.concurrency != 1
        || !fresh(r.issued_at, r.expires_at, now, 90 * 86400)
        || (activation && now - r.issued_at > 300)
    {
        return Err(Error::Authority);
    }
    let v = serde_json::to_value(&signed).map_err(|_| Error::Parse)?;
    verify_role(
        &v,
        "owner_signature",
        &v["rule"],
        RULE_DOMAIN,
        "owner",
        &p.owner_key_ids,
        p,
        trust,
    )?;
    // A revoked producer cannot become authorized merely because the rule remains signed.
    let producer = trust.keys.get(&r.producer_key_id).ok_or(Error::Authority)?;
    if trust.revoked.contains(&r.producer_key_id)
        || trust.compromised.contains(&r.producer_key_id)
        || producer.entry["role"] != "ci"
    {
        return Err(Error::Authority);
    }
    Ok(signed)
}

/// Accept a producer-only release using the independently stored, current rule.
/// Callers must hold the same registered-policy/rule lease until reservation.
pub fn verify_release(
    raw: &[u8],
    stored_rule: &[u8],
    p: &RegisteredPolicy,
    trust: &TrustStore,
    now: i64,
) -> Result<String, Error> {
    let signed = verify_rule(stored_rule, p, trust, now, false)?;
    let e: StandingEnvelope = parse(raw)?;
    let r = &e.release;
    let a = &e.attestation;
    let rule = &signed.rule;
    if e.authority_mode != "standing-rule-v1"
        || e.rule_id != rule.rule_id
        || e.rule_revision != rule.revision
        || e.producer_signature.key_id != rule.producer_key_id
        || r.version != 1
        || r.capability != "compose-release-v1"
        || r.action != "compose.release"
        || r.application_id != p.application_id
        || r.policy_revision != p.revision
        || r.spec_digest != p.spec_digest
        || r.policy_digest != p.policy_digest
        || serde_json::to_value(&r.target).map_err(|_| Error::Parse)? != p.target
        || r.source.repository != p.repository
        || r.source.r#ref != p.git_ref
        || r.migrations != "none"
        || r.previous_generation.checked_add(1) != Some(r.generation)
        || r.release_id == r.previous_release_id
        || !identifier(&r.release_id)
        || !identifier(&r.previous_release_id)
        || !hash(&r.source.commit, 40)
        || !hash(&r.source.tree, 40)
        || !hash(&r.source.desktop_tree, 40)
        || !hash(&r.inventory_digest, 64)
        || a.policy_revision != p.revision
        || a.policy_digest != p.policy_digest
        || a.verification_config_digest != p.verification_config_digest
        || a.producer_id != p.producer_id
        || !identifier(&a.run_id)
        || !fresh(
            a.issued_at,
            a.expires_at,
            now,
            rule.max_evidence_age_seconds,
        )
        || a.gates.len() != p.required_gates.len()
        || p.required_gates
            .iter()
            .any(|g| a.gates.get(g).is_none_or(|s| s != "success"))
    {
        return Err(Error::Authority);
    }
    for artifacts in [&r.candidate, &r.previous] {
        if artifacts
            .backend
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != ["server", "worker"]
            || artifacts.backend.values().any(|s| !hash(s, 64))
            || !hash(&artifacts.authenticated_frontend, 64)
            || !hash(&artifacts.public_frontend, 64)
        {
            return Err(Error::Authority);
        }
    }
    let rv = serde_json::to_value(r).map_err(|_| Error::Parse)?;
    let rd = schema::digest(b"permanu-compose-release-v1\n", &rv)?;
    if a.release_digest != rd {
        return Err(Error::Authority);
    }
    let v = serde_json::to_value(&e).map_err(|_| Error::Parse)?;
    verify_role(
        &v,
        "producer_signature",
        &v["attestation"],
        b"permanu-compose-attestation-v1\n",
        "ci",
        &p.producer_key_ids,
        p,
        trust,
    )?;
    Ok(rd)
}

#[cfg(test)]
#[path = "standing_tests.rs"]
mod tests;
