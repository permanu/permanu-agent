use super::super::authority::tests::{fixture_with_keys, signature};
use super::*;
use serde_json::json;

#[test]
fn standing_owner_activates_once_two_producer_only_releases_verify() {
    let (e, p, mut trust, now, owner, producer) = fixture_with_keys();
    let rule = json!({"version":1,"capability":CAPABILITY,"action":"compose.rule.activate",
 "rule_id":"continuous","revision":1,"application_id":p.application_id,"policy_revision":p.revision,
 "spec_digest":p.spec_digest,"policy_digest":p.policy_digest,"repository":p.repository,"ref":p.git_ref,
 "verification_config_digest":p.verification_config_digest,"target":p.target,"owner_id":p.owner_id,
 "producer_id":p.producer_id,"producer_key_id":e["producer_signature"]["key_id"],"producer_key_purpose":"compose-evidence-v1",
 "backend_services":["server","worker"],"required_gates":p.required_gates,"frontend_targets":["authenticated","public"],
 "migrations":"none","max_evidence_age_seconds":p.max_age_seconds,"issued_at":now-1,"expires_at":now+86400,
 "max_releases_per_hour":2,"concurrency":1});
    let signed = json!({"rule":rule,"owner_signature":{"key_id":e["owner_signature"]["key_id"],"alg":"ES256-raw","sig":signature(&owner,&rule,RULE_DOMAIN)}});
    let stored = serde_json::to_vec(&signed).unwrap();
    assert!(verify_rule(&stored, &p, &trust, now, true).is_ok());
    let mut request = json!({"authority_mode":"standing-rule-v1","rule_id":"continuous","rule_revision":1,
 "release":e["release"],"attestation":e["attestation"],"producer_signature":e["producer_signature"]});
    assert!(request.get("owner_signature").is_none());
    assert!(verify_release(
        &serde_json::to_vec(&request).unwrap(),
        &stored,
        &p,
        &trust,
        now
    )
    .is_ok());
    request["release"]["release_id"] = json!("second-release");
    request["release"]["source"]["commit"] = json!("c".repeat(40));
    request["attestation"]["release_digest"] =
        json!(schema::digest(b"permanu-compose-release-v1\n", &request["release"]).unwrap());
    request["producer_signature"]["sig"] = json!(signature(
        &producer,
        &request["attestation"],
        b"permanu-compose-attestation-v1\n"
    ));
    let raw = serde_json::to_vec(&request).unwrap();
    assert!(verify_release(&raw, &stored, &p, &trust, now).is_ok());
    trust
        .revoked
        .insert(e["owner_signature"]["key_id"].as_str().unwrap().into());
    assert!(verify_release(&raw, &stored, &p, &trust, now).is_err());
    trust.revoked.clear();
    trust
        .revoked
        .insert(e["producer_signature"]["key_id"].as_str().unwrap().into());
    assert!(verify_release(&raw, &stored, &p, &trust, now).is_err());
    trust.revoked.clear();
    request["rule_revision"] = json!(2);
    assert!(verify_release(
        &serde_json::to_vec(&request).unwrap(),
        &stored,
        &p,
        &trust,
        now
    )
    .is_err());
    let mut changed = p.clone();
    changed.revision += 1;
    assert!(verify_release(&raw, &stored, &changed, &trust, now).is_err());
    assert!(verify_release(&raw, &stored, &p, &trust, now + 86401).is_err());
}
