use super::*;
use crate::signed_plan::trust::{TrustMode, TrustedKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use serde_json::json;
use std::collections::BTreeMap;

fn key(role: &str) -> (SigningKey, TrustedKey) {
    let signing = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let mut der = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    der.extend_from_slice(signing.verifying_key().to_encoded_point(false).as_bytes());
    let spki = STANDARD.encode(der);
    let public_key = crypto::parse_spki_base64(&spki).unwrap();
    let entry = json!({"key_id":public_key.key_id,"alg":"ES256-raw","spki":spki,"role":role,
        "scope":if role=="owner" {Value::Null} else {json!({"project_ids":["project"],"environments":["production"],"server_level":false})},
        "presence":if role=="owner" {"user_presence"} else {"none"}});
    (signing, TrustedKey { public_key, entry })
}
pub(crate) fn signature(k: &SigningKey, body: &Value, domain: &[u8]) -> String {
    let sig: Signature = k
        .sign_prehash(&crypto::prefixed_digest(
            domain,
            &jcs::canonicalize(body).unwrap(),
        ))
        .unwrap();
    crypto::b64url_encode(&sig.to_bytes())
}
pub(crate) fn fixture_with_keys() -> (
    Value,
    RegisteredPolicy,
    TrustStore,
    i64,
    SigningKey,
    SigningKey,
) {
    let mut e: Value = serde_json::from_slice(include_bytes!(
        "../../tests/vectors/compose-release-v1/structural-only.fake.json"
    ))
    .unwrap();
    let (owner, ok) = key("owner");
    let (producer, pk) = key("ci");
    e["owner_signature"]["key_id"] = json!(ok.public_key.key_id);
    e["producer_signature"]["key_id"] = json!(pk.public_key.key_id);
    e["owner_signature"]["sig"] = json!(signature(
        &owner,
        &e["authorization"],
        generated::AUTHORIZATION_DOMAIN.as_bytes()
    ));
    e["producer_signature"]["sig"] = json!(signature(
        &producer,
        &e["attestation"],
        generated::ATTESTATION_DOMAIN.as_bytes()
    ));
    let text = |v: &Value, k: &str| v[k].as_str().unwrap().to_owned();
    let r = &e["release"];
    let a = &e["attestation"];
    let o = &e["authorization"];
    let p = RegisteredPolicy {
        application_id: text(r, "application_id"),
        revision: 1,
        spec_digest: text(r, "spec_digest"),
        policy_digest: text(r, "policy_digest"),
        target: r["target"].clone(),
        repository: text(&r["source"], "repository"),
        git_ref: text(&r["source"], "ref"),
        project_id: "project".into(),
        environment: "production".into(),
        verification_config_digest: text(a, "verification_config_digest"),
        owner_id: text(o, "owner_id"),
        producer_id: text(a, "producer_id"),
        owner_key_ids: [ok.public_key.key_id.clone()].into(),
        producer_key_ids: [pk.public_key.key_id.clone()].into(),
        required_gates: a["gates"].as_object().unwrap().keys().cloned().collect(),
        max_age_seconds: 900,
    };
    let trust = TrustStore {
        server_id: text(&r["target"], "server_id"),
        keys: BTreeMap::from([
            (ok.public_key.key_id.clone(), ok),
            (pk.public_key.key_id.clone(), pk),
        ]),
        revoked: BTreeSet::new(),
        compromised: BTreeSet::new(),
        revocations: BTreeMap::new(),
        mode: TrustMode::Production,
        document: json!({}),
        raw: vec![],
    };
    let now = a["issued_at"].as_i64().unwrap() + 1;
    (e, p, trust, now, owner, producer)
}

fn fixture() -> (Value, RegisteredPolicy, TrustStore, i64) {
    let (e, p, t, n, _, _) = fixture_with_keys();
    (e, p, t, n)
}

#[test]
fn real_es256_accepts_ephemeral_separate_role_signatures() {
    let (e, p, t, n) = fixture();
    assert!(verify_registered(&e, &p, &t, n).is_ok());
}
#[test]
fn real_es256_rejects_forgery_and_cross_domain_signature() {
    let (e, p, t, n) = fixture();
    let mut forged = e.clone();
    forged["producer_signature"]["sig"] = json!(crypto::b64url_encode(&[0; 64]));
    assert!(verify_registered(&forged, &p, &t, n).is_err());
    let mut crossed = e.clone();
    crossed["producer_signature"]["sig"] = e["owner_signature"]["sig"].clone();
    assert!(verify_registered(&crossed, &p, &t, n).is_err());
}
#[test]
fn real_es256_rechecks_revocation_policy_and_ci_scope() {
    let (e, p, mut t, n) = fixture();
    let id = e["producer_signature"]["key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.revoked.insert(id.clone());
    assert!(verify_registered(&e, &p, &t, n).is_err());
    t.revoked.clear();
    t.keys.get_mut(&id).unwrap().entry["scope"]["project_ids"] = json!(["another-project"]);
    assert!(verify_registered(&e, &p, &t, n).is_err());
    let (e, mut p, t, n) = fixture();
    p.revision += 1;
    assert!(verify_registered(&e, &p, &t, n).is_err());
}
#[test]
fn real_es256_rejects_expiry_and_missing_gate_without_trusting_json() {
    let (e, p, t, n) = fixture();
    assert!(verify_registered(&e, &p, &t, n + 1000).is_err());
    let mut p = p;
    p.required_gates.insert("additional-required-gate".into());
    assert!(verify_registered(&e, &p, &t, n).is_err());
}
