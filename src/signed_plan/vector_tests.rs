//! Contract vectors (contracts-v1.1.2): JCS, digests, signatures, the trust
//! store, every policy case through the full ordered verifier (steps 1–12)
//! and the bootstrap cases.

use std::collections::BTreeSet;

use serde_json::Value;

use super::crypto::{hex, parse_spki_base64, prefixed_digest, PLAN_PREFIX, RULE_PREFIX};
use super::jcs::canonicalize;
use super::test_support::{case_specs, vector, VectorContext, SERVER_A};
use super::trust::{validate_trust, TrustMode, TEST_KEY_IDS};
use super::verify::{
    next_head, parse_spec, verify_bootstrap, verify_signed_plan, Submitter, Verdict,
};
use super::PlanCode;

#[test]
fn jcs_vectors_canonicalize_exactly() {
    for case in vector("jcs")["cases"].as_array().expect("cases") {
        let canonical = canonicalize(&case["value"]).expect("canonical");
        assert_eq!(canonical, case["jcs"].as_str().expect("jcs"));
        assert_eq!(hex(canonical.as_bytes()), case["jcs_utf8_hex"]);
    }
}

#[test]
fn plan_vectors_match_jcs_digest_specs_and_signatures() {
    let plans = vector("plans");
    for case in plans["vectors"].as_array().expect("vectors") {
        let name = case["name"].as_str().expect("name");
        let canonical = canonicalize(&case["plan"]).expect("canonical plan");
        assert_eq!(canonical, case["jcs"], "{name}");
        let digest = hex(&prefixed_digest(PLAN_PREFIX, &canonical));
        assert_eq!(digest, case["digest_hex"], "{name}");
        for spec in case["specs"].as_array().expect("specs") {
            let (_, spec_digest) = parse_spec(spec["jcs"].as_str().unwrap()).expect("valid spec");
            assert_eq!(spec_digest, spec["spec_digest_hex"], "{name}");
        }
    }
    let extras = &plans["extras"];
    let rule_jcs = canonicalize(&extras["rule"]).expect("rule");
    assert_eq!(rule_jcs, extras["rule_jcs"]);
    assert_eq!(
        hex(&prefixed_digest(RULE_PREFIX, &rule_jcs)),
        extras["rule_digest_hex"]
    );
}

/// contracts v1.1.11 (D-069): the vendored `server-accounts-migrate` plan
/// is a server-level plan the schema accepts.
#[test]
fn the_server_accounts_migrate_vector_is_a_server_plan() {
    let plans = vector("plans");
    let case = plans["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "server-accounts-migrate")
        .expect("server-accounts-migrate vector");
    assert!(
        super::schema::validate_plan(&case["plan"]),
        "server.accounts.migrate must parse"
    );
}

#[test]
fn state_head_chain_matches_the_worked_vector() {
    let before = "4a98af3eeae054bf7585746ce20fa5907ec9c079ee1b049a7d01146d1c92ebfb";
    let plans = vector("plans");
    assert_eq!(plans["extras"]["state_head_before_hex"], before);
    let user_deploy = plans["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "user-deploy")
        .unwrap();
    let after = next_head(before, user_deploy["digest_hex"].as_str().unwrap());
    assert_eq!(
        after,
        "46621faca524ff37eeb468903e0fb7faf0bfb27520fbb8b7521d9e7e7f05f766"
    );
    assert_eq!(
        vector("plans")["extras"]["state_head_after_user_deploy_hex"],
        after.as_str()
    );
}

#[test]
fn key_ids_and_test_key_list_match_the_vectors() {
    for key in vector("trusted-keys")["keys"].as_array().expect("keys") {
        let parsed = parse_spki_base64(key["spki"].as_str().unwrap()).expect("spki");
        assert_eq!(parsed.key_id, key["key_id"].as_str().unwrap());
        assert!(TEST_KEY_IDS.contains(&parsed.key_id.as_str()));
    }
    let expected: BTreeSet<&str> = TEST_KEY_IDS.iter().copied().collect();
    let listed = vector("plans");
    let extras: BTreeSet<&str> = listed["extras"]["test_key_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    assert_eq!(extras, expected);
}

#[test]
fn trusted_keys_vector_loads_only_in_test_mode_and_rejects_tampering() {
    let file = vector("trusted-keys");
    let store = validate_trust(&file, TrustMode::Test).expect("test-mode trust store");
    assert!(store.revoked.contains("AqhPUHwy5byXy_JwVWyl7w"));
    assert!(validate_trust(&file, TrustMode::Production).is_err());
    let mut bad_label = file.clone();
    bad_label["keys"][1]["label"] = Value::String("Studio Mac (EVIL)".to_owned());
    assert!(validate_trust(&bad_label, TrustMode::Test).is_err());
    let mut not_owner_root = file.clone();
    not_owner_root["keys"][0]["role"] = Value::String("deployer".to_owned());
    assert!(validate_trust(&not_owner_root, TrustMode::Test).is_err());
    let mut bad_revocation = file.clone();
    bad_revocation["revocations"][0]["reason"] = Value::String("rotated".to_owned());
    assert!(validate_trust(&bad_revocation, TrustMode::Test).is_err());
    let mut unknown_field = file;
    unknown_field["extra"] = Value::Bool(true);
    assert!(validate_trust(&unknown_field, TrustMode::Test).is_err());
}

fn expected(expect: &str) -> Result<&'static str, PlanCode> {
    match expect {
        "OK" => Ok("OK"),
        "DEDUPED" => Ok("DEDUPED"),
        other => Err(PlanCode::parse(other).unwrap_or_else(|| panic!("unknown code {other}"))),
    }
}

#[test]
fn every_policy_case_returns_the_contract_code() {
    let cases = vector("policy-cases");
    let cases = cases["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 226);
    let mut mismatches = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let context = VectorContext::new(case["mode"] == "production");
        assert_eq!(context.trust.server_id, SERVER_A);
        let submitter = match case["submitter"].as_str().unwrap() {
            "agent_webhook" => Submitter::AgentWebhook,
            _ => Submitter::Client,
        };
        let actual = verify_signed_plan(
            case["input"].as_str().unwrap().as_bytes(),
            &case_specs(case),
            submitter,
            &context,
        )
        .map(|verdict| match verdict {
            Verdict::Admit(_) => "OK",
            Verdict::Deduped { .. } => "DEDUPED",
        });
        let want = expected(case["expect"].as_str().unwrap());
        if actual != want {
            mismatches.push(format!("{name}: {actual:?} != {want:?}"));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn bootstrap_cases_match() {
    let cases = vector("policy-cases");
    let cases = cases["bootstrap_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let digests: Vec<String> = case["host_key_digests_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap().to_owned())
            .collect();
        let now = crate::signed_plan::text::timestamp(case["now"].as_str().unwrap()).unwrap();
        let age_recipient = case["age_recipient"].as_str().unwrap();
        let actual = verify_bootstrap(
            case["input"].as_str().unwrap().as_bytes(),
            &digests,
            age_recipient,
            now,
        )
        .map(|plan| {
            assert_eq!(plan.server_id, case["server_id"].as_str().unwrap());
            "OK"
        });
        assert_eq!(
            actual,
            expected(case["expect"].as_str().unwrap()),
            "{}",
            case["name"]
        );
    }
}

/// A git.push rule whose only allowed kind is `scale` (contracts v1.2.1, D-072).
/// Built from the vendored deploy rule plan; the corpus itself stays on
/// contracts-v1.1.11.
struct ScaleRulePlan {
    text: Vec<u8>,
    specs: Vec<String>,
    ctx: VectorContext,
    rule: Value,
}

fn scale_rule_plan(replicas: i64, max_replicas: Option<i64>) -> ScaleRulePlan {
    let cases = vector("policy-cases");
    let case = cases["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == "ok_rule_invocation")
        .expect("ok_rule_invocation");
    let mut envelope: Value =
        serde_json::from_str(case["input"].as_str().expect("input")).expect("envelope");
    let mut ctx = VectorContext::new(false);
    let rule_id = envelope["plan"]["invocation"]["rule_id"]
        .as_str()
        .expect("rule id")
        .to_owned();
    let record = ctx.context["rules"]
        .as_array_mut()
        .expect("rules")
        .iter_mut()
        .find(|record| record["rule"]["id"] == rule_id)
        .expect("stored rule");
    record["rule"]["allowed_kinds"] = serde_json::json!(["scale"]);
    record["rule"]["limits"]["max_replicas"] = match max_replicas {
        Some(max) => serde_json::json!(max),
        None => Value::Null,
    };
    let digest = {
        let canonical = canonicalize(&record["rule"]).expect("rule jcs");
        hex(&prefixed_digest(RULE_PREFIX, &canonical))
    };
    record["rule_digest_hex"] = serde_json::json!(digest.clone());
    let rule = record["rule"].clone();
    envelope["plan"]["invocation"]["rule_digest_hex"] = serde_json::json!(digest);
    let service_id = envelope["plan"]["service_ids"][0]
        .as_str()
        .expect("service")
        .to_owned();
    let mut spec = ctx.context["admitted_specs"][&service_id].clone();
    spec["replicas"] = serde_json::json!(replicas);
    let spec_text = canonicalize(&spec).expect("spec jcs");
    let (_, spec_digest) = parse_spec(&spec_text).expect("scale spec");
    envelope["plan"]["actions"] = serde_json::json!([{
        "kind": "scale",
        "params": {
            "service_id": service_id,
            "replicas": replicas,
            "spec_digest_hex": spec_digest,
        }
    }]);
    ScaleRulePlan {
        text: serde_json::to_vec(&envelope).expect("envelope json"),
        specs: vec![spec_text],
        ctx,
        rule,
    }
}

fn admit_scale(replicas: i64, max_replicas: Option<i64>) -> Result<Verdict, PlanCode> {
    let plan = scale_rule_plan(replicas, max_replicas);
    verify_signed_plan(&plan.text, &plan.specs, Submitter::AgentWebhook, &plan.ctx)
}

#[test]
fn rule_scale_within_replica_cap_is_admitted() {
    let plan = scale_rule_plan(4, Some(4));
    assert!(
        super::schema::check(&super::schema::RULE, &plan.rule),
        "a scale rule with max_replicas set must parse"
    );
    let actual = verify_signed_plan(&plan.text, &plan.specs, Submitter::AgentWebhook, &plan.ctx);
    assert!(
        matches!(actual, Ok(Verdict::Admit(_))),
        "scale within max_replicas: {actual:?}"
    );
}

#[test]
fn rule_scale_over_replica_cap_is_rule_limit() {
    let actual = admit_scale(5, Some(4));
    assert!(matches!(actual, Err(PlanCode::RuleLimit)), "{actual:?}");
}

#[test]
fn rule_scale_null_max_replicas_is_rejected() {
    let plan = scale_rule_plan(4, None);
    assert!(
        !super::schema::check(&super::schema::RULE, &plan.rule),
        "scale with null max_replicas is a parse error"
    );
    let actual = verify_signed_plan(&plan.text, &plan.specs, Submitter::AgentWebhook, &plan.ctx);
    assert!(
        matches!(actual, Err(PlanCode::RuleLimit)),
        "stored scale rule with null max_replicas: {actual:?}"
    );
}

#[test]
fn rule_scale_deploy_only_rule_still_verifies() {
    let cases = vector("policy-cases");
    let case = cases["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == "ok_rule_invocation")
        .expect("ok_rule_invocation");
    let ctx = VectorContext::new(false);
    let actual = verify_signed_plan(
        case["input"].as_str().unwrap().as_bytes(),
        &case_specs(case),
        Submitter::AgentWebhook,
        &ctx,
    );
    assert!(
        matches!(actual, Ok(Verdict::Admit(_))),
        "deploy-only rule: {actual:?}"
    );
}
