//! The rule-backed plan (signed-plan.md 3.5 step 5): built by the agent, as
//! the plan's author, from the admitted rule, the verified delivery and the
//! images the runner built. Nothing here comes from a request: the rule is
//! the admitted `rule.create`'s, the environment id is copied from that
//! admission, every spec is the service's last admitted spec with only
//! `image_digest_hex` replaced, and each deploy gets a fresh UUIDv7
//! `deployment_id` (v1.0.3, D-035).

use serde_json::{json, Value};

use crate::admissions::new_uuid7;
use crate::admissions::webhooks::{DeliveryRow, LastSpec};
use crate::signed_plan::crypto::{b64url_encode, hex, prefixed_digest, SPEC_PREFIX};
use crate::signed_plan::jcs::canonicalize;
use crate::signed_plan::text::format_timestamp;

/// A rule plan lives 15 minutes (section 3.5 step 5).
pub const RULE_PLAN_LIFETIME_SECONDS: i64 = 900;

/// One service of the rule's scope and the image built for it.
#[derive(Debug, Clone)]
pub struct ServiceBuild {
    pub service_id: String,
    pub last_spec: LastSpec,
    pub image_digest_hex: String,
}

#[derive(Debug, Clone)]
pub struct RulePlanInput<'a> {
    pub rule: &'a Value,
    pub rule_digest_hex: &'a str,
    /// `admissions.environment_id` of the rule's `rule.create` plan.
    pub environment_id: &'a str,
    pub server_id: &'a str,
    /// The scope's current head (`GetStateHead`).
    pub head: &'a str,
    pub delivery: &'a DeliveryRow,
    pub services: &'a [ServiceBuild],
    pub now: i64,
}

/// The envelope and spec texts to admit with `Submitter::AgentWebhook`.
#[derive(Debug, Clone)]
pub struct RulePlan {
    pub plan_id: String,
    pub envelope: Vec<u8>,
    pub specs: Vec<Vec<u8>>,
    /// `(service_id, deployment_id)` per deploy action, in plan order.
    pub deployments: Vec<(String, String)>,
}

fn nonce() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).ok()?;
    Some(b64url_encode(&bytes))
}

/// Builds the plan, or `None` when a spec cannot be canonicalized.
pub fn build_rule_plan(input: &RulePlanInput<'_>) -> Option<RulePlan> {
    let unix_ms = u64::try_from(input.now).unwrap_or(0).saturating_mul(1_000);
    let plan_id = new_uuid7(unix_ms);
    let mut services: Vec<&ServiceBuild> = input.services.iter().collect();
    services.sort_by(|a, b| a.service_id.cmp(&b.service_id));
    let mut actions = Vec::new();
    let mut specs = Vec::new();
    let mut deployments = Vec::new();
    for service in &services {
        let mut spec = service.last_spec.spec.clone();
        spec["image_digest_hex"] = json!(service.image_digest_hex);
        let text = canonicalize(&spec)?;
        let digest = hex(&prefixed_digest(SPEC_PREFIX, &text));
        let deployment_id = new_uuid7(unix_ms);
        actions.push(json!({"kind": "deploy", "params": {
            "service_id": service.service_id,
            "commit_sha": input.delivery.commit_sha,
            "spec_digest_hex": digest,
            "deployment_id": deployment_id,
        }}));
        specs.push(text.into_bytes());
        deployments.push((service.service_id.clone(), deployment_id));
    }
    let scope = &input.rule["scope"];
    let delivery = input.delivery;
    let plan = json!({
        "version": 1,
        "id": plan_id,
        "project_id": scope["project_id"],
        "environment": scope["environment"],
        "environment_id": input.environment_id,
        "service_ids": services.iter().map(|s| s.service_id.as_str()).collect::<Vec<_>>(),
        "targets": [input.server_id],
        "actions": actions,
        "base": {"force": false, "heads": {input.server_id: input.head}},
        "created_at": format_timestamp(input.now),
        "expires_at": format_timestamp(input.now + RULE_PLAN_LIFETIME_SECONDS),
        "nonce": nonce()?,
        "author": {"kind": "rule", "agent_session_id": null},
        "invocation": {
            "rule_id": input.rule["id"],
            "rule_digest_hex": input.rule_digest_hex,
            "trigger": "git.push",
            "evidence": {
                "provider": delivery.provider,
                "repo": delivery.repo,
                "ref": delivery.r#ref,
                "commit_sha": delivery.commit_sha,
                "commit_time": delivery.commit_time,
                "delivery_id": delivery.delivery_id,
                "body_digest_hex": delivery.body_digest_hex,
                "received_at": delivery.received_at,
            },
        },
    });
    let envelope = canonicalize(&json!({"plan": plan, "signatures": []}))?;
    Some(RulePlan {
        plan_id,
        envelope: envelope.into_bytes(),
        specs,
        deployments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_plan::schema::validate_plan;
    use crate::signed_plan::test_support::vector;
    use crate::signed_plan::text::timestamp;

    pub(crate) fn delivery() -> DeliveryRow {
        DeliveryRow {
            delivery_id: "01a0cdb5-3500-70e9-8000-000000000001".to_owned(),
            provider: "github".to_owned(),
            event: "push".to_owned(),
            body_digest_hex: "5".repeat(64),
            repo: "github.com/acme/web".to_owned(),
            r#ref: "refs/heads/main".to_owned(),
            commit_sha: "4f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39".to_owned(),
            commit_time: "2026-09-23T09:59:30Z".to_owned(),
            environments: vec!["production".to_owned()],
            received_at: "2026-09-23T10:04:30Z".to_owned(),
            expires_at: "2026-09-30T10:04:30Z".to_owned(),
            status: "pending".to_owned(),
        }
    }

    #[test]
    fn the_plan_is_a_valid_rule_plan_with_only_the_image_replaced() {
        let context = &vector("policy-cases")["context"];
        let rule = &context["rules"][0]["rule"];
        let service = "01a0cdb5-3500-70c1-8000-000000000001";
        let base = context["admitted_specs"][service].clone();
        let delivery = delivery();
        let services = [ServiceBuild {
            service_id: service.to_owned(),
            last_spec: LastSpec {
                spec: base.clone(),
                spec_digest_hex: "0".repeat(64),
            },
            image_digest_hex: "e".repeat(64),
        }];
        let now = timestamp("2026-09-23T10:05:00Z").unwrap();
        let built = build_rule_plan(&RulePlanInput {
            rule,
            rule_digest_hex: context["rules"][0]["rule_digest_hex"].as_str().unwrap(),
            environment_id: "01a0cdb5-3500-70b2-8000-000000000001",
            server_id: "01a0cdb5-3500-70a1-8000-000000000001",
            head: &"4".repeat(64),
            delivery: &delivery,
            services: &services,
            now,
        })
        .unwrap();
        let envelope: Value = serde_json::from_slice(&built.envelope).unwrap();
        let plan = &envelope["plan"];
        assert!(validate_plan(plan), "{plan}");
        assert_eq!(envelope["signatures"], json!([]));
        assert_eq!(plan["author"]["kind"], "rule");
        assert_eq!(
            plan["environment_id"],
            "01a0cdb5-3500-70b2-8000-000000000001"
        );
        assert_eq!(
            plan["targets"],
            json!(["01a0cdb5-3500-70a1-8000-000000000001"])
        );
        assert_eq!(plan["expires_at"], "2026-09-23T10:20:00Z");
        assert_eq!(
            plan["invocation"]["evidence"]["delivery_id"],
            delivery.delivery_id
        );
        let deploy = &plan["actions"][0]["params"];
        assert_eq!(deploy["commit_sha"], delivery.commit_sha);
        assert_eq!(deploy["deployment_id"], built.deployments[0].1);
        assert!(crate::signed_plan::text::uuid7(&built.deployments[0].1));
        let spec: Value = serde_json::from_slice(&built.specs[0]).unwrap();
        assert_eq!(spec["image_digest_hex"], "e".repeat(64));
        let mut rebased = spec.clone();
        rebased["image_digest_hex"] = base["image_digest_hex"].clone();
        assert_eq!(rebased, base);
        let (_, digest) =
            crate::signed_plan::verify::parse_spec(std::str::from_utf8(&built.specs[0]).unwrap())
                .unwrap();
        assert_eq!(deploy["spec_digest_hex"], digest);
        // Two plans never share an id, nonce or deployment id.
        let again = build_rule_plan(&RulePlanInput {
            rule,
            rule_digest_hex: "0",
            environment_id: "e",
            server_id: "01a0cdb5-3500-70a1-8000-000000000001",
            head: "h",
            delivery: &delivery,
            services: &services,
            now,
        })
        .unwrap();
        assert_ne!(again.plan_id, built.plan_id);
        assert_ne!(again.deployments[0].1, built.deployments[0].1);
    }
}
