//! The action catalog (signed-plan.md section 3.2) and the plan-level checks
//! of section 3.1.

use serde_json::Value;

use super::super::crypto::b64url_decode;
use super::super::text;
use super::{
    check, key_scope_shape_ok, Shape, ARGV, BUCKET, CRON, ENV, HEX64, HOST, INVOCATION, KEY_ENTRY,
    LABEL, PATH, REF, REVOCATION, RULE, TZ, UUID7,
};

const CRON_PARAMS: &[(&str, Shape)] = &[
    ("cron_id", UUID7),
    ("service_id", UUID7),
    // contracts v1.1.0: the signed job name.
    ("name", LABEL),
    ("schedule", CRON),
    ("timezone", TZ),
    ("command", ARGV),
    ("timeout_seconds", Shape::Int(1, 86_400)),
    ("retries", Shape::Int(0, 10)),
    ("overlap", Shape::Enum(&["skip", "queue", "allow"])),
    ("heartbeat_alert", Shape::Bool),
];
const ALERT_RULE: &[(&str, Shape)] = &[
    ("alert_rule_id", UUID7),
    ("name", LABEL),
    ("spec", Shape::Text(2, 16_384)),
];
const ALERT_CHANNEL: &[(&str, Shape)] = &[
    ("channel_id", UUID7),
    ("name", LABEL),
    (
        "channel_kind",
        Shape::Enum(&["slack", "discord", "webhook"]),
    ),
    ("credential_ciphertext_digest_hex", HEX64),
];
const CRON_ID: &[(&str, Shape)] = &[("cron_id", UUID7)];
const SIZE: Shape = Shape::Int(1 << 30, 1 << 46);
/// `rollback` with the deprecated `to_release_id` alias (v1.0.3, D-035).
const ROLLBACK_LEGACY: &[(&str, Shape)] = &[
    ("service_id", UUID7),
    ("to_release_id", UUID7),
    ("spec_digest_hex", HEX64),
];

fn env_map(value: &Value) -> bool {
    value.as_object().is_some_and(|map| {
        map.len() <= 128
            && map
                .iter()
                .all(|(name, text)| text::env_name(name) && check(&Shape::Text(0, 4_096), text))
    })
}

/// Params of every kind, exactly as the reference script's `ACTIONS`.
#[allow(clippy::too_many_lines)]
fn params_for(kind: &str) -> Option<&'static [(&'static str, Shape)]> {
    Some(match kind {
        "deploy" => &[
            ("service_id", UUID7),
            ("commit_sha", Shape::Nullable(&Shape::Pattern(text::hex40))),
            ("spec_digest_hex", HEX64),
            // v1.0.3 (D-035): minted by the plan's author, copied by the agent.
            ("deployment_id", UUID7),
        ],
        // v1.0.3 (D-035); `to_release_id` is the deprecated alias
        // (`ROLLBACK_LEGACY`), exactly one of the two.
        "rollback" => &[
            ("service_id", UUID7),
            ("to_deployment_id", UUID7),
            ("spec_digest_hex", HEX64),
        ],
        "restart" | "service.elevate" => &[("service_id", UUID7), ("spec_digest_hex", HEX64)],
        "scale" => &[
            ("service_id", UUID7),
            ("replicas", Shape::Int(0, 1_000)),
            ("spec_digest_hex", HEX64),
        ],
        "operation.cancel" => &[("plan_id", UUID7), ("plan_digest_hex", HEX64)],
        "env.set" => &[
            ("service_id", UUID7),
            ("set", Shape::Custom(env_map)),
            ("unset", Shape::Set(&ENV, 0, 128)),
        ],
        "secret.set" => &[
            ("service_id", Shape::Nullable(&UUID7)),
            ("name", ENV),
            ("ciphertext_digest_hex", HEX64),
        ],
        "secret.unset" => &[("service_id", Shape::Nullable(&UUID7)), ("name", ENV)],
        "service.delete" => &[("service_id", UUID7)],
        "environment.delete" => &[("environment", REF)],
        "project.delete" => &[("project_id", UUID7)],
        "volume.create" => &[
            ("volume_id", UUID7),
            ("service_id", UUID7),
            ("mount_path", PATH),
            ("size_bytes", SIZE),
        ],
        "volume.resize" => &[
            ("volume_id", UUID7),
            ("service_id", UUID7),
            ("size_bytes", SIZE),
        ],
        "volume.delete" => &[("volume_id", UUID7), ("service_id", UUID7)],
        "bucket.create" | "bucket.delete" | "bucket.credentials.rotate" => {
            &[("service_id", UUID7), ("bucket", BUCKET)]
        }
        "domain.add" => &[
            ("service_id", UUID7),
            ("hostname", HOST),
            ("tls", Shape::Enum(&["acme", "none"])),
        ],
        "domain.remove" => &[("service_id", UUID7), ("hostname", HOST)],
        "domain.switch" => &[
            ("service_id", UUID7),
            ("from_hostname", HOST),
            ("to_hostname", HOST),
        ],
        "edge.rule.set" => &[
            ("service_id", UUID7),
            ("edge_rule_id", UUID7),
            ("spec", Shape::Text(2, 16_384)),
        ],
        "edge.rule.delete" => &[("service_id", UUID7), ("edge_rule_id", UUID7)],
        "cron.create" | "cron.update" => CRON_PARAMS,
        "cron.delete" | "cron.run" | "cron.pause" | "cron.resume" => CRON_ID,
        "backup.run" | "backup.policy.delete" => &[("resource_id", UUID7)],
        "backup.verify" | "backup.delete" => &[("resource_id", UUID7), ("backup_id", UUID7)],
        "backup.policy.set" => &[
            ("resource_id", UUID7),
            ("schedule", CRON),
            ("timezone", TZ),
            ("keep_daily", Shape::Int(0, 366)),
            ("keep_weekly", Shape::Int(0, 260)),
            ("keep_monthly", Shape::Int(0, 120)),
            ("verify_schedule", Shape::Nullable(&CRON)),
            ("destination_ref", REF),
        ],
        "restore" => &[
            ("resource_id", UUID7),
            ("backup_id", UUID7),
            ("backup_digest_hex", HEX64),
            // contracts v1.1.0 (section 3.8): who wrote the object.
            ("origin", Shape::Enum(&["server", "imported"])),
        ],
        "db.upgrade" => &[
            ("resource_id", UUID7),
            ("engine", Shape::Enum(&["postgres"])),
            ("from_version", Shape::Text(1, 32)),
            ("to_version", Shape::Text(1, 32)),
        ],
        "alert.rule.create" | "alert.rule.update" => ALERT_RULE,
        "alert.rule.delete" => &[("alert_rule_id", UUID7)],
        "alert.silence" => &[
            ("alert_rule_id", UUID7),
            ("until", Shape::Nullable(&Shape::Timestamp)),
        ],
        "alert.channel.create" | "alert.channel.update" => ALERT_CHANNEL,
        "alert.channel.delete" => &[("channel_id", UUID7)],
        "telemetry.retention.set" => &[
            (
                "telemetry_kind",
                Shape::Enum(&["logs", "http", "traces", "metrics", "analytics"]),
            ),
            ("max_age_days", Shape::Int(1, 3_650)),
            ("max_bytes", Shape::Int(1 << 20, (1 << 53) - 1)),
        ],
        "server.add" => &[
            ("server_id", UUID7),
            ("ssh_host_key_digest_hex", HEX64),
            ("owner_key", KEY_ENTRY),
            // v1.0.2 (D-029): the server bundle the engine installed.
            ("bundle_manifest_digest_hex", HEX64),
            // v1.0.5 (D-045): hex SHA-256 of the server's age recipient.
            ("age_recipient_fingerprint", HEX64),
        ],
        "server.remove" => &[("server_id", UUID7), ("wipe", Shape::Bool)],
        // v1.0.4 (D-040): the bundle manifest is signed too.
        "agent.update" => &[
            ("version", Shape::Pattern(text::semver)),
            ("artifact_digest_hex", HEX64),
            ("bundle_manifest_digest_hex", HEX64),
            // v1.0.8 (section 3.9 step 5b).
            ("allow_downgrade", Shape::Bool),
        ],
        "component.update" => &[
            (
                "component",
                Shape::Enum(&["dwaar", "runner", "permanu-env", "os_packages"]),
            ),
            ("version", Shape::Text(1, 64)),
            ("artifact_digest_hex", Shape::Nullable(&HEX64)),
            ("bundle_manifest_digest_hex", Shape::Nullable(&HEX64)),
            ("allow_downgrade", Shape::Bool),
        ],
        "shell.open" => &[
            ("service_id", Shape::Nullable(&UUID7)),
            ("ttl_seconds", Shape::Int(1, 900)),
        ],
        "rule.create" => &[("rule", RULE)],
        "rule.revoke" => &[("rule_id", UUID7), ("rule_digest_hex", HEX64)],
        "key.add" => &[("entry", KEY_ENTRY)],
        "key.revoke" => &[("revocation", REVOCATION)],
        _ => return super::actions_m2::params_for(kind),
    })
}

/// The params shape of one action: a `rollback` carrying the deprecated
/// `to_release_id` is checked against the alias shape, so an action with
/// both names (or neither) fails `E_PARSE` (v1.0.3, D-035).
fn params_of(kind: &str, params: Option<&Value>) -> Option<&'static [(&'static str, Shape)]> {
    if kind == "rollback" && params.is_some_and(|p| p.get("to_release_id").is_some()) {
        return Some(ROLLBACK_LEGACY);
    }
    // v1.0.10 (D-060): `recovery_recipient.set` may carry `fingerprint_hex`.
    if kind == "recovery_recipient.set"
        && params.is_some_and(|p| p.get("fingerprint_hex").is_some())
    {
        return super::actions_m2::params_for("recovery_recipient.set+fingerprint");
    }
    params_for(kind)
}

/// The deployment id a rollback returns to: `to_deployment_id`, or its
/// deprecated alias `to_release_id` (v1.0.3, D-035).
pub(crate) fn rollback_target(params: &Value) -> Option<&str> {
    params["to_deployment_id"]
        .as_str()
        .or_else(|| params["to_release_id"].as_str())
}

/// Kinds whose action pins a `ServiceSpec` by digest (section 3.7).
pub(crate) const SPEC_KINDS: &[&str] =
    &["deploy", "rollback", "restart", "scale", "service.elevate"];
const SERVER_KINDS: &[&str] = &[
    "server.add",
    "server.remove",
    "agent.update",
    "component.update",
    "key.add",
    "key.revoke",
    "alert.rule.create",
    "alert.rule.update",
    "alert.rule.delete",
    "alert.silence",
    "alert.channel.create",
    "alert.channel.update",
    "alert.channel.delete",
    "telemetry.retention.set",
];
const NEUTRAL_KIND: &str = "operation.cancel";

fn server_kind(kind: &str) -> bool {
    SERVER_KINDS.contains(&kind) || super::actions_m2::SERVER_KINDS_M2.contains(&kind)
}

fn nonce(value: &Value) -> bool {
    value
        .as_str()
        .and_then(b64url_decode)
        .is_some_and(|bytes| bytes.len() == 16)
}

/// One action's params: the kind's fixed members, plus (v1.0.11, D-061)
/// any optional member it carries, each checked against its own shape
/// (never null; absent keeps the v1.0.10 meaning).
fn params_ok(kind: &str, params: Option<&Value>) -> bool {
    let (Some(fixed), Some(value)) = (params_of(kind, params), params) else {
        return false;
    };
    let optional = super::actions_m2::optional_params_for(kind);
    let Some(map) = value.as_object() else {
        return false;
    };
    let mut base = map.clone();
    for (name, shape) in optional {
        if let Some(member) = base.remove(*name) {
            if !check(shape, &member) {
                return false;
            }
        }
    }
    check(&Shape::Object(fixed), &Value::Object(base))
}

fn actions(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        (1..=64).contains(&items.len())
            && items.iter().all(|action| {
                action.as_object().is_some_and(|map| {
                    map.len() == 2
                        && map
                            .get("kind")
                            .and_then(Value::as_str)
                            .is_some_and(|kind| params_ok(kind, map.get("params")))
                })
            })
    })
}

fn heads(value: &Value) -> bool {
    value.as_object().is_some_and(|map| {
        map.iter()
            .all(|(server, head)| text::uuid7(server) && check(&HEX64, head))
    })
}

const PLAN: Shape = Shape::Object(&[
    ("version", Shape::Int(1, 1)),
    ("id", UUID7),
    ("project_id", Shape::Nullable(&UUID7)),
    ("environment", Shape::Nullable(&REF)),
    // v1.0.2 (D-026): null exactly when environment is null.
    ("environment_id", Shape::Nullable(&UUID7)),
    ("service_ids", Shape::Set(&UUID7, 0, 64)),
    ("targets", Shape::Set(&UUID7, 1, 32)),
    ("actions", Shape::Custom(actions)),
    (
        "base",
        Shape::Object(&[("force", Shape::Bool), ("heads", Shape::Custom(heads))]),
    ),
    ("created_at", Shape::Timestamp),
    ("expires_at", Shape::Timestamp),
    ("nonce", Shape::Custom(nonce)),
    (
        "author",
        Shape::Object(&[
            ("kind", Shape::Enum(&["user", "rule", "agent-draft"])),
            ("agent_session_id", Shape::Nullable(&UUID7)),
        ]),
    ),
    ("invocation", Shape::Nullable(&INVOCATION)),
]);

/// Section 6.1 step 3 for the plan object: every field rule of sections 2–3.
pub(crate) fn validate_plan(plan: &Value) -> bool {
    check(&PLAN, plan) && plan_rules_hold(plan)
}

fn plan_rules_hold(plan: &Value) -> bool {
    let actions = plan["actions"].as_array().map_or(&[][..], Vec::as_slice);
    let kinds: Vec<&str> = actions.iter().filter_map(|a| a["kind"].as_str()).collect();
    let targets = super::string_set(&plan["targets"]);
    let heads: std::collections::BTreeSet<&str> = plan["base"]["heads"]
        .as_object()
        .map(|map| map.keys().map(String::as_str).collect())
        .unwrap_or_default();
    if heads != targets {
        return false;
    }
    let author = &plan["author"];
    if (author["kind"] == "agent-draft") == author["agent_session_id"].is_null() {
        return false;
    }
    if plan["environment"].is_null() != plan["environment_id"].is_null() {
        return false;
    }
    if !scope_rules_hold(plan, &kinds) {
        return false;
    }
    let used: std::collections::BTreeSet<&str> = actions
        .iter()
        .filter_map(|action| action["params"].get("service_id").and_then(Value::as_str))
        .collect();
    if used != super::string_set(&plan["service_ids"]) {
        return false;
    }
    // v1.0.3 (D-035): deployment ids are distinct within one plan.
    let deployment_ids: Vec<&str> = actions
        .iter()
        .filter(|action| action["kind"] == "deploy")
        .filter_map(|action| action["params"]["deployment_id"].as_str())
        .collect();
    let distinct: std::collections::BTreeSet<&str> = deployment_ids.iter().copied().collect();
    if distinct.len() != deployment_ids.len() {
        return false;
    }
    actions
        .iter()
        .enumerate()
        .all(|(index, action)| action_rules_hold(plan, index, action))
        && super::super::jcs::canonicalize(plan).is_some()
}

fn scope_rules_hold(plan: &Value, kinds: &[&str]) -> bool {
    let has_project = !plan["project_id"].is_null();
    let has_environment = !plan["environment"].is_null();
    let no_services = plan["service_ids"].as_array().is_some_and(Vec::is_empty);
    if kinds.contains(&NEUTRAL_KIND) {
        kinds.len() == 1 && no_services && has_project == has_environment
    } else if kinds.iter().any(|kind| server_kind(kind)) {
        kinds.iter().all(|kind| server_kind(kind))
            && !has_project
            && !has_environment
            && no_services
    } else {
        has_project && has_environment
    }
}

fn action_rules_hold(plan: &Value, index: usize, action: &Value) -> bool {
    let params = &action["params"];
    let single_target = |server: &Value| {
        plan["targets"]
            .as_array()
            .is_some_and(|targets| targets.len() == 1 && targets[0] == *server)
    };
    let key_entry_ok = |entry: &Value| key_scope_shape_ok(entry);
    match action["kind"].as_str().unwrap_or_default() {
        "server.add" => {
            single_target(&params["server_id"])
                && params["owner_key"]["added_by"].is_null()
                && key_entry_ok(&params["owner_key"])
        }
        "server.remove" => single_target(&params["server_id"]),
        "component.update" => {
            (params["component"] == "os_packages") == params["bundle_manifest_digest_hex"].is_null()
        }
        "env.set" => {
            let unset = super::string_set(&params["unset"]);
            params["set"]
                .as_object()
                .is_some_and(|set| set.keys().all(|name| !unset.contains(name.as_str())))
        }
        "rule.create" => {
            let rule = &params["rule"];
            let window = text::timestamp(rule["expires_at"].as_str().unwrap_or_default())
                .zip(text::timestamp(
                    rule["not_before"].as_str().unwrap_or_default(),
                ))
                .map(|(expires, not_before)| expires - not_before);
            rule["scope"]["project_id"] == plan["project_id"]
                && rule["scope"]["environment"] == plan["environment"]
                && window.is_some_and(|seconds| 0 < seconds && seconds <= 400 * 86_400)
        }
        "key.add" => !params["entry"]["added_by"].is_null() && key_entry_ok(&params["entry"]),
        "project.delete" => params["project_id"] == plan["project_id"],
        "environment.delete" => params["environment"] == plan["environment"],
        "domain.switch" => params["from_hostname"] != params["to_hostname"],
        "backup.policy.set" => {
            ["keep_daily", "keep_weekly", "keep_monthly"]
                .iter()
                .any(|keep| params[*keep].as_i64().unwrap_or(0) > 0)
                && super::actions_m2::action_rules_hold(plan, "backup.policy.set", params)
        }
        "restore" => super::actions_m2::restore_shape(plan, index, params),
        kind => super::actions_m2::action_rules_hold(plan, kind, params),
    }
}
