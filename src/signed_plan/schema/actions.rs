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
        ],
        "rollback" => &[
            ("service_id", UUID7),
            ("to_release_id", UUID7),
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
        ],
        "server.remove" => &[("server_id", UUID7), ("wipe", Shape::Bool)],
        "agent.update" => &[
            ("version", Shape::Pattern(text::semver)),
            ("artifact_digest_hex", HEX64),
        ],
        "component.update" => &[
            (
                "component",
                Shape::Enum(&["dwaar", "runner", "os_packages"]),
            ),
            ("version", Shape::Text(1, 64)),
            ("artifact_digest_hex", Shape::Nullable(&HEX64)),
        ],
        "shell.open" => &[
            ("service_id", Shape::Nullable(&UUID7)),
            ("ttl_seconds", Shape::Int(1, 900)),
        ],
        "rule.create" => &[("rule", RULE)],
        "rule.revoke" => &[("rule_id", UUID7), ("rule_digest_hex", HEX64)],
        "key.add" => &[("entry", KEY_ENTRY)],
        "key.revoke" => &[("revocation", REVOCATION)],
        _ => return None,
    })
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

fn nonce(value: &Value) -> bool {
    value
        .as_str()
        .and_then(b64url_decode)
        .is_some_and(|bytes| bytes.len() == 16)
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
                            .and_then(params_for)
                            .is_some_and(|params| {
                                map.get("params")
                                    .is_some_and(|value| check(&Shape::Object(params), value))
                            })
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
    actions.iter().all(|action| action_rules_hold(plan, action))
        && super::super::jcs::canonicalize(plan).is_some()
}

fn scope_rules_hold(plan: &Value, kinds: &[&str]) -> bool {
    let has_project = !plan["project_id"].is_null();
    let has_environment = !plan["environment"].is_null();
    let no_services = plan["service_ids"].as_array().is_some_and(Vec::is_empty);
    if kinds.contains(&NEUTRAL_KIND) {
        kinds.len() == 1 && no_services && has_project == has_environment
    } else if kinds.iter().any(|kind| SERVER_KINDS.contains(kind)) {
        kinds.iter().all(|kind| SERVER_KINDS.contains(kind))
            && !has_project
            && !has_environment
            && no_services
    } else {
        has_project && has_environment
    }
}

fn action_rules_hold(plan: &Value, action: &Value) -> bool {
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
        "backup.policy.set" => ["keep_daily", "keep_weekly", "keep_monthly"]
            .iter()
            .any(|keep| params[*keep].as_i64().unwrap_or(0) > 0),
        _ => true,
    }
}
