//! Full schema check of signed-plan.md sections 2–3 (section 6.1 step 3).
//!
//! A small declarative shape language mirrors the reference script so each
//! field rule can be compared line by line with the contract.

use std::collections::BTreeSet;

use serde_json::Value;

use super::crypto::b64url_decode;
use super::text;

#[derive(Clone, Copy)]
pub(crate) enum Shape {
    Pattern(fn(&str) -> bool),
    Text(usize, usize),
    Label(usize, usize),
    GitRef(bool),
    Int(i64, i64),
    Enum(&'static [&'static str]),
    Bool,
    Timestamp,
    Sig64,
    Nullable(&'static Shape),
    Set(&'static Shape, usize, usize),
    Object(&'static [(&'static str, Shape)]),
    Custom(fn(&Value) -> bool),
}

pub(crate) fn check(shape: &Shape, value: &Value) -> bool {
    match *shape {
        Shape::Pattern(matcher) => value.as_str().is_some_and(matcher),
        Shape::Text(low, high) => value
            .as_str()
            .is_some_and(|text| (low..=high).contains(&text.len())),
        Shape::Label(low, high) => value
            .as_str()
            .is_some_and(|text| (low..=high).contains(&text.len()) && text::label_chars_ok(text)),
        Shape::GitRef(pattern) => value
            .as_str()
            .is_some_and(|text| text::git_ref(text, pattern)),
        Shape::Int(low, high) => value
            .as_i64()
            .is_some_and(|number| (low..=high).contains(&number)),
        Shape::Enum(options) => value.as_str().is_some_and(|text| options.contains(&text)),
        Shape::Bool => value.is_boolean(),
        Shape::Timestamp => value.as_str().and_then(text::timestamp).is_some(),
        Shape::Sig64 => value
            .as_str()
            .and_then(b64url_decode)
            .is_some_and(|bytes| bytes.len() == 64),
        Shape::Nullable(inner) => value.is_null() || check(inner, value),
        Shape::Set(inner, low, high) => check_set(inner, low, high, value),
        Shape::Object(fields) => check_object(fields, value),
        Shape::Custom(function) => function(value),
    }
}

fn check_set(inner: &Shape, low: usize, high: usize, value: &Value) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    if !(low..=high).contains(&items.len()) || !items.iter().all(|item| check(inner, item)) {
        return false;
    }
    let Some(strings) = items.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else {
        return false;
    };
    strings.windows(2).all(|pair| pair[0] < pair[1])
}

fn check_object(fields: &[(&str, Shape)], value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    map.len() == fields.len()
        && fields
            .iter()
            .all(|(name, shape)| map.get(*name).is_some_and(|field| check(shape, field)))
}

const REF: Shape = Shape::Pattern(text::reference);
const UUID7: Shape = Shape::Pattern(text::uuid7);
const HEX64: Shape = Shape::Pattern(text::hex64);
const KID: Shape = Shape::Pattern(text::key_id);
const ENV: Shape = Shape::Pattern(text::env_name);
const HOST: Shape = Shape::Pattern(text::hostname);
const CRON: Shape = Shape::Pattern(text::cron);
const TZ: Shape = Shape::Pattern(text::timezone);
const PATH: Shape = Shape::Pattern(text::abs_path);
const BUCKET: Shape = Shape::Pattern(text::bucket);
const LABEL: Shape = Shape::Label(1, 128);
const ARGV: Shape = Shape::Custom(argv);

fn argv(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        (1..=64).contains(&items.len())
            && items.iter().all(|item| check(&Shape::Text(1, 1024), item))
    })
}

const SIGREF: Shape = Shape::Object(&[("key_id", KID), ("sig", Shape::Sig64)]);
const KEY_SCOPE: Shape = Shape::Object(&[
    ("project_ids", Shape::Set(&UUID7, 1, 32)),
    ("environments", Shape::Set(&REF, 1, 16)),
    ("server_level", Shape::Bool),
]);
pub(crate) const KEY_ENTRY: Shape = Shape::Object(&[
    ("key_id", KID),
    ("alg", Shape::Enum(&["ES256-raw"])),
    ("spki", Shape::Text(1, 200)),
    ("label", LABEL),
    ("role", Shape::Enum(&["owner", "deployer", "ci"])),
    (
        "presence",
        Shape::Enum(&["biometry", "user_presence", "none"]),
    ),
    ("scope", Shape::Nullable(&KEY_SCOPE)),
    ("added_at", Shape::Timestamp),
    ("added_by", Shape::Nullable(&SIGREF)),
]);
pub(crate) const REVOCATION: Shape = Shape::Object(&[
    ("key_id", KID),
    ("revoked_at", Shape::Timestamp),
    (
        "reason",
        Shape::Enum(&["lost", "compromised", "rotated", "other"]),
    ),
    ("revoked_by", SIGREF),
]);
pub(crate) const RULE: Shape = Shape::Object(&[
    ("version", Shape::Int(1, 1)),
    ("id", UUID7),
    ("label", LABEL),
    ("trigger", Shape::Enum(&["git.push"])),
    (
        "scope",
        Shape::Object(&[
            ("project_id", UUID7),
            ("environment", REF),
            ("service_ids", Shape::Set(&UUID7, 1, 32)),
            ("server_ids", Shape::Set(&UUID7, 1, 32)),
            ("repo", Shape::Pattern(text::repo)),
            ("branch_patterns", Shape::Set(&Shape::GitRef(true), 1, 8)),
        ]),
    ),
    ("allowed_kinds", Shape::Set(&Shape::Enum(&["deploy"]), 1, 8)),
    (
        "limits",
        Shape::Object(&[
            ("max_replicas", Shape::Nullable(&Shape::Int(1, 1000))),
            ("max_invocations_per_hour", Shape::Int(1, 120)),
        ]),
    ),
    ("not_before", Shape::Timestamp),
    ("expires_at", Shape::Timestamp),
]);

const HEALTHCHECK: Shape = Shape::Object(&[
    ("kind", Shape::Enum(&["http", "tcp", "cmd"])),
    ("path", Shape::Nullable(&PATH)),
    ("port", Shape::Nullable(&Shape::Int(1, 65_535))),
    ("command", Shape::Nullable(&ARGV)),
    ("interval_seconds", Shape::Int(1, 3_600)),
    ("timeout_seconds", Shape::Int(1, 600)),
    ("retries", Shape::Int(0, 100)),
    ("start_period_seconds", Shape::Int(0, 3_600)),
]);
const PORT: Shape = Shape::Object(&[
    ("container_port", Shape::Int(1, 65_535)),
    ("protocol", Shape::Enum(&["tcp", "udp"])),
    ("public", Shape::Bool),
]);
const MOUNT: Shape = Shape::Object(&[
    ("volume_id", UUID7),
    ("mount_path", PATH),
    ("read_only", Shape::Bool),
]);
const SPEC_FIELDS: &[(&str, Shape)] = &[
    ("version", Shape::Int(1, 1)),
    ("service_id", UUID7),
    ("image_repository", Shape::Custom(image_repository)),
    ("image_digest_hex", HEX64),
    ("entrypoint", Shape::Nullable(&ARGV)),
    ("command", Shape::Nullable(&ARGV)),
    ("working_dir", Shape::Nullable(&PATH)),
    ("user", Shape::Nullable(&Shape::Pattern(text::user))),
    ("env", Shape::Custom(spec_env)),
    ("ports", Shape::Custom(spec_ports)),
    ("mounts", Shape::Custom(spec_mounts)),
    (
        "resources",
        Shape::Object(&[
            ("cpu_millis", Shape::Nullable(&Shape::Int(10, 256_000))),
            (
                "memory_bytes",
                Shape::Nullable(&Shape::Int(1 << 22, 1 << 40)),
            ),
            ("pids_limit", Shape::Nullable(&Shape::Int(16, 1 << 22))),
        ]),
    ),
    ("privileged", Shape::Bool),
    (
        "cap_add",
        Shape::Set(&Shape::Pattern(text::capability), 0, 16),
    ),
    (
        "network",
        Shape::Object(&[
            ("mode", Shape::Enum(&["project", "host", "none"])),
            ("aliases", Shape::Set(&HOST, 0, 8)),
        ]),
    ),
    ("healthcheck", Shape::Nullable(&HEALTHCHECK)),
    ("replicas", Shape::Int(0, 1_000)),
    (
        "placement",
        Shape::Object(&[("server_ids", Shape::Set(&UUID7, 1, 32))]),
    ),
    // v1.0.2 (D-027): secrets only as files under /run/secrets.
    ("secrets_as_files_only", Shape::Bool),
    // v1.0.5 (D-045): the Engine API ServiceKind, written into the
    // permanu.service_kind label. Never elevates the spec.
    (
        "service_kind",
        Shape::Enum(&["web", "worker", "database", "bucket", "cron", "static"]),
    ),
    // v1.0.7 (D-053): `false` opts the service out of the runner-derived
    // OpenTelemetry environment (section 14.7).
    ("otel_inject", Shape::Bool),
];

/// A `ServiceSpec` (section 3.7): every field of `SPEC_FIELDS`, plus the
/// optional members `build` (v1.0.9, D-056), `routes` (v1.0.14, D-064) and
/// `strategy` (v1.0.17, D-067), which are never `null`.
pub(crate) const SPEC: Shape = Shape::Custom(spec_shape);

fn spec_shape(value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    let mut rest = map.clone();
    if let Some(recipe) = rest.remove("build") {
        if !spec_build::build_recipe(&recipe) {
            return false;
        }
    }
    // v1.0.14 (D-064 #9): the optional member `routes`, never `null`.
    if let Some(routes) = rest.remove("routes") {
        if !spec_routes(&routes) {
            return false;
        }
    }
    // v1.0.17 (D-067 #1): the optional member `strategy`, never `null`.
    let strategy = match rest.remove("strategy") {
        None => None,
        Some(Value::String(s)) if s == "rolling" || s == "recreate" => Some(s),
        Some(_) => return false,
    };
    if !check(&Shape::Object(SPEC_FIELDS), &Value::Object(rest)) {
        return false;
    }
    // A spec that mounts a named volume is `recreate` (signed or derived)
    // with at most one replica: never two containers on one volume.
    let mounts_volume = map["mounts"].as_array().is_some_and(|m| !m.is_empty());
    !mounts_volume
        || (strategy.as_deref() != Some("rolling") && map["replicas"].as_i64().unwrap_or(0) <= 1)
}

/// `ServiceSpec.routes` (v1.0.14, D-064 #9): 0–16 `{hostname, source}`
/// sorted and unique by `hostname`; a `default` entry is a default route
/// host, a `custom` one never ends in `.sslip.io` (reference `spec_routes`).
fn spec_routes(value: &Value) -> bool {
    const ROUTE: Shape = Shape::Object(&[
        ("hostname", HOST),
        ("source", Shape::Enum(&["default", "custom"])),
    ]);
    sorted_unique_objects(value, &ROUTE, 16, |route| {
        route["hostname"].as_str().map(str::to_owned)
    }) && value.as_array().is_some_and(|routes| {
        routes.iter().all(|route| {
            let host = route["hostname"].as_str().unwrap_or_default();
            if route["source"] == "default" {
                text::default_route(host)
            } else {
                !host.ends_with(".sslip.io")
            }
        })
    })
}

fn image_repository(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| (1..=255).contains(&text.len()) && text::image_repository(text))
}

fn spec_env(value: &Value) -> bool {
    const BINDING: Shape = Shape::Object(&[
        ("kind", Shape::Enum(&["plain", "secret", "reference"])),
        ("ref", Shape::Nullable(&Shape::Text(1, 256))),
    ]);
    value.as_object().is_some_and(|map| {
        map.len() <= 256
            && map.iter().all(|(name, binding)| {
                text::env_name(name)
                    && check(&BINDING, binding)
                    && (binding["kind"] == "plain") == binding["ref"].is_null()
            })
    })
}

fn sorted_unique_objects<K: Ord>(
    value: &Value,
    shape: &Shape,
    high: usize,
    key: impl Fn(&Value) -> K,
) -> bool {
    value.as_array().is_some_and(|items| {
        items.len() <= high
            && items.iter().all(|item| check(shape, item))
            && items.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
    })
}

fn spec_ports(value: &Value) -> bool {
    sorted_unique_objects(value, &PORT, 32, |port| {
        (
            port["container_port"].as_i64(),
            port["protocol"].as_str().map(str::to_owned),
        )
    })
}

fn spec_mounts(value: &Value) -> bool {
    sorted_unique_objects(value, &MOUNT, 16, |mount| {
        mount["mount_path"].as_str().map(str::to_owned)
    })
}

/// Elevated specs need a `service.elevate` action for the same digest.
pub(crate) fn spec_elevated(spec: &Value) -> bool {
    let extra_capability = spec["cap_add"]
        .as_array()
        .is_some_and(|caps| caps.iter().any(|cap| cap != "NET_BIND_SERVICE"));
    spec["privileged"] == true || extra_capability || spec["network"]["mode"] == "host"
}

mod actions;
mod actions_m2;
mod spec_build;
pub(crate) use actions::{rollback_target, validate_plan, SPEC_KINDS};

const EVIDENCE: Shape = Shape::Object(&[
    (
        "provider",
        Shape::Enum(&["github", "gitlab", "gitea", "generic"]),
    ),
    ("repo", Shape::Pattern(text::repo)),
    ("ref", Shape::GitRef(false)),
    ("commit_sha", Shape::Pattern(text::hex40)),
    ("commit_time", Shape::Timestamp),
    ("delivery_id", Shape::Pattern(text::delivery_id)),
    ("body_digest_hex", HEX64),
    ("received_at", Shape::Timestamp),
]);
const INVOCATION: Shape = Shape::Object(&[
    ("rule_id", UUID7),
    ("rule_digest_hex", HEX64),
    ("trigger", Shape::Enum(&["git.push"])),
    ("evidence", EVIDENCE),
]);
pub(crate) const SIGNATURE: Shape = Shape::Object(&[
    ("key_id", KID),
    ("alg", Shape::Text(1, 32)),
    ("sig", Shape::Sig64),
    ("signed_at", Shape::Timestamp),
]);

/// Owner keys have no scope; deployer and ci keys do; ci keys are never
/// server-level and are exactly the keys with presence `none`.
pub(crate) fn key_scope_shape_ok(entry: &Value) -> bool {
    let role = entry["role"].as_str().unwrap_or_default();
    let scope = &entry["scope"];
    (role == "owner") == scope.is_null()
        && !(role == "ci" && scope["server_level"] == true)
        && (role == "ci") == (entry["presence"] == "none")
}

/// Distinct string values of a set, for comparisons.
pub(crate) fn string_set(value: &Value) -> BTreeSet<&str> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}
