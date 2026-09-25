//! Action kinds and rules added by contracts v1.0.7–v1.1.2 (signed-plan.md
//! section 3.2): backup destinations, the recovery recipient, environment
//! protection, release keys and repository credentials, plus the cron
//! grammar of section 14.9 that `cron.*` and `backup.policy.set` must parse.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::crypto::{b64url_encode, hex};
use super::super::text;
use super::{Shape, HEX64, LABEL, REF};

/// `age1[02-9ac-hj-np-z]{58}`
fn age_recipient(value: &str) -> bool {
    value.strip_prefix("age1").is_some_and(|rest| {
        rest.len() == 58
            && rest.bytes().all(|b| {
                matches!(b, b'0' | b'2'..=b'9' | b'a' | b'c'..=b'h' | b'j'..=b'n' | b'p'..=b'z')
            })
    })
}

fn host_chars(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && host
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && host
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric())
}

/// `(https|sftp)://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?`
fn endpoint(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("sftp://"))
    else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    host_chars(host)
        && port.is_none_or(|port| {
            (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit())
        })
}

/// `([A-Za-z0-9._-]{1,64}(/[A-Za-z0-9._-]{1,64}){0,7})?`; v1.0.11 (D-061):
/// no `.` or `..` segment, so an object key never leaves the prefix.
fn prefix(value: &str) -> bool {
    value.is_empty() || {
        let parts: Vec<&str> = value.split('/').collect();
        parts.len() <= 8
            && parts.iter().all(|part| {
                (1..=64).contains(&part.len())
                    && !matches!(*part, "." | "..")
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
    }
}

/// `permanu/v1/<uuid7>/<uuid7>/<uuid7>.age` (v1.0.11, D-061): where an
/// imported restore's object is, below the destination's prefix.
fn object_key(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("permanu/v1/") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    parts.len() == 3
        && text::uuid7(parts[0])
        && text::uuid7(parts[1])
        && parts[2].strip_suffix(".age").is_some_and(text::uuid7)
}

const DB_CREDENTIALS: Shape = Shape::Object(&[
    ("user", Shape::Pattern(text::env_name)),
    ("password", Shape::Pattern(text::env_name)),
    ("database", Shape::Pattern(text::env_name)),
]);
const UUID7: Shape = Shape::Pattern(text::uuid7);

/// v1.0.11 (D-061): members an action MAY carry, never null (reference
/// `OPTIONAL_PARAMS`).
pub(super) fn optional_params_for(kind: &str) -> &'static [(&'static str, Shape)] {
    match kind {
        "restore" => &[
            ("source_resource_id", UUID7),
            ("destination_ref", REF),
            ("object_key", Shape::Pattern(object_key)),
        ],
        "backup.policy.set" => &[
            ("db_credentials_ref", DB_CREDENTIALS),
            ("channel_ids", Shape::Set(&UUID7, 0, 16)),
        ],
        // v1.0.13 (D-063 #5, #10): a default route; the one run a cancel stops.
        "domain.add" => &[("source", Shape::Enum(&["custom", "default"]))],
        "operation.cancel" => &[("run_id", UUID7)],
        // v1.0.14 (D-064 #11): the pinned private CA of an S3-compatible
        // endpoint (reference `_ca_pem`).
        "backup.destination.set" => &[("ca_pem", Shape::Custom(ca_pem))],
        _ => &[],
    }
}

/// v1.0.11 (D-061, reference `_restore_shape`): an imported restore signs
/// its location and never `source_resource_id`; a server restore signs no
/// location; a restore into another service needs a `deploy` of that
/// service earlier in the same plan.
pub(super) fn restore_shape(plan: &Value, index: usize, params: &Value) -> bool {
    let located = params.get("destination_ref").is_some() || params.get("object_key").is_some();
    if params["origin"] == "imported" {
        let key_names_backup = params["object_key"]
            .as_str()
            .and_then(|key| key.rsplit('/').next())
            .zip(params["backup_id"].as_str())
            .is_some_and(|(last, backup)| last.strip_suffix(".age") == Some(backup));
        if params.get("destination_ref").is_none()
            || params.get("object_key").is_none()
            || params.get("source_resource_id").is_some()
            || !key_names_backup
        {
            return false;
        }
    } else if located {
        return false;
    }
    let resource = &params["resource_id"];
    let source = params.get("source_resource_id").unwrap_or(resource);
    source == resource
        || plan["actions"].as_array().is_some_and(|actions| {
            actions.iter().take(index).any(|earlier| {
                earlier["kind"] == "deploy" && earlier["params"]["service_id"] == *resource
            })
        })
}

/// `[a-z0-9-]{1,64}`
fn region(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `SHA256:[A-Za-z0-9+/]{43}`
fn fingerprint(value: &str) -> bool {
    value.strip_prefix("SHA256:").is_some_and(|rest| {
        rest.len() == 43
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
    })
}

/// The params of a kind added after v1.0.6, or `None`.
pub(super) fn params_for(kind: &str) -> Option<&'static [(&'static str, Shape)]> {
    Some(match kind {
        "backup.destination.set" => &[
            ("destination_ref", REF),
            (
                "destination_kind",
                Shape::Enum(&["r2", "s3", "b2", "sftp", "server_local"]),
            ),
            ("endpoint", Shape::Nullable(&Shape::Pattern(endpoint))),
            ("region", Shape::Nullable(&Shape::Pattern(region))),
            ("bucket", Shape::Nullable(&Shape::Pattern(text::bucket))),
            ("prefix", Shape::Pattern(prefix)),
            ("credential_ciphertext_digest_hex", Shape::Nullable(&HEX64)),
        ],
        "backup.destination.delete" => &[("destination_ref", REF)],
        "recovery_recipient.set" => &[("recipient", Shape::Pattern(age_recipient))],
        // v1.0.10 (contracts v1.1.2, D-060): `fingerprint_hex` is optional.
        "recovery_recipient.set+fingerprint" => &[
            ("recipient", Shape::Pattern(age_recipient)),
            ("fingerprint_hex", HEX64),
        ],
        "env.protection.set" => &[("environment", REF), ("protected", Shape::Bool)],
        "release_key.add" => &[
            ("key_id", Shape::Pattern(text::key_id)),
            ("spki", Shape::Text(1, 100)),
            ("label", LABEL),
        ],
        "release_key.revoke" => &[
            ("key_id", Shape::Pattern(text::key_id)),
            ("reason", Shape::Enum(&["compromised", "rotated", "other"])),
        ],
        "repo.credential.set" => &[
            ("repo", Shape::Pattern(text::repo)),
            (
                "credential_kind",
                Shape::Enum(&["ssh_deploy_key", "https_token"]),
            ),
            ("fingerprint", Shape::Pattern(fingerprint)),
            ("credential_ciphertext_digest_hex", HEX64),
        ],
        "repo.credential.delete" => &[("repo", Shape::Pattern(text::repo))],
        // v1.0.11 (D-061): the hostname Dwaar routes /hooks/* on.
        // v1.0.13 (D-063 #4): or a public IPv4 address.
        "webhook.host.set" => &[("webhook_host", Shape::Pattern(webhook_host))],
        // v1.0.19 (D-069): fixed-id migration of an already-set-up server.
        "server.accounts.migrate" => &[("server_id", UUID7)],
        _ => return None,
    })
}

/// `webhook.host.set` host: a hostname, or (v1.0.13, D-063 #4) a public
/// IPv4 address; any other dotted quad fails `E_PARSE`.
fn webhook_host(value: &str) -> bool {
    if text::ipv4_shaped(value) {
        text::public_ipv4(value)
    } else {
        text::hostname(value)
    }
}

/// Server-level kinds added in v1.0.7 (section 3.2).
pub(super) const SERVER_KINDS_M2: &[&str] = &[
    "backup.destination.set",
    "backup.destination.delete",
    "recovery_recipient.set",
    "release_key.add",
    "release_key.revoke",
    // v1.0.11 (D-061).
    "webhook.host.set",
    // v1.0.19 (D-069).
    "server.accounts.migrate",
];

/// Largest `backup.destination.set` `ca_pem` (v1.0.14, D-064 #11).
const CA_PEM_MAX: usize = 16_384;

/// `ca_pem`: 1–8 PEM `CERTIFICATE` blocks and nothing else (LF line ends,
/// base64 lines of at most 64 characters, each block decoding to DER), at
/// most 16384 bytes.
fn ca_pem(value: &Value) -> bool {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const END: &str = "-----END CERTIFICATE-----\n";
    let Some(mut rest) = value.as_str() else {
        return false;
    };
    if rest.is_empty() || rest.len() > CA_PEM_MAX {
        return false;
    }
    let mut blocks = 0;
    while !rest.is_empty() {
        let Some(body_and_more) = rest.strip_prefix(BEGIN) else {
            return false;
        };
        let Some(end) = body_and_more.find(END) else {
            return false;
        };
        if !pem_body(&body_and_more[..end]) {
            return false;
        }
        rest = &body_and_more[end + END.len()..];
        blocks += 1;
    }
    (1..=8).contains(&blocks)
}

/// A PEM block body: lines of 1–64 base64 characters ending in LF, only the
/// last one padded, decoding to a DER SEQUENCE.
fn pem_body(body: &str) -> bool {
    let Some(lines) = body.strip_suffix('\n') else {
        return false;
    };
    let lines: Vec<&str> = lines.split('\n').collect();
    let last = lines.len() - 1;
    let shaped = lines.iter().enumerate().all(|(index, line)| {
        let data = if index == last {
            line.trim_end_matches('=')
        } else {
            line
        };
        (1..=64).contains(&line.len())
            && line.len() - data.len() <= 2
            && data
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    });
    shaped
        && STANDARD
            .decode(lines.concat())
            .is_ok_and(|der| der.first() == Some(&0x30))
}

/// `backup.destination.set` (D-049): which optional fields each
/// destination kind carries.
fn destination_shape(params: &Value) -> bool {
    let endpoint = params["endpoint"].as_str();
    // v1.0.14 (D-064 #11): `ca_pem` only for an S3-API destination with its
    // own `https://` endpoint.
    if params.get("ca_pem").is_some()
        && (!matches!(
            params["destination_kind"].as_str(),
            Some("r2" | "s3" | "b2")
        ) || endpoint.is_none())
    {
        return false;
    }
    let credential = !params["credential_ciphertext_digest_hex"].is_null();
    let bucket = !params["bucket"].is_null();
    let region = !params["region"].is_null();
    match params["destination_kind"].as_str().unwrap_or_default() {
        "server_local" => endpoint.is_none() && !region && !bucket && !credential,
        "sftp" => {
            endpoint.is_some_and(|url| url.starts_with("sftp://"))
                && !bucket
                && !region
                && credential
        }
        kind => {
            bucket
                && credential
                && match endpoint {
                    Some(url) => url.starts_with("https://"),
                    None => kind == "s3",
                }
        }
    }
}

/// The plan-level rules of the kinds added after v1.0.6.
pub(super) fn action_rules_hold(plan: &Value, kind: &str, params: &Value) -> bool {
    match kind {
        "cron.create" | "cron.update" => params["schedule"].as_str().is_some_and(cron_parses),
        "backup.policy.set" => {
            params["schedule"].as_str().is_some_and(cron_parses)
                && params["verify_schedule"].as_str().is_none_or(cron_parses)
        }
        "env.protection.set" => params["environment"] == plan["environment"],
        // v1.0.13 (D-063 #5): a default route is an sslip.io host with ACME.
        "domain.add" => {
            params
                .get("source")
                .is_none_or(|source| source != "default")
                || (params["tls"] == "acme"
                    && params["hostname"].as_str().is_some_and(text::default_route))
        }
        "backup.destination.set" => destination_shape(params),
        "release_key.add" => params["spki"]
            .as_str()
            .and_then(release_key_id)
            .is_some_and(|key_id| params["key_id"] == key_id.as_str()),
        "recovery_recipient.set" => params.get("fingerprint_hex").is_none_or(|fingerprint| {
            params["recipient"]
                .as_str()
                .is_some_and(|recipient| *fingerprint == hex(&Sha256::digest(recipient.as_bytes())))
        }),
        // targets MUST be [server_id] (signed-plan.md 3.2).
        "server.accounts.migrate" => plan["targets"]
            .as_array()
            .is_some_and(|targets| targets.len() == 1 && targets[0] == params["server_id"]),
        _ => true,
    }
}

/// `SubjectPublicKeyInfo` DER of an Ed25519 key, before the 32 key bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The key id of a `release_key.add` SPKI (section 3.9): standard base64
/// (padded, canonical) of a 44-byte Ed25519 SPKI whose point is canonical
/// and on the curve; `key_id = base64url(SHA-256(DER)[0:16])`.
pub(crate) fn release_key_id(spki: &str) -> Option<String> {
    let der = STANDARD.decode(spki).ok()?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX || STANDARD.encode(&der) != spki {
        return None;
    }
    let bytes: [u8; 32] = der[12..].try_into().ok()?;
    let mut y = bytes;
    y[31] &= 0x7f;
    let at_or_above_p = y[31] == 0x7f && y[1..31].iter().all(|byte| *byte == 0xff) && y[0] >= 0xed;
    if at_or_above_p {
        return None;
    }
    curve25519_dalek::edwards::CompressedEdwardsY(bytes).decompress()?;
    Some(b64url_encode(&Sha256::digest(&der)[..16]))
}

const CRON_FIELDS: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];

/// Parses one cron item `(\*|\d{1,2}(-\d{1,2})?)(/\d{1,2})?` in `low..=high`.
fn cron_item(item: &str, low: u32, high: u32) -> bool {
    let (range, step) = match item.split_once('/') {
        Some((range, step)) => (range, Some(step)),
        None => (item, None),
    };
    let number = |text: &str| {
        ((1..=2).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse::<u32>().ok())
            .flatten()
    };
    if step.is_some_and(|step| number(step).is_none_or(|step| step < 1)) {
        return false;
    }
    let bounds = if range == "*" {
        Some((low, high))
    } else if let Some((start, end)) = range.split_once('-') {
        number(start).zip(number(end))
    } else {
        number(range).map(|start| (start, if item.contains('/') { high } else { start }))
    };
    bounds.is_some_and(|(start, end)| low <= start && start <= end && end <= high)
}

/// The five-field grammar of section 14.9 (reference `cron_parse`).
pub(crate) fn cron_parses(expression: &str) -> bool {
    let fields: Vec<&str> = expression.split(' ').collect();
    fields.len() == 5
        && fields
            .iter()
            .zip(CRON_FIELDS)
            .all(|(field, (low, high))| field.split(',').all(|item| cron_item(item, low, high)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_grammar_matches_section_14_9() {
        for ok in [
            "* * * * *",
            "*/15 0-6 1,15 * 1-5",
            "0 3 * * 7",
            "5/10 * * * *",
            "0 0 31 12 0",
        ] {
            assert!(cron_parses(ok), "{ok}");
        }
        for bad in [
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "* * * *",
            "MON * * * *",
            "* * * * * *",
            "1,,2 * * * *",
            "100 * * * *",
            "  * * * *",
        ] {
            assert!(!cron_parses(bad), "{bad}");
        }
    }

    #[test]
    fn destinations_carry_exactly_their_fields() {
        let base = serde_json::json!({"destination_ref": "d", "destination_kind": "s3",
            "endpoint": null, "region": "eu-central-1", "bucket": "backups",
            "prefix": "", "credential_ciphertext_digest_hex": "00".repeat(32)});
        assert!(destination_shape(&base));
        let mut r2 = base.clone();
        r2["destination_kind"] = "r2".into();
        assert!(!destination_shape(&r2), "r2 names its endpoint");
        r2["endpoint"] = "https://acct.r2.cloudflarestorage.com".into();
        assert!(destination_shape(&r2));
        let local = serde_json::json!({"destination_ref": "d", "destination_kind": "server_local",
            "endpoint": null, "region": null, "bucket": null, "prefix": "",
            "credential_ciphertext_digest_hex": null});
        assert!(destination_shape(&local));
        assert!(age_recipient(
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        ));
        assert!(!age_recipient("age1BAD"));
        assert!(endpoint("sftp://backup.example.com:22"));
        assert!(!endpoint("http://x.example.com"));
        assert!(fingerprint(
            "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"
        ));
    }
}
