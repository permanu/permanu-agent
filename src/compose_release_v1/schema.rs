use super::{generated, Error, CAPABILITY, MAX_BYTES};
use crate::signed_plan::{crypto, jcs};
use serde_json::Value;

pub(super) fn digest(domain: &[u8], value: &Value) -> Result<String, Error> {
    let canonical = jcs::canonicalize(value).ok_or(Error::Parse)?;
    Ok(hex::encode(crypto::prefixed_digest(domain, &canonical)))
}
fn fields(v: &Value, names: &[&str]) -> Result<(), Error> {
    let obj = v.as_object().ok_or(Error::Parse)?;
    if obj.len() != names.len() || names.iter().any(|k| !obj.contains_key(*k)) {
        return Err(Error::Parse);
    }
    Ok(())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, Error> {
    v[k].as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or(Error::Parse)
}
fn hash(v: &Value, k: &str, n: usize) -> Result<(), Error> {
    let s = text(v, k)?;
    if s.len() != n
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Parse);
    };
    Ok(())
}
fn identifier(v: &Value, k: &str) -> Result<(), Error> {
    let s = text(v, k)?;
    if s.len() > 128
        || !s.as_bytes()[0].is_ascii_alphanumeric()
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(Error::Parse);
    };
    Ok(())
}
fn artifacts(v: &Value) -> Result<(), Error> {
    fields(v, &["backend", "authenticated_frontend", "public_frontend"])?;
    fields(&v["backend"], &["server", "worker"])?;
    hash(&v["backend"], "server", 64)?;
    hash(&v["backend"], "worker", 64)?;
    hash(v, "authenticated_frontend", 64)?;
    hash(v, "public_frontend", 64)
}
fn time(v: &Value, now: i64) -> Result<(), Error> {
    let issued = v["issued_at"].as_i64().ok_or(Error::Parse)?;
    let expires = v["expires_at"].as_i64().ok_or(Error::Parse)?;
    if issued <= 0 || issued > now || expires <= now || expires <= issued {
        return Err(Error::Binding);
    };
    Ok(())
}
pub(super) fn parse(raw: &[u8], now: i64) -> Result<Value, Error> {
    let e = jcs::parse_strict(raw, MAX_BYTES).ok_or(Error::Parse)?;
    fields(
        &e,
        &[
            "release",
            "attestation",
            "authorization",
            "producer_signature",
            "owner_signature",
        ],
    )?;
    let r = &e["release"];
    let a = &e["attestation"];
    let o = &e["authorization"];
    fields(
        r,
        &[
            "version",
            "capability",
            "action",
            "application_id",
            "spec_digest",
            "policy_digest",
            "policy_revision",
            "target",
            "source",
            "candidate",
            "previous",
            "release_id",
            "previous_release_id",
            "inventory_digest",
            "migrations",
            "generation",
            "previous_generation",
        ],
    )?;
    if r["version"] != 1
        || r["capability"] != CAPABILITY
        || r["action"] != "compose.release"
        || r["migrations"] != "none"
    {
        return Err(Error::Binding);
    }
    for key in ["application_id", "release_id", "previous_release_id"] {
        identifier(r, key)?
    }
    for key in ["spec_digest", "policy_digest", "inventory_digest"] {
        hash(r, key, 64)?
    }
    let generation = r["generation"].as_u64().ok_or(Error::Parse)?;
    let previous = r["previous_generation"].as_u64().ok_or(Error::Parse)?;
    if previous.checked_add(1) != Some(generation)
        || generation == 0
        || r["release_id"] == r["previous_release_id"]
        || r["policy_revision"].as_u64().unwrap_or(0) == 0
    {
        return Err(Error::Binding);
    }
    let t = &r["target"];
    fields(
        t,
        &[
            "server_id",
            "root",
            "compose_project",
            "config_digest",
            "protected_digest",
        ],
    )?;
    identifier(t, "server_id")?;
    identifier(t, "compose_project")?;
    hash(t, "config_digest", 64)?;
    hash(t, "protected_digest", 64)?;
    let root = text(t, "root")?;
    if root.len() >= 256
        || !root.starts_with('/')
        || root.split('/').skip(1).any(|s| {
            s.is_empty()
                || s == "."
                || s == ".."
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(Error::Parse);
    }
    let s = &r["source"];
    fields(s, &["repository", "ref", "commit", "tree", "desktop_tree"])?;
    text(s, "repository")?;
    text(s, "ref")?;
    for key in ["commit", "tree", "desktop_tree"] {
        hash(s, key, 40)?
    }
    artifacts(&r["candidate"])?;
    artifacts(&r["previous"])?;
    fields(
        a,
        &[
            "release_digest",
            "policy_digest",
            "policy_revision",
            "verification_config_digest",
            "run_id",
            "producer_id",
            "issued_at",
            "expires_at",
            "gates",
        ],
    )?;
    for key in [
        "release_digest",
        "policy_digest",
        "verification_config_digest",
    ] {
        hash(a, key, 64)?
    }
    identifier(a, "run_id")?;
    identifier(a, "producer_id")?;
    time(a, now)?;
    let gates = a["gates"].as_object().ok_or(Error::Parse)?;
    if gates.keys().any(|k| {
        let v = serde_json::json!({"gate":k});
        identifier(&v, "gate").is_err()
    }) || gates.is_empty()
        || gates.len() > 32
        || gates.values().any(|s| s != "success")
    {
        return Err(Error::Binding);
    }
    fields(
        o,
        &[
            "release_digest",
            "attestation_digest",
            "owner_id",
            "issued_at",
            "expires_at",
        ],
    )?;
    hash(o, "release_digest", 64)?;
    hash(o, "attestation_digest", 64)?;
    identifier(o, "owner_id")?;
    time(o, now)?;
    for key in ["producer_signature", "owner_signature"] {
        let sig = &e[key];
        fields(sig, &["key_id", "alg", "sig"])?;
        if !canonical_b64(text(sig, "key_id")?, 16)
            || !canonical_b64(text(sig, "sig")?, 64)
            || text(sig, "key_id")?.len() != 22
            || sig["alg"] != "ES256-raw"
            || text(sig, "sig")?.len() != 86
        {
            return Err(Error::Parse);
        }
    }
    let rd = digest(generated::RELEASE_DOMAIN.as_bytes(), r)?;
    if a["release_digest"] != rd
        || o["release_digest"] != rd
        || o["attestation_digest"] != digest(generated::ATTESTATION_DOMAIN.as_bytes(), a)?
        || a["policy_digest"] != r["policy_digest"]
        || a["policy_revision"] != r["policy_revision"]
        || a["producer_id"] == o["owner_id"]
        || e["producer_signature"]["key_id"] == e["owner_signature"]["key_id"]
    {
        return Err(Error::Binding);
    }
    Ok(e)
}

fn canonical_b64(s: &str, n: usize) -> bool {
    crypto::b64url_decode(s)
        .is_some_and(|decoded| decoded.len() == n && crypto::b64url_encode(&decoded) == s)
}
