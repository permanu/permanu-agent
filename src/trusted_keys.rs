//! Read-only view of `/etc/permanu/trusted-keys.json` (signed-plan.md section 7).
//!
//! This module does not verify key entries or signatures; it answers "is
//! signing enabled" (S8) and builds the `TrustedKeysSummary` for Hello.

use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TRUSTED_KEYS_PATH: &str = "/etc/permanu/trusted-keys.json";
const MAX_TRUSTED_KEYS_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedKeysSummary {
    pub fingerprint_digest_hex: String,
    pub key_count: u32,
    pub generation: u64,
    pub server_id: String,
}

#[derive(Debug, Error)]
pub enum TrustedKeysError {
    #[error("trusted-keys file is invalid: {0}")]
    Invalid(String),
    #[error("read trusted-keys file: {0}")]
    Io(#[from] std::io::Error),
}

/// Signing is enabled once anything exists at `path`. Any error other than
/// "not found" (a dangling symlink, EACCES) also counts as enabled: fail closed.
pub fn signing_enabled(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(err) => err.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Reads and summarises the trusted-keys file. `Ok(None)` when it is absent.
pub fn read_summary(
    path: &Path,
    require_root_owner: bool,
) -> Result<Option<TrustedKeysSummary>, TrustedKeysError> {
    // O_NOFOLLOW: a symlink at the path fails the open (ELOOP) instead of
    // being followed (signed-plan.md 7.1).
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(invalid("not a regular file"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(invalid("group- or world-writable"));
    }
    if require_root_owner && meta.uid() != 0 {
        return Err(invalid("not owned by root"));
    }
    if meta.len() > MAX_TRUSTED_KEYS_BYTES {
        return Err(invalid("larger than 256 KiB"));
    }
    let mut raw = Vec::with_capacity(meta.len() as usize);
    file.by_ref()
        .take(MAX_TRUSTED_KEYS_BYTES + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_TRUSTED_KEYS_BYTES {
        return Err(invalid("larger than 256 KiB"));
    }
    summarize(&raw).map(Some)
}

fn summarize(raw: &[u8]) -> Result<TrustedKeysSummary, TrustedKeysError> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|err| invalid(&format!("not JSON: {err}")))?;
    let object = value.as_object().ok_or_else(|| invalid("not an object"))?;
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("keys must be an array"))?;
    let revocations = object
        .get("revocations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("revocations must be an array"))?;
    let revoked: HashSet<&str> = revocations
        .iter()
        .filter_map(|r| r.get("key_id").and_then(Value::as_str))
        .collect();
    let active = keys
        .iter()
        .filter_map(|k| k.get("key_id").and_then(Value::as_str))
        .filter(|id| !revoked.contains(id))
        .count();

    let mut canonical = String::with_capacity(raw.len());
    write_jcs(&value, &mut canonical)?;

    Ok(TrustedKeysSummary {
        fingerprint_digest_hex: hex::encode(Sha256::digest(canonical.as_bytes())),
        key_count: u32::try_from(active).unwrap_or(u32::MAX),
        // The file is append-only (signed-plan.md 7), so the number of entries
        // is monotonic and bumps on every add and revoke.
        generation: (keys.len() + revocations.len()) as u64,
        server_id: object
            .get("server_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// RFC 8785 JCS restricted to the signed-plan profile (integers only).
fn write_jcs(value: &Value, out: &mut String) -> Result<(), TrustedKeysError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            out.push_str(&serde_json::to_string(value).map_err(|e| invalid(&e.to_string()))?);
        }
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(invalid("non-integer number"));
            }
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // JCS sorts member names by their UTF-16 code units.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).map_err(|e| invalid(&e.to_string()))?);
                out.push(':');
                write_jcs(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn invalid(reason: &str) -> TrustedKeysError {
    TrustedKeysError::Invalid(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permanu-trusted-keys-{name}-{}-{}",
            std::process::id(),
            crate::timeutil::now_unix_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SAMPLE: &str = r#"{
      "version": 1,
      "server_id": "01a0cdb5-3500-70a1-8000-000000000001",
      "keys": [
        {"key_id": "a", "alg": "ES256-raw", "label": "Mac é", "added_by": null},
        {"key_id": "b", "alg": "ES256-raw", "label": "Old", "added_by": {"key_id": "a", "sig": "x"}}
      ],
      "revocations": [{"key_id": "b", "reason": "lost"}]
    }"#;

    #[test]
    fn absent_file_is_not_signing_enabled() {
        let dir = temp_dir("absent");
        assert!(!signing_enabled(&dir.join("trusted-keys.json")));
        assert!(read_summary(&dir.join("trusted-keys.json"), false)
            .unwrap()
            .is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn summary_counts_active_keys_and_generation() {
        let dir = temp_dir("summary");
        let path = dir.join("trusted-keys.json");
        fs::write(&path, SAMPLE).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(signing_enabled(&path));
        let summary = read_summary(&path, false).unwrap().unwrap();
        assert_eq!(summary.key_count, 1);
        assert_eq!(summary.generation, 3);
        assert_eq!(summary.server_id, "01a0cdb5-3500-70a1-8000-000000000001");
        assert_eq!(summary.fingerprint_digest_hex.len(), 64);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fingerprint_ignores_whitespace_and_key_order() {
        let dir = temp_dir("canon");
        let a = dir.join("a.json");
        let b = dir.join("b.json");
        fs::write(
            &a,
            r#"{"version":1,"keys":[],"revocations":[],"server_id":"s"}"#,
        )
        .unwrap();
        fs::write(
            &b,
            "{ \"server_id\" : \"s\",\n \"revocations\": [], \"keys\": [], \"version\": 1 }",
        )
        .unwrap();
        let fa = read_summary(&a, false).unwrap().unwrap();
        let fb = read_summary(&b, false).unwrap().unwrap();
        assert_eq!(fa.fingerprint_digest_hex, fb.fingerprint_digest_hex);
        // sha256(JCS) of {"keys":[],"revocations":[],"server_id":"s","version":1}
        assert_eq!(
            fa.fingerprint_digest_hex,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                br#"{"keys":[],"revocations":[],"server_id":"s","version":1}"#
            ))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_group_writable_symlink_oversize_and_floats() {
        let dir = temp_dir("reject");
        let path = dir.join("trusted-keys.json");
        fs::write(&path, SAMPLE).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_summary(&path, false).is_err());

        let link = dir.join("link.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_summary(&link, false).is_err());

        let big = dir.join("big.json");
        fs::write(&big, vec![b' '; 256 * 1024 + 1]).unwrap();
        fs::set_permissions(&big, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_summary(&big, false).is_err());

        let float = dir.join("float.json");
        fs::write(&float, r#"{"version":1.0,"keys":[],"revocations":[]}"#).unwrap();
        fs::set_permissions(&float, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_summary(&float, false).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn requires_root_owner_when_asked() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = temp_dir("owner");
        let path = dir.join("trusted-keys.json");
        fs::write(&path, SAMPLE).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_summary(&path, true).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
