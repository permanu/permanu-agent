//! `/etc/permanu/trusted-keys.json`: load-time validation (signed-plan.md
//! section 7.2), the trust state reported by Hello, and the write procedure
//! of section 7.4 (bootstrap, `key.add`, `key.revoke`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
#[cfg(test)]
use std::fs::{self, File};
use std::io::Read;
#[cfg(test)]
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::crypto::{
    b64url_decode, hex, parse_spki_base64, prefixed_digest, PublicKey, KEY_ADD_PREFIX,
    KEY_REVOKE_PREFIX,
};
use super::jcs::{canonicalize, parse_strict};
use super::schema::{check, key_scope_shape_ok, Shape, KEY_ENTRY, REVOCATION};
use super::text;

pub const MAX_TRUST_FILE_BYTES: usize = 256 * 1024;

/// The public TEST key ids of `vectors/signed-plan/keys.json` (section 7.2).
pub const TEST_KEY_IDS: [&str; 5] = [
    "dYLNItf797wK7n5moGt2cw",
    "Hph9XRkn48eogeehAgeI9A",
    "AqhPUHwy5byXy_JwVWyl7w",
    "cJWnw46mKT4S-FIYD8h8iA",
    "TTnId5ZJWi6UIgsNoJGjLA",
];

/// Whether the public TEST keys may be trusted. Only unit tests can construct
/// `Test`; every production path uses `Production`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    Production,
    #[cfg(test)]
    Test,
}

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub public_key: PublicKey,
    pub entry: Value,
}

/// A validated trust store.
#[derive(Debug, Clone)]
pub struct TrustStore {
    pub server_id: String,
    pub keys: BTreeMap<String, TrustedKey>,
    /// Effective revoked set: direct revocations plus the compromised cascade.
    pub revoked: BTreeSet<String>,
    pub compromised: BTreeSet<String>,
    /// key_id → (revoked_at, reason) of direct revocations.
    pub revocations: BTreeMap<String, (String, String)>,
    pub mode: TrustMode,
    /// The parsed file, for the section 7.4 superset write.
    pub document: Value,
    /// The file bytes as read (empty when not loaded from disk).
    pub raw: Vec<u8>,
}

impl TrustStore {
    pub fn is_test_key(&self, key_id: &str) -> bool {
        self.mode == TrustMode::Production && TEST_KEY_IDS.contains(&key_id)
    }

    pub fn fingerprint_digest_hex(&self) -> String {
        fingerprint(&self.document)
    }

    /// Monotonic: entries are never removed (section 7.2).
    pub fn generation(&self) -> u64 {
        let count = |field: &str| self.document[field].as_array().map_or(0, Vec::len);
        (count("keys") + count("revocations")) as u64
    }

    pub fn active_key_count(&self) -> u32 {
        let active = self
            .keys
            .keys()
            .filter(|id| !self.revoked.contains(*id))
            .count();
        u32::try_from(active).unwrap_or(u32::MAX)
    }

    /// Non-revoked owner keys, for the key.revoke lockout guard.
    pub fn active_owner_count(&self) -> usize {
        self.keys
            .iter()
            .filter(|(id, key)| key.entry["role"] == "owner" && !self.revoked.contains(*id))
            .count()
    }
}

/// hex SHA-256 of JCS(parsed file) (section 7.2).
pub fn fingerprint(document: &Value) -> String {
    canonicalize(document)
        .map(|jcs| hex(&Sha256::digest(jcs.as_bytes())))
        .unwrap_or_default()
}

const TRUST_FILE: Shape = Shape::Object(&[
    ("version", Shape::Int(1, 1)),
    ("server_id", Shape::Pattern(text::uuid7)),
    ("keys", Shape::Custom(key_entries)),
    ("revocations", Shape::Custom(revocations)),
]);

fn key_entries(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(|entry| check(&KEY_ENTRY, entry)))
}

fn revocations(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(|entry| check(&REVOCATION, entry)))
}

fn statement_digest(entry: &Value, prefix: &[u8], field: &str) -> Option<[u8; 32]> {
    let mut statement = entry.clone();
    statement
        .as_object_mut()?
        .insert(field.to_owned(), Value::Null);
    Some(prefixed_digest(prefix, &canonicalize(&statement)?))
}

fn signed_by_owner(
    keys: &BTreeMap<String, TrustedKey>,
    signer: &Value,
    digest: Option<[u8; 32]>,
) -> bool {
    let (Some(signer_id), Some(digest)) = (signer["key_id"].as_str(), digest) else {
        return false;
    };
    let Some(owner) = keys.get(signer_id) else {
        return false;
    };
    owner.entry["role"] == "owner"
        && signer["sig"]
            .as_str()
            .and_then(b64url_decode)
            .is_some_and(|sig| owner.public_key.verify_prehash(&digest, &sig))
}

/// Validates a parsed trusted-keys object (section 7.2 load-time rules).
/// The error names the rule that failed (`TrustedKeysSummary.invalid_reason`).
pub fn validate_trust(value: &Value, mode: TrustMode) -> Result<TrustStore, &'static str> {
    if !check(&TRUST_FILE, value) {
        return Err("schema: unknown, missing or malformed field");
    }
    let mut keys: BTreeMap<String, TrustedKey> = BTreeMap::new();
    let mut order = Vec::new();
    let entries = value["keys"].as_array().ok_or("schema: keys")?;
    if entries.is_empty() {
        return Err("keys[0] must be the TOFU owner");
    }
    for (index, entry) in entries.iter().enumerate() {
        let key_id = entry["key_id"].as_str().ok_or("schema: key_id")?;
        let public_key = parse_spki_base64(entry["spki"].as_str().unwrap_or_default())
            .ok_or("spki is not an uncompressed P-256 point")?;
        if public_key.key_id != key_id {
            return Err("key_id does not match the spki");
        }
        if keys.contains_key(key_id) {
            return Err("duplicate key_id");
        }
        if !key_scope_shape_ok(entry) {
            return Err("scope or presence does not match the role");
        }
        if mode == TrustMode::Production && TEST_KEY_IDS.contains(&key_id) {
            return Err("lists a public TEST key");
        }
        if index == 0 {
            if !entry["added_by"].is_null() || entry["role"] != "owner" {
                return Err("keys[0] must be the TOFU owner");
            }
        } else {
            let digest = statement_digest(entry, KEY_ADD_PREFIX, "added_by");
            if !signed_by_owner(&keys, &entry["added_by"], digest) {
                return Err("added_by is not a valid earlier owner signature");
            }
        }
        keys.insert(
            key_id.to_owned(),
            TrustedKey {
                public_key,
                entry: entry.clone(),
            },
        );
        order.push(key_id.to_owned());
    }
    let mut revoked = BTreeSet::new();
    let mut compromised = BTreeSet::new();
    let mut revocation_map = BTreeMap::new();
    for revocation in value["revocations"]
        .as_array()
        .ok_or("schema: revocations")?
    {
        let key_id = revocation["key_id"].as_str().ok_or("schema: key_id")?;
        if !keys.contains_key(key_id) {
            return Err("revocation names an unknown key");
        }
        let digest = statement_digest(revocation, KEY_REVOKE_PREFIX, "revoked_by");
        if !signed_by_owner(&keys, &revocation["revoked_by"], digest) {
            return Err("revoked_by is not a valid owner signature");
        }
        if !revoked.insert(key_id.to_owned()) {
            return Err("key revoked twice");
        }
        revocation_map.insert(
            key_id.to_owned(),
            (
                revocation["revoked_at"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                revocation["reason"].as_str().unwrap_or_default().to_owned(),
            ),
        );
        if revocation["reason"] == "compromised" {
            compromised.insert(key_id.to_owned());
        }
    }
    for key_id in &order {
        let added_by = keys[key_id].entry["added_by"]["key_id"].as_str();
        if added_by.is_some_and(|parent| compromised.contains(parent)) {
            compromised.insert(key_id.clone());
        }
    }
    revoked.extend(compromised.iter().cloned());
    Ok(TrustStore {
        server_id: value["server_id"]
            .as_str()
            .ok_or("schema: server_id")?
            .to_owned(),
        keys,
        revoked,
        compromised,
        revocations: revocation_map,
        mode,
        document: value.clone(),
        raw: Vec::new(),
    })
}

/// Trust state of the file, as `HelloResponse.trusted_keys.state` reports it.
#[derive(Debug, Clone)]
pub enum TrustState {
    /// No file: bootstrap state.
    Absent,
    Valid(Box<TrustStore>),
    /// Present but failed a rule. `document` is set when the file parsed, so
    /// Hello can still report its `server_id` and fingerprint.
    Invalid {
        reason: String,
        document: Option<Value>,
    },
}

/// Where the trust file lives and who must own it (section 7.1).
#[derive(Debug, Clone)]
pub struct TrustPaths {
    pub file: PathBuf,
    /// `flock` target of the section 7.4 write procedure (the runner's, D-030).
    #[cfg_attr(not(test), allow(dead_code))]
    pub lock: PathBuf,
    /// uid that must own the file (root in production).
    pub owner_uid: u32,
    pub mode: TrustMode,
}

impl TrustPaths {
    pub fn production(file: PathBuf) -> Self {
        Self {
            file,
            lock: PathBuf::from("/run/permanu/trust.lock"),
            owner_uid: 0,
            mode: TrustMode::Production,
        }
    }

    /// Reads and validates the file with the section 7.1 checks.
    pub fn load(&self) -> TrustState {
        let bytes = match read_trust_bytes(&self.file, self.owner_uid) {
            Ok(None) => return TrustState::Absent,
            Ok(Some(bytes)) => bytes,
            Err(reason) => {
                return TrustState::Invalid {
                    reason: reason.to_owned(),
                    document: None,
                }
            }
        };
        let Some(document) = parse_strict(&bytes, MAX_TRUST_FILE_BYTES) else {
            return TrustState::Invalid {
                reason: "not strict JSON".to_owned(),
                document: None,
            };
        };
        match validate_trust(&document, self.mode) {
            Ok(mut store) => {
                store.raw = bytes;
                TrustState::Valid(Box::new(store))
            }
            Err(reason) => TrustState::Invalid {
                reason: reason.to_owned(),
                document: Some(document),
            },
        }
    }
}

/// `Ok(None)` when the file is absent. Opens with `O_NOFOLLOW` and requires
/// a regular file owned by `owner_uid`, not group- or world-writable, ≤ 256 KiB.
fn read_trust_bytes(path: &Path, owner_uid: u32) -> Result<Option<Vec<u8>>, &'static str> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot open (symlink or permission)"),
    };
    let metadata = file.metadata().map_err(|_| "cannot stat")?;
    if !metadata.file_type().is_file() {
        return Err("not a regular file");
    }
    if metadata.uid() != owner_uid {
        return Err("not owned by root");
    }
    if metadata.mode() & 0o022 != 0 {
        return Err("group- or world-writable");
    }
    if metadata.len() > MAX_TRUST_FILE_BYTES as u64 {
        return Err("larger than 256 KiB");
    }
    let mut bytes = Vec::new();
    file.take(MAX_TRUST_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read")?;
    if bytes.len() > MAX_TRUST_FILE_BYTES {
        return Err("larger than 256 KiB");
    }
    Ok(Some(bytes))
}

/// Why a section 7.4 write was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustWriteError {
    /// The bootstrap found a file already there.
    AlreadyBootstrapped,
    /// The current file is absent or invalid.
    CurrentInvalid(String),
    /// The new object failed section 7.2, or the change is not allowed.
    Rejected(String),
    #[cfg_attr(not(test), allow(dead_code))]
    Io(String),
}

impl std::fmt::Display for TrustWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyBootstrapped => f.write_str("trusted-keys.json already exists"),
            Self::CurrentInvalid(reason) => write!(f, "current trusted-keys.json: {reason}"),
            Self::Rejected(reason) => write!(f, "trusted-keys change refused: {reason}"),
            Self::Io(reason) => write!(f, "trusted-keys write failed: {reason}"),
        }
    }
}

/// A change to the trust file (section 7.4).
#[derive(Debug, Clone)]
pub enum TrustChange<'a> {
    /// Section 7.3 step 4: `keys = [owner_key]`, `revocations = []`.
    #[cfg_attr(not(test), allow(dead_code))]
    Bootstrap {
        server_id: &'a str,
        owner_key: &'a Value,
    },
    AddKey(&'a Value),
    Revoke(&'a Value),
}

/// Builds the new document for `change` over `current` (strict superset) and
/// validates it. Used both as the admission-time precondition and by the write.
pub fn apply_change(
    current: Option<&TrustStore>,
    change: &TrustChange<'_>,
    mode: TrustMode,
) -> Result<Value, TrustWriteError> {
    let document = match (change, current) {
        (TrustChange::Bootstrap { .. }, Some(_)) => {
            return Err(TrustWriteError::AlreadyBootstrapped)
        }
        (
            TrustChange::Bootstrap {
                server_id,
                owner_key,
            },
            None,
        ) => serde_json::json!({
            "version": 1,
            "server_id": server_id,
            "keys": [owner_key],
            "revocations": [],
        }),
        (_, None) => {
            return Err(TrustWriteError::CurrentInvalid(
                "no valid trust file".to_owned(),
            ))
        }
        (TrustChange::AddKey(entry), Some(store)) => {
            let key_id = entry["key_id"].as_str().unwrap_or_default();
            if store.keys.contains_key(key_id) {
                // Entries are never removed and a revoked id never returns.
                return Err(TrustWriteError::Rejected(
                    "key_id already present".to_owned(),
                ));
            }
            let mut document = store.document.clone();
            push(&mut document, "keys", (*entry).clone())?;
            document
        }
        (TrustChange::Revoke(revocation), Some(store)) => {
            let key_id = revocation["key_id"].as_str().unwrap_or_default();
            if store.revocations.contains_key(key_id) {
                return Err(TrustWriteError::Rejected("key already revoked".to_owned()));
            }
            let mut document = store.document.clone();
            push(&mut document, "revocations", (*revocation).clone())?;
            document
        }
    };
    let validated =
        validate_trust(&document, mode).map_err(|r| TrustWriteError::Rejected(r.to_owned()))?;
    if matches!(change, TrustChange::Revoke(_)) && validated.active_owner_count() == 0 {
        return Err(TrustWriteError::Rejected(
            "would leave no active owner key".to_owned(),
        ));
    }
    Ok(document)
}

fn push(document: &mut Value, field: &str, value: Value) -> Result<(), TrustWriteError> {
    document[field]
        .as_array_mut()
        .ok_or_else(|| TrustWriteError::CurrentInvalid(format!("{field} is not an array")))?
        .push(value);
    Ok(())
}

/// The section 7.4 write procedure. Since v1.0.2 (D-030) the root runner
/// writes trusted-keys.json (`bootstrap_trust`, `update_trusted_keys`) and the
/// non-root agent never does; the procedure stays here for the test runner.
#[cfg(test)]
impl TrustPaths {
    /// The section 7.4 write procedure: flock, read and validate, build the
    /// superset, validate, write a temp file 0644, fsync, rename, fsync dir.
    pub fn write_change(&self, change: &TrustChange<'_>) -> Result<TrustStore, TrustWriteError> {
        let _lock = self.lock_file()?;
        let current = match self.load() {
            TrustState::Absent => None,
            TrustState::Valid(store) => Some(*store),
            TrustState::Invalid { .. } if matches!(change, TrustChange::Bootstrap { .. }) => {
                return Err(TrustWriteError::AlreadyBootstrapped)
            }
            TrustState::Invalid { reason, .. } => {
                return Err(TrustWriteError::CurrentInvalid(reason))
            }
        };
        let document = apply_change(current.as_ref(), change, self.mode)?;
        let text = canonicalize(&document)
            .ok_or_else(|| TrustWriteError::Rejected("not canonicalizable".to_owned()))?;
        if text.len() > MAX_TRUST_FILE_BYTES {
            return Err(TrustWriteError::Rejected("larger than 256 KiB".to_owned()));
        }
        self.atomic_write(text.as_bytes())?;
        let mut store = validate_trust(&document, self.mode)
            .map_err(|r| TrustWriteError::Rejected(r.to_owned()))?;
        store.raw = text.into_bytes();
        Ok(store)
    }

    fn lock_file(&self) -> Result<File, TrustWriteError> {
        use std::os::fd::AsRawFd;
        if let Some(dir) = self.lock.parent() {
            fs::create_dir_all(dir).map_err(|e| TrustWriteError::Io(e.to_string()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.lock)
            .map_err(|e| TrustWriteError::Io(format!("lock: {e}")))?;
        // SAFETY: flock on a valid, owned descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(TrustWriteError::Io("flock failed".to_owned()));
        }
        Ok(file)
    }

    fn atomic_write(&self, bytes: &[u8]) -> Result<(), TrustWriteError> {
        let io = |e: std::io::Error| TrustWriteError::Io(e.to_string());
        let dir = self
            .file
            .parent()
            .ok_or_else(|| TrustWriteError::Io("no parent directory".to_owned()))?;
        if !dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(dir)
                .map_err(io)?;
        }
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).map_err(|e| TrustWriteError::Io(e.to_string()))?;
        let temp = dir.join(format!(".trusted-keys.json.{}", hex(&random)));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)
                .map_err(io)?;
            // The mode is exact regardless of umask.
            file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))
                .map_err(io)?;
            file.write_all(bytes).map_err(io)?;
            file.sync_all().map_err(io)?;
            fs::rename(&temp, &self.file).map_err(io)?;
            File::open(dir).and_then(|d| d.sync_all()).map_err(io)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

#[cfg(test)]
use std::os::unix::fs::DirBuilderExt;

#[cfg(test)]
mod tests {
    use super::super::test_support::{policy_context, temp_dir, vector};
    use super::*;

    fn paths(dir: &Path) -> TrustPaths {
        TrustPaths {
            file: dir.join("etc/trusted-keys.json"),
            lock: dir.join("run/trust.lock"),
            owner_uid: unsafe { libc::geteuid() },
            mode: TrustMode::Test,
        }
    }

    #[test]
    fn state_is_absent_valid_or_invalid_with_a_reason() {
        let dir = temp_dir("trust-state");
        let paths = paths(&dir);
        assert!(matches!(paths.load(), TrustState::Absent));

        fs::create_dir_all(paths.file.parent().unwrap()).unwrap();
        let text = serde_json::to_string_pretty(&vector("trusted-keys")).unwrap();
        fs::write(&paths.file, text).unwrap();
        fs::set_permissions(
            &paths.file,
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        let TrustState::Valid(store) = paths.load() else {
            panic!("valid");
        };
        assert_eq!(store.server_id, "01a0cdb5-3500-70a1-8000-000000000001");
        assert_eq!(store.fingerprint_digest_hex().len(), 64);

        let production = TrustPaths {
            mode: TrustMode::Production,
            ..paths.clone()
        };
        let TrustState::Invalid { reason, document } = production.load() else {
            panic!("production refuses TEST keys");
        };
        assert_eq!(reason, "lists a public TEST key");
        assert!(document.is_some());

        fs::set_permissions(
            &paths.file,
            std::os::unix::fs::PermissionsExt::from_mode(0o666),
        )
        .unwrap();
        assert!(matches!(paths.load(), TrustState::Invalid { .. }));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bootstrap_writes_once_and_changes_are_supersets() {
        let dir = temp_dir("trust-write");
        let paths = paths(&dir);
        let context = policy_context();
        let file = &context["trusted_keys"];
        let owner = &file["keys"][0];
        let store = paths
            .write_change(&TrustChange::Bootstrap {
                server_id: "01a0cdb5-3500-70a1-8000-000000000001",
                owner_key: owner,
            })
            .unwrap();
        assert_eq!(store.keys.len(), 1);
        let mode = fs::metadata(&paths.file).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert_eq!(
            paths
                .write_change(&TrustChange::Bootstrap {
                    server_id: "01a0cdb5-3500-70a1-8000-000000000001",
                    owner_key: owner,
                })
                .unwrap_err(),
            TrustWriteError::AlreadyBootstrapped
        );
        // The vector file's later keys were added by the owner in order.
        for entry in file["keys"].as_array().unwrap().iter().skip(1) {
            paths.write_change(&TrustChange::AddKey(entry)).unwrap();
        }
        let tampered = {
            let mut entry = file["keys"][1].clone();
            entry["label"] = Value::String("Evil".to_owned());
            entry["key_id"] = Value::String("AAAAAAAAAAAAAAAAAAAAAA".to_owned());
            entry
        };
        assert!(matches!(
            paths.write_change(&TrustChange::AddKey(&tampered)),
            Err(TrustWriteError::Rejected(_))
        ));
        for revocation in file["revocations"].as_array().unwrap() {
            paths
                .write_change(&TrustChange::Revoke(revocation))
                .unwrap();
        }
        let TrustState::Valid(store) = paths.load() else {
            panic!("valid");
        };
        assert_eq!(fingerprint(&store.document), fingerprint(file));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn revoking_the_last_owner_is_refused() {
        let file = vector("trusted-keys");
        let store = validate_trust(&file, TrustMode::Test).unwrap();
        let owner_id = file["keys"][0]["key_id"].as_str().unwrap();
        assert_eq!(store.active_owner_count(), 1);
        let revocation = serde_json::json!({
            "key_id": owner_id, "revoked_at": "2026-09-23T10:00:00Z", "reason": "lost",
            "revoked_by": {"key_id": owner_id, "sig": "A".repeat(86)}
        });
        // The signature is not valid either; the owner-count guard or the
        // signature check refuses it, never an accepted write.
        assert!(apply_change(
            Some(&store),
            &TrustChange::Revoke(&revocation),
            TrustMode::Test
        )
        .is_err());
    }
}
