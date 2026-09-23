//! Artifact staging (agent-protocol.md 13, `artifacts.v1`, D-051).
//!
//! - `StageArtifact` uploads one set: a header, then per file its size and
//!   digest followed by its chunks, then a commit. Files land in a private
//!   upload directory as `<name>.part` (`0640`), are size- and
//!   digest-checked and renamed; at commit the whole set replaces
//!   `/var/lib/permanu/staging/<bundle_manifest_digest_hex>/`.
//! - At commit the agent runs the checks of signed-plan.md 3.9 that need no
//!   plan: `release-keys.json` loads (step 1), the manifest hashes to the
//!   header's digest (step 2), is a canonical version 2 manifest (step 3),
//!   its `manifest.sig.json` verifies under a pinned, unrevoked release key
//!   that is not a TEST key in production (step 4), and every staged binary
//!   is a manifest entry of this server's arch with the same digest. This
//!   is a convenience: the runner's `stage_artifact_verify` checks again on
//!   its own root-only copy, and nothing is ever executed from here.
//! - Limits (section 7): one upload at a time, at most 16 files, each at
//!   most 128 MiB and 256 MiB per set, chunks at most 1 MiB, at most two
//!   committed sets, each kept 24 hours.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tonic::{Code, Request, Response, Status, Streaming};

use super::execution::Clock;
use super::facts::HostProbe;
use super::sched::ops_store::{Listing, OpsStore, RecordKind};
use super::sched::pts;
use super::status_with_reason;
use crate::proto::agent::v2::{
    artifact_service_server::ArtifactService, stage_artifact_request::Frame, ErrorReason,
    GetReleaseKeysRequest, ListStagedArtifactsRequest, ListStagedArtifactsResponse, PageInfo,
    ReleaseKey, ReleaseKeySet, ReleaseKeysSummary, StageArtifactRequest, StageArtifactResponse,
    StageFile, StagedArtifactSet,
};
use crate::signed_plan::crypto::{b64url_decode, b64url_encode};
use crate::signed_plan::jcs::{canonicalize, parse_strict};
use crate::signed_plan::text;

pub const CAPABILITY_ARTIFACTS: &str = "artifacts.v1";
pub const DEFAULT_STAGING_ROOT: &str = "/var/lib/permanu/staging";
pub const DEFAULT_RELEASE_KEYS: &str = "/etc/permanu/release-keys.json";
/// signed-plan.md 3.9: the public TEST release keys production refuses.
pub const TEST_RELEASE_KEY_IDS: [&str; 3] = [
    "cl98Xxg2voSKlukyuAPKJg",
    "RE1jopVSq8Moy0jDftg6Kg",
    "MA975uwluIeABZVJLGWMaA",
];
const MANIFEST_PREFIX: &[u8] = b"permanu-release-manifest-v1\n";
/// signed-plan.md 3.2 (v1.0.11, D-061: the build tools and `rclone`).
const COMPONENT_NAMES: [&str; 9] = [
    "permanu-agent",
    "permanu-runner",
    "dwaar",
    "permanu-env",
    "buildkitd",
    "buildctl",
    "rootlesskit",
    "slirp4netns",
    "rclone",
];
const MAX_RELEASE_KEYS_BYTES: u64 = 64 * 1024;
const MAX_FILES: usize = 16;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SET_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_COMMITTED_SETS: usize = 2;
pub const SET_LIFETIME_SECONDS: i64 = 24 * 3_600;
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Whether this build trusts the public TEST release keys (dev and QA
/// builds only, never production).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseMode {
    pub trust_test_keys: bool,
}

impl ReleaseMode {
    pub fn production() -> Self {
        Self {
            trust_test_keys: cfg!(feature = "dev-paths"),
        }
    }
}

/// A loaded `release-keys.json`.
#[derive(Debug, Clone)]
pub struct ReleaseKeys {
    pub keys: BTreeMap<String, ed25519_dalek::VerifyingKey>,
    pub revoked: BTreeSet<String>,
    pub document: Value,
}

fn key_id_of(der: &[u8]) -> String {
    b64url_encode(&Sha256::digest(der)[..16])
}

/// signed-plan.md 3.9 load-time rules; `Err` is `release_keys_invalid`.
pub fn parse_release_keys(raw: &[u8], mode: ReleaseMode) -> Result<ReleaseKeys, &'static str> {
    let document = parse_strict(raw, MAX_RELEASE_KEYS_BYTES as usize).ok_or("not strict JSON")?;
    let object = document.as_object().ok_or("not an object")?;
    if object.len() != 3 || document["version"] != 1 {
        return Err("unexpected fields or version");
    }
    let entries = document["keys"].as_array().ok_or("keys")?;
    let revocations = document["revocations"].as_array().ok_or("revocations")?;
    if entries.is_empty() {
        return Err("no release key");
    }
    let mut keys = BTreeMap::new();
    for entry in entries {
        let id = entry["key_id"].as_str().ok_or("key_id")?;
        let spki = entry["spki"].as_str().ok_or("spki")?;
        if entry["alg"] != "Ed25519" || entry["label"].as_str().is_none() {
            return Err("alg or label");
        }
        let der = STANDARD.decode(spki).map_err(|_| "spki encoding")?;
        if der.len() != 44 || der[..12] != SPKI_PREFIX || key_id_of(&der) != id {
            return Err("key_id does not match spki");
        }
        let bytes: [u8; 32] = der[12..].try_into().map_err(|_| "spki")?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| "spki point")?;
        if !mode.trust_test_keys && TEST_RELEASE_KEY_IDS.contains(&id) {
            return Err("TEST release key in production");
        }
        if keys.insert(id.to_owned(), key).is_some() {
            return Err("duplicate key_id");
        }
    }
    let mut revoked = BTreeSet::new();
    for revocation in revocations {
        let id = revocation["key_id"].as_str().ok_or("revocation key_id")?;
        if !keys.contains_key(id) {
            return Err("revocation of an unknown key");
        }
        revoked.insert(id.to_owned());
    }
    Ok(ReleaseKeys {
        keys,
        revoked,
        document,
    })
}

/// Reads `release-keys.json` with the section 7.1 rules: no symlink, a
/// regular file owned by `owner_uid`, not group- or world-writable, at most
/// 64 KiB. `Ok(None)` when absent.
pub fn read_release_keys(path: &Path, owner_uid: u32) -> Result<Option<Vec<u8>>, &'static str> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot open"),
    };
    let meta = file.metadata().map_err(|_| "cannot stat")?;
    if !meta.file_type().is_file() || meta.uid() != owner_uid || meta.mode() & 0o022 != 0 {
        return Err("unexpected owner, mode or type");
    }
    let mut bytes = Vec::new();
    file.take(MAX_RELEASE_KEYS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read")?;
    if bytes.len() as u64 > MAX_RELEASE_KEYS_BYTES {
        return Err("larger than 64 KiB");
    }
    Ok(Some(bytes))
}

/// Why a staged set was refused at commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub reason: ErrorReason,
    /// The equivalent runner code (`release_keys_invalid`,
    /// `E_ARTIFACT_UNTRUSTED`, `E_EXEC_PRECONDITION`).
    pub code: &'static str,
    pub detail: String,
}

fn rejected(code: &'static str, detail: impl Into<String>) -> Rejection {
    Rejection {
        reason: if code == "E_EXEC_PRECONDITION" {
            ErrorReason::ExecPrecondition
        } else {
            ErrorReason::ArtifactRejected
        },
        code,
        detail: detail.into(),
    }
}

/// What the commit-time check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub release_key_id: String,
    /// `"<name> <version>"` of this arch's entries.
    pub components: Vec<String>,
}

fn manifest_shape_ok(manifest: &Value) -> bool {
    let Some(object) = manifest.as_object() else {
        return false;
    };
    let components = manifest["components"].as_array();
    let keys = manifest["release_keys"].as_array();
    let (Some(components), Some(keys)) = (components, keys) else {
        return false;
    };
    object.len() == 3
        && manifest["version"] == 2
        && (1..=32).contains(&components.len())
        && (1..=8).contains(&keys.len())
        && components.iter().all(|c| {
            c.as_object().is_some_and(|m| m.len() == 5)
                && c["name"]
                    .as_str()
                    .is_some_and(|n| COMPONENT_NAMES.contains(&n))
                && matches!(c["arch"].as_str(), Some("amd64" | "arm64"))
                && c["version"]
                    .as_str()
                    .is_some_and(|v| (1..=64).contains(&v.len()))
                && c["path"].as_str()
                    == Some(&format!(
                        "{}/{}",
                        c["arch"].as_str().unwrap_or_default(),
                        c["name"].as_str().unwrap_or_default()
                    ))
                && c["artifact_digest_hex"].as_str().is_some_and(text::hex64)
        })
        && components.windows(2).all(|w| {
            (w[0]["name"].as_str(), w[0]["arch"].as_str())
                < (w[1]["name"].as_str(), w[1]["arch"].as_str())
        })
        && keys.iter().all(|k| {
            k.as_object().is_some_and(|m| m.len() == 3)
                && k["key_id"].is_string()
                && k["spki"].is_string()
                && k["label"].is_string()
        })
        && keys
            .windows(2)
            .all(|w| w[0]["key_id"].as_str() < w[1]["key_id"].as_str())
}

/// The plan-free checks of signed-plan.md 3.9 over a staged set.
/// `staged` maps each staged binary's manifest path to its digest.
pub fn verify_staged(
    release_keys: Result<Option<Vec<u8>>, &'static str>,
    mode: ReleaseMode,
    manifest_raw: &[u8],
    signature_raw: &[u8],
    bundle_manifest_digest_hex: &str,
    arch: &str,
    staged: &BTreeMap<String, String>,
) -> Result<Verified, Rejection> {
    // Step 1.
    let keys = match release_keys {
        Ok(Some(raw)) => parse_release_keys(&raw, mode),
        Ok(None) => Err("absent"),
        Err(reason) => Err(reason),
    }
    .map_err(|reason| rejected("release_keys_invalid", reason))?;
    // Step 2.
    if hex::encode(Sha256::digest(manifest_raw)) != bundle_manifest_digest_hex {
        return Err(rejected(
            "E_EXEC_PRECONDITION",
            "manifest.json does not hash to bundle_manifest_digest_hex",
        ));
    }
    // Step 3.
    let manifest = parse_strict(manifest_raw, MAX_MANIFEST_BYTES as usize)
        .filter(manifest_shape_ok)
        .filter(|m| canonicalize(m).is_some_and(|text| text.as_bytes() == manifest_raw))
        .ok_or_else(|| {
            rejected(
                "E_ARTIFACT_UNTRUSTED",
                "manifest is not a canonical version 2 manifest",
            )
        })?;
    // Step 4.
    let signature = parse_strict(signature_raw, 4 * 1024)
        .filter(|s| {
            s.as_object().is_some_and(|m| m.len() == 4)
                && s["version"] == 1
                && s["alg"] == "Ed25519"
                && s["key_id"].is_string()
        })
        .ok_or_else(|| rejected("E_ARTIFACT_UNTRUSTED", "manifest.sig.json is malformed"))?;
    let key_id = signature["key_id"].as_str().unwrap_or_default();
    let key = keys
        .keys
        .get(key_id)
        .filter(|_| !keys.revoked.contains(key_id))
        .filter(|_| mode.trust_test_keys || !TEST_RELEASE_KEY_IDS.contains(&key_id))
        .ok_or_else(|| {
            rejected(
                "E_ARTIFACT_UNTRUSTED",
                "signing key is not pinned or is revoked",
            )
        })?;
    let sig_bytes: [u8; 64] = signature["sig"]
        .as_str()
        .and_then(b64url_decode)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| rejected("E_ARTIFACT_UNTRUSTED", "signature encoding"))?;
    let mut message = MANIFEST_PREFIX.to_vec();
    message.extend_from_slice(manifest_raw);
    key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
        .map_err(|_| rejected("E_ARTIFACT_UNTRUSTED", "signature does not verify"))?;
    // Every staged binary is an entry of this arch with the same digest.
    let entries: Vec<&Value> = manifest["components"]
        .as_array()
        .map(|c| c.iter().filter(|c| c["arch"] == arch).collect())
        .unwrap_or_default();
    for (path, digest) in staged {
        let entry = entries.iter().find(|c| c["path"] == path.as_str());
        if entry.is_none_or(|c| c["artifact_digest_hex"] != digest.as_str()) {
            return Err(rejected(
                "E_EXEC_PRECONDITION",
                format!("{path} is not the manifest's binary for {arch}"),
            ));
        }
    }
    Ok(Verified {
        release_key_id: key_id.to_owned(),
        components: entries
            .iter()
            .map(|c| {
                format!(
                    "{} {}",
                    c["name"].as_str().unwrap_or_default(),
                    c["version"].as_str().unwrap_or_default()
                )
            })
            .collect(),
    })
}

/// What staging needs.
pub struct ArtifactDeps {
    pub root: PathBuf,
    pub release_keys: PathBuf,
    pub release_keys_owner: u32,
    pub ops: Arc<OpsStore>,
    pub probe: Arc<dyn HostProbe>,
    pub clock: Arc<dyn Clock>,
    pub mode: ReleaseMode,
}

pub struct Artifacts {
    deps: ArtifactDeps,
    upload: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Artifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Artifacts").finish()
    }
}

fn invalid(message: &str) -> Status {
    Status::invalid_argument(message.to_owned())
}

/// A file name of a set: the two manifest files or `<arch>/<name>`.
fn file_name_ok(name: &str, arch: &str) -> bool {
    if name == "manifest.json" || name == "manifest.sig.json" {
        return true;
    }
    let Some((prefix, rest)) = name.split_once('/') else {
        return false;
    };
    prefix == arch
        && (1..=128).contains(&rest.len())
        && rest != "."
        && rest != ".."
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Removes the upload directory unless the commit moved it.
struct UploadDir {
    path: PathBuf,
    keep: bool,
}

impl Drop for UploadDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct OpenFile {
    name: String,
    size: u64,
    digest_hex: String,
    written: u64,
    hasher: Sha256,
    file: fs::File,
    part: PathBuf,
    target: PathBuf,
}

impl Artifacts {
    pub fn new(deps: ArtifactDeps) -> Arc<Self> {
        Arc::new(Self {
            deps,
            upload: tokio::sync::Mutex::new(()),
        })
    }

    fn now(&self) -> i64 {
        self.deps.clock.now()
    }

    fn release_keys_bytes(&self) -> Result<Option<Vec<u8>>, &'static str> {
        read_release_keys(&self.deps.release_keys, self.deps.release_keys_owner)
    }

    /// `AgentInfo.release_keys` (D-051).
    pub fn summary(&self) -> ReleaseKeysSummary {
        use crate::proto::agent::v2::trusted_keys_summary::TrustState;
        let mut summary = ReleaseKeysSummary {
            test_key_trusted: self.deps.mode.trust_test_keys,
            ..Default::default()
        };
        match self.release_keys_bytes() {
            Ok(None) => summary.state = TrustState::Absent as i32,
            Ok(Some(raw)) => match parse_release_keys(&raw, self.deps.mode) {
                Ok(keys) => {
                    summary.state = TrustState::Valid as i32;
                    summary.fingerprint_digest_hex = canonicalize(&keys.document)
                        .map(|t| hex::encode(Sha256::digest(t.as_bytes())))
                        .unwrap_or_default();
                    summary.key_ids = keys
                        .keys
                        .keys()
                        .filter(|id| !keys.revoked.contains(*id))
                        .cloned()
                        .collect();
                }
                Err(reason) => {
                    summary.state = TrustState::Invalid as i32;
                    summary.invalid_reason = reason.to_owned();
                }
            },
            Err(reason) => {
                summary.state = TrustState::Invalid as i32;
                summary.invalid_reason = reason.to_owned();
            }
        }
        summary
    }

    /// Committed, verified, unexpired sets (newest first).
    pub fn sets(&self) -> Vec<StagedArtifactSet> {
        let now = self.now();
        self.deps
            .ops
            .list(
                RecordKind::StagedSet,
                &Listing {
                    limit: 64,
                    ..Default::default()
                },
            )
            .into_iter()
            .filter_map(|row| row.decode::<StagedArtifactSet>())
            .filter(|set| set.expires_at.as_ref().is_some_and(|t| t.seconds > now))
            .collect()
    }

    /// Admission precondition of `agent.update` / `component.update`
    /// (section 13 "Install"): a committed, verified, unexpired set with
    /// this digest for this server's arch.
    pub async fn staged(&self, bundle_manifest_digest_hex: &str) -> bool {
        let arch = self.deps.probe.server_facts().await.arch;
        self.sets().iter().any(|set| {
            set.verified
                && set.bundle_manifest_digest_hex == bundle_manifest_digest_hex
                && set.arch == arch
                && self.deps.root.join(bundle_manifest_digest_hex).is_dir()
        })
    }

    /// v1.1.3 (D-061, agent-protocol.md 13): an `agent.update` /
    /// `component.update` installed from this set ended `succeeded`, so the
    /// set is deleted at once (a failed or cancelled install keeps it until
    /// its 24 h expiry for a retry).
    pub fn consumed(&self, bundle_manifest_digest_hex: &str) {
        if !text::hex64(bundle_manifest_digest_hex) {
            return;
        }
        for row in self.deps.ops.list(
            RecordKind::StagedSet,
            &Listing {
                limit: 1_000,
                ..Default::default()
            },
        ) {
            let same = row
                .decode::<StagedArtifactSet>()
                .is_some_and(|set| set.bundle_manifest_digest_hex == bundle_manifest_digest_hex);
            if same {
                self.deps.ops.remove(RecordKind::StagedSet, &row.id);
            }
        }
        let _ = fs::remove_dir_all(self.deps.root.join(bundle_manifest_digest_hex));
    }

    /// Drops expired sets and all but the newest two.
    fn prune(&self) {
        let now = self.now();
        let rows = self.deps.ops.list(
            RecordKind::StagedSet,
            &Listing {
                limit: 1_000,
                ..Default::default()
            },
        );
        let mut kept = 0;
        for row in rows {
            let Some(set) = row.decode::<StagedArtifactSet>() else {
                self.deps.ops.remove(RecordKind::StagedSet, &row.id);
                continue;
            };
            let live = set.expires_at.as_ref().is_some_and(|t| t.seconds > now);
            if live && kept < MAX_COMMITTED_SETS {
                kept += 1;
                continue;
            }
            self.deps.ops.remove(RecordKind::StagedSet, &row.id);
            if text::hex64(&set.bundle_manifest_digest_hex) {
                let still_used = self
                    .sets()
                    .iter()
                    .any(|s| s.bundle_manifest_digest_hex == set.bundle_manifest_digest_hex);
                if !still_used {
                    let _ =
                        fs::remove_dir_all(self.deps.root.join(&set.bundle_manifest_digest_hex));
                }
            }
        }
    }

    fn begin_file(
        &self,
        dir: &Path,
        arch: &str,
        file: &StageFile,
        seen: &mut BTreeSet<String>,
    ) -> Result<OpenFile, Status> {
        if !file_name_ok(&file.name, arch) || !seen.insert(file.name.clone()) {
            return Err(invalid("unexpected or repeated file name"));
        }
        if seen.len() > MAX_FILES {
            return Err(Status::resource_exhausted("more than 16 files"));
        }
        if file.size_bytes > MAX_FILE_BYTES {
            return Err(Status::resource_exhausted("file larger than 128 MiB"));
        }
        if !text::hex64(&file.digest_hex) {
            return Err(invalid("digest_hex is not 64 hex characters"));
        }
        let target = dir.join(&file.name);
        if let Some(parent) = target.parent() {
            if parent != dir {
                fs::DirBuilder::new()
                    .mode(0o750)
                    .create(parent)
                    .or_else(|err| {
                        if err.kind() == std::io::ErrorKind::AlreadyExists {
                            Ok(())
                        } else {
                            Err(err)
                        }
                    })
                    .map_err(|_| Status::internal("staging directory not writable"))?;
            }
        }
        let mut part = target.as_os_str().to_owned();
        part.push(".part");
        let part = PathBuf::from(part);
        let handle = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&part)
            .map_err(|_| Status::internal("staging file not writable"))?;
        Ok(OpenFile {
            name: file.name.clone(),
            size: file.size_bytes,
            digest_hex: file.digest_hex.clone(),
            written: 0,
            hasher: Sha256::new(),
            file: handle,
            part,
            target,
        })
    }

    fn finish_file(open: OpenFile) -> Result<(String, String), Status> {
        if open.written != open.size {
            return Err(invalid("file ended before its declared size"));
        }
        if hex::encode(open.hasher.finalize()) != open.digest_hex {
            return Err(invalid("file does not match its digest_hex"));
        }
        open.file
            .sync_all()
            .map_err(|_| Status::internal("staging file not synced"))?;
        fs::rename(&open.part, &open.target)
            .map_err(|_| Status::internal("staging file not renamed"))?;
        Ok((open.name, open.digest_hex))
    }

    /// Runs one upload to its commit.
    async fn stage(
        &self,
        mut stream: Streaming<StageArtifactRequest>,
    ) -> Result<StagedArtifactSet, Status> {
        let Ok(_guard) = self.upload.try_lock() else {
            return Err(status_with_reason(
                Code::ResourceExhausted,
                "another upload is in progress",
                ErrorReason::LimitExceeded,
            ));
        };
        let first = stream
            .message()
            .await?
            .and_then(|m| m.frame)
            .ok_or_else(|| invalid("the first frame must be a StageHeader"))?;
        let Frame::Header(header) = first else {
            return Err(invalid("the first frame must be a StageHeader"));
        };
        if !text::uuid7(&header.stage_id) || !text::hex64(&header.bundle_manifest_digest_hex) {
            return Err(invalid(
                "stage_id or bundle_manifest_digest_hex is malformed",
            ));
        }
        let arch = self.deps.probe.server_facts().await.arch;
        if header.arch != arch {
            return Err(invalid("arch is not this server's"));
        }
        if self
            .deps
            .ops
            .get(RecordKind::StagedSet, &header.stage_id)
            .is_some()
        {
            return Err(Status::already_exists("stage_id was already committed"));
        }
        if !self.deps.root.is_dir() {
            return Err(Status::unavailable("staging directory missing"));
        }
        let dir = UploadDir {
            path: self.deps.root.join(format!(".upload-{}", header.stage_id)),
            keep: false,
        };
        let _ = fs::remove_dir_all(&dir.path);
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&dir.path)
            .map_err(|_| Status::internal("staging directory not writable"))?;
        let mut seen = BTreeSet::new();
        let mut current: Option<OpenFile> = None;
        let mut done: Vec<(String, String)> = Vec::new();
        let mut files: Vec<StageFile> = Vec::new();
        let mut total: u64 = 0;
        loop {
            let frame = stream
                .message()
                .await?
                .and_then(|m| m.frame)
                .ok_or_else(|| invalid("the upload ended without a StageCommit"))?;
            match frame {
                Frame::Header(_) => return Err(invalid("a second StageHeader")),
                Frame::File(file) => {
                    if let Some(open) = current.take() {
                        done.push(Self::finish_file(open)?);
                    }
                    total = total.saturating_add(file.size_bytes);
                    if total > MAX_SET_BYTES {
                        return Err(Status::resource_exhausted("set larger than 256 MiB"));
                    }
                    current = Some(self.begin_file(&dir.path, &arch, &file, &mut seen)?);
                    files.push(file);
                }
                Frame::Chunk(chunk) => {
                    let open = current
                        .as_mut()
                        .ok_or_else(|| invalid("a StageChunk before any StageFile"))?;
                    if chunk.data.len() > MAX_CHUNK_BYTES {
                        return Err(Status::resource_exhausted("chunk larger than 1 MiB"));
                    }
                    if open.written + chunk.data.len() as u64 > open.size {
                        return Err(invalid("chunk overruns the declared size"));
                    }
                    open.file
                        .write_all(&chunk.data)
                        .map_err(|_| Status::internal("staging write failed"))?;
                    open.hasher.update(&chunk.data);
                    open.written += chunk.data.len() as u64;
                }
                Frame::Commit(_) => {
                    if let Some(open) = current.take() {
                        done.push(Self::finish_file(open)?);
                    }
                    break;
                }
            }
        }
        let read = |name: &str| fs::read(dir.path.join(name)).ok();
        let (Some(manifest), Some(signature)) = (read("manifest.json"), read("manifest.sig.json"))
        else {
            return Err(invalid("manifest.json and manifest.sig.json are required"));
        };
        let staged: BTreeMap<String, String> = done
            .into_iter()
            .filter(|(name, _)| name.contains('/'))
            .collect();
        let verified = verify_staged(
            self.release_keys_bytes(),
            self.deps.mode,
            &manifest,
            &signature,
            &header.bundle_manifest_digest_hex,
            &arch,
            &staged,
        )
        .map_err(|rejection| {
            tracing::warn!(code = rejection.code, detail = %rejection.detail, "staged set refused");
            status_with_reason(
                Code::FailedPrecondition,
                &format!("{}: {}", rejection.code, rejection.detail),
                rejection.reason,
            )
        })?;
        // A commit replaces an earlier set of the same digest.
        let target = self.deps.root.join(&header.bundle_manifest_digest_hex);
        let _ = fs::remove_dir_all(&target);
        fs::rename(&dir.path, &target).map_err(|_| Status::internal("set not committed"))?;
        let mut dir = dir;
        dir.keep = true;
        let now = self.now();
        let set = StagedArtifactSet {
            stage_id: header.stage_id.clone(),
            bundle_manifest_digest_hex: header.bundle_manifest_digest_hex.clone(),
            arch,
            files,
            staged_at: Some(pts(now)),
            expires_at: Some(pts(now + SET_LIFETIME_SECONDS)),
            verified: true,
            release_key_id: verified.release_key_id,
            components: verified.components,
        };
        // Older records of the same digest now name the replaced set.
        for old in self.sets() {
            if old.bundle_manifest_digest_hex == set.bundle_manifest_digest_hex {
                self.deps.ops.remove(RecordKind::StagedSet, &old.stage_id);
            }
        }
        self.deps
            .ops
            .put(
                RecordKind::StagedSet,
                &set.stage_id,
                &set.bundle_manifest_digest_hex,
                "",
                1,
                now,
                &set,
            )
            .map_err(|_| Status::internal("set not recorded"))?;
        self.prune();
        tracing::info!(
            digest = %set.bundle_manifest_digest_hex,
            key_id = %set.release_key_id,
            "artifact set staged"
        );
        Ok(set)
    }
}

pub struct ArtifactSvc {
    pub artifacts: Arc<Artifacts>,
}

#[tonic::async_trait]
impl ArtifactService for ArtifactSvc {
    async fn stage_artifact(
        &self,
        request: Request<Streaming<StageArtifactRequest>>,
    ) -> Result<Response<StageArtifactResponse>, Status> {
        let set = self.artifacts.stage(request.into_inner()).await?;
        Ok(Response::new(StageArtifactResponse { set: Some(set) }))
    }

    async fn list_staged_artifacts(
        &self,
        request: Request<ListStagedArtifactsRequest>,
    ) -> Result<Response<ListStagedArtifactsResponse>, Status> {
        let page = request.into_inner().page;
        let size = super::sched::rpc::page_size(page.as_ref());
        let mut sets = self.artifacts.sets();
        sets.truncate(size);
        Ok(Response::new(ListStagedArtifactsResponse {
            sets,
            page: Some(PageInfo::default()),
        }))
    }

    async fn get_release_keys(
        &self,
        _request: Request<GetReleaseKeysRequest>,
    ) -> Result<Response<ReleaseKeySet>, Status> {
        let raw = match self.artifacts.release_keys_bytes() {
            Ok(Some(raw)) => raw,
            Ok(None) => return Err(Status::not_found("no release-keys.json")),
            Err(reason) => {
                return Err(status_with_reason(
                    Code::FailedPrecondition,
                    &format!("release_keys_invalid: {reason}"),
                    ErrorReason::ArtifactRejected,
                ))
            }
        };
        let document: Value = parse_strict(&raw, MAX_RELEASE_KEYS_BYTES as usize)
            .ok_or_else(|| Status::failed_precondition("release_keys_invalid"))?;
        let revocations: BTreeMap<&str, &str> = document["revocations"]
            .as_array()
            .map(|list| {
                list.iter()
                    .filter_map(|r| Some((r["key_id"].as_str()?, r["revoked_at"].as_str()?)))
                    .collect()
            })
            .unwrap_or_default();
        let keys = document["keys"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|k| {
                        let id = k["key_id"].as_str().unwrap_or_default();
                        let revoked_at = revocations.get(id);
                        ReleaseKey {
                            key_id: id.to_owned(),
                            alg: k["alg"].as_str().unwrap_or_default().to_owned(),
                            spki: k["spki"]
                                .as_str()
                                .and_then(|s| STANDARD.decode(s).ok())
                                .unwrap_or_default(),
                            label: k["label"].as_str().unwrap_or_default().to_owned(),
                            added_at: k["added_at"].as_str().and_then(text::timestamp).map(pts),
                            revoked: revoked_at.is_some(),
                            revoked_at: revoked_at.and_then(|t| text::timestamp(t)).map(pts),
                            test: TEST_RELEASE_KEY_IDS.contains(&id),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Response::new(ReleaseKeySet {
            keys,
            fingerprint_digest_hex: canonicalize(&document)
                .map(|t| hex::encode(Sha256::digest(t.as_bytes())))
                .unwrap_or_default(),
            release_keys_json: raw,
        }))
    }
}

#[cfg(test)]
mod tests;
