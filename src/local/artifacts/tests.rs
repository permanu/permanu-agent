//! Artifact staging: the commit-time checks against the contract's
//! `artifact-cases.json` and `StageArtifact` over the socket.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tonic::Code;

use super::*;
use crate::local::test_harness::{Harness, Options};
use crate::proto::agent::v2::{
    artifact_service_client::ArtifactServiceClient, info_service_client::InfoServiceClient,
    HelloRequest, StageChunk, StageCommit, StageHeader,
};
use crate::signed_plan::test_support::vector;

const TEST: ReleaseMode = ReleaseMode {
    trust_test_keys: true,
};
const PRODUCTION: ReleaseMode = ReleaseMode {
    trust_test_keys: false,
};

/// Plan-level steps (5 and 5b: the action's version, the permanu-env
/// entry of a runner update, downgrades) are the runner's alone; the agent
/// has no plan at commit and passes those sets.
const PLAN_ONLY_CASES: &[&str] = &[
    "artifact_version_mismatch",
    "artifact_runner_without_permanu_env",
    "artifact_downgrade_refused",
    "artifact_downgrade_below_prerelease",
];

#[test]
fn the_commit_check_agrees_with_the_contract_vectors() {
    let cases = vector("artifact-cases");
    let cases = cases["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let arch = case["arch"].as_str().unwrap();
        let mode = if case["mode"] == "production" {
            PRODUCTION
        } else {
            TEST
        };
        let staged: BTreeMap<String, String> = case["staged_digests_hex"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(n, d)| (format!("{arch}/{n}"), d.as_str().unwrap().to_owned()))
            .collect();
        let keys = serde_json::to_vec(&case["release_keys"]).unwrap();
        let got = verify_staged(
            Ok(Some(keys)),
            mode,
            case["manifest"].as_str().unwrap().as_bytes(),
            case["manifest_sig"].as_str().unwrap().as_bytes(),
            case["action"]["params"]["bundle_manifest_digest_hex"]
                .as_str()
                .unwrap(),
            arch,
            &staged,
        );
        let want = if PLAN_ONLY_CASES.contains(&name) {
            "OK"
        } else {
            case["expect"].as_str().unwrap()
        };
        match got {
            Ok(verified) => {
                assert_eq!(want, "OK", "{name}");
                assert!(!verified.components.is_empty(), "{name}");
            }
            Err(rejection) => assert_eq!(rejection.code, want, "{name}: {}", rejection.detail),
        }
    }
}

#[test]
fn a_missing_or_unsafe_release_keys_file_rejects_every_set() {
    let case = &vector("artifact-cases")["cases"][0];
    let staged = BTreeMap::new();
    for keys in [Ok(None), Err("unexpected owner, mode or type")] {
        let got = verify_staged(
            keys,
            TEST,
            case["manifest"].as_str().unwrap().as_bytes(),
            case["manifest_sig"].as_str().unwrap().as_bytes(),
            case["action"]["params"]["bundle_manifest_digest_hex"]
                .as_str()
                .unwrap(),
            "amd64",
            &staged,
        );
        assert_eq!(got.unwrap_err().code, "release_keys_invalid");
    }
    let dir = crate::signed_plan::test_support::temp_dir("release-keys-mode");
    let file = dir.join("release-keys.json");
    std::fs::write(&file, b"{}").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    assert!(read_release_keys(&file, uid).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(read_release_keys(&file, uid).unwrap().unwrap(), b"{}");
    assert!(read_release_keys(&dir.join("absent"), uid)
        .unwrap()
        .is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

/// The vector set `ok_artifact_agent_update` (amd64 binaries are
/// `SHA-256("TEST binary <name> <arch> 2.1.0")` preimages), staged on an
/// arm64 fake server: only the arm64 agent binary.
fn vector_set() -> (Value, Vec<u8>) {
    let case = vector("artifact-cases")["cases"][0].clone();
    let binary = b"TEST binary permanu-agent arm64 2.1.0".to_vec();
    (case, binary)
}

fn frames(
    case: &Value,
    stage_id: &str,
    files: &[(&str, &[u8])],
    commit: bool,
) -> Vec<StageArtifactRequest> {
    let mut out = vec![StageArtifactRequest {
        frame: Some(Frame::Header(StageHeader {
            stage_id: stage_id.to_owned(),
            bundle_manifest_digest_hex: case["action"]["params"]["bundle_manifest_digest_hex"]
                .as_str()
                .unwrap()
                .to_owned(),
            arch: "arm64".to_owned(),
        })),
    }];
    for (name, bytes) in files {
        out.push(StageArtifactRequest {
            frame: Some(Frame::File(StageFile {
                name: (*name).to_owned(),
                size_bytes: bytes.len() as u64,
                digest_hex: hex::encode(Sha256::digest(bytes)),
            })),
        });
        for chunk in bytes.chunks(7) {
            out.push(StageArtifactRequest {
                frame: Some(Frame::Chunk(StageChunk {
                    data: chunk.to_vec(),
                })),
            });
        }
    }
    if commit {
        out.push(StageArtifactRequest {
            frame: Some(Frame::Commit(StageCommit {})),
        });
    }
    out
}

async fn harness(name: &str, case: &Value) -> Harness {
    let h = Harness::with(
        name,
        Options {
            artifacts: true,
            ..Default::default()
        },
    )
    .await;
    let file = h.dir.join("etc/release-keys.json");
    std::fs::write(&file, serde_json::to_vec(&case["release_keys"]).unwrap()).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    h
}

#[tokio::test]
async fn a_signed_set_is_staged_under_its_manifest_digest() {
    let (case, binary) = vector_set();
    let h = harness("stage-ok", &case).await;
    let digest = case["action"]["params"]["bundle_manifest_digest_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let manifest = case["manifest"].as_str().unwrap().as_bytes().to_vec();
    let signature = case["manifest_sig"].as_str().unwrap().as_bytes().to_vec();
    let mut client = ArtifactServiceClient::new(h.channel.clone());
    let set = client
        .stage_artifact(futures::stream::iter(frames(
            &case,
            "01a0cdb5-3500-7a01-8000-000000000001",
            &[
                ("manifest.json", &manifest),
                ("manifest.sig.json", &signature),
                ("arm64/permanu-agent", &binary),
            ],
            true,
        )))
        .await
        .unwrap()
        .into_inner()
        .set
        .unwrap();
    assert!(set.verified);
    assert_eq!(set.release_key_id, "cl98Xxg2voSKlukyuAPKJg");
    assert!(set.components.contains(&"permanu-agent 2.1.0".to_owned()));
    let root = h.dir.join("staging").join(&digest);
    assert_eq!(
        std::fs::read(root.join("arm64/permanu-agent")).unwrap(),
        binary
    );
    assert_eq!(std::fs::read(root.join("manifest.json")).unwrap(), manifest);
    let mode = std::fs::metadata(root.join("manifest.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o640);
    assert!(h.artifacts.as_ref().unwrap().staged(&digest).await);
    // Re-using a committed stage id is refused.
    let again = client
        .stage_artifact(futures::stream::iter(frames(
            &case,
            "01a0cdb5-3500-7a01-8000-000000000001",
            &[],
            true,
        )))
        .await
        .unwrap_err();
    assert_eq!(again.code(), Code::AlreadyExists);
    let listed = client
        .list_staged_artifacts(ListStagedArtifactsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .sets;
    assert_eq!(listed.len(), 1);
    let keys = client
        .get_release_keys(GetReleaseKeysRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(keys.keys.len(), 2);
    assert!(keys.keys.iter().all(|k| k.test && k.spki.len() == 44));
    // Hello advertises the capability and the release keys.
    let hello = InfoServiceClient::new(h.channel.clone())
        .hello(HelloRequest {
            protocol_versions: vec!["2.1".to_owned()],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(hello.capabilities.contains(&"artifacts.v1".to_owned()));
    let summary = hello.agent.unwrap().release_keys.unwrap();
    assert_eq!(summary.key_ids.len(), 2);
    assert!(summary.test_key_trusted);
    // After 24 hours the set no longer counts.
    h.clock
        .0
        .fetch_add(SET_LIFETIME_SECONDS, std::sync::atomic::Ordering::SeqCst);
    assert!(!h.artifacts.as_ref().unwrap().staged(&digest).await);
    h.stop().await;
}

#[tokio::test]
async fn a_bad_signature_or_binary_deletes_the_set() {
    let (case, binary) = vector_set();
    let h = harness("stage-bad", &case).await;
    let digest = case["action"]["params"]["bundle_manifest_digest_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let manifest = case["manifest"].as_str().unwrap().as_bytes().to_vec();
    let mut forged: Value = serde_json::from_str(case["manifest_sig"].as_str().unwrap()).unwrap();
    forged["sig"] = Value::String(crate::signed_plan::crypto::b64url_encode(&[7u8; 64]));
    let forged = crate::signed_plan::jcs::canonicalize(&forged)
        .unwrap()
        .into_bytes();
    let signature = case["manifest_sig"].as_str().unwrap().as_bytes().to_vec();
    let mut client = ArtifactServiceClient::new(h.channel.clone());
    let refused = client
        .stage_artifact(futures::stream::iter(frames(
            &case,
            "01a0cdb5-3500-7a01-8000-000000000002",
            &[
                ("manifest.json", &manifest),
                ("manifest.sig.json", &forged),
                ("arm64/permanu-agent", &binary),
            ],
            true,
        )))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert!(refused.message().starts_with("E_ARTIFACT_UNTRUSTED"));
    assert_eq!(
        refused
            .metadata()
            .get(crate::local::ERROR_REASON_HEADER)
            .unwrap(),
        "ERROR_REASON_ARTIFACT_REJECTED"
    );
    // A binary that is not the manifest's: EXEC_PRECONDITION.
    let other = b"TEST binary something else".to_vec();
    let refused = client
        .stage_artifact(futures::stream::iter(frames(
            &case,
            "01a0cdb5-3500-7a01-8000-000000000003",
            &[
                ("manifest.json", &manifest),
                ("manifest.sig.json", &signature),
                ("arm64/permanu-agent", &other),
            ],
            true,
        )))
        .await
        .unwrap_err();
    assert_eq!(
        refused
            .metadata()
            .get(crate::local::ERROR_REASON_HEADER)
            .unwrap(),
        "ERROR_REASON_EXEC_PRECONDITION"
    );
    assert!(!h.dir.join("staging").join(&digest).exists());
    // Nothing is left behind: no upload directory, no record.
    assert_eq!(std::fs::read_dir(h.dir.join("staging")).unwrap().count(), 0);
    assert!(h.artifacts.as_ref().unwrap().sets().is_empty());
    h.stop().await;
}

#[tokio::test]
async fn gaps_overruns_names_and_limits_abort_the_upload() {
    let (case, _) = vector_set();
    let h = harness("stage-limits", &case).await;
    let mut client = ArtifactServiceClient::new(h.channel.clone());
    let stage = |frames: Vec<StageArtifactRequest>| {
        let mut client = client.clone();
        async move {
            client
                .stage_artifact(futures::stream::iter(frames))
                .await
                .unwrap_err()
        }
    };
    let id = "01a0cdb5-3500-7a01-8000-000000000004";
    // A path outside this arch, or a traversal.
    for name in ["amd64/permanu-agent", "arm64/..", "../x", "arm64/a/b"] {
        let err = stage(frames(&case, id, &[(name, b"x")], true)).await;
        assert_eq!(err.code(), Code::InvalidArgument, "{name}");
    }
    // A file cut short before the next file or the commit.
    let mut short = frames(&case, id, &[("manifest.json", b"abcdef")], false);
    short.pop();
    short.push(StageArtifactRequest {
        frame: Some(Frame::Commit(StageCommit {})),
    });
    assert_eq!(stage(short).await.code(), Code::InvalidArgument);
    // A chunk past the declared size.
    let mut over = frames(&case, id, &[("manifest.json", b"ab")], false);
    over.push(StageArtifactRequest {
        frame: Some(Frame::Chunk(StageChunk { data: vec![1; 5] })),
    });
    assert_eq!(stage(over).await.code(), Code::InvalidArgument);
    // A chunk over 1 MiB.
    let mut huge = vec![frames(&case, id, &[], false).remove(0)];
    huge.push(StageArtifactRequest {
        frame: Some(Frame::File(StageFile {
            name: "manifest.json".to_owned(),
            size_bytes: 2 * 1024 * 1024,
            digest_hex: "0".repeat(64),
        })),
    });
    huge.push(StageArtifactRequest {
        frame: Some(Frame::Chunk(StageChunk {
            data: vec![0; 1024 * 1024 + 1],
        })),
    });
    assert_eq!(stage(huge).await.code(), Code::ResourceExhausted);
    // A declared file over 128 MiB.
    let mut big = vec![frames(&case, id, &[], false).remove(0)];
    big.push(StageArtifactRequest {
        frame: Some(Frame::File(StageFile {
            name: "manifest.json".to_owned(),
            size_bytes: MAX_FILE_BYTES + 1,
            digest_hex: "0".repeat(64),
        })),
    });
    assert_eq!(stage(big).await.code(), Code::ResourceExhausted);
    // Another arch.
    let mut wrong = frames(&case, id, &[], true);
    if let Some(Frame::Header(header)) = &mut wrong[0].frame {
        header.arch = "amd64".to_owned();
    }
    assert_eq!(stage(wrong).await.code(), Code::InvalidArgument);
    // No commit.
    let err = stage(frames(&case, id, &[("manifest.json", b"{}")], false)).await;
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(std::fs::read_dir(h.dir.join("staging")).unwrap().count(), 0);
    let _ = &mut client;
    h.stop().await;
}

/// D-051 lifts the D-046 refusal once staging is served: an update is
/// admitted only when its set is staged, and the executor runs
/// `stage_artifact_verify` before `update_agent`.
#[tokio::test]
async fn an_update_needs_its_staged_set_and_verifies_it_first() {
    use crate::proto::agent::v2::{
        change_service_client::ChangeServiceClient, SignedPlan, SubmitSignedPlanRequest,
    };
    use crate::signed_plan::test_support::{plan_vector, TestSigner, SERVER_A};
    use crate::signed_plan::verify::GENESIS_HEAD;
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let (case, binary) = vector_set();
    let h = Harness::with(
        "stage-update",
        Options {
            artifacts: true,
            trust: Some(serde_json::to_string(&vector("trusted-keys")).unwrap()),
            ..Default::default()
        },
    )
    .await;
    let file = h.dir.join("etc/release-keys.json");
    std::fs::write(&file, serde_json::to_vec(&case["release_keys"]).unwrap()).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut plan = plan_vector("key-add")["plan"].clone();
    plan["id"] = Value::String("01a0cdb5-3500-7001-8000-0000000d5101".to_owned());
    plan["nonce"] = Value::String("D051AAAAAAAAAAAAAAAAAA".to_owned());
    plan["targets"] = serde_json::json!([SERVER_A]);
    plan["base"]["heads"] = serde_json::json!({ SERVER_A: GENESIS_HEAD });
    plan["actions"] = serde_json::json!([case["action"]]);
    let request = || SubmitSignedPlanRequest {
        plan: Some(SignedPlan {
            envelope_json: owner.envelope(&plan).into_bytes(),
            specs_jcs: Vec::new(),
            sealed_secrets: Vec::new(),
        }),
    };
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let refused = change.submit_signed_plan(request()).await.unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert!(refused.message().starts_with("artifact_not_staged"));
    assert_eq!(
        refused
            .metadata()
            .get(crate::local::ERROR_REASON_HEADER)
            .unwrap(),
        "ERROR_REASON_EXEC_PRECONDITION"
    );
    let manifest = case["manifest"].as_str().unwrap().as_bytes().to_vec();
    let signature = case["manifest_sig"].as_str().unwrap().as_bytes().to_vec();
    ArtifactServiceClient::new(h.channel.clone())
        .stage_artifact(futures::stream::iter(frames(
            &case,
            "01a0cdb5-3500-7a01-8000-000000000009",
            &[
                ("manifest.json", &manifest),
                ("manifest.sig.json", &signature),
                ("arm64/permanu-agent", &binary),
            ],
            true,
        )))
        .await
        .unwrap();
    let admitted = change
        .submit_signed_plan(request())
        .await
        .unwrap()
        .into_inner();
    for _ in 0..200 {
        if h.runner.ops_for(&admitted.plan_id).len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let ops: Vec<String> = h
        .runner
        .ops_for(&admitted.plan_id)
        .into_iter()
        .map(|(op, _)| op)
        .collect();
    assert_eq!(ops, vec!["stage_artifact_verify", "update_agent"]);
    // v1.1.3 (D-061): the set is deleted once the install succeeded.
    let digest = case["action"]["params"]["bundle_manifest_digest_hex"]
        .as_str()
        .unwrap();
    let staging = h.core.staging.get().unwrap().clone();
    for _ in 0..200 {
        h.core.reconcile_once().await;
        if staging.sets().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(staging.sets().is_empty());
    assert!(!h.dir.join("staging").join(digest).exists());
    h.stop().await;
}

/// A QA bundle is signed with a TEST release key and its runner is built with
/// `test-release-keys` (D-051); the agent needs the same switch, or it reads
/// the pinned `release-keys.json` as invalid ("TEST release key in
/// production") and no update of a TEST-signed server can be staged.
#[cfg(feature = "test-release-keys")]
#[test]
fn a_test_release_keys_build_trusts_the_test_keys() {
    assert!(ReleaseMode::production().trust_test_keys);
}

/// A release build (neither dev feature) never trusts them.
#[cfg(not(any(feature = "dev-paths", feature = "test-release-keys")))]
#[test]
fn a_release_build_never_trusts_the_test_keys() {
    assert!(!ReleaseMode::production().trust_test_keys);
}
