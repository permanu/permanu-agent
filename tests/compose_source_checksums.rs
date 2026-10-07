//! Immutable published inputs used by build.rs and the Compose boundary.
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn compose_inputs_match_published_sources() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("vectors/compose-release-sources.json")).unwrap();
    assert_eq!(manifest["deployment_enabled"], false);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for entry in manifest["files"].as_array().unwrap() {
        let expected_commit = match entry["tag"].as_str().unwrap() {
            "proto-v2.1.13" => "be921a7602ed7814743ac02c2309a9bca9047d74",
            "contracts-v1.7.0" => "36fa35b4e85bb684b1ffc9da19190a932980c8d6",
            tag => panic!("unrecognized source tag: {tag}"),
        };
        assert_eq!(entry["commit"], expected_commit);
        let path = entry["path"].as_str().unwrap();
        let bytes = std::fs::read(root.join(path)).expect("pinned source exists");
        assert_eq!(
            hex::encode(Sha256::digest(bytes)),
            entry["sha256"],
            "{path}"
        );
    }
}
