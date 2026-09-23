//! The vendored signed-plan vectors must be byte-identical to the frozen
//! contract (`docs` tag `contracts-v1.0.1`, `contracts/vectors/signed-plan`).
//! `keys.json` (public TEST private keys) is deliberately not vendored.

use std::collections::BTreeSet;
use std::path::Path;

use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("vectors/signed-plan.sha256");

#[test]
fn vendored_vectors_match_the_contract_tag_checksums() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/signed-plan");
    let mut header = None;
    let mut listed = BTreeSet::new();
    for line in MANIFEST.lines() {
        if let Some(comment) = line.strip_prefix("# ") {
            header = Some(comment.to_owned());
            continue;
        }
        let (expected, name) = line.split_once("  ").expect("sha256sum line");
        let bytes = std::fs::read(directory.join(name)).expect("vendored vector");
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            expected,
            "{name} differs from contracts-v1.0.1"
        );
        listed.insert(name.to_owned());
    }
    assert_eq!(
        header.as_deref(),
        Some("contracts-v1.0.1 d5fdb1ebe17596c9f311c6aa9d364eea62252bef contracts/vectors/signed-plan")
    );
    let present: BTreeSet<String> = std::fs::read_dir(&directory)
        .expect("vector directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("name")
        })
        .collect();
    assert_eq!(present, listed, "every vendored file is pinned");
    assert!(
        !present.contains("keys.json"),
        "TEST private keys are never vendored"
    );
}

/// `src/admissions/schema_v1.sql` is the section 6.4 DDL verbatim. Checked
/// against the docs checkout when it sits next to this repo.
#[test]
fn admissions_schema_is_the_normative_ddl() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(contract) = [manifest.join("../docs"), manifest.join("../../docs")]
        .into_iter()
        .map(|d| d.join("contracts/signed-plan.md"))
        .find(|p| p.exists())
    else {
        eprintln!("skipped: docs checkout not found");
        return;
    };
    let text = std::fs::read_to_string(contract).unwrap();
    if !text.contains("### 6.4 `admissions.db` schema") {
        eprintln!("skipped: docs checkout predates contracts-v1.0.1");
        return;
    }
    let section = &text[text.find("### 6.4").unwrap()..];
    let start = section.find("```sql\n").unwrap() + "```sql\n".len();
    let end = start + section[start..].find("```").unwrap();
    let ddl = &section[start..end];
    let tables = &ddl[ddl.find("-- One row, written").unwrap()..];
    let ours = std::fs::read_to_string(manifest.join("src/admissions/schema_v1.sql")).unwrap();
    assert_eq!(ours, tables);
}
