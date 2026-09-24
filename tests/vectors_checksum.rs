//! The vendored signed-plan vectors must be byte-identical to the frozen
//! contract (`docs` tag `contracts-v1.1.5`, `contracts/vectors/signed-plan`).
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
            "{name} differs from contracts-v1.1.5"
        );
        listed.insert(name.to_owned());
    }
    assert_eq!(
        header.as_deref(),
        Some("contracts-v1.1.5 06d2efa98bdd4651dbd83af48427e3b756f492fd contracts/vectors/signed-plan")
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
    // Our store is the v1.0.1 DDL (verbatim) plus the migrations; every
    // normative column must exist, in order, with the contract's type,
    // nullability, key and default (trailing agent-only columns allowed).
    let contract = rusqlite::Connection::open_in_memory().unwrap();
    contract.execute_batch(ddl).unwrap();
    let ours = rusqlite::Connection::open_in_memory().unwrap();
    for file in [
        "schema_v1.sql",
        "schema_v1_agent.sql",
        "schema_v2.sql",
        "schema_v3.sql",
    ] {
        let sql = std::fs::read_to_string(manifest.join("src/admissions").join(file)).unwrap();
        ours.execute_batch(&sql).unwrap();
    }
    let tables: Vec<String> = contract
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    // v1.0.8 (stated in v1.0.10, D-060): `rejected_deliveries` is the 14th.
    assert_eq!(tables.len(), 14);
    type Column = (String, String, i64, Option<String>, i64);
    let columns = |conn: &rusqlite::Connection, table: &str| -> Vec<Column> {
        conn.prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |r| {
                Ok((r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    for table in &tables {
        let mut want = columns(&contract, table);
        let mut have = columns(&ours, table);
        assert!(have.len() >= want.len(), "{table}");
        have.truncate(want.len());
        if table == "meta" {
            // DEFAULT 2 in v1.0.2; ADD COLUMN cannot change the v1.0.1
            // default and the agent always writes the value.
            for column in want.iter_mut().chain(have.iter_mut()) {
                if column.0 == "schema_version" {
                    column.3 = None;
                }
            }
        }
        assert_eq!(have, want, "{table}");
    }
    let indexes = |conn: &rusqlite::Connection| -> Vec<(String, String)> {
        conn.prepare(
            "SELECT name, tbl_name FROM sqlite_master WHERE type = 'index' \
             AND name NOT LIKE 'sqlite_autoindex%' ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    };
    let ours_indexes = indexes(&ours);
    for index in indexes(&contract) {
        assert!(ours_indexes.contains(&index), "{index:?}");
    }
}

/// The vendored redaction-v1 vectors (agent-protocol.md 9.6) must be
/// byte-identical to `contracts-v1.1.1` `contracts/vectors/redaction`.
#[test]
fn vendored_redaction_vectors_match_the_contract_tag_checksums() {
    const REDACTION: &str = include_str!("vectors/redaction.sha256");
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/redaction");
    let mut header = None;
    let mut listed = BTreeSet::new();
    for line in REDACTION.lines() {
        if let Some(comment) = line.strip_prefix("# ") {
            header = Some(comment.to_owned());
            continue;
        }
        let (expected, name) = line.split_once("  ").expect("sha256sum line");
        let bytes = std::fs::read(directory.join(name)).expect("vendored vector");
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            expected,
            "{name} differs from contracts-v1.1.1"
        );
        listed.insert(name.to_owned());
    }
    assert_eq!(
        header.as_deref(),
        Some(
            "contracts-v1.1.1 ccba5b6746511abe475e46e24c914a031e3d7893 contracts/vectors/redaction"
        )
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
}
