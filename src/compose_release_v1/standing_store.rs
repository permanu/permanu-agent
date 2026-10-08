//! Read-only view of the Go coordinator's standing rule record and lock.
//! Does not register rules, consume rate budgets, or execute releases.
use super::{
    authority::Registry,
    standing::{self, SignedRule, StandingEnvelope},
    Error,
};
use crate::signed_plan::{
    jcs,
    trust::{TrustPaths, TrustState},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    signed: SignedRule,
    disabled: bool,
}
pub(crate) struct StandingVerifier {
    pub directory: PathBuf,
    pub owner_uid: u32,
    pub trust: TrustPaths,
    pub policies: Arc<Registry>,
}
fn private_file(path: &Path, uid: u32) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Error::Authority)?;
    let m = file.metadata().map_err(|_| Error::Authority)?;
    if !m.is_file() || m.uid() != uid || m.mode() & 0o077 != 0 || m.nlink() != 1 {
        return Err(Error::Authority);
    }
    Ok(file)
}
impl StandingVerifier {
    pub fn verify(&self, raw: &[u8], now: i64) -> Result<String, Error> {
        let value = jcs::parse_strict(raw, 65536).ok_or(Error::Parse)?;
        let e: StandingEnvelope = serde_json::from_value(value).map_err(|_| Error::Parse)?;
        let policies = self.policies.0.read().map_err(|_| Error::Authority)?;
        let p = policies.as_ref().ok_or(Error::Authority)?;
        if e.release.application_id != p.application_id {
            return Err(Error::Authority);
        }
        let m = std::fs::symlink_metadata(&self.directory).map_err(|_| Error::Authority)?;
        if !m.is_dir() || m.uid() != self.owner_uid || m.mode() & 0o077 != 0 {
            return Err(Error::Authority);
        }
        let hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&["standing", p.application_id.as_str(), e.rule_id.as_str()])
                .map_err(|_| Error::Parse)?,
        ));
        let lock = private_file(&self.directory.join(format!("{hash}.lock")), self.owner_uid)?;
        lock.try_lock_shared().map_err(|_| Error::Authority)?;
        let record = private_file(&self.directory.join(format!("{hash}.json")), self.owner_uid)?;
        let mut raw_record = Vec::new();
        record
            .take(65537)
            .read_to_end(&mut raw_record)
            .map_err(|_| Error::Authority)?;
        let v = jcs::parse_strict(&raw_record, 65536).ok_or(Error::Parse)?;
        let record: Record = serde_json::from_value(v).map_err(|_| Error::Parse)?;
        if record.disabled
            || record.signed.rule.rule_id != e.rule_id
            || record.signed.rule.application_id != p.application_id
        {
            return Err(Error::Authority);
        }
        let TrustState::Valid(trust) = self.trust.load() else {
            return Err(Error::Authority);
        };
        let signed = serde_json::to_vec(&record.signed).map_err(|_| Error::Parse)?;
        standing::verify_release(raw, &signed, p, &trust, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn standing_store_private_reader_rejects_symlink_and_public_file() {
        let dir =
            std::env::temp_dir().join(format!("compose-standing-reader-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("record");
        std::fs::write(&path, b"fixture-only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let uid = std::fs::metadata(&path).unwrap().uid();
        assert!(private_file(&path, uid).is_ok());
        assert!(private_file(&path, uid.wrapping_add(1)).is_err());
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(private_file(&link, uid).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(&path, uid).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
