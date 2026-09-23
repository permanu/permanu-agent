//! The agent's age X25519 identity (signed-plan.md section 3.2, "Sealed
//! secrets"; D-024): `/var/lib/permanu/agent/age-identity`, mode 0600, owned
//! by the agent, generated at the first local-mode start, never leaving the
//! server. `AgentInfo.age_recipient` publishes its public recipient.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::str::FromStr;

use age::secrecy::ExposeSecret;

pub const DEFAULT_AGE_IDENTITY_PATH: &str = "/var/lib/permanu/agent/age-identity";
const MAX_IDENTITY_BYTES: u64 = 4 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AgeIdentityError {
    #[error("age identity: {0}")]
    Io(#[from] std::io::Error),
    #[error("age identity: {0}")]
    Unsafe(&'static str),
}

/// Loads the identity at `path`, generating it if absent. Returns the
/// recipient string (`age1…`). An existing file with a loose mode, another
/// owner, a symlink or bad contents is never replaced: the caller reports no
/// recipient and the engine cannot seal for this server (fail closed).
pub fn load_or_generate(
    path: &Path,
    owner: Option<(u32, u32)>,
) -> Result<String, AgeIdentityError> {
    match read_identity(path, owner.map(|(uid, _)| uid)) {
        Ok(identity) => return Ok(identity.to_public().to_string()),
        Err(AgeIdentityError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let secret = identity.to_string();
    let contents = format!("# public key: {recipient}\n{}\n", secret.expose_secret());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
    }
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    drop(file);
    if let Some(dir) = path.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(recipient)
}

fn read_identity(
    path: &Path,
    owner_uid: Option<u32>,
) -> Result<age::x25519::Identity, AgeIdentityError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(AgeIdentityError::Unsafe("not a regular file"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(AgeIdentityError::Unsafe("readable by group or others"));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid && Some(meta.uid()) != owner_uid {
        return Err(AgeIdentityError::Unsafe("not owned by the agent"));
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_IDENTITY_BYTES)
        .read_to_string(&mut text)?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("AGE-SECRET-KEY-1"))
        .ok_or(AgeIdentityError::Unsafe("no AGE-SECRET-KEY line"))?;
    age::x25519::Identity::from_str(line).map_err(|_| AgeIdentityError::Unsafe("invalid identity"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_plan::test_support::temp_dir;

    #[test]
    fn generates_once_with_mode_0600_and_reloads_the_same_recipient() {
        let dir = temp_dir("age");
        let path = dir.join("age-identity");
        let first = load_or_generate(&path, None).unwrap();
        assert!(first.starts_with("age1"), "{first}");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let second = load_or_generate(&path, None).unwrap();
        assert_eq!(first, second);
        // The secret never appears in the recipient.
        assert!(!first.contains("SECRET"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_a_loose_or_linked_identity_and_never_overwrites_it() {
        let dir = temp_dir("age-bad");
        let path = dir.join("age-identity");
        load_or_generate(&path, None).unwrap();
        let before = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_or_generate(&path, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);

        let link = dir.join("linked");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_or_generate(&link, None).is_err());

        let garbage = dir.join("garbage");
        fs::write(&garbage, "hello").unwrap();
        fs::set_permissions(&garbage, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_or_generate(&garbage, None).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
