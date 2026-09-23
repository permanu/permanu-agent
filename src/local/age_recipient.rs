//! The server's age X25519 recipient (signed-plan.md section 3.2, "Sealed
//! secrets"; D-027): `/var/lib/permanu/agent/age-recipient`, `root:root
//! 0644`, written by the installer next to the identity. The agent only reads
//! this public file to fill `AgentInfo.age_recipient`; it never opens the
//! identity, and only the runner decrypts.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::str::FromStr;

pub const DEFAULT_AGE_RECIPIENT_PATH: &str = "/var/lib/permanu/agent/age-recipient";
const MAX_RECIPIENT_BYTES: u64 = 4 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AgeRecipientError {
    #[error("age recipient: {0}")]
    Io(#[from] std::io::Error),
    #[error("age recipient: {0}")]
    Unsafe(&'static str),
}

/// Reads the recipient (`age1…`). The file must be a regular file owned by
/// `owner_uid` (root) that nobody else can write; anything else is refused
/// and the engine cannot seal for this server (fail closed).
pub fn read_recipient(path: &Path, owner_uid: u32) -> Result<String, AgeRecipientError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(AgeRecipientError::Unsafe("not a regular file"));
    }
    if meta.uid() != owner_uid {
        return Err(AgeRecipientError::Unsafe("not owned by root"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(AgeRecipientError::Unsafe("writable by group or others"));
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_RECIPIENT_BYTES)
        .read_to_string(&mut text)?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or(AgeRecipientError::Unsafe("no recipient line"))?;
    if line.starts_with("AGE-SECRET-KEY-") {
        // An identity in the public file would be published in Hello.
        return Err(AgeRecipientError::Unsafe("file holds an identity"));
    }
    age::x25519::Recipient::from_str(line)
        .map(|recipient| recipient.to_string())
        .map_err(|_| AgeRecipientError::Unsafe("invalid recipient"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_plan::test_support::temp_dir;
    use age::secrecy::ExposeSecret;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn write(path: &Path, text: &str, mode: u32) {
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn reads_the_public_recipient_file() {
        let dir = temp_dir("age-recipient");
        let path = dir.join("age-recipient");
        let recipient = age::x25519::Identity::generate().to_public().to_string();
        write(
            &path,
            &format!("# created by the installer\n{recipient}\n"),
            0o644,
        );
        assert_eq!(read_recipient(&path, euid()).unwrap(), recipient);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_unsafe_or_wrong_contents() {
        let dir = temp_dir("age-recipient-bad");
        let recipient = age::x25519::Identity::generate().to_public().to_string();
        let path = dir.join("age-recipient");
        write(&path, &recipient, 0o664);
        assert!(read_recipient(&path, euid()).is_err(), "group-writable");
        write(&path, &recipient, 0o644);
        assert!(read_recipient(&path, euid() + 1).is_err(), "wrong owner");
        let link = dir.join("linked");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_recipient(&link, euid()).is_err(), "symlink");
        let identity = age::x25519::Identity::generate();
        write(&path, identity.to_string().expose_secret(), 0o644);
        assert!(read_recipient(&path, euid()).is_err(), "identity");
        write(&path, "hello", 0o644);
        assert!(read_recipient(&path, euid()).is_err(), "garbage");
        assert!(read_recipient(&dir.join("absent"), euid()).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
