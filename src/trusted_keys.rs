//! Whether signing is on (S8): `/etc/permanu/trusted-keys.json` exists.
//!
//! Validation, the Hello trust state and writes live in
//! `signed_plan::trust` (signed-plan.md section 7).

use std::{fs, path::Path};

pub const TRUSTED_KEYS_PATH: &str = "/etc/permanu/trusted-keys.json";

/// Signing is enabled once anything exists at `path`. Any error other than
/// "not found" (a dangling symlink, EACCES) also counts as enabled: fail closed.
pub fn signing_enabled(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(err) => err.kind() != std::io::ErrorKind::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_is_enabled_by_any_file_or_link() {
        let dir = std::env::temp_dir().join(format!(
            "permanu-trusted-keys-{}-{}",
            std::process::id(),
            crate::timeutil::now_unix_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trusted-keys.json");
        assert!(!signing_enabled(&path));
        std::os::unix::fs::symlink(dir.join("missing"), &path).unwrap();
        assert!(signing_enabled(&path), "a dangling link fails closed");
        fs::remove_file(&path).unwrap();
        fs::write(&path, "{}").unwrap();
        assert!(signing_enabled(&path));
        fs::remove_dir_all(dir).unwrap();
    }
}
