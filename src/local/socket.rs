//! The v2 unix socket (agent-protocol.md section 1): `root:permanu`, mode
//! 0660, directory 0750. The listener refuses to start when the path is a
//! symlink or the resulting ownership/mode differs.

use std::{
    ffi::CString,
    fs,
    io::{self, ErrorKind},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
};

use tokio::net::UnixListener;

pub const SOCKET_MODE: u32 = 0o660;
pub const DIR_MODE: u32 = 0o750;

/// Resolves a user name to its uid (`permanu-agent` for the store files).
pub fn resolve_user(name: &str) -> io::Result<u32> {
    let c_name = CString::new(name).map_err(|_| io::Error::other("user name contains NUL"))?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut user: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call and buf.len()
    // is the true buffer size.
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut user,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(io::Error::new(
            ErrorKind::NotFound,
            format!("user {name:?} does not exist"),
        ));
    }
    Ok(user.pw_uid)
}

/// Resolves a group name to its gid.
pub fn resolve_group(name: &str) -> io::Result<u32> {
    let c_name = CString::new(name).map_err(|_| io::Error::other("group name contains NUL"))?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call and buf.len()
    // is the true buffer size.
    let rc = unsafe {
        libc::getgrnam_r(
            c_name.as_ptr(),
            &mut group,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(io::Error::new(
            ErrorKind::NotFound,
            format!("group {name:?} does not exist"),
        ));
    }
    Ok(group.gr_gid)
}

/// Binds the socket at `path`, owned by the current euid and `gid` (when
/// given) with mode 0660, and verifies the result.
pub fn bind(path: &Path, gid: Option<u32>) -> io::Result<UnixListener> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "socket path has no parent"))?;
    prepare_dir(parent, gid)?;

    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(refuse(path, "is a symlink"));
        }
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => return Err(refuse(path, "exists and is not a socket")),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let std_listener = std::os::unix::net::UnixListener::bind(path)?;
    let result = (|| {
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;
        if let Some(gid) = gid {
            std::os::unix::fs::chown(path, None, Some(gid))?;
        }
        verify_socket(path, gid)?;
        std_listener.set_nonblocking(true)?;
        UnixListener::from_std(std_listener)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn prepare_dir(dir: &Path, gid: Option<u32>) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Err(err) if err.kind() == ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE)
                .create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))?;
            if let Some(gid) = gid {
                std::os::unix::fs::chown(dir, None, Some(gid))?;
            }
        }
        Err(err) => return Err(err),
        Ok(_) => {}
    }
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(refuse(dir, "is not a directory"));
    }
    // Nobody but the agent user may create or replace entries next to the socket.
    if meta.mode() & 0o022 != 0 {
        return Err(refuse(dir, "is group- or world-writable"));
    }
    // SAFETY: geteuid has no preconditions.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(refuse(dir, "is not owned by the agent user"));
    }
    Ok(())
}

fn verify_socket(path: &Path, gid: Option<u32>) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() {
        return Err(refuse(path, "is not a socket after bind"));
    }
    if meta.mode() & 0o777 != SOCKET_MODE {
        return Err(refuse(
            path,
            &format!("has mode {:o}, want 660", meta.mode() & 0o777),
        ));
    }
    // SAFETY: geteuid has no preconditions.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(refuse(path, "is not owned by the agent user"));
    }
    if let Some(gid) = gid {
        if meta.gid() != gid {
            return Err(refuse(path, "has the wrong group"));
        }
    }
    Ok(())
}

fn refuse(path: &Path, why: &str) -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        format!("refusing local socket {}: {why}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        // Short base: macOS caps unix socket paths at 104 bytes.
        let dir = std::path::PathBuf::from("/tmp").join(format!(
            "pa-sock-{name}-{}-{}",
            std::process::id(),
            crate::timeutil::now_unix_nanos() % 1_000_000_000
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn binds_with_mode_0660_and_creates_dir_0750() {
        let base = temp_dir("mode");
        let path = base.join("run").join("agent.sock");
        let _listener = bind(&path, None).unwrap();
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.mode() & 0o777, 0o660);
        let dir = fs::metadata(base.join("run")).unwrap();
        assert_eq!(dir.mode() & 0o777, 0o750);
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn applies_group_when_given() {
        let base = temp_dir("group");
        let path = base.join("agent.sock");
        // SAFETY: getegid has no preconditions.
        let gid = unsafe { libc::getegid() };
        let _listener = bind(&path, Some(gid)).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().gid(), gid);
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn replaces_stale_socket() {
        let base = temp_dir("stale");
        let path = base.join("agent.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let _listener = bind(&path, None).unwrap();
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn refuses_symlink_and_regular_file() {
        let base = temp_dir("refuse");
        let target = base.join("elsewhere");
        fs::write(&target, b"x").unwrap();
        let link = base.join("agent.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = bind(&link, None).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(target.exists(), "symlink target must not be touched");

        let err = bind(&target, None).unwrap_err();
        assert!(err.to_string().contains("not a socket"), "{err}");
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn refuses_world_writable_or_symlinked_dir() {
        let base = temp_dir("dir");
        let open = base.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(bind(&open.join("agent.sock"), None).is_err());

        let linked = base.join("linked");
        std::os::unix::fs::symlink(&open, &linked).unwrap();
        assert!(bind(&linked.join("agent.sock"), None).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn refuses_group_writable_dir() {
        let base = temp_dir("gw");
        let dir = base.join("run");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
        let err = bind(&dir.join("agent.sock"), None).unwrap_err();
        assert!(err.to_string().contains("writable"), "{err}");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn resolve_unknown_group_fails() {
        assert!(resolve_group("permanu-no-such-group-xyz").is_err());
    }
}
