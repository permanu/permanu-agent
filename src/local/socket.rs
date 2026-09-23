//! The v2 unix socket (agent-protocol.md section 1): `root:permanu`, mode
//! 0660, directory 0750. The listener refuses to start when the path is a
//! symlink or the resulting ownership/mode differs. On a server the socket
//! comes from `permanu-agent.socket` (section 8) and is adopted, not bound.

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

/// The first file descriptor systemd passes (`SD_LISTEN_FDS_START`).
pub const LISTEN_FDS_START: std::os::fd::RawFd = 3;

/// Takes the socket systemd passed (`permanu-agent.socket`,
/// agent-protocol.md section 8) when the agent was socket-activated, else
/// binds `path` itself (dev paths, tests).
pub fn listen(path: &Path, gid: Option<u32>) -> io::Result<UnixListener> {
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    match activation_fd(
        listen_pid.as_deref(),
        listen_fds.as_deref(),
        std::process::id(),
    )? {
        Some(fd) => adopt(fd, path, gid),
        None => bind(path, gid),
    }
}

/// The activated descriptor, when `LISTEN_PID` names this process. Exactly one
/// socket is expected; any other count is refused rather than guessed.
pub fn activation_fd(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    pid: u32,
) -> io::Result<Option<std::os::fd::RawFd>> {
    let Some(listen_pid) = listen_pid else {
        return Ok(None);
    };
    if listen_pid.trim().parse::<u32>().ok() != Some(pid) {
        return Ok(None);
    }
    match listen_fds.and_then(|count| count.trim().parse::<u32>().ok()) {
        Some(1) => Ok(Some(LISTEN_FDS_START)),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "socket activation must pass exactly one socket (LISTEN_FDS=1)",
        )),
    }
}

/// Adopts an activated descriptor: it must be a listening unix stream socket
/// bound at `path` with the same owner, mode and group `bind` enforces.
pub fn adopt(fd: std::os::fd::RawFd, path: &Path, gid: Option<u32>) -> io::Result<UnixListener> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: the descriptor was handed to this process (systemd socket
    // activation, or a test) and nothing else owns it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let int_option = |option: libc::c_int| -> io::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: value and len are valid for writes of the sizes given.
        let rc = unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    };
    if int_option(libc::SO_TYPE)? != libc::SOCK_STREAM {
        return Err(refuse(path, "activated socket is not a stream socket"));
    }
    // Linux answers SO_ACCEPTCONN for unix sockets; macOS (dev only) does not.
    #[cfg(target_os = "linux")]
    if int_option(libc::SO_ACCEPTCONN)? == 0 {
        return Err(refuse(path, "activated socket is not listening"));
    }
    let std_listener = std::os::unix::net::UnixListener::from(owned);
    let local = std_listener.local_addr()?;
    if local.as_pathname() != Some(path) {
        return Err(refuse(
            path,
            "activated socket is not the configured socket",
        ));
    }
    verify_socket(path, gid)?;
    // SAFETY: fcntl on a descriptor this function owns.
    if unsafe { libc::fcntl(std_listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std_listener.set_nonblocking(true)?;
    UnixListener::from_std(std_listener)
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

    // agent-protocol.md section 8: permanu-agent.socket creates
    // /run/permanu/agent.sock in the root-owned /run/permanu and passes it to
    // the sandboxed agent, which cannot bind there itself.
    #[test]
    fn activation_fd_follows_listen_pid_and_listen_fds() {
        assert_eq!(activation_fd(None, None, 42).unwrap(), None);
        assert_eq!(activation_fd(Some("41"), Some("1"), 42).unwrap(), None);
        assert_eq!(
            activation_fd(Some("42"), Some("1"), 42).unwrap(),
            Some(LISTEN_FDS_START)
        );
        assert!(activation_fd(Some("42"), Some("2"), 42).is_err());
        assert!(activation_fd(Some("42"), Some("0"), 42).is_err());
        assert!(activation_fd(Some("42"), Some("x"), 42).is_err());
    }

    #[tokio::test]
    async fn adopts_an_activated_socket_at_the_configured_path() {
        use std::os::fd::IntoRawFd;
        let base = temp_dir("adopt");
        let path = base.join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE)).unwrap();
        // SAFETY: getegid has no preconditions.
        let gid = unsafe { libc::getegid() };
        std::os::unix::fs::chown(&path, None, Some(gid)).unwrap();
        let fd = listener.into_raw_fd();
        let adopted = adopt(fd, &path, Some(gid)).unwrap();
        let client = tokio::net::UnixStream::connect(&path).await;
        assert!(client.is_ok(), "adopted listener accepts connections");
        drop(adopted);
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn refuses_an_activated_socket_elsewhere_or_with_a_wrong_mode() {
        use std::os::fd::IntoRawFd;
        let base = temp_dir("adoptbad");
        let path = base.join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let fd = listener.into_raw_fd();
        let err = adopt(fd, &base.join("other.sock"), None).unwrap_err();
        assert!(
            err.to_string().contains("not the configured socket"),
            "{err}"
        );

        let listener = std::os::unix::net::UnixListener::bind(base.join("b.sock")).unwrap();
        fs::set_permissions(base.join("b.sock"), fs::Permissions::from_mode(0o666)).unwrap();
        let err = adopt(listener.into_raw_fd(), &base.join("b.sock"), None).unwrap_err();
        assert!(err.to_string().contains("want 660"), "{err}");

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(adopt(udp.into_raw_fd(), &path, None).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn resolve_unknown_group_fails() {
        assert!(resolve_group("permanu-no-such-group-xyz").is_err());
    }
}
