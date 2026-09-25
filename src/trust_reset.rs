//! `permanu-agent trust reset --i-understand` (signed-plan.md 7.5).
//!
//! Root on a terminal, after the operator types `yes`, moves
//! `trusted-keys.json` aside, re-seeds `admissions.db` (section 6.3) and
//! leaves the server in bootstrap (section 7.3: the trust file is absent).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::admissions::{AdmissionStore, StoreConfig, StoreError, StoreOwner};
use crate::signed_plan::text::format_timestamp;

pub const AUDIT_LOG: &str = "/var/log/permanu/audit.log";
pub const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// Paths the command touches. Tests pass a temp directory; production uses
/// [`TrustResetPaths::production`].
pub struct TrustResetPaths {
    pub trusted_keys: PathBuf,
    pub admissions_db: PathBuf,
    pub audit_log: PathBuf,
    pub journal_socket: PathBuf,
}

impl TrustResetPaths {
    pub fn production() -> Self {
        Self {
            trusted_keys: PathBuf::from(crate::trusted_keys::TRUSTED_KEYS_PATH),
            admissions_db: PathBuf::from(crate::admissions::DEFAULT_ADMISSIONS_DB),
            audit_log: PathBuf::from(AUDIT_LOG),
            journal_socket: PathBuf::from(JOURNAL_SOCKET),
        }
    }
}

#[derive(Debug)]
pub enum TrustResetDone {
    Reset { backup: PathBuf },
    AlreadyBootstrap,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustResetError {
    #[error("trust reset requires --i-understand")]
    Flag,
    #[error("trust reset must be run as root")]
    Root,
    #[error("trust reset requires a terminal")]
    Tty,
    #[error("trust reset was not confirmed")]
    Confirm,
    #[error("trust reset: {0}")]
    Io(#[from] io::Error),
    #[error("trust reset: {0}")]
    Store(#[from] StoreError),
}

/// Gates, then the reset. `confirm` is read only after the flag, root and
/// TTY checks, and before any file changes.
pub fn trust_reset(
    paths: &TrustResetPaths,
    understand: bool,
    euid: u32,
    tty: bool,
    now: i64,
    owner: Option<StoreOwner>,
    confirm: impl FnOnce() -> io::Result<String>,
) -> Result<TrustResetDone, TrustResetError> {
    if !understand {
        return Err(TrustResetError::Flag);
    }
    if euid != 0 {
        return Err(TrustResetError::Root);
    }
    if !tty {
        return Err(TrustResetError::Tty);
    }
    let line = confirm()?;
    if line.trim() != "yes" {
        return Err(TrustResetError::Confirm);
    }
    match fs::symlink_metadata(&paths.trusted_keys) {
        Ok(meta) if meta.file_type().is_file() || meta.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(TrustResetError::Io(io::Error::other(
                "trusted-keys.json is not a file",
            )));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(TrustResetDone::AlreadyBootstrap);
        }
        Err(err) => return Err(err.into()),
    }
    // Re-seed while the trust file is still in place, then move it. A crash
    // after the re-seed and before the rename leaves the section 6.3
    // quarantine, which is the fail-closed direction.
    AdmissionStore::reseed(
        &StoreConfig {
            path: paths.admissions_db.clone(),
            owner,
        },
        now,
    )?;
    let backup = backup_path(&paths.trusted_keys, now);
    if fs::symlink_metadata(&backup).is_ok() {
        return Err(TrustResetError::Io(io::Error::other(
            "trust reset backup already exists",
        )));
    }
    fs::rename(&paths.trusted_keys, &backup)?;
    let notice = format!(
        "trust reset: moved trusted-keys.json to {}; admissions.db re-seeded; server is in bootstrap",
        backup.file_name().unwrap_or_default().to_string_lossy()
    );
    append_audit(&paths.audit_log, now, &notice)?;
    journal_notice(&paths.journal_socket, &notice);
    Ok(TrustResetDone::Reset { backup })
}

fn backup_path(path: &Path, now: i64) -> PathBuf {
    let stamp = format_timestamp(now).replace(':', "");
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{name}.bak-{stamp}"))
}

fn append_audit(path: &Path, now: i64, line: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{} {line}", format_timestamp(now))?;
    file.sync_all()?;
    Ok(())
}

/// Native journald datagram. A missing socket is not an error (section 7.5
/// still succeeds on a host without journald).
fn journal_notice(socket: &Path, message: &str) {
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return;
    };
    let payload = format!("PRIORITY=6\nSYSLOG_IDENTIFIER=permanu-agent\nMESSAGE={message}\n");
    let _ = sock.send_to(payload.as_bytes(), socket);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::signed_plan::text::{format_timestamp, timestamp};

    fn now() -> i64 {
        timestamp("2026-09-23T10:05:00Z").unwrap()
    }

    fn temp_root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permanu-trust-reset-{label}-{}-{}",
            std::process::id(),
            crate::timeutil::now_unix_nanos()
        ));
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::create_dir_all(dir.join("agent")).unwrap();
        dir
    }

    fn paths_of(dir: &std::path::Path) -> TrustResetPaths {
        TrustResetPaths {
            trusted_keys: dir.join("etc/trusted-keys.json"),
            admissions_db: dir.join("agent/admissions.db"),
            audit_log: dir.join("log/audit.log"),
            journal_socket: dir.join("missing-journal.sock"),
        }
    }

    fn store_config(paths: &TrustResetPaths) -> StoreConfig {
        StoreConfig {
            path: paths.admissions_db.clone(),
            owner: None,
        }
    }

    /// A healthy store (no quarantine) and a trust file.
    fn fixture(label: &str) -> (PathBuf, TrustResetPaths) {
        let dir = temp_root(label);
        let paths = paths_of(&dir);
        let (store, report) = AdmissionStore::open(&store_config(&paths), false, now()).unwrap();
        assert!(report.quarantine_ends_at.is_none());
        drop(store);
        fs::write(&paths.trusted_keys, b"{\"version\":1,\"keys\":[]}\n").unwrap();
        (dir, paths)
    }

    fn yes_was_not_asked() -> impl FnOnce() -> io::Result<String> {
        || panic!("confirmation was read")
    }

    #[test]
    fn trust_reset_refuses_without_the_flag_and_changes_nothing() {
        let (dir, paths) = fixture("flag");
        let before = fs::read(&paths.trusted_keys).unwrap();
        let err =
            trust_reset(&paths, false, 0, true, now(), None, yes_was_not_asked()).unwrap_err();
        assert!(matches!(err, TrustResetError::Flag), "{err}");
        assert_eq!(fs::read(&paths.trusted_keys).unwrap(), before);
        assert!(fs::read_dir(dir.join("etc")).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".bak-")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_reset_refuses_when_not_root() {
        let (dir, paths) = fixture("uid");
        let err =
            trust_reset(&paths, true, 1000, true, now(), None, yes_was_not_asked()).unwrap_err();
        assert!(matches!(err, TrustResetError::Root), "{err}");
        assert!(paths.trusted_keys.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_reset_refuses_when_not_a_tty() {
        let (dir, paths) = fixture("tty");
        let err =
            trust_reset(&paths, true, 0, false, now(), None, yes_was_not_asked()).unwrap_err();
        assert!(matches!(err, TrustResetError::Tty), "{err}");
        assert!(paths.trusted_keys.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_reset_refuses_when_confirmation_is_no() {
        let (dir, paths) = fixture("no");
        let asked = Cell::new(false);
        let err = trust_reset(&paths, true, 0, true, now(), None, || {
            asked.set(true);
            assert!(
                paths.trusted_keys.exists(),
                "confirm runs before any change"
            );
            Ok("no\n".to_owned())
        })
        .unwrap_err();
        assert!(asked.get());
        assert!(matches!(err, TrustResetError::Confirm), "{err}");
        assert!(paths.trusted_keys.exists());
        assert!(!paths.audit_log.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_reset_moves_the_trust_file_reseeds_and_logs() {
        let (dir, paths) = fixture("yes");
        let stamp = format_timestamp(now()).replace(':', "");
        let backup = dir.join(format!("etc/trusted-keys.json.bak-{stamp}"));
        let done = trust_reset(&paths, true, 0, true, now(), None, || {
            assert!(paths.trusted_keys.is_file());
            Ok("yes\n".to_owned())
        })
        .unwrap();
        let TrustResetDone::Reset { backup: got } = done else {
            panic!("expected a reset");
        };
        assert_eq!(got, backup);
        assert!(
            !paths.trusted_keys.exists(),
            "bootstrap: trusted-keys.json absent"
        );
        assert_eq!(fs::read(&backup).unwrap(), b"{\"version\":1,\"keys\":[]}\n");
        let (store, _) = AdmissionStore::open(&store_config(&paths), false, now()).unwrap();
        assert_eq!(
            store.quarantine_ends_at().unwrap(),
            Some(now() + crate::admissions::QUARANTINE_SECONDS)
        );
        drop(store);
        let aside = fs::read_dir(dir.join("agent")).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("admissions.db.corrupt-")
        });
        assert!(aside, "the old store was moved aside");
        let audit = fs::read_to_string(&paths.audit_log).unwrap();
        let lines: Vec<_> = audit.lines().collect();
        assert_eq!(lines.len(), 1, "{audit}");
        assert!(lines[0].contains("trust reset"), "{audit}");
        assert!(lines[0].contains(&stamp), "{audit}");

        let again = trust_reset(&paths, true, 0, true, now() + 5, None, || {
            Ok("yes".to_owned())
        })
        .unwrap();
        assert!(matches!(again, TrustResetDone::AlreadyBootstrap));
        assert_eq!(fs::read_to_string(&paths.audit_log).unwrap(), audit);
        assert!(!paths.trusted_keys.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
