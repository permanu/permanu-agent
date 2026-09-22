//! S8 (agent-protocol.md section 4): once `/etc/permanu/trusted-keys.json`
//! exists, signed plans are the only way to change the server. The agent then
//! refuses every mutating v1 command from the hosted control plane; read-only
//! v1 commands keep working.

use std::path::Path;

use crate::{proto::agent::v1::CommandType, trusted_keys};

/// v1 command types that only read state. Everything else, including unknown
/// types, counts as mutating (fail closed).
pub fn is_read_only(command_type: i32) -> bool {
    matches!(
        CommandType::try_from(command_type),
        Ok(CommandType::Logs
            | CommandType::ServiceLogs
            | CommandType::WaitForHealthy
            | CommandType::ComposeLogs
            | CommandType::AppLogs
            | CommandType::RouteList
            | CommandType::CertList
            | CommandType::ProxyTraffic
            | CommandType::AgentLogs
            | CommandType::AgentStatus
            | CommandType::AgentPing
            | CommandType::NetworkInspect
            | CommandType::HostDiagnostic
            | CommandType::SwarmStackStatus
            | CommandType::CancelCommand)
    )
}

/// Returns the refusal message when `command_type` must be refused because
/// signing is enabled at `trusted_keys_path`, or `None` when it may run.
pub fn refusal_message(command_type: i32, trusted_keys_path: &Path) -> Option<String> {
    if is_read_only(command_type) || !trusted_keys::signing_enabled(trusted_keys_path) {
        return None;
    }
    Some(format!(
        "signed_plans_required: {} refused; {} exists, so this server only accepts \
         signed plans for changes and hosted v1 commands are read-only",
        command_type_name(command_type),
        trusted_keys_path.display()
    ))
}

fn command_type_name(command_type: i32) -> String {
    CommandType::try_from(command_type)
        .map(|t| t.as_str_name().to_string())
        .unwrap_or_else(|_| format!("COMMAND_TYPE_{command_type}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permanu-v1-guard-{name}-{}-{}",
            std::process::id(),
            crate::timeutil::now_unix_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn allows_everything_when_trusted_keys_absent() {
        let dir = temp_dir("absent");
        let path = dir.join("trusted-keys.json");
        assert_eq!(refusal_message(CommandType::Exec as i32, &path), None);
        assert_eq!(refusal_message(CommandType::AppDeploy as i32, &path), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_exec_and_deploy_once_trusted_keys_exist() {
        let dir = temp_dir("present");
        let path = dir.join("trusted-keys.json");
        fs::write(&path, b"{}").unwrap();
        for t in [
            CommandType::Exec,
            CommandType::Deploy,
            CommandType::AppDeploy,
            CommandType::ServiceCreate,
            CommandType::UpdateAgent,
            CommandType::SwarmStackDeploy,
            CommandType::BootstrapSecrets,
            CommandType::RestartSelf,
            CommandType::BackupDownload,
        ] {
            let msg =
                refusal_message(t as i32, &path).unwrap_or_else(|| panic!("{t:?} must be refused"));
            assert!(msg.contains("signed_plans_required"), "{msg}");
            assert!(msg.contains(t.as_str_name()), "{msg}");
            assert!(msg.contains("trusted-keys.json"), "{msg}");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keeps_read_only_commands_once_trusted_keys_exist() {
        let dir = temp_dir("readonly");
        let path = dir.join("trusted-keys.json");
        fs::write(&path, b"{}").unwrap();
        for t in [
            CommandType::Logs,
            CommandType::ServiceLogs,
            CommandType::AppLogs,
            CommandType::ComposeLogs,
            CommandType::AgentLogs,
            CommandType::AgentPing,
            CommandType::AgentStatus,
            CommandType::RouteList,
            CommandType::CertList,
            CommandType::HostDiagnostic,
            CommandType::SwarmStackStatus,
        ] {
            assert_eq!(refusal_message(t as i32, &path), None, "{t:?}");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_command_types_are_mutating() {
        assert!(!is_read_only(9999));
        assert!(!is_read_only(CommandType::Unspecified as i32));
    }

    #[test]
    fn dangling_symlink_counts_as_signing_enabled() {
        let dir = temp_dir("symlink");
        let path = dir.join("trusted-keys.json");
        std::os::unix::fs::symlink(dir.join("missing"), &path).unwrap();
        assert!(refusal_message(CommandType::Exec as i32, &path).is_some());
        fs::remove_dir_all(dir).unwrap();
    }
}
