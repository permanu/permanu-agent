use std::{collections::HashMap, sync::Mutex};

use anyhow::Result;
use futures::future::AbortHandle;
use serde::Deserialize;

use crate::proto::agent::v1::CommandType;

pub const MAX_CONCURRENT_COMMANDS: usize = 50;

const COMMAND_TYPE_UPDATE_AGENT: i32 = 4;
const COMMAND_TYPE_COMPOSE_LOGS: i32 = 33;
const COMMAND_TYPE_APP_LOGS: i32 = 44;
const COMMAND_TYPE_SERVICE_LOGS: i32 = 15;
const COMMAND_TYPE_BACKUP_DOWNLOAD: i32 = 24;
const COMMAND_TYPE_CANCEL_COMMAND: i32 = 99;
const COMMAND_TYPE_RESTART_SELF: i32 = 123;
const COMMAND_TYPE_REENROLL: i32 = 124;
const COMMAND_TYPE_BOOTSTRAP_SECRETS: i32 = 140;
const COMMAND_TYPE_ROTATE_SECRETS: i32 = 141;
const COMMAND_TYPE_ROTATE_AGENT_SECRET: i32 = 142;

#[derive(Default)]
pub struct CommandCancels {
    inner: Mutex<HashMap<String, AbortHandle>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandAdmission {
    AcquirePermit,
    BypassLimit,
    RejectBusy,
}

impl CommandCancels {
    pub fn register(&self, command_id: &str, abort: AbortHandle) {
        if command_id.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().expect("command cancel map poisoned");
        inner.insert(command_id.to_string(), abort);
    }

    pub fn cancel(&self, command_id: &str) -> bool {
        let abort = {
            let inner = self.inner.lock().expect("command cancel map poisoned");
            inner.get(command_id).cloned()
        };
        if let Some(abort) = abort {
            abort.abort();
            true
        } else {
            false
        }
    }

    pub fn remove(&self, command_id: &str) {
        let mut inner = self.inner.lock().expect("command cancel map poisoned");
        inner.remove(command_id);
    }
}

pub fn parse_cancel_target(payload: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct Payload {
        cancel_command_id: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let target = payload.cancel_command_id.trim();
    if target.is_empty() {
        anyhow::bail!("cancel_command_id is required");
    }
    Ok(target.to_string())
}

pub fn command_bypasses_limit(command_type: i32) -> bool {
    is_control_plane_command(command_type) || is_streaming_command(command_type)
}

pub fn admission_for(command_type: i32, available_permits: usize) -> CommandAdmission {
    if command_bypasses_limit(command_type) {
        return CommandAdmission::BypassLimit;
    }
    if available_permits == 0 {
        return CommandAdmission::RejectBusy;
    }
    CommandAdmission::AcquirePermit
}

pub fn command_type_is_valid(command_type: i32) -> bool {
    CommandType::try_from(command_type)
        .map(|kind| kind != CommandType::Unspecified)
        .unwrap_or(false)
}

pub fn is_control_plane_command(command_type: i32) -> bool {
    matches!(
        command_type,
        COMMAND_TYPE_CANCEL_COMMAND
            | COMMAND_TYPE_UPDATE_AGENT
            | COMMAND_TYPE_RESTART_SELF
            | COMMAND_TYPE_REENROLL
            | COMMAND_TYPE_BOOTSTRAP_SECRETS
            | COMMAND_TYPE_ROTATE_SECRETS
            | COMMAND_TYPE_ROTATE_AGENT_SECRET
    )
}

pub fn is_streaming_command(command_type: i32) -> bool {
    matches!(
        command_type,
        COMMAND_TYPE_COMPOSE_LOGS
            | COMMAND_TYPE_APP_LOGS
            | COMMAND_TYPE_SERVICE_LOGS
            | COMMAND_TYPE_BACKUP_DOWNLOAD
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_payload_requires_target_command_id() {
        let err = parse_cancel_target(br#"{"cancel_command_id":""}"#).unwrap_err();
        assert!(err.to_string().contains("cancel_command_id is required"));
    }

    #[test]
    fn cancel_payload_parses_target_command_id() {
        let target = parse_cancel_target(br#"{"cancel_command_id":"cmd-123"}"#)
            .expect("parse cancel target");
        assert_eq!(target, "cmd-123");
    }

    #[test]
    fn control_plane_commands_bypass_limit() {
        for command_type in [4, 99, 123, 124, 140, 141, 142] {
            assert!(command_bypasses_limit(command_type));
        }
    }

    #[test]
    fn streaming_commands_bypass_limit() {
        for command_type in [15, 24, 33, 44] {
            assert!(command_bypasses_limit(command_type));
        }
    }

    #[test]
    fn transactional_commands_do_not_bypass_limit() {
        for command_type in [1, 41, 50, 70, 117, 130] {
            assert!(!command_bypasses_limit(command_type));
        }
    }

    #[test]
    fn transactional_commands_are_rejected_when_capacity_is_full() {
        assert_eq!(admission_for(50, 0), CommandAdmission::RejectBusy);
    }

    #[test]
    fn control_plane_commands_are_admitted_even_when_capacity_is_full() {
        assert_eq!(admission_for(99, 0), CommandAdmission::BypassLimit);
    }

    #[test]
    fn unspecified_command_type_is_invalid() {
        assert!(!command_type_is_valid(0));
    }

    #[test]
    fn future_unknown_command_type_is_invalid() {
        assert!(!command_type_is_valid(9999));
    }

    #[test]
    fn known_command_type_is_valid() {
        assert!(command_type_is_valid(50));
    }

    #[test]
    fn command_cancels_abort_registered_handle() {
        let cancels = CommandCancels::default();
        let (handle, registration) = AbortHandle::new_pair();
        let future =
            futures::future::Abortable::new(futures::future::pending::<()>(), registration);

        cancels.register("cmd-1", handle);

        assert!(cancels.cancel("cmd-1"));
        let result = futures::executor::block_on(future);
        assert!(result.is_err());
    }

    #[test]
    fn command_cancels_reports_missing_target() {
        let cancels = CommandCancels::default();
        assert!(!cancels.cancel("missing"));
    }
}
