//! The agent's schedulers (agent-protocol.md 10): cron jobs (`cron.v1`),
//! backup policies (`backups.v1`) and alert rules (`alerts.v1`).
//!
//! - Definitions come only from admitted plans. The cron and backup
//!   definition kinds are bound with `bind_plan` alone; the runner records
//!   them (`consumed`, then `result succeeded`) and a definition is in force
//!   once that result is reconciled into `admission_actions`
//!   (signed-plan.md 14.5, 14.6). The `alert.*` kinds the agent applies
//!   itself. Every tick re-reads the definitions, so the schedulers never
//!   hold a definition the store does not.
//! - Every run that touches containers, data or the network is a runner op
//!   with a schedule binding (signed-plan.md 14.9) naming the definition,
//!   the fire time and the attempt; the runner re-verifies all of it.
//!   Notifications go through `notify_channel`: the agent never holds a
//!   channel URL, a destination credential or a decrypted backup.
//! - Run history, alert state and checkpoints live in `ops.db`.
//! - The schedulers write their own `CRON`, `BACKUP` and `AGENT` log
//!   records (ingest `agent`) into the telemetry store, redacted.

pub mod alert_spec;
pub mod alerts;
pub mod backup;
pub mod cron;
pub mod cron_expr;
pub mod ops_store;
pub mod rpc;

#[cfg(test)]
pub(crate) mod test_support;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prost_types::Timestamp;

use super::events::EventBus;
use super::execution::Clock;
use super::runner::Runner;
use super::telemetry::records::{encode, TAG_LOG};
use super::telemetry::redaction::redact;
use super::telemetry::store::{valid_id, Kind, Producer};
use super::telemetry::Telemetry;
use crate::admissions::AdmissionStore;
use crate::proto::agent::v2::{event_condition, LogLevel, LogRecord, LogSourceType, Scope};
use crate::signed_plan::text::format_timestamp;
use ops_store::OpsStore;

/// v2.1.0 capabilities (agent-protocol.md 10).
pub const CAPABILITY_CRON: &str = "cron.v1";
pub const CAPABILITY_BACKUPS: &str = "backups.v1";
pub const CAPABILITY_ALERTS: &str = "alerts.v1";

/// The scheduler checkpoint is written every 10 s (agent-protocol.md 10).
pub const TICK_SECONDS: u64 = 10;
/// A gap over this is downtime or a forward clock jump.
pub const DOWNTIME_SECONDS: i64 = 120;

/// What every scheduler needs.
#[derive(Clone)]
pub struct Deps {
    pub store: Arc<AdmissionStore>,
    pub ops: Arc<OpsStore>,
    pub runner: Arc<dyn Runner>,
    pub events: EventBus,
    pub clock: Arc<dyn Clock>,
    pub logs: AgentLogs,
    pub server_id: String,
}

/// RFC 3339 of Unix seconds.
pub fn rfc(seconds: i64) -> String {
    format_timestamp(seconds)
}

pub fn pts(seconds: i64) -> Timestamp {
    Timestamp { seconds, nanos: 0 }
}

pub fn parse_rfc(text: &str) -> Option<i64> {
    crate::signed_plan::text::timestamp(text)
}

/// A fresh record id (UUIDv7).
pub fn new_id(now: i64) -> String {
    let ms = u64::try_from(now).unwrap_or(0).saturating_mul(1_000)
        + u64::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.subsec_millis()),
        );
    crate::admissions::new_uuid7(ms)
}

/// The signed scope of a definition as a proto `Scope`.
pub fn scope_of(scope: &(String, String, String), service_id: &str) -> Scope {
    Scope {
        project_id: scope.0.clone(),
        environment: scope.1.clone(),
        environment_id: scope.2.clone(),
        service_id: service_id.to_owned(),
        ..Default::default()
    }
}

/// The identity of one agent-written log record.
#[derive(Debug, Clone, Default)]
pub struct LogIdentity {
    pub source: String,
    pub project_id: String,
    pub environment: String,
    pub environment_id: String,
    pub service_id: String,
    pub run_id: String,
}

/// Writes the schedulers' own log records into the telemetry store
/// (agent-protocol.md 9.4: ingest `agent`). Every message is redacted
/// before it is queued; nothing is written without a store.
#[derive(Clone, Default)]
pub struct AgentLogs {
    pub telemetry: Option<Arc<Telemetry>>,
    pub host: String,
}

impl AgentLogs {
    pub fn write(
        &self,
        source_type: LogSourceType,
        level: LogLevel,
        message: &str,
        identity: &LogIdentity,
    ) {
        let Some(telemetry) = &self.telemetry else {
            return;
        };
        let (text, redacted) = match redact(message) {
            std::borrow::Cow::Borrowed(text) => (text.to_owned(), false),
            std::borrow::Cow::Owned(text) => (text, true),
        };
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
        let record = LogRecord {
            timestamp: Some(Timestamp {
                seconds: nanos.div_euclid(1_000_000_000),
                nanos: i32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap_or(0),
            }),
            level: level as i32,
            message: text,
            source_type: source_type as i32,
            source: identity.source.clone(),
            host: self.host.clone(),
            project_id: identity.project_id.clone(),
            service_id: identity.service_id.clone(),
            environment: identity.environment.clone(),
            environment_id: identity.environment_id.clone(),
            run_id: identity.run_id.clone(),
            redacted,
            ingest: "agent".to_owned(),
            ..Default::default()
        };
        let producer = if valid_id(&identity.project_id) {
            Producer::Project(identity.project_id.clone())
        } else {
            Producer::System
        };
        telemetry.submit(
            Kind::Logs,
            producer,
            nanos,
            TAG_LOG,
            encode(&record),
            redacted,
        );
    }
}

/// A built-in event the schedulers report to the alert evaluator
/// (agent-protocol.md 10.1 heartbeat alerts, 10.2 backup failures, 10.3
/// event rules).
#[derive(Debug, Clone, PartialEq)]
pub struct BuiltinEvent {
    pub kind: event_condition::Kind,
    pub scope: Scope,
    /// `cron_heartbeat`, `backup` or `telemetry`.
    pub source: &'static str,
    /// The cron_id or policy id ("" for server-wide events).
    pub subject_id: String,
    /// True for an occurrence, false for its counterpart (resolution).
    pub occurred: bool,
    /// Open an `AlertEvent` even when no rule matches (a job with
    /// `heartbeat_alert`, or a backup policy with channels).
    pub standalone: bool,
    /// Channels of the subject itself (a backup policy's `channel_ids`).
    pub channel_ids: Vec<String>,
    pub summary: String,
}

/// Where the schedulers report built-in events.
pub trait AlertSink: Send + Sync {
    fn builtin(&self, event: BuiltinEvent);
}

/// Discards built-in events (tests, and before the evaluator starts).
#[derive(Debug, Default)]
pub struct NoAlerts;

impl AlertSink for NoAlerts {
    fn builtin(&self, _: BuiltinEvent) {}
}
