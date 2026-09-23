//! The `AgentStatus` fields beyond health and telemetry (agent-protocol.md
//! 12.3): engine presence and the away summary, the webhook queue and
//! on-server builds, and the scheduler counters.

use std::sync::Arc;

use super::hooks::Hooks;
use super::presence::Presence;
use super::sched::{pts, Schedulers};
use crate::proto::agent::v2::{agent_status, AgentStatus, AlertState, RestoreVerificationStatus};

/// Where the status fields come from; any may be absent.
#[derive(Clone, Default)]
pub struct StatusSources {
    pub presence: Option<Arc<Presence>>,
    pub hooks: Option<Arc<Hooks>>,
    pub schedulers: Option<Schedulers>,
}

impl StatusSources {
    /// Adds presence, webhook and scheduler fields to `status` (and
    /// `buildkit_unavailable` to its degraded reasons).
    pub fn fill(&self, status: &mut AgentStatus, now: i64) {
        if let Some(presence) = &self.presence {
            let view = presence.view();
            status.engine_online = view.engine_online;
            status.engine_last_seen_at = view.engine_last_seen_at.map(pts);
            status.engine_id = view.engine_id;
            status.away = Some(view.away);
        }
        if let Some(hooks) = &self.hooks {
            status.webhook_pending = hooks.pending();
            status.server_builds_enabled = hooks.server_builds_enabled();
            if !status.server_builds_enabled {
                status
                    .degraded_reasons
                    .push("buildkit_unavailable".to_owned());
            }
        }
        if let Some(schedulers) = &self.schedulers {
            let jobs = schedulers.cron.jobs();
            status.cron_jobs = u32::try_from(jobs.len()).unwrap_or(u32::MAX);
            status.next_cron_run_at = jobs
                .values()
                .filter(|job| job.enabled)
                .filter_map(|job| job.next_fire(now))
                .min()
                .map(pts);
            let defs = schedulers.backups.definitions();
            let policies: Vec<_> = defs
                .policies
                .values()
                .map(|policy| schedulers.backups.policy_proto(policy, &defs))
                .collect();
            status.next_backup_at = policies
                .iter()
                .filter_map(|p| p.next_run_at)
                .min_by_key(|t| t.seconds);
            status.last_verify_passed_at = policies
                .iter()
                .filter_map(|p| p.last_verification.as_ref())
                .filter(|v| v.status == RestoreVerificationStatus::Passed as i32)
                .filter_map(|v| v.finished_at)
                .max_by_key(|t| t.seconds);
            status.alerts_firing = u32::try_from(
                schedulers
                    .alerts
                    .rules()
                    .iter()
                    .filter(|rule| rule.state == AlertState::Firing as i32)
                    .count(),
            )
            .unwrap_or(u32::MAX);
            if !policies.is_empty() && defs.recovery_recipient.is_none() {
                status
                    .degraded_reasons
                    .push("recovery_recipient_missing".to_owned());
            }
        }
        status.degraded_reasons.sort();
        status.degraded_reasons.dedup();
        if status.health != agent_status::Health::Quarantined as i32 {
            status.health = if status.degraded_reasons.is_empty() {
                agent_status::Health::Ok
            } else {
                agent_status::Health::Degraded
            } as i32;
        }
    }
}
