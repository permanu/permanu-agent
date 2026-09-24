//! The alert evaluator (`alerts.v1`, agent-protocol.md 10.3).
//!
//! - Rules, silences and channels are the admitted `alert.*` actions the
//!   agent applied (never anything else). A rule whose spec does not parse
//!   is not evaluated.
//! - Metric and log rules are evaluated every 30 s (aligned to :00 and :30
//!   UTC) against the telemetry store; event rules on each matching
//!   built-in event (cron heartbeat, backup, verify-restore, telemetry
//!   dropping). `OK → PENDING → FIRING`, `FIRING → RESOLVED` after two
//!   false evaluations (event rules: on the counterpart event or after 24 h
//!   without an occurrence), `RESOLVED → OK` once notified; `NO_DATA` after
//!   three evaluations without a point (`ABSENT` fires on it); `MUTED` while
//!   silenced (the state is tracked, nothing is sent; a rule still firing
//!   when the silence ends notifies once).
//! - Notifications on entering `FIRING`, every `repeat_interval` while
//!   firing, and on `RESOLVED` with `notify_on_resolve`: the runner's
//!   `notify_channel` posts a fixed-template text (never log lines or
//!   attribute dumps). 408/429/5xx and transport errors retry after 10 s,
//!   60 s and 300 s; more than 30 per channel per minute are coalesced.
//! - Built-in: `TELEMETRY_DROPPING` fires while the telemetry store drops
//!   records and resolves after 5 min without a drop.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::warn;

use super::alert_spec;
use super::ops_store::{Listing, RecordKind};
use super::{new_id, parse_rfc, pts, rfc, AlertSink, BuiltinEvent, Deps, LogIdentity};
use crate::local::runner::{self, Notification};
use crate::proto::agent::v2::{
    alert_rule, event, event_condition, notification_channel, AlertEvent, AlertRule, AlertSeverity,
    AlertState, ComparisonOp, DeliveryResult, EventKind, LogCondition, LogLevel, LogSourceType,
    MetricCondition, NotificationChannel, Scope,
};

pub const ALERT_KINDS: &[&str] = &[
    "alert.rule.create",
    "alert.rule.update",
    "alert.rule.delete",
    "alert.silence",
    "alert.channel.create",
    "alert.channel.update",
    "alert.channel.delete",
];
pub const EVAL_SECONDS: i64 = 30;
const RESOLVE_AFTER_FALSE: u32 = 2;
const NO_DATA_AFTER: u32 = 3;
const EVENT_RESOLVE_SECONDS: i64 = 86_400;
const DROPPING_CLEAR_SECONDS: i64 = 300;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_SUMMARY_BYTES: usize = 512;
const PER_CHANNEL_PER_MINUTE: usize = 30;
/// `TestNotificationChannel`: one per channel per 10 s.
pub const TEST_INTERVAL_SECONDS: i64 = 10;

/// Values the evaluator reads from the telemetry store.
#[tonic::async_trait]
pub trait AlertSource: Send + Sync {
    /// The aggregated value of each matching series over the window
    /// ending at `now`; empty when there is no point.
    async fn metric(&self, condition: &MetricCondition, now: i64) -> Vec<f64>;
    /// Matching log records in the window ending at `now`.
    async fn log_count(&self, condition: &LogCondition, now: i64) -> u64;
    /// Records dropped by the telemetry store since start.
    fn dropped_total(&self) -> u64;
}

/// No telemetry store: metric rules see no data, log rules count nothing.
#[derive(Debug, Default)]
pub struct NoSource;

#[tonic::async_trait]
impl AlertSource for NoSource {
    async fn metric(&self, _: &MetricCondition, _: i64) -> Vec<f64> {
        Vec::new()
    }
    async fn log_count(&self, _: &LogCondition, _: i64) -> u64 {
        0
    }
    fn dropped_total(&self) -> u64 {
        0
    }
}

/// An applied rule.
#[derive(Debug, Clone)]
pub struct RuleDef {
    pub rule: AlertRule,
    pub silenced_until: Option<i64>,
}

/// An applied channel (the credential stays sealed in admissions.db).
#[derive(Debug, Clone)]
pub struct ChannelDef {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub credential_digest: String,
    pub plan_digest_hex: String,
}

/// The applied rules and channels, oldest action first.
pub fn load(
    actions: &[crate::admissions::definitions::AdmittedAction],
) -> (BTreeMap<String, RuleDef>, BTreeMap<String, ChannelDef>) {
    let mut rules: BTreeMap<String, RuleDef> = BTreeMap::new();
    let mut channels = BTreeMap::new();
    for action in actions.iter().rev().filter(|a| a.succeeded()) {
        let p = &action.params;
        let text = |name: &str| p[name].as_str().unwrap_or_default().to_owned();
        match action.kind.as_str() {
            "alert.rule.create" | "alert.rule.update" => {
                let id = text("alert_rule_id");
                match alert_spec::parse(&id, &text("name"), &text("spec")) {
                    Ok(mut rule) => {
                        rule.plan_digest_hex = action.plan_digest_hex.clone();
                        let silenced_until = rules.get(&id).and_then(|r| r.silenced_until);
                        rules.insert(
                            id,
                            RuleDef {
                                rule,
                                silenced_until,
                            },
                        );
                    }
                    Err(err) => {
                        warn!(rule = %id, error = %err, "alert rule spec is invalid; not evaluated")
                    }
                }
            }
            "alert.rule.delete" => {
                rules.remove(p["alert_rule_id"].as_str().unwrap_or_default());
            }
            "alert.silence" => {
                if let Some(rule) = rules.get_mut(p["alert_rule_id"].as_str().unwrap_or_default()) {
                    rule.silenced_until = p["until"].as_str().and_then(parse_rfc);
                }
            }
            "alert.channel.create" | "alert.channel.update" => {
                let id = text("channel_id");
                channels.insert(
                    id.clone(),
                    ChannelDef {
                        id,
                        name: text("name"),
                        kind: text("channel_kind"),
                        credential_digest: text("credential_ciphertext_digest_hex"),
                        plan_digest_hex: action.plan_digest_hex.clone(),
                    },
                );
            }
            "alert.channel.delete" => {
                channels.remove(p["channel_id"].as_str().unwrap_or_default());
            }
            _ => {}
        }
    }
    (rules, channels)
}

/// Per-rule evaluation state (kept across evaluations).
#[derive(Debug, Clone, Default)]
struct Runtime {
    state: i32,
    since: i64,
    pending_since: Option<i64>,
    false_streak: u32,
    no_data_streak: u32,
    last_evaluated: i64,
    last_value: f64,
    /// The open `AlertEvent` of the current firing episode.
    episode: Option<String>,
    last_notified: i64,
    last_occurrence: i64,
    /// Notifications held back by a silence.
    held: bool,
}

#[derive(Default)]
struct State {
    rules: BTreeMap<String, RuleDef>,
    channels: BTreeMap<String, ChannelDef>,
    runtime: HashMap<String, Runtime>,
    /// Standalone episodes of built-in sources, by (source, subject, kind).
    builtin: HashMap<(String, String, i32), String>,
    dropped: Option<u64>,
    dropping_since: Option<i64>,
    last_drop_seen: i64,
    sends: HashMap<String, VecDeque<i64>>,
    coalesced: HashMap<String, u32>,
    last_test: HashMap<String, i64>,
    target_display: HashMap<String, String>,
    last_delivery: HashMap<String, DeliveryResult>,
}

pub struct AlertEvaluator {
    deps: Deps,
    source: Arc<dyn AlertSource>,
    state: Mutex<State>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    live: broadcast::Sender<AlertEvent>,
    /// Retry delays after a failed send (section 10.3: 10 s, 60 s, 300 s).
    retry_delays: Vec<Duration>,
    me: std::sync::Weak<Self>,
}

fn severity_word(severity: i32) -> &'static str {
    match AlertSeverity::try_from(severity) {
        Ok(AlertSeverity::Critical) => "CRITICAL",
        Ok(AlertSeverity::Info) => "INFO",
        _ => "WARNING",
    }
}

fn bounded(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

fn compare(op: i32, value: f64, threshold: f64) -> bool {
    match ComparisonOp::try_from(op) {
        Ok(ComparisonOp::Gt) => value > threshold,
        Ok(ComparisonOp::Gte) => value >= threshold,
        Ok(ComparisonOp::Lt) => value < threshold,
        Ok(ComparisonOp::Lte) => value <= threshold,
        Ok(ComparisonOp::Eq) => (value - threshold).abs() < f64::EPSILON,
        Ok(ComparisonOp::Neq) => (value - threshold).abs() >= f64::EPSILON,
        _ => false,
    }
}

/// A rule's scope matches when every field it sets equals the event's.
fn scope_matches(rule: Option<&Scope>, event: &Scope) -> bool {
    let Some(rule) = rule else {
        return true;
    };
    let same = |a: &str, b: &str| a.is_empty() || a == b;
    same(&rule.project_id, &event.project_id)
        && same(&rule.environment, &event.environment)
        && same(&rule.environment_id, &event.environment_id)
        && same(&rule.service_id, &event.service_id)
}

impl AlertEvaluator {
    pub fn new(deps: Deps, source: Arc<dyn AlertSource>) -> Arc<Self> {
        Self::with_retry_delays(
            deps,
            source,
            vec![
                Duration::from_secs(10),
                Duration::from_secs(60),
                Duration::from_secs(300),
            ],
        )
    }

    pub fn with_retry_delays(
        deps: Deps,
        source: Arc<dyn AlertSource>,
        retry_delays: Vec<Duration>,
    ) -> Arc<Self> {
        let (live, _) = broadcast::channel(256);
        Arc::new_cyclic(|me| Self {
            deps,
            source,
            state: Mutex::new(State::default()),
            tasks: Mutex::new(Vec::new()),
            live,
            retry_delays,
            me: me.clone(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now(&self) -> i64 {
        self.deps.clock.now()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AlertEvent> {
        self.live.subscribe()
    }

    fn reload(&self) {
        match self.deps.store.admitted_actions(ALERT_KINDS) {
            Ok(actions) => {
                let (rules, channels) = load(&actions);
                let mut state = self.state();
                state.rules = rules;
                state.channels = channels;
            }
            Err(err) => warn!(error = %err, "alert definitions unreadable; keeping the last set"),
        }
    }

    /// The applied rules with their live state.
    pub fn rules(&self) -> Vec<AlertRule> {
        self.reload();
        let now = self.now();
        let state = self.state();
        state
            .rules
            .values()
            .map(|def| {
                let mut rule = def.rule.clone();
                let runtime = state.runtime.get(&rule.id).cloned().unwrap_or_default();
                rule.silenced_until = def.silenced_until.map(pts);
                rule.state = if def.silenced_until.is_some_and(|until| until > now) {
                    AlertState::Muted as i32
                } else if runtime.state == 0 {
                    AlertState::Ok as i32
                } else {
                    runtime.state
                };
                rule.state_since = (runtime.since > 0).then(|| pts(runtime.since));
                rule.last_evaluated_at =
                    (runtime.last_evaluated > 0).then(|| pts(runtime.last_evaluated));
                rule.last_value = runtime.last_value;
                rule
            })
            .collect()
    }

    pub fn channels(&self) -> Vec<NotificationChannel> {
        self.reload();
        let state = self.state();
        state
            .channels
            .values()
            .map(|channel| NotificationChannel {
                id: channel.id.clone(),
                name: channel.name.clone(),
                kind: match channel.kind.as_str() {
                    "slack" => notification_channel::Kind::Slack,
                    "discord" => notification_channel::Kind::Discord,
                    "webhook" => notification_channel::Kind::Webhook,
                    _ => notification_channel::Kind::Unspecified,
                } as i32,
                target_display: state
                    .target_display
                    .get(&channel.id)
                    .cloned()
                    .unwrap_or_default(),
                credential_ref: String::new(),
                enabled: true,
                last_delivery: state.last_delivery.get(&channel.id).cloned(),
                plan_digest_hex: channel.plan_digest_hex.clone(),
                credential_ciphertext_digest_hex: channel.credential_digest.clone(),
            })
            .collect()
    }

    fn log(&self, level: LogLevel, message: &str) {
        self.deps.logs.write(
            LogSourceType::Agent,
            level,
            message,
            &LogIdentity {
                source: "agent:alerts".to_owned(),
                ..Default::default()
            },
        );
    }

    /// One evaluation of every metric and log rule, plus the built-in
    /// telemetry check and event-rule expiry.
    pub async fn evaluate(self: &Arc<Self>) {
        let now = self.now();
        self.reload();
        self.check_dropping(now);
        let rules: Vec<RuleDef> = self.state().rules.values().cloned().collect();
        for def in rules {
            if !def.rule.enabled {
                continue;
            }
            match &def.rule.condition {
                Some(alert_rule::Condition::Metric(condition)) => {
                    let values = self.source.metric(condition, now).await;
                    self.apply_metric(&def, condition, &values, now);
                }
                Some(alert_rule::Condition::Log(condition)) => {
                    let count = self.source.log_count(condition, now).await;
                    #[allow(clippy::cast_precision_loss)]
                    let value = count as f64;
                    self.step(
                        &def,
                        Some(count > u64::from(condition.count)),
                        value,
                        now,
                        0,
                    );
                }
                Some(alert_rule::Condition::Event(_)) => self.expire_event_rule(&def, now),
                None => {}
            }
            self.repeat_or_release(&def, now);
        }
    }

    fn apply_metric(&self, def: &RuleDef, condition: &MetricCondition, values: &[f64], now: i64) {
        let for_duration = condition.for_duration.map_or(0, |d| d.seconds);
        if condition.op == ComparisonOp::Absent as i32 {
            self.step(def, Some(values.is_empty()), f64::NAN, now, for_duration);
            return;
        }
        if values.is_empty() {
            self.step(def, None, f64::NAN, now, for_duration);
            return;
        }
        let hit = values
            .iter()
            .copied()
            .find(|value| compare(condition.op, *value, condition.threshold));
        let value = hit.unwrap_or(values[0]);
        self.step(def, Some(hit.is_some()), value, now, for_duration);
    }

    /// The state machine for one evaluation (`None` = no data).
    fn step(&self, def: &RuleDef, holds: Option<bool>, value: f64, now: i64, for_duration: i64) {
        let id = def.rule.id.clone();
        let mut state = self.state();
        let runtime = state.runtime.entry(id).or_default();
        runtime.last_evaluated = now;
        runtime.last_value = value;
        let current = AlertState::try_from(runtime.state).unwrap_or(AlertState::Ok);
        let mut fire = false;
        let mut resolve = false;
        match holds {
            None => {
                runtime.no_data_streak += 1;
                if current == AlertState::Firing {
                    runtime.false_streak += 1;
                    resolve = runtime.false_streak >= RESOLVE_AFTER_FALSE;
                } else if runtime.no_data_streak >= NO_DATA_AFTER && current != AlertState::NoData {
                    runtime.state = AlertState::NoData as i32;
                    runtime.since = now;
                    runtime.pending_since = None;
                }
            }
            Some(true) => {
                runtime.no_data_streak = 0;
                runtime.false_streak = 0;
                match current {
                    AlertState::Firing => {}
                    AlertState::Pending => {
                        if now - runtime.pending_since.unwrap_or(now) >= for_duration {
                            fire = true;
                        }
                    }
                    _ if for_duration == 0 => fire = true,
                    _ => {
                        runtime.state = AlertState::Pending as i32;
                        runtime.since = now;
                        runtime.pending_since = Some(now);
                    }
                }
            }
            Some(false) => {
                runtime.no_data_streak = 0;
                match current {
                    AlertState::Firing => {
                        runtime.false_streak += 1;
                        resolve = runtime.false_streak >= RESOLVE_AFTER_FALSE;
                    }
                    AlertState::Pending | AlertState::NoData | AlertState::Resolved => {
                        runtime.state = AlertState::Ok as i32;
                        runtime.since = now;
                        runtime.pending_since = None;
                    }
                    _ => {
                        runtime.state = AlertState::Ok as i32;
                    }
                }
            }
        }
        drop(state);
        if fire {
            self.open_rule_episode(def, value, now, "");
        } else if resolve {
            self.resolve_rule_episode(def, now);
        }
    }

    fn silenced(def: &RuleDef, now: i64) -> bool {
        def.silenced_until.is_some_and(|until| until > now)
    }

    fn summary_of(def: &RuleDef, value: f64, extra: &str) -> String {
        let text = if !extra.is_empty() {
            extra.to_owned()
        } else if value.is_nan() {
            format!("{}: no data", def.rule.name)
        } else {
            format!("{}: value {value}", def.rule.name)
        };
        bounded(
            &crate::local::telemetry::redaction::redact(&text),
            MAX_SUMMARY_BYTES,
        )
    }

    fn open_rule_episode(&self, def: &RuleDef, value: f64, now: i64, summary: &str) {
        let event = AlertEvent {
            id: new_id(now),
            rule_id: def.rule.id.clone(),
            rule_name: def.rule.name.clone(),
            severity: def.rule.severity,
            state: AlertState::Firing as i32,
            summary: Self::summary_of(def, value, summary),
            value,
            started_at: Some(pts(now)),
            source: "rule".to_owned(),
            ..Default::default()
        };
        {
            let mut state = self.state();
            let runtime = state.runtime.entry(def.rule.id.clone()).or_default();
            runtime.state = AlertState::Firing as i32;
            runtime.since = now;
            runtime.pending_since = None;
            runtime.false_streak = 0;
            runtime.episode = Some(event.id.clone());
            runtime.last_occurrence = now;
            runtime.last_notified = now;
            runtime.held = Self::silenced(def, now);
        }
        self.store_event(&event);
        self.log(LogLevel::Warn, &format!("alert firing: {}", event.summary));
        if !Self::silenced(def, now) {
            self.notify(event, def.rule.channel_ids.clone());
        }
    }

    fn resolve_rule_episode(&self, def: &RuleDef, now: i64) {
        let episode = {
            let mut state = self.state();
            let runtime = state.runtime.entry(def.rule.id.clone()).or_default();
            runtime.state = AlertState::Resolved as i32;
            runtime.since = now;
            runtime.false_streak = 0;
            runtime.held = false;
            runtime.episode.take()
        };
        let Some(mut event) = episode.and_then(|id| self.load_event(&id)) else {
            return;
        };
        event.state = AlertState::Resolved as i32;
        event.resolved_at = Some(pts(now));
        self.store_event(&event);
        self.log(
            LogLevel::Info,
            &format!("alert resolved: {}", event.summary),
        );
        if def.rule.notify_on_resolve && !Self::silenced(def, now) {
            self.notify(event, def.rule.channel_ids.clone());
        }
        // RESOLVED → OK once notified.
        if let Some(runtime) = self.state().runtime.get_mut(&def.rule.id) {
            runtime.state = AlertState::Ok as i32;
        }
    }

    /// Repeats a firing rule's notification every `repeat_interval`, and
    /// sends the held one when a silence ends while it still fires.
    fn repeat_or_release(&self, def: &RuleDef, now: i64) {
        let repeat = def
            .rule
            .repeat_interval
            .map_or(alert_spec::DEFAULT_REPEAT_SECONDS, |d| d.seconds);
        let due = {
            let mut state = self.state();
            let Some(runtime) = state.runtime.get_mut(&def.rule.id) else {
                return;
            };
            if runtime.state != AlertState::Firing as i32 || Self::silenced(def, now) {
                return;
            }
            let due = runtime.held || now - runtime.last_notified >= repeat;
            if due {
                runtime.held = false;
                runtime.last_notified = now;
            }
            due.then(|| runtime.episode.clone()).flatten()
        };
        if let Some(event) = due.and_then(|id| self.load_event(&id)) {
            self.notify(event, def.rule.channel_ids.clone());
        }
    }

    fn expire_event_rule(&self, def: &RuleDef, now: i64) {
        let expired = self.state().runtime.get(&def.rule.id).is_some_and(|r| {
            r.state == AlertState::Firing as i32 && now - r.last_occurrence >= EVENT_RESOLVE_SECONDS
        });
        if expired {
            self.resolve_rule_episode(def, now);
        }
    }

    /// Built-in `TELEMETRY_DROPPING` (section 10.3).
    fn check_dropping(&self, now: i64) {
        let total = self.source.dropped_total();
        let (occurred, cleared) = {
            let mut state = self.state();
            let previous = state.dropped.replace(total);
            let increased = previous.is_some_and(|p| total > p);
            if increased {
                state.last_drop_seen = now;
            }
            let occurred = increased && state.dropping_since.is_none();
            if occurred {
                state.dropping_since = Some(now);
            }
            let cleared = !increased
                && state.dropping_since.is_some()
                && now - state.last_drop_seen >= DROPPING_CLEAR_SECONDS;
            if cleared {
                state.dropping_since = None;
            }
            (occurred, cleared)
        };
        if occurred || cleared {
            self.builtin(BuiltinEvent {
                kind: event_condition::Kind::TelemetryDropping,
                scope: Scope::default(),
                source: "telemetry",
                subject_id: String::new(),
                occurred,
                standalone: false,
                channel_ids: Vec::new(),
                summary: if occurred {
                    "the telemetry store is dropping records".to_owned()
                } else {
                    "the telemetry store stopped dropping records".to_owned()
                },
            });
        }
    }

    fn store_event(&self, event: &AlertEvent) {
        let at = event.started_at.map_or_else(|| self.now(), |t| t.seconds);
        let subject = if event.rule_id.is_empty() {
            &event.subject_id
        } else {
            &event.rule_id
        };
        match self.deps.ops.put(
            RecordKind::AlertEvent,
            &event.id,
            subject,
            &event.source,
            event.severity,
            at,
            event,
        ) {
            Ok(seq) => {
                let mut published = event.clone();
                published.cursor = seq.to_string();
                self.deps.events.publish(
                    EventKind::Alert,
                    Scope::default(),
                    event::Payload::Alert(published.clone()),
                );
                let _ = self.live.send(published);
            }
            Err(err) => warn!(error = %err, "alert event not recorded"),
        }
    }

    fn load_event(&self, id: &str) -> Option<AlertEvent> {
        self.deps
            .ops
            .get(RecordKind::AlertEvent, id)
            .and_then(|row| row.decode())
    }

    /// Sends one notification of `event` to each recorded channel.
    fn notify(&self, event: AlertEvent, channel_ids: Vec<String>) {
        let now = self.now();
        let channels: Vec<ChannelDef> = {
            let state = self.state();
            let mut seen = std::collections::BTreeSet::new();
            channel_ids
                .iter()
                .filter(|id| seen.insert((*id).clone()))
                .filter_map(|id| state.channels.get(id).cloned())
                .collect()
        };
        for channel in channels {
            let Some(coalesced) = self.admit_send(&channel.id, now) else {
                continue;
            };
            let mut text = self.text_of(&event);
            if coalesced > 0 {
                text = bounded(
                    &format!("{text} (+{coalesced} more alerts)"),
                    MAX_TEXT_BYTES,
                );
            }
            let notification = Notification {
                channel_id: channel.id.clone(),
                text,
                event_id: event.id.clone(),
                payload_json: (channel.kind == "webhook")
                    .then(|| self.webhook_body(&event).to_string()),
            };
            let this = self.self_arc();
            let event_id = event.id.clone();
            let task = tokio::spawn(async move {
                if let Some(this) = this {
                    let result = this.deliver(&notification).await;
                    this.record_delivery(&event_id, result);
                }
            });
            self.tasks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(task);
        }
    }

    /// Section 10.3: at most 30 sends per channel per minute; the rest are
    /// counted and mentioned in the next one. Returns the coalesced count,
    /// or `None` when this send is coalesced.
    fn admit_send(&self, channel_id: &str, now: i64) -> Option<u32> {
        let mut state = self.state();
        let sends = state.sends.entry(channel_id.to_owned()).or_default();
        while sends.front().is_some_and(|at| now - at >= 60) {
            sends.pop_front();
        }
        if sends.len() >= PER_CHANNEL_PER_MINUTE {
            *state.coalesced.entry(channel_id.to_owned()).or_default() += 1;
            return None;
        }
        sends.push_back(now);
        Some(state.coalesced.remove(channel_id).unwrap_or(0))
    }

    fn text_of(&self, event: &AlertEvent) -> String {
        let state = if event.state == AlertState::Resolved as i32 {
            "RESOLVED".to_owned()
        } else {
            severity_word(event.severity).to_owned()
        };
        let name = if event.rule_name.is_empty() {
            event.source.as_str()
        } else {
            event.rule_name.as_str()
        };
        let mut text = format!("[{state}] {name}: {}", event.summary);
        if !event.value.is_nan() && event.value != 0.0 {
            text.push_str(&format!(" (value {})", event.value));
        }
        let server_id = self.deps.server_id.get();
        if !server_id.is_empty() {
            text.push_str(&format!(" on server {server_id}"));
        }
        bounded(&text, MAX_TEXT_BYTES)
    }

    /// The `webhook` body (section 10.3) with the event's fields.
    fn webhook_body(&self, event: &AlertEvent) -> Value {
        let state = AlertState::try_from(event.state).unwrap_or(AlertState::Unspecified);
        let severity =
            AlertSeverity::try_from(event.severity).unwrap_or(AlertSeverity::Unspecified);
        json!({
            "version": 1,
            "type": "alert",
            "server_id": self.deps.server_id.get(),
            "event": {
                "id": event.id,
                "ruleId": event.rule_id,
                "ruleName": event.rule_name,
                "severity": severity.as_str_name(),
                "state": state.as_str_name(),
                "summary": event.summary,
                "value": if event.value.is_finite() { json!(event.value) } else { json!("NaN") },
                "startedAt": event.started_at.map(|t| rfc(t.seconds)),
                "resolvedAt": event.resolved_at.map(|t| rfc(t.seconds)),
                "source": event.source,
                "subjectId": event.subject_id,
            }
        })
    }

    fn self_arc(&self) -> Option<Arc<Self>> {
        self.me.upgrade()
    }

    /// `notify_channel` with the section 10.3 retries.
    async fn deliver(&self, notification: &Notification) -> DeliveryResult {
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let answer = runner::notify_channel(self.deps.runner.as_ref(), notification).await;
            let (ok, status, error, retryable) = match &answer {
                Ok(sent) => {
                    if !sent.target_display.is_empty() {
                        self.state()
                            .target_display
                            .insert(notification.channel_id.clone(), sent.target_display.clone());
                    }
                    let retryable = !sent.delivered
                        && (sent.status_code == 0
                            || sent.status_code == 408
                            || sent.status_code == 429
                            || sent.status_code >= 500);
                    (
                        sent.delivered,
                        sent.status_code,
                        sent.error.clone(),
                        retryable,
                    )
                }
                Err(failure) => (
                    false,
                    0,
                    format!("{}: {}", failure.code, failure.message),
                    failure.code == "E_INTERNAL",
                ),
            };
            let result = DeliveryResult {
                channel_id: notification.channel_id.clone(),
                ok,
                http_status: status,
                error: bounded(&error, 256),
                attempted_at: Some(pts(self.now())),
                attempts,
            };
            let delay = self.retry_delays.get(attempts as usize - 1).copied();
            match delay {
                Some(delay) if retryable => tokio::time::sleep(delay).await,
                _ => return result,
            }
        }
    }

    fn record_delivery(&self, event_id: &str, result: DeliveryResult) {
        self.state()
            .last_delivery
            .insert(result.channel_id.clone(), result.clone());
        if !result.ok {
            self.log(
                LogLevel::Warn,
                &format!(
                    "alert notification to channel {} failed after {} attempt(s): {}",
                    result.channel_id, result.attempts, result.error
                ),
            );
        }
        if let Some(mut event) = self.load_event(event_id) {
            event.deliveries.push(result);
            let at = event.started_at.map_or(0, |t| t.seconds);
            let subject = if event.rule_id.is_empty() {
                event.subject_id.clone()
            } else {
                event.rule_id.clone()
            };
            let _ = self.deps.ops.put(
                RecordKind::AlertEvent,
                &event.id,
                &subject,
                &event.source,
                event.severity,
                at,
                &event,
            );
        }
    }

    /// `TestNotificationChannel` (contracts v1.1.2: one per channel per
    /// 10 s). Sends a fixed text; `Err` is `(not found, rate limited)`.
    pub async fn test_channel(&self, channel_id: &str) -> Result<DeliveryResult, TestRefusal> {
        self.reload();
        let now = self.now();
        {
            let mut state = self.state();
            if !state.channels.contains_key(channel_id) {
                return Err(TestRefusal::NotFound);
            }
            if state
                .last_test
                .get(channel_id)
                .is_some_and(|at| now - at < TEST_INTERVAL_SECONDS)
            {
                return Err(TestRefusal::RateLimited);
            }
            state.last_test.insert(channel_id.to_owned(), now);
        }
        let notification = Notification {
            channel_id: channel_id.to_owned(),
            text: "Permanu test notification: this channel works.".to_owned(),
            event_id: new_id(now),
            payload_json: None,
        };
        let answer = runner::notify_channel(self.deps.runner.as_ref(), &notification).await;
        let result = match answer {
            Ok(sent) => {
                if !sent.target_display.is_empty() {
                    self.state()
                        .target_display
                        .insert(channel_id.to_owned(), sent.target_display);
                }
                DeliveryResult {
                    channel_id: channel_id.to_owned(),
                    ok: sent.delivered,
                    http_status: sent.status_code,
                    error: bounded(&sent.error, 256),
                    attempted_at: Some(pts(now)),
                    attempts: 1,
                }
            }
            Err(failure) => DeliveryResult {
                channel_id: channel_id.to_owned(),
                ok: false,
                error: bounded(&format!("{}: {}", failure.code, failure.message), 256),
                attempted_at: Some(pts(now)),
                attempts: 1,
                ..Default::default()
            },
        };
        self.state()
            .last_delivery
            .insert(channel_id.to_owned(), result.clone());
        Ok(result)
    }

    /// Stored alert events, oldest first after `after` (a cursor).
    pub fn history(&self, after: Option<i64>, limit: usize) -> Vec<AlertEvent> {
        self.deps
            .ops
            .list(
                RecordKind::AlertEvent,
                &Listing {
                    after,
                    ascending: true,
                    limit,
                    ..Default::default()
                },
            )
            .into_iter()
            .filter_map(|row| {
                let mut event: AlertEvent = row.decode()?;
                event.cursor = row.seq.to_string();
                Some(event)
            })
            .collect()
    }

    #[cfg(test)]
    pub async fn settle(&self) {
        loop {
            let tasks: Vec<JoinHandle<()>> =
                std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|p| p.into_inner()));
            if tasks.is_empty() {
                return;
            }
            for task in tasks {
                let _ = task.await;
            }
        }
    }

    /// contracts v1.1.5 (D-063 #2): `KIND_DEPLOY_FAILED` from the deploy
    /// events: a deploy that ended `FAILED` or `ROLLED_BACK` occurs, a deploy
    /// of the service that went `LIVE` resolves it (`CANCELLED` is neither).
    pub fn spawn_deploy_watch(self: &Arc<Self>) -> JoinHandle<()> {
        let this = self.clone();
        let mut live = self.deps.events.live();
        tokio::spawn(async move {
            loop {
                match live.recv().await {
                    Ok(event) => this.deploy_event(&event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        })
    }

    fn deploy_event(&self, event: &crate::proto::agent::v2::Event) {
        use crate::proto::agent::v2::deploy_status_event::Phase;
        let Some(event::Payload::Deploy(deploy)) = &event.payload else {
            return;
        };
        let occurred = match Phase::try_from(deploy.phase) {
            Ok(Phase::Failed | Phase::RolledBack) => true,
            Ok(Phase::Live) => false,
            _ => return,
        };
        let scope = event.scope.clone().unwrap_or_default();
        self.builtin(BuiltinEvent {
            kind: event_condition::Kind::DeployFailed,
            scope,
            source: "deploy",
            subject_id: deploy.service_id.clone(),
            occurred,
            standalone: false,
            channel_ids: Vec::new(),
            summary: if occurred {
                format!("deploy failed: {}", deploy.message)
            } else {
                "deploy live".to_owned()
            },
        });
    }

    /// Evaluates at :00 and :30 of every minute until aborted.
    pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let now = this.now();
                let next = (now / EVAL_SECONDS + 1) * EVAL_SECONDS;
                tokio::time::sleep(Duration::from_secs(u64::try_from(next - now).unwrap_or(1)))
                    .await;
                this.evaluate().await;
                this.tasks
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .retain(|task| !task.is_finished());
            }
        })
    }
}

/// Why a `TestNotificationChannel` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestRefusal {
    NotFound,
    RateLimited,
}

impl AlertSink for AlertEvaluator {
    /// Built-in events (section 10.1 heartbeat, 10.2 backups, 10.3 event
    /// rules).
    fn builtin(&self, event: BuiltinEvent) {
        let now = self.now();
        self.reload();
        let matching: Vec<RuleDef> = self
            .state()
            .rules
            .values()
            .filter(|def| def.rule.enabled)
            .filter(|def| match &def.rule.condition {
                Some(alert_rule::Condition::Event(condition)) => {
                    condition.kind == event.kind as i32
                        && scope_matches(condition.scope.as_ref(), &event.scope)
                }
                _ => false,
            })
            .cloned()
            .collect();
        let summary = bounded(
            &crate::local::telemetry::redaction::redact(&event.summary),
            MAX_SUMMARY_BYTES,
        );
        if event.standalone {
            self.standalone(&event, &matching, &summary, now);
        } else {
            for def in &matching {
                let firing = self
                    .state()
                    .runtime
                    .get(&def.rule.id)
                    .is_some_and(|r| r.state == AlertState::Firing as i32);
                if event.occurred {
                    if firing {
                        if let Some(r) = self.state().runtime.get_mut(&def.rule.id) {
                            r.last_occurrence = now;
                        }
                    } else {
                        self.open_rule_episode(def, f64::NAN, now, &summary);
                    }
                } else if firing {
                    self.resolve_rule_episode(def, now);
                }
            }
        }
    }
}

impl AlertEvaluator {
    /// A heartbeat (or policy) alert of its own: one `AlertEvent` per
    /// episode, sent to the channels of every matching rule and the
    /// subject's own channels; with none it reaches the Inbox only.
    fn standalone(&self, event: &BuiltinEvent, matching: &[RuleDef], summary: &str, now: i64) {
        let key = (
            event.source.to_owned(),
            event.subject_id.clone(),
            event.kind as i32,
        );
        let mut channels: Vec<String> = event.channel_ids.clone();
        for def in matching {
            if !Self::silenced(def, now) {
                channels.extend(def.rule.channel_ids.iter().cloned());
            }
        }
        if event.occurred {
            if self.state().builtin.contains_key(&key) {
                return;
            }
            let alert = AlertEvent {
                id: new_id(now),
                severity: AlertSeverity::Warning as i32,
                state: AlertState::Firing as i32,
                summary: summary.to_owned(),
                labels: [
                    ("project_id".to_owned(), event.scope.project_id.clone()),
                    ("environment".to_owned(), event.scope.environment.clone()),
                    ("service_id".to_owned(), event.scope.service_id.clone()),
                ]
                .into_iter()
                .filter(|(_, v)| !v.is_empty())
                .collect(),
                value: f64::NAN,
                started_at: Some(pts(now)),
                source: event.source.to_owned(),
                subject_id: event.subject_id.clone(),
                ..Default::default()
            };
            self.state().builtin.insert(key, alert.id.clone());
            self.store_event(&alert);
            self.notify(alert, channels);
        } else {
            let open = self.state().builtin.remove(&key);
            // A counterpart resolves every kind of the subject's episodes.
            let open = open.or_else(|| {
                let mut state = self.state();
                let other = state
                    .builtin
                    .keys()
                    .find(|(s, subject, _)| s == event.source && *subject == event.subject_id)
                    .cloned();
                other.and_then(|k| state.builtin.remove(&k))
            });
            if let Some(mut alert) = open.and_then(|id| self.load_event(&id)) {
                alert.state = AlertState::Resolved as i32;
                alert.resolved_at = Some(pts(now));
                self.store_event(&alert);
                self.notify(alert, channels);
            }
        }
    }
}

#[cfg(test)]
mod tests;
