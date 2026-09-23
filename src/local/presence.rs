//! Engine presence ("Mac online") and the away summary (agent-protocol.md
//! 12.1, 12.2).
//!
//! - An engine session is a connection whose `Hello` had `client_name =
//!   "permanu-engine"` and a non-empty `engine_id`. The engine is online
//!   while at least one session has a `Subscribe` stream open or made an
//!   RPC in the last 90 s; it goes offline when the last such session
//!   closes or has been silent for 90 s.
//! - Presence never changes what the server does; it only frames the away
//!   summary and tells the app whether the server sees its Mac.
//! - `AwaySummary` counts, for the most recent offline period, what the
//!   server did. While offline the counters grow and `until` is unset; at
//!   the first session `until` is set and the summary is frozen until the
//!   next offline period. All zero and unset before the first session.

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tonic::transport::server::{Connected, UdsConnectInfo};

use super::execution::Clock;
use crate::proto::agent::v2::{
    event, AlertState, AwaySummary, BackupRunStatus, CronRunStatus, EventKind, OperationState,
    RestoreVerificationStatus,
};

/// agent-protocol.md 12.1.
pub const SILENCE_SECONDS: i64 = 90;
pub const ENGINE_CLIENT_NAME: &str = "permanu-engine";
/// Operation ids remembered per offline period (to count each once).
const MAX_TRACKED_OPERATIONS: usize = 10_000;

/// What happened on the server, as the away summary counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwayEvent {
    /// An operation finished (`OPERATION` event), with its id and state.
    Operation {
        id: String,
        failed: bool,
    },
    RuleDeploy,
    ServerBuildFailed,
    WebhookDelivery,
    AlertFired,
    CronRunFailed,
    CronRunMissed,
    BackupFailed,
    VerificationFailed,
}

#[derive(Debug, Default)]
struct Session {
    engine_id: String,
    last_rpc: i64,
    subscribes: u32,
}

#[derive(Debug, Default)]
struct State {
    /// Connections that sent an engine `Hello`, by connection id.
    sessions: HashMap<u64, Session>,
    online: bool,
    last_seen: Option<i64>,
    engine_id: String,
    since: Option<i64>,
    until: Option<i64>,
    counts: AwaySummary,
    operations: HashSet<String>,
}

impl State {
    fn live(&self, now: i64) -> bool {
        self.sessions
            .values()
            .any(|s| s.subscribes > 0 || now - s.last_rpc < SILENCE_SECONDS)
    }

    fn offline_period(&self) -> bool {
        !self.online && self.since.is_some() && self.until.is_none()
    }
}

/// The presence tracker; `changed` fires when `engine_online` flips.
pub struct Presence {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    pub changed: tokio::sync::Notify,
}

impl std::fmt::Debug for Presence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presence").finish()
    }
}

/// The presence fields of `AgentStatus`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PresenceView {
    pub engine_online: bool,
    pub engine_last_seen_at: Option<i64>,
    pub engine_id: String,
    pub away: AwaySummary,
}

impl Presence {
    pub fn new(clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            clock,
            changed: tokio::sync::Notify::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    /// Re-evaluates presence after a change; returns whether it flipped.
    fn settle(&self, state: &mut State, now: i64) -> bool {
        let live = state.live(now);
        if live {
            state.last_seen = Some(now);
        }
        if live == state.online {
            return false;
        }
        state.online = live;
        if live {
            // A session started: freeze the summary of the offline period.
            if state.since.is_some() {
                state.until = Some(now);
            }
        } else {
            // A new offline period: fresh counters.
            state.since = Some(now);
            state.until = None;
            state.counts = AwaySummary::default();
            state.operations.clear();
        }
        true
    }

    fn after(&self, mut state: MutexGuard<'_, State>, now: i64) {
        let flipped = self.settle(&mut state, now);
        drop(state);
        if flipped {
            self.changed.notify_waiters();
        }
    }

    /// An engine `Hello` on connection `conn`. Other clients (tests, CLI
    /// probes) never count.
    pub fn hello(&self, conn: u64, client_name: &str, engine_id: &str) {
        if client_name != ENGINE_CLIENT_NAME || engine_id.is_empty() || engine_id.len() > 64 {
            return;
        }
        let now = self.now();
        let mut state = self.lock();
        let session = state.sessions.entry(conn).or_default();
        session.engine_id = engine_id.to_owned();
        session.last_rpc = now;
        state.engine_id = engine_id.to_owned();
        self.after(state, now);
    }

    /// Any RPC on connection `conn`.
    pub fn touch(&self, conn: u64) {
        let now = self.now();
        let mut state = self.lock();
        let Some(session) = state.sessions.get_mut(&conn) else {
            return;
        };
        session.last_rpc = now;
        self.after(state, now);
    }

    /// A `Subscribe` stream opened on `conn`; the guard closes it.
    pub fn subscribe_opened(self: &Arc<Self>, conn: u64) -> SubscribeGuard {
        let now = self.now();
        let mut state = self.lock();
        if let Some(session) = state.sessions.get_mut(&conn) {
            session.subscribes += 1;
            session.last_rpc = now;
        }
        self.after(state, now);
        SubscribeGuard {
            presence: self.clone(),
            conn,
        }
    }

    fn subscribe_closed(&self, conn: u64) {
        let now = self.now();
        let mut state = self.lock();
        if let Some(session) = state.sessions.get_mut(&conn) {
            session.subscribes = session.subscribes.saturating_sub(1);
            session.last_rpc = now;
        }
        self.after(state, now);
    }

    /// The connection closed.
    pub fn closed(&self, conn: u64) {
        let now = self.now();
        let mut state = self.lock();
        if state.sessions.remove(&conn).is_none() {
            return;
        }
        self.after(state, now);
    }

    /// Periodic check: a session silent for 90 s no longer counts.
    pub fn tick(&self) {
        let now = self.now();
        let state = self.lock();
        self.after(state, now);
    }

    /// Counts `event` when it happens during an offline period.
    pub fn record(&self, event: AwayEvent) {
        let mut state = self.lock();
        if !state.offline_period() {
            return;
        }
        let state = &mut *state;
        let counts = &mut state.counts;
        match event {
            AwayEvent::Operation { id, failed } => {
                if state.operations.len() >= MAX_TRACKED_OPERATIONS || !state.operations.insert(id)
                {
                    return;
                }
                counts.operations += 1;
                if failed {
                    counts.operations_failed += 1;
                }
            }
            AwayEvent::RuleDeploy => counts.rule_deploys += 1,
            AwayEvent::ServerBuildFailed => counts.server_builds_failed += 1,
            AwayEvent::WebhookDelivery => counts.webhook_deliveries += 1,
            AwayEvent::AlertFired => counts.alerts_fired += 1,
            AwayEvent::CronRunFailed => counts.cron_runs_failed += 1,
            AwayEvent::CronRunMissed => counts.cron_runs_missed += 1,
            AwayEvent::BackupFailed => counts.backups_failed += 1,
            AwayEvent::VerificationFailed => counts.verifications_failed += 1,
        }
    }

    pub fn view(&self) -> PresenceView {
        let now = self.now();
        let mut state = self.lock();
        let flipped = self.settle(&mut state, now);
        let mut away = state.counts;
        away.since = state.since.map(super::sched::pts);
        away.until = state.until.map(super::sched::pts);
        let view = PresenceView {
            engine_online: state.online,
            engine_last_seen_at: state.last_seen,
            engine_id: state.engine_id.clone(),
            away,
        };
        drop(state);
        if flipped {
            self.changed.notify_waiters();
        }
        view
    }

    /// Feeds the away counters from the agent's own events (operations,
    /// alerts, cron and backup runs, verifications).
    pub fn observe(&self, event: &crate::proto::agent::v2::Event) {
        let Some(payload) = &event.payload else {
            return;
        };
        let kind = EventKind::try_from(event.kind).unwrap_or(EventKind::Unspecified);
        let away = match (kind, payload) {
            (EventKind::Operation, event::Payload::Operation(op)) => {
                let state = OperationState::try_from(op.state).unwrap_or_default();
                if !matches!(
                    state,
                    OperationState::Succeeded
                        | OperationState::Failed
                        | OperationState::Cancelled
                        | OperationState::RolledBack
                ) {
                    return;
                }
                AwayEvent::Operation {
                    id: op.id.clone(),
                    failed: matches!(state, OperationState::Failed | OperationState::RolledBack),
                }
            }
            (EventKind::Alert, event::Payload::Alert(alert))
                if alert.state == AlertState::Firing as i32 =>
            {
                AwayEvent::AlertFired
            }
            (EventKind::CronRun, event::Payload::CronRun(run)) => {
                match CronRunStatus::try_from(run.status).unwrap_or_default() {
                    CronRunStatus::Failed | CronRunStatus::TimedOut => AwayEvent::CronRunFailed,
                    CronRunStatus::Missed => AwayEvent::CronRunMissed,
                    _ => return,
                }
            }
            (EventKind::BackupRun, event::Payload::BackupRun(run))
                if run.status == BackupRunStatus::Failed as i32 =>
            {
                AwayEvent::BackupFailed
            }
            (EventKind::RestoreVerification, event::Payload::RestoreVerification(v))
                if v.status == RestoreVerificationStatus::Failed as i32 =>
            {
                AwayEvent::VerificationFailed
            }
            _ => return,
        };
        self.record(away);
    }
}

/// Closes a `Subscribe` stream's presence when dropped.
pub struct SubscribeGuard {
    presence: Arc<Presence>,
    conn: u64,
}

impl Drop for SubscribeGuard {
    fn drop(&mut self) {
        self.presence.subscribe_closed(self.conn);
    }
}

/// Connection identity for presence: a per-connection id plus the peer
/// credentials (the request extension handlers read).
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: u64,
    pub uds: UdsConnectInfo,
}

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

/// A v2 connection that tells presence when it closes.
pub struct TrackedStream {
    inner: UnixStream,
    info: ConnectionInfo,
    presence: Option<Arc<Presence>>,
}

impl TrackedStream {
    pub fn new(inner: UnixStream, presence: Option<Arc<Presence>>) -> Self {
        let uds = inner.connect_info();
        Self {
            inner,
            info: ConnectionInfo {
                id: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
                uds,
            },
            presence,
        }
    }
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        if let Some(presence) = &self.presence {
            presence.closed(self.info.id);
        }
    }
}

impl Connected for TrackedStream {
    type ConnectInfo = ConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Counts every RPC on an engine connection as activity (12.1).
#[derive(Clone)]
pub struct PresenceLayer(pub Arc<Presence>);

impl<S> tower::Layer<S> for PresenceLayer {
    type Service = PresenceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PresenceService {
            inner,
            presence: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct PresenceService<S> {
    inner: S,
    presence: Arc<Presence>,
}

impl<S, B> tower::Service<tonic::codegen::http::Request<B>> for PresenceService<S>
where
    S: tower::Service<tonic::codegen::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: tonic::codegen::http::Request<B>) -> Self::Future {
        if let Some(info) = request.extensions().get::<ConnectionInfo>() {
            self.presence.touch(info.id);
        }
        self.inner.call(request)
    }
}

/// The connection id of a request, when it came through [`TrackedStream`].
pub fn connection_of<T>(request: &tonic::Request<T>) -> Option<u64> {
    request
        .extensions()
        .get::<ConnectionInfo>()
        .map(|info| info.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::test_harness::FixedClock;
    use std::sync::atomic::AtomicI64;

    fn presence() -> (Arc<FixedClock>, Arc<Presence>) {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        (clock.clone(), Presence::new(clock))
    }

    #[test]
    fn only_engine_hellos_count_and_silence_ends_the_session() {
        let (clock, p) = presence();
        p.hello(1, "permanu-cli", "e-1");
        p.hello(2, ENGINE_CLIENT_NAME, "");
        assert!(!p.view().engine_online);
        // Before the first session there is no away period.
        p.record(AwayEvent::RuleDeploy);
        assert_eq!(p.view().away, AwaySummary::default());

        p.hello(3, ENGINE_CLIENT_NAME, "e-1");
        let view = p.view();
        assert!(view.engine_online);
        assert_eq!(view.engine_id, "e-1");
        assert_eq!(view.engine_last_seen_at, Some(1_000));
        // An RPC keeps it alive; 90 s of silence ends it.
        clock.0.store(1_080, Ordering::SeqCst);
        p.touch(3);
        clock.0.store(1_169, Ordering::SeqCst);
        assert!(p.view().engine_online);
        clock.0.store(1_170, Ordering::SeqCst);
        let offline = p.view();
        assert!(!offline.engine_online);
        assert_eq!(offline.engine_last_seen_at, Some(1_169));
        assert_eq!(offline.away.since.unwrap().seconds, 1_170);
        assert!(offline.away.until.is_none());
    }

    #[test]
    fn an_open_subscribe_keeps_the_engine_online() {
        let (clock, p) = presence();
        p.hello(7, ENGINE_CLIENT_NAME, "e-1");
        let guard = p.subscribe_opened(7);
        clock.0.store(5_000, Ordering::SeqCst);
        assert!(p.view().engine_online);
        drop(guard);
        clock.0.store(5_089, Ordering::SeqCst);
        assert!(p.view().engine_online);
        p.closed(7);
        assert!(!p.view().engine_online);
    }

    #[test]
    fn the_away_summary_grows_offline_and_freezes_at_the_next_session() {
        let (clock, p) = presence();
        p.hello(1, ENGINE_CLIENT_NAME, "e-1");
        p.closed(1);
        clock.0.store(2_000, Ordering::SeqCst);
        p.record(AwayEvent::RuleDeploy);
        p.record(AwayEvent::WebhookDelivery);
        p.record(AwayEvent::ServerBuildFailed);
        p.record(AwayEvent::Operation {
            id: "op-1".to_owned(),
            failed: true,
        });
        // The same operation counts once.
        p.record(AwayEvent::Operation {
            id: "op-1".to_owned(),
            failed: true,
        });
        let away = p.view().away;
        assert_eq!(away.since.unwrap().seconds, 1_000);
        assert!(away.until.is_none());
        assert_eq!(
            (
                away.rule_deploys,
                away.webhook_deliveries,
                away.server_builds_failed
            ),
            (1, 1, 1)
        );
        assert_eq!((away.operations, away.operations_failed), (1, 1));

        clock.0.store(3_000, Ordering::SeqCst);
        p.hello(2, ENGINE_CLIENT_NAME, "e-1");
        p.record(AwayEvent::RuleDeploy);
        let frozen = p.view().away;
        assert_eq!(frozen.until.unwrap().seconds, 3_000);
        assert_eq!(frozen.rule_deploys, 1);
        // Every connection of that engine sees the same values.
        p.hello(3, ENGINE_CLIENT_NAME, "e-1");
        assert_eq!(p.view().away, frozen);

        // The next offline period starts from zero.
        p.closed(2);
        p.closed(3);
        let fresh = p.view().away;
        assert_eq!(fresh.rule_deploys, 0);
        assert_eq!(fresh.since.unwrap().seconds, 3_000);
    }

    #[tokio::test]
    async fn a_flip_notifies_the_status_publisher() {
        let (_, p) = presence();
        let notified = p.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        p.hello(1, ENGINE_CLIENT_NAME, "e-1");
        tokio::time::timeout(std::time::Duration::from_secs(1), notified)
            .await
            .unwrap();
    }
}
