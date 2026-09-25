//! `EventService.Subscribe`: an in-memory, agent-wide event log with resume
//! tokens (agent-protocol.md section 6). This slice publishes
//! `DeployStatusEvent`, `Operation` and `TrustChangedEvent`.
//!
//! Tokens are `<boot id>.<seq>`; a token from another boot or older than the
//! retained window yields `RESYNC_REQUIRED{resume_gap}` and then live events.
//! A subscriber that falls behind gets `RESYNC_REQUIRED{overflow}`.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use futures::Stream;
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

use super::facts::timestamp;
use crate::proto::agent::v2::{
    event, event_service_server::EventService, Event, EventKind, Keepalive, ResyncRequired, Scope,
    SubscribeRequest,
};

const RETAINED_EVENTS: usize = 10_000;
const LIVE_BUFFER: usize = 4_096;
const KEEPALIVE: Duration = Duration::from_secs(15);

struct Ring {
    events: VecDeque<Event>,
    next_seq: u64,
}

/// Agent-wide event log.
#[derive(Clone)]
pub struct EventBus {
    ring: Arc<Mutex<Ring>>,
    live: broadcast::Sender<Event>,
    boot: String,
    /// Set at shutdown so open streams end and the server can drain.
    closed: tokio::sync::watch::Sender<bool>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let mut boot = [0u8; 6];
        let _ = getrandom::getrandom(&mut boot);
        Self {
            ring: Arc::new(Mutex::new(Ring {
                events: VecDeque::new(),
                next_seq: 1,
            })),
            live: broadcast::channel(LIVE_BUFFER).0,
            boot: hex::encode(boot),
            closed: tokio::sync::watch::channel(false).0,
        }
    }

    /// Ends every open stream (server shutdown).
    pub fn close(&self) {
        self.closed.send_replace(true);
    }

    /// Resolves once `close` was called.
    pub fn closed(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut receiver = self.closed.subscribe();
        async move {
            let _ = receiver.wait_for(|closed| *closed).await;
        }
    }

    /// Every event published from now on (the away summary's feed).
    pub fn live(&self) -> broadcast::Receiver<Event> {
        self.live.subscribe()
    }

    /// The token of the newest event: `Subscribe` from it delivers every
    /// event published after this call (`GetStateSnapshot`).
    pub fn resume_token(&self) -> String {
        let ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
        format!("{}.{}", self.boot, ring.next_seq - 1)
    }

    pub fn publish(&self, kind: EventKind, scope: Scope, payload: event::Payload) {
        let mut ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
        let seq = ring.next_seq;
        ring.next_seq += 1;
        let event = Event {
            resume_token: format!("{}.{seq}", self.boot),
            seq,
            timestamp: Some(timestamp(SystemTime::now())),
            kind: kind as i32,
            scope: Some(scope),
            payload: Some(payload),
        };
        if ring.events.len() == RETAINED_EVENTS {
            ring.events.pop_front();
        }
        ring.events.push_back(event.clone());
        // Sent while holding the ring lock so replay and live never overlap.
        let _ = self.live.send(event);
    }

    /// Replay after `token` (None when the token cannot be honoured) plus a
    /// live receiver positioned right after the replay.
    fn replay(&self, token: &str) -> (Option<Vec<Event>>, broadcast::Receiver<Event>) {
        let ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
        let receiver = self.live.subscribe();
        if token.is_empty() {
            return (Some(Vec::new()), receiver);
        }
        let Some(seq) = token
            .strip_prefix(&self.boot)
            .and_then(|rest| rest.strip_prefix('.'))
            .and_then(|seq| seq.parse::<u64>().ok())
        else {
            return (None, receiver);
        };
        let oldest = ring.events.front().map_or(ring.next_seq, |e| e.seq);
        if seq + 1 < oldest || seq >= ring.next_seq {
            return (None, receiver);
        }
        let events = ring
            .events
            .iter()
            .filter(|e| e.seq > seq)
            .cloned()
            .collect();
        (Some(events), receiver)
    }
}

fn matches(request: &SubscribeRequest, event: &Event) -> bool {
    let kind_ok = request.kinds.is_empty() || request.kinds.contains(&event.kind);
    let scope_ok = match (&request.scope, &event.scope) {
        (Some(filter), Some(scope)) => {
            let field = |f: &str, v: &str| f.is_empty() || f == v;
            field(&filter.project_id, &scope.project_id)
                && field(&filter.service_id, &scope.service_id)
                && field(&filter.environment, &scope.environment)
                && field(&filter.deployment_id, &scope.deployment_id)
        }
        _ => true,
    };
    kind_ok && scope_ok
}

fn resync(reason: &str) -> Event {
    Event {
        timestamp: Some(timestamp(SystemTime::now())),
        kind: EventKind::ResyncRequired as i32,
        payload: Some(event::Payload::ResyncRequired(ResyncRequired {
            reason: reason.to_owned(),
            kinds: Vec::new(),
        })),
        ..Default::default()
    }
}

pub struct EventSvc {
    pub bus: EventBus,
    /// An engine's open `Subscribe` keeps it online (agent-protocol.md 12.1).
    pub presence: Option<Arc<super::presence::Presence>>,
}

type EventStream = Pin<Box<dyn Stream<Item = Result<Event, Status>> + Send>>;

#[tonic::async_trait]
impl EventService for EventSvc {
    type SubscribeStream = EventStream;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let guard = match (&self.presence, super::presence::connection_of(&request)) {
            (Some(presence), Some(conn)) => Some(presence.subscribe_opened(conn)),
            _ => None,
        };
        let request = request.into_inner();
        let (replay, mut live) = self.bus.replay(&request.resume_token);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Status>>(256);
        let closed = self.bus.closed();
        tokio::spawn(async move {
            // Held for the stream's life; dropping it ends the subscription.
            let _guard = guard;
            tokio::pin!(closed);
            match replay {
                None => {
                    if tx.send(Ok(resync("resume_gap"))).await.is_err() {
                        return;
                    }
                }
                Some(events) => {
                    for event in events.into_iter().filter(|e| matches(&request, e)) {
                        if tx.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                }
            }
            loop {
                let next = tokio::select! {
                    () = &mut closed => return,
                    next = tokio::time::timeout(KEEPALIVE, live.recv()) => next,
                };
                let event = match next {
                    Err(_) => Event {
                        timestamp: Some(timestamp(SystemTime::now())),
                        kind: EventKind::Keepalive as i32,
                        payload: Some(event::Payload::Keepalive(Keepalive {
                            agent_time: Some(timestamp(SystemTime::now())),
                        })),
                        ..Default::default()
                    },
                    Ok(Ok(event)) if matches(&request, &event) => event,
                    Ok(Ok(_)) => continue,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => resync("overflow"),
                    Ok(Err(broadcast::error::RecvError::Closed)) => return,
                };
                if tx.send(Ok(event)).await.is_err() {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::agent::v2::TrustChangedEvent;

    fn trust(change: &str) -> event::Payload {
        event::Payload::TrustChanged(TrustChangedEvent {
            change: change.to_owned(),
            ..Default::default()
        })
    }

    #[test]
    fn resume_tokens_replay_after_the_token_and_reject_foreign_ones() {
        let bus = EventBus::new();
        bus.publish(EventKind::TrustChanged, Scope::default(), trust("a"));
        bus.publish(EventKind::TrustChanged, Scope::default(), trust("b"));
        let first = bus.ring.lock().unwrap().events[0].resume_token.clone();
        let (replay, _) = bus.replay(&first);
        let replay = replay.unwrap();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].seq, 2);
        assert!(bus.replay("otherboot.1").0.is_none());
        assert!(bus.replay(&format!("{}.99", bus.boot)).0.is_none());
        assert_eq!(bus.replay("").0.unwrap().len(), 0);
    }

    /// `GetStateSnapshot`'s token replays exactly the events after it, also
    /// before the first event.
    #[test]
    fn the_snapshot_token_replays_every_later_event() {
        let bus = EventBus::new();
        let empty = bus.resume_token();
        assert_eq!(bus.replay(&empty).0.unwrap().len(), 0);
        bus.publish(EventKind::TrustChanged, Scope::default(), trust("a"));
        let token = bus.resume_token();
        bus.publish(EventKind::TrustChanged, Scope::default(), trust("b"));
        let replay = bus.replay(&token).0.unwrap();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].seq, 2);
        assert_eq!(bus.replay(&empty).0.unwrap().len(), 2);
    }
}
