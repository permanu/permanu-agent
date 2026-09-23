//! Webhook intake (agent-protocol.md 11.1 steps 1–7), independent of the
//! HTTP server so it can be driven directly.
//!
//! Order: method and path, body cap (413), the pre-authentication budget
//! (429), the provider headers, then the runner's `webhook_verify` before
//! anything parses the body. Every authentication failure, including a
//! project with no webhook secret on this server, is the same 401 after
//! the same work. A verified delivery counts against the deploy budget
//! (429), is deduplicated by body digest (200 `DUPLICATE`) and recorded
//! (202); only pushes go on to rule matching.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use hyper::header::HeaderMap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{Hooks, MAX_BODY_BYTES, PENDING_TTL_SECONDS};
use crate::admissions::new_uuid7;
use crate::admissions::webhooks::{DeliveryRow, RejectReason};
use crate::local::presence::AwayEvent;
use crate::local::sched::pts;
use crate::proto::agent::v2::{WebhookDelivery, WebhookDeliveryStatus};
use crate::signed_plan::text::{self, format_timestamp};

/// `webhook_verify` is a constant-time compare and a strict parse.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// A signature or token header longer than this is malformed.
const MAX_SIGNATURE_BYTES: usize = 1_024;

/// One request as the listener received it.
#[derive(Debug, Clone, Default)]
pub struct HookRequest {
    pub method: String,
    /// Path without the query.
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// The answer: an HTTP status and a fixed body (never request data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookResponse {
    pub status: u16,
    pub body: &'static str,
}

const NOT_FOUND: HookResponse = HookResponse {
    status: 404,
    body: "not found\n",
};
const UNAUTHORIZED: HookResponse = HookResponse {
    status: 401,
    body: "unauthorized\n",
};
const TOO_LARGE: HookResponse = HookResponse {
    status: 413,
    body: "payload too large\n",
};
const TOO_MANY: HookResponse = HookResponse {
    status: 429,
    body: "too many requests\n",
};
const UNAVAILABLE: HookResponse = HookResponse {
    status: 503,
    body: "unavailable\n",
};
const DUPLICATE: HookResponse = HookResponse {
    status: 200,
    body: "duplicate\n",
};
const ACCEPTED: HookResponse = HookResponse {
    status: 202,
    body: "accepted\n",
};

pub fn too_large() -> HookResponse {
    TOO_LARGE
}

pub fn not_found() -> HookResponse {
    NOT_FOUND
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Provider and its signature (or token) header (section 11.1 step 4).
/// Gitea also sends `X-GitHub-Event`, so it is recognised first.
fn provider(headers: &HeaderMap) -> Option<(&'static str, Option<&str>)> {
    if header(headers, "x-gitea-event").is_some() {
        return Some(("gitea", header(headers, "x-gitea-signature")));
    }
    if header(headers, "x-github-event").is_some() {
        return Some(("github", header(headers, "x-hub-signature-256")));
    }
    if header(headers, "x-gitlab-event").is_some() {
        return Some(("gitlab", header(headers, "x-gitlab-token")));
    }
    None
}

/// The provider's delivery id header, if it is a safe short token.
fn delivery_ref(headers: &HeaderMap) -> String {
    [
        "x-github-delivery",
        "x-gitea-delivery",
        "x-gitlab-event-uuid",
    ]
    .iter()
    .find_map(|name| header(headers, name))
    .filter(|v| text::delivery_id(v))
    .unwrap_or_default()
    .to_owned()
}

/// The pre-authentication key: the client address Dwaar sets in
/// `X-Real-IP` (it overwrites any client value).
fn source(headers: &HeaderMap) -> String {
    header(headers, "x-real-ip")
        .and_then(|v| v.parse::<IpAddr>().ok())
        .map_or_else(|| "unknown".to_owned(), |ip| ip.to_string())
}

/// The push fields `webhook_verify` returned, checked before they are
/// stored or used.
struct Push {
    repo: String,
    r#ref: String,
    commit_sha: String,
    commit_time: String,
}

fn push_fields(result: &Value) -> Option<Push> {
    let field = |name: &str| result[name].as_str().map(str::to_owned);
    let push = Push {
        repo: field("repo")?,
        r#ref: field("ref")?,
        commit_sha: field("commit_sha")?,
        commit_time: field("commit_time")?,
    };
    (text::repo(&push.repo)
        && push.r#ref.starts_with("refs/")
        && push.r#ref.len() <= 255
        && !push
            .r#ref
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ')
        && text::hex40(&push.commit_sha)
        && text::timestamp(&push.commit_time).is_some())
    .then_some(push)
}

/// A short event name (`push`, `ping`, ...).
fn event_name(result: &Value) -> String {
    result["event"]
        .as_str()
        .filter(|e| {
            (1..=64).contains(&e.len())
                && e.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b' '))
        })
        .unwrap_or("unknown")
        .to_owned()
}

fn environments(result: &Value) -> Option<Vec<String>> {
    let list = result["environments"].as_array()?;
    let names: Vec<String> = list
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|name| (1..=64).contains(&name.len()))
        .map(str::to_owned)
        .collect();
    (names.len() == list.len() && names.len() <= 64).then_some(names)
}

impl Hooks {
    /// Handles one forwarded webhook request.
    pub async fn intake(self: &Arc<Self>, request: HookRequest) -> HookResponse {
        if request.method != "POST" {
            return NOT_FOUND;
        }
        let Some(project_id) = request.path.strip_prefix("/hooks/") else {
            return NOT_FOUND;
        };
        if project_id.is_empty() || project_id.len() > 64 || project_id.contains('/') {
            return NOT_FOUND;
        }
        if request.body.len() > MAX_BODY_BYTES {
            self.count_oversize();
            return TOO_LARGE;
        }
        let now = self.now();
        if !self.pre_auth.admit(&source(&request.headers), now) {
            super::locked(&self.counters).rate_limited += 1;
            return TOO_MANY;
        }
        let body_digest_hex = hex::encode(Sha256::digest(&request.body));
        let received_at = format_timestamp(now);
        let reject = |provider: &str, reason: RejectReason| {
            if let Err(err) = self.deps.store.insert_rejected_delivery(
                &body_digest_hex,
                request.body.len() as u64,
                project_id,
                provider,
                &received_at,
                reason,
            ) {
                tracing::warn!(error = %err, "rejected delivery not recorded");
            }
            UNAUTHORIZED
        };
        let Some((provider, signature)) = provider(&request.headers) else {
            return reject("", RejectReason::Malformed);
        };
        let Some(signature) = signature.filter(|s| s.len() <= MAX_SIGNATURE_BYTES) else {
            return reject(provider, RejectReason::Malformed);
        };
        if !text::uuid7(project_id) {
            return reject(provider, RejectReason::Malformed);
        }

        let verify = json!({"op": "webhook_verify", "payload": {
            "project_id": project_id,
            "provider": provider,
            "signature": signature,
            "body_b64": base64::engine::general_purpose::STANDARD.encode(&request.body),
        }});
        let result = match self.deps.core.runner.exchange(verify, VERIFY_TIMEOUT).await {
            Ok(result) => result,
            Err(failure) => {
                tracing::warn!(code = %failure.code, "webhook_verify failed");
                return UNAVAILABLE;
            }
        };
        if result["ok"] != true {
            return match result["error"]["code"].as_str() {
                // No webhook secret of this project on this server: the
                // same 401, only a counter (section 11.1 step 3).
                Some("not_found") => {
                    super::locked(&self.counters).unknown_project += 1;
                    UNAUTHORIZED
                }
                Some("invalid_request") => reject(provider, RejectReason::Malformed),
                _ => UNAVAILABLE,
            };
        }
        if result["verified"] != true {
            return reject(provider, RejectReason::Signature);
        }
        // The runner hashed the same bytes; anything else is a broken reply.
        let (Some(environments), true) = (
            environments(&result),
            result["body_digest_hex"] == body_digest_hex.as_str(),
        ) else {
            tracing::warn!("webhook_verify answered an unexpected shape");
            return UNAVAILABLE;
        };
        if !self.deploys.admit(project_id, now) {
            super::locked(&self.counters).rate_limited += 1;
            return TOO_MANY;
        }
        let event = event_name(&result);
        let push = (event == "push").then(|| push_fields(&result)).flatten();
        let status = if push.is_some() {
            WebhookDeliveryStatus::Pending
        } else {
            WebhookDeliveryStatus::Ignored
        };
        let unix_ms = u64::try_from(now).unwrap_or(0).saturating_mul(1_000);
        let delivery_id = new_uuid7(unix_ms);
        let push_or_empty = push.unwrap_or(Push {
            repo: String::new(),
            r#ref: String::new(),
            commit_sha: String::new(),
            commit_time: String::new(),
        });
        let row = DeliveryRow {
            delivery_id: delivery_id.clone(),
            provider: provider.to_owned(),
            event: event.clone(),
            body_digest_hex: body_digest_hex.clone(),
            repo: push_or_empty.repo.clone(),
            r#ref: push_or_empty.r#ref.clone(),
            commit_sha: push_or_empty.commit_sha.clone(),
            commit_time: push_or_empty.commit_time.clone(),
            environments: environments.clone(),
            received_at: received_at.clone(),
            expires_at: format_timestamp(now + PENDING_TTL_SECONDS),
            status: if status == WebhookDeliveryStatus::Pending {
                "pending"
            } else {
                "ignored"
            }
            .to_owned(),
        };
        match self.deps.store.insert_delivery(&row) {
            Ok(true) => {}
            Ok(false) => {
                super::locked(&self.counters).duplicates.push_back(now);
                return DUPLICATE;
            }
            Err(err) => {
                tracing::warn!(error = %err, "delivery not recorded");
                return UNAVAILABLE;
            }
        }
        let delivery = WebhookDelivery {
            id: delivery_id.clone(),
            received_at: Some(pts(now)),
            provider: provider.to_owned(),
            event,
            delivery_ref: delivery_ref(&request.headers),
            repository: row.repo,
            r#ref: row.r#ref,
            commit_sha: row.commit_sha,
            project_id: project_id.to_owned(),
            signature_valid: true,
            status: status as i32,
            status_reason: if status == WebhookDeliveryStatus::Ignored {
                "not a push".to_owned()
            } else {
                String::new()
            },
            body_digest_hex,
            body_bytes: request.body.len() as u64,
            verified_at: Some(pts(now)),
            commit_time: text::timestamp(&row.commit_time).map(pts),
            expires_at: Some(pts(now + PENDING_TTL_SECONDS)),
            environments,
            processed_at: (status == WebhookDeliveryStatus::Ignored).then(|| pts(now)),
            ..Default::default()
        };
        self.put_delivery(&delivery);
        self.away(AwayEvent::WebhookDelivery);
        tracing::info!(
            delivery_id = %delivery_id,
            project_id = %project_id,
            provider,
            "webhook delivery verified"
        );
        if status == WebhookDeliveryStatus::Pending {
            self.enqueue(delivery_id);
        }
        ACCEPTED
    }
}
