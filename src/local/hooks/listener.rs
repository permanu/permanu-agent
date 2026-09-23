//! The webhook listener on `127.0.0.1:7461` (agent-protocol.md 8, 11.1).
//! Dwaar forwards `POST /hooks/<project_id>` here as plain HTTP/1 with the
//! raw body; the agent serves nothing else on the port and accepts only
//! loopback peers. Bodies over 1 MiB are refused from `Content-Length`
//! before they are read, and a body that grows past 1 MiB while it is read
//! is refused too (a chunked body Dwaar cut short never reaches the
//! runner). Slow clients are bounded by a header and a body deadline.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::warn;

use super::intake::{not_found, too_large, HookRequest, HookResponse};
use super::{Hooks, MAX_BODY_BYTES};

const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Connections served at once; more wait in the accept backlog.
const MAX_CONNECTIONS: usize = 64;

fn reply(answer: HookResponse) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(answer.body.as_bytes())));
    *response.status_mut() =
        StatusCode::from_u16(answer.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

async fn handle(hooks: Arc<Hooks>, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    if !parts.uri.path().starts_with("/hooks/") {
        return reply(not_found());
    }
    let declared = parts
        .headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_BODY_BYTES as u64) {
        hooks.count_oversize();
        return reply(too_large());
    }
    let collected =
        tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, MAX_BODY_BYTES).collect()).await;
    let body = match collected {
        Ok(Ok(collected)) => collected.to_bytes().to_vec(),
        Ok(Err(err)) if err.is::<http_body_util::LengthLimitError>() => {
            hooks.count_oversize();
            return reply(too_large());
        }
        _ => {
            return reply(HookResponse {
                status: 400,
                body: "bad request\n",
            })
        }
    };
    let answer = hooks
        .intake(HookRequest {
            method: parts.method.as_str().to_owned(),
            path: parts.uri.path().to_owned(),
            headers: parts.headers,
            body,
        })
        .await;
    reply(answer)
}

/// Serves `listener` until the task is aborted.
pub fn serve(hooks: Arc<Hooks>, listener: TcpListener) -> JoinHandle<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let Ok(permit) = slots.clone().acquire_owned().await else {
                return;
            };
            let (stream, peer): (_, SocketAddr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    warn!(error = %err, "webhook accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Only Dwaar, on this host, forwards here.
            if !peer.ip().is_loopback() {
                warn!(%peer, "webhook connection refused: not loopback");
                continue;
            }
            let hooks = hooks.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request| {
                    let hooks = hooks.clone();
                    async move { Ok::<_, std::convert::Infallible>(handle(hooks, request).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HEADER_TIMEOUT)
                    .max_buf_size(64 * 1024)
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                drop(permit);
            });
        }
    })
}

/// Binds `127.0.0.1:7461` (or `addr` in tests) and serves it.
pub async fn bind_and_serve(hooks: Arc<Hooks>, addr: &str) -> std::io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(addr).await?;
    Ok(serve(hooks, listener))
}
