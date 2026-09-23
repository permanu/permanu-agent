//! OTLP listeners (agent-protocol.md 9.5, D-053): OTLP/gRPC on 4317 and
//! OTLP/HTTP (`/v1/traces`, `/v1/metrics`, `/v1/logs`; protobuf or JSON;
//! gzip allowed) on 4318, bound **only** to the IPv4 address of the Docker
//! bridge gateway (`docker0`), never `0.0.0.0`, a public address or
//! `127.0.0.1`.
//!
//! - Every 30 s the agent re-reads the gateway address and the firewall
//!   state; it binds when both are present and rebinds when the address
//!   changes. While unbound, `AgentStatus.otlp_*_listen` are empty
//!   (`otlp_unbound`).
//! - Two independent checks on who may connect: the `inet permanu_otlp`
//!   nftables table must be present ([`FirewallCheck`]; in production the
//!   runner's `diagnose` check `otlp_nft`, [`RunnerFirewall`]), and a
//!   connection is
//!   accepted only when its source address is inside the subnet of a Docker
//!   bridge (`docker0`, `br-*`) and the kernel's route to that source goes
//!   out of that same bridge ([`Network`]).
//! - Limits: 100 requests/s per source address (burst 200), request ≤ 4 MiB
//!   on the wire and ≤ 16 MiB decompressed; excess is HTTP 429 with
//!   `Retry-After` / gRPC `RESOURCE_EXHAUSTED`.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use opentelemetry_proto::tonic::collector::logs::v1::{
    logs_service_server::{LogsService, LogsServiceServer},
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    metrics_service_server::{MetricsService, MetricsServiceServer},
    ExportMetricsPartialSuccess, ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    trace_service_server::{TraceService, TraceServiceServer},
    ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use prost::Message;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::codec::CompressionEncoding;
use tracing::{info, warn};

use super::otlp::{Outcome, TooMany};
use super::{Buckets, OtlpListen, Telemetry};

pub const GRPC_PORT: u16 = 4317;
pub const HTTP_PORT: u16 = 4318;
pub const GATEWAY_IFACE: &str = "docker0";
const WIRE_MAX: usize = 4 * 1024 * 1024;
const DECOMPRESSED_MAX: usize = 16 * 1024 * 1024;
const SOURCE_RATE: f64 = 100.0;
const SOURCE_BURST: f64 = 200.0;
const RECHECK: Duration = Duration::from_secs(30);

/// A Docker bridge interface and its connected IPv4 subnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    pub name: String,
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Bridge {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix.min(32)))
        };
        u32::from(self.addr) & mask == u32::from(ip) & mask
    }
}

/// Interface and route facts (netlink-equivalent reads).
pub trait Network: Send + Sync {
    /// `docker0` and `br-*` IPv4 addresses with their prefixes.
    fn bridges(&self) -> Vec<Bridge>;
    /// The interface the kernel's route to `ip` leaves through.
    fn route_iface(&self, ip: Ipv4Addr) -> Option<String>;
}

/// The nftables table `inet permanu_otlp` (9.5).
#[tonic::async_trait]
pub trait FirewallCheck: Send + Sync {
    async fn table_present(&self) -> bool;
}

/// The runner's read-only `diagnose` op (signed-plan.md 14.3, contracts
/// v1.1.2/v1.1.3, D-060, D-061): `{checks: ["otlp_nft"]}` answers
/// `{otlp_nft: "present" | "absent"}`, `present` exactly when the canonical
/// `inet permanu_otlp` ruleset (agent-protocol.md 8) is loaded. `absent`, a
/// refusal, a malformed answer or no runner keeps OTLP unbound (fail
/// closed).
pub struct RunnerFirewall {
    pub runner: Arc<dyn crate::local::runner::Runner>,
}

const DIAGNOSE_TIMEOUT: Duration = Duration::from_secs(10);

#[tonic::async_trait]
impl FirewallCheck for RunnerFirewall {
    async fn table_present(&self) -> bool {
        let request = serde_json::json!({"op": "diagnose", "payload": {"checks": ["otlp_nft"]}});
        match self.runner.exchange(request, DIAGNOSE_TIMEOUT).await {
            Ok(result) => result["ok"] == true && result["otlp_nft"] == "present",
            Err(failure) => {
                warn!(error = %failure.message, "diagnose otlp_nft failed; OTLP stays unbound");
                false
            }
        }
    }
}

/// Development builds only (`dev-paths`, never shipped): the loopback
/// "bridge" a smoke test binds OTLP to, since a dev machine has neither
/// `docker0` nor the `inet permanu_otlp` table.
#[cfg(feature = "dev-paths")]
pub const DEV_LOOPBACK_IFACE: &str = "dev-loopback";

/// Development builds only: 127.0.0.0/8 is the one bridge, and only
/// loopback peers route through it.
#[cfg(feature = "dev-paths")]
pub struct DevLoopback;

#[cfg(feature = "dev-paths")]
impl Network for DevLoopback {
    fn bridges(&self) -> Vec<Bridge> {
        vec![Bridge {
            name: DEV_LOOPBACK_IFACE.to_owned(),
            addr: Ipv4Addr::LOCALHOST,
            prefix: 8,
        }]
    }

    fn route_iface(&self, ip: Ipv4Addr) -> Option<String> {
        ip.is_loopback().then(|| DEV_LOOPBACK_IFACE.to_owned())
    }
}

/// Development builds only: loopback needs no nftables table.
#[cfg(feature = "dev-paths")]
struct DevLoopbackFirewall;

#[cfg(feature = "dev-paths")]
#[tonic::async_trait]
impl FirewallCheck for DevLoopbackFirewall {
    async fn table_present(&self) -> bool {
        true
    }
}

/// `getifaddrs` for the bridges and `/proc/net/route` for the route check.
pub struct SystemNetwork {
    pub proc_root: PathBuf,
}

impl Network for SystemNetwork {
    fn bridges(&self) -> Vec<Bridge> {
        interfaces()
            .into_iter()
            .filter(|b| b.name == GATEWAY_IFACE || b.name.starts_with("br-"))
            .collect()
    }

    fn route_iface(&self, ip: Ipv4Addr) -> Option<String> {
        let table = std::fs::read_to_string(self.proc_root.join("net/route")).ok()?;
        route_lookup(&table, ip)
    }
}

/// IPv4 interfaces with their prefix lengths.
fn interfaces() -> Vec<Bridge> {
    let mut out = Vec::new();
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list we free with freeifaddrs below; every
    // pointer is checked for null before it is read.
    unsafe {
        if libc::getifaddrs(&mut addrs) != 0 {
            return out;
        }
        let mut cur = addrs;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null()
                && !ifa.ifa_netmask.is_null()
                && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET
            {
                let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let mask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                out.push(Bridge {
                    name,
                    addr: Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                    prefix: u32::from_be(mask.sin_addr.s_addr).count_ones() as u8,
                });
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(addrs);
    }
    out
}

/// Longest-prefix match over `/proc/net/route` (hex, little endian).
pub fn route_lookup(table: &str, ip: Ipv4Addr) -> Option<String> {
    let target = u32::from(ip);
    let mut best: Option<(u32, u32, String)> = None;
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let parse = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::from_be);
        let (Some(dest), Some(flags), Some(metric), Some(mask)) = (
            parse(cols[1]),
            u32::from_str_radix(cols[3], 16).ok(),
            cols[6].parse::<u32>().ok(),
            parse(cols[7]),
        ) else {
            continue;
        };
        if flags & 1 == 0 || target & mask != dest & mask {
            continue;
        }
        let better = match &best {
            None => true,
            Some((m, met, _)) => {
                mask.count_ones() > m.count_ones()
                    || (mask.count_ones() == m.count_ones() && metric < *met)
            }
        };
        if better {
            best = Some((mask, metric, cols[0].to_owned()));
        }
    }
    best.map(|(_, _, iface)| iface)
}

/// The source check of 9.5: inside a bridge subnet and routed out of it.
pub fn accept_peer(net: &dyn Network, peer: IpAddr) -> bool {
    let IpAddr::V4(ip) = peer else {
        return false;
    };
    net.bridges()
        .iter()
        .any(|b| b.contains(ip) && net.route_iface(ip).as_deref() == Some(b.name.as_str()))
}

#[derive(Clone)]
struct Receiver {
    telemetry: Arc<Telemetry>,
    sources: Arc<Mutex<Buckets>>,
}

impl Receiver {
    fn allow(&self, peer: Option<SocketAddr>) -> bool {
        let key = peer.map(|p| p.ip().to_string()).unwrap_or_default();
        self.sources.lock().unwrap_or_else(|p| p.into_inner()).take(
            &key,
            SOURCE_RATE,
            SOURCE_BURST,
            Instant::now(),
        )
    }
}

fn exhausted(message: &str) -> tonic::Status {
    tonic::Status::resource_exhausted(message)
}

fn partial(outcome: &Outcome) -> (i64, String) {
    let n = i64::try_from(outcome.rejected).unwrap_or(i64::MAX);
    let message = if n > 0 {
        "some items were rejected or dropped".to_owned()
    } else {
        String::new()
    };
    (n, message)
}

#[tonic::async_trait]
impl TraceService for Receiver {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        if !self.allow(request.remote_addr()) {
            return Err(exhausted("rate limited"));
        }
        let outcome = self
            .telemetry
            .otlp_state
            .traces(&self.telemetry, request.into_inner())
            .map_err(|TooMany(m)| exhausted(m))?;
        let (rejected_spans, error_message) = partial(&outcome);
        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: (rejected_spans > 0).then_some(ExportTracePartialSuccess {
                rejected_spans,
                error_message,
            }),
        }))
    }
}

#[tonic::async_trait]
impl MetricsService for Receiver {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        if !self.allow(request.remote_addr()) {
            return Err(exhausted("rate limited"));
        }
        let outcome = self
            .telemetry
            .otlp_state
            .metrics(&self.telemetry, request.into_inner())
            .map_err(|TooMany(m)| exhausted(m))?;
        let (rejected_data_points, error_message) = partial(&outcome);
        Ok(tonic::Response::new(ExportMetricsServiceResponse {
            partial_success: (rejected_data_points > 0).then_some(ExportMetricsPartialSuccess {
                rejected_data_points,
                error_message,
            }),
        }))
    }
}

#[tonic::async_trait]
impl LogsService for Receiver {
    async fn export(
        &self,
        request: tonic::Request<ExportLogsServiceRequest>,
    ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
        if !self.allow(request.remote_addr()) {
            return Err(exhausted("rate limited"));
        }
        let outcome = self
            .telemetry
            .otlp_state
            .logs(&self.telemetry, request.into_inner())
            .map_err(|TooMany(m)| exhausted(m))?;
        let (rejected_log_records, error_message) = partial(&outcome);
        Ok(tonic::Response::new(ExportLogsServiceResponse {
            partial_success: (rejected_log_records > 0).then_some(ExportLogsPartialSuccess {
                rejected_log_records,
                error_message,
            }),
        }))
    }
}

fn reply(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    if let Ok(v) = hyper::header::HeaderValue::from_str(content_type) {
        response
            .headers_mut()
            .insert(hyper::header::CONTENT_TYPE, v);
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("1"),
        );
    }
    response
}

fn plain(status: StatusCode) -> Response<Full<Bytes>> {
    reply(
        status,
        "text/plain",
        status.canonical_reason().unwrap_or("").as_bytes().to_vec(),
    )
}

enum Signal {
    Traces,
    Metrics,
    Logs,
}

fn decode<M: Message + Default + serde::de::DeserializeOwned>(
    json: bool,
    body: &[u8],
) -> Option<M> {
    if json {
        serde_json::from_slice(body).ok()
    } else {
        M::decode(body).ok()
    }
}

fn encode<M: Message + serde::Serialize>(json: bool, message: &M) -> Vec<u8> {
    if json {
        serde_json::to_vec(message).unwrap_or_else(|_| b"{}".to_vec())
    } else {
        message.encode_to_vec()
    }
}

async fn handle_http(
    receiver: Receiver,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    if request.method() != Method::POST {
        return plain(StatusCode::METHOD_NOT_ALLOWED);
    }
    let signal = match request.uri().path() {
        "/v1/traces" => Signal::Traces,
        "/v1/metrics" => Signal::Metrics,
        "/v1/logs" => Signal::Logs,
        _ => return plain(StatusCode::NOT_FOUND),
    };
    if !receiver.allow(Some(peer)) {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    }
    let header = |name: hyper::header::HeaderName| {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    let content_type = header(hyper::header::CONTENT_TYPE);
    let json = if content_type.starts_with("application/json") {
        true
    } else if content_type.starts_with("application/x-protobuf") {
        false
    } else {
        return plain(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    };
    let encoding = header(hyper::header::CONTENT_ENCODING);
    if !matches!(encoding.as_str(), "" | "identity" | "gzip") {
        return plain(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let body = match Limited::new(request.into_body(), WIRE_MAX).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let body: Vec<u8> = if encoding == "gzip" {
        let mut out = Vec::new();
        let read = flate2::read::GzDecoder::new(body.as_ref())
            .take(DECOMPRESSED_MAX as u64 + 1)
            .read_to_end(&mut out);
        match read {
            Ok(n) if n <= DECOMPRESSED_MAX => out,
            Ok(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE),
            Err(_) => return plain(StatusCode::BAD_REQUEST),
        }
    } else {
        body.to_vec()
    };
    let content_type = if json {
        "application/json"
    } else {
        "application/x-protobuf"
    };
    let telemetry = receiver.telemetry.clone();
    let state = telemetry.otlp_state.clone();
    let result = match signal {
        Signal::Traces => decode::<ExportTraceServiceRequest>(json, &body).map(|req| {
            state.traces(&telemetry, req).map(|o| {
                let (n, m) = partial(&o);
                encode(
                    json,
                    &ExportTraceServiceResponse {
                        partial_success: (n > 0).then_some(ExportTracePartialSuccess {
                            rejected_spans: n,
                            error_message: m,
                        }),
                    },
                )
            })
        }),
        Signal::Metrics => decode::<ExportMetricsServiceRequest>(json, &body).map(|req| {
            state.metrics(&telemetry, req).map(|o| {
                let (n, m) = partial(&o);
                encode(
                    json,
                    &ExportMetricsServiceResponse {
                        partial_success: (n > 0).then_some(ExportMetricsPartialSuccess {
                            rejected_data_points: n,
                            error_message: m,
                        }),
                    },
                )
            })
        }),
        Signal::Logs => decode::<ExportLogsServiceRequest>(json, &body).map(|req| {
            state.logs(&telemetry, req).map(|o| {
                let (n, m) = partial(&o);
                encode(
                    json,
                    &ExportLogsServiceResponse {
                        partial_success: (n > 0).then_some(ExportLogsPartialSuccess {
                            rejected_log_records: n,
                            error_message: m,
                        }),
                    },
                )
            })
        }),
    };
    match result {
        None => plain(StatusCode::BAD_REQUEST),
        Some(Err(TooMany(_))) => plain(StatusCode::TOO_MANY_REQUESTS),
        Some(Ok(bytes)) => reply(StatusCode::OK, content_type, bytes),
    }
}

/// Accepts connections that pass the source check (9.5).
async fn accept_checked(
    listener: &TcpListener,
    net: &Arc<dyn Network>,
) -> Option<(TcpStream, SocketAddr)> {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                if accept_peer(net.as_ref(), peer.ip()) {
                    return Some((stream, peer));
                }
                warn!(%peer, "OTLP connection refused: source is not on a Docker bridge");
            }
            Err(err) => {
                warn!(error = %err, "OTLP accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn serve_http(listener: TcpListener, receiver: Receiver, net: Arc<dyn Network>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some((stream, peer)) = accept_checked(&listener, &net).await {
            let receiver = receiver.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let receiver = receiver.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(handle_http(receiver, peer, req).await)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(10))
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    })
}

fn serve_grpc(listener: TcpListener, receiver: Receiver, net: Arc<dyn Network>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (tx, rx) = mpsc::channel::<std::io::Result<TcpStream>>(16);
        let accept = tokio::spawn(async move {
            while let Some((stream, _)) = accept_checked(&listener, &net).await {
                if tx.send(Ok(stream)).await.is_err() {
                    return;
                }
            }
        });
        let limit = DECOMPRESSED_MAX;
        let result = tonic::transport::Server::builder()
            .concurrency_limit_per_connection(32)
            .add_service(
                TraceServiceServer::new(receiver.clone())
                    .accept_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(limit),
            )
            .add_service(
                MetricsServiceServer::new(receiver.clone())
                    .accept_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(limit),
            )
            .add_service(
                LogsServiceServer::new(receiver)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(limit),
            )
            .serve_with_incoming(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await;
        accept.abort();
        if let Err(err) = result {
            warn!(error = %err, "OTLP gRPC server ended");
        }
    })
}

/// Keeps the listeners bound to the gateway while the checks pass.
pub struct Listeners {
    pub telemetry: Arc<Telemetry>,
    pub net: Arc<dyn Network>,
    pub firewall: Arc<dyn FirewallCheck>,
    pub gateway_iface: String,
    pub grpc_port: u16,
    pub http_port: u16,
}

struct Bound {
    addr: Ipv4Addr,
    tasks: [JoinHandle<()>; 2],
}

impl Listeners {
    /// Development builds only (`dev-paths`): listeners on 127.0.0.1 that
    /// accept loopback peers only.
    #[cfg(feature = "dev-paths")]
    pub fn dev_loopback(telemetry: Arc<Telemetry>, grpc_port: u16, http_port: u16) -> Self {
        Self {
            telemetry,
            net: Arc::new(DevLoopback),
            firewall: Arc::new(DevLoopbackFirewall),
            gateway_iface: DEV_LOOPBACK_IFACE.to_owned(),
            grpc_port,
            http_port,
        }
    }

    /// Loopback is never a production gateway; tests and the dev-paths
    /// loopback listeners are the only exceptions.
    fn loopback_allowed(&self) -> bool {
        #[cfg(feature = "dev-paths")]
        if self.gateway_iface == DEV_LOOPBACK_IFACE {
            return true;
        }
        cfg!(test)
    }

    fn gateway(&self) -> Option<Ipv4Addr> {
        self.net
            .bridges()
            .into_iter()
            .find(|b| b.name == self.gateway_iface)
            .map(|b| b.addr)
            // Never a wildcard, loopback or public address (9.5).
            .filter(|a| !a.is_unspecified() && (!a.is_loopback() || self.loopback_allowed()))
    }

    async fn bind(&self, addr: Ipv4Addr) -> std::io::Result<(Bound, OtlpListen)> {
        let grpc = TcpListener::bind(SocketAddr::from((addr, self.grpc_port))).await?;
        let http = TcpListener::bind(SocketAddr::from((addr, self.http_port))).await?;
        let listen = OtlpListen {
            grpc_listen: grpc.local_addr()?.to_string(),
            http_listen: http.local_addr()?.to_string(),
        };
        let receiver = Receiver {
            telemetry: self.telemetry.clone(),
            sources: Arc::new(Mutex::new(Buckets::default())),
        };
        let tasks = [
            serve_grpc(grpc, receiver.clone(), self.net.clone()),
            serve_http(http, receiver, self.net.clone()),
        ];
        Ok((Bound { addr, tasks }, listen))
    }

    /// One check: returns the new bound state.
    async fn reconcile(&self, current: Option<Bound>) -> Option<Bound> {
        let wanted = match self.gateway() {
            Some(addr) if self.firewall.table_present().await => Some(addr),
            _ => None,
        };
        if current.as_ref().map(|b| b.addr) == wanted {
            return current;
        }
        if let Some(old) = current {
            old.tasks.iter().for_each(JoinHandle::abort);
        }
        self.telemetry.set_otlp(OtlpListen::default());
        let addr = wanted?;
        match self.bind(addr).await {
            Ok((bound, listen)) => {
                info!(grpc = %listen.grpc_listen, http = %listen.http_listen, "OTLP receiver bound");
                self.telemetry.set_otlp(listen);
                Some(bound)
            }
            Err(err) => {
                warn!(error = %err, %addr, "OTLP bind failed");
                None
            }
        }
    }

    pub async fn run(self) {
        let mut bound = None;
        let mut tick = tokio::time::interval(RECHECK);
        loop {
            tick.tick().await;
            bound = self.reconcile(bound).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::telemetry::otlp::tests::{otlp_span, trace_request};
    use crate::local::telemetry::store::{Kind, ScanSpec};
    use crate::local::telemetry::test_support;
    use crate::signed_plan::test_support::temp_dir;
    use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct TestNet {
        bridges: Vec<Bridge>,
        route: Option<String>,
    }

    impl Network for TestNet {
        fn bridges(&self) -> Vec<Bridge> {
            self.bridges.clone()
        }
        fn route_iface(&self, _: Ipv4Addr) -> Option<String> {
            self.route.clone()
        }
    }

    struct Firewall(AtomicBool);

    #[tonic::async_trait]
    impl FirewallCheck for Firewall {
        async fn table_present(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn lo_bridge() -> Bridge {
        Bridge {
            name: "test-br".into(),
            addr: Ipv4Addr::LOCALHOST,
            prefix: 8,
        }
    }

    #[test]
    fn routes_use_the_longest_prefix() {
        let table =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                     docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
                     br-abc\t000012AC\t00000000\t0000\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        assert_eq!(
            route_lookup(table, Ipv4Addr::new(172, 17, 0, 5)).as_deref(),
            Some("docker0")
        );
        assert_eq!(
            route_lookup(table, Ipv4Addr::new(8, 8, 8, 8)).as_deref(),
            Some("eth0")
        );
        // br-abc is down (flags without RTF_UP): default route.
        assert_eq!(
            route_lookup(table, Ipv4Addr::new(172, 18, 0, 5)).as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn peers_must_be_on_a_bridge_and_routed_through_it() {
        let docker0 = Bridge {
            name: "docker0".into(),
            addr: Ipv4Addr::new(172, 17, 0, 1),
            prefix: 16,
        };
        let net = |route: &str| TestNet {
            bridges: vec![docker0.clone()],
            route: Some(route.to_owned()),
        };
        let inside = IpAddr::V4(Ipv4Addr::new(172, 17, 0, 9));
        assert!(accept_peer(&net("docker0"), inside));
        // Same subnet, but the kernel routes it elsewhere (a spoofed or
        // neighbour source): refused.
        assert!(!accept_peer(&net("eth0"), inside));
        assert!(!accept_peer(
            &net("docker0"),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
        assert!(!accept_peer(&net("docker0"), "::1".parse().unwrap()));
    }

    fn listeners(t: Arc<Telemetry>, route: Option<&str>, firewall: bool) -> Listeners {
        Listeners {
            telemetry: t,
            net: Arc::new(TestNet {
                bridges: vec![lo_bridge()],
                route: route.map(str::to_owned),
            }),
            firewall: Arc::new(Firewall(AtomicBool::new(firewall))),
            gateway_iface: "test-br".into(),
            grpc_port: 0,
            http_port: 0,
        }
    }

    #[cfg(feature = "dev-paths")]
    #[test]
    fn dev_loopback_accepts_only_loopback_peers() {
        let net = DevLoopback;
        assert!(accept_peer(&net, IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(accept_peer(&net, IpAddr::V4(Ipv4Addr::new(127, 1, 2, 3))));
        assert!(!accept_peer(&net, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!accept_peer(&net, IpAddr::V4(Ipv4Addr::new(172, 17, 0, 9))));
        assert!(!accept_peer(&net, "::1".parse().unwrap()));
    }

    #[cfg(feature = "dev-paths")]
    #[tokio::test]
    async fn dev_loopback_listeners_bind_only_127_0_0_1() {
        let dir = temp_dir("otlp-devlo");
        let t = test_support::open(dir.join("telemetry"));
        let l = Listeners::dev_loopback(t.clone(), 0, 0);
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        assert!(listen.grpc_listen.starts_with("127.0.0.1:"), "{listen:?}");
        assert!(listen.http_listen.starts_with("127.0.0.1:"), "{listen:?}");
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn no_firewall_table_means_unbound() {
        let dir = temp_dir("otlp-nofw");
        let t = test_support::open(dir.join("telemetry"));
        let l = listeners(t.clone(), Some("test-br"), false);
        assert!(l.reconcile(None).await.is_none());
        assert_eq!(t.otlp(), OtlpListen::default());
        assert!(t.degraded_reasons().contains(&"otlp_unbound"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A runner that answers `diagnose` with a fixed result line.
    struct Diagnose(Result<serde_json::Value, ()>, Mutex<Vec<serde_json::Value>>);

    #[tonic::async_trait]
    impl crate::local::runner::Runner for Diagnose {
        async fn exchange(
            &self,
            request: serde_json::Value,
            _timeout: Duration,
        ) -> Result<serde_json::Value, crate::local::runner::RunnerFailure> {
            self.1.lock().unwrap().push(request);
            self.0
                .clone()
                .map_err(|()| crate::local::runner::RunnerFailure::transport("closed"))
        }

        async fn open(
            &self,
            _request: serde_json::Value,
        ) -> Result<crate::local::runner::EventLines, crate::local::runner::RunnerFailure> {
            Err(crate::local::runner::RunnerFailure::transport("unused"))
        }
    }

    /// contracts v1.1.2/v1.1.3 (D-060, D-061): the production check is the
    /// runner's read-only `diagnose {checks: ["otlp_nft"]}`; only
    /// `present` binds, and anything else fails closed.
    #[tokio::test]
    async fn the_runner_diagnose_check_decides_the_firewall() {
        use serde_json::json;
        let ask = |answer: Result<serde_json::Value, ()>| async move {
            let runner = Arc::new(Diagnose(answer, Mutex::new(Vec::new())));
            let present = RunnerFirewall {
                runner: runner.clone(),
            }
            .table_present()
            .await;
            let requests = runner.1.lock().unwrap().clone();
            (present, requests)
        };
        let (present, requests) = ask(Ok(json!({"ok": true, "otlp_nft": "present"}))).await;
        assert!(present);
        assert_eq!(
            requests,
            vec![json!({"op": "diagnose", "payload": {"checks": ["otlp_nft"]}})]
        );
        for answer in [
            Ok(json!({"ok": true, "otlp_nft": "absent"})),
            Ok(json!({"ok": true})),
            Ok(json!({"ok": false, "otlp_nft": "present",
                      "error": {"code": "invalid_request", "message": "x"}})),
            Ok(json!({"ok": true, "otlp_nft": true})),
            Err(()),
        ] {
            assert!(!ask(answer.clone()).await.0, "{answer:?}");
        }
    }

    #[tokio::test]
    async fn grpc_and_http_receive_from_bridge_sources() {
        let dir = temp_dir("otlp-serve");
        let t = test_support::open(dir.join("telemetry"));
        let l = listeners(t.clone(), Some("test-br"), true);
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        assert!(listen.grpc_listen.starts_with("127.0.0.1:"));
        assert!(!t.degraded_reasons().contains(&"otlp_unbound"));

        let mut client = TraceServiceClient::connect(format!("http://{}", listen.grpc_listen))
            .await
            .unwrap();
        let response = client
            .export(trace_request(
                "p1",
                vec![otlp_span(7, 1, 0, "GET /", false)],
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(response.partial_success.is_none());

        // OTLP/HTTP JSON (hex ids per the OTLP JSON mapping).
        let body = serde_json::json!({"resourceSpans": [{"resource": {"attributes": [
            {"key": "permanu.project_id", "value": {"stringValue": "p1"}}]},
            "scopeSpans": [{"spans": [{"traceId": "08080808080808080808080808080808",
              "spanId": "0101010101010101", "name": "json span", "kind": 2,
              "startTimeUnixNano": "1790000000000000000", "endTimeUnixNano": "1790000000100000000"}]}]}]});
        let (status, _) = http_post(
            &listen.http_listen,
            "/v1/traces",
            "application/json",
            &body.to_string(),
        )
        .await;
        assert_eq!(status, 200);
        let (status, _) = http_post(&listen.http_listen, "/v1/traces", "text/plain", "x").await;
        assert_eq!(status, 415);
        let (status, _) =
            http_post(&listen.http_listen, "/v1/nope", "application/json", "{}").await;
        assert_eq!(status, 404);
        t.sync().await;
        let names: Vec<String> = t
            .snapshot(Kind::Traces)
            .scan(ScanSpec::default())
            .filter_map(|r| {
                let r = r.unwrap();
                crate::proto::agent::v2::Span::decode(r.payload.as_slice())
                    .ok()
                    .map(|s| s.name)
            })
            .collect();
        assert_eq!(names, vec!["GET /", "json span"]);

        // The firewall table disappears: the listeners go away.
        let l2 = listeners(t.clone(), Some("test-br"), false);
        assert!(l2.reconcile(Some(bound)).await.is_none());
        assert_eq!(t.otlp(), OtlpListen::default());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn sources_routed_elsewhere_are_refused() {
        let dir = temp_dir("otlp-refuse");
        let t = test_support::open(dir.join("telemetry"));
        let l = listeners(t.clone(), Some("eth0"), true);
        let _bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        let mut stream = TcpStream::connect(&listen.http_listen).await.unwrap();
        let _ = stream
            .write_all(b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await;
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
        // Closed without an answer.
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    async fn http_post(addr: &str, path: &str, content_type: &str, body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, text)
    }
}
