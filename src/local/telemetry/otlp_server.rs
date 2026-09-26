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
//! - Connection limits (contracts v1.1.5, D-063 #17): at most 64 concurrent
//!   connections over both listeners (further ones are closed at accept),
//!   a request body read completely within 30 s (HTTP 408 and close / gRPC
//!   `DEADLINE_EXCEEDED`) and at most 16 MiB of request data in flight per
//!   connection (the HTTP/2 connection window; HTTP/1.1 reads one ≤ 4 MiB
//!   body at a time). Every cut-off client is counted
//!   ([`Telemetry::otlp_connections_refused`]).
//! - Connection limits (contracts v1.1.7, D-065 #8): at most 8 concurrent
//!   connections per source address (further ones closed at accept and
//!   counted); a connection with no request in flight for 30 s is closed
//!   (HTTP/1.1: no request bytes, a TCP close; gRPC: no open stream, an
//!   HTTP/2 `GOAWAY` and then a close, with HTTP/2 keepalive `PING`s after
//!   30 s and a 10 s ack timeout); the 30 s body deadline of a connection's
//!   first request starts at accept.

use std::collections::HashMap;
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
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
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tonic::codec::CompressionEncoding;
use tonic::codegen::http;
use tonic::transport::server::{Connected, TcpConnectInfo};
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
/// D-063 #17: request data in flight per connection (HTTP/2 window).
pub const CONNECTION_IN_FLIGHT: u32 = 16 * 1024 * 1024;
/// D-065 #8: HTTP/2 keepalive `PING` after this long without frames.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// D-065 #8: a keepalive `PING` not acknowledged within this closes it.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection limits of the OTLP listeners (D-063 #17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtlpLimits {
    /// Concurrent connections over both listeners together.
    pub max_connections: usize,
    /// A request body must be read completely within this (the first
    /// request's from accept, D-065 #8).
    pub body_read: Duration,
    /// D-065 #8: a connection with no request in flight this long is closed.
    pub idle: Duration,
    /// D-065 #8: concurrent connections per source address.
    pub per_source: usize,
}

impl Default for OtlpLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            body_read: Duration::from_secs(30),
            idle: Duration::from_secs(30),
            per_source: 8,
        }
    }
}

/// One connection's request activity (D-065 #8).
struct ConnState {
    accepted: Instant,
    /// Requests (HTTP/1.1) or streams (gRPC) in flight.
    open: AtomicUsize,
    /// Requests begun so far.
    begun: AtomicU64,
    /// When the connection was last active.
    last: Mutex<Instant>,
}

impl ConnState {
    fn new() -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            accepted: now,
            open: AtomicUsize::new(0),
            begun: AtomicU64::new(0),
            last: Mutex::new(now),
        })
    }

    fn touch(&self) {
        *self.last.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
    }

    fn last(&self) -> Instant {
        *self.last.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Starts a request; its body deadline (the first one's runs from
    /// accept).
    fn begin(self: &Arc<Self>, body_read: Duration) -> (Active, Duration) {
        self.open.fetch_add(1, Ordering::SeqCst);
        self.touch();
        let deadline = if self.begun.fetch_add(1, Ordering::SeqCst) == 0 {
            body_read.saturating_sub(self.accepted.elapsed())
        } else {
            body_read
        };
        (Active(self.clone()), deadline)
    }
}

/// A request in flight; its end makes the connection idle again.
struct Active(Arc<ConnState>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.touch();
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Connections per source address (D-065 #8).
type SourceCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// One of a source address's connection slots.
struct SourceSlot {
    counts: SourceCounts,
    ip: IpAddr,
}

impl SourceSlot {
    fn take(counts: &SourceCounts, ip: IpAddr, max: usize) -> Option<Self> {
        let mut map = counts.lock().unwrap_or_else(|p| p.into_inner());
        let count = map.entry(ip).or_default();
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(Self {
            counts: counts.clone(),
            ip,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// gRPC connections by peer, so a call finds its connection's state.
type ConnRegistry = Arc<Mutex<HashMap<SocketAddr, Arc<ConnState>>>>;

/// Removes a connection from the registry when it closes.
struct Registered {
    registry: ConnRegistry,
    peer: SocketAddr,
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.peer);
    }
}

/// A TCP connection holding one of the listeners' connection slots and one
/// of its source's; it reads as closed once idle (D-065 #8). gRPC sends
/// `GOAWAY` first. HTTP/1.1 closes the TCP connection.
struct Permitted {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    _source: SourceSlot,
    _registered: Option<Registered>,
    state: Arc<ConnState>,
    idle: Duration,
    /// HTTP/1.1: request bytes count as activity; gRPC: only streams do
    /// (keepalive `PING`s never keep a connection open).
    bytes_are_activity: bool,
    timer: Pin<Box<tokio::time::Sleep>>,
    closed: bool,
    /// gRPC idle close. HTTP/1.1 stays at [`Goaway::Wait`] and ends on EOF.
    goaway: Goaway,
}

/// HTTP/2 GOAWAY, `NO_ERROR`, last-stream-id `2^31-1` (no new streams).
const GOAWAY_FRAME: [u8; 17] = [
    0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0,
];

enum Goaway {
    Wait,
    Write(usize),
    Flush,
    Shutdown,
}

impl Permitted {
    /// Whether the connection has been idle long enough to close.
    fn idle_expired(&self) -> bool {
        self.state.open.load(Ordering::SeqCst) == 0 && self.state.last().elapsed() >= self.idle
    }
}

/// Writes the gRPC idle `GOAWAY`, then ends the read side.
fn poll_goaway(stream: &mut Permitted, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    loop {
        match stream.goaway {
            Goaway::Wait => return Poll::Pending,
            Goaway::Write(sent) if sent >= GOAWAY_FRAME.len() => stream.goaway = Goaway::Flush,
            Goaway::Write(sent) => {
                match Pin::new(&mut stream.stream).poll_write(cx, &GOAWAY_FRAME[sent..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "goaway",
                        )));
                    }
                    Poll::Ready(Ok(n)) => stream.goaway = Goaway::Write(sent + n),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Goaway::Flush => match Pin::new(&mut stream.stream).poll_flush(cx) {
                Poll::Ready(Ok(())) => stream.goaway = Goaway::Shutdown,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            },
            Goaway::Shutdown => match Pin::new(&mut stream.stream).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    stream.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            },
        }
    }
}

impl AsyncRead for Permitted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        if !this.bytes_are_activity && !matches!(this.goaway, Goaway::Wait) {
            return poll_goaway(this, cx);
        }
        let before = buf.filled().len();
        if let Poll::Ready(result) = Pin::new(&mut this.stream).poll_read(cx, buf) {
            if this.bytes_are_activity && buf.filled().len() > before {
                this.state.touch();
            }
            return Poll::Ready(result);
        }
        loop {
            if this.idle_expired() {
                // A frame that arrived as the timer fired is delivered first,
                // so the idle close does not leave it unread (a TCP RST).
                let before = buf.filled().len();
                if let Poll::Ready(result) = Pin::new(&mut this.stream).poll_read(cx, buf) {
                    if this.bytes_are_activity && buf.filled().len() > before {
                        this.state.touch();
                    }
                    return Poll::Ready(result);
                }
                if this.bytes_are_activity {
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
                this.goaway = Goaway::Write(0);
                return poll_goaway(this, cx);
            }
            let next = if this.state.open.load(Ordering::SeqCst) == 0 {
                this.state.last() + this.idle
            } else {
                Instant::now() + this.idle
            };
            this.timer
                .as_mut()
                .reset(tokio::time::Instant::from_std(next));
            if this.timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
    }
}

impl AsyncWrite for Permitted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

impl Connected for Permitted {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> TcpConnectInfo {
        self.stream.connect_info()
    }
}

/// gRPC: a call whose handling (reading and decoding the body included) is
/// not done within the deadline answers `DEADLINE_EXCEEDED` (D-063 #17).
#[derive(Clone)]
struct BodyDeadline {
    after: Duration,
    telemetry: Option<Arc<Telemetry>>,
    /// The connections, so a call counts as activity and its connection's
    /// first call gets its deadline from accept (D-065 #8).
    conns: ConnRegistry,
}

impl<S> tower::Layer<S> for BodyDeadline {
    type Service = Deadline<S>;

    fn layer(&self, inner: S) -> Deadline<S> {
        Deadline {
            inner,
            deadline: self.clone(),
        }
    }
}

#[derive(Clone)]
struct Deadline<S> {
    inner: S,
    deadline: BodyDeadline,
}

impl<S, B> tower::Service<http::Request<B>> for Deadline<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<tonic::body::Body>>,
    S::Future: Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let BodyDeadline {
            after,
            telemetry,
            conns,
        } = self.deadline.clone();
        let state = request
            .extensions()
            .get::<TcpConnectInfo>()
            .and_then(TcpConnectInfo::remote_addr)
            .and_then(|peer| {
                conns
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&peer)
                    .cloned()
            });
        let (active, after) = match state {
            Some(state) => {
                let (active, deadline) = state.begin(after);
                (Some(active), deadline)
            }
            None => (None, after),
        };
        let call = self.inner.call(request);
        Box::pin(async move {
            let _active = active;
            match tokio::time::timeout(after, call).await {
                Ok(result) => result,
                Err(_) => {
                    if let Some(telemetry) = telemetry {
                        telemetry.count_otlp_refused();
                    }
                    warn!("OTLP gRPC request body not read in time");
                    Ok(
                        tonic::Status::deadline_exceeded("request body not read in time")
                            .into_http(),
                    )
                }
            }
        })
    }
}

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
    body_read: Duration,
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

/// An answer after which the connection is closed.
fn closing(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = plain(status);
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
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
        let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
        int64_strings_to_numbers(&mut value);
        serde_json::from_value(value).ok()
    } else {
        M::decode(body).ok()
    }
}

/// OTLP/JSON encodes int64 as a decimal string (the protobuf JSON mapping),
/// and the `opentelemetry-proto` serde derive reads the data point and
/// exemplar oneof member `asInt` only as a JSON number: a string dropped the
/// metric's data, so the point was stored as 0. Every `asInt` member that
/// holds an int64 string becomes that number; anything else is left for the
/// decoder to refuse.
fn int64_strings_to_numbers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, member) in map.iter_mut() {
                if key == "asInt" {
                    if let Some(number) = member.as_str().and_then(|s| s.parse::<i64>().ok()) {
                        *member = serde_json::Value::from(number);
                        continue;
                    }
                }
                int64_strings_to_numbers(member);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(int64_strings_to_numbers),
        _ => {}
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
    body_read: Duration,
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
    let read = Limited::new(request.into_body(), WIRE_MAX).collect();
    let body = match tokio::time::timeout(body_read, read).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(_)) => return plain(StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => {
            receiver.telemetry.count_otlp_refused();
            warn!(%peer, "OTLP/HTTP request body not read in time");
            return closing(StatusCode::REQUEST_TIMEOUT);
        }
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

/// What both listeners share: the source check (9.5) and the connection
/// slots (D-063 #17).
#[derive(Clone)]
struct Gate {
    net: Arc<dyn Network>,
    slots: Arc<Semaphore>,
    telemetry: Arc<Telemetry>,
    /// D-065 #8: connections per source address.
    sources: SourceCounts,
    per_source: usize,
    idle: Duration,
}

/// Accepts connections that pass the source check (9.5) while a connection
/// slot and one of the source's slots are free; others are closed at once
/// (and counted when over a cap). `registry` (gRPC) maps the peer to its
/// connection state.
async fn accept_checked(
    listener: &TcpListener,
    gate: &Gate,
    registry: Option<&ConnRegistry>,
) -> Option<(Permitted, SocketAddr)> {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                if !accept_peer(gate.net.as_ref(), peer.ip()) {
                    warn!(%peer, "OTLP connection refused: source is not on a Docker bridge");
                    continue;
                }
                let Some(source) = SourceSlot::take(&gate.sources, peer.ip(), gate.per_source)
                else {
                    gate.telemetry.count_otlp_refused();
                    warn!(%peer, "OTLP connection refused: too many connections from this source");
                    continue;
                };
                match gate.slots.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let state = ConnState::new();
                        let registered = registry.map(|registry| {
                            registry
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .insert(peer, state.clone());
                            Registered {
                                registry: registry.clone(),
                                peer,
                            }
                        });
                        return Some((
                            Permitted {
                                stream,
                                _permit: permit,
                                _source: source,
                                _registered: registered,
                                state,
                                idle: gate.idle,
                                bytes_are_activity: registry.is_none(),
                                timer: Box::pin(tokio::time::sleep(gate.idle)),
                                closed: false,
                                goaway: Goaway::Wait,
                            },
                            peer,
                        ));
                    }
                    Err(_) => {
                        gate.telemetry.count_otlp_refused();
                        warn!(%peer, "OTLP connection refused: too many connections");
                    }
                }
            }
            Err(err) => {
                warn!(error = %err, "OTLP accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn serve_http(listener: TcpListener, receiver: Receiver, gate: Gate) -> JoinHandle<()> {
    tokio::spawn(async move {
        // D-066 #6 (QA_M2 run 3 O1): hyper's header-read timer also runs
        // while a kept-alive connection waits for its next request, so it is
        // the idle time (30 s), never shorter.
        let header_read = gate.idle;
        while let Some((stream, peer)) = accept_checked(&listener, &gate, None).await {
            let receiver = receiver.clone();
            let state = stream.state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let receiver = receiver.clone();
                    let (active, body_read) = state.begin(receiver.body_read);
                    async move {
                        let response = handle_http(receiver, peer, req, body_read).await;
                        drop(active);
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(header_read)
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    })
}

fn serve_grpc(listener: TcpListener, receiver: Receiver, gate: Gate) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (tx, rx) = mpsc::channel::<std::io::Result<Permitted>>(16);
        let conns: ConnRegistry = Arc::default();
        let deadline = BodyDeadline {
            after: receiver.body_read,
            telemetry: Some(gate.telemetry.clone()),
            conns: conns.clone(),
        };
        // QA_M2 G4: the accept task owns the listener; it must end with this
        // task (an unbind aborts it), or the port stays taken and every
        // rebind fails with `Address in use`.
        let accept = AbortOnDrop(tokio::spawn(async move {
            while let Some((stream, _)) = accept_checked(&listener, &gate, Some(&conns)).await {
                if tx.send(Ok(stream)).await.is_err() {
                    return;
                }
            }
        }));
        let limit = DECOMPRESSED_MAX;
        let result = tonic::transport::Server::builder()
            .concurrency_limit_per_connection(32)
            .initial_connection_window_size(CONNECTION_IN_FLIGHT)
            .http2_keepalive_interval(Some(KEEPALIVE_INTERVAL))
            .http2_keepalive_timeout(Some(KEEPALIVE_TIMEOUT))
            .layer(deadline)
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
        drop(accept);
        if let Err(err) = result {
            warn!(error = %err, "OTLP gRPC server ended");
        }
    })
}

/// Aborts a task when dropped (also when its owner is aborted).
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keeps the listeners bound to the gateway while the checks pass.
pub struct Listeners {
    pub telemetry: Arc<Telemetry>,
    pub net: Arc<dyn Network>,
    pub firewall: Arc<dyn FirewallCheck>,
    pub gateway_iface: String,
    pub grpc_port: u16,
    pub http_port: u16,
    pub limits: OtlpLimits,
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
            limits: OtlpLimits::default(),
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
            body_read: self.limits.body_read,
        };
        let gate = Gate {
            net: self.net.clone(),
            slots: Arc::new(Semaphore::new(self.limits.max_connections)),
            telemetry: self.telemetry.clone(),
            sources: Arc::default(),
            per_source: self.limits.per_source,
            idle: self.limits.idle,
        };
        let tasks = [
            serve_grpc(grpc, receiver.clone(), gate.clone()),
            serve_http(http, receiver, gate),
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
    use crate::local::telemetry::otlp::tests::{otlp_span, t0, trace_request};
    use crate::local::telemetry::store::{Kind, ScanSpec};
    use crate::local::telemetry::test_support;
    use crate::signed_plan::test_support::temp_dir;
    use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// OTLP/JSON encodes int64 as a string (the protobuf JSON mapping every
    /// SDK uses); `asInt` must keep its value, as a JSON number does.
    #[test]
    fn json_as_int_strings_keep_their_value() {
        use opentelemetry_proto::tonic::metrics::v1::{metric, number_data_point};
        let body = |value: &str| {
            format!(
                r#"{{"resourceMetrics":[{{"scopeMetrics":[{{"metrics":[
                {{"name":"qa.sum","sum":{{"aggregationTemporality":2,"isMonotonic":true,
                  "dataPoints":[{{"asInt":{value},"timeUnixNano":"1790000000000000000"}}]}}}},
                {{"name":"qa.gauge","gauge":{{"dataPoints":[{{"asInt":{value}}}]}}}}]}}]}}]}}"#
            )
        };
        for value in ["\"42\"", "42"] {
            let request: ExportMetricsServiceRequest =
                decode(true, body(value).as_bytes()).expect("decodes");
            let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;
            let Some(metric::Data::Sum(sum)) = &metrics[0].data else {
                panic!("sum")
            };
            assert_eq!(
                sum.data_points[0].value,
                Some(number_data_point::Value::AsInt(42)),
                "{value}"
            );
            let Some(metric::Data::Gauge(gauge)) = &metrics[1].data else {
                panic!("gauge")
            };
            assert_eq!(
                gauge.data_points[0].value,
                Some(number_data_point::Value::AsInt(42)),
                "{value}"
            );
        }
        // Not an int64: the value is refused as before (no point), never 0.
        let request: ExportMetricsServiceRequest =
            decode(true, body("\"4x2\"").as_bytes()).unwrap_or_default();
        let value = request
            .resource_metrics
            .first()
            .and_then(|r| r.scope_metrics.first())
            .and_then(|s| s.metrics.first())
            .and_then(|m| match &m.data {
                Some(metric::Data::Sum(sum)) => sum.data_points.first().and_then(|p| p.value),
                _ => None,
            });
        assert_ne!(value, Some(number_data_point::Value::AsInt(0)));
    }

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
            limits: OtlpLimits::default(),
        }
    }

    /// D-063 #17: the normative numbers.
    #[test]
    fn default_limits_are_the_contract_numbers() {
        let limits = OtlpLimits::default();
        assert_eq!(limits.max_connections, 64);
        assert_eq!(limits.body_read, Duration::from_secs(30));
        assert_eq!(CONNECTION_IN_FLIGHT, 16 * 1024 * 1024);
    }

    /// D-063 #17: connections over the cap (both listeners together) are
    /// closed at accept and counted; a freed slot is reused.
    #[tokio::test]
    async fn connections_over_the_cap_are_closed_and_counted() {
        let dir = temp_dir("otlp-cap");
        let t = test_support::open(dir.join("telemetry"));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.limits.max_connections = 2;
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        let held_http = TcpStream::connect(&listen.http_listen).await.unwrap();
        let held_grpc = TcpStream::connect(&listen.grpc_listen).await.unwrap();
        // Let the accept loops take both slots.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut refused = TcpStream::connect(&listen.http_listen).await.unwrap();
        let _ = refused
            .write_all(b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await;
        let mut buf = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(2), refused.read_to_end(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
        assert_eq!(t.otlp_connections_refused(), 1);

        drop(held_http);
        drop(held_grpc);
        let mut status = 0;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            status = http_post(&listen.http_listen, "/v1/traces", "text/plain", "x")
                .await
                .0;
            if status != 0 {
                break;
            }
        }
        assert_eq!(status, 415);
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// D-063 #17: a body not read completely in time closes the connection.
    #[tokio::test]
    async fn a_slow_http_body_is_cut_off() {
        let dir = temp_dir("otlp-slow");
        let t = test_support::open(dir.join("telemetry"));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.limits.body_read = Duration::from_millis(200);
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        let mut stream = TcpStream::connect(&listen.http_listen).await.unwrap();
        stream
            .write_all(
                b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(_))), "{read:?}");
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 408"), "{text}");
        assert_eq!(t.otlp_connections_refused(), 1);
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// D-063 #17: a gRPC call whose body is not read in time ends with
    /// `DEADLINE_EXCEEDED`.
    #[tokio::test]
    async fn grpc_deadline_answers_deadline_exceeded() {
        use tonic::codegen::http;
        use tower::{Layer, Service, ServiceExt};
        let never = tower::service_fn(|_: http::Request<tonic::body::Body>| async {
            std::future::pending::<
                Result<http::Response<tonic::body::Body>, std::convert::Infallible>,
            >()
            .await
        });
        let mut svc = BodyDeadline {
            after: Duration::from_millis(50),
            telemetry: None,
            conns: Arc::default(),
        }
        .layer(never);
        let response = svc
            .ready()
            .await
            .unwrap()
            .call(http::Request::new(tonic::body::Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            tonic::Status::from_header_map(response.headers()).map(|s| s.code()),
            Some(tonic::Code::DeadlineExceeded)
        );
    }

    /// D-065 #8: the normative numbers.
    #[test]
    fn connection_limits_are_the_v1_1_7_numbers() {
        let limits = OtlpLimits::default();
        assert_eq!(limits.idle, Duration::from_secs(30));
        assert_eq!(limits.per_source, 8);
        assert_eq!(KEEPALIVE_INTERVAL, Duration::from_secs(30));
        assert_eq!(KEEPALIVE_TIMEOUT, Duration::from_secs(10));
    }

    /// D-065 #8: a connection with no request for the idle time is closed
    /// (HTTP/1.1 and gRPC alike).
    #[tokio::test]
    async fn an_idle_connection_is_closed() {
        let dir = temp_dir("otlp-idle");
        let t = test_support::open(dir.join("telemetry"));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.limits.idle = Duration::from_millis(200);
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        for addr in [&listen.http_listen, &listen.grpc_listen] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut buf = Vec::new();
            let read =
                tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
            assert!(matches!(read, Ok(Ok(_)) | Ok(Err(_))), "{addr}: {read:?}");
        }
        // A kept-alive HTTP connection is closed once idle after a request.
        let mut stream = TcpStream::connect(&listen.http_listen).await.unwrap();
        stream
            .write_all(b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(_))), "{read:?}");
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 415"));
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// D-065 #8: an idle OTLP/gRPC connection is closed with HTTP/2 `GOAWAY`,
    /// not a bare TCP drop. The idle duration is the listener's `limits.idle`
    /// (30 s unless a test shortens it).
    #[tokio::test]
    async fn an_idle_grpc_close_sends_goaway() {
        let dir = temp_dir("otlp-goaway");
        let t = test_support::open(dir.join("telemetry"));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.limits.idle = Duration::from_millis(200);
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        let mut stream = TcpStream::connect(&listen.grpc_listen).await.unwrap();
        let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        // Empty SETTINGS so the handshake can finish before the idle close.
        preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        stream.write_all(&preface).await.unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(_))),
            "idle close was not a finished read: {read:?} buf={buf:?}"
        );
        assert!(
            http2_has_goaway(&buf),
            "idle close dropped the connection without GOAWAY: {buf:?}"
        );
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A GOAWAY frame (type 0x7, stream 0) somewhere in an HTTP/2 byte stream
    /// that starts on a frame boundary.
    fn http2_has_goaway(buf: &[u8]) -> bool {
        let mut i = 0;
        while i + 9 <= buf.len() {
            let len =
                ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | buf[i + 2] as usize;
            if len > 16 * 1024 * 1024 {
                return false;
            }
            let kind = buf[i + 3];
            let stream =
                u32::from_be_bytes([buf[i + 5], buf[i + 6], buf[i + 7], buf[i + 8]]) & 0x7fff_ffff;
            if kind == 0x7 && stream == 0 {
                return true;
            }
            let next = i + 9 + len;
            if next > buf.len() {
                break;
            }
            i = next;
        }
        false
    }

    /// D-066 #6 (QA_M2 run 3 O1): OTLP/HTTP has no header-read timeout
    /// shorter than the idle time; a silent connection lives until it (the
    /// old fixed 10 s closed it early). Real time: the bug was a fixed 10 s.
    #[tokio::test]
    async fn a_silent_http_connection_is_not_closed_before_the_idle_time() {
        let dir = temp_dir("otlp-http-idle");
        let t = test_support::open(dir.join("telemetry"));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.limits.idle = Duration::from_secs(11);
        l.limits.body_read = Duration::from_secs(11);
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        let accepted = Instant::now();
        let mut stream = TcpStream::connect(&listen.http_listen).await.unwrap();
        let mut buf = Vec::new();
        let early =
            tokio::time::timeout(Duration::from_millis(10_500), stream.read_to_end(&mut buf)).await;
        assert!(early.is_err(), "closed after {:?}", accepted.elapsed());
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(_)) | Ok(Err(_))), "{read:?}");
        assert!(accepted.elapsed() >= Duration::from_secs(11));
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// D-065 #8: at most `per_source` concurrent connections per source
    /// address; the next one is closed at accept and counted.
    #[tokio::test]
    async fn connections_per_source_are_capped() {
        let dir = temp_dir("otlp-per-source");
        let t = test_support::open(dir.join("telemetry"));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.limits.per_source = 2;
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        let held_http = TcpStream::connect(&listen.http_listen).await.unwrap();
        let held_grpc = TcpStream::connect(&listen.grpc_listen).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut refused = TcpStream::connect(&listen.http_listen).await.unwrap();
        let mut buf = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(2), refused.read_to_end(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
        assert_eq!(t.otlp_connections_refused(), 1);
        drop(held_http);
        drop(held_grpc);
        let mut status = 0;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            status = http_post(&listen.http_listen, "/v1/traces", "text/plain", "x")
                .await
                .0;
            if status != 0 {
                break;
            }
        }
        assert_eq!(status, 415);
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// D-065 #8: the first request's body deadline starts at accept, so a
    /// client that waits before sending gets less time.
    #[tokio::test]
    async fn the_first_request_deadline_starts_at_accept() {
        let dir = temp_dir("otlp-accept-deadline");
        let t = test_support::open(dir.join("telemetry"));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.limits.body_read = Duration::from_millis(600);
        let bound = l.reconcile(None).await.expect("bound");
        let listen = t.otlp();
        let mut stream = TcpStream::connect(&listen.http_listen).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let sent = Instant::now();
        stream
            .write_all(
                b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(_))), "{read:?}");
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 408"));
        assert!(
            sent.elapsed() < Duration::from_millis(450),
            "{:?}",
            sent.elapsed()
        );
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// QA_M2 G4: unbinding releases both ports, so the next rebind on the
    /// same ports succeeds instead of `Address in use` every 30 s.
    #[tokio::test]
    async fn an_unbind_releases_the_ports_for_a_rebind() {
        let dir = temp_dir("otlp-rebind");
        let t = test_support::open(dir.join("telemetry"));
        let free = || {
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };
        let firewall = Arc::new(Firewall(AtomicBool::new(true)));
        let mut l = listeners(t.clone(), Some("test-br"), true);
        l.firewall = firewall.clone();
        l.grpc_port = free();
        l.http_port = free();
        let bound = l.reconcile(None).await;
        assert!(bound.is_some());
        let listen = t.otlp();
        // Let the listener tasks start (their accept loops own the sockets).
        tokio::time::sleep(Duration::from_millis(100)).await;
        firewall.0.store(false, Ordering::SeqCst);
        let bound = l.reconcile(bound).await;
        assert!(bound.is_none());
        assert!(t.otlp().grpc_listen.is_empty());
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Nothing listens any more (a leftover accept task would).
        for addr in [&listen.grpc_listen, &listen.http_listen] {
            assert!(
                TcpStream::connect(addr).await.is_err(),
                "{addr} still listens"
            );
        }
        firewall.0.store(true, Ordering::SeqCst);
        let bound = l.reconcile(bound).await.expect("rebound on the same ports");
        assert!(!t.otlp().grpc_listen.is_empty());
        bound.tasks.iter().for_each(JoinHandle::abort);
        std::fs::remove_dir_all(dir).unwrap();
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
              "startTimeUnixNano": t0().to_string(),
              "endTimeUnixNano": (t0() + 100_000_000).to_string()}]}]}]});
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
