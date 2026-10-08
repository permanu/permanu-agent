use super::*;
use crate::local::runner::{EventLines, RunnerFailure, READ_TIMEOUT};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Instant;

struct Delayed {
    delay: Duration,
    response: Value,
    dropped: Arc<AtomicBool>,
}
struct DropMarker(Arc<AtomicBool>);
impl Drop for DropMarker {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[tonic::async_trait]
impl Runner for Delayed {
    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value, RunnerFailure> {
        assert_eq!(
            request,
            json!({"op":"compose_v1_capabilities","payload":{"schema_version":1}})
        );
        // Mirror SocketRunner's timeout/drop boundary, with deterministic time.
        tokio::time::timeout(timeout, async {
            let _guard = DropMarker(self.dropped.clone());
            tokio::time::sleep(self.delay).await;
            Ok(self.response.clone())
        })
        .await
        .map_err(|_| RunnerFailure::transport("fixture timeout"))?
    }
    async fn open(&self, _: Value) -> Result<EventLines, RunnerFailure> {
        panic!("capability checks never open a stream")
    }
}
fn fixture(delay: u64, response: Value) -> Delayed {
    Delayed {
        delay: Duration::from_secs(delay),
        response,
        dropped: Arc::new(AtomicBool::new(false)),
    }
}
fn ready() -> Value {
    json!({"ok":true,"data":{"schema_version":1,"standing_release":true}})
}

#[tokio::test(start_paused = true)]
async fn capability_accepts_valid_live_check_after_two_seconds() {
    let runner = fixture(16, ready());
    let start = Instant::now();
    assert!(available(&runner).await);
    assert_eq!(start.elapsed(), Duration::from_secs(16));
    assert!(runner.dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn capability_timeout_is_bounded_and_cancels_exchange() {
    let runner = fixture(31, ready());
    let start = Instant::now();
    assert!(!available(&runner).await);
    assert_eq!(start.elapsed(), READ_TIMEOUT);
    assert!(runner.dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn capability_caller_cancellation_drops_exchange() {
    let runner = fixture(16, ready());
    let start = Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), available(&runner))
            .await
            .is_err()
    );
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert!(runner.dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn capability_delayed_refusal_or_malformed_never_becomes_ready() {
    for response in [
        json!({"ok":false,"data":{"schema_version":1,"standing_release":true}}),
        json!({"ok":true,"data":{"schema_version":1,"standing_release":false}}),
        json!({"ok":true,"data":{"schema_version":2,"standing_release":true}}),
        json!({"ok":true,"data":{"schema_version":1,"standing_release":true,"extra":true}}),
        json!({"ok":true,"data":{"schema_version":1}}),
    ] {
        let runner = fixture(16, response);
        let start = Instant::now();
        assert!(!available(&runner).await);
        assert_eq!(start.elapsed(), Duration::from_secs(16));
        assert!(runner.dropped.load(Ordering::SeqCst));
    }
}
