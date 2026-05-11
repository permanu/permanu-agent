use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_timestamp() -> prost_types::Timestamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    prost_types::Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}

pub fn now_unix_nanos() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs() as i64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now.subsec_nanos() as i64)
}
