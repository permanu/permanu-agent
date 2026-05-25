use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use prost::Message;
use tokio::sync::watch;
use tonic::transport::Channel;
use tracing::warn;

use crate::{
    config::Config,
    proto::agent::v1::{agent_service_client::AgentServiceClient, LogBatch, LogEntry},
    spool::{DiskSpool, SpoolConfig, SpoolCounters},
    timeutil::now_unix_nanos,
};

#[derive(Debug)]
pub struct LogForwarder {
    spool: DiskSpool,
}

impl LogForwarder {
    pub fn open(cfg: &Config) -> Result<Self> {
        let dir = cfg.spool_dir.join("logs");
        let spool = DiskSpool::open(SpoolConfig {
            dir,
            max_bytes: cfg.log_spool_max_bytes,
            max_segment_bytes: cfg.log_spool_segment_bytes,
        })
        .context("open log spool")?;
        Ok(Self { spool })
    }

    pub fn push(&self, entry: LogEntry) -> Result<()> {
        self.spool
            .append_bytes(&entry.encode_to_vec())
            .context("append log entry to spool")
    }

    pub fn counters(&self) -> SpoolCounters {
        self.spool.counters()
    }
}

pub async fn run(
    cfg: Arc<Config>,
    forwarder: Arc<LogForwarder>,
    client: AgentServiceClient<Channel>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if let Err(err) = drain_once(cfg.clone(), forwarder.clone(), client.clone()).await {
            warn!(error = ?err, "log spool drain failed");
        }

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

pub fn agent_log(
    level: &str,
    message: impl Into<String>,
    fields: HashMap<String, String>,
) -> LogEntry {
    LogEntry {
        timestamp_ns: now_unix_nanos(),
        source: "agent".to_string(),
        level: level.to_string(),
        message: message.into(),
        fields,
        app_id: String::new(),
        deployment_id: String::new(),
    }
}

pub struct RedactedLogMessage {
    pub message: String,
    pub was_redacted: bool,
}

pub fn redact_log_message(message: &str) -> RedactedLogMessage {
    let words: Vec<&str> = message.split_whitespace().collect();
    let mut redacted = Vec::with_capacity(words.len());
    let mut redact_next = false;
    let mut was_redacted = false;

    for word in words {
        let lower = word.to_ascii_lowercase();
        if redact_next {
            redacted.push("[REDACTED]".to_string());
            redact_next = false;
            was_redacted = true;
            continue;
        }

        if lower.trim_end_matches(':') == "authorization" {
            redacted.push(word.to_string());
            continue;
        }

        if is_secret_assignment(&lower) {
            redacted.push(redact_assignment(word));
            redact_next = word.ends_with(':');
            was_redacted = true;
            continue;
        }

        if is_secret_flag(&lower) || is_secret_label(&lower) || lower == "bearer" {
            redacted.push(word.to_string());
            redact_next = true;
            continue;
        }

        redacted.push(word.to_string());
    }

    RedactedLogMessage {
        message: redacted.join(" "),
        was_redacted,
    }
}

fn is_secret_assignment(lower: &str) -> bool {
    SECRET_MARKERS.iter().any(|marker| {
        lower.starts_with(&format!("{marker}=")) || lower.starts_with(&format!("{marker}:"))
    })
}

fn is_secret_flag(lower: &str) -> bool {
    matches!(
        lower,
        "--token" | "--password" | "--secret" | "--api-key" | "--apikey" | "-token" | "-password"
    )
}

fn is_secret_label(lower: &str) -> bool {
    SECRET_MARKERS
        .iter()
        .any(|marker| lower.trim_end_matches(':') == *marker)
}

fn redact_assignment(word: &str) -> String {
    let separator = if word.contains('=') { '=' } else { ':' };
    word.split_once(separator)
        .map(|(key, _)| format!("{key}{separator}[REDACTED]"))
        .unwrap_or_else(|| "[REDACTED]".to_string())
}

const SECRET_MARKERS: &[&str] = &[
    "authorization",
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "client_secret",
    "database_url",
];

async fn drain_once(
    cfg: Arc<Config>,
    forwarder: Arc<LogForwarder>,
    mut client: AgentServiceClient<Channel>,
) -> Result<()> {
    let batch = forwarder
        .spool
        .read_batch(100, 1024 * 1024)
        .context("read log spool batch")?;
    if batch.records.is_empty() {
        return Ok(());
    }

    let mut decode_errors = 0_usize;
    let mut entries = Vec::with_capacity(batch.records.len());
    for record in &batch.records {
        match LogEntry::decode(record.payload.as_slice()) {
            Ok(entry) => entries.push(entry),
            Err(err) => {
                decode_errors += 1;
                warn!(error = ?err, "dropping corrupt spooled log record");
            }
        }
    }

    if entries.is_empty() {
        forwarder
            .spool
            .ack(batch.ack)
            .context("ack corrupt log batch")?;
        return Ok(());
    }

    if decode_errors > 0 {
        warn!(decode_errors, "decoded log batch with corrupt records");
    }

    let request = cfg.attach_auth(tonic::Request::new(tokio_stream::iter(vec![LogBatch {
        server_id: cfg.server_id.clone(),
        entries,
    }])))?;
    let ack = client
        .push_logs(request)
        .await
        .context("push logs rpc")?
        .into_inner();
    if !ack.accepted {
        anyhow::bail!("backend rejected logs: {}", ack.error_message);
    }
    forwarder
        .spool
        .ack(batch.ack)
        .context("ack log spool batch")?;
    Ok(())
}
