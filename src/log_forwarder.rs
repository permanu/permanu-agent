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
