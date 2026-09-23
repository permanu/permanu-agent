//! The alert evaluator's view of the telemetry store (agent-protocol.md
//! 10.3): metric and log rules query the store like any client would.

use std::sync::Arc;

use futures::StreamExt;

use super::alerts::AlertSource;
use crate::local::telemetry::query::StoreQueries;
use crate::local::telemetry::Telemetry;
use crate::proto::agent::v2::{
    log_query_response, metric_query_response, LogCondition, LogLevel, LogQuery, MetricCondition,
    MetricQuery, TimeRange,
};

/// Log rules count at most this many records per evaluation.
const MAX_LOG_COUNT: u32 = 10_000;

pub struct StoreSource {
    pub queries: StoreQueries,
    pub telemetry: Arc<Telemetry>,
}

impl StoreSource {
    pub fn new(telemetry: Arc<Telemetry>) -> Self {
        Self {
            queries: StoreQueries::new(telemetry.clone()),
            telemetry,
        }
    }
}

fn range(now: i64, window: i64) -> Option<TimeRange> {
    Some(TimeRange {
        start: Some(prost_types::Timestamp {
            seconds: now - window,
            nanos: 0,
        }),
        end: Some(prost_types::Timestamp {
            seconds: now,
            nanos: 0,
        }),
    })
}

#[tonic::async_trait]
impl AlertSource for StoreSource {
    async fn metric(&self, condition: &MetricCondition, now: i64) -> Vec<f64> {
        let window = condition.window.map_or(300, |d| d.seconds).max(30);
        let query = MetricQuery {
            name: condition.metric.clone(),
            matchers: condition.matchers.clone(),
            range: range(now, window),
            step: Some(prost_types::Duration {
                seconds: window,
                nanos: 0,
            }),
            aggregation: condition.aggregation,
            max_series: 100,
            ..Default::default()
        };
        let Ok(mut stream) = self.queries.query_metrics(query).await else {
            return Vec::new();
        };
        let mut values = Vec::new();
        while let Some(Ok(frame)) = stream.next().await {
            match frame.frame {
                Some(metric_query_response::Frame::Batch(batch)) => {
                    values.extend(
                        batch
                            .series
                            .iter()
                            .filter_map(|series| series.points.last().map(|p| p.value)),
                    );
                }
                Some(metric_query_response::Frame::Status(_)) | None => {}
            }
        }
        values
    }

    async fn log_count(&self, condition: &LogCondition, now: i64) -> u64 {
        let window = condition.window.map_or(300, |d| d.seconds).max(60);
        let min = condition.min_level;
        let levels = if min <= LogLevel::Unspecified as i32 {
            Vec::new()
        } else {
            (min..=LogLevel::Fatal as i32).collect()
        };
        let query = LogQuery {
            scope: condition.scope.clone(),
            contains: condition.contains.clone(),
            regex: condition.regex.clone(),
            range: range(now, window),
            limit: MAX_LOG_COUNT,
            levels,
            ..Default::default()
        };
        let Ok(mut stream) = self.queries.query_logs(query).await else {
            return 0;
        };
        let mut count = 0u64;
        while let Some(Ok(frame)) = stream.next().await {
            if let Some(log_query_response::Frame::Batch(batch)) = frame.frame {
                count += batch.records.len() as u64;
            }
        }
        count
    }

    fn dropped_total(&self) -> u64 {
        self.telemetry
            .usage()
            .kinds
            .iter()
            .map(|(usage, _)| usage.counters.dropped_total)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::local::sched::{AgentLogs, LogIdentity};
    use crate::local::telemetry::records::{MetricSample, TAG_METRIC};
    use crate::local::telemetry::store::{Kind, Producer};
    use crate::proto::agent::v2::{ComparisonOp, LogSourceType, Scope};
    use crate::signed_plan::test_support::temp_dir;

    const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[tokio::test]
    async fn agent_logs_are_redacted_stored_and_counted_by_log_rules() {
        let dir = temp_dir("sched-source-logs");
        let telemetry = crate::local::telemetry::test_support::open(dir.clone());
        let logs = AgentLogs {
            telemetry: Some(telemetry.clone()),
            host: "h".to_owned(),
        };
        let identity = LogIdentity {
            source: "cron:nightly".to_owned(),
            project_id: PROJECT.to_owned(),
            run_id: "01a0cdb5-3500-7f01-8000-000000000001".to_owned(),
            ..Default::default()
        };
        logs.write(
            LogSourceType::Cron,
            LogLevel::Error,
            "cron run failed: password=hunter2hunter2",
            &identity,
        );
        logs.write(
            LogSourceType::Cron,
            LogLevel::Info,
            "cron run started",
            &identity,
        );
        telemetry.sync().await;
        let source = StoreSource::new(telemetry.clone());
        let condition = |min: LogLevel, contains: &str| LogCondition {
            scope: Some(Scope {
                project_id: PROJECT.to_owned(),
                ..Default::default()
            }),
            min_level: min as i32,
            contains: contains.to_owned(),
            window: Some(prost_types::Duration {
                seconds: 300,
                nanos: 0,
            }),
            ..Default::default()
        };
        assert_eq!(
            source
                .log_count(&condition(LogLevel::Unspecified, ""), now() + 1)
                .await,
            2
        );
        assert_eq!(
            source
                .log_count(&condition(LogLevel::Error, ""), now() + 1)
                .await,
            1
        );
        assert_eq!(
            source
                .log_count(&condition(LogLevel::Unspecified, "hunter2"), now() + 1)
                .await,
            0
        );
        let mut stream = source
            .queries
            .query_logs(LogQuery {
                run_id: identity.run_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut records = Vec::new();
        while let Some(Ok(frame)) = stream.next().await {
            if let Some(log_query_response::Frame::Batch(batch)) = frame.frame {
                records.extend(batch.records);
            }
        }
        assert_eq!(records.len(), 2);
        assert!(records[0].redacted);
        assert_eq!(records[0].ingest, "agent");
        assert_eq!(records[0].source_type, LogSourceType::Cron as i32);
        telemetry.close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn metric_rules_see_the_latest_value_per_series() {
        let dir = temp_dir("sched-source-metrics");
        let telemetry = crate::local::telemetry::test_support::open(dir.clone());
        let at = now();
        for (offset, value) in [(20, 40.0), (5, 97.0)] {
            let ts = (at - offset) * 1_000_000_000;
            let sample = MetricSample {
                name: "host.cpu.percent".to_owned(),
                kind: 1,
                source: 1,
                value,
                ..Default::default()
            };
            telemetry.submit(
                Kind::Metrics,
                Producer::System,
                ts,
                TAG_METRIC,
                crate::local::telemetry::records::encode(&sample),
                false,
            );
        }
        telemetry.sync().await;
        let source = StoreSource::new(telemetry.clone());
        let condition = MetricCondition {
            metric: "host.cpu.percent".to_owned(),
            window: Some(prost_types::Duration {
                seconds: 60,
                nanos: 0,
            }),
            op: ComparisonOp::Gt as i32,
            threshold: 90.0,
            ..Default::default()
        };
        let values = source.metric(&condition, at).await;
        assert!(!values.is_empty(), "the store has points in the window");
        let missing = MetricCondition {
            metric: "host.none".to_owned(),
            ..condition
        };
        assert!(source.metric(&missing, at).await.is_empty());
        assert_eq!(source.dropped_total(), 0);
        telemetry.close();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
