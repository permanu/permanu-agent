//! `TelemetryService` over the agent socket with `telemetry.v1`: every RPC
//! is served from the store (agent-protocol.md 9.7).

use std::time::{Duration, Instant};

use tonic::Code;

use super::otlp::tests::{otlp_span, trace_request};
use super::records::{encode, MetricSample, TAG_LOG};
use super::store::{Kind, Producer};
use crate::local::test_harness::{Harness, Options};
use crate::local::ERROR_REASON_HEADER;
use crate::proto::agent::v2::{
    log_query_response::Frame, metric_descriptor, metric_query_response, stream_status,
    telemetry_service_client::TelemetryServiceClient, trace_search_response, AnalyticsQuery,
    GetTelemetryUsageRequest, GetTraceRequest, ListMetricsRequest, LogLevel, LogQuery, LogRecord,
    LogSourceType, MetricAggregation, MetricQuery, MetricSource, QueryDirection, Scope,
    StreamStatus, TimeRange, TraceSearch,
};

const NANOS: i64 = 1_000_000_000;

async fn harness(name: &str) -> Harness {
    Harness::with(
        name,
        Options {
            telemetry: true,
            ..Default::default()
        },
    )
    .await
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64
}

fn log(project: &str, level: LogLevel, message: &str, source: LogSourceType) -> LogRecord {
    LogRecord {
        timestamp: Some(super::ingest::timestamp_of(now())),
        level: level as i32,
        message: message.into(),
        source_type: source as i32,
        project_id: project.into(),
        ingest: "runner_follow".into(),
        ..Default::default()
    }
}

fn put(h: &Harness, record: LogRecord) {
    let t = h.telemetry.as_ref().unwrap();
    let stamp = record.timestamp.unwrap();
    let ts = stamp.seconds * NANOS + i64::from(stamp.nanos);
    let producer = if record.project_id.is_empty() {
        Producer::System
    } else {
        Producer::Project(record.project_id.clone())
    };
    t.submit(Kind::Logs, producer, ts, TAG_LOG, encode(&record), false);
}

async fn run(
    h: &Harness,
    q: LogQuery,
) -> Result<(Vec<LogRecord>, Vec<StreamStatus>), tonic::Status> {
    let mut stream = TelemetryServiceClient::new(h.channel.clone())
        .query_logs(q)
        .await?
        .into_inner();
    let (mut records, mut statuses) = (Vec::new(), Vec::new());
    while let Some(frame) = stream.message().await? {
        match frame.frame {
            Some(Frame::Batch(b)) => records.extend(b.records),
            Some(Frame::Status(s)) => statuses.push(s),
            None => {}
        }
    }
    Ok((records, statuses))
}

fn messages(records: &[LogRecord]) -> Vec<&str> {
    records.iter().map(|r| r.message.as_str()).collect()
}

fn reason(status: &tonic::Status) -> String {
    status
        .metadata()
        .get(ERROR_REASON_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn query_logs_reads_the_store_with_filters_cursors_and_directions() {
    let h = harness("svc-logs").await;
    put(&h, log("p1", LogLevel::Info, "one", LogSourceType::App));
    put(&h, log("p2", LogLevel::Error, "two", LogSourceType::App));
    put(&h, log("", LogLevel::Warn, "three", LogSourceType::Agent));
    put(
        &h,
        log("p1", LogLevel::Error, "four", LogSourceType::Service),
    );
    let mut cron = log("p1", LogLevel::Info, "cron out", LogSourceType::Cron);
    cron.run_id = "run-1".into();
    put(&h, cron);
    h.telemetry.as_ref().unwrap().sync().await;

    let (all, statuses) = run(&h, LogQuery::default()).await.unwrap();
    assert_eq!(
        messages(&all),
        vec!["one", "two", "three", "four", "cron out"]
    );
    assert!(all.iter().all(|r| !r.cursor.is_empty()));
    let end = statuses.last().unwrap();
    assert_eq!(end.kind, stream_status::Kind::End as i32);
    assert_eq!(end.cursor, all[4].cursor);

    let scoped = LogQuery {
        scope: Some(Scope {
            project_id: "p1".into(),
            ..Default::default()
        }),
        levels: vec![LogLevel::Error as i32],
        ..Default::default()
    };
    assert_eq!(messages(&run(&h, scoped).await.unwrap().0), vec!["four"]);
    let sources = LogQuery {
        source_types: vec![LogSourceType::Agent as i32],
        ..Default::default()
    };
    assert_eq!(messages(&run(&h, sources).await.unwrap().0), vec!["three"]);
    let by_run = LogQuery {
        run_id: "run-1".into(),
        ..Default::default()
    };
    assert_eq!(
        messages(&run(&h, by_run).await.unwrap().0),
        vec!["cron out"]
    );
    let contains = LogQuery {
        contains: "TW".into(),
        case_insensitive: true,
        ..Default::default()
    };
    assert_eq!(messages(&run(&h, contains).await.unwrap().0), vec!["two"]);

    // Resume after a cursor, both ways.
    let after = LogQuery {
        cursor: all[1].cursor.clone(),
        ..Default::default()
    };
    assert_eq!(
        messages(&run(&h, after).await.unwrap().0),
        vec!["three", "four", "cron out"]
    );
    let back = LogQuery {
        cursor: all[3].cursor.clone(),
        direction: QueryDirection::Backward as i32,
        ..Default::default()
    };
    assert_eq!(
        messages(&run(&h, back).await.unwrap().0),
        vec!["three", "two", "one"]
    );
    let (page, statuses) = run(
        &h,
        LogQuery {
            limit: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(messages(&page), vec!["one", "two"]);
    assert!(statuses
        .iter()
        .any(|s| s.kind == stream_status::Kind::Truncated as i32));
    let tail = LogQuery {
        tail: 2,
        ..Default::default()
    };
    assert_eq!(
        messages(&run(&h, tail).await.unwrap().0),
        vec!["four", "cron out"]
    );

    let bad = run(
        &h,
        LogQuery {
            cursor: "nope".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(bad.code(), Code::InvalidArgument);
    let follow_back = LogQuery {
        follow: true,
        direction: QueryDirection::Backward as i32,
        ..Default::default()
    };
    assert_eq!(
        run(&h, follow_back).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    h.stop().await;
}

#[tokio::test]
async fn an_evicted_cursor_is_cursor_expired() {
    let h = harness("svc-expired").await;
    put(&h, log("p1", LogLevel::Info, "old", LogSourceType::App));
    let t = h.telemetry.clone().unwrap();
    t.sync().await;
    let (records, _) = run(&h, LogQuery::default()).await.unwrap();
    // Everything ages out.
    t.close();
    t.enforce(std::time::SystemTime::now() + Duration::from_secs(8 * 86_400));
    let status = run(
        &h,
        LogQuery {
            cursor: records[0].cursor.clone(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), Code::OutOfRange);
    assert_eq!(reason(&status), "ERROR_REASON_CURSOR_EXPIRED");
    h.stop().await;
}

#[tokio::test]
async fn follow_tails_the_store() {
    let h = harness("svc-follow").await;
    put(&h, log("p1", LogLevel::Info, "before", LogSourceType::App));
    h.telemetry.as_ref().unwrap().sync().await;
    let mut stream = TelemetryServiceClient::new(h.channel.clone())
        .query_logs(LogQuery {
            follow: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut seen = Vec::new();
    let mut caught_up = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let frame = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match frame.frame {
            Some(Frame::Batch(b)) => seen.extend(b.records.into_iter().map(|r| r.message)),
            Some(Frame::Status(s)) if s.kind == stream_status::Kind::CaughtUp as i32 => {
                caught_up = true;
                put(&h, log("p1", LogLevel::Info, "live", LogSourceType::App));
            }
            _ => {}
        }
        if seen.len() == 2 {
            break;
        }
    }
    assert!(caught_up);
    assert_eq!(seen, vec!["before", "live"]);
    drop(stream);
    h.stop().await;
}

#[tokio::test]
async fn usage_traces_metrics_and_analytics() {
    let h = harness("svc-usage").await;
    let t = h.telemetry.clone().unwrap();
    let mut client = TelemetryServiceClient::new(h.channel.clone());

    let usage = client
        .get_telemetry_usage(GetTelemetryUsageRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(usage.redaction_rules_version, "redaction-v1");
    assert_eq!(usage.kinds.len(), 5);
    assert_eq!(
        usage.kinds.iter().map(|k| k.kind).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    let logs = &usage.kinds[0];
    assert_eq!(logs.retention.unwrap().max_bytes, 1 << 30);
    assert_eq!(logs.retention.unwrap().max_age_days, 7);
    assert!(logs.retention_is_default);
    assert!(!usage.ingest_paused);

    // Traces: stored and settled through the OTLP path.
    let spans = vec![
        otlp_span(5, 1, 0, "GET /users", false),
        otlp_span(5, 2, 1, "SELECT", true),
    ];
    t.otlp_state.traces(&t, trace_request("p1", spans)).unwrap();
    t.otlp_state.settle(&t, Instant::now(), true);
    t.sync().await;
    let trace = client
        .get_trace(GetTraceRequest {
            trace_id: "05".repeat(16),
        })
        .await
        .unwrap()
        .into_inner();
    let names: Vec<&str> = trace.spans.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["GET /users", "SELECT"]);
    assert!(!trace.truncated);
    let missing = client
        .get_trace(GetTraceRequest {
            trace_id: "06".repeat(16),
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::NotFound);

    let wide = TimeRange {
        start: Some(super::ingest::timestamp_of(
            super::otlp::tests::T0 as i64 - NANOS,
        )),
        end: None,
    };
    let search = |extra: TraceSearch| TraceSearch {
        range: Some(wide),
        ..extra
    };
    let found = |q: TraceSearch| {
        let mut client = client.clone();
        async move {
            let mut stream = client.search_traces(q).await.unwrap().into_inner();
            let mut ids = Vec::new();
            while let Some(frame) = stream.message().await.unwrap() {
                if let Some(trace_search_response::Frame::Batch(b)) = frame.frame {
                    ids.extend(
                        b.traces
                            .into_iter()
                            .map(|t| (t.root_span_name, t.error_span_count)),
                    );
                }
            }
            ids
        }
    };
    assert_eq!(
        found(search(TraceSearch::default())).await,
        vec![("GET /users".to_owned(), 1)]
    );
    assert_eq!(
        found(search(TraceSearch {
            span_name: "SELECT".into(),
            ..Default::default()
        }))
        .await
        .len(),
        1
    );
    assert!(found(search(TraceSearch {
        span_name: "nope".into(),
        ..Default::default()
    }))
    .await
    .is_empty());
    let attr = crate::proto::agent::v2::AttributeFilter {
        key: "http.route".into(),
        op: 1,
        value: "/users".into(),
    };
    assert_eq!(
        found(search(TraceSearch {
            attributes: vec![attr],
            ..Default::default()
        }))
        .await
        .len(),
        1
    );
    let scope = Scope {
        project_id: "p2".into(),
        ..Default::default()
    };
    assert!(found(search(TraceSearch {
        scope: Some(scope),
        ..Default::default()
    }))
    .await
    .is_empty());

    // Metrics: a gauge over two steps.
    let base = now() - 120 * NANOS;
    let base = base - base.rem_euclid(60 * NANOS);
    for (offset, value) in [(0, 10.0), (5, 20.0), (60, 30.0)] {
        let sample = MetricSample {
            name: "host.cpu.percent".into(),
            kind: metric_descriptor::Kind::Gauge as i32,
            source: MetricSource::Host as i32,
            unit: "%".into(),
            value,
            ..Default::default()
        };
        t.otlp_state
            .metric(&t, Producer::System, base + offset * NANOS, sample);
    }
    t.sync().await;
    let range = TimeRange {
        start: Some(super::ingest::timestamp_of(base)),
        end: Some(super::ingest::timestamp_of(base + 120 * NANOS)),
    };
    let query = MetricQuery {
        name: "host.cpu.percent".into(),
        range: Some(range),
        step: Some(prost_types::Duration {
            seconds: 60,
            nanos: 0,
        }),
        aggregation: MetricAggregation::Avg as i32,
        ..Default::default()
    };
    let mut stream = client
        .query_metrics(query.clone())
        .await
        .unwrap()
        .into_inner();
    let mut points = Vec::new();
    while let Some(frame) = stream.message().await.unwrap() {
        if let Some(metric_query_response::Frame::Batch(b)) = frame.frame {
            for s in b.series {
                assert_eq!(s.unit, "%");
                points.extend(s.points.into_iter().map(|p| p.value));
            }
        }
    }
    assert_eq!(points, vec![15.0, 30.0]);
    let p95 = MetricQuery {
        aggregation: MetricAggregation::P95 as i32,
        ..query
    };
    let mut stream = client.query_metrics(p95).await.unwrap().into_inner();
    let err = loop {
        match stream.message().await {
            Err(e) => break e,
            Ok(None) => panic!("P95 on a gauge must fail"),
            Ok(Some(_)) => {}
        }
    };
    assert_eq!(err.code(), Code::InvalidArgument);
    let listed = client
        .list_metrics(ListMetricsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.metrics[0].name, "host.cpu.percent");
    assert_eq!(listed.metrics[0].source, MetricSource::Host as i32);

    // No Dwaar feed on the log stream yet: analytics stay unimplemented.
    let mut stream_err = client
        .query_analytics(AnalyticsQuery::default())
        .await
        .err();
    let status = stream_err.take().unwrap();
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(reason(&status), "ERROR_REASON_CAPABILITY_MISSING");
    h.stop().await;
}

#[tokio::test]
async fn without_the_store_traces_and_run_ids_are_capability_missing() {
    let h = Harness::start("svc-m1", None).await;
    let mut client = TelemetryServiceClient::new(h.channel.clone());
    let status = client
        .search_traces(TraceSearch::default())
        .await
        .err()
        .unwrap();
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(reason(&status), "ERROR_REASON_CAPABILITY_MISSING");
    let status = client
        .get_telemetry_usage(GetTelemetryUsageRequest {})
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unimplemented);
    let status = client
        .query_logs(LogQuery {
            run_id: "r".into(),
            ..Default::default()
        })
        .await
        .err()
        .unwrap();
    assert_eq!(reason(&status), "ERROR_REASON_CAPABILITY_MISSING");
    h.stop().await;
}
