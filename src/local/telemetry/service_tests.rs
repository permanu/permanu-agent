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
            super::otlp::tests::t0() as i64 - NANOS,
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

    h.stop().await;
}

fn analytics_row(
    minute: i64,
    host: &str,
    service: &str,
    requests: f64,
    views: f64,
    bots: f64,
) -> super::records::StoredAnalyticsRow {
    use crate::proto::agent::v2::{
        AnalyticsDimension, AnalyticsDimensionValue, AnalyticsMeasure, AnalyticsMeasureValue,
    };
    let value = |measure: AnalyticsMeasure, value: f64| AnalyticsMeasureValue {
        measure: measure as i32,
        value,
    };
    super::records::StoredAnalyticsRow {
        bucket_start: Some(prost_types::Timestamp {
            seconds: minute,
            nanos: 0,
        }),
        dimensions: vec![AnalyticsDimensionValue {
            dimension: AnalyticsDimension::Domain as i32,
            value: host.into(),
        }],
        values: vec![
            value(AnalyticsMeasure::Requests, requests),
            value(AnalyticsMeasure::PageViews, views),
            value(AnalyticsMeasure::UniqueVisitors, 1.0),
            value(AnalyticsMeasure::LatencyP95Ms, 10.0),
            value(AnalyticsMeasure::ErrorRate, 0.5),
            value(AnalyticsMeasure::BotRequests, bots),
        ],
        service_id: service.into(),
        project_id: String::new(),
        environment_id: String::new(),
    }
}

async fn analytics(
    client: &mut TelemetryServiceClient<tonic::transport::Channel>,
    query: AnalyticsQuery,
) -> Result<
    (
        Vec<crate::proto::agent::v2::AnalyticsRow>,
        Vec<StreamStatus>,
    ),
    tonic::Status,
> {
    use crate::proto::agent::v2::analytics_query_response;
    let mut stream = client.query_analytics(query).await?.into_inner();
    let (mut rows, mut statuses) = (Vec::new(), Vec::new());
    while let Some(frame) = stream.message().await? {
        match frame.frame {
            Some(analytics_query_response::Frame::Batch(b)) => rows.extend(b.rows),
            Some(analytics_query_response::Frame::Status(s)) => statuses.push(s),
            None => {}
        }
    }
    Ok((rows, statuses))
}

/// QA_M2 X1 (agent-protocol.md 9.7, D-060): `QueryAnalytics` serves the
/// 60 s rollups filtered by `service_ids` (the `routes_map` attribution)
/// and route hosts, in buckets, grouped by route host, top-N.
#[tokio::test]
async fn analytics_are_served_by_service_and_route_host() {
    use crate::proto::agent::v2::{AnalyticsDimension, AnalyticsMeasure};
    const WEB: &str = "01a0cdb5-3500-70c1-8000-000000000001";
    const API: &str = "01a0cdb5-3500-70c1-8000-000000000002";
    let h = harness("svc-analytics").await;
    let t = h.telemetry.as_ref().unwrap();
    let base = now().div_euclid(NANOS) - 600;
    let base = base - base.rem_euclid(60);
    for row in [
        analytics_row(base, "web.example.com", WEB, 10.0, 6.0, 2.0),
        analytics_row(base + 60, "web.example.com", WEB, 20.0, 8.0, 0.0),
        analytics_row(base + 60, "www.example.com", WEB, 5.0, 1.0, 0.0),
        analytics_row(base, "api.example.com", API, 100.0, 0.0, 0.0),
        analytics_row(base, "hooks.example.com", "", 3.0, 0.0, 0.0),
    ] {
        let ts = row.bucket_start.unwrap().seconds * NANOS;
        t.submit(
            Kind::Analytics,
            Producer::System,
            ts,
            super::ingest::TAG_ANALYTICS_ROW,
            encode(&row),
            false,
        );
    }
    t.sync().await;
    let mut client = TelemetryServiceClient::new(h.channel.clone());
    let range = TimeRange {
        start: Some(prost_types::Timestamp {
            seconds: base,
            nanos: 0,
        }),
        end: Some(prost_types::Timestamp {
            seconds: base + 120,
            nanos: 0,
        }),
    };
    let measure = |row: &crate::proto::agent::v2::AnalyticsRow, m: AnalyticsMeasure| {
        row.values
            .iter()
            .find(|v| v.measure == m as i32)
            .map(|v| v.value)
    };
    // One bucket over the range, one service: the default measures.
    let (rows, statuses) = analytics(
        &mut client,
        AnalyticsQuery {
            service_ids: vec![WEB.into()],
            range: Some(range),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(measure(&rows[0], AnalyticsMeasure::Requests), Some(35.0));
    assert_eq!(measure(&rows[0], AnalyticsMeasure::PageViews), Some(15.0));
    assert_eq!(
        measure(&rows[0], AnalyticsMeasure::UniqueVisitors),
        Some(3.0)
    );
    assert_eq!(rows[0].values.len(), 3);
    assert_eq!(rows[0].bucket_start.unwrap().seconds, base);
    assert_eq!(
        statuses.last().unwrap().kind,
        stream_status::Kind::End as i32
    );
    // 60 s buckets grouped by route host, bots excluded, top 1 per bucket.
    let (rows, _) = analytics(
        &mut client,
        AnalyticsQuery {
            service_ids: vec![WEB.into()],
            range: Some(range),
            bucket: Some(prost_types::Duration {
                seconds: 60,
                nanos: 0,
            }),
            group_by: vec![AnalyticsDimension::Domain as i32],
            measures: vec![
                AnalyticsMeasure::Requests as i32,
                AnalyticsMeasure::LatencyP95Ms as i32,
                AnalyticsMeasure::ErrorRate as i32,
            ],
            exclude_bots: true,
            limit: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].bucket_start.unwrap().seconds, base);
    assert_eq!(rows[0].dimensions[0].value, "web.example.com");
    assert_eq!(measure(&rows[0], AnalyticsMeasure::Requests), Some(8.0));
    assert_eq!(
        measure(&rows[0], AnalyticsMeasure::LatencyP95Ms),
        Some(10.0)
    );
    assert_eq!(measure(&rows[0], AnalyticsMeasure::ErrorRate), Some(0.5));
    assert_eq!(rows[1].bucket_start.unwrap().seconds, base + 60);
    assert_eq!(rows[1].dimensions[0].value, "web.example.com");
    // Route hosts filter; both filters empty = every route on the server.
    let (rows, _) = analytics(
        &mut client,
        AnalyticsQuery {
            domains: vec!["API.example.com".into()],
            range: Some(range),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(measure(&rows[0], AnalyticsMeasure::Requests), Some(100.0));
    let (rows, _) = analytics(
        &mut client,
        AnalyticsQuery {
            range: Some(range),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(measure(&rows[0], AnalyticsMeasure::Requests), Some(138.0));
    // A dimension the rollups do not record yields no rows, never an error.
    let (rows, _) = analytics(
        &mut client,
        AnalyticsQuery {
            service_ids: vec![WEB.into()],
            range: Some(range),
            group_by: vec![AnalyticsDimension::Country as i32],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(rows.is_empty());
    // Bad requests.
    for bad in [
        AnalyticsQuery {
            bucket: Some(prost_types::Duration {
                seconds: 90,
                nanos: 0,
            }),
            ..Default::default()
        },
        AnalyticsQuery {
            limit: 501,
            ..Default::default()
        },
        AnalyticsQuery {
            group_by: vec![1, 2, 3],
            ..Default::default()
        },
        AnalyticsQuery {
            service_ids: vec!["not-a-uuid".into()],
            ..Default::default()
        },
    ] {
        let status = analytics(&mut client, bad).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
    }
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
