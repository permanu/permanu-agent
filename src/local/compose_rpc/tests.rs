use super::*;
use crate::local::runner::{EventLines, RunnerFailure};
struct Fake {
    enabled: bool,
}
#[tonic::async_trait]
impl Runner for Fake {
    async fn exchange(&self, r: Value, _: Duration) -> Result<Value, RunnerFailure> {
        if r["op"] == "compose_v1_capabilities" {
            return Ok(
                json!({"ok":true,"data":{"schema_version":1,"standing_release":self.enabled}}),
            );
        }
        assert_eq!(r["op"], "compose_v1_get_release_operation");
        Ok(
            json!({"ok":true,"data":{"schema_version":1,"application_id":r["payload"]["application_id"],"operation_id":r["payload"]["operation_id"],"release_digest":r["payload"]["operation_id"],"outcome":"rolled_back","reason":"readiness_failed"}}),
        )
    }
    async fn open(&self, _: Value) -> Result<EventLines, RunnerFailure> {
        panic!("no stream")
    }
}
#[tokio::test]
async fn compose_rpc_disabled_and_accepting() {
    for enabled in [false, true] {
        let svc = Service {
            runner: Arc::new(Fake { enabled }),
        };
        let r = svc
            .get_release_operation(Request::new(pb::GetReleaseOperationRequest {
                schema_version: 1,
                application_id: "colrow".into(),
                operation_id: "a".repeat(64),
            }))
            .await;
        if enabled {
            assert_eq!(r.unwrap().into_inner().outcome, 3)
        } else {
            assert_eq!(r.unwrap_err().code(), tonic::Code::Unimplemented)
        }
    }
}
#[tokio::test]
async fn compose_rpc_unknown_version() {
    let svc = Service {
        runner: Arc::new(Fake { enabled: true }),
    };
    assert_eq!(
        svc.get_release_operation(Request::new(pb::GetReleaseOperationRequest {
            schema_version: 2,
            application_id: "colrow".into(),
            operation_id: "a".repeat(64)
        }))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn compose_rpc_uses_existing_socket_runner() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("compose-rpc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("runner.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let serve = tokio::spawn(async move {
        for expected in [
            "compose_v1_capabilities",
            "compose_v1_get_release_operation",
        ] {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["op"], expected);
            let data = if expected == "compose_v1_capabilities" {
                json!({"schema_version":1,"standing_release":true})
            } else {
                json!({"schema_version":1,"application_id":"colrow","operation_id":"a".repeat(64),"release_digest":"a".repeat(64),"outcome":"deployed","reason":""})
            };
            write
                .write_all(
                    format!("{}\n", json!({"type":"result","ok":true,"data":data})).as_bytes(),
                )
                .await
                .unwrap();
            write.shutdown().await.unwrap();
        }
    });
    let svc = Service {
        runner: Arc::new(crate::local::runner::SocketRunner { path }),
    };
    let r = svc
        .get_release_operation(Request::new(pb::GetReleaseOperationRequest {
            schema_version: 1,
            application_id: "colrow".into(),
            operation_id: "a".repeat(64),
        }))
        .await
        .unwrap();
    assert_eq!(r.into_inner().outcome, 2);
    serve.await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

// Explicit local cross-component harness. No default test/production enrollment.
#[tokio::test]
#[ignore = "requires isolated root_fixture_daemon with ephemeral test authority"]
async fn compose_rpc_real_root_fixture() {
    let root = std::path::PathBuf::from(
        std::env::var_os("PERMANU_COMPOSE_FIXTURE_DIR").expect("fixture dir"),
    );
    let raw = std::fs::read(root.join("envelope.json")).unwrap();
    let value: Value = serde_json::from_slice(&raw).unwrap();
    let app = value["release"]["application_id"].as_str().unwrap();
    let svc = Service {
        runner: Arc::new(crate::local::runner::SocketRunner {
            path: root.join("runner.sock"),
        }),
    };
    let first = svc
        .observe_registered_application(Request::new(pb::ObserveRegisteredApplicationRequest {
            schema_version: 1,
            application_id: app.into(),
        }))
        .await
        .unwrap()
        .into_inner();
    let submitted = svc
        .submit_standing_release(Request::new(pb::SubmitStandingReleaseRequest {
            schema_version: 1,
            envelope_json: raw,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(submitted.outcome, 2);
    let status = svc
        .get_release_operation(Request::new(pb::GetReleaseOperationRequest {
            schema_version: 1,
            application_id: app.into(),
            operation_id: submitted.operation_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status, submitted);
    let after = svc
        .observe_registered_application(Request::new(pb::ObserveRegisteredApplicationRequest {
            schema_version: 1,
            application_id: app.into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(after.generation, first.generation + 1);
}
