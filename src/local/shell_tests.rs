//! `ShellService.Shell` against the fake runner's `shell_open` session
//! (agent-protocol.md 4 "Shell", signed-plan.md 3.2 `shell.open`, 14.8
//! "Shell stream").

use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Code;

use super::test_harness::Harness;
use crate::proto::agent::v2::{
    change_service_client::ChangeServiceClient, shell_client_frame, shell_server_frame,
    shell_service_client::ShellServiceClient, GetOperationRequest, OperationState,
    ShellClientFrame, ShellOpen, ShellServerFrame, SignedPlan, SubmitSignedPlanRequest,
    TerminalSize,
};
use crate::signed_plan::test_support::{vector, TestSigner, SERVER_A};
use crate::signed_plan::verify::GENESIS_HEAD;

const WEB: &str = "01a0cdb5-3500-70c1-8000-000000000001";

fn vector_trust() -> String {
    serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap()
}

/// The `ok_owner_shell_open` vector plan on a fresh server, re-signed.
fn shell_plan(owner: &TestSigner, tail: &str, ttl: u32, actions: Option<Value>) -> SignedPlan {
    let cases = vector("policy-cases");
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok_owner_shell_open")
        .unwrap();
    let base: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
    let mut plan = base["plan"].clone();
    plan["id"] = Value::String(format!("01a0cdb5-3500-7001-8000-{tail}"));
    plan["nonce"] = Value::String(format!("{tail}AAAAAAAAAA"));
    plan["base"]["heads"] = json!({ SERVER_A: GENESIS_HEAD });
    plan["actions"][0]["params"]["ttl_seconds"] = json!(ttl);
    if let Some(actions) = actions {
        plan["actions"] = actions;
    }
    SignedPlan {
        envelope_json: owner.envelope(&plan).into_bytes(),
        ..Default::default()
    }
}

fn open_frame(plan: SignedPlan) -> ShellClientFrame {
    ShellClientFrame {
        frame: Some(shell_client_frame::Frame::Open(ShellOpen {
            plan: Some(plan),
            tty: true,
            term: "xterm-256color".to_owned(),
            size: Some(TerminalSize { cols: 80, rows: 24 }),
        })),
    }
}

fn frame(frame: shell_client_frame::Frame) -> ShellClientFrame {
    ShellClientFrame { frame: Some(frame) }
}

struct Session {
    tx: mpsc::Sender<ShellClientFrame>,
    rx: tonic::Streaming<ShellServerFrame>,
}

async fn open(h: &Harness, first: ShellClientFrame) -> Result<Session, tonic::Status> {
    let (tx, rx) = mpsc::channel(16);
    tx.send(first).await.unwrap();
    let response = ShellServiceClient::new(h.channel.clone())
        .shell(ReceiverStream::new(rx))
        .await?;
    Ok(Session {
        tx,
        rx: response.into_inner(),
    })
}

async fn next(session: &mut Session) -> shell_server_frame::Frame {
    tokio::time::timeout(Duration::from_secs(10), session.rx.message())
        .await
        .expect("a frame in time")
        .expect("no stream error")
        .expect("a frame")
        .frame
        .expect("frame set")
}

async fn operation_state(h: &Harness, plan_id: &str) -> i32 {
    let record = h.core.store.admission(plan_id).unwrap().unwrap();
    let mut client = ChangeServiceClient::new(h.channel.clone());
    for _ in 0..200 {
        h.core.reconcile_once().await;
        let operation = client
            .get_operation(GetOperationRequest {
                operation_id: record.operation_id.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        if operation.state != OperationState::Running as i32
            && operation.state != OperationState::Queued as i32
        {
            return operation.state;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("operation of {plan_id} never finished");
}

#[tokio::test]
async fn a_shell_session_relays_input_and_output_and_ends_when_the_client_closes() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("shell-session", Some(&vector_trust())).await;
    let plan = shell_plan(&owner, "0000000005a1", 600, None);
    let mut session = open(&h, open_frame(plan)).await.unwrap();
    let shell_server_frame::Frame::Opened(opened) = next(&mut session).await else {
        panic!("the first frame is Opened");
    };
    assert_eq!(opened.service_id, WEB);
    assert_eq!(opened.plan_digest_hex.len(), 64);
    assert!(opened.expires_at.is_some());
    assert!(!opened.session_id.is_empty());
    // The runner session gets the terminal size, then the input.
    session
        .tx
        .send(frame(shell_client_frame::Frame::Stdin(
            b"echo hi\n".to_vec(),
        )))
        .await
        .unwrap();
    let shell_server_frame::Frame::Stdout(out) = next(&mut session).await else {
        panic!("stdout");
    };
    assert_eq!(out, b"echo hi\n");
    session
        .tx
        .send(frame(shell_client_frame::Frame::Resize(TerminalSize {
            cols: 120,
            rows: 40,
        })))
        .await
        .unwrap();
    // Replacing the sender drops the client's half: the stream ends.
    session.tx = mpsc::channel(1).0;
    let shell_server_frame::Frame::Exit(exit) = next(&mut session).await else {
        panic!("exit");
    };
    assert_eq!(exit.reason, "client_closed");
    let lines = h.runner.shell_lines();
    assert!(
        lines.contains(&json!({"op": "shell_resize", "cols": 80, "rows": 24})),
        "{lines:?}"
    );
    assert!(
        lines.contains(&json!({"op": "shell_resize", "cols": 120, "rows": 40})),
        "{lines:?}"
    );
    assert_eq!(lines.last(), Some(&json!({"op": "shell_close"})));
    let plan_id = "01a0cdb5-3500-7001-8000-0000000005a1";
    assert_eq!(
        operation_state(&h, plan_id).await,
        OperationState::Succeeded as i32
    );
    h.stop().await;
}

#[tokio::test]
async fn a_shell_session_ends_at_its_signed_ttl() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("shell-ttl", Some(&vector_trust())).await;
    let mut session = open(&h, open_frame(shell_plan(&owner, "0000000005a2", 1, None)))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut session).await,
        shell_server_frame::Frame::Opened(_)
    ));
    let shell_server_frame::Frame::Exit(exit) = next(&mut session).await else {
        panic!("exit");
    };
    assert_eq!(exit.reason, "expired");
    h.stop().await;
}

#[tokio::test]
async fn the_first_frame_must_open_with_a_shell_only_plan() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("shell-refusals", Some(&vector_trust())).await;
    let stdin_first = frame(shell_client_frame::Frame::Stdin(b"id\n".to_vec()));
    let status = match open(&h, stdin_first).await {
        Ok(mut session) => session.rx.message().await.unwrap_err(),
        Err(status) => status,
    };
    assert_eq!(status.code(), Code::InvalidArgument);
    // A plan with another action never opens a shell and is not admitted.
    let other = shell_plan(
        &owner,
        "0000000005a3",
        600,
        Some(
            json!([{"kind": "shell.open", "params": {"service_id": WEB, "ttl_seconds": 600}},
                    {"kind": "shell.open", "params": {"service_id": null, "ttl_seconds": 600}}]),
        ),
    );
    let status = match open(&h, open_frame(other)).await {
        Ok(mut session) => session.rx.message().await.unwrap_err(),
        Err(status) => status,
    };
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert!(h.core.store.admissions_after(0, 10).unwrap().is_empty());
    // SubmitSignedPlan never admits shell.open (Shell only, direct).
    let status = ChangeServiceClient::new(h.channel.clone())
        .submit_signed_plan(SubmitSignedPlanRequest {
            plan: Some(shell_plan(&owner, "0000000005a4", 600, None)),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert!(h.core.store.admissions_after(0, 10).unwrap().is_empty());
    h.stop().await;
}

/// The shell plan of `tail` on the server's current head (every admission
/// advances it).
fn shell_plan_at_head(h: &Harness, owner: &TestSigner, tail: &str) -> SignedPlan {
    let cases = vector("policy-cases");
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok_owner_shell_open")
        .unwrap();
    let base: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
    let mut plan = base["plan"].clone();
    let head = h
        .core
        .store
        .head(
            plan["project_id"].as_str().unwrap(),
            plan["environment"].as_str().unwrap(),
        )
        .map(|record| record.head_digest_hex)
        .unwrap_or_else(|_| GENESIS_HEAD.to_owned());
    plan["id"] = Value::String(format!("01a0cdb5-3500-7001-8000-{tail}"));
    plan["nonce"] = Value::String(format!("{tail}AAAAAAAAAA"));
    plan["base"]["heads"] = json!({ SERVER_A: head });
    SignedPlan {
        envelope_json: owner.envelope(&plan).into_bytes(),
        ..Default::default()
    }
}

/// contracts v1.1.7 (D-065 #9): at most 4 shells per agent; the 5th
/// `ShellOpen` is `RESOURCE_EXHAUSTED` + `LIMIT_EXCEEDED` before admission,
/// and a slot is free again once a session ends.
#[tokio::test]
async fn the_fifth_concurrent_shell_is_refused_before_admission() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("shell-limit", Some(&vector_trust())).await;
    let mut sessions = Vec::new();
    for n in 1..=4 {
        let plan = shell_plan_at_head(&h, &owner, &format!("0000000005b{n}"));
        let mut session = open(&h, open_frame(plan)).await.unwrap();
        assert!(matches!(
            next(&mut session).await,
            shell_server_frame::Frame::Opened(_)
        ));
        sessions.push(session);
    }
    let fifth = shell_plan_at_head(&h, &owner, "0000000005b5");
    let status = match open(&h, open_frame(fifth.clone())).await {
        Ok(mut session) => session.rx.message().await.unwrap_err(),
        Err(status) => status,
    };
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(
        status.metadata().get("permanu-error-reason").unwrap(),
        "ERROR_REASON_LIMIT_EXCEEDED"
    );
    assert_eq!(h.core.store.admissions_after(0, 10).unwrap().len(), 4);
    // One session ends: its slot is free again.
    let mut first = sessions.remove(0);
    first.tx = mpsc::channel(1).0;
    assert!(matches!(
        next(&mut first).await,
        shell_server_frame::Frame::Exit(_)
    ));
    let mut again = None;
    for _ in 0..100 {
        match open(&h, open_frame(fifth.clone())).await {
            Ok(mut session) => match session.rx.message().await {
                Ok(Some(ShellServerFrame {
                    frame: Some(shell_server_frame::Frame::Opened(_)),
                })) => {
                    again = Some(session);
                    break;
                }
                _ => {}
            },
            Err(status) => assert_eq!(status.code(), Code::ResourceExhausted),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(again.is_some(), "the freed slot opens a fifth session");
    // Every client ends its stream, so the server can shut down.
    sessions.extend(again);
    for mut session in sessions {
        session.tx = mpsc::channel(1).0;
        assert!(matches!(
            next(&mut session).await,
            shell_server_frame::Frame::Exit(_)
        ));
    }
    h.stop().await;
}

/// contracts v1.1.7 (D-065 #3): `ShellExit` relays the runner's
/// `exit_code` and `signal`.
#[tokio::test]
async fn the_shell_exit_carries_the_runners_exit_code_and_signal() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("shell-exit-code", Some(&vector_trust())).await;
    let plan = shell_plan_at_head(&h, &owner, "0000000005c1");
    let mut session = open(&h, open_frame(plan)).await.unwrap();
    assert!(matches!(
        next(&mut session).await,
        shell_server_frame::Frame::Opened(_)
    ));
    session
        .tx
        .send(frame(shell_client_frame::Frame::Stdin(
            b"exit 3\n".to_vec(),
        )))
        .await
        .unwrap();
    let shell_server_frame::Frame::Exit(exit) = next(&mut session).await else {
        panic!("exit");
    };
    assert_eq!(exit.reason, "exited");
    assert_eq!(exit.exit_code, 3);
    assert_eq!(exit.signal, "");
    // Closed by the client: the runner names the signal that ended it.
    let plan = shell_plan_at_head(&h, &owner, "0000000005c2");
    let mut session = open(&h, open_frame(plan)).await.unwrap();
    assert!(matches!(
        next(&mut session).await,
        shell_server_frame::Frame::Opened(_)
    ));
    session.tx = mpsc::channel(1).0;
    let shell_server_frame::Frame::Exit(exit) = next(&mut session).await else {
        panic!("exit");
    };
    assert_eq!(exit.reason, "client_closed");
    assert_eq!(exit.exit_code, 0);
    assert_eq!(exit.signal, "SIGHUP");
    h.stop().await;
}

/// contracts v1.1.7 (D-065 #9): the runner's `E_SHELL_LIMIT` (a session
/// left over from before an agent restart holds a slot) ends the stream
/// with `RESOURCE_EXHAUSTED` + `LIMIT_EXCEEDED`.
#[tokio::test]
async fn the_runners_shell_limit_is_resource_exhausted() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("shell-runner-limit", Some(&vector_trust())).await;
    h.runner
        .shell_limit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let plan = shell_plan_at_head(&h, &owner, "0000000005d1");
    let status = match open(&h, open_frame(plan)).await {
        Ok(mut session) => session.rx.message().await.unwrap_err(),
        Err(status) => status,
    };
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(
        status.metadata().get("permanu-error-reason").unwrap(),
        "ERROR_REASON_LIMIT_EXCEEDED"
    );
    h.stop().await;
}

/// contracts v1.1.6 (D-064 #2): a host shell signed as a server-level plan
/// (no project) opens a host login shell.
#[tokio::test]
async fn a_server_level_host_shell_opens() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("shell-host-server-plan", Some(&vector_trust())).await;
    let cases = vector("policy-cases");
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok_owner_host_shell_server_plan")
        .unwrap();
    let base: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
    let plan = SignedPlan {
        envelope_json: owner.envelope(&base["plan"]).into_bytes(),
        ..Default::default()
    };
    let mut session = open(&h, open_frame(plan)).await.unwrap();
    let shell_server_frame::Frame::Opened(opened) = next(&mut session).await else {
        panic!("the first frame is Opened");
    };
    assert_eq!(opened.service_id, "");
    session.tx = mpsc::channel(1).0;
    assert!(matches!(
        next(&mut session).await,
        shell_server_frame::Frame::Exit(_)
    ));
    h.stop().await;
}
