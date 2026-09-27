//! ChangeService and EventService over the unix socket: bootstrap, admission,
//! idempotent resubmission, error trailers, execution through the runner,
//! consumed-log reconciliation, operations and events.

use std::time::Duration;

use serde_json::{json, Value};
use tokio_stream::StreamExt;
use tonic::Code;

use super::errors::PLAN_ERROR_HEADER;
use super::execution::decode_event;
use super::test_harness::{Harness, OpBehavior, Options};
use super::ERROR_REASON_HEADER;
use crate::proto::agent::v2::{
    change_service_client::ChangeServiceClient, deploy_status_event::Phase, event,
    event_service_client::EventServiceClient, info_service_client::InfoServiceClient,
    operation_event, trusted_keys_summary::TrustState, CancelOperationRequest, ErrorReason,
    EventKind, GetOperationRequest, GetStateHeadRequest, GetTrustedKeysRequest, HelloRequest,
    ListAdmissionsRequest, ListOperationsRequest, ListStandingRulesRequest, Operation,
    OperationRef, OperationState, PageRequest, SignedPlan, SubmitSignedPlanRequest,
    SubscribeRequest, VerifySignedPlanRequest, WatchOperationRequest,
};
use crate::signed_plan::crypto::{KEY_ADD_PREFIX, SPEC_PREFIX};
use crate::signed_plan::jcs::canonicalize;
use crate::signed_plan::test_support::{plan_vector, vector, TestSigner, SERVER_A};
use crate::signed_plan::verify::{next_head, GENESIS_HEAD};
use crate::signed_plan::PlanCode;

const SERVER_C: &str = "01a0cdb5-3500-70a1-8000-000000000003";
const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";
const ENVIRONMENT_ID: &str = "01a0cdb5-3500-70b2-8000-000000000001";
const WEB: &str = "01a0cdb5-3500-70c1-8000-000000000001";

fn signed(case: &Value) -> SignedPlan {
    SignedPlan {
        envelope_json: serde_json::to_vec(&case["signed_plan"]).unwrap(),
        specs_jcs: case["specs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["jcs"].as_str().unwrap().as_bytes().to_vec())
            .collect(),
        sealed_secrets: Vec::new(),
    }
}

fn submit(plan: SignedPlan) -> SubmitSignedPlanRequest {
    SubmitSignedPlanRequest { plan: Some(plan) }
}

fn trailer(status: &tonic::Status, name: &str) -> String {
    status
        .metadata()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn owner_only_trust() -> String {
    let file = vector("trusted-keys");
    json!({
        "version": 1, "server_id": SERVER_A, "keys": [file["keys"][0]], "revocations": []
    })
    .to_string()
}

async fn wait_for_state(h: &Harness, operation_id: &str, state: OperationState) {
    let mut client = ChangeServiceClient::new(h.channel.clone());
    for _ in 0..200 {
        h.core.reconcile_once().await;
        let operation = client
            .get_operation(GetOperationRequest {
                operation_id: operation_id.to_owned(),
            })
            .await
            .unwrap()
            .into_inner();
        if operation.state == state as i32 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("operation {operation_id} never reached {state:?}");
}

#[tokio::test]
async fn bootstrap_admits_server_add_writes_trust_and_dedupes() {
    let case = plan_vector("server-add-bootstrap");
    let host_key = case["plan"]["actions"][0]["params"]["ssh_host_key_digest_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let h = Harness::with(
        "boot",
        Options {
            host_keys: vec![host_key],
            ..Default::default()
        },
    )
    .await;
    let mut change = ChangeServiceClient::new(h.channel.clone());

    // VerifySignedPlan in bootstrap state reports the plan, writes nothing.
    let verified = change
        .verify_signed_plan(VerifySignedPlanRequest {
            plan: Some(signed(&case)),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(verified.valid);
    assert_eq!(
        verified.plan_digest_hex,
        case["digest_hex"].as_str().unwrap()
    );
    assert!(!h.trust_file.exists());

    let reference = change
        .submit_signed_plan(submit(signed(&case)))
        .await
        .unwrap()
        .into_inner();
    assert!(!reference.deduplicated);
    assert_eq!(
        reference.plan_digest_hex,
        case["digest_hex"].as_str().unwrap()
    );
    assert_eq!(reference.plan_id, case["plan"]["id"].as_str().unwrap());

    // The trust file now holds exactly the owner key, root of the chain.
    let written: Value = serde_json::from_slice(&std::fs::read(&h.trust_file).unwrap()).unwrap();
    assert_eq!(written["server_id"], SERVER_C);
    assert_eq!(written["keys"].as_array().unwrap().len(), 1);
    assert_eq!(
        written["keys"][0],
        case["plan"]["actions"][0]["params"]["owner_key"]
    );
    let hello = InfoServiceClient::new(h.channel.clone())
        .hello(HelloRequest {
            protocol_versions: vec!["2.0".to_owned()],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(hello.agent.unwrap().server_id, SERVER_C);
    assert_eq!(hello.trusted_keys.unwrap().state, TrustState::Valid as i32);

    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    // The runner wrote the trust file (D-030); server.add itself is applied
    // by the agent and never bound.
    let requests = h.runner.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["op"], "bootstrap_trust");
    assert_eq!(
        requests[0]["payload"]["signed_plan"],
        String::from_utf8(signed(&case).envelope_json).unwrap()
    );

    let head = change
        .get_state_head(GetStateHeadRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        head.head_digest_hex,
        next_head(GENESIS_HEAD, case["digest_hex"].as_str().unwrap())
    );
    assert_eq!(head.server_id, SERVER_C);
    assert!(!head.quarantined);

    let again = change
        .submit_signed_plan(submit(signed(&case)))
        .await
        .unwrap()
        .into_inner();
    assert!(again.deduplicated);
    assert_eq!(again.operation_id, reference.operation_id);

    let keys = change
        .get_trusted_keys(GetTrustedKeysRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(keys.keys.len(), 1);
    assert_eq!(keys.keys[0].role, "owner");
    assert_eq!(keys.keys[0].spki_der.len(), 91);
    assert_eq!(keys.generation, 1);

    let admissions = change
        .list_admissions(ListAdmissionsRequest {
            include_signed_plan: true,
            page: Some(PageRequest::default()),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(admissions.admissions.len(), 1);
    let admission = &admissions.admissions[0];
    assert_eq!(admission.submitter, "client");
    assert_eq!(admission.author_kind, "user");
    assert_eq!(admission.actions, vec!["server.add"]);
    assert_eq!(admission.outcome, "succeeded");
    assert!(!admission.signed_plan_json.is_empty());
    // A durable position, set even on the last page.
    let token = admissions.page.unwrap().next_page_token;
    assert!(!token.is_empty());
    let later = change
        .list_admissions(ListAdmissionsRequest {
            include_signed_plan: false,
            page: Some(PageRequest {
                page_size: 10,
                page_token: token.clone(),
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(later.admissions.is_empty());
    assert_eq!(later.page.unwrap().next_page_token, token);

    // WatchOperation replays every event, then closes after `finished`.
    let mut stream = change
        .watch_operation(WatchOperationRequest {
            operation_id: reference.operation_id.clone(),
            after_seq: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let mut seqs = Vec::new();
    let mut finished = None;
    while let Some(event) = stream.next().await {
        let event = event.unwrap();
        seqs.push(event.seq);
        if let Some(operation_event::Event::Finished(op)) = event.event {
            finished = Some(op);
        }
    }
    assert_eq!(seqs, (1..=seqs.len() as u64).collect::<Vec<_>>());
    assert_eq!(finished.unwrap().state, OperationState::Succeeded as i32);
    h.stop().await;
}

#[tokio::test]
async fn an_expired_bootstrap_writes_no_trust_file() {
    let case = plan_vector("server-add-bootstrap");
    let host_key = case["plan"]["actions"][0]["params"]["ssh_host_key_digest_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let h = Harness::with(
        "boot-late",
        Options {
            host_keys: vec![host_key],
            ..Default::default()
        },
    )
    .await;
    h.clock
        .0
        .fetch_add(3_600, std::sync::atomic::Ordering::SeqCst);
    let status = ChangeServiceClient::new(h.channel.clone())
        .submit_signed_plan(submit(signed(&case)))
        .await
        .unwrap_err();
    assert_eq!(trailer(&status, PLAN_ERROR_HEADER), "E_EXPIRED");
    assert!(!h.trust_file.exists());
    // The time window is checked before the runner is asked (D-033).
    assert!(h.runner.requests.lock().unwrap().is_empty());
    h.stop().await;
}

#[tokio::test]
async fn bootstrap_refuses_a_plan_pinned_to_another_host_key() {
    let case = plan_vector("server-add-bootstrap");
    let h = Harness::start("boot-bad", None).await;
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let status = change
        .submit_signed_plan(submit(signed(&case)))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(
        trailer(&status, ERROR_REASON_HEADER),
        "ERROR_REASON_BOOTSTRAP_REJECTED"
    );
    assert_eq!(trailer(&status, PLAN_ERROR_HEADER), "E_BOOTSTRAP");
    assert!(!h.trust_file.exists());
    h.stop().await;
}

/// v1.0.5 (D-045): the bootstrap `server.add` signs the fingerprint of the
/// recipient the user confirmed; a server with another recipient refuses it
/// before the runner is asked.
#[tokio::test]
async fn bootstrap_refuses_a_plan_signed_for_another_age_recipient() {
    let case = plan_vector("server-add-bootstrap");
    let host_key = case["plan"]["actions"][0]["params"]["ssh_host_key_digest_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let h = Harness::with(
        "boot-age",
        Options {
            host_keys: vec![host_key],
            age_recipient: Some(age::x25519::Identity::generate().to_public().to_string()),
            ..Default::default()
        },
    )
    .await;
    let status = ChangeServiceClient::new(h.channel.clone())
        .submit_signed_plan(submit(signed(&case)))
        .await
        .unwrap_err();
    assert_eq!(trailer(&status, PLAN_ERROR_HEADER), "E_BOOTSTRAP");
    assert!(!h.trust_file.exists());
    assert!(h.runner.requests.lock().unwrap().is_empty());
    h.stop().await;
}

/// D-046: until the M2 artifact trust root, `agent.update` and
/// `component.update` for `runner` or `permanu-env` are refused before
/// admission (`not_supported_yet`), even when validly signed; the runner
/// is never asked and nothing is admitted. `component.update(dwaar)` and
/// `os_packages` are not refused here.
#[tokio::test]
async fn updates_without_an_artifact_trust_root_are_refused_before_admission() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("m1-updates", Some(&vector_trust())).await;
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let digest = "ab".repeat(32);
    let plan_for = |suffix: &str, action: Value| {
        let mut plan = plan_vector("key-add")["plan"].clone();
        plan["id"] = Value::String(format!("01a0cdb5-3500-7001-8000-0000000d46{suffix}"));
        // 16 bytes: the 22nd base64url character carries 2 bits (`A`).
        plan["nonce"] = Value::String(format!("D046AAAAAAAAAAAAAA{suffix}AA"));
        plan["targets"] = json!([SERVER_A]);
        plan["base"]["heads"] = json!({ SERVER_A: GENESIS_HEAD });
        plan["actions"] = json!([action]);
        SignedPlan {
            envelope_json: owner.envelope(&plan).into_bytes(),
            specs_jcs: Vec::new(),
            sealed_secrets: Vec::new(),
        }
    };
    let refused = [
        json!({"kind": "agent.update", "params": {"version": "1.2.3",
               "artifact_digest_hex": digest, "bundle_manifest_digest_hex": digest, "allow_downgrade": false}}),
        json!({"kind": "component.update", "params": {"component": "runner", "version": "1.2.3",
               "artifact_digest_hex": digest, "bundle_manifest_digest_hex": digest, "allow_downgrade": false}}),
        json!({"kind": "component.update", "params": {"component": "permanu-env",
               "version": "1.2.3", "artifact_digest_hex": digest,
               "bundle_manifest_digest_hex": digest, "allow_downgrade": false}}),
    ];
    for (index, action) in refused.into_iter().enumerate() {
        let status = change
            .submit_signed_plan(submit(plan_for(&format!("a{index}"), action.clone())))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Unimplemented, "{action}");
        assert_eq!(
            trailer(&status, ERROR_REASON_HEADER),
            "ERROR_REASON_NOT_SUPPORTED_YET"
        );
        assert!(
            status.message().starts_with("not_supported_yet"),
            "{action}"
        );
    }
    assert!(h.runner.requests.lock().unwrap().is_empty());
    let admissions = change
        .list_admissions(ListAdmissionsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(admissions.admissions.is_empty());

    // Dwaar updates are built in M1 and pass this gate.
    let dwaar = json!({"kind": "component.update", "params": {"component": "dwaar",
                       "version": "0.3.24", "artifact_digest_hex": digest,
                       "bundle_manifest_digest_hex": digest, "allow_downgrade": false}});
    let admitted = change
        .submit_signed_plan(submit(plan_for("b0", dwaar)))
        .await
        .unwrap()
        .into_inner();
    assert!(!admitted.deduplicated);
    h.stop().await;
}

#[tokio::test]
async fn rejections_carry_the_contract_codes_and_admit_nothing() {
    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = Harness::start("reject", Some(&trust)).await;
    let mut change = ChangeServiceClient::new(h.channel.clone());
    // The user-deploy vector names a head this fresh store does not have.
    let status = change
        .submit_signed_plan(submit(signed(&plan_vector("user-deploy"))))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Aborted);
    assert_eq!(
        trailer(&status, ERROR_REASON_HEADER),
        "ERROR_REASON_BASE_MISMATCH"
    );
    assert_eq!(trailer(&status, PLAN_ERROR_HEADER), "E_BASE_MISMATCH");

    // A rule-backed plan from a client (policy case rule_plan_from_client).
    let cases = vector("policy-cases");
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "rule_plan_from_client")
        .unwrap();
    let status = change
        .submit_signed_plan(submit(SignedPlan {
            envelope_json: case["input"].as_str().unwrap().as_bytes().to_vec(),
            specs_jcs: case["specs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().as_bytes().to_vec())
                .collect(),
            sealed_secrets: Vec::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(
        trailer(&status, ERROR_REASON_HEADER),
        "ERROR_REASON_PLAN_AUTHORITY"
    );
    assert_eq!(trailer(&status, PLAN_ERROR_HEADER), "E_AUTHOR");

    // Malformed input.
    let status = change
        .submit_signed_plan(submit(SignedPlan {
            envelope_json: br#"{"plan":{},"plan":{}}"#.to_vec(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(trailer(&status, PLAN_ERROR_HEADER), "E_PARSE");

    // VerifySignedPlan returns the failure instead of an error.
    let verified = change
        .verify_signed_plan(VerifySignedPlanRequest {
            plan: Some(signed(&plan_vector("user-deploy"))),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!verified.valid);
    assert_eq!(verified.failures[0].code, "E_BASE_MISMATCH");

    let listed = change
        .list_admissions(ListAdmissionsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(listed.admissions.is_empty());
    assert_eq!(listed.page.unwrap().next_page_token, "");
    h.stop().await;
}

#[tokio::test]
async fn invalid_trust_or_quarantine_refuse_every_admission() {
    let mut file = vector("trusted-keys");
    file["keys"][0]["role"] = Value::String("deployer".to_owned());
    let h = Harness::start("invalid-trust", Some(&file.to_string())).await;
    let status = ChangeServiceClient::new(h.channel.clone())
        .submit_signed_plan(submit(signed(&plan_vector("user-deploy"))))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        trailer(&status, ERROR_REASON_HEADER),
        "ERROR_REASON_TRUST_STORE_INVALID"
    );
    h.stop().await;

    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = Harness::with(
        "quarantine",
        Options {
            trust: Some(trust),
            store_lost: true,
            ..Default::default()
        },
    )
    .await;
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let status = change
        .submit_signed_plan(submit(signed(&plan_vector("key-add"))))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        trailer(&status, ERROR_REASON_HEADER),
        "ERROR_REASON_STORE_QUARANTINED"
    );
    let head = change
        .get_state_head(GetStateHeadRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(head.quarantined);
    assert_eq!(
        head.quarantine_ends_at.unwrap().seconds,
        h.clock.0.load(std::sync::atomic::Ordering::SeqCst) + 1_200
    );
    h.stop().await;
}

#[tokio::test]
async fn key_add_is_admitted_then_written_to_the_trust_file() {
    let h = Harness::start("key-add", Some(&owner_only_trust())).await;
    let mut events = EventServiceClient::new(h.channel.clone())
        .subscribe(SubscribeRequest {
            kinds: vec![EventKind::TrustChanged as i32],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let case = plan_vector("key-add");
    let reference = change
        .submit_signed_plan(submit(signed(&case)))
        .await
        .unwrap()
        .into_inner();
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    let keys = change
        .get_trusted_keys(GetTrustedKeysRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(keys.keys.len(), 2);
    let added = &keys.keys[1];
    assert_eq!(
        added.key_id,
        case["plan"]["actions"][0]["params"]["entry"]["key_id"]
            .as_str()
            .unwrap()
    );
    assert_eq!(added.role, "deployer");
    assert_eq!(added.scope_project_ids, vec![PROJECT]);
    assert_eq!(added.added_by_key_id, "dYLNItf797wK7n5moGt2cw");
    let event = tokio::time::timeout(Duration::from_secs(5), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Some(event::Payload::TrustChanged(changed)) = event.payload else {
        panic!("trust event");
    };
    assert_eq!(changed.change, "key.add");
    assert_eq!(changed.generation, 2);
    assert_eq!(changed.fingerprint_digest_hex, keys.fingerprint_digest_hex);
    h.stop().await;
}

/// A fresh user deploy signed with the TEST owner key (docs keys.json).
fn fresh_deploy(signer: &TestSigner, id_tail: &str, nonce: &str, head: &str) -> SignedPlan {
    let case = plan_vector("user-deploy");
    let spec = case["specs"][0]["jcs"].as_str().unwrap().to_owned();
    let mut plan = case["plan"].clone();
    plan["id"] = Value::String(format!("01a0cdb5-3500-7001-8000-{id_tail}"));
    plan["nonce"] = Value::String(nonce.to_owned());
    plan["base"]["heads"][SERVER_A] = Value::String(head.to_owned());
    // D-035: every deploy carries its own engine-minted deployment id.
    plan["actions"][0]["params"]["deployment_id"] =
        Value::String(format!("01a0cdb5-3500-70c7-8000-{id_tail}"));
    let spec_digest = crate::signed_plan::crypto::hex(
        &crate::signed_plan::crypto::prefixed_digest(SPEC_PREFIX, &spec),
    );
    assert_eq!(
        plan["actions"][0]["params"]["spec_digest_hex"],
        spec_digest.as_str()
    );
    SignedPlan {
        envelope_json: signer.envelope(&plan).into_bytes(),
        specs_jcs: vec![spec.into_bytes()],
        sealed_secrets: Vec::new(),
    }
}

fn vector_trust() -> String {
    serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap()
}

async fn submit_ok(h: &Harness, plan: SignedPlan) -> OperationRef {
    ChangeServiceClient::new(h.channel.clone())
        .submit_signed_plan(submit(plan))
        .await
        .unwrap()
        .into_inner()
}

async fn operation(h: &Harness, operation_id: &str) -> Operation {
    ChangeServiceClient::new(h.channel.clone())
        .get_operation(GetOperationRequest {
            operation_id: operation_id.to_owned(),
        })
        .await
        .unwrap()
        .into_inner()
}

/// Every step of an operation as `(action_index, name, state, failure_code)`.
fn steps(operation: &Operation) -> Vec<(u32, String, i32, String)> {
    operation
        .steps
        .iter()
        .map(|s| {
            (
                s.action_index,
                s.name.clone(),
                s.state,
                s.failure_code.clone(),
            )
        })
        .collect()
}

fn names(operation: &Operation, action_index: u32) -> Vec<String> {
    operation
        .steps
        .iter()
        .filter(|s| s.action_index == action_index && !s.action.is_empty())
        .map(|s| s.name.clone())
        .collect()
}

/// Deploy status events until the first final phase.
async fn deploy_phases(
    events: &mut tonic::Streaming<crate::proto::agent::v2::Event>,
) -> Vec<(i32, String)> {
    let mut phases = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(10), events.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Some(event::Payload::Deploy(status)) = event.payload else {
            continue;
        };
        assert_eq!(status.project_id, PROJECT);
        assert_eq!(status.environment_id, ENVIRONMENT_ID);
        assert!(crate::signed_plan::text::uuid7(&status.deployment_id));
        let done = [
            Phase::Live,
            Phase::Failed,
            Phase::RolledBack,
            Phase::Cancelled,
        ]
        .iter()
        .any(|p| *p as i32 == status.phase);
        phases.push((status.phase, status.failure_code));
        if done {
            return phases;
        }
    }
}

async fn deploy_events(h: &Harness) -> tonic::Streaming<crate::proto::agent::v2::Event> {
    EventServiceClient::new(h.channel.clone())
        .subscribe(SubscribeRequest {
            kinds: vec![EventKind::DeployStatus as i32],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
}

#[tokio::test]
async fn deploy_success_binds_runs_the_op_sequence_and_goes_live() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("deploy", Some(&vector_trust())).await;
    let mut deploys = deploy_events(&h).await;
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000d1",
            "AAAAAAAAAAAAAAAAAAAAAA",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    // bind_plan, then prepare → verify → activate, each with payload {},
    // then (v1.0.18, D-068) prune_releases on the closed action.
    assert_eq!(
        h.runner.binds(),
        vec![(
            reference.plan_id.clone(),
            reference.plan_digest_hex.clone(),
            0
        )]
    );
    assert_eq!(
        h.runner.ops_for(&reference.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
            ("activate_release".to_owned(), 0),
            ("prune_releases".to_owned(), 0),
        ]
    );
    let phases = deploy_phases(&mut deploys).await;
    assert_eq!(
        phases.iter().map(|p| p.0).collect::<Vec<_>>(),
        vec![
            Phase::Queued as i32,
            Phase::Starting as i32,
            Phase::HealthChecking as i32,
            Phase::HealthChecking as i32,
            Phase::Live as i32,
        ]
    );
    let op = operation(&h, &reference.operation_id).await;
    assert_eq!(op.plan_id, reference.plan_id);
    assert_eq!(
        steps(&op)[0],
        (
            0,
            "admitted".to_owned(),
            OperationState::Succeeded as i32,
            String::new()
        )
    );
    assert_eq!(
        names(&op, 0),
        vec![
            "queued",
            "bound",
            "prepare_release",
            "verify_health",
            "activate_release",
            "prune_releases",
            "succeeded"
        ]
    );
    // Every step of the deploy names its deployment.
    let deployment = op.steps[1].deployment_id.clone();
    assert!(crate::signed_plan::text::uuid7(&deployment));
    assert!(op.steps[1..].iter().all(|s| s.deployment_id == deployment));

    // The runner's result line was reconciled, and the head advanced.
    let admission = ChangeServiceClient::new(h.channel.clone())
        .list_admissions(ListAdmissionsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .admissions
        .remove(0);
    assert_eq!(admission.outcome, "succeeded");
    assert_eq!(admission.environment_id, ENVIRONMENT_ID);
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let head = change
        .get_state_head(GetStateHeadRequest {
            project_id: PROJECT.to_owned(),
            environment: "production".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        head.head_digest_hex,
        next_head(GENESIS_HEAD, &reference.plan_digest_hex)
    );
    let stale = fresh_deploy(
        &owner,
        "0000000000d2",
        "BBBBBBBBBBBBBBBBBBBBBA",
        GENESIS_HEAD,
    );
    let status = change.submit_signed_plan(submit(stale)).await.unwrap_err();
    assert_eq!(trailer(&status, PLAN_ERROR_HEADER), "E_BASE_MISMATCH");
    let listed = change
        .list_operations(ListOperationsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.operations.len(), 1);
    assert_eq!(listed.operations[0].state, OperationState::Succeeded as i32);
    h.stop().await;
}

#[tokio::test]
async fn failed_health_rolls_back_to_the_previous_release() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("rollback", Some(&vector_trust())).await;
    let first = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000a1",
            "BAAAAAAAAAAAAAAAAAAAAA",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &first.operation_id, OperationState::Succeeded).await;

    h.runner
        .behave("verify_health", OpBehavior::Fail("health_failed"));
    let mut deploys = deploy_events(&h).await;
    let second = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000a2",
            "CAAAAAAAAAAAAAAAAAAAAA",
            &next_head(GENESIS_HEAD, &first.plan_digest_hex),
        ),
    )
    .await;
    wait_for_state(&h, &second.operation_id, OperationState::RolledBack).await;
    assert_eq!(
        h.runner.ops_for(&second.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
            ("rollback_release".to_owned(), 0),
        ]
    );
    let phases = deploy_phases(&mut deploys).await;
    assert_eq!(
        phases.last().unwrap(),
        &(Phase::RolledBack as i32, "candidate_health".to_owned())
    );
    assert!(phases.contains(&(Phase::RollingBack as i32, String::new())));
    let op = operation(&h, &second.operation_id).await;
    assert_eq!(
        names(&op, 0),
        vec![
            "queued",
            "bound",
            "prepare_release",
            "verify_health",
            "rollback_release",
            "rolled_back"
        ]
    );
    let health = op.steps.iter().find(|s| s.name == "verify_health").unwrap();
    assert_eq!(health.state, OperationState::Failed as i32);
    assert_eq!(health.failure_code, "candidate_health");
    let last = op.steps.last().unwrap();
    assert_eq!(last.state, OperationState::RolledBack as i32);
    assert_eq!(last.failure_code, "candidate_health");
    h.stop().await;
}

/// A first successful deploy, so the service has an active release; returns
/// the head the next plan builds on.
async fn first_release(h: &Harness, owner: &TestSigner, tail: &str, nonce: &str) -> String {
    let first = submit_ok(h, fresh_deploy(owner, tail, nonce, GENESIS_HEAD)).await;
    wait_for_state(h, &first.operation_id, OperationState::Succeeded).await;
    next_head(GENESIS_HEAD, &first.plan_digest_hex)
}

fn final_step(op: &Operation) -> (String, i32, String) {
    let last = op.steps.last().unwrap();
    (last.name.clone(), last.state, last.failure_code.clone())
}

// D-038 (signed-plan 14.6): a failed prepare_release cleans the candidate
// up, even when the service has an earlier release to return to.
#[tokio::test]
async fn a_failed_prepare_cleans_up_the_candidate() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("prepfail", Some(&vector_trust())).await;
    let head = first_release(&h, &owner, "0000000000a3", "GAAAAAAAAAAAAAAAAAAAAA").await;
    h.runner
        .behave("prepare_release", OpBehavior::Fail("pull_failed"));
    let second = submit_ok(
        &h,
        fresh_deploy(&owner, "0000000000a4", "HAAAAAAAAAAAAAAAAAAAAA", &head),
    )
    .await;
    wait_for_state(&h, &second.operation_id, OperationState::Failed).await;
    assert_eq!(
        h.runner.ops_for(&second.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("cleanup_candidate".to_owned(), 0),
        ]
    );
    let op = operation(&h, &second.operation_id).await;
    assert_eq!(
        final_step(&op),
        (
            "failed".to_owned(),
            OperationState::Failed as i32,
            "prepare".to_owned()
        )
    );
    h.stop().await;
}

// D-038: a failed activate_release rolls back when there is an earlier
// release; the runner's error.failure_code (public_health) is kept.
#[tokio::test]
async fn a_failed_activate_rolls_back_to_the_previous_release() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("actfail", Some(&vector_trust())).await;
    let head = first_release(&h, &owner, "0000000000a5", "IAAAAAAAAAAAAAAAAAAAAA").await;
    h.runner.behave(
        "activate_release",
        OpBehavior::FailCode("health_failed", "public_health"),
    );
    let second = submit_ok(
        &h,
        fresh_deploy(&owner, "0000000000a6", "JAAAAAAAAAAAAAAAAAAAAA", &head),
    )
    .await;
    wait_for_state(&h, &second.operation_id, OperationState::RolledBack).await;
    assert_eq!(
        h.runner.ops_for(&second.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
            ("activate_release".to_owned(), 0),
            ("rollback_release".to_owned(), 0),
        ]
    );
    let op = operation(&h, &second.operation_id).await;
    let activate = op
        .steps
        .iter()
        .find(|s| s.name == "activate_release")
        .unwrap();
    assert_eq!(activate.failure_code, "public_health");
    assert_eq!(
        final_step(&op),
        (
            "rolled_back".to_owned(),
            OperationState::RolledBack as i32,
            "public_health".to_owned()
        )
    );
    h.stop().await;
}

/// D-069: `verify_health` returning `state: rolled_back` means the runner
/// already restarted the previous release. The executor records the rollback
/// step done and does not send `rollback_release`.
#[tokio::test]
async fn a_health_hand_back_records_rollback_without_calling_it() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("health-handback", Some(&vector_trust())).await;
    let head = first_release(&h, &owner, "0000000000c1", "PAAAAAAAAAAAAAAAAAAAAA").await;
    h.runner.behave("verify_health", OpBehavior::HandBack);
    let second = submit_ok(
        &h,
        fresh_deploy(&owner, "0000000000c2", "QAAAAAAAAAAAAAAAAAAAAA", &head),
    )
    .await;
    wait_for_state(&h, &second.operation_id, OperationState::RolledBack).await;
    assert_eq!(
        h.runner.ops_for(&second.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
        ]
    );
    let op = operation(&h, &second.operation_id).await;
    let health = op.steps.iter().find(|s| s.name == "verify_health").unwrap();
    assert_eq!(health.state, OperationState::Failed as i32);
    assert_eq!(health.failure_code, "candidate_health");
    let rollback = op
        .steps
        .iter()
        .find(|s| s.name == "rollback_release")
        .unwrap();
    assert_eq!(rollback.state, OperationState::Succeeded as i32);
    assert_eq!(rollback.failure_code, "");
    assert!(!rollback.error.contains("interrupted"), "{rollback:?}");
    assert_eq!(
        final_step(&op),
        (
            "rolled_back".to_owned(),
            OperationState::RolledBack as i32,
            "candidate_health".to_owned()
        )
    );
    h.stop().await;
}

/// D-069: the same hand-back from `activate_release` keeps `failure_code`
/// `activate` and sends no `rollback_release`.
#[tokio::test]
async fn an_activate_hand_back_records_rollback_without_calling_it() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("activate-handback", Some(&vector_trust())).await;
    let head = first_release(&h, &owner, "0000000000c3", "RAAAAAAAAAAAAAAAAAAAAA").await;
    h.runner.behave("activate_release", OpBehavior::HandBack);
    let second = submit_ok(
        &h,
        fresh_deploy(&owner, "0000000000c4", "SAAAAAAAAAAAAAAAAAAAAA", &head),
    )
    .await;
    wait_for_state(&h, &second.operation_id, OperationState::RolledBack).await;
    assert_eq!(
        h.runner.ops_for(&second.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
            ("activate_release".to_owned(), 0),
        ]
    );
    let op = operation(&h, &second.operation_id).await;
    let activate = op
        .steps
        .iter()
        .find(|s| s.name == "activate_release")
        .unwrap();
    assert_eq!(activate.state, OperationState::Failed as i32);
    assert_eq!(activate.failure_code, "activate");
    let rollback = op
        .steps
        .iter()
        .find(|s| s.name == "rollback_release")
        .unwrap();
    assert_eq!(rollback.state, OperationState::Succeeded as i32);
    assert!(!rollback.error.contains("interrupted"), "{rollback:?}");
    assert_eq!(
        final_step(&op),
        (
            "rolled_back".to_owned(),
            OperationState::RolledBack as i32,
            "activate".to_owned()
        )
    );
    h.stop().await;
}

// D-038: a failed activate_release with no earlier release cleans up.
#[tokio::test]
async fn a_failed_activate_without_a_previous_release_cleans_up() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("actclean", Some(&vector_trust())).await;
    h.runner
        .behave("activate_release", OpBehavior::Fail("activate_failed"));
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000a7",
            "KAAAAAAAAAAAAAAAAAAAAA",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Failed).await;
    assert_eq!(
        h.runner.ops_for(&reference.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
            ("activate_release".to_owned(), 0),
            ("cleanup_candidate".to_owned(), 0),
        ]
    );
    let op = operation(&h, &reference.operation_id).await;
    assert_eq!(
        final_step(&op),
        (
            "failed".to_owned(),
            OperationState::Failed as i32,
            "activate".to_owned()
        )
    );
    h.stop().await;
}

// D-038: a failed recovery op (here cleanup_candidate) ends the action
// failed with failure code recovery.
#[tokio::test]
async fn a_failed_recovery_op_fails_with_recovery() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("recovery", Some(&vector_trust())).await;
    h.runner
        .behave("verify_health", OpBehavior::Fail("health_failed"));
    h.runner
        .behave("cleanup_candidate", OpBehavior::Fail("runtime_failed"));
    h.runner
        .write_results
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000a8",
            "LAAAAAAAAAAAAAAAAAAAAA",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Failed).await;
    let op = operation(&h, &reference.operation_id).await;
    assert_eq!(
        final_step(&op),
        (
            "failed".to_owned(),
            OperationState::Failed as i32,
            "recovery".to_owned()
        )
    );
    h.stop().await;
}

#[tokio::test]
async fn failed_health_without_a_previous_release_cleans_up_and_fails() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("cleanup", Some(&vector_trust())).await;
    h.runner
        .behave("verify_health", OpBehavior::Fail("health_failed"));
    // A runner that writes no result lines: the executor records outcomes.
    h.runner
        .write_results
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000b1",
            "DAAAAAAAAAAAAAAAAAAAAA",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Failed).await;
    assert_eq!(
        h.runner.ops_for(&reference.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
            ("cleanup_candidate".to_owned(), 0),
        ]
    );
    let op = operation(&h, &reference.operation_id).await;
    let last = op.steps.last().unwrap();
    assert_eq!(
        (last.name.as_str(), last.failure_code.as_str()),
        ("failed", "candidate_health")
    );
    assert!(op.error.contains("health_failed"), "{}", op.error);
    h.stop().await;
}

#[tokio::test]
async fn a_start_phase_past_the_timeout_fails_with_start() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::with(
        "timeout",
        Options {
            trust: Some(vector_trust()),
            start_timeout: Duration::from_millis(300),
            ..Default::default()
        },
    )
    .await;
    h.runner.behave("prepare_release", OpBehavior::Hang);
    let mut deploys = deploy_events(&h).await;
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000b2",
            "EAAAAAAAAAAAAAAAAAAAAA",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Failed).await;
    assert_eq!(
        h.runner.ops_for(&reference.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("cleanup_candidate".to_owned(), 0),
        ]
    );
    let phases = deploy_phases(&mut deploys).await;
    assert_eq!(
        phases.last().unwrap(),
        &(Phase::Failed as i32, "start".to_owned())
    );
    let op = operation(&h, &reference.operation_id).await;
    let prepare = op
        .steps
        .iter()
        .find(|s| s.name == "prepare_release")
        .unwrap();
    assert_eq!(prepare.state, OperationState::Failed as i32);
    assert_eq!(prepare.failure_code, "start");
    assert_eq!(op.steps.last().unwrap().failure_code, "start");
    h.stop().await;
}

#[tokio::test]
async fn runner_refusal_fails_the_operation_with_the_mapped_reason() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("refuse", Some(&vector_trust())).await;
    *h.runner.fail_bind_with.lock().unwrap() = Some(PlanCode::PlanWindow);
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000e1",
            "CCCCCCCCCCCCCCCCCCCCCA",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Failed).await;
    let op = operation(&h, &reference.operation_id).await;
    // v2.0.6: the runner code has its own reason (was EXEC_PRECONDITION),
    // carried on the step and the operation next to the message.
    assert!(
        op.error
            .starts_with("ERROR_REASON_PLAN_WINDOW (E_PLAN_WINDOW)"),
        "{}",
        op.error
    );
    assert_eq!(op.error_code, "E_PLAN_WINDOW");
    assert_eq!(op.error_reason, ErrorReason::PlanWindow as i32);
    let failed = op.steps.last().unwrap();
    assert_eq!(failed.name, "failed");
    assert_eq!(failed.error_code, "E_PLAN_WINDOW");
    assert_eq!(failed.error_reason, ErrorReason::PlanWindow as i32);
    // Nothing ran after the refused bind.
    assert!(h.runner.ops_for(&reference.plan_id).is_empty());
    assert_eq!(names(&op, 0), vec!["queued", "failed"]);
    h.stop().await;
}

/// F-23 (QA_M1 run 5): `prepare_release` refused before it created a
/// candidate (a refused input fold, `E_SCOPE_MISMATCH`) runs no recovery:
/// the deploy fails `prepare` with the runner's reason, never `recovery` /
/// `internal`.
#[tokio::test]
async fn a_refused_input_fold_reports_the_runner_reason_not_recovery() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("fold-refused", Some(&vector_trust())).await;
    h.runner
        .behave("prepare_release", OpBehavior::Fail("E_SCOPE_MISMATCH"));
    h.runner
        .behave("cleanup_candidate", OpBehavior::Fail("E_SCOPE_MISMATCH"));
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000e2",
            "CCCCCCCCCCCCCCCCCCCCCQ",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Failed).await;
    assert_eq!(
        h.runner.ops_for(&reference.plan_id),
        vec![("prepare_release".to_owned(), 0)]
    );
    let op = operation(&h, &reference.operation_id).await;
    assert_eq!(
        final_step(&op),
        (
            "failed".to_owned(),
            OperationState::Failed as i32,
            "prepare".to_owned()
        )
    );
    let prepare = op
        .steps
        .iter()
        .find(|s| s.name == "prepare_release")
        .unwrap();
    assert_eq!(prepare.error_code, "E_SCOPE_MISMATCH");
    assert_eq!(prepare.error_reason, ErrorReason::ScopeMismatch as i32);
    assert!(
        op.error
            .starts_with("ERROR_REASON_SCOPE_MISMATCH (E_SCOPE_MISMATCH)"),
        "{}",
        op.error
    );
    assert_eq!(op.error_code, "E_SCOPE_MISMATCH");
    assert_eq!(op.error_reason, ErrorReason::ScopeMismatch as i32);
    h.stop().await;
}

#[tokio::test]
async fn inputs_are_bound_and_take_the_composed_deploy_outcome() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("inputs", Some(&vector_trust())).await;
    let mut plan = plan_vector("user-deploy")["plan"].clone();
    let deploy = plan["actions"][0].clone();
    plan["id"] = Value::String("01a0cdb5-3500-7001-8000-0000000000c1".to_owned());
    plan["nonce"] = Value::String("FAAAAAAAAAAAAAAAAAAAAA".to_owned());
    plan["base"]["heads"][SERVER_A] = Value::String(GENESIS_HEAD.to_owned());
    plan["actions"] = json!([
        {"kind": "env.set", "params": {"service_id": WEB, "set": {"LOG_LEVEL": "debug"},
                                       "unset": []}},
        deploy
    ]);
    let case = plan_vector("user-deploy");
    let reference = submit_ok(
        &h,
        SignedPlan {
            envelope_json: owner.envelope(&plan).into_bytes(),
            specs_jcs: vec![case["specs"][0]["jcs"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec()],
            sealed_secrets: Vec::new(),
        },
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    // The input is bound (consumed once) and runs no op of its own.
    let binds: Vec<u32> = h.runner.binds().iter().map(|b| b.2).collect();
    assert_eq!(binds, vec![0, 1]);
    assert!(h
        .runner
        .ops_for(&reference.plan_id)
        .iter()
        .all(|(_, index)| *index == 1));
    let op = operation(&h, &reference.operation_id).await;
    assert_eq!(names(&op, 0), vec!["queued", "bound", "succeeded"]);
    h.stop().await;
}

/// v1.0.17 (D-067 #3): the reader outcome of a managed PostgreSQL
/// activation (`reader_status`, `reader_reason` of `activate_release`'s
/// `result`) is shown on the deploy's steps; a failed reader never fails the
/// deploy.
#[tokio::test]
async fn activation_reader_status_is_shown_and_never_fails_the_deploy() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("deploy-reader", Some(&vector_trust())).await;
    h.runner.op_extra.lock().unwrap().insert(
        "activate_release".to_owned(),
        json!({"reader_status": "failed", "reader_reason": "not_ready"}),
    );
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000d9",
            "AAAAAAAAAAAAAAAAAAAAAQ",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    let lines = step_logs(&h, &reference.operation_id);
    assert!(
        lines
            .iter()
            .any(|l| l == "database reader permanu_reader: failed (not_ready)"),
        "{lines:?}"
    );
    h.stop().await;
}

/// v1.0.18 (D-068 #3, signed-plan 14.4/14.6): after a `succeeded`
/// `activate_release` the agent calls `prune_releases` on the same (closed)
/// action and records it as an operation-only step before the final step.
#[tokio::test]
async fn a_successful_activation_prunes_older_releases() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("deploy-prune", Some(&vector_trust())).await;
    h.runner
        .op_extra
        .lock()
        .unwrap()
        .insert("prune_releases".to_owned(), json!({"pruned_releases": 2}));
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000e1",
            "AAAAAAAAAAAAAAAAAAAAEQ",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    assert_eq!(
        h.runner.ops_for(&reference.plan_id),
        vec![
            ("prepare_release".to_owned(), 0),
            ("verify_health".to_owned(), 0),
            ("activate_release".to_owned(), 0),
            ("prune_releases".to_owned(), 0),
        ]
    );
    let op = operation(&h, &reference.operation_id).await;
    assert_eq!(
        names(&op, 0),
        vec![
            "queued",
            "bound",
            "prepare_release",
            "verify_health",
            "activate_release",
            "prune_releases",
            "succeeded"
        ]
    );
    let prune = op
        .steps
        .iter()
        .find(|s| s.name == "prune_releases")
        .unwrap();
    assert_eq!(prune.state, OperationState::Succeeded as i32);
    assert_eq!(prune.failure_code, "");
    let lines = step_logs(&h, &reference.operation_id);
    assert!(
        lines.iter().any(|l| l == "pruned 2 older releases"),
        "{lines:?}"
    );
    h.stop().await;
}

/// D-068 #3: a failed `prune_releases` is logged on its step and never
/// changes the deploy's outcome.
#[tokio::test]
async fn a_failed_prune_never_changes_the_deploy_outcome() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("deploy-prunefail", Some(&vector_trust())).await;
    h.runner
        .behave("prune_releases", OpBehavior::Fail("E_EXEC_RUNTIME"));
    let reference = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000e2",
            "AAAAAAAAAAAAAAAAAAAAEg",
            GENESIS_HEAD,
        ),
    )
    .await;
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    let op = operation(&h, &reference.operation_id).await;
    let prune = op
        .steps
        .iter()
        .find(|s| s.name == "prune_releases")
        .unwrap();
    assert_eq!(prune.state, OperationState::Failed as i32);
    assert_eq!(prune.failure_code, "");
    assert!(prune.error.contains("prune_releases failed"), "{prune:?}");
    assert_eq!(
        final_step(&op),
        (
            "succeeded".to_owned(),
            OperationState::Succeeded as i32,
            String::new()
        )
    );
    h.stop().await;
}

/// Every `StepLog` line recorded for an operation, including lines recorded
/// after its `finished` event (which a WatchOperation replay stops at).
fn step_logs(h: &Harness, operation_id: &str) -> Vec<String> {
    h.core
        .store
        .operation_events_after(operation_id, 0)
        .unwrap()
        .into_iter()
        .filter_map(|(_, text)| match decode_event(&text)?.event {
            Some(operation_event::Event::Log(log)) => Some(log.line),
            _ => None,
        })
        .collect()
}

/// A deploy cancelled inside `prepare_release` (its candidate is prepared,
/// never activated). Returns the deploy and the cancel plan's operation.
async fn cancel_in_prepare(h: &Harness, owner: &TestSigner) -> (OperationRef, Operation) {
    h.runner.behave("prepare_release", OpBehavior::Hang);
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let deploy = submit_ok(
        h,
        fresh_deploy(
            owner,
            "0000000000f1",
            "DDDDDDDDDDDDDDDDDDDDDA",
            GENESIS_HEAD,
        ),
    )
    .await;
    // Wait until the deploy is inside prepare_release.
    for _ in 0..500 {
        if !h.runner.ops_for(&deploy.plan_id).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        h.runner.ops_for(&deploy.plan_id),
        vec![("prepare_release".to_owned(), 0)]
    );

    let head = next_head(GENESIS_HEAD, &deploy.plan_digest_hex);
    let cancel_plan = json!({
        "version": 1, "id": "01a0cdb5-3500-7001-8000-0000000000f2",
        "project_id": PROJECT, "environment": "production", "environment_id": ENVIRONMENT_ID,
        "service_ids": [], "targets": [SERVER_A],
        "actions": [{"kind": "operation.cancel", "params": {
            "plan_id": deploy.plan_id, "plan_digest_hex": deploy.plan_digest_hex}}],
        "base": {"force": false, "heads": {SERVER_A: head}},
        "created_at": "2026-09-23T10:04:00Z", "expires_at": "2026-09-23T10:14:00Z",
        "nonce": "EEEEEEEEEEEEEEEEEEEEEA",
        "author": {"kind": "user", "agent_session_id": null}, "invocation": null
    });
    let signed_cancel = SignedPlan {
        envelope_json: owner.envelope(&cancel_plan).into_bytes(),
        ..Default::default()
    };
    // CancelOperation for an unknown operation is refused before admission.
    let wrong = change
        .cancel_operation(CancelOperationRequest {
            operation_id: "01a0cdb5-3500-7001-8000-0000000000ff".to_owned(),
            plan: Some(signed_cancel.clone()),
        })
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), Code::NotFound);
    let cancel = change
        .cancel_operation(CancelOperationRequest {
            operation_id: deploy.operation_id.clone(),
            plan: Some(signed_cancel),
        })
        .await
        .unwrap()
        .into_inner();
    // D-033: the cancel plan's own operation.
    assert_ne!(cancel.id, deploy.operation_id);
    assert_eq!(cancel.actions, vec!["operation.cancel"]);
    wait_for_state(h, &cancel.id, OperationState::Succeeded).await;
    wait_for_state(h, &deploy.operation_id, OperationState::Cancelled).await;
    // v1.0.11 (D-061): cancel_running always runs first.
    assert_eq!(
        h.runner.ops_for(&cancel.plan_id),
        vec![
            ("cancel_running".to_owned(), 0),
            ("cancel_execution".to_owned(), 0)
        ]
    );
    // The deploy stopped before its next step: no health check, no rollback.
    assert_eq!(
        h.runner.ops_for(&deploy.plan_id),
        vec![("prepare_release".to_owned(), 0)]
    );
    (deploy, cancel)
}

#[tokio::test]
async fn cancel_stops_a_running_deploy_and_returns_the_cancel_operation() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("cancel", Some(&vector_trust())).await;
    let (deploy, cancel) = cancel_in_prepare(&h, &owner).await;
    // D-044: the runner cleaned up the prepared candidate within the cancel;
    // the deploy's steps show it, and the deployment stays `cancelled`.
    let op = operation(&h, &deploy.operation_id).await;
    assert_eq!(
        names(&op, 0),
        vec![
            "queued",
            "bound",
            "prepare_release",
            "cleanup_candidate",
            "cancelled"
        ]
    );
    let cleanup = op
        .steps
        .iter()
        .find(|s| s.name == "cleanup_candidate")
        .unwrap();
    assert_eq!(cleanup.state, OperationState::Succeeded as i32);
    assert_eq!(cleanup.failure_code, "");
    assert_eq!(op.state, OperationState::Cancelled as i32);
    // D-064 #7: a cancelled operation carries CANCELLED (runner E_CANCELLED).
    assert_eq!(op.error_reason, ErrorReason::Cancelled as i32);
    assert_eq!(op.error_code, "E_CANCELLED");
    // The cancel plan's own step logs what the runner cancelled, before its
    // `finished` (v1.0.6, D-048): no waiting once the cancel succeeded.
    let expected = format!(
        "cancelled action 0 (deployment {}): cleanup done",
        cleanup.deployment_id
    );
    let lines = step_logs(&h, &cancel.id);
    assert!(lines.contains(&expected), "{lines:?}");
    h.stop().await;
}

/// D-069: a cancel during a hung `verify_health` still records the prepared
/// candidate's cleanup. The plan is held from the health check on, so the
/// held result must not drop `cleanup_candidate`.
#[tokio::test]
async fn cancel_during_verify_health() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("cancel-health", Some(&vector_trust())).await;
    h.runner.behave("verify_health", OpBehavior::Hang);
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let deploy = submit_ok(
        &h,
        fresh_deploy(
            &owner,
            "0000000000f3",
            "VVVVVVVVVVVVVVVVVVVVVA",
            GENESIS_HEAD,
        ),
    )
    .await;
    for _ in 0..500 {
        if h.runner
            .ops_for(&deploy.plan_id)
            .iter()
            .any(|(op, _)| op == "verify_health")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        h.runner
            .ops_for(&deploy.plan_id)
            .iter()
            .any(|(op, _)| op == "verify_health"),
        "verify_health never started: {:?}",
        h.runner.ops_for(&deploy.plan_id)
    );

    let head = next_head(GENESIS_HEAD, &deploy.plan_digest_hex);
    let cancel_plan = json!({
        "version": 1, "id": "01a0cdb5-3500-7001-8000-0000000000f4",
        "project_id": PROJECT, "environment": "production", "environment_id": ENVIRONMENT_ID,
        "service_ids": [], "targets": [SERVER_A],
        "actions": [{"kind": "operation.cancel", "params": {
            "plan_id": deploy.plan_id, "plan_digest_hex": deploy.plan_digest_hex}}],
        "base": {"force": false, "heads": {SERVER_A: head}},
        "created_at": "2026-09-23T10:04:00Z", "expires_at": "2026-09-23T10:14:00Z",
        "nonce": "WWWWWWWWWWWWWWWWWWWWWA",
        "author": {"kind": "user", "agent_session_id": null}, "invocation": null
    });
    let signed_cancel = SignedPlan {
        envelope_json: owner.envelope(&cancel_plan).into_bytes(),
        ..Default::default()
    };
    let cancel = change
        .cancel_operation(CancelOperationRequest {
            operation_id: deploy.operation_id.clone(),
            plan: Some(signed_cancel),
        })
        .await
        .unwrap()
        .into_inner();
    wait_for_state(&h, &cancel.id, OperationState::Succeeded).await;
    wait_for_state(&h, &deploy.operation_id, OperationState::Cancelled).await;
    let op = operation(&h, &deploy.operation_id).await;
    assert_eq!(
        names(&op, 0),
        vec![
            "queued",
            "bound",
            "prepare_release",
            "verify_health",
            "cleanup_candidate",
            "cancelled"
        ]
    );
    let cleanup = op
        .steps
        .iter()
        .find(|s| s.name == "cleanup_candidate")
        .unwrap();
    assert_eq!(cleanup.state, OperationState::Succeeded as i32);
    assert_eq!(cleanup.failure_code, "");
    assert_eq!(op.state, OperationState::Cancelled as i32);
    h.stop().await;
}

/// One operation event in the order the agent emitted it:
/// `(operation_id, "step:<name>:<state>" | "log:<line>" | "finished")`.
fn describe_event(event: &crate::proto::agent::v2::OperationEvent) -> (String, String) {
    let what = match &event.event {
        Some(operation_event::Event::Step(step)) => format!("step:{}:{}", step.name, step.state),
        Some(operation_event::Event::Log(log)) => format!("log:{}", log.line),
        Some(operation_event::Event::Finished(_)) => "finished".to_owned(),
        None => String::new(),
    };
    (event.operation_id.clone(), what)
}

fn position(events: &[(String, String)], operation_id: &str, what: &str) -> usize {
    events
        .iter()
        .position(|(id, w)| id == operation_id && w.starts_with(what))
        .unwrap_or_else(|| panic!("{operation_id} {what} missing: {events:#?}"))
}

/// Contracts v1.0.6 (D-048, signed-plan.md 14.6): the cancelled deploy's
/// cleanup step, its `cancelled` step and its `finished` come first; then the
/// cancel operation's step logs listing each cancelled action, its
/// `cancel_execution` step completion, and only then its `finished`. A
/// `WatchOperation` replay of the cancel therefore holds the list.
#[tokio::test]
async fn a_cancel_emits_the_cancelled_list_before_its_finished() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("cancel-order", Some(&vector_trust())).await;
    let mut feed = h.core.subscribe_operations();
    let (deploy, cancel) = cancel_in_prepare(&h, &owner).await;
    let mut events = Vec::new();
    while let Ok(event) = feed.try_recv() {
        events.push(describe_event(&event));
    }
    let succeeded = OperationState::Succeeded as i32;
    let cleanup = position(
        &events,
        &deploy.operation_id,
        &format!("step:cleanup_candidate:{succeeded}"),
    );
    let cancelled = position(
        &events,
        &deploy.operation_id,
        &format!("step:cancelled:{}", OperationState::Cancelled as i32),
    );
    let deploy_finished = position(&events, &deploy.operation_id, "finished");
    let listed = position(&events, &cancel.id, "log:cancelled action 0 (deployment ");
    let step_done = position(
        &events,
        &cancel.id,
        &format!("step:cancel_execution:{succeeded}"),
    );
    let cancel_finished = position(&events, &cancel.id, "finished");
    assert!(cleanup < cancelled, "{events:#?}");
    assert!(cancelled < deploy_finished, "{events:#?}");
    assert!(deploy_finished < listed, "{events:#?}");
    assert!(listed < step_done, "{events:#?}");
    assert!(step_done < cancel_finished, "{events:#?}");
    // Exactly one finished per operation.
    for id in [&deploy.operation_id, &cancel.id] {
        assert_eq!(
            events
                .iter()
                .filter(|(o, w)| o == id && w == "finished")
                .count(),
            1,
            "{events:#?}"
        );
    }
    // The runner closed the deploy's action when the cancel started: the
    // close marker precedes the cleanup and the one cancelled result.
    let log = std::fs::read_to_string(&h.runner.log).unwrap();
    let deploy_lines: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|l| l["plan_id"] == deploy.plan_id.as_str() && l["event"] != "consumed")
        .map(|l| json!([l["event"], l["op"], l["outcome"]]))
        .collect();
    assert_eq!(
        deploy_lines,
        vec![
            json!(["op", "prepare_release", null]),
            json!(["op", "cancel_execution", null]),
            json!(["op", "cleanup_candidate", null]),
            json!(["result", null, "cancelled"]),
        ]
    );
    h.stop().await;
}

/// v1.0.6 (signed-plan.md 14.6): when the `cancel_execution` wire result is
/// lost (connection closed), the executor takes the cancelled list from the
/// consumed log's `cancelled` result lines and still emits it before the
/// cancel operation's `finished`; the cancel succeeded.
#[tokio::test]
async fn a_lost_cancel_result_takes_the_list_from_the_consumed_log() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("cancel-lost", Some(&vector_trust())).await;
    h.runner
        .drop_cancel_result
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (deploy, cancel) = cancel_in_prepare(&h, &owner).await;
    let op = operation(&h, &deploy.operation_id).await;
    let deployment_id = op
        .steps
        .iter()
        .find(|s| s.name == "cleanup_candidate")
        .unwrap()
        .deployment_id
        .clone();
    let lines = step_logs(&h, &cancel.id);
    assert!(
        lines.contains(&format!(
            "cancelled action 0 (deployment {deployment_id}): cleanup done"
        )),
        "{lines:?}"
    );
    let cancel_op = operation(&h, &cancel.id).await;
    assert_eq!(cancel_op.error, "");
    h.stop().await;
}

/// D-044: a cleanup the runner could not finish still ends the deploy
/// `cancelled`, and the leftover candidate is reported in the step error.
#[tokio::test]
async fn a_cancel_whose_cleanup_failed_reports_the_leftover_candidate() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("cancel-leftover", Some(&vector_trust())).await;
    *h.runner.cancel_cleanup.lock().unwrap() = "failed";
    let (deploy, _) = cancel_in_prepare(&h, &owner).await;
    let op = operation(&h, &deploy.operation_id).await;
    assert_eq!(op.state, OperationState::Cancelled as i32);
    let cleanup = op
        .steps
        .iter()
        .find(|s| s.name == "cleanup_candidate")
        .unwrap();
    assert_eq!(cleanup.state, OperationState::Failed as i32);
    assert_eq!(cleanup.failure_code, "");
    assert!(
        cleanup.error.contains(&cleanup.deployment_id),
        "{}",
        cleanup.error
    );
    assert!(!cleanup.deployment_id.is_empty());
    assert!(op.error.contains("candidate"), "{}", op.error);
    assert_eq!(names(&op, 0).last().unwrap(), "cancelled");
    h.stop().await;
}

#[tokio::test]
async fn key_add_is_written_by_the_runner_not_the_agent() {
    let h = Harness::start("key-add-runner", Some(&owner_only_trust())).await;
    let reference = submit_ok(&h, signed(&plan_vector("key-add"))).await;
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    assert_eq!(
        h.runner.ops_for(&reference.plan_id),
        vec![("update_trusted_keys".to_owned(), 0)]
    );
    let op = operation(&h, &reference.operation_id).await;
    assert_eq!(
        names(&op, 0),
        vec!["queued", "bound", "update_trusted_keys", "succeeded"]
    );
    h.stop().await;
}

#[tokio::test]
async fn standing_rules_list_after_rule_create() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = Harness::start("rules", Some(&trust)).await;
    let mut plan = plan_vector("rule-create")["plan"].clone();
    plan["base"]["heads"][SERVER_A] = Value::String(GENESIS_HEAD.to_owned());
    let reference = ChangeServiceClient::new(h.channel.clone())
        .submit_signed_plan(submit(SignedPlan {
            envelope_json: owner.envelope(&plan).into_bytes(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    let rules = ChangeServiceClient::new(h.channel.clone())
        .list_standing_rules(ListStandingRulesRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rules.rules.len(), 1);
    let rule = &rules.rules[0];
    assert_eq!(
        rule.rule_digest_hex,
        vector("plans")["extras"]["rule_digest_hex"]
    );
    assert_eq!(rule.created_by_key_id, owner.key_id);
    assert_eq!(
        rule.rule_jcs,
        canonicalize(&plan["actions"][0]["params"]["rule"])
            .unwrap()
            .into_bytes()
    );
    assert!(!rule.revoked);
    h.stop().await;
}

/// v1.0.11 (D-061): `rule.revoke` is bound through the runner like every
/// definition kind. Admission only stops the rule from triggering; the rule
/// is marked revoked once the runner's `result` line is reconciled.
#[tokio::test]
async fn rule_revoke_is_bound_and_recorded_from_the_runner_result() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = Harness::start("rule-revoke", Some(&trust)).await;
    let mut create = plan_vector("rule-create")["plan"].clone();
    create["base"]["heads"][SERVER_A] = Value::String(GENESIS_HEAD.to_owned());
    let created = submit_ok(
        &h,
        SignedPlan {
            envelope_json: owner.envelope(&create).into_bytes(),
            ..Default::default()
        },
    )
    .await;
    wait_for_state(&h, &created.operation_id, OperationState::Succeeded).await;
    let rule = &create["actions"][0]["params"]["rule"];
    let mut revoke = create.clone();
    revoke["id"] = json!("01a0cdb5-3500-7001-8000-0000000000e1");
    revoke["nonce"] = json!("RRRRRRRRRRRRRRRRRRRRRA");
    revoke["base"]["heads"][SERVER_A] = json!(next_head(GENESIS_HEAD, &created.plan_digest_hex));
    revoke["actions"] = json!([{"kind": "rule.revoke", "params": {
        "rule_id": rule["id"],
        "rule_digest_hex": vector("plans")["extras"]["rule_digest_hex"]}}]);
    let revoked = submit_ok(
        &h,
        SignedPlan {
            envelope_json: owner.envelope(&revoke).into_bytes(),
            ..Default::default()
        },
    )
    .await;
    for _ in 0..200 {
        if !h.runner.consumed_for(&revoked.plan_id).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(h.runner.consumed_for(&revoked.plan_id), vec![0]);
    // Admitted and bound, not yet recorded: no longer triggers, not revoked.
    assert!(h.core.store.rules(false, 0).unwrap().is_empty());
    let all = h.core.store.rules(true, 0).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].revoked_at, None);
    h.runner
        .result(&revoked.plan_id, &revoked.plan_digest_hex, 0, "succeeded");
    wait_for_state(&h, &revoked.operation_id, OperationState::Succeeded).await;
    let all = h.core.store.rules(true, 0).unwrap();
    assert!(all[0].revoked_at.is_some());
    h.stop().await;
}

/// contracts v1.1.4 (D-062, agent-protocol.md 5.1): a `SubmitSignedPlan`
/// refused with `RATE_LIMITED` admitted nothing and reserved nothing, so
/// the engine's later re-submission of the same signed envelope is
/// admitted; refusals do not count against the budget.
#[tokio::test]
async fn a_rate_limited_plan_admits_nothing_and_its_resubmission_is_admitted() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let h = Harness::start("rate-limited", Some(&vector_trust())).await;
    for _ in 0..10 {
        assert!(h.core.allow_submission());
    }
    let plan = fresh_deploy(
        &owner,
        "0000000000a1",
        "RATELIMITEDAAAAAAAAAAA",
        GENESIS_HEAD,
    );
    let mut change = ChangeServiceClient::new(h.channel.clone());
    for _ in 0..3 {
        let refused = change
            .submit_signed_plan(submit(plan.clone()))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::ResourceExhausted);
        assert_eq!(
            trailer(&refused, ERROR_REASON_HEADER),
            "ERROR_REASON_RATE_LIMITED"
        );
    }
    let admissions = change
        .list_admissions(ListAdmissionsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(admissions.admissions.is_empty());
    // Verify sees the same limit and still admits nothing (D-071).
    let verified = change
        .verify_signed_plan(VerifySignedPlanRequest {
            plan: Some(plan.clone()),
        })
        .await
        .unwrap_err();
    assert_eq!(verified.code(), Code::ResourceExhausted);
    assert_eq!(
        trailer(&verified, ERROR_REASON_HEADER),
        "ERROR_REASON_RATE_LIMITED"
    );
    // The minute passes; the refused attempts were not counted.
    h.core.forget_submissions();
    let admitted = change
        .submit_signed_plan(submit(plan))
        .await
        .unwrap()
        .into_inner();
    assert!(!admitted.deduplicated);
    h.stop().await;
}

#[test]
fn key_statement_signing_helper_matches_the_vector_chain() {
    // The helper signs key statements exactly as trusted-keys.json expects,
    // so tests that enroll keys build valid entries.
    let Some(owner) = TestSigner::load("owner") else {
        return;
    };
    let file = vector("trusted-keys");
    let entry = &file["keys"][1];
    let resigned = owner.sign_statement(entry, KEY_ADD_PREFIX, "added_by");
    let mut rebuilt = file.clone();
    rebuilt["keys"][1] = resigned;
    assert!(crate::signed_plan::trust::validate_trust(
        &rebuilt,
        crate::signed_plan::trust::TrustMode::Test
    )
    .is_ok());
}
