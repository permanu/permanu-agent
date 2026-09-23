//! ChangeService and EventService over the unix socket: bootstrap, admission,
//! idempotent resubmission, error trailers, execution through the runner,
//! consumed-log reconciliation, operations and events.

use std::time::Duration;

use serde_json::{json, Value};
use tokio_stream::StreamExt;
use tonic::Code;

use super::errors::PLAN_ERROR_HEADER;
use super::test_harness::{Harness, Options};
use super::ERROR_REASON_HEADER;
use crate::proto::agent::v2::{
    change_service_client::ChangeServiceClient, deploy_status_event::Phase, event,
    event_service_client::EventServiceClient, info_service_client::InfoServiceClient,
    operation_event, trusted_keys_summary::TrustState, CancelOperationRequest, EventKind,
    GetOperationRequest, GetStateHeadRequest, GetTrustedKeysRequest, HelloRequest,
    ListAdmissionsRequest, ListOperationsRequest, ListStandingRulesRequest, OperationState,
    PageRequest, SignedPlan, SubmitSignedPlanRequest, SubscribeRequest, VerifySignedPlanRequest,
    WatchOperationRequest,
};
use crate::signed_plan::crypto::{KEY_ADD_PREFIX, SPEC_PREFIX};
use crate::signed_plan::jcs::canonicalize;
use crate::signed_plan::test_support::{plan_vector, vector, TestSigner, SERVER_A};
use crate::signed_plan::verify::{next_head, GENESIS_HEAD};
use crate::signed_plan::PlanCode;

const SERVER_C: &str = "01a0cdb5-3500-70a1-8000-000000000003";
const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";

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
    // server.add is executed by the agent, never bound to the runner.
    assert!(h.runner.calls.lock().unwrap().is_empty());

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

#[tokio::test]
async fn deploy_binds_to_the_runner_and_reconciles_to_live() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = Harness::start("deploy", Some(&trust)).await;
    let mut deploys = EventServiceClient::new(h.channel.clone())
        .subscribe(SubscribeRequest {
            kinds: vec![EventKind::DeployStatus as i32],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let plan = fresh_deploy(
        &owner,
        "0000000000d1",
        "AAAAAAAAAAAAAAAAAAAAAA",
        GENESIS_HEAD,
    );
    let reference = change
        .submit_signed_plan(submit(plan))
        .await
        .unwrap()
        .into_inner();
    wait_for_state(&h, &reference.operation_id, OperationState::Running).await;
    let calls = h.runner.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![(
            reference.plan_id.clone(),
            reference.plan_digest_hex.clone(),
            0
        )]
    );

    let mut phases = Vec::new();
    for _ in 0..2 {
        let event = tokio::time::timeout(Duration::from_secs(5), deploys.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Some(event::Payload::Deploy(status)) = event.payload else {
            panic!("deploy event");
        };
        assert_eq!(status.operation_id, reference.operation_id);
        assert_eq!(status.project_id, PROJECT);
        assert!(crate::signed_plan::text::uuid7(&status.deployment_id));
        phases.push(status.phase);
    }
    assert_eq!(phases, vec![Phase::Queued as i32, Phase::Starting as i32]);

    h.runner.result(
        &reference.plan_id,
        &reference.plan_digest_hex,
        0,
        "succeeded",
    );
    wait_for_state(&h, &reference.operation_id, OperationState::Succeeded).await;
    let event = tokio::time::timeout(Duration::from_secs(5), deploys.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Some(event::Payload::Deploy(status)) = event.payload else {
        panic!("deploy event");
    };
    assert_eq!(status.phase, Phase::Live as i32);

    // The head chain advanced; the next plan must name the new head.
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
async fn runner_refusal_fails_the_operation_with_the_mapped_reason() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = Harness::start("refuse", Some(&trust)).await;
    *h.runner.fail_with.lock().unwrap() = Some(PlanCode::PlanWindow);
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let reference = change
        .submit_signed_plan(submit(fresh_deploy(
            &owner,
            "0000000000e1",
            "CCCCCCCCCCCCCCCCCCCCCA",
            GENESIS_HEAD,
        )))
        .await
        .unwrap()
        .into_inner();
    wait_for_state(&h, &reference.operation_id, OperationState::Failed).await;
    let operation = change
        .get_operation(GetOperationRequest {
            operation_id: reference.operation_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        operation
            .error
            .starts_with("ERROR_REASON_EXEC_PRECONDITION (E_PLAN_WINDOW)"),
        "{}",
        operation.error
    );
    assert_eq!(operation.steps[0].state, OperationState::Failed as i32);
    h.stop().await;
}

#[tokio::test]
async fn cancel_operation_admits_a_cancel_naming_that_operation() {
    let Some(owner) = TestSigner::load("owner") else {
        eprintln!("skipped: docs keys.json not found");
        return;
    };
    let trust = serde_json::to_string(&vector("policy-cases")["context"]["trusted_keys"]).unwrap();
    let h = Harness::start("cancel", Some(&trust)).await;
    // Binds fail so the deploy finishes without consuming anything.
    *h.runner.fail_with.lock().unwrap() = Some(PlanCode::Internal);
    let mut change = ChangeServiceClient::new(h.channel.clone());
    let deploy = change
        .submit_signed_plan(submit(fresh_deploy(
            &owner,
            "0000000000f1",
            "DDDDDDDDDDDDDDDDDDDDDA",
            GENESIS_HEAD,
        )))
        .await
        .unwrap()
        .into_inner();
    wait_for_state(&h, &deploy.operation_id, OperationState::Failed).await;

    // CancelOperation for an unknown operation is refused before admission.
    let head = next_head(GENESIS_HEAD, &deploy.plan_digest_hex);
    let cancel_plan = json!({
        "version": 1, "id": "01a0cdb5-3500-7001-8000-0000000000f2",
        "project_id": PROJECT, "environment": "production", "service_ids": [],
        "targets": [SERVER_A],
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
    let wrong = change
        .cancel_operation(CancelOperationRequest {
            operation_id: "01a0cdb5-3500-7001-8000-0000000000ff".to_owned(),
            plan: Some(signed_cancel.clone()),
        })
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), Code::NotFound);
    let cancelled = change
        .cancel_operation(CancelOperationRequest {
            operation_id: deploy.operation_id.clone(),
            plan: Some(signed_cancel),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(cancelled.actions, vec!["operation.cancel"]);
    wait_for_state(&h, &cancelled.id, OperationState::Succeeded).await;
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
