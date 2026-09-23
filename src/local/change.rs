//! `ChangeService` (agent-protocol.md sections 3–6): the only general write
//! path in local mode. Every mutation is a signed plan admitted by
//! `ChangeCore`; everything else here is read-only.

use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use futures::Stream;
use serde_json::Value;
use tonic::{Code, Request, Response, Status};

use super::errors::{plan_status, reason_for};
use super::execution::{decode_event, not_supported_yet, ChangeCore, Submission};
use super::{log_peer, status_with_reason};
use crate::admissions::AdmissionRecord;
use crate::proto::agent::v2::{
    change_service_server::ChangeService, operation_event, Admission, CancelOperationRequest,
    ErrorReason, GetOperationRequest, GetStateHeadRequest, GetTrustedKeysRequest,
    ListAdmissionsRequest, ListAdmissionsResponse, ListOperationsRequest, ListOperationsResponse,
    ListStandingRulesRequest, ListStandingRulesResponse, Operation, OperationEvent, OperationRef,
    PageInfo, PageRequest, SignedPlan, StandingRuleInfo, StateHead, SubmitSignedPlanRequest,
    TrustedKey, TrustedKeySet, VerificationFailure, VerifySignedPlanRequest,
    VerifySignedPlanResponse, WatchOperationRequest,
};
use crate::signed_plan::text::{self, timestamp as parse_ts};
use crate::signed_plan::trust::TrustState;
use crate::signed_plan::verify::Submitter;
use crate::signed_plan::PlanCode;

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 500;

pub struct ChangeSvc {
    pub core: Arc<ChangeCore>,
}

fn ts(text: &str) -> Option<prost_types::Timestamp> {
    parse_ts(text).map(|seconds| prost_types::Timestamp { seconds, nanos: 0 })
}

fn page_size(page: &PageRequest) -> usize {
    match page.page_size as usize {
        0 => DEFAULT_PAGE_SIZE,
        n => n.min(MAX_PAGE_SIZE),
    }
}

fn page_position(token: &str) -> Result<i64, Status> {
    if token.is_empty() {
        return Ok(0);
    }
    token
        .strip_prefix("a")
        .and_then(|n| n.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .ok_or_else(|| Status::invalid_argument("invalid page_token"))
}

fn internal() -> Status {
    plan_status(PlanCode::Internal)
}

fn submission(plan: Option<SignedPlan>) -> Result<Submission, Status> {
    let plan = plan.ok_or_else(|| plan_status(PlanCode::Parse))?;
    Ok(Submission {
        envelope: plan.envelope_json,
        specs: plan.specs_jcs,
        sealed_secrets: plan.sealed_secrets,
    })
}

fn admission_proto(record: AdmissionRecord, include_signed_plan: bool) -> Admission {
    Admission {
        plan_id: record.plan_id,
        nonce: record.nonce,
        plan_digest_hex: record.plan_digest_hex,
        admitted_at: ts(&record.admitted_at),
        finished_at: record.finished_at.as_deref().and_then(ts),
        outcome: record.outcome,
        author_kind: record.author_kind,
        key_ids: record.signer_key_ids,
        rule_id: record.rule_id.unwrap_or_default(),
        actions: record.action_kinds,
        project_id: record.project_id,
        environment: record.environment,
        head_after_digest_hex: record.head_after_hex,
        signed_plan_json: if include_signed_plan {
            record.signed_plan_json.into_bytes()
        } else {
            Vec::new()
        },
        expires_at: ts(&record.expires_at),
        submitter: record.submitter,
        operation_id: record.operation_id,
        environment_id: record.environment_id,
    }
}

impl ChangeSvc {
    fn operation_by_id(&self, operation_id: &str) -> Result<(AdmissionRecord, Operation), Status> {
        if !text::uuid7(operation_id) {
            return Err(Status::invalid_argument("operation_id must be a UUIDv7"));
        }
        let record = self
            .core
            .store
            .admission_by_operation(operation_id)
            .map_err(|_| internal())?
            .ok_or_else(|| Status::not_found("unknown operation"))?;
        let operation = self.core.operation(&record);
        Ok((record, operation))
    }

    pub(crate) async fn submit(&self, plan: Option<SignedPlan>) -> Result<OperationRef, Status> {
        if !self.core.allow_submission() {
            return Err(status_with_reason(
                Code::ResourceExhausted,
                "at most 10 plan submissions per minute",
                ErrorReason::RateLimited,
            ));
        }
        let submission = submission(plan)?;
        if let Some(staging) = self.core.staging.get() {
            // agent-protocol.md 13 "Install": a committed, verified,
            // unexpired set with the plan's digest must be staged.
            for digest in update_digests(&submission.envelope) {
                if !staging.staged(&digest).await {
                    return Err(status_with_reason(
                        Code::FailedPrecondition,
                        "artifact_not_staged: no verified staged set for bundle_manifest_digest_hex",
                        ErrorReason::ExecPrecondition,
                    ));
                }
            }
        } else if let Some(action) = not_supported_yet(&submission.envelope) {
            return Err(status_with_reason(
                Code::Unimplemented,
                &format!(
                    "not_supported_yet: {action} waits for the M2 artifact trust root (D-046)"
                ),
                // v2.0.6: its own reason (was CAPABILITY_MISSING).
                ErrorReason::NotSupportedYet,
            ));
        }
        let admission = self
            .core
            .submit(submission, Submitter::Client)
            .await
            .map_err(plan_status)?;
        Ok(OperationRef {
            operation_id: admission.operation_id,
            plan_digest_hex: admission.plan_digest_hex,
            accepted_at: ts(&admission.admitted_at),
            deduplicated: admission.deduplicated,
            plan_id: admission.plan_id,
        })
    }
}

/// `bundle_manifest_digest_hex` of every `agent.update` and
/// `component.update` (not `os_packages`) of an envelope. Not verified
/// here: this can only refuse.
fn update_digests(envelope: &[u8]) -> Vec<String> {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(envelope) else {
        return Vec::new();
    };
    parsed["plan"]["actions"]
        .as_array()
        .map(|actions| {
            actions
                .iter()
                .filter(|a| {
                    a["kind"] == "agent.update"
                        || (a["kind"] == "component.update"
                            && a["params"]["component"] != "os_packages")
                })
                .map(|a| {
                    a["params"]["bundle_manifest_digest_hex"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

type WatchStream = Pin<Box<dyn Stream<Item = Result<OperationEvent, Status>> + Send>>;

#[tonic::async_trait]
impl ChangeService for ChangeSvc {
    async fn submit_signed_plan(
        &self,
        request: Request<SubmitSignedPlanRequest>,
    ) -> Result<Response<OperationRef>, Status> {
        log_peer(&request, "SubmitSignedPlan");
        let reference = self.submit(request.into_inner().plan).await?;
        Ok(Response::new(reference))
    }

    async fn verify_signed_plan(
        &self,
        request: Request<VerifySignedPlanRequest>,
    ) -> Result<Response<VerifySignedPlanResponse>, Status> {
        log_peer(&request, "VerifySignedPlan");
        let submission = submission(request.into_inner().plan)?;
        let response = match self.core.verify(submission).await {
            Ok((plan, digest, signers)) => {
                let field = |name: &str| plan[name].as_str().and_then(ts);
                VerifySignedPlanResponse {
                    valid: true,
                    plan_digest_hex: digest,
                    verified_key_ids: signers,
                    rule_id: plan["invocation"]["rule_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    actions: plan["actions"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x["kind"].as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                    created_at: field("created_at"),
                    expires_at: field("expires_at"),
                    failures: Vec::new(),
                    plan_id: plan["id"].as_str().unwrap_or_default().to_owned(),
                }
            }
            Err(PlanCode::Internal) => return Err(internal()),
            Err(code) => VerifySignedPlanResponse {
                valid: false,
                failures: vec![VerificationFailure {
                    reason: reason_for(code) as i32,
                    detail: plan_status(code).message().to_owned(),
                    code: code.as_str().to_owned(),
                }],
                ..Default::default()
            },
        };
        Ok(Response::new(response))
    }

    async fn get_operation(
        &self,
        request: Request<GetOperationRequest>,
    ) -> Result<Response<Operation>, Status> {
        let (_, operation) = self.operation_by_id(&request.into_inner().operation_id)?;
        Ok(Response::new(operation))
    }

    async fn list_operations(
        &self,
        request: Request<ListOperationsRequest>,
    ) -> Result<Response<ListOperationsResponse>, Status> {
        let request = request.into_inner();
        if request.range.is_some() {
            return Err(Status::invalid_argument("range filtering is not supported"));
        }
        let page = request.page.unwrap_or_default();
        let limit = page_size(&page);
        let mut before = page_position(&page.page_token)?;
        let mut operations = Vec::new();
        let mut next = String::new();
        // Newest first; state filtering happens after the fetch, so walk
        // pages until this one is full or the log ends.
        'fetch: loop {
            let rows = self
                .core
                .store
                .admissions_before(before, limit)
                .map_err(|_| internal())?;
            if rows.is_empty() {
                break;
            }
            for record in rows {
                before = record.admission_seq;
                let operation = self.core.operation(&record);
                if request.states.is_empty() || request.states.contains(&operation.state) {
                    operations.push(operation);
                    if operations.len() == limit {
                        if before > 1 {
                            next = format!("a{before}");
                        }
                        break 'fetch;
                    }
                }
            }
        }
        Ok(Response::new(ListOperationsResponse {
            operations,
            page: Some(PageInfo {
                next_page_token: next,
            }),
        }))
    }

    type WatchOperationStream = WatchStream;

    async fn watch_operation(
        &self,
        request: Request<WatchOperationRequest>,
    ) -> Result<Response<Self::WatchOperationStream>, Status> {
        let request = request.into_inner();
        // Subscribe before replaying so no event falls between the two.
        let mut live = self.core.subscribe_operations();
        let (record, _) = self.operation_by_id(&request.operation_id)?;
        let replay = self
            .core
            .store
            .operation_events_after(&record.operation_id, request.after_seq)
            .map_err(|_| internal())?;
        let operation_id = record.operation_id.clone();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<OperationEvent, Status>>(64);
        let closed = self.core.events.closed();
        tokio::spawn(async move {
            tokio::pin!(closed);
            let mut last = request.after_seq;
            for (_, text) in replay {
                let Some(event) = decode_event(&text) else {
                    continue;
                };
                last = event.seq;
                let finished = matches!(event.event, Some(operation_event::Event::Finished(_)));
                if tx.send(Ok(event)).await.is_err() || finished {
                    return;
                }
            }
            loop {
                let received = tokio::select! {
                    () = &mut closed => return,
                    received = live.recv() => received,
                };
                match received {
                    Ok(event) if event.operation_id == operation_id && event.seq > last => {
                        last = event.seq;
                        let finished =
                            matches!(event.event, Some(operation_event::Event::Finished(_)));
                        if tx.send(Ok(event)).await.is_err() || finished {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let _ = tx
                            .send(Err(status_with_reason(
                                Code::OutOfRange,
                                "watcher fell behind; resume with after_seq",
                                ErrorReason::CursorExpired,
                            )))
                            .await;
                        return;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn cancel_operation(
        &self,
        request: Request<CancelOperationRequest>,
    ) -> Result<Response<Operation>, Status> {
        log_peer(&request, "CancelOperation");
        let request = request.into_inner();
        let (target, _) = self.operation_by_id(&request.operation_id)?;
        let plan = request
            .plan
            .clone()
            .ok_or_else(|| plan_status(PlanCode::Parse))?;
        // The plan's only action must be operation.cancel naming this
        // operation's plan; the agent checks the shape before admitting.
        let envelope: Value = serde_json::from_slice(&plan.envelope_json)
            .map_err(|_| plan_status(PlanCode::Parse))?;
        let actions = envelope["plan"]["actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let names_target = actions.len() == 1
            && actions[0]["kind"] == "operation.cancel"
            && actions[0]["params"]["plan_id"] == target.plan_id.as_str()
            && actions[0]["params"]["plan_digest_hex"] == target.plan_digest_hex.as_str();
        if !names_target {
            return Err(plan_status(PlanCode::ExecPrecondition));
        }
        let reference = self.submit(Some(plan)).await?;
        let (_, operation) = self.operation_by_id(&reference.operation_id)?;
        Ok(Response::new(operation))
    }

    async fn get_state_head(
        &self,
        request: Request<GetStateHeadRequest>,
    ) -> Result<Response<StateHead>, Status> {
        let request = request.into_inner();
        let server_level = request.project_id.is_empty() && request.environment.is_empty();
        let valid = server_level
            || (text::uuid7(&request.project_id) && text::reference(&request.environment));
        if !valid {
            return Err(Status::invalid_argument(
                "project_id (UUIDv7) and environment (REF) must both be set, or both empty",
            ));
        }
        let head = self
            .core
            .store
            .head(&request.project_id, &request.environment)
            .map_err(|_| internal())?;
        let quarantine = self
            .core
            .store
            .quarantine_ends_at()
            .map_err(|_| internal())?
            .filter(|end| self.core.now() < *end);
        let server_id = match self.core.trust.load() {
            TrustState::Valid(store) => store.server_id,
            _ => String::new(),
        };
        Ok(Response::new(StateHead {
            project_id: request.project_id,
            environment: request.environment,
            head_digest_hex: head.head_digest_hex,
            server_id,
            last_plan_id: head.last_plan_id,
            updated_at: head.updated_at.as_deref().and_then(ts),
            quarantined: quarantine.is_some(),
            quarantine_ends_at: quarantine
                .map(|seconds| prost_types::Timestamp { seconds, nanos: 0 }),
        }))
    }

    async fn list_admissions(
        &self,
        request: Request<ListAdmissionsRequest>,
    ) -> Result<Response<ListAdmissionsResponse>, Status> {
        let request = request.into_inner();
        let page = request.page.unwrap_or_default();
        let after = page_position(&page.page_token)?;
        let rows = self
            .core
            .store
            .admissions_after(after, page_size(&page))
            .map_err(|_| internal())?;
        // The token is a durable position, set even on the last page, and
        // empty only while no admission exists.
        let next = match rows.last() {
            Some(last) => format!("a{}", last.admission_seq),
            None => page.page_token.clone(),
        };
        let admissions = rows
            .into_iter()
            .map(|record| admission_proto(record, request.include_signed_plan))
            .collect();
        Ok(Response::new(ListAdmissionsResponse {
            admissions,
            page: Some(PageInfo {
                next_page_token: next,
            }),
        }))
    }

    async fn list_standing_rules(
        &self,
        request: Request<ListStandingRulesRequest>,
    ) -> Result<Response<ListStandingRulesResponse>, Status> {
        let request = request.into_inner();
        let page = request.page.unwrap_or_default();
        let offset = page_position(&page.page_token)? as usize;
        let limit = page_size(&page);
        let rules = self
            .core
            .store
            .rules(request.include_revoked, self.core.now())
            .map_err(|_| internal())?;
        let end = (offset + limit).min(rules.len());
        let next = if end < rules.len() {
            format!("a{end}")
        } else {
            String::new()
        };
        let items = rules
            .get(offset..end)
            .unwrap_or_default()
            .iter()
            .map(|rule| {
                let expires = serde_json::from_str::<Value>(&rule.rule_jcs)
                    .ok()
                    .and_then(|r| r["expires_at"].as_str().and_then(ts));
                StandingRuleInfo {
                    rule_id: rule.rule_id.clone(),
                    rule_jcs: rule.rule_jcs.clone().into_bytes(),
                    rule_digest_hex: rule.rule_digest_hex.clone(),
                    installed_at: ts(&rule.installed_at),
                    revoked: rule.revoked_at.is_some(),
                    revoked_at: rule.revoked_at.as_deref().and_then(ts),
                    match_count: rule.match_count,
                    last_matched_at: rule.last_matched_at.as_deref().and_then(ts),
                    created_by_key_id: rule.created_by_key_id.clone(),
                    created_plan_id: rule.created_plan_id.clone(),
                    expires_at: expires,
                    invocations_last_hour: rule.invocations_last_hour,
                }
            })
            .collect();
        Ok(Response::new(ListStandingRulesResponse {
            rules: items,
            page: Some(PageInfo {
                next_page_token: next,
            }),
        }))
    }

    async fn get_trusted_keys(
        &self,
        request: Request<GetTrustedKeysRequest>,
    ) -> Result<Response<TrustedKeySet>, Status> {
        let include_revoked = request.into_inner().include_revoked;
        let store = match self.core.trust.load() {
            TrustState::Valid(store) => store,
            TrustState::Absent => {
                return Err(status_with_reason(
                    Code::FailedPrecondition,
                    "no trusted-keys file yet (bootstrap state)",
                    ErrorReason::TrustSetEmpty,
                ))
            }
            TrustState::Invalid { .. } => return Err(plan_status(PlanCode::TrustStoreInvalid)),
        };
        let mut keys = Vec::new();
        for entry in store.document["keys"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
        {
            let key_id = entry["key_id"].as_str().unwrap_or_default().to_owned();
            let revoked = store.revoked.contains(&key_id);
            if revoked && !include_revoked {
                continue;
            }
            let direct = store.revocations.get(&key_id);
            let strings = |value: &Value| -> Vec<String> {
                value
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|i| i.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            keys.push(TrustedKey {
                key_id: key_id.clone(),
                alg: entry["alg"].as_str().unwrap_or_default().to_owned(),
                spki_der: base64::engine::general_purpose::STANDARD
                    .decode(entry["spki"].as_str().unwrap_or_default())
                    .unwrap_or_default(),
                label: entry["label"].as_str().unwrap_or_default().to_owned(),
                added_at: entry["added_at"].as_str().and_then(ts),
                revoked,
                revoked_at: direct.and_then(|(at, _)| ts(at)),
                role: entry["role"].as_str().unwrap_or_default().to_owned(),
                presence: entry["presence"].as_str().unwrap_or_default().to_owned(),
                added_by_key_id: entry["added_by"]["key_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                revocation_reason: match direct {
                    Some((_, reason)) => reason.clone(),
                    None if revoked => "cascade".to_owned(),
                    None => String::new(),
                },
                scope_project_ids: strings(&entry["scope"]["project_ids"]),
                scope_environments: strings(&entry["scope"]["environments"]),
                scope_server_level: entry["scope"]["server_level"] == true,
            });
        }
        Ok(Response::new(TrustedKeySet {
            keys,
            fingerprint_digest_hex: store.fingerprint_digest_hex(),
            generation: store.generation(),
            trusted_keys_json: store.raw.clone(),
        }))
    }
}
