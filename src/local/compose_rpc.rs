//! Whole-release forwarding only. Root runner owns trust, replay and host effects.
use super::runner::{Runner, READ_TIMEOUT};
use crate::proto::agent::compose::v1::{
    self as pb, compose_release_service_server::ComposeReleaseService,
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tonic::{Request, Response, Status};
pub const CAPABILITY: &str = "compose-release-standing-v1";
pub struct Service {
    pub runner: Arc<dyn Runner>,
}
pub async fn available(runner: &dyn Runner) -> bool {
    match runner
        .exchange(
            json!({"op":"compose_v1_capabilities","payload":{"schema_version":1}}),
            // Live inventory/artifact checks use the existing bounded read budget.
            // Unavailable callers may now wait up to 30 seconds rather than two.
            READ_TIMEOUT,
        )
        .await
    {
        Ok(v) => {
            v["ok"] == true && v["data"] == json!({"schema_version":1,"standing_release":true})
        }
        Err(_) => false,
    }
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn invalid() -> Status {
    Status::invalid_argument("Invalid Compose binding")
}
fn malformed() -> Status {
    Status::internal("Invalid Compose runner response")
}
impl Service {
    async fn call(&self, op: &str, payload: Value) -> Result<Value, Status> {
        if !available(self.runner.as_ref()).await {
            return Err(Status::unimplemented("Compose backend unavailable"));
        }
        let result = self
            .runner
            .exchange(json!({"op":op,"payload":payload}), Duration::from_secs(310))
            .await
            .map_err(|_| {
                Status::unavailable("Compose runner unavailable; query operation status")
            })?;
        if result["ok"] != true {
            return Err(match result["error"]["code"].as_str() {
                Some("E_UNIMPLEMENTED") => Status::unimplemented("Compose backend unavailable"),
                Some("E_NOT_FOUND") => Status::not_found("Compose operation not found"),
                _ => Status::failed_precondition("Compose runner refused operation"),
            });
        }
        let data = result.get("data").cloned().ok_or_else(malformed)?;
        if serde_json::to_vec(&data).map_err(|_| malformed())?.len() > 16384 {
            return Err(malformed());
        }
        Ok(data)
    }
}
#[tonic::async_trait]
impl ComposeReleaseService for Service {
    async fn submit_standing_release(
        &self,
        r: Request<pb::SubmitStandingReleaseRequest>,
    ) -> Result<Response<pb::ReleaseOperation>, Status> {
        let r = r.into_inner();
        if r.schema_version != 1 {
            return Err(invalid());
        }
        let v =
            crate::signed_plan::jcs::parse_strict(&r.envelope_json, 65536).ok_or_else(invalid)?;
        let env: crate::compose_release_v1::standing::StandingEnvelope =
            serde_json::from_value(v.clone()).map_err(|_| invalid())?;
        if env.authority_mode != "standing-rule-v1"
            || env.release.version != 1
            || env.release.capability != "compose-release-v1"
            || env.release.action != "compose.release"
            || !id(&env.release.application_id)
        {
            return Err(invalid());
        }
        let canonical = crate::signed_plan::jcs::canonicalize(&v["release"]).ok_or_else(invalid)?;
        let hash = hex::encode(crate::signed_plan::crypto::prefixed_digest(
            b"permanu-compose-release-v1\n",
            &canonical,
        ));
        let text = String::from_utf8(r.envelope_json).map_err(|_| invalid())?;
        let data = self
            .call(
                "compose_v1_submit_standing_release",
                json!({"schema_version":1,"envelope_json":text}),
            )
            .await?;
        Ok(Response::new(operation(
            data,
            &env.release.application_id,
            &hash,
        )?))
    }
    async fn get_release_operation(
        &self,
        r: Request<pb::GetReleaseOperationRequest>,
    ) -> Result<Response<pb::ReleaseOperation>, Status> {
        let r = r.into_inner();
        if r.schema_version != 1 || !id(&r.application_id) || !digest(&r.operation_id) {
            return Err(invalid());
        }
        let data=self.call("compose_v1_get_release_operation",json!({"schema_version":1,"application_id":r.application_id,"operation_id":r.operation_id})).await?;
        Ok(Response::new(operation(
            data,
            &r.application_id,
            &r.operation_id,
        )?))
    }
    async fn observe_registered_application(
        &self,
        r: Request<pb::ObserveRegisteredApplicationRequest>,
    ) -> Result<Response<pb::RegisteredApplicationObservation>, Status> {
        let r = r.into_inner();
        if r.schema_version != 1 || !id(&r.application_id) {
            return Err(invalid());
        }
        let data = self
            .call(
                "compose_v1_observe_registered_application",
                json!({"schema_version":1,"application_id":r.application_id}),
            )
            .await?;
        Ok(Response::new(observation(data, &r.application_id)?))
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    schema_version: u32,
    operation_id: String,
    application_id: String,
    release_digest: String,
    outcome: String,
    reason: String,
}
fn operation(data: Value, app: &str, hash: &str) -> Result<pb::ReleaseOperation, Status> {
    let r: Operation = serde_json::from_value(data).map_err(|_| malformed())?;
    if r.schema_version != 1
        || r.application_id != app
        || r.operation_id != hash
        || r.release_digest != hash
        || (!r.reason.is_empty() && !id(&r.reason))
    {
        return Err(malformed());
    }
    let outcome = match r.outcome.as_str() {
        "in_progress" => 1,
        "deployed" => 2,
        "rolled_back" => 3,
        "failed" => 4,
        "recovery_required" => 5,
        _ => return Err(malformed()),
    };
    Ok(pb::ReleaseOperation {
        schema_version: 1,
        operation_id: r.operation_id,
        application_id: r.application_id,
        release_digest: r.release_digest,
        outcome,
        reason: r.reason,
    })
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema_version: u32,
    application_id: String,
    spec_digest: String,
    policy_revision: u64,
    target: Target,
    inventory_digest: String,
    release_id: String,
    generation: u64,
    artifacts: Artifacts,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    server_id: String,
    root: String,
    compose_project: String,
    config_digest: String,
    protected_digest: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    server: String,
    worker: String,
    authenticated_frontend: String,
    public_frontend: String,
}
fn observation(data: Value, app: &str) -> Result<pb::RegisteredApplicationObservation, Status> {
    let r: Observation = serde_json::from_value(data).map_err(|_| malformed())?;
    if r.schema_version != 1
        || r.application_id != app
        || r.policy_revision == 0
        || r.policy_revision > 9007199254740991
        || r.generation > 9007199254740991
        || !id(&r.release_id)
        || !id(&r.target.server_id)
        || !id(&r.target.compose_project)
        || r.target.root.len() > 1024
        || !r.target.root.starts_with('/')
        || r.target.root == "/"
        || r.target.root.contains('\\')
        || r.target.root[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || r.target.root.bytes().any(|b| b < 32 || b == 127)
        || [
            &r.spec_digest,
            &r.inventory_digest,
            &r.target.config_digest,
            &r.target.protected_digest,
            &r.artifacts.server,
            &r.artifacts.worker,
            &r.artifacts.authenticated_frontend,
            &r.artifacts.public_frontend,
        ]
        .iter()
        .any(|s| !digest(s))
    {
        return Err(malformed());
    }
    Ok(pb::RegisteredApplicationObservation {
        schema_version: 1,
        application_id: r.application_id,
        spec_digest: r.spec_digest,
        policy_revision: r.policy_revision,
        inventory_digest: r.inventory_digest,
        release_id: r.release_id,
        generation: r.generation,
        target: Some(pb::RegisteredTarget {
            server_id: r.target.server_id,
            root: r.target.root,
            compose_project: r.target.compose_project,
            config_digest: r.target.config_digest,
            protected_digest: r.target.protected_digest,
        }),
        artifacts: Some(pb::ReleaseArtifacts {
            server: r.artifacts.server,
            worker: r.artifacts.worker,
            authenticated_frontend: r.artifacts.authenticated_frontend,
            public_frontend: r.artifacts.public_frontend,
        }),
    })
}
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "compose_rpc/availability_tests.rs"]
mod availability_tests;
