//! Owner-signed authority forwarding. The root writer alone validates and persists.
use super::runner::Runner;
use crate::proto::agent::compose::v1::{
    self as pb, compose_authority_service_server::ComposeAuthorityService,
};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tonic::{Request, Response, Status};
pub const CAPABILITY: &str = "compose-application-authority-v1";
pub struct Service {
    pub runner: Arc<dyn Runner>,
}
pub async fn available(runner: &dyn Runner) -> bool {
    matches!(runner.exchange(json!({"op":"compose_v1_authority_capabilities","payload":{"schema_version":1}}),Duration::from_secs(2)).await,Ok(v) if v["ok"]==true && v["data"]==json!({"schema_version":1,"application_authority":true}))
}
fn invalid() -> Status {
    Status::invalid_argument("Invalid Compose authority binding")
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    application_id: String,
    policy_revision: u64,
    rule_id: String,
    rule_revision: u64,
    authority_digest: String,
    active: bool,
}
impl Service {
    async fn apply(
        &self,
        version: u32,
        raw: Vec<u8>,
        activate: bool,
    ) -> Result<Response<pb::AuthorityReceipt>, Status> {
        if version != 1 {
            return Err(invalid());
        }
        let doc = crate::signed_plan::jcs::parse_strict(&raw, 65536).ok_or_else(invalid)?;
        let (app, policy, rule, revision) = if activate {
            (
                &doc["signed_enrollment"]["enrollment"]["policy"]["application_id"],
                &doc["signed_enrollment"]["enrollment"]["policy"]["revision"],
                &doc["signed_rule"]["rule"]["rule_id"],
                &doc["signed_rule"]["rule"]["revision"],
            )
        } else {
            (
                &doc["revocation"]["application_id"],
                &doc["revocation"]["policy_revision"],
                &doc["revocation"]["rule_id"],
                &doc["revocation"]["rule_revision"],
            )
        };
        let app = app.as_str().filter(|s| id(s)).ok_or_else(invalid)?;
        let rule = rule.as_str().filter(|s| id(s)).ok_or_else(invalid)?;
        let policy = policy
            .as_u64()
            .filter(|n| *n > 0 && *n <= 9007199254740991)
            .ok_or_else(invalid)?;
        let revision = revision
            .as_u64()
            .filter(|n| *n > 0 && *n <= 9007199254740991)
            .ok_or_else(invalid)?;
        let expected = if activate {
            let canonical = crate::signed_plan::jcs::canonicalize(&doc).ok_or_else(invalid)?;
            Some(hex::encode(crate::signed_plan::crypto::prefixed_digest(
                b"permanu-compose-authority-v1\n",
                &canonical,
            )))
        } else {
            None
        };
        if !available(self.runner.as_ref()).await {
            return Err(Status::unimplemented(
                "Compose authority writer unavailable",
            ));
        }
        let op = if activate {
            "compose_v1_activate_application"
        } else {
            "compose_v1_revoke_application"
        };
        let signed_json = String::from_utf8(raw).map_err(|_| invalid())?;
        let result = self
            .runner
            .exchange(
                json!({"op":op,"payload":{"schema_version":1,"signed_json":signed_json}}),
                Duration::from_secs(30),
            )
            .await
            .map_err(|_| Status::unavailable("Compose authority writer unavailable"))?;
        if result["ok"] != true {
            return Err(Status::failed_precondition(
                "Compose authority writer refused request",
            ));
        }
        let r: Receipt = serde_json::from_value(result["data"].clone())
            .map_err(|_| Status::internal("Invalid authority receipt"))?;
        if r.schema_version != 1
            || r.application_id != app
            || r.policy_revision != policy
            || r.rule_id != rule
            || r.rule_revision != revision
            || r.active != activate
            || r.authority_digest.len() != 64
            || !r
                .authority_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || expected.is_some_and(|d| d != r.authority_digest)
        {
            return Err(Status::internal("Mismatched authority receipt"));
        }
        Ok(Response::new(pb::AuthorityReceipt {
            schema_version: 1,
            application_id: r.application_id,
            policy_revision: r.policy_revision,
            rule_id: r.rule_id,
            rule_revision: r.rule_revision,
            authority_digest: r.authority_digest,
            active: r.active,
        }))
    }
}
#[tonic::async_trait]
impl ComposeAuthorityService for Service {
    async fn get_application_authority(
        &self,
        r: Request<pb::GetApplicationAuthorityRequest>,
    ) -> Result<Response<pb::AuthorityReceipt>, Status> {
        let r = r.into_inner();
        if r.schema_version != 1 || !id(&r.application_id) {
            return Err(invalid());
        }
        if !available(self.runner.as_ref()).await {
            return Err(Status::unimplemented(
                "Compose authority writer unavailable",
            ));
        }
        let result = self
            .runner
            .exchange(
                json!({"op":"compose_v1_get_application_authority",
            "payload":{"schema_version":1,"application_id":r.application_id}}),
                Duration::from_secs(10),
            )
            .await
            .map_err(|_| Status::unavailable("Compose authority writer unavailable"))?;
        if result["ok"] != true {
            return Err(Status::failed_precondition(
                "Compose authority observation refused",
            ));
        }
        let receipt: Receipt = serde_json::from_value(result["data"].clone())
            .map_err(|_| Status::internal("Invalid authority receipt"))?;
        if receipt.schema_version != 1
            || receipt.application_id != r.application_id
            || !id(&receipt.rule_id)
            || receipt.policy_revision == 0
            || receipt.policy_revision > 9007199254740991
            || receipt.rule_revision == 0
            || receipt.rule_revision > 9007199254740991
            || receipt.authority_digest.len() != 64
            || !receipt
                .authority_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Status::internal("Mismatched authority receipt"));
        }
        Ok(Response::new(pb::AuthorityReceipt {
            schema_version: 1,
            application_id: receipt.application_id,
            policy_revision: receipt.policy_revision,
            rule_id: receipt.rule_id,
            rule_revision: receipt.rule_revision,
            authority_digest: receipt.authority_digest,
            active: receipt.active,
        }))
    }
    async fn activate_application(
        &self,
        r: Request<pb::ActivateApplicationRequest>,
    ) -> Result<Response<pb::AuthorityReceipt>, Status> {
        let r = r.into_inner();
        self.apply(r.schema_version, r.signed_authority_json, true)
            .await
    }
    async fn revoke_application(
        &self,
        r: Request<pb::RevokeApplicationRequest>,
    ) -> Result<Response<pb::AuthorityReceipt>, Status> {
        let r = r.into_inner();
        self.apply(r.schema_version, r.signed_revocation_json, false)
            .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::runner::{EventLines, RunnerFailure};
    use serde_json::Value;
    struct Disabled;
    #[tonic::async_trait]
    impl Runner for Disabled {
        async fn exchange(&self, r: Value, _: Duration) -> Result<Value, RunnerFailure> {
            assert_eq!(r["op"], "compose_v1_authority_capabilities");
            Ok(json!({"ok":true,"data":{"schema_version":1,"application_authority":false}}))
        }
        async fn open(&self, _: Value) -> Result<EventLines, RunnerFailure> {
            panic!("no stream")
        }
    }
    struct Observation {
        app: &'static str,
        active: bool,
    }
    #[tonic::async_trait]
    impl Runner for Observation {
        async fn exchange(&self, r: Value, _: Duration) -> Result<Value, RunnerFailure> {
            if r["op"] == "compose_v1_authority_capabilities" {
                return Ok(
                    json!({"ok":true,"data":{"schema_version":1,"application_authority":true}}),
                );
            }
            assert_eq!(
                r,
                json!({"op":"compose_v1_get_application_authority","payload":{"schema_version":1,"application_id":"colrow"}})
            );
            Ok(
                json!({"ok":true,"data":{"schema_version":1,"application_id":self.app,"policy_revision":1,
                "rule_id":"rule","rule_revision":1,"authority_digest":"a".repeat(64),"active":self.active}}),
            )
        }
        async fn open(&self, _: Value) -> Result<EventLines, RunnerFailure> {
            panic!("no stream")
        }
    }
    #[tokio::test]
    async fn current_authority_is_scoped_and_preserves_inactive_state() {
        for active in [true, false] {
            let s = Service {
                runner: Arc::new(Observation {
                    app: "colrow",
                    active,
                }),
            };
            let result = s
                .get_application_authority(Request::new(pb::GetApplicationAuthorityRequest {
                    schema_version: 1,
                    application_id: "colrow".into(),
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(result.active, active);
        }
        let s = Service {
            runner: Arc::new(Observation {
                app: "another-app",
                active: true,
            }),
        };
        assert_eq!(
            s.get_application_authority(Request::new(pb::GetApplicationAuthorityRequest {
                schema_version: 1,
                application_id: "colrow".into()
            }))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Internal
        );
        let s = Service {
            runner: Arc::new(Disabled),
        };
        assert_eq!(
            s.get_application_authority(Request::new(pb::GetApplicationAuthorityRequest {
                schema_version: 1,
                application_id: "colrow".into()
            }))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unimplemented
        );
    }
    #[tokio::test]
    async fn authority_writer_unavailable() {
        let s = Service {
            runner: Arc::new(Disabled),
        };
        let raw=serde_json::to_vec(&json!({"revocation":{"application_id":"colrow","policy_revision":1,"rule_id":"rule","rule_revision":1}})).unwrap();
        let e = s
            .revoke_application(Request::new(pb::RevokeApplicationRequest {
                schema_version: 1,
                signed_revocation_json: raw,
            }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::Unimplemented);
    }
}

#[cfg(test)]
mod connected_tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires isolated registration fixture with ephemeral owner signatures"]
    async fn authority_rpc_real_root_fixture() {
        let dir = std::path::PathBuf::from(
            std::env::var_os("PERMANU_COMPOSE_FIXTURE_DIR").expect("fixture dir"),
        );
        let svc = Service {
            runner: Arc::new(crate::local::runner::SocketRunner {
                path: dir.join("runner.sock"),
            }),
        };
        let activation = std::fs::read(dir.join("activation.json")).unwrap();
        let revoked = std::fs::read(dir.join("revocation.json")).unwrap();
        let active = svc
            .activate_application(Request::new(pb::ActivateApplicationRequest {
                schema_version: 1,
                signed_authority_json: activation,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(active.active);
        let inactive = svc
            .revoke_application(Request::new(pb::RevokeApplicationRequest {
                schema_version: 1,
                signed_revocation_json: revoked,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!inactive.active);
        assert_eq!(active.application_id, inactive.application_id);
        assert_eq!(active.authority_digest, inactive.authority_digest);
    }
}
