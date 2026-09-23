//! signed-plan.md codes → agent `ErrorReason` and gRPC status
//! (agent-protocol.md section 5). Admission failures and runner `bind_plan`
//! failures use the same mapping.

use tonic::{
    metadata::{MetadataMap, MetadataValue},
    Code, Status,
};

use super::ERROR_REASON_HEADER;
use crate::proto::agent::v2::ErrorReason;
use crate::signed_plan::PlanCode;

pub const PLAN_ERROR_HEADER: &str = "permanu-plan-error";

/// The agent reason for a signed-plan (or runner) code.
pub fn reason_for(code: PlanCode) -> ErrorReason {
    use ErrorReason as R;
    use PlanCode as P;
    match code {
        P::Parse => R::PlanMalformed,
        P::SpecMismatch => R::SpecMismatch,
        P::Version => R::PlanVersion,
        P::Author => R::PlanAuthority,
        P::Target => R::PlanWrongServer,
        P::SigAlg | P::SigInvalid => R::SignatureInvalid,
        P::KeyUnknown => R::KeyUntrusted,
        P::KeyRevoked => R::KeyRevoked,
        P::Lifetime | P::Expired => R::PlanExpired,
        P::NotYetValid => R::PlanNotYetValid,
        P::Replay => R::PlanReplayed,
        P::BaseMismatch => R::BaseMismatch,
        P::ForceForbidden => R::ForceForbidden,
        P::TouchIdRequired => R::TouchIdRequired,
        P::KindForbidden => R::ActionNotPermitted,
        P::KeyScope => R::KeyScope,
        P::RuleUnknown
        | P::RuleRevoked
        | P::RuleWindow
        | P::RuleScope
        | P::RuleLimit
        | P::RuleEvidence
        | P::RuleSpec => R::RuleRejected,
        P::Bootstrap => R::BootstrapRejected,
        P::ExecPrecondition => R::ExecPrecondition,
        P::TrustStoreInvalid => R::TrustStoreInvalid,
        P::StoreQuarantined => R::StoreQuarantined,
        P::Internal => R::Internal,
        // Runner binding codes (section 14): the admitted action cannot be
        // bound in its current state.
        P::PlanRequired
        | P::PlanNotAdmitted
        | P::PlanWindow
        | P::PlanAction
        | P::PlanArgs
        | P::PlanConsumed => R::ExecPrecondition,
    }
}

/// The gRPC code for a reason (agent-protocol.md section 5 table).
pub fn grpc_code_for(reason: ErrorReason) -> Code {
    use ErrorReason as R;
    match reason {
        R::PlanMalformed | R::PlanVersion | R::SpecMismatch => Code::InvalidArgument,
        R::SignatureInvalid
        | R::KeyUntrusted
        | R::KeyRevoked
        | R::KeyScope
        | R::ActionNotPermitted
        | R::PlanAuthority
        | R::ForceForbidden
        | R::TouchIdRequired
        | R::RuleRejected
        | R::BootstrapRejected
        | R::StandingRuleMismatch => Code::PermissionDenied,
        R::PlanReplayed => Code::AlreadyExists,
        R::BaseMismatch | R::Conflict => Code::Aborted,
        R::CursorExpired | R::ResumeTokenExpired => Code::OutOfRange,
        R::LimitExceeded | R::RateLimited => Code::ResourceExhausted,
        R::CapabilityMissing => Code::Unimplemented,
        R::Internal => Code::Internal,
        _ => Code::FailedPrecondition,
    }
}

fn message_for(code: PlanCode) -> &'static str {
    match code {
        PlanCode::StoreQuarantined => {
            "admissions.db was recreated; admissions resume after the 20-minute quarantine"
        }
        PlanCode::TrustStoreInvalid => "the trusted-keys file is invalid",
        PlanCode::Internal => "the agent could not read or write its store",
        PlanCode::Bootstrap => "the plan is not a valid server.add bootstrap for this server",
        PlanCode::ExecPrecondition => "the plan cannot execute in the server's current state",
        _ => "the signed plan was rejected",
    }
}

/// A plan failure as a gRPC status with both trailers.
pub fn plan_status(code: PlanCode) -> Status {
    let reason = reason_for(code);
    let mut metadata = MetadataMap::new();
    metadata.insert(
        ERROR_REASON_HEADER,
        MetadataValue::from_static(reason.as_str_name()),
    );
    if code != PlanCode::StoreQuarantined {
        metadata.insert(PLAN_ERROR_HEADER, MetadataValue::from_static(code.as_str()));
    }
    Status::with_metadata(
        grpc_code_for(reason),
        format!("{}: {}", code.as_str(), message_for(code)),
        metadata,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_table_rows_map_exactly() {
        let rows = [
            (
                PlanCode::Parse,
                ErrorReason::PlanMalformed,
                Code::InvalidArgument,
            ),
            (
                PlanCode::SpecMismatch,
                ErrorReason::SpecMismatch,
                Code::InvalidArgument,
            ),
            (
                PlanCode::Version,
                ErrorReason::PlanVersion,
                Code::InvalidArgument,
            ),
            (
                PlanCode::Author,
                ErrorReason::PlanAuthority,
                Code::PermissionDenied,
            ),
            (
                PlanCode::Target,
                ErrorReason::PlanWrongServer,
                Code::FailedPrecondition,
            ),
            (
                PlanCode::SigAlg,
                ErrorReason::SignatureInvalid,
                Code::PermissionDenied,
            ),
            (
                PlanCode::KeyUnknown,
                ErrorReason::KeyUntrusted,
                Code::PermissionDenied,
            ),
            (
                PlanCode::Lifetime,
                ErrorReason::PlanExpired,
                Code::FailedPrecondition,
            ),
            (
                PlanCode::Replay,
                ErrorReason::PlanReplayed,
                Code::AlreadyExists,
            ),
            (
                PlanCode::BaseMismatch,
                ErrorReason::BaseMismatch,
                Code::Aborted,
            ),
            (
                PlanCode::KindForbidden,
                ErrorReason::ActionNotPermitted,
                Code::PermissionDenied,
            ),
            (
                PlanCode::KeyScope,
                ErrorReason::KeyScope,
                Code::PermissionDenied,
            ),
            (
                PlanCode::RuleSpec,
                ErrorReason::RuleRejected,
                Code::PermissionDenied,
            ),
            (
                PlanCode::Bootstrap,
                ErrorReason::BootstrapRejected,
                Code::PermissionDenied,
            ),
            (
                PlanCode::ExecPrecondition,
                ErrorReason::ExecPrecondition,
                Code::FailedPrecondition,
            ),
            (
                PlanCode::TrustStoreInvalid,
                ErrorReason::TrustStoreInvalid,
                Code::FailedPrecondition,
            ),
            (
                PlanCode::StoreQuarantined,
                ErrorReason::StoreQuarantined,
                Code::FailedPrecondition,
            ),
            (PlanCode::Internal, ErrorReason::Internal, Code::Internal),
            (
                PlanCode::PlanWindow,
                ErrorReason::ExecPrecondition,
                Code::FailedPrecondition,
            ),
        ];
        for (code, reason, grpc) in rows {
            assert_eq!(reason_for(code), reason, "{code:?}");
            let status = plan_status(code);
            assert_eq!(status.code(), grpc, "{code:?}");
            assert_eq!(
                status.metadata().get(ERROR_REASON_HEADER).unwrap(),
                reason.as_str_name()
            );
        }
        let status = plan_status(PlanCode::KeyScope);
        assert_eq!(
            status.metadata().get(PLAN_ERROR_HEADER).unwrap(),
            "E_KEY_SCOPE"
        );
    }
}
