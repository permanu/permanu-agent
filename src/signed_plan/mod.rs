//! Signed-plan v1 verification for the agent, the single admitter
//! (signed-plan.md sections 2–7, D-017, D-022).
//!
//! `jcs`, `text`, `crypto`, `schema` and `strict_json` are ported from
//! `permanu-runner` (`runner/src/signed_plan`, feat/ws3-verify) so both
//! verifiers apply the same parse and schema rules. `verify` adds the
//! admission-only steps 7–12 and the bootstrap of section 7.3.

pub mod crypto;
pub mod jcs;
pub mod schema;
mod strict_json;
pub mod text;
pub mod trust;
pub mod verify;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod vector_tests;

/// Error codes of signed-plan.md sections 6.1, 7.3 and 14 (runner codes are
/// here so runner failures map to the same agent reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanCode {
    Parse,
    Version,
    SpecMismatch,
    Target,
    Author,
    SigAlg,
    KeyUnknown,
    KeyRevoked,
    SigInvalid,
    RuleUnknown,
    RuleRevoked,
    Lifetime,
    NotYetValid,
    Expired,
    Replay,
    BaseMismatch,
    ForceForbidden,
    TouchIdRequired,
    KindForbidden,
    KeyScope,
    RuleWindow,
    RuleScope,
    RuleLimit,
    RuleEvidence,
    RuleSpec,
    Bootstrap,
    ExecPrecondition,
    TrustStoreInvalid,
    /// Not a signed-plan code: the 1200 s re-seed quarantine (section 6.3).
    StoreQuarantined,
    Internal,
    PlanRequired,
    PlanNotAdmitted,
    PlanWindow,
    PlanAction,
    PlanArgs,
    PlanConsumed,
    /// Runner (sections 14.2 check 3b, 14.7, v1.0.5 D-042).
    ScopeMismatch,
    /// Runner (section 14.4).
    RollbackTargetUnknown,
    /// Runner (section 14.4, v1.0.6 D-046 clarification): M1 refuses
    /// `agent.update` and `component.update(runner|permanu-env)`.
    NotSupportedYet,
    /// Runner (section 14.11, v1.0.13 D-063 #11): an admitted
    /// `operation.cancel` stopped the op; not a failure.
    Cancelled,
    /// Runner (section 14.8, v1.0.15 D-065 #9): four shells are open.
    ShellLimit,
}

impl PlanCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "E_PARSE",
            Self::Version => "E_VERSION",
            Self::SpecMismatch => "E_SPEC_MISMATCH",
            Self::Target => "E_TARGET",
            Self::Author => "E_AUTHOR",
            Self::SigAlg => "E_SIG_ALG",
            Self::KeyUnknown => "E_KEY_UNKNOWN",
            Self::KeyRevoked => "E_KEY_REVOKED",
            Self::SigInvalid => "E_SIG_INVALID",
            Self::RuleUnknown => "E_RULE_UNKNOWN",
            Self::RuleRevoked => "E_RULE_REVOKED",
            Self::Lifetime => "E_LIFETIME",
            Self::NotYetValid => "E_NOT_YET_VALID",
            Self::Expired => "E_EXPIRED",
            Self::Replay => "E_REPLAY",
            Self::BaseMismatch => "E_BASE_MISMATCH",
            Self::ForceForbidden => "E_FORCE_FORBIDDEN",
            Self::TouchIdRequired => "E_TOUCH_ID_REQUIRED",
            Self::KindForbidden => "E_KIND_FORBIDDEN",
            Self::KeyScope => "E_KEY_SCOPE",
            Self::RuleWindow => "E_RULE_WINDOW",
            Self::RuleScope => "E_RULE_SCOPE",
            Self::RuleLimit => "E_RULE_LIMIT",
            Self::RuleEvidence => "E_RULE_EVIDENCE",
            Self::RuleSpec => "E_RULE_SPEC",
            Self::Bootstrap => "E_BOOTSTRAP",
            Self::ExecPrecondition => "E_EXEC_PRECONDITION",
            Self::TrustStoreInvalid => "trust_store_invalid",
            Self::StoreQuarantined => "STORE_QUARANTINED",
            Self::Internal => "E_INTERNAL",
            Self::PlanRequired => "E_PLAN_REQUIRED",
            Self::PlanNotAdmitted => "E_PLAN_NOT_ADMITTED",
            Self::PlanWindow => "E_PLAN_WINDOW",
            Self::PlanAction => "E_PLAN_ACTION",
            Self::PlanArgs => "E_PLAN_ARGS",
            Self::PlanConsumed => "E_PLAN_CONSUMED",
            Self::ScopeMismatch => "E_SCOPE_MISMATCH",
            Self::RollbackTargetUnknown => "E_ROLLBACK_TARGET_UNKNOWN",
            Self::NotSupportedYet => "E_NOT_SUPPORTED_YET",
            Self::Cancelled => "E_CANCELLED",
            Self::ShellLimit => "E_SHELL_LIMIT",
        }
    }

    /// Parses a code as the runner reports it (`error.code` of `bind_plan`).
    pub fn parse(code: &str) -> Option<Self> {
        ALL_CODES.iter().copied().find(|c| c.as_str() == code)
    }
}

const ALL_CODES: &[PlanCode] = &[
    PlanCode::Parse,
    PlanCode::Version,
    PlanCode::SpecMismatch,
    PlanCode::Target,
    PlanCode::Author,
    PlanCode::SigAlg,
    PlanCode::KeyUnknown,
    PlanCode::KeyRevoked,
    PlanCode::SigInvalid,
    PlanCode::RuleUnknown,
    PlanCode::RuleRevoked,
    PlanCode::Lifetime,
    PlanCode::NotYetValid,
    PlanCode::Expired,
    PlanCode::Replay,
    PlanCode::BaseMismatch,
    PlanCode::ForceForbidden,
    PlanCode::TouchIdRequired,
    PlanCode::KindForbidden,
    PlanCode::KeyScope,
    PlanCode::RuleWindow,
    PlanCode::RuleScope,
    PlanCode::RuleLimit,
    PlanCode::RuleEvidence,
    PlanCode::RuleSpec,
    PlanCode::Bootstrap,
    PlanCode::ExecPrecondition,
    PlanCode::TrustStoreInvalid,
    PlanCode::StoreQuarantined,
    PlanCode::Internal,
    PlanCode::PlanRequired,
    PlanCode::PlanNotAdmitted,
    PlanCode::PlanWindow,
    PlanCode::PlanAction,
    PlanCode::PlanArgs,
    PlanCode::PlanConsumed,
    PlanCode::ScopeMismatch,
    PlanCode::RollbackTargetUnknown,
    PlanCode::NotSupportedYet,
    PlanCode::Cancelled,
    PlanCode::ShellLimit,
];

#[cfg(test)]
mod code_tests {
    use super::*;

    #[test]
    fn codes_round_trip_through_their_contract_strings() {
        for code in ALL_CODES {
            assert_eq!(PlanCode::parse(code.as_str()), Some(*code));
        }
        assert_eq!(PlanCode::parse("E_NOPE"), None);
        // v1.0.6 runner codes (signed-plan.md 14.2-14.4).
        for (text, code) in [
            ("E_SCOPE_MISMATCH", PlanCode::ScopeMismatch),
            ("E_ROLLBACK_TARGET_UNKNOWN", PlanCode::RollbackTargetUnknown),
            ("E_NOT_SUPPORTED_YET", PlanCode::NotSupportedYet),
            // v1.0.13 (D-063 #11) and v1.0.15 (D-065 #9).
            ("E_CANCELLED", PlanCode::Cancelled),
            ("E_SHELL_LIMIT", PlanCode::ShellLimit),
        ] {
            assert_eq!(PlanCode::parse(text), Some(code));
        }
    }
}
