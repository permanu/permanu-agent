//! Draft standalone schema mirrored from engine composereleasev1/types.go.
//! Shape validation is not signature, policy, freshness, or replay verification.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

macro_rules! record {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
record!(Target {
    server_id: String,
    root: String,
    compose_project: String,
    config_digest: String,
    protected_digest: String,
});
record!(Source {
    repository: String,
    r#ref: String,
    commit: String,
    tree: String,
    desktop_tree: String,
});
record!(Artifacts {
    backend: BTreeMap<String, String>, authenticated_frontend: String, public_frontend: String,
});
record!(Release {
    policy_revision: u64,
    version: u32,
    capability: String,
    action: String,
    application_id: String,
    spec_digest: String,
    policy_digest: String,
    target: Target,
    source: Source,
    candidate: Artifacts,
    previous: Artifacts,
    release_id: String,
    previous_release_id: String,
    inventory_digest: String,
    migrations: String,
    generation: u64,
    previous_generation: u64,
});
record!(Attestation {
    policy_revision: u64, release_digest: String, policy_digest: String,
    verification_config_digest: String, run_id: String, producer_id: String,
    issued_at: i64, expires_at: i64, gates: BTreeMap<String, String>,
});
record!(Authorization {
    release_digest: String,
    attestation_digest: String,
    owner_id: String,
    issued_at: i64,
    expires_at: i64,
});
record!(Signature {
    key_id: String,
    alg: String,
    sig: String
});
record!(Envelope {
    release: Release,
    attestation: Attestation,
    authorization: Authorization,
    producer_signature: Signature,
    owner_signature: Signature,
});
record!(FixtureRequest {
    version: u32,
    capability: String,
    op: String,
    envelope: Envelope,
});
