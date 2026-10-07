# Proposed proto-v2.1.13 — unpublished

Base: published proto-v2.1.11, commit
3837313364f752fdc6b0d6329104699ad533e818. The proposed tag is not published.
Review: https://github.com/permanu/permanu-agent/pull/1. The PR uses main
ancestry and includes a separate test-only CI correction. A clean local candidate
from the published protocol base contains only the protocol/documentation delta;
its commit identity is recorded in the coherent specs release graph.
Only protocol changes are required native-CI baseline (new 21-line ci.proto and
three state.proto lines adding spec_jcs=12), plus new standalone
agent/compose/v1/compose.proto. Mixed local proto-v2.1.12 runtime commits are not
included or published by implication. No runtime consumer is enabled by a proto tag.

ComposeReleaseService is additive, schema version 1, explicitly negotiated as
compose-release-standing-v1. Submit delivers one complete signed standing
invocation to a root-runner-owned durable transaction. Get recovers outcomes by
application and deterministic release digest after dropped replies. Observe is
read-only registered scope, never enrollment. No legacy SignedPlan/RPC meaning
changes. Unknown/missing/bounded fields still require semantic validation by
accepting implementations; protobuf generation alone does not enforce them.

Generate Go with existing protoc-gen-go and protoc-gen-go-grpc into the engine's
new internal/agentpb/composev1 package; do not regenerate old frozen messages.
The isolated agent compiles this new namespace via existing tonic/prost build.rs.
No service may advertise capability or route mutation without registered policy,
standing authority and a configured qualified production root host adapter.
No credentials, registration grants, live changes or publication are authorized
by this candidate. Review source, generated bindings and cross-language tests
before freezing a tag.

Transport IDs use `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`. This matches the
current agent validator and deliberately excludes colon, although the draft
envelope schemas permit a wider identifier alphabet. Accepted requests must
satisfy both schema and transport validation; no validator is broadened here.
