# Experimental Compose fixture boundary

This isolated candidate adds the default-disabled Cargo feature `compose-release-v1`.
With the feature enabled, the local agent registers bounded Compose release and
authority RPCs and forwards whole transactions to the runner. Enabling the feature
alone does not enroll a host, install a signer or activate deployment. The runner
independently verifies authority and executes admitted transactions.

The fixture boundary described below remains a separate structural test harness;
its fixture-only result is not evidence of runtime deployment qualification.

`Boundary::bind` owns a trusted `AdmissionVerifier` and `FixtureTransport`.
`prepare` checks the exact bounded schema and digest links, then invokes that
verifier. `dispatch` rechecks freshness and the same verifier before forwarding an
immutable envelope. The only accepted result state is `fixture_validated`; a
`deployed` response is rejected. The complete wrapped request is limited to 64 KiB;
an envelope near that limit can be refused when wrapping adds overhead.

The fixture boundary contains no production verifier or host implementation. Its
verifier must
independently enforce both signatures, role-specific enrolled public keys,
revocation, policy revision, target/config/source/artifact binding and required
CI gates. Structural checks and the fake fixture authority are not cryptographic
admission. Durable replay/journal/host execution are also not provided here.

Published source provenance (runtime qualification remains separate):

- Protocol `proto-v2.1.13` at `be921a7602ed7814743ac02c2309a9bca9047d74`.
- Contracts `contracts-v1.7.0` at `36fa35b4e85bb684b1ffc9da19190a932980c8d6`.
- Exact vendored sources and SHA-256 values: `tests/vectors/compose-release-sources.json`.
  The checksum regression checks these actual build inputs; `build.rs` generates
  tonic/prost bindings from the pinned protocol. Publication does not enable CD.

- `src/compose_release_v1/generated.rs` copied verbatim from the published
  contracts generator. SHA-256:
  `d52af480b40b8ce56bc5c2f73a48451a554e8a4ea0a82ad50e04ba604d34a64f`.
- `tests/vectors/compose-release-v1/structural-only.fake.json` copied from the
  published structural vector. SHA-256:
  `b2a1a279c4ecbbbb2d52e83ea557207868fc6fa51e5c28eb94d6c77e236c9ae1`.
  Its signatures are deliberately invalid and timestamps expired. Tests use
  an explicitly injected exact-fixture authority and historical time.

Focused check:

```sh
CARGO_TARGET_DIR=/tmp/permanu-compose-agent-target cargo test --offline --jobs 2 --features compose-release-v1 compose_release_v1
```

A separate local qualification harness at `/tmp/permanu-compose-crosscomponent`
loads these actual source modules and the isolated runner crate through local
paths to demonstrate their accepting fixture round-trip. It is not a production
package dependency or a deployment qualification.

Reproduce that cross-component check using the preserved harness source:

```sh
python3 tools/compose-fixture/run.py --runner /absolute/path/to/permanu-ai/runner --target-dir /tmp/permanu-compose-compat-target
```

The script accepts an explicit runner checkout, generates a disposable Cargo
manifest outside either repository, and runs offline with two build jobs. It
introduces no dependency into the main agent package.
