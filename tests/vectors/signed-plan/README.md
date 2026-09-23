# Signed-plan test vectors

**TEST ONLY. The private keys in `keys.json` are public. Never trust these keys, and never put any of them in a
real `trusted-keys.json`.** Contract: `../../signed-plan.md`. Verify with
`python3 contracts/tools/signed_plan_vectors.py`; rebuild with `--generate`.

Production builds of every verifier and of the app reject these key ids (signed-plan.md §7.2):
`dYLNItf797wK7n5moGt2cw`, `Hph9XRkn48eogeehAgeI9A`, `AqhPUHwy5byXy_JwVWyl7w`, `cJWnw46mKT4S-FIYD8h8iA`,
`TTnId5ZJWi6UIgsNoJGjLA`. `policy-cases.json` gives each case the ServiceSpecs supplied beside the envelope
(`specs`), the `submitter` (`client` or `agent_webhook`) and the verifier `mode` (`test` or `production`).
