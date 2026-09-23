# Signed-plan test vectors

**TEST ONLY. The private keys in `keys.json` are public. Never trust these keys, and never put any of them in a
real `trusted-keys.json`.** Contract: `../../signed-plan.md`. Verify with
`python3 contracts/tools/signed_plan_vectors.py`; rebuild with `--generate`.

Production builds of every verifier and of the app reject these key ids (signed-plan.md §7.2):
`dYLNItf797wK7n5moGt2cw`, `Hph9XRkn48eogeehAgeI9A`, `AqhPUHwy5byXy_JwVWyl7w`, `cJWnw46mKT4S-FIYD8h8iA`,
`TTnId5ZJWi6UIgsNoJGjLA`. `policy-cases.json` gives each case the ServiceSpecs supplied beside the envelope
(`specs`), the `submitter` (`client` or `agent_webhook`) and the verifier `mode` (`test` or `production`). Each
`bootstrap_cases` entry carries the server's own `age_recipient` string (v1.0.5). `runner_context` and `runner_cases`
(v1.0.5, D-041 to D-043) test the runner's `bind_plan` checks 1–3 and the scope fold against a stored admissions view:
each case names the bound `{plan_id, plan_digest_hex}`, the runner's `now`, its `first_consumed_at` for the plan (or
null) and any `extra_admissions` rows, and the runner must return `expect` (reference `verify_runner_bound`).

v1.0.7 (M2): `build_cases` test the runner's `build_image` checks on `runner_context` (reference
`verify_build_bound`); `schedule_context` and `schedule_cases` test the schedule binding of scheduled cron and backup
runs against the runner's rows and its own consumed log (reference `verify_schedule_bound`). `release-keys.json`
holds three **public TEST Ed25519 release keys** (seeds included) and a sample `/etc/permanu/release-keys.json`;
production builds refuse their key ids `cl98Xxg2voSKlukyuAPKJg`, `RE1jopVSq8Moy0jDftg6Kg` and
`MA975uwluIeABZVJLGWMaA` (signed-plan.md §3.9). The real release key is generated offline by the user and never
appears here. `artifact-cases.json` tests the artifact trust verification order (reference `verify_artifact`).
