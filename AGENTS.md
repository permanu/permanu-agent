# Permanu Agent Guide

The Permanu agent runs on BYOS servers and is part of the production observability chain. Treat agent logs as customer-visible product data, not debug noise.

## Logging and Tracing Contract

- Container, service, Dwaar, host diagnostic, and agent logs must preserve source identity whenever available: source type, container id/name, image, compose project, server/host, app id, deployment id, stream, trace id, span id, redaction status, and ingest status.
- Redact secrets before logs are enqueued, streamed, or sent to the control plane. Treat unredacted tokens/passwords/API keys in stdout/stderr as production bugs.
- Prefer structured `LogEntry.fields` over encoding identity into the free-form `source` string. Keep the source string compatible with existing conventions, but add explicit fields for backend/Shell correlation.
- Do not add broad host log collection by default. New sources must be allowlisted, bounded, and safe for BYOS machines.
- Preserve spool/backpressure behavior. If logs are dropped due to spool limits, expose counters/status rather than silently hiding the condition.
- Any change to log tailing must include tests for retry/resume behavior so a transient Docker stream error does not permanently stop tailing that container.

## Verification

For logging changes, run targeted Rust tests for the changed modules, typically:

```bash
cargo test container_logs
cargo test log_forwarder
cargo test service_lifecycle
```

If the full suite fails on unrelated tests, report the exact failing test and keep the logging-focused verification separate.
