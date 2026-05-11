# Permanu Agent

Rust implementation of the Permanu remote agent.

The agent is a long-lived process that connects a customer server to the
Permanu control plane over gRPC/TLS. It is designed for low idle memory,
bounded host inspection, reliable command execution, and SRE-grade debugging
without keeping heavyweight workers resident when they are not needed.

## Capabilities

- Host heartbeat with version, boot time, container runtime status, and resource
  usage.
- Deployment, service, compose, backup, Dwaar, and control-plane identity
  command handling.
- Docker and systemd observation with bounded output and redaction.
- Log forwarding with local spool fallback.
- SRE tools exposed through the Permanu control plane, including host snapshots,
  metrics samples, process and network inspection, DNS/HTTP/TLS probes, journal
  queries, service status, container inspection/logs, file stats, config digests,
  package inventory, audit events, alerts, and safe TCP probes.

## Build

```bash
cargo build --release
```

The build uses the vendored `protoc` dependency and the checked-in
`proto/agent/v1/agent.proto` file.

## Test

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

## Runtime

Required environment:

- `BACKEND_GRPC_ADDR`: control-plane gRPC endpoint.
- `SERVER_ID`: Permanu server identifier.
- `AGENT_SECRET`: shared agent authentication secret.

Optional environment:

- `AGENT_INSECURE=true`: allow plaintext gRPC for local development.
- `AGENT_VERSION`: override reported agent version.
- `PERMANU_AGENT_REPORT_CHECKSUM=1`: include the running binary SHA-256 in
  heartbeat metadata.
- `PERMANU_AGENT_TLS_INSECURE_SKIP_VERIFY=true`: development-only TLS bypass.
- `PERMANU_AGENT_SPOOL_DIR`: local command/log spool directory.

The production service should run with a dedicated system user, least-privilege
filesystem access, and narrowly scoped access to Docker/systemd only where the
managed server role requires it.
