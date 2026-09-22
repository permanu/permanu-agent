const V2_PROTOS: &[&str] = &[
    "proto/agent/v2/common.proto",
    "proto/agent/v2/info.proto",
    "proto/agent/v2/telemetry.proto",
    "proto/agent/v2/schedules.proto",
    "proto/agent/v2/backups.proto",
    "proto/agent/v2/alerts.proto",
    "proto/agent/v2/webhooks.proto",
    "proto/agent/v2/changes.proto",
    "proto/agent/v2/events.proto",
    "proto/agent/v2/shell.proto",
    "proto/agent/v2/state.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    // v1: hosted mode. The agent is a gRPC client of the control plane.
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(&["proto/agent/v1/agent.proto"], &["proto"])?;

    // v2: local mode. The agent serves these on its unix socket; the client
    // stubs are generated for in-crate integration tests.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(V2_PROTOS, &["proto"])?;

    println!("cargo:rerun-if-changed=proto/agent/v1/agent.proto");
    for proto in V2_PROTOS {
        println!("cargo:rerun-if-changed={proto}");
    }
    Ok(())
}
