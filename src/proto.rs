pub mod agent {
    pub mod v1 {
        #![allow(dead_code)]
        tonic::include_proto!("agent.v1");
    }

    /// Agent protocol v2 (local mode), package `permanu.agent.v2`.
    /// Generated only; no service is implemented or served yet.
    pub mod v2 {
        #![allow(dead_code)]
        tonic::include_proto!("permanu.agent.v2");
    }
}
