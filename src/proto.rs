#[path = "compose_codec.rs"]
pub mod compose_codec;
pub mod agent {
    /// Unpublished additive bindings; no service registration is implied.
    pub mod compose {
        pub mod v1 {
            #![allow(
                dead_code,
                clippy::doc_lazy_continuation,
                clippy::doc_overindented_list_items
            )]
            tonic::include_proto!("permanu.agent.compose.v1");
        }
    }
    pub mod v1 {
        #![allow(dead_code)]
        tonic::include_proto!("agent.v1");
    }

    /// Agent protocol v2 (local mode), package `permanu.agent.v2`.
    /// Generated only; no service is implemented or served yet.
    pub mod v2 {
        #![allow(dead_code)]
        // Generated from the proto comments, which are prose, not markdown.
        #![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]
        // prost names oneof variants after their fields (DbCell.value: *_value).
        #![allow(clippy::enum_variant_names)]
        tonic::include_proto!("permanu.agent.v2");
    }
}
