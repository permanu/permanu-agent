use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{pin_mut, StreamExt};
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::{
    docker_observe::{self, ContainerLogLine, LogLevel, NameFilter, ObservableContainer},
    log_forwarder::{agent_log, redact_log_message, LogForwarder},
    proto::agent::v1::{AppContainerMapping, LogEntry},
};

pub async fn run(
    forwarder: Arc<LogForwarder>,
    identity_mappings: ContainerIdentityMappings,
    mut shutdown: watch::Receiver<bool>,
) {
    let Ok(docker) = docker_observe::docker_client() else {
        warn!("docker socket unavailable; container log tailing disabled");
        return;
    };

    let filter = NameFilter::default();
    let tailed = TailRegistry::default();

    loop {
        match docker_observe::list_observable_containers(&docker, &filter).await {
            Ok(containers) => {
                for container in containers {
                    if !tailed.try_mark_tailed(&container.id) {
                        continue;
                    }
                    let docker = docker.clone();
                    let forwarder = forwarder.clone();
                    let identity_mappings = identity_mappings.clone();
                    let tailed = tailed.clone();
                    let container_id = container.id.clone();
                    tokio::spawn(async move {
                        tail_container(docker, forwarder, identity_mappings, container).await;
                        tailed.mark_finished(&container_id);
                    });
                }
            }
            Err(err) => warn!(error = ?err, "list observable containers for log tailing failed"),
        }

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(15)) => {}
        }
    }
}

async fn tail_container(
    docker: bollard::Docker,
    forwarder: Arc<LogForwarder>,
    identity_mappings: ContainerIdentityMappings,
    container: ObservableContainer,
) {
    debug!(container = %container.name, "starting container log tail");
    let context = ContainerLogContext::from_container(&container, &identity_mappings);
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let stream = docker_observe::stream_container_logs(&docker, container, Some(since)).await;
    pin_mut!(stream);

    while let Some(item) = stream.next().await {
        match item {
            Ok(line) => {
                if let Err(err) = forwarder.push(log_entry_with_context(line, &context)) {
                    warn!(error = ?err, "failed to enqueue container log");
                }
            }
            Err(err) => {
                warn!(error = ?err, "container log stream ended with error");
                return;
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContainerIdentityMappings {
    mappings: Arc<std::sync::RwLock<HashMap<String, ContainerIdentity>>>,
}

impl ContainerIdentityMappings {
    #[cfg(test)]
    pub fn from_heartbeat(mappings: Vec<AppContainerMapping>) -> Self {
        let state = Self::default();
        state.update_from_heartbeat(mappings);
        state
    }

    pub fn update_from_heartbeat(&self, mappings: Vec<AppContainerMapping>) {
        let mut next = HashMap::new();
        for mapping in mappings {
            let identity = ContainerIdentity {
                app_id: mapping.app_id,
                deployment_id: mapping.deployment_id,
            };
            if !mapping.container_name.is_empty() {
                next.insert(mapping.container_name, identity.clone());
            }
            if !mapping.container_id.is_empty() {
                next.insert(mapping.container_id, identity);
            }
        }
        *self
            .mappings
            .write()
            .expect("container identity mapping lock poisoned") = next;
    }

    fn lookup(&self, container_id: &str, container_name: &str) -> Option<ContainerIdentity> {
        let mappings = self
            .mappings
            .read()
            .expect("container identity mapping lock poisoned");
        mappings
            .get(container_id)
            .or_else(|| mappings.get(container_name))
            .cloned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContainerIdentity {
    app_id: String,
    deployment_id: String,
}

#[derive(Clone, Default)]
struct TailRegistry {
    tailed: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl TailRegistry {
    fn try_mark_tailed(&self, container_id: &str) -> bool {
        self.tailed
            .lock()
            .expect("tail registry mutex poisoned")
            .insert(container_id.to_string())
    }

    fn mark_finished(&self, container_id: &str) {
        self.tailed
            .lock()
            .expect("tail registry mutex poisoned")
            .remove(container_id);
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ContainerLogContext {
    image: String,
    status: String,
    app_slug: String,
    process: String,
    replica: String,
    compose_project: String,
    app_id: String,
    deployment_id: String,
}

impl From<&ObservableContainer> for ContainerLogContext {
    fn from(container: &ObservableContainer) -> Self {
        Self::from_container(container, &ContainerIdentityMappings::default())
    }
}

impl ContainerLogContext {
    fn from_container(
        container: &ObservableContainer,
        mappings: &ContainerIdentityMappings,
    ) -> Self {
        let mut context = Self {
            image: container.image.clone(),
            status: container.status.clone(),
            app_slug: container
                .labels
                .get("deploy-app")
                .cloned()
                .unwrap_or_default(),
            process: container
                .labels
                .get("permanu.process")
                .cloned()
                .unwrap_or_default(),
            replica: container
                .labels
                .get("permanu.replica")
                .cloned()
                .unwrap_or_default(),
            compose_project: container
                .labels
                .get("com.docker.compose.project")
                .cloned()
                .unwrap_or_default(),
            app_id: String::new(),
            deployment_id: String::new(),
        };
        if let Some(identity) = mappings.lookup(&container.id, &container.name) {
            context.app_id = identity.app_id;
            context.deployment_id = identity.deployment_id;
        }
        context
    }

    #[cfg(test)]
    fn from_mapping(
        mappings: &ContainerIdentityMappings,
        container_id: &str,
        container_name: &str,
    ) -> Self {
        let mut context = Self::default();
        if let Some(identity) = mappings.lookup(container_id, container_name) {
            context.app_id = identity.app_id;
            context.deployment_id = identity.deployment_id;
        }
        context
    }
}

#[cfg(test)]
fn log_entry(line: ContainerLogLine) -> LogEntry {
    log_entry_with_context(line, &ContainerLogContext::default())
}

fn log_entry_with_context(line: ContainerLogLine, context: &ContainerLogContext) -> LogEntry {
    let level = match line.level {
        LogLevel::Stdout | LogLevel::Console => "info",
        LogLevel::Stderr => "error",
    };
    let redacted = redact_log_message(&line.message);
    let mut fields = std::collections::HashMap::new();
    fields.insert("source_type".to_string(), "container".to_string());
    fields.insert("container_id".to_string(), line.container_id);
    fields.insert("container_name".to_string(), line.container_name.clone());
    fields.insert("stream".to_string(), line.level.as_str().to_string());
    fields.insert("ingest_status".to_string(), "live".to_string());
    fields.insert(
        "redaction_status".to_string(),
        if redacted.was_redacted {
            "redacted".to_string()
        } else {
            "none".to_string()
        },
    );
    insert_nonempty(&mut fields, "image", &context.image);
    insert_nonempty(&mut fields, "container_status", &context.status);
    insert_nonempty(&mut fields, "app_slug", &context.app_slug);
    insert_nonempty(&mut fields, "process", &context.process);
    insert_nonempty(&mut fields, "replica", &context.replica);
    insert_nonempty(&mut fields, "compose_project", &context.compose_project);

    let mut entry = agent_log(level, redacted.message, fields);
    entry.source = source_for_container(&line.container_name);
    entry.app_id = context.app_id.clone();
    entry.deployment_id = context.deployment_id.clone();
    entry
}

fn insert_nonempty(fields: &mut std::collections::HashMap<String, String>, key: &str, value: &str) {
    if !value.is_empty() {
        fields.insert(key.to_string(), value.to_string());
    }
}

fn source_for_container(name: &str) -> String {
    if name.starts_with("deploy-app-") {
        format!("app:{name}")
    } else if name.starts_with("deploy-svc-") {
        format!("service:{name}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::agent::v1::AppContainerMapping;

    #[test]
    fn source_names_match_backend_log_conventions() {
        assert_eq!(
            source_for_container("deploy-app-web-a1"),
            "app:deploy-app-web-a1"
        );
        assert_eq!(
            source_for_container("deploy-svc-postgres-a1"),
            "service:deploy-svc-postgres-a1"
        );
        assert_eq!(source_for_container("dwaar"), "dwaar");
    }

    #[test]
    fn container_log_entry_carries_canonical_source_fields() {
        let entry = log_entry(ContainerLogLine {
            container_id: "ctr-1".to_string(),
            container_name: "deploy-app-web-a1".to_string(),
            level: LogLevel::Stderr,
            message: "boom".to_string(),
        });

        assert_eq!(entry.source, "app:deploy-app-web-a1");
        assert_eq!(entry.level, "error");
        assert_eq!(
            entry.fields.get("source_type").map(String::as_str),
            Some("container")
        );
        assert_eq!(
            entry.fields.get("container_id").map(String::as_str),
            Some("ctr-1")
        );
        assert_eq!(
            entry.fields.get("container_name").map(String::as_str),
            Some("deploy-app-web-a1")
        );
        assert_eq!(
            entry.fields.get("stream").map(String::as_str),
            Some("stderr")
        );
        assert_eq!(
            entry.fields.get("ingest_status").map(String::as_str),
            Some("live")
        );
        assert_eq!(
            entry.fields.get("redaction_status").map(String::as_str),
            Some("none")
        );
    }

    #[test]
    fn container_log_entry_redacts_common_secret_patterns() {
        let entry = log_entry(ContainerLogLine {
            container_id: "ctr-1".to_string(),
            container_name: "deploy-app-web-a1".to_string(),
            level: LogLevel::Stdout,
            message: "Authorization: Bearer ghp_rawtoken password=hunter2 api_key=abc123 --secret shh token: xyz".to_string(),
        });

        assert!(!entry.message.contains("ghp_rawtoken"));
        assert!(!entry.message.contains("hunter2"));
        assert!(!entry.message.contains("abc123"));
        assert!(!entry.message.contains("shh"));
        assert!(!entry.message.contains("xyz"));
        assert!(entry.message.contains("[REDACTED]"));
        assert_eq!(
            entry.fields.get("redaction_status").map(String::as_str),
            Some("redacted")
        );
    }

    #[test]
    fn container_log_entry_uses_observable_context_when_available() {
        let mut labels = std::collections::HashMap::new();
        labels.insert("deploy-app".to_string(), "web".to_string());
        labels.insert("permanu.process".to_string(), "worker".to_string());
        labels.insert("permanu.replica".to_string(), "2".to_string());
        labels.insert("com.docker.compose.project".to_string(), "demo".to_string());
        let context = ContainerLogContext::from(&ObservableContainer {
            id: "ctr-1".to_string(),
            name: "deploy-app-web-a1".to_string(),
            image: "deploy-app-web:abc123".to_string(),
            status: "running".to_string(),
            labels,
        });

        let entry = log_entry_with_context(
            ContainerLogLine {
                container_id: "ctr-1".to_string(),
                container_name: "deploy-app-web-a1".to_string(),
                level: LogLevel::Stdout,
                message: "ready".to_string(),
            },
            &context,
        );

        assert_eq!(
            entry.fields.get("image").map(String::as_str),
            Some("deploy-app-web:abc123")
        );
        assert_eq!(
            entry.fields.get("container_status").map(String::as_str),
            Some("running")
        );
        assert_eq!(
            entry.fields.get("app_slug").map(String::as_str),
            Some("web")
        );
        assert_eq!(
            entry.fields.get("process").map(String::as_str),
            Some("worker")
        );
        assert_eq!(entry.fields.get("replica").map(String::as_str), Some("2"));
        assert_eq!(
            entry.fields.get("compose_project").map(String::as_str),
            Some("demo")
        );
    }

    #[test]
    fn container_log_entry_uses_heartbeat_identity_mapping_when_available() {
        let mappings = ContainerIdentityMappings::from_heartbeat(vec![AppContainerMapping {
            container_name: "deploy-app-web-a1".to_string(),
            app_id: "app-123".to_string(),
            deployment_id: "deploy-456".to_string(),
            container_id: "ctr-1".to_string(),
        }]);
        let context = ContainerLogContext::from_mapping(&mappings, "ctr-1", "deploy-app-web-a1");

        let entry = log_entry_with_context(
            ContainerLogLine {
                container_id: "ctr-1".to_string(),
                container_name: "deploy-app-web-a1".to_string(),
                level: LogLevel::Stdout,
                message: "ready".to_string(),
            },
            &context,
        );

        assert_eq!(entry.app_id, "app-123");
        assert_eq!(entry.deployment_id, "deploy-456");
    }

    #[test]
    fn tail_registry_allows_retry_after_stream_finishes() {
        let registry = TailRegistry::default();

        assert!(registry.try_mark_tailed("ctr-1"));
        assert!(!registry.try_mark_tailed("ctr-1"));

        registry.mark_finished("ctr-1");

        assert!(registry.try_mark_tailed("ctr-1"));
    }
}
