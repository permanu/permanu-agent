use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{pin_mut, StreamExt};
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::{
    docker_observe::{self, ContainerLogLine, LogLevel, NameFilter, ObservableContainer},
    log_forwarder::{agent_log, LogForwarder},
    proto::agent::v1::LogEntry,
};

pub async fn run(forwarder: Arc<LogForwarder>, mut shutdown: watch::Receiver<bool>) {
    let Ok(docker) = docker_observe::docker_client() else {
        warn!("docker socket unavailable; container log tailing disabled");
        return;
    };

    let filter = NameFilter::default();
    let mut tailed = HashSet::<String>::new();

    loop {
        match docker_observe::list_observable_containers(&docker, &filter).await {
            Ok(containers) => {
                for container in containers {
                    if !tailed.insert(container.id.clone()) {
                        continue;
                    }
                    let docker = docker.clone();
                    let forwarder = forwarder.clone();
                    tokio::spawn(async move {
                        tail_container(docker, forwarder, container).await;
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
    container: ObservableContainer,
) {
    debug!(container = %container.name, "starting container log tail");
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let stream = docker_observe::stream_container_logs(&docker, container, Some(since)).await;
    pin_mut!(stream);

    while let Some(item) = stream.next().await {
        match item {
            Ok(line) => {
                if let Err(err) = forwarder.push(log_entry(line)) {
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

fn log_entry(line: ContainerLogLine) -> LogEntry {
    let level = match line.level {
        LogLevel::Stdout | LogLevel::Console => "info",
        LogLevel::Stderr => "error",
    };
    let mut fields = std::collections::HashMap::new();
    fields.insert("container_id".to_string(), line.container_id);
    fields.insert("container_name".to_string(), line.container_name.clone());
    fields.insert("stream".to_string(), line.level.as_str().to_string());

    let mut entry = agent_log(level, line.message, fields);
    entry.source = source_for_container(&line.container_name);
    entry
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
}
