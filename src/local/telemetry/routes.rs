//! Route host → service attribution of Dwaar records (contracts v1.1.5,
//! D-063 #9; agent-protocol.md 9.5, signed-plan.md 14.3 `routes_map`).
//!
//! The agent asks the runner's read-only op `routes_map` at start, every
//! 60 s, after every finished plan that holds a `domain.*`,
//! `webhook.host.set`, `deploy` or `rollback` action, and (QA_M2 run 5 X1)
//! when a Dwaar record names a host the map does not know; it files each
//! Dwaar `http` record under the `service_id`, `project_id` and
//! `environment_id` of the route host it matched. A host the map does not
//! name (the webhook host, an unknown host) is stored with no service ids;
//! its `dwaar.*` samples wait up to 120 s for a refresh that names it. A
//! failed refresh keeps the last map.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::local::runner::{self, Runner, RunnerFailure};
use crate::signed_plan::text;

/// signed-plan.md 14.3: at most 10,000 entries.
const MAX_ROUTES: usize = 10_000;
/// agent-protocol.md 9.5: refreshed every 60 s.
const REFRESH_EVERY: Duration = Duration::from_secs(60);
/// QA_M2 run 5 X1: a host the map does not name asks for a refresh at most
/// this often.
const UNKNOWN_HOST_EVERY: Duration = Duration::from_secs(5);

/// The owner of one route host (ids are empty for the webhook host).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteOwner {
    pub service_id: String,
    pub project_id: String,
    pub environment_id: String,
    /// `custom`, `default` or `webhook`.
    pub source: String,
}

/// Parses a `routes_map` result; `None` when it has no `routes` list.
/// Entries with a malformed host or id are skipped.
pub fn parse_routes(result: &Value) -> Option<HashMap<String, RouteOwner>> {
    let routes = result["routes"].as_array()?;
    let mut map = HashMap::new();
    for route in routes.iter().take(MAX_ROUTES) {
        let Some(host) = route["host"]
            .as_str()
            .filter(|h| text::hostname(h) || text::public_ipv4(h))
        else {
            continue;
        };
        let id = |name: &str| match &route[name] {
            Value::Null => Some(String::new()),
            Value::String(id) if text::uuid7(id) => Some(id.clone()),
            _ => None,
        };
        let (Some(service_id), Some(project_id), Some(environment_id)) =
            (id("service_id"), id("project_id"), id("environment_id"))
        else {
            continue;
        };
        let source = route["source"].as_str().unwrap_or_default();
        if !matches!(source, "custom" | "default" | "webhook") {
            continue;
        }
        map.insert(
            host.to_owned(),
            RouteOwner {
                service_id,
                project_id,
                environment_id,
                source: source.to_owned(),
            },
        );
    }
    Some(map)
}

/// The current route host → owner map.
#[derive(Default)]
pub struct RoutesMap {
    map: RwLock<HashMap<String, RouteOwner>>,
    nudge: Notify,
    /// Bumped by every [`RoutesMap::replace`].
    generation: AtomicU64,
    /// When an unknown host last asked for a refresh.
    unknown_nudged: Mutex<Option<Instant>>,
}

impl RoutesMap {
    /// The service that owns `host` (any case, no port); `None` for a host
    /// the map does not name or that names no service.
    pub fn owner(&self, host: &str) -> Option<RouteOwner> {
        self.map
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&host.to_ascii_lowercase())
            .filter(|owner| !owner.service_id.is_empty())
            .cloned()
    }

    /// Whether the map names `host` (any case), with or without a service.
    pub fn knows(&self, host: &str) -> bool {
        self.map
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&host.to_ascii_lowercase())
    }

    pub fn replace(&self, map: HashMap<String, RouteOwner>) {
        *self.map.write().unwrap_or_else(|p| p.into_inner()) = map;
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Changes with every refresh that replaced the map.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// QA_M2 run 5 X1: a Dwaar record named `host`, which the map may not
    /// know yet (a route created since the last refresh). Asks for a refresh
    /// when the map does not name the host, at most once per
    /// [`UNKNOWN_HOST_EVERY`]; true when it asked.
    pub fn unknown_host(&self, host: &str) -> bool {
        if self.knows(host) {
            return false;
        }
        let mut last = self
            .unknown_nudged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if last.is_some_and(|at| at.elapsed() < UNKNOWN_HOST_EVERY) {
            return false;
        }
        *last = Some(Instant::now());
        self.nudge();
        true
    }

    /// One `routes_map` call; the map is kept when it fails.
    pub async fn refresh(&self, runner: &dyn Runner) -> Result<(), RunnerFailure> {
        let request = json!({"op": "routes_map", "payload": {}});
        let result = runner::ok_or_failure(runner.exchange(request, runner::READ_TIMEOUT).await?)?;
        let map = parse_routes(&result)
            .ok_or_else(|| RunnerFailure::transport("routes_map returned no routes"))?;
        self.replace(map);
        Ok(())
    }

    /// Asks for a refresh now (a plan changed the routes).
    pub fn nudge(&self) {
        self.nudge.notify_one();
    }

    /// Refreshes at start, every 60 s and on every nudge until aborted.
    pub fn spawn(self: &Arc<Self>, runner: Arc<dyn Runner>) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(failure) = this.refresh(runner.as_ref()).await {
                    debug!(code = %failure.code, "routes_map failed; the last map is kept");
                }
                tokio::select! {
                    () = tokio::time::sleep(REFRESH_EVERY) => {}
                    () = this.nudge.notified() => {}
                }
            }
        })
    }
}

/// Whether a finished plan's actions can change the routes: a domain, the
/// webhook host, or (QA_M2 run 5 X1) a release whose `ServiceSpec.routes`
/// Dwaar now serves (`deploy`, `rollback`).
pub fn changes_routes(actions: &[String]) -> bool {
    actions.iter().any(|kind| {
        kind.starts_with("domain.")
            || matches!(kind.as_str(), "webhook.host.set" | "deploy" | "rollback")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SVC: &str = "01a0cdb5-3500-70c1-8000-000000000001";
    const PROJECT: &str = "01a0cdb5-3500-70b1-8000-000000000001";
    const ENV: &str = "01a0cdb5-3500-70b2-8000-000000000001";

    #[test]
    fn routes_parse_and_refuse_malformed_entries() {
        let answer = json!({"ok": true, "routes": [
            {"host": "shop.example.com", "service_id": SVC, "project_id": PROJECT,
             "environment_id": ENV, "source": "custom"},
            {"host": "web-production-shop.11-22-0-10.sslip.io", "service_id": SVC,
             "project_id": PROJECT, "environment_id": ENV, "source": "default"},
            {"host": "hooks.example.com", "service_id": null, "project_id": null,
             "environment_id": null, "source": "webhook"},
            {"host": "Upper.example.com", "service_id": SVC, "project_id": PROJECT,
             "environment_id": ENV, "source": "custom"},
            {"host": "x.example.com", "service_id": "not-a-uuid", "project_id": PROJECT,
             "environment_id": ENV, "source": "custom"},
            {"host": "y.example.com:443", "service_id": SVC, "project_id": PROJECT,
             "environment_id": ENV, "source": "custom"}
        ]});
        let map = parse_routes(&answer).expect("routes");
        assert_eq!(map.len(), 3, "{map:?}");
        let owner = &map["shop.example.com"];
        assert_eq!(owner.service_id, SVC);
        assert_eq!(owner.project_id, PROJECT);
        assert_eq!(owner.environment_id, ENV);
        assert_eq!(
            map["web-production-shop.11-22-0-10.sslip.io"].source,
            "default"
        );
        assert_eq!(map["hooks.example.com"].service_id, "");
        assert!(parse_routes(&json!({"ok": true})).is_none());
    }

    #[test]
    fn the_map_answers_by_host_and_a_failed_refresh_keeps_it() {
        let routes = RoutesMap::default();
        assert!(routes.owner("shop.example.com").is_none());
        routes.replace(
            parse_routes(
                &json!({"routes": [{"host": "shop.example.com", "service_id": SVC,
                "project_id": PROJECT, "environment_id": ENV, "source": "custom"}]}),
            )
            .unwrap(),
        );
        assert_eq!(routes.owner("SHOP.example.com").unwrap().service_id, SVC);
        // The webhook host is known but names no service.
        assert!(routes.owner("hooks.example.com").is_none());
    }

    struct Answers(std::sync::Mutex<Vec<Result<Value, RunnerFailure>>>);

    #[tonic::async_trait]
    impl Runner for Answers {
        async fn exchange(&self, request: Value, _: Duration) -> Result<Value, RunnerFailure> {
            assert_eq!(request, json!({"op": "routes_map", "payload": {}}));
            self.0.lock().unwrap().remove(0)
        }

        async fn open(&self, _: Value) -> Result<runner::EventLines, RunnerFailure> {
            Err(RunnerFailure::transport("unused"))
        }
    }

    #[tokio::test]
    async fn refresh_asks_the_runner_and_keeps_the_map_on_failure() {
        let runner = Answers(std::sync::Mutex::new(vec![
            Ok(
                json!({"type": "result", "ok": true, "routes": [{"host": "shop.example.com",
                "service_id": SVC, "project_id": PROJECT, "environment_id": ENV,
                "source": "default"}]}),
            ),
            Err(RunnerFailure::transport("closed")),
            Ok(json!({"type": "result", "ok": false,
                      "error": {"code": "E_INTERNAL", "message": "x"}})),
        ]));
        let routes = RoutesMap::default();
        routes.refresh(&runner).await.unwrap();
        assert!(routes.refresh(&runner).await.is_err());
        assert!(routes.refresh(&runner).await.is_err());
        assert_eq!(routes.owner("shop.example.com").unwrap().source, "default");
        assert!(changes_routes(&["deploy".into(), "domain.add".into()]));
        assert!(changes_routes(&["webhook.host.set".into()]));
        // QA_M2 run 5 X1: a deploy or rollback activates a release whose
        // `ServiceSpec.routes` (default and custom hosts) Dwaar serves.
        assert!(changes_routes(&["deploy".into()]));
        assert!(changes_routes(&["rollback".into()]));
        assert!(!changes_routes(&["cron.run".into()]));
    }

    /// QA_M2 run 5 X1: a Dwaar record for a host the map does not name asks
    /// for a refresh, at most once per window; a known host (the webhook
    /// host names no service) never does. Every replace is a new generation.
    #[test]
    fn an_unknown_host_nudges_a_refresh_at_most_once_per_window() {
        let routes = RoutesMap::default();
        let first = routes.generation();
        routes.replace(
            parse_routes(
                &json!({"routes": [{"host": "hooks.example.com", "service_id": null,
                "project_id": null, "environment_id": null, "source": "webhook"}]}),
            )
            .unwrap(),
        );
        assert_ne!(routes.generation(), first);
        assert!(!routes.unknown_host("hooks.example.com"));
        assert!(routes.unknown_host("New.example.com"));
        assert!(!routes.unknown_host("other.example.com"));
    }
}
