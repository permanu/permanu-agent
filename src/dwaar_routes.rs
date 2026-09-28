use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use anyhow::{Context, Result};
use bollard::{
    query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder},
    Docker,
};
use serde::{Deserialize, Serialize};

use crate::dwaar_admin::DwaarAdmin;

const MAX_ROUTES_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STATUS_RESPONSE_BYTES: usize = 64 * 1024;
const DEPLOY_APP_PREFIX: &str = "deploy-app-";
const DWAAR_APPS_DIR: &str = "/etc/dwaar/apps";
const MAX_ROUTE_REPLICAS: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DwaarRoute {
    pub domain: String,
    #[serde(default)]
    pub upstream: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAddPayload {
    pub domain: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub path_prefix: String,
    pub analytics_enabled: bool,
    pub replicas: Vec<RouteEndpoint>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct CreateRouteRequest {
    pub domain: String,
    pub upstream: String,
    /// Every resolved replica. Omitted when the route has a single upstream.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,
    pub tls: bool,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ReconcileSummary {
    pub routes_added: usize,
    pub routes_skipped: usize,
    pub errors: Vec<ReconcileRouteError>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ReconcileRouteError {
    pub domain: String,
    pub app_id: String,
    pub reason: String,
}

pub fn parse_live_routes(body: &[u8]) -> Result<Vec<DwaarRoute>> {
    Ok(serde_json::from_slice(body)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicaPayload {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u16,
}

pub fn parse_route_add_payload(payload: &[u8]) -> Result<RouteAddPayload> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        #[serde(default)]
        domain: String,
        #[serde(default)]
        upstream_host: String,
        #[serde(default)]
        upstream_port: u16,
        #[serde(default)]
        path_prefix: String,
        #[serde(default)]
        analytics_enabled: bool,
        #[serde(default)]
        replicas: Vec<ReplicaPayload>,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let domain = payload.domain.trim();
    if domain.is_empty() {
        anyhow::bail!("domain is required");
    }
    validate_domain(domain)?;

    let upstream_host = payload.upstream_host.trim();
    if upstream_host.is_empty() {
        anyhow::bail!("upstream_host is required");
    }
    validate_upstream_host(upstream_host)?;

    if payload.upstream_port == 0 {
        anyhow::bail!("upstream_port is required");
    }
    let replicas = validate_replicas(upstream_host, payload.upstream_port, payload.replicas)?;
    let path_prefix = payload.path_prefix.trim();
    if !path_prefix.is_empty() {
        validate_path_prefix(path_prefix)?;
    }

    Ok(RouteAddPayload {
        domain: domain.to_owned(),
        upstream_host: upstream_host.to_owned(),
        upstream_port: payload.upstream_port,
        path_prefix: path_prefix.to_owned(),
        analytics_enabled: payload.analytics_enabled,
        replicas,
    })
}

fn validate_replicas(
    primary_host: &str,
    primary_port: u16,
    replicas: Vec<ReplicaPayload>,
) -> Result<Vec<RouteEndpoint>> {
    if replicas.is_empty() {
        return Ok(Vec::new());
    }
    if replicas.len() > MAX_ROUTE_REPLICAS {
        anyhow::bail!("at most {MAX_ROUTE_REPLICAS} replicas");
    }

    let mut seen = HashSet::with_capacity(replicas.len());
    let mut parsed = Vec::with_capacity(replicas.len());
    let mut includes_primary = false;
    for replica in replicas {
        let host = replica.host.trim();
        if host.is_empty() {
            anyhow::bail!("replica host is required");
        }
        validate_upstream_host(host)?;
        if replica.port == 0 {
            anyhow::bail!("replica port is required");
        }
        let address = literal_upstream(host, replica.port);
        if seen.contains(&address) {
            anyhow::bail!("duplicate upstream address: {address}");
        }
        seen.insert(address);
        if host == primary_host && replica.port == primary_port {
            includes_primary = true;
        }
        parsed.push(RouteEndpoint {
            host: host.to_owned(),
            port: replica.port,
        });
    }

    if parsed.len() == 1 && !includes_primary {
        anyhow::bail!("replica must match upstream_host and upstream_port");
    }
    if parsed.len() > 1 && !includes_primary {
        anyhow::bail!("replicas must include the primary upstream host");
    }
    Ok(parsed)
}

pub fn parse_route_remove_domain(payload: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        domain: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let domain = payload.domain.trim();
    if domain.is_empty() {
        anyhow::bail!("domain is required");
    }
    validate_domain(domain)?;
    Ok(domain.to_owned())
}

pub fn create_route_request(domain: &str, upstream: &str) -> CreateRouteRequest {
    CreateRouteRequest {
        domain: domain.to_owned(),
        upstream: upstream.to_owned(),
        upstreams: Vec::new(),
        tls: true,
        source: "permanu-agent".to_string(),
    }
}

/// Hosts to resolve, in the order they are posted.
///
/// A snippet route (path prefix or analytics) stays on the primary host.
/// An absent list, or one entry that matches the primary, does too.
pub fn route_add_targets(payload: &RouteAddPayload) -> Vec<RouteEndpoint> {
    if route_needs_snippet(&payload.path_prefix, payload.analytics_enabled)
        || payload.replicas.len() <= 1
    {
        return vec![RouteEndpoint {
            host: payload.upstream_host.clone(),
            port: payload.upstream_port,
        }];
    }
    payload.replicas.clone()
}

/// Admin `POST /routes` body. One address omits `upstreams`. Two or more set
/// `upstream` to the first address and `upstreams` to every address.
pub fn create_route_request_from_resolved(
    domain: &str,
    resolved: &[String],
) -> Result<CreateRouteRequest> {
    if resolved.is_empty() {
        anyhow::bail!("upstream is required");
    }
    if resolved.len() > MAX_ROUTE_REPLICAS {
        anyhow::bail!("at most {MAX_ROUTE_REPLICAS} replicas");
    }

    let mut seen = HashSet::with_capacity(resolved.len());
    for address in resolved {
        if address.is_empty() || address_port_is_zero(address) {
            anyhow::bail!("invalid upstream address");
        }
        if !seen.insert(address) {
            anyhow::bail!("duplicate upstream address: {address}");
        }
    }

    if resolved.len() == 1 {
        return Ok(create_route_request(domain, &resolved[0]));
    }

    let upstream = resolved[0].clone();
    Ok(CreateRouteRequest {
        domain: domain.to_owned(),
        upstream,
        upstreams: resolved.to_vec(),
        tls: true,
        source: "permanu-agent".to_string(),
    })
}

fn address_port_is_zero(address: &str) -> bool {
    address
        .rsplit_once(':')
        .is_some_and(|(_, port)| port == "0")
}

pub fn route_needs_snippet(path_prefix: &str, analytics_enabled: bool) -> bool {
    !path_prefix.trim().is_empty() || analytics_enabled
}

pub fn literal_upstream(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

pub async fn fetch_live_routes(dwaar: &DwaarAdmin) -> Result<Vec<DwaarRoute>> {
    let response = dwaar
        .request("GET", "/routes", &[], MAX_ROUTES_RESPONSE_BYTES)
        .await?;
    if response.status >= 400 {
        anyhow::bail!(
            "dwaar returned {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body).trim()
        );
    }
    parse_live_routes(&response.body).context("parse Dwaar routes")
}

pub async fn post_route(dwaar: &DwaarAdmin, request: &CreateRouteRequest) -> Result<()> {
    let body = serde_json::to_vec(request)?;
    let response = dwaar
        .request("POST", "/routes", &body, MAX_STATUS_RESPONSE_BYTES)
        .await?;
    if response.status >= 400 {
        anyhow::bail!(
            "dwaar returned {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body).trim()
        );
    }
    Ok(())
}

pub async fn delete_route(dwaar: &DwaarAdmin, domain: &str) -> Result<bool> {
    validate_domain(domain)?;
    let path = format!("/routes/{domain}");
    let response = dwaar
        .request("DELETE", &path, &[], MAX_STATUS_RESPONSE_BYTES)
        .await?;
    if response.status == 404 {
        return Ok(false);
    }
    if response.status >= 400 {
        anyhow::bail!(
            "dwaar returned {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body).trim()
        );
    }
    Ok(true)
}

pub async fn reload_dwaar(dwaar: &DwaarAdmin) -> Result<()> {
    match dwaar
        .request("POST", "/reload", &[], MAX_STATUS_RESPONSE_BYTES)
        .await
    {
        Ok(response) if response.status == 429 => Ok(()),
        Ok(response) if response.status >= 400 => anyhow::bail!(
            "dwaar reload returned {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body).trim()
        ),
        Ok(_) => Ok(()),
        Err(admin_err) => {
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::process::Command::new("dwaar").arg("reload").output(),
            )
            .await
            .context("dwaar reload CLI timed out")?
            .context("run dwaar reload")?;
            if !output.status.success() {
                anyhow::bail!(
                    "dwaar admin reload failed ({admin_err}); CLI fallback failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Ok(())
        }
    }
}

pub async fn resolve_route_upstream(
    docker: &Docker,
    container_name: &str,
    port: u16,
) -> Result<String> {
    let mut resolved_name = container_name.to_owned();
    if let Some(slug) = container_name.strip_prefix(DEPLOY_APP_PREFIX) {
        if !slug.is_empty() {
            let live = live_app_slugs(docker).await?;
            if let Some(live_name) = live.get(slug) {
                resolved_name = live_name.clone();
            }
        }
    }
    resolve_container_addr(docker, &resolved_name, port, "deploy-net").await
}

pub async fn resolve_container_addr(
    docker: &Docker,
    container_name: &str,
    port: u16,
    prefer_network: &str,
) -> Result<String> {
    let options = InspectContainerOptionsBuilder::default()
        .size(false)
        .build();
    let inspect = docker
        .inspect_container(container_name, Some(options))
        .await
        .with_context(|| format!("inspect container {container_name:?}"))?;
    let networks = inspect
        .network_settings
        .and_then(|settings| settings.networks)
        .unwrap_or_default();

    if let Some(ip) = networks
        .get(prefer_network)
        .and_then(|endpoint| endpoint.ip_address.as_deref())
        .filter(|ip| !ip.is_empty())
    {
        return Ok(literal_upstream(ip, port));
    }

    for endpoint in networks.values() {
        if let Some(ip) = endpoint.ip_address.as_deref().filter(|ip| !ip.is_empty()) {
            return Ok(literal_upstream(ip, port));
        }
    }

    anyhow::bail!("container {container_name:?} has no IP address on any network")
}

pub async fn live_app_slugs(docker: &Docker) -> Result<HashMap<String, String>> {
    let options = ListContainersOptionsBuilder::default().all(true).build();
    let containers = docker.list_containers(Some(options)).await?;
    let mut slugs = HashMap::new();
    for container in containers {
        let state = container
            .state
            .as_ref()
            .map(|state| format!("{state:?}").to_lowercase())
            .unwrap_or_default();
        if state != "running" && state != "restarting" {
            continue;
        }
        let Some(name) = container
            .names
            .as_ref()
            .and_then(|names| names.first())
            .map(|name| name.trim_start_matches('/'))
        else {
            continue;
        };
        let slug = extract_slug_from_container(name)
            .filter(|slug| !slug.is_empty())
            .or_else(|| name.strip_prefix(DEPLOY_APP_PREFIX).map(str::to_string));
        if let Some(slug) = slug {
            slugs.insert(slug, name.to_string());
        }
    }
    Ok(slugs)
}

pub fn route_file_paths(domain: &str) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    validate_domain(domain)?;
    let sanitized = if let Some(rest) = domain.strip_prefix("*.") {
        format!("wildcard.{rest}")
    } else {
        domain.to_string()
    };
    Ok((
        std::path::Path::new(DWAAR_APPS_DIR).join(format!("{sanitized}.dwaar")),
        std::path::Path::new(DWAAR_APPS_DIR).join(format!("route-{sanitized}.dwaar")),
    ))
}

pub fn persist_route_file(domain: &str, upstream: &str) -> Result<()> {
    let (route_path, _) = route_file_paths(domain)?;
    let Some(parent) = route_path.parent() else {
        anyhow::bail!("route file path has no parent");
    };
    if !parent.is_dir() {
        return Ok(());
    }
    let content = format!(
        "# App: {domain}  (source=permanu-agent)\n{domain} {{\n    reverse_proxy {upstream}\n}}\n"
    );
    let tmp = route_path.with_extension("dwaar.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(tmp, route_path)?;
    Ok(())
}

pub fn persist_route_snippet(
    domain: &str,
    upstream: &str,
    path_prefix: &str,
    analytics_enabled: bool,
) -> Result<()> {
    let (_, snippet_path) = route_file_paths(domain)?;
    let Some(parent) = snippet_path.parent() else {
        anyhow::bail!("route snippet path has no parent");
    };
    if !parent.is_dir() {
        anyhow::bail!("dwaar apps dir {} missing", parent.display());
    }
    let content = render_route_snippet(domain, upstream, path_prefix, analytics_enabled)?;
    let tmp = snippet_path.with_extension("dwaar.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(tmp, snippet_path)?;
    Ok(())
}

pub fn remove_route_files(domain: &str) -> Result<()> {
    let (route_path, snippet_path) = route_file_paths(domain)?;
    for path in [route_path, snippet_path] {
        if let Err(err) = std::fs::remove_file(&path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err).with_context(|| format!("remove {}", path.display()));
            }
        }
    }
    Ok(())
}

pub fn extract_slug_from_container(name: &str) -> Option<String> {
    let body = name.strip_prefix(DEPLOY_APP_PREFIX)?;
    let idx = body.rfind('-')?;
    if idx == 0 {
        return None;
    }
    Some(body[..idx].to_string())
}

pub fn host_is_literal(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok()
}

fn validate_domain(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n' | b'/' | b'\\' | b'"' | b'\''))
    {
        anyhow::bail!("invalid domain");
    }
    Ok(())
}

fn validate_upstream_host(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n' | b'\\' | b'"' | b'\''))
    {
        anyhow::bail!("invalid upstream_host");
    }
    Ok(())
}

fn validate_path_prefix(value: &str) -> Result<()> {
    if value == "/" {
        anyhow::bail!("path_prefix / is not allowed; omit it for root routing");
    }
    if !value.starts_with('/')
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'{' | b'}' | b'"' | b'\'' | b'\\' | b'*'))
    {
        anyhow::bail!("invalid path_prefix");
    }
    Ok(())
}

fn render_route_snippet(
    domain: &str,
    upstream: &str,
    path_prefix: &str,
    analytics_enabled: bool,
) -> Result<String> {
    validate_domain(domain)?;
    validate_upstream(upstream)?;
    if !path_prefix.trim().is_empty() {
        validate_path_prefix(path_prefix)?;
    }
    let mut content = String::new();
    content.push_str("# Managed by permanu-agent. DO NOT EDIT.\n");
    content.push_str(domain);
    content.push_str(" {\n");
    if path_prefix.trim().is_empty() {
        content.push_str("    reverse_proxy ");
        content.push_str(upstream);
        content.push('\n');
    } else {
        content.push_str("    handle ");
        content.push_str(path_prefix.trim());
        content.push_str("/* {\n        reverse_proxy ");
        content.push_str(upstream);
        content.push_str("\n    }\n");
    }
    if analytics_enabled {
        content.push_str("    analytics on\n");
    }
    content.push_str("}\n");
    Ok(content)
}

fn validate_upstream(value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'{' | b'}' | b'"' | b'\'' | b'\\'))
    {
        anyhow::bail!("invalid upstream");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_dwaar_routes() {
        let routes = parse_live_routes(
            br#"[{"domain":"api.example.com","upstream":"172.18.0.2:3000","tls":true,"source":"permanu-agent"}]"#,
        )
        .expect("parse routes");

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].domain, "api.example.com");
        assert_eq!(routes[0].upstream, "172.18.0.2:3000");
        assert!(routes[0].tls);
    }

    #[test]
    fn route_add_requires_domain() {
        let err = parse_route_add_payload(br#"{"upstream_host":"127.0.0.1","upstream_port":3000}"#)
            .unwrap_err();
        assert!(err.to_string().contains("domain is required"));
    }

    #[test]
    fn route_add_rejects_injection_in_domain() {
        let err = parse_route_add_payload(
            b"{\"domain\":\"example.com\\r\\nX: y\",\"upstream_host\":\"127.0.0.1\",\"upstream_port\":3000}",
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid domain"));
    }

    #[test]
    fn route_add_parses_valid_payload() {
        let payload = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"127.0.0.1","upstream_port":3000}"#,
        )
        .expect("parse route add payload");

        assert_eq!(payload.domain, "api.example.com");
        assert_eq!(payload.upstream_host, "127.0.0.1");
        assert_eq!(payload.upstream_port, 3000);
        assert_eq!(payload.path_prefix, "");
        assert!(!payload.analytics_enabled);
    }

    #[test]
    fn route_add_accepts_path_prefix_and_analytics_for_snippet_routes() {
        let payload = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"127.0.0.1","upstream_port":3000,"path_prefix":"/api","analytics_enabled":true}"#,
        )
        .expect("parse route add payload");

        assert_eq!(payload.path_prefix, "/api");
        assert!(payload.analytics_enabled);
    }

    #[test]
    fn route_remove_requires_domain() {
        let err = parse_route_remove_domain(br#"{"domain":""}"#).unwrap_err();
        assert!(err.to_string().contains("domain is required"));
    }

    #[test]
    fn create_route_request_matches_go_shape() {
        let request = create_route_request("api.example.com", "172.18.0.2:3000");

        assert_eq!(
            request,
            CreateRouteRequest {
                domain: "api.example.com".to_string(),
                upstream: "172.18.0.2:3000".to_string(),
                upstreams: Vec::new(),
                tls: true,
                source: "permanu-agent".to_string(),
            }
        );
    }

    #[test]
    fn route_needs_snippet_for_path_prefix_or_analytics() {
        assert!(!route_needs_snippet("", false));
        assert!(route_needs_snippet("/api", false));
        assert!(route_needs_snippet("", true));
    }

    #[test]
    fn extract_slug_from_uuid_suffixed_container_name() {
        assert_eq!(
            extract_slug_from_container("deploy-app-my-long-slug-abc123").as_deref(),
            Some("my-long-slug")
        );
        assert_eq!(extract_slug_from_container("deploy-app-x"), None);
        assert_eq!(extract_slug_from_container("postgres"), None);
    }

    #[test]
    fn route_file_paths_match_go_persistence_names() {
        let (route, snippet) = route_file_paths("*.example.com").expect("route file paths");
        assert_eq!(
            route,
            std::path::Path::new("/etc/dwaar/apps/wildcard.example.com.dwaar")
        );
        assert_eq!(
            snippet,
            std::path::Path::new("/etc/dwaar/apps/route-wildcard.example.com.dwaar")
        );
    }

    fn posted_route_json(payload: &str) -> serde_json::Value {
        let payload = parse_route_add_payload(payload.as_bytes()).expect("payload");
        let resolved: Vec<String> = route_add_targets(&payload)
            .into_iter()
            .map(|target| literal_upstream(&target.host, target.port))
            .collect();
        let request =
            create_route_request_from_resolved(&payload.domain, &resolved).expect("request");
        serde_json::to_value(&request).expect("json")
    }

    #[test]
    fn single_host_omits_upstreams() {
        let json = posted_route_json(
            r#"{"domain":"api.example.com","upstream_host":"127.0.0.1","upstream_port":3000}"#,
        );

        assert_eq!(json["upstream"], "127.0.0.1:3000");
        assert!(json.get("upstreams").is_none());
        assert!(!json.to_string().contains("upstreams"));
    }

    #[test]
    fn one_matching_replica_omits_upstreams() {
        let json = posted_route_json(
            r#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":3000,"replicas":[{"host":"10.0.0.1","port":3000}]}"#,
        );

        assert_eq!(json["upstream"], "10.0.0.1:3000");
        assert!(json.get("upstreams").is_none());
    }

    #[test]
    fn two_replicas_post_both_addresses_and_upstream_is_first() {
        let json = posted_route_json(
            r#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":3000,"replicas":[{"host":"10.0.0.1","port":3000},{"host":"10.0.0.2","port":3000}]}"#,
        );

        assert_eq!(json["upstream"], "10.0.0.1:3000");
        assert_eq!(
            json["upstreams"],
            serde_json::json!(["10.0.0.1:3000", "10.0.0.2:3000"])
        );
        assert_eq!(json["upstream"], json["upstreams"][0]);
    }

    #[test]
    fn replica_list_without_primary_host_is_rejected() {
        let err = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":3000,"replicas":[{"host":"10.0.0.2","port":3000},{"host":"10.0.0.3","port":3000}]}"#,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("primary"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn single_replica_that_differs_from_primary_is_rejected() {
        let err = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":3000,"replicas":[{"host":"10.0.0.2","port":3000}]}"#,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("upstream_host"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn replica_port_zero_is_rejected() {
        let err = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":3000,"replicas":[{"host":"10.0.0.1","port":0}]}"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("port"), "unexpected error: {err}");
    }

    #[test]
    fn primary_port_zero_is_rejected() {
        let err = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":0}"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("port"), "unexpected error: {err}");
    }

    #[test]
    fn empty_replica_host_is_rejected() {
        let err = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":3000,"replicas":[{"host":"  ","port":3000}]}"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("host"), "unexpected error: {err}");
    }

    #[test]
    fn duplicate_replica_address_is_rejected() {
        let err = parse_route_add_payload(
            br#"{"domain":"api.example.com","upstream_host":"10.0.0.1","upstream_port":3000,"replicas":[{"host":"10.0.0.1","port":3000},{"host":"10.0.0.1","port":3000}]}"#,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("duplicate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn more_than_64_replicas_is_rejected() {
        let mut replicas = Vec::new();
        for octet in 1..=65 {
            replicas.push(serde_json::json!({"host": format!("10.0.0.{octet}"), "port": 3000}));
        }
        replicas[0] = serde_json::json!({"host": "10.0.0.1", "port": 3000});
        let body = serde_json::json!({
            "domain": "api.example.com",
            "upstream_host": "10.0.0.1",
            "upstream_port": 3000,
            "replicas": replicas,
        });
        let err = parse_route_add_payload(body.to_string().as_bytes()).unwrap_err();

        assert!(err.to_string().contains("64"), "unexpected error: {err}");
    }

    #[test]
    fn snippet_route_stays_on_the_single_upstream() {
        let payload = parse_route_add_payload(
            br#"{"domain":"hooks.example.com","upstream_host":"127.0.0.1","upstream_port":7461,"path_prefix":"/hooks","replicas":[{"host":"127.0.0.1","port":7461},{"host":"127.0.0.2","port":7461}]}"#,
        )
        .expect("payload");

        let targets = route_add_targets(&payload);
        assert_eq!(
            targets,
            vec![RouteEndpoint {
                host: "127.0.0.1".to_string(),
                port: 7461,
            }]
        );
        let resolved: Vec<String> = targets
            .iter()
            .map(|target| literal_upstream(&target.host, target.port))
            .collect();
        let request =
            create_route_request_from_resolved(&payload.domain, &resolved).expect("request");
        let json = serde_json::to_value(&request).expect("json");
        assert_eq!(json["upstream"], "127.0.0.1:7461");
        assert!(json.get("upstreams").is_none());
    }
}
