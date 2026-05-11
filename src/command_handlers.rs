use anyhow::Result;
use serde::Deserialize;

pub fn parse_cache_purge_path(payload: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        host: String,
        #[serde(default)]
        path: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let host = payload.host.trim();
    if host.is_empty() {
        anyhow::bail!("cache purge: host is required");
    }
    validate_request_segment(host, "host")?;

    let mut path = payload.path.trim().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    validate_request_path(&path)?;

    Ok(format!("/cache/{host}{path}"))
}

pub fn parse_agent_logs_lines(payload: &[u8]) -> Result<usize> {
    #[derive(Deserialize, Default)]
    struct Payload {
        #[serde(default)]
        lines: usize,
    }

    let payload: Payload = if payload.is_empty() {
        Payload::default()
    } else {
        serde_json::from_slice(payload)?
    };
    let lines = if payload.lines == 0 {
        200
    } else {
        payload.lines
    };
    Ok(lines.min(2000))
}

pub fn parse_network_remove_name(payload: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        network_name: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let name = payload.network_name.trim();
    if name.is_empty() {
        anyhow::bail!("network_name is required");
    }
    validate_docker_resource_name(name, "network_name")?;
    Ok(name.to_owned())
}

pub fn parse_volume_remove_name(payload: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        volume_name: String,
    }

    let payload: Payload = serde_json::from_slice(payload)?;
    let name = payload.volume_name.trim();
    if name.is_empty() {
        anyhow::bail!("volume_name is required");
    }
    validate_docker_resource_name(name, "volume_name")?;
    Ok(name.to_owned())
}

fn validate_request_segment(value: &str, label: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n' | b'/'))
    {
        anyhow::bail!("cache purge: invalid {label}");
    }
    Ok(())
}

fn validate_request_path(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n'))
    {
        anyhow::bail!("cache purge: invalid path");
    }
    Ok(())
}

fn validate_docker_resource_name(value: &str, label: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n' | b'/'))
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_purge_requires_host() {
        let err = parse_cache_purge_path(br#"{"path":"/"}"#).unwrap_err();
        assert!(err.to_string().contains("host is required"));
    }

    #[test]
    fn cache_purge_normalizes_empty_path_to_root() {
        let path = parse_cache_purge_path(br#"{"host":"example.com","path":""}"#)
            .expect("parse cache purge");

        assert_eq!(path, "/cache/example.com/");
    }

    #[test]
    fn cache_purge_prefixes_relative_path() {
        let path = parse_cache_purge_path(br#"{"host":"example.com","path":"assets/app.js"}"#)
            .expect("parse cache purge");

        assert_eq!(path, "/cache/example.com/assets/app.js");
    }

    #[test]
    fn cache_purge_rejects_header_injection() {
        let err = parse_cache_purge_path(b"{\"host\":\"example.com\",\"path\":\"/ok\\r\\nX: y\"}")
            .unwrap_err();

        assert!(err.to_string().contains("invalid path"));
    }

    #[test]
    fn agent_logs_defaults_to_200_lines() {
        let lines = parse_agent_logs_lines(b"{}").expect("parse lines");
        assert_eq!(lines, 200);
    }

    #[test]
    fn agent_logs_caps_lines_to_2000() {
        let lines = parse_agent_logs_lines(br#"{"lines":999999}"#).expect("parse lines");
        assert_eq!(lines, 2000);
    }

    #[test]
    fn network_remove_requires_name() {
        let err = parse_network_remove_name(br#"{"network_name":""}"#).unwrap_err();
        assert!(err.to_string().contains("network_name is required"));
    }

    #[test]
    fn network_remove_rejects_path_like_name() {
        let err = parse_network_remove_name(br#"{"network_name":"../deploy-net"}"#).unwrap_err();
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn volume_remove_parses_name() {
        let name = parse_volume_remove_name(br#"{"volume_name":"deploy-data"}"#)
            .expect("parse volume name");
        assert_eq!(name, "deploy-data");
    }

    #[test]
    fn volume_remove_rejects_control_characters() {
        let err = parse_volume_remove_name(b"{\"volume_name\":\"deploy\\nsecret\"}").unwrap_err();
        assert!(err.to_string().contains("invalid characters"));
    }
}
