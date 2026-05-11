use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

#[derive(Clone, Debug)]
pub struct DwaarAdmin {
    socket_path: PathBuf,
    timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl DwaarAdmin {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: Duration::from_secs(10),
        }
    }

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        max_body_bytes: usize,
    ) -> Result<AdminResponse> {
        request_unix_http(
            &self.socket_path,
            method,
            path,
            body,
            max_body_bytes,
            self.timeout,
        )
        .await
    }
}

async fn request_unix_http(
    socket_path: &std::path::Path,
    method: &str,
    path: &str,
    body: &[u8],
    max_body_bytes: usize,
    timeout: Duration,
) -> Result<AdminResponse> {
    validate_token(method, "method")?;
    validate_request_path(path)?;

    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(socket_path))
        .await
        .context("dwaar admin socket connect timed out")?
        .with_context(|| format!("connect dwaar admin socket {}", socket_path.display()))?;

    let content_type = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/json\r\n".to_string()
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: dwaar\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tokio::time::timeout(timeout, async {
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.shutdown().await?;
        Result::<(), std::io::Error>::Ok(())
    })
    .await
    .context("dwaar admin request write timed out")??;

    let mut raw = Vec::new();
    let read_cap = max_body_bytes.saturating_add(8192).max(8192);
    tokio::time::timeout(timeout, stream.take(read_cap as u64).read_to_end(&mut raw))
        .await
        .context("dwaar admin response read timed out")?
        .context("read dwaar admin response")?;
    parse_response(&raw, max_body_bytes)
}

fn parse_response(raw: &[u8], max_body_bytes: usize) -> Result<AdminResponse> {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .ok_or_else(|| anyhow!("malformed HTTP response: missing header terminator"))?;
    let header = std::str::from_utf8(&raw[..header_end])
        .context("malformed HTTP response: headers are not UTF-8")?;
    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| anyhow!("malformed HTTP response: missing status line"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(anyhow!("malformed HTTP response: invalid status line"));
    }
    let status = parts
        .next()
        .ok_or_else(|| anyhow!("malformed HTTP response: missing status code"))?
        .parse::<u16>()
        .context("malformed HTTP response: invalid status code")?;
    let body_end = raw.len().min(header_end.saturating_add(max_body_bytes));
    Ok(AdminResponse {
        status,
        body: raw[header_end..body_end].to_vec(),
    })
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n' | b':'))
    {
        return Err(anyhow!("invalid HTTP {label}"));
    }
    Ok(())
}

fn validate_request_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'\r' | b'\n'))
    {
        return Err(anyhow!("invalid HTTP request path"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::UnixListener;

    #[test]
    fn parses_status_and_body_from_http_response() {
        let parsed = parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"ok\":true}\nrest",
            1024,
        )
        .expect("parse response");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"{\"ok\":true}\nrest");
    }

    #[test]
    fn caps_response_body() {
        let parsed =
            parse_response(b"HTTP/1.1 500 Error\r\n\r\nabcdefgh", 4).expect("parse response");

        assert_eq!(parsed.status, 500);
        assert_eq!(parsed.body, b"abcd");
    }

    #[test]
    fn rejects_malformed_status_line() {
        let err = parse_response(b"not-http\r\n\r\nbody", 1024).unwrap_err();
        assert!(err.to_string().contains("status line"));
    }

    #[tokio::test]
    async fn sends_admin_request_over_unix_socket() {
        let socket = std::path::PathBuf::from(format!(
            "/tmp/pa-dw-{}-{}.sock",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let listener = UnixListener::bind(&socket).expect("bind unix listener");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept connection");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert!(request.starts_with(b"GET /routes HTTP/1.1\r\n"));
            assert!(request
                .windows(b"\r\nConnection: close\r\n".len())
                .any(|window| window == b"\r\nConnection: close\r\n"));
            assert!(!request
                .windows(b"Content-Type: application/json".len())
                .any(|window| window == b"Content-Type: application/json"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                .await
                .expect("write response");
        });

        let response = DwaarAdmin::new(&socket)
            .request("GET", "/routes", &[], 1024)
            .await
            .expect("request dwaar admin");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"ok":true}"#);
        server.await.expect("server task");
        let _ = std::fs::remove_file(socket);
    }
}
