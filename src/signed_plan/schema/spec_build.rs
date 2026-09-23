//! The signed build recipe of a `ServiceSpec` (signed-plan.md section 3.7,
//! v1.0.9, D-056) and the redaction-v1 key pattern `K` that refuses
//! secret-looking build argument names (agent-protocol.md section 9.6).

use serde_json::Value;

use super::super::text;
use super::{check, Shape, ENV};

/// The keyword alternatives of `K`, expanded for an `ENV_NAME` (which has
/// no `.` or `-`, so every optional `[_-]` is `_` or nothing).
const K_KEYWORDS: &[&str] = &[
    "pass",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "privatekey",
    "private_key",
    "clientsecret",
    "client_secret",
    "credential",
    "credentials",
    "authorization",
    "authtoken",
    "auth_token",
    "sessionid",
    "session_id",
    "sessiontoken",
    "session_token",
    "cookie",
    "databaseurl",
    "database_url",
    "dsn",
    "connstring",
    "conn_string",
    "connectionstring",
    "connection_string",
];

/// `([a-z0-9]+_)*`: empty, or non-empty segments each followed by `_`.
fn prefix_segments(value: &str) -> bool {
    value.is_empty()
        || value.strip_suffix('_').is_some_and(|body| {
            body.split('_')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()))
        })
}

/// `(_[a-z0-9]+)*`: empty, or `_` then non-empty segments.
fn suffix_segments(value: &str) -> bool {
    value.is_empty()
        || value.strip_prefix('_').is_some_and(|body| {
            body.split('_')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()))
        })
}

/// Whether the redaction-v1 key pattern `K` matches `name` as a whole
/// (Python `re.fullmatch(K_TEXT, name, re.ASCII)`), for an `ENV_NAME`.
pub(crate) fn secret_looking_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (0..=lower.len()).any(|start| {
        lower.is_char_boundary(start)
            && prefix_segments(&lower[..start])
            && K_KEYWORDS.iter().any(|keyword| {
                lower[start..]
                    .strip_prefix(keyword)
                    .is_some_and(suffix_segments)
            })
    })
}

/// `[A-Za-z0-9._-]{1,64}(/[A-Za-z0-9._-]{1,64}){0,15}` with no `.` or `..`
/// segment.
fn relative_path(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    (1..=16).contains(&parts.len())
        && parts.iter().all(|part| {
            (1..=64).contains(&part.len())
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn subdir(value: &str) -> bool {
    value.is_empty() || relative_path(value)
}

fn context(value: &str) -> bool {
    value == "." || relative_path(value)
}

/// `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
fn build_target(value: &str) -> bool {
    let mut bytes = value.bytes();
    (1..=64).contains(&value.len())
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A branch (`refs/heads/…`) or tag (`refs/tags/…`), git rules.
fn build_ref(value: &str) -> bool {
    match value.strip_prefix("refs/tags/") {
        Some(tag) => text::git_ref(&format!("refs/heads/{tag}"), false),
        None => text::git_ref(value, false),
    }
}

/// `https://host[:port]/path`: lowercase host, 1–8 path segments of
/// `[A-Za-z0-9._-]`, no userinfo, query or fragment.
fn repo_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host_ok = (1..=253).contains(&host.len())
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && host
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && host
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric());
    let port_ok = port.is_none_or(|port| {
        (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit())
    });
    let segments: Vec<&str> = path.split('/').collect();
    let path_ok = !path.is_empty()
        && (1..=8).contains(&segments.len())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    host_ok && port_ok && path_ok
}

fn build_args(value: &Value) -> bool {
    value.as_object().is_some_and(|map| {
        map.len() <= 64
            && map.iter().all(|(name, literal)| {
                text::env_name(name)
                    && check(&Shape::Text(0, 4_096), literal)
                    && !secret_looking_name(name)
            })
    })
}

const BUILD: Shape = Shape::Object(&[
    (
        "source",
        Shape::Object(&[
            ("repo_url", Shape::Pattern(repo_url)),
            ("ref", Shape::Pattern(build_ref)),
            ("subdir", Shape::Pattern(subdir)),
        ]),
    ),
    ("dockerfile", Shape::Pattern(relative_path)),
    ("context", Shape::Pattern(context)),
    ("target", Shape::Nullable(&Shape::Pattern(build_target))),
    ("build_args", Shape::Custom(build_args)),
    ("build_secrets", Shape::Set(&ENV, 0, 32)),
]);

/// A `build` recipe: its shape, and no name both a build arg and a build
/// secret.
pub(crate) fn build_recipe(value: &Value) -> bool {
    check(&BUILD, value)
        && value["build_secrets"].as_array().is_some_and(|secrets| {
            secrets.iter().all(|name| {
                name.as_str()
                    .is_some_and(|name| value["build_args"].get(name).is_none())
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_matches_whole_secret_names_only() {
        for name in [
            "NPM_TOKEN",
            "API_KEY",
            "APIKEY",
            "DB_PASSWORD",
            "MY_API_KEY_V2",
            "PASSWORD",
            "SECRET",
            "GITHUB_AUTH_TOKEN",
            "DATABASE_URL",
            "PG_DSN",
            "SESSION_ID",
            "CREDENTIALS",
            "X_CONNECTION_STRING_2",
        ] {
            assert!(secret_looking_name(name), "{name}");
        }
        for name in [
            "NODE_ENV",
            "BYPASS",
            "PASSX",
            "TOKENS",
            "API_KEY_",
            "_TOKEN",
            "PUBLIC_URL",
            "VERSION",
            "SECRETARY",
        ] {
            assert!(!secret_looking_name(name), "{name}");
        }
    }

    #[test]
    fn repo_urls_are_https_without_userinfo_query_or_fragment() {
        assert!(repo_url("https://github.com/acme/web"));
        assert!(repo_url("https://git.example.com:8443/a/b/c.git"));
        assert!(!repo_url("http://github.com/acme/web"));
        assert!(!repo_url("https://user@github.com/acme/web"));
        assert!(!repo_url("https://github.com/acme/web?x=1"));
        assert!(!repo_url("https://github.com/acme/web#frag"));
        assert!(!repo_url("https://GitHub.com/acme/web"));
        assert!(!repo_url("https://github.com"));
        assert!(!repo_url("https://github.com/a/b/c/d/e/f/g/h/i"));
    }

    #[test]
    fn recipe_paths_never_escape_the_checkout() {
        assert!(relative_path("Dockerfile"));
        assert!(relative_path("docker/web.Dockerfile"));
        assert!(!relative_path("../Dockerfile"));
        assert!(!relative_path("a/./b"));
        assert!(!relative_path("/abs"));
        assert!(!relative_path(""));
        assert!(context("."));
        assert!(subdir(""));
        assert!(!subdir("."));
        assert!(build_ref("refs/tags/v1.2.3"));
        assert!(build_ref("refs/heads/main"));
        assert!(!build_ref("main"));
        assert!(build_target("prod"));
        assert!(!build_target("-prod"));
    }
}
