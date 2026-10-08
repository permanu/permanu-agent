//! Shared native-CI configuration validation (signed-plan ci.configure).
use super::{jcs, text};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub approval_id: String,
    pub project_id: String,
    pub enabled: bool,
    pub runner: Runner,
    pub repository: String,
    pub branch: String,
    pub pull_requests: bool,
    pub jobs: Vec<Job>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Runner {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub name: String,
    pub image: String,
    pub command: String,
    pub cpus: u32,
    pub memory_mb: u32,
    pub timeout_seconds: u32,
}
impl Configuration {
    pub fn parse(raw: &str, digest: &str) -> Option<Self> {
        if raw.len() > 16384 || format!("{:x}", Sha256::digest(raw.as_bytes())) != digest {
            return None;
        }
        let value = jcs::parse_strict(raw.as_bytes(), 16384)?;
        if jcs::canonicalize(&value)?.as_bytes() != raw.as_bytes() {
            return None;
        }
        let c: Self = serde_json::from_value(value).ok()?;
        c.valid().then_some(c)
    }
    pub fn valid(&self) -> bool {
        if !text::uuid7(&self.approval_id)
            || !text::uuid7(&self.project_id)
            || !matches!(self.runner.kind.as_str(), "local" | "server")
            || ((self.runner.kind == "server") != self.runner.server_id.is_some())
            || self
                .runner
                .server_id
                .as_deref()
                .is_some_and(|id| !text::uuid7(id))
        {
            return false;
        }
        let pieces: Vec<_> = self.repository.split('/').collect();
        if pieces.len() != 2
            || pieces.iter().any(|p| {
                p.is_empty()
                    || p.len() > 100
                    || !p.as_bytes()[0].is_ascii_alphanumeric()
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
            })
        {
            return false;
        }
        if self.branch.is_empty()
            || self.branch.len() > 200
            || !text::git_ref(&format!("refs/heads/{}", self.branch), false)
        {
            return false;
        }
        if self
            .jobs
            .iter()
            .map(|j| u64::from(j.timeout_seconds))
            .sum::<u64>()
            > 7200
            || self.jobs.is_empty()
            || self.jobs.len() > 16
        {
            return false;
        }
        let mut names = BTreeSet::new();
        self.jobs.iter().all(|j| {
            !j.name.is_empty()
                && j.name.len() <= 64
                && !j.name.contains(['\0', '\r', '\n'])
                && names.insert(&j.name)
                && !j.command.is_empty()
                && j.command.len() <= 8192
                && !j.command.contains('\0')
                && !sensitive_command(&j.command)
                && !j.image.is_empty()
                && j.image.len() <= 256
                && j.image.as_bytes()[0].is_ascii_alphanumeric()
                && j.image.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'.' | b'_' | b'/' | b':' | b'@' | b'-')
                })
                && (1..=16).contains(&j.cpus)
                && (256..=32768).contains(&j.memory_mb)
                && (1..=7200).contains(&j.timeout_seconds)
        })
    }
}
fn sensitive_command(command: &str) -> bool {
    static ASSIGNMENT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\b(?:[A-Za-z0-9_]*_)?(?:TOKEN|PASSWORD|SECRET|API_KEY|PRIVATE_KEY)\s*=\s*[^\s]+",
        )
        .expect("constant regex")
    });
    command.contains("-----BEGIN ") || ASSIGNMENT.is_match(command)
}
pub(crate) fn action_scope(plan: &Value, params: &Value) -> bool {
    let Some(c) = Configuration::parse(
        params["configuration_jcs"].as_str().unwrap_or_default(),
        params["configuration_digest_hex"]
            .as_str()
            .unwrap_or_default(),
    ) else {
        return false;
    };
    if plan["project_id"] != c.project_id || plan["actions"].as_array().is_none_or(|a| a.len() != 1)
    {
        return false;
    }
    match c.runner.server_id {
        Some(id) => plan["targets"]
            .as_array()
            .is_some_and(|ids| ids.len() == 1 && ids[0] == id),
        None => plan["targets"].as_array().is_some_and(|ids| ids.len() == 1),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_unbounded_or_privileged_parameters() {
        let raw = serde_json::json!({"approval_id":"01a0cdb5-3500-70a1-8000-000000000003","project_id":"01a0cdb5-3500-70a1-8000-000000000001","enabled":true,"runner":{"kind":"server","server_id":"01a0cdb5-3500-70a1-8000-000000000002"},"repository":"permanu/Dwaar","branch":"main","pull_requests":false,"jobs":[{"name":"test","image":"rust:1.90","command":"cargo test","cpus":1,"memory_mb":2048,"timeout_seconds":60}]});
        let valid: Configuration = serde_json::from_value(raw.clone()).unwrap();
        assert!(valid.valid());
        let mut bad = raw.clone();
        bad["jobs"][0]["cpus"] = serde_json::json!(0);
        assert!(!serde_json::from_value::<Configuration>(bad)
            .unwrap()
            .valid());
        let mut bad = raw;
        bad["jobs"][0]["privileged"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Configuration>(bad).is_err());
    }
}
