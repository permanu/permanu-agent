use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::common::{format_duration, parse_duration, CommandSpec, MAX_COMMAND_OUTPUT_BYTES};

const PROCESS_LIST_DEFAULT_LIMIT: usize = 50;
const PROCESS_LIST_MAX_LIMIT: usize = 200;
const JOURNAL_DEFAULT_LINES: usize = 100;
const JOURNAL_MAX_LINES: usize = 500;
const JOURNAL_MAX_SINCE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostDiagnosticPlan {
    ProcessList {
        command: CommandSpec,
        limit: usize,
    },
    Listeners {
        primary: CommandSpec,
        fallback: CommandSpec,
    },
    JournalTail {
        command: CommandSpec,
        unit: String,
        since: Duration,
        lines: usize,
    },
}

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct HostDiagnosticResponse<T> {
    pub kind: String,
    pub data: T,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ListenerEntry {
    pub addr: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

pub fn build_host_diagnostic_plan(payload: &[u8]) -> Result<HostDiagnosticPlan> {
    #[derive(Deserialize)]
    struct Payload {
        kind: String,
        #[serde(default)]
        limit: usize,
        #[serde(default)]
        sort_by: String,
        #[serde(default)]
        unit: String,
        #[serde(default)]
        since: String,
        #[serde(default)]
        lines: usize,
    }

    let payload: Payload = serde_json::from_slice(payload).context("malformed payload")?;
    match payload.kind.as_str() {
        "process_list" => {
            let limit = if payload.limit == 0 {
                PROCESS_LIST_DEFAULT_LIMIT
            } else {
                payload.limit.min(PROCESS_LIST_MAX_LIMIT)
            };
            let sort = match payload.sort_by.as_str() {
                "" | "cpu" => "-pcpu",
                "mem" => "-pmem",
                other => anyhow::bail!("invalid sort_by {other:?} (expected cpu|mem)"),
            };
            Ok(HostDiagnosticPlan::ProcessList {
                command: CommandSpec::new(
                    "ps",
                    [
                        "-eo",
                        "pid,user,comm,pcpu,pmem,rss",
                        &format!("--sort={sort}"),
                        "--no-headers",
                    ],
                    Duration::from_secs(30),
                    MAX_COMMAND_OUTPUT_BYTES,
                ),
                limit,
            })
        }
        "listeners" => Ok(HostDiagnosticPlan::Listeners {
            primary: CommandSpec::new(
                "ss",
                ["-tlnp", "-H"],
                Duration::from_secs(30),
                MAX_COMMAND_OUTPUT_BYTES,
            ),
            fallback: CommandSpec::new(
                "lsof",
                ["-iTCP", "-sTCP:LISTEN", "-P", "-n"],
                Duration::from_secs(30),
                MAX_COMMAND_OUTPUT_BYTES,
            ),
        }),
        "journal_tail" => build_journal_tail_plan(&payload.unit, &payload.since, payload.lines),
        other => anyhow::bail!(
            "unsupported kind {other:?} (expected process_list|listeners|journal_tail)"
        ),
    }
}

pub fn parse_ss_output(output: &str) -> Vec<ListenerEntry> {
    let mut entries = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (addr, port) = split_addr_port(fields[3]);
        let (pid, command) = fields
            .iter()
            .skip(4)
            .find_map(parse_ss_users)
            .unwrap_or((None, None));
        entries.push(ListenerEntry {
            addr,
            port,
            pid,
            command,
        });
    }
    entries
}

pub fn parse_lsof_output(output: &str) -> Vec<ListenerEntry> {
    let mut entries = Vec::new();
    for (idx, line) in output.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        let (addr, port) = split_addr_port(fields[8]);
        entries.push(ListenerEntry {
            addr,
            port,
            pid: fields[1].parse::<u32>().ok(),
            command: Some(fields[0].to_string()),
        });
    }
    entries
}

fn build_journal_tail_plan(unit: &str, since: &str, lines: usize) -> Result<HostDiagnosticPlan> {
    if !matches!(unit, "permanu-agent" | "dwaar" | "docker") {
        anyhow::bail!("unit {unit:?} not in allowlist (permanu-agent|dwaar|docker)");
    }
    let since = if since.trim().is_empty() { "5m" } else { since };
    let since = parse_duration(since).with_context(|| format!("invalid since {since:?}"))?;
    if since.is_zero() || since > JOURNAL_MAX_SINCE {
        anyhow::bail!("since must be in (0, 24h]; got {}s", since.as_secs());
    }
    let lines = if lines == 0 {
        JOURNAL_DEFAULT_LINES
    } else {
        lines.min(JOURNAL_MAX_LINES)
    };
    Ok(HostDiagnosticPlan::JournalTail {
        command: CommandSpec::new(
            "journalctl",
            [
                "-u".to_string(),
                unit.to_string(),
                "--since".to_string(),
                format_duration(since),
                "--no-pager".to_string(),
                "-n".to_string(),
                lines.to_string(),
                "--output=short-iso".to_string(),
            ],
            Duration::from_secs(30),
            MAX_COMMAND_OUTPUT_BYTES,
        ),
        unit: unit.to_string(),
        since,
        lines,
    })
}

fn parse_ss_users(field: &&str) -> Option<(Option<u32>, Option<String>)> {
    let body = field.strip_prefix("users:((")?.trim_end_matches("))");
    let mut pid = None;
    let mut command = None;
    for part in body.split(',') {
        if let Some(name) = part.strip_prefix('"') {
            command = Some(name.trim_matches('"').to_string());
        } else if let Some(raw_pid) = part.strip_prefix("pid=") {
            pid = raw_pid.parse::<u32>().ok();
        }
    }
    Some((pid, command))
}

fn split_addr_port(value: &str) -> (String, u16) {
    let Some(idx) = value.rfind(':') else {
        return (value.to_string(), 0);
    };
    let addr = value[..idx].to_string();
    let port = value[idx + 1..].parse::<u16>().unwrap_or(0);
    (addr, port)
}
