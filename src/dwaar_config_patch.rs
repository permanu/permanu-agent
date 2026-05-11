use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::common::{CommandSpec, MAX_STATUS_OUTPUT_BYTES};

const DWAAR_VALUE_MAX_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwaarConfigPatch {
    pub block: String,
    pub action: DwaarConfigAction,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DwaarConfigAction {
    Upsert,
    Remove,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct DwaarConfigPatchResult {
    pub block: String,
    pub action: String,
    pub prev: String,
    pub new: String,
    pub restart_ok: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwaarConfigPatchPlan {
    pub content: String,
    pub result: DwaarConfigPatchResult,
    pub backup_retention: usize,
    pub restart: CommandSpec,
    pub active_check: CommandSpec,
}

pub fn parse_dwaar_config_patch(payload: &[u8]) -> Result<DwaarConfigPatch> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        block: String,
        #[serde(default)]
        action: String,
        #[serde(default)]
        value: String,
    }

    let payload: Payload = serde_json::from_slice(payload).context("malformed payload")?;
    let block = payload.block.trim();
    if !matches!(block, "analytics" | "log_level" | "rate_limit_default") {
        anyhow::bail!("block {block:?} not in allowlist");
    }
    let action = match payload.action.as_str() {
        "upsert" => DwaarConfigAction::Upsert,
        "remove" => DwaarConfigAction::Remove,
        other => anyhow::bail!("action {other:?} must be upsert|remove"),
    };
    let value = payload.value.trim().to_string();
    if action == DwaarConfigAction::Upsert {
        validate_dwaar_value(&value)?;
    }
    Ok(DwaarConfigPatch {
        block: block.to_string(),
        action,
        value,
    })
}

pub fn plan_dwaar_config_patch(
    current_content: &str,
    patch: &DwaarConfigPatch,
) -> Result<DwaarConfigPatchPlan> {
    let had_final_newline = current_content.ends_with('\n');
    let lines = split_lines_preserving_shape(current_content);
    let prev = extract_dwaar_block_body(&lines, &patch.block).unwrap_or_default();
    let (new_lines, new_body) = match patch.action {
        DwaarConfigAction::Upsert => upsert_dwaar_block(&lines, &patch.block, &patch.value),
        DwaarConfigAction::Remove => (remove_dwaar_block(&lines, &patch.block), String::new()),
    };
    let mut content = new_lines.join("\n");
    if had_final_newline && !content.ends_with('\n') {
        content.push('\n');
    }

    Ok(DwaarConfigPatchPlan {
        content,
        result: DwaarConfigPatchResult {
            block: patch.block.clone(),
            action: match patch.action {
                DwaarConfigAction::Upsert => "upsert",
                DwaarConfigAction::Remove => "remove",
            }
            .to_string(),
            prev,
            new: new_body,
            restart_ok: true,
        },
        backup_retention: 5,
        restart: CommandSpec::new(
            "systemctl",
            ["restart", "dwaar"],
            Duration::from_secs(20),
            MAX_STATUS_OUTPUT_BYTES,
        ),
        active_check: CommandSpec::new(
            "systemctl",
            ["is-active", "dwaar"],
            Duration::from_secs(2),
            MAX_STATUS_OUTPUT_BYTES,
        ),
    })
}

fn validate_dwaar_value(value: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("value is required for upsert");
    }
    if value.len() > DWAAR_VALUE_MAX_BYTES {
        anyhow::bail!("value exceeds {DWAAR_VALUE_MAX_BYTES} bytes");
    }
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        anyhow::bail!("value must be a single line");
    }
    Ok(())
}

fn split_lines_preserving_shape(content: &str) -> Vec<String> {
    if content.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    if content.ends_with('\n') {
        lines.push(String::new());
    }
    lines
}

fn strip_dwaar_comment(line: &str) -> &str {
    line.split_once('#')
        .map(|(before, _)| before)
        .unwrap_or(line)
}

fn find_dwaar_global_block(lines: &[String]) -> Option<(usize, usize)> {
    let mut depth = 0isize;
    let mut start = None;
    for (idx, raw) in lines.iter().enumerate() {
        let line = strip_dwaar_comment(raw);
        let opens = line.matches('{').count() as isize;
        let closes = line.matches('}').count() as isize;
        if depth == 0 && start.is_none() && opens > 0 {
            let head = line.split_once('{').map(|(head, _)| head).unwrap_or(line);
            if head.trim().is_empty() {
                start = Some(idx);
            }
        }
        depth += opens - closes;
        if let Some(start_idx) = start {
            if depth == 0 {
                return Some((start_idx, idx));
            }
        }
    }
    None
}

fn find_dwaar_block(lines: &[String], name: &str) -> Option<(usize, usize)> {
    let (configurable_depth, scan_from, scan_to) =
        if let Some((global_start, global_end)) = find_dwaar_global_block(lines) {
            if global_end <= global_start + 1 {
                return None;
            }
            (1isize, global_start + 1, global_end - 1)
        } else if lines.is_empty() {
            return None;
        } else {
            (0isize, 0, lines.len() - 1)
        };

    let mut depth = 0isize;
    let mut start = None;
    for (idx, raw) in lines.iter().enumerate() {
        let line = strip_dwaar_comment(raw);
        if start.is_none()
            && depth == configurable_depth
            && idx >= scan_from
            && idx <= scan_to
            && line.contains('{')
        {
            let head = line.split_once('{').map(|(head, _)| head).unwrap_or(line);
            if head.trim() == name {
                start = Some(idx);
            }
        }
        depth += line.matches('{').count() as isize - line.matches('}').count() as isize;
        if let Some(start_idx) = start {
            if depth == configurable_depth {
                return Some((start_idx, idx));
            }
        }
    }
    None
}

fn extract_dwaar_block_body(lines: &[String], name: &str) -> Option<String> {
    let (start, end) = find_dwaar_block(lines, name)?;
    if start == end {
        let line = &lines[start];
        let open = line.find('{')?;
        let close = line.rfind('}')?;
        if close <= open {
            return Some(String::new());
        }
        return Some(line[open + 1..close].trim().to_string());
    }
    Some(lines[start + 1..end].join("\n").trim().to_string())
}

fn upsert_dwaar_block(lines: &[String], name: &str, value: &str) -> (Vec<String>, String) {
    let body = value.trim().to_string();
    let new_line = format!("{name} {{ {body} }}");
    if let Some((start, end)) = find_dwaar_block(lines, name) {
        let mut out = Vec::with_capacity(lines.len().saturating_sub(end - start));
        out.extend_from_slice(&lines[..start]);
        out.push(new_line);
        out.extend_from_slice(&lines[end + 1..]);
        return (out, body);
    }

    let mut insert_at = lines.len();
    if let Some((global_start, global_end)) = find_dwaar_global_block(lines) {
        if global_end > global_start {
            insert_at = global_end;
        }
    } else {
        while insert_at > 0 && lines[insert_at - 1].trim().is_empty() {
            insert_at -= 1;
        }
    }

    let mut out = Vec::with_capacity(lines.len() + 1);
    out.extend_from_slice(&lines[..insert_at]);
    out.push(new_line);
    out.extend_from_slice(&lines[insert_at..]);
    (out, body)
}

fn remove_dwaar_block(lines: &[String], name: &str) -> Vec<String> {
    let Some((start, end)) = find_dwaar_block(lines, name) else {
        return lines.to_vec();
    };
    let mut out = Vec::with_capacity(lines.len().saturating_sub(end - start + 1));
    out.extend_from_slice(&lines[..start]);
    out.extend_from_slice(&lines[end + 1..]);
    out
}
