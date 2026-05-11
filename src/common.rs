use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl CommandSpec {
    pub(crate) fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            timeout,
            max_output_bytes,
        }
    }
}

pub(crate) const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_STATUS_OUTPUT_BYTES: usize = 64 * 1024;

pub(crate) fn parse_duration(value: &str) -> anyhow::Result<Duration> {
    use anyhow::{anyhow, Context};

    let value = value.trim();
    if value.len() < 2 {
        anyhow::bail!("duration must include a unit");
    }
    let (number, unit) = value.split_at(value.len() - 1);
    let number = number.parse::<u64>().context("duration must be numeric")?;
    match unit {
        "s" => Ok(Duration::from_secs(number)),
        "m" => Ok(Duration::from_secs(number.saturating_mul(60))),
        "h" => Ok(Duration::from_secs(number.saturating_mul(60 * 60))),
        _ => Err(anyhow!("duration unit must be s|m|h")),
    }
}

pub(crate) fn format_duration(duration: Duration) -> String {
    if duration.as_secs().is_multiple_of(60 * 60) {
        format!("{}h", duration.as_secs() / (60 * 60))
    } else if duration.as_secs().is_multiple_of(60) {
        format!("{}m", duration.as_secs() / 60)
    } else {
        format!("{}s", duration.as_secs())
    }
}

pub(crate) fn validate_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{label} is required");
    }
    if value.len() > 128 {
        anyhow::bail!("{label} is too long");
    }
    if value
        .bytes()
        .any(|byte| !matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}
