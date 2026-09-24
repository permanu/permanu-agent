//! The `spec` of `alert.rule.create`/`update` (signed-plan.md 3.2): the
//! proto3 JSON of `AlertRule` without server-assigned fields
//! (agent-protocol.md 10.3). Field names are accepted in lowerCamelCase and
//! as declared; enums by name or number; durations as `"300s"`.
//! Out-of-range values make the spec invalid (the rule is not applied).

use serde_json::{Map, Value};

use crate::proto::agent::v2::{
    alert_rule, event_condition, label_matcher, AlertRule, AlertSeverity, ComparisonOp,
    EventCondition, LabelMatcher, LogCondition, LogLevel, MetricAggregation, MetricCondition,
    Scope,
};

/// Section 10.3 bounds.
pub const DEFAULT_REPEAT_SECONDS: i64 = 4 * 3_600;
const REPEAT_RANGE: (i64, i64) = (300, 7 * 86_400);
const METRIC_WINDOW: (i64, i64) = (30, 86_400);
const DEFAULT_METRIC_WINDOW: i64 = 300;
const FOR_RANGE: (i64, i64) = (0, 86_400);
const LOG_WINDOW: (i64, i64) = (60, 86_400);
const MAX_REGEX_BYTES: usize = 512;

fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn field<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    map.get(&camel(name))
        .or_else(|| map.get(name))
        .filter(|v| !v.is_null())
}

fn string(map: &Map<String, Value>, name: &str) -> Result<String, String> {
    match field(map, name) {
        None => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(format!("{name} must be a string")),
    }
}

fn boolean(map: &Map<String, Value>, name: &str) -> Result<bool, String> {
    match field(map, name) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{name} must be a boolean")),
    }
}

fn number(map: &Map<String, Value>, name: &str) -> Result<f64, String> {
    match field(map, name) {
        None => Ok(0.0),
        Some(Value::Number(n)) => n.as_f64().ok_or_else(|| format!("{name} is not a number")),
        // proto3 JSON allows numbers as strings.
        Some(Value::String(s)) => s.parse().map_err(|_| format!("{name} is not a number")),
        Some(_) => Err(format!("{name} must be a number")),
    }
}

/// `"300s"` / `"1.5s"` → whole seconds (fractions rounded up).
fn duration(map: &Map<String, Value>, name: &str) -> Result<Option<i64>, String> {
    let Some(value) = field(map, name) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .and_then(|t| t.strip_suffix('s'))
        .ok_or_else(|| format!("{name} must be a duration like \"300s\""))?;
    let seconds: f64 = text
        .parse()
        .map_err(|_| format!("{name} must be a duration like \"300s\""))?;
    if !seconds.is_finite() || !(0.0..=1e9).contains(&seconds) {
        return Err(format!("{name} is out of range"));
    }
    Ok(Some(seconds.ceil() as i64))
}

fn enum_value<E: TryFrom<i32>>(
    map: &Map<String, Value>,
    name: &str,
    from_name: fn(&str) -> Option<E>,
) -> Result<Option<E>, String> {
    match field(map, name) {
        None => Ok(None),
        Some(Value::String(text)) => from_name(text)
            .map(Some)
            .ok_or_else(|| format!("{name}: unknown value")),
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .and_then(|n| E::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| format!("{name}: unknown value")),
        Some(_) => Err(format!("{name}: unknown value")),
    }
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn in_range(value: i64, (low, high): (i64, i64), name: &str) -> Result<i64, String> {
    if (low..=high).contains(&value) {
        Ok(value)
    } else {
        Err(format!("{name} must be {low}-{high} s"))
    }
}

fn scope(map: &Map<String, Value>) -> Result<Option<Scope>, String> {
    let Some(value) = field(map, "scope") else {
        return Ok(None);
    };
    let map = object(value, "scope")?;
    Ok(Some(Scope {
        project_id: string(map, "project_id")?,
        service_id: string(map, "service_id")?,
        deployment_id: string(map, "deployment_id")?,
        app_id: string(map, "app_id")?,
        environment: string(map, "environment")?,
        environment_id: string(map, "environment_id")?,
    }))
}

fn metric(map: &Map<String, Value>) -> Result<MetricCondition, String> {
    let name = string(map, "metric")?;
    if name.is_empty() || name.len() > 256 {
        return Err("metric is required".to_owned());
    }
    let mut matchers = Vec::new();
    if let Some(list) = field(map, "matchers") {
        for item in list
            .as_array()
            .ok_or("matchers must be a list")?
            .iter()
            .take(16)
        {
            let item = object(item, "matcher")?;
            let op = enum_value(item, "op", label_matcher::Op::from_str_name)?
                .unwrap_or(label_matcher::Op::Unspecified);
            let value = string(item, "value")?;
            if matches!(op, label_matcher::Op::Regex | label_matcher::Op::NotRegex)
                && (value.len() > MAX_REGEX_BYTES || regex::Regex::new(&value).is_err())
            {
                return Err("matcher regex is invalid".to_owned());
            }
            matchers.push(LabelMatcher {
                name: string(item, "name")?,
                op: op as i32,
                value,
            });
        }
    }
    let window = in_range(
        duration(map, "window")?.unwrap_or(DEFAULT_METRIC_WINDOW),
        METRIC_WINDOW,
        "window",
    )?;
    let for_duration = in_range(
        duration(map, "for_duration")?.unwrap_or(0),
        FOR_RANGE,
        "for_duration",
    )?;
    let op = enum_value(map, "op", ComparisonOp::from_str_name)?
        .filter(|op| *op != ComparisonOp::Unspecified)
        .ok_or("op is required")?;
    Ok(MetricCondition {
        metric: name,
        matchers,
        aggregation: enum_value(map, "aggregation", MetricAggregation::from_str_name)?
            .unwrap_or(MetricAggregation::Unspecified) as i32,
        window: Some(prost_types::Duration {
            seconds: window,
            nanos: 0,
        }),
        op: op as i32,
        threshold: number(map, "threshold")?,
        for_duration: Some(prost_types::Duration {
            seconds: for_duration,
            nanos: 0,
        }),
    })
}

fn log(map: &Map<String, Value>) -> Result<LogCondition, String> {
    let regex = string(map, "regex")?;
    if regex.len() > MAX_REGEX_BYTES || (!regex.is_empty() && regex::Regex::new(&regex).is_err()) {
        return Err("regex is invalid".to_owned());
    }
    let window = in_range(
        duration(map, "window")?.unwrap_or(300),
        LOG_WINDOW,
        "window",
    )?;
    let count = number(map, "count")?;
    if !(0.0..=1e9).contains(&count) {
        return Err("count is out of range".to_owned());
    }
    Ok(LogCondition {
        scope: scope(map)?,
        min_level: enum_value(map, "min_level", LogLevel::from_str_name)?
            .unwrap_or(LogLevel::Unspecified) as i32,
        contains: string(map, "contains")?,
        regex,
        window: Some(prost_types::Duration {
            seconds: window,
            nanos: 0,
        }),
        count: count as u32,
    })
}

fn event(map: &Map<String, Value>) -> Result<EventCondition, String> {
    let kind = enum_value(map, "kind", event_condition::Kind::from_str_name)?
        .filter(|kind| *kind != event_condition::Kind::Unspecified)
        .ok_or("kind is required")?;
    Ok(EventCondition {
        kind: kind as i32,
        scope: scope(map)?,
    })
}

/// Parses a rule's signed `spec` into an `AlertRule` with `id` and `name`
/// from the plan. Exactly one condition is required.
pub fn parse(rule_id: &str, name: &str, spec: &str) -> Result<AlertRule, String> {
    let value: Value = serde_json::from_str(spec).map_err(|_| "spec is not JSON".to_owned())?;
    let map = object(&value, "spec")?;
    let conditions: Vec<(&str, &Value)> = ["metric", "log", "event"]
        .iter()
        .filter_map(|name| field(map, name).map(|v| (*name, v)))
        .collect();
    let [(kind, body)] = conditions.as_slice() else {
        return Err("exactly one of metric, log or event is required".to_owned());
    };
    let body = object(body, kind)?;
    let condition = match *kind {
        "metric" => alert_rule::Condition::Metric(metric(body)?),
        "log" => alert_rule::Condition::Log(log(body)?),
        _ => alert_rule::Condition::Event(event(body)?),
    };
    let mut channel_ids = Vec::new();
    if let Some(list) = field(map, "channel_ids") {
        for id in list
            .as_array()
            .ok_or("channel_ids must be a list")?
            .iter()
            .take(16)
        {
            channel_ids.push(id.as_str().ok_or("channel_ids must be strings")?.to_owned());
        }
    }
    let repeat = in_range(
        duration(map, "repeat_interval")?.unwrap_or(DEFAULT_REPEAT_SECONDS),
        REPEAT_RANGE,
        "repeat_interval",
    )?;
    Ok(AlertRule {
        id: rule_id.to_owned(),
        name: name.to_owned(),
        severity: enum_value(map, "severity", AlertSeverity::from_str_name)?
            .unwrap_or(AlertSeverity::Warning) as i32,
        condition: Some(condition),
        channel_ids,
        repeat_interval: Some(prost_types::Duration {
            seconds: repeat,
            nanos: 0,
        }),
        notify_on_resolve: boolean(map, "notify_on_resolve")?,
        enabled: boolean(map, "enabled")?,
        ..Default::default()
    })
}

/// contracts v1.1.5 (D-063 #2, agent-protocol.md 10.3): the built-in event
/// kinds this agent emits, so an event rule of one of them can fire.
pub const EVALUATED_EVENTS: &[event_condition::Kind] = &[
    event_condition::Kind::CronMissed,
    event_condition::Kind::CronFailed,
    event_condition::Kind::BackupFailed,
    event_condition::Kind::DeployFailed,
    event_condition::Kind::WebhookBuildFailed,
    event_condition::Kind::RestoreVerificationFailed,
    event_condition::Kind::TelemetryDropping,
];

/// False only for a valid event rule of a kind this agent does not
/// evaluate (refused `EXEC_PRECONDITION`); any other spec passes here and is
/// judged by [`parse`].
pub fn event_kind_evaluated(spec: &str) -> bool {
    match parse("rule", "rule", spec) {
        Ok(AlertRule {
            condition: Some(alert_rule::Condition::Event(condition)),
            ..
        }) => EVALUATED_EVENTS
            .iter()
            .any(|kind| *kind as i32 == condition.kind),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_rules_parse_in_both_field_spellings() {
        let rule = parse(
            "r1",
            "CPU high",
            r#"{"severity": "ALERT_SEVERITY_CRITICAL", "metric": {"metric": "host.cpu.percent",
                "matchers": [{"name": "server_id", "op": "OP_EQ", "value": "s"}],
                "aggregation": "METRIC_AGGREGATION_AVG", "window": "60s", "op": "COMPARISON_OP_GT",
                "threshold": 90, "forDuration": "120s"}, "channelIds": ["c1"],
                "repeat_interval": "3600s", "notifyOnResolve": true, "enabled": true}"#,
        )
        .unwrap();
        assert_eq!(rule.severity, AlertSeverity::Critical as i32);
        let Some(alert_rule::Condition::Metric(metric)) = rule.condition else {
            panic!("metric");
        };
        assert_eq!(metric.window.unwrap().seconds, 60);
        assert_eq!(metric.for_duration.unwrap().seconds, 120);
        assert_eq!(metric.op, ComparisonOp::Gt as i32);
        assert_eq!(metric.threshold, 90.0);
        assert_eq!(rule.channel_ids, ["c1"]);
        assert_eq!(rule.repeat_interval.unwrap().seconds, 3_600);
        assert!(rule.notify_on_resolve && rule.enabled);
    }

    #[test]
    fn defaults_and_bounds_follow_section_10_3() {
        let rule = parse(
            "r",
            "n",
            r#"{"event": {"kind": "KIND_TELEMETRY_DROPPING"}, "enabled": true}"#,
        )
        .unwrap();
        assert_eq!(rule.repeat_interval.unwrap().seconds, 4 * 3_600);
        assert_eq!(rule.severity, AlertSeverity::Warning as i32);
        for bad in [
            r#"{}"#,
            r#"{"metric": {"metric": "m", "op": "COMPARISON_OP_GT"}, "log": {}}"#,
            r#"{"metric": {"metric": "m", "op": "COMPARISON_OP_GT", "window": "10s"}}"#,
            r#"{"metric": {"metric": "m"}}"#,
            r#"{"log": {"window": "30s"}}"#,
            r#"{"log": {"regex": "("}}"#,
            r#"{"event": {"kind": "KIND_NOPE"}}"#,
            r#"{"event": {"kind": 6}, "repeatInterval": "60s"}"#,
            "not json",
        ] {
            assert!(parse("r", "n", bad).is_err(), "{bad}");
        }
        let log = parse(
            "r",
            "n",
            r#"{"log": {"contains": "panic", "count": 3, "minLevel": 5}}"#,
        )
        .unwrap();
        let Some(alert_rule::Condition::Log(log)) = log.condition else {
            panic!("log");
        };
        assert_eq!(log.window.unwrap().seconds, 300);
        assert_eq!(log.min_level, LogLevel::Error as i32);
        assert_eq!(log.count, 3);
    }
}
