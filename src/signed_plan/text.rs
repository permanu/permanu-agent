//! Hand-written matchers for the string patterns of signed-plan.md sections 2 and 3.
//!
//! Each function mirrors one pattern of the reference script (`RE` in
//! `signed_plan_vectors.py`). They are anchored full matches over ASCII only.

fn all_bytes(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    value.bytes().all(allowed)
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

pub(crate) fn hex_n(value: &str, length: usize) -> bool {
    value.len() == length && all_bytes(value, is_lower_hex)
}

pub(crate) fn hex64(value: &str) -> bool {
    hex_n(value, 64)
}

pub(crate) fn hex40(value: &str) -> bool {
    hex_n(value, 40)
}

/// `[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`
pub(crate) fn uuid7(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let valid = match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            14 => *byte == b'7',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => is_lower_hex(*byte),
        };
        if !valid {
            return false;
        }
    }
    true
}

/// `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
pub(crate) fn reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && all_bytes(value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_b64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

/// `[A-Za-z0-9_-]{22}`
pub(crate) fn key_id(value: &str) -> bool {
    value.len() == 22 && all_bytes(value, is_b64url)
}

/// `[A-Za-z_][A-Za-z0-9_]{0,127}`
pub(crate) fn env_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && all_bytes(value, |byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn host_label(label: &str, final_label: bool) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let first_ok = if final_label {
        bytes[0].is_ascii_lowercase()
    } else {
        bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()
    };
    let last = bytes[bytes.len() - 1];
    let last_ok = final_label || last.is_ascii_lowercase() || last.is_ascii_digit();
    first_ok
        && last_ok
        && all_bytes(label, |byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
        })
}

/// `(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}`
pub(crate) fn hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let (last, rest) = labels.split_last().expect("at least two labels");
    rest.iter().all(|label| host_label(label, false)) && host_label(last, true)
}

/// One decimal IPv4 octet without leading zeros (`0`..`255`).
fn octet(value: &str) -> Option<u32> {
    let ok = !value.is_empty()
        && value.len() <= 3
        && all_bytes(value, |byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'));
    ok.then(|| value.parse::<u32>().ok())
        .flatten()
        .filter(|n| *n <= 255)
}

fn ipv4_parts(value: &str, separator: char) -> Option<u32> {
    let parts: Vec<&str> = value.split(separator).collect();
    if parts.len() != 4 {
        return None;
    }
    parts
        .iter()
        .try_fold(0u32, |acc, part| Some((acc << 8) | octet(part)?))
}

/// v1.0.13 (D-063 #4): RFC 6890 blocks that are never a public address.
const NON_PUBLIC_IPV4: &[(u32, u32)] = &[
    (0x0000_0000, 8),
    (0x0a00_0000, 8),
    (0x6440_0000, 10),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xac10_0000, 12),
    (0xc000_0000, 24),
    (0xc000_0200, 24),
    (0xc058_6300, 24),
    (0xc0a8_0000, 16),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
];

/// v1.0.13 (D-063 #4): a dotted-quad IPv4 address without leading zeros,
/// outside every special-purpose block (a `webhook.host.set` host).
pub(crate) fn public_ipv4(value: &str) -> bool {
    ipv4_parts(value, '.').is_some_and(|ip| {
        NON_PUBLIC_IPV4
            .iter()
            .all(|(net, bits)| ip >> (32 - bits) != net >> (32 - bits))
    })
}

/// Whether `value` has the dotted-quad shape (any address).
pub(crate) fn ipv4_shaped(value: &str) -> bool {
    !value.is_empty() && all_bytes(value, |byte| byte.is_ascii_digit() || byte == b'.')
}

/// v1.0.13 (D-063 #5): `<label>.<a>-<b>-<c>-<d>.sslip.io`, one DNS label and
/// the dashed IPv4 octets without leading zeros.
pub(crate) fn default_route(value: &str) -> bool {
    let Some(rest) = value.strip_suffix(".sslip.io") else {
        return false;
    };
    let Some((label, ip)) = rest.split_once('.') else {
        return false;
    };
    let label_ok = !label.is_empty()
        && label.len() <= 63
        && all_bytes(label, |byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
        })
        && !label.starts_with('-')
        && !label.ends_with('-');
    label_ok && ipv4_parts(ip, '-').is_some()
}

/// `[0-9*/,-]+( [0-9*/,-]+){4}`
pub(crate) fn cron(value: &str) -> bool {
    let fields: Vec<&str> = value.split(' ').collect();
    fields.len() == 5
        && fields.iter().all(|field| {
            !field.is_empty()
                && all_bytes(field, |byte| {
                    byte.is_ascii_digit() || matches!(byte, b'*' | b'/' | b',' | b'-')
                })
        })
}

fn digits(value: &str) -> bool {
    !value.is_empty() && all_bytes(value, |byte| byte.is_ascii_digit())
}

/// `\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?`
pub(crate) fn semver(value: &str) -> bool {
    let (core, pre) = match value.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (value, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| digits(part))
        && pre.is_none_or(|pre| {
            !pre.is_empty()
                && all_bytes(pre, |byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
                })
        })
}

/// `[a-z0-9.-]+(/[A-Za-z0-9._-]+){1,4}`
pub(crate) fn repo(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    let Some((host, path)) = parts.split_first() else {
        return false;
    };
    !host.is_empty()
        && all_bytes(host, |byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && (1..=4).contains(&path.len())
        && path.iter().all(|segment| {
            !segment.is_empty()
                && all_bytes(segment, |byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

/// `[A-Za-z0-9._:-]{1,128}`
pub(crate) fn delivery_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && all_bytes(value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

/// `/[A-Za-z0-9._/-]{1,255}`
pub(crate) fn abs_path(value: &str) -> bool {
    value.len() >= 2
        && value.len() <= 256
        && value.starts_with('/')
        && all_bytes(&value[1..], |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}

/// `[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]`
pub(crate) fn bucket(value: &str) -> bool {
    let bytes = value.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    (3..=63).contains(&bytes.len())
        && edge(bytes[0])
        && edge(bytes[bytes.len() - 1])
        && all_bytes(value, |byte| edge(byte) || matches!(byte, b'.' | b'-'))
}

/// `UTC|[A-Za-z_]+(/[A-Za-z0-9_+-]+){1,2}`
pub(crate) fn timezone(value: &str) -> bool {
    if value == "UTC" {
        return true;
    }
    let parts: Vec<&str> = value.split('/').collect();
    let Some((area, rest)) = parts.split_first() else {
        return false;
    };
    !area.is_empty()
        && all_bytes(area, |byte| byte.is_ascii_alphabetic() || byte == b'_')
        && (1..=2).contains(&rest.len())
        && rest.iter().all(|part| {
            !part.is_empty()
                && all_bytes(part, |byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-')
                })
        })
}

/// `[a-z0-9]([a-z0-9._-]*[a-z0-9])?`
fn image_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && edge(bytes[0])
        && edge(bytes[bytes.len() - 1])
        && all_bytes(value, |byte| {
            edge(byte) || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// `[a-z0-9]([a-z0-9._-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?){0,6}`
pub(crate) fn image_repository(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    let Some((host, path)) = parts.split_first() else {
        return false;
    };
    let host_ok = match host.split_once(':') {
        Some((name, port)) => image_component(name) && digits(port) && port.len() <= 5,
        None => image_component(host),
    };
    host_ok && path.len() <= 6 && path.iter().all(|segment| image_component(segment))
}

/// `[A-Z][A-Z_]{1,31}`
pub(crate) fn capability(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=32).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && all_bytes(value, |byte| byte.is_ascii_uppercase() || byte == b'_')
}

fn user_part(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=32).contains(&bytes.len())
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        && all_bytes(value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
        })
}

/// `[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,31})?`
pub(crate) fn user(value: &str) -> bool {
    match value.split_once(':') {
        Some((name, group)) => user_part(name) && user_part(group),
        None => user_part(value),
    }
}

/// Labels: no C0/C1 controls, DEL, bidi controls, zero-width characters or BOM,
/// and no leading or trailing whitespace.
pub(crate) fn label_chars_ok(value: &str) -> bool {
    let forbidden = |character: char| {
        let code = u32::from(character);
        code <= 0x1f
            || (0x7f..=0x9f).contains(&code)
            || code == 0x061c
            || (0x200b..=0x200f).contains(&code)
            || (0x202a..=0x202e).contains(&code)
            || (0x2060..=0x2069).contains(&code)
            || code == 0xfeff
    };
    !value.chars().any(forbidden) && value.trim() == value
}

/// `refs/heads/<name>` under `git check-ref-format` (git ref names are
/// case-sensitive, so `.lock` is compared exactly); with `pattern`, also `refs/heads/<prefix>/*`.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
pub(crate) fn git_ref(value: &str, pattern: bool) -> bool {
    if value.len() > 211 {
        return false;
    }
    let Some(mut name) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    if pattern {
        if let Some(prefix) = name.strip_suffix("/*") {
            name = prefix;
        }
    }
    (1..=200).contains(&name.len())
        && all_bytes(name, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && !name.starts_with('/')
        && !name.starts_with('-')
        && !name.ends_with('/')
        && !name.ends_with('.')
        && !name.ends_with(".lock")
        && name
            .split('/')
            .all(|component| !component.starts_with('.') && !component.ends_with(".lock"))
}

/// `YYYY-MM-DDTHH:MM:SSZ` → Unix seconds, with calendar validation.
pub(crate) fn timestamp(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 {
        return None;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let valid = match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        };
        if !valid {
            return None;
        }
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if year < 1 || !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn format_timestamp(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_accept_and_reject_representative_values() {
        assert!(uuid7("01a0cdb5-3500-70a1-8000-000000000001"));
        assert!(!uuid7("01a0cdb5-3500-40a1-8000-000000000001"));
        assert!(!uuid7("01A0cdb5-3500-70a1-8000-000000000001"));
        assert!(hostname("app.example.com"));
        assert!(!hostname("example"));
        assert!(!hostname("app.1com"));
        assert!(git_ref("refs/heads/main", false));
        assert!(git_ref("refs/heads/release/*", true));
        assert!(!git_ref("refs/heads/release/*", false));
        assert!(!git_ref("refs/heads/a..b", false));
        assert!(!git_ref("refs/heads/x.lock", false));
        assert!(image_repository("registry.permanu.internal/acme/web"));
        assert!(image_repository("localhost:5000/web"));
        assert!(!image_repository("Registry/web"));
        assert!(!image_repository("web@sha256"));
        assert!(semver("1.2.3-rc.1"));
        assert!(!semver("1.2"));
        assert!(cron("0 4 * * 0"));
        assert!(!cron("0 4 * *"));
        assert!(timezone("Europe/Berlin") && timezone("UTC"));
        assert!(user("1000:1000") && !user(":1000"));
        assert!(!label_chars_ok("evil\u{202e}txt"));
        assert!(!label_chars_ok(" padded"));
    }

    #[test]
    fn timestamps_round_trip_and_reject_invalid_dates() {
        let seconds = timestamp("2026-09-23T10:05:00Z").expect("valid");
        assert_eq!(format_timestamp(seconds), "2026-09-23T10:05:00Z");
        assert_eq!(timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert!(timestamp("2026-02-29T00:00:00Z").is_none());
        assert!(timestamp("2024-02-29T00:00:00Z").is_some());
        assert!(timestamp("2026-09-23T10:05:00+00:00").is_none());
        assert!(timestamp("2026-09-23 10:05:00Z").is_none());
    }

    /// v1.0.13 (D-063 #4, #5): IPv4 webhook hosts and default routes.
    #[test]
    fn public_ipv4_and_default_routes() {
        assert!(public_ipv4("11.22.0.10") && public_ipv4("8.8.8.8"));
        assert!(public_ipv4("223.255.255.255"));
        for bad in [
            "10.0.0.5",
            "0.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.19.0.1",
            "198.51.100.1",
            "203.0.113.7",
            "224.0.0.1",
            "255.255.255.255",
            "11.22.0.010",
            "11.22.0",
            "11.22.0.256",
            "11.22.0.1.",
            "a.b.c.d",
            "",
        ] {
            assert!(!public_ipv4(bad), "{bad}");
        }
        assert!(public_ipv4("172.32.0.1") && public_ipv4("100.128.0.1"));
        assert!(default_route("web-production-shop.11-22-0-10.sslip.io"));
        assert!(default_route("a.0-0-0-0.sslip.io"));
        assert!(!default_route("web-production-shop.11-22-0-010.sslip.io"));
        assert!(!default_route("shop.example.com"));
        assert!(!default_route("-web.11-22-0-10.sslip.io"));
        assert!(!default_route("a.b.11-22-0-10.sslip.io"));
        assert!(!default_route("web.11-22-0.sslip.io"));
        assert!(!default_route("web.11-22-0-256.sslip.io"));
        assert!(!default_route("Web.11-22-0-10.sslip.io"));
    }
}
