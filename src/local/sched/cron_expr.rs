//! Cron expressions and fire times (signed-plan.md 14.9, agent-protocol.md
//! 10): five fields (minute, hour, day of month, month, day of week) with
//! lists, ranges and steps; `0` and `7` are Sunday; when both day fields are
//! restricted a day matches either (Vixie cron). Fire times are whole
//! minutes of local wall time in the job's IANA timezone, resolved with the
//! tz database compiled into the agent: a wall time skipped by a DST change
//! never fires and one repeated by it fires once, at its first occurrence.

use jiff::civil::{Date, DateTime};
use jiff::tz::{AmbiguousOffset, TimeZone};
use jiff::Timestamp;

/// Fire times are searched at most this many days ahead (a `31 2 *` job
/// never fires; leap-day jobs fire every four years).
const SEARCH_DAYS: i64 = 366 * 8 + 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    minutes: u64,
    hours: u32,
    days: u32,
    months: u16,
    weekdays: u8,
    /// Whether the raw day-of-month / day-of-week field starts with `*`.
    dom_star: bool,
    dow_star: bool,
}

const FIELDS: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];

fn number(text: &str) -> Option<u32> {
    ((1..=2).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// One item `(\*|n(-m)?)(/step)?` as a bit set, or `None`.
fn item(item: &str, low: u32, high: u32) -> Option<u64> {
    let (range, step) = match item.split_once('/') {
        Some((range, step)) => (range, Some(number(step).filter(|s| *s >= 1)?)),
        None => (item, None),
    };
    let (start, end) = if range == "*" {
        (low, high)
    } else if let Some((a, b)) = range.split_once('-') {
        (number(a)?, number(b)?)
    } else {
        let start = number(range)?;
        (start, if step.is_some() { high } else { start })
    };
    if !(low <= start && start <= end && end <= high) {
        return None;
    }
    let mut bits = 0u64;
    let mut value = start;
    while value <= end {
        bits |= 1 << value;
        value += step.unwrap_or(1);
    }
    Some(bits)
}

fn field(text: &str, (low, high): (u32, u32)) -> Option<u64> {
    text.split(',')
        .try_fold(0u64, |bits, part| Some(bits | item(part, low, high)?))
}

impl CronExpr {
    /// The grammar of section 14.9 (single spaces, no names or macros).
    pub fn parse(expression: &str) -> Option<Self> {
        let parts: Vec<&str> = expression.split(' ').collect();
        if parts.len() != 5 {
            return None;
        }
        let mut bits = [0u64; 5];
        for (index, part) in parts.iter().enumerate() {
            bits[index] = field(part, FIELDS[index])?;
        }
        let mut weekdays = bits[4];
        if weekdays & (1 << 7) != 0 {
            weekdays = (weekdays | 1) & !(1 << 7);
        }
        Some(Self {
            minutes: bits[0],
            hours: bits[1] as u32,
            days: bits[2] as u32,
            months: bits[3] as u16,
            weekdays: weekdays as u8,
            dom_star: parts[2].starts_with('*'),
            dow_star: parts[4].starts_with('*'),
        })
    }

    fn day_matches(&self, date: Date) -> bool {
        let dom = self.days & (1 << date.day()) != 0;
        let dow = self.weekdays & (1 << date.weekday().to_sunday_zero_offset()) != 0;
        if self.dom_star || self.dow_star {
            dom && dow
        } else {
            dom || dow
        }
    }

    /// The first fire time strictly after `after` (Unix seconds), in `tz`.
    pub fn next_after(&self, tz: &TimeZone, after: i64) -> Option<i64> {
        let start = Timestamp::from_second(after).ok()?.to_zoned(tz.clone());
        let mut date = start.date();
        for _ in 0..SEARCH_DAYS {
            if self.months & (1 << date.month()) != 0 && self.day_matches(date) {
                if let Some(at) = self.first_on(tz, date, after) {
                    return Some(at);
                }
            }
            date = date.tomorrow().ok()?;
        }
        None
    }

    /// The first fire time on local `date` after `after`, if any. First
    /// occurrences grow with local time, so the first match is the least.
    fn first_on(&self, tz: &TimeZone, date: Date, after: i64) -> Option<i64> {
        for hour in 0..24i8 {
            if self.hours & (1 << hour) == 0 {
                continue;
            }
            for minute in 0..60i8 {
                if self.minutes & (1 << minute) == 0 {
                    continue;
                }
                let local =
                    DateTime::new(date.year(), date.month(), date.day(), hour, minute, 0, 0)
                        .ok()?;
                match first_occurrence(tz, local) {
                    Some(at) if at > after => return Some(at),
                    _ => {}
                }
            }
        }
        None
    }

    /// Whether `at` is a fire time (the reference `cron_fires`).
    #[cfg(test)]
    pub fn fires_at(&self, tz: &TimeZone, at: i64) -> bool {
        at % 60 == 0 && self.next_after(tz, at - 1) == Some(at)
    }

    /// Fire times in `(from, to]`, at most `limit` of them, plus how many
    /// there were in all (counted up to `count_limit`).
    pub fn fire_times(
        &self,
        tz: &TimeZone,
        from: i64,
        to: i64,
        limit: usize,
        count_limit: u32,
    ) -> (Vec<i64>, u32) {
        let mut out = Vec::new();
        let mut count = 0u32;
        let mut cursor = from;
        while count < count_limit {
            let Some(next) = self.next_after(tz, cursor) else {
                break;
            };
            if next > to {
                break;
            }
            if out.len() < limit {
                out.push(next);
            }
            count += 1;
            cursor = next;
        }
        (out, count)
    }
}

/// The instant of local wall time `local`: `None` in a gap, the earlier
/// instant when it is ambiguous.
fn first_occurrence(tz: &TimeZone, local: DateTime) -> Option<i64> {
    let ambiguous = tz.to_ambiguous_timestamp(local);
    match ambiguous.offset() {
        AmbiguousOffset::Unambiguous { .. } | AmbiguousOffset::Fold { .. } => ambiguous
            .compatible()
            .ok()
            .map(|timestamp| timestamp.as_second()),
        AmbiguousOffset::Gap { .. } => None,
    }
}

/// The job's timezone from the bundled tz database (`UTC` included).
pub fn timezone(name: &str) -> Option<TimeZone> {
    if name == "UTC" {
        return Some(TimeZone::UTC);
    }
    jiff::tz::db().get(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> i64 {
        text.parse::<Timestamp>().unwrap().as_second()
    }

    fn show(seconds: i64) -> String {
        Timestamp::from_second(seconds).unwrap().to_string()
    }

    #[test]
    fn the_grammar_is_section_14_9() {
        for ok in [
            "* * * * *",
            "*/15 0-6 1,15 * 1-5",
            "0 3 * * 7",
            "5/10 * * * *",
        ] {
            assert!(CronExpr::parse(ok).is_some(), "{ok}");
        }
        for bad in [
            "60 * * * *",
            "* * 0 * *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "MON * * * *",
            "@daily",
            "* * * *",
            "1,,2 * * * *",
        ] {
            assert!(CronExpr::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn next_fire_times_in_utc_do_not_drift() {
        let every_15 = CronExpr::parse("*/15 * * * *").unwrap();
        let tz = timezone("UTC").unwrap();
        let next = every_15
            .next_after(&tz, at("2026-09-23T10:07:31Z"))
            .unwrap();
        assert_eq!(show(next), "2026-09-23T10:15:00Z");
        assert_eq!(
            show(every_15.next_after(&tz, next).unwrap()),
            "2026-09-23T10:30:00Z"
        );
        let (times, count) = every_15.fire_times(
            &tz,
            at("2026-09-23T10:00:00Z"),
            at("2026-09-23T11:00:00Z"),
            2,
            100,
        );
        assert_eq!(count, 4, "10:15, 10:30, 10:45, 11:00");
        assert_eq!(times.len(), 2);
        assert!(every_15.fires_at(&tz, at("2026-09-23T10:45:00Z")));
        assert!(!every_15.fires_at(&tz, at("2026-09-23T10:46:00Z")));
    }

    #[test]
    fn sunday_is_zero_and_seven_and_restricted_day_fields_match_either() {
        let tz = TimeZone::UTC;
        let sunday = CronExpr::parse("0 4 * * 7").unwrap();
        // 2026-09-23 is a Wednesday; the next Sunday is the 27th.
        assert_eq!(
            show(sunday.next_after(&tz, at("2026-09-23T00:00:00Z")).unwrap()),
            "2026-09-27T04:00:00Z"
        );
        let either = CronExpr::parse("0 0 1 * 1").unwrap();
        // The 28th is a Monday, before October 1st.
        assert_eq!(
            show(either.next_after(&tz, at("2026-09-23T00:00:00Z")).unwrap()),
            "2026-09-28T00:00:00Z"
        );
        let both = CronExpr::parse("0 0 1 * *").unwrap();
        assert_eq!(
            show(both.next_after(&tz, at("2026-09-23T00:00:00Z")).unwrap()),
            "2026-10-01T00:00:00Z"
        );
    }

    #[test]
    fn a_skipped_wall_time_never_fires_and_a_repeated_one_fires_once() {
        let berlin = timezone("Europe/Berlin").unwrap();
        // 2026-03-29: 02:00 CET jumps to 03:00 CEST; 02:30 does not exist.
        let gap = CronExpr::parse("30 2 * * *").unwrap();
        assert_eq!(
            show(gap.next_after(&berlin, at("2026-03-28T12:00:00Z")).unwrap()),
            "2026-03-30T00:30:00Z",
            "the 29th is skipped; the 30th is 02:30 CEST"
        );
        // 2026-10-25: 03:00 CEST falls back to 02:00 CET; 02:30 happens twice.
        let fold = CronExpr::parse("30 2 * * *").unwrap();
        let first = fold
            .next_after(&berlin, at("2026-10-24T12:00:00Z"))
            .unwrap();
        assert_eq!(show(first), "2026-10-25T00:30:00Z", "02:30 CEST, the first");
        assert_eq!(
            show(fold.next_after(&berlin, first).unwrap()),
            "2026-10-26T01:30:00Z",
            "not again at 02:30 CET"
        );
        assert!(!fold.fires_at(&berlin, at("2026-10-25T01:30:00Z")));
        // Every minute across the fold: the repeated hour fires once.
        let minutely = CronExpr::parse("* * * * *").unwrap();
        let (_, count) = minutely.fire_times(
            &berlin,
            at("2026-10-24T23:59:00Z"),
            at("2026-10-25T01:59:00Z"),
            0,
            1_000,
        );
        assert_eq!(count, 60, "02:00-02:59 local fire once, not twice");
    }

    #[test]
    fn timezones_come_from_the_bundled_database() {
        assert!(timezone("America/New_York").is_some());
        assert!(timezone("UTC").is_some());
        assert!(timezone("Mars/Olympus").is_none());
        let new_york = timezone("America/New_York").unwrap();
        let daily = CronExpr::parse("0 9 * * *").unwrap();
        assert_eq!(
            show(
                daily
                    .next_after(&new_york, at("2026-09-23T00:00:00Z"))
                    .unwrap()
            ),
            "2026-09-23T13:00:00Z"
        );
        let never = CronExpr::parse("0 0 31 2 *").unwrap();
        assert_eq!(never.next_after(&new_york, 0), None);
    }
}
