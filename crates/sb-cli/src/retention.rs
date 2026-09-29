//! Which artifacts a retention policy lets go of.
//!
//! This is the whole decision `storage prune` makes, kept apart from the part
//! that talks to the storage target: [`expired`] takes what was listed and says
//! what has to go, and never looks at what is inside an artifact. That is what
//! keeps the core agnostic -- "how long is an artifact kept" is a question about
//! `ArtifactMeta.modified_at` and nothing else -- and it is also what makes the
//! decision testable without a plugin, a socket or a clock.
//!
//! Every rule here leans the same way, because the only irreversible thing
//! `prune` does is delete: **when in doubt, keep**. An artifact whose age is not
//! known is never expired, and a GFS policy always keeps the newest artifact of
//! every period it counts.

use sb_config::{GfsRetention, Retention};
use sb_proto::ArtifactMeta;
use time::{Date, Month, OffsetDateTime};

/// The artifacts in `artifacts` that `retention` no longer keeps, in the order
/// they were listed.
///
/// `now` is a parameter, not read from the clock, so a test can say what day it
/// is.
#[must_use]
pub fn expired(
    retention: Retention,
    artifacts: &[ArtifactMeta],
    now: OffsetDateTime,
) -> Vec<&ArtifactMeta> {
    match retention {
        Retention::Days(days) => {
            let cutoff = cutoff_timestamp(now, days);
            artifacts
                .iter()
                .filter(|artifact| is_expired(artifact, &cutoff))
                .collect()
        }
        Retention::Gfs(gfs) => expired_gfs(artifacts, gfs),
    }
}

/// Whether `artifact` is older than `cutoff`.
///
/// Both are the same fixed-width `YYYY-MM-DDTHH:MM:SSZ` shape, always UTC, so
/// comparing them as strings agrees with comparing them as instants -- the
/// same property `sb-plugin-r2::admin` relies on to keep two storage targets'
/// timestamps sortable against each other. An artifact whose storage target
/// did not report `modified_at` is left alone: an unknown age is not the same
/// as an old one, and deleting on a guess is the one mistake `prune` cannot
/// recover from.
fn is_expired(artifact: &ArtifactMeta, cutoff: &str) -> bool {
    !artifact.modified_at.is_empty() && artifact.modified_at.as_str() < cutoff
}

/// The `modified_at` cutoff: `now` minus `days`, in the same shape the storage
/// targets report. Built from a Unix timestamp, the same way
/// [`sb_core::naming`] builds `{timestamp}`, rather than through `Duration`
/// subtraction: a `u32` count of days that overflows the representable range
/// falls back to the epoch, which prunes everything instead of panicking mid
/// backup-maintenance run.
fn cutoff_timestamp(now: OffsetDateTime, days: u32) -> String {
    let seconds = i64::from(days).saturating_mul(86_400);
    let cutoff = OffsetDateTime::from_unix_timestamp(now.unix_timestamp().saturating_sub(seconds))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        cutoff.year(),
        u8::from(cutoff.month()),
        cutoff.day(),
        cutoff.hour(),
        cutoff.minute(),
        cutoff.second()
    )
}

/// The artifacts a grandfather-father-son policy does not keep.
///
/// One pass per kind of period over the artifacts newest first: the first
/// artifact seen in a period is that period's newest, so it is the one kept, and
/// the pass stops after `keep_*` periods. What one pass keeps is kept for good,
/// which is why a policy is the union of its periods and never their
/// intersection -- an artifact that is the newest of its month stays even when
/// its day has aged out of `keep_daily`.
///
/// Periods are counted **among the artifacts that exist**, not on the calendar:
/// `keep_daily = 7` keeps the newest artifact of the last seven days that have
/// one. A week without backups (an outage, a paused job) must not eat into the
/// history that is left, which is the moment history matters most.
fn expired_gfs(artifacts: &[ArtifactMeta], gfs: GfsRetention) -> Vec<&ArtifactMeta> {
    // Only what has a readable date takes part; the rest is never expired.
    let mut dated: Vec<(usize, Date)> = artifacts
        .iter()
        .enumerate()
        .filter_map(|(index, artifact)| Some((index, date_of(&artifact.modified_at)?)))
        .collect();
    // Newest first. The timestamps sort as strings (see [`is_expired`]); the key
    // breaks ties so the same listing always gives the same answer.
    dated.sort_by(|(a, _), (b, _)| {
        artifacts[*b]
            .modified_at
            .cmp(&artifacts[*a].modified_at)
            .then_with(|| artifacts[*b].key.cmp(&artifacts[*a].key))
    });

    let mut keep = vec![false; artifacts.len()];
    mark_newest_per_period(&dated, gfs.keep_daily, day_of, &mut keep);
    mark_newest_per_period(&dated, gfs.keep_weekly, week_of, &mut keep);
    mark_newest_per_period(&dated, gfs.keep_monthly, month_of, &mut keep);
    mark_newest_per_period(&dated, gfs.keep_yearly, year_of, &mut keep);

    let dated_indexes: std::collections::HashSet<usize> =
        dated.iter().map(|(index, _)| *index).collect();
    artifacts
        .iter()
        .enumerate()
        .filter(|(index, _)| dated_indexes.contains(index) && !keep[*index])
        .map(|(_, artifact)| artifact)
        .collect()
}

/// Marks the first artifact of each of the first `periods` distinct periods in
/// `newest_first`.
fn mark_newest_per_period(
    newest_first: &[(usize, Date)],
    periods: u32,
    period_of: fn(Date) -> (i32, u16),
    keep: &mut [bool],
) {
    let mut current = None;
    let mut counted = 0_u32;
    for &(index, date) in newest_first {
        let period = period_of(date);
        if current == Some(period) {
            continue;
        }
        if counted == periods {
            return;
        }
        current = Some(period);
        keep[index] = true;
        counted += 1;
    }
}

fn day_of(date: Date) -> (i32, u16) {
    (date.year(), date.ordinal())
}

/// ISO weeks, so a week never straddles two `keep_weekly` periods just because
/// the calendar year turned in the middle of it.
fn week_of(date: Date) -> (i32, u16) {
    let (year, week, _) = date.to_iso_week_date();
    (year, u16::from(week))
}

fn month_of(date: Date) -> (i32, u16) {
    (date.year(), u16::from(u8::from(date.month())))
}

fn year_of(date: Date) -> (i32, u16) {
    (date.year(), 0)
}

/// The calendar date of a `YYYY-MM-DDTHH:MM:SSZ` timestamp, or `None` for
/// anything else -- an empty one included. Anything that cannot be read is an
/// age that is not known, and an unknown age is never expired.
fn date_of(timestamp: &str) -> Option<Date> {
    if timestamp.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    let mut parts = timestamp.get(..10)?.split('-');
    let year = parts.next()?.parse().ok()?;
    let month = Month::try_from(parts.next()?.parse::<u8>().ok()?).ok()?;
    let day = parts.next()?.parse().ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(key: &str, modified_at: &str) -> ArtifactMeta {
        ArtifactMeta {
            key: key.into(),
            size: 0,
            modified_at: modified_at.into(),
        }
    }

    /// One artifact per timestamp, keyed by it.
    fn at(timestamps: &[&str]) -> Vec<ArtifactMeta> {
        timestamps.iter().map(|t| artifact(t, t)).collect()
    }

    fn keys<'a>(expired: &[&'a ArtifactMeta]) -> Vec<&'a str> {
        expired.iter().map(|a| a.key.as_str()).collect()
    }

    fn gfs(daily: u32, weekly: u32, monthly: u32, yearly: u32) -> Retention {
        Retention::Gfs(GfsRetention {
            keep_daily: daily,
            keep_weekly: weekly,
            keep_monthly: monthly,
            keep_yearly: yearly,
        })
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_768_000_000).unwrap()
    }

    // --- retention_days -----------------------------------------------------

    #[test]
    fn an_artifact_older_than_the_cutoff_is_expired() {
        assert!(is_expired(
            &artifact("a", "2026-01-01T00:00:00Z"),
            "2026-01-05T00:00:00Z"
        ));
    }

    #[test]
    fn an_artifact_newer_than_the_cutoff_is_kept() {
        assert!(!is_expired(
            &artifact("a", "2026-01-10T00:00:00Z"),
            "2026-01-05T00:00:00Z"
        ));
    }

    #[test]
    fn an_artifact_without_a_reported_age_is_never_guessed_at() {
        // Deleting on a guess is the one mistake `prune` cannot take back.
        assert!(!is_expired(&artifact("a", ""), "2026-01-05T00:00:00Z"));
    }

    #[test]
    fn the_cutoff_is_five_days_before_now() {
        let cutoff = cutoff_timestamp(now(), 5);
        let expected = OffsetDateTime::from_unix_timestamp(1_768_000_000 - 5 * 86_400).unwrap();
        assert_eq!(
            cutoff,
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                expected.year(),
                u8::from(expected.month()),
                expected.day(),
                expected.hour(),
                expected.minute(),
                expected.second()
            )
        );
    }

    #[test]
    fn a_retention_that_would_overflow_falls_back_to_the_epoch_instead_of_panicking() {
        assert_eq!(
            cutoff_timestamp(OffsetDateTime::now_utc(), u32::MAX),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn days_expires_what_is_older_than_the_cutoff_and_nothing_else() {
        let artifacts = vec![
            artifact("old", "2000-01-01T00:00:00Z"),
            artifact("unknown", ""),
            artifact("new", "2999-01-01T00:00:00Z"),
        ];
        assert_eq!(
            keys(&expired(Retention::Days(30), &artifacts, now())),
            ["old"]
        );
    }

    // --- GFS ----------------------------------------------------------------

    #[test]
    fn daily_keeps_the_newest_artifact_of_each_recent_day() {
        let artifacts = at(&[
            "2026-03-01T02:00:00Z",
            "2026-03-02T02:00:00Z",
            "2026-03-03T02:00:00Z",
        ]);
        assert_eq!(
            keys(&expired(gfs(2, 0, 0, 0), &artifacts, now())),
            ["2026-03-01T02:00:00Z"]
        );
    }

    #[test]
    fn two_artifacts_on_the_same_day_count_once_and_the_newer_wins() {
        let artifacts = at(&[
            "2026-03-03T02:00:00Z",
            "2026-03-03T14:00:00Z",
            "2026-03-02T02:00:00Z",
        ]);
        assert_eq!(
            keys(&expired(gfs(1, 0, 0, 0), &artifacts, now())),
            ["2026-03-03T02:00:00Z", "2026-03-02T02:00:00Z"]
        );
    }

    #[test]
    fn periods_are_counted_among_the_days_that_have_a_backup_not_on_the_calendar() {
        // A gap in the schedule must not eat the history that is left.
        let artifacts = at(&[
            "2026-01-01T02:00:00Z",
            "2026-01-10T02:00:00Z",
            "2026-01-20T02:00:00Z",
        ]);
        assert_eq!(
            keys(&expired(gfs(2, 0, 0, 0), &artifacts, now())),
            ["2026-01-01T02:00:00Z"]
        );
    }

    #[test]
    fn weekly_uses_iso_weeks_across_the_new_year() {
        // 2026-12-31 (Thu) and 2027-01-01 (Fri) are both in ISO week 53 of
        // 2026: one week, although the calendar year changed inside it.
        let artifacts = at(&["2026-12-31T02:00:00Z", "2027-01-01T02:00:00Z"]);
        assert_eq!(
            keys(&expired(gfs(0, 1, 0, 0), &artifacts, now())),
            ["2026-12-31T02:00:00Z"]
        );
    }

    #[test]
    fn monthly_keeps_the_newest_artifact_of_each_recent_month() {
        let artifacts = at(&[
            "2026-01-05T02:00:00Z",
            "2026-01-28T02:00:00Z",
            "2026-02-10T02:00:00Z",
            "2026-03-15T02:00:00Z",
        ]);
        assert_eq!(
            keys(&expired(gfs(0, 0, 2, 0), &artifacts, now())),
            ["2026-01-05T02:00:00Z", "2026-01-28T02:00:00Z"]
        );
    }

    #[test]
    fn yearly_keeps_the_newest_artifact_of_each_recent_year() {
        let artifacts = at(&[
            "2024-06-01T02:00:00Z",
            "2024-12-31T02:00:00Z",
            "2025-06-01T02:00:00Z",
            "2026-06-01T02:00:00Z",
        ]);
        assert_eq!(
            keys(&expired(gfs(0, 0, 0, 2), &artifacts, now())),
            ["2024-06-01T02:00:00Z", "2024-12-31T02:00:00Z"]
        );
    }

    #[test]
    fn an_artifact_kept_by_any_period_is_kept() {
        // 2026-01-31 has aged out of `keep_daily = 1` but is the newest of its
        // month, so `keep_monthly` holds on to it.
        let artifacts = at(&[
            "2026-01-10T02:00:00Z",
            "2026-01-31T02:00:00Z",
            "2026-02-20T02:00:00Z",
        ]);
        assert_eq!(
            keys(&expired(gfs(1, 0, 2, 0), &artifacts, now())),
            ["2026-01-10T02:00:00Z"]
        );
    }

    #[test]
    fn the_order_of_the_listing_does_not_change_the_answer() {
        let mut artifacts = at(&[
            "2026-03-03T14:00:00Z",
            "2026-03-03T02:00:00Z",
            "2026-03-02T02:00:00Z",
            "2026-02-01T02:00:00Z",
        ]);
        let mut forward = keys(&expired(gfs(1, 0, 1, 0), &artifacts, now()))
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        artifacts.reverse();
        let mut backward = keys(&expired(gfs(1, 0, 1, 0), &artifacts, now()))
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        forward.sort();
        backward.sort();
        assert_eq!(forward, backward);
    }

    #[test]
    fn an_artifact_whose_age_cannot_be_read_is_never_expired() {
        let artifacts = vec![
            artifact("empty", ""),
            artifact("garbage", "yesterday"),
            artifact("not-a-day", "2026-13-40T00:00:00Z"),
            artifact("no-time", "2026-03-01"),
            artifact("old", "2000-01-01T00:00:00Z"),
            artifact("new", "2026-03-01T00:00:00Z"),
        ];
        assert_eq!(keys(&expired(gfs(1, 0, 0, 0), &artifacts, now())), ["old"]);
    }

    #[test]
    fn a_schedule_never_keeps_more_than_it_asks_for_and_never_loses_the_newest() {
        // A year of daily backups against several policies.
        let start = Date::from_calendar_date(2025, Month::January, 1).unwrap();
        let artifacts: Vec<ArtifactMeta> = (0..400)
            .map(|offset| {
                let day = start + time::Duration::days(offset);
                let stamp = format!(
                    "{:04}-{:02}-{:02}T02:00:00Z",
                    day.year(),
                    u8::from(day.month()),
                    day.day()
                );
                artifact(&stamp, &stamp)
            })
            .collect();
        let newest = artifacts.last().unwrap().key.clone();

        for (d, w, m, y) in [(7, 4, 12, 3), (1, 0, 0, 0), (0, 0, 0, 1), (30, 0, 0, 0)] {
            let gone = expired(gfs(d, w, m, y), &artifacts, now());
            let kept = artifacts.len() - gone.len();
            assert!(kept >= 1, "policy {d}/{w}/{m}/{y} kept nothing");
            assert!(
                usize::try_from(d + w + m + y).unwrap() >= kept,
                "policy {d}/{w}/{m}/{y} kept {kept}, more than the sum of its buckets"
            );
            assert!(
                gone.iter().all(|a| a.key != newest),
                "policy {d}/{w}/{m}/{y} expired the newest artifact"
            );
        }
    }
}
