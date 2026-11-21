//! Time intervals in OpenSSH's formats.

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;

/// Parse a time interval like `sshd_config(5)` and `ssh-add -t`: a sequence
/// of numbers, each optionally followed by a unit (`s`, `m`, `h`, `d`, `w`,
/// case-insensitive), summed up. A number without a unit is seconds, so
/// `90`, `1m30` and `1m30s` are all 90 seconds.
pub fn parse_interval(text: &str) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits == 0 {
            return None;
        }
        let value: u64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let unit = match rest.chars().next() {
            None => 1,
            Some(c) => {
                rest = &rest[1..];
                match c.to_ascii_lowercase() {
                    's' => 1,
                    'm' => MINUTE,
                    'h' => HOUR,
                    'd' => DAY,
                    'w' => WEEK,
                    _ => return None,
                }
            }
        };
        total = total.checked_add(value.checked_mul(unit)?)?;
    }
    Some(total)
}

/// Format an interval like OpenSSH's `fmt_timeframe`: `HH:MM:SS` below a
/// day, `NdHHhMMm` below a week, `NNwNdHHh` above.
pub fn format_interval(seconds: u64) -> String {
    let (weeks, days) = (seconds / WEEK, seconds % WEEK / DAY);
    let (hours, minutes, secs) = (
        seconds % DAY / HOUR,
        seconds % HOUR / MINUTE,
        seconds % MINUTE,
    );
    if seconds < DAY {
        format!("{hours:02}:{minutes:02}:{secs:02}")
    } else if seconds < WEEK {
        format!("{days}d{hours:02}h{minutes:02}m")
    } else {
        format!("{weeks:02}w{days}d{hours:02}h")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_intervals() {
        assert_eq!(parse_interval("90"), Some(90));
        assert_eq!(parse_interval("1m30"), Some(90));
        assert_eq!(parse_interval("1M30S"), Some(90));
        assert_eq!(
            parse_interval("2d3h4m5s"),
            Some(2 * DAY + 3 * HOUR + 4 * MINUTE + 5)
        );
        assert_eq!(parse_interval("1w"), Some(WEEK));
        assert_eq!(parse_interval("0"), Some(0));
        for bad in ["", "bogus", "1x", "h", "1hh", "-5", "99999999999999999999"] {
            assert_eq!(parse_interval(bad), None, "{bad}");
        }
    }

    #[test]
    fn formats_like_openssh() {
        // Expected values from OpenSSH 10.5 `ssh-add -t`.
        assert_eq!(format_interval(60), "00:01:00");
        assert_eq!(format_interval(90), "00:01:30");
        assert_eq!(format_interval(3 * HOUR), "03:00:00");
        assert_eq!(
            format_interval(2 * DAY + 3 * HOUR + 4 * MINUTE + 5),
            "2d03h04m"
        );
        assert_eq!(format_interval(2 * WEEK + 3 * DAY + 4 * HOUR), "02w3d04h");
    }
}
