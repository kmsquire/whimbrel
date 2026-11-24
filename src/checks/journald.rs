//! Units journald dropped lines from in the last hour: its rate limit, hit when something logs in
//! a loop.
//!
//! ```toml
//! [[check]]
//! kind = "journald-drops"
//! units = '^(nginx|app@.*)\.service$'
//! ```
//!
//! journald says what it dropped in notices of its own, under one catalog id. Each names the unit
//! at the end of its message, as the unit's control group path:
//! `Suppressed 1200 messages from /system.slice/app.service`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;

use crate::check::{At, Check, Finding, Kind, Shared, sentence_case};
use crate::config::from_table;
use crate::process;
use crate::sentence::{and_list, shown};

/// systemd's catalog entry "Messages from a service have been suppressed".
pub const DROPPED_ID: &str = "a596d6fe7bfa4994828e72309e95d61e";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    units: Option<String>,
    #[serde(default = "journalctl")]
    journalctl: PathBuf,
    #[serde(default = "secs")]
    timeout_secs: u64,
}

fn journalctl() -> PathBuf {
    "journalctl".into()
}
fn secs() -> u64 {
    120
}

pub struct JournaldDrops {
    units: Option<Regex>,
    journalctl: PathBuf,
    timeout: Duration,
}

/// `journald-drops`, keyed `journald-drops` and recovering as "the journal's dropped lines" unless
/// its table says otherwise.
pub const KIND: Kind = Kind {
    name: "journald-drops",
    key: "journald-drops",
    about: "the journal's dropped lines",
    build,
};

fn build(table: toml::Table, _: &Shared) -> Result<Box<dyn Check>, String> {
    let t: Table = from_table(table)?;
    let units = match t.units {
        Some(p) => Some(Regex::new(&p).map_err(|_| "units isn't a pattern whimbrel can use")?),
        None => None,
    };
    Ok(Box::new(JournaldDrops {
        units,
        journalctl: t.journalctl,
        timeout: process::timeout_secs("timeout_secs", t.timeout_secs)?,
    }))
}

impl Check for JournaldDrops {
    /// WARN naming each unit journald dropped lines from in the last hour. The units are the
    /// fingerprint, not the counts, so a loop that goes on is said once, not every hour.
    fn run(&self, at: &At) -> Finding {
        let id = format!("MESSAGE_ID={DROPPED_ID}");
        let all = format!("journalctl {id} --since -1h");
        let args = ["-q", "--no-pager", "-o", "json", "--since", "-1h", &id];
        let out = match process::run(&self.journalctl, &args, b"", self.timeout) {
            Ok(done) if done.status.success() => done.stdout,
            _ => {
                return Finding::warn()
                    .says(format!(
                        "{}'s watch couldn't read journald's dropped-message notices.",
                        sentence_case(at.host)
                    ))
                    .see(all);
            }
        };
        let dropped: BTreeMap<String, u64> = dropped(&String::from_utf8_lossy(&out))
            .into_iter()
            .filter(|(unit, _)| self.units.as_ref().is_none_or(|re| re.is_match(unit)))
            .collect();
        if dropped.is_empty() {
            return Finding::ok();
        }
        // A notice is anyone's to log, so a unit's name is shown only if it's plain, and units
        // with names it can't show are counted together.
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for (unit, n) in &dropped {
            let c: &mut u64 = counts.entry(shown(unit, "unit")).or_insert(0);
            *c = c.saturating_add(*n);
        }
        let unusual = shown("", "unit");
        let said: Vec<String> = counts
            .iter()
            .map(|(unit, n)| format!("{n} lines from {unit}"))
            .collect();
        let plain: Vec<&String> = counts.keys().filter(|u| **u != unusual).collect();
        let see = if counts.contains_key(&unusual) {
            all
        } else {
            let flags: Vec<String> = plain.iter().map(|u| format!("-u {u}")).collect();
            format!("journalctl {} --since -1h", flags.join(" "))
        };
        let fingerprint: Vec<&str> = counts.keys().map(String::as_str).collect();
        Finding::warn()
            .says(format!(
                "{}'s journal dropped {} in the last hour, so something there is logging in a \
                 loop.",
                sentence_case(at.host),
                and_list(&said)
            ))
            .see(see)
            .fingerprint(fingerprint.join(","))
    }
}

/// Lines dropped per unit, from journald's notices as `-o json` lines. A line that isn't one, or
/// names no unit, is passed over; a count that isn't a number counts as none.
fn dropped(json_lines: &str) -> BTreeMap<String, u64> {
    let mut dropped = BTreeMap::new();
    for line in json_lines.lines() {
        let Ok(serde_json::Value::Object(notice)) = serde_json::from_str(line) else {
            continue;
        };
        let Some(serde_json::Value::String(message)) = notice.get("MESSAGE") else {
            continue;
        };
        let Some((_, from)) = message.split_once(" messages from ") else {
            continue;
        };
        let unit = from.trim_end().rsplit('/').next().unwrap_or("");
        if unit.is_empty() {
            continue;
        }
        let n = match notice.get("N_DROPPED") {
            Some(serde_json::Value::String(s)) => s.parse().unwrap_or(0),
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
            _ => 0,
        };
        let d: &mut u64 = dropped.entry(unit.to_string()).or_insert(0);
        *d = d.saturating_add(n);
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_is_the_last_part_of_the_notices_path() {
        let lines = [
            r#"{"MESSAGE": "Suppressed 40 messages from /system.slice/app.service", "N_DROPPED": "40"}"#,
            r#"{"MESSAGE": "Suppressed 2 messages from /system.slice/system-app.slice/app@a.service", "N_DROPPED": 2}"#,
            r#"{"MESSAGE": "Suppressed 1 messages from nginx.service", "N_DROPPED": "1"}"#,
            r#"{"MESSAGE": "Suppressed 1 messages from /", "N_DROPPED": "1"}"#,
        ]
        .join("\n");
        let got = dropped(&lines);
        let want: BTreeMap<String, u64> = [
            ("app.service", 40),
            ("app@a.service", 2),
            ("nginx.service", 1),
        ]
        .into_iter()
        .map(|(u, n)| (u.to_string(), n))
        .collect();
        assert_eq!(got, want);
    }
}
