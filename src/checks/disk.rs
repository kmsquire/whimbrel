//! How full a disk is, against WARN and FAIL thresholds, and what's biggest when it's full.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::check::{At, Check, Finding, Kind, sentence_case};
use crate::config::from_table;
use crate::process;
use crate::sentence::{and_list, shown};

/// A disk's use, by `df -P -k`: the same number a person sees with `df`.
///
/// ```toml
/// [[check]]
/// kind = "disk"
/// path = "/"
/// suspects = ["/var/log", "/tmp"]
/// ```
#[derive(Debug, Deserialize)]
#[serde(try_from = "DiskTable")]
pub struct Disk {
    /// Any path on the volume to watch. On a Mac, `/System/Volumes/Data`, not `/`.
    pub path: String,
    pub thresholds: Thresholds,
    /// Where to look for what's big. The three biggest folders one level under these are named.
    /// That's folders only, since `du -d 1` sizes no loose files, and a suspect inside another
    /// is counted in both.
    pub suspects: Vec<String>,
    /// Found on PATH unless config says where.
    pub df: PathBuf,
    pub du: PathBuf,
    pub timeout: Duration,
}

/// WARN at `warn`% and FAIL at `fail`%, with `warn` under `fail` and `fail` at most 100.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thresholds {
    warn: u8,
    fail: u8,
}

impl Thresholds {
    pub fn new(warn: u8, fail: u8) -> Result<Self, String> {
        if warn < fail && fail <= 100 {
            Ok(Thresholds { warn, fail })
        } else {
            Err("warn must be under fail, and fail at most 100".into())
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds { warn: 80, fail: 90 }
    }
}

/// The table as written, before its thresholds are checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskTable {
    path: String,
    #[serde(default = "warn")]
    warn: u8,
    #[serde(default = "fail")]
    fail: u8,
    #[serde(default)]
    suspects: Vec<String>,
    #[serde(default = "df")]
    df: PathBuf,
    #[serde(default = "du")]
    du: PathBuf,
}

fn warn() -> u8 {
    Thresholds::default().warn
}
fn fail() -> u8 {
    Thresholds::default().fail
}
fn df() -> PathBuf {
    "df".into()
}
fn du() -> PathBuf {
    "du".into()
}

impl TryFrom<DiskTable> for Disk {
    type Error = String;

    fn try_from(t: DiskTable) -> Result<Self, String> {
        Ok(Disk {
            path: t.path,
            thresholds: Thresholds::new(t.warn, t.fail)?,
            suspects: t.suspects,
            df: t.df,
            du: t.du,
            timeout: Duration::from_secs(120),
        })
    }
}

impl Disk {
    /// The defaults: 80% and 90%, `df` and `du` from PATH, no suspects.
    pub fn new(path: impl Into<String>) -> Self {
        Disk {
            path: path.into(),
            thresholds: Thresholds::default(),
            suspects: Vec::new(),
            df: df(),
            du: du(),
            timeout: Duration::from_secs(120),
        }
    }

    fn percent(&self) -> Option<u8> {
        let out =
            process::run(&self.df, &["-P", "-k", "--", &self.path], b"", self.timeout).ok()?;
        if !out.status.success() {
            return None;
        }
        parse_df(&String::from_utf8_lossy(&out.stdout))
    }

    /// Each suspect's folders, one level down, by size.
    fn sizes(&self) -> Vec<(u64, String)> {
        let mut rows = Vec::new();
        for suspect in &self.suspects {
            let Ok(out) = process::run(
                &self.du,
                &["-x", "-k", "-d", "1", "--", suspect],
                b"",
                self.timeout,
            ) else {
                continue;
            };
            // du exits 1 when it couldn't read part of the tree, and still sizes the rest.
            rows.extend(
                parse_du(&String::from_utf8_lossy(&out.stdout))
                    .into_iter()
                    .filter(|(_, path)| {
                        path.trim_end_matches('/') != suspect.trim_end_matches('/')
                    }),
            );
        }
        rows
    }
}

/// `disk`, keyed `disk` and recovering as "the disk" unless its table says otherwise.
pub const KIND: Kind = Kind {
    name: "disk",
    key: "disk",
    about: "the disk",
    build: |table, _| Ok(Box::new(from_table::<Disk>(table)?)),
};

impl Check for Disk {
    fn run(&self, at: &At) -> Finding {
        assess(
            at.host,
            &self.path,
            self.thresholds,
            self.percent(),
            !self.suspects.is_empty(),
            || self.sizes(),
        )
    }
}

/// What `pct` means for the disk at `path`, with the biggest folders when it's over. `sizes` is
/// only asked for then, since sizing is slow.
fn assess(
    host: &str,
    path: &str,
    t: Thresholds,
    pct: Option<u8>,
    has_suspects: bool,
    sizes: impl FnOnce() -> Vec<(u64, String)>,
) -> Finding {
    // As given mid-sentence, capitalized to start one.
    let (on, host) = (host, sentence_case(host));
    let Some(pct) = pct else {
        return Finding::warn()
            .says(format!(
                "{host}'s watch couldn't tell how full its disk is."
            ))
            .see(format!("df -h {path}"));
    };
    if pct < t.warn {
        return Finding::ok();
    }
    // No fingerprint: 85% to 86% isn't news.
    let finding = if pct >= t.fail {
        Finding::fail()
    } else {
        Finding::warn()
    }
    .says(format!("{host}'s disk is {pct}% full."))
    .see(format!("df -h {path}"));
    if !has_suspects {
        return finding;
    }
    match biggest(sizes()) {
        Some(rows) => finding.details(format!("Biggest folders on {on}: {rows}.")),
        None => finding.details(format!("Biggest folders on {on}: couldn't size them.")),
    }
}

/// "/var/log 3 GB, /tmp 512 MB and /var/lib/x 40 MB", or `None` if nothing could be sized.
fn biggest(mut rows: Vec<(u64, String)>) -> Option<String> {
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let named: Vec<String> = rows
        .iter()
        .take(3)
        .map(|(kb, path)| format!("{} {}", shown(path, "folder"), size(*kb)))
        .collect();
    (!named.is_empty()).then(|| and_list(&named))
}

/// The Capacity column of `df -P`'s one data row. Filesystem and mount names can hold spaces, so
/// it's the field ending in `%`, not a fixed column.
fn parse_df(out: &str) -> Option<u8> {
    let row = out.lines().nth(1)?;
    row.split_whitespace()
        .find_map(|f| f.strip_suffix('%'))
        .and_then(|p| p.parse::<u8>().ok())
        .filter(|&p| p <= 100)
}

/// `du -k`'s rows: kilobytes, a tab, the path.
fn parse_du(out: &str) -> Vec<(u64, String)> {
    out.lines()
        .filter_map(|line| {
            let (kb, path) = line.split_once('\t')?;
            Some((kb.trim().parse().ok()?, path.to_string()))
        })
        .collect()
}

/// Whole megabytes, or whole gigabytes once it rounds to 1024 MB or more.
fn size(kb: u64) -> String {
    const MB: u64 = 1024;
    const GB: u64 = 1024 * 1024;
    let mb = (kb + MB / 2) / MB;
    if mb >= 1024 {
        format!("{} GB", (kb + GB / 2) / GB)
    } else {
        format!("{mb} MB")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1024 * 1024;

    fn at(pct: Option<u8>) -> Finding {
        assess(
            "the test host",
            "/",
            Thresholds::default(),
            pct,
            false,
            Vec::new,
        )
    }

    #[test]
    fn under_80_percent_is_ok_with_no_sentence() {
        assert_eq!(at(Some(79)), Finding::ok());
    }

    #[test]
    fn at_80_percent_it_is_warn() {
        assert_eq!(
            at(Some(80)),
            Finding::warn()
                .says("The test host's disk is 80% full.")
                .see("df -h /")
        );
    }

    #[test]
    fn at_90_percent_it_is_fail() {
        assert_eq!(at(Some(89)).level, crate::Level::Warn);
        assert_eq!(
            at(Some(90)),
            Finding::fail()
                .says("The test host's disk is 90% full.")
                .see("df -h /")
        );
    }

    #[test]
    fn a_disk_that_cant_be_read_is_warn_never_ok() {
        assert_eq!(
            at(None),
            Finding::warn()
                .says("The test host's watch couldn't tell how full its disk is.")
                .see("df -h /")
        );
    }

    #[test]
    fn the_thresholds_come_from_config() {
        let t = Thresholds::new(60, 70).unwrap();
        let f = assess("h", "/", t, Some(70), false, Vec::new);
        assert_eq!(f.level, crate::Level::Fail);
    }

    #[test]
    fn thresholds_out_of_order_or_over_100_are_refused() {
        assert!(Thresholds::new(90, 80).is_err());
        assert!(Thresholds::new(80, 80).is_err());
        assert!(Thresholds::new(80, 101).is_err());
        assert!(Thresholds::new(99, 100).is_ok());
    }

    #[test]
    fn a_full_disk_names_the_three_biggest_folders() {
        let rows = vec![
            (30 * GB, "/var/log/journal".to_string()),
            (2 * GB, "/var/log/syslog.d".to_string()),
            (5 * GB, "/tmp/crashes".to_string()),
            (1024, "/tmp/small".to_string()),
        ];
        let f = assess("h", "/", Thresholds::default(), Some(92), true, || rows);
        assert_eq!(
            f.details.as_deref(),
            Some(
                "Biggest folders on h: /var/log/journal 30 GB, /tmp/crashes 5 GB and /var/log/syslog.d 2 GB."
            )
        );
    }

    #[test]
    fn folders_that_cant_be_sized_say_so_rather_than_nothing() {
        let f = assess("h", "/", Thresholds::default(), Some(92), true, Vec::new);
        assert_eq!(
            f.details.as_deref(),
            Some("Biggest folders on h: couldn't size them.")
        );
    }

    #[test]
    fn under_the_threshold_nothing_is_sized() {
        let f = assess("h", "/", Thresholds::default(), Some(10), true, || {
            panic!("sized an OK disk")
        });
        assert_eq!(f, Finding::ok());
    }

    #[test]
    fn df_capacity_is_found_whatever_the_names_hold() {
        let out = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                   /dev/disk1s1s1   244810132 9127640  70845028    12%    /\n";
        assert_eq!(parse_df(out), Some(12));
        let spaced = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                      map auto_home 0 0 0 100% /System/Volumes/Data/home dir\n";
        assert_eq!(parse_df(spaced), Some(100));
        assert_eq!(parse_df("Filesystem\n"), None);
        assert_eq!(parse_df("h\n/dev/x 1 1 1 120% /\n"), None);
    }

    #[test]
    fn sizes_are_whole_gigabytes_or_megabytes() {
        assert_eq!(size(30 * GB), "30 GB");
        assert_eq!(size(GB - 1), "1 GB");
        assert_eq!(size(GB - 600), "1023 MB");
        assert_eq!(size(512), "1 MB");
        assert_eq!(size(4 * 1024), "4 MB");
    }
}
