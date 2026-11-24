//! A scan of logs and the journal for the host's secret patterns: a count per log, never the
//! match.
//!
//! ```toml
//! [[check]]
//! kind = "secrets"
//! logs = ["/var/log/cloud-init-output.log"]
//! optional_logs = ["/var/log/syslog*"]
//! log_dirs = ["/srv/app/logs"]
//! journal = true
//! ```

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::check::{At, Check, CheckDir, Finding, Kind, Shared, sentence_case};
use crate::config::from_table;
use crate::process::{self, Unfinished};
use crate::secret_patterns::{Matched, SecretPatterns};
use crate::sentence::{and_list, shown};

const COUNTS_ONLY: &str = "Counts only: the watch never copies what it finds.";

/// The most patterns one log's part of the sentence names; the rest are counted.
pub const MAX_NAMED: usize = 3;

/// Lines with a hit, and how many of them each pattern matched. A line two patterns match is one
/// line, and one for each pattern. Kept by name: a built-in's id, or `own N` for the config's Nth
/// pattern, so it can go in the journal's record. Names only, never what matched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Tally {
    lines: u64,
    by: BTreeMap<String, u64>,
}

impl Tally {
    /// Count one line with a hit, matched by `which`.
    fn line(&mut self, which: &[Matched]) {
        self.lines = self.lines.saturating_add(1);
        for m in which {
            let n = self.by.entry(name_of(*m)).or_default();
            *n = n.saturating_add(1);
        }
    }

    fn add(&mut self, other: &Tally) {
        self.lines = self.lines.saturating_add(other.lines);
        for (k, v) in &other.by {
            let n = self.by.entry(k.clone()).or_default();
            *n = n.saturating_add(*v);
        }
    }

    /// For a journal read again from the start of a boot: each count the larger of the two.
    fn most(&mut self, other: &Tally) {
        self.lines = self.lines.max(other.lines);
        for (k, v) in &other.by {
            let n = self.by.entry(k.clone()).or_default();
            *n = (*n).max(*v);
        }
    }

    /// The patterns, most lines first, then by name: a built-in's id in code font, and the
    /// config's own together, never quoted. At most [`MAX_NAMED`], and how many more there are.
    fn named(&self) -> String {
        let mut ids: Vec<(&String, &u64)> = self
            .by
            .iter()
            .filter(|(k, _)| !k.starts_with(OWN))
            .collect();
        ids.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let own = self.by.keys().filter(|k| k.starts_with(OWN)).count();
        let mut parts: Vec<String> = ids.iter().map(|(id, _)| format!("`{id}`")).collect();
        match own {
            0 => {}
            1 => parts.push("one of your own patterns".into()),
            n => parts.push(format!("{n} of your own patterns")),
        }
        if parts.len() > MAX_NAMED {
            let more = parts.len() - MAX_NAMED;
            parts.truncate(MAX_NAMED);
            parts.push(format!("{more} more"));
        }
        and_list(&parts)
    }

    /// Each pattern and its count, for the details: every one, uncapped.
    fn counted(&self) -> String {
        let mut ids: Vec<(&String, &u64)> = self.by.iter().collect();
        ids.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        ids.iter()
            .map(|(k, n)| match k.strip_prefix(OWN) {
                Some(place) => format!("{n} by your own pattern {place}"),
                None => format!("{n} `{k}`"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// How a config's own pattern is kept in a tally: never as itself.
const OWN: &str = "own ";

fn name_of(m: Matched) -> String {
    match m {
        Matched::Builtin(id) => id.to_string(),
        Matched::Own(place) => format!("{OWN}{place}"),
    }
}

/// The longest line matched at once, so a file with no newlines can't take all the memory. A
/// token split across two reads is missed, which a log line never is.
const LINE_MAX: u64 = 1 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    /// Always there, so one that's missing is unscanned, not clean.
    #[serde(default)]
    logs: Vec<PathBuf>,
    /// Scanned if they're there. Their last part may end in `*`: `/var/log/syslog*`.
    #[serde(default)]
    optional_logs: Vec<String>,
    /// Every `*.log` under these, however deep.
    #[serde(default)]
    log_dirs: Vec<PathBuf>,
    #[serde(default = "max_mb")]
    max_mb: u64,
    #[serde(default)]
    journal: bool,
    #[serde(default = "journalctl")]
    journalctl: PathBuf,
    #[serde(default = "journal_secs")]
    journal_secs: u64,
}

fn max_mb() -> u64 {
    200
}
fn journalctl() -> PathBuf {
    "journalctl".into()
}
fn journal_secs() -> u64 {
    600
}

pub struct Secrets {
    patterns: SecretPatterns,
    logs: Vec<PathBuf>,
    optional_logs: Vec<String>,
    log_dirs: Vec<PathBuf>,
    max_mb: u64,
    journal: bool,
    journalctl: PathBuf,
    journal_secs: u64,
}

/// `secrets`, keyed `secrets` and recovering as "the secrets scan" unless its table says
/// otherwise.
pub const KIND: Kind = Kind {
    name: "secrets",
    key: "secrets",
    about: "the secrets scan",
    build,
};

fn build(table: toml::Table, shared: &Shared) -> Result<Box<dyn Check>, String> {
    let t: Table = from_table(table)?;
    if shared.secret_patterns.is_empty() {
        return Err(
            "there are no secret patterns to look for: secret_patterns has its \
                    built-ins off and none of its own"
                .into(),
        );
    }
    if t.logs.is_empty() && t.optional_logs.is_empty() && t.log_dirs.is_empty() && !t.journal {
        return Err("there's nothing to scan: set logs, optional_logs, log_dirs or journal".into());
    }
    let absolute = t.logs.iter().chain(&t.log_dirs).all(|p| p.is_absolute())
        && t.optional_logs.iter().all(|p| Path::new(p).is_absolute());
    if !absolute {
        return Err("every log and log directory must be an absolute path".into());
    }
    process::timeout_secs("journal_secs", t.journal_secs)?;
    Ok(Box::new(Secrets {
        patterns: shared.secret_patterns.clone(),
        logs: t.logs,
        optional_logs: t.optional_logs,
        log_dirs: t.log_dirs,
        max_mb: t.max_mb,
        journal: t.journal,
        journalctl: t.journalctl,
        journal_secs: t.journal_secs,
    }))
}

/// Hits in one rotation group of logs: `syslog`, `syslog.1` and `syslog.2.gz` are one.
struct Group {
    /// As a sentence shows it.
    name: String,
    tally: Tally,
}

/// The journal's record, in the check's own directory.
const RECORD: &str = "journal.json";

/// Where the journal was last read to, and its hits so far. One record, written whole, so the
/// cursor and the total can never disagree: a total lost while the cursor moved on would clear a
/// FAIL with no new hits.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Journal {
    /// None: read this boot from the start, and replace the total rather than add to it.
    cursor: Option<String>,
    total: u64,
    /// Which patterns made the total, by name, and how many lines each.
    by: BTreeMap<String, u64>,
}

impl Journal {
    fn tally(&self) -> Tally {
        Tally {
            lines: self.total,
            by: self.by.clone(),
        }
    }
}

impl Check for Secrets {
    /// FAIL naming each log with a hit and how many, never what matched; WARN for what it
    /// couldn't scan. The fingerprint is the logs with hits and what wasn't scanned, so a FAIL
    /// that comes to say more, a cursor reset say, is news. The total is a count whose rise is
    /// news too: a second leak shouldn't wait a day for the reminder.
    fn run(&self, at: &At) -> Finding {
        let mut groups: BTreeMap<String, Group> = BTreeMap::new();
        let mut unread = Vec::new();
        for path in self.files(&mut unread) {
            match self.scan(&path) {
                Ok(t) if t.lines == 0 => {}
                Ok(t) => {
                    let base = rotation_base(&path);
                    let group = groups
                        .entry(self.patterns.redact(&base.to_string_lossy()))
                        .or_insert(Group {
                            name: self.shown_name(&base),
                            tally: Tally::default(),
                        });
                    group.tally.add(&t);
                }
                Err(label) => unread.push(label),
            }
        }
        let (journal, why) = if self.journal {
            self.journal(&at.state)
        } else {
            (Tally::default(), None)
        };
        unread.extend(why);

        let total = groups
            .values()
            .fold(journal.lines, |sum, g| sum.saturating_add(g.tally.lines));
        if total > 0 {
            let unusual = shown("", "log");
            // Where, as a sentence names it, and what was found there.
            let mut places: Vec<(String, Tally)> = groups
                .values()
                .filter(|g| g.name != unusual)
                .map(|g| (g.name.clone(), g.tally.clone()))
                .collect();
            // Logs it can't name are told apart only by their count, which reads better as one.
            let odd: Vec<&Tally> = groups
                .values()
                .filter(|g| g.name == unusual)
                .map(|g| &g.tally)
                .collect();
            if !odd.is_empty() {
                let mut all = Tally::default();
                odd.iter().for_each(|t| all.add(t));
                let place = match odd.len() {
                    1 => unusual.clone(),
                    n => format!("{n} logs with unusual names"),
                };
                places.push((place, all));
            }
            let mut fingerprint: Vec<String> = groups.keys().cloned().collect();
            if journal.lines > 0 {
                places.push(("the journal".into(), journal.clone()));
                fingerprint.push("journal".into());
            }
            let counts: Vec<String> = places
                .iter()
                .map(|(place, t)| match t.named() {
                    // A record kept before it kept names says only how many.
                    names if names.is_empty() => format!("{} in {place}", t.lines),
                    names => format!("{} in {place} matched {names}", t.lines),
                })
                .collect();
            let details: Vec<String> = places
                .iter()
                .map(|(place, t)| {
                    let lines = match t.lines {
                        1 => "1 line".to_string(),
                        n => format!("{n} lines"),
                    };
                    match t.counted() {
                        by if by.is_empty() => format!("{place}: {lines}."),
                        by => format!("{place}: {lines}, {by}."),
                    }
                })
                .collect();
            let also = if unread.is_empty() {
                String::new()
            } else {
                fingerprint.push(format!("unscanned {}", unread.join(",")));
                format!("; the watch also couldn't scan {}", unread.join(", "))
            };
            return Finding::fail()
                .says(format!(
                    "Something on {} logged a secret, so rotate it and find what logged it: \
                     {}{also}.",
                    at.host,
                    counts.join("; ")
                ))
                .see_dry_run()
                .details(format!("{}\n{COUNTS_ONLY}", details.join("\n")))
                .fingerprint(fingerprint.join(","))
                .count(total);
        }
        if !unread.is_empty() {
            return Finding::warn()
                .says(format!(
                    "{}'s watch couldn't scan some logs for secrets: {}.",
                    sentence_case(at.host),
                    unread.join(", ")
                ))
                .see_dry_run()
                .fingerprint(unread.join(","));
        }
        Finding::ok()
    }
}

impl Secrets {
    /// Every log to scan: `logs`, whether or not they're there, the optional logs that are,
    /// and every `*.log` under the log directories, links and all, which are then refused one by
    /// one. A directory it can't read goes in `unread`.
    fn files(&self, unread: &mut Vec<String>) -> Vec<PathBuf> {
        let mut files = self.logs.clone();
        for pattern in &self.optional_logs {
            match self.glob(pattern) {
                Ok(found) => files.extend(found),
                Err(label) => unread.push(label),
            }
        }
        for dir in &self.log_dirs {
            self.walk(dir, &mut files, unread);
        }
        files
    }

    /// Lines with a hit in one log, or how to say it couldn't be scanned. Regular files only, and
    /// never through a link: a FIFO named `*.log` would block for good, and a link to `/dev/zero`
    /// would never end.
    fn scan(&self, path: &Path) -> Result<Tally, String> {
        let name = self.shown_name(path);
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| name.clone())?;
        let m = f.metadata().map_err(|_| name.clone())?;
        if !m.is_file() {
            return Err(format!("{name} (not a regular file)"));
        }
        if m.len() > self.max_mb.saturating_mul(1024 * 1024) {
            return Err(format!("{name} (over {} MB)", self.max_mb));
        }
        let gz = path.extension().is_some_and(|e| e == "gz");
        self.count_opened(f, m.len(), gz, name)
    }

    /// Lines with a hit in a file already opened and judged, `len` long when it was: a `.gz` up
    /// to `max_mb` of what it decompresses to, a plain file up to `len`.
    fn count_opened(
        &self,
        f: std::fs::File,
        len: u64,
        gz: bool,
        name: String,
    ) -> Result<Tally, String> {
        let limit = self.max_mb.saturating_mul(1024 * 1024);
        let too_big = || format!("{name} (over {} MB)", self.max_mb);
        if gz {
            // Its compressed size says nothing about what it holds: stop at the limit of what it
            // decompresses to, and say it was too big, as for a plain file.
            let mut capped = Capped::new(flate2::read::MultiGzDecoder::new(f), limit);
            // A truncated .gz ends in an error: unscanned, never clean.
            let hits = count(&self.patterns, &mut capped).map_err(|_| name.clone())?;
            if capped.over {
                return Err(too_big());
            }
            return Ok(hits);
        }
        // Only as far as it reached when it was opened, so a log that keeps growing as it's read
        // can't keep the scan going.
        count(&self.patterns, f.take(len)).map_err(|_| name)
    }

    /// The journal's running total of hits, read on from the cursor, and why it couldn't be read
    /// if it couldn't, in which case the total stands as it was. A dry run reads from the same
    /// cursor and writes nothing.
    fn journal(&self, state: &CheckDir) -> (Tally, Option<String>) {
        let saved: Journal = state
            .read(RECORD)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        // A directory that can't be made doesn't stop the read: the hits it finds still count,
        // so a token is a FAIL even then, and only the cursor goes unkept.
        let homeless = state.make().is_err();
        let mut args: Vec<String> = ["-q", "-o", "export", "--no-pager"]
            .map(String::from)
            .into();
        args.push(match &saved.cursor {
            Some(cursor) => format!("--after-cursor={cursor}"),
            // This boot only: a whole journal can take longer than the limit, and a run that's
            // killed keeps no cursor, so it would start over every hour and never finish.
            None => "-b".into(),
        });
        let secs = self.journal_secs;
        let patterns = self.patterns.clone();
        let stream = process::stream(
            &self.journalctl,
            &args,
            Duration::from_secs(secs),
            move |out| read_export(&patterns, out),
        );
        // What to keep, if anything, and why the journal wasn't read, if it wasn't.
        let because = |why: &str| Some(format!("journal ({why})"));
        let (next, mut why) = match stream {
            Ok((status, Ok((hits, cursor)))) if status.success() => {
                // With no cursor this boot was read from its start: after a reset, what an
                // earlier boot logged isn't in it, so the total never goes below what was kept.
                let mut tally = saved.tally();
                match saved.cursor {
                    Some(_) => tally.add(&hits),
                    None => tally.most(&hits),
                }
                let next = Journal {
                    cursor: cursor.or(saved.cursor.clone()),
                    total: tally.lines,
                    by: tally.by,
                };
                (Some(next), None)
            }
            Err(Unfinished::TimedOut) => (None, because(&format!("no answer in {secs}s"))),
            // A cursor journalctl won't take, from a journal that was rotated away say, would
            // fail every run from now on. Start over from this boot; the total stands meanwhile,
            // so a FAIL stays FAIL. Only a plain refusal: journalctl read through to its end and
            // exited non-zero. A signal, our own SIGPIPE when the reader gave up included, or a
            // reader that failed is unscanned, and leaves the record as it was.
            Ok((status, Ok(_)))
                if !status.success() && status.signal().is_none() && saved.cursor.is_some() =>
            {
                let reset = Journal {
                    cursor: None,
                    total: saved.total,
                    by: saved.by.clone(),
                };
                (
                    Some(reset),
                    because("cursor refused, so it's read again from this boot"),
                )
            }
            _ => (None, Some("journal".to_string())),
        };
        // What was read counts even if it can't be kept; a reset keeps the total as it stood.
        let tally = next.as_ref().map_or(saved.tally(), Journal::tally);
        // The one write. A dry run reads from the same cursor, and its directory keeps nothing.
        if let Some(next) = &next {
            let kept = serde_json::to_vec(next)
                .map_err(io::Error::from)
                .and_then(|b| state.write(RECORD, &b));
            if homeless {
                why = because("no place to keep its cursor");
            } else if kept.is_err() {
                why = because("its cursor can't be kept");
            }
        }
        (tally, why)
    }
}

/// A reader that stops after `left` bytes and notes whether there was more.
struct Capped<R> {
    inner: R,
    left: u64,
    over: bool,
}

impl<R: Read> Capped<R> {
    fn new(inner: R, limit: u64) -> Self {
        Capped {
            inner,
            left: limit,
            over: false,
        }
    }
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            // At the limit: a byte more means it's over, and the reading ends here either way.
            let mut one = [0u8; 1];
            if !self.over && self.inner.read(&mut one)? > 0 {
                self.over = true;
            }
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Lines with a hit.
fn count(patterns: &SecretPatterns, r: impl Read) -> io::Result<Tally> {
    let mut r = BufReader::new(r);
    let mut line = Vec::new();
    let mut tally = Tally::default();
    loop {
        line.clear();
        if (&mut r).take(LINE_MAX).read_until(b'\n', &mut line)? == 0 {
            return Ok(tally);
        }
        // Which patterns, only for a line that has a hit: most lines don't.
        if patterns.found_in(&line) {
            tally.line(&patterns.which(&line));
        }
    }
}

/// Fields with a hit in journalctl's `-o export`, and the last entry's cursor. An entry is
/// `FIELD=value` lines and a blank line, its first field `__CURSOR`. A field whose value isn't
/// text is its name alone on a line, then its length as eight little-endian bytes, the value,
/// and a newline, so it's read by length rather than by line.
fn read_export(patterns: &SecretPatterns, r: impl Read) -> io::Result<(Tally, Option<String>)> {
    let mut r = BufReader::new(r);
    let mut line = Vec::new();
    let (mut hits, mut cursor) = (Tally::default(), None);
    let (mut entry_start, mut whole_line) = (true, true);
    loop {
        line.clear();
        if (&mut r).take(LINE_MAX).read_until(b'\n', &mut line)? == 0 {
            return Ok((hits, cursor));
        }
        // Only a line read from its start can be a blank line, a cursor or a binary field's
        // name; the rest of a line longer than LINE_MAX is only text.
        let fresh = whole_line;
        whole_line = line.ends_with(b"\n");
        if fresh && line == b"\n" {
            entry_start = true;
            continue;
        }
        // Taken whether or not it's a cursor: only an entry's first field can be.
        if fresh
            && std::mem::take(&mut entry_start)
            && let Some(c) = line.strip_prefix(b"__CURSOR=")
        {
            cursor = Some(String::from_utf8_lossy(c).trim_end().to_string());
        }
        if fresh && whole_line && !line.contains(&b'=') {
            let mut len = [0u8; 8];
            r.read_exact(&mut len)?;
            let len = u64::from_le_bytes(len);
            let mut value = Vec::new();
            (&mut r).take(len.min(LINE_MAX)).read_to_end(&mut value)?;
            if patterns.found_in(&value) {
                hits.line(&patterns.which(&value));
            }
            io::copy(
                &mut (&mut r).take(len - value.len() as u64),
                &mut io::sink(),
            )?;
            r.read_exact(&mut [0u8; 1])?;
            continue;
        }
        if patterns.found_in(&line) {
            hits.line(&patterns.which(&line));
        }
    }
}

impl Secrets {
    /// The paths a pattern names: as it is, if it's there, or, when its last part ends in `*`, every
    /// name in its directory that starts with the rest, in order. A directory it can't read is said.
    fn glob(&self, pattern: &str) -> Result<Vec<PathBuf>, String> {
        let path = Path::new(pattern);
        let Some(prefix) = pattern.strip_suffix('*') else {
            return Ok(if fs::symlink_metadata(path).is_ok() {
                vec![path.to_path_buf()]
            } else {
                Vec::new()
            });
        };
        let prefix = Path::new(prefix);
        let (Some(dir), Some(start)) = (prefix.parent(), prefix.file_name()) else {
            return Ok(Vec::new());
        };
        let start = start.to_string_lossy();
        let entries = fs::read_dir(dir).map_err(|_| self.shown_name(dir))?;
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&*start))
            .map(|e| e.path())
            .collect();
        found.sort();
        Ok(found)
    }

    /// Every `*.log` under `dir`, in order, not following links.
    fn walk(&self, dir: &Path, files: &mut Vec<PathBuf>, unread: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            unread.push(self.shown_name(dir));
            return;
        };
        let mut entries: Vec<fs::DirEntry> = entries.flatten().collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        for e in entries {
            let path = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                self.walk(&path, files, unread);
            } else if path.extension().is_some_and(|x| x == "log") {
                files.push(path);
            }
        }
    }

    /// A file's name as a sentence may show it: plain, or described.
    fn shown_name(&self, path: &Path) -> String {
        let name = path
            .file_name()
            .map_or_else(|| path.to_string_lossy(), |n| n.to_string_lossy());
        shown(&self.patterns.redact(&name), "log")
    }
}

/// The path a log has across rotations: `/var/log/syslog.2.gz` is `/var/log/syslog`.
fn rotation_base(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = name.strip_suffix(".gz").unwrap_or(&name);
    let base = match name.rsplit_once('.') {
        Some((base, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => name,
    };
    path.with_file_name(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A field whose value isn't text, as `-o export` writes it: its name, its length as eight
    /// little-endian bytes, the value, then a newline.
    fn binary(name: &str, value: &[u8]) -> Vec<u8> {
        let mut b = format!("{name}\n").into_bytes();
        b.extend((value.len() as u64).to_le_bytes());
        b.extend(value);
        b.push(b'\n');
        b
    }

    #[test]
    fn export_is_read_by_entry_with_binary_fields_read_by_length() {
        let token = format!(
            "xoxb-{}-{}-{}",
            "1".repeat(12),
            "2".repeat(13),
            "a".repeat(24)
        );
        let mut export = b"__CURSOR=s=1;i=1\nMESSAGE=ordinary\n\n".to_vec();
        export.extend(b"__CURSOR=s=1;i=2\n");
        // A value holding newlines, a blank line and a field-shaped line, which a reader going
        // by lines would take for the next entry and its cursor.
        let value = format!("one\n\n__CURSOR=not-a-cursor\n{token}\n");
        export.extend(binary("MESSAGE", value.as_bytes()));
        export.extend(format!("_CMDLINE=x {token}\n\n").as_bytes());
        let (hits, cursor) = read_export(&SecretPatterns::builtins(), &export[..]).unwrap();
        assert_eq!(hits.lines, 2);
        assert_eq!(cursor.as_deref(), Some("s=1;i=2"));
    }

    fn secrets(max_mb: u64) -> Secrets {
        Secrets {
            patterns: SecretPatterns::builtins(),
            logs: Vec::new(),
            optional_logs: Vec::new(),
            log_dirs: Vec::new(),
            max_mb,
            journal: false,
            journalctl: journalctl(),
            journal_secs: journal_secs(),
        }
    }

    #[test]
    fn a_plain_log_is_read_only_as_far_as_it_reached_when_opened() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("app.log");
        std::fs::write(&path, "an ordinary line\n").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let len = f.metadata().unwrap().len();
        // Written after it was opened, as a log that keeps growing is.
        let token = format!("ghp_{}", "a1".repeat(18));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(format!("{token}\n").repeat(1000).as_bytes())
            .unwrap();
        assert_eq!(
            secrets(200)
                .count_opened(f, len, false, "app.log".into())
                .map(|t| t.lines),
            Ok(0)
        );
        // Opened again, the same file is read to its new end.
        let f = std::fs::File::open(&path).unwrap();
        let len = f.metadata().unwrap().len();
        assert_eq!(
            secrets(200)
                .count_opened(f, len, false, "app.log".into())
                .map(|t| t.lines),
            Ok(1000)
        );
    }

    #[test]
    fn a_gz_that_decompresses_past_max_mb_is_too_big_to_scan() {
        use flate2::write::GzEncoder;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("app.log.1.gz");
        let mut e = GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::best(),
        );
        // About 3 MB of ordinary lines, a few kilobytes compressed.
        for _ in 0..100_000 {
            e.write_all(b"an ordinary line, again\n").unwrap();
        }
        e.finish().unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < 1024 * 1024);
        let open = || std::fs::File::open(&path).unwrap();
        assert_eq!(
            secrets(1).count_opened(open(), 0, true, "app.log.1.gz".into()),
            Err("app.log.1.gz (over 1 MB)".into())
        );
        assert_eq!(
            secrets(3)
                .count_opened(open(), 0, true, "app.log.1.gz".into())
                .map(|t| t.lines),
            Ok(0)
        );
    }

    #[test]
    fn a_rotated_logs_base_is_its_path_without_the_rotation() {
        let p = |s: &str| rotation_base(Path::new(s));
        assert_eq!(p("/var/log/syslog.2.gz"), Path::new("/var/log/syslog"));
        assert_eq!(p("/var/log/syslog.1"), Path::new("/var/log/syslog"));
        assert_eq!(p("/var/log/syslog"), Path::new("/var/log/syslog"));
        assert_eq!(p("/x/app.log"), Path::new("/x/app.log"));
    }
}
