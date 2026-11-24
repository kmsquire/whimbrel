//! A check that runs somewhere whimbrel can't run it, as another account, in a GUI session or on
//! its own schedule, leaves [result rows](crate::rows) in a file, and this reads them.
//!
//! ```toml
//! [[check]]
//! kind = "result-file"
//! key = "backup"
//! about = "the nightly backup"
//! path = "/var/lib/backup/result.tsv"
//! owner_uid = 34
//! max_age_mins = 1500
//! stale_see = "systemctl status backup.timer"
//! ```
//!
//! The writer must write a temp file beside it and rename it over, or a run that reads it midway
//! sees half a file and warns until the next.
//!
//! The file must be a plain file of the account that writes it, with no write bit for its group
//! or for others. The mode check sees the permission bits, not macOS ACLs. A file that's missing,
//! unsafe, stale or dated in the future is a WARN about the file; what it says is judged as rows.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::check::{At, Check, Finding, Kind, Shared, sentence_case};
use crate::config::from_table;
use crate::rows;
use crate::sentence::quoted;

/// The most read: a result is a few dozen short rows.
pub const MAX: u64 = 64 * 1024;
/// A file this far ahead of the clock is dated in the future, not merely by a clock's drift.
const AHEAD: Duration = Duration::from_secs(5 * 60);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    path: PathBuf,
    /// The account that writes it: the only one whose file it believes.
    #[serde(default)]
    owner_uid: u32,
    /// Older than this, whatever writes it may have stopped.
    #[serde(default = "max_age")]
    max_age_mins: u64,
    /// A row it must always have, which comes first and mustn't be skipped.
    required_row: Option<String>,
    /// What to run when the file is missing or stale. Unset, `ls -l` of it.
    stale_see: Option<String>,
}

fn max_age() -> u64 {
    90
}

pub struct ResultFile {
    path: PathBuf,
    owner_uid: u32,
    max_age_mins: u64,
    required_row: Option<String>,
    stale_see: Option<String>,
}

/// `result-file`, keyed `result-file` and recovering as "the result file" unless its table says
/// otherwise; a config names it for what writes it.
pub const KIND: Kind = Kind {
    name: "result-file",
    key: "result-file",
    about: "the result file",
    build,
};

fn build(table: toml::Table, _: &Shared) -> Result<Box<dyn Check>, String> {
    let t: Table = from_table(table)?;
    if !t.path.is_absolute() {
        return Err("path must be an absolute path".into());
    }
    if t.max_age_mins == 0 {
        return Err("max_age_mins must be at least 1".into());
    }
    if t.required_row.as_deref() == Some("") {
        return Err("required_row must name a row".into());
    }
    Ok(Box::new(ResultFile {
        path: t.path,
        owner_uid: t.owner_uid,
        max_age_mins: t.max_age_mins,
        required_row: t.required_row,
        stale_see: t.stale_see,
    }))
}

/// Why the file itself can't be believed, before a word of it is read. Each is a WARN.
#[derive(Debug, PartialEq, Eq)]
enum Doubt {
    Missing,
    Unsafe(String),
    /// Its age, and the limit it's past, in minutes.
    Stale(Duration, u64),
    Future,
}

impl Doubt {
    fn tag(&self) -> &'static str {
        match self {
            Doubt::Missing => "file:missing",
            Doubt::Unsafe(_) => "file:unsafe",
            Doubt::Stale(..) => "file:stale",
            Doubt::Future => "file:future",
        }
    }

    fn what(&self, host: &str, about: &str) -> String {
        let whose = format!("{host}'s result for {about}");
        match self {
            Doubt::Missing => format!("{host} has no result for {about}."),
            Doubt::Unsafe(why) => format!("{whose} isn't safe to read: {why}."),
            Doubt::Stale(age, limit) => format!(
                "{whose} is {} minutes old, past its limit of {limit}, so whatever writes it may \
                 have stopped.",
                age.as_secs() / 60
            ),
            Doubt::Future => format!("{whose} is dated in the future, so its age can't be told."),
        }
    }
}

impl Check for ResultFile {
    /// The worst row's level, with each WARN or FAIL row a problem; see [`rows`].
    fn run(&self, at: &At) -> Finding {
        let host = sentence_case(at.host);
        let path = quoted(&self.path.display().to_string());
        let bytes = match self.read(at.now) {
            Ok(bytes) => bytes,
            Err(d) => {
                let next = match (&d, &self.stale_see) {
                    (Doubt::Missing | Doubt::Stale(..) | Doubt::Future, Some(see)) => see.clone(),
                    _ => format!("ls -l {path}"),
                };
                return Finding::warn()
                    .says(d.what(&host, at.about))
                    .see(next)
                    .fingerprint(d.tag());
            }
        };
        let whose = format!("{host}'s result for {}", at.about);
        rows::judge(
            &bytes,
            self.required_row.as_deref(),
            &whose,
            &format!("cat {path}"),
        )
    }
}

impl ResultFile {
    /// The file's bytes if it's safe, fresh and finished being written, or why not. Opened without
    /// following a link and without blocking on a FIFO, and judged on the open file, so a swap
    /// after the checks can't slip another in.
    fn read(&self, now: SystemTime) -> Result<Vec<u8>, Doubt> {
        let unsafe_ = |why: &str| Doubt::Unsafe(why.to_string());
        let too_big = || unsafe_("it's over 64 KiB");
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
            .map_err(|e| match e.kind() {
                ErrorKind::NotFound => Doubt::Missing,
                _ if e.raw_os_error() == Some(libc::ELOOP) => unsafe_("it's a link"),
                _ => unsafe_("it can't be opened"),
            })?;
        let m = f.metadata().map_err(|_| unsafe_("it can't be opened"))?;
        if !m.is_file() {
            return Err(unsafe_("it isn't a plain file"));
        }
        if m.uid() != self.owner_uid {
            return Err(Doubt::Unsafe(format!("it belongs to uid {}", m.uid())));
        }
        if m.mode() & 0o022 != 0 {
            return Err(unsafe_("other accounts can write it"));
        }
        if m.len() > MAX {
            return Err(too_big());
        }
        let modified = m.modified().map_err(|_| unsafe_("it can't be opened"))?;
        match now.duration_since(modified) {
            Ok(age) if age > Duration::from_secs(self.max_age_mins.saturating_mul(60)) => {
                return Err(Doubt::Stale(age, self.max_age_mins));
            }
            Ok(_) => {}
            Err(e) if e.duration() > AHEAD => return Err(Doubt::Future),
            Err(_) => {}
        }
        // One byte past the limit, so a file that grew after the size check is refused, not cut.
        let mut bytes = Vec::new();
        f.take(MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| unsafe_("it can't be opened"))?;
        if bytes.len() as u64 > MAX {
            return Err(too_big());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_table_defaults_to_roots_file_stale_after_90_minutes() {
        let t: Table = from_table(toml::from_str("path = \"/r.tsv\"").unwrap()).unwrap();
        assert_eq!((t.owner_uid, t.max_age_mins), (0, 90));
    }
}
