//! Files that must belong to one account and be no more open than a mode: boot logs that hold
//! secrets on their way through, say.
//!
//! ```toml
//! [[check]]
//! kind = "file"
//! key = "modes"
//! about = "the boot logs' permissions"
//! paths = ["/var/log/cloud-init-output.log"]
//! mode = 0o600
//! ```

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use serde::Deserialize;

use crate::check::{At, Check, Finding, Kind, sentence_case};
use crate::config::from_table;
use crate::sentence::{and_list, quoted, shown};

#[derive(Debug, Deserialize)]
#[serde(try_from = "FileTable")]
pub struct File {
    pub paths: Vec<PathBuf>,
    pub owner_uid: u32,
    /// The most open each may be: 0o600 means no group or other bits, and no execute.
    pub mode: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTable {
    paths: Vec<PathBuf>,
    #[serde(default)]
    owner_uid: u32,
    #[serde(default = "owner_only")]
    mode: u32,
}

fn owner_only() -> u32 {
    0o600
}

impl TryFrom<FileTable> for File {
    type Error = String;

    fn try_from(t: FileTable) -> Result<Self, String> {
        if t.paths.iter().any(|p| !p.is_absolute()) {
            return Err("every path must be an absolute path".into());
        }
        if t.mode > 0o7777 {
            return Err("mode must be a permission mode, such as 0o600".into());
        }
        Ok(File {
            paths: t.paths,
            owner_uid: t.owner_uid,
            mode: t.mode,
        })
    }
}

/// `file`, keyed `file` and recovering as "the files' permissions" unless its table says
/// otherwise.
pub const KIND: Kind = Kind {
    name: "file",
    key: "file",
    about: "the files' permissions",
    build: |table, _| Ok(Box::new(from_table::<File>(table)?)),
};

impl Check for File {
    /// FAIL for each file that isn't a plain file, isn't the owner's, or is more open than the
    /// mode, saying which; WARN for one it can't see, never OK. The fingerprint is the paths, so
    /// another file going bad is news.
    fn run(&self, at: &At) -> Finding {
        let host = sentence_case(at.host);
        let (mut wrong, mut bad, mut unseen) = (Vec::new(), Vec::new(), Vec::new());
        let mut all_plain = true;
        for path in &self.paths {
            let name = shown(
                &path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().into(),
                ),
                "file",
            );
            // Not followed: a symlink's own target could be anything.
            let Ok(m) = fs::symlink_metadata(path) else {
                unseen.push((name, path));
                continue;
            };
            let mode = m.mode() & 0o7777;
            let before = wrong.len();
            if !m.is_file() {
                all_plain = false;
                wrong.push(format!("{name} isn't a plain file"));
            } else {
                if m.uid() != self.owner_uid {
                    wrong.push(format!("{name} belongs to uid {}", m.uid()));
                }
                let extra = mode & !self.mode;
                if extra & 0o077 != 0 {
                    wrong.push(format!("other accounts can reach {name} (mode {mode:o})"));
                } else if extra != 0 {
                    wrong.push(format!(
                        "{name} has mode {mode:o}, more than {:o} allows",
                        self.mode
                    ));
                }
            }
            if wrong.len() > before {
                bad.push(path.display().to_string());
            }
        }
        if !wrong.is_empty() {
            let paths: Vec<String> = bad.iter().map(|p| quoted(p)).collect();
            let paths = paths.join(" ");
            let finding = Finding::fail()
                .says(format!(
                    "Some of {}'s files aren't locked down: {}.",
                    at.host,
                    wrong.join("; ")
                ))
                .fingerprint(bad.join(","));
            return if all_plain {
                let owner = match self.owner_uid {
                    0 => "root:root".to_string(),
                    uid => uid.to_string(),
                };
                finding.to_fix(format!(
                    "chown {owner} {paths} && chmod {:o} {paths}",
                    self.mode
                ))
            } else {
                finding.see(format!("ls -l {paths}"))
            };
        }
        if !unseen.is_empty() {
            let names: Vec<String> = unseen.iter().map(|(n, _)| n.clone()).collect();
            let paths: Vec<String> = unseen
                .iter()
                .map(|(_, p)| p.display().to_string())
                .collect();
            return Finding::warn()
                .says(format!(
                    "{host}'s watch couldn't see who can reach {}.",
                    and_list(&names)
                ))
                .see(format!(
                    "ls -l {}",
                    paths
                        .iter()
                        .map(|p| quoted(p))
                        .collect::<Vec<_>>()
                        .join(" ")
                ))
                .fingerprint(paths.join(","));
        }
        Finding::ok()
    }
}
