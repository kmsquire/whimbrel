//! The channels, each kind in a file of its own and named in [`KINDS`]: Slack by incoming
//! webhook, iMessage through a BlueBubbles server, and print, which writes to stdout and stands
//! in for every channel in a dry run.
//!
//! Each real channel reads its secrets from files at send time, so config holds paths, never the
//! values, and a rotated secret needs no restart. A secret file must be an absolute path, belong
//! to us and be readable by us alone. Every channel sends through [`crate::request`], which
//! decides where each part of a request goes; a channel only says which parts are secret.
//! Nothing a send returns names the URL, the password, the recipient or a secret file's path:
//! it's logged, and a path is where a secret pasted into the wrong key would land.

pub mod bluebubbles;
pub mod print;
pub mod slack;

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::config::from_table;
use crate::ledger::Channel;

pub use crate::request::Curl;
pub use bluebubbles::{BlueBubbles, Server};
pub use print::Print;
pub use slack::Slack;

/// Every kind a config can name.
pub const KINDS: &[Kind] = &[slack::KIND, bluebubbles::KIND, print::KIND];

/// A kind of channel: its name in config, what its secret URL looks like if it has one, and how
/// it's built from its table.
#[derive(Clone, Copy, Debug)]
pub struct Kind {
    pub name: &'static str,
    pub secret_url: Option<SecretUrl>,
    pub build: Build,
}

/// How a kind builds a channel from its table, less `kind`, or says why it can't. The reason
/// never repeats a value from the table.
///
/// It depends on the table and [`Shared`] alone, and reads no file and nothing from the
/// environment: config builds each channel once to check it, and again for each run, expecting
/// the same answer. A channel reads its secrets when it sends.
pub type Build = fn(toml::Table, &Shared) -> Result<Box<dyn Channel>, String>;

/// What every channel on a host may build with, besides its own table.
pub struct Shared {
    /// `curl`, as config says where to find it.
    pub curl: Curl,
}

/// A channel that sends with `curl`, which config hands it.
pub trait SendsWithCurl: Channel + DeserializeOwned + 'static {
    fn curl_mut(&mut self) -> &mut Curl;
}

/// The [`Build`] of a kind that sends with `curl`: its table as `T`, with config's `curl`.
pub fn build_with_curl<T: SendsWithCurl>(
    table: toml::Table,
    shared: &Shared,
) -> Result<Box<dyn Channel>, String> {
    let mut channel: T = from_table(table)?;
    channel.curl_mut().clone_from(&shared.curl);
    Ok(Box::new(channel))
}

/// A kind whose URL is itself a secret, so it's read from a file. A config holding one of
/// `hosts` anywhere, in any case, is refused, whether or not it has a channel of this kind.
#[derive(Clone, Copy, Debug)]
pub struct SecretUrl {
    /// What the URL is, after "it holds": "a Slack webhook URL".
    pub what: &'static str,
    pub hosts: &'static [&'static str],
    /// The key that names the file to put it in.
    pub file_key: &'static str,
}

impl SecretUrl {
    /// Why a config holding one is refused.
    pub fn refusal(&self) -> String {
        format!(
            "it holds {}. Put the URL in a file only root can read, and name that file with {}.",
            self.what, self.file_key
        )
    }
}

/// A file holding a secret: an absolute path, so it can't depend on where whimbrel was started.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "PathBuf")]
pub struct SecretFile(PathBuf);

impl TryFrom<PathBuf> for SecretFile {
    type Error = String;

    fn try_from(path: PathBuf) -> Result<Self, String> {
        // The path itself isn't repeated: a secret pasted here by mistake would be.
        if path.is_absolute() {
            Ok(SecretFile(path))
        } else {
            Err("a secret file must be an absolute path".into())
        }
    }
}

/// The most a secret file is read: every secret here is one short line.
const SECRET_MAX: u64 = 64 * 1024;

impl SecretFile {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::try_from(path.into())
    }

    /// The file's name alone, for messages.
    fn name(&self) -> String {
        self.0
            .file_name()
            .map_or_else(|| "?".into(), |n| n.to_string_lossy().into_owned())
    }

    /// Its first line, trimmed, if it's a regular file of ours that only we can read. The
    /// failure names the file, never its path or contents.
    ///
    /// The checks are on the open file, so a swap after them can't slip a different file in. A
    /// directory above it that someone else can write is still a way in; keep secrets under a
    /// directory only root can change.
    pub fn read(&self, what: &str) -> Result<String, String> {
        let name = self.name();
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.0)
            .map_err(|e| format!("can't read the {what} file {name} ({})", e.kind()))?;
        let m = f
            .metadata()
            .map_err(|e| format!("can't read the {what} file {name} ({})", e.kind()))?;
        if !m.is_file() {
            return Err(format!("the {what} file {name} isn't a regular file"));
        }
        // SAFETY: geteuid has no preconditions and can't fail.
        if m.uid() != unsafe { libc::geteuid() } {
            return Err(format!("the {what} file {name} belongs to another account"));
        }
        if m.mode() & 0o077 != 0 {
            return Err(format!(
                "the {what} file {name} can be read by other accounts ({:o}); it should be 600",
                m.mode() & 0o777
            ));
        }
        let mut text = String::new();
        (&mut f)
            .take(SECRET_MAX)
            .read_to_string(&mut text)
            .map_err(|e| format!("can't read the {what} file {name} ({})", e.kind()))?;
        let line = text.lines().next().unwrap_or("").trim().to_string();
        if line.is_empty() {
            return Err(format!("the {what} file {name} is empty"));
        }
        Ok(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_file_is_an_absolute_path() {
        assert!(SecretFile::new("/etc/whimbrel/webhook").is_ok());
        let why = SecretFile::new("https://hooks.example/sekrit").unwrap_err();
        assert!(!why.contains("sekrit"), "{why}");
    }
}
