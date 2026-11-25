//! What a check hands the core: a level, a key, and its own words.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::run::Mode;
use crate::secret_patterns::SecretPatterns;
use crate::sentence::{Commands, Next, Problem};
use crate::state::write_whole;

/// How bad it is. Only WARN and FAIL are problems; the order is the order of badness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Level::Ok => "OK",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        })
    }
}

/// `s` with its first letter capitalized, so a host's name can start a sentence: "the test host"
/// becomes "The test host".
pub fn sentence_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// One check's result for one run: what it found, under its key and about.
///
/// Between runs only the finding's `level`, `fingerprint` and a rise in `count` are compared,
/// under `key`, so its problems can carry today's numbers without making every run news.
///
/// ```
/// use whimbrel::Finding;
/// let r = Finding::warn()
///     .says("The disk is 85% full.")
///     .see("df -h /")
///     .stamped("disk", "the disk");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    /// Stable across runs and unique on a host: `disk`, `backup`.
    pub key: String,
    /// What recovered, as a noun phrase, for when it does: "the disk", "the nightly backup".
    pub about: String,
    pub finding: Finding,
}

impl CheckResult {
    /// WARN or FAIL.
    pub fn is_problem(&self) -> bool {
        self.finding.level > Level::Ok
    }
}

/// What one check found this run. The core stamps it with the check's key and about, so a check
/// can't report under a key that isn't its own.
///
/// ```
/// use whimbrel::Finding;
/// let f = Finding::warn().says("The disk is 85% full.").see("df -h /");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    /// What's wrong, for a person, one problem per thing wrong. None when OK.
    pub problems: Vec<Problem>,
    /// More, for the channels that take the full form: the biggest folders, say.
    pub details: Option<String>,
    /// What makes a change at the same level news. A check sets it only when that's so, such as
    /// the set of files a scan found something in. `None` is the usual case: the disk going from
    /// 85% to 86% is not news.
    pub fingerprint: Option<String>,
    /// A count whose rise is news, though it isn't in the fingerprint: a second leak in a log
    /// already named, say. A fall isn't news. So a problem that keeps growing is told every run
    /// it grows, an hourly alert for an ongoing leak, on purpose: each one is a new secret out.
    pub count: Option<u64>,
}

impl Finding {
    pub fn ok() -> Self {
        Self::at(Level::Ok)
    }

    pub fn warn() -> Self {
        Self::at(Level::Warn)
    }

    pub fn fail() -> Self {
        Self::at(Level::Fail)
    }

    fn at(level: Level) -> Self {
        Finding {
            level,
            problems: Vec::new(),
            details: None,
            fingerprint: None,
            count: None,
        }
    }

    /// A problem: what's wrong, in one sentence. Another `says` adds another problem, and what
    /// follows each says what to run about it.
    pub fn says(mut self, what: impl Into<String>) -> Self {
        self.problems.push(Problem {
            what: what.into(),
            next: None,
        });
        self
    }

    /// A problem with what to run about it, in one go.
    pub fn problem(mut self, what: impl Into<String>, next: Next) -> Self {
        self.problems.push(Problem {
            what: what.into(),
            next: Some(next),
        });
        self
    }

    /// What to run about the last problem. Before any `says` it's a mistake in the check, and it
    /// panics, which the core turns into a WARN that the check broke.
    pub fn next(mut self, next: Next) -> Self {
        let last = self
            .problems
            .last_mut()
            .expect("what to run, before saying what's wrong");
        last.next = Some(next);
        self
    }

    /// "See `cmd`."
    pub fn see(self, cmd: impl Into<String>) -> Self {
        self.next(Next::See(cmd.into()))
    }

    /// "To fix: `cmd`."
    pub fn to_fix(self, cmd: impl Into<String>) -> Self {
        self.next(Next::ToFix(cmd.into()))
    }

    /// "See" a dry run of this host's config.
    pub fn see_dry_run(self) -> Self {
        self.next(Next::DryRun)
    }

    pub fn details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    pub fn count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    /// The first problem's what, or nothing when OK. What came and went is named by it, so a check
    /// with several problems puts its worst first: otherwise a problem that cleared could be named
    /// by one still open.
    pub fn first_what(&self) -> &str {
        self.problems.first().map_or("", |p| p.what.as_str())
    }

    /// Every problem's sentences, one per line, with `commands` the core's own commands on this
    /// host's config.
    pub fn sentence(&self, commands: &Commands) -> String {
        let lines: Vec<String> = self.problems.iter().map(|p| p.sentence(commands)).collect();
        lines.join("\n")
    }

    /// Under `key`, recovering as `about`.
    pub fn stamped(self, key: &str, about: &str) -> CheckResult {
        CheckResult {
            key: key.to_string(),
            about: about.to_string(),
            finding: self,
        }
    }
}

/// Something whimbrel watches. Config picks which run on a host, and names each.
/// It's `Any`, so a command of the core can find the checks of one kind among those a config
/// built, the `secrets` command its scans.
pub trait Check: std::any::Any {
    /// Look, once. Everything it may need beyond its own table is in `at`.
    fn run(&self, at: &At) -> Finding;
}

/// One run of the watch: what every check in it shares.
pub struct Run<'a> {
    /// The run's, so every check in a run agrees on the time.
    pub now: SystemTime,
    /// What the all-clear calls this host, for a check's sentences.
    pub host: &'a str,
    /// The watch's own directory. Each check's is in it, named for its key.
    pub state_dir: &'a Path,
    pub mode: Mode,
}

impl Run<'_> {
    /// What the check under `key`, recovering as `about`, is handed: the only place an `At` is
    /// made.
    pub(crate) fn at<'b>(&'b self, key: &str, about: &'b str) -> At<'b> {
        At {
            now: self.now,
            host: self.host,
            about,
            state: CheckDir {
                path: self.state_dir.join(key),
                mode: self.mode,
            },
        }
    }
}

/// What a check is handed each time it runs.
pub struct At<'a> {
    /// The run's, so every check in a run agrees on the time.
    pub now: SystemTime,
    /// What the all-clear calls this host, for a check's sentences.
    pub host: &'a str,
    /// What the check is about, as its config names it: for a sentence that needs it.
    pub about: &'a str,
    /// The check's own directory, for what it keeps between runs.
    pub state: CheckDir,
}

/// A check's own directory, named for its key under the watch's state directory. In a dry run it
/// keeps nothing: `make` and `write` do nothing and say they did, so a dry run can't change a
/// check's own directory, whatever the check does with it. Only the core makes one.
pub struct CheckDir {
    path: PathBuf,
    mode: Mode,
}

impl CheckDir {
    /// The file `name` in it, or `None` if there's none.
    pub fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.file(name)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Make the directory, owner-only, if it's missing. In a dry run, nothing.
    pub fn make(&self) -> io::Result<()> {
        if self.mode == Mode::DryRun {
            return Ok(());
        }
        match DirBuilder::new().mode(0o700).create(&self.path) {
            Err(e) if !(e.kind() == io::ErrorKind::AlreadyExists && self.path.is_dir()) => Err(e),
            _ => Ok(()),
        }
    }

    /// Replace the file `name` whole, making the directory first. In a dry run, nothing.
    pub fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if self.mode == Mode::DryRun {
            return Ok(());
        }
        let file = self.file(name)?;
        self.make()?;
        write_whole(&file, bytes)
    }

    /// `name`'s path in it, if `name` is a plain file name, so a check's files stay in its own
    /// directory too.
    fn file(&self, name: &str) -> io::Result<PathBuf> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name:?} isn't a plain file name"),
            ));
        }
        Ok(self.path.join(name))
    }
}

/// A kind of check: its name in a config, the key and about a check of it has unless its table
/// says otherwise, and how to build one from the rest of its table.
#[derive(Clone, Copy)]
pub struct Kind {
    pub name: &'static str,
    pub key: &'static str,
    pub about: &'static str,
    pub build: Build,
}

/// How a kind builds a check from its table, less `kind`, `key` and `about`, or says why it can't.
pub type Build = fn(toml::Table, &Shared) -> Result<Box<dyn Check>, String>;

/// What every check on a host may build with, besides its own table.
#[derive(Clone, Copy)]
pub struct Shared<'a> {
    pub secret_patterns: &'a SecretPatterns,
}

impl Kind {
    /// A check of this kind from its table, `kind` already taken out: its `key` and `about`, or
    /// the kind's, then the check from the rest. A key must be lowercase letters, digits and
    /// dashes, since it names the check's own directory.
    pub fn configure(&self, mut table: toml::Table, shared: &Shared) -> Result<Configured, String> {
        let mut text = |field: &str, default: &str| match table.remove(field) {
            None => Ok(default.to_string()),
            Some(toml::Value::String(s)) => Ok(s),
            Some(_) => Err(format!("{field} must be text")),
        };
        let key = text("key", self.key)?;
        let about = text("about", self.about)?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!(
                "key {key:?} must be lowercase letters, digits and dashes, since it names a \
                 directory"
            ));
        }
        let check = (self.build)(table, shared)?;
        Ok(Configured { key, about, check })
    }
}

/// A check as config built it, under its key and about.
pub struct Configured {
    /// Stable across runs and unique on a host: `disk`, `backup`.
    pub key: String,
    /// What recovered, as a noun phrase, for when it does.
    pub about: String,
    pub check: Box<dyn Check>,
}

impl Configured {
    /// What it finds this run. A check that panics is a WARN, so the others still report and the
    /// run still alerts.
    pub fn find(&self, run: &Run) -> Finding {
        let at = run.at(&self.key, &self.about);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check.run(&at)))
            .unwrap_or_else(|_| crashed(&self.about))
    }

    /// What it finds, under its key and about.
    pub fn run(&self, run: &Run) -> CheckResult {
        self.find(run).stamped(&self.key, &self.about)
    }
}

/// Run every check, each under its own key and about.
pub fn run_checks(checks: &[Configured], run: &Run) -> Vec<CheckResult> {
    checks.iter().map(|c| c.run(run)).collect()
}

/// A check that panicked. The others still ran.
fn crashed(about: &str) -> Finding {
    Finding::warn()
        .says(format!(
            "The watch hit a bug looking at {about}, but the rest still ran."
        ))
        .see_dry_run()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fine;
    impl Check for Fine {
        fn run(&self, _: &At) -> Finding {
            Finding::warn().says("Fine is not fine.")
        }
    }

    struct Buggy;
    impl Check for Buggy {
        fn run(&self, _: &At) -> Finding {
            panic!("a bug")
        }
    }

    fn configured(key: &str, about: &str, check: impl Check + 'static) -> Configured {
        Configured {
            key: key.into(),
            about: about.into(),
            check: Box::new(check),
        }
    }

    #[test]
    fn a_checks_files_stay_in_its_own_directory() {
        let d = tempfile::tempdir().unwrap();
        let run = Run {
            now: SystemTime::UNIX_EPOCH,
            host: "h",
            state_dir: d.path(),
            mode: Mode::Run,
        };
        let at = run.at("mine", "mine");
        for name in ["", ".", "..", "../theirs", "a/b", "/etc/passwd"] {
            assert_eq!(
                at.state.write(name, b"x").unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{name:?}"
            );
            assert!(at.state.read(name).is_err(), "{name:?}");
        }
        at.state.write("ok.json", b"x").unwrap();
        assert_eq!(
            at.state.read("ok.json").unwrap().as_deref(),
            Some(&b"x"[..])
        );
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    #[should_panic(expected = "what to run, before saying what's wrong")]
    fn what_to_run_before_whats_wrong_is_a_mistake_not_a_silent_empty_problem() {
        let _ = Finding::warn().see("df -h /");
    }

    #[test]
    fn several_problems_each_say_what_to_run_about_themselves() {
        let f = Finding::fail()
            .says("A broke.")
            .see("a")
            .problem("B broke.", Next::ToFix("b".into()))
            .says("C broke.");
        assert_eq!(f.first_what(), "A broke.");
        assert_eq!(
            f.sentence(&Commands::default()),
            "A broke. See `a`.\nB broke. To fix: `b`.\nC broke."
        );
    }

    #[test]
    fn a_check_that_panics_is_warn_and_the_others_still_run() {
        let checks = [
            configured("buggy", "the buggy thing", Buggy),
            configured("fine", "the fine check", Fine),
        ];
        let run = Run {
            now: SystemTime::UNIX_EPOCH,
            host: "h",
            state_dir: Path::new("/nonexistent"),
            mode: Mode::DryRun,
        };
        let results = run_checks(&checks, &run);
        assert_eq!(
            results[0],
            Finding::warn()
                .says("The watch hit a bug looking at the buggy thing, but the rest still ran.")
                .see_dry_run()
                .stamped("buggy", "the buggy thing")
        );
        assert_eq!(
            results[0]
                .finding
                .sentence(&Commands::new("w", Some(Path::new("/etc/w.toml")))),
            "The watch hit a bug looking at the buggy thing, but the rest still ran. \
             See `w dry-run --config /etc/w.toml`."
        );
        assert_eq!(
            crate::sentence::breaks("buggy", &results[0].finding.sentence(&Commands::default())),
            Vec::<String>::new()
        );
        assert_eq!(
            results[1],
            Finding::warn()
                .says("Fine is not fine.")
                .stamped("fine", "the fine check")
        );
    }
}
