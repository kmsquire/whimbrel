//! One run, from a config: check, tell each channel what's new, keep the ledger, log one line.

use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use std::time::{Duration, UNIX_EPOCH};

use crate::alert::Frame;
use crate::channels::Print;
use crate::check::Run;
use crate::check::{CheckResult, Level, run_checks};
use crate::config::Config;
use crate::ledger::{Channel, Outcome, State, deliver};
use crate::sentence::Commands;
use crate::state::StateDir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Send, and keep the ledger.
    Run,
    /// Say what each channel would be sent, and change nothing.
    DryRun,
}

/// How a run ended, as the process's exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// The run went through, even if a send failed, since the ledger retries it.
    Ran = 0,
    /// It ran, but the ledger couldn't be kept.
    NotKept = 1,
    /// It couldn't start.
    NotStarted = 2,
}

impl From<Exit> for std::process::ExitCode {
    fn from(e: Exit) -> Self {
        std::process::ExitCode::from(e as u8)
    }
}

/// Where a run reports: the program's name, for stderr, and the log a run that can't start
/// still writes to, as `alert failed`, which is what a health check looks for.
struct Report<'a> {
    program: &'a str,
    log_file: Option<&'a Path>,
    mode: Mode,
    now: u64,
}

impl Report<'_> {
    fn not_started(&self, why: impl std::fmt::Display) -> Exit {
        eprintln!("{}: {why}", self.program);
        // A dry run changes nothing, the log included.
        if self.mode == Mode::Run {
            let line = format!("{} alert failed: couldn't start: {why}", utc(self.now));
            let _ = log(self.log_file, &line);
        }
        Exit::NotStarted
    }
}

/// Run once. `config_path` is for pointing at a dry run.
pub(crate) fn once(
    config: &Config,
    config_path: &Path,
    program: &str,
    mode: Mode,
    now: u64,
) -> Exit {
    let report = Report {
        program,
        log_file: config.log_file.as_deref(),
        mode,
        now,
    };
    // Built before anything touches the state directory, so a config they refuse changes nothing.
    let checks = match config.build_checks() {
        Ok(checks) => checks,
        Err(why) => return report.not_started(why),
    };
    let frame = Frame::new(&config.host)
        .with_commands(Commands::new(program, Some(config_path)))
        .with_redact(config.secret_patterns().clone());
    let started = UNIX_EPOCH + Duration::from_secs(now);
    let run = Run {
        now: started,
        host: &config.host,
        state_dir: &config.state_dir,
        mode,
    };
    let dir = StateDir::new(&config.state_dir);

    if mode == Mode::DryRun {
        // No directory made, no lock taken: a dry run leaves the host as it found it.
        let mut state = match state_dir(&config.state_dir, false) {
            Ok(false) => State::default(),
            Ok(true) => match dir.peek() {
                Ok(state) => state,
                Err(e) => return report.not_started(e),
            },
            Err(why) => return report.not_started(why),
        };
        let results = run_checks(&checks, &run);
        let channels = config.build_channels();
        let mut sinks: Vec<Print> = channels
            .iter()
            .map(|c| Print::instead_of(c.as_ref()))
            .collect();
        let mut refs: Vec<&mut dyn Channel> =
            sinks.iter_mut().map(|p| p as &mut dyn Channel).collect();
        println!("{}", summary(&results));
        let outcomes = match deliver(&mut state, &results, &mut refs, &frame, now) {
            Ok(outcomes) => outcomes,
            Err(e) => return report.not_started(e),
        };
        for (name, outcome) in outcomes {
            if outcome == Outcome::Unchanged {
                println!("\n{name}: no change since it was last told.");
            }
        }
        return Exit::Ran;
    }

    if let Err(why) = state_dir(&config.state_dir, true) {
        return report.not_started(why);
    }
    let locked = match dir.lock() {
        Ok(Some(locked)) => locked,
        Ok(None) => {
            eprintln!(
                "{program}: another run holds {}/lock",
                config.state_dir.display()
            );
            return Exit::Ran;
        }
        Err(e) => return report.not_started(e),
    };
    let mut notes = Vec::new();
    let mut state = match locked.load() {
        Ok(state) => state,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => match locked.set_aside(now) {
            Ok(to) => {
                notes.push(format!(
                    "ledger lost: set aside an unreadable ledger as {}, and every channel is told",
                    to.display()
                ));
                State::lost_track()
            }
            Err(e) => return report.not_started(e),
        },
        Err(e) => return report.not_started(e),
    };
    let results = run_checks(&checks, &run);
    let mut channels = config.build_channels();
    let mut refs: Vec<&mut dyn Channel> = channels
        .iter_mut()
        .map(|c| -> &mut dyn Channel { &mut **c })
        .collect();
    let outcomes = match deliver(&mut state, &results, &mut refs, &frame, now) {
        Ok(outcomes) => outcomes,
        Err(e) => return report.not_started(e),
    };
    let mut exit = Exit::Ran;
    if let Err(e) = locked.save(&state) {
        notes.push(format!("couldn't save the ledger: {e}"));
        exit = Exit::NotKept;
    }
    let line = log_line(now, &results, &outcomes, &notes);
    if let Err(e) = log(config.log_file.as_deref(), &line) {
        eprintln!("{program}: couldn't write the log: {e}");
        eprintln!("{line}");
    }
    exit
}

/// Make the state directory owner-only if it's missing, and refuse one that someone else could
/// write to or that isn't ours: its ledger decides what we say.
///
/// Whether it existed. With `make` false a missing one is left missing.
fn state_dir(dir: &Path, make: bool) -> Result<bool, String> {
    let shown = dir.display();
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound && !make => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map(|()| false)
            .map_err(|e| format!("can't make {shown}: {e}")),
        Err(e) => Err(format!("{shown}: {e}")),
        Ok(m) if !m.is_dir() => Err(format!("{shown} isn't a directory")),
        Ok(m) if m.mode() & 0o022 != 0 => Err(format!(
            "{shown} can be written by other accounts ({:o}); it should be 700",
            m.mode() & 0o777
        )),
        // SAFETY: geteuid has no preconditions and can't fail.
        Ok(m) if m.uid() != unsafe { libc::geteuid() } => {
            Err(format!("{shown} belongs to another account"))
        }
        Ok(_) => Ok(true),
    }
}

/// One line per run: when, the worst level, each check's level, then each channel.
fn log_line(
    now: u64,
    results: &[CheckResult],
    outcomes: &[(String, Outcome)],
    notes: &[String],
) -> String {
    let mut line = format!("{} {}", utc(now), summary(results));
    for (name, outcome) in outcomes {
        let _ = match outcome {
            Outcome::Unchanged => write!(line, "; {name}: no change"),
            Outcome::Sent => write!(line, "; {name}: sent"),
            // "alert failed" is what other tools grep the log for.
            Outcome::Failed(why) => write!(line, "; {name}: alert failed: {why}"),
        };
    }
    for note in notes {
        let _ = write!(line, "; {note}");
    }
    line
}

/// "WARN disk=WARN backup=OK", or "OK" with no checks.
fn summary(results: &[CheckResult]) -> String {
    let worst = results
        .iter()
        .map(|r| r.finding.level)
        .max()
        .unwrap_or(Level::Ok);
    let mut s = worst.to_string();
    for r in results {
        let _ = write!(s, " {}={}", r.key, r.finding.level);
    }
    s
}

fn log(file: Option<&Path>, line: &str) -> io::Result<()> {
    match file {
        None => {
            println!("{line}");
            Ok(())
        }
        Some(path) => OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .and_then(|mut f| writeln!(f, "{line}")),
    }
}

/// `2026-11-21T10:00:00Z`.
pub(crate) fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finding;

    #[test]
    fn utc_is_iso_8601_with_a_z() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc(1_800_000_000), "2027-01-15T08:00:00Z");
        assert_eq!(utc(1_795_000_000 + 59), "2026-11-18T11:07:39Z");
    }

    #[test]
    fn the_log_line_names_every_check_and_channel() {
        let results = [
            Finding::warn().says("x").stamped("disk", ""),
            Finding::ok().stamped("backup", ""),
        ];
        let outcomes = [
            ("chat".to_string(), Outcome::Sent),
            (
                "phone".to_string(),
                Outcome::Failed("connection refused".into()),
            ),
            ("print".to_string(), Outcome::Unchanged),
        ];
        assert_eq!(
            log_line(0, &results, &outcomes, &["a note".into()]),
            "1970-01-01T00:00:00Z WARN disk=WARN backup=OK; chat: sent; \
             phone: alert failed: connection refused; print: no change; a note"
        );
    }
}
