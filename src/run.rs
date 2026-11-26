//! One run, from a config: check, tell each channel what's new, keep the ledger. [`run`] returns
//! a [`Report`], and the log line, a dry run's printout and stderr are each rendered from it.

use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use crate::alert::{Alert, Frame};
use crate::check::Run;
use crate::check::{CheckResult, Level, run_checks};
use crate::config::Config;
use crate::ledger::{Channel, Form, Outcome, State, deliver};
use crate::sentence::Commands;
use crate::state::{Locked, StateDir};

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

/// What one run did: the one value that the log line, a dry run's printout and the messages on
/// stderr are rendered from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub mode: Mode,
    /// When it ran, in seconds since the Unix epoch.
    pub now: u64,
    pub ended: Ended,
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It couldn't start, and why: a config its checks refuse, a state directory it can't use.
    NotStarted(String),
    /// Another run held the lock at this path, so this one did nothing.
    LockedOut(PathBuf),
    Ran(Ran),
}

/// A run that went through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ran {
    pub results: Vec<CheckResult>,
    /// Each channel, in the config's order.
    pub channels: Vec<ChannelReport>,
    /// What else happened, for the log: a ledger set aside, a ledger that couldn't be saved.
    pub notes: Vec<String>,
    /// Whether saving the ledger failed. A dry run saves nothing, and that's no failure.
    pub save_failed: bool,
}

/// What one channel did this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelReport {
    pub name: String,
    pub outcome: Outcome,
    /// In a dry run, what it would have been sent, in its form.
    pub would_send: Option<String>,
}

impl Report {
    /// The process's exit status.
    pub fn exit(&self) -> Exit {
        match &self.ended {
            Ended::NotStarted(_) => Exit::NotStarted,
            Ended::LockedOut(_) => Exit::Ran,
            Ended::Ran(ran) if ran.save_failed => Exit::NotKept,
            Ended::Ran(_) => Exit::Ran,
        }
    }

    /// The run's one line for the log, if it writes one: a dry run changes nothing, the log
    /// included. "alert failed" is what other tools grep the log for.
    pub fn log_line(&self) -> Option<String> {
        if self.mode == Mode::DryRun {
            return None;
        }
        match &self.ended {
            Ended::NotStarted(why) => Some(format!(
                "{} alert failed: couldn't start: {why}",
                utc(self.now)
            )),
            Ended::LockedOut(_) => None,
            Ended::Ran(ran) => Some(log_line(
                self.now,
                &ran.results,
                ran.channels.iter().map(|t| (t.name.as_str(), &t.outcome)),
                &ran.notes,
            )),
        }
    }

    /// What a dry run prints: the levels, then what each channel would be sent, then each
    /// channel with nothing new.
    pub fn printout(&self) -> String {
        let Ended::Ran(ran) = &self.ended else {
            return String::new();
        };
        let mut out = format!("{}\n", summary(&ran.results));
        for t in &ran.channels {
            if let Some(text) = &t.would_send {
                let _ = write!(out, "\n{} would be sent:\n{text}\n", t.name);
            }
        }
        for t in ran
            .channels
            .iter()
            .filter(|t| t.outcome == Outcome::Unchanged)
        {
            let _ = write!(out, "\n{}: no change since it was last told.\n", t.name);
        }
        out
    }

    /// What goes to stderr, after `program: `, if anything.
    pub fn complaint(&self) -> Option<String> {
        match &self.ended {
            Ended::NotStarted(why) => Some(why.clone()),
            Ended::LockedOut(lock) => Some(format!("another run holds {}", lock.display())),
            Ended::Ran(_) => None,
        }
    }
}

/// Run once from `config`, and render the report: the log line, or a dry run's printout, and
/// stderr. `config_path` is for pointing at a dry run.
pub(crate) fn once(
    config: &Config,
    config_path: &Path,
    program: &str,
    mode: Mode,
    now: u64,
) -> Exit {
    let mut channels = config.build_channels();
    let mut refs: Vec<&mut dyn Channel> = channels
        .iter_mut()
        .map(|c| -> &mut dyn Channel { &mut **c })
        .collect();
    // Rendered while the run still holds the lock, so the log line is written under it.
    run(
        config,
        config_path,
        program,
        mode,
        now,
        &mut refs,
        |report| {
            if let Some(why) = report.complaint() {
                eprintln!("{program}: {why}");
            }
            if mode == Mode::DryRun {
                print!("{}", report.printout());
            }
            if let Some(line) = report.log_line()
                && let Err(e) = log(config.log_file.as_deref(), &line)
            {
                // A run that couldn't start has said why on stderr already.
                if !matches!(report.ended, Ended::NotStarted(_)) {
                    eprintln!("{program}: couldn't write the log: {e}");
                    eprintln!("{line}");
                }
            }
            report.exit()
        },
    )
}

/// Run once: build the checks from `config` and run them, tell `channels` what's new, and keep
/// the ledger. The checks come from the config; the alerts go to the channels passed in, which a
/// caller can replace. A dry run tells a stand-in for each channel instead, which records what it
/// would have been sent, and changes nothing. `program` and `config_path` are for the commands
/// an alert names.
///
/// `finish` gets the report while the run still holds the lock, and its answer is returned: what
/// it writes, the log line, is written under the lock.
pub fn run<T>(
    config: &Config,
    config_path: &Path,
    program: &str,
    mode: Mode,
    now: u64,
    channels: &mut [&mut dyn Channel],
    finish: impl FnOnce(Report) -> T,
) -> T {
    let dir = StateDir::new(&config.state_dir);
    let (ended, _locked) = match run_inner(config, config_path, program, mode, now, &dir, channels)
    {
        Ok((ran, locked)) => (Ended::Ran(ran), locked),
        Err(ended) => (ended, None),
    };
    finish(Report { mode, now, ended })
}

/// A run that went through, and its hold on the lock, or how it ended early.
fn run_inner<'d>(
    config: &Config,
    config_path: &Path,
    program: &str,
    mode: Mode,
    now: u64,
    dir: &'d StateDir,
    channels: &mut [&mut dyn Channel],
) -> Result<(Ran, Option<Locked<'d>>), Ended> {
    let not_started = |why: &dyn std::fmt::Display| Ended::NotStarted(why.to_string());
    // Built before anything touches the state directory, so a config they refuse changes nothing.
    let checks = config.build_checks().map_err(|e| not_started(&e))?;
    let frame = Frame::new(&config.host)
        .with_commands(Commands::new(program, Some(config_path)))
        .with_redact(config.secret_patterns().clone());
    let run = Run {
        now: UNIX_EPOCH + Duration::from_secs(now),
        host: &config.host,
        state_dir: &config.state_dir,
        mode,
    };

    // What each channel was told, and the lock for a run that keeps it. A dry run makes no
    // directory and takes no lock: it leaves the host as it found it.
    let mut notes = Vec::new();
    let (mut state, locked) = match mode {
        Mode::DryRun => match state_dir(&config.state_dir, false).map_err(|e| not_started(&e))? {
            false => (State::default(), None),
            true => (dir.peek().map_err(|e| not_started(&e))?, None),
        },
        Mode::Run => {
            state_dir(&config.state_dir, true).map_err(|e| not_started(&e))?;
            let locked = match dir.lock() {
                Ok(Some(locked)) => locked,
                Ok(None) => return Err(Ended::LockedOut(config.state_dir.join("lock"))),
                Err(e) => return Err(not_started(&e)),
            };
            let state = match locked.load() {
                Ok(state) => state,
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    let to = locked.set_aside(now).map_err(|e| not_started(&e))?;
                    notes.push(format!(
                        "ledger lost: set aside an unreadable ledger as {}, and every channel is \
                         told",
                        to.display()
                    ));
                    State::lost_track()
                }
                Err(e) => return Err(not_started(&e)),
            };
            (state, Some(locked))
        }
    };

    let results = run_checks(&checks, &run);
    let mut stand_ins: Vec<StandIn> = match mode {
        Mode::DryRun => channels.iter().map(|c| StandIn::new(&**c)).collect(),
        Mode::Run => Vec::new(),
    };
    let outcomes = match mode {
        Mode::DryRun => {
            let mut refs: Vec<&mut dyn Channel> = stand_ins
                .iter_mut()
                .map(|s| s as &mut dyn Channel)
                .collect();
            deliver(&mut state, &results, &mut refs, &frame, now)
        }
        Mode::Run => deliver(&mut state, &results, channels, &frame, now),
    }
    .map_err(|e| not_started(&e))?;
    let mut save_failed = false;
    if let Some(locked) = &locked
        && let Err(e) = locked.save(&state)
    {
        notes.push(format!("couldn't save the ledger: {e}"));
        save_failed = true;
    }
    let mut would_send = stand_ins.into_iter().map(|s| s.said);
    let channels = outcomes
        .into_iter()
        .map(|(name, outcome)| ChannelReport {
            name,
            outcome,
            would_send: would_send.next().flatten(),
        })
        .collect();
    let ran = Ran {
        results,
        channels,
        notes,
        save_failed,
    };
    Ok((ran, locked))
}

/// A dry run's stand-in for a channel: its name and form, and what it was handed.
struct StandIn {
    name: String,
    form: Form,
    /// One alert at most: `deliver` sends to each channel at most once a run.
    said: Option<String>,
}

impl StandIn {
    fn new(channel: &dyn Channel) -> Self {
        StandIn {
            name: channel.name().to_string(),
            form: channel.form(),
            said: None,
        }
    }
}

impl Channel for StandIn {
    fn name(&self) -> &str {
        &self.name
    }

    fn form(&self) -> Form {
        self.form
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        self.said = Some(match self.form {
            Form::Short => alert.short.clone(),
            Form::Full => alert.full.clone(),
        });
        Ok(())
    }
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
fn log_line<'a>(
    now: u64,
    results: &[CheckResult],
    outcomes: impl IntoIterator<Item = (&'a str, &'a Outcome)>,
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

    struct Phone;

    impl Channel for Phone {
        fn name(&self) -> &str {
            "phone"
        }
        fn form(&self) -> Form {
            Form::Short
        }
        fn send(&mut self, _: &Alert) -> Result<(), String> {
            unreachable!("a dry run sends through its stand-in")
        }
    }

    #[test]
    fn a_dry_runs_stand_in_keeps_its_channels_name_and_form() {
        let mut s = StandIn::new(&Phone);
        assert_eq!((s.name(), s.form()), ("phone", Form::Short));
        let alert = Alert {
            short: "short".into(),
            full: "full".into(),
            urgent: false,
        };
        s.send(&alert).unwrap();
        assert_eq!(s.said.as_deref(), Some("short"));
    }

    #[test]
    fn a_printout_lists_what_would_be_sent_then_what_has_nothing_new() {
        let told = |name: &str, outcome, would_send: Option<&str>| ChannelReport {
            name: name.into(),
            outcome,
            would_send: would_send.map(String::from),
        };
        let report = Report {
            mode: Mode::DryRun,
            now: 0,
            ended: Ended::Ran(Ran {
                results: vec![Finding::ok().stamped("disk", "")],
                channels: vec![
                    told("a", Outcome::Unchanged, None),
                    told("b", Outcome::Sent, Some("to b")),
                ],
                notes: Vec::new(),
                save_failed: false,
            }),
        };
        assert_eq!(
            report.printout(),
            "OK disk=OK\n\nb would be sent:\nto b\n\na: no change since it was last told.\n"
        );
        assert_eq!(report.log_line(), None);
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
            log_line(
                0,
                &results,
                outcomes.iter().map(|(n, o)| (n.as_str(), o)),
                &["a note".into()]
            ),
            "1970-01-01T00:00:00Z WARN disk=WARN backup=OK; chat: sent; \
             phone: alert failed: connection refused; print: no change; a note"
        );
    }
}
