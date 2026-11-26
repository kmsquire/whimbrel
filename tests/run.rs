//! One run, from a config with a stand-in df and the print channel, so nothing sends. Most tests
//! call the run in-process, with a channel that keeps what it's sent in place of print, and read
//! the report it returns. The rest, about the config file, stderr and the log file, run the
//! binary.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use whimbrel::config::Config;
use whimbrel::run::{Ended, Exit, Report, run};
use whimbrel::{Alert, Channel, Mode, StateDir};

mod common;

/// When every in-process run happens: 2026-11-18T11:06:40Z.
const NOW: u64 = 1_795_000_000;
const AT: &str = "2026-11-18T11:06:40Z";

/// Stands in for the print channel, and keeps the full form of each alert it's sent.
#[derive(Default)]
struct Kept {
    sent: Vec<String>,
}

impl Channel for Kept {
    fn name(&self) -> &str {
        "print"
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        self.sent.push(alert.full.clone());
        Ok(())
    }
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let h = Host {
            dir: tempfile::tempdir().unwrap(),
        };
        common::stub(h.dir.path(), "df", common::DF);
        h.at(40);
        h.config("");
        h
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.path("state")
    }

    fn at(&self, percent: u32) {
        common::df_at(self.dir.path(), percent);
    }

    /// A config with the disk check and the print channel, then `extra`.
    fn config(&self, extra: &str) {
        self.config_with_state(&self.state(), extra);
    }

    fn config_with_state(&self, state: &Path, extra: &str) {
        fs::write(
            self.path("config.toml"),
            format!(
                "host = \"the test host\"\n\
                 state_dir = {:?}\n\
                 log_file = {:?}\n\
                 [[check]]\nkind = \"disk\"\npath = \"/\"\ndf = {:?}\n\
                 [[channel]]\nkind = \"print\"\n{extra}",
                state,
                self.path("log"),
                self.path("df"),
            ),
        )
        .unwrap();
    }

    /// A directory or file, not writable by others, that belongs to another account: one root
    /// owns when the tests aren't root, and one handed to `nobody` when they are, so the test
    /// asserts either way.
    fn theirs(&self, name: &str, dir: bool) -> PathBuf {
        if !running_as_root() {
            return PathBuf::from(if dir { "/usr" } else { "/etc/hosts" });
        }
        let p = self.path(name);
        if dir {
            fs::create_dir(&p).unwrap();
        } else {
            fs::copy(self.path("config.toml"), &p).unwrap();
        }
        fs::set_permissions(
            &p,
            fs::Permissions::from_mode(if dir { 0o755 } else { 0o644 }),
        )
        .unwrap();
        let path = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: path is a valid C string; chown only changes the file's owner.
        assert_eq!(unsafe { libc::chown(path.as_ptr(), 65534, 65534) }, 0);
        p
    }

    fn load(&self) -> Config {
        Config::load(&self.path("config.toml")).unwrap()
    }

    /// One run in-process, with [`Kept`] in place of the print channel: its report, and what
    /// print was sent.
    fn run(&self, mode: Mode) -> (Report, Vec<String>) {
        let config = self.load();
        let mut kept = Kept::default();
        let mut others = config.build_channels();
        let mut refs: Vec<&mut dyn Channel> = Vec::new();
        let mut print = Some(&mut kept);
        for c in &mut others {
            if c.name() == "print" {
                refs.push(print.take().expect("one print channel"));
            } else {
                refs.push(&mut **c);
            }
        }
        let report = run(
            &config,
            &self.path("config.toml"),
            "whimbrel",
            mode,
            NOW,
            &mut refs,
            |report| report,
        );
        drop(refs);
        (report, kept.sent)
    }

    fn whimbrel(&self, command: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_whimbrel"))
            .args([command, "--config"])
            .arg(self.path("config.toml"))
            .output()
            .unwrap()
    }

    fn log(&self) -> String {
        fs::read_to_string(self.path("log")).unwrap_or_default()
    }

    /// The log's last line, less its timestamp, which must be UTC with a Z.
    fn last_log_line(&self) -> String {
        let log = self.log();
        let line = log.lines().last().unwrap_or("");
        let (time, rest) = line.split_once(' ').unwrap_or(("", ""));
        assert!(
            time.len() == 20 && time.ends_with('Z') && time.as_bytes()[10] == b'T',
            "{time:?} isn't UTC with a Z"
        );
        rest.to_string()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| o.stdout == b"0\n")
}

#[test]
fn a_run_sends_what_changed_keeps_the_ledger_and_logs_one_line() {
    let h = Host::new();
    h.at(85);
    let (report, sent) = h.run(Mode::Run);
    assert_eq!(report.exit(), Exit::Ran);
    assert_eq!(
        sent,
        ["No rush, but something needs a look:\nThe test host's disk is 85% full. See `df -h /`."]
    );
    assert!(h.state().join("ledger.json").exists());
    assert_eq!(
        report.log_line().unwrap(),
        format!("{AT} WARN disk=WARN alerting=OK; print: sent")
    );
}

#[test]
fn the_binary_prints_what_print_is_sent_and_logs_the_line() {
    let h = Host::new();
    h.at(85);
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "No rush, but something needs a look:\nThe test host's disk is 85% full. See `df -h /`.\n"
    );
    assert_eq!(h.last_log_line(), "WARN disk=WARN alerting=OK; print: sent");
}

#[test]
fn a_second_run_with_nothing_new_sends_nothing() {
    let h = Host::new();
    h.at(85);
    h.run(Mode::Run);
    let (report, sent) = h.run(Mode::Run);
    assert_eq!(sent, Vec::<String>::new());
    assert_eq!(
        report.log_line().unwrap(),
        format!("{AT} WARN disk=WARN alerting=OK; print: no change")
    );
}

#[test]
fn a_missing_state_directory_is_made_owner_only() {
    let h = Host::new();
    h.run(Mode::Run);
    assert_eq!(mode(&h.state()), 0o700);
}

#[test]
fn a_state_directory_others_can_write_is_refused_and_logged() {
    for bits in [0o770, 0o702] {
        let h = Host::new();
        fs::create_dir(h.state()).unwrap();
        fs::set_permissions(h.state(), fs::Permissions::from_mode(bits)).unwrap();
        let (report, _) = h.run(Mode::Run);
        assert_eq!(report.exit(), Exit::NotStarted, "{bits:o}");
        let why = format!(
            "{} can be written by other accounts ({bits:o}); it should be 700",
            h.state().display()
        );
        assert_eq!(report.complaint(), Some(why.clone()));
        // What a health check that greps the log for "alert failed" sees.
        assert_eq!(
            report.log_line().unwrap(),
            format!("{AT} alert failed: couldn't start: {why}")
        );
    }
}

#[test]
fn a_state_directory_that_belongs_to_another_account_is_refused() {
    let h = Host::new();
    let theirs = h.theirs("theirs", true);
    h.config_with_state(&theirs, "");
    let (report, _) = h.run(Mode::Run);
    assert_eq!(report.exit(), Exit::NotStarted);
    assert_eq!(
        report.complaint(),
        Some(format!("{} belongs to another account", theirs.display()))
    );
}

#[test]
fn a_config_that_belongs_to_another_account_is_refused() {
    let h = Host::new();
    let theirs = h.theirs("theirs.toml", false);
    let out = Command::new(env!("CARGO_BIN_EXE_whimbrel"))
        .args(["run", "--config"])
        .arg(&theirs)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stderr(&out),
        format!(
            "whimbrel: {}: it belongs to another account\n",
            theirs.display()
        )
    );
}

#[test]
fn a_config_others_can_write_is_refused() {
    let h = Host::new();
    fs::set_permissions(h.path("config.toml"), fs::Permissions::from_mode(0o620)).unwrap();
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stderr(&out),
        format!(
            "whimbrel: {}: other accounts can write it (620); it should be 600\n",
            h.path("config.toml").display()
        )
    );
    assert!(!h.state().exists());
}

#[test]
fn a_symlink_in_place_of_the_log_is_never_written_through() {
    let h = Host::new();
    fs::write(h.path("target"), "keep me").unwrap();
    symlink(h.path("target"), h.path("log")).unwrap();
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(fs::read_to_string(h.path("target")).unwrap(), "keep me");
    assert!(
        stderr(&out).starts_with("whimbrel: couldn't write the log: "),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_dry_run_says_what_each_channel_would_be_sent_and_changes_nothing() {
    let h = Host::new();
    h.at(92);
    let (report, sent) = h.run(Mode::DryRun);
    assert_eq!(report.exit(), Exit::Ran);
    assert_eq!(
        report.printout(),
        "FAIL disk=FAIL alerting=OK\n\n\
         print would be sent:\nNeeds you soon:\nThe test host's disk is 92% full. See `df -h /`.\n"
    );
    assert_eq!(
        sent,
        Vec::<String>::new(),
        "a dry run sent through the channel"
    );
    assert!(!h.state().exists(), "a dry run made the state directory");
    assert_eq!(report.log_line(), None);
}

#[test]
fn the_binary_prints_a_dry_runs_printout_and_writes_no_log() {
    let h = Host::new();
    h.at(92);
    let out = h.whimbrel("dry-run");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "FAIL disk=FAIL alerting=OK\n\n\
         print would be sent:\nNeeds you soon:\nThe test host's disk is 92% full. See `df -h /`.\n"
    );
    assert_eq!(h.log(), "");
}

#[test]
fn a_dry_run_after_a_run_with_nothing_new_says_so_and_takes_no_lock() {
    let h = Host::new();
    h.at(92);
    h.run(Mode::Run);
    fs::remove_file(h.state().join("lock")).unwrap();
    let before = fs::read(h.state().join("ledger.json")).unwrap();
    let (report, _) = h.run(Mode::DryRun);
    assert_eq!(
        report.printout(),
        "FAIL disk=FAIL alerting=OK\n\nprint: no change since it was last told.\n"
    );
    assert_eq!(fs::read(h.state().join("ledger.json")).unwrap(), before);
    assert!(!h.state().join("lock").exists(), "a dry run made the lock");
}

#[test]
fn a_failed_send_is_logged_as_alert_failed_and_the_run_still_succeeds() {
    let h = Host::new();
    h.config(&format!(
        "[[channel]]\nkind = \"slack\"\nwebhook_file = {:?}\n",
        h.path("no-such-webhook")
    ));
    h.at(85);
    let (report, _) = h.run(Mode::Run);
    assert_eq!(report.exit(), Exit::Ran);
    assert_eq!(
        report.log_line().unwrap(),
        format!(
            "{AT} WARN disk=WARN alerting=WARN; print: sent; \
             slack: alert failed: can't read the Slack webhook file no-such-webhook (entity not found)"
        )
    );
}

#[test]
fn a_channel_that_cant_send_is_reported_through_the_others() {
    let h = Host::new();
    h.config(&format!(
        "[[channel]]\nkind = \"slack\"\nwebhook_file = {:?}\n",
        h.path("no-such-webhook")
    ));
    let (report, sent) = h.run(Mode::Run);
    let sentence = format!(
        "Alerts can't get to slack: can't read the Slack webhook file no-such-webhook \
         (entity not found). See `whimbrel dry-run --config {}`.",
        h.path("config.toml").display()
    );
    assert_eq!(
        sent,
        [format!("No rush, but something needs a look:\n{sentence}")]
    );
    assert_eq!(
        whimbrel::sentence::breaks("alerting", &sentence),
        Vec::<String>::new()
    );
    let line = report.log_line().unwrap();
    assert!(
        line.starts_with(&format!(
            "{AT} WARN disk=OK alerting=WARN; print: sent; slack: alert failed"
        )),
        "{line}"
    );
    // Fixed, it says so.
    let hook = h.path("no-such-webhook");
    fs::write(
        &hook,
        format!("https://hooks.slack.com/services/{}\n", "T0/B0/x"),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o600)).unwrap();
    let (report, _) = h.run(Mode::DryRun);
    assert!(
        report.printout().starts_with("OK disk=OK alerting=OK\n"),
        "{}",
        report.printout()
    );
}

#[test]
fn with_no_channels_there_is_nothing_to_report_alerting_on() {
    let h = Host::new();
    let cfg = fs::read_to_string(h.path("config.toml")).unwrap();
    fs::write(
        h.path("config.toml"),
        cfg.replace("[[channel]]\nkind = \"print\"\n", ""),
    )
    .unwrap();
    let (report, _) = h.run(Mode::DryRun);
    assert_eq!(report.printout(), "OK disk=OK\n");
}

#[test]
fn a_config_whose_checks_are_refused_leaves_no_state() {
    let h = Host::new();
    for (extra, says) in [
        (
            "[[check]]\nkind = \"smoke\"\n",
            "check 2 (smoke): there's no check kind \"smoke\"",
        ),
        (
            "[[check]]\nkind = \"disk\"\npath = \"/\"\nsecret = \"hunter2\"\n",
            "check 2 (disk): unknown field `secret`, expected one of `path`, `warn`, `fail`, \
             `suspects`, `df`, `du`",
        ),
        (
            "[[check]]\nkind = \"disk\"\npath = \"/d\"\n",
            "check 2 (disk): another check has the key \"disk\"",
        ),
    ] {
        h.config(extra);
        let (report, _) = h.run(Mode::Run);
        assert_eq!(report.exit(), Exit::NotStarted, "{extra}");
        assert_eq!(report.complaint(), Some(says.to_string()), "{extra}");
        assert!(!h.state().exists(), "{extra} touched the state directory");
    }
}

#[test]
fn a_held_lock_stops_a_second_run_and_logs_that_it_was_skipped() {
    let h = Host::new();
    fs::create_dir(h.state()).unwrap();
    fs::set_permissions(h.state(), fs::Permissions::from_mode(0o700)).unwrap();
    h.at(92);
    let dir = StateDir::new(h.state());
    let _held = dir.lock().unwrap().unwrap();
    let (report, sent) = h.run(Mode::Run);
    assert_eq!(report.exit(), Exit::Ran);
    assert_eq!(report.ended, Ended::LockedOut(h.state().join("lock")));
    assert_eq!(sent, Vec::<String>::new());
    assert_eq!(
        report.complaint(),
        Some(format!("another run holds {}/lock", h.state().display()))
    );
    assert_eq!(
        report.log_line().unwrap(),
        format!(
            "{AT} skipped: another run holds {}/lock",
            h.state().display()
        )
    );
}

#[test]
fn an_unreadable_ledger_is_set_aside_and_every_channel_is_told() {
    let h = Host::new();
    h.run(Mode::Run);
    fs::write(h.state().join("ledger.json"), "{ not json").unwrap();
    h.at(92);
    let (report, sent) = h.run(Mode::Run);
    assert_eq!(report.exit(), Exit::Ran);
    assert_eq!(
        sent,
        [
            "I lost track of what I'd told you, so here's everything open now:\n\
          The test host's disk is 92% full. See `df -h /`."
        ]
    );
    let aside: Vec<_> = fs::read_dir(h.state())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("ledger.json.corrupt-"))
        .collect();
    assert_eq!(aside.len(), 1);
    assert_eq!(
        fs::read_to_string(h.state().join(&aside[0])).unwrap(),
        "{ not json"
    );
    assert_eq!(
        report.log_line().unwrap(),
        format!(
            "{AT} FAIL disk=FAIL alerting=OK; print: sent; ledger lost: set aside an unreadable \
             ledger as {}, and every channel is told",
            h.state().join(&aside[0]).display()
        )
    );
}

#[test]
fn a_dry_run_leaves_an_unreadable_ledger_where_it_is() {
    let h = Host::new();
    h.run(Mode::Run);
    fs::write(h.state().join("ledger.json"), "{ not json").unwrap();
    let (report, _) = h.run(Mode::DryRun);
    assert_eq!(report.exit(), Exit::NotStarted);
    assert_eq!(
        fs::read_to_string(h.state().join("ledger.json")).unwrap(),
        "{ not json"
    );
    assert_eq!(report.log_line(), None, "a dry run would write the log");
}

#[test]
fn a_config_with_a_webhook_in_it_is_refused_without_printing_it() {
    let h = Host::new();
    h.config(
        "[[channel]]\nkind = \"slack\"\nwebhook = \"https://hooks.slack.com/services/T/B/sekrit\"\n",
    );
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stderr(&out),
        format!(
            "whimbrel: {}: it holds a Slack webhook URL. Put the URL in a file only root can \
             read, and name that file with webhook_file.\n",
            h.path("config.toml").display()
        )
    );
    assert!(!h.state().exists());
}

#[test]
fn two_channels_with_one_name_are_refused() {
    let h = Host::new();
    h.config("[[channel]]\nkind = \"print\"\n");
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stderr(&out),
        format!(
            "whimbrel: {}: two channels are named \"print\"\n",
            h.path("config.toml").display()
        )
    );
}

#[test]
fn a_check_cant_take_the_alerting_key_with_or_without_channels() {
    let h = Host::new();
    let extra = format!(
        "[[check]]\nkind = \"disk\"\nkey = \"alerting\"\npath = \"/\"\ndf = {:?}\n",
        h.path("df")
    );
    h.config(&extra);
    let (with, _) = h.run(Mode::DryRun);
    let cfg = fs::read_to_string(h.path("config.toml")).unwrap();
    fs::write(
        h.path("config.toml"),
        cfg.replace("[[channel]]\nkind = \"print\"\n", ""),
    )
    .unwrap();
    let (without, _) = h.run(Mode::DryRun);
    for report in [with, without] {
        assert_eq!(report.exit(), Exit::NotStarted);
        let why = report.complaint().unwrap();
        assert!(
            why.ends_with(
                ": the key \"alerting\" is whimbrel's own, for its check of the channels"
            ),
            "{why}"
        );
    }
}

#[test]
fn what_a_secret_pattern_matches_never_leaves_in_an_alert() {
    let h = Host::new();
    h.at(85);
    let cfg = fs::read_to_string(h.path("config.toml")).unwrap();
    fs::write(
        h.path("config.toml"),
        format!("{cfg}\n[secret_patterns]\npatterns = ['[0-9]+%']\n"),
    )
    .unwrap();
    let (_, sent) = h.run(Mode::Run);
    assert_eq!(
        sent,
        [
            "No rush, but something needs a look:\nThe test host's disk is [redacted] full. \
          See `df -h /`."
        ]
    );
}

#[test]
fn a_secret_pattern_that_wont_compile_is_refused_without_repeating_it() {
    let h = Host::new();
    let cfg = fs::read_to_string(h.path("config.toml")).unwrap();
    fs::write(
        h.path("config.toml"),
        format!("{cfg}\n[secret_patterns]\npatterns = ['(sekrit']\n"),
    )
    .unwrap();
    let out = h.whimbrel("dry-run");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out)
            .ends_with(": secret_patterns.patterns: pattern 1 isn't one whimbrel can use\n"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("sekrit"));
}

#[test]
fn the_report_is_rendered_while_the_run_still_holds_the_lock() {
    let h = Host::new();
    h.run(Mode::Run);
    let config = h.load();
    let mut kept = Kept::default();
    let mut refs: Vec<&mut dyn Channel> = vec![&mut kept];
    let dir = StateDir::new(h.state());
    let held_while_rendering = run(
        &config,
        &h.path("config.toml"),
        "whimbrel",
        Mode::Run,
        NOW,
        &mut refs,
        |_| dir.lock().unwrap().is_none(),
    );
    assert!(
        held_while_rendering,
        "the lock was free while the report was rendered"
    );
    assert!(dir.lock().unwrap().is_some(), "the lock outlived the run");
}
