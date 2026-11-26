//! The log line's wording, byte for byte, through the binary. Scripts that watch whimbrel grep
//! these lines, for "alert failed" among others, so every kind of line a run writes is pinned
//! here, whole: the timestamp's shape, then every word after it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use whimbrel::StateDir;

mod common;

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new(percent: u32) -> Self {
        let h = Host {
            dir: tempfile::tempdir().unwrap(),
        };
        common::stub(h.dir.path(), "df", common::DF);
        common::df_at(h.dir.path(), percent);
        h.config(true, "[[channel]]\nkind = \"print\"\n");
        h
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.path("state")
    }

    /// The disk check, a log file if `log_file`, then `extra`.
    fn config(&self, log_file: bool, extra: &str) {
        let log = if log_file {
            format!("log_file = {:?}\n", self.path("log"))
        } else {
            String::new()
        };
        fs::write(
            self.path("config.toml"),
            format!(
                "host = \"the test host\"\nstate_dir = {:?}\n{log}\
                 [[check]]\nkind = \"disk\"\npath = \"/\"\ndf = {:?}\n{extra}",
                self.state(),
                self.path("df"),
            ),
        )
        .unwrap();
    }

    fn run(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_whimbrel"))
            .args(["run", "--config"])
            .arg(self.path("config.toml"))
            .output()
            .unwrap()
    }

    fn lines(&self) -> Vec<String> {
        fs::read_to_string(self.path("log"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

/// `line` less its timestamp, which must be `YYYY-MM-DDTHH:MM:SSZ` and a space.
fn words(line: &str) -> &str {
    let (time, rest) = line.split_once(' ').unwrap_or_else(|| panic!("{line:?}"));
    let shape: String = time
        .chars()
        .map(|c| if c.is_ascii_digit() { '9' } else { c })
        .collect();
    assert_eq!(shape, "9999-99-99T99:99:99Z", "{line:?}");
    rest
}

fn only_line(h: &Host) -> String {
    let lines = h.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    words(&lines[0]).to_string()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn path(p: &Path) -> String {
    p.display().to_string()
}

#[test]
fn a_run_that_sends_logs_the_levels_and_sent() {
    let h = Host::new(85);
    h.run();
    assert_eq!(only_line(&h), "WARN disk=WARN alerting=OK; print: sent");
}

#[test]
fn a_run_with_nothing_new_logs_no_change() {
    let h = Host::new(92);
    h.run();
    h.run();
    let lines = h.lines();
    assert_eq!(
        words(&lines[1]),
        "FAIL disk=FAIL alerting=OK; print: no change"
    );
}

#[test]
fn a_run_with_no_channels_logs_the_levels_alone() {
    let h = Host::new(40);
    h.config(true, "");
    h.run();
    assert_eq!(only_line(&h), "OK disk=OK");
}

#[test]
fn a_failed_send_logs_alert_failed_and_why() {
    let h = Host::new(85);
    h.config(
        true,
        &format!(
            "[[channel]]\nkind = \"print\"\n[[channel]]\nkind = \"slack\"\nwebhook_file = {:?}\n",
            h.path("gone")
        ),
    );
    h.run();
    assert_eq!(
        only_line(&h),
        "WARN disk=WARN alerting=WARN; print: sent; \
         slack: alert failed: can't read the Slack webhook file gone (entity not found)"
    );
}

#[test]
fn a_run_that_cant_start_logs_alert_failed_couldnt_start() {
    let h = Host::new(85);
    fs::create_dir(h.state()).unwrap();
    fs::set_permissions(h.state(), fs::Permissions::from_mode(0o770)).unwrap();
    let out = h.run();
    let why = format!(
        "{} can be written by other accounts (770); it should be 700",
        path(&h.state())
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "");
    assert_eq!(stderr(&out), format!("whimbrel: {why}\n"));
    assert_eq!(
        only_line(&h),
        format!("alert failed: couldn't start: {why}")
    );
}

#[test]
fn a_run_locked_out_by_another_says_so_on_stderr_and_exits_0() {
    let h = Host::new(92);
    fs::create_dir(h.state()).unwrap();
    fs::set_permissions(h.state(), fs::Permissions::from_mode(0o700)).unwrap();
    let dir = StateDir::new(h.state());
    let _held = dir.lock().unwrap().unwrap();
    let out = h.run();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "");
    assert_eq!(
        stderr(&out),
        format!("whimbrel: another run holds {}/lock\n", path(&h.state()))
    );
    assert_eq!(
        h.lines(),
        Vec::<String>::new(),
        "a locked-out run logs nothing"
    );
}

#[test]
fn a_lost_ledger_is_a_note_after_the_channels() {
    let h = Host::new(40);
    h.run();
    fs::write(h.state().join("ledger.json"), "{ not json").unwrap();
    common::df_at(h.dir.path(), 92);
    h.run();
    let aside = fs::read_dir(h.state())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| path(p).contains("ledger.json.corrupt-"))
        .unwrap();
    assert_eq!(
        words(&h.lines()[1]),
        format!(
            "FAIL disk=FAIL alerting=OK; print: sent; ledger lost: set aside an unreadable \
             ledger as {}, and every channel is told",
            path(&aside)
        )
    );
}

#[test]
fn a_ledger_that_cant_be_saved_is_a_note_and_exit_1() {
    let h = Host::new(85);
    fs::create_dir_all(h.state().join(".ledger.json.tmp/in-the-way")).unwrap();
    fs::set_permissions(h.state(), fs::Permissions::from_mode(0o700)).unwrap();
    let out = h.run();
    assert_eq!(out.status.code(), Some(1));
    let line = only_line(&h);
    let prefix = format!(
        "WARN disk=WARN alerting=OK; print: sent; couldn't save the ledger: {}: ",
        path(&h.state().join(".ledger.json.tmp"))
    );
    assert!(line.starts_with(&prefix), "{line}");
}

#[test]
fn with_no_log_file_the_line_goes_to_stdout_after_whatever_print_said() {
    let h = Host::new(85);
    h.config(false, "[[channel]]\nkind = \"print\"\n");
    let out = h.run();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let last = stdout.lines().last().unwrap();
    assert_eq!(words(last), "WARN disk=WARN alerting=OK; print: sent");
    assert!(
        stdout.starts_with("No rush, but something needs a look:\n"),
        "{stdout}"
    );
}
