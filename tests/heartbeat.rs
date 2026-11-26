//! The heartbeat through the binary, against the stand-in curl: a ping after every run that
//! completes, carrying the worst level alone, none after one that doesn't, and a ping that fails
//! never failing the run or holding back an alert.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use whimbrel::StateDir;
use whimbrel::config::Config;

mod common;

use common::curl::Stub;

const URL: &str = "https://hc.example.net/ping/hb-sekrit-5e1f";

struct Host {
    stub: Stub,
}

impl Host {
    /// A disk check at `percent`, the print channel, and a heartbeat whose URL file holds
    /// [`URL`], with curl the stand-in.
    fn new(percent: u32) -> Self {
        let h = Host { stub: Stub::new() };
        common::stub(h.stub.dir.path(), "df", common::DF);
        common::df_at(h.stub.dir.path(), percent);
        h.stub.secret("heartbeat-url", URL);
        h.config(&format!(
            "[heartbeat]\nurl_file = {:?}\n",
            h.path("heartbeat-url")
        ));
        h
    }

    fn path(&self, name: &str) -> PathBuf {
        self.stub.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.path("state")
    }

    fn config(&self, extra: &str) {
        fs::write(
            self.path("config.toml"),
            format!(
                "host = \"the test host\"\nstate_dir = {:?}\nlog_file = {:?}\ncurl = {:?}\n\
                 [[check]]\nkind = \"disk\"\npath = \"/\"\ndf = {:?}\n\
                 [[channel]]\nkind = \"print\"\n{extra}",
                self.state(),
                self.path("log"),
                self.stub.curl().program,
                self.path("df"),
            ),
        )
        .unwrap();
    }

    fn whimbrel(&self, command: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_whimbrel"))
            .args([command, "--config"])
            .arg(self.path("config.toml"))
            .output()
            .unwrap()
    }

    /// The log's last line, less its timestamp.
    fn last_log_line(&self) -> String {
        let log = fs::read_to_string(self.path("log")).unwrap_or_default();
        let line = log.lines().last().unwrap_or("");
        line.split_once(' ')
            .unwrap_or_else(|| panic!("no timestamped line in the log: {log:?}"))
            .1
            .to_string()
    }

    /// Forget the last ping, so the next run's can be told apart.
    fn forget_ping(&self) {
        for f in ["args", "stdin"] {
            let _ = fs::remove_file(self.path(f));
        }
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn a_run_pings_the_url_from_its_file_with_the_status_alone() {
    let h = Host::new(85);
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.stub.config("url"), URL);
    // The whole body: no alert text, no host, no check.
    assert_eq!(h.stub.body(), serde_json::json!({ "status": "WARN" }));
    assert!(!h.stub.args().contains("hb-sekrit"), "{}", h.stub.args());
    // A ping that went through adds nothing to the line.
    assert_eq!(h.last_log_line(), "WARN disk=WARN alerting=OK; print: sent");
}

#[test]
fn a_run_with_nothing_new_to_say_still_pings() {
    let h = Host::new(92);
    h.whimbrel("run");
    h.forget_ping();
    let out = h.whimbrel("run");
    assert_eq!(stdout(&out), "", "the second run sent an alert");
    assert!(h.stub.called(), "the second run didn't ping");
    assert_eq!(h.stub.body(), serde_json::json!({ "status": "FAIL" }));
    assert_eq!(
        h.last_log_line(),
        "FAIL disk=FAIL alerting=OK; print: no change"
    );
}

#[test]
fn a_dry_run_never_pings() {
    let h = Host::new(85);
    let out = h.whimbrel("dry-run");
    assert_eq!(out.status.code(), Some(0));
    assert!(!h.stub.called(), "a dry run pinged");
}

#[test]
fn a_failed_ping_is_noted_after_the_alerts_and_the_run_still_succeeds() {
    let h = Host::new(85);
    h.stub.answer("500", 0);
    h.stub.reply(&format!("no check at {URL}"));
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        stdout(&out),
        "No rush, but something needs a look:\nThe test host's disk is 85% full. See `df -h /`.\n",
        "the alert didn't go out"
    );
    assert_eq!(
        h.last_log_line(),
        "WARN disk=WARN alerting=OK; print: sent; \
         heartbeat failed: the heartbeat said HTTP 500: \"no check at [redacted]\""
    );
    assert!(h.state().join("ledger.json").exists());
}

#[test]
fn a_reply_that_echoes_only_the_token_is_redacted() {
    let h = Host::new(40);
    h.stub.answer("404", 0);
    h.stub.reply("no check hb-sekrit-5e1f");
    h.whimbrel("run");
    assert_eq!(
        h.last_log_line(),
        "OK disk=OK alerting=OK; print: no change; \
         heartbeat failed: the heartbeat said HTTP 404: \"no check [redacted]\""
    );
}

#[test]
fn a_token_in_a_failed_pings_reply_is_redacted_by_the_secret_patterns() {
    let h = Host::new(40);
    let token = common::token();
    h.stub.answer("500", 0);
    h.stub.reply(&format!("echoing {token}"));
    h.whimbrel("run");
    assert_eq!(
        h.last_log_line(),
        "OK disk=OK alerting=OK; print: no change; \
         heartbeat failed: the heartbeat said HTTP 500: \"echoing [redacted]\""
    );
}

#[test]
fn a_ping_that_hangs_is_cut_off_and_the_run_still_finishes() {
    let h = Host::new(40);
    // Past curl's 20 s limit, by enough to tell the limit from the sleep's own end.
    fs::write(h.path("sleep"), "40").unwrap();
    let start = Instant::now();
    let out = h.whimbrel("run");
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        h.last_log_line(),
        "OK disk=OK alerting=OK; print: no change; \
         heartbeat failed: nothing from the heartbeat within 20 s"
    );
}

#[test]
fn a_heartbeat_that_cant_connect_or_read_its_file_says_why_without_the_url() {
    let h = Host::new(40);
    h.stub.answer("000", 7);
    h.whimbrel("run");
    assert_eq!(
        h.last_log_line(),
        "OK disk=OK alerting=OK; print: no change; \
         heartbeat failed: couldn't connect to the heartbeat"
    );
    fs::remove_file(h.path("heartbeat-url")).unwrap();
    h.forget_ping();
    h.whimbrel("run");
    assert_eq!(
        h.last_log_line(),
        "OK disk=OK alerting=OK; print: no change; \
         heartbeat failed: can't read the heartbeat URL file heartbeat-url (entity not found)"
    );
    assert!(!h.stub.called());
}

#[test]
fn a_run_that_cant_start_doesnt_ping_and_logs_as_before() {
    let h = Host::new(85);
    fs::create_dir(h.state()).unwrap();
    fs::set_permissions(h.state(), fs::Permissions::from_mode(0o770)).unwrap();
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(!h.stub.called(), "a run that couldn't start pinged");
    assert_eq!(
        h.last_log_line(),
        format!(
            "alert failed: couldn't start: {} can be written by other accounts (770); it should \
             be 700",
            h.state().display()
        )
    );
}

#[test]
fn a_locked_out_run_doesnt_ping_and_logs_a_line_no_failure_watch_matches() {
    let h = Host::new(92);
    fs::create_dir(h.state()).unwrap();
    fs::set_permissions(h.state(), fs::Permissions::from_mode(0o700)).unwrap();
    let dir = StateDir::new(h.state());
    let _held = dir.lock().unwrap().unwrap();
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "");
    assert!(!h.stub.called(), "a locked-out run pinged");
    let line = h.last_log_line();
    assert_eq!(
        line,
        format!("skipped: another run holds {}/lock", h.state().display())
    );
    for watched in ["alert failed", "fail", "couldn't", "error"] {
        assert!(!line.to_lowercase().contains(watched), "{line}");
    }
}

#[test]
fn a_run_that_cant_save_its_ledger_doesnt_ping() {
    let h = Host::new(85);
    fs::create_dir_all(h.state().join(".ledger.json.tmp/in-the-way")).unwrap();
    fs::set_permissions(h.state(), fs::Permissions::from_mode(0o700)).unwrap();
    let out = h.whimbrel("run");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        !h.stub.called(),
        "a run that couldn't save its ledger pinged"
    );
    let line = h.last_log_line();
    assert!(
        line.starts_with("WARN disk=WARN alerting=OK; print: sent; couldn't save the ledger: "),
        "{line}"
    );
    assert!(!line.contains("heartbeat"), "{line}");
}

/// Written out, so the wording is held here and not taken from the code.
const URL_INLINE: &str = "it holds a heartbeat URL. Put the URL in a file only root can read, \
                          and name that file with url_file.";

#[test]
fn a_heartbeat_url_in_the_config_is_refused_without_repeating_it() {
    let base = "host = \"h\"\nstate_dir = \"/s\"\n";
    for table in [
        "[heartbeat]\nurl = \"https://hc.example.net/ping/hb-sekrit\"\n",
        "[heartbeat]\nurl_file = \"https://hc.example.net/ping/hb-sekrit\"\n",
        // An escape, which only the parsed value shows.
        "[heartbeat]\nurl_file = \"https\\u003a//hc.example.net/ping/hb-sekrit\"\n",
    ] {
        let why = Config::parse(&format!("{base}{table}"))
            .unwrap_err()
            .to_string();
        assert_eq!(why, URL_INLINE, "{table}");
    }
    let ok = Config::parse(&format!(
        "{base}[heartbeat]\nurl_file = \"/etc/whimbrel/hb\"\n"
    ));
    assert!(ok.unwrap().heartbeat.is_some());
}
