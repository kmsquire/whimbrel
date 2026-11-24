//! The result-file check against files in a temporary directory, on a clock of the test's own: a
//! check that runs somewhere else leaves its rows there, and this reads them. The file sits in a
//! directory with a space in its name, as macOS's Application Support does, so every command shown has to quote it.
//! How the rows are parsed is tested in rows.rs itself.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use whimbrel::checks::result_file::KIND;
use whimbrel::sentence::Next;
use whimbrel::{Finding, Mode};

mod common;

/// The test's clock, and the file's time unless a test moves it.
const NOW: Duration = Duration::from_secs(1_800_000_000);

const OK_ROWS: &str = "OK\tbackup freshness\t12min old\t\n\
                       OK\tssh\treached the server\t\n\
                       SKIP\tos updates\tnot judged\t\n\
                       RESULT\tOK\n";

const BAD_ROWS: &str = "OK\tssh\treached the server\t\n\
                        FAIL\tapp service\tThe server's app isn't running.\tSee `journalctl -u app`.\n\
                        WARN\tdisk\tThe server's disk is 85% full.\tSee `df -h /`.\n\
                        RESULT\tFAIL\n";

struct Place {
    dir: tempfile::TempDir,
}

impl Place {
    fn new() -> Self {
        let p = Place {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(p.dir.path().join("Shared Results")).unwrap();
        p
    }

    fn file(&self) -> PathBuf {
        self.dir.path().join("Shared Results/replica-health.tsv")
    }

    /// The file's path quoted as a shell word, written out.
    fn quoted(&self) -> String {
        format!("'{}'", self.file().display())
    }

    fn write(&self, rows: &str) {
        fs::write(self.file(), rows).unwrap();
        fs::set_permissions(self.file(), fs::Permissions::from_mode(0o644)).unwrap();
        self.touch(SystemTime::UNIX_EPOCH + NOW);
    }

    fn touch(&self, at: SystemTime) {
        fs::File::options()
            .write(true)
            .open(self.file())
            .unwrap()
            .set_modified(at)
            .unwrap();
    }

    fn me(&self) -> u32 {
        fs::metadata(self.dir.path()).unwrap().uid()
    }

    /// Run with `owner` as the account meant to write it, the table's `extra` after, at NOW.
    fn run_as(&self, owner: u32, extra: &str) -> Finding {
        let table = format!(
            "key = \"replica-health\"\nabout = \"the replica's health\"\npath = {:?}\n\
             owner_uid = {owner}\nmax_age_mins = 90\nrequired_row = \"ssh\"\n{extra}",
            self.file(),
        );
        common::run_at(
            &KIND,
            &table,
            "the backup host",
            self.dir.path(),
            Mode::DryRun,
            SystemTime::UNIX_EPOCH + NOW,
        )
    }

    fn run_with(&self, extra: &str) -> Finding {
        self.run_as(self.me(), extra)
    }

    fn run(&self) -> Finding {
        self.run_with("")
    }

    /// A WARN about the file as a whole, with `ls -l` of it to run.
    fn doubt(&self, what: &str, tag: &str) -> Finding {
        Finding::warn()
            .says(what)
            .see(format!("ls -l {}", self.quoted()))
            .fingerprint(tag)
    }

    /// A WARN about what the file says, with `cat` of it to run.
    fn says_doubt(&self, what: &str, tag: &str) -> Finding {
        Finding::warn()
            .says(what)
            .see(format!("cat {}", self.quoted()))
            .fingerprint(tag)
    }
}

#[test]
fn every_row_ok_or_skipped_is_ok() {
    let p = Place::new();
    p.write(OK_ROWS);
    assert_eq!(p.run(), Finding::ok());
}

#[test]
fn each_bad_row_is_a_problem_as_written_in_file_order_and_the_worst_is_the_level() {
    let p = Place::new();
    p.write(BAD_ROWS);
    assert_eq!(
        p.run(),
        Finding::fail()
            .problem(
                "The server's app isn't running.",
                Next::Written("See `journalctl -u app`.".into())
            )
            .problem(
                "The server's disk is 85% full.",
                Next::Written("See `df -h /`.".into())
            )
            .fingerprint("FAIL:app service\tWARN:disk")
    );
}

#[test]
fn a_row_going_from_warn_to_fail_beside_another_fail_is_news() {
    let p = Place::new();
    p.write(BAD_ROWS);
    let before = p.run().fingerprint;
    p.write(&BAD_ROWS.replace("WARN\tdisk", "FAIL\tdisk"));
    let after = p.run().fingerprint;
    assert_eq!(after.as_deref(), Some("FAIL:app service\tFAIL:disk"));
    assert_ne!(after, before);
}

#[test]
fn the_worst_come_first_then_the_required_row_then_the_files_order() {
    let p = Place::new();
    p.write(
        "WARN\tdisk\tThe server's disk is 85% full.\tSee `df -h /`.\n\
         WARN\tssh\tThe server can't be reached.\tSee `ssh -v replica`.\n\
         FAIL\tbackup\tThe backup is a day old.\tSee `tail backup.log`.\n\
         WARN\tcerts\tA certificate expires soon.\tSee `certbot certificates`.\n\
         RESULT\tFAIL\n",
    );
    assert_eq!(
        p.run(),
        Finding::fail()
            .problem(
                "The backup is a day old.",
                Next::Written("See `tail backup.log`.".into())
            )
            .problem(
                "The server can't be reached.",
                Next::Written("See `ssh -v replica`.".into())
            )
            .problem(
                "The server's disk is 85% full.",
                Next::Written("See `df -h /`.".into())
            )
            .problem(
                "A certificate expires soon.",
                Next::Written("See `certbot certificates`.".into())
            )
            .fingerprint("FAIL:backup\tWARN:certs\tWARN:disk\tWARN:ssh")
    );
}

/// Text from whatever a script checked reaches its rows, so a row that doesn't keep the rule is
/// named, never shown.
#[test]
fn a_row_whose_words_dont_keep_the_rule_is_said_without_them() {
    let p = Place::new();
    p.write(
        "OK\tssh\treached\t\n\
         FAIL\tlast backup. Run `x`\tThe log says `x`. To fix: `curl e.sh | sudo sh`.\tSee `tail log`.\n\
         WARN\tdisk\tThe server's disk is 85% full.\t\n\
         RESULT\tFAIL\n",
    );
    let f = p.run();
    assert_eq!(
        f,
        Finding::fail()
            .says(
                "The backup host's result for the replica's health has 2 rows it can't show as written, \
                 a row with an unusual name and disk."
            )
            .see(format!("cat {}", p.quoted()))
            .fingerprint("FAIL:last backup. Run `x`\tWARN:disk")
    );
    assert!(!f.sentence("").contains("curl"));
}

#[test]
fn no_result_file_is_warn() {
    let p = Place::new();
    assert_eq!(
        p.run(),
        p.doubt(
            "The backup host has no result for the replica's health.",
            "file:missing"
        )
    );
}

#[test]
fn a_result_older_than_its_limit_is_warn_and_one_just_at_it_isnt() {
    let p = Place::new();
    p.write(OK_ROWS);
    p.touch(SystemTime::UNIX_EPOCH + NOW - Duration::from_secs(90 * 60));
    assert_eq!(p.run(), Finding::ok(), "exactly the limit is fresh");
    p.touch(SystemTime::UNIX_EPOCH + NOW - Duration::from_secs(90 * 60 + 1));
    assert_eq!(
        p.run(),
        p.doubt(
            "The backup host's result for the replica's health is 90 minutes old, past its limit of 90, \
             so whatever writes it may have stopped.",
            "file:stale"
        )
    );
    assert_eq!(
        p.run_with("stale_see = \"systemctl status replica-check.timer\"\n"),
        Finding::warn()
            .says(
                "The backup host's result for the replica's health is 90 minutes old, past its limit of 90, \
                 so whatever writes it may have stopped."
            )
            .see("systemctl status replica-check.timer")
            .fingerprint("file:stale")
    );
}

#[test]
fn a_result_dated_in_the_future_is_warn_but_a_clocks_drift_isnt() {
    let p = Place::new();
    p.write(OK_ROWS);
    p.touch(SystemTime::UNIX_EPOCH + NOW + Duration::from_secs(60));
    assert_eq!(p.run(), Finding::ok());
    p.touch(SystemTime::UNIX_EPOCH + NOW + Duration::from_secs(10 * 60));
    assert_eq!(
        p.run(),
        p.doubt(
            "The backup host's result for the replica's health is dated in the future, so its age can't \
             be told.",
            "file:future"
        )
    );
}

#[test]
fn a_result_with_no_result_line_is_warn_never_ok() {
    let p = Place::new();
    p.write("OK\tssh\treached the server\t\n");
    assert_eq!(
        p.run(),
        p.says_doubt(
            "The backup host's result for the replica's health ends before its RESULT line, so whatever \
             wrote it stopped partway.",
            "rows:unfinished"
        )
    );
}

/// The silent break the result-file contract warns of: a writer that renames the row.
#[test]
fn a_result_without_its_required_row_says_it_was_most_likely_renamed() {
    let p = Place::new();
    p.write("OK\tssh reach\treached\t\nRESULT\tOK\n");
    assert_eq!(
        p.run(),
        p.says_doubt(
            "The backup host's result for the replica's health has no ssh row, which it must always have, \
             so its writer has most likely renamed it and none of it can be believed.",
            "rows:no-required-row"
        )
    );
}

#[test]
fn a_skipped_required_row_is_warn_since_a_scheduled_run_never_skips_it() {
    let p = Place::new();
    p.write("SKIP\tssh\tnot checked this run\t\nOK\treplica\trunning\t\nRESULT\tOK\n");
    assert_eq!(
        p.run(),
        Finding::warn()
            .says(
                "The backup host's result for the replica's health skipped its ssh row, which a \
                 scheduled run never should, so most of it wasn't checked."
            )
            .see(format!("cat {}", p.quoted()))
            .fingerprint("SKIP:ssh")
    );
    p.write("OK\tssh\treached\t\nSKIP\tos updates\tnot judged\t\nRESULT\tOK\n");
    assert_eq!(p.run(), Finding::ok(), "a SKIP on any other row is OK");
}

#[test]
fn each_way_a_file_can_be_unreadable_is_said_in_its_own_words() {
    let p = Place::new();
    let w = "The backup host's result for the replica's health";
    for (rows, what, tag) in [
        (
            "OK\tssh\treached\t\nnot a row\nRESULT\tOK\n",
            format!("{w} has a line that isn't a row it can read, line 2."),
            "rows:malformed",
        ),
        (
            "OK\tssh\treached\t\nOK\tssh\tagain\t\nRESULT\tOK\n",
            format!("{w} names a row twice, the second time on line 2."),
            "rows:duplicate",
        ),
        (
            "OK\tssh\treached\t\nRESULT\tOK\nRESULT\tOK\n",
            format!("{w} goes on past its RESULT line, so it may be two runs written together."),
            "rows:past-result",
        ),
        (
            "OK\tssh\treached\t\nRESULT\tFAIL\n",
            format!(
                "{w} ends with RESULT FAIL though its worst row is OK, so it can't be believed."
            ),
            "rows:disagrees",
        ),
    ] {
        p.write(rows);
        assert_eq!(p.run(), p.says_doubt(&what, tag), "{rows:?}");
    }
}

#[test]
fn a_result_that_isnt_text_is_warn() {
    let p = Place::new();
    p.write(OK_ROWS);
    fs::write(p.file(), b"OK\tssh\t\xff\xfe\t\nRESULT\tOK\n").unwrap();
    p.touch(SystemTime::UNIX_EPOCH + NOW);
    assert_eq!(
        p.run(),
        p.says_doubt(
            "The backup host's result for the replica's health isn't text, so none of it can be read.",
            "rows:not-text"
        )
    );
}

/// Its rows are shown as written, so only the account that's meant to write it may.
#[test]
fn a_file_another_account_could_have_written_is_refused_unread() {
    let p = Place::new();
    p.write(BAD_ROWS);
    let unsafe_ = |why: &str| {
        p.doubt(
            &format!(
                "The backup host's result for the replica's health isn't safe to read: {why}."
            ),
            "file:unsafe",
        )
    };
    for mode in [0o664, 0o646] {
        fs::set_permissions(p.file(), fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(p.run(), unsafe_("other accounts can write it"), "{mode:o}");
    }
    fs::set_permissions(p.file(), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        p.run_as(p.me() + 1, ""),
        unsafe_(&format!("it belongs to uid {}", p.me()))
    );
}

#[test]
fn a_file_it_cant_open_is_refused() {
    // A plain file where its folder should be: no account, root included, can open the path.
    let p = Place::new();
    fs::remove_dir(p.dir.path().join("Shared Results")).unwrap();
    fs::write(p.dir.path().join("Shared Results"), "").unwrap();
    assert_eq!(
        p.run(),
        p.doubt(
            "The backup host's result for the replica's health isn't safe to read: it can't be opened.",
            "file:unsafe",
        )
    );
}

#[test]
fn a_symlink_or_a_fifo_in_its_place_is_refused_unread() {
    let p = Place::new();
    let elsewhere = p.dir.path().join("elsewhere.tsv");
    fs::write(&elsewhere, OK_ROWS).unwrap();
    symlink(&elsewhere, p.file()).unwrap();
    assert_eq!(
        p.run(),
        p.doubt(
            "The backup host's result for the replica's health isn't safe to read: it's a link.",
            "file:unsafe"
        )
    );
    fs::remove_file(p.file()).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(p.file())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        p.run(),
        p.doubt(
            "The backup host's result for the replica's health isn't safe to read: it isn't a plain file.",
            "file:unsafe"
        )
    );
}

#[test]
fn a_file_too_big_to_be_a_result_is_refused_unread_and_one_just_at_the_limit_is_read() {
    let p = Place::new();
    let row = "OK\tssh\treached\t\n";
    let fill = 64 * 1024 - row.len() - "RESULT\tOK\n".len() - "OK\tpad\t\t\n".len();
    let exact = format!("{row}OK\tpad\t{}\t\nRESULT\tOK\n", "x".repeat(fill));
    assert_eq!(exact.len(), 64 * 1024);
    p.write(&exact);
    assert_eq!(p.run(), Finding::ok());
    p.write(&"OK\tx\ty\t\n".repeat(20_000));
    assert_eq!(
        p.run(),
        p.doubt(
            "The backup host's result for the replica's health isn't safe to read: it's over 64 KiB.",
            "file:unsafe"
        )
    );
}

#[test]
fn its_table_needs_an_absolute_path_and_defaults_the_rest() {
    let refused = |table: &str| {
        let table: whimbrel::toml::Table = whimbrel::toml::from_str(table).unwrap();
        common::configure(&KIND, table).err().unwrap()
    };
    assert_eq!(
        refused("path = \"rel.tsv\""),
        "path must be an absolute path"
    );
    assert_eq!(
        refused("path = \"/r.tsv\"\nmax_age_mins = 0"),
        "max_age_mins must be at least 1"
    );
    assert_eq!(
        refused("path = \"/r.tsv\"\nrequired_row = \"\""),
        "required_row must name a row"
    );
    // max_age_mins defaults to 90; that owner_uid defaults to root's is tested in the module.
    let p = Place::new();
    p.write(OK_ROWS);
    let mine = format!("path = {:?}\nowner_uid = {}\n", p.file(), p.me());
    let at = |secs: u64| {
        common::run_at(
            &KIND,
            &mine,
            "the backup host",
            p.dir.path(),
            Mode::DryRun,
            SystemTime::UNIX_EPOCH + NOW + Duration::from_secs(secs),
        )
    };
    assert_eq!(at(90 * 60), Finding::ok());
    assert_eq!(at(90 * 60 + 1).fingerprint.as_deref(), Some("file:stale"));
}

/// Thousands of rows it can't show come to one sentence, so the alert stays one a channel takes.
#[test]
fn every_row_it_cant_show_is_said_once_counted_with_a_few_named() {
    let p = Place::new();
    let mut rows = String::from("OK\tssh\treached\t\n");
    for i in 0..3000 {
        rows.push_str(&format!("WARN\tr{i}\tno next\t\n"));
    }
    rows.push_str("RESULT\tWARN\n");
    p.write(&rows);
    let f = p.run();
    assert_eq!(f.problems.len(), 1);
    assert_eq!(
        f.first_what(),
        "The backup host's result for the replica's health has 3000 rows it can't show as written, r0, \
         r1, r2 and 2997 more."
    );
}

#[test]
fn at_most_ten_problems_are_shown_and_the_rest_counted() {
    let p = Place::new();
    let mut rows = String::from("OK\tssh\treached\t\n");
    for i in 0..15 {
        rows.push_str(&format!("WARN\tr{i}\tRow {i} is bad.\tSee `cat r{i}`.\n"));
    }
    rows.push_str("RESULT\tWARN\n");
    p.write(&rows);
    let f = p.run();
    assert_eq!(f.problems.len(), whimbrel::rows::MAX_PROBLEMS + 1);
    assert_eq!(f.problems[9].what, "Row 9 is bad.");
    assert_eq!(
        f.problems[10].what,
        "The backup host's result for the replica's health has 5 more rows gone bad than an alert shows."
    );
    assert_eq!(f.fingerprint.unwrap().split('\t').count(), 15);
}

/// Rows a writer really writes, each shown exactly as written.
#[test]
fn rows_in_every_shape_a_writer_uses_are_shown_as_written() {
    for (what, next) in [
        // A period inside a code span.
        ("The file `a.b. C` is gone.", "See `ls -l /srv`."),
        // A NEXT with no command.
        (
            "The backup is a day old.",
            "See the Backups page in the hosting console.",
        ),
        // Prose before the command.
        (
            "The cache is stale.",
            "To fix: run `systemctl restart cache` as root.",
        ),
        // Prose after the code span.
        (
            "The app isn't running.",
            "See `journalctl -u app` for details.",
        ),
        // A code span holding a semicolon, a comma and quotes.
        (
            "The log has errors.",
            "See `grep -c 'a;b, \"c\"' /var/log/app.log`.",
        ),
        // A single-quoted path with a space, inside a code span.
        ("The report is missing.", "See `ls -l '/srv/my reports'`."),
    ] {
        let p = Place::new();
        p.write(&format!(
            "OK\tssh\tfine\t\nWARN\tcase\t{what}\t{next}\nRESULT\tWARN\n"
        ));
        assert_eq!(
            p.run(),
            Finding::warn()
                .problem(what, Next::Written(next.into()))
                .fingerprint("WARN:case"),
            "{what} {next}"
        );
    }
}

#[test]
fn a_row_named_with_its_time_is_news_each_time() {
    let p = Place::new();
    p.write("WARN\trecovery 10:00\tThe service restarted.\tSee `journalctl -u app`.\nOK\tssh\tfine\t\nRESULT\tWARN\n");
    let first = p.run();
    p.write("WARN\trecovery 11:00\tThe service restarted.\tSee `journalctl -u app`.\nOK\tssh\tfine\t\nRESULT\tWARN\n");
    let second = p.run();
    assert_eq!(first.fingerprint.as_deref(), Some("WARN:recovery 10:00"));
    assert_eq!(second.fingerprint.as_deref(), Some("WARN:recovery 11:00"));
}

#[test]
fn a_missing_file_points_at_stale_see_when_its_set() {
    let p = Place::new();
    assert_eq!(
        p.run_with("stale_see = \"systemctl status replica-check.timer\"\n"),
        Finding::warn()
            .says("The backup host has no result for the replica's health.")
            .see("systemctl status replica-check.timer")
            .fingerprint("file:missing")
    );
}
