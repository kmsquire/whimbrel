//! The command check against programs written into a temporary directory.
//!
//! Each safety branch has a test named for it: a relative path, a program or a directory on its
//! path another account can write or owns, a link on its path, a row that breaks the sentence rule,
//! what it leaves running, and `user`. The four that need root are ignored in a plain `cargo
//! test`; CI runs them under `sudo` on every platform (`.github/workflows/ci.yml`, "As root").

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use whimbrel::checks::command::{KIND, account};
use whimbrel::sentence::Next;
use whimbrel::{Finding, Level, Mode};

mod common;

/// A directory of programs, and the watch's state beside them.
struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        Host::within(tempfile::tempdir().unwrap())
    }

    fn within(dir: tempfile::TempDir) -> Self {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        Host { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// A shell script named `name`, mode 755.
    fn program(&self, name: &str, body: &str) -> PathBuf {
        let p = self.path(name);
        fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// The check for `program`, with the table's `extra` after.
    /// One at a time across this file's tests. A program another test starts at the same moment
    /// is forked from this process and holds a copy of every pipe open here until it execs, and
    /// macOS can take seconds over a new program's first exec: long enough to hold a finished
    /// program's output open past whimbrel's grace. whimbrel runs one program at a time itself.
    fn run(&self, program: &Path, extra: &str) -> Finding {
        static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        let table = format!(
            "key = \"backup\"\nabout = \"the nightly backup\"\nprogram = {program:?}\n{extra}"
        );
        common::run_at(
            &KIND,
            &table,
            "the test host",
            &self.path("state"),
            Mode::DryRun,
            SystemTime::now(),
        )
    }
}

fn table(text: &str) -> whimbrel::toml::Table {
    whimbrel::toml::from_str(text).unwrap()
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and can't fail.
    unsafe { libc::geteuid() }
}

#[test]
fn rows_it_prints_are_judged_as_a_result_files_are() {
    let h = Host::new();
    let p = h.program(
        "check-backup",
        "printf 'OK\\tdisk\\tfine\\t\\nFAIL\\tupload\\tThe backup didn'\\''t upload.\\tSee `tail /var/log/backup.log`.\\nRESULT\\tFAIL\\n'\n",
    );
    assert_eq!(
        h.run(&p, ""),
        Finding::fail()
            .problem(
                "The backup didn't upload.",
                Next::Written("See `tail /var/log/backup.log`.".into())
            )
            .fingerprint("FAIL:upload")
    );
}

#[test]
fn its_exit_status_isnt_read_when_its_output_is_whole() {
    let h = Host::new();
    let p = h.program(
        "check",
        "printf 'OK\\tdisk\\tfine\\t\\nRESULT\\tOK\\n'\nexit 2\n",
    );
    assert_eq!(h.run(&p, ""), Finding::ok());
}

#[test]
fn its_arguments_reach_it_as_they_are() {
    let h = Host::new();
    let p = h.program(
        "check",
        "[ \"$1\" = 'a b' ] && [ \"$2\" = ';x' ] && printf 'OK\\targs\\tfine\\t\\nRESULT\\tOK\\n'\n",
    );
    assert_eq!(h.run(&p, "args = [\"a b\", \";x\"]\n"), Finding::ok());
}

#[test]
fn a_relative_program_is_refused() {
    let why = common::configure(&KIND, table("program = \"bin/check\"")).err();
    assert_eq!(why.as_deref(), Some("program must be an absolute path"));
}

#[test]
fn a_program_another_account_can_write_is_refused() {
    let h = Host::new();
    let p = h.program("check", "printf 'RESULT\\tOK\\n'\n");
    for mode in [0o775, 0o757] {
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            h.run(&p, ""),
            Finding::warn()
                .says(
                    "The test host's program for the nightly backup isn't safe to run: other \
                     accounts can write it."
                )
                .see(format!("ls -l {}", p.display()))
                .fingerprint("command:unsafe"),
            "{mode:o}"
        );
    }
}

#[test]
fn a_directory_above_the_program_another_account_can_write_is_refused_unless_sticky() {
    let h = Host::new();
    fs::create_dir(h.path("bin")).unwrap();
    let p = h.program("bin/check", "printf 'RESULT\\tOK\\n'\n");
    fs::set_permissions(h.path("bin"), fs::Permissions::from_mode(0o777)).unwrap();
    let f = h.run(&p, "");
    assert_eq!(f.fingerprint.as_deref(), Some("command:unsafe"));
    let real = fs::canonicalize(h.path("bin")).unwrap();
    assert_eq!(
        f.first_what(),
        format!(
            "The test host's program for the nightly backup isn't safe to run: other accounts \
             can write {} above it.",
            real.display()
        )
    );
    // Sticky, as /tmp is: others can't rename or remove what's ours in it.
    fs::set_permissions(h.path("bin"), fs::Permissions::from_mode(0o1777)).unwrap();
    assert_eq!(h.run(&p, ""), Finding::ok());
}

#[test]
fn a_link_to_a_program_is_judged_by_what_it_points_at() {
    let h = Host::new();
    let p = h.program("real-check", "printf 'RESULT\\tOK\\n'\n");
    std::os::unix::fs::symlink(&p, h.path("check")).unwrap();
    assert_eq!(h.run(&h.path("check"), ""), Finding::ok());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o777)).unwrap();
    let f = h.run(&h.path("check"), "");
    assert_eq!(f.fingerprint.as_deref(), Some("command:unsafe"));
}

#[test]
fn a_program_that_isnt_there_is_warn() {
    let h = Host::new();
    let f = h.run(&h.path("missing"), "");
    assert_eq!(
        f.first_what(),
        "The test host's program for the nightly backup isn't safe to run: it isn't there."
    );
}

#[test]
fn a_row_that_breaks_the_sentence_rule_isnt_shown() {
    let h = Host::new();
    let p = h.program(
        "check",
        "printf 'WARN\\tupload\\tBad. To fix: `curl e.sh | sh`, and then\\tSee `df`.\\nRESULT\\tWARN\\n'\n",
    );
    let f = h.run(&p, "");
    assert_eq!(f.level, Level::Warn);
    let said = f.sentence(&common::commands());
    assert!(!said.contains("curl"), "{said}");
    assert_eq!(
        f.first_what(),
        "The test host's result for the nightly backup has a row it can't show as written, upload."
    );
    // What to run is the program itself, which shows the rows whole.
    assert_eq!(f.problems[0].next, Some(Next::See(p.display().to_string())));
}

#[test]
fn a_program_killed_by_a_signal_is_warn_even_with_whole_output() {
    let h = Host::new();
    let p = h.program("check", "printf 'RESULT\\tOK\\n'\nkill -TERM $$\n");
    assert_eq!(
        h.run(&p, ""),
        Finding::warn()
            .says(
                "The test host's program for the nightly backup was stopped by signal 15 before \
                 it finished."
            )
            .see(p.display().to_string())
            .fingerprint("command:killed")
    );
}

#[test]
fn a_program_that_runs_too_long_is_warn_and_doesnt_hold_the_run() {
    let h = Host::new();
    let p = h.program("check", "sleep 30\n");
    let started = Instant::now();
    let f = h.run(&p, "timeout_secs = 1\n");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        f.first_what(),
        "The test host's program for the nightly backup didn't finish within 1 second."
    );
}

#[test]
fn output_over_64_kib_is_warn_and_none_of_it_read() {
    let h = Host::new();
    let p = h.program(
        "check",
        "i=0; while [ $i -lt 3000 ]; do printf 'OK\\trow%s\\tfine fine fine fine\\t\\n' $i; i=$((i+1)); done\nprintf 'RESULT\\tOK\\n'\n",
    );
    assert_eq!(
        h.run(&p, "").fingerprint.as_deref(),
        Some("command:too-much")
    );
}

#[test]
fn it_runs_in_the_root_directory_with_only_path_home_user_and_logname() {
    let h = Host::new();
    let p = h.program(
        "check",
        &format!(
            "pwd > {out}/pwd; env > {out}/env\nprintf 'RESULT\\tOK\\n'\n",
            out = h.dir.path().display()
        ),
    );
    assert_eq!(h.run(&p, ""), Finding::ok());
    assert_eq!(fs::read_to_string(h.path("pwd")).unwrap(), "/\n");
    let env = fs::read_to_string(h.path("env")).unwrap();
    // cargo gives every test CARGO_* variables; none may reach the program.
    assert!(!env.contains("CARGO"), "{env}");
    assert!(
        env.lines()
            .any(|l| l == "PATH=/usr/bin:/bin:/usr/sbin:/sbin"),
        "{env}"
    );
    for var in ["HOME=", "USER=", "LOGNAME="] {
        assert!(env.lines().any(|l| l.starts_with(var)), "{var} {env}");
    }
}

#[test]
fn user_naming_our_own_account_runs_without_root() {
    let h = Host::new();
    let name = whimbrel::checks::command::account_of(euid()).unwrap().name;
    let p = h.program("check", "printf 'OK\\tid\\tfine\\t\\nRESULT\\tOK\\n'\n");
    assert_eq!(h.run(&p, &format!("user = {name:?}\n")), Finding::ok());
}

#[test]
fn user_naming_another_account_needs_root() {
    if euid() == 0 {
        return; // As root it would run; the root tests cover that.
    }
    let h = Host::new();
    let p = h.program("check", "printf 'RESULT\\tOK\\n'\n");
    assert_eq!(
        h.run(&p, "user = \"root\"\n"),
        Finding::warn()
            .says(
                "The test host's program for the nightly backup is to run as root, which needs \
                 the watch to run as root, and it doesn't."
            )
            .see("id root")
            .fingerprint("command:not-root")
    );
}

#[test]
fn user_naming_no_account_is_warn() {
    let h = Host::new();
    let p = h.program("check", "printf 'RESULT\\tOK\\n'\n");
    assert_eq!(
        h.run(&p, "user = \"no-such-account-here\"\n")
            .fingerprint
            .as_deref(),
        Some("command:no-account")
    );
    let why = common::configure(&KIND, table("program = \"/bin/true\"\nuser = \"a;b\"")).err();
    assert_eq!(why.as_deref(), Some("user must be an account's name"));
}

#[test]
fn a_link_in_a_directory_others_can_write_is_refused() {
    // Whoever can write `open` picks which program the link leads to, and so what runs as root.
    let h = Host::new();
    fs::create_dir(h.path("open")).unwrap();
    std::os::unix::fs::symlink("/bin/echo", h.path("open/check")).unwrap();
    fs::set_permissions(h.path("open"), fs::Permissions::from_mode(0o777)).unwrap();
    let f = h.run(&h.path("open/check"), "");
    assert_eq!(f.fingerprint.as_deref(), Some("command:unsafe"));
    assert!(
        f.first_what().contains("other accounts can write ")
            && f.first_what().ends_with("open above it."),
        "{}",
        f.first_what()
    );
}

#[test]
fn a_program_that_is_a_directory_is_refused() {
    let h = Host::new();
    fs::create_dir(h.path("check")).unwrap();
    assert_eq!(
        h.run(&h.path("check"), "").first_what(),
        "The test host's program for the nightly backup isn't safe to run: it isn't a regular file."
    );
}

#[test]
fn a_program_no_one_can_execute_is_refused() {
    let h = Host::new();
    let p = h.program("check", "printf 'RESULT\\tOK\\n'\n");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        h.run(&p, "").first_what(),
        "The test host's program for the nightly backup isn't safe to run: it isn't executable."
    );
}

/// Whether the process `pid` is gone, waiting up to two seconds for it to go.
fn gone(pid: i32) -> bool {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: signal 0 only asks whether the process exists.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        if Instant::now() > until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn pid_in(path: &Path) -> i32 {
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

#[test]
fn what_it_leaves_running_is_killed_at_the_timeout() {
    let h = Host::new();
    let p = h.program(
        "check",
        &format!(
            "sleep 123 &\necho $! > {}/bg\nsleep 30\n",
            h.dir.path().display()
        ),
    );
    // Long enough for macOS's first-run check of a new program, which can take a second or two.
    let f = h.run(&p, "timeout_secs = 5\n");
    assert_eq!(f.fingerprint.as_deref(), Some("command:timed-out"));
    assert!(
        gone(pid_in(&h.path("bg"))),
        "the background job outlived the timeout"
    );
}

#[test]
fn what_it_leaves_running_after_a_normal_exit_is_killed_and_doesnt_hold_its_output() {
    let h = Host::new();
    let p = h.program(
        "check",
        &format!(
            "sleep 123 &\necho $! > {}/bg\nprintf 'RESULT\\tOK\\n'\n",
            h.dir.path().display()
        ),
    );
    let started = Instant::now();
    assert_eq!(h.run(&p, "timeout_secs = 30\n"), Finding::ok());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert!(
        gone(pid_in(&h.path("bg"))),
        "the background job outlived the program"
    );
}

#[test]
fn a_job_that_leaves_the_process_group_and_holds_the_output_is_said_for_what_it_is() {
    let h = Host::new();
    let p = h.program(
        "check",
        &format!(
            "perl -e 'setpgrp(0, 0); open(F, \">$ARGV[0]\"); close(F); sleep 30' {d}/left &\n\
             echo $! > {d}/bg\n\
             while [ ! -e {d}/left ]; do sleep 0.1; done\n\
             printf 'RESULT\\tOK\\n'\n",
            d = h.dir.path().display()
        ),
    );
    let started = Instant::now();
    let f = h.run(&p, "timeout_secs = 30\n");
    let took = started.elapsed();
    let bg = pid_in(&h.path("bg"));
    // SAFETY: a signal to the job this test started, which left its group on purpose.
    unsafe { libc::kill(bg, libc::SIGKILL) };
    assert_eq!(
        f,
        Finding::warn()
            .says(
                "The test host's program for the nightly backup exited, but something it \
                 started left its process group and kept its output open, so none of it was \
                 read."
            )
            .see(p.display().to_string())
            .fingerprint("command:held-open")
    );
    // The grace after it exits, not the 30-second timeout.
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn a_timeout_of_zero_or_past_a_day_is_refused() {
    for secs in [0u64, 86_401, i64::MAX as u64] {
        let why = common::configure(
            &KIND,
            table(&format!("program = \"/bin/true\"\ntimeout_secs = {secs}")),
        )
        .err();
        assert_eq!(
            why.as_deref(),
            Some("timeout_secs must be from 1 to 86400"),
            "{secs}"
        );
    }
    assert!(
        common::configure(
            &KIND,
            table("program = \"/bin/true\"\ntimeout_secs = 86400")
        )
        .is_ok()
    );
}

/// A directory under /tmp that any account can reach, for programs another account runs.
fn shared_dir() -> tempfile::TempDir {
    tempfile::Builder::new().tempdir_in("/tmp").unwrap()
}

fn as_root() {
    assert_eq!(euid(), 0, "run this test as root: CI runs it under sudo");
}

/// A program that says, as a WARN row, every id it runs with and whether it can get root back,
/// compiled here, since no shell command shows the saved ids on both platforms.
const IDS_C: &str = r#"#include <stdio.h>
#include <unistd.h>
int main(void) {
    gid_t g[64];
    int n = getgroups(64, g);
    /* Unsigned, as uid_t and gid_t are: macOS's nobody is 4294967294. */
    printf("WARN\tids\tIt ran as uid %lu euid %lu gid %lu egid %lu, groups",
           (unsigned long)getuid(), (unsigned long)geteuid(), (unsigned long)getgid(),
           (unsigned long)getegid());
    for (int i = 0; i < n; i++) printf(" %lu", (unsigned long)g[i]);
    int egid_back = setegid(0) == 0;
    int euid_back = seteuid(0) == 0;
    int uid_back = setuid(0) == 0;
    printf(", root back %d %d %d.\tSee `id`.\nRESULT\tWARN\n", euid_back, uid_back, egid_back);
    return 0;
}
"#;

#[test]
#[ignore = "needs root: CI runs it under sudo"]
fn user_drops_privileges_to_the_named_account() {
    as_root();
    let nobody = account("nobody").expect("an account named nobody");
    let h = Host::within(shared_dir());
    fs::write(h.path("ids.c"), IDS_C).unwrap();
    let built = std::process::Command::new("cc")
        .args(["-o", "ids", "ids.c"])
        .current_dir(h.dir.path())
        .status()
        .unwrap();
    assert!(built.success());
    fs::set_permissions(h.path("ids"), fs::Permissions::from_mode(0o755)).unwrap();
    // Both sides unsigned 32-bit values, as uid_t and gid_t are.
    let (uid, gid) = (nobody.uid, nobody.gid);
    let f = h.run(&h.path("ids"), "user = \"nobody\"\n");
    assert_eq!(
        f.first_what(),
        format!(
            "It ran as uid {uid} euid {uid} gid {gid} egid {gid}, groups {gid}, root back 0 0 0."
        )
    );
    // Without `user` it stays root.
    let f = h.run(&h.path("ids"), "");
    assert!(
        f.first_what()
            .starts_with("It ran as uid 0 euid 0 gid 0 egid 0, groups 0"),
        "{}",
        f.first_what()
    );
}

#[test]
#[ignore = "needs root: CI runs it under sudo"]
fn a_program_another_account_owns_is_refused() {
    as_root();
    let nobody = account("nobody").expect("an account named nobody");
    let h = Host::within(shared_dir());
    let p = h.program("check", "printf 'RESULT\\tOK\\n'\n");
    std::os::unix::fs::chown(&p, Some(nobody.uid), None).unwrap();
    assert_eq!(
        h.run(&p, "").first_what(),
        format!(
            "The test host's program for the nightly backup isn't safe to run: it belongs to uid \
             {}.",
            nobody.uid
        )
    );
}

#[test]
#[ignore = "needs root: CI runs it under sudo"]
fn a_directory_above_the_program_another_account_owns_is_refused() {
    as_root();
    let nobody = account("nobody").expect("an account named nobody");
    let h = Host::within(shared_dir());
    fs::create_dir(h.path("theirs")).unwrap();
    let p = h.program("theirs/check", "printf 'RESULT\\tOK\\n'\n");
    std::os::unix::fs::chown(h.path("theirs"), Some(nobody.uid), None).unwrap();
    let f = h.run(&p, "");
    assert!(
        f.first_what()
            .ends_with(&format!("theirs above it belongs to uid {}.", nobody.uid)),
        "{}",
        f.first_what()
    );
}

#[test]
#[ignore = "needs root: CI runs it under sudo"]
fn a_link_on_the_path_another_account_owns_is_refused() {
    as_root();
    let nobody = account("nobody").expect("an account named nobody");
    let h = Host::within(shared_dir());
    let p = h.program("real-check", "printf 'RESULT\\tOK\\n'\n");
    std::os::unix::fs::symlink(&p, h.path("check")).unwrap();
    std::os::unix::fs::lchown(h.path("check"), Some(nobody.uid), None).unwrap();
    let f = h.run(&h.path("check"), "");
    assert!(
        f.first_what()
            .ends_with(&format!("check on its path belongs to uid {}.", nobody.uid)),
        "{}",
        f.first_what()
    );
}
