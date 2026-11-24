//! What the integration tests share: stand-in programs, each a shared script linked into a test's
//! own directory, and running one check the way a real run runs it.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Link the script `body` into `dir` as `name`, and return the link. The script finds the test's
/// directory from `$0`.
///
/// Every test gets the same file behind its link, run once before any test's clock starts. macOS
/// checks each new executable on its first run, and one check per test, under parallel tests,
/// takes long enough to trip their timeouts.
pub fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    static SCRIPTS: OnceLock<(tempfile::TempDir, Mutex<HashMap<String, PathBuf>>)> =
        OnceLock::new();
    let (home, made) = SCRIPTS.get_or_init(|| (tempfile::tempdir().unwrap(), Mutex::default()));
    let script = made
        .lock()
        .unwrap()
        .entry(name.to_string())
        .or_insert_with(|| {
            let path = home.path().join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            // Run it once now, so the first exec's check is paid here, under the lock, rather
            // than inside some test's timeout.
            let _ = std::process::Command::new(&path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            path
        })
        .clone();
    let link = dir.join(name);
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(script, &link).unwrap();
    link
}

/// A df that prints `df.out` from its own directory.
pub const DF: &str = r#"#!/bin/sh
d=$(dirname "$0")
cat "$d/df.out"
exit "$(cat "$d/df.rc" 2>/dev/null || echo 0)"
"#;

/// Have the df in `dir` report `percent`% used.
pub fn df_at(dir: &Path, percent: u32) {
    fs::write(
        dir.join("df.out"),
        format!(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
             /dev/sda1 47000000 1 1 {percent}% /\n"
        ),
    )
    .unwrap();
}

/// The dry-run command [`run`] renders sentences with.
pub const DRY_RUN: &str = "whimbrel dry-run --config /etc/whimbrel.toml";

/// A check of `kind` from `table`, TOML as a config would hold it less its `kind`, run once on
/// `host` with `state_dir` as the watch's, the way a real run runs it, at the Unix epoch. Any
/// problem it reports is held to the alert sentence rule, so every test that runs a check through
/// here is also a test of its wording.
pub fn run(
    kind: &whimbrel::Kind,
    table: &str,
    host: &str,
    state_dir: &std::path::Path,
    mode: whimbrel::Mode,
) -> whimbrel::Finding {
    run_at(
        kind,
        table,
        host,
        state_dir,
        mode,
        std::time::SystemTime::UNIX_EPOCH,
    )
}

/// [`run`], at `now`: for a check that reads the clock, so its test never depends on wall time.
pub fn run_at(
    kind: &whimbrel::Kind,
    table: &str,
    host: &str,
    state_dir: &std::path::Path,
    mode: whimbrel::Mode,
    now: std::time::SystemTime,
) -> whimbrel::Finding {
    let table: whimbrel::toml::Table = whimbrel::toml::from_str(table).expect("a TOML table");
    let patterns = whimbrel::secret_patterns::SecretPatterns::builtins();
    let shared = whimbrel::Shared {
        secret_patterns: &patterns,
    };
    let check = kind
        .configure(table, &shared)
        .unwrap_or_else(|why| panic!("{} refused its table: {why}", kind.name));
    let run = whimbrel::Run {
        now,
        host,
        state_dir,
        mode,
    };
    let f = check.find(&run);
    if f.level != whimbrel::Level::Ok {
        assert!(!f.problems.is_empty(), "a {:?} with nothing said", f.level);
    }
    for p in &f.problems {
        let said = p.sentence(DRY_RUN);
        assert_eq!(
            whimbrel::sentence::breaks(&check.key, &said),
            Vec::<String>::new(),
            "{said}"
        );
    }
    f
}

/// A Slack-shaped token made at run time, so no real or realistic one is ever in the repo.
pub fn token() -> String {
    use std::hash::{BuildHasher, RandomState};
    let s = RandomState::new();
    let digits = |n: usize, salt: u64| -> String {
        (0..n)
            .map(|i| char::from(b'0' + (s.hash_one((salt, i)) % 10) as u8))
            .collect()
    };
    let letters: String = (0..24)
        .map(|i| char::from(b'a' + (s.hash_one((3u64, i)) % 26) as u8))
        .collect();
    format!("xoxb-{}-{}-{letters}", digits(12, 1), digits(13, 2))
}

/// A journalctl that serves `journal` from its own directory as `-o export`, each line an entry's
/// `MESSAGE`, with cursors `c1`, `c2` and so on, numbered by line. A line `--boot--` starts a new
/// boot, and `-b` reads from the last one. `--after-cursor` reads on from a cursor, and one that
/// isn't of that form is refused, as journalctl refuses a cursor it can't use. A `MESSAGE_ID=`
/// query is answered from `dropped`. `journal.fail` makes it fail, `journal.fail-once` fail once
/// having printed nothing, and `journal.killed` die of SIGTERM; `dropped.fail` makes the
/// `MESSAGE_ID=` query fail. Every call's arguments go to `args`.
pub const JOURNALCTL: &str = r#"#!/bin/sh
d=$(dirname "$0")
echo "$*" >> "$d/args"
case " $* " in *" MESSAGE_ID="*)
  [ -e "$d/dropped.fail" ] && exit 1
  [ -e "$d/dropped" ] && cat "$d/dropped"
  exit 0 ;;
esac
[ -e "$d/journal.fail" ] && exit 1
[ -e "$d/journal.fail-once" ] && { rm "$d/journal.fail-once"; exit 1; }
[ -e "$d/journal.killed" ] && kill -TERM $$
n=0; boot=0
for a in "$@"; do
  case $a in
    --after-cursor=*)
      n=${a#--after-cursor=c}
      case $n in ''|*[!0-9]*) exit 1 ;; esac ;;
    -b) boot=1 ;;
  esac
done
touch "$d/journal"
awk -v s="$n" -v b="$boot" '
  FNR == NR { if ($0 == "--boot--") last = FNR; next }
  FNR > s && (!b || FNR > last) && $0 != "--boot--" {
    printf "__CURSOR=c%d\nMESSAGE=%s\n\n", FNR, $0
  }' "$d/journal" "$d/journal"
"#;

/// A check of `kind` from `table`, less its `kind`, with the built-in secret patterns.
pub fn configure(
    kind: &whimbrel::Kind,
    table: whimbrel::toml::Table,
) -> Result<whimbrel::Configured, String> {
    let patterns = whimbrel::secret_patterns::SecretPatterns::builtins();
    let shared = whimbrel::Shared {
        secret_patterns: &patterns,
    };
    kind.configure(table, &shared)
}
