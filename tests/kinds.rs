//! Kinds as data: each a name, a default key and about, and a function from its table to a check.
//! A check is handed the host, the mode and a directory of its own each time it runs, and keeps
//! none of them. These tests add a kind of their own beside whimbrel's.

use std::fs;
use std::time::SystemTime;

use serde::Deserialize;
use whimbrel::checks::KINDS;
use whimbrel::config::{Config, from_table};
use whimbrel::{At, Check, Finding, Kind, Mode, Run, run_checks};

/// Writes `runs` in its own directory and says where it ran.
struct Counter;

impl Check for Counter {
    fn run(&self, at: &At) -> Finding {
        at.state.write("runs", b"1").unwrap();
        Finding::warn().says(format!("It ran on {}.", at.host))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CounterTable {}

const COUNTER: Kind = Kind {
    name: "counter",
    key: "counter",
    about: "the counter",
    build: |table, _| {
        from_table::<CounterTable>(table)?;
        Ok(Box::new(Counter))
    },
};

/// whimbrel's kinds and `more`.
fn plus(more: &[Kind]) -> Vec<Kind> {
    KINDS.iter().chain(more).copied().collect()
}

fn config(state_dir: &std::path::Path, checks: &str) -> Config {
    Config::parse(&format!(
        "host = \"the test host\"\nstate_dir = {state_dir:?}\n{checks}"
    ))
    .unwrap()
}

fn run(state_dir: &std::path::Path, mode: Mode) -> Run<'_> {
    Run {
        now: SystemTime::UNIX_EPOCH,
        host: "the test host",
        state_dir,
        mode,
    }
}

const TWO: &str = "[[check]]\nkind = \"counter\"\n\
                   [[check]]\nkind = \"counter\"\nkey = \"second\"\nabout = \"the second one\"\n";

#[test]
fn a_kinds_key_and_about_are_its_defaults_and_a_table_can_name_its_own() {
    let d = tempfile::tempdir().unwrap();
    let checks = config(d.path(), TWO)
        .build_checks_of(&plus(&[COUNTER]))
        .unwrap();
    let named: Vec<(&str, &str)> = checks
        .iter()
        .map(|c| (c.key.as_str(), c.about.as_str()))
        .collect();
    assert_eq!(
        named,
        [("counter", "the counter"), ("second", "the second one")]
    );
}

#[test]
fn each_check_runs_on_the_host_with_a_directory_of_its_own_named_for_its_key() {
    let d = tempfile::tempdir().unwrap();
    let checks = config(d.path(), TWO)
        .build_checks_of(&plus(&[COUNTER]))
        .unwrap();
    let results = run_checks(&checks, &run(d.path(), Mode::Run));
    assert_eq!(results[1].finding.first_what(), "It ran on the test host.");
    for key in ["counter", "second"] {
        assert_eq!(fs::read(d.path().join(key).join("runs")).unwrap(), b"1");
    }
}

#[test]
fn in_a_dry_run_a_checks_own_directory_keeps_nothing() {
    let d = tempfile::tempdir().unwrap();
    let checks = config(d.path(), TWO)
        .build_checks_of(&plus(&[COUNTER]))
        .unwrap();
    run_checks(&checks, &run(d.path(), Mode::DryRun));
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn a_kind_cant_take_a_name_already_taken() {
    let d = tempfile::tempdir().unwrap();
    let disk = Kind {
        name: "disk",
        ..COUNTER
    };
    for (kinds, says) in [
        (vec![disk], "two check kinds are named \"disk\""),
        (
            vec![COUNTER, COUNTER],
            "two check kinds are named \"counter\"",
        ),
    ] {
        let why = config(d.path(), "")
            .build_checks_of(&plus(&kinds))
            .err()
            .unwrap();
        assert_eq!(why.to_string(), says);
    }
}

#[test]
fn a_key_or_about_that_isnt_text_is_refused_naming_the_check() {
    let d = tempfile::tempdir().unwrap();
    let why = config(d.path(), "[[check]]\nkind = \"counter\"\nkey = 3\n")
        .build_checks_of(&plus(&[COUNTER]))
        .err()
        .unwrap();
    assert_eq!(why.to_string(), "check 1 (counter): key must be text");
}

#[test]
fn a_key_that_isnt_a_plain_name_is_refused_naming_the_check() {
    let d = tempfile::tempdir().unwrap();
    for key in ["", ".", "..", "/etc", "a/.", "Disk", "a b"] {
        let why = config(
            d.path(),
            &format!("[[check]]\nkind = \"counter\"\nkey = {key:?}\n"),
        )
        .build_checks_of(&plus(&[COUNTER]))
        .err()
        .unwrap();
        assert_eq!(
            why.to_string(),
            format!(
                "check 1 (counter): key {key:?} must be lowercase letters, digits and dashes, \
                 since it names a directory"
            )
        );
    }
}

#[test]
fn a_taken_key_is_refused_naming_the_check_that_takes_it() {
    let d = tempfile::tempdir().unwrap();
    for (checks, says) in [
        (
            "[[check]]\nkind = \"counter\"\n[[check]]\nkind = \"counter\"\n",
            "check 2 (counter): another check has the key \"counter\"",
        ),
        (
            "[[check]]\nkind = \"counter\"\nkey = \"alerting\"\n",
            "check 1 (counter): the key \"alerting\" is whimbrel's own, for its check of the \
             channels",
        ),
    ] {
        let why = config(d.path(), checks)
            .build_checks_of(&plus(&[COUNTER]))
            .err()
            .unwrap();
        assert_eq!(why.to_string(), says);
    }
}
