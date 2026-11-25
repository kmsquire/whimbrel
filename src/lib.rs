//! whimbrel, a friendly watch for your hosts.
//!
//! The contract is the command line, the config file and the result-row format, all described in
//! the README and `docs/config.md`. The items here are public only so the crate's own integration
//! tests reach them: they aren't a library API, and any release may change them.
//!
//! A run builds the configured checks (`checks`), runs them, and tells each channel (`channels`)
//! what changed since it was last told. The ledger behind that is [`deliver`], and [`StateDir`]
//! keeps it on disk.

use std::process::ExitCode;

mod alert;
pub mod channels;
mod check;
pub mod checks;
pub mod config;
mod ledger;
pub mod process;
pub mod rows;
pub mod run;
pub mod secret_patterns;
pub mod sentence;
mod state;

pub use alert::{Alert, Frame};
pub use check::{
    At, Check, CheckDir, CheckResult, Configured, Finding, Kind, Level, Run, Shared, run_checks,
    sentence_case,
};
pub use ledger::{Channel, DuplicateChannel, Form, Outcome, REMIND_AFTER_SECS, State, deliver};
pub use run::Mode;
pub use state::{Locked, StateDir};
pub use toml;

/// The commit this build came from: `WHIMBREL_COMMIT` at compile time, which CI sets, or
/// "unknown" for a local build.
pub const COMMIT: &str = match option_env!("WHIMBREL_COMMIT") {
    Some(commit) if !commit.is_empty() => commit,
    _ => "unknown",
};

/// `<name> <version> (<commit>)`, as `--version` prints it.
pub fn version_line(name: &str, version: &str) -> String {
    format!("{name} {version} ({COMMIT})")
}

/// The command line: `name` and `version` are the program's, for `--version` and usage.
pub fn run(name: &str, version: &str, mut args: impl Iterator<Item = String>) -> ExitCode {
    let usage = format!(
        "usage: {name} run --config FILE\n       {name} dry-run --config FILE\n       {name} --version"
    );
    let mode = match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("{}", version_line(name, version));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!(
                "{usage}\n\n\
                 run      runs the checks and tells each channel what changed since it was last told.\n\
                 dry-run  says what each channel would be sent, and changes nothing."
            );
            return ExitCode::SUCCESS;
        }
        Some("run") => run::Mode::Run,
        Some("dry-run") => run::Mode::DryRun,
        _ => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let path = match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--config"), Some(path), None) => std::path::PathBuf::from(path),
        _ => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let config = match config::Config::load(&path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{name}: {e}");
            return ExitCode::from(2);
        }
    };
    for warning in config.warnings() {
        eprintln!("{name}: warning: {warning}");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    run::once(&config, &path, name, mode, now).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_commit_is_unknown_or_a_full_sha() {
        assert!(
            COMMIT == "unknown"
                || (COMMIT.len() == 40 && COMMIT.bytes().all(|b| b.is_ascii_hexdigit())),
            "{COMMIT:?}"
        );
    }

    #[test]
    fn the_version_line_is_name_version_then_the_commit_in_parentheses() {
        let line = version_line("whimbrel", "1.2.3");
        let commit = line
            .strip_prefix("whimbrel 1.2.3 (")
            .and_then(|rest| rest.strip_suffix(')'));
        assert_eq!(commit, Some(COMMIT), "{line}");
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        let none: [String; 0] = [];
        assert_eq!(
            run("whimbrel", "0.0.0", none.into_iter()),
            ExitCode::from(2)
        );
        for bad in [
            &["frobnicate"][..],
            &["run"],
            &["run", "--config"],
            &["dry-run", "--config", "a", "b"],
        ] {
            let args = bad.iter().map(|s| s.to_string());
            assert_eq!(run("whimbrel", "0.0.0", args), ExitCode::from(2), "{bad:?}");
        }
    }
}
