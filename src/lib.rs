//! whimbrel, a friendly watch for your hosts.
//!
//! The contract is the command line, the config file and the result-row format, all described in
//! the README and `docs/config.md`. The items here are public only so the crate's own integration
//! tests reach them: they aren't a library API, and any release may change them.
//!
//! A run ([`run::run`]) builds the configured checks (`checks`), runs them, and tells each
//! channel (`channels`) what changed since it was last told. The ledger behind that is
//! [`deliver`], and [`StateDir`] keeps it on disk. The run returns a [`run::Report`], and the log
//! line and a dry run's printout are each rendered from it.

use std::process::ExitCode;

mod alert;
pub mod channels;
mod check;
pub mod checks;
pub mod config;
pub mod heartbeat;
mod ledger;
pub mod process;
pub mod request;
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
        "usage: {name} run --config FILE\n       {name} dry-run --config FILE\n       \
         {name} secrets --config FILE [--allow-non-terminal]\n       {name} --version"
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
                 dry-run  says what each channel would be sent, and changes nothing.\n\
                 secrets  shows where each secret the secrets check counts is: the file and line, or\n\
                 \x20        the journal entry, the pattern, and the token masked. It writes only to a\n\
                 \x20        terminal, unless --allow-non-terminal; never prints a whole token; and changes\n\
                 \x20        nothing.\n\
                 \x20        Run it as an account that can read the logs, usually root."
            );
            return ExitCode::SUCCESS;
        }
        Some("run") => run::Mode::Run,
        Some("dry-run") => run::Mode::DryRun,
        Some("secrets") => return secrets(name, &usage, args),
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
    let Some(config) = load(
        name,
        &path,
        &mut std::io::stderr(),
        config::Config::warnings,
    ) else {
        return ExitCode::from(2);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    run::once(&config, &path, name, mode, now).into()
}

/// The config at `path`, as every command loads it: a refusal, or each of `warnings` about it,
/// written to `err` under `name`. The one place a command loads a config, so none of them skips
/// a warning.
fn load(
    name: &str,
    path: &std::path::Path,
    err: &mut dyn std::io::Write,
    warnings: fn(&config::Config) -> Vec<String>,
) -> Option<config::Config> {
    match config::Config::load(path) {
        Ok(config) => {
            for warning in warnings(&config) {
                let _ = writeln!(err, "{name}: warning: {warning}");
            }
            Some(config)
        }
        Err(e) => {
            let _ = writeln!(err, "{name}: {e}");
            None
        }
    }
}

/// The `secrets` command: `--config FILE`, and `--allow-non-terminal` to write to a pipe, a file
/// or anything else that isn't a terminal. What it prints shows where secrets are, so by default
/// it writes only where a person is likely reading. That's a guard against an accident, such as
/// output piped into a log, not a boundary: a program can pose as a terminal.
fn secrets(name: &str, usage: &str, args: impl Iterator<Item = String>) -> ExitCode {
    let (mut path, mut allow_non_terminal) = (None, false);
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" if path.is_none() && args.peek().is_some() => {
                path = args.next().map(std::path::PathBuf::from);
            }
            "--allow-non-terminal" if !allow_non_terminal => allow_non_terminal = true,
            _ => {
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    // SAFETY: isatty only reads the descriptor's state.
    if !allow_non_terminal && unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1 {
        eprintln!(
            "{name}: secrets prints where secrets are, so it writes only to a terminal; \
             to write it to a pipe or a file anyway, add --allow-non-terminal"
        );
        return ExitCode::from(2);
    }
    let Some(config) = load(
        name,
        &path,
        &mut std::io::stderr(),
        config::Config::warnings,
    ) else {
        return ExitCode::from(2);
    };
    let mut out = std::io::stdout().lock();
    match checks::secrets::show(&config, &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(checks::secrets::ShowError::Config(e)) => {
            eprintln!("{name}: {e}");
            ExitCode::from(2)
        }
        Err(checks::secrets::ShowError::Output(e)) => {
            eprintln!("{name}: couldn't write the output: {e}");
            ExitCode::from(1)
        }
    }
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
    fn every_command_loads_its_config_through_one_loader_that_prints_its_warnings() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("w.toml");
        let text = format!("host = \"h\"\nstate_dir = {:?}\n", d.path().join("state"));
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut err = Vec::new();
        let said = |_: &config::Config| vec!["it does nothing".to_string()];
        assert!(load("w", &path, &mut err, said).is_some());
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "w: warning: it does nothing\n"
        );
        // A config it refuses is said once, with no warnings.
        let mut err = Vec::new();
        assert!(load("w", &d.path().join("none.toml"), &mut err, said).is_none());
        let err = String::from_utf8(err).unwrap();
        assert!(err.starts_with("w: ") && !err.contains("warning"), "{err}");
        // No command loads a config any other way, so none skips the warnings: outside the
        // tests, only `load` calls `Config::load`.
        let src = include_str!("lib.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        assert_eq!(code.matches("Config::load(").count(), 1);
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
