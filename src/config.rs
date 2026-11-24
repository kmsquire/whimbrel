//! A host's config: its name, where the ledger lives, what a secret looks like, its checks and
//! its channels. `docs/config.md` is the reference for every key.
//!
//! ```toml
//! host = "the test host"
//! state_dir = "/var/lib/whimbrel"
//!
//! [[check]]
//! kind = "disk"
//! path = "/"
//! suspects = ["/var/log", "/tmp"]
//!
//! [[channel]]
//! kind = "slack"
//! webhook_file = "/etc/whimbrel/slack-webhook"
//! ```
//!
//! Every check takes `key` and `about`, which default to its kind's; a key is lowercase letters,
//! digits and dashes, since it names the check's own directory.
//!
//! Secrets are named by file, never written here. A Slack webhook URL anywhere in the file is
//! refused, and an error never repeats a value from it, in case that value is a secret. The file
//! names programs whimbrel runs, as root on a server, so it must be ours and writable by us alone.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::channels::{BlueBubbles, Print, Slack};
use crate::check::{Configured, Kind, Shared};
use crate::checks::KINDS;
use crate::checks::alerting::{self, Alerting};
use crate::ledger::Channel;
use crate::secret_patterns::SecretPatterns;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// What the all-clear calls this host: "the test host", "your Mac".
    pub host: String,
    /// Owner-only: the ledger and the lock.
    pub state_dir: PathBuf,
    /// Where each run's one line goes. Unset, it's stdout.
    pub log_file: Option<PathBuf>,
    /// `curl`, found on PATH unless this says where.
    pub curl: Option<PathBuf>,
    /// What a secret looks like here: every match in an alert is replaced before any channel
    /// sees it, whichever check wrote it, and the `secrets` check looks for them.
    #[serde(default)]
    secret_patterns: SecretPatternsTable,
    #[serde(skip)]
    secret_patterns_compiled: SecretPatterns,
    /// Each check's table, read by its kind when the checks are built.
    #[serde(default, rename = "check")]
    pub checks: Vec<toml::Table>,
    #[serde(default, rename = "channel")]
    channels: Vec<ChannelConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretPatternsTable {
    #[serde(default = "yes")]
    builtins: bool,
    #[serde(default)]
    disable: Vec<String>,
    #[serde(default)]
    patterns: Vec<String>,
}

impl Default for SecretPatternsTable {
    fn default() -> Self {
        SecretPatternsTable {
            builtins: true,
            disable: Vec::new(),
            patterns: Vec::new(),
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum ChannelConfig {
    Slack(Slack),
    Bluebubbles(BlueBubbles),
    Print(Print),
}

/// A table as `T`, refusing keys `T` doesn't have. The error names a key, never a value.
pub fn from_table<T: DeserializeOwned>(table: toml::Table) -> Result<T, String> {
    toml::Value::Table(table)
        .try_into()
        .map_err(|e: toml::de::Error| scrub(e.message()))
}

/// Why a config was refused. It names the file and, for a parse error, the line, never a value.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// The most a config is read.
const CONFIG_MAX: u64 = 1024 * 1024;

const WEBHOOK_INLINE: &str = "it holds a Slack webhook URL. Put the URL in a file only root can \
                              read, and name that file with webhook_file.";

impl Config {
    /// The config at `path`, if it's ours, no one else can write it, and it parses.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let shown = path.display();
        let fail = |why: String| ConfigError(format!("{shown}: {why}"));
        let mut f = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| fail(format!("can't read it ({})", e.kind())))?;
        let m = f
            .metadata()
            .map_err(|e| fail(format!("can't read it ({})", e.kind())))?;
        // SAFETY: geteuid has no preconditions and can't fail.
        if m.uid() != unsafe { libc::geteuid() } {
            return Err(fail("it belongs to another account".into()));
        }
        if m.mode() & 0o022 != 0 {
            return Err(fail(format!(
                "other accounts can write it ({:o}); it should be 600",
                m.mode() & 0o777
            )));
        }
        let mut text = String::new();
        (&mut f)
            .take(CONFIG_MAX)
            .read_to_string(&mut text)
            .map_err(|e| fail(format!("can't read it ({})", e.kind())))?;
        Config::parse(&text).map_err(|e| fail(e.0))
    }

    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        // Before parsing, so an error that would quote it never runs. Escapes and line
        // continuations can hide it here; the walk over the parsed values below catches those.
        if text.to_lowercase().contains("hooks.slack.com") {
            return Err(ConfigError(WEBHOOK_INLINE.into()));
        }
        let at_line = |e: toml::de::Error| {
            let line = e
                .span()
                .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
            ConfigError(match line {
                Some(n) => format!("line {n}: {}", scrub(e.message())),
                None => scrub(e.message()),
            })
        };
        let table: toml::Table = toml::from_str(text).map_err(at_line)?;
        if holds_webhook(&toml::Value::Table(table)) {
            return Err(ConfigError(WEBHOOK_INLINE.into()));
        }
        let mut config: Config = toml::from_str(text).map_err(at_line)?;
        let t = &config.secret_patterns;
        config.secret_patterns_compiled =
            SecretPatterns::new(t.builtins, &t.disable, &t.patterns).map_err(ConfigError)?;
        if !config.state_dir.is_absolute() {
            return Err(ConfigError("state_dir must be an absolute path".into()));
        }
        if config.log_file.as_ref().is_some_and(|p| !p.is_absolute()) {
            return Err(ConfigError("log_file must be an absolute path".into()));
        }
        let mut names = BTreeSet::new();
        for channel in &config.channels {
            if !names.insert(channel.name().to_string()) {
                return Err(ConfigError(format!(
                    "two channels are named {:?}",
                    channel.name()
                )));
            }
        }
        if let Some(program) = config.curl.clone() {
            for channel in &mut config.channels {
                match channel {
                    ChannelConfig::Slack(s) => s.curl.program.clone_from(&program),
                    ChannelConfig::Bluebubbles(b) => b.curl.program.clone_from(&program),
                    ChannelConfig::Print(_) => {}
                }
            }
        }
        Ok(config)
    }

    /// Every configured check, then `alerting` if there are channels. A check whose kind nobody
    /// knows, whose table its kind refuses, or whose key is taken is refused, and the error names
    /// the check.
    pub fn build_checks(&self) -> Result<Vec<Configured>, ConfigError> {
        self.build_checks_of(KINDS)
    }

    /// [`Config::build_checks`], with `kinds` the kinds a config can name: for tests. Two with
    /// one name are refused.
    pub fn build_checks_of(&self, kinds: &[Kind]) -> Result<Vec<Configured>, ConfigError> {
        let shared = Shared {
            secret_patterns: &self.secret_patterns_compiled,
        };
        let mut by_name = BTreeMap::new();
        for kind in kinds {
            if by_name.insert(kind.name, kind).is_some() {
                return Err(ConfigError(format!(
                    "two check kinds are named {:?}",
                    kind.name
                )));
            }
        }
        // Reserved with or without channels, so adding the first channel can't break a config.
        let mut keys = BTreeSet::from([alerting::KEY.to_string()]);
        let mut checks = Vec::new();
        for (i, table) in self.checks.iter().enumerate() {
            let n = i + 1;
            let name = table.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            let refused = |why: String| {
                ConfigError(match name {
                    "" => format!("check {n} has no kind"),
                    _ => format!("check {n} ({name}): {why}"),
                })
            };
            let kind = by_name
                .get(name)
                .ok_or_else(|| refused(format!("there's no check kind {name:?}")))?;
            let mut table = table.clone();
            table.remove("kind");
            let check = kind.configure(table, &shared).map_err(refused)?;
            if check.key == alerting::KEY {
                return Err(refused(format!(
                    "the key {:?} is whimbrel's own, for its check of the channels",
                    alerting::KEY
                )));
            }
            if !keys.insert(check.key.clone()) {
                return Err(refused(format!(
                    "another check has the key {:?}",
                    check.key
                )));
            }
            checks.push(check);
        }
        if !self.channels.is_empty() {
            checks.push(Alerting::configured(self.build_channels()));
        }
        Ok(checks)
    }

    /// What every alert is redacted with, and what the `secrets` check looks for.
    pub fn secret_patterns(&self) -> &SecretPatterns {
        &self.secret_patterns_compiled
    }

    pub fn build_channels(&self) -> Vec<Box<dyn Channel>> {
        self.channels
            .iter()
            .map(|c| -> Box<dyn Channel> {
                match c.clone() {
                    ChannelConfig::Slack(s) => Box::new(s),
                    ChannelConfig::Bluebubbles(b) => Box::new(b),
                    ChannelConfig::Print(p) => Box::new(p),
                }
            })
            .collect()
    }
}

impl ChannelConfig {
    fn name(&self) -> &str {
        match self {
            ChannelConfig::Slack(s) => &s.name,
            ChannelConfig::Bluebubbles(b) => &b.name,
            ChannelConfig::Print(p) => &p.name,
        }
    }
}

/// Whether any key or string in `v`, decoded and in any case, holds a Slack webhook's host.
fn holds_webhook(v: &toml::Value) -> bool {
    let hit = |s: &str| s.to_lowercase().contains("hooks.slack.com");
    match v {
        toml::Value::String(s) => hit(s),
        toml::Value::Array(a) => a.iter().any(holds_webhook),
        toml::Value::Table(t) => t.iter().any(|(k, v)| hit(k) || holds_webhook(v)),
        _ => false,
    }
}

/// A parser's message with every value it quotes taken out: `invalid type: string "…"`, and the
/// variant in `unknown variant`. Keys stay, since they're what tells you where to look.
fn scrub(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut quoted = false;
    for c in message.chars() {
        if c == '"' {
            quoted = !quoted;
            out.push_str(if quoted { "\"…" } else { "\"" });
        } else if !quoted {
            out.push(c);
        }
    }
    if let Some(rest) = out.strip_prefix("unknown variant `")
        && let Some((_, after)) = rest.split_once('`')
    {
        out = format!("unknown variant `…`{after}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "host = \"the test host\"\nstate_dir = \"/var/lib/whimbrel\"\n";

    fn parse(extra: &str) -> Result<Config, String> {
        Config::parse(&format!("{BASE}{extra}")).map_err(|e| e.0)
    }

    fn build(extra: &str) -> Result<Vec<Configured>, String> {
        parse(extra)?.build_checks().map_err(|e| e.0)
    }

    #[test]
    fn a_minimal_config_has_no_checks_or_channels() {
        let c = parse("").unwrap();
        assert!(c.checks.is_empty() && c.channels.is_empty());
    }

    #[test]
    fn core_kinds_build_with_their_keys() {
        let checks = build(
            "[[check]]\nkind = \"disk\"\npath = \"/\"\n\
             [[check]]\nkind = \"disk\"\nkey = \"data\"\npath = \"/data\"\n",
        )
        .unwrap();
        let keys: Vec<_> = checks.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["disk", "data"]);
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProbeTable {
        level: String,
    }

    struct ProbeCheck;

    impl crate::Check for ProbeCheck {
        fn run(&self, _: &crate::At) -> crate::Finding {
            crate::Finding::ok()
        }
    }

    /// Takes a table with `level` alone, which it checks is "ok".
    const PROBE: Kind = Kind {
        name: "probe",
        key: "probe",
        about: "the probe",
        build: |table, _| {
            let t: ProbeTable = from_table(table)?;
            if t.level != "ok" {
                return Err("level must be ok".into());
            }
            Ok(Box::new(ProbeCheck))
        },
    };

    fn with_probe() -> Vec<Kind> {
        KINDS.iter().copied().chain([PROBE]).collect()
    }

    #[test]
    fn two_kinds_with_one_name_are_refused() {
        let c = parse("").unwrap();
        let twice = [PROBE, PROBE];
        let why = c.build_checks_of(&twice).err().unwrap().0;
        assert_eq!(why, "two check kinds are named \"probe\"");
    }

    #[test]
    fn an_added_kind_gets_its_table_without_kind_key_or_about() {
        let c =
            parse("[[check]]\nkind = \"probe\"\nkey = \"p\"\nabout = \"a p\"\nlevel = \"ok\"\n")
                .unwrap();
        let checks = c.build_checks_of(&with_probe()).unwrap();
        assert_eq!(
            (checks[0].key.as_str(), checks[0].about.as_str()),
            ("p", "a p")
        );
    }

    #[test]
    fn an_added_kind_refusing_its_table_names_the_check() {
        let c = parse(
            "[[check]]\nkind = \"disk\"\npath = \"/\"\n\
             [[check]]\nkind = \"probe\"\nlevel = \"ok\"\nsecret = \"hunter2\"\n\
             [[check]]\nkind = \"probe\"\nkey = \"q\"\nlevel = \"bad\"\n",
        )
        .unwrap();
        let why = c.build_checks_of(&with_probe()).err().unwrap().0;
        assert_eq!(
            why,
            "check 2 (probe): unknown field `secret`, expected `level`"
        );
        let c = parse("[[check]]\nkind = \"probe\"\nlevel = \"bad\"\n").unwrap();
        let why = c.build_checks_of(&with_probe()).err().unwrap().0;
        assert_eq!(why, "check 1 (probe): level must be ok");
    }

    #[test]
    fn a_kind_nobody_knows_is_refused() {
        let why = build("[[check]]\nkind = \"smoke\"\n").err().unwrap();
        assert_eq!(why, "check 1 (smoke): there's no check kind \"smoke\"");
        let why = build("[[check]]\npath = \"/\"\n").err().unwrap();
        assert_eq!(why, "check 1 has no kind");
    }

    #[test]
    fn every_channel_kind_parses() {
        let c = parse(
            "[[channel]]\nkind = \"slack\"\nwebhook_file = \"/etc/w\"\n\
             [[channel]]\nkind = \"bluebubbles\"\nserver = \"http://127.0.0.1:1234\"\n\
             password_file = \"/etc/p\"\nrecipient_file = \"/etc/r\"\n\
             [[channel]]\nkind = \"print\"\n",
        )
        .unwrap();
        let names: Vec<_> = c
            .build_channels()
            .iter()
            .map(|c| c.name().to_string())
            .collect();
        assert_eq!(names, ["slack", "bluebubbles", "print"]);
    }

    #[test]
    fn a_webhook_url_anywhere_is_refused_without_repeating_it() {
        for extra in [
            "[[channel]]\nkind = \"slack\"\nwebhook = \"https://hooks.slack.com/services/T/B/sekrit\"\n",
            "[[channel]]\nkind = \"slack\"\nwebhook_file = \"https://HOOKS.Slack.com/services/T/B/sekrit\"\n",
            // A \u escape and a line continuation, which only the parsed value shows.
            "[[channel]]\nkind = \"slack\"\nwebhook_file = \"https://\\u0068ooks.slack.com/services/T/B/sekrit\"\n",
            "[[channel]]\nkind = \"slack\"\nwebhook_file = \"\"\"https://hooks.\\\n    slack.com/services/T/B/sekrit\"\"\"\n",
        ] {
            let why = parse(extra).unwrap_err();
            assert_eq!(why, WEBHOOK_INLINE, "{extra}");
        }
    }

    #[test]
    fn a_file_too_broken_to_parse_is_still_refused_for_holding_a_webhook() {
        let why = parse("[[channel]\nwebhook = \"https://HOOKS.slack.com/services/T/B/sekrit\"\n")
            .unwrap_err();
        assert_eq!(why, WEBHOOK_INLINE);
    }

    #[test]
    fn an_unknown_key_names_its_line_but_never_its_value() {
        let why = parse("[[channel]]\nkind = \"bluebubbles\"\npassword = \"hunter2hunter2\"\n")
            .unwrap_err();
        // toml points at the table the key is in, which is near enough to find it.
        assert!(why.starts_with("line 3: unknown field `password`"), "{why}");
        assert!(!why.contains("hunter2"), "{why}");
    }

    #[test]
    fn a_value_of_the_wrong_type_or_kind_is_never_repeated() {
        for extra in [
            "[[check]]\nkind = \"disk\"\npath = \"/\"\nwarn = \"hunter2pw\"\n",
            "[[channel]]\nkind = \"hunter2pw\"\n",
            "[[channel]]\nkind = \"slack\"\nwebhook_file = \"hunter2pw\"\n",
        ] {
            let why = match parse(extra) {
                Err(why) => why,
                Ok(c) => c.build_checks().err().unwrap().0,
            };
            assert!(!why.contains("hunter2pw"), "{extra}: {why}");
        }
    }

    #[test]
    fn scrubbing_keeps_keys_and_drops_values() {
        assert_eq!(
            scrub("invalid type: string \"hunter2\", expected u8"),
            "invalid type: string \"…\", expected u8"
        );
        assert_eq!(
            scrub("unknown variant `hunter2`, expected one of `slack`, `print`"),
            "unknown variant `…`, expected one of `slack`, `print`"
        );
        assert_eq!(scrub("unknown field `secret`"), "unknown field `secret`");
    }

    #[test]
    fn nonsense_is_refused() {
        for (extra, says) in [
            (
                "[[check]]\nkind = \"disk\"\npath = \"/\"\nwarn = 90\nfail = 80\n",
                "check 1 (disk): warn must be under fail, and fail at most 100",
            ),
            (
                "[[check]]\nkind = \"disk\"\npath = \"/\"\nfail = 101\n",
                "check 1 (disk): warn must be under fail, and fail at most 100",
            ),
            (
                "[[check]]\nkind = \"disk\"\npath = \"/\"\n[[check]]\nkind = \"disk\"\npath = \"/d\"\n",
                "check 2 (disk): another check has the key \"disk\"",
            ),
        ] {
            let why = build(extra).err().unwrap();
            assert_eq!(why, says, "{extra:?}");
        }
        for (extra, says) in [
            (
                "[[channel]]\nkind = \"print\"\n[[channel]]\nkind = \"print\"\n",
                "two channels are named \"print\"",
            ),
            (
                "[[channel]]\nkind = \"bluebubbles\"\nserver = \"http://u:p@h:1\"\npassword_file = \"/p\"\nrecipient_file = \"/r\"\n",
                "no path or credentials",
            ),
            (
                "[[channel]]\nkind = \"slack\"\nwebhook_file = \"relative/w\"\n",
                "a secret file must be an absolute path",
            ),
        ] {
            let why = parse(extra).err().unwrap();
            assert!(why.contains(says), "{extra:?} gave {why:?}");
        }
        let relative = Config::parse("host = \"h\"\nstate_dir = \"state\"\n").unwrap_err();
        assert_eq!(relative.0, "state_dir must be an absolute path");
    }

    #[test]
    fn a_relative_log_file_is_refused() {
        let why = parse("log_file = \"whimbrel.log\"\n").unwrap_err();
        assert_eq!(why, "log_file must be an absolute path");
    }
}
