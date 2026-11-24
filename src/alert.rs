//! The words around each check's sentence. Every fixed string whimbrel sends is here.

use crate::check::{CheckResult, Level};
use crate::secret_patterns::SecretPatterns;
use crate::sentence::and_list;

/// What a channel is handed: `short` for a phone, `full` with every check's details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub short: String,
    pub full: String,
    /// Something is FAIL.
    pub urgent: bool,
}

/// Per host: the name the all-clear uses, and the dry run to point at when a check breaks.
#[derive(Clone, Debug)]
pub struct Frame {
    host: String,
    dry_run: String,
    redact: SecretPatterns,
}

/// Why a channel is being told anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Why {
    /// What's wrong differs from what it was last told, or something came and went unheard.
    Changed,
    /// Nothing changed, but a problem it was told about has been open a day.
    Reminder,
    /// The ledger was lost, so what it was told isn't known.
    LostTrack,
}

/// What one channel hasn't heard yet. The ledger decides it; the frame only words it.
#[derive(Debug)]
pub(crate) struct News<'a> {
    pub why: Why,
    /// Every problem now, in the order the checks ran.
    pub current: Vec<&'a CheckResult>,
    /// The `about` of each problem it was told about that's gone.
    pub recovered: Vec<String>,
    /// What was wrong, for each problem that came and went while nothing got through.
    pub came_and_went: Vec<String>,
}

impl Frame {
    pub fn new(host: impl Into<String>) -> Self {
        Frame {
            host: host.into(),
            dry_run: "whimbrel dry-run".into(),
            redact: SecretPatterns::default(),
        }
    }

    /// The command for a dry run of this host's config: `whimbrel dry-run --config <file>`.
    pub fn with_dry_run(mut self, command: impl Into<String>) -> Self {
        self.dry_run = command.into();
        self
    }

    /// Replace every match of `patterns` in what's sent with `[redacted]`.
    pub fn with_redact(mut self, patterns: SecretPatterns) -> Self {
        self.redact = patterns;
        self
    }

    /// `text` with every secret pattern's match replaced. The alert, a failed send's reason
    /// and what the ledger keeps all go through here.
    pub(crate) fn redacted(&self, text: String) -> String {
        self.redact.redact(&text)
    }

    /// The message: the lead, each current problem's sentence, what recovered, then anything that
    /// came and went unheard. The details follow, in the full form only.
    pub(crate) fn compose(&self, news: &News) -> Alert {
        let urgent = news.current.iter().any(|r| r.finding.level == Level::Fail);
        let mut lines: Vec<String> = Vec::new();
        if news.why == Why::LostTrack && news.current.is_empty() {
            lines.push("I lost track of what I'd told you, but nothing is open now.".into());
        } else if news.current.is_empty() {
            if !news.recovered.is_empty() {
                lines.push(all_clear(&self.host, &news.recovered));
            }
        } else {
            lines.push(lead(news.why, urgent).to_string());
            lines.extend(
                news.current
                    .iter()
                    .map(|r| r.finding.sentence(&self.dry_run)),
            );
            if !news.recovered.is_empty() {
                lines.push(back(&news.recovered));
            }
        }
        lines.extend(news.came_and_went.iter().map(|s| came_and_went(s)));
        let short = lines.join("\n");
        let details: Vec<&str> = news
            .current
            .iter()
            .filter_map(|r| r.finding.details.as_deref())
            .collect();
        let full = if details.is_empty() {
            short.clone()
        } else {
            format!("{short}\n\n{}", details.join("\n"))
        };
        Alert {
            short: self.redacted(short),
            full: self.redacted(full),
            urgent,
        }
    }
}

fn lead(why: Why, urgent: bool) -> &'static str {
    match (why, urgent) {
        (Why::Reminder, _) => "Still waiting on you:",
        (Why::LostTrack, _) => "I lost track of what I'd told you, so here's everything open now:",
        (Why::Changed, true) => "Needs you soon:",
        (Why::Changed, false) => "No rush, but something needs a look:",
    }
}

/// Nothing is wrong now, and these recovered.
fn all_clear(host: &str, recovered: &[String]) -> String {
    let verb = if recovered.len() == 1 { "is" } else { "are" };
    format!(
        "All clear on {host}: {} {verb} back to normal.",
        and_list(recovered)
    )
}

/// Some problems remain, and these recovered.
fn back(recovered: &[String]) -> String {
    format!("Back to normal: {}.", and_list(recovered))
}

/// A problem seen while no alert got through, and gone before one did: what was wrong, without
/// what to run, which is no use once it's gone.
fn came_and_went(what: &str) -> String {
    format!("While alerts weren't getting through, this happened and has since cleared up: {what}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_name_with_braces_is_only_a_name() {
        assert_eq!(
            all_clear("{what}", &["the disk".into()]),
            "All clear on {what}: the disk is back to normal."
        );
    }
}
