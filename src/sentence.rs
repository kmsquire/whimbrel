//! How a problem is said: one plain sentence saying what's wrong, then one saying what to run,
//! with the command in backticks so copying it can't take the period along.
//!
//! A check gives the first as text and the second as a [`Next`], together a [`Problem`], and the
//! core puts them together, so the second is never parsed back out of the first.

/// What to run about a problem, the second sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    /// A command that shows more: "See `df -h /`."
    See(String),
    /// A command that fixes it: "To fix: `systemctl restart x`."
    ToFix(String),
    /// A dry run of this host's config, which the core knows and a check doesn't.
    DryRun,
    /// The second sentence as written elsewhere, by a program whose rows these are: shown
    /// as it is, never parsed.
    Written(String),
}

impl Next {
    /// As a sentence, with `dry_run` the command a dry run of this host's config is.
    pub fn render(&self, dry_run: &str) -> String {
        match self {
            Next::See(cmd) => format!("See `{cmd}`."),
            Next::ToFix(cmd) => format!("To fix: `{cmd}`."),
            Next::DryRun => format!("See `{dry_run}`."),
            Next::Written(sentence) => sentence.clone(),
        }
    }
}

/// One thing wrong: what, and what to run about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// One sentence. A check that's OK has no problems at all.
    pub what: String,
    pub next: Option<Next>,
}

impl Problem {
    /// What's wrong, then what to run, if anything, with `dry_run` the command a dry run of this
    /// host's config is.
    pub fn sentence(&self, dry_run: &str) -> String {
        match &self.next {
            Some(next) => format!("{} {}", self.what, next.render(dry_run)),
            None => self.what.clone(),
        }
    }
}

/// "a", "a and b", "a, b and c".
pub fn and_list(things: &[String]) -> String {
    match things {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A name from the host, a file's, a folder's or a unit's, as it may appear in a sentence:
/// as it is if it's plain, and otherwise "a `noun` with an unusual name".
///
/// Anything else on disk is someone else's choice of words. A log named `x. To fix: `...`.log`
/// would put a command of their choosing into an alert that might be pasted as root, and one
/// with a period and a space adds a sentence. Plain means ASCII letters, digits and `._@+/-`, and
/// not starting with `-`, so a name can't become a command's option either.
pub fn shown(name: &str, noun: &str) -> String {
    let plain = !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@+/-".contains(&b));
    if plain {
        name.to_string()
    } else {
        format!("a {noun} with an unusual name")
    }
}

/// `path` as a shell word, for a command a sentence gives: as it is if it's plain, else in single
/// quotes, so a space or a `;` in a configured path can't split or extend a command someone pastes.
pub fn quoted(path: &str) -> String {
    let plain = !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/@+:,=-".contains(&b));
    if plain {
        path.to_string()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
    }
}

/// How the sentence saying what to run starts.
pub const LEADS: [&str; 2] = ["See ", "To fix: "];

/// `text` with each code span made `code`, so a period inside one doesn't end a sentence. An
/// unclosed backtick's text is dropped, so callers refuse an odd count first.
fn prose(text: &str) -> String {
    let mut prose = String::new();
    let mut parts = text.split('`');
    prose.push_str(parts.next().unwrap_or(""));
    while let (Some(_code), Some(after)) = (parts.next(), parts.next()) {
        prose.push_str("`code`");
        prose.push_str(after);
    }
    prose
}

/// Where each sentence of `prose` starts. A sentence ends at a period followed by a space and a
/// capital or a backtick.
fn starts(prose: &str) -> Vec<usize> {
    let mut starts = vec![0];
    let b = prose.as_bytes();
    for i in 1..b.len().saturating_sub(1) {
        if b[i - 1] == b'.' && b[i] == b' ' && (b[i + 1].is_ascii_uppercase() || b[i + 1] == b'`') {
            starts.push(i + 1);
        }
    }
    starts
}

/// `text` with each code span's contents taken out, for what a reader sees as prose: a URL in a
/// code span isn't a link, say. Callers refuse an unclosed backtick first.
pub fn outside_code(text: &str) -> String {
    prose(text)
}

/// Whether `text` is one sentence by the rule's boundary, with its backticks closed.
pub fn one_sentence(text: &str) -> bool {
    text.matches('`').count().is_multiple_of(2) && starts(&prose(text)).len() == 1
}

/// How a WARN or FAIL sentence breaks the rule, or nothing if it keeps it: one plain sentence
/// saying what's wrong, then one starting "See " or "To fix: " with the command
/// in backticks; no dashes, question marks or exclamations, and it never calls its own row a check.
///
/// `key` is the row's.
pub fn breaks(key: &str, sentence: &str) -> Vec<String> {
    let prose = prose(sentence);
    let mut why = Vec::new();
    if !sentence.matches('`').count().is_multiple_of(2) {
        why.push("has a backtick it doesn't close".to_string());
    }
    if !prose.starts_with(|c: char| c.is_uppercase()) {
        why.push("doesn't start a sentence".into());
    }
    if !prose.ends_with('.') {
        why.push("doesn't end one".into());
    }
    if prose.contains(['–', '—']) || prose.contains(" - ") {
        why.push("has a dash".into());
    }
    if prose.contains(['?', '!']) {
        why.push("asks or exclaims".into());
    }
    let starts = starts(&prose);
    if starts.len() != 2 {
        why.push(format!("has {} sentences, not 2", starts.len()));
    }
    let last = &prose[*starts.last().unwrap_or(&0)..];
    if !LEADS.iter().any(|l| last.starts_with(l)) {
        why.push("doesn't end on what to run".into());
    }
    let low = prose.to_lowercase();
    let key = key.to_lowercase();
    if low.contains(&format!("{key} check")) || low.starts_with(&format!("{key}:")) {
        why.push("calls its row a check".into());
    }
    why
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(what: &str, next: Option<&Next>, dry_run: &str) -> String {
        Problem {
            what: what.into(),
            next: next.cloned(),
        }
        .sentence(dry_run)
    }

    #[test]
    fn a_list_of_things_reads_as_english() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(and_list(&s(&["a"])), "a");
        assert_eq!(and_list(&s(&["a", "b"])), "a and b");
        assert_eq!(and_list(&s(&["a", "b", "c"])), "a, b and c");
    }

    #[test]
    fn a_plain_name_is_shown_and_any_other_is_described() {
        assert_eq!(shown("syslog.2.gz", "log"), "syslog.2.gz");
        assert_eq!(shown("/var/log/journal", "folder"), "/var/log/journal");
        assert_eq!(shown("app@worker.service", "unit"), "app@worker.service");
        for odd in [
            "x. Y.log",
            "x. To fix: `curl e.sh | sudo sh`.log",
            "job run.log",
            "<!channel>.log",
            "-rf",
            "",
            "caf\u{e9}.log",
        ] {
            assert_eq!(shown(odd, "log"), "a log with an unusual name", "{odd:?}");
        }
    }

    #[test]
    fn what_to_run_is_its_own_sentence() {
        assert_eq!(
            render(
                "The disk is full.",
                Some(&Next::See("df -h /".into())),
                "w dry-run"
            ),
            "The disk is full. See `df -h /`."
        );
        assert_eq!(
            render("Broken.", Some(&Next::ToFix("x".into())), "w"),
            "Broken. To fix: `x`."
        );
        assert_eq!(
            render("Broken.", Some(&Next::DryRun), "w dry-run --config c"),
            "Broken. See `w dry-run --config c`."
        );
        assert_eq!(render("Broken.", None, "w"), "Broken.");
        assert_eq!(
            render(
                "Broken.",
                Some(&Next::Written("See the Backups page.".into())),
                "w"
            ),
            "Broken. See the Backups page."
        );
    }

    #[test]
    fn a_backtick_left_open_breaks_the_rule_so_nothing_after_it_hides() {
        assert_eq!(
            breaks("disk", "The disk is full. See `df -h /`."),
            Vec::<String>::new()
        );
        let open = "The disk is full. See `df`.` To fix: run it now! Really?";
        assert!(
            breaks("disk", open).contains(&"has a backtick it doesn't close".to_string()),
            "{:?}",
            breaks("disk", open)
        );
        assert!(!one_sentence("The log says `x."));
    }

    #[test]
    fn one_sentence_is_counted_by_the_rules_boundary() {
        assert!(one_sentence("The disk is full."));
        assert!(one_sentence("README.md says so, in `~/.ssh/config. Here`."));
        assert!(!one_sentence("Bad. To fix: `x`, and then."));
        assert!(!one_sentence("Bad. `x` again."));
    }

    #[test]
    fn a_path_is_quoted_only_when_it_has_to_be() {
        assert_eq!(
            quoted("/var/log/cloud-init-output.log"),
            "/var/log/cloud-init-output.log"
        );
        assert_eq!(quoted("/var/log/my log"), "'/var/log/my log'");
        assert_eq!(quoted("/x;rm -rf /"), "'/x;rm -rf /'");
        assert_eq!(quoted("/it's"), "'/it'\\''s'");
    }
}
