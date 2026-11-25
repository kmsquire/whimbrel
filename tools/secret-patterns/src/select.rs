//! The selection rule, applied to every rule in list order: what it takes, and why it leaves each
//! of the rest. `src/secret_patterns.rs` states the rule in prose; this is the rule.

use regex::Regex;
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::changes::Changes;
use crate::extract::Item;

const MIN_PREFIX: usize = 3;
const MIN_LEN: usize = 16;

pub struct Picked {
    pub source: String,
    pub rule: String,
    pub pattern: String,
    /// How it differs from the rule's token, if it does: a hand change's reason.
    pub changed: Option<String>,
}

pub struct Left {
    pub source: String,
    pub rule: String,
    pub why: String,
}

pub struct Selection {
    pub picked: Vec<Picked>,
    pub left: Vec<Left>,
}

pub fn select(items: Vec<Item>, changes: &Changes) -> Result<Selection, String> {
    let mut taken: Vec<(String, Regex)> = Vec::new();
    let mut sel = Selection {
        picked: Vec::new(),
        left: Vec::new(),
    };
    let mut used = vec![false; changes.change.len()];
    for item in items {
        let r = match item {
            Item::Rule(r) => r,
            Item::Unread { source, rule, why } => {
                sel.left.push(Left {
                    source,
                    rule,
                    why: why.to_string(),
                });
                continue;
            }
        };
        // The token as it's judged, and as it's published if it's taken.
        let mut core = r.core;
        let mut shipped = None;
        let mut changed = None;
        for (i, c) in changes.change.iter().enumerate() {
            if c.source == r.source && c.rule == r.rule {
                core = c.apply(&core)?;
                shipped = c.pattern.clone().or(shipped);
                changed = Some(c.why.clone());
                used[i] = true;
            }
        }
        let tag = format!("{}:{}", r.source, r.rule);
        let why = judge(&r.source, &core, &taken);
        match why {
            Ok(re) => {
                if let Some(p) = &shipped {
                    Regex::new(p).map_err(|e| {
                        format!("changes.toml's pattern for {tag} doesn't compile: {e}")
                    })?;
                }
                taken.push((tag, re));
                sel.picked.push(Picked {
                    source: r.source,
                    rule: r.rule,
                    pattern: shipped.unwrap_or(core),
                    changed,
                });
            }
            Err(why) => sel.left.push(Left {
                source: r.source,
                rule: r.rule,
                why,
            }),
        }
    }
    if let Some(i) = used.iter().position(|u| !u) {
        let c = &changes.change[i];
        return Err(format!(
            "changes.toml changes {} {:?}, which no list has: drop the change or fix its name",
            c.source, c.rule
        ));
    }
    Ok(sel)
}

/// The token compiled, if the selection rule takes it, or why it doesn't. `taken` is every rule
/// taken so far, each by `<list>:<rule>`; one from another list that matches an example of the
/// token already covers it.
fn judge(source: &str, core: &str, taken: &[(String, Regex)]) -> Result<Regex, String> {
    let re = Regex::new(core).map_err(|e| match e {
        regex::Error::CompiledTooBig(_) => "too big for Rust's regex".to_string(),
        e => format!(
            "doesn't compile in Rust: {}",
            e.to_string().lines().last().unwrap_or("")
        ),
    })?;
    let hir = regex_syntax::Parser::new()
        .parse(core)
        .map_err(|e| e.to_string())?;
    if hir.properties().is_literal() {
        return Err("it's one fixed string, not a shape".into());
    }
    if !token_first(&hir) {
        return Err("a keyword comes before the token".into());
    }
    if hir.properties().minimum_len().unwrap_or(0) < MIN_LEN {
        return Err(format!("can match fewer than {MIN_LEN} characters"));
    }
    let seq = Extractor::new().kind(ExtractKind::Prefix).extract(&hir);
    match seq.min_literal_len() {
        Some(n) if seq.is_finite() && n >= MIN_PREFIX => {}
        _ => {
            return Err(format!(
                "doesn't start with a literal of {MIN_PREFIX} or more characters"
            ));
        }
    }
    let mut ex = String::new();
    example(&hir, &mut ex);
    let line = format!("a line with {ex} in it");
    if !re.is_match(&line) {
        return Err("no example could be made for it".into());
    }
    let own = format!("{source}:");
    if let Some((by, _)) = taken
        .iter()
        .find(|(by, t)| !by.starts_with(&own) && t.is_match(&line))
    {
        return Err(format!("already covered by {by}"));
    }
    Ok(re)
}

/// The shortest string the pattern matches by its first alternative and smallest counts.
fn example(h: &Hir, out: &mut String) {
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(l) => out.push_str(&String::from_utf8_lossy(&l.0)),
        HirKind::Class(Class::Unicode(c)) => {
            // A letter or digit if the class has one, so a `\b` after it still holds; else a
            // printable start, so a class from `\s` or `.` gives a space.
            let has = |x: char| c.ranges().iter().any(|r| r.start() <= x && x <= r.end());
            let ch = ['a', 'A', '0']
                .into_iter()
                .find(|x| has(*x))
                .unwrap_or_else(|| {
                    let r = c.ranges()[0];
                    if r.start() < ' ' && r.end() >= ' ' {
                        ' '
                    } else {
                        r.start()
                    }
                });
            out.push(ch);
        }
        HirKind::Class(Class::Bytes(c)) => out.push(char::from(c.ranges()[0].start())),
        HirKind::Repetition(r) => {
            for _ in 0..r.min {
                example(&r.sub, out);
            }
        }
        HirKind::Capture(c) => example(&c.sub, out),
        HirKind::Concat(v) => v.iter().for_each(|h| example(h, out)),
        HirKind::Alternation(v) => example(&v[0], out),
    }
}

/// Whether the token starts the match: the pattern captures nothing, or its first part, after
/// any word boundaries, is the capture that holds the token. A rule whose match starts with a
/// keyword before the token fails this, whatever that keyword's prefix.
fn token_first(h: &Hir) -> bool {
    if h.properties().explicit_captures_len() == 0 {
        return true;
    }
    match h.kind() {
        HirKind::Capture(_) => true,
        HirKind::Concat(v) => v
            .iter()
            .find(|h| !matches!(h.kind(), HirKind::Look(_) | HirKind::Empty))
            .is_some_and(|h| matches!(h.kind(), HirKind::Capture(_))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changes::Change;
    use crate::extract::Rule;

    fn why(core: &str) -> String {
        judge("gitleaks", core, &[]).err().unwrap_or_default()
    }

    #[test]
    fn each_part_of_the_rule_has_its_reason() {
        assert_eq!(why(r"\b(abc_[a-z0-9]{16})"), "");
        assert_eq!(
            why(r"key\s*=\s*([a-z0-9]{32})"),
            "a keyword comes before the token"
        );
        assert_eq!(
            why(r"abc_[a-z0-9]{8}"),
            "can match fewer than 16 characters"
        );
        assert_eq!(
            why(r"[a-z]{2}_[a-z0-9]{32}"),
            "doesn't start with a literal of 3 or more characters"
        );
        assert_eq!(
            why("abcdefghijklmnopq"),
            "it's one fixed string, not a shape"
        );
        assert!(why("abc(").starts_with("doesn't compile in Rust"));
    }

    #[test]
    fn a_rule_another_list_already_covers_is_left_out_and_one_from_its_own_list_isnt() {
        let taken = [(
            "gitleaks:abc".to_string(),
            Regex::new(r"abc_[a-z0-9]{16}").unwrap(),
        )];
        let same = r"\b(abc_[a-z0-9]{20})";
        assert_eq!(
            judge("betterleaks", same, &taken).err().as_deref(),
            Some("already covered by gitleaks:abc")
        );
        assert!(judge("gitleaks", same, &taken).is_ok());
    }

    fn rule(source: &str, rule: &str, core: &str) -> Item {
        Item::Rule(Rule {
            source: source.into(),
            rule: rule.into(),
            core: core.into(),
        })
    }

    fn change(rule: &str, pattern: Option<&str>, replace: Option<[&str; 2]>) -> Change {
        Change {
            source: "gitleaks".into(),
            rule: rule.into(),
            pattern: pattern.map(str::to_string),
            replace: replace.map(|[a, b]| [a.to_string(), b.to_string()]),
            why: "because".into(),
        }
    }

    #[test]
    fn a_pattern_change_is_published_but_the_rule_is_judged_and_covers_as_published() {
        let changes = Changes {
            change: vec![change("key", Some("-----BEGIN KEY-----"), None)],
            own: Vec::new(),
        };
        let items = vec![
            rule("gitleaks", "key", r"-----BEGIN KEY-----[a-z]{20}-----END"),
            // Its example has the header alone: covered by the published pattern, not the rule.
            rule("betterleaks", "header", r"-----BEGIN KEY-----[a-z]{0,3}"),
        ];
        let sel = select(items, &changes).unwrap();
        assert_eq!(sel.picked.len(), 2);
        assert_eq!(sel.picked[0].pattern, "-----BEGIN KEY-----");
        assert_eq!(sel.picked[0].changed.as_deref(), Some("because"));
    }

    #[test]
    fn a_replace_change_is_judged_and_a_change_that_no_longer_applies_is_an_error() {
        let changes = Changes {
            change: vec![change("w", None, Some(["X", "[a-z]"]))],
            own: Vec::new(),
        };
        let sel = select(vec![rule("gitleaks", "w", r"abc_X{16}")], &changes).unwrap();
        assert_eq!(sel.picked[0].pattern, "abc_[a-z]{16}");
        let gone = select(vec![rule("gitleaks", "w", r"abc_[a-z]{16}")], &changes);
        assert!(gone.err().unwrap().contains("no longer has it"));
        let missing = select(vec![rule("gitleaks", "v", r"abc_[a-z]{16}")], &changes);
        assert!(missing.err().unwrap().contains("which no list has"));
    }
}
