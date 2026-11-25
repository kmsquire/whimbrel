//! Every rule of a list, in the list's order, as published. Nothing is chosen here.
//!
//! osv-scalibr's rules are Go source, read by matching text, not by parsing Go: a call of
//! `regexp.MustCompile` (or `Compile`) whose one argument is a raw string literal, assigned to a
//! name, is a rule. A pattern built any other way (joined from pieces, or from a variable) can't be
//! read like that, so it's reported as left out with that reason rather than dropped quietly, and a
//! list that yields no rule at all is an error.

use std::collections::BTreeMap;

use crate::sources::{Format, Source};

/// One rule as its list publishes it.
pub struct Rule {
    pub source: String,
    /// Its id in a TOML list; `<directory> <variable>` in Go.
    pub rule: String,
    /// The regex less a trailing non-capturing group ending in `|$)`, the boundary a list matches
    /// after a token.
    pub core: String,
}

/// A rule, or something that looked like one and couldn't be read as one.
pub enum Item {
    Rule(Rule),
    Unread {
        source: String,
        rule: String,
        why: &'static str,
    },
}

pub fn extract(source: &Source, files: &[(String, Vec<u8>)]) -> Result<Vec<Item>, String> {
    let mut out = Vec::new();
    match source.format {
        Format::Toml => {
            for (path, bytes) in files {
                let text = std::str::from_utf8(bytes).map_err(|e| format!("{path}: {e}"))?;
                let doc: toml::Table = toml::from_str(text).map_err(|e| format!("{path}: {e}"))?;
                let rules = doc
                    .get("rules")
                    .and_then(|r| r.as_array())
                    .ok_or_else(|| format!("{path} has no [[rules]]"))?;
                for r in rules {
                    let id = r
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{path}: a rule has no id"))?;
                    match r.get("regex").and_then(|v| v.as_str()) {
                        Some(regex) => out.push(Item::Rule(Rule {
                            source: source.name.clone(),
                            rule: id.to_string(),
                            core: strip_boundary(regex).to_string(),
                        })),
                        None => out.push(Item::Unread {
                            source: source.name.clone(),
                            rule: id.to_string(),
                            why: "it has no regex for what's in a file",
                        }),
                    }
                }
            }
        }
        Format::Go => {
            // In directory order, then file order, as a walk of the tree visits them.
            let mut by_dir: BTreeMap<&str, Vec<(&str, &[u8])>> = BTreeMap::new();
            for (path, bytes) in files {
                let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
                by_dir.entry(dir).or_default().push((name, bytes));
            }
            let mut found = Vec::new();
            for (dir, mut names) in by_dir {
                names.sort_by_key(|(n, _)| *n);
                for (name, bytes) in names {
                    let text =
                        std::str::from_utf8(bytes).map_err(|e| format!("{dir}/{name}: {e}"))?;
                    go_rules(&source.name, dir, name, text, &mut found);
                }
            }
            out.extend(unique_names(found));
        }
    }
    let mut names = std::collections::BTreeSet::new();
    if let Some(dup) = out.iter().find(|i| !names.insert(i.rule())) {
        return Err(format!(
            "{} has two rules named {:?}",
            source.name,
            dup.rule()
        ));
    }
    if !out.iter().any(|i| matches!(i, Item::Rule(_))) {
        return Err(format!(
            "{} at {} yields no rule: has the list moved or changed form?",
            source.name, source.commit
        ));
    }
    Ok(out)
}

/// `rx` less its last top-level group, if that ends the regex and is `(?:…|$)`.
pub fn strip_boundary(rx: &str) -> &str {
    let b = rx.as_bytes();
    let (mut i, mut depth, mut start, mut last, mut in_class) = (0, 0, 0, None, false);
    while i < b.len() {
        let c = b[i];
        if c == b'\\' {
            i += 2;
            continue;
        }
        if in_class {
            if c == b']' {
                in_class = false;
            }
        } else if c == b'[' {
            in_class = true;
            if b.get(i + 1) == Some(&b']') {
                i += 1;
            }
        } else if c == b'(' {
            if depth == 0 {
                start = i;
            }
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                last = Some((start, i));
            }
        }
        i += 1;
    }
    match last {
        Some((s, e)) if e == b.len() - 1 => {
            let g = &rx[s..=e];
            if g.starts_with("(?:") && g.ends_with("|$)") {
                &rx[..s]
            } else {
                rx
            }
        }
        _ => rx,
    }
}

const CALLS: [&str; 4] = [
    "regexp.MustCompile(",
    "regexp.Compile(",
    "regexp.MustCompilePOSIX(",
    "regexp.CompilePOSIX(",
];

/// Each call in one Go file, as an item named `<directory> <variable>`, and the name it takes
/// instead if another call in the directory has that name: `<directory>/<file> <variable>`.
fn go_rules(source: &str, dir: &str, file: &str, text: &str, out: &mut Vec<(String, Item)>) {
    let mut at = 0;
    while let Some((start, call)) = CALLS
        .iter()
        .filter_map(|c| text[at..].find(c).map(|i| (at + i, *c)))
        .min_by_key(|(i, c)| (*i, std::cmp::Reverse(c.len())))
    {
        at = start + call.len();
        let line = text[..start].matches('\n').count() + 1;
        // The name it's assigned to: `name = regexp…` or `name: regexp…`, on the same line.
        let before = text[..start].rsplit('\n').next().unwrap_or("");
        let name = before
            .trim_end()
            .strip_suffix(['=', ':'])
            .map(str::trim_end)
            .and_then(|s| {
                let n = s
                    .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .next()?;
                (!n.is_empty()).then_some(n)
            });
        let literal = call == "regexp.MustCompile(" && name.is_some();
        let arg = text[at..].trim_start();
        let pattern = literal
            .then(|| arg.strip_prefix('`'))
            .flatten()
            .and_then(|rest| {
                let end = rest.find('`')?;
                let after = rest[end + 1..].trim_start();
                let after = after.strip_prefix(',').map_or(after, str::trim_start);
                after.starts_with(')').then(|| &rest[..end])
            });
        let (rule, qualified) = match name {
            Some(n) => (format!("{dir} {n}"), format!("{dir}/{file} {n}")),
            None => (
                format!("{dir}/{file}:{line}"),
                format!("{dir}/{file}:{line}"),
            ),
        };
        let item = match pattern {
            Some(p) => Item::Rule(Rule {
                source: source.to_string(),
                rule,
                core: p.to_string(),
            }),
            None => Item::Unread {
                source: source.to_string(),
                rule,
                why: "its pattern is built by Go code, not one literal, so the tool can't read it",
            },
        };
        out.push((qualified, item));
    }
}

impl Item {
    pub fn source(&self) -> &str {
        match self {
            Item::Rule(r) => &r.source,
            Item::Unread { source, .. } => source,
        }
    }

    pub fn rule(&self) -> &str {
        match self {
            Item::Rule(r) => &r.rule,
            Item::Unread { rule, .. } => rule,
        }
    }

    fn rule_mut(&mut self) -> &mut String {
        match self {
            Item::Rule(r) => &mut r.rule,
            Item::Unread { rule, .. } => rule,
        }
    }
}

/// The items, each named so that no two share a name: a name two calls share takes its file, and
/// one two calls in a file share takes the start of its pattern's SHA-256, `#3f2a9c1e`, so the name
/// moves with the pattern, not with its place, and a changed pattern is a new name, which stops a
/// run that would retire the old one's id. A call the tool can't read has no pattern to name it
/// by, so it takes its place among those, `#1`, `#2`; it never has an id.
fn unique_names(found: Vec<(String, Item)>) -> Vec<Item> {
    let count = |names: Vec<&str>| {
        let mut n: BTreeMap<String, usize> = BTreeMap::new();
        for name in names {
            *n.entry(name.to_string()).or_default() += 1;
        }
        n
    };
    let short = count(found.iter().map(|(_, i)| i.rule()).collect());
    let long = count(found.iter().map(|(q, _)| q.as_str()).collect());
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    found
        .into_iter()
        .map(|(qualified, mut item)| {
            if short[item.rule()] > 1 {
                *item.rule_mut() = match &item {
                    _ if long[&qualified] == 1 => qualified,
                    Item::Rule(r) => {
                        format!(
                            "{qualified} #{}",
                            &crate::sources::sha256(r.core.as_bytes())[..8]
                        )
                    }
                    Item::Unread { .. } => {
                        let n = seen.entry(qualified.clone()).or_default();
                        *n += 1;
                        format!("{qualified} #{n}")
                    }
                };
            }
            item
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        go_rules("osv-scalibr", "veles/secrets/x", "d.go", text, &mut out);
        unique_names(out)
            .into_iter()
            .map(|i| match i {
                Item::Rule(r) => (r.rule, Some(r.core)),
                Item::Unread { rule, .. } => (rule, None),
            })
            .collect()
    }

    #[test]
    fn a_literal_is_read_on_its_line_or_the_next_and_anything_else_is_reported() {
        let text = "var a = regexp.MustCompile(`abc[0-9]+`)\n\
                    var b = regexp.MustCompile(\n\t`def`,\n)\n\
                    var c = regexp.MustCompile(`(?i)` +\n\t`x`)\n\
                    \tre: regexp.MustCompile(`ghi`),\n\
                    \treturn regexp.MustCompile(\"(?i)\" + k)\n";
        assert_eq!(
            read(text),
            [
                ("veles/secrets/x a".into(), Some("abc[0-9]+".into())),
                ("veles/secrets/x b".into(), Some("def".into())),
                ("veles/secrets/x c".into(), None),
                ("veles/secrets/x re".into(), Some("ghi".into())),
                ("veles/secrets/x/d.go:8".into(), None),
            ]
        );
    }

    #[test]
    fn a_name_two_calls_share_takes_its_file_and_then_its_patterns_hash() {
        let mut out = Vec::new();
        let d = "veles/secrets/http";
        let mut read = |file: &str, text: &str| go_rules("osv-scalibr", d, file, text, &mut out);
        read("a.go", "x: regexp.MustCompile(`aaa`)\n");
        read("b.go", "x: regexp.MustCompile(`bbb`)\n");
        read(
            "c.go",
            "x: regexp.MustCompile(`ccc`)\nx: regexp.MustCompile(`ddd`)\n",
        );
        read("c.go", "y = regexp.MustCompile(`eee`)\n");
        read(
            "e.go",
            "x: regexp.MustCompile(a + b)\nx: regexp.MustCompile(c + d)\n",
        );
        let names: Vec<String> = unique_names(out)
            .iter()
            .map(|i| i.rule().to_string())
            .collect();
        // The start of the SHA-256 of `ccc` and of `ddd`, from shasum, not from the tool.
        assert_eq!(
            names,
            [
                "veles/secrets/http/a.go x",
                "veles/secrets/http/b.go x",
                "veles/secrets/http/c.go x #64daa44a",
                "veles/secrets/http/c.go x #730f75da",
                "veles/secrets/http y",
                "veles/secrets/http/e.go x #1",
                "veles/secrets/http/e.go x #2",
            ]
        );
    }

    #[test]
    fn a_shared_name_moves_with_its_pattern_not_its_place() {
        let names = |text: &str| -> Vec<(String, String)> {
            let mut out = Vec::new();
            go_rules("osv-scalibr", "veles/secrets/http", "c.go", text, &mut out);
            unique_names(out)
                .into_iter()
                .filter_map(|i| match i {
                    Item::Rule(r) => Some((r.rule, r.core)),
                    Item::Unread { .. } => None,
                })
                .collect()
        };
        let x = |p: &str| format!("x: regexp.MustCompile(`{p}`)\n");
        let before = names(&[x("ccc"), x("ddd")].concat());
        // Another call of that name inserted above both: each keeps its name and its pattern.
        let after = names(&[x("zzz"), x("ccc"), x("ddd")].concat());
        assert_eq!(after.len(), 3);
        for named in &before {
            assert!(after.contains(named), "{named:?} isn't in {after:?}");
        }
    }

    #[test]
    fn the_boundary_group_alone_is_stripped() {
        assert_eq!(
            strip_boundary(r"\b(ab[c)]{3})(?:[\x60'\s;]|\\[nr]|$)"),
            r"\b(ab[c)]{3})"
        );
        assert_eq!(strip_boundary(r"ab(?:c|d)"), r"ab(?:c|d)");
        assert_eq!(strip_boundary(r"ab(c|$)"), r"ab(c|$)");
    }
}
