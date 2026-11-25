//! Generates whimbrel's built-in secret patterns from the lists they're taken from.
//!
//! ```text
//! secret-patterns write [--retire]       fetch the pinned lists, select, write every generated file
//! secret-patterns check                  the same, but change nothing and fail on any difference
//! secret-patterns bump <list> <commit> [<tag>] [--retire]
//!                                        pin a list at another commit, then write
//!
//! An id whose rule its list no longer has stops the run, since the list may have renamed it:
//! `--retire` retires such ids.
//! ```
//!
//! It reads `sources.toml` (the pins), `changes.toml` (the hand changes) and `ids.toml` (every id
//! given) beside its manifest, and writes `src/secret_patterns/builtins.rs`,
//! `src/secret_patterns/left-out.md`, the table in `docs/config.md`, the pin lines in
//! `THIRD-PARTY.md`, and `ids.toml`. Fetched files are cached in its `target/` by checksum.

mod changes;
mod extract;
mod ids;
mod output;
mod select;
mod sources;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use output::Row;

/// A TOML basic string.
pub fn toml_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out += "\\\"",
            '\\' => out += "\\\\",
            c if c.is_control() => out += &format!("\\u{:04X}", c as u32),
            c => out.push(c),
        }
    }
    out + "\""
}

struct Paths {
    tool: PathBuf,
    repo: PathBuf,
}

impl Paths {
    fn new() -> Self {
        let tool = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("the tool's own directory");
        let repo = tool
            .join("../..")
            .canonicalize()
            .expect("the tool is in a whimbrel checkout");
        Paths { tool, repo }
    }
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// What the generated files should hold, by path, and what changed in the built-ins.
fn generate(
    p: &Paths,
    sources: &sources::Sources,
    retire: bool,
) -> Result<BTreeMap<PathBuf, String>, String> {
    let changes = changes::load(&p.tool.join("changes.toml"))?;
    let mut ids = ids::load(&p.tool.join("ids.toml"))?;

    let cache = p.tool.join("target/sources");
    let mut items = Vec::new();
    for s in &sources.source {
        let files = s
            .files
            .iter()
            .map(|f| Ok((f.path.clone(), sources::fetch(s, f, &cache)?)))
            .collect::<Result<Vec<_>, String>>()?;
        items.extend(extract::extract(s, &files)?);
    }
    let read_count = items.len();
    // Only the rules it can read: one that turned into Go code the tool can't read is as gone as
    // one the list dropped, and a person should say which it is.
    let listed: BTreeSet<ids::Holder> = items
        .iter()
        .filter(|i| matches!(i, extract::Item::Rule(_)))
        .map(|i| ids::Holder {
            source: i.source().to_string(),
            rule: i.rule().to_string(),
        })
        .collect();
    let sel = select::select(items, &changes)?;
    let gone = ids::Gone {
        listed: &listed,
        retire,
    };
    let given = ids::assign(&mut ids, &sel.picked, &changes.own, gone, &mut || {
        last_release(&p.repo)
    })?;

    let mut rows: Vec<Row> = sel
        .picked
        .iter()
        .zip(given)
        .map(|(pk, id)| Row {
            id,
            source: pk.source.clone(),
            rule: pk.rule.clone(),
            pattern: pk.pattern.clone(),
            changed: pk.changed.clone(),
        })
        .collect();
    rows.extend(changes.own.iter().map(|o| Row {
        id: o.id.clone(),
        source: ids::OWN.into(),
        rule: o.why.clone(),
        pattern: o.pattern.clone(),
        changed: None,
    }));
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let retired: Vec<(String, String)> = ids
        .retired
        .iter()
        .map(|(id, r)| (id.clone(), r.last.clone()))
        .collect();

    let mut out = BTreeMap::new();
    out.insert(
        p.repo.join("src/secret_patterns/builtins.rs"),
        output::rust(&rows, &retired)?,
    );
    out.insert(
        p.repo.join("src/secret_patterns/left-out.md"),
        output::left_out(read_count, sel.picked.len(), &sel.left),
    );
    let docs = p.repo.join("docs/config.md");
    let table = format!(
        "{}\n\n{}\n{}",
        output::DOCS_BEGIN,
        output::docs_table(&rows),
        output::END
    );
    out.insert(
        docs.clone(),
        output::splice(&read(&docs)?, output::DOCS_BEGIN, output::END, &table)
            .map_err(|e| format!("docs/config.md: {e}"))?,
    );
    let third = p.repo.join("THIRD-PARTY.md");
    let mut text = read(&third)?;
    for s in &sources.source {
        text = output::splice(
            &text,
            &output::pin_begin(&s.name),
            output::END,
            &output::pin(s),
        )
        .map_err(|e| format!("THIRD-PARTY.md: {e}"))?;
    }
    out.insert(third, text);
    out.insert(p.tool.join("ids.toml"), ids::render(&ids));
    out.insert(p.tool.join("sources.toml"), sources::render(sources));
    Ok(out)
}

/// The last release in the history of `repo`'s HEAD, as `0.3.0`: the last that had an id retired
/// now. From its tags, so a version bumped ahead of a release doesn't count.
fn last_release(repo: &Path) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "tag",
            "--merged",
            "HEAD",
            "--list",
            "v[0-9]*",
            "--sort=-v:refname",
        ])
        .output()
        .map_err(|e| format!("couldn't run git to find the last release: {e}"))?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .filter(|_| out.status.success())
        .and_then(|tag| tag.strip_prefix('v'))
        .map(str::to_string)
        .ok_or_else(|| {
            "an id is retired, and no release tag is in HEAD's history to say which release last \
             had it: fetch the tags (git fetch --tags)"
                .to_string()
        })
}

/// The built-ins' ids and patterns in a generated Rust table, for saying what a run changed.
fn table(rust: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut id = None;
    for line in rust.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("id: \"") {
            id = rest.strip_suffix("\",").map(str::to_string);
        } else if let Some(pattern) = line.strip_prefix("pattern: ")
            && let Some(i) = id.take()
        {
            out.insert(i, pattern.trim_end_matches(',').to_string());
        }
    }
    out
}

fn summarize(before: &str, after: &str) {
    let (b, a) = (table(before), table(after));
    let added: Vec<_> = a.keys().filter(|k| !b.contains_key(*k)).collect();
    let gone: Vec<_> = b.keys().filter(|k| !a.contains_key(*k)).collect();
    let changed: Vec<_> = a
        .iter()
        .filter(|(k, v)| b.get(*k).is_some_and(|old| old != *v))
        .map(|(k, _)| k)
        .collect();
    println!(
        "{} built-ins: {} added, {} removed, {} with a changed pattern",
        a.len(),
        added.len(),
        gone.len(),
        changed.len()
    );
    for (what, ids) in [("added", added), ("removed", gone), ("changed", changed)] {
        for id in ids {
            println!("  {what} {id}");
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let retire = args.iter().any(|a| a == "--retire");
    args.retain(|a| a != "--retire");
    let p = Paths::new();
    let pins = p.tool.join("sources.toml");
    let mut sources = sources::load(&pins)?;
    let check = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["write"] => false,
        ["check"] if !retire => true,
        ["bump", name, commit, ref tag @ ..] if tag.len() <= 1 => {
            let s = sources
                .source
                .iter_mut()
                .find(|s| s.name == name)
                .ok_or_else(|| format!("sources.toml has no list {name:?}"))?;
            sources::bump(s, commit, tag.first().map(|t| t.to_string()))?;
            false
        }
        _ => {
            return Err(
                "usage: secret-patterns write [--retire] | check | bump <list> <commit> [<tag>] [--retire]"
                    .into(),
            );
        }
    };
    let rust_path = p.repo.join("src/secret_patterns/builtins.rs");
    let before = std::fs::read_to_string(&rust_path).unwrap_or_default();
    let files = generate(&p, &sources, retire)?;
    let mut stale = Vec::new();
    for (path, text) in &files {
        if std::fs::read_to_string(path).ok().as_deref() != Some(text.as_str()) {
            stale.push(path);
            if !check {
                std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
            }
        }
    }
    summarize(&before, &files[&rust_path]);
    let shown = |path: &PathBuf| {
        path.strip_prefix(&p.repo)
            .map_or_else(|_| path.display().to_string(), |r| r.display().to_string())
    };
    if check && !stale.is_empty() {
        for path in &stale {
            eprintln!("{} isn't what the tool writes", shown(path));
        }
        eprintln!(
            "Don't edit generated files by hand. Change sources.toml, changes.toml or ids.toml \
             and run: cargo run --locked --manifest-path tools/secret-patterns/Cargo.toml -- write"
        );
        return Ok(ExitCode::FAILURE);
    }
    for path in &stale {
        println!("wrote {}", shown(path));
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    run().unwrap_or_else(|e| {
        eprintln!("secret-patterns: {e}");
        ExitCode::FAILURE
    })
}
