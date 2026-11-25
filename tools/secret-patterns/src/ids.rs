//! Ids are part of the config contract: `disable` names them. So an id, once given to a rule,
//! stays with that rule. `ids.toml` records every id given; a new rule gets a new id, and one that
//! leaves is retired with the release it was last in, never reused. A rule an upstream list
//! renames is a new rule unless someone points its old id at the new name in `ids.toml`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::changes::Own;
use crate::select::Picked;
use crate::toml_str;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Ids {
    #[serde(default)]
    pub id: BTreeMap<String, Holder>,
    #[serde(default)]
    pub retired: BTreeMap<String, Retired>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Holder {
    pub source: String,
    pub rule: String,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Retired {
    pub source: String,
    pub rule: String,
    /// The last release that had it.
    pub last: String,
}

pub fn load(path: &std::path::Path) -> Result<Ids, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// What a rule's id would be if it had none: its name in kebab case.
fn derive(p: &Picked) -> String {
    let id = match p.rule.split_once(' ') {
        Some((path, var)) if p.source == "osv-scalibr" => {
            let var = ["Regexp", "Regex", "Pattern", "Re", "RE"]
                .iter()
                .find_map(|s| var.strip_suffix(s))
                .unwrap_or(var);
            let mut kebab = String::new();
            let mut prev = None::<char>;
            for c in var.chars() {
                if c.is_ascii_uppercase()
                    && prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
                {
                    kebab.push('-');
                }
                kebab.push(c);
                prev = Some(c);
            }
            format!("{}-{kebab}", path.rsplit('/').next().unwrap_or(path))
        }
        _ => p.rule.replace('.', "-"),
    };
    id.to_lowercase()
}

/// The source whimbrel's own patterns are held under, each by its id.
pub const OWN: &str = "whimbrel";

/// What an id must be: lowercase letters, digits and hyphens.
fn check_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "{id:?} isn't lowercase letters, digits and hyphens"
        ));
    }
    Ok(())
}

/// How [`assign`] treats an id whose rule isn't in its list any more.
pub struct Gone<'a> {
    /// Every rule the lists hold now, taken or not.
    pub listed: &'a BTreeSet<Holder>,
    /// Whether to retire such an id. Otherwise it's an error: the rule may have been renamed,
    /// and only a person can say so.
    pub retire: bool,
}

/// Each picked rule's id, in `picked`'s order, and `ids` brought up to date: new rules and
/// whimbrel's own patterns given ids, and the ids of those no longer taken retired with the
/// release `last_release` names, asked only if one is.
pub fn assign(
    ids: &mut Ids,
    picked: &[Picked],
    own: &[Own],
    gone: Gone,
    last_release: &mut dyn FnMut() -> Result<String, String>,
) -> Result<Vec<String>, String> {
    // Every id given, live or retired, by the rule it names. Two ids for one rule would leave
    // one of them to chance.
    let mut by_rule: BTreeMap<Holder, String> = BTreeMap::new();
    let held = ids
        .id
        .iter()
        .map(|(id, h)| (id, h.clone()))
        .chain(ids.retired.iter().map(|(id, r)| {
            (
                id,
                Holder {
                    source: r.source.clone(),
                    rule: r.rule.clone(),
                },
            )
        }));
    for (id, h) in held {
        if let Some(other) = by_rule.insert(h.clone(), id.clone()) {
            return Err(format!(
                "ids.toml gives {} {:?} two ids, {other:?} and {id:?}: keep one",
                h.source, h.rule
            ));
        }
    }
    let mut taken: BTreeSet<String> = ids.id.keys().chain(ids.retired.keys()).cloned().collect();
    let mut live = BTreeMap::new();
    for o in own {
        check_id(&o.id)?;
        let holder = Holder {
            source: OWN.into(),
            rule: o.id.clone(),
        };
        if taken.contains(&o.id) && by_rule.get(&holder) != Some(&o.id) {
            return Err(format!(
                "whimbrel's own {:?} has an id a list's rule has or had",
                o.id
            ));
        }
        taken.insert(o.id.clone());
        if live.insert(o.id.clone(), holder).is_some() {
            return Err(format!("two of whimbrel's own have the id {:?}", o.id));
        }
    }
    let mut out = Vec::new();
    for p in picked {
        let holder = Holder {
            source: p.source.clone(),
            rule: p.rule.clone(),
        };
        let id = match by_rule.get(&holder) {
            Some(id) => id.clone(),
            None => {
                let base = derive(p);
                let id = [base.clone(), format!("{base}-{}", p.source)]
                    .into_iter()
                    .find(|i| !taken.contains(i))
                    .ok_or_else(|| {
                        format!(
                            "no free id for {} {:?}: give it one in ids.toml",
                            p.source, p.rule
                        )
                    })?;
                taken.insert(id.clone());
                id
            }
        };
        check_id(&id)?;
        if live.insert(id.clone(), holder).is_some() {
            return Err(format!("two rules have the id {id:?}"));
        }
        out.push(id);
    }
    // Nothing in `ids` changes until nothing can fail.
    let leaving: Vec<(String, Holder)> = ids
        .id
        .iter()
        .filter(|(id, _)| !live.contains_key(*id))
        .map(|(id, h)| (id.clone(), h.clone()))
        .collect();
    let vanished: Vec<String> = leaving
        .iter()
        .filter(|(_, h)| h.source != OWN && !gone.listed.contains(h))
        .map(|(id, h)| format!("{id} ({} {:?})", h.source, h.rule))
        .collect();
    if !vanished.is_empty() && !gone.retire {
        return Err(format!(
            "these ids' rules aren't in their lists any more, or the tool can't read them: {}. If \
             a list renamed one, point its id at the new name in ids.toml. If the lists dropped \
             them, rerun with --retire.",
            vanished.join(", ")
        ));
    }
    let last = if leaving.is_empty() {
        String::new()
    } else {
        last_release()?
    };
    {
        for (id, h) in leaving {
            ids.retired.insert(
                id,
                Retired {
                    source: h.source,
                    rule: h.rule,
                    last: last.clone(),
                },
            );
        }
    }
    ids.retired.retain(|id, _| !live.contains_key(id));
    ids.id = live;
    Ok(out)
}

/// `ids.toml` as the tool writes it.
pub fn render(ids: &Ids) -> String {
    let mut out = String::from(
        "# Every id a built-in pattern has had, and the rule it names: a list's, or whimbrel's own under\n\
         # source \"whimbrel\". The tool keeps this file:\n\
         # it gives a new rule a new id, and retires the id of a rule that leaves, with the last release\n\
         # that had it. An id is never reused. When a list renames a rule, keep its id by pointing it at\n\
         # the new name here.\n\n[id]\n",
    );
    for (id, h) in &ids.id {
        out += &format!(
            "{} = {{ source = {}, rule = {} }}\n",
            toml_str(id),
            toml_str(&h.source),
            toml_str(&h.rule)
        );
    }
    out += "\n[retired]\n";
    for (id, r) in &ids.retired {
        out += &format!(
            "{} = {{ source = {}, rule = {}, last = {} }}\n",
            toml_str(id),
            toml_str(&r.source),
            toml_str(&r.rule),
            toml_str(&r.last)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pick(source: &str, rule: &str) -> Picked {
        Picked {
            source: source.into(),
            rule: rule.into(),
            pattern: String::new(),
            changed: None,
        }
    }

    fn holder(source: &str, rule: &str) -> Holder {
        Holder {
            source: source.into(),
            rule: rule.into(),
        }
    }

    fn own(id: &str) -> Own {
        Own {
            id: id.into(),
            pattern: String::new(),
            why: String::new(),
        }
    }

    /// `assign`, with every picked rule listed, the lists also holding `listed`, and `version` the
    /// last release.
    fn run(
        ids: &mut Ids,
        picked: &[Picked],
        owns: &[Own],
        listed: &[Holder],
        retire: bool,
        version: &str,
    ) -> Result<Vec<String>, String> {
        let mut all: BTreeSet<Holder> = listed.iter().cloned().collect();
        all.extend(picked.iter().map(|p| holder(&p.source, &p.rule)));
        let gone = Gone {
            listed: &all,
            retire,
        };
        assign(ids, picked, owns, gone, &mut || Ok(version.to_string()))
    }

    #[test]
    fn an_id_stays_with_its_rule_and_a_new_rule_never_takes_a_given_one() {
        let mut ids = Ids::default();
        let first = [pick("betterleaks", "foo-token")];
        assert_eq!(
            run(&mut ids, &first, &[], &[], false, "0.3.0").unwrap(),
            ["foo-token"]
        );
        // An earlier list gains a rule of the same name: the id stays where it was.
        let second = [
            pick("gitleaks", "foo-token"),
            pick("betterleaks", "foo-token"),
        ];
        assert_eq!(
            run(&mut ids, &second, &[], &[], false, "0.3.0").unwrap(),
            ["foo-token-gitleaks", "foo-token"]
        );
    }

    #[test]
    fn a_rule_left_out_retires_its_id_and_one_that_returns_gets_it_back() {
        let mut ids = Ids::default();
        let both = [pick("gitleaks", "a.1"), pick("gitleaks", "b")];
        run(&mut ids, &both, &[], &[], false, "0.3.0").unwrap();
        // Still in its list, but no longer taken.
        let listed = [holder("gitleaks", "a.1")];
        run(
            &mut ids,
            &[pick("gitleaks", "b")],
            &[],
            &listed,
            false,
            "0.4.0",
        )
        .unwrap();
        assert_eq!(ids.retired["a-1"].last, "0.4.0");
        assert!(!ids.id.contains_key("a-1"));
        // A new rule whose name would give the retired id doesn't get it.
        let other = [pick("betterleaks", "a.1")];
        let now = run(&mut ids, &other, &[], &listed, true, "0.5.0").unwrap();
        assert_eq!(now, ["a-1-betterleaks"]);
        let back = run(
            &mut ids,
            &[pick("gitleaks", "a.1")],
            &[],
            &[],
            true,
            "0.6.0",
        )
        .unwrap();
        assert_eq!(back, ["a-1"]);
        assert!(!ids.retired.contains_key("a-1"));
    }

    #[test]
    fn a_rule_gone_from_its_list_retires_its_id_only_when_asked() {
        let mut ids = Ids::default();
        run(&mut ids, &[pick("gitleaks", "a")], &[], &[], false, "0.3.0").unwrap();
        let why = run(&mut ids, &[], &[], &[], false, "0.3.0").unwrap_err();
        assert!(why.contains("a (gitleaks \"a\")"), "{why}");
        assert!(ids.retired.is_empty());
        run(&mut ids, &[], &[], &[], true, "0.3.0").unwrap();
        assert_eq!(ids.retired["a"].last, "0.3.0");
    }

    #[test]
    fn the_last_release_is_asked_for_only_when_an_id_is_retired() {
        let mut ids = Ids::default();
        let all = BTreeSet::new();
        let gone = || Gone {
            listed: &all,
            retire: true,
        };
        let mut never = || -> Result<String, String> { Err("asked".into()) };
        assign(&mut ids, &[], &[own("x-y")], gone(), &mut never).unwrap();
        let mut all = BTreeSet::new();
        all.insert(holder("gitleaks", "a"));
        let listed = Gone {
            listed: &all,
            retire: false,
        };
        assign(
            &mut ids,
            &[pick("gitleaks", "a")],
            &[own("x-y")],
            listed,
            &mut never,
        )
        .unwrap();
    }

    #[test]
    fn two_ids_for_one_rule_are_refused() {
        let mut ids = Ids::default();
        ids.id.insert("foo".into(), holder("gitleaks", "foo-v2"));
        ids.id.insert("foo-v2".into(), holder("gitleaks", "foo-v2"));
        let why = run(
            &mut ids,
            &[pick("gitleaks", "foo-v2")],
            &[],
            &[],
            false,
            "0.3.0",
        );
        assert!(why.unwrap_err().contains("two ids"));
    }

    #[test]
    fn our_own_ids_are_kept_retired_and_never_given_to_a_list() {
        let mut ids = Ids::default();
        run(
            &mut ids,
            &[],
            &[own("password-in-url")],
            &[],
            false,
            "0.3.0",
        )
        .unwrap();
        assert_eq!(ids.id["password-in-url"], holder(OWN, "password-in-url"));
        // A list's rule of that name gets another id.
        let rule = [pick("gitleaks", "password-in-url")];
        let got = run(
            &mut ids,
            &rule,
            &[own("password-in-url")],
            &[],
            false,
            "0.3.0",
        )
        .unwrap();
        assert_eq!(got, ["password-in-url-gitleaks"]);
        // Ours dropped: retired, with no --retire needed.
        run(&mut ids, &rule, &[], &[], false, "0.4.0").unwrap();
        assert_eq!(ids.retired["password-in-url"].last, "0.4.0");
        // And not taken back by a list.
        let mut fresh = Ids {
            retired: ids.retired.clone(),
            ..Default::default()
        };
        let again = run(
            &mut fresh,
            &[pick("betterleaks", "password-in-url")],
            &[],
            &[],
            false,
            "0.4.0",
        );
        assert_eq!(again.unwrap(), ["password-in-url-betterleaks"]);
        assert!(run(&mut ids, &[], &[own("Bad Id")], &[], true, "0.4.0").is_err());
    }

    #[test]
    fn an_osv_scalibr_variable_becomes_a_kebab_case_id() {
        let p = pick("osv-scalibr", "veles/secrets/gcpoauth2access accessTokenRe");
        assert_eq!(derive(&p), "gcpoauth2access-access-token");
    }
}
