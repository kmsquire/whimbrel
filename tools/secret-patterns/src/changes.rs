//! The hand changes, read from `changes.toml`: a rule's token replaced whole or in part, and
//! whimbrel's own patterns. Each says why, and the reason is published beside the pattern.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Changes {
    #[serde(default)]
    pub change: Vec<Change>,
    #[serde(default)]
    pub own: Vec<Own>,
}

/// A change to one rule: `replace` changes its token before the selection rule judges it;
/// `pattern` is published in its place, and the rule is judged as its list publishes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub source: String,
    pub rule: String,
    /// What's published in place of the rule's token, if the rule is taken.
    pub pattern: Option<String>,
    /// `[from, to]`: every `from` in the token becomes `to`.
    pub replace: Option<[String; 2]>,
    pub why: String,
}

/// One of whimbrel's own patterns.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Own {
    pub id: String,
    pub pattern: String,
    pub why: String,
}

impl Change {
    /// The token with `replace` applied. A change has one of `pattern` and `replace`.
    pub fn apply(&self, token: &str) -> Result<String, String> {
        match (&self.pattern, &self.replace) {
            (Some(_), None) => Ok(token.to_string()),
            (None, Some([from, to])) if token.contains(from.as_str()) => {
                Ok(token.replace(from.as_str(), to))
            }
            (None, Some([from, _])) => Err(format!(
                "changes.toml replaces {from:?} in {} {:?}, whose token no longer has it",
                self.source, self.rule
            )),
            _ => Err(format!(
                "changes.toml: the change to {} {:?} needs one of `pattern` or `replace`",
                self.source, self.rule
            )),
        }
    }
}

pub fn load(path: &std::path::Path) -> Result<Changes, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}
