//! A stand-in for curl, which records what it was handed and answers as told. Nothing that uses
//! it reaches the network.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use whimbrel::channels::SecretFile;
use whimbrel::request::Curl;

/// A curl that keeps its argv and stdin, prints `body` if that's set, then a line break and
/// `code` (200 by default) as `-w '\n%{http_code}'` would, and exits with `rc` (0 by default),
/// after sleeping `sleep` seconds if that's set.
pub struct Stub {
    pub dir: tempfile::TempDir,
}

const CURL: &str = r#"#!/bin/sh
d=$(dirname "$0")
printf '%s\n' "$@" > "$d/args"
cat > "$d/stdin"
# exec, so killing curl kills the sleep too, rather than leaving it holding other tests' pipes.
[ -f "$d/sleep" ] && exec sleep "$(cat "$d/sleep")"
[ -f "$d/body" ] && cat "$d/body"
printf '\n'
cat "$d/code" 2>/dev/null || printf 200
exit "$(cat "$d/rc" 2>/dev/null || echo 0)"
"#;

impl Stub {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        super::stub(dir.path(), "curl", CURL);
        Stub { dir }
    }

    pub fn curl(&self) -> Curl {
        Curl {
            program: self.dir.path().join("curl"),
            timeout: Duration::from_secs(2),
        }
    }

    pub fn answer(&self, code: &str, rc: u8) {
        fs::write(self.dir.path().join("code"), code).unwrap();
        fs::write(self.dir.path().join("rc"), rc.to_string()).unwrap();
    }

    /// The reply's body, printed before the status.
    pub fn reply(&self, body: &str) {
        fs::write(self.dir.path().join("body"), body).unwrap();
    }

    /// A secret file, owner-only, as the channels require.
    pub fn secret(&self, name: &str, value: &str) -> SecretFile {
        let path = self.dir.path().join(name);
        fs::write(&path, format!("{value}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        SecretFile::new(path).unwrap()
    }

    pub fn args(&self) -> String {
        fs::read_to_string(self.dir.path().join("args")).unwrap_or_default()
    }

    pub fn stdin(&self) -> String {
        fs::read_to_string(self.dir.path().join("stdin")).unwrap()
    }

    /// The value of one key in the curl config it was handed, unquoted.
    pub fn config(&self, key: &str) -> String {
        let all = self.config_all(key);
        all.into_iter()
            .next()
            .unwrap_or_else(|| panic!("no {key} in {:?}", self.stdin()))
    }

    /// Every value of `key` in the curl config it was handed, unquoted, in order.
    pub fn config_all(&self, key: &str) -> Vec<String> {
        self.stdin()
            .lines()
            .filter_map(|l| l.strip_prefix(&format!("{key} = ")))
            .map(unquote)
            .collect()
    }

    pub fn body(&self) -> serde_json::Value {
        serde_json::from_str(&self.config("data-binary")).unwrap()
    }

    pub fn called(&self) -> bool {
        self.dir.path().join("args").exists()
    }
}

/// curl's config quoting, undone: the test's own reading of it, not the code's.
fn unquote(s: &str) -> String {
    let inner = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap();
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next().unwrap() {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => out.push(other),
            }
        } else {
            out.push(c);
        }
    }
    out
}
