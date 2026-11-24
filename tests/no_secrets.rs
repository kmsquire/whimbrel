//! The repo's own files hold nothing a built-in secret pattern matches: every example a test needs
//! is built at run time, so a public repo's secret scanning never sees a token-shaped string here.

use std::fs;
use std::path::{Path, PathBuf};

use whimbrel::secret_patterns::SecretPatterns;

/// Every file under `dir`, but not build output or git's own.
fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let path = e.path();
        let name = e.file_name();
        if [".git", "target", "dist"].iter().any(|n| name == *n) {
            continue;
        }
        if e.file_type().unwrap().is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn no_file_in_the_repo_holds_or_is_named_with_a_token_shaped_string() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut all = Vec::new();
    files(root, &mut all);
    assert!(all.iter().any(|p| p.ends_with("src/secret_patterns.rs")));
    let patterns = SecretPatterns::builtins();
    let mut found = Vec::new();
    for path in &all {
        let name = path.strip_prefix(root).unwrap().to_string_lossy();
        if patterns.found_in(name.as_bytes()) {
            found.push(format!("the name {name}"));
        }
        let bytes = fs::read(path).unwrap();
        for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
            if patterns.found_in(line) {
                found.push(format!("{}:{}", path.display(), i + 1));
            }
        }
    }
    assert!(found.is_empty(), "token-shaped strings at {found:?}");
}
