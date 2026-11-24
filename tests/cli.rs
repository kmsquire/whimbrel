//! The binary's --version, checked against values worked out here rather than whimbrel::COMMIT.

use std::process::Command;

#[test]
fn version_names_the_binary_and_the_commit_it_was_built_from() {
    let out = Command::new(env!("CARGO_BIN_EXE_whimbrel"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    // CI builds and tests with WHIMBREL_COMMIT set; a local build has none.
    let commit = std::env::var("WHIMBREL_COMMIT").unwrap_or_else(|_| "unknown".into());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("whimbrel {} ({commit})\n", env!("CARGO_PKG_VERSION"))
    );
}
