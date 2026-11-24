//! What the release workflow and the README promise about where whimbrel runs from, checked
//! against the files themselves, since nothing here can run the workflow.

const CI: &str = include_str!("../.github/workflows/ci.yml");
const README: &str = include_str!("../README.md");
const TOOLCHAIN: &str = include_str!("../rust-toolchain.toml");

#[test]
fn nothing_is_published_while_the_repo_is_private() {
    let publish = CI.split("\n  publish:\n").nth(1).expect("a publish job");
    let cond = publish
        .lines()
        .find_map(|l| l.trim().strip_prefix("if: "))
        .expect("an if on the publish job");
    assert_eq!(
        cond,
        "startsWith(github.ref, 'refs/tags/v') && !github.event.repository.private"
    );
}

#[test]
fn every_target_is_built_and_published() {
    let targets: Vec<&str> = TOOLCHAIN
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.split('"').next())
        .collect();
    assert_eq!(targets.len(), 4, "{targets:?}");
    for t in &targets {
        assert!(
            CI.contains(&format!("- target: {t}\n")),
            "{t} isn't in the matrix"
        );
        assert!(
            README.contains(&format!("`{t}`")),
            "{t} isn't in the README"
        );
    }
    assert!(CI.contains(&format!("[[ $found == {} ]]", targets.len())));
}

#[test]
fn the_mac_runs_whimbrel_from_a_directory_of_its_own() {
    // On a Mac with Homebrew, /usr/local/bin belongs to a user, who could then replace what
    // the LaunchDaemon runs as root.
    let plist = README
        .split("<key>ProgramArguments</key>")
        .nth(1)
        .expect("a LaunchDaemon plist");
    let program = plist
        .split("<string>")
        .nth(1)
        .and_then(|s| s.split("</string>").next())
        .unwrap();
    assert_eq!(program, "/opt/whimbrel/bin/whimbrel");
    assert!(README.contains("B=/usr/local/bin        # Mac: B=/opt/whimbrel/bin"));
    assert!(README.contains("must belong to root and be writable by root alone"));
}
