//! The docs against the code: what a reader copies from them works.

use whimbrel::checks::KINDS;
use whimbrel::config::Config;
use whimbrel::secret_patterns::BUILTINS;

const CONFIG_MD: &str = include_str!("../docs/config.md");
const README: &str = include_str!("../README.md");

/// Every fenced block in `md` whose info string is `lang`.
fn blocks<'a>(md: &'a str, lang: &str) -> Vec<&'a str> {
    let open = format!("```{lang}\n");
    md.split(open.as_str())
        .skip(1)
        .map(|rest| rest.split("```").next().unwrap())
        .collect()
}

#[test]
fn the_reference_lists_every_builtin_pattern_in_order() {
    let listed: Vec<&str> = CONFIG_MD
        .lines()
        .skip_while(|l| !l.starts_with("### Built-in patterns"))
        .take_while(|l| !l.starts_with("## "))
        .filter_map(|l| l.strip_prefix("| `"))
        .filter_map(|l| l.split('`').next())
        .collect();
    let ids: Vec<&str> = BUILTINS.iter().map(|s| s.id).collect();
    assert_eq!(listed, ids);
}

#[test]
fn every_check_example_in_the_docs_builds() {
    let mut seen = Vec::new();
    for block in blocks(CONFIG_MD, "toml")
        .into_iter()
        .chain(blocks(README, "toml"))
    {
        let base = "host = \"the web server\"\nstate_dir = \"/var/lib/whimbrel\"\n";
        let text = if block.contains("state_dir") {
            block.to_string()
        } else {
            format!("{base}{block}")
        };
        let config = Config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        let checks = config
            .build_checks()
            .unwrap_or_else(|e| panic!("{e}\n{text}"));
        seen.extend(checks.iter().map(|c| c.key.clone()));
    }
    // Each kind has an example, under its own key or the one the example gives it.
    for kind in KINDS {
        assert!(
            CONFIG_MD.contains(&format!("kind = \"{}\"", kind.name)),
            "no example of {}",
            kind.name
        );
    }
    assert!(!seen.is_empty());
}
