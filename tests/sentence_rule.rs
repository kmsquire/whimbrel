//! The sentence rule the other tests hold each check to, checked on sentences that break it, so a
//! rule that passes everything can't pass for one that holds.

use whimbrel::sentence::breaks;

#[test]
fn a_sentence_and_what_to_run_keeps_it() {
    let ok = Vec::<String>::new();
    assert_eq!(breaks("disk", "The disk is 90% full. See `df -h /`."), ok);
    assert_eq!(
        breaks("x", "A thing broke. To fix: `systemctl restart x`."),
        ok
    );
    // A period inside code, or in a file name, doesn't end a sentence.
    assert_eq!(breaks("x", "README.md says no. See `cat a. B`."), ok);
}

#[test]
fn each_way_of_breaking_it_is_named() {
    let has = |key: &str, s: &str, why: &str| {
        let got = breaks(key, s);
        assert!(got.iter().any(|g| g.contains(why)), "{s:?}: {got:?}");
    };
    has(
        "x",
        "the disk is full. See `df`.",
        "doesn't start a sentence",
    );
    has("x", "The disk is full. See `df`", "doesn't end one");
    has("x", "The disk is full - badly. See `df`.", "has a dash");
    has("x", "The disk is full — badly. See `df`.", "has a dash");
    has("x", "Is the disk full? See `df`.", "asks or exclaims");
    has(
        "x",
        "The disk is full. It's bad. See `df`.",
        "has 3 sentences, not 2",
    );
    has("x", "The disk is full.", "has 1 sentences, not 2");
    has(
        "x",
        "The disk is full. Run `df`.",
        "doesn't end on what to run",
    );
    has(
        "x",
        "The disk is full. Ask the admin: `df`.",
        "doesn't end on what to run",
    );
    has(
        "disk",
        "The disk check failed. See `df`.",
        "calls its row a check",
    );
    has("disk", "Disk: full. See `df`.", "calls its row a check");
}
