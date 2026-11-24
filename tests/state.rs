//! The ledger on disk: one JSON file, replaced whole, behind a lock that's the only way in.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use whimbrel::{Alert, Channel, Finding, Frame, State, StateDir, deliver};

struct Down;

impl Channel for Down {
    fn name(&self) -> &str {
        "chat"
    }
    fn send(&mut self, _: &Alert) -> Result<(), String> {
        Err("no answer".into())
    }
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// A state with something in it: a problem a channel hasn't heard about.
fn unheard() -> State {
    let mut state = State::default();
    let problem = Finding::fail()
        .says("The disk is 95% full.")
        .see("df -h /")
        .stamped("disk", "the disk");
    deliver(
        &mut state,
        &[problem],
        &mut [&mut Down],
        &Frame::new("h"),
        1_800_000_000,
    )
    .unwrap();
    assert_ne!(state, State::default());
    state
}

fn mode(path: &std::path::Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn no_state_file_is_a_first_run() {
    let d = dir();
    let dir = StateDir::new(d.path());
    let locked = dir.lock().unwrap().unwrap();
    assert_eq!(locked.load().unwrap(), State::default());
}

#[test]
fn a_missing_state_directory_is_an_error_not_a_first_run() {
    let d = dir();
    let missing = d.path().join("gone");
    let err = StateDir::new(&missing).lock().err().expect("an error");
    assert!(err.to_string().contains("gone"), "{err}");
}

#[test]
fn a_saved_ledger_loads_back_the_same() {
    let d = dir();
    let dir = StateDir::new(d.path());
    let locked = dir.lock().unwrap().unwrap();
    let state = unheard();
    locked.save(&state).unwrap();
    assert_eq!(locked.load().unwrap(), state);
}

#[test]
fn saving_replaces_the_file_and_leaves_only_it_and_the_lock() {
    let d = dir();
    let dir = StateDir::new(d.path());
    let locked = dir.lock().unwrap().unwrap();
    locked.save(&State::default()).unwrap();
    locked.save(&unheard()).unwrap();
    let mut names: Vec<_> = fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["ledger.json", "lock"]);
    assert_eq!(locked.load().unwrap(), unheard());
}

#[test]
fn the_state_file_is_readable_by_its_owner_only() {
    let d = dir();
    let dir = StateDir::new(d.path());
    dir.lock()
        .unwrap()
        .unwrap()
        .save(&State::default())
        .unwrap();
    assert_eq!(mode(&d.path().join("ledger.json")), 0o600);
    assert_eq!(mode(&d.path().join("lock")), 0o600);
}

#[test]
fn a_stale_temporary_file_doesnt_lend_the_ledger_its_mode() {
    let d = dir();
    let tmp = d.path().join(".ledger.json.tmp");
    fs::write(&tmp, "old").unwrap();
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();
    let dir = StateDir::new(d.path());
    dir.lock()
        .unwrap()
        .unwrap()
        .save(&State::default())
        .unwrap();
    assert_eq!(mode(&d.path().join("ledger.json")), 0o600);
}

#[test]
fn a_symlink_in_place_of_the_temporary_file_is_never_written_through() {
    let d = dir();
    let target = d.path().join("target");
    fs::write(&target, "keep me").unwrap();
    symlink(&target, d.path().join(".ledger.json.tmp")).unwrap();
    let dir = StateDir::new(d.path());
    dir.lock()
        .unwrap()
        .unwrap()
        .save(&State::default())
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "keep me");
    assert!(
        !fs::symlink_metadata(d.path().join("ledger.json"))
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn a_symlink_in_place_of_the_lock_is_refused() {
    let d = dir();
    let target = d.path().join("target");
    fs::write(&target, "keep me").unwrap();
    symlink(&target, d.path().join("lock")).unwrap();
    assert!(StateDir::new(d.path()).lock().is_err());
}

#[test]
fn a_corrupt_state_file_is_an_error_not_a_first_run() {
    let d = dir();
    fs::write(d.path().join("ledger.json"), "{ not json").unwrap();
    let dir = StateDir::new(d.path());
    let err = dir.lock().unwrap().unwrap().load().unwrap_err();
    assert!(err.to_string().contains("ledger.json"), "{err}");
}

#[test]
fn a_ledger_missing_fields_a_later_version_added_still_loads() {
    let d = dir();
    fs::write(
        d.path().join("ledger.json"),
        r#"{"channels": {"chat": {}}}"#,
    )
    .unwrap();
    let dir = StateDir::new(d.path());
    let state = dir.lock().unwrap().unwrap().load().unwrap();
    assert_eq!(state.channels().collect::<Vec<_>>(), ["chat"]);
}

#[test]
fn a_held_lock_stops_a_second_run() {
    let d = dir();
    let dir = StateDir::new(d.path());
    let held = dir.lock().unwrap().expect("the first lock");
    assert!(dir.lock().unwrap().is_none(), "a second run got the lock");
    drop(held);
    assert!(dir.lock().unwrap().is_some(), "the lock wasn't released");
}
