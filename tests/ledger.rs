//! What each channel is told, run after run: the ledger's behavior through `whimbrel::deliver`.
//!
//! First the basics: what's news, how it's worded, and retrying a failed send. Then what the
//! simple approach, remembering only the last attempt, gets wrong: a failed recovery that forgets
//! what recovered, a second failed send that forgets the first problem, and one channel's failure
//! resending to another. Then the reminder after a day.
//!
//! Each test drives the ledger an hour at a time with fake channels, so nothing here sends.

use whimbrel::secret_patterns::SecretPatterns;
use whimbrel::sentence::Next;
use whimbrel::{
    Alert, Channel, CheckResult, DuplicateChannel, Finding, Frame, Outcome, REMIND_AFTER_SECS,
    State, deliver,
};

mod common;

const HOUR: u64 = 3600;

/// A channel that records what it was handed, and fails with `fail` while it's set.
struct Fake {
    name: &'static str,
    fail: Option<&'static str>,
    delivered: Vec<Alert>,
}

impl Fake {
    fn new(name: &'static str) -> Self {
        Fake {
            name,
            fail: None,
            delivered: Vec::new(),
        }
    }
}

impl Channel for Fake {
    fn name(&self) -> &str {
        self.name
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        match self.fail {
            Some(why) => Err(why.to_string()),
            None => {
                self.delivered.push(alert.clone());
                Ok(())
            }
        }
    }
}

/// A host with two channels, `chat` and `phone`, advanced an hour per run.
struct World {
    state: State,
    now: u64,
    chat: Fake,
    phone: Fake,
}

/// What one run delivered, per channel, and what it reported.
struct Hour {
    chat: Option<Alert>,
    phone: Option<Alert>,
    outcomes: Vec<(String, Outcome)>,
}

impl Hour {
    /// The chat channel's message this hour, which must exist.
    fn says(&self) -> &str {
        &self.chat.as_ref().expect("chat was sent nothing").full
    }
}

/// The chat channel was sent exactly `expected` this hour.
#[track_caller]
fn assert_says(hour: &Hour, expected: &str) {
    assert_eq!(hour.says(), expected);
}

impl World {
    fn new() -> Self {
        World {
            state: State::default(),
            now: 1_800_000_000,
            chat: Fake::new("chat"),
            phone: Fake::new("phone"),
        }
    }

    fn run(&mut self, results: &[CheckResult]) -> Hour {
        self.now += HOUR;
        self.run_now(results)
    }

    /// A run at `now` exactly, for the reminder's boundaries.
    fn run_now(&mut self, results: &[CheckResult]) -> Hour {
        let (c, p) = (self.chat.delivered.len(), self.phone.delivered.len());
        let frame = Frame::new("the test host");
        let outcomes = {
            let mut channels: [&mut dyn Channel; 2] = [&mut self.chat, &mut self.phone];
            deliver(&mut self.state, results, &mut channels, &frame, self.now).unwrap()
        };
        Hour {
            chat: self.chat.delivered.get(c).cloned(),
            phone: self.phone.delivered.get(p).cloned(),
            outcomes,
        }
    }

    #[track_caller]
    fn quiet(&mut self, results: &[CheckResult]) {
        let hour = self.run(results);
        assert!(
            hour.chat.is_none() && hour.phone.is_none(),
            "expected nothing sent, got {:?} / {:?}",
            hour.chat,
            hour.phone
        );
    }

    fn both_fail(&mut self) {
        self.chat.fail = Some("webhook returned 500");
        self.phone.fail = Some("webhook returned 500");
    }

    fn both_work(&mut self) {
        self.chat.fail = None;
        self.phone.fail = None;
    }
}

fn disk(percent: u32) -> CheckResult {
    let f = match percent {
        90.. => Finding::fail(),
        80.. => Finding::warn(),
        _ => return Finding::ok().stamped("disk", "the disk"),
    };
    f.says(format!("The disk is {percent}% full."))
        .see("df -h /")
        .stamped("disk", "the disk")
}

/// A scan that found secrets in `files`, which it gives as its fingerprint: a new file is news.
fn scan(files: &[&str]) -> CheckResult {
    scan_finding(files).stamped("scan", "the secrets scan")
}

fn scan_finding(files: &[&str]) -> Finding {
    if files.is_empty() {
        return Finding::ok();
    }
    Finding::fail()
        .says(format!("A secret turned up in {}.", files.join(" and ")))
        .see("grep -c token app.log")
        .fingerprint(files.join(","))
}

/// The scan with `count` hits, a count whose rise is news.
fn scan_counting(count: u64) -> CheckResult {
    scan_finding(&["app.log"])
        .count(count)
        .stamped("scan", "the secrets scan")
}

fn clean() -> Vec<CheckResult> {
    vec![disk(40), scan(&[])]
}

// The basics.

#[test]
fn a_clean_first_run_sends_nothing_and_records_every_channel() {
    let mut w = World::new();
    w.quiet(&clean());
    assert_eq!(w.state.channels().collect::<Vec<_>>(), ["chat", "phone"]);
}

#[test]
fn a_first_run_that_is_already_failing_alerts() {
    let mut w = World::new();
    let hour = w.run(&[disk(40), scan(&["app.log"])]);
    assert_says(
        &hour,
        "Needs you soon:\nA secret turned up in app.log. See `grep -c token app.log`.",
    );
    assert!(hour.phone.is_some());
}

#[test]
fn the_same_problem_an_hour_later_sends_nothing() {
    let mut w = World::new();
    w.run(&[disk(40), scan(&["app.log"])]);
    w.quiet(&[disk(40), scan(&["app.log"])]);
}

#[test]
fn a_fail_is_urgent_and_a_warn_is_not() {
    let mut w = World::new();
    w.run(&clean());
    let warn = w.run(&[disk(85), scan(&[])]);
    assert_says(
        &warn,
        "No rush, but something needs a look:\nThe disk is 85% full. See `df -h /`.",
    );
    assert!(!warn.chat.as_ref().unwrap().urgent);
    let fail = w.run(&[disk(92), scan(&[])]);
    assert_says(
        &fail,
        "Needs you soon:\nThe disk is 92% full. See `df -h /`.",
    );
    assert!(fail.chat.as_ref().unwrap().urgent);
}

#[test]
fn a_fail_easing_to_a_warn_is_news_and_no_longer_urgent() {
    let mut w = World::new();
    w.run(&[disk(92)]);
    let hour = w.run(&[disk(85)]);
    assert_says(
        &hour,
        "No rush, but something needs a look:\nThe disk is 85% full. See `df -h /`.",
    );
    assert!(!hour.chat.unwrap().urgent);
}

#[test]
fn each_problem_is_its_checks_own_sentence_verbatim_in_check_order() {
    let mut w = World::new();
    let hour = w.run(&[disk(85), scan(&["app.log"])]);
    assert_says(
        &hour,
        "Needs you soon:\n\
         The disk is 85% full. See `df -h /`.\n\
         A secret turned up in app.log. See `grep -c token app.log`.",
    );
}

#[test]
fn a_new_sentence_with_no_fingerprint_at_the_same_level_is_no_change() {
    let mut w = World::new();
    w.run(&[disk(85), scan(&[])]);
    w.quiet(&[disk(86), scan(&[])]);
}

#[test]
fn a_new_fingerprint_at_the_same_level_is_news() {
    let mut w = World::new();
    w.run(&[scan(&["app.log"])]);
    let hour = w.run(&[scan(&["app.log", "setup.log"])]);
    assert_says(
        &hour,
        "Needs you soon:\nA secret turned up in app.log and setup.log. See `grep -c token app.log`.",
    );
    w.quiet(&[scan(&["app.log", "setup.log"])]);
}

#[test]
fn a_count_that_rises_is_news_and_one_that_falls_isnt() {
    let mut w = World::new();
    w.run(&[scan_counting(1)]);
    let hour = w.run(&[scan_counting(2)]);
    assert_says(
        &hour,
        "Needs you soon:\nA secret turned up in app.log. See `grep -c token app.log`.",
    );
    // Lower than told, as when a rotated log is deleted, and then back up to it: neither is news.
    w.quiet(&[scan_counting(1)]);
    w.quiet(&[scan_counting(2)]);
}

#[test]
fn a_recovery_says_what_recovered() {
    let mut w = World::new();
    w.run(&[disk(92), scan(&[])]);
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "All clear on the test host: the disk is back to normal.",
    );
}

#[test]
fn a_recovery_of_several_names_them_all() {
    let mut w = World::new();
    w.run(&[disk(92), scan(&["app.log"])]);
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "All clear on the test host: the disk and the secrets scan are back to normal.",
    );
}

#[test]
fn a_partial_recovery_says_what_recovered_beside_whats_still_wrong() {
    let mut w = World::new();
    w.run(&clean());
    w.run(&[disk(85), scan(&["app.log"])]);
    let hour = w.run(&[disk(85), scan(&[])]);
    assert_says(
        &hour,
        "No rush, but something needs a look:\n\
         The disk is 85% full. See `df -h /`.\n\
         Back to normal: the secrets scan.",
    );
}

#[test]
fn a_failed_send_is_reported_and_sent_again_next_run_with_no_change() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    let failed = w.run(&[disk(85), scan(&[])]);
    assert_eq!(
        failed.outcomes,
        [
            (
                "chat".into(),
                Outcome::Failed("webhook returned 500".into())
            ),
            (
                "phone".into(),
                Outcome::Failed("webhook returned 500".into())
            ),
        ]
    );
    w.both_work();
    let hour = w.run(&[disk(85), scan(&[])]);
    assert_says(
        &hour,
        "No rush, but something needs a look:\nThe disk is 85% full. See `df -h /`.",
    );
    assert_eq!(
        hour.outcomes,
        [
            ("chat".into(), Outcome::Sent),
            ("phone".into(), Outcome::Sent)
        ]
    );
}

#[test]
fn a_problem_that_never_got_through_is_named_by_its_first_sentence_once_it_has_recovered() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[disk(40), scan(&["app.log"])]);
    w.both_work();
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "While alerts weren't getting through, this happened and has since cleared up: \
         A secret turned up in app.log.",
    );
}

#[test]
fn a_recovery_that_also_fails_to_send_still_names_the_fail_later() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[disk(40), scan(&["app.log"])]);
    w.run(&clean());
    w.both_work();
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "While alerts weren't getting through, this happened and has since cleared up: \
         A secret turned up in app.log.",
    );
}

// What remembering only the last attempt gets wrong.

/// A was delivered, then the recovery didn't get through. The retry still names A.
#[test]
fn a_failed_recovery_still_names_what_recovered() {
    let mut w = World::new();
    w.run(&[disk(92), scan(&[])]);
    w.both_fail();
    w.run(&clean());
    w.both_work();
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "All clear on the test host: the disk is back to normal.",
    );
}

/// A failed to send, then B replaced it and failed too. Both are named when one gets through.
#[test]
fn a_second_failed_send_still_names_the_first_problem() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[disk(40), scan(&["app.log"])]);
    w.run(&[disk(85), scan(&[])]);
    w.both_work();
    let hour = w.run(&[disk(85), scan(&[])]);
    assert_says(
        &hour,
        "No rush, but something needs a look:\n\
         The disk is 85% full. See `df -h /`.\n\
         While alerts weren't getting through, this happened and has since cleared up: \
         A secret turned up in app.log.",
    );
}

/// A came and went while nothing could send, so what's wrong now equals what was last told.
/// That's still news.
#[test]
fn a_problem_that_came_and_went_unsent_is_named_with_nothing_else_changed() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[disk(92), scan(&[])]);
    w.run(&clean());
    w.both_work();
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "While alerts weren't getting through, this happened and has since cleared up: \
         The disk is 92% full.",
    );
}

/// The disk was told as a WARN, went to FAIL while sends failed, and came back to WARN.
#[test]
fn a_worse_level_that_came_and_went_unsent_is_named() {
    let mut w = World::new();
    w.run(&[disk(85), scan(&[])]);
    w.both_fail();
    w.run(&[disk(95), scan(&[])]);
    w.run(&[disk(85), scan(&[])]);
    w.both_work();
    let hour = w.run(&[disk(85), scan(&[])]);
    assert_says(
        &hour,
        "No rush, but something needs a look:\n\
         The disk is 85% full. See `df -h /`.\n\
         While alerts weren't getting through, this happened and has since cleared up: \
         The disk is 95% full.",
    );
}

/// Seen at two levels while sends failed, a check is named once, at its worst.
#[test]
fn a_check_that_came_and_went_at_two_levels_is_named_once_at_its_worst() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[disk(85)]);
    w.run(&[disk(95)]);
    w.run(&[disk(85)]);
    w.run(&[disk(40)]);
    w.both_work();
    let hour = w.run(&[disk(40)]);
    assert_says(
        &hour,
        "While alerts weren't getting through, this happened and has since cleared up: \
         The disk is 95% full.",
    );
}

/// The disk was told as a FAIL, eased to a WARN while sends failed, and is a FAIL again. A milder
/// level in between is no news.
#[test]
fn a_milder_level_seen_while_sends_failed_is_not_named() {
    let mut w = World::new();
    w.run(&[disk(92), scan(&[])]);
    w.both_fail();
    w.run(&[disk(85), scan(&[])]);
    w.both_work();
    w.quiet(&[disk(92), scan(&[])]);
}

/// Told as a FAIL, eased to a WARN while sends failed, then recovered. The recovery is the news;
/// the easing on the way isn't.
#[test]
fn a_milder_level_on_the_way_to_recovering_is_not_named() {
    let mut w = World::new();
    w.run(&[disk(92)]);
    w.both_fail();
    w.run(&[disk(85)]);
    w.run(&[disk(40)]);
    w.both_work();
    let hour = w.run(&[disk(40)]);
    assert_says(
        &hour,
        "All clear on the test host: the disk is back to normal.",
    );
}

#[test]
fn a_problem_that_came_and_went_is_named_only_once() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[disk(40), scan(&["app.log"])]);
    w.both_work();
    w.run(&clean());
    w.quiet(&clean());
}

// Per channel.

#[test]
fn a_channel_that_delivered_is_not_sent_again_when_another_failed() {
    let mut w = World::new();
    w.run(&clean());
    w.phone.fail = Some("connection refused");
    let hour = w.run(&[disk(85), scan(&[])]);
    assert!(hour.chat.is_some() && hour.phone.is_none());
    w.phone.fail = None;
    let hour = w.run(&[disk(85), scan(&[])]);
    assert!(hour.chat.is_none(), "chat was sent the same alert twice");
    assert_eq!(
        hour.phone.unwrap().short,
        "No rush, but something needs a look:\nThe disk is 85% full. See `df -h /`."
    );
}

#[test]
fn each_channel_is_told_the_difference_from_what_it_was_last_told() {
    let mut w = World::new();
    w.run(&clean());
    w.phone.fail = Some("connection refused");
    w.run(&[disk(85), scan(&[])]);
    w.run(&clean());
    w.phone.fail = None;
    let hour = w.run(&clean());
    assert!(hour.chat.is_none());
    assert_eq!(
        hour.phone.unwrap().short,
        "While alerts weren't getting through, this happened and has since cleared up: \
         The disk is 85% full."
    );
}

#[test]
fn a_channel_added_later_is_told_whats_wrong_now() {
    let mut w = World::new();
    let frame = Frame::new("the test host");
    let mut chat = Fake::new("chat");
    deliver(&mut w.state, &[disk(85)], &mut [&mut chat], &frame, w.now).unwrap();
    let hour = w.run(&[disk(85)]);
    assert!(hour.chat.is_none(), "chat already had it");
    assert!(hour.phone.is_some(), "phone never had it");
}

#[test]
fn a_channel_no_longer_configured_loses_its_ledger() {
    let mut w = World::new();
    w.run(&[disk(85)]);
    let mut chat = Fake::new("chat");
    let frame = Frame::new("the test host");
    deliver(&mut w.state, &[disk(85)], &mut [&mut chat], &frame, w.now).unwrap();
    assert_eq!(w.state.channels().collect::<Vec<_>>(), ["chat"]);
}

#[test]
fn two_channels_with_one_name_are_refused_and_nothing_is_sent() {
    let mut state = State::default();
    let (mut a, mut b) = (Fake::new("chat"), Fake::new("chat"));
    let got = deliver(
        &mut state,
        &[disk(95)],
        &mut [&mut a, &mut b],
        &Frame::new("h"),
        0,
    );
    assert_eq!(got, Err(DuplicateChannel("chat".into())));
    assert!(a.delivered.is_empty() && b.delivered.is_empty());
    assert_eq!(state, State::default());
}

#[test]
fn the_short_form_leaves_out_the_details() {
    let mut w = World::new();
    let mut full = disk(92);
    full.finding = full.finding.details("/var/log 30 GB\n/tmp 4 GB");
    let hour = w.run(&[full]);
    let alert = hour.chat.unwrap();
    assert_eq!(
        alert.short,
        "Needs you soon:\nThe disk is 92% full. See `df -h /`."
    );
    assert_eq!(
        alert.full,
        format!("{}\n\n/var/log 30 GB\n/tmp 4 GB", alert.short)
    );
}

// The reminder.

const DAY: u64 = 24 * HOUR;

#[test]
fn the_reminder_is_due_a_little_before_a_full_day_to_allow_for_timer_drift() {
    assert_eq!(REMIND_AFTER_SECS, DAY - 10 * 60);
}

#[test]
fn a_problem_still_open_after_a_day_is_sent_again() {
    let mut w = World::new();
    w.run(&[disk(92)]);
    let start = w.now;
    for _ in 0..22 {
        w.quiet(&[disk(92)]);
    }
    w.now = start + REMIND_AFTER_SECS - 1;
    assert!(
        w.run_now(&[disk(92)]).chat.is_none(),
        "reminded a second early"
    );
    w.now = start + REMIND_AFTER_SECS;
    let hour = w.run_now(&[disk(92)]);
    assert_says(
        &hour,
        "Still waiting on you:\nThe disk is 92% full. See `df -h /`.",
    );
    assert!(hour.chat.unwrap().urgent);
}

#[test]
fn a_warn_reminder_is_not_urgent() {
    let mut w = World::new();
    w.run(&[disk(85)]);
    w.now += DAY;
    let hour = w.run_now(&[disk(85)]);
    assert_says(
        &hour,
        "Still waiting on you:\nThe disk is 85% full. See `df -h /`.",
    );
    assert!(!hour.chat.unwrap().urgent);
}

#[test]
fn the_next_reminder_is_a_day_after_the_last_delivery() {
    let mut w = World::new();
    w.run(&[disk(92)]);
    let start = w.now;
    w.now = start + DAY;
    w.run_now(&[disk(92)]);
    w.now = start + DAY + REMIND_AFTER_SECS - 1;
    assert!(w.run_now(&[disk(92)]).chat.is_none());
    w.now = start + DAY + REMIND_AFTER_SECS;
    assert!(w.run_now(&[disk(92)]).chat.is_some());
}

#[test]
fn a_reminder_that_fails_is_tried_again_the_next_hour() {
    let mut w = World::new();
    w.run(&[disk(92)]);
    w.now += 23 * HOUR;
    w.both_fail();
    w.run(&[disk(92)]);
    w.both_work();
    assert!(w.run(&[disk(92)]).chat.is_some());
}

#[test]
fn a_clean_host_is_never_reminded() {
    let mut w = World::new();
    w.run(&clean());
    w.now += 3 * DAY;
    w.quiet(&clean());
}

#[test]
fn an_all_clear_is_never_reminded() {
    let mut w = World::new();
    w.run(&[disk(92)]);
    w.run(&[disk(40)]);
    w.now += 3 * DAY;
    w.quiet(&[disk(40)]);
}

// A lost ledger.

#[test]
fn a_lost_ledger_tells_every_channel_whats_open_once() {
    let mut w = World::new();
    w.state = State::lost_track();
    let hour = w.run(&[disk(85), scan(&[])]);
    assert_says(
        &hour,
        "I lost track of what I'd told you, so here's everything open now:\n\
         The disk is 85% full. See `df -h /`.",
    );
    assert!(hour.phone.is_some());
    w.quiet(&[disk(85), scan(&[])]);
}

#[test]
fn a_lost_ledger_with_nothing_open_still_says_so() {
    let mut w = World::new();
    w.state = State::lost_track();
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "I lost track of what I'd told you, but nothing is open now.",
    );
}

#[test]
fn a_lost_ledger_keeps_trying_a_channel_until_it_hears() {
    let mut w = World::new();
    w.state = State::lost_track();
    w.phone.fail = Some("connection refused");
    w.run(&clean());
    w.phone.fail = None;
    let hour = w.run(&clean());
    assert!(hour.chat.is_none());
    assert_eq!(
        hour.phone.unwrap().short,
        "I lost track of what I'd told you, but nothing is open now."
    );
}

#[test]
fn what_a_secret_pattern_matches_is_never_kept_or_logged() {
    let mut state = State::default();
    let patterns = SecretPatterns::new(false, &[], &["sekrit".into()]).unwrap();
    let frame = Frame::new("the test host").with_redact(patterns);
    let mut chat = Fake::new("chat");
    chat.fail = Some("the server said sekrit");
    let leak = Finding::fail()
        .says("Found sekrit in app.log.")
        .see("grep -c token app.log")
        .stamped("scan", "the scan");
    let outcomes = {
        let mut channels: [&mut dyn Channel; 1] = [&mut chat];
        deliver(&mut state, &[leak], &mut channels, &frame, 1_800_000_000).unwrap()
    };
    assert_eq!(
        outcomes,
        [(
            "chat".to_string(),
            Outcome::Failed("the server said [redacted]".into())
        )]
    );
    // What the ledger keeps for the came-and-went line, which is saved to disk.
    let kept = serde_json::to_string(&state).unwrap();
    assert!(!kept.contains("sekrit"), "{kept}");
    assert!(kept.contains("Found [redacted] in app.log."), "{kept}");
}

// A check with several problems: a result file, say, where each row is one.

/// Two rows of a result file gone wrong: one with a command to run, one with a written-out step.
fn rows() -> CheckResult {
    Finding::fail()
        .says("The web server's app isn't running.")
        .see("journalctl -u app")
        .problem(
            "The web server's backup is a day old.",
            Next::Written("See the Backups page in the hosting console.".into()),
        )
        .fingerprint("app service,last backup run")
        .stamped("web-health", "the web server's health")
}

#[test]
fn each_of_a_checks_problems_is_its_own_line_as_written() {
    let mut w = World::new();
    let hour = w.run(&[rows()]);
    assert_says(
        &hour,
        "Needs you soon:\n\
         The web server's app isn't running. See `journalctl -u app`.\n\
         The web server's backup is a day old. See the Backups page in the hosting console.",
    );
}

#[test]
fn a_check_with_several_problems_that_came_and_went_is_named_by_its_first() {
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[rows()]);
    w.both_work();
    let hour = w.run(&clean());
    assert_says(
        &hour,
        "While alerts weren't getting through, this happened and has since cleared up: \
         The web server's app isn't running.",
    );
}

/// What `result-file` makes of `rows`, a fresh file the test's account wrote.
fn result_file(rows: &str) -> CheckResult {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("web-health.tsv");
    std::fs::write(&file, rows).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let owner = std::fs::metadata(&file).unwrap().uid();
    let table = format!("path = {file:?}\nowner_uid = {owner}\nrequired_row = \"ssh\"\n");
    common::run_at(
        &whimbrel::checks::result_file::KIND,
        &table,
        "the test host",
        dir.path(),
        whimbrel::Mode::DryRun,
        std::time::SystemTime::now(),
    )
    .stamped("web-health", "the web server's health")
}

/// Its worst problem names it, wherever the file put it: here the disk's WARN comes first in the
/// file, and it's the backup's FAIL that clears while alerts aren't getting through.
#[test]
fn a_result_file_whose_fail_cleared_while_alerts_failed_names_the_fail_not_the_warn_left() {
    let disk = "WARN\tdisk\tThe server's disk is 85% full.\tSee `df -h /`.\n";
    let backup =
        "FAIL\tlast backup run\tThe server's last backup didn't upload.\tSee `tail log`.\n";
    let mut w = World::new();
    w.run(&clean());
    w.both_fail();
    w.run(&[result_file(&format!(
        "OK\tssh\treached\t\n{disk}{backup}RESULT\tFAIL\n"
    ))]);
    w.both_work();
    let hour = w.run(&[result_file(&format!(
        "OK\tssh\treached\t\n{disk}RESULT\tWARN\n"
    ))]);
    assert!(
        hour.says().ends_with(
            "While alerts weren't getting through, this happened and has since cleared up: \
             The server's last backup didn't upload."
        ),
        "{}",
        hour.says()
    );
}

#[test]
fn a_token_shaped_fingerprint_never_reaches_the_ledger() {
    // A check builds its fingerprint from words it found, a row's name say.
    let token = format!("xoxb-{}-{}abc", "1".repeat(12), "1".repeat(12));
    let mut state = State::default();
    let frame = Frame::new("the test host").with_redact(SecretPatterns::builtins());
    let mut chat = Fake::new("chat");
    let leak = Finding::warn()
        .says("A row went bad.")
        .see("cat r")
        .fingerprint(format!("WARN:{token}"))
        .stamped("rows", "the rows");
    {
        let mut channels: [&mut dyn Channel; 1] = [&mut chat];
        deliver(&mut state, &[leak], &mut channels, &frame, 1_800_000_000).unwrap();
    }
    let kept = serde_json::to_string(&state).unwrap();
    assert!(!kept.contains(&token), "{kept}");
    assert!(kept.contains("WARN:[redacted]"), "{kept}");
}
