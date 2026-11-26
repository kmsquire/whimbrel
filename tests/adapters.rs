//! Slack and iMessage against a stand-in for curl, which records what it was handed and answers
//! as told. Nothing here reaches the network.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use whimbrel::channels::{self, BlueBubbles, SecretFile, Server, Slack};
use whimbrel::config::Config;
use whimbrel::{Alert, Channel, Form};

mod common;

use common::curl::Stub;

const WEBHOOK: &str = "https://hooks.slack.com/services/T000/B000/sekritsekritsekrit";
const PASSWORD: &str = "bbpassw0rd";
const TO: &str = "+15555550100";

fn alert() -> Alert {
    Alert {
        short: "Needs you soon:\nThe disk is 95% full. See `df -h /`.".into(),
        full: "Needs you soon:\nThe disk is 95% full. See `df -h /`.\n\nBiggest folders: <!channel> 3 GB & more."
            .into(),
        urgent: true,
    }
}

fn slack(stub: &Stub) -> Slack {
    let mut s = Slack::new(stub.secret("webhook", WEBHOOK));
    s.curl = stub.curl();
    s
}

fn bluebubbles(stub: &Stub) -> BlueBubbles {
    let mut m = BlueBubbles::new(
        Server::new("http://127.0.0.1:1234").unwrap(),
        stub.secret("password", PASSWORD),
        stub.secret("recipient", TO),
    );
    m.curl = stub.curl();
    m
}

/// What every send hands curl on its command line, whatever the channel: the rest is on stdin.
const ARGV: &str = "-q\n-sS\n--max-time\n2\n-w\n\\n%{http_code}\n-K\n-\n";

fn assert_no_secret(why: &str) {
    for secret in [WEBHOOK, "sekrit", PASSWORD, TO] {
        assert!(!why.contains(secret), "{why:?} holds a secret");
    }
}

// Slack.

#[test]
fn slack_posts_the_full_form_to_the_webhook() {
    let stub = Stub::new();
    assert_eq!(slack(&stub).send(&alert()), Ok(()));
    assert_eq!(stub.config("url"), WEBHOOK);
    assert_eq!(
        stub.body()["text"],
        "Needs you soon:\nThe disk is 95% full. See `df -h /`.\n\n\
         Biggest folders: &lt;!channel&gt; 3 GB &amp; more."
    );
}

#[test]
fn slack_markup_in_an_alert_doesnt_ping() {
    let stub = Stub::new();
    slack(&stub).send(&alert()).unwrap();
    let text = stub.body()["text"].as_str().unwrap().to_string();
    assert!(
        text.ends_with("Biggest folders: &lt;!channel&gt; 3 GB &amp; more."),
        "{text}"
    );
    assert!(!text.contains("<!channel>"), "{text}");
}

#[test]
fn the_webhook_never_reaches_curls_argv() {
    let stub = Stub::new();
    slack(&stub).send(&alert()).unwrap();
    assert!(stub.called());
    // The whole argv: -q first, and nothing in it from the webhook.
    assert_eq!(stub.args(), ARGV);
}

/// How a registered channel kind sends, for the argv test.
enum Sends {
    /// With curl: the rest of its `[[channel]]` table, and its secrets, written out.
    Curl(String, &'static [&'static str]),
    /// Without: it never runs curl.
    Nothing,
}

/// Each registered kind's table, with its secret files written into `stub`'s directory. A kind
/// with no entry here fails the test, so a new kind can't skip it.
fn sends(kind: &str, stub: &Stub) -> Sends {
    let file = |name: &str, value: &str| {
        stub.secret(name, value);
        format!("{:?}", stub.dir.path().join(name))
    };
    match kind {
        "slack" => Sends::Curl(
            format!("webhook_file = {}\n", file("webhook", WEBHOOK)),
            &[WEBHOOK],
        ),
        "bluebubbles" => Sends::Curl(
            format!(
                "server = \"http://127.0.0.1:1234\"\npassword_file = {}\nrecipient_file = {}\n",
                file("password", PASSWORD),
                file("recipient", TO)
            ),
            &[PASSWORD, TO],
        ),
        "print" => Sends::Nothing,
        other => panic!("say how the {other} channel sends, so its secrets are checked"),
    }
}

#[test]
fn no_channel_puts_a_secret_on_curls_argv() {
    let mut checked = 0;
    for kind in channels::KINDS {
        let stub = Stub::new();
        let Sends::Curl(table, secrets) = sends(kind.name, &stub) else {
            continue;
        };
        let config = Config::parse(&format!(
            "host = \"h\"\nstate_dir = \"/s\"\ncurl = {:?}\n[[channel]]\nkind = {:?}\n{table}",
            stub.curl().program,
            kind.name
        ))
        .unwrap();
        let mut channel = config.build_channels().pop().unwrap();
        channel.send(&alert()).unwrap();
        checked += 1;
        for secret in secrets {
            assert!(
                stub.stdin().contains(secret),
                "{}: {secret} isn't on stdin, so this test can't see where it went",
                channel.name()
            );
            assert!(
                !stub.args().contains(secret),
                "{}: {secret} is on curl's argv: {:?}",
                channel.name(),
                stub.args()
            );
        }
    }
    // Slack and BlueBubbles at least: a registry that lost them would otherwise pass.
    assert!(checked >= 2, "{checked}");
}

#[test]
fn a_failed_send_quotes_the_reply_without_its_secrets() {
    let stub = Stub::new();
    stub.answer("400", 0);
    stub.reply(&format!(
        "{{\"error\": \"no chat with {TO}\",\n \"password\": \"{PASSWORD}\"}}"
    ));
    let why = bluebubbles(&stub).send(&alert()).unwrap_err();
    assert_eq!(
        why,
        r#"BlueBubbles said HTTP 400: "{\"error\": \"no chat with [redacted]\", \"password\": \"[redacted]\"}""#
    );
    stub.reply(&format!("invalid_token {WEBHOOK}"));
    let why = slack(&stub).send(&alert()).unwrap_err();
    assert_eq!(why, r#"Slack said HTTP 400: "invalid_token [redacted]""#);
}

#[test]
fn a_file_that_isnt_a_webhook_is_refused_before_curl_runs() {
    let stub = Stub::new();
    let mut s = slack(&stub);
    s.webhook_file = stub.secret("webhook", "https://example.com/collect?x=sekrit");
    let why = s.send(&alert()).unwrap_err();
    assert_eq!(
        why,
        "the Slack webhook file webhook doesn't hold a Slack incoming-webhook URL"
    );
    assert!(!stub.called());
}

#[test]
fn a_missing_webhook_file_names_the_file_but_not_its_path() {
    let stub = Stub::new();
    let mut s = slack(&stub);
    s.webhook_file = SecretFile::new(stub.dir.path().join("nowhere")).unwrap();
    let why = s.send(&alert()).unwrap_err();
    assert_eq!(
        why,
        "can't read the Slack webhook file nowhere (entity not found)"
    );
}

#[test]
fn a_webhook_file_others_can_read_is_refused_before_curl_runs() {
    let stub = Stub::new();
    let mut s = slack(&stub);
    let path = stub.dir.path().join("webhook");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let why = s.send(&alert()).unwrap_err();
    assert_eq!(
        why,
        "the Slack webhook file webhook can be read by other accounts (640); it should be 600"
    );
    assert!(!stub.called());
}

#[test]
fn a_webhook_file_that_belongs_to_another_account_is_refused() {
    use std::os::unix::fs::MetadataExt;
    let theirs = Path::new("/etc/hosts");
    let id = std::process::Command::new("id").arg("-u").output().unwrap();
    let me: u32 = String::from_utf8(id.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    if fs::metadata(theirs).unwrap().uid() == me {
        return; // running as root: nothing here is someone else's
    }
    let stub = Stub::new();
    let mut s = slack(&stub);
    s.webhook_file = SecretFile::new(theirs).unwrap();
    assert_eq!(
        s.send(&alert()).unwrap_err(),
        "the Slack webhook file hosts belongs to another account"
    );
    assert!(!stub.called());
}

#[test]
fn a_symlinked_webhook_file_is_refused() {
    let stub = Stub::new();
    let mut s = slack(&stub);
    let link = stub.dir.path().join("link");
    std::os::unix::fs::symlink(stub.dir.path().join("webhook"), &link).unwrap();
    s.webhook_file = SecretFile::new(link).unwrap();
    assert!(s.send(&alert()).is_err());
    assert!(!stub.called());
}

#[test]
fn slack_saying_no_is_a_failed_send_that_names_the_status() {
    let stub = Stub::new();
    stub.answer("404", 0);
    let why = slack(&stub).send(&alert()).unwrap_err();
    assert_eq!(why, "Slack said HTTP 404");
}

#[test]
fn no_answer_says_why_without_the_url() {
    for (rc, expected) in [
        (28, "nothing from Slack within 2 s"),
        (6, "couldn't resolve Slack's host"),
        (7, "couldn't connect to Slack"),
        (35, "no HTTP reply from Slack (curl exit 35)"),
    ] {
        let stub = Stub::new();
        stub.answer("000", rc);
        let why = slack(&stub).send(&alert()).unwrap_err();
        assert_eq!(why, expected);
        assert_no_secret(&why);
    }
}

#[test]
fn a_curl_that_hangs_is_killed_and_the_send_fails() {
    let stub = Stub::new();
    fs::write(stub.dir.path().join("sleep"), "30").unwrap();
    let mut s = slack(&stub);
    s.curl.timeout = Duration::from_secs(1);
    let started = std::time::Instant::now();
    let why = s.send(&alert()).unwrap_err();
    assert_eq!(why, "nothing from Slack within 1 s");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn no_curl_is_a_failed_send() {
    let stub = Stub::new();
    let mut s = slack(&stub);
    s.curl.program = Path::new("/nonexistent/curl").into();
    assert_eq!(s.send(&alert()), Err("couldn't run curl".into()));
}

// iMessage.

#[test]
fn bluebubbles_sends_the_short_form_to_a_one_to_one_chat() {
    let stub = Stub::new();
    assert_eq!(bluebubbles(&stub).send(&alert()), Ok(()));
    let body = stub.body();
    assert_eq!(body["chatGuid"], format!("iMessage;-;{TO}"));
    assert_eq!(body["message"], alert().short);
    assert_eq!(body["method"], "apple-script");
    assert!(body["tempGuid"].as_str().unwrap().starts_with("whimbrel-"));
    assert_eq!(
        stub.config("url"),
        format!("http://127.0.0.1:1234/api/v1/message/text?password={PASSWORD}")
    );
}

#[test]
fn bluebubbles_never_goes_through_a_proxy() {
    for server in ["http://127.0.0.1:1234", "https://mac.example.net:1234"] {
        let stub = Stub::new();
        let mut m = bluebubbles(&stub);
        m.server = Server::new(server).unwrap();
        m.send(&alert()).unwrap();
        assert_eq!(stub.config("noproxy"), "*", "{server}");
        assert_eq!(stub.args(), ARGV);
    }
}

#[test]
fn slack_goes_through_a_proxy_if_the_environment_names_one() {
    let stub = Stub::new();
    slack(&stub).send(&alert()).unwrap();
    assert_eq!(stub.config_all("noproxy"), Vec::<String>::new());
}

#[test]
fn the_password_and_recipient_never_reach_curls_argv() {
    let stub = Stub::new();
    bluebubbles(&stub).send(&alert()).unwrap();
    assert!(
        !stub.args().contains(PASSWORD) && !stub.args().contains(TO),
        "{}",
        stub.args()
    );
}

#[test]
fn a_group_chat_is_refused_before_curl_runs() {
    let stub = Stub::new();
    let mut m = bluebubbles(&stub);
    m.recipient_file = stub.secret("recipient", "iMessage;+;chat123456789");
    let why = m.send(&alert()).unwrap_err();
    assert_eq!(
        why,
        "the recipient in recipient isn't a phone number or an Apple ID email"
    );
    assert!(!stub.called());
}

#[test]
fn a_password_that_would_break_the_url_is_refused() {
    let stub = Stub::new();
    let mut m = bluebubbles(&stub);
    m.password_file = stub.secret("password", "pw&to=+19999999999");
    let why = m.send(&alert()).unwrap_err();
    assert_eq!(
        why,
        "the BlueBubbles password in password has characters other than letters and digits"
    );
    assert!(!stub.called());
}

#[test]
fn bluebubbles_saying_no_names_bluebubbles() {
    let stub = Stub::new();
    stub.answer("500", 0);
    let why = bluebubbles(&stub).send(&alert()).unwrap_err();
    assert_eq!(why, "BlueBubbles said HTTP 500");
}

#[test]
fn bluebubbles_takes_the_short_form_and_slack_the_full_one() {
    let stub = Stub::new();
    assert_eq!(bluebubbles(&stub).form(), Form::Short);
    assert_eq!(slack(&stub).form(), Form::Full);
}

#[test]
fn bluebubbles_is_ready_only_when_a_send_could_go_through_and_never_sends_to_find_out() {
    let stub = Stub::new();
    let m = bluebubbles(&stub);
    assert_eq!(m.ready(), Ok(()));
    let mut group = bluebubbles(&stub);
    group.recipient_file = stub.secret("recipient", "iMessage;+;chat123456789");
    assert_eq!(
        group.ready(),
        Err("the recipient in recipient isn't a phone number or an Apple ID email".into())
    );
    let mut gone = bluebubbles(&stub);
    gone.password_file = SecretFile::new(stub.dir.path().join("nowhere")).unwrap();
    let why = gone.ready().unwrap_err();
    assert!(
        why.starts_with("can't read the BlueBubbles password file nowhere"),
        "{why}"
    );
    assert_no_secret(&why);
    assert!(!stub.called());
}

#[test]
fn slack_is_ready_only_with_a_webhook_it_could_post_to() {
    let stub = Stub::new();
    assert_eq!(slack(&stub).ready(), Ok(()));
    let mut s = slack(&stub);
    s.webhook_file = stub.secret("webhook", "https://example.com/hook");
    assert!(s.ready().is_err());
    assert!(!stub.called());
}
