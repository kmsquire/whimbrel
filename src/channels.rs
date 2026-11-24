//! The channels: Slack by incoming webhook, iMessage through a BlueBubbles server, and print, which
//! writes to stdout and stands in for every channel in a dry run.
//!
//! Each real channel reads its secrets from files at send time, so config holds paths, never the
//! values, and a rotated secret needs no restart. A secret file must be an absolute path, belong
//! to us and be readable by us alone. Both send with `curl`, handing it the URL and the body on
//! stdin as a curl config, so neither appears in a process listing. Nothing a send returns names
//! the URL, the password, the recipient or a secret file's path: it's logged, and a path is where
//! a secret pasted into the wrong key would land.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::id;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::Deserialize;

use crate::alert::Alert;
use crate::ledger::{Channel, Form};
use crate::process::{self, Unfinished};

/// How to reach `curl`, and how long to give it.
#[derive(Clone, Debug)]
pub struct Curl {
    pub program: PathBuf,
    pub timeout: Duration,
}

impl Default for Curl {
    fn default() -> Self {
        Curl {
            program: "curl".into(),
            timeout: Duration::from_secs(20),
        }
    }
}

impl Curl {
    /// POST `body` as JSON to `url`, with `extra` arguments. `service` names the far end in a
    /// failure.
    fn post(
        &self,
        service: &str,
        url: &str,
        body: &serde_json::Value,
        extra: &[&str],
    ) -> Result<(), String> {
        let config = format!(
            "url = {}\ndata-binary = {}\n",
            quoted(url),
            quoted(&body.to_string())
        );
        let secs = self.timeout.as_secs().max(1).to_string();
        // -q first: a ~/.curlrc could otherwise turn on tracing that writes the URL to a file.
        let mut args = vec![
            "-q",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            &secs,
            "-H",
            "Content-Type: application/json",
        ];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["-K", "-"]);
        // A second more than curl's own limit, so curl's timeout is the one that's reported.
        let finished = process::run(
            &self.program,
            &args,
            config.as_bytes(),
            self.timeout + Duration::from_secs(1),
        );
        let out = match finished {
            Ok(out) => out,
            Err(
                Unfinished::NotStarted
                | Unfinished::Unread
                | Unfinished::TooMuch
                | Unfinished::HeldOpen,
            ) => {
                return Err("couldn't run curl".into());
            }
            Err(Unfinished::TimedOut) => {
                return Err(format!("nothing from {service} within {secs} s"));
            }
        };
        let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if code == "200" {
            return Ok(());
        }
        Err(match (code.as_str(), out.status.code()) {
            ("000" | "", Some(28)) => format!("nothing from {service} within {secs} s"),
            ("000" | "", Some(6)) => format!("couldn't resolve {service}'s host"),
            ("000" | "", Some(7)) => format!("couldn't connect to {service}"),
            ("000" | "", Some(rc)) => format!("no HTTP reply from {service} (curl exit {rc})"),
            ("000" | "", None) => format!("no HTTP reply from {service} (curl killed)"),
            (code, _) if code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) => {
                format!("{service} said HTTP {code}")
            }
            _ => format!("no HTTP reply from {service}"),
        })
    }
}

/// A string as a curl config file quotes it: backslash and double quote escaped, and no raw line
/// breaks, which JSON's own escaping already guarantees for a body.
fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A file holding a secret: an absolute path, so it can't depend on where whimbrel was started.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "PathBuf")]
pub struct SecretFile(PathBuf);

impl TryFrom<PathBuf> for SecretFile {
    type Error = String;

    fn try_from(path: PathBuf) -> Result<Self, String> {
        // The path itself isn't repeated: a secret pasted here by mistake would be.
        if path.is_absolute() {
            Ok(SecretFile(path))
        } else {
            Err("a secret file must be an absolute path".into())
        }
    }
}

/// The most a secret file is read: every secret here is one short line.
const SECRET_MAX: u64 = 64 * 1024;

impl SecretFile {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::try_from(path.into())
    }

    /// The file's name alone, for messages.
    fn name(&self) -> String {
        self.0
            .file_name()
            .map_or_else(|| "?".into(), |n| n.to_string_lossy().into_owned())
    }

    /// Its first line, trimmed, if it's a regular file of ours that only we can read. The
    /// failure names the file, never its path or contents.
    ///
    /// The checks are on the open file, so a swap after them can't slip a different file in. A
    /// directory above it that someone else can write is still a way in; keep secrets under a
    /// directory only root can change.
    fn read(&self, what: &str) -> Result<String, String> {
        let name = self.name();
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.0)
            .map_err(|e| format!("can't read the {what} file {name} ({})", e.kind()))?;
        let m = f
            .metadata()
            .map_err(|e| format!("can't read the {what} file {name} ({})", e.kind()))?;
        if !m.is_file() {
            return Err(format!("the {what} file {name} isn't a regular file"));
        }
        // SAFETY: geteuid has no preconditions and can't fail.
        if m.uid() != unsafe { libc::geteuid() } {
            return Err(format!("the {what} file {name} belongs to another account"));
        }
        if m.mode() & 0o077 != 0 {
            return Err(format!(
                "the {what} file {name} can be read by other accounts ({:o}); it should be 600",
                m.mode() & 0o777
            ));
        }
        let mut text = String::new();
        (&mut f)
            .take(SECRET_MAX)
            .read_to_string(&mut text)
            .map_err(|e| format!("can't read the {what} file {name} ({})", e.kind()))?;
        let line = text.lines().next().unwrap_or("").trim().to_string();
        if line.is_empty() {
            return Err(format!("the {what} file {name} is empty"));
        }
        Ok(line)
    }
}

/// A BlueBubbles server's address: `http://` or `https://`, a host and an optional port, and
/// nothing else, so no path, query or credentials ride along with the password.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct Server(String);

impl TryFrom<String> for Server {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let s = s.trim_end_matches('/');
        let rest = s
            .strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"));
        let ok = rest.is_some_and(|r| {
            !r.is_empty()
                && r.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        });
        if ok {
            Ok(Server(s.to_string()))
        } else {
            Err(
                "server must be http:// or https://, a host and a port, with no path or credentials"
                    .into(),
            )
        }
    }
}

impl Server {
    pub fn new(s: impl Into<String>) -> Result<Self, String> {
        Self::try_from(s.into())
    }
}

/// Slack, by incoming webhook. It gets the full form.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slack {
    #[serde(default = "slack")]
    pub name: String,
    pub webhook_file: SecretFile,
    #[serde(skip)]
    pub curl: Curl,
}

fn slack() -> String {
    "slack".into()
}

impl Slack {
    pub fn new(webhook_file: SecretFile) -> Self {
        Slack {
            name: slack(),
            webhook_file,
            curl: Curl::default(),
        }
    }

    /// The webhook from its file, checked.
    fn webhook(&self) -> Result<String, String> {
        let url = self.webhook_file.read("Slack webhook")?;
        if !valid_slack_webhook(&url) {
            return Err(format!(
                "the Slack webhook file {} doesn't hold a Slack incoming-webhook URL",
                self.webhook_file.name()
            ));
        }
        Ok(url)
    }
}

/// `https://hooks.slack.com/services/` and the path's own characters, nothing else.
fn valid_slack_webhook(url: &str) -> bool {
    url.strip_prefix("https://hooks.slack.com/services/")
        .is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-'))
        })
}

/// Slack reads `<...>` as a link or a mention, so a log named `<!channel>.log` would ping.
fn slack_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl Channel for Slack {
    fn name(&self) -> &str {
        &self.name
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let url = self.webhook()?;
        let body = serde_json::json!({ "text": slack_escape(&alert.full) });
        self.curl.post("Slack", &url, &body, &[])
    }

    fn ready(&self) -> Result<(), String> {
        self.webhook().map(|_| ())
    }
}

/// iMessage, through a BlueBubbles server's `message/text`, to one person's one-to-one chat. It
/// gets the short form.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueBubbles {
    #[serde(default = "bluebubbles")]
    pub name: String,
    pub server: Server,
    pub password_file: SecretFile,
    /// A phone number in international form or an Apple ID email, never a chat GUID.
    pub recipient_file: SecretFile,
    #[serde(skip)]
    pub curl: Curl,
}

fn bluebubbles() -> String {
    "bluebubbles".into()
}

impl BlueBubbles {
    pub fn new(server: Server, password_file: SecretFile, recipient_file: SecretFile) -> Self {
        BlueBubbles {
            name: bluebubbles(),
            server,
            password_file,
            recipient_file,
            curl: Curl::default(),
        }
    }

    /// The endpoint, with the password in its query, and the recipient, from their files, checked.
    fn target(&self) -> Result<(String, String), String> {
        let password = self.password_file.read("BlueBubbles password")?;
        // It goes into the query string as it is, so letters and digits only.
        if !password.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!(
                "the BlueBubbles password in {} has characters other than letters and digits",
                self.password_file.name()
            ));
        }
        let to = self.recipient_file.read("iMessage recipient")?;
        if !valid_recipient(&to) {
            return Err(format!(
                "the recipient in {} isn't a phone number or an Apple ID email",
                self.recipient_file.name()
            ));
        }
        let url = format!("{}/api/v1/message/text?password={password}", self.server.0);
        Ok((url, to))
    }
}

/// An E.164 number, `+` and 8 to 15 digits with no leading 0, or a lowercase email whose local
/// part and each domain label start and end with a letter or digit, with no `..`. A group chat's
/// GUID is neither, so an alert can never land in a chat other people read.
fn valid_recipient(to: &str) -> bool {
    static PHONE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\+[1-9][0-9]{7,14}$").expect("a valid pattern"));
    static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$",
        )
        .expect("a valid pattern")
    });
    PHONE.is_match(to) || (EMAIL.is_match(to) && !to.contains(".."))
}

impl Channel for BlueBubbles {
    fn name(&self) -> &str {
        &self.name
    }

    fn form(&self) -> Form {
        Form::Short
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let (url, to) = self.target()?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let body = serde_json::json!({
            "chatGuid": format!("iMessage;-;{to}"),
            "tempGuid": format!("whimbrel-{nanos}-{}", id()),
            "message": alert.short,
            "method": "apple-script",
        });
        // No proxy, whatever the environment says: the password is in the URL.
        self.curl
            .post("BlueBubbles", &url, &body, &["--noproxy", "*"])
    }

    fn ready(&self) -> Result<(), String> {
        self.target().map(|_| ())
    }
}

/// Writes to stdout and always succeeds. A config can use it to try a host's checks out; a dry
/// run puts one in place of each real channel, with its name and form and a heading.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Print {
    #[serde(default = "print")]
    pub name: String,
    #[serde(skip)]
    pub form: Form,
    /// Printed above each message: "slack would be sent".
    #[serde(skip)]
    pub heading: Option<String>,
}

fn print() -> String {
    "print".into()
}

impl Print {
    /// The dry run's stand-in for `channel`.
    pub fn instead_of(channel: &dyn Channel) -> Self {
        Print {
            name: channel.name().to_string(),
            form: channel.form(),
            heading: Some(format!("{} would be sent", channel.name())),
        }
    }
}

impl Channel for Print {
    fn name(&self) -> &str {
        &self.name
    }

    fn form(&self) -> Form {
        self.form
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let text = match self.form {
            Form::Short => &alert.short,
            Form::Full => &alert.full,
        };
        match &self.heading {
            Some(h) => println!("\n{h}:\n{text}"),
            None => println!("{text}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_slack_incoming_webhook_is_a_webhook() {
        assert!(valid_slack_webhook(
            "https://hooks.slack.com/services/T0/B0/abc_-9"
        ));
        assert!(!valid_slack_webhook("https://hooks.slack.com/services/"));
        assert!(!valid_slack_webhook(
            "http://hooks.slack.com/services/T0/B0/x"
        ));
        assert!(!valid_slack_webhook(
            "https://hooks.slack.com.evil/services/T0"
        ));
        assert!(!valid_slack_webhook(
            "https://hooks.slack.com/services/T0?x=1"
        ));
        assert!(!valid_slack_webhook(
            "https://hooks.slack.com/services/T0\"\nurl=x"
        ));
    }

    #[test]
    fn a_number_is_e164_from_8_to_15_digits() {
        assert!(valid_recipient("+15555550100"));
        assert!(valid_recipient("+442079460000"));
        assert!(valid_recipient("+12345678"));
        assert!(valid_recipient("+123456789012345"));
        assert!(!valid_recipient("+1234567"));
        assert!(!valid_recipient("+1234567890123456"));
        assert!(!valid_recipient("+1 555 555 0100"));
        assert!(!valid_recipient("+15555550100\n"));
    }

    #[test]
    fn a_number_with_0_after_the_plus_isnt_e164() {
        assert!(!valid_recipient("+0123456789"));
        assert!(!valid_recipient("+05555550100"));
    }

    #[test]
    fn an_email_is_lowercase_and_starts_and_ends_each_part_with_a_letter_or_digit() {
        assert!(valid_recipient("name@example.com"));
        assert!(valid_recipient("first.last+tag@sub.example.org"));
        assert!(valid_recipient("a@b.co"));
        for bad in [
            "-a@example.com",
            "a-@example.com",
            "a.@x.com",
            "a@-example.com",
            "a@example-.com",
            "a@.com",
            "a@b.com.",
            "a@@b.com",
            "a@b.c",
            "a@b.c1",
            "josé@example.com",
            "a@exämple.com",
            " kid@example.com",
            "kid@example.com ",
            "a@b.co\n",
        ] {
            assert!(!valid_recipient(bad), "{bad:?} passed");
        }
    }

    #[test]
    fn an_email_with_capitals_isnt_a_handle() {
        for bad in [
            "Kid@example.com",
            "kid@Example.com",
            "kid@example.COM",
            "KID@EXAMPLE.COM",
        ] {
            assert!(!valid_recipient(bad), "{bad:?} passed");
        }
    }

    #[test]
    fn an_email_with_a_percent_isnt_a_handle() {
        assert!(!valid_recipient("name%x@example.com"));
        assert!(!valid_recipient("a%b@example.com"));
    }

    #[test]
    fn an_email_with_two_dots_together_isnt_a_handle() {
        assert!(!valid_recipient("a..b@x.com"));
        assert!(!valid_recipient("a@b..com"));
    }

    #[test]
    fn an_email_keeps_to_the_lengths_dns_and_the_map_allow() {
        let label = |n| "b".repeat(n);
        assert!(valid_recipient(&format!("{}@x.com", "a".repeat(64))));
        assert!(!valid_recipient(&format!("{}@x.com", "a".repeat(65))));
        assert!(valid_recipient(&format!("a@{}.com", label(63))));
        assert!(!valid_recipient(&format!("a@{}.com", label(64))));
        assert!(valid_recipient(&format!("a@c.{}.com", label(63))));
        assert!(!valid_recipient(&format!("a@c.{}.com", label(64))));
        assert!(valid_recipient(&format!("a@b.{}", "c".repeat(24))));
        assert!(!valid_recipient(&format!("a@b.{}", "c".repeat(25))));
    }

    #[test]
    fn a_recipient_is_one_person_never_a_group() {
        assert!(valid_recipient("+15555550100"));
        assert!(valid_recipient("someone.else+tag@example.com"));
        assert!(!valid_recipient("+1555"));
        assert!(!valid_recipient("15555550100"));
        assert!(!valid_recipient("iMessage;+;chat123456"));
        assert!(!valid_recipient("iMessage;-;+15555550100"));
        assert!(!valid_recipient("a@b"));
        assert!(!valid_recipient("@example.com"));
    }

    #[test]
    fn a_server_is_a_scheme_a_host_and_a_port() {
        assert!(Server::new("http://127.0.0.1:1234").is_ok());
        assert!(Server::new("https://mac.example.net:1234").is_ok());
        assert!(Server::new("http://[::1]:1234").is_ok());
        assert_eq!(
            Server::new("http://127.0.0.1:1234/").unwrap(),
            Server("http://127.0.0.1:1234".into())
        );
        assert!(Server::new("http://user:pw@host:1234").is_err());
        // Built here, so the repo holds no URL with a password in it.
        let with_password = format!("http://host:1234/api?{}=x", "password");
        assert!(Server::new(with_password).is_err());
        assert!(Server::new("ftp://host").is_err());
        assert!(Server::new("http://").is_err());
    }

    #[test]
    fn a_secret_file_is_an_absolute_path() {
        assert!(SecretFile::new("/etc/whimbrel/webhook").is_ok());
        let why = SecretFile::new("https://hooks.example/sekrit").unwrap_err();
        assert!(!why.contains("sekrit"), "{why}");
    }

    #[test]
    fn slack_markup_is_escaped() {
        assert_eq!(
            slack_escape("<!channel> & <x>"),
            "&lt;!channel&gt; &amp; &lt;x&gt;"
        );
    }

    #[test]
    fn a_quoted_value_survives_quotes_backslashes_and_line_breaks() {
        assert_eq!(quoted(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quoted("a\nb"), r#""a\nb""#);
    }
}
