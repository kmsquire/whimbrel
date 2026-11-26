//! Slack, by incoming webhook.

use serde::Deserialize;

use super::{Kind, SecretFile, SecretUrl, SendsWithCurl, build_with_curl};
use crate::alert::Alert;
use crate::ledger::Channel;
use crate::request::{Body, Curl, Part, Request};

/// ```toml
/// [[channel]]
/// kind = "slack"
/// webhook_file = "/etc/whimbrel/slack-webhook"
/// ```
pub const KIND: Kind = Kind {
    name: "slack",
    secret_url: Some(SecretUrl {
        what: "a Slack webhook URL",
        hosts: &["hooks.slack.com"],
        file_key: "webhook_file",
    }),
    build: build_with_curl::<Slack>,
};

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

impl SendsWithCurl for Slack {
    fn curl_mut(&mut self) -> &mut Curl {
        &mut self.curl
    }
}

impl Channel for Slack {
    fn name(&self) -> &str {
        &self.name
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let url = self.webhook()?;
        let body = serde_json::json!({ "text": slack_escape(&alert.full) });
        Request::post("Slack", [Part::secret(url)], Body::Json(body)).send(&self.curl)
    }

    fn ready(&self) -> Result<(), String> {
        self.webhook().map(|_| ())
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
    fn slack_markup_is_escaped() {
        assert_eq!(
            slack_escape("<!channel> & <x>"),
            "&lt;!channel&gt; &amp; &lt;x&gt;"
        );
    }
}
