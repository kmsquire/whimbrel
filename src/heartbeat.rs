//! A ping after every run that went through and kept its ledger, to a URL the config names, so a
//! service watching for it notices when whimbrel stops running, or runs but can't do its job. Its
//! body is the worst level alone: never an alert's text.
//!
//! ```toml
//! [heartbeat]
//! url_file = "/etc/whimbrel/heartbeat-url"
//! ```
//!
//! The URL is a secret, as anyone who has it can ping, so it's read from a file at each run and
//! goes to curl on stdin, as a channel's does. A config holding a URL in its `[heartbeat]` table is
//! refused.

use serde::Deserialize;

use crate::channels::{SecretFile, SecretUrl};
use crate::request::{Body, Curl, Part, Request};
use crate::run::Ran;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub url_file: SecretFile,
}

/// A heartbeat's URL, which could be on any host, so any URL in the `[heartbeat]` table is
/// refused.
pub const SECRET_URL: SecretUrl = SecretUrl {
    what: "a heartbeat URL",
    hosts: &["://"],
    file_key: "url_file",
};

/// What the far end is called in a failure.
const SERVICE: &str = "the heartbeat";

impl Heartbeat {
    /// Ping with the run's worst level. The reason a ping failed never holds the URL, or any
    /// piece of its path, which is where a service puts the token.
    pub fn ping(&self, curl: &Curl, ran: &Ran) -> Result<(), String> {
        let url = self.url_file.read("heartbeat URL")?;
        let body = serde_json::json!({ "status": ran.worst().as_str() });
        let mut request = Request::post(SERVICE, [Part::secret(url.clone())], Body::Json(body))
            .accept(&[200, 201, 202, 204]);
        // A reply can echo the token alone, without the rest of the URL.
        for segment in path_segments(&url) {
            request = request.secret(segment);
        }
        request.send(curl)
    }
}

/// Each piece of `url`'s path, without its query or fragment: "/ping/abc" gives "ping", "abc".
fn path_segments(url: &str) -> impl Iterator<Item = &str> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = after_scheme.split_once('/').map_or("", |(_, path)| path);
    let path = path.split(['?', '#']).next().unwrap_or("");
    path.split('/').filter(|s| !s.is_empty())
}
