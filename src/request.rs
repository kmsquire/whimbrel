//! An HTTP request by `curl`, the one way a channel reaches the network. It decides where every
//! part of a request goes: curl's argv is the same for every request but the timeout, and
//! everything else, the URL, the body, the headers and any credentials, goes to curl on stdin as
//! a curl config, so none of it appears in a process listing. A channel says which parts are
//! secret; those also never go through a proxy over plain HTTP, and never appear in what a send
//! returns, which is logged.
//!
//! ```no_run
//! use whimbrel::request::{Body, Curl, Part, Request};
//! # let url = String::new();
//! let body = Body::Json(serde_json::json!({ "text": "The disk is 95% full." }));
//! let sent = Request::post("Slack", [Part::secret(&url)], body).send(&Curl::default());
//! ```

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ChildStdout;
use std::time::Duration;

use crate::process::{self, Unfinished};
use crate::secret_patterns::REDACTED;

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

/// The HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Post,
    Put,
}

/// A piece of a URL or a form field's value, and whether it's secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    text: String,
    secret: bool,
}

impl Part {
    pub fn plain(text: impl Into<String>) -> Self {
        Part {
            text: text.into(),
            secret: false,
        }
    }

    pub fn secret(text: impl Into<String>) -> Self {
        Part {
            text: text.into(),
            secret: true,
        }
    }
}

/// What a request carries. It's given once, when the request is made.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    None,
    /// Sent as `application/json`. Nothing in it is known to be secret: name each secret value
    /// in it with [`Request::secret`], or it can show in the excerpt of a failed send's reply
    /// and doesn't count for the proxy rule.
    Json(serde_json::Value),
    /// Sent as `application/x-www-form-urlencoded`, each value encoded by curl. A field's name is
    /// letters, digits, `_`, `-` and `.`, and sent as it is. A secret part is kept out of the
    /// excerpt as it was given and as a form encodes it, not in any other encoding a far end
    /// might echo it back in.
    Form(Vec<(String, Part)>),
}

impl Body {
    pub fn form(fields: impl IntoIterator<Item = (String, Part)>) -> Self {
        Body::Form(fields.into_iter().collect())
    }
}

/// One request: where it goes, what it carries, which statuses mean it arrived, and which parts
/// are secret.
#[derive(Clone, Debug)]
pub struct Request {
    service: String,
    method: Method,
    url: Vec<Part>,
    body: Body,
    accept: Vec<u16>,
    basic_auth: Option<(String, String)>,
    secrets: Vec<String>,
    proxy: bool,
}

/// The most of a reply that's kept for its excerpt.
const HEAD_MAX: usize = 4096;

/// The most of a reply a failure quotes, in characters.
pub const EXCERPT_MAX: usize = 200;

/// How curl's `-w` ends its output: the status on a line of its own, after the reply.
const WRITE_OUT: &str = "\\n%{http_code}";

impl Request {
    /// A `method` request carrying `body` to the URL that `url`'s parts make, joined as they
    /// are. `service` names the far end in a failure: "Slack".
    pub fn new(
        service: &str,
        method: Method,
        url: impl IntoIterator<Item = Part>,
        body: Body,
    ) -> Self {
        Request {
            service: service.to_string(),
            method,
            url: url.into_iter().collect(),
            body,
            accept: vec![200],
            basic_auth: None,
            secrets: Vec::new(),
            proxy: true,
        }
    }

    pub fn post(service: &str, url: impl IntoIterator<Item = Part>, body: Body) -> Self {
        Self::new(service, Method::Post, url, body)
    }

    /// The statuses that mean it arrived: 200 alone unless this says otherwise.
    pub fn accept(mut self, statuses: &[u16]) -> Self {
        self.accept = statuses.to_vec();
        self
    }

    /// HTTP basic auth. The password is secret; the user isn't, unless it's also named in
    /// [`Request::secret`].
    pub fn basic_auth(mut self, user: &str, password: &str) -> Self {
        self.basic_auth = Some((user.to_string(), password.to_string()));
        self
    }

    /// A secret the request carries somewhere this module can't see it as one, such as inside a
    /// JSON body: kept out of the reply's excerpt, and counted for the proxy rule. A secret in a
    /// JSON body is protected only if it's named here.
    pub fn secret(mut self, value: &str) -> Self {
        self.secrets.push(value.to_string());
        self
    }

    /// Never through a proxy, whatever the environment says. A request that carries a secret
    /// over plain HTTP never goes through one anyway.
    pub fn no_proxy(mut self) -> Self {
        self.proxy = false;
        self
    }

    fn url(&self) -> String {
        self.url.iter().map(|p| p.text.as_str()).collect()
    }

    /// Every secret value it carries, and each secret form value as a form encodes it, longest
    /// first, so a secret inside another is never left half shown by replacing the shorter first.
    /// An empty secret is left out: replacing it would put the marker between every character.
    fn secret_values(&self) -> Vec<String> {
        let form: Vec<&Part> = match &self.body {
            Body::Form(fields) => fields.iter().map(|(_, p)| p).collect(),
            Body::None | Body::Json(_) => Vec::new(),
        };
        let mut all: Vec<String> = self
            .url
            .iter()
            .chain(form.iter().copied())
            .filter(|p| p.secret)
            .map(|p| p.text.clone())
            .chain(self.basic_auth.as_ref().map(|(_, pw)| pw.clone()))
            .chain(self.secrets.iter().cloned())
            .chain(
                form.iter()
                    .filter(|p| p.secret)
                    .flat_map(|p| form_encoded(&p.text)),
            )
            .filter(|s| !s.is_empty())
            .collect();
        all.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        all.dedup();
        all
    }

    /// Whether it may go through a proxy the environment names: not when asked not to, and not
    /// when it carries a secret in the clear, where a proxy would read it.
    fn may_use_proxy(&self) -> bool {
        self.proxy && (self.url().starts_with("https://") || self.secret_values().is_empty())
    }

    /// The curl config it's sent as, on stdin.
    fn config(&self) -> Result<String, String> {
        let url = self.url();
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(format!("{}'s URL isn't http:// or https://", self.service));
        }
        // No globbing: `[` and `]` are an IPv6 address's, never a range of hosts to send to.
        let mut config = format!("url = {}\ngloboff\n", quoted(&url));
        if self.method == Method::Put {
            config.push_str("request = \"PUT\"\n");
        }
        match &self.body {
            Body::None => {}
            Body::Json(body) => {
                config.push_str("header = \"Content-Type: application/json\"\n");
                config.push_str(&format!("data-binary = {}\n", quoted(&body.to_string())));
            }
            Body::Form(fields) => {
                for (name, value) in fields {
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                    {
                        return Err(format!(
                            "a form field's name for {} isn't plain",
                            self.service
                        ));
                    }
                    config.push_str(&format!(
                        "data-urlencode = {}\n",
                        quoted(&format!("{name}={}", value.text))
                    ));
                }
            }
        }
        if let Some((user, password)) = &self.basic_auth {
            config.push_str(&format!(
                "user = {}\n",
                quoted(&format!("{user}:{password}"))
            ));
        }
        if !self.may_use_proxy() {
            config.push_str("noproxy = \"*\"\n");
        }
        // curl's config reader ends a line at a NUL and joins the next line onto it, which would
        // drop `noproxy` or `user`. The value isn't quoted: it could be a secret.
        if config.contains('\0') {
            return Err(format!(
                "a value in the request to {} holds a NUL",
                self.service
            ));
        }
        Ok(config)
    }

    /// Send it. Its status must be one it accepts. A failure says why without the URL or any
    /// secret: the status, and a short excerpt of the reply with every secret it carries
    /// replaced.
    pub fn send(&self, curl: &Curl) -> Result<(), String> {
        let service = &self.service;
        let config = self.config()?;
        let secs = curl.timeout.as_secs().max(1).to_string();
        // The same for every request but the timeout: nothing a channel hands over goes here.
        // -q first: a ~/.curlrc could otherwise turn on tracing that writes the URL to a file.
        let args = ["-q", "-sS", "--max-time", &secs, "-w", WRITE_OUT, "-K", "-"];
        // A second more than curl's own limit, so curl's timeout is the one that's reported.
        let finished = process::run_reading(
            &curl.program,
            &args,
            config.as_bytes(),
            curl.timeout + Duration::from_secs(1),
            read_reply,
        );
        let (status, reply) = match finished {
            Ok((status, Ok(reply))) => (status, reply),
            Ok((_, Err(_)))
            | Err(
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
        let (code, body, cut) = reply.split();
        if let Ok(n) = code.parse::<u16>()
            && code.len() == 3
            && self.accept.contains(&n)
        {
            return Ok(());
        }
        Err(match (code.as_str(), status.code()) {
            ("000" | "", Some(28)) => format!("nothing from {service} within {secs} s"),
            ("000" | "", Some(6)) => format!("couldn't resolve {service}'s host"),
            ("000" | "", Some(7)) => format!("couldn't connect to {service}"),
            ("000" | "", Some(rc)) => format!("no HTTP reply from {service} (curl exit {rc})"),
            ("000" | "", None) => format!("no HTTP reply from {service} (curl killed)"),
            (code, _) if code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) => {
                let secrets = self.secret_values();
                let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
                let excerpt = excerpt(body, cut, &secrets);
                if excerpt.is_empty() {
                    format!("{service} said HTTP {code}")
                } else {
                    // Quoted, so a reply can't pass for more of the log line.
                    format!("{service} said HTTP {code}: {excerpt:?}")
                }
            }
            _ => format!("no HTTP reply from {service}"),
        })
    }
}

/// What curl printed: the start of the reply and the end of everything, which holds the status.
struct Reply {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: usize,
}

/// The most of the end of curl's output kept: the newline and the status, with room to spare.
const TAIL_MAX: usize = 16;

/// The first [`HEAD_MAX`] bytes and the last [`TAIL_MAX`], however much there is.
fn read_reply(mut out: ChildStdout) -> io::Result<Reply> {
    let mut head = Vec::new();
    let mut tail = Vec::new();
    let mut total = 0;
    let mut buf = [0u8; 8192];
    loop {
        let n = match out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = &buf[..n];
        let room = HEAD_MAX.saturating_sub(head.len());
        head.extend_from_slice(&chunk[..room.min(n)]);
        tail.extend_from_slice(chunk);
        if tail.len() > TAIL_MAX {
            tail.drain(..tail.len() - TAIL_MAX);
        }
        total += n;
    }
    Ok(Reply { head, tail, total })
}

impl Reply {
    /// The status, as much of the reply as was kept, and whether the reply went on past that.
    /// The status follows the last line break, even with no reply: a curl that never reached
    /// the far end prints `\n000`. With no line break at all there's no status.
    fn split(&self) -> (String, &[u8], bool) {
        let (code, suffix) = match self.tail.iter().rposition(|&b| b == b'\n') {
            Some(i) => (&self.tail[i + 1..], self.tail.len() - i),
            None => (&b""[..], 0),
        };
        let body_len = self.total - suffix;
        let code = String::from_utf8_lossy(code).trim().to_string();
        let kept = self.head.len().min(body_len);
        (code, &self.head[..kept], body_len > kept)
    }
}

/// Up to [`EXCERPT_MAX`] characters of `body`, `…` included, on one line, with every one of
/// `secrets` replaced and every control character a space.
/// When the reply went on past `body` (`cut`), its last bytes, where a secret could begin and
/// not end, are dropped first.
fn excerpt(body: &[u8], cut: bool, secrets: &[&str]) -> String {
    let longest = secrets.iter().map(|s| s.len()).max().unwrap_or(0);
    let keep = if cut {
        body.len().saturating_sub(longest)
    } else {
        body.len()
    };
    let mut text = String::from_utf8_lossy(&body[..keep]).into_owned();
    for secret in secrets {
        text = text.replace(secret, REDACTED);
    }
    let words: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|w| !w.is_empty())
        .collect();
    let line = words.join(" ");
    if line.chars().count() > EXCERPT_MAX || (cut && !line.is_empty()) {
        let short: String = line.chars().take(EXCERPT_MAX - 1).collect();
        format!("{}…", short.trim_end())
    } else {
        line
    }
}

/// `s` as a form encodes it, both ways a space can go: `+`, as curl sends it, and `%20`.
/// Everything but letters, digits and `-._~` is percent-encoded, in either case of hex digit.
fn form_encoded(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for space in ["+", "%20"] {
        for upper in [true, false] {
            let mut e = String::new();
            for b in s.bytes() {
                match b {
                    b' ' => e.push_str(space),
                    b if b.is_ascii_alphanumeric() || b"-._~".contains(&b) => e.push(b as char),
                    b if upper => e.push_str(&format!("%{b:02X}")),
                    b => e.push_str(&format!("%{b:02x}")),
                }
            }
            out.push(e);
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_value_survives_quotes_backslashes_and_line_breaks() {
        assert_eq!(quoted(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quoted("a\nb"), r#""a\nb""#);
    }

    fn reply(bytes: &[u8]) -> Reply {
        Reply {
            head: bytes[..bytes.len().min(HEAD_MAX)].to_vec(),
            tail: bytes[bytes.len().saturating_sub(TAIL_MAX)..].to_vec(),
            total: bytes.len(),
        }
    }

    #[test]
    fn the_status_is_the_last_line_and_the_reply_is_what_comes_before() {
        let r = reply(b"{\"ok\":false}\n404");
        let (code, body, cut) = r.split();
        assert_eq!(
            (code.as_str(), body, cut),
            ("404", &b"{\"ok\":false}"[..], false)
        );
        let r = reply(b"\n000");
        assert_eq!(r.split(), ("000".to_string(), &b""[..], false));
        // No line break: no status, so a send reads it as no reply.
        assert_eq!(reply(b"200").split().0, "");
        let r = reply(b"line one\nline two\n500");
        assert_eq!(r.split().1, b"line one\nline two");
    }

    #[test]
    fn a_long_reply_keeps_its_start_and_its_status() {
        let mut bytes = vec![b'x'; HEAD_MAX * 3];
        bytes.extend_from_slice(b"\n503");
        let r = reply(&bytes);
        let (code, body, cut) = r.split();
        assert_eq!(code, "503");
        assert_eq!(body.len(), HEAD_MAX);
        assert!(cut);
    }

    #[test]
    fn an_excerpt_is_one_short_line() {
        assert_eq!(
            excerpt(b"  no_service\n\tat all ", false, &[]),
            "no_service at all"
        );
        let long = "word ".repeat(100);
        let e = excerpt(long.as_bytes(), false, &[]);
        assert!(e.ends_with('…'), "{e}");
        assert_eq!(e.chars().count(), 200);
        assert_eq!(excerpt(b"", false, &[]), "");
    }

    #[test]
    fn an_excerpt_never_holds_a_secret() {
        let e = excerpt(
            b"bad recipient +15555550100, key s3kr1t",
            false,
            &["+15555550100", "s3kr1t"],
        );
        assert_eq!(e, "bad recipient [redacted], key [redacted]");
    }

    #[test]
    fn a_cut_reply_drops_where_a_secret_could_start_unfinished() {
        let mut body = vec![b'a'; HEAD_MAX - 3];
        body.extend_from_slice(b"s3k");
        let e = excerpt(&body, true, &["s3kr1t"]);
        assert!(!e.contains("s3k"), "{e}");
    }

    #[test]
    fn a_secret_inside_a_longer_one_is_replaced_after_it() {
        let r = Request::post(
            "X",
            [Part::plain("https://x/"), Part::secret("abc")],
            Body::None,
        )
        .secret("abcdef");
        assert_eq!(r.secret_values(), ["abcdef", "abc"]);
    }

    #[test]
    fn a_secret_named_twice_is_listed_once_wherever_it_sorts() {
        let r = Request::post(
            "X",
            [Part::plain("https://x/"), Part::secret("bb")],
            Body::None,
        )
        .secret("aa")
        .secret("bb");
        assert_eq!(r.secret_values(), ["aa", "bb"]);
    }

    #[test]
    fn an_empty_secret_is_left_out() {
        let r = Request::post(
            "X",
            [Part::plain("http://x/"), Part::secret("")],
            Body::None,
        )
        .secret("");
        assert_eq!(r.secret_values(), Vec::<String>::new());
        assert!(r.may_use_proxy());
    }

    #[test]
    fn a_secret_form_value_is_also_kept_out_as_a_form_encodes_it() {
        let body = Body::form([("To".into(), Part::secret("+1 555/0100"))]);
        let r = Request::post("X", [Part::plain("https://x/")], body);
        let values = r.secret_values();
        for encoded in ["%2B1+555%2F0100", "%2B1%20555%2F0100", "%2b1+555%2f0100"] {
            assert!(values.iter().any(|v| v == encoded), "{encoded}: {values:?}");
        }
        assert!(values.iter().any(|v| v == "+1 555/0100"), "{values:?}");
    }

    #[test]
    fn escape_and_c1_characters_never_reach_an_excerpt() {
        let e = excerpt("a\x1b[31mred\u{9b}2Jb\x07".as_bytes(), false, &[]);
        assert_eq!(e, "a [31mred 2Jb");
    }

    #[test]
    fn a_secret_in_the_clear_never_goes_through_a_proxy() {
        let http = |p: Part| Request::post("X", [Part::plain("http://h/"), p], Body::None);
        assert!(http(Part::plain("a")).may_use_proxy());
        assert!(!http(Part::secret("a")).may_use_proxy());
        assert!(!http(Part::plain("a")).secret("s").may_use_proxy());
        assert!(!http(Part::plain("a")).basic_auth("u", "pw").may_use_proxy());
        let form = Body::form([("To".into(), Part::secret("+15555550100"))]);
        let form = Request::post("X", [Part::plain("http://h/")], form);
        assert!(!form.may_use_proxy());
        let https = Request::post("X", [Part::secret("https://h/s")], Body::None);
        assert!(https.may_use_proxy());
        assert!(!https.no_proxy().may_use_proxy());
    }

    #[test]
    fn a_url_that_isnt_http_is_refused_without_naming_it() {
        let r = Request::post("X", [Part::secret("file:///etc/sekrit")], Body::None);
        let why = r.config().unwrap_err();
        assert_eq!(why, "X's URL isn't http:// or https://");
    }

    #[test]
    fn a_form_field_name_that_isnt_plain_is_refused() {
        let body = Body::form([("a\"\nurl".into(), Part::plain("x"))]);
        let r = Request::post("X", [Part::plain("https://h/")], body);
        assert!(r.config().is_err());
    }

    #[test]
    fn a_value_with_a_nul_is_refused() {
        let url = || [Part::plain("http://h/"), Part::secret("sekrit")];
        for body in [
            Body::form([("message".into(), Part::plain("disk full\0tail"))]),
            Body::form([("To".into(), Part::secret("+1555\0"))]),
        ] {
            let why = Request::post("X", url(), body).config().unwrap_err();
            assert_eq!(why, "a value in the request to X holds a NUL");
        }
        let auth = Request::post("X", url(), Body::None).basic_auth("u\0", "pw");
        assert!(auth.config().is_err());
        let url = Request::post("X", [Part::plain("https://h/\0x")], Body::None);
        assert!(url.config().is_err());
        // JSON escapes it, so it never reaches the config raw.
        let json = Body::Json(serde_json::json!({ "text": "a\0b" }));
        assert!(
            Request::post("X", [Part::plain("https://h/")], json)
                .config()
                .is_ok()
        );
    }

    #[test]
    fn a_url_is_never_globbed() {
        let r = Request::post("X", [Part::plain("http://[::1]:1234/a")], Body::None);
        let config = r.config().unwrap();
        assert!(config.lines().any(|l| l == "globoff"), "{config}");
    }
}
