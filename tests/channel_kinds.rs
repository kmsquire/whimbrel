//! Channel kinds as data: each a name, what its secret URL looks like if it has one, and a
//! function from its table to a channel. These tests add a kind of their own beside whimbrel's,
//! which sends through the request module the way a real one would.

use serde::Deserialize;
use whimbrel::channels::{
    KINDS, Kind, SecretFile, SecretUrl, SendsWithCurl, Shared, build_with_curl,
};
use whimbrel::config::Config;
use whimbrel::request::{Body, Curl, Part, Request};
use whimbrel::{Alert, Channel};

mod common;

use common::curl::Stub;

/// A pager service that answers 201 and takes basic auth and a form: the shape that didn't fit
/// before the request module. Its hook URL is a secret, so it's read from a file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pager {
    #[serde(default = "pager")]
    name: String,
    account: String,
    hook_file: SecretFile,
    token_file: SecretFile,
    #[serde(skip)]
    curl: Curl,
}

fn pager() -> String {
    "pager".into()
}

impl Channel for Pager {
    fn name(&self) -> &str {
        &self.name
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let hook = self.hook_file.read("pager hook")?;
        let token = self.token_file.read("pager token")?;
        let body = Body::form([("message".to_string(), Part::plain(&alert.short))]);
        Request::post("the pager", [Part::secret(hook)], body)
            .basic_auth(&self.account, &token)
            .accept(&[201])
            .send(&self.curl)
    }
}

const PAGER: Kind = Kind {
    name: "pager",
    secret_url: Some(SecretUrl {
        what: "a pager hook URL",
        hosts: &["hooks.pager.example.net"],
        file_key: "hook_file",
    }),
    build: build_with_curl::<Pager>,
};

impl SendsWithCurl for Pager {
    fn curl_mut(&mut self) -> &mut Curl {
        &mut self.curl
    }
}

/// whimbrel's kinds and `more`: the one line a new kind adds.
fn plus(more: &[Kind]) -> Vec<Kind> {
    KINDS.iter().chain(more).copied().collect()
}

const BASE: &str = "host = \"the test host\"\nstate_dir = \"/var/lib/whimbrel\"\n";

fn alert() -> Alert {
    Alert {
        short: "The disk is 95% full.".into(),
        full: "The disk is 95% full.".into(),
        urgent: true,
    }
}

#[test]
fn an_added_kind_is_built_from_its_table_and_sends_through_curl() {
    let stub = Stub::new();
    stub.secret("token", "pager-sekrit-31c8");
    stub.secret("hook", "https://hooks.pager.example.net/p/hook-sekrit-90d2");
    let text = format!(
        "{BASE}curl = {:?}\n[[channel]]\nkind = \"pager\"\naccount = \"ops\"\n\
         hook_file = {:?}\ntoken_file = {:?}\n",
        stub.curl().program,
        stub.dir.path().join("hook"),
        stub.dir.path().join("token"),
    );
    let config = Config::parse_with(&text, &plus(&[PAGER])).unwrap();
    let mut channels = config.build_channels();
    assert_eq!(channels[0].name(), "pager");
    stub.answer("201", 0);
    assert_eq!(channels[0].send(&alert()), Ok(()));
    assert_eq!(stub.config("user"), "ops:pager-sekrit-31c8");
    assert_eq!(
        stub.config("url"),
        "https://hooks.pager.example.net/p/hook-sekrit-90d2"
    );
    for secret in ["pager-sekrit-31c8", "hook-sekrit-90d2"] {
        assert!(!stub.args().contains(secret), "{}", stub.args());
    }
}

#[test]
fn a_kind_not_in_the_registry_is_refused_without_repeating_it() {
    let text = format!("{BASE}[[channel]]\nkind = \"pager\"\naccount = \"ops\"\n");
    let why = Config::parse(&text).unwrap_err().to_string();
    assert_eq!(
        why,
        "line 3: a channel's kind is one of `slack`, `bluebubbles`, `print`"
    );
}

#[test]
fn an_added_kind_refusing_its_table_names_the_line() {
    let text = format!("{BASE}[[channel]]\nkind = \"pager\"\naccount = \"ops\"\ntoken = \"x\"\n");
    let why = Config::parse_with(&text, &plus(&[PAGER]))
        .unwrap_err()
        .to_string();
    assert!(why.starts_with("line 3: unknown field `token`"), "{why}");
}

#[test]
fn two_kinds_with_one_name_are_refused() {
    let why = Config::parse_with(BASE, &[PAGER, PAGER])
        .unwrap_err()
        .to_string();
    assert_eq!(why, "two channel kinds are named \"pager\"");
}

#[test]
fn an_added_kinds_secret_url_is_refused_anywhere_in_the_config() {
    for extra in [
        "[[channel]]\nkind = \"print\"\nname = \"https://HOOKS.pager.example.net/p/sekrit\"\n",
        "log_file = \"/https://hooks.pager.example.net/p/sekrit\"\n",
        // An escape, which only the parsed value shows.
        "[[channel]]\nkind = \"print\"\nname = \"https://\\u0068ooks.pager.example.net/p/sekrit\"\n",
    ] {
        let text = format!("{BASE}{extra}");
        let why = Config::parse_with(&text, &plus(&[PAGER]))
            .unwrap_err()
            .to_string();
        assert_eq!(
            why,
            "it holds a pager hook URL. Put the URL in a file only root can read, and name that \
             file with hook_file.",
            "{extra}"
        );
        // Without the kind registered, nothing marks it secret.
        assert!(Config::parse(&text).is_ok(), "{extra}");
    }
}

#[test]
fn every_registered_kind_with_a_secret_url_refuses_it_in_the_config() {
    let mut seen = 0;
    for kind in KINDS {
        let Some(url) = kind.secret_url else { continue };
        for host in url.hosts {
            let text =
                format!("{BASE}[[channel]]\nkind = \"print\"\nname = \"https://{host}/x\"\n");
            let why = Config::parse(&text).unwrap_err().to_string();
            assert_eq!(why, url.refusal(), "{}", kind.name);
            seen += 1;
        }
    }
    // Slack's, at least: a kind losing its secret_url would otherwise pass unseen.
    assert!(seen >= 1);
}

#[test]
fn the_key_a_secret_url_refusal_names_is_one_its_kind_accepts() {
    let shared = Shared {
        curl: Curl::default(),
    };
    let mut seen = 0;
    for kind in plus(&[PAGER]) {
        let Some(url) = kind.secret_url else { continue };
        let mut table = whimbrel::toml::Table::new();
        table.insert(url.file_key.into(), "/etc/whimbrel/hook".into());
        // Missing other keys is fine; not knowing this one isn't.
        if let Err(why) = (kind.build)(table, &shared) {
            assert!(
                !why.contains(&format!("unknown field `{}`", url.file_key)),
                "{}: {why}",
                kind.name
            );
        }
        seen += 1;
    }
    assert!(seen >= 2, "{seen}");
}
