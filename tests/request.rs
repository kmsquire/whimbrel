//! The request module against the stand-in curl: where each part of a request goes, which
//! statuses it takes, and what a failure says. Nothing here reaches the network.

use whimbrel::request::{Body, EXCERPT_MAX, Method, Part, Request};

mod common;

use common::curl::Stub;

const IN_URL: &str = "url-sekrit-4b1e9d";
const IN_FORM: &str = "form-sekrit-77a0c2";
const PASSWORD: &str = "auth-sekrit-e5f318";
const IN_JSON: &str = "json-sekrit-0c9d6a";

/// A request with a secret in every place one can go.
fn everywhere(scheme: &str) -> Request {
    Request::post(
        "the service",
        [
            Part::plain(format!("{scheme}://example.net/v1/")),
            Part::secret(IN_URL),
            Part::plain("/send"),
        ],
        Body::form([
            ("To".to_string(), Part::secret(IN_FORM)),
            ("Body".to_string(), Part::plain("The disk is full.")),
        ]),
    )
    .basic_auth("account", PASSWORD)
    .secret(IN_JSON)
}

#[test]
fn every_secret_goes_on_stdin_and_none_on_argv() {
    let stub = Stub::new();
    everywhere("https").send(&stub.curl()).unwrap();
    let json = Stub::new();
    let body = Body::Json(serde_json::json!({ "to": IN_JSON }));
    Request::post("the service", [Part::plain("https://example.net/")], body)
        .secret(IN_JSON)
        .send(&json.curl())
        .unwrap();
    for (stub, secret) in [
        (&stub, IN_URL),
        (&stub, IN_FORM),
        (&stub, PASSWORD),
        (&json, IN_JSON),
    ] {
        assert!(stub.stdin().contains(secret), "{secret} isn't on stdin");
        assert!(
            !stub.args().contains(secret),
            "{secret} is on curl's argv: {:?}",
            stub.args()
        );
    }
    assert_eq!(
        stub.args(),
        "-q\n-sS\n--max-time\n2\n-w\n\\n%{http_code}\n-K\n-\n"
    );
}

#[test]
fn the_url_is_its_parts_joined() {
    let stub = Stub::new();
    everywhere("https").send(&stub.curl()).unwrap();
    assert_eq!(
        stub.config("url"),
        format!("https://example.net/v1/{IN_URL}/send")
    );
}

#[test]
fn a_form_is_each_field_for_curl_to_encode() {
    let stub = Stub::new();
    everywhere("https").send(&stub.curl()).unwrap();
    assert_eq!(
        stub.config_all("data-urlencode"),
        [
            format!("To={IN_FORM}"),
            "Body=The disk is full.".to_string()
        ]
    );
    assert_eq!(stub.config_all("header"), Vec::<String>::new());
    assert_eq!(stub.config("user"), format!("account:{PASSWORD}"));
}

#[test]
fn json_is_sent_as_json() {
    let stub = Stub::new();
    let body = Body::Json(serde_json::json!({ "text": "a \"quoted\" line\nand another" }));
    Request::post("the service", [Part::plain("https://example.net/")], body)
        .send(&stub.curl())
        .unwrap();
    assert_eq!(stub.config("header"), "Content-Type: application/json");
    assert_eq!(stub.body()["text"], "a \"quoted\" line\nand another");
    assert_eq!(stub.config_all("request"), Vec::<String>::new());
}

#[test]
fn a_put_says_so() {
    let stub = Stub::new();
    Request::new(
        "the service",
        Method::Put,
        [Part::plain("https://example.net/")],
        Body::None,
    )
    .send(&stub.curl())
    .unwrap();
    assert_eq!(stub.config("request"), "PUT");
}

#[test]
fn only_200_is_accepted_unless_the_request_says_otherwise() {
    let request = || {
        Request::post(
            "the service",
            [Part::plain("https://example.net/")],
            Body::None,
        )
    };
    let stub = Stub::new();
    stub.answer("201", 0);
    assert_eq!(
        request().send(&stub.curl()),
        Err("the service said HTTP 201".into())
    );
    assert_eq!(request().accept(&[200, 201]).send(&stub.curl()), Ok(()));
    stub.answer("200", 0);
    assert_eq!(
        request().accept(&[201]).send(&stub.curl()),
        Err("the service said HTTP 200".into())
    );
}

#[test]
fn a_secret_over_plain_http_never_goes_through_a_proxy() {
    let stub = Stub::new();
    everywhere("http").send(&stub.curl()).unwrap();
    assert_eq!(stub.config("noproxy"), "*");
    let stub = Stub::new();
    everywhere("https").send(&stub.curl()).unwrap();
    assert_eq!(stub.config_all("noproxy"), Vec::<String>::new());
    let stub = Stub::new();
    Request::post(
        "the service",
        [Part::plain("http://example.net/")],
        Body::None,
    )
    .send(&stub.curl())
    .unwrap();
    assert_eq!(stub.config_all("noproxy"), Vec::<String>::new());
}

#[test]
fn a_failure_quotes_the_start_of_the_reply_on_one_line_without_secrets() {
    let stub = Stub::new();
    stub.answer("422", 0);
    stub.reply(&format!(
        "{{\"message\": \"The 'To' number {IN_FORM} is not valid.\",\n\
         \"auth\": \"account:{PASSWORD}\", \"more\": \"{}\"}}",
        "x".repeat(500)
    ));
    let why = everywhere("https").send(&stub.curl()).unwrap_err();
    // In double quotes, with its own quotes escaped, so it can't pass for more of the log line.
    let quoted = why
        .strip_prefix("the service said HTTP 422: \"")
        .and_then(|q| q.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{why}"));
    assert!(
        quoted.starts_with(
            r#"{\"message\": \"The 'To' number [redacted] is not valid.\", \"auth\": \"account:[redacted]\", \"more\": \"xxx"#
        ),
        "{quoted}"
    );
    assert!(quoted.ends_with('…'), "{quoted}");
    assert_eq!(quoted.replace("\\\"", "\"").chars().count(), EXCERPT_MAX);
}

#[test]
fn a_reply_cant_pass_for_more_of_the_log_line() {
    let stub = Stub::new();
    stub.answer("500", 0);
    stub.reply("oops\"; slack: sent");
    let request = Request::post("the service", [Part::plain("https://x/")], Body::None);
    assert_eq!(
        request.send(&stub.curl()),
        Err(r#"the service said HTTP 500: "oops\"; slack: sent""#.into())
    );
}

#[test]
fn a_status_that_isnt_three_digits_is_no_reply() {
    for code in ["0200", "+200", "20"] {
        let stub = Stub::new();
        stub.answer(code, 0);
        let request = Request::post("the service", [Part::plain("https://x/")], Body::None);
        assert_eq!(
            request.accept(&[200, 20]).send(&stub.curl()),
            Err("no HTTP reply from the service".into()),
            "{code}"
        );
    }
}

#[test]
fn a_secret_form_value_echoed_back_encoded_is_kept_out() {
    let stub = Stub::new();
    stub.answer("400", 0);
    stub.reply("bad To=%2B1+555+0100");
    let body = Body::form([("To".into(), Part::secret("+1 555 0100"))]);
    let request = Request::post("the service", [Part::plain("https://x/")], body);
    assert_eq!(
        request.send(&stub.curl()),
        Err(r#"the service said HTTP 400: "bad To=[redacted]""#.into())
    );
}

#[test]
fn a_reply_bigger_than_any_other_program_may_print_is_still_read() {
    let stub = Stub::new();
    stub.reply(&"x".repeat(2 * 1024 * 1024));
    let request = Request::post(
        "the service",
        [Part::plain("https://example.net/")],
        Body::None,
    );
    assert_eq!(request.send(&stub.curl()), Ok(()));
}
