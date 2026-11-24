//! What a secret looks like: the built-in shapes, each with an id, plus a config's own patterns.
//! The same set redacts every alert and drives the `secrets` check.
//!
//! The built-in shapes are every rule of three published lists that passes one test, taken in list
//! order: gitleaks v8.30.1 (MIT), betterleaks (MIT) and Google's osv-scalibr (Apache-2.0), at the
//! commits `THIRD-PARTY.md` names with their notices. A rule passes if
//!
//! - its token, the rule less the boundary group a list matches after it, compiles here;
//! - the token starts the match: nothing but word boundaries comes before the part that captures
//!   it, so no rule that needs a keyword nearby passes;
//! - every way it can match starts with the same 3 or more fixed characters;
//! - it can't match fewer than 16 characters;
//! - it's a shape, not one fixed string;
//! - and no rule taken from an earlier list already matches an example made from it.
//!
//! The built-ins compile as one set with Unicode classes off, each pattern as its source
//! publishes it. A config's own patterns compile as written, with Unicode.
//!
//! Nothing is chosen by service. Where a shape differs from its rule beyond the boundary group,
//! `changed` says how. One shape is whimbrel's own, for a secret whimbrel itself handles.

use regex::Regex;

/// One built-in shape.
pub struct Shape {
    /// What `disable` names it by.
    pub id: &'static str,
    /// The published list it's taken from: `gitleaks`, `betterleaks`, `osv-scalibr`, or
    /// `whimbrel` for one of its own.
    pub source: &'static str,
    /// The rule in that list it's taken from, or for one of whimbrel's own, why it's here.
    pub rule: &'static str,
    pub pattern: &'static str,
    /// How it differs from the rule's token, if it does.
    pub changed: Option<&'static str>,
}

/// Every built-in shape, by id. The selection rule is in the module's doc; `docs/config.md`
/// lists them in the same order.
pub const BUILTINS: &[Shape] = &[
    Shape {
        id: "1password-secret-key",
        source: "gitleaks",
        rule: "1password-secret-key",
        pattern: r#"\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b"#,
        changed: None,
    },
    Shape {
        id: "1password-service-account-token",
        source: "gitleaks",
        rule: "1password-service-account-token",
        pattern: r#"ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}"#,
        changed: None,
    },
    Shape {
        id: "adobe-client-secret",
        source: "gitleaks",
        rule: "adobe-client-secret",
        pattern: r#"\b(p8e-(?i)[a-z0-9]{32})"#,
        changed: None,
    },
    Shape {
        id: "age-secret-key",
        source: "gitleaks",
        rule: "age-secret-key",
        pattern: r#"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"#,
        changed: None,
    },
    Shape {
        id: "aikido-ci-token",
        source: "betterleaks",
        rule: "aikido-ci-token",
        pattern: r#"\b(AIK_CI_[A-Za-z0-9]{20,44})\b"#,
        changed: None,
    },
    Shape {
        id: "aikido-client-id",
        source: "betterleaks",
        rule: "aikido-client-id",
        pattern: r#"\b(AIK_CLIENT_[A-Za-z0-9]{24})"#,
        changed: None,
    },
    Shape {
        id: "aikido-client-secret",
        source: "betterleaks",
        rule: "aikido-client-secret",
        pattern: r#"\b(AIK_SECRET_[A-Za-z0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "airtable-personnal-access-token",
        source: "gitleaks",
        rule: "airtable-personnal-access-token",
        pattern: r#"\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b"#,
        changed: None,
    },
    Shape {
        id: "alibaba-access-key-id",
        source: "gitleaks",
        rule: "alibaba-access-key-id",
        pattern: r#"\b(LTAI(?i)[a-z0-9]{20})"#,
        changed: None,
    },
    Shape {
        id: "alibaba-access-key-id-betterleaks",
        source: "betterleaks",
        rule: "alibaba-access-key-id",
        pattern: r#"\b(LTAI[A-Za-z0-9]{17,21})\b"#,
        changed: None,
    },
    Shape {
        id: "alibaba-sts-access-key-id",
        source: "betterleaks",
        rule: "alibaba-sts-access-key-id",
        pattern: r#"\b(STS\.[A-Za-z0-9]{16,64})\b"#,
        changed: None,
    },
    Shape {
        id: "anthropic-admin-api-key",
        source: "gitleaks",
        rule: "anthropic-admin-api-key",
        pattern: r#"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)"#,
        changed: None,
    },
    Shape {
        id: "anthropic-api-key",
        source: "gitleaks",
        rule: "anthropic-api-key",
        pattern: r#"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)"#,
        changed: None,
    },
    Shape {
        id: "anthropic-oauth-access-token",
        source: "betterleaks",
        rule: "anthropic-oauth-access-token",
        pattern: r#"\b(sk-ant-oat01-[a-zA-Z0-9_\-]{80,})"#,
        changed: None,
    },
    Shape {
        id: "anthropic-oauth-refresh-token",
        source: "betterleaks",
        rule: "anthropic-oauth-refresh-token",
        pattern: r#"\b(sk-ant-ort01-[a-zA-Z0-9_\-]{80,})"#,
        changed: None,
    },
    Shape {
        id: "apify-api-token",
        source: "betterleaks",
        rule: "apify-api-token",
        pattern: r#"\b(apify_api_[A-Za-z0-9]{34,38})\b"#,
        changed: None,
    },
    Shape {
        id: "artifactory-api-key",
        source: "gitleaks",
        rule: "artifactory-api-key",
        pattern: r#"\bAKCp[A-Za-z0-9]{69}\b"#,
        changed: None,
    },
    Shape {
        id: "artifactory-api-key-betterleaks",
        source: "betterleaks",
        rule: "artifactory-api-key",
        pattern: r#"\bAKCp[A-Za-z0-9]{68,70}\b"#,
        changed: None,
    },
    Shape {
        id: "artifactory-reference-token",
        source: "gitleaks",
        rule: "artifactory-reference-token",
        pattern: r#"\bcmVmd[A-Za-z0-9]{59}\b"#,
        changed: None,
    },
    Shape {
        id: "atlassian-api-token",
        source: "betterleaks",
        rule: "atlassian-api-token",
        pattern: r#"\b(ATAT[A-Za-z0-9_\-=]{100,})"#,
        changed: None,
    },
    Shape {
        id: "authress-service-client-access-key",
        source: "gitleaks",
        rule: "authress-service-client-access-key",
        pattern: r#"\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})"#,
        changed: None,
    },
    Shape {
        id: "authress-service-client-access-key-betterleaks",
        source: "betterleaks",
        rule: "authress-service-client-access-key",
        pattern: r#"(?i)\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})\b"#,
        changed: None,
    },
    Shape {
        id: "aws-access-token",
        source: "gitleaks",
        rule: "aws-access-token",
        pattern: r#"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"#,
        changed: None,
    },
    Shape {
        id: "aws-amazon-bedrock-api-key-long-lived",
        source: "gitleaks",
        rule: "aws-amazon-bedrock-api-key-long-lived",
        pattern: r#"\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})"#,
        changed: None,
    },
    Shape {
        id: "azure-servicebus-connection-string",
        source: "betterleaks",
        rule: "azure-servicebus-connection-string",
        pattern: r#"(?i)(Endpoint=sb://[a-z0-9-]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;=\s'"]{1,128};SharedAccessKey=[A-Za-z0-9+/]{32,100}={0,2}(?:;EntityPath=[^;\s'"]{1,128})?)"#,
        changed: None,
    },
    Shape {
        id: "bitbucket-data-center-token",
        source: "betterleaks",
        rule: "bitbucket-data-center-token",
        pattern: r#"\b(BBDC-[A-Za-z0-9+/=]{32,})"#,
        changed: None,
    },
    Shape {
        id: "bitbucket-url",
        source: "osv-scalibr",
        rule: "veles/secrets/gitbasicauth/bitbucket urlPattern",
        pattern: r#"\bhttps://[^:\s]+:[^\s@]+@bitbucket\.org/[^\s]+\.git\b"#,
        changed: None,
    },
    Shape {
        id: "brave-search-api-key",
        source: "betterleaks",
        rule: "brave-search-api-key",
        pattern: r#"\b(BSA[A-Za-z0-9_-]{24,40})\b"#,
        changed: None,
    },
    Shape {
        id: "buildkite-service-token",
        source: "betterleaks",
        rule: "buildkite-service-token",
        pattern: r#"\b(bkaa_[A-Za-z0-9_-]{75}|bkaj_[A-Za-z0-9_-]{333}|bkar_[A-Za-z0-9_-]{73}|bkct_[A-Za-z0-9_-]{73}|bkpt_[A-Za-z0-9_-]{199}|bkpat_[A-Za-z0-9_-]{54}|bkps_[A-Za-z0-9_-]{64})(?:$|[^A-Za-z0-9_-])"#,
        changed: None,
    },
    Shape {
        id: "buildkite-user-access-token",
        source: "betterleaks",
        rule: "buildkite-user-access-token",
        pattern: r#"\b(bkua_(?:[a-z0-9]{40}|[a-z0-9]{53}))\b"#,
        changed: None,
    },
    Shape {
        id: "cal-api-key",
        source: "betterleaks",
        rule: "cal-api-key",
        pattern: r#"\b(cal_live_[a-f0-9]{32})"#,
        changed: None,
    },
    Shape {
        id: "canadian-digital-service-notify-api-key",
        source: "betterleaks",
        rule: "canadian-digital-service-notify-api-key",
        pattern: r#"(?i:\b(ApiKey-v1\s+gcntfy-[a-z0-9_]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b)"#,
        changed: None,
    },
    Shape {
        id: "canva-client-secret",
        source: "betterleaks",
        rule: "canva-client-secret",
        pattern: r#"\b(cnvca[a-zA-Z0-9_-]{51})\b"#,
        changed: None,
    },
    Shape {
        id: "cartesia-api-key-1",
        source: "betterleaks",
        rule: "cartesia-api-key.1",
        pattern: r#"\b(sk_car_[A-Za-z0-9_]{20})"#,
        changed: None,
    },
    Shape {
        id: "cerebras-api-key",
        source: "betterleaks",
        rule: "cerebras-api-key",
        pattern: r#"(?i)\b(csk-[a-z0-9]{48})"#,
        changed: None,
    },
    Shape {
        id: "circleci-circle-ciproject",
        source: "osv-scalibr",
        rule: "veles/secrets/circleci circleCIProjectRe",
        pattern: r#"CCIPRJ_[A-Za-z0-9]{22}_[0-9a-f]{40}"#,
        changed: None,
    },
    Shape {
        id: "circleci-personal-token",
        source: "betterleaks",
        rule: "circleci-personal-token",
        pattern: r#"\b(CCIPAT_[a-zA-Z0-9]{22}_[a-z0-9]{40})"#,
        changed: None,
    },
    Shape {
        id: "clickhouse-cloud-api-secret-key",
        source: "gitleaks",
        rule: "clickhouse-cloud-api-secret-key",
        pattern: r#"\b(4b1d[A-Za-z0-9]{38})\b"#,
        changed: None,
    },
    Shape {
        id: "clojars-api-token",
        source: "gitleaks",
        rule: "clojars-api-token",
        pattern: r#"(?i)CLOJARS_[a-z0-9]{60}"#,
        changed: None,
    },
    Shape {
        id: "cloudflare-api-key-2",
        source: "betterleaks",
        rule: "cloudflare-api-key.2",
        pattern: r#"\b(cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8})"#,
        changed: None,
    },
    Shape {
        id: "cloudflare-origin-ca-key",
        source: "gitleaks",
        rule: "cloudflare-origin-ca-key",
        pattern: r#"\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})"#,
        changed: None,
    },
    Shape {
        id: "cloudsmith-api-key",
        source: "betterleaks",
        rule: "cloudsmith-api-key",
        pattern: r#"\b(csa_[a-f0-9]{30}[A-Za-z0-9]{6})"#,
        changed: None,
    },
    Shape {
        id: "cockroachlabs-cloud-api-key",
        source: "betterleaks",
        rule: "cockroachlabs-cloud-api-key",
        pattern: r#"\b(CCDB1_[A-Za-z0-9]{22}_[A-Za-z0-9]{40})\b"#,
        changed: None,
    },
    Shape {
        id: "codecatalyst-url",
        source: "osv-scalibr",
        rule: "veles/secrets/gitbasicauth/codecatalyst urlPattern",
        pattern: r#"\bhttps://[^:\s]+:[^\s@]+@git\.[^/]*codecatalyst\.aws/[^\s]*"#,
        changed: None,
    },
    Shape {
        id: "codecommit-url",
        source: "osv-scalibr",
        rule: "veles/secrets/gitbasicauth/codecommit urlPattern",
        pattern: r#"https://[^:\s]+:[^\s@]+@git-codecommit\.[a-zA-Z\-0-9]+\.amazonaws\.com/[^\s]+"#,
        changed: None,
    },
    Shape {
        id: "configcat-sdk-key-extended",
        source: "betterleaks",
        rule: "configcat-sdk-key-extended",
        pattern: r#"\b(configcat-sdk-1/[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{22})"#,
        changed: None,
    },
    Shape {
        id: "cratesioapitoken-key",
        source: "osv-scalibr",
        rule: "veles/secrets/cratesioapitoken keyRe",
        pattern: r#"\bcio[a-zA-Z-0-9]{32}\b"#,
        changed: None,
    },
    Shape {
        id: "cursorapikey-key",
        source: "osv-scalibr",
        rule: "veles/secrets/cursorapikey keyRe",
        pattern: r#"\bkey_[a-z0-9]{64}\b"#,
        changed: None,
    },
    Shape {
        id: "databricks-api-token",
        source: "gitleaks",
        rule: "databricks-api-token",
        pattern: r#"\b(dapi[a-f0-9]{32}(?:-\d)?)"#,
        changed: None,
    },
    Shape {
        id: "datastax-astra-application-token",
        source: "betterleaks",
        rule: "datastax-astra-application-token",
        pattern: r#"\b(AstraCS:[A-Za-z0-9]{20,})"#,
        changed: None,
    },
    Shape {
        id: "daytona-api-key",
        source: "betterleaks",
        rule: "daytona-api-key",
        pattern: r#"\b(dtn_[a-f0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "deno-account-token",
        source: "betterleaks",
        rule: "deno-account-token",
        pattern: r#"\b(ddp_[A-Za-z0-9]{36})"#,
        changed: None,
    },
    Shape {
        id: "denopat-org-pat",
        source: "osv-scalibr",
        rule: "veles/secrets/denopat orgPatRe",
        pattern: r#"ddo_[A-Za-z0-9]{36}"#,
        changed: None,
    },
    Shape {
        id: "devcycle-server-sdk-key",
        source: "betterleaks",
        rule: "devcycle-server-sdk-key",
        pattern: r#"\b(dvc_server_[A-Za-z0-9]{8,32})"#,
        changed: None,
    },
    Shape {
        id: "devin-personal-api-key",
        source: "betterleaks",
        rule: "devin-personal-api-key",
        pattern: r#"\b(apk_user_[A-Za-z0-9+/]{120,180}={0,2})"#,
        changed: None,
    },
    Shape {
        id: "devin-service-api-key",
        source: "betterleaks",
        rule: "devin-service-api-key",
        pattern: r#"\b(apk_[A-Za-z0-9+/]{80,100}={0,2})"#,
        changed: None,
    },
    Shape {
        id: "devin-service-user-token",
        source: "betterleaks",
        rule: "devin-service-user-token",
        pattern: r#"\b(cog_[a-z2-7]{52})"#,
        changed: None,
    },
    Shape {
        id: "digitalocean-access-token",
        source: "gitleaks",
        rule: "digitalocean-access-token",
        pattern: r#"\b(doo_v1_[a-f0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "digitalocean-pat",
        source: "gitleaks",
        rule: "digitalocean-pat",
        pattern: r#"\b(dop_v1_[a-f0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "digitalocean-refresh-token",
        source: "gitleaks",
        rule: "digitalocean-refresh-token",
        pattern: r#"(?i)\b(dor_v1_[a-f0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "docker-swarm-join-token",
        source: "betterleaks",
        rule: "docker-swarm-join-token",
        pattern: r#"\b(SWMTKN-1-[a-z0-9]{50,60}-[a-z0-9]{24,30})"#,
        changed: None,
    },
    Shape {
        id: "docker-swarm-unlock-key",
        source: "betterleaks",
        rule: "docker-swarm-unlock-key",
        pattern: r#"\b(SWMKEY-1-[A-Za-z0-9+/]{40,50})"#,
        changed: None,
    },
    Shape {
        id: "dockerhub-organization-access-token",
        source: "betterleaks",
        rule: "dockerhub-organization-access-token",
        pattern: r#"\b(dckr_oat_[A-Za-z0-9_-]{32})"#,
        changed: None,
    },
    Shape {
        id: "dockerhub-personal-access-token",
        source: "betterleaks",
        rule: "dockerhub-personal-access-token",
        pattern: r#"\b(dckr_pat_[A-Za-z0-9_-]{27})"#,
        changed: None,
    },
    Shape {
        id: "doppler-api-token",
        source: "gitleaks",
        rule: "doppler-api-token",
        pattern: r#"dp\.pt\.(?i)[a-z0-9]{43}"#,
        changed: None,
    },
    Shape {
        id: "duffel-api-token",
        source: "gitleaks",
        rule: "duffel-api-token",
        pattern: r#"duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}"#,
        changed: None,
    },
    Shape {
        id: "dynatrace-api-token",
        source: "gitleaks",
        rule: "dynatrace-api-token",
        pattern: r#"dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}"#,
        changed: None,
    },
    Shape {
        id: "easypost-api-token",
        source: "gitleaks",
        rule: "easypost-api-token",
        pattern: r#"\bEZAK(?i)[a-z0-9]{54}\b"#,
        changed: None,
    },
    Shape {
        id: "easypost-test-api-token",
        source: "gitleaks",
        rule: "easypost-test-api-token",
        pattern: r#"\bEZTK(?i)[a-z0-9]{54}\b"#,
        changed: None,
    },
    Shape {
        id: "elastic-cloud-api-key",
        source: "betterleaks",
        rule: "elastic-cloud-api-key",
        pattern: r#"\b(essu_[A-Za-z0-9_\-]{60,200}={0,2})"#,
        changed: None,
    },
    Shape {
        id: "exoscale-api-key",
        source: "betterleaks",
        rule: "exoscale-api-key",
        pattern: r#"\b(EXO[a-zA-Z0-9]{24,30})"#,
        changed: None,
    },
    Shape {
        id: "facebook-page-access-token",
        source: "gitleaks",
        rule: "facebook-page-access-token",
        pattern: r#"\b(EAA[MC](?i)[a-z0-9]{100,})"#,
        changed: None,
    },
    Shape {
        id: "figma-personal-access-token",
        source: "betterleaks",
        rule: "figma-personal-access-token",
        pattern: r#"(?i)\b(figd_[A-Z0-9_-]{38,42})"#,
        changed: None,
    },
    Shape {
        id: "flutterwave-encryption-key",
        source: "gitleaks",
        rule: "flutterwave-encryption-key",
        pattern: r#"FLWSECK_TEST-(?i)[a-h0-9]{12}"#,
        changed: None,
    },
    Shape {
        id: "flutterwave-public-key",
        source: "gitleaks",
        rule: "flutterwave-public-key",
        pattern: r#"FLWPUBK_TEST-(?i)[a-h0-9]{32}-X"#,
        changed: None,
    },
    Shape {
        id: "flutterwave-secret-key",
        source: "gitleaks",
        rule: "flutterwave-secret-key",
        pattern: r#"FLWSECK_TEST-(?i)[a-h0-9]{32}-X"#,
        changed: None,
    },
    Shape {
        id: "flyio-access-token",
        source: "gitleaks",
        rule: "flyio-access-token",
        pattern: r#"\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))"#,
        changed: None,
    },
    Shape {
        id: "flyio-access-token-betterleaks",
        source: "betterleaks",
        rule: "flyio-access-token",
        pattern: r#"\b(FlyV1\s[A-Za-z0-9=_\-,/+]{100,})"#,
        changed: None,
    },
    Shape {
        id: "frameio-api-token",
        source: "gitleaks",
        rule: "frameio-api-token",
        pattern: r#"fio-u-(?i)[a-z0-9\-_=]{64}"#,
        changed: None,
    },
    Shape {
        id: "gcp-api-key",
        source: "gitleaks",
        rule: "gcp-api-key",
        pattern: r#"\b(AIza[\w-]{35})"#,
        changed: None,
    },
    Shape {
        id: "gcp-gemini-api",
        source: "betterleaks",
        rule: "gcp-gemini-api",
        pattern: r#"\b(AQ\.Ab8RN6[A-Za-z0-9_-]{44})"#,
        changed: None,
    },
    Shape {
        id: "gcpexpressmode-key",
        source: "osv-scalibr",
        rule: "veles/secrets/gcpexpressmode keyRe",
        pattern: r#"AQ\.Ab8R[a-zA-Z0-9_-]{46}"#,
        changed: None,
    },
    Shape {
        id: "gcpoauth2client-client-secret",
        source: "osv-scalibr",
        rule: "veles/secrets/gcpoauth2client clientSecretRe",
        pattern: r#"\bGOCSPX-[a-zA-Z0-9_-]{28}"#,
        changed: None,
    },
    Shape {
        id: "gcpsak-re-base64",
        source: "osv-scalibr",
        rule: "veles/secrets/gcpsak reBase64",
        pattern: r#"ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIs[a-zA-Z0-9/+]{52,}"#,
        changed: None,
    },
    Shape {
        id: "gcshmackey-access-id",
        source: "osv-scalibr",
        rule: "veles/secrets/gcshmackey accessIDPattern",
        pattern: r#"GOOG(?:[A-Z0-9]{57}|[A-Z0-9]{20})"#,
        changed: None,
    },
    Shape {
        id: "github-app-token",
        source: "gitleaks",
        rule: "github-app-token",
        pattern: r#"(?:ghu|ghs)_[0-9a-zA-Z]{36}"#,
        changed: None,
    },
    Shape {
        id: "github-fine-grained-pat",
        source: "gitleaks",
        rule: "github-fine-grained-pat",
        pattern: r#"github_pat_\w{82}"#,
        changed: None,
    },
    Shape {
        id: "github-oauth",
        source: "gitleaks",
        rule: "github-oauth",
        pattern: r#"gho_[0-9a-zA-Z]{36}"#,
        changed: None,
    },
    Shape {
        id: "github-pat",
        source: "gitleaks",
        rule: "github-pat",
        pattern: r#"ghp_[0-9a-zA-Z]{36}"#,
        changed: None,
    },
    Shape {
        id: "github-refresh-token",
        source: "gitleaks",
        rule: "github-refresh-token",
        pattern: r#"ghr_[0-9a-zA-Z]{36}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-cicd-job-token",
        source: "gitleaks",
        rule: "gitlab-cicd-job-token",
        pattern: r#"glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-deploy-token",
        source: "gitleaks",
        rule: "gitlab-deploy-token",
        pattern: r#"gldt-[0-9a-zA-Z_\-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-feature-flag-client-token",
        source: "gitleaks",
        rule: "gitlab-feature-flag-client-token",
        pattern: r#"glffct-[0-9a-zA-Z_\-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-feed-token",
        source: "gitleaks",
        rule: "gitlab-feed-token",
        pattern: r#"glft-[0-9a-zA-Z_\-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-incoming-mail-token",
        source: "gitleaks",
        rule: "gitlab-incoming-mail-token",
        pattern: r#"glimt-[0-9a-zA-Z_\-]{25}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-kubernetes-agent-token",
        source: "gitleaks",
        rule: "gitlab-kubernetes-agent-token",
        pattern: r#"glagent-[0-9a-zA-Z_\-]{50}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-oauth-app-secret",
        source: "gitleaks",
        rule: "gitlab-oauth-app-secret",
        pattern: r#"gloas-[0-9a-zA-Z_\-]{64}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-pat",
        source: "gitleaks",
        rule: "gitlab-pat",
        pattern: r#"glpat-[\w-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-pat-routable",
        source: "gitleaks",
        rule: "gitlab-pat-routable",
        pattern: r#"\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b"#,
        changed: None,
    },
    Shape {
        id: "gitlab-ptt",
        source: "gitleaks",
        rule: "gitlab-ptt",
        pattern: r#"glptt-[0-9a-f]{40}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-rrt",
        source: "gitleaks",
        rule: "gitlab-rrt",
        pattern: r#"GR1348941[\w-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-runner-authentication-token",
        source: "gitleaks",
        rule: "gitlab-runner-authentication-token",
        pattern: r#"glrt-[0-9a-zA-Z_\-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-runner-authentication-token-routable",
        source: "gitleaks",
        rule: "gitlab-runner-authentication-token-routable",
        pattern: r#"\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b"#,
        changed: None,
    },
    Shape {
        id: "gitlab-scim-token",
        source: "gitleaks",
        rule: "gitlab-scim-token",
        pattern: r#"glsoat-[0-9a-zA-Z_\-]{20}"#,
        changed: None,
    },
    Shape {
        id: "gitlab-session-cookie",
        source: "gitleaks",
        rule: "gitlab-session-cookie",
        pattern: r#"_gitlab_session=[0-9a-z]{32}"#,
        changed: None,
    },
    Shape {
        id: "grafana-api-key",
        source: "gitleaks",
        rule: "grafana-api-key",
        pattern: r#"(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})"#,
        changed: None,
    },
    Shape {
        id: "grafana-api-key-betterleaks",
        source: "betterleaks",
        rule: "grafana-api-key",
        pattern: r#"\b(eyJrIjoi[A-Za-z0-9+/]{40,380}={0,2})"#,
        changed: None,
    },
    Shape {
        id: "grafana-cloud-api-token",
        source: "gitleaks",
        rule: "grafana-cloud-api-token",
        pattern: r#"(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})"#,
        changed: None,
    },
    Shape {
        id: "grafana-service-account-token",
        source: "gitleaks",
        rule: "grafana-service-account-token",
        pattern: r#"(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})"#,
        changed: None,
    },
    Shape {
        id: "groq-api-key",
        source: "betterleaks",
        rule: "groq-api-key",
        pattern: r#"(?i)\b(gsk_[A-Z0-9]{52})"#,
        changed: None,
    },
    Shape {
        id: "harness-api-key",
        source: "gitleaks",
        rule: "harness-api-key",
        pattern: r#"(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}"#,
        changed: None,
    },
    Shape {
        id: "heroku-api-key-v2",
        source: "gitleaks",
        rule: "heroku-api-key-v2",
        pattern: r#"\b((HRKU-AA[0-9a-zA-Z_-]{58}))"#,
        changed: None,
    },
    Shape {
        id: "herokuplatformkey-key",
        source: "osv-scalibr",
        rule: "veles/secrets/herokuplatformkey keyRe",
        pattern: r#"\b(HRKU-[0-9a-zA-Z_-]{60})\b"#,
        changed: None,
    },
    Shape {
        id: "huggingface-access-token",
        source: "gitleaks",
        rule: "huggingface-access-token",
        pattern: r#"\b(hf_(?i:[a-z]{34}))"#,
        changed: None,
    },
    Shape {
        id: "huggingface-organization-api-token",
        source: "gitleaks",
        rule: "huggingface-organization-api-token",
        pattern: r#"\b(api_org_(?i:[a-z]{34}))"#,
        changed: None,
    },
    Shape {
        id: "infracost-api-token",
        source: "gitleaks",
        rule: "infracost-api-token",
        pattern: r#"\b(ico-[a-zA-Z0-9]{32})"#,
        changed: None,
    },
    Shape {
        id: "intra42-client-secret",
        source: "gitleaks",
        rule: "intra42-client-secret",
        pattern: r#"\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})"#,
        changed: None,
    },
    Shape {
        id: "ionic-personal-access-token",
        source: "betterleaks",
        rule: "ionic-personal-access-token",
        pattern: r#"\b(ion_[A-Za-z0-9]{42})"#,
        changed: None,
    },
    Shape {
        id: "jina-ai-api-key",
        source: "betterleaks",
        rule: "jina-ai-api-key",
        pattern: r#"\b(jina_[A-Za-z0-9_\-]{60})"#,
        changed: None,
    },
    Shape {
        id: "labelbox-api-key",
        source: "betterleaks",
        rule: "labelbox-api-key",
        pattern: r#"\b(lbx_[\w-]{42}[AEIMQUYcgkosw048])"#,
        changed: None,
    },
    Shape {
        id: "labelbox-recursion-api-key",
        source: "betterleaks",
        rule: "labelbox-recursion-api-key",
        pattern: r#"\b(rma_[\w-]{42}[AEIMQUYcgkosw048])"#,
        changed: None,
    },
    Shape {
        id: "langchain-langsmith-personal-access-token",
        source: "betterleaks",
        rule: "langchain-langsmith-personal-access-token",
        pattern: r#"\b(lsv2_pt_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})"#,
        changed: None,
    },
    Shape {
        id: "langchain-langsmith-service-key",
        source: "betterleaks",
        rule: "langchain-langsmith-service-key",
        pattern: r#"\b(lsv2_sk_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})"#,
        changed: None,
    },
    Shape {
        id: "langfuse-public-key-1",
        source: "betterleaks",
        rule: "langfuse-public-key.1",
        pattern: r#"\b(pk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"#,
        changed: None,
    },
    Shape {
        id: "langfuse-secret-key-1",
        source: "betterleaks",
        rule: "langfuse-secret-key.1",
        pattern: r#"\b(sk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"#,
        changed: None,
    },
    Shape {
        id: "lark-app-id",
        source: "betterleaks",
        rule: "lark-app-id",
        pattern: r#"\b(cli_[A-Za-z0-9]{16})"#,
        changed: None,
    },
    Shape {
        id: "lichess-personal-access-token",
        source: "betterleaks",
        rule: "lichess-personal-access-token",
        pattern: r#"\b(lip_[A-Za-z0-9_]{16,60})"#,
        changed: None,
    },
    Shape {
        id: "linear-api-key",
        source: "gitleaks",
        rule: "linear-api-key",
        pattern: r#"lin_api_(?i)[a-z0-9]{40}"#,
        changed: None,
    },
    Shape {
        id: "llama-cloud-api-key-1",
        source: "betterleaks",
        rule: "llama-cloud-api-key.1",
        pattern: r#"\b(llx-[A-Za-z0-9]{44,52})"#,
        changed: None,
    },
    Shape {
        id: "mailersend-api-token",
        source: "betterleaks",
        rule: "mailersend-api-token",
        pattern: r#"\b(mlsn\.[A-Za-z0-9]{30,100})"#,
        changed: None,
    },
    Shape {
        id: "mapbox-api-token",
        source: "betterleaks",
        rule: "mapbox-api-token",
        pattern: r#"\b(pk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$|[^A-Za-z0-9_-])"#,
        changed: None,
    },
    Shape {
        id: "mapbox-secret-token",
        source: "betterleaks",
        rule: "mapbox-secret-token",
        pattern: r#"\b(sk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$|[^A-Za-z0-9_-])"#,
        changed: None,
    },
    Shape {
        id: "mercury-production-api-token",
        source: "betterleaks",
        rule: "mercury-production-api-token",
        pattern: r#"\b(mercury_production_[a-z]{3,6}_[A-Za-z0-9]{40,50}_yrucrem)"#,
        changed: None,
    },
    Shape {
        id: "mergify-application-key",
        source: "betterleaks",
        rule: "mergify-application-key",
        pattern: r#"\b(mergify_application_key_[A-Za-z0-9_-]{40,200})"#,
        changed: None,
    },
    Shape {
        id: "minimax-api-key",
        source: "betterleaks",
        rule: "minimax-api-key",
        pattern: r#"(?i)\b(sk-api-[A-Za-z0-9_-]{119})"#,
        changed: None,
    },
    Shape {
        id: "miro-access-token",
        source: "betterleaks",
        rule: "miro-access-token",
        pattern: r#"\b(eyJtaXJv[A-Za-z0-9-]{10,64}_[A-Za-z0-9_-]{20,64})"#,
        changed: None,
    },
    Shape {
        id: "mongodb-atlas-service-account-id",
        source: "betterleaks",
        rule: "mongodb-atlas-service-account-id",
        pattern: r#"\b(mdb_sa_id_[a-f0-9]{24})"#,
        changed: None,
    },
    Shape {
        id: "mongodb-atlas-service-account-secret",
        source: "betterleaks",
        rule: "mongodb-atlas-service-account-secret",
        pattern: r#"\b(mdb_sa_sk_[A-Za-z0-9_-]{40})"#,
        changed: None,
    },
    Shape {
        id: "mongodb-connection-string",
        source: "betterleaks",
        rule: "mongodb-connection-string",
        pattern: r#"\b(mongodb(?:\+srv)?://(?P<username>[!-9;-~]{3,50}):(?P<password>[!-?A-~]{3,88})@(?P<host>(?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:,(?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?)*)/?(?:(?P<authdb>[\w-]+)?(?P<options>\?\w+=[\w@/.$-]+(?:&(?:amp;)?\w+=[\w@/.$-]+)*)?)?)"#,
        changed: None,
    },
    Shape {
        id: "neon-api-key",
        source: "betterleaks",
        rule: "neon-api-key",
        pattern: r#"\b(napi_[A-Za-z0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "notion-api-token",
        source: "gitleaks",
        rule: "notion-api-token",
        pattern: r#"\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})"#,
        changed: None,
    },
    Shape {
        id: "npm-access-token",
        source: "gitleaks",
        rule: "npm-access-token",
        pattern: r#"(?i)\b(npm_[a-z0-9]{36})"#,
        changed: None,
    },
    Shape {
        id: "nuget-api-key",
        source: "betterleaks",
        rule: "nuget-api-key",
        pattern: r#"(?i)\b(oy2[a-p][a-z2-7]{15}[aq][a-z2-7]{25}[aeimquy4])"#,
        changed: None,
    },
    Shape {
        id: "nvidia-api-key",
        source: "betterleaks",
        rule: "nvidia-api-key",
        pattern: r#"(?i)\b(nvapi-[A-Z0-9_-]{60,70})"#,
        changed: None,
    },
    Shape {
        id: "nylas-api-key-1",
        source: "betterleaks",
        rule: "nylas-api-key.1",
        pattern: r#"\b(nyk_[A-Za-z0-9]{67})"#,
        changed: None,
    },
    Shape {
        id: "octopus-deploy-api-key",
        source: "gitleaks",
        rule: "octopus-deploy-api-key",
        pattern: r#"\b(API-[A-Z0-9]{26})"#,
        changed: None,
    },
    Shape {
        id: "onepasswordkeys-recovery-token",
        source: "osv-scalibr",
        rule: "veles/secrets/onepasswordkeys recoveryTokenRe",
        pattern: r#"1PRK(?:-[A-Z0-9]{4}){13}"#,
        changed: None,
    },
    Shape {
        id: "onesignal-rich-authentication-token",
        source: "betterleaks",
        rule: "onesignal-rich-authentication-token",
        pattern: r#"\b(os_v2_(?:app|org)_[a-z2-7]{103})"#,
        changed: None,
    },
    Shape {
        id: "onfido-live-api-token-ca",
        source: "betterleaks",
        rule: "onfido-live-api-token-ca",
        pattern: r#"\b(api_live_ca\.[A-Za-z0-9_-]{20,80})"#,
        changed: None,
    },
    Shape {
        id: "onfido-live-api-token-eu",
        source: "betterleaks",
        rule: "onfido-live-api-token-eu",
        pattern: r#"\b(api_live\.[A-Za-z0-9_-]{20,80})"#,
        changed: None,
    },
    Shape {
        id: "onfido-live-api-token-us",
        source: "betterleaks",
        rule: "onfido-live-api-token-us",
        pattern: r#"\b(api_live_us\.[A-Za-z0-9_-]{20,80})"#,
        changed: None,
    },
    Shape {
        id: "openai-api-key",
        source: "gitleaks",
        rule: "openai-api-key",
        pattern: r#"\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})"#,
        changed: None,
    },
    Shape {
        id: "openrouter-api-key",
        source: "betterleaks",
        rule: "openrouter-api-key",
        pattern: r#"(?i)\b(sk-or-v1-[0-9a-f]{64})"#,
        changed: None,
    },
    Shape {
        id: "openrouter-key",
        source: "osv-scalibr",
        rule: "veles/secrets/openrouter keyRe",
        pattern: r#"sk-or-v[0-9]+-[A-Za-z0-9_-]{20,}"#,
        changed: None,
    },
    Shape {
        id: "openshift-user-token",
        source: "gitleaks",
        rule: "openshift-user-token",
        pattern: r#"\b(sha256~[\w-]{43})(?:[^\w-]|\z)"#,
        changed: None,
    },
    Shape {
        id: "packagist-api-key",
        source: "osv-scalibr",
        rule: "veles/secrets/packagist apiKeyRe",
        pattern: r#"packagist_ack_[0-9a-f]{28,32}"#,
        changed: None,
    },
    Shape {
        id: "packagist-api-secret",
        source: "osv-scalibr",
        rule: "veles/secrets/packagist apiSecretRe",
        pattern: r#"packagist_acs_[0-9a-f]{64,96}"#,
        changed: None,
    },
    Shape {
        id: "packagist-conductor-update-token",
        source: "osv-scalibr",
        rule: "veles/secrets/packagist conductorUpdateTokenRe",
        pattern: r#"packagist_cut_[0-9a-f]{68}"#,
        changed: None,
    },
    Shape {
        id: "packagist-org-read-token",
        source: "osv-scalibr",
        rule: "veles/secrets/packagist orgReadTokenRe",
        pattern: r#"packagist_ort_[0-9a-f]{68}"#,
        changed: None,
    },
    Shape {
        id: "packagist-org-update-token",
        source: "osv-scalibr",
        rule: "veles/secrets/packagist orgUpdateTokenRe",
        pattern: r#"packagist_out_[0-9a-f]{68}"#,
        changed: None,
    },
    Shape {
        id: "packagist-repo-url",
        source: "osv-scalibr",
        rule: "veles/secrets/packagist repoURLRe",
        pattern: r#"https?://repo\.packagist\.com[/\w\-\.]*"#,
        changed: None,
    },
    Shape {
        id: "packagist-user-update-token",
        source: "osv-scalibr",
        rule: "veles/secrets/packagist userUpdateTokenRe",
        pattern: r#"packagist_uut_[0-9a-f]{68}"#,
        changed: None,
    },
    Shape {
        id: "paddle-live-api-key",
        source: "betterleaks",
        rule: "paddle-live-api-key",
        pattern: r#"\b(pdl_live_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3})"#,
        changed: None,
    },
    Shape {
        id: "password-in-url",
        source: "whimbrel",
        rule: "the bluebubbles channel sends its password, letters and digits of any length, in the URL's query, and a URL can end up in a log",
        pattern: r#"[?&]password=[0-9A-Za-z]+"#,
        changed: None,
    },
    Shape {
        id: "paystacksecretkey-sk",
        source: "osv-scalibr",
        rule: "veles/secrets/paystacksecretkey skRe",
        pattern: r#"\bsk_[a-z]{1,15}_[a-z0-9]{40}\b"#,
        changed: None,
    },
    Shape {
        id: "perplexity-api-key",
        source: "gitleaks",
        rule: "perplexity-api-key",
        pattern: r#"\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)"#,
        changed: None,
    },
    Shape {
        id: "persona-production-api-key",
        source: "betterleaks",
        rule: "persona-production-api-key",
        pattern: r#"\b(persona_production_[a-z0-9_-]{20,80})"#,
        changed: None,
    },
    Shape {
        id: "pinecone-api-key-2",
        source: "betterleaks",
        rule: "pinecone-api-key.2",
        pattern: r#"\b(pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63})"#,
        changed: None,
    },
    Shape {
        id: "pinterest-access-token",
        source: "betterleaks",
        rule: "pinterest-access-token",
        pattern: r#"\b(pina_[A-Za-z0-9_-]{20,200})"#,
        changed: None,
    },
    Shape {
        id: "planetscale-api-token",
        source: "gitleaks",
        rule: "planetscale-api-token",
        pattern: r#"\b(pscale_tkn_(?i)[\w=\.-]{32,64})"#,
        changed: None,
    },
    Shape {
        id: "planetscale-oauth-token",
        source: "gitleaks",
        rule: "planetscale-oauth-token",
        pattern: r#"\b(pscale_oauth_[\w=\.-]{32,64})"#,
        changed: None,
    },
    Shape {
        id: "planetscale-password",
        source: "gitleaks",
        rule: "planetscale-password",
        pattern: r#"(?i)\b(pscale_pw_(?i)[\w=\.-]{32,64})"#,
        changed: None,
    },
    Shape {
        id: "polar-oauth-access-token",
        source: "betterleaks",
        rule: "polar-oauth-access-token",
        pattern: r#"\b(polar_at_[A-Za-z0-9_-]{20,100})"#,
        changed: None,
    },
    Shape {
        id: "polar-organization-access-token",
        source: "betterleaks",
        rule: "polar-organization-access-token",
        pattern: r#"\b(polar_oat_[A-Za-z0-9_-]{20,100})"#,
        changed: None,
    },
    Shape {
        id: "polar-personal-access-token",
        source: "betterleaks",
        rule: "polar-personal-access-token",
        pattern: r#"\b(polar_pat_[A-Za-z0-9_-]{20,100})"#,
        changed: None,
    },
    Shape {
        id: "posthog-personal-api-key",
        source: "betterleaks",
        rule: "posthog-personal-api-key",
        pattern: r#"(?i)\b(phx_[a-zA-Z0-9_\-]{41,49})"#,
        changed: None,
    },
    Shape {
        id: "postman-api-token",
        source: "gitleaks",
        rule: "postman-api-token",
        pattern: r#"\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})"#,
        changed: None,
    },
    Shape {
        id: "postmanapikey-pmat",
        source: "osv-scalibr",
        rule: "veles/secrets/postmanapikey pmatRe",
        pattern: r#"PMAT-[A-Za-z0-9]{26}"#,
        changed: None,
    },
    Shape {
        id: "prefect-api-token",
        source: "gitleaks",
        rule: "prefect-api-token",
        pattern: r#"\b(pnu_[a-zA-Z0-9]{36})"#,
        changed: None,
    },
    Shape {
        id: "private-key",
        source: "gitleaks",
        rule: "private-key",
        pattern: r#"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"#,
        changed: Some("the header line alone, since a log is read a line at a time"),
    },
    Shape {
        id: "privatekey-block",
        source: "osv-scalibr",
        rule: "veles/secrets/privatekey blockRe",
        pattern: r#"(?s)-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----"#,
        changed: None,
    },
    Shape {
        id: "proof-full-access-api-key",
        source: "betterleaks",
        rule: "proof-full-access-api-key",
        pattern: r#"\b(prf_(?:cli_)?[A-Za-z0-9_-]{20,80})"#,
        changed: None,
    },
    Shape {
        id: "pulumi-api-token",
        source: "gitleaks",
        rule: "pulumi-api-token",
        pattern: r#"\b(pul-[a-f0-9]{40})"#,
        changed: None,
    },
    Shape {
        id: "pypi-upload-token",
        source: "gitleaks",
        rule: "pypi-upload-token",
        pattern: r#"pypi-AgEIcHlwaS5vcmc[[A-Za-z0-9_]-]{50,1000}"#,
        changed: Some("an ASCII class for \\w, since the Unicode one is too big for Rust's regex"),
    },
    Shape {
        id: "pypiapitoken-key",
        source: "osv-scalibr",
        rule: "veles/secrets/pypiapitoken keyRe",
        pattern: r#"pypi-[A-Za-z0-9-_]{85,}"#,
        changed: None,
    },
    Shape {
        id: "pyxkeyv1-key",
        source: "osv-scalibr",
        rule: "veles/secrets/pyxkeyv1 keyRe",
        pattern: r#"sk-pyx-[a-zA-Z0-9]{64}"#,
        changed: None,
    },
    Shape {
        id: "pyxkeyv2-key",
        source: "osv-scalibr",
        rule: "veles/secrets/pyxkeyv2 keyRe",
        pattern: r#"sk-pyx-2[a-zA-Z]{45}"#,
        changed: None,
    },
    Shape {
        id: "ramp-client-id",
        source: "betterleaks",
        rule: "ramp-client-id",
        pattern: r#"\b(ramp_id_[A-Za-z0-9]{40})"#,
        changed: None,
    },
    Shape {
        id: "ramp-client-secret",
        source: "betterleaks",
        rule: "ramp-client-secret",
        pattern: r#"\b(ramp_sec_[A-Za-z0-9]{48})"#,
        changed: None,
    },
    Shape {
        id: "razorpay-key-id-1",
        source: "betterleaks",
        rule: "razorpay-key-id.1",
        pattern: r#"\b(rzp_(?:live|test)_[A-Za-z0-9]{14})"#,
        changed: None,
    },
    Shape {
        id: "readme-api-token",
        source: "gitleaks",
        rule: "readme-api-token",
        pattern: r#"\b(rdme_[a-z0-9]{70})"#,
        changed: None,
    },
    Shape {
        id: "redirect-pizza-api-token-1",
        source: "betterleaks",
        rule: "redirect-pizza-api-token.1",
        pattern: r#"\b(rpa_[A-Za-z0-9]{30})"#,
        changed: None,
    },
    Shape {
        id: "render-api-key",
        source: "betterleaks",
        rule: "render-api-key",
        pattern: r#"\b(rnd_[A-Za-z0-9]{28})"#,
        changed: None,
    },
    Shape {
        id: "replicate-api-token",
        source: "betterleaks",
        rule: "replicate-api-token",
        pattern: r#"(?i)\b(r8_[A-Za-z0-9]{37})"#,
        changed: None,
    },
    Shape {
        id: "resend-api-key-1",
        source: "betterleaks",
        rule: "resend-api-key.1",
        pattern: r#"\b(re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24})"#,
        changed: None,
    },
    Shape {
        id: "rootly-api-key-1",
        source: "betterleaks",
        rule: "rootly-api-key.1",
        pattern: r#"\b(rootly_[a-f0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "rubygems-api-token",
        source: "gitleaks",
        rule: "rubygems-api-token",
        pattern: r#"\b(rubygems_[a-f0-9]{48})"#,
        changed: None,
    },
    Shape {
        id: "runpod-api-key-1",
        source: "betterleaks",
        rule: "runpod-api-key.1",
        pattern: r#"\b(rpa_[A-Z0-9]{40}[A-Za-z0-9]{6})"#,
        changed: None,
    },
    Shape {
        id: "salesforceoauth2access-token",
        source: "osv-scalibr",
        rule: "veles/secrets/salesforceoauth2access tokenRe",
        pattern: r#"\b00D[0-9A-Za-z]{8,15}![A-Za-z0-9._\-]{30,100}\b"#,
        changed: None,
    },
    Shape {
        id: "salesforceoauth2client-client-id",
        source: "osv-scalibr",
        rule: "veles/secrets/salesforceoauth2client clientIDRe",
        pattern: r#"\b3MVG[a-zA-Z0-9._\-]{20,180}\b"#,
        changed: None,
    },
    Shape {
        id: "salesforceoauth2jwt-client-id",
        source: "osv-scalibr",
        rule: "veles/secrets/salesforceoauth2jwt clientIDRe",
        pattern: r#"\b3MVG[a-zA-Z0-9._\-]{20,180}\b"#,
        changed: None,
    },
    Shape {
        id: "salesforceoauth2jwt-private-key",
        source: "osv-scalibr",
        rule: "veles/secrets/salesforceoauth2jwt privateKeyRe",
        pattern: r#"(?s)-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----"#,
        changed: None,
    },
    Shape {
        id: "salesforceoauth2refresh-client-id",
        source: "osv-scalibr",
        rule: "veles/secrets/salesforceoauth2refresh clientIDRe",
        pattern: r#"\b3MVG[a-zA-Z0-9._\-]{20,180}\b"#,
        changed: None,
    },
    Shape {
        id: "samsara-api-token-1",
        source: "betterleaks",
        rule: "samsara-api-token.1",
        pattern: r#"\b(samsara_api_[A-Za-z0-9]{26,32})"#,
        changed: None,
    },
    Shape {
        id: "scalingo-api-token",
        source: "gitleaks",
        rule: "scalingo-api-token",
        pattern: r#"\b(tk-us-[\w-]{48})"#,
        changed: None,
    },
    Shape {
        id: "segment-public-api-token-1",
        source: "betterleaks",
        rule: "segment-public-api-token.1",
        pattern: r#"\b(sgp_[A-Za-z0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "sendgrid-api-token",
        source: "gitleaks",
        rule: "sendgrid-api-token",
        pattern: r#"\b(SG\.(?i)[a-z0-9=_\-\.]{66})"#,
        changed: None,
    },
    Shape {
        id: "sendinblue-api-token",
        source: "gitleaks",
        rule: "sendinblue-api-token",
        pattern: r#"\b(xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16})"#,
        changed: None,
    },
    Shape {
        id: "sentry-org-token",
        source: "gitleaks",
        rule: "sentry-org-token",
        pattern: r#"\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\z)"#,
        changed: None,
    },
    Shape {
        id: "sentry-user-token",
        source: "gitleaks",
        rule: "sentry-user-token",
        pattern: r#"\b(sntryu_[a-f0-9]{64})"#,
        changed: None,
    },
    Shape {
        id: "settlemint-application-access-token",
        source: "gitleaks",
        rule: "settlemint-application-access-token",
        pattern: r#"\b(sm_aat_[a-zA-Z0-9]{16})"#,
        changed: None,
    },
    Shape {
        id: "settlemint-personal-access-token",
        source: "gitleaks",
        rule: "settlemint-personal-access-token",
        pattern: r#"\b(sm_pat_[a-zA-Z0-9]{16})"#,
        changed: None,
    },
    Shape {
        id: "settlemint-service-access-token",
        source: "gitleaks",
        rule: "settlemint-service-access-token",
        pattern: r#"\b(sm_sat_[a-zA-Z0-9]{16})"#,
        changed: None,
    },
    Shape {
        id: "shippo-api-token",
        source: "gitleaks",
        rule: "shippo-api-token",
        pattern: r#"\b(shippo_(?:live|test)_[a-fA-F0-9]{40})"#,
        changed: None,
    },
    Shape {
        id: "shopify-access-token",
        source: "gitleaks",
        rule: "shopify-access-token",
        pattern: r#"shpat_[a-fA-F0-9]{32}"#,
        changed: None,
    },
    Shape {
        id: "shopify-custom-access-token",
        source: "gitleaks",
        rule: "shopify-custom-access-token",
        pattern: r#"shpca_[a-fA-F0-9]{32}"#,
        changed: None,
    },
    Shape {
        id: "shopify-private-app-access-token",
        source: "gitleaks",
        rule: "shopify-private-app-access-token",
        pattern: r#"shppa_[a-fA-F0-9]{32}"#,
        changed: None,
    },
    Shape {
        id: "shopify-shared-secret",
        source: "gitleaks",
        rule: "shopify-shared-secret",
        pattern: r#"shpss_[a-fA-F0-9]{32}"#,
        changed: None,
    },
    Shape {
        id: "slack-bot-token",
        source: "gitleaks",
        rule: "slack-bot-token",
        pattern: r#"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"#,
        changed: None,
    },
    Shape {
        id: "slack-config-access-token",
        source: "gitleaks",
        rule: "slack-config-access-token",
        pattern: r#"(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}"#,
        changed: None,
    },
    Shape {
        id: "slack-config-refresh-token",
        source: "gitleaks",
        rule: "slack-config-refresh-token",
        pattern: r#"(?i)xoxe-\d-[A-Z0-9]{146}"#,
        changed: None,
    },
    Shape {
        id: "slack-legacy-bot-token",
        source: "gitleaks",
        rule: "slack-legacy-bot-token",
        pattern: r#"xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}"#,
        changed: None,
    },
    Shape {
        id: "slack-session-cookie",
        source: "betterleaks",
        rule: "slack-session-cookie",
        pattern: r#"(xoxd-[\w\/\\+-]{100,}={0,2})(?:[^\w\/+=-]|\z)"#,
        changed: None,
    },
    Shape {
        id: "slack-session-token",
        source: "betterleaks",
        rule: "slack-session-token",
        pattern: r#"xoxc-\d{9,15}-\d{9,15}-\d{9,15}-[a-f0-9]{64}\b"#,
        changed: None,
    },
    Shape {
        id: "slack-user-token",
        source: "gitleaks",
        rule: "slack-user-token",
        pattern: r#"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}"#,
        changed: None,
    },
    Shape {
        id: "slack-webhook-url",
        source: "gitleaks",
        rule: "slack-webhook-url",
        pattern: r#"(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"#,
        changed: None,
    },
    Shape {
        id: "slacktoken-app-level-token",
        source: "osv-scalibr",
        rule: "veles/secrets/slacktoken appLevelTokenRe",
        pattern: r#"xapp-\d{1,10}-[A-Za-z0-9]{11}-[0-9]{13}-[a-fA-F0-9]{64}"#,
        changed: None,
    },
    Shape {
        id: "sourcegraph-access-token",
        source: "betterleaks",
        rule: "sourcegraph-access-token",
        pattern: r#"(?i)\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})"#,
        changed: None,
    },
    Shape {
        id: "square-access-token",
        source: "gitleaks",
        rule: "square-access-token",
        pattern: r#"\b((?:EAAA|sq0atp-)[\w-]{22,60})"#,
        changed: None,
    },
    Shape {
        id: "squareapikey-o-auth-application-id",
        source: "osv-scalibr",
        rule: "veles/secrets/squareapikey oAuthApplicationIDRe",
        pattern: r#"sq0idp-[A-Za-z0-9_-]{22}"#,
        changed: None,
    },
    Shape {
        id: "squareapikey-o-auth-application-secret",
        source: "osv-scalibr",
        rule: "veles/secrets/squareapikey oAuthApplicationSecretRe",
        pattern: r#"sq0csp-[A-Za-z0-9_-]{43}"#,
        changed: None,
    },
    Shape {
        id: "stripe-access-token",
        source: "gitleaks",
        rule: "stripe-access-token",
        pattern: r#"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})"#,
        changed: None,
    },
    Shape {
        id: "stripeapikeys-whsec",
        source: "osv-scalibr",
        rule: "veles/secrets/stripeapikeys whsecRe",
        pattern: r#"whsec_[A-Za-z0-9]{32}"#,
        changed: None,
    },
    Shape {
        id: "supabase-management-token",
        source: "betterleaks",
        rule: "supabase-management-token",
        pattern: r#"\b(sbp_[a-z0-9_-]{40})"#,
        changed: None,
    },
    Shape {
        id: "supabase-project-api-key",
        source: "betterleaks",
        rule: "supabase-project-api-key",
        pattern: r#"\b(sb_secret_[A-Za-z0-9_-]{31})"#,
        changed: None,
    },
    Shape {
        id: "supabase-project-url",
        source: "betterleaks",
        rule: "supabase-project-url",
        pattern: r#"\b(https://[a-z0-9]{16,32}\.supabase\.co)\b"#,
        changed: None,
    },
    Shape {
        id: "tailscale-api-key-1",
        source: "betterleaks",
        rule: "tailscale-api-key.1",
        pattern: r#"\b(tskey-api-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b"#,
        changed: None,
    },
    Shape {
        id: "tailscale-auth-key",
        source: "betterleaks",
        rule: "tailscale-auth-key",
        pattern: r#"\b(tskey-auth-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b"#,
        changed: None,
    },
    Shape {
        id: "tailscale-key",
        source: "betterleaks",
        rule: "tailscale-key",
        pattern: r#"\b(tskey-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{20,40})\b"#,
        changed: None,
    },
    Shape {
        id: "tailscale-oauth-client-secret",
        source: "betterleaks",
        rule: "tailscale-oauth-client-secret",
        pattern: r#"\b(tskey-client-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b"#,
        changed: None,
    },
    Shape {
        id: "tailscale-scim-key",
        source: "betterleaks",
        rule: "tailscale-scim-key",
        pattern: r#"\b(tskey-scim-[A-Za-z0-9]{8,24}-[A-Za-z0-9]{28,40})\b"#,
        changed: None,
    },
    Shape {
        id: "tailscale-webhook-secret",
        source: "betterleaks",
        rule: "tailscale-webhook-secret",
        pattern: r#"\b(tskey-webhook-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b"#,
        changed: None,
    },
    Shape {
        id: "temporal-cloud-api-key-1",
        source: "betterleaks",
        rule: "temporal-cloud-api-key.1",
        pattern: r#"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*Y2NvdW50X2lk[A-Za-z0-9_-]*InRlbXBvcmFsLmlv[A-Za-z0-9_-]*(?:ICJrZXlfaWQiOi|a2V5X2lk|rZXlfaWQi)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})"#,
        changed: None,
    },
    Shape {
        id: "thunderstore-api-token-1",
        source: "betterleaks",
        rule: "thunderstore-api-token.1",
        pattern: r#"\b(tss_[A-Za-z0-9_-]{20,80})"#,
        changed: None,
    },
    Shape {
        id: "togetherai-api-key",
        source: "betterleaks",
        rule: "togetherai-api-key",
        pattern: r#"(?i)\b(tgp_v1_[A-Za-z0-9_-]{43})"#,
        changed: None,
    },
    Shape {
        id: "unkey-root-key-1",
        source: "betterleaks",
        rule: "unkey-root-key.1",
        pattern: r#"\b(unkey_[A-Za-z0-9]{20,32})"#,
        changed: None,
    },
    Shape {
        id: "upcloud-api-token",
        source: "betterleaks",
        rule: "upcloud-api-token",
        pattern: r#"\b(ucat_[0-9A-Za-z]{24,32})"#,
        changed: None,
    },
    Shape {
        id: "upstash-redis-rest-url-1",
        source: "betterleaks",
        rule: "upstash-redis-rest-url.1",
        pattern: r#"(?i)\b(https://[a-z0-9][a-z0-9-]{2,63}\.upstash\.io)"#,
        changed: None,
    },
    Shape {
        id: "val-town-api-token-1",
        source: "betterleaks",
        rule: "val-town-api-token.1",
        pattern: r#"\b(vtwn_[A-Za-z0-9_-]{20,80})"#,
        changed: None,
    },
    Shape {
        id: "vault-batch-token",
        source: "gitleaks",
        rule: "vault-batch-token",
        pattern: r#"\b(hvb\.[[A-Za-z0-9_]-]{138,300})"#,
        changed: Some("an ASCII class for \\w, since the Unicode one is too big for Rust's regex"),
    },
    Shape {
        id: "vercel-ai-gateway-key",
        source: "betterleaks",
        rule: "vercel-ai-gateway-key",
        pattern: r#"(?i)\b(vck_[A-Za-z0-9_-]{56})"#,
        changed: None,
    },
    Shape {
        id: "vercel-app-access-token",
        source: "betterleaks",
        rule: "vercel-app-access-token",
        pattern: r#"(?i)\b(vca_[A-Za-z0-9_-]{56})"#,
        changed: None,
    },
    Shape {
        id: "vercel-app-refresh-token",
        source: "betterleaks",
        rule: "vercel-app-refresh-token",
        pattern: r#"(?i)\b(vcr_[A-Za-z0-9_-]{56})"#,
        changed: None,
    },
    Shape {
        id: "vercel-integration-token",
        source: "betterleaks",
        rule: "vercel-integration-token",
        pattern: r#"(?i)\b(vci_[A-Za-z0-9_-]{56})"#,
        changed: None,
    },
    Shape {
        id: "vercel-personal-access-token",
        source: "betterleaks",
        rule: "vercel-personal-access-token",
        pattern: r#"(?i)\b(vcp_[A-Za-z0-9_-]{56})"#,
        changed: None,
    },
    Shape {
        id: "wakatime-api-key-2",
        source: "betterleaks",
        rule: "wakatime-api-key.2",
        pattern: r#"(?i)\b(waka_[a-z0-9]{36,64})"#,
        changed: None,
    },
    Shape {
        id: "weights-and-biases-api-key-v1",
        source: "betterleaks",
        rule: "weights-and-biases-api-key-v1",
        pattern: r#"(?i)\b(wandb_v1_[A-Za-z0-9_]{77})"#,
        changed: None,
    },
    Shape {
        id: "workato-developer-api-token-1",
        source: "betterleaks",
        rule: "workato-developer-api-token.1",
        pattern: r#"\b(wrka(?:[a-z]{2})?-eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{64,})"#,
        changed: None,
    },
    Shape {
        id: "xai-api-key",
        source: "betterleaks",
        rule: "xai-api-key",
        pattern: r#"(?i)\b(xai-[A-Za-z0-9_-]{70,120})"#,
        changed: None,
    },
    Shape {
        id: "xendit-production-api-key-1",
        source: "betterleaks",
        rule: "xendit-production-api-key.1",
        pattern: r#"\b(xnd_production_[A-Za-z0-9]{56,72})"#,
        changed: None,
    },
    Shape {
        id: "zuplo-consumer-api-key-1",
        source: "betterleaks",
        rule: "zuplo-consumer-api-key.1",
        pattern: r#"\b(zpka_[a-z0-9]{32}_[0-9a-f]{8})"#,
        changed: None,
    },
];

/// What redaction puts in place of a match.
pub const REDACTED: &str = "[redacted]";

/// A host's secret patterns: the built-ins in one group, a config's own in another. Empty when
/// the built-ins are off and the config adds none.
#[derive(Clone, Debug, Default)]
pub struct SecretPatterns {
    builtins: Option<std::sync::Arc<Group>>,
    own: Option<std::sync::Arc<Group>>,
}

/// Patterns compiled together: as one set, so a line is matched against all of them in one pass,
/// and each on its own, so its flags and comments stay its own and its matches can be found.
#[derive(Debug)]
pub struct Group {
    set: regex::bytes::RegexSet,
    each: Vec<regex::bytes::Regex>,
    /// Whether Unicode classes were on when it was compiled.
    pub unicode: bool,
}

/// Room for every built-in and a config's own, well past `regex`'s default.
const SIZE_LIMIT: usize = 64 * 1024 * 1024;

impl Group {
    /// `patterns` compiled with Unicode classes on or off.
    fn compile(patterns: &[&str], unicode: bool) -> Result<Group, String> {
        let too_big = |_| "secret_patterns are too big to use together".to_string();
        let each = patterns
            .iter()
            .map(|p| {
                regex::bytes::RegexBuilder::new(p)
                    .unicode(unicode)
                    .size_limit(SIZE_LIMIT)
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(too_big)?;
        let set = regex::bytes::RegexSetBuilder::new(patterns)
            .unicode(unicode)
            .size_limit(SIZE_LIMIT)
            .build()
            .map_err(too_big)?;
        Ok(Group { set, each, unicode })
    }

    /// Each match in `bytes`, as byte offsets, of any pattern.
    fn spans(&self, bytes: &[u8], out: &mut Vec<(usize, usize)>) {
        for i in self.set.matches(bytes).iter() {
            out.extend(self.each[i].find_iter(bytes).map(|m| (m.start(), m.end())));
        }
    }

    /// Whether `bytes` hold a match.
    fn found_in(&self, bytes: &[u8]) -> bool {
        self.set.is_match(bytes)
    }
}

impl SecretPatterns {
    /// The built-ins, less `disable`, if `builtins`; then `patterns`. An unknown id in `disable`
    /// is refused, and so is a pattern that doesn't compile or that matches empty text, which
    /// would match every line. A pattern is never repeated: it may describe a secret's shape.
    ///
    /// The built-ins compile with Unicode classes off: every token is ASCII, and Unicode's tables
    /// make a few hundred patterns cost hundreds of megabytes. A config's own patterns compile with
    /// them on, as written.
    pub fn new(builtins: bool, disable: &[String], patterns: &[String]) -> Result<Self, String> {
        for id in disable {
            if !BUILTINS.iter().any(|s| s.id == id) {
                return Err(format!(
                    "secret_patterns.disable names {id:?}, which isn't a built-in"
                ));
            }
        }
        for (i, p) in patterns.iter().enumerate() {
            let n = i + 1;
            let re = Regex::new(p).map_err(|e| match e {
                regex::Error::CompiledTooBig(_) => {
                    format!("secret_patterns.patterns: pattern {n} is too big to use")
                }
                _ => format!("secret_patterns.patterns: pattern {n} isn't one whimbrel can use"),
            })?;
            let empty = regex_syntax::Parser::new()
                .parse(p)
                .map_or(true, |hir| hir.properties().minimum_len() == Some(0));
            if re.is_match("") || empty {
                return Err(format!(
                    "secret_patterns.patterns: pattern {n} can match empty text, so it would match \
                     every line"
                ));
            }
        }
        let builtins = match (builtins, disable.is_empty()) {
            (false, _) => None,
            (true, true) => Self::builtins().builtins,
            (true, false) => {
                let kept: Vec<&str> = BUILTINS
                    .iter()
                    .filter(|s| !disable.iter().any(|d| d == s.id))
                    .map(|s| s.pattern)
                    .collect();
                if kept.is_empty() {
                    None
                } else {
                    Some(std::sync::Arc::new(Group::compile(&kept, false)?))
                }
            }
        };
        let own = if patterns.is_empty() {
            None
        } else {
            let own: Vec<&str> = patterns.iter().map(String::as_str).collect();
            Some(std::sync::Arc::new(Group::compile(&own, true)?))
        };
        Ok(SecretPatterns { builtins, own })
    }

    /// The built-ins alone, compiled once a process.
    pub fn builtins() -> Self {
        static BUILT: std::sync::LazyLock<std::sync::Arc<Group>> = std::sync::LazyLock::new(|| {
            let all: Vec<&str> = BUILTINS.iter().map(|s| s.pattern).collect();
            std::sync::Arc::new(Group::compile(&all, false).expect("the built-ins compile"))
        });
        SecretPatterns {
            builtins: Some(std::sync::Arc::clone(&BUILT)),
            own: None,
        }
    }

    /// The built-ins' group, if they're on: for tests that check how it was compiled.
    pub fn builtin_group(&self) -> Option<&Group> {
        self.builtins.as_deref()
    }

    /// The config's own patterns' group, if it has any: for the same tests.
    pub fn own_group(&self) -> Option<&Group> {
        self.own.as_deref()
    }

    pub fn is_empty(&self) -> bool {
        self.builtins.is_none() && self.own.is_none()
    }

    fn groups(&self) -> impl Iterator<Item = &Group> {
        self.builtins.iter().chain(self.own.iter()).map(|g| &**g)
    }

    /// `text` with every match replaced by [`REDACTED`].
    pub fn redact(&self, text: &str) -> String {
        // Every pattern's matches on the text as it is, merged, then replaced once: replacing one
        // pattern's matches before looking for the next would let a shorter pattern cut into a
        // longer token and leave the rest of it showing. The patterns match bytes, so a span is
        // widened to the characters it touches before it's cut.
        let bytes = text.as_bytes();
        let mut spans = Vec::new();
        for g in self.groups() {
            g.spans(bytes, &mut spans);
        }
        if spans.is_empty() {
            return text.to_string();
        }
        for (start, end) in &mut spans {
            while !text.is_char_boundary(*start) {
                *start -= 1;
            }
            while !text.is_char_boundary(*end) {
                *end += 1;
            }
        }
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in spans {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for (start, end) in merged {
            out.push_str(&text[at..start]);
            out.push_str(REDACTED);
            at = end;
        }
        out.push_str(&text[at..]);
        out
    }

    /// Whether `bytes` hold a match.
    pub fn found_in(&self, bytes: &[u8]) -> bool {
        self.groups().any(|g| g.found_in(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real tokens' shapes, written from each service's own format rather than from a pattern,
    /// and made at run time from a prefix and a repeated character, so no token-shaped string is
    /// ever written in the repo.
    fn known_tokens() -> Vec<(&'static str, String)> {
        let r = |c: &str, n: usize| c.repeat(n);
        let d = |n: usize| "1".repeat(n);
        vec![
            ("slack-bot-token", format!("xoxb-{}-{}abc", d(12), d(12))),
            (
                "slack-legacy-bot-token",
                format!("xoxb-{}-{}", d(10), r("a", 20)),
            ),
            (
                "slack-user-token",
                format!("xoxp-{}-{}-{}-{}", d(10), d(10), d(10), r("a", 30)),
            ),
            (
                "slack-app-token",
                format!("xapp-{}-A{}-123-abc", d(1), d(1)),
            ),
            (
                "slack-config-access-token",
                format!("xoxe.xoxp-1-{}", r("A", 163)),
            ),
            (
                "slack-config-refresh-token",
                format!("xoxe-1-{}", r("A", 146)),
            ),
            ("slack-legacy-token", format!("xoxs-{}-2-3-abc", d(1))),
            (
                "slack-legacy-workspace-token",
                format!("xoxa-1-{}", r("a", 10)),
            ),
            (
                "slack-webhook-url",
                format!("https://hooks.slack.com/services/{}", r("A", 44)),
            ),
            ("github-pat", format!("ghp_{}", r("a", 36))),
            (
                "github-fine-grained-pat",
                format!("github_pat_{}", r("a", 82)),
            ),
            ("github-oauth", format!("gho_{}", r("a", 36))),
            ("github-app-token", format!("ghs_{}", r("a", 36))),
            ("github-refresh-token", format!("ghr_{}", r("a", 36))),
            ("gitlab-pat", format!("glpat-{}", r("a", 20))),
            (
                "gitlab-pat-routable",
                format!("glpat-{}.01abcdefg", r("a", 27)),
            ),
            ("aws-access-key-id", format!("AKIA{}", r("Q", 16))),
            ("google-api-key", format!("AIza{}", r("a", 35))),
            ("stripe-key", format!("sk_live_{}", r("a", 20))),
            (
                "openai-api-key",
                format!("sk-{}T3BlbkFJ{}", r("a", 20), r("a", 20)),
            ),
            (
                "anthropic-api-key",
                format!("sk-ant-api03-{}AA", r("a", 93)),
            ),
            (
                "anthropic-admin-key",
                format!("sk-ant-admin01-{}AA", r("a", 93)),
            ),
            ("age-secret-key", format!("AGE-SECRET-KEY-1{}", r("Q", 58))),
            (
                "private-key",
                format!("-----BEGIN RSA {} KEY-----", "PRIVATE"),
            ),
            ("npm-token", format!("npm_{}", r("a", 36))),
            ("pypi-token", format!("pypi-AgEIcHlwaS5vcmc{}", r("a", 50))),
            ("twilio-api-key", format!("SK{}", r("a", 32))),
            ("sendgrid-api-key", format!("SG.{}", r("a", 66))),
            ("huggingface-token", format!("hf_{}", r("a", 34))),
            ("huggingface-org-token", format!("api_org_{}", r("a", 34))),
            ("digitalocean-pat", format!("dop_v1_{}", r("a", 64))),
            (
                "digitalocean-access-token",
                format!("doo_v1_{}", r("a", 64)),
            ),
            (
                "digitalocean-refresh-token",
                format!("dor_v1_{}", r("a", 64)),
            ),
            ("shopify-access-token", format!("shpat_{}", r("a", 32))),
            (
                "shopify-custom-access-token",
                format!("shpca_{}", r("a", 32)),
            ),
            ("shopify-private-app-token", format!("shppa_{}", r("a", 32))),
            ("shopify-shared-secret", format!("shpss_{}", r("a", 32))),
            (
                "password-in-url",
                format!("http://h:1/api?password={}", r("a", 16)),
            ),
        ]
    }

    /// Shapes of the old hand-picked list that no rule of the three lists passes the test for:
    /// too short to tell from ordinary text, or with a fixed prefix under 3 characters.
    const NOT_CAUGHT: &[&str] = &[
        "slack-app-token",
        "slack-legacy-token",
        "slack-legacy-workspace-token",
        "twilio-api-key",
    ];

    #[test]
    fn real_tokens_shapes_are_caught_except_the_ones_the_rule_leaves_out() {
        let all = SecretPatterns::builtins();
        let mut wrong = Vec::new();
        for (name, token) in known_tokens() {
            let line = format!("a log line with {token} in it");
            let caught = all.found_in(line.as_bytes());
            if caught == NOT_CAUGHT.contains(&name) {
                wrong.push(name);
            }
            if caught {
                assert!(!all.redact(&line).contains(&token), "{name}");
            }
        }
        assert!(
            wrong.is_empty(),
            "caught when it shouldn't be, or the reverse: {wrong:?}"
        );
    }

    /// The shortest text `h` matches by its first alternative and smallest counts, with a letter
    /// or digit picked from a class when it has one, so a `\b` after it still holds.
    fn shortest(h: &regex_syntax::hir::Hir, out: &mut String) {
        use regex_syntax::hir::{Class, HirKind};
        match h.kind() {
            HirKind::Empty | HirKind::Look(_) => {}
            HirKind::Literal(l) => out.push_str(&String::from_utf8_lossy(&l.0)),
            HirKind::Class(Class::Unicode(c)) => {
                let has = |x: char| c.ranges().iter().any(|r| r.start() <= x && x <= r.end());
                let ch = ['a', 'A', '0']
                    .into_iter()
                    .find(|x| has(*x))
                    .unwrap_or_else(|| {
                        let r = c.ranges()[0];
                        if r.start() < ' ' && r.end() >= ' ' {
                            ' '
                        } else {
                            r.start()
                        }
                    });
                out.push(ch);
            }
            HirKind::Class(Class::Bytes(c)) => out.push(char::from(c.ranges()[0].start())),
            HirKind::Repetition(r) => (0..r.min).for_each(|_| shortest(&r.sub, out)),
            HirKind::Capture(c) => shortest(&c.sub, out),
            HirKind::Concat(v) => v.iter().for_each(|h| shortest(h, out)),
            HirKind::Alternation(v) => shortest(&v[0], out),
        }
    }

    #[test]
    fn every_builtin_finds_an_example_of_its_own_and_redaction_takes_it_out() {
        let all = SecretPatterns::builtins();
        for s in BUILTINS {
            let hir = regex_syntax::Parser::new().parse(s.pattern).unwrap();
            let mut token = String::new();
            shortest(&hir, &mut token);
            let line = format!("a log line with {token} in it");
            let alone = Regex::new(s.pattern).unwrap();
            assert!(
                alone.is_match(&line),
                "{} misses its example {token:?}",
                s.id
            );
            assert!(all.found_in(line.as_bytes()), "{}", s.id);
            let redacted = all.redact(&line);
            assert!(
                redacted.starts_with("a log line with "),
                "{}: {redacted}",
                s.id
            );
            assert!(redacted.contains(REDACTED), "{}: {redacted}", s.id);
            assert!(!redacted.contains(token.trim()), "{}: {redacted}", s.id);
        }
    }

    #[test]
    fn the_builtins_are_one_set_without_unicode_and_a_configs_own_keep_it() {
        let p = SecretPatterns::new(true, &[], &["myco_[0-9a-f]{8}".into()]).unwrap();
        let built = p.builtin_group().unwrap();
        assert!(!built.unicode);
        assert_eq!(built.each.len(), BUILTINS.len());
        assert_eq!(built.set.len(), BUILTINS.len());
        assert!(p.own_group().unwrap().unicode);
        // A config pattern with a Unicode class still matches what it says.
        let own = SecretPatterns::new(false, &[], &[r"caf\w_[0-9]{8}".into()]).unwrap();
        assert!(own.found_in("le café_12345678 ouvert".as_bytes()));
    }

    #[test]
    fn a_non_ascii_alert_is_redacted_on_character_boundaries() {
        let p = SecretPatterns::builtins();
        // This shape's pattern ends by taking one more character, which here is the first byte
        // of a two-byte "é": the cut widens to the whole character.
        let token = format!("pk.eyJ1Ijoi{}.{}A", "a".repeat(15), "a".repeat(21));
        let text = format!("Clé ☕ {token}é et fin");
        assert_eq!(p.redact(&text), "Clé ☕ [redacted] et fin");
    }

    #[test]
    fn a_token_next_to_multibyte_text_is_still_taken_out_whole() {
        let p = SecretPatterns::builtins();
        let token = format!("ghp_{}", "a1".repeat(18));
        for text in [
            format!("☕{token}☕"),
            format!("日本語 {token} 日本語"),
            format!("é{token}"),
        ] {
            let out = p.redact(&text);
            assert!(!out.contains(&token), "{out}");
            assert!(out.contains(REDACTED), "{out}");
        }
        assert_eq!(p.redact(&format!("☕{token}☕")), "☕[redacted]☕");
    }

    #[test]
    fn the_password_in_a_bluebubbles_style_url_is_redacted_whatever_its_length() {
        let p = SecretPatterns::builtins();
        for password in ["Short1", "x", &"Ab3".repeat(6)] {
            for (url, redacted) in [
                (
                    format!("http://127.0.0.1:1234/api/v1/message/text?password={password}"),
                    "http://127.0.0.1:1234/api/v1/message/text[redacted]".to_string(),
                ),
                (
                    format!("https://h/api?x=1&password={password}&y=2 sent"),
                    "https://h/api?x=1[redacted]&y=2 sent".to_string(),
                ),
                (
                    format!("\"url\":\"http://h/a?password={password}\""),
                    "\"url\":\"http://h/a[redacted]\"".to_string(),
                ),
            ] {
                assert!(p.found_in(url.as_bytes()), "{url}");
                assert_eq!(p.redact(&url), redacted);
            }
        }
    }

    #[test]
    fn a_url_template_with_a_placeholder_for_the_password_isnt_taken_for_one() {
        let p = SecretPatterns::builtins();
        for text in [
            "/api?password={password}",
            "/api?password=%s",
            "/api?password=${PASS}",
        ] {
            assert!(!p.found_in(text.as_bytes()), "{text}");
        }
    }

    #[test]
    fn two_tokens_with_no_separator_are_both_taken_out() {
        let p = SecretPatterns::builtins();
        let one = format!("ghp_{}", "a1".repeat(18));
        let two = format!("ghp_{}", "b2".repeat(18));
        let out = p.redact(&format!("x {one}{two} y"));
        assert!(!out.contains(&one) && !out.contains(&two), "{out}");
        assert_eq!(out, "x [redacted] y");
    }

    #[test]
    fn a_token_after_an_escape_an_encoding_or_a_name_is_caught() {
        let p = SecretPatterns::builtins();
        let token = format!("ghp_{}", "a1".repeat(18));
        for before in [
            "{\"msg\":\"line\\n",
            "q=%20",
            "q=%3D",
            "a+",
            "MY_TOKEN_",
            "-p",
        ] {
            let line = format!("{before}{token}\"");
            assert!(p.found_in(line.as_bytes()), "{line}");
            assert!(!p.redact(&line).contains(&token), "{line}");
        }
    }

    #[test]
    fn a_line_of_a_repeated_prefix_at_the_line_cap_finishes_promptly() {
        // A guard against matching that grows with the square of a line's length: a whole line
        // of near-tokens, at the 1 MiB the scan reads at once, through both the scan and redaction.
        let p = SecretPatterns::builtins();
        for unit in ["-ATAT", "ghp_", "xoxb-1-", "AKIA"] {
            let line = unit.repeat((1 << 20) / unit.len());
            let started = std::time::Instant::now();
            let _ = p.found_in(line.as_bytes());
            let _ = p.redact(&line);
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(30),
                "{unit}: {took:?}"
            );
        }
    }

    #[test]
    fn overlapping_patterns_redact_the_whole_of_the_longer_token() {
        // gitlab-pat matches the first 26 characters of a routable token; gitlab-pat-routable
        // the whole of it. Replacing the shorter first left the rest showing.
        let token = format!("glpat-{}.01abcdefg", "a".repeat(100));
        let p = SecretPatterns::builtins();
        assert_eq!(
            p.redact(&format!("token {token} end")),
            "token [redacted] end"
        );
        let two = SecretPatterns::new(false, &[], &["ab".into(), "bcd".into()]).unwrap();
        assert_eq!(
            two.redact("xabcdx ab bcd"),
            "x[redacted]x [redacted] [redacted]"
        );
        assert_eq!(two.redact("abcd"), "[redacted]");
    }

    #[test]
    fn a_pattern_that_can_match_empty_text_is_refused() {
        // `\b` and `x*\b` don't match "" itself, but match nothing between words on every line.
        for p in ["", "a*", "(x)?", r"\b", r"x*\b", r"^"] {
            let why = SecretPatterns::new(true, &[], &[p.into()]).unwrap_err();
            assert_eq!(
                why,
                "secret_patterns.patterns: pattern 1 can match empty text, so it would match every line",
                "{p:?}"
            );
        }
    }

    #[test]
    fn a_patterns_flags_and_comments_stay_its_own() {
        // Alone, `(?x)` with a `#` comment is fine; joined into one pattern it ate the rest.
        let p =
            SecretPatterns::new(true, &[], &["(?x) myco_ [0-9a-f]{8} # a comment".into()]).unwrap();
        assert!(p.found_in(b"issued myco_0123abcd today"));
        assert!(p.found_in(format!("AKIA{}", "Q".repeat(16)).as_bytes()));
        // A case-insensitive flag in one doesn't spread to the next.
        let p = SecretPatterns::new(
            false,
            &[],
            &["(?i)abc_[0-9]{4}".into(), "XYZ_[0-9]{4}".into()],
        )
        .unwrap();
        assert!(p.found_in(b"ABC_1234"));
        assert!(!p.found_in(b"xyz_1234"));
    }

    #[test]
    fn every_builtin_compiles_on_its_own_and_ids_are_unique() {
        let mut ids = std::collections::BTreeSet::new();
        for s in BUILTINS {
            assert!(Regex::new(s.pattern).is_ok(), "{}", s.id);
            assert!(ids.insert(s.id), "{} twice", s.id);
            assert!(
                s.id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{}",
                s.id
            );
        }
    }

    #[test]
    fn disabling_an_id_drops_only_that_shape() {
        let all = SecretPatterns::builtins();
        let pat = format!("ghp_{}", "a1".repeat(18));
        assert!(all.found_in(pat.as_bytes()));
        let header = format!("-----BEGIN OPENSSH {} KEY-----", "PRIVATE");
        assert!(all.found_in(header.as_bytes()));
        let less = SecretPatterns::new(true, &["github-pat".into()], &[]).unwrap();
        assert!(!less.found_in(pat.as_bytes()));
        let aws = format!("AKIA{}", "Q".repeat(16));
        assert!(less.found_in(aws.as_bytes()));
    }

    #[test]
    fn an_unknown_id_or_a_bad_pattern_is_refused_without_repeating_it() {
        let why = SecretPatterns::new(true, &["no-such".into()], &[]).unwrap_err();
        assert_eq!(
            why,
            "secret_patterns.disable names \"no-such\", which isn't a built-in"
        );
        let why = SecretPatterns::new(true, &[], &["hunter2(".into()]).unwrap_err();
        assert_eq!(
            why,
            "secret_patterns.patterns: pattern 1 isn't one whimbrel can use"
        );
    }

    #[test]
    fn with_nothing_on_nothing_is_redacted() {
        let none = SecretPatterns::new(false, &[], &[]).unwrap();
        assert!(none.is_empty());
        let aws = format!("key AKIA{}", "Q".repeat(16));
        assert_eq!(none.redact(&aws), aws);
        assert!(!none.found_in(aws.as_bytes()));
    }

    #[test]
    fn a_config_pattern_adds_to_the_builtins_and_redaction_keeps_whats_around_a_match() {
        let p = SecretPatterns::new(true, &[], &["myco_[0-9a-f]{8}".into()]).unwrap();
        assert_eq!(
            p.redact(&format!("a myco_0123abcd and \"AKIA{}\".", "Q".repeat(16))),
            "a [redacted] and \"[redacted]\"."
        );
    }

    /// Common words, and the kinds of name and number ordinary logs are made of.
    const WORDS: &str = "the of and to in is it that for on was with as at be by this from or had \
        not are but have an they which one you were all we her she there been his if has more \
        when will would who so no out up into than them can only other new some what time about \
        could these two may first then do any like my now over such our man me even most made \
        after also did many before must through back years where much your way well down should \
        because each just those people how too little state good very make world still own see \
        work long get here between both life being under never day same another know while last \
        might us great old year off come since against go came right used take three states \
        himself few house use during without again place around however home small found \
        thought went say part once general high upon school every does got united left number \
        course war until always away something fact though water less public put think almost \
        hand enough far took head yet government system better set told nothing night end why \
        called didn eyes find going look asked later knew point next program city business give \
        group toward young days let room president side social given present several order \
        national possible rather second face per among form important often things looked early \
        white case john become large big need four within felt along children saw best church \
        ever least power development light thing seemed friends interest want members mind \
        country service backup restore deploy release config secret token password session \
        cookie header request response timeout retry connection socket listener worker queue \
        scheduler cron daemon kernel module device volume partition filesystem mount network \
        interface address gateway route firewall certificate authority signature checksum \
        database replica primary index migration transaction rollback commit branch merge \
        pipeline artifact container image registry cluster node pod namespace ingress proxy \
        upstream downstream cache bucket object storage archive compress snapshot journal";

    /// A few hundred lines of ordinary logging, built from templates, the words above, and ids,
    /// hashes and counts of the kinds logs carry.
    fn ordinary_lines() -> Vec<String> {
        let words: Vec<&str> = WORDS.split_whitespace().collect();
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let hex = |n: usize, x: u64| -> String {
            (0..n)
                .map(|i| char::from(b"0123456789abcdef"[((x >> ((i * 4) % 60)) & 15) as usize]))
                .collect()
        };
        let mut lines: Vec<String> = words.chunks(12).map(|c| c.join(" ")).collect();
        for _ in 0..300 {
            let (a, b, c) = (next(), next(), next());
            let w = |x: u64| words[(x % words.len() as u64) as usize];
            lines.push(match a % 8 {
                0 => format!(
                    "Nov 24 10:{:02}:{:02} web sshd[{}]: Accepted publickey for {} from 192.0.2.{} port {} ssh2",
                    b % 60, c % 60, b % 65536, w(c), a % 255, c % 65535
                ),
                1 => format!(
                    "203.0.113.{} - - [24/Nov/2026:10:00:{:02} +0000] \"GET /api/v1/{}/{}?page={} HTTP/1.1\" 200 {}",
                    a % 255, b % 60, w(b), w(c), c % 50, b % 100_000
                ),
                2 => format!(
                    "{{\"level\":\"info\",\"msg\":\"{} {} {}\",\"request_id\":\"{}-{}-{}-{}-{}\",\"ms\":{}}}",
                    w(a), w(b), w(c), hex(8, a), hex(4, b), hex(4, c), hex(4, a ^ b), hex(12, b ^ c), c % 5000
                ),
                3 => format!("commit {} {} the {} {}", hex(40, a ^ (b << 1)), w(a), w(b), w(c)),
                4 => format!(
                    "systemd[1]: Started {}-{}.service - {} {} {}.",
                    w(a), w(b), w(c), w(a ^ c), w(b ^ c)
                ),
                5 => format!(
                    "kernel: [{}.{:06}] EXT4-fs ({}{}): mounted filesystem with ordered data mode",
                    a % 100_000, b % 1_000_000, w(c), c % 9
                ),
                6 => format!(
                    "sha256:{}{}{}{} {} {} done in {}ms",
                    hex(16, a), hex(16, b), hex(16, c), hex(16, a ^ c), w(a), w(b), c % 9999
                ),
                _ => format!(
                    "{} {} {} {} {} {} {}",
                    w(a), w(b), w(c), w(a ^ b), w(b ^ c), w(a ^ c), w(a.rotate_left(7))
                ),
            });
        }
        lines
    }

    #[test]
    fn no_builtin_matches_ordinary_log_lines_or_words() {
        let lines = ordinary_lines();
        assert!(lines.len() >= 300, "{}", lines.len());
        let each: Vec<(&str, Regex)> = BUILTINS
            .iter()
            .map(|s| (s.id, Regex::new(s.pattern).unwrap()))
            .collect();
        let mut hits = Vec::new();
        for line in &lines {
            for (id, re) in &each {
                if re.is_match(line) {
                    hits.push(format!("{id}: {line}"));
                }
            }
        }
        assert!(hits.is_empty(), "{hits:#?}");
        // The same scan does find a token in a line like these.
        let planted = format!("{} AKIA{} {}", lines[0], "Q".repeat(16), lines[1]);
        assert!(each.iter().any(|(_, re)| re.is_match(&planted)));
    }

    #[test]
    fn ordinary_log_lines_dont_match() {
        let p = SecretPatterns::builtins();
        for line in [
            "Nov 24 10:00:00 web sshd[123]: Accepted publickey for deploy from 192.0.2.1",
            "GET /api/v1/items?page=2 HTTP/1.1 200",
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "-----BEGIN PUBLIC KEY-----",
            "TASK_0123456789abcdef0123456789abcdef done",
        ] {
            assert!(!p.found_in(line.as_bytes()), "{line}");
        }
    }
}
