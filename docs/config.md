# Config reference

whimbrel reads one TOML file, named on the command line:

```sh
whimbrel run --config FILE       # check, tell each channel what changed, keep the ledger
whimbrel dry-run --config FILE   # say what each channel would be sent, and change nothing
whimbrel --version
```

The file must belong to the account running whimbrel and not be writable by its group or others
(600 is right). It names programs whimbrel runs, often as root.

Every table refuses keys it doesn't know, so a typo is an error, not a silently ignored setting.
An error names the file and what's wrong: the key, and for a TOML or top-level error the line, which
for a `[[channel]]` table is its first. A check's error names the check by its number and kind
instead: `check 2 (disk): warn must be under fail`. No error repeats a value, in case the value is
a secret pasted into the wrong place. Paths must be absolute wherever this page says so, and a
relative one is refused.

- [Top level](#top-level)
- [Secret patterns](#secret-patterns)
- [Checks](#checks): [`disk`](#disk), [`file`](#file), [`secrets`](#secrets),
  [`journald-drops`](#journald-drops), [`command`](#command), [`result-file`](#result-file)
- [Result rows](#result-rows)
- [Channels](#channels): [`slack`](#slack), [`bluebubbles`](#bluebubbles), [`print`](#print)
- [The alerting check](#the-alerting-check)
- [Sentences](#sentences)

## Top level

| Key | Type | Default | |
|---|---|---|---|
| `host` | string | required | What alerts call this machine: "the web server", "your Mac". It's used mid-sentence and capitalized when it starts one. |
| `state_dir` | absolute path | required | Where whimbrel keeps what each channel was told, its lock, and each check's own state. Made owner-only (700) if missing; refused if another account owns it or can write it. |
| `log_file` | absolute path | stdout | Where each run's one line is appended. Made 600 if missing. |
| `curl` | path | `curl` from `PATH` | The `curl` the `slack` and `bluebubbles` channels send with. |
| `[secret_patterns]` | table | built-ins on | What a secret looks like here. See [Secret patterns](#secret-patterns). |
| `[[check]]` | array of tables | none | The checks, in the order they run and alerts list them. |
| `[[channel]]` | array of tables | none | Where alerts go. With none, `run` checks and logs but tells no one. |

A Slack webhook URL anywhere in the file is refused: put it in a file and name that file.

## Secret patterns

```toml
[secret_patterns]
builtins = true
disable = ["stripe-access-token"]
patterns = ['myco_[0-9a-f]{40}']
```

| Key | Type | Default | |
|---|---|---|---|
| `builtins` | bool | `true` | Use the built-in patterns below. `false` turns them all off. |
| `disable` | array of ids | `[]` | Built-in patterns to leave out, by id. They're published shapes, and on some hosts some will match ordinary ids that happen to share a token's prefix; leave those out here. An id that isn't below is refused, even with `builtins = false`. An id named twice is the same as once, and naming every id is the same as `builtins = false`. |
| `patterns` | array of regexes | `[]` | More patterns, in [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax), matched as written, Unicode classes included. An invalid one, or one that can match empty text, is refused without being repeated. |

The patterns are used twice:

- **Redaction.** Every match in an alert, a failed send's reason, and the ledger is replaced with
  `[redacted]` before any channel or file sees it, whichever check wrote the words. This matters
  most for `command` and `result-file`, whose rows are text from elsewhere.
- **The [`secrets`](#secrets) check**, which counts lines holding a match.

With the built-ins off and no `patterns` of your own, nothing is redacted and a `secrets` check is
refused.

### Built-in patterns

The built-ins are every rule of three published lists that passes one test, taken in list order:
gitleaks v8.30.1, betterleaks and Google's osv-scalibr, recorded with their licenses in
`THIRD-PARTY.md`. A rule passes if

- its token, the rule less the boundary a list matches after the token, compiles in Rust's regex;
- the token starts the match, so no rule that needs a keyword nearby passes;
- every way it can match starts with the same 3 or more fixed characters;
- it can't match fewer than 16 characters, so ordinary words and log lines don't;
- it's a shape, not one fixed string;
- and no rule taken from an earlier list already matches an example made from it.

Nothing is chosen by service, so some services you use may be missing and some patterns match
things that aren't secret, such as a service's public URL. Add what's missing with `patterns`, and
switch off what's noisy with `disable`. One pattern is whimbrel's own, `password-in-url`, for the
password the `bluebubbles` channel sends in its URL.

Each built-in matches as its source publishes it, except that `\w`, `\d` and `(?i)` in them mean
their ASCII forms: every token is ASCII, and Unicode's tables would make a few hundred patterns
cost hundreds of megabytes. Your own `patterns` match as written, Unicode included.

<!-- The ids and their order must match src/secret_patterns.rs; tests/docs.rs checks. -->

| Id | Pattern | Source |
|---|---|---|
| `1password-secret-key` | `\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})\|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b` | gitleaks `1password-secret-key` |
| `1password-service-account-token` | `ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}` | gitleaks `1password-service-account-token` |
| `adobe-client-secret` | `\b(p8e-(?i)[a-z0-9]{32})` | gitleaks `adobe-client-secret` |
| `age-secret-key` | `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}` | gitleaks `age-secret-key` |
| `aikido-ci-token` | `\b(AIK_CI_[A-Za-z0-9]{20,44})\b` | betterleaks `aikido-ci-token` |
| `aikido-client-id` | `\b(AIK_CLIENT_[A-Za-z0-9]{24})` | betterleaks `aikido-client-id` |
| `aikido-client-secret` | `\b(AIK_SECRET_[A-Za-z0-9]{64})` | betterleaks `aikido-client-secret` |
| `airtable-personnal-access-token` | `\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b` | gitleaks `airtable-personnal-access-token` |
| `alibaba-access-key-id` | `\b(LTAI(?i)[a-z0-9]{20})` | gitleaks `alibaba-access-key-id` |
| `alibaba-access-key-id-betterleaks` | `\b(LTAI[A-Za-z0-9]{17,21})\b` | betterleaks `alibaba-access-key-id` |
| `alibaba-sts-access-key-id` | `\b(STS\.[A-Za-z0-9]{16,64})\b` | betterleaks `alibaba-sts-access-key-id` |
| `anthropic-admin-api-key` | `\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)` | gitleaks `anthropic-admin-api-key` |
| `anthropic-api-key` | `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)` | gitleaks `anthropic-api-key` |
| `anthropic-oauth-access-token` | `\b(sk-ant-oat01-[a-zA-Z0-9_\-]{80,})` | betterleaks `anthropic-oauth-access-token` |
| `anthropic-oauth-refresh-token` | `\b(sk-ant-ort01-[a-zA-Z0-9_\-]{80,})` | betterleaks `anthropic-oauth-refresh-token` |
| `apify-api-token` | `\b(apify_api_[A-Za-z0-9]{34,38})\b` | betterleaks `apify-api-token` |
| `artifactory-api-key` | `\bAKCp[A-Za-z0-9]{69}\b` | gitleaks `artifactory-api-key` |
| `artifactory-api-key-betterleaks` | `\bAKCp[A-Za-z0-9]{68,70}\b` | betterleaks `artifactory-api-key` |
| `artifactory-reference-token` | `\bcmVmd[A-Za-z0-9]{59}\b` | gitleaks `artifactory-reference-token` |
| `atlassian-api-token` | `\b(ATAT[A-Za-z0-9_\-=]{100,})` | betterleaks `atlassian-api-token` |
| `authress-service-client-access-key` | `\b((?:sc\|ext\|scauth\|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})` | gitleaks `authress-service-client-access-key` |
| `authress-service-client-access-key-betterleaks` | `(?i)\b((?:sc\|ext\|scauth\|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})\b` | betterleaks `authress-service-client-access-key` |
| `aws-access-token` | `\b((?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16})\b` | gitleaks `aws-access-token` |
| `aws-amazon-bedrock-api-key-long-lived` | `\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})` | gitleaks `aws-amazon-bedrock-api-key-long-lived` |
| `azure-servicebus-connection-string` | `(?i)(Endpoint=sb://[a-z0-9-]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;=\s'"]{1,128};SharedAccessKey=[A-Za-z0-9+/]{32,100}={0,2}(?:;EntityPath=[^;\s'"]{1,128})?)` | betterleaks `azure-servicebus-connection-string` |
| `bitbucket-data-center-token` | `\b(BBDC-[A-Za-z0-9+/=]{32,})` | betterleaks `bitbucket-data-center-token` |
| `bitbucket-url` | `\bhttps://[^:\s]+:[^\s@]+@bitbucket\.org/[^\s]+\.git\b` | osv-scalibr `veles/secrets/gitbasicauth/bitbucket urlPattern` |
| `brave-search-api-key` | `\b(BSA[A-Za-z0-9_-]{24,40})\b` | betterleaks `brave-search-api-key` |
| `buildkite-service-token` | `\b(bkaa_[A-Za-z0-9_-]{75}\|bkaj_[A-Za-z0-9_-]{333}\|bkar_[A-Za-z0-9_-]{73}\|bkct_[A-Za-z0-9_-]{73}\|bkpt_[A-Za-z0-9_-]{199}\|bkpat_[A-Za-z0-9_-]{54}\|bkps_[A-Za-z0-9_-]{64})(?:$\|[^A-Za-z0-9_-])` | betterleaks `buildkite-service-token` |
| `buildkite-user-access-token` | `\b(bkua_(?:[a-z0-9]{40}\|[a-z0-9]{53}))\b` | betterleaks `buildkite-user-access-token` |
| `cal-api-key` | `\b(cal_live_[a-f0-9]{32})` | betterleaks `cal-api-key` |
| `canadian-digital-service-notify-api-key` | `(?i:\b(ApiKey-v1\s+gcntfy-[a-z0-9_]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b)` | betterleaks `canadian-digital-service-notify-api-key` |
| `canva-client-secret` | `\b(cnvca[a-zA-Z0-9_-]{51})\b` | betterleaks `canva-client-secret` |
| `cartesia-api-key-1` | `\b(sk_car_[A-Za-z0-9_]{20})` | betterleaks `cartesia-api-key.1` |
| `cerebras-api-key` | `(?i)\b(csk-[a-z0-9]{48})` | betterleaks `cerebras-api-key` |
| `circleci-circle-ciproject` | `CCIPRJ_[A-Za-z0-9]{22}_[0-9a-f]{40}` | osv-scalibr `veles/secrets/circleci circleCIProjectRe` |
| `circleci-personal-token` | `\b(CCIPAT_[a-zA-Z0-9]{22}_[a-z0-9]{40})` | betterleaks `circleci-personal-token` |
| `clickhouse-cloud-api-secret-key` | `\b(4b1d[A-Za-z0-9]{38})\b` | gitleaks `clickhouse-cloud-api-secret-key` |
| `clojars-api-token` | `(?i)CLOJARS_[a-z0-9]{60}` | gitleaks `clojars-api-token` |
| `cloudflare-api-key-2` | `\b(cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8})` | betterleaks `cloudflare-api-key.2` |
| `cloudflare-origin-ca-key` | `\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})` | gitleaks `cloudflare-origin-ca-key` |
| `cloudsmith-api-key` | `\b(csa_[a-f0-9]{30}[A-Za-z0-9]{6})` | betterleaks `cloudsmith-api-key` |
| `cockroachlabs-cloud-api-key` | `\b(CCDB1_[A-Za-z0-9]{22}_[A-Za-z0-9]{40})\b` | betterleaks `cockroachlabs-cloud-api-key` |
| `codecatalyst-url` | `\bhttps://[^:\s]+:[^\s@]+@git\.[^/]*codecatalyst\.aws/[^\s]*` | osv-scalibr `veles/secrets/gitbasicauth/codecatalyst urlPattern` |
| `codecommit-url` | `https://[^:\s]+:[^\s@]+@git-codecommit\.[a-zA-Z\-0-9]+\.amazonaws\.com/[^\s]+` | osv-scalibr `veles/secrets/gitbasicauth/codecommit urlPattern` |
| `configcat-sdk-key-extended` | `\b(configcat-sdk-1/[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{22})` | betterleaks `configcat-sdk-key-extended` |
| `cratesioapitoken-key` | `\bcio[a-zA-Z-0-9]{32}\b` | osv-scalibr `veles/secrets/cratesioapitoken keyRe` |
| `cursorapikey-key` | `\bkey_[a-z0-9]{64}\b` | osv-scalibr `veles/secrets/cursorapikey keyRe` |
| `databricks-api-token` | `\b(dapi[a-f0-9]{32}(?:-\d)?)` | gitleaks `databricks-api-token` |
| `datastax-astra-application-token` | `\b(AstraCS:[A-Za-z0-9]{20,})` | betterleaks `datastax-astra-application-token` |
| `daytona-api-key` | `\b(dtn_[a-f0-9]{64})` | betterleaks `daytona-api-key` |
| `deno-account-token` | `\b(ddp_[A-Za-z0-9]{36})` | betterleaks `deno-account-token` |
| `denopat-org-pat` | `ddo_[A-Za-z0-9]{36}` | osv-scalibr `veles/secrets/denopat orgPatRe` |
| `devcycle-server-sdk-key` | `\b(dvc_server_[A-Za-z0-9]{8,32})` | betterleaks `devcycle-server-sdk-key` |
| `devin-personal-api-key` | `\b(apk_user_[A-Za-z0-9+/]{120,180}={0,2})` | betterleaks `devin-personal-api-key` |
| `devin-service-api-key` | `\b(apk_[A-Za-z0-9+/]{80,100}={0,2})` | betterleaks `devin-service-api-key` |
| `devin-service-user-token` | `\b(cog_[a-z2-7]{52})` | betterleaks `devin-service-user-token` |
| `digitalocean-access-token` | `\b(doo_v1_[a-f0-9]{64})` | gitleaks `digitalocean-access-token` |
| `digitalocean-pat` | `\b(dop_v1_[a-f0-9]{64})` | gitleaks `digitalocean-pat` |
| `digitalocean-refresh-token` | `(?i)\b(dor_v1_[a-f0-9]{64})` | gitleaks `digitalocean-refresh-token` |
| `docker-swarm-join-token` | `\b(SWMTKN-1-[a-z0-9]{50,60}-[a-z0-9]{24,30})` | betterleaks `docker-swarm-join-token` |
| `docker-swarm-unlock-key` | `\b(SWMKEY-1-[A-Za-z0-9+/]{40,50})` | betterleaks `docker-swarm-unlock-key` |
| `dockerhub-organization-access-token` | `\b(dckr_oat_[A-Za-z0-9_-]{32})` | betterleaks `dockerhub-organization-access-token` |
| `dockerhub-personal-access-token` | `\b(dckr_pat_[A-Za-z0-9_-]{27})` | betterleaks `dockerhub-personal-access-token` |
| `doppler-api-token` | `dp\.pt\.(?i)[a-z0-9]{43}` | gitleaks `doppler-api-token` |
| `duffel-api-token` | `duffel_(?:test\|live)_(?i)[a-z0-9_\-=]{43}` | gitleaks `duffel-api-token` |
| `dynatrace-api-token` | `dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}` | gitleaks `dynatrace-api-token` |
| `easypost-api-token` | `\bEZAK(?i)[a-z0-9]{54}\b` | gitleaks `easypost-api-token` |
| `easypost-test-api-token` | `\bEZTK(?i)[a-z0-9]{54}\b` | gitleaks `easypost-test-api-token` |
| `elastic-cloud-api-key` | `\b(essu_[A-Za-z0-9_\-]{60,200}={0,2})` | betterleaks `elastic-cloud-api-key` |
| `exoscale-api-key` | `\b(EXO[a-zA-Z0-9]{24,30})` | betterleaks `exoscale-api-key` |
| `facebook-page-access-token` | `\b(EAA[MC](?i)[a-z0-9]{100,})` | gitleaks `facebook-page-access-token` |
| `figma-personal-access-token` | `(?i)\b(figd_[A-Z0-9_-]{38,42})` | betterleaks `figma-personal-access-token` |
| `flutterwave-encryption-key` | `FLWSECK_TEST-(?i)[a-h0-9]{12}` | gitleaks `flutterwave-encryption-key` |
| `flutterwave-public-key` | `FLWPUBK_TEST-(?i)[a-h0-9]{32}-X` | gitleaks `flutterwave-public-key` |
| `flutterwave-secret-key` | `FLWSECK_TEST-(?i)[a-h0-9]{32}-X` | gitleaks `flutterwave-secret-key` |
| `flyio-access-token` | `\b((?:fo1_[\w-]{43}\|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}\|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))` | gitleaks `flyio-access-token` |
| `flyio-access-token-betterleaks` | `\b(FlyV1\s[A-Za-z0-9=_\-,/+]{100,})` | betterleaks `flyio-access-token` |
| `frameio-api-token` | `fio-u-(?i)[a-z0-9\-_=]{64}` | gitleaks `frameio-api-token` |
| `gcp-api-key` | `\b(AIza[\w-]{35})` | gitleaks `gcp-api-key` |
| `gcp-gemini-api` | `\b(AQ\.Ab8RN6[A-Za-z0-9_-]{44})` | betterleaks `gcp-gemini-api` |
| `gcpexpressmode-key` | `AQ\.Ab8R[a-zA-Z0-9_-]{46}` | osv-scalibr `veles/secrets/gcpexpressmode keyRe` |
| `gcpoauth2client-client-secret` | `\bGOCSPX-[a-zA-Z0-9_-]{28}` | osv-scalibr `veles/secrets/gcpoauth2client clientSecretRe` |
| `gcpsak-re-base64` | `ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIs[a-zA-Z0-9/+]{52,}` | osv-scalibr `veles/secrets/gcpsak reBase64` |
| `gcshmackey-access-id` | `GOOG(?:[A-Z0-9]{57}\|[A-Z0-9]{20})` | osv-scalibr `veles/secrets/gcshmackey accessIDPattern` |
| `github-app-token` | `(?:ghu\|ghs)_[0-9a-zA-Z]{36}` | gitleaks `github-app-token` |
| `github-fine-grained-pat` | `github_pat_\w{82}` | gitleaks `github-fine-grained-pat` |
| `github-oauth` | `gho_[0-9a-zA-Z]{36}` | gitleaks `github-oauth` |
| `github-pat` | `ghp_[0-9a-zA-Z]{36}` | gitleaks `github-pat` |
| `github-refresh-token` | `ghr_[0-9a-zA-Z]{36}` | gitleaks `github-refresh-token` |
| `gitlab-cicd-job-token` | `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}` | gitleaks `gitlab-cicd-job-token` |
| `gitlab-deploy-token` | `gldt-[0-9a-zA-Z_\-]{20}` | gitleaks `gitlab-deploy-token` |
| `gitlab-feature-flag-client-token` | `glffct-[0-9a-zA-Z_\-]{20}` | gitleaks `gitlab-feature-flag-client-token` |
| `gitlab-feed-token` | `glft-[0-9a-zA-Z_\-]{20}` | gitleaks `gitlab-feed-token` |
| `gitlab-incoming-mail-token` | `glimt-[0-9a-zA-Z_\-]{25}` | gitleaks `gitlab-incoming-mail-token` |
| `gitlab-kubernetes-agent-token` | `glagent-[0-9a-zA-Z_\-]{50}` | gitleaks `gitlab-kubernetes-agent-token` |
| `gitlab-oauth-app-secret` | `gloas-[0-9a-zA-Z_\-]{64}` | gitleaks `gitlab-oauth-app-secret` |
| `gitlab-pat` | `glpat-[\w-]{20}` | gitleaks `gitlab-pat` |
| `gitlab-pat-routable` | `\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b` | gitleaks `gitlab-pat-routable` |
| `gitlab-ptt` | `glptt-[0-9a-f]{40}` | gitleaks `gitlab-ptt` |
| `gitlab-rrt` | `GR1348941[\w-]{20}` | gitleaks `gitlab-rrt` |
| `gitlab-runner-authentication-token` | `glrt-[0-9a-zA-Z_\-]{20}` | gitleaks `gitlab-runner-authentication-token` |
| `gitlab-runner-authentication-token-routable` | `\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b` | gitleaks `gitlab-runner-authentication-token-routable` |
| `gitlab-scim-token` | `glsoat-[0-9a-zA-Z_\-]{20}` | gitleaks `gitlab-scim-token` |
| `gitlab-session-cookie` | `_gitlab_session=[0-9a-z]{32}` | gitleaks `gitlab-session-cookie` |
| `grafana-api-key` | `(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})` | gitleaks `grafana-api-key` |
| `grafana-api-key-betterleaks` | `\b(eyJrIjoi[A-Za-z0-9+/]{40,380}={0,2})` | betterleaks `grafana-api-key` |
| `grafana-cloud-api-token` | `(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})` | gitleaks `grafana-cloud-api-token` |
| `grafana-service-account-token` | `(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})` | gitleaks `grafana-service-account-token` |
| `groq-api-key` | `(?i)\b(gsk_[A-Z0-9]{52})` | betterleaks `groq-api-key` |
| `harness-api-key` | `(?:pat\|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}` | gitleaks `harness-api-key` |
| `heroku-api-key-v2` | `\b((HRKU-AA[0-9a-zA-Z_-]{58}))` | gitleaks `heroku-api-key-v2` |
| `herokuplatformkey-key` | `\b(HRKU-[0-9a-zA-Z_-]{60})\b` | osv-scalibr `veles/secrets/herokuplatformkey keyRe` |
| `huggingface-access-token` | `\b(hf_(?i:[a-z]{34}))` | gitleaks `huggingface-access-token` |
| `huggingface-organization-api-token` | `\b(api_org_(?i:[a-z]{34}))` | gitleaks `huggingface-organization-api-token` |
| `infracost-api-token` | `\b(ico-[a-zA-Z0-9]{32})` | gitleaks `infracost-api-token` |
| `intra42-client-secret` | `\b(s-s4t2(?:ud\|af)-(?i)[abcdef0123456789]{64})` | gitleaks `intra42-client-secret` |
| `ionic-personal-access-token` | `\b(ion_[A-Za-z0-9]{42})` | betterleaks `ionic-personal-access-token` |
| `jina-ai-api-key` | `\b(jina_[A-Za-z0-9_\-]{60})` | betterleaks `jina-ai-api-key` |
| `labelbox-api-key` | `\b(lbx_[\w-]{42}[AEIMQUYcgkosw048])` | betterleaks `labelbox-api-key` |
| `labelbox-recursion-api-key` | `\b(rma_[\w-]{42}[AEIMQUYcgkosw048])` | betterleaks `labelbox-recursion-api-key` |
| `langchain-langsmith-personal-access-token` | `\b(lsv2_pt_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})` | betterleaks `langchain-langsmith-personal-access-token` |
| `langchain-langsmith-service-key` | `\b(lsv2_sk_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})` | betterleaks `langchain-langsmith-service-key` |
| `langfuse-public-key-1` | `\b(pk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})` | betterleaks `langfuse-public-key.1` |
| `langfuse-secret-key-1` | `\b(sk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})` | betterleaks `langfuse-secret-key.1` |
| `lark-app-id` | `\b(cli_[A-Za-z0-9]{16})` | betterleaks `lark-app-id` |
| `lichess-personal-access-token` | `\b(lip_[A-Za-z0-9_]{16,60})` | betterleaks `lichess-personal-access-token` |
| `linear-api-key` | `lin_api_(?i)[a-z0-9]{40}` | gitleaks `linear-api-key` |
| `llama-cloud-api-key-1` | `\b(llx-[A-Za-z0-9]{44,52})` | betterleaks `llama-cloud-api-key.1` |
| `mailersend-api-token` | `\b(mlsn\.[A-Za-z0-9]{30,100})` | betterleaks `mailersend-api-token` |
| `mapbox-api-token` | `\b(pk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$\|[^A-Za-z0-9_-])` | betterleaks `mapbox-api-token` |
| `mapbox-secret-token` | `\b(sk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$\|[^A-Za-z0-9_-])` | betterleaks `mapbox-secret-token` |
| `mercury-production-api-token` | `\b(mercury_production_[a-z]{3,6}_[A-Za-z0-9]{40,50}_yrucrem)` | betterleaks `mercury-production-api-token` |
| `mergify-application-key` | `\b(mergify_application_key_[A-Za-z0-9_-]{40,200})` | betterleaks `mergify-application-key` |
| `minimax-api-key` | `(?i)\b(sk-api-[A-Za-z0-9_-]{119})` | betterleaks `minimax-api-key` |
| `miro-access-token` | `\b(eyJtaXJv[A-Za-z0-9-]{10,64}_[A-Za-z0-9_-]{20,64})` | betterleaks `miro-access-token` |
| `mongodb-atlas-service-account-id` | `\b(mdb_sa_id_[a-f0-9]{24})` | betterleaks `mongodb-atlas-service-account-id` |
| `mongodb-atlas-service-account-secret` | `\b(mdb_sa_sk_[A-Za-z0-9_-]{40})` | betterleaks `mongodb-atlas-service-account-secret` |
| `mongodb-connection-string` | `\b(mongodb(?:\+srv)?://(?P<username>[!-9;-~]{3,50}):(?P<password>[!-?A-~]{3,88})@(?P<host>(?:[a-zA-Z0-9][\w.-]+\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:,(?:[a-zA-Z0-9][\w.-]+\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?)*)/?(?:(?P<authdb>[\w-]+)?(?P<options>\?\w+=[\w@/.$-]+(?:&(?:amp;)?\w+=[\w@/.$-]+)*)?)?)` | betterleaks `mongodb-connection-string` |
| `neon-api-key` | `\b(napi_[A-Za-z0-9]{64})` | betterleaks `neon-api-key` |
| `notion-api-token` | `\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})` | gitleaks `notion-api-token` |
| `npm-access-token` | `(?i)\b(npm_[a-z0-9]{36})` | gitleaks `npm-access-token` |
| `nuget-api-key` | `(?i)\b(oy2[a-p][a-z2-7]{15}[aq][a-z2-7]{25}[aeimquy4])` | betterleaks `nuget-api-key` |
| `nvidia-api-key` | `(?i)\b(nvapi-[A-Z0-9_-]{60,70})` | betterleaks `nvidia-api-key` |
| `nylas-api-key-1` | `\b(nyk_[A-Za-z0-9]{67})` | betterleaks `nylas-api-key.1` |
| `octopus-deploy-api-key` | `\b(API-[A-Z0-9]{26})` | gitleaks `octopus-deploy-api-key` |
| `onepasswordkeys-recovery-token` | `1PRK(?:-[A-Z0-9]{4}){13}` | osv-scalibr `veles/secrets/onepasswordkeys recoveryTokenRe` |
| `onesignal-rich-authentication-token` | `\b(os_v2_(?:app\|org)_[a-z2-7]{103})` | betterleaks `onesignal-rich-authentication-token` |
| `onfido-live-api-token-ca` | `\b(api_live_ca\.[A-Za-z0-9_-]{20,80})` | betterleaks `onfido-live-api-token-ca` |
| `onfido-live-api-token-eu` | `\b(api_live\.[A-Za-z0-9_-]{20,80})` | betterleaks `onfido-live-api-token-eu` |
| `onfido-live-api-token-us` | `\b(api_live_us\.[A-Za-z0-9_-]{20,80})` | betterleaks `onfido-live-api-token-us` |
| `openai-api-key` | `\b(sk-(?:proj\|svcacct\|admin)-(?:[A-Za-z0-9_-]{74}\|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}\|[A-Za-z0-9_-]{58})\b\|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})` | gitleaks `openai-api-key` |
| `openrouter-api-key` | `(?i)\b(sk-or-v1-[0-9a-f]{64})` | betterleaks `openrouter-api-key` |
| `openrouter-key` | `sk-or-v[0-9]+-[A-Za-z0-9_-]{20,}` | osv-scalibr `veles/secrets/openrouter keyRe` |
| `openshift-user-token` | `\b(sha256~[\w-]{43})(?:[^\w-]\|\z)` | gitleaks `openshift-user-token` |
| `packagist-api-key` | `packagist_ack_[0-9a-f]{28,32}` | osv-scalibr `veles/secrets/packagist apiKeyRe` |
| `packagist-api-secret` | `packagist_acs_[0-9a-f]{64,96}` | osv-scalibr `veles/secrets/packagist apiSecretRe` |
| `packagist-conductor-update-token` | `packagist_cut_[0-9a-f]{68}` | osv-scalibr `veles/secrets/packagist conductorUpdateTokenRe` |
| `packagist-org-read-token` | `packagist_ort_[0-9a-f]{68}` | osv-scalibr `veles/secrets/packagist orgReadTokenRe` |
| `packagist-org-update-token` | `packagist_out_[0-9a-f]{68}` | osv-scalibr `veles/secrets/packagist orgUpdateTokenRe` |
| `packagist-repo-url` | `https?://repo\.packagist\.com[/\w\-\.]*` | osv-scalibr `veles/secrets/packagist repoURLRe` |
| `packagist-user-update-token` | `packagist_uut_[0-9a-f]{68}` | osv-scalibr `veles/secrets/packagist userUpdateTokenRe` |
| `paddle-live-api-key` | `\b(pdl_live_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3})` | betterleaks `paddle-live-api-key` |
| `password-in-url` | `[?&]password=[0-9A-Za-z]+` | whimbrel's own: the bluebubbles channel sends its password, letters and digits of any length, in the URL's query, and a URL can end up in a log |
| `paystacksecretkey-sk` | `\bsk_[a-z]{1,15}_[a-z0-9]{40}\b` | osv-scalibr `veles/secrets/paystacksecretkey skRe` |
| `perplexity-api-key` | `\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]\|\\[nr]\|$\|\b)` | gitleaks `perplexity-api-key` |
| `persona-production-api-key` | `\b(persona_production_[a-z0-9_-]{20,80})` | betterleaks `persona-production-api-key` |
| `pinecone-api-key-2` | `\b(pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63})` | betterleaks `pinecone-api-key.2` |
| `pinterest-access-token` | `\b(pina_[A-Za-z0-9_-]{20,200})` | betterleaks `pinterest-access-token` |
| `planetscale-api-token` | `\b(pscale_tkn_(?i)[\w=\.-]{32,64})` | gitleaks `planetscale-api-token` |
| `planetscale-oauth-token` | `\b(pscale_oauth_[\w=\.-]{32,64})` | gitleaks `planetscale-oauth-token` |
| `planetscale-password` | `(?i)\b(pscale_pw_(?i)[\w=\.-]{32,64})` | gitleaks `planetscale-password` |
| `polar-oauth-access-token` | `\b(polar_at_[A-Za-z0-9_-]{20,100})` | betterleaks `polar-oauth-access-token` |
| `polar-organization-access-token` | `\b(polar_oat_[A-Za-z0-9_-]{20,100})` | betterleaks `polar-organization-access-token` |
| `polar-personal-access-token` | `\b(polar_pat_[A-Za-z0-9_-]{20,100})` | betterleaks `polar-personal-access-token` |
| `posthog-personal-api-key` | `(?i)\b(phx_[a-zA-Z0-9_\-]{41,49})` | betterleaks `posthog-personal-api-key` |
| `postman-api-token` | `\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})` | gitleaks `postman-api-token` |
| `postmanapikey-pmat` | `PMAT-[A-Za-z0-9]{26}` | osv-scalibr `veles/secrets/postmanapikey pmatRe` |
| `prefect-api-token` | `\b(pnu_[a-zA-Z0-9]{36})` | gitleaks `prefect-api-token` |
| `private-key` | `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----` | gitleaks `private-key`; the header line alone, since a log is read a line at a time |
| `privatekey-block` | `(?s)-----BEGIN (?:OPENSSH\|RSA\|DSA\|EC\|ED25519\|ENCRYPTED)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH\|RSA\|DSA\|EC\|ED25519\|ENCRYPTED)? ?PRIVATE KEY-----` | osv-scalibr `veles/secrets/privatekey blockRe` |
| `proof-full-access-api-key` | `\b(prf_(?:cli_)?[A-Za-z0-9_-]{20,80})` | betterleaks `proof-full-access-api-key` |
| `pulumi-api-token` | `\b(pul-[a-f0-9]{40})` | gitleaks `pulumi-api-token` |
| `pypi-upload-token` | `pypi-AgEIcHlwaS5vcmc[[A-Za-z0-9_]-]{50,1000}` | gitleaks `pypi-upload-token`; an ASCII class for \w, since the Unicode one is too big for Rust's regex |
| `pypiapitoken-key` | `pypi-[A-Za-z0-9-_]{85,}` | osv-scalibr `veles/secrets/pypiapitoken keyRe` |
| `pyxkeyv1-key` | `sk-pyx-[a-zA-Z0-9]{64}` | osv-scalibr `veles/secrets/pyxkeyv1 keyRe` |
| `pyxkeyv2-key` | `sk-pyx-2[a-zA-Z]{45}` | osv-scalibr `veles/secrets/pyxkeyv2 keyRe` |
| `ramp-client-id` | `\b(ramp_id_[A-Za-z0-9]{40})` | betterleaks `ramp-client-id` |
| `ramp-client-secret` | `\b(ramp_sec_[A-Za-z0-9]{48})` | betterleaks `ramp-client-secret` |
| `razorpay-key-id-1` | `\b(rzp_(?:live\|test)_[A-Za-z0-9]{14})` | betterleaks `razorpay-key-id.1` |
| `readme-api-token` | `\b(rdme_[a-z0-9]{70})` | gitleaks `readme-api-token` |
| `redirect-pizza-api-token-1` | `\b(rpa_[A-Za-z0-9]{30})` | betterleaks `redirect-pizza-api-token.1` |
| `render-api-key` | `\b(rnd_[A-Za-z0-9]{28})` | betterleaks `render-api-key` |
| `replicate-api-token` | `(?i)\b(r8_[A-Za-z0-9]{37})` | betterleaks `replicate-api-token` |
| `resend-api-key-1` | `\b(re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24})` | betterleaks `resend-api-key.1` |
| `rootly-api-key-1` | `\b(rootly_[a-f0-9]{64})` | betterleaks `rootly-api-key.1` |
| `rubygems-api-token` | `\b(rubygems_[a-f0-9]{48})` | gitleaks `rubygems-api-token` |
| `runpod-api-key-1` | `\b(rpa_[A-Z0-9]{40}[A-Za-z0-9]{6})` | betterleaks `runpod-api-key.1` |
| `salesforceoauth2access-token` | `\b00D[0-9A-Za-z]{8,15}![A-Za-z0-9._\-]{30,100}\b` | osv-scalibr `veles/secrets/salesforceoauth2access tokenRe` |
| `salesforceoauth2client-client-id` | `\b3MVG[a-zA-Z0-9._\-]{20,180}\b` | osv-scalibr `veles/secrets/salesforceoauth2client clientIDRe` |
| `salesforceoauth2jwt-client-id` | `\b3MVG[a-zA-Z0-9._\-]{20,180}\b` | osv-scalibr `veles/secrets/salesforceoauth2jwt clientIDRe` |
| `salesforceoauth2jwt-private-key` | `(?s)-----BEGIN (?:OPENSSH\|RSA\|DSA\|EC\|ED25519\|ENCRYPTED)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH\|RSA\|DSA\|EC\|ED25519\|ENCRYPTED)? ?PRIVATE KEY-----` | osv-scalibr `veles/secrets/salesforceoauth2jwt privateKeyRe` |
| `salesforceoauth2refresh-client-id` | `\b3MVG[a-zA-Z0-9._\-]{20,180}\b` | osv-scalibr `veles/secrets/salesforceoauth2refresh clientIDRe` |
| `samsara-api-token-1` | `\b(samsara_api_[A-Za-z0-9]{26,32})` | betterleaks `samsara-api-token.1` |
| `scalingo-api-token` | `\b(tk-us-[\w-]{48})` | gitleaks `scalingo-api-token` |
| `segment-public-api-token-1` | `\b(sgp_[A-Za-z0-9]{64})` | betterleaks `segment-public-api-token.1` |
| `sendgrid-api-token` | `\b(SG\.(?i)[a-z0-9=_\-\.]{66})` | gitleaks `sendgrid-api-token` |
| `sendinblue-api-token` | `\b(xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16})` | gitleaks `sendinblue-api-token` |
| `sentry-org-token` | `\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs\|InJlZ2lvbl91cmwi\|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]\|\z)` | gitleaks `sentry-org-token` |
| `sentry-user-token` | `\b(sntryu_[a-f0-9]{64})` | gitleaks `sentry-user-token` |
| `settlemint-application-access-token` | `\b(sm_aat_[a-zA-Z0-9]{16})` | gitleaks `settlemint-application-access-token` |
| `settlemint-personal-access-token` | `\b(sm_pat_[a-zA-Z0-9]{16})` | gitleaks `settlemint-personal-access-token` |
| `settlemint-service-access-token` | `\b(sm_sat_[a-zA-Z0-9]{16})` | gitleaks `settlemint-service-access-token` |
| `shippo-api-token` | `\b(shippo_(?:live\|test)_[a-fA-F0-9]{40})` | gitleaks `shippo-api-token` |
| `shopify-access-token` | `shpat_[a-fA-F0-9]{32}` | gitleaks `shopify-access-token` |
| `shopify-custom-access-token` | `shpca_[a-fA-F0-9]{32}` | gitleaks `shopify-custom-access-token` |
| `shopify-private-app-access-token` | `shppa_[a-fA-F0-9]{32}` | gitleaks `shopify-private-app-access-token` |
| `shopify-shared-secret` | `shpss_[a-fA-F0-9]{32}` | gitleaks `shopify-shared-secret` |
| `slack-bot-token` | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | gitleaks `slack-bot-token` |
| `slack-config-access-token` | `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}` | gitleaks `slack-config-access-token` |
| `slack-config-refresh-token` | `(?i)xoxe-\d-[A-Z0-9]{146}` | gitleaks `slack-config-refresh-token` |
| `slack-legacy-bot-token` | `xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}` | gitleaks `slack-legacy-bot-token` |
| `slack-session-cookie` | `(xoxd-[\w\/\\+-]{100,}={0,2})(?:[^\w\/+=-]\|\z)` | betterleaks `slack-session-cookie` |
| `slack-session-token` | `xoxc-\d{9,15}-\d{9,15}-\d{9,15}-[a-f0-9]{64}\b` | betterleaks `slack-session-token` |
| `slack-user-token` | `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}` | gitleaks `slack-user-token` |
| `slack-webhook-url` | `(?:https?://)?hooks.slack.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}` | gitleaks `slack-webhook-url` |
| `slacktoken-app-level-token` | `xapp-\d{1,10}-[A-Za-z0-9]{11}-[0-9]{13}-[a-fA-F0-9]{64}` | osv-scalibr `veles/secrets/slacktoken appLevelTokenRe` |
| `sourcegraph-access-token` | `(?i)\b(sgp_(?:[a-fA-F0-9]{16}\|local)_[a-fA-F0-9]{40}\|sgp_[a-fA-F0-9]{40})` | betterleaks `sourcegraph-access-token` |
| `square-access-token` | `\b((?:EAAA\|sq0atp-)[\w-]{22,60})` | gitleaks `square-access-token` |
| `squareapikey-o-auth-application-id` | `sq0idp-[A-Za-z0-9_-]{22}` | osv-scalibr `veles/secrets/squareapikey oAuthApplicationIDRe` |
| `squareapikey-o-auth-application-secret` | `sq0csp-[A-Za-z0-9_-]{43}` | osv-scalibr `veles/secrets/squareapikey oAuthApplicationSecretRe` |
| `stripe-access-token` | `\b((?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99})` | gitleaks `stripe-access-token` |
| `stripeapikeys-whsec` | `whsec_[A-Za-z0-9]{32}` | osv-scalibr `veles/secrets/stripeapikeys whsecRe` |
| `supabase-management-token` | `\b(sbp_[a-z0-9_-]{40})` | betterleaks `supabase-management-token` |
| `supabase-project-api-key` | `\b(sb_secret_[A-Za-z0-9_-]{31})` | betterleaks `supabase-project-api-key` |
| `supabase-project-url` | `\b(https://[a-z0-9]{16,32}\.supabase\.co)\b` | betterleaks `supabase-project-url` |
| `tailscale-api-key-1` | `\b(tskey-api-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b` | betterleaks `tailscale-api-key.1` |
| `tailscale-auth-key` | `\b(tskey-auth-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b` | betterleaks `tailscale-auth-key` |
| `tailscale-key` | `\b(tskey-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{20,40})\b` | betterleaks `tailscale-key` |
| `tailscale-oauth-client-secret` | `\b(tskey-client-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b` | betterleaks `tailscale-oauth-client-secret` |
| `tailscale-scim-key` | `\b(tskey-scim-[A-Za-z0-9]{8,24}-[A-Za-z0-9]{28,40})\b` | betterleaks `tailscale-scim-key` |
| `tailscale-webhook-secret` | `\b(tskey-webhook-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b` | betterleaks `tailscale-webhook-secret` |
| `temporal-cloud-api-key-1` | `\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*Y2NvdW50X2lk[A-Za-z0-9_-]*InRlbXBvcmFsLmlv[A-Za-z0-9_-]*(?:ICJrZXlfaWQiOi\|a2V5X2lk\|rZXlfaWQi)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})` | betterleaks `temporal-cloud-api-key.1` |
| `thunderstore-api-token-1` | `\b(tss_[A-Za-z0-9_-]{20,80})` | betterleaks `thunderstore-api-token.1` |
| `togetherai-api-key` | `(?i)\b(tgp_v1_[A-Za-z0-9_-]{43})` | betterleaks `togetherai-api-key` |
| `unkey-root-key-1` | `\b(unkey_[A-Za-z0-9]{20,32})` | betterleaks `unkey-root-key.1` |
| `upcloud-api-token` | `\b(ucat_[0-9A-Za-z]{24,32})` | betterleaks `upcloud-api-token` |
| `upstash-redis-rest-url-1` | `(?i)\b(https://[a-z0-9][a-z0-9-]{2,63}\.upstash\.io)` | betterleaks `upstash-redis-rest-url.1` |
| `val-town-api-token-1` | `\b(vtwn_[A-Za-z0-9_-]{20,80})` | betterleaks `val-town-api-token.1` |
| `vault-batch-token` | `\b(hvb\.[[A-Za-z0-9_]-]{138,300})` | gitleaks `vault-batch-token`; an ASCII class for \w, since the Unicode one is too big for Rust's regex |
| `vercel-ai-gateway-key` | `(?i)\b(vck_[A-Za-z0-9_-]{56})` | betterleaks `vercel-ai-gateway-key` |
| `vercel-app-access-token` | `(?i)\b(vca_[A-Za-z0-9_-]{56})` | betterleaks `vercel-app-access-token` |
| `vercel-app-refresh-token` | `(?i)\b(vcr_[A-Za-z0-9_-]{56})` | betterleaks `vercel-app-refresh-token` |
| `vercel-integration-token` | `(?i)\b(vci_[A-Za-z0-9_-]{56})` | betterleaks `vercel-integration-token` |
| `vercel-personal-access-token` | `(?i)\b(vcp_[A-Za-z0-9_-]{56})` | betterleaks `vercel-personal-access-token` |
| `wakatime-api-key-2` | `(?i)\b(waka_[a-z0-9]{36,64})` | betterleaks `wakatime-api-key.2` |
| `weights-and-biases-api-key-v1` | `(?i)\b(wandb_v1_[A-Za-z0-9_]{77})` | betterleaks `weights-and-biases-api-key-v1` |
| `workato-developer-api-token-1` | `\b(wrka(?:[a-z]{2})?-eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{64,})` | betterleaks `workato-developer-api-token.1` |
| `xai-api-key` | `(?i)\b(xai-[A-Za-z0-9_-]{70,120})` | betterleaks `xai-api-key` |
| `xendit-production-api-key-1` | `\b(xnd_production_[A-Za-z0-9]{56,72})` | betterleaks `xendit-production-api-key.1` |
| `zuplo-consumer-api-key-1` | `\b(zpka_[a-z0-9]{32}_[0-9a-f]{8})` | betterleaks `zuplo-consumer-api-key.1` |

## Checks

Every check takes these, besides its own keys:

| Key | Type | Default | |
|---|---|---|---|
| `kind` | string | required | One of the kinds below. |
| `key` | string | the kind's name | Stable and unique on this host. Lowercase letters, digits and dashes, since it names the check's own directory under `state_dir`. `alerting` is taken. Changing it makes the check new: its open problem is told as recovered and found again. |
| `about` | string | per kind | What recovered, as a noun phrase, for the all-clear: "the disk", "the nightly backup". |

Two checks of one kind need different keys.

Between runs, whimbrel compares each check's level and what its problems are about, not their
exact numbers, so the disk going from 85% to 86% full isn't news. Each kind below says what is.

### `disk`

How full the volume holding `path` is, by `df -P -k`: the number `df` shows a person.

```toml
[[check]]
kind = "disk"
path = "/"
suspects = ["/var/log", "/home", "/tmp"]
```

| Key | Type | Default | |
|---|---|---|---|
| `path` | string | required | Any path on the volume. On a Mac, `/System/Volumes/Data`: `/` is the sealed system volume. |
| `warn` | integer | `80` | WARN at this percent full. |
| `fail` | integer | `90` | FAIL at this percent. `warn` must be under `fail`, and `fail` at most 100. |
| `suspects` | array of paths | `[]` | When it's WARN or FAIL, the three biggest folders one level under these are named, by `du -d 1`. |
| `df` | path | `df` from `PATH` | |
| `du` | path | `du` from `PATH` | |

Default `about`: "the disk". News: the level changing.

### `file`

That each file is a plain file of one account and no more open than a mode. For files that hold
secrets on their way through, such as a provisioning log.

```toml
[[check]]
kind = "file"
key = "provision-log"
about = "the provisioning log's permissions"
paths = ["/var/log/cloud-init-output.log"]
```

| Key | Type | Default | |
|---|---|---|---|
| `paths` | array of absolute paths | required | Not followed if they're links: a link is "not a plain file". |
| `owner_uid` | integer | `0` | The account each must belong to. |
| `mode` | integer | `0o600` | The most open each may be. Extra bits, execute included, are FAIL. |

A file that isn't there is WARN, never OK. Default `about`: "the files' permissions". News: which
files are wrong.

### `secrets`

Lines in logs, and entries in the systemd journal, that match a [secret pattern](#secret-patterns). It's FAIL with a
count per log and never copies what matched, into an alert or anywhere else. A log it can't read
is WARN, never clean.

```toml
[[check]]
kind = "secrets"
logs = ["/var/log/cloud-init-output.log"]
optional_logs = ["/var/log/syslog*"]
log_dirs = ["/srv/app/logs"]
journal = true
```

| Key | Type | Default | |
|---|---|---|---|
| `logs` | array of absolute paths | `[]` | Logs that must be there: a missing one is WARN, unscanned. |
| `optional_logs` | array of absolute paths | `[]` | Logs scanned if they're there. The last part may end in `*`, which matches any rest of a name: `/var/log/syslog*` is `syslog`, `syslog.1` and `syslog.2.gz`. |
| `log_dirs` | array of absolute paths | `[]` | Every `*.log` under each, however deep. Links aren't followed. |
| `max_mb` | integer | `200` | A log bigger than this is WARN, unscanned: for a `.gz`, what it decompresses to. A log still growing is read as far as it reached when it was opened. |
| `journal` | bool | `false` | Also read the journal, with `journalctl`. |
| `journalctl` | path | `journalctl` from `PATH` | |
| `journal_secs` | integer | `600` | How long `journalctl` gets each run, from 1 to 86400. |

At least one of `logs`, `optional_logs`, `log_dirs` and `journal` must be set.

- Rotated logs count as one: `syslog`, `syslog.1` and `syslog.2.gz` are "syslog". `.gz` files are
  read compressed.
- A log is matched a line at a time, up to 1 MiB of a line at once. A longer line is read in
  1 MiB pieces, each counted as a line of its own, and a token that straddles two pieces isn't
  found. Nor is a token a program wrapped across two lines.
- Only regular files are read, never through a link, so a FIFO or a link to `/dev/zero` named
  `*.log` can't hang the run.
- The journal is read from where the last run stopped, using a cursor kept in the check's
  directory, and its hits are a running total. The first run reads the current boot. A total
  stays after a reboot, so a FAIL doesn't clear by itself: rotate the secret, then fix or remove
  the log, then delete the check's directory under `state_dir` to clear the journal's count.

Default `about`: "the secrets scan". News: another log with hits, and the total count rising, so
an ongoing leak alerts every run it grows.

### `journald-drops`

Units journald dropped lines from in the last hour. journald drops a unit's lines when it logs
faster than the rate limit, which usually means something is failing in a loop.

```toml
[[check]]
kind = "journald-drops"
units = '^(nginx|app@.*)\.service$'
```

| Key | Type | Default | |
|---|---|---|---|
| `units` | regex | every unit | Only units whose name matches. Unanchored: add `^` and `$` to match whole names. |
| `journalctl` | path | `journalctl` from `PATH` | |
| `timeout_secs` | integer | `120` | How long `journalctl` gets, from 1 to 86400. |

It reads journald's own "suppressed messages" notices (`MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e`)
from the last hour. A journal it can't read is WARN. Any process can log such a notice, so a unit
whose name isn't plain ASCII letters, digits and `._@+/-` is counted as "a unit with an unusual
name" rather than named. Default `about`: "the journal's dropped
lines". News: which units; not the counts, so a loop that goes on is told once and then by the
daily reminder.

### `command`

Runs a program and reads [result rows](#result-rows) from its stdout. This is how to watch
anything whimbrel has no kind for.

```toml
[[check]]
kind = "command"
key = "backup"
about = "the nightly backup"
program = "/usr/local/libexec/check-backup"
args = ["--max-age-hours", "26"]
user = "backup"
timeout_secs = 120
```

| Key | Type | Default | |
|---|---|---|---|
| `program` | absolute path | required | A relative path is refused. |
| `args` | array of strings | `[]` | Passed as they are, with no shell. |
| `user` | string | whimbrel's own | Run as this account: its uid, its primary group, and a group list of its primary group only, with real, effective and saved ids all switched so root can't be had back, and its home directory as `HOME`. It gets **no supplementary groups**, since looking them up isn't safe at the moment the account is switched: a program that needs a group's access must have that group as the account's primary group. Needs whimbrel to run as root, unless it names the account whimbrel already runs as. |
| `timeout_secs` | integer | `60` | From 1 to 86400. Killed after this, with its process group, and WARN. |
| `required_row` | string | none | A row that must always be there. See [Result rows](#result-rows). |

Before it runs, the configured path is walked a part at a time, following each link, and the
program is refused with a WARN that says why if:

- it isn't a regular file, or no one can execute it;
- it, any directory on the way to it, or any link on the way doesn't belong to root or to the
  account whimbrel runs as;
- its group or others can write it, or can write any directory on the way, unless that directory
  is sticky like `/tmp`. Anyone who can change the program, or which program a path leads to, can
  run code as whimbrel.

The checks see permission bits, not macOS ACLs: an ACL that lets another account write the program
or a directory above it isn't caught, so don't put one there.

The program runs in a process group of its own. When it exits, or at the timeout, the whole group
is killed, so nothing in its process group outlives it. Something it started that leaves the
group, with `setsid` or `setpgrp`, isn't killed: if it holds the program's output open for more
than 2 seconds after the program exits, that's a WARN saying so, and none of the output is read.

It runs with stdin empty, stderr discarded, the working directory `/`, and only `PATH`
(`/usr/bin:/bin:/usr/sbin:/sbin`), `HOME`, `USER` and `LOGNAME` set. Its exit status isn't read, so
a script that exits 1 when something is wrong works as is, but a program killed by a signal is
WARN even if its output looks whole. Its output is read the way `result-file` reads a file, up to
64 KiB.

Default `about`: "the command's result". News: as for result rows.

### `result-file`

Reads [result rows](#result-rows) another job left in a file. For checks whimbrel can't run itself:
ones that need a user's GUI session on a Mac, a different schedule, or another machine's results
copied over.

```toml
[[check]]
kind = "result-file"
key = "backup"
about = "the nightly backup"
path = "/var/lib/backup/result.tsv"
owner_uid = 34
max_age_mins = 1500
stale_see = "systemctl status backup.timer"
```

| Key | Type | Default | |
|---|---|---|---|
| `path` | absolute path | required | |
| `owner_uid` | integer | `0` | The account that writes it: the only one whose file is believed. |
| `max_age_mins` | integer | `90` | Older than this, WARN that whatever writes it may have stopped. |
| `stale_see` | string | `ls -l` of the file | The command an alert gives when the file is missing or stale. |
| `required_row` | string | none | A row that must always be there. See [Result rows](#result-rows). |

The file must be a plain file of `owner_uid` with no write bit for its group or others (the mode
check sees permission bits, not macOS ACLs), at most 64 KiB, not a link, and not dated more than
five minutes in the future. The writer should write a temporary file beside it and rename it over
the old one: a run that reads a half-written file warns until the next.

Default `about`: "the result file".

## Result rows

What `command` prints and `result-file` holds: UTF-8 text, one row per line, each four fields
separated by tabs, then a last line with `RESULT`, a tab and the worst level.

```text
LEVEL<TAB>NAME<TAB>WHAT<TAB>NEXT
...
RESULT<TAB>LEVEL
```

| Field | |
|---|---|
| `LEVEL` | `OK`, `WARN`, `FAIL`, or `SKIP` for a row not checked this time, which counts as OK. |
| `NAME` | What the row is about, unique in the output and stable across runs: `backup`, `replica lag`. At most 64 bytes. |
| `WHAT` | What's wrong, one sentence ending in a period. Empty is fine on an OK row. |
| `NEXT` | What to run, starting `See ` or `To fix: ` with the command in backticks, ending in a period. Empty is fine on an OK row. |

The whole output is read or none of it is. Each of these is one WARN about the output, saying
which, and none of its rows are shown:

- a line that isn't four fields or a `RESULT` line, a level that isn't one of the above, or a name
  that's empty or longer than 64 bytes;
- a name used twice;
- no `RESULT` line, or anything after it (a blank line included);
- `RESULT` saying a different level than the worst row;
- with `required_row` set, no row of that name.

Each WARN or FAIL row is a problem in the alert, its WHAT and NEXT shown as written, worst first,
then in the output's order, at most 10; more are counted in one more problem. The level is the
worst row's.

**The sentence rule.** A row is shown as written only if its WHAT is one sentence ending in a
period, its NEXT starts `See ` or `To fix: `, every backtick is closed, it has no dashes used as
punctuation, question or exclamation marks, control characters, line separators or format
characters (bidi marks, zero-width and invisible characters, the zero-width joiner among them,
the soft hyphen, tag characters), and the two together are at most 500 bytes. Because the joiner
is refused, some scripts and emoji sequences that need it aren't shown as written. Rows that
don't are not shown: they're counted, and a few named, in one problem that points at the output.
This is because the words come from whatever the program read, and an alert is something a
person may paste into a root shell. [Sentences](#sentences) has the rule in full.

**Links.** A row isn't shown as written if `://`, `www.` or `mailto:`, in any case, appears in its
WHAT or NEXT outside a code span, or anywhere in its name: those are the forms a channel is sure
to turn into a link. This doesn't catch everything a channel might link. A bare domain such as
`example.com/login` isn't caught, since refusing every dotted name would refuse file and host
names in honest rows. And the `bluebubbles` channel has no code spans, so a URL inside backticks
may still be tappable there.

**`required_row`.** A row that must always be there, usually the one that says whether the rest
could be checked at all, such as `ssh` for a script that checks another machine over SSH. Without
it the output is one WARN and none of its rows are read: a script that renamed the row would
otherwise break the watch silently. Its problem also sorts first among those of its level, and a
`SKIP` on it is a WARN, since a scheduled run never means to skip it.

News: the set of rows gone bad, each with its level, so another row going bad, or one going from
WARN to FAIL, is news. A row's name is part of that, so renaming a bad row is news once.

## Channels

Every channel takes:

| Key | Type | Default | |
|---|---|---|---|
| `kind` | string | required | `slack`, `bluebubbles` or `print`. |
| `name` | string | the kind | Unique among this host's channels. What each channel was told is kept under its name, so renaming one makes it new: it's told everything open. |

A secret file must be an absolute path, a regular file of the account running whimbrel, readable
by it alone (600), not a link, with the secret on its first line. It's read at each send, so a
rotated secret needs nothing restarted. Keep it in a directory only root can change. A failure to
send never names the file's path or contents.

Both real channels send with `curl`, handing it the URL and the message on stdin, so neither shows
in a process listing, with a 20-second limit.

### `slack`

Slack, by [incoming webhook](https://api.slack.com/messaging/webhooks). Gets the full form: every
problem, then each check's details, such as the biggest folders on a full disk.

| Key | Type | |
|---|---|---|
| `webhook_file` | secret file | Holds `https://hooks.slack.com/services/...`, and nothing else. |

`<`, `>` and `&` in an alert are escaped, so a name from the host can't become a mention.

### `bluebubbles`

iMessage to one person, through a [BlueBubbles](https://bluebubbles.app) server's API. Gets the
short form: the problems without details.

| Key | Type | |
|---|---|---|
| `server` | string | `http://` or `https://`, a host and an optional port: `http://127.0.0.1:1234`. No path or credentials. |
| `password_file` | secret file | The server's password: letters and digits only, since it goes in the query string. |
| `recipient_file` | secret file | A phone number in international form (`+15555550100`) or an Apple ID email. Never a chat GUID, so an alert can't land in a group chat. |

The request never goes through a proxy, whatever the environment says, since the password is in
its URL.

### `print`

Writes each alert to stdout. For trying a config out. A dry run puts one in place of every real
channel, under its name and form.

## The alerting check

With any channel configured, whimbrel adds a check under the key `alerting` that's WARN when a
channel can't send, such as when its secret file is missing or unreadable, so the other channels
carry the news. It's checked without sending.

## Sentences

Every WARN or FAIL whimbrel sends follows one rule, and rows from `command` and `result-file` are
held to it:

1. One plain sentence saying what's wrong.
2. One sentence starting `See ` or `To fix: ` with the command in backticks, so copying the
   command can't take the period with it.
3. No dashes as punctuation, no question or exclamation marks.
4. It never calls itself a check.

A sentence ends at a period followed by a space and a capital letter or a backtick; periods inside
backticks don't count. Names that come from the host (files, folders, units) are shown as they
are only if they're plain ASCII letters, digits and `._@+/-` and don't start with `-`, and are
otherwise described ("a log with an unusual name"), so a file named to look like a command can't
put one in an alert.
