# Config reference

whimbrel reads one TOML config file, which you name on the command line:

```sh
whimbrel run --config FILE       # check, tell each channel what changed, keep the ledger
whimbrel dry-run --config FILE   # say what each channel would be sent, and change nothing
whimbrel --version
```

The config file must belong to the account that runs whimbrel, and its group and other accounts
must not be able to write it. Mode 600 is appropriate. The file names programs that whimbrel
runs, often as root.

Every table refuses keys that it doesn't recognize, so a typo is an error and not a setting that
whimbrel silently ignores. An error message names the file and says what's wrong:

- For a TOML error or a top-level error, the message gives the key and the line. For a
  `[[channel]]` table, the line is the table's first line.
- For an error in a check, the message names the check by its number and kind instead, for
  example `check 2 (disk): warn must be under fail`.

An error message never repeats a value, in case the value is a secret that was pasted into the
wrong place. Where this page says that a path must be absolute, whimbrel refuses a relative path.

- [Top level](#top-level)
- [Secret patterns](#secret-patterns)
- [Checks](#checks): [`disk`](#disk), [`file`](#file), [`secrets`](#secrets),
  [`journald-drops`](#journald-drops), [`command`](#command), [`result-file`](#result-file)
- [Result rows](#result-rows)
- [Channels](#channels): [`slack`](#slack), [`bluebubbles`](#bluebubbles), [`print`](#print)
- [The alerting check](#the-alerting-check)
- [Sentences](#sentences)

## Top level

| Key | Type | Default | Description |
|---|---|---|---|
| `host` | string | required | The name that alerts use for this machine, for example "the web server" or "your Mac". whimbrel uses the name mid-sentence and capitalizes it at the start of a sentence. |
| `state_dir` | absolute path | required | The directory where whimbrel keeps what it told each channel, its lock, and each check's own state. If the directory is missing, whimbrel creates it with mode 700. whimbrel refuses a directory that another account owns or can write. |
| `log_file` | absolute path | stdout | The file to which whimbrel appends each run's one log line. If the file is missing, whimbrel creates it with mode 600. |
| `curl` | path | `curl` from `PATH` | The `curl` program that the `slack` and `bluebubbles` channels use to send. |
| `[secret_patterns]` | table | built-ins on | What a secret looks like on this host. See [Secret patterns](#secret-patterns). |
| `[[check]]` | array of tables | none | The checks, in the order in which whimbrel runs them and alerts list them. |
| `[[channel]]` | array of tables | none | Where alerts go. With no channels, `run` checks and logs but sends no alerts. |

whimbrel refuses a config file that contains a Slack webhook URL anywhere. Put the URL in a
separate file, and name that file in the config file.

## Secret patterns

```toml
[secret_patterns]
builtins = true
disable = ["stripe-access-token"]
patterns = ['myco_[0-9a-f]{40}']
```

| Key | Type | Default | Description |
|---|---|---|---|
| `builtins` | Boolean | `true` | Whether to use the built-in patterns. To turn off all of them, set this key to `false`. |
| `disable` | array of ids | `[]` | The ids of built-in patterns to leave out. The built-in patterns are published shapes, and on some hosts some of them match ordinary ids that share a token's prefix. When the `secrets` check reports a match that isn't a secret, its alert names the pattern's id; list that id here. whimbrel refuses an id that isn't in the table of built-in patterns, even when `builtins = false`, but accepts the id of a built-in pattern that a later release removed. Such an id turns nothing off, and whimbrel prints a warning about it to stderr each time it starts. Listing an id twice has the same effect as listing it once, and listing every id has the same effect as `builtins = false`. |
| `patterns` | array of regexes | `[]` | Additional patterns, in [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax). whimbrel matches them as written, including Unicode classes. whimbrel refuses a pattern that is invalid or that can match empty text, and the error message doesn't repeat the pattern. |

whimbrel uses the patterns in two ways:

- **Redaction.** Before a channel or a file receives any text, whimbrel replaces every match in
  an alert, in the reason for a failed send, and in the ledger with `[redacted]`, regardless of
  which check wrote the text. Redaction matters most for `command` and `result-file`, because
  their rows contain text from outside whimbrel.
- **The [`secrets`](#secrets) check.** The check counts the lines that contain a match.

If you turn off the built-in patterns and set no `patterns` of your own, whimbrel redacts nothing
and refuses a `secrets` check.

### Built-in patterns

The built-in patterns are every rule from three published lists that passes one test. whimbrel
takes the lists in the following order: gitleaks, betterleaks, and Google's osv-scalibr.
`THIRD-PARTY.md` records the commit of each list and its license. The rules that don't pass, and
why, are listed in
[`src/secret_patterns/left-out.md`](../src/secret_patterns/left-out.md).

A rule passes the test if all of the following are true:

- The rule's token compiles in Rust's regex engine. The token is the rule without the boundary
  that a list matches after the token.
- The token starts the match. A rule that requires a keyword near the token doesn't pass.
- Every string that the token can match starts with the same three or more fixed characters.
- The token can't match fewer than 16 characters, so it doesn't match ordinary words and log
  lines.
- The token is a shape, not one fixed string.
- No rule from an earlier list already matches an example that is generated from the token.

whimbrel doesn't choose patterns by service. As a result, patterns for some services that you use
might be missing, and some patterns match text that isn't secret, such as a service's public URL.
To add a missing pattern, use `patterns`. To turn off a noisy pattern, use `disable`.

One pattern is whimbrel's own: `password-in-url`, which matches the password that the
`bluebubbles` channel sends in its URL.

Each built-in pattern matches as its source publishes it, with one exception: `\w`, `\d`, and
`(?i)` in built-in patterns have their ASCII meanings. Every token is ASCII, and the Unicode
tables would make a few hundred patterns use hundreds of megabytes of memory. Your own `patterns`
match as written, including Unicode.

<!-- BEGIN generated by tools/secret-patterns: the built-in patterns. Don't edit. -->

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

<!-- END generated -->

## Checks

Every check takes the following keys in addition to its own:

| Key | Type | Default | Description |
|---|---|---|---|
| `kind` | string | required | One of the kinds in this section. |
| `key` | string | the kind's name | A name for the check that is stable and unique on this host. Use lowercase letters, digits, and dashes, because the key names the check's own directory under `state_dir`. The key `alerting` is reserved. If you change a key, whimbrel treats the check as new: it reports the check's open problem as recovered and then reports the problem again. |
| `about` | string | per kind | A noun phrase that says what recovered, for the all-clear message. For example, "the disk" or "the nightly backup". |

If you configure two checks of the same kind, give them different keys.

On this page, *news* means a change that whimbrel reports. Between runs, whimbrel compares each
check's level and what its problems are about, not the exact numbers. For example, a disk that
goes from 85% to 86% full isn't news. Each kind's section says what counts as news for that kind.

### `disk`

The `disk` check reports how full the volume that contains `path` is. It uses `df -P -k`, so the
percentage is the one that `df` displays.

```toml
[[check]]
kind = "disk"
path = "/"
suspects = ["/var/log", "/home", "/tmp"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `path` | string | required | Any path on the volume. On a Mac, use `/System/Volumes/Data`, because `/` is the sealed system volume. |
| `warn` | integer | `80` | The percent full at which the check is `WARN`. |
| `fail` | integer | `90` | The percent full at which the check is `FAIL`. `warn` must be less than `fail`, and `fail` must be at most 100. |
| `suspects` | array of paths | `[]` | When the check is `WARN` or `FAIL`, the alert names the three largest folders one level under these paths, as measured by `du -d 1`. |
| `df` | path | `df` from `PATH` | The `df` program to use. |
| `du` | path | `du` from `PATH` | The `du` program to use. |

- **Default `about`:** "the disk"
- **News:** The level changes.

### `file`

The `file` check verifies that each file is a regular file, belongs to one account, and has
permissions no broader than a given mode. Use it for files that can temporarily contain secrets,
such as a provisioning log.

```toml
[[check]]
kind = "file"
key = "provision-log"
about = "the provisioning log's permissions"
paths = ["/var/log/cloud-init-output.log"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `paths` | array of absolute paths | required | The files to check. whimbrel doesn't follow links. It reports a link as "not a plain file". |
| `owner_uid` | integer | `0` | The uid of the account that each file must belong to. |
| `mode` | integer | `0o600` | The broadest permissions that each file can have. Any additional bit, including an execute bit, is `FAIL`. |

A missing file is `WARN`, never `OK`.

- **Default `about`:** "the files' permissions"
- **News:** The set of files that are wrong changes.

### `secrets`

The `secrets` check finds lines in logs, and entries in the systemd journal, that match a [secret
pattern](#secret-patterns). When it finds a match, the check is `FAIL`, and for each log it gives
the number of lines with a match and the patterns that matched. It never copies the matched text
into an alert or anywhere else. A log that the check can't read is `WARN`, never clean.

An alert looks like this:

```text
Something on the web server logged a secret, so rotate it and find what logged it: 5 in syslog
matched `github-pat` and `slack-bot-token`; 2 in the journal matched one of your own patterns.
```

The alert names patterns as follows:

- A built-in pattern by its id, in code font. The id tells you which kind of key to rotate. If
  the match isn't a secret, list the id in [`disable`](#secret-patterns).
- One of your own `patterns` as "one of your own patterns", never by the pattern itself, since a
  pattern can describe what a secret looks like.
- At most three patterns for each log, with the number of others. The full form of the alert,
  which Slack gets, lists every pattern with its count for each log.
- A line that two patterns match counts once in the log's total, and once for each pattern.

```toml
[[check]]
kind = "secrets"
logs = ["/var/log/cloud-init-output.log"]
optional_logs = ["/var/log/syslog*"]
log_dirs = ["/srv/app/logs"]
journal = true
```

| Key | Type | Default | Description |
|---|---|---|---|
| `logs` | array of absolute paths | `[]` | Logs that must exist. A missing log is `WARN`, and whimbrel reports it as unscanned. |
| `optional_logs` | array of absolute paths | `[]` | Logs that whimbrel scans if they exist. The last path component can end in `*`, which matches the rest of a filename. For example, `/var/log/syslog*` matches `syslog`, `syslog.1`, and `syslog.2.gz`. |
| `log_dirs` | array of absolute paths | `[]` | Directories in which whimbrel scans every `*.log` file, at any depth. whimbrel doesn't follow links. |
| `max_mb` | integer | `200` | The largest log, in megabytes, that whimbrel scans. A larger log is `WARN`, and whimbrel reports it as unscanned. For a `.gz` file, the limit applies to the decompressed size. whimbrel reads a log that is still growing only up to the size that the log had when whimbrel opened it. |
| `journal` | Boolean | `false` | Whether to also read the journal, by using `journalctl`. |
| `journalctl` | path | `journalctl` from `PATH` | The `journalctl` program to use. |
| `journal_secs` | integer | `600` | The time limit for `journalctl` in each run, in seconds, from 1 to 86400. |

You must set at least one of `logs`, `optional_logs`, `log_dirs`, and `journal`.

The check reads logs and the journal as follows:

- Rotated logs count as one log. For example, `syslog`, `syslog.1`, and `syslog.2.gz` are all
  "syslog". whimbrel decompresses `.gz` files as it reads them.
- whimbrel matches a log one line at a time, up to 1 MiB of a line at once. It reads a longer line
  in 1 MiB pieces and counts each piece as a separate line. It doesn't find a token that spans two
  pieces, or a token that a program wrapped across two lines.
- whimbrel reads only regular files, and never reads through a link. As a result, a FIFO or a link
  to `/dev/zero` that is named `*.log` can't hang the run.
- whimbrel reads the journal from where the previous run stopped, by using a cursor that it keeps
  in the check's directory. The journal's hit count is a running total, kept with the id of each
  pattern that matched and its count, and never the matched text. The first run reads the current
  boot.

The journal's total persists across a reboot, so a `FAIL` doesn't clear by itself. To clear it, do
the following:

1. Rotate the secret.
2. Fix or remove the log.
3. Delete the check's directory under `state_dir`, which clears the journal's count.

- **Default `about`:** "the secrets scan"
- **News:** Another log has hits, or the total count rises. An ongoing leak therefore causes an
  alert on every run in which the count grows. A different pattern matching in a log that already
  has hits isn't news by itself; it's news when it raises the count.

### `journald-drops`

The `journald-drops` check reports the units whose log lines journald dropped in the last hour.
journald drops a unit's lines when the unit logs faster than the rate limit, which usually means
that something is failing in a loop.

```toml
[[check]]
kind = "journald-drops"
units = '^(nginx|app@.*)\.service$'
```

| Key | Type | Default | Description |
|---|---|---|---|
| `units` | regex | every unit | Report only the units whose names match. The pattern is unanchored. To match whole names, add `^` and `$`. |
| `journalctl` | path | `journalctl` from `PATH` | The `journalctl` program to use. |
| `timeout_secs` | integer | `120` | The time limit for `journalctl`, in seconds, from 1 to 86400. |

The check reads journald's own "suppressed messages" notices
(`MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e`) from the last hour. A journal that the check can't
read is `WARN`.

Any process can log such a notice. For that reason, if a unit's name contains anything other than
ASCII letters, digits, and the characters `._@+/-`, the alert calls it "a unit with an unusual
name" and doesn't show the name.

- **Default `about`:** "the journal's dropped lines"
- **News:** The set of units changes. The counts aren't news, so whimbrel reports a continuing
  loop once and then in the daily reminder.

### `command`

The `command` check runs a program and reads [result rows](#result-rows) from the program's
stdout. Use it to watch anything that whimbrel has no kind for.

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

| Key | Type | Default | Description |
|---|---|---|---|
| `program` | absolute path | required | The program to run. whimbrel refuses a relative path. |
| `args` | array of strings | `[]` | Arguments for the program. whimbrel passes them unchanged, without a shell. |
| `user` | string | whimbrel's own account | The account to run the program as. whimbrel switches to the account's uid and primary group, sets the group list to the primary group only, and sets `HOME` to the account's home directory. It switches the real, effective, and saved ids, so the program can't regain root. The program gets **no supplementary groups**, because looking them up isn't safe at the moment that whimbrel switches accounts. If the program needs a group's access, make that group the account's primary group. To use `user`, whimbrel must run as root, unless `user` names the account that whimbrel already runs as. |
| `timeout_secs` | integer | `60` | The time limit, in seconds, from 1 to 86400. At the limit, whimbrel kills the program and its process group, and the check is `WARN`. |
| `required_row` | string | none | The name of a row that must always be present. See [Result rows](#result-rows). |

Before whimbrel runs the program, it walks the configured path one component at a time and
follows each link. whimbrel refuses the program, with a `WARN` that gives the reason, in any of
the following cases:

- The program isn't a regular file, or no one can execute it.
- The program, a directory on the path to it, or a link on the path to it doesn't belong to root
  or to the account that whimbrel runs as.
- The program's group or other accounts can write the program, or can write a directory on the
  path to it, unless that directory is sticky, like `/tmp`.

Anyone who can change the program, or change which program a path leads to, can run code as
whimbrel.

These checks read permission bits, not macOS ACLs. whimbrel doesn't detect an ACL that lets
another account write the program or a directory above it, so don't set one.

The program runs in its own process group. When the program exits, or at the timeout, whimbrel
kills the whole group, so nothing in the group outlives the program. whimbrel doesn't kill a
process that the program starts and that leaves the group by using `setsid` or `setpgrp`. If such
a process holds the program's output open for more than 2 seconds after the program exits, the
check is `WARN` with a message that says so, and whimbrel reads none of the output.

The program runs with the following environment:

- Stdin is empty, and stderr is discarded.
- The working directory is `/`.
- Only `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`), `HOME`, `USER`, and `LOGNAME` are set.

whimbrel doesn't read the program's exit status, so a script that exits with status 1 when
something is wrong works without changes. However, a program that a signal kills is `WARN`, even
if its output looks complete. whimbrel reads the output the same way that `result-file` reads a
file, up to 64 KiB.

- **Default `about`:** "the command's result"
- **News:** The same as for [result rows](#news).

### `result-file`

The `result-file` check reads [result rows](#result-rows) that another job wrote to a file. Use
it for checks that whimbrel can't run itself, such as the following:

- A check that needs a user's GUI session on a Mac
- A check that runs on a different schedule
- Results that are copied from another machine

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

| Key | Type | Default | Description |
|---|---|---|---|
| `path` | absolute path | required | The file to read. |
| `owner_uid` | integer | `0` | The uid of the account that writes the file. whimbrel trusts the file only if this account owns it. |
| `max_age_mins` | integer | `90` | The maximum age of the file, in minutes. For an older file, the check is `WARN` and says that whatever writes the file might have stopped. |
| `stale_see` | string | `ls -l` of the file | The command that an alert gives when the file is missing or stale. |
| `required_row` | string | none | The name of a row that must always be present. See [Result rows](#result-rows). |

The file must meet all of the following requirements:

- It is a regular file that belongs to `owner_uid`, and it isn't a link.
- Its group and other accounts can't write it. The check reads permission bits, not macOS ACLs.
- It is at most 64 KiB.
- Its modification time isn't more than five minutes in the future.

To avoid a partial read, have the writer write a temporary file in the same directory and then
rename it over the old file. If a run reads a half-written file, the check warns until the next
run.

- **Default `about`:** "the result file"
- **News:** The same as for [result rows](#news).

## Result rows

Result rows are what a `command` program prints and what a `result-file` file contains. The
format is UTF-8 text with one row per line. Each row has four fields that are separated by tabs.
The last line contains `RESULT`, a tab, and the worst level.

```text
LEVEL<TAB>NAME<TAB>WHAT<TAB>NEXT
...
RESULT<TAB>LEVEL
```

| Field | Description |
|---|---|
| `LEVEL` | `OK`, `WARN`, `FAIL`, or `SKIP`. Use `SKIP` for a row that wasn't checked in this run. `SKIP` counts as `OK`. |
| `NAME` | What the row is about, for example `backup` or `replica lag`. The name must be unique in the output, stable across runs, and at most 64 bytes. |
| `WHAT` | What's wrong, as one sentence that ends in a period. This field can be empty on an `OK` row. |
| `NEXT` | What to run. The text starts with `See ` or `To fix: `, has the command in backticks, and ends in a period. This field can be empty on an `OK` row. |

whimbrel reads the whole output or none of it. In each of the following cases, the check is one
`WARN` about the output that says which case applies, and whimbrel shows none of the rows:

- A line isn't four fields or a `RESULT` line, a level isn't one of the levels in the table, or a
  name is empty or longer than 64 bytes.
- Two rows have the same name.
- The output has no `RESULT` line, or it has anything after the `RESULT` line, including a blank
  line.
- The `RESULT` line gives a level that differs from the worst row's level.
- `required_row` is set, and no row has that name.

Each `WARN` or `FAIL` row is a problem in the alert, and whimbrel shows the row's `WHAT` and
`NEXT` as written. whimbrel lists the worst problems first and otherwise keeps the output's
order. It shows at most 10 problems and counts the rest in one additional problem. The check's
level is the worst row's level.

### The sentence rule

whimbrel shows a row as written only if all of the following are true:

- Its `WHAT` is one sentence that ends in a period.
- Its `NEXT` starts with `See ` or `To fix: `.
- Every backtick is closed.
- It contains none of the following: dashes used as punctuation, question marks, exclamation
  marks, control characters, line separators, or format characters. Format characters include
  bidirectional marks, zero-width and invisible characters (including the zero-width joiner), the
  soft hyphen, and tag characters.
- Its `WHAT` and `NEXT` together are at most 500 bytes.

Because whimbrel refuses the zero-width joiner, it doesn't show as written some scripts and emoji
sequences that need the joiner.

whimbrel doesn't show the rows that break the rule. It counts them, and names a few of them, in
one problem that points to the output.

The rule exists because the text comes from whatever the program read, and a person might paste
text from an alert into a root shell. For the full rule, see [Sentences](#sentences).

### Links

whimbrel doesn't show a row as written if `://`, `www.`, or `mailto:`, in any letter case, appears
in its `WHAT` or `NEXT` outside a code span, or anywhere in its name. Those are the forms that a
channel is certain to turn into a link.

This rule doesn't catch everything that a channel might turn into a link:

- A bare domain such as `example.com/login` isn't caught, because refusing every dotted name
  would refuse the file names and host names in legitimate rows.
- The `bluebubbles` channel has no code spans, so a URL inside backticks might still be tappable
  there.

### The required row

`required_row` names a row that must always be present. It's usually the row that says whether
the rest could be checked at all, such as `ssh` for a script that checks another machine over SSH.

If the row is missing, the check is one `WARN`, and whimbrel reads none of the rows. Without this
rule, a script that renamed the row would silently break the watch.

The required row's problem sorts first among the problems of its level. A `SKIP` on the required
row is a `WARN`, because a scheduled run never intends to skip it.

### News

For result rows, news is a change in the set of bad rows, each with its level. For example,
another row going bad is news, and so is a row going from `WARN` to `FAIL`. A row's name is part
of the set, so renaming a bad row is news once.

## Channels

Every channel takes the following keys:

| Key | Type | Default | Description |
|---|---|---|---|
| `kind` | string | required | `slack`, `bluebubbles`, or `print`. |
| `name` | string | the kind | A name that is unique among this host's channels. whimbrel keeps what it told each channel under the channel's name. If you rename a channel, whimbrel treats it as new and tells it about every open problem. |

Some keys name a *secret file*. A secret file must meet all of the following requirements:

- Its path is absolute.
- It is a regular file that belongs to the account that runs whimbrel, and it isn't a link.
- Only that account can read it (mode 600).
- The secret is on its first line.

whimbrel reads the file at each send, so you don't need to restart anything after you rotate a
secret. Keep the file in a directory that only root can change. When a send fails, the reason
never includes the file's path or contents.

The `slack` and `bluebubbles` channels send with `curl`. They pass the URL and the message to
`curl` on stdin, so neither appears in a process listing. Each send has a 20-second limit.

### `slack`

The `slack` channel sends to Slack through an [incoming
webhook](https://api.slack.com/messaging/webhooks). It gets the full form of an alert: every
problem, followed by each check's details, such as the largest folders on a full disk.

| Key | Type | Description |
|---|---|---|
| `webhook_file` | secret file | A file that contains a `https://hooks.slack.com/services/...` URL and nothing else. |

whimbrel escapes `<`, `>`, and `&` in an alert, so a name from the host can't become a mention.

### `bluebubbles`

The `bluebubbles` channel sends an iMessage to one person through the API of a
[BlueBubbles](https://bluebubbles.app) server. It gets the short form of an alert: the problems
without details.

| Key | Type | Description |
|---|---|---|
| `server` | string | The server's URL: `http://` or `https://`, a host, and an optional port. For example, `http://127.0.0.1:1234`. The URL can't include a path or credentials. |
| `password_file` | secret file | The server's password. The password can contain only letters and digits, because whimbrel sends it in the query string. |
| `recipient_file` | secret file | A phone number in international form, such as `+15555550100`, or an Apple ID email address. whimbrel doesn't accept a chat GUID, so an alert can't go to a group chat. |

The request never goes through a proxy, regardless of the environment's proxy settings, because
the password is in the URL.

### `print`

The `print` channel writes each alert to stdout. Use it to try out a config file. In a dry run,
whimbrel replaces every real channel with a `print` channel that has the same name and form.

## The alerting check

When you configure any channel, whimbrel adds a check with the key `alerting`. The check is `WARN`
when a channel can't send, for example when the channel's secret file is missing or unreadable.
The other channels then report the problem. whimbrel performs this check without sending
anything.

## Sentences

Every `WARN` or `FAIL` that whimbrel sends follows one rule, and whimbrel holds rows from
`command` and `result-file` to the same rule. Each problem is two sentences, in the following
order:

1. One plain sentence that says what's wrong.
2. One sentence that starts with `See ` or `To fix: ` and has the command in backticks, so that
   copying the command can't include the period.

In addition, both sentences follow these rules:

- They don't use dashes as punctuation, question marks, or exclamation marks.
- They never call themselves a check.

A sentence ends at a period that is followed by a space and then a capital letter or a backtick.
Periods inside backticks don't count.

whimbrel shows a name that comes from the host, such as a file, folder, or unit name, only if the
name consists of ASCII letters, digits, and the characters `._@+/-`, and doesn't start with `-`.
Otherwise, whimbrel describes the name, for example "a log with an unusual name". As a result, a
file whose name looks like a command can't put that command in an alert.
