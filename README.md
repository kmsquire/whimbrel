# whimbrel

A friendly watch for your hosts.

whimbrel checks a machine on a schedule and tells you when something changes. It sends one alert
when a problem starts, one when the problem is fixed, and a daily reminder while the problem
remains.

whimbrel has checks for the following:

- Disk usage
- File ownership and permissions
- Secrets that leak into logs
- Log lines that journald drops

It also reads results from your own scripts, so it can watch anything that you can check from a
shell.

whimbrel remembers what it told each alert channel. If an alert doesn't get through, the next
alert that does get through says what you missed, including problems that started and ended in
between. A recovery is never lost.

whimbrel is designed for a small server or a home machine:

- It runs once per invocation from your scheduler: a systemd timer, launchd, or cron.
- It keeps its state in one directory.
- It sends alerts to a Slack incoming webhook, or to iMessage through a BlueBubbles server.
- It reads secrets from files that you name. You never write a secret in the config file.

## What an alert looks like

The following alert reports two problems:

```text
Needs you soon:
The web server's disk is 93% full. See `df -h /`.
The nightly backup hasn't finished since yesterday. See `journalctl -u backup`.
```

When both problems are fixed, whimbrel sends the following:

```text
All clear on the web server: the disk and the nightly backup are back to normal.
```

Each problem is one plain sentence that says what's wrong, followed by one sentence that says
what to run, with the command in backticks.

## Install whimbrel

Each release includes an archive for each of the following targets, with a checksum and build
provenance. The Linux binaries are statically linked, so they run on any distribution. The macOS
binaries require macOS 13 or later.

| Machine | Target |
|---|---|
| Linux, ARM | `aarch64-unknown-linux-musl` |
| Linux, x86-64 | `x86_64-unknown-linux-musl` |
| Mac, Apple silicon | `aarch64-apple-darwin` |
| Mac, Intel | `x86_64-apple-darwin` |

To download, verify, and unpack a release, set `t` to the target for your machine and run the
following commands:

```sh
v=0.3.0 t=x86_64-unknown-linux-musl
curl -LO https://github.com/kmsquire/whimbrel/releases/download/v$v/whimbrel-$v-$t.tar.gz
gh attestation verify whimbrel-$v-$t.tar.gz --repo kmsquire/whimbrel \
  --signer-workflow kmsquire/whimbrel/.github/workflows/ci.yml --source-ref refs/tags/v$v
tar xzf whimbrel-$v-$t.tar.gz
```

Because whimbrel runs as root, make sure that only root can change the binary. Every directory
from `/` down to the binary must belong to root and be writable by root alone. On a Mac that has Homebrew,
`/usr/local/bin` belongs to your own account, so the Mac path in the following commands is a
directory that only whimbrel uses.

To create the directory and check its ownership, run the following commands:

```sh
B=/usr/local/bin        # Mac: B=/opt/whimbrel/bin
sudo install -d -m 755 "$B"
d=$B; until [ "$d" = / ]; do
  ls -ld "$d" | awk -v d="$d" '$3 != "root" || substr($1, 6, 1) == "w" || substr($1, 9, 1) == "w" {
    print d " must belong to root and be writable by root alone" }'
  d=$(dirname "$d")
done
```

If the commands print anything, fix the directory that the output names, or choose another value
for `B`, before you continue. Then install the binary:

```sh
sudo install -m 755 whimbrel-$v-$t/whimbrel "$B/"
```

On any other platform, build whimbrel with a Rust toolchain:

```sh
cargo install --locked --git https://github.com/kmsquire/whimbrel --tag v0.3.0
```

## Send your first alert

The following steps set up whimbrel to run hourly as root. whimbrel keeps its config and secret
files in one directory, which the steps call `W`.

| Item | Linux | Mac |
|---|---|---|
| `W`, the config file and its secret files | `/etc/whimbrel` | `/Library/Application Support/whimbrel` |
| `state_dir` | `/var/lib/whimbrel` | `/Library/Application Support/whimbrel/state` |
| The disk to watch | `/` | `/System/Volumes/Data`, because `/` is the sealed system volume |
| The binary | `/usr/local/bin/whimbrel` | `/opt/whimbrel/bin/whimbrel` |
| The schedule | A systemd timer | A LaunchDaemon |

The examples use the Linux paths. On a Mac, use the paths in the Mac column.

1. Create the config file, and make it readable and writable by root alone. whimbrel refuses a
   config file that another account can write, because the config file names programs that
   whimbrel runs.

   Create the file and open it in an editor:

   ```sh
   W=/etc/whimbrel        # Mac: W="/Library/Application Support/whimbrel"
   sudo install -d -m 700 "$W"
   sudo install -m 600 /dev/null "$W/whimbrel.toml"
   sudo -e "$W/whimbrel.toml"
   ```

   Add the following configuration:

   ```toml
   host = "the web server"
   state_dir = "/var/lib/whimbrel"

   [[check]]
   kind = "disk"
   path = "/"
   warn = 1     # so the first run has something to say
   fail = 99

   [[channel]]
   kind = "print"
   ```

2. Test the configuration with a dry run. A dry run shows what whimbrel would send to each
   channel, and it changes nothing.

   ```sh
   sudo "$B/whimbrel" dry-run --config "$W/whimbrel.toml"
   ```

   The command prints the run's summary line, `WARN disk=WARN alerting=OK`, followed by the
   alert.

3. Send the alert to Slack. Create a Slack app that has an [incoming
   webhook](https://api.slack.com/messaging/webhooks), and then put the webhook URL in a file that
   only root can read:

   ```sh
   sudo install -m 600 /dev/null "$W/slack-webhook"
   sudo -e "$W/slack-webhook"
   ```

   In the config file, replace the `print` channel with a `slack` channel that gives the file's
   full path:

   ```toml
   [[channel]]
   kind = "slack"
   webhook_file = "/etc/whimbrel/slack-webhook"
   ```

   whimbrel refuses a config file that contains a webhook URL.

4. Run whimbrel:

   ```sh
   sudo "$B/whimbrel" run --config "$W/whimbrel.toml"
   ```

   The alert arrives in Slack. If you run the command again, whimbrel sends nothing, because
   nothing changed. To get the all-clear message, delete the `warn` and `fail` lines so that the
   defaults apply, and then run the command again.

5. Schedule whimbrel to run hourly.

   On Linux, create a systemd service and a timer:

   ```ini
   # /etc/systemd/system/whimbrel.service
   [Service]
   Type=oneshot
   ExecStart=/usr/local/bin/whimbrel run --config /etc/whimbrel/whimbrel.toml

   # /etc/systemd/system/whimbrel.timer
   [Timer]
   OnCalendar=hourly
   Persistent=true

   [Install]
   WantedBy=timers.target
   ```

   Then enable the timer:

   ```sh
   sudo systemctl daemon-reload && sudo systemctl enable --now whimbrel.timer
   ```

   On a Mac, save the following LaunchDaemon as `/Library/LaunchDaemons/whimbrel.plist`. The file
   must belong to root and have mode 644.

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>Label</key><string>whimbrel</string>
     <key>ProgramArguments</key>
     <array>
       <string>/opt/whimbrel/bin/whimbrel</string>
       <string>run</string>
       <string>--config</string>
       <string>/Library/Application Support/whimbrel/whimbrel.toml</string>
     </array>
     <key>StartInterval</key><integer>3600</integer>
     <key>StandardOutPath</key><string>/Library/Logs/whimbrel.log</string>
     <key>StandardErrorPath</key><string>/Library/Logs/whimbrel.log</string>
   </dict>
   </plist>
   ```

   Then load the LaunchDaemon:

   ```sh
   sudo launchctl bootstrap system /Library/LaunchDaemons/whimbrel.plist
   ```

   To use cron instead, add the following line to root's crontab:

   ```text
   0 * * * * /usr/local/bin/whimbrel run --config /etc/whimbrel/whimbrel.toml
   ```

After you receive your first alert, add the checks that you want. For every key, see the [config
reference](docs/config.md).

## Checks

| Kind | What it watches |
|---|---|
| `disk` | How full a volume is. When the volume is nearly full, the alert names the largest folders. |
| `file` | Whether files belong to one account and have permissions no broader than a given mode. |
| `secrets` | Token-shaped strings in logs and in the journal. The alert gives counts only, never the matched text. |
| `journald-drops` | Units whose log lines journald dropped in the last hour because the units log in a loop. |
| `command` | Your own program, which prints result rows. |
| `result-file` | Result rows that another job wrote to a file. |

To watch anything else, use `command` or `result-file`. Write a script that prints one row for
each thing that it checks, followed by a `RESULT` line that gives the worst level:

```text
OK	backup	The backup finished.	
FAIL	replica	The replica is 3 hours behind.	See `psql -c 'select now() - pg_last_xact_replay_timestamp()'`.
RESULT	FAIL
```

Each row has four tab-separated fields: the level, a name, what's wrong, and what to run. whimbrel
shows the text of each `WARN` or `FAIL` row as written if the row follows the sentence rule, and
it counts the rows that don't.

- Use `command` when whimbrel can run the script itself, optionally as another account.
- Use `result-file` when the script must run where whimbrel can't, for example in a user's GUI
  session on a Mac. The script writes its rows to a file, and whimbrel reads the file.

For details, see [Result rows](docs/config.md#result-rows).

## Redaction

whimbrel redacts every alert, and every reason that a send failed, before a channel or the log
receives it. whimbrel includes a few hundred built-in token patterns: every prefix-anchored rule
from three published secret-scanning lists. You can add your own patterns or turn off any built-in
pattern. For the list of patterns, see [Secret patterns](docs/config.md#secret-patterns). The
list is generated from the published lists by a tool in this repository; to move it to a newer
release of a list, see [tools/secret-patterns](tools/secret-patterns/README.md).

## Exit status

The `run` command exits with one of the following statuses:

| Status | Meaning |
|---|---|
| 0 | The run completed. This includes a run in which a send failed, because the next run retries the send. |
| 1 | The run completed, but whimbrel couldn't save its state. |
| 2 | whimbrel couldn't start, for example because it refused the config file. |

Each run writes one line to the log. The log is stdout unless you set `log_file`.

```text
2026-11-24T10:00:00Z WARN disk=WARN alerting=OK; slack: sent
```

When a send fails, the log line contains `alert failed` and the reason. To monitor whimbrel
itself, search the log for that text.

## Stability

The stable interface is the command line, the config file format, and the result-row format. The
crate's Rust items are public only so that the crate's own tests can use them. They aren't a
library API, and they can change in any release. whimbrel isn't published to crates.io.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT
license](LICENSE-MIT), at your option. The built-in secret patterns are adapted from gitleaks and
betterleaks, under the MIT license, and from osv-scalibr, under Apache-2.0; see
[THIRD-PARTY.md](THIRD-PARTY.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
whimbrel by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
