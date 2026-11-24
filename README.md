# whimbrel

A friendly watch for your hosts.

whimbrel checks a machine on a schedule and tells you when something changes: once when it goes
wrong, once when it's fixed, and a reminder a day while it stays broken. It checks disks, file
permissions, logs for leaked secrets and journald dropping lines, and it reads results from your
own scripts, so anything you can check from a shell, it can watch.

It remembers what each alert channel was actually told. If an alert didn't get through, the next
one that does says what you missed, including problems that came and went in between, and a
recovery is never lost.

It's for a small server or a home machine. It runs once per invocation from your scheduler (a
systemd timer, launchd or cron), keeps its state in one directory, and sends to a Slack incoming
webhook or to iMessage through a BlueBubbles server. Secrets are read from files you point it at,
never written in its config.

## What an alert looks like

```text
Needs you soon:
The web server's disk is 93% full. See `df -h /`.
The nightly backup hasn't finished since yesterday. See `journalctl -u backup`.
```

and later, when both are fixed:

```text
All clear on the web server: the disk and the nightly backup are back to normal.
```

Every problem is one plain sentence saying what's wrong, then one saying what to run about it,
with the command in backticks.

## Install

Each release has an archive for Linux on ARM and on x86-64 (statically linked, so any
distribution) and for macOS 13 or later on Apple silicon and on Intel, with a checksum and build
provenance. Pick the target for your machine:

| Machine | Target |
|---|---|
| Linux, ARM | `aarch64-unknown-linux-musl` |
| Linux, x86-64 | `x86_64-unknown-linux-musl` |
| Mac, Apple silicon | `aarch64-apple-darwin` |
| Mac, Intel | `x86_64-apple-darwin` |

```sh
v=0.3.0 t=x86_64-unknown-linux-musl
curl -LO https://github.com/kmsquire/whimbrel/releases/download/v$v/whimbrel-$v-$t.tar.gz
gh attestation verify whimbrel-$v-$t.tar.gz --repo kmsquire/whimbrel \
  --signer-workflow kmsquire/whimbrel/.github/workflows/ci.yml --source-ref refs/tags/v$v
tar xzf whimbrel-$v-$t.tar.gz
```

whimbrel runs as root, so it must live where only root can change it: every directory from `/`
down to it must belong to root and be writable by root alone. On a Mac with Homebrew,
`/usr/local/bin` belongs to your own account, so the Mac path below is a directory of whimbrel's
own:

```sh
B=/usr/local/bin        # Mac: B=/opt/whimbrel/bin
sudo install -d -m 755 "$B"
d=$B; until [ "$d" = / ]; do
  ls -ld "$d" | awk -v d="$d" '$3 != "root" || substr($1, 6, 1) == "w" || substr($1, 9, 1) == "w" {
    print d " must belong to root and be writable by root alone" }'
  d=$(dirname "$d")
done
```

If that prints anything, fix the directory it names, or pick another `B`, before going on. Then:

```sh
sudo install -m 755 whimbrel-$v-$t/whimbrel "$B/"
```

Anywhere else, build it with a Rust toolchain: `cargo install --locked --git
https://github.com/kmsquire/whimbrel --tag v0.3.0`.

## From nothing to a first alert

These steps run whimbrel as root, hourly. Everything it keeps goes in one directory, `W` below:

| | Linux | Mac |
|---|---|---|
| `W`, the config and its secret files | `/etc/whimbrel` | `/Library/Application Support/whimbrel` |
| `state_dir` | `/var/lib/whimbrel` | `/Library/Application Support/whimbrel/state` |
| The disk to watch | `/` | `/System/Volumes/Data` (`/` is the sealed system volume) |
| The binary | `/usr/local/bin/whimbrel` | `/opt/whimbrel/bin/whimbrel` |
| The schedule | a systemd timer | a LaunchDaemon |

The examples show Linux's paths; on a Mac, use the Mac column.

1. Make the config, readable and writable by root alone. whimbrel refuses a config another
   account can write, since the config names programs it runs.

   ```sh
   W=/etc/whimbrel        # Mac: W="/Library/Application Support/whimbrel"
   sudo install -d -m 700 "$W"
   sudo install -m 600 /dev/null "$W/whimbrel.toml"
   sudo -e "$W/whimbrel.toml"
   ```

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

2. Try it. A dry run shows what each channel would be sent and changes nothing:

   ```sh
   sudo "$B/whimbrel" dry-run --config "$W/whimbrel.toml"
   ```

   It prints the run's summary line (`WARN disk=WARN alerting=OK`), then the alert.

3. Send it somewhere real. Make a Slack app with an [incoming
   webhook](https://api.slack.com/messaging/webhooks), and put the webhook URL in a file only root
   can read:

   ```sh
   sudo install -m 600 /dev/null "$W/slack-webhook"
   sudo -e "$W/slack-webhook"
   ```

   Then replace the `print` channel, with the file's full path:

   ```toml
   [[channel]]
   kind = "slack"
   webhook_file = "/etc/whimbrel/slack-webhook"
   ```

   whimbrel refuses a config that holds a webhook URL itself.

4. Run it for real: `sudo "$B/whimbrel" run --config "$W/whimbrel.toml"`. The alert arrives in Slack.
   Run it again and nothing is sent: nothing changed. Delete the `warn` and `fail` lines, so the
   defaults apply, and run once more for the all-clear.

5. Schedule it hourly. On Linux, with systemd:

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

   ```sh
   sudo systemctl daemon-reload && sudo systemctl enable --now whimbrel.timer
   ```

   On a Mac, with a LaunchDaemon saved as `/Library/LaunchDaemons/whimbrel.plist`, owned by root
   and mode 644:

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

   ```sh
   sudo launchctl bootstrap system /Library/LaunchDaemons/whimbrel.plist
   ```

   With cron instead: `0 * * * * /usr/local/bin/whimbrel run --config /etc/whimbrel/whimbrel.toml`.

From here, add the checks you want. [The config reference](docs/config.md) has every key.

## Checks

| Kind | Watches |
|---|---|
| `disk` | How full a volume is, and the biggest folders when it's full. |
| `file` | That files belong to one account and are no more open than a mode. |
| `secrets` | Logs and the journal for token-shaped strings: counts only, never the match. |
| `journald-drops` | Units journald dropped lines from in the last hour, because they log in a loop. |
| `command` | Your own program, which prints result rows. |
| `result-file` | Result rows another job left in a file. |

`command` and `result-file` are how you watch anything else. Write a script that prints one row
per thing it checked, then `RESULT` and its worst level:

```text
OK	backup	The backup finished.	
FAIL	replica	The replica is 3 hours behind.	See `psql -c 'select now() - pg_last_xact_replay_timestamp()'`.
RESULT	FAIL
```

Each line is tab-separated: level, a name, what's wrong, and what to run. whimbrel shows each WARN
or FAIL row's words as written, if they keep the sentence rule, and counts the ones that don't.
Run it with `command` when whimbrel can run it, optionally as another account. Have it write a
file for `result-file` when it has to run somewhere whimbrel can't, such as in a user's GUI session
on a Mac. [Result rows](docs/config.md#result-rows) has the details.

## Redaction

Every alert, and every reason a send failed, goes through redaction before any channel or the log
sees it. Built in are a few hundred token shapes, every prefix-anchored rule of three published
secret-scanning lists, and you can add your own patterns or switch any of them off. [Secret
patterns](docs/config.md#secret-patterns) lists them.

## Exit status

`run` exits 0 when the run went through, even if a send failed, since the next run retries it; 1
when it ran but couldn't keep its state; and 2 when it couldn't start, such as with a config it
refuses. Each run writes one line to the log (stdout unless `log_file` is set):

```text
2026-11-24T10:00:00Z WARN disk=WARN alerting=OK; slack: sent
```

A send that fails logs `alert failed` with the reason, which is what to grep for if you watch the
watch.

## Stability

The contract is the command line, the config file and the result-row format. The crate's Rust
items are public only so its own tests reach them; they aren't a library API and can change in
any release. whimbrel isn't published to crates.io.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT
license](LICENSE-MIT), at your option. The built-in secret patterns are adapted from gitleaks and
betterleaks, under the MIT license, and from osv-scalibr, under Apache-2.0; see
[THIRD-PARTY.md](THIRD-PARTY.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
whimbrel by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
