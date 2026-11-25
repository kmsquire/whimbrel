# secret-patterns

This tool generates whimbrel's built-in secret patterns from the published lists they're taken
from. It isn't shipped or published. It fetches each pinned file from GitHub, checks the file's
checksum, applies the selection rule that `src/secret_patterns.rs` describes, and writes these
files:

- `src/secret_patterns/builtins.rs`: the table of built-in patterns.
- `src/secret_patterns/left-out.md`: every rule that the selection rule leaves out, and why.
- The table of built-in patterns in `docs/config.md`, between its markers.
- The pin of each list in `THIRD-PARTY.md`, between its markers.
- `ids.toml` in this directory.

Don't edit those files by hand. CI regenerates them and fails on any difference.

The tool reads three files in this directory:

| File | What it holds |
|---|---|
| `sources.toml` | Each list's repository, commit, and files, with the SHA-256 checksum of every file. The `bump` command writes it. |
| `changes.toml` | The hand changes to the lists' rules, each with its reason, and whimbrel's own patterns. Edit it by hand. |
| `ids.toml` | Every id that a built-in pattern has had. The tool adds ids and retires them. Edit it only to keep an id when a list renames a rule. |

The tool needs the network. It caches fetched files in `target/sources/`, by checksum.

## Run the tool

Run the commands from the root of the repository:

```sh
# Write every generated file.
cargo run --locked --manifest-path tools/secret-patterns/Cargo.toml -- write

# Change nothing, and fail if a generated file differs from what the tool writes.
cargo run --locked --manifest-path tools/secret-patterns/Cargo.toml -- check
```

## Bump a list

To move a list to a newer commit, do the following:

1. Run `bump` with the list's name, the full 40-character commit, and the release tag at that
   commit, if there is one:

   ```sh
   cargo run --locked --manifest-path tools/secret-patterns/Cargo.toml -- \
     bump gitleaks <commit> v8.31.0
   ```

   The tool pins every file it reads at that commit, then writes the generated files. It prints
   the ids that it added and retired, and the ids whose pattern changed.

2. Review the diff:

   - `src/secret_patterns/builtins.rs` and `docs/config.md` show the patterns that were added,
     removed, or changed.
   - `src/secret_patterns/left-out.md` shows the rules that the selection rule now leaves out,
     and why.
   - `ids.toml` shows each new id and each retired id.

   If a rule that has an id is no longer in its list, or is now in a form that the tool can't
   read, the tool stops and names it, because only you can tell a rename from a removal:

   - If the list renamed the rule, keep its id: in `ids.toml`, change the id's `rule` to the
     new name, and run the same command again. The tool refuses two ids for one rule.
   - If the list removed the rule, run the same command again with `--retire`.

   A `bump` that stops changes nothing, `sources.toml` included.

3. Run `cargo test` at the root of the repository. Every built-in must still match an example
   of itself and no ordinary log line.

4. If the tool fails because a change in `changes.toml` no longer applies, the list might have
   fixed the rule itself. Remove the change, or update it, and run `write` again.

## How ids work

`disable` in a config names built-in patterns by id, so an id is part of the config contract.
Once a rule has an id, it keeps it. A new rule gets an id from its name. If another rule has
or had that id, the new rule's id ends with the list's name, such as `-betterleaks`. whimbrel's
own patterns are in `ids.toml` too, under the source `whimbrel`, so a list's rule never takes
their ids. When a rule leaves the table, its id is retired with the last release that had it,
which the tool reads from the release tags in the history of `HEAD`, and it's never given to
another rule. whimbrel accepts a retired id in `disable`, warns that it turns nothing off, and
names the last release that had it.

## What the tool can't read

osv-scalibr's rules are Go code. The tool reads a rule from a call to `regexp.MustCompile`
whose argument is one raw string literal. It reports every other call, such as one that joins a
pattern from pieces, in `left-out.md` as a pattern that it can't read. A rule is named
`<directory> <variable>`; when two calls in a directory share that name, each takes its file,
and then, if they're in one file, the start of its pattern's SHA-256, such as `#64daa44a`, so
the name moves with the pattern rather than its place. A changed pattern is then a new name, and
the tool stops on the old one's id as it does for a removed rule. If a list yields no rule at all, the tool fails, and
if a rule that has an id turns into a form the tool can't read, the tool stops as it does for a
rule that left its list.
