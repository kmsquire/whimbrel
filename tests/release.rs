//! What the release workflow and the README promise about where whimbrel runs from, checked
//! against the files themselves, since nothing here can run the workflow.

const CI: &str = include_str!("../.github/workflows/ci.yml");
const README: &str = include_str!("../README.md");
const TOOLCHAIN: &str = include_str!("../rust-toolchain.toml");

#[test]
fn nothing_is_published_while_the_repo_is_private() {
    let publish = CI.split("\n  publish:\n").nth(1).expect("a publish job");
    let cond = publish
        .lines()
        .find_map(|l| l.trim().strip_prefix("if: "))
        .expect("an if on the publish job");
    assert_eq!(
        cond,
        "startsWith(github.ref, 'refs/tags/v') && !github.event.repository.private"
    );
}

#[test]
fn every_target_is_built_and_published() {
    let targets: Vec<&str> = TOOLCHAIN
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.split('"').next())
        .collect();
    assert_eq!(targets.len(), 4, "{targets:?}");
    for t in &targets {
        assert!(
            CI.contains(&format!("- target: {t}\n")),
            "{t} isn't in the matrix"
        );
        assert!(
            README.contains(&format!("`{t}`")),
            "{t} isn't in the README"
        );
    }
    assert!(CI.contains(&format!("[[ $found == {} ]]", targets.len())));
}

#[test]
fn the_mac_runs_whimbrel_from_a_directory_of_its_own() {
    // On a Mac with Homebrew, /usr/local/bin belongs to a user, who could then replace what
    // the LaunchDaemon runs as root.
    let plist = README
        .split("<key>ProgramArguments</key>")
        .nth(1)
        .expect("a LaunchDaemon plist");
    let program = plist
        .split("<string>")
        .nth(1)
        .and_then(|s| s.split("</string>").next())
        .unwrap();
    assert_eq!(program, "/opt/whimbrel/bin/whimbrel");
    assert!(README.contains("B=/usr/local/bin        # Mac: B=/opt/whimbrel/bin"));
    assert!(README.contains("must belong to root and be writable by root alone"));
}

/// What `scripts/prove` says of a Linux binary whose `file` line, program headers and dynamic
/// section are as given, run against stand-ins for `file` and `readelf`, so no cross build is
/// needed. Its exit status and what it printed.
fn prove_linux(file_says: &str, headers: &str, dynamic: &str) -> (bool, String) {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let write = |rel: &str, text: &str, exec: bool| {
        let p = d.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        if exec {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    };
    let target = "x86_64-unknown-linux-musl";
    write(
        &format!("target/{target}/release/whimbrel"),
        "#!/bin/sh\necho 'whimbrel 0.3.0 (abc123)'\n",
        true,
    );
    write("stub/says", file_says, false);
    write("stub/headers", headers, false);
    write("stub/dynamic", dynamic, false);
    write(
        "stub/file",
        "#!/bin/sh\ncat \"$(dirname \"$0\")/says\"\n",
        true,
    );
    write(
        "stub/readelf",
        "#!/bin/sh\nd=$(dirname \"$0\")\ncase $1 in -l) cat \"$d/headers\" ;; -d) cat \"$d/dynamic\" ;; esac\n",
        true,
    );
    let path = format!(
        "{}:{}",
        d.path().join("stub").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = std::process::Command::new(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/prove"))
        .arg(target)
        .current_dir(d.path())
        .env("PATH", path)
        .env("WHIMBREL_COMMIT", "abc123")
        .output()
        .unwrap();
    let said =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), said)
}

const LOAD: &str = "Program Headers:\n  LOAD 0x000000 0x0000000000000000\n";

#[test]
fn prove_accepts_a_static_pie_and_a_static_binary() {
    // x86-64 musl links static-pie: a dynamic section, for relocation, but nothing NEEDED.
    let (ok, said) = prove_linux(
        "ELF 64-bit LSB pie executable, x86-64, static-pie linked\n",
        LOAD,
        "Dynamic section at offset 0x1000 contains 3 entries:\n 0x000000006ffffffb (FLAGS_1) Flags: PIE\n",
    );
    assert!(ok, "{said}");
    assert!(said.contains("static-pie linked"), "{said}");
    let (ok, said) = prove_linux(
        "ELF 64-bit LSB executable, ARM aarch64, statically linked\n",
        LOAD,
        "\nThere is no dynamic section in this file.\n",
    );
    assert!(ok, "{said}");
}

#[test]
fn prove_refuses_a_dynamically_linked_binary() {
    let (ok, said) = prove_linux(
        "ELF 64-bit LSB pie executable, x86-64, dynamically linked, interpreter /lib/ld-musl-x86_64.so.1\n",
        "Program Headers:\n  INTERP 0x0002a8\n      [Requesting program interpreter: /lib/ld-musl-x86_64.so.1]\n",
        " 0x0000000000000001 (NEEDED) Shared library: [libc.so]\n",
    );
    assert!(!ok, "{said}");
    assert!(said.contains("names an interpreter"), "{said}");
    // Shared libraries with no interpreter named is refused too.
    let (ok, said) = prove_linux(
        "ELF 64-bit LSB shared object, x86-64\n",
        LOAD,
        " 0x0000000000000001 (NEEDED) Shared library: [libc.so]\n",
    );
    assert!(!ok, "{said}");
    assert!(said.contains("needs shared libraries"), "{said}");
}
