//! Runs a program and reads [result rows](crate::rows) from its stdout: how to watch anything
//! whimbrel has no kind for.
//!
//! ```toml
//! [[check]]
//! kind = "command"
//! key = "backup"
//! about = "the nightly backup"
//! program = "/usr/local/libexec/check-backup"
//! args = ["--max-age-hours", "26"]
//! user = "backup"
//! ```
//!
//! whimbrel often runs as root, so the program is run only if no other account could have changed
//! it: it and every directory above it, links resolved, must belong to root or to whimbrel's own
//! account, and none may be writable by group or others, except a sticky directory such as `/tmp`.
//! That's checked every run, since files change between runs, and a program that fails it is a
//! WARN for this check alone.
//!
//! With `user` it runs as that account: its uid and primary group, and no supplementary groups,
//! since looking those up isn't safe between fork and exec. It always runs with stdin empty,
//! stderr dropped, `/` as its directory, and only `PATH`, `HOME`, `USER` and `LOGNAME` in its
//! environment. Its exit status isn't read when its output is whole, so a script that exits 1 on
//! FAIL works as it is; one killed by a signal or by the timeout is a WARN.

use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::check::{At, Check, Finding, Kind, Shared, sentence_case};
use crate::checks::result_file::MAX;
use crate::config::from_table;
use crate::process::{self, Unfinished};
use crate::rows;
use crate::sentence::{quoted, shown};

/// The only `PATH` the program sees.
pub const PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    program: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    user: Option<String>,
    #[serde(default = "timeout_secs")]
    timeout_secs: u64,
    required_row: Option<String>,
}

fn timeout_secs() -> u64 {
    60
}

pub struct CommandCheck {
    program: PathBuf,
    args: Vec<String>,
    user: Option<String>,
    timeout: Duration,
    required_row: Option<String>,
}

/// `command`, keyed `command` and recovering as "the command's result" unless its table says
/// otherwise.
pub const KIND: Kind = Kind {
    name: "command",
    key: "command",
    about: "the command's result",
    build,
};

fn build(table: toml::Table, _: &Shared) -> Result<Box<dyn Check>, String> {
    let t: Table = from_table(table)?;
    if !t.program.is_absolute() {
        return Err("program must be an absolute path".into());
    }
    if let Some(user) = &t.user
        && !account_name(user)
    {
        return Err("user must be an account's name".into());
    }
    process::timeout_secs("timeout_secs", t.timeout_secs)?;
    if t.required_row.as_deref() == Some("") {
        return Err("required_row must name a row".into());
    }
    Ok(Box::new(CommandCheck {
        program: t.program,
        args: t.args,
        user: t.user,
        timeout: Duration::from_secs(t.timeout_secs),
        required_row: t.required_row,
    }))
}

/// A plain account name: what a sentence and a `sudo -u` may show as it is.
fn account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// An account, as the password database has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

/// Looks an account up by name or by uid.
enum By<'a> {
    Name(&'a str),
    Uid(u32),
}

fn lookup(by: By) -> Option<Account> {
    let name = match by {
        By::Name(n) => Some(CString::new(n).ok()?),
        By::Uid(_) => None,
    };
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: passwd is plain data, for which all zeroes is valid.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call, and buf's length is passed with it.
        let rc = unsafe {
            match (&by, &name) {
                (By::Name(_), Some(n)) => libc::getpwnam_r(
                    n.as_ptr(),
                    &raw mut pw,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &raw mut found,
                ),
                (By::Uid(uid), _) => libc::getpwuid_r(
                    *uid,
                    &raw mut pw,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &raw mut found,
                ),
                _ => return None,
            }
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() {
            return None;
        }
        // SAFETY: on success pw's strings point into buf, which is still alive.
        let text = |p: *const libc::c_char| unsafe { CStr::from_ptr(p) }.to_string_lossy();
        return Some(Account {
            name: text(pw.pw_name).into_owned(),
            uid: pw.pw_uid,
            gid: pw.pw_gid,
            home: PathBuf::from(text(pw.pw_dir).into_owned()),
        });
    }
}

/// The account named `name`, if there is one.
pub fn account(name: &str) -> Option<Account> {
    lookup(By::Name(name))
}

/// The account with `uid`, if there is one.
pub fn account_of(uid: u32) -> Option<Account> {
    lookup(By::Uid(uid))
}

/// The name of the group with `gid`, if there is one.
pub fn group_name(gid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: group is plain data, for which all zeroes is valid.
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::group = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call, and buf's length is passed with it.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &raw mut gr,
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut found,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() {
            return None;
        }
        // SAFETY: on success gr's name points into buf, which is still alive.
        return Some(
            unsafe { CStr::from_ptr(gr.gr_name) }
                .to_string_lossy()
                .into_owned(),
        );
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and can't fail.
    unsafe { libc::geteuid() }
}

/// The most links followed on the way to the program, as the kernel's own limit is about.
const MAX_LINKS: u32 = 40;

/// Why the program at `path` isn't safe to run, or the path it really is, every link resolved,
/// if it is. The words finish "It isn't safe to run: …".
///
/// The configured path is walked a part at a time, links included, and every directory on the way,
/// every link, and the program itself must belong to root or to us. No directory may be writable
/// by group or others unless it's sticky, so no other account can swap a part, and the program
/// can't be writable by them at all. Checking only where the links end would let anyone who can
/// write a directory on the way pick which program runs as root.
pub fn vet(path: &Path) -> Result<PathBuf, String> {
    walk(path, 0)
}

fn walk(path: &Path, links: u32) -> Result<PathBuf, String> {
    let me = euid();
    let ours = |uid: u32| uid == 0 || uid == me;
    let named = |p: &Path| shown(&p.display().to_string(), "directory");
    let look = |p: &Path| {
        fs::symlink_metadata(p).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => "it isn't there".to_string(),
            _ => format!("{} can't be looked at", named(p)),
        })
    };
    let dir_ok = |p: &Path, m: &fs::Metadata| -> Result<(), String> {
        if !m.is_dir() {
            return Err(format!("{} on its path isn't a directory", named(p)));
        }
        if !ours(m.uid()) {
            return Err(format!("{} above it belongs to uid {}", named(p), m.uid()));
        }
        if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
            return Err(format!("other accounts can write {} above it", named(p)));
        }
        Ok(())
    };
    let root = Path::new("/");
    dir_ok(root, &look(root)?)?;
    let parts: Vec<std::path::Component> = path.components().collect();
    let mut at = PathBuf::from("/");
    for (i, part) in parts.iter().enumerate() {
        let name = match part {
            std::path::Component::Normal(name) => name,
            std::path::Component::ParentDir => {
                at.pop();
                continue;
            }
            _ => continue,
        };
        let next = at.join(name);
        let m = look(&next)?;
        if m.file_type().is_symlink() {
            if !ours(m.uid()) {
                return Err(format!(
                    "the link {} on its path belongs to uid {}",
                    named(&next),
                    m.uid()
                ));
            }
            if links >= MAX_LINKS {
                return Err("its path has too many links".into());
            }
            let target = fs::read_link(&next).map_err(|_| "it can't be looked at".to_string())?;
            let mut rest = at.join(target);
            for later in &parts[i + 1..] {
                rest.push(later);
            }
            return walk(&rest, links + 1);
        }
        if i + 1 < parts.len() {
            dir_ok(&next, &m)?;
            at = next;
            continue;
        }
        if !m.is_file() {
            return Err("it isn't a regular file".into());
        }
        if !ours(m.uid()) {
            return Err(format!("it belongs to uid {}", m.uid()));
        }
        if m.mode() & 0o022 != 0 {
            return Err("other accounts can write it".into());
        }
        if m.mode() & 0o111 == 0 {
            return Err("it isn't executable".into());
        }
        return Ok(next);
    }
    Err("it isn't a regular file".into())
}

/// Become `uid` in `gid` alone, for good: the group list first, while still root, then the
/// group, then the user, each fatal if it fails, and then a check that root can't be had back.
/// Run between fork and exec, so it only makes system calls.
fn drop_to(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    let fail = || Err(io::Error::last_os_error());
    // SAFETY: plain system calls on our own process, with a pointer to one valid gid.
    unsafe {
        if libc::setgroups(1, &raw const gid) != 0 {
            return fail();
        }
        if libc::setgid(gid) != 0 {
            return fail();
        }
        if libc::setuid(uid) != 0 {
            return fail();
        }
        if uid != 0 && (libc::setuid(0) == 0 || libc::seteuid(0) == 0) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
    }
    Ok(())
}

/// What came of running it, short of its rows.
#[derive(Debug, PartialEq, Eq)]
enum Doubt {
    Unsafe(String),
    NoAccount(String),
    NotRoot(String),
    NotStarted,
    TimedOut(u64),
    Killed(i32),
    TooMuch,
    HeldOpen,
}

impl Doubt {
    fn tag(&self) -> &'static str {
        match self {
            Doubt::Unsafe(_) => "command:unsafe",
            Doubt::NoAccount(_) => "command:no-account",
            Doubt::NotRoot(_) => "command:not-root",
            Doubt::NotStarted => "command:not-started",
            Doubt::TimedOut(_) => "command:timed-out",
            Doubt::Killed(_) => "command:killed",
            Doubt::TooMuch => "command:too-much",
            Doubt::HeldOpen => "command:held-open",
        }
    }

    fn what(&self, host: &str, about: &str) -> String {
        let its = format!("{host}'s program for {about}");
        match self {
            Doubt::Unsafe(why) => format!("{its} isn't safe to run: {why}."),
            Doubt::NoAccount(user) => {
                format!("{its} is to run as {user}, but there's no account of that name.")
            }
            Doubt::NotRoot(user) => format!(
                "{its} is to run as {user}, which needs the watch to run as root, and it doesn't."
            ),
            Doubt::NotStarted => format!("{its} couldn't be started."),
            Doubt::TimedOut(1) => format!("{its} didn't finish within 1 second."),
            Doubt::TimedOut(secs) => format!("{its} didn't finish within {secs} seconds."),
            Doubt::Killed(signal) => {
                format!("{its} was stopped by signal {signal} before it finished.")
            }
            Doubt::TooMuch => format!("{its} printed more than 64 KiB, so none of it was read."),
            Doubt::HeldOpen => format!(
                "{its} exited, but something it started left its process group and kept its \
                 output open, so none of it was read."
            ),
        }
    }
}

impl CommandCheck {
    /// The command line a person would run to see what it prints.
    fn shown(&self) -> String {
        let mut words = vec![quoted(&self.program.display().to_string())];
        words.extend(self.args.iter().map(|a| quoted(a)));
        let line = words.join(" ");
        match &self.user {
            Some(user) => format!("sudo -u {user} {line}"),
            None => line,
        }
    }

    /// Its output, or why there's none to judge.
    fn output(&self) -> Result<Vec<u8>, Doubt> {
        let real = self.program_path()?;
        let as_whom = match &self.user {
            Some(name) => {
                let acct = account(name).ok_or_else(|| Doubt::NoAccount(name.clone()))?;
                if acct.uid != euid() && euid() != 0 {
                    return Err(Doubt::NotRoot(name.clone()));
                }
                Some(acct)
            }
            None => account_of(euid()),
        };
        let mut command = Command::new(&real);
        command
            .args(&self.args)
            .env_clear()
            .env("PATH", PATH)
            .current_dir("/");
        if let Some(acct) = &as_whom {
            command
                .env("HOME", &acct.home)
                .env("USER", &acct.name)
                .env("LOGNAME", &acct.name);
        }
        if euid() == 0
            && let Some(acct) = as_whom.filter(|_| self.user.is_some())
        {
            let (uid, gid) = (acct.uid, acct.gid);
            // SAFETY: drop_to makes only system calls, which are safe between fork and exec.
            unsafe { command.pre_exec(move || drop_to(uid, gid)) };
        }
        let read = |out: std::process::ChildStdout| -> io::Result<(Vec<u8>, bool)> {
            let mut out = out;
            let mut bytes = Vec::new();
            (&mut out).take(MAX + 1).read_to_end(&mut bytes)?;
            // The rest is read and dropped, so a program with more to say isn't left blocked.
            io::copy(&mut out, &mut io::sink())?;
            let over = bytes.len() as u64 > MAX;
            Ok((bytes, over))
        };
        match process::stream_command(command, self.timeout, read) {
            Err(Unfinished::TimedOut) => Err(Doubt::TimedOut(self.timeout.as_secs())),
            Err(Unfinished::TooMuch) => Err(Doubt::TooMuch),
            Err(Unfinished::HeldOpen) => Err(Doubt::HeldOpen),
            Err(Unfinished::NotStarted | Unfinished::Unread) => Err(Doubt::NotStarted),
            Ok((status, _)) if status.signal().is_some() => {
                Err(Doubt::Killed(status.signal().unwrap_or(0)))
            }
            Ok((_, Err(_))) => Err(Doubt::NotStarted),
            Ok((_, Ok((_, true)))) => Err(Doubt::TooMuch),
            Ok((_, Ok((bytes, false)))) => Ok(bytes),
        }
    }

    fn program_path(&self) -> Result<PathBuf, Doubt> {
        vet(&self.program).map_err(Doubt::Unsafe)
    }
}

impl Check for CommandCheck {
    /// The worst row's level, with each WARN or FAIL row a problem; see [`rows`].
    fn run(&self, at: &At) -> Finding {
        let host = sentence_case(at.host);
        match self.output() {
            Ok(bytes) => rows::judge(
                &bytes,
                self.required_row.as_deref(),
                &format!("{host}'s result for {}", at.about),
                &self.shown(),
            ),
            Err(d) => {
                let see = match &d {
                    Doubt::Unsafe(_) | Doubt::NotStarted => {
                        format!("ls -l {}", quoted(&self.program.display().to_string()))
                    }
                    Doubt::NoAccount(user) | Doubt::NotRoot(user) => format!("id {user}"),
                    _ => self.shown(),
                };
                Finding::warn()
                    .says(d.what(&host, at.about))
                    .see(see)
                    .fingerprint(d.tag())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_name_is_plain() {
        for ok in ["backup", "_www", "app.svc", "a-b"] {
            assert!(account_name(ok), "{ok}");
        }
        for bad in ["", "-rf", "a b", "a;b", "a/b", &"x".repeat(33)] {
            assert!(!account_name(bad), "{bad}");
        }
    }

    #[test]
    fn our_own_account_is_found_by_uid_and_by_name() {
        let me = account_of(euid()).expect("our own account");
        assert_eq!(account(&me.name), Some(me));
        assert_eq!(account("no-such-account-here"), None);
    }
}
