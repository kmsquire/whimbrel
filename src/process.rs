//! Running another program with a deadline: `df`, `du`, `curl`, `journalctl`, and a `command`
//! check's own.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// The most of a program's output [`run`] keeps: `df`, `du`, `curl` and an hour of journald's
/// notices are far less.
pub const RUN_MAX: u64 = 1024 * 1024;

/// The longest a program may be given, so a deadline is never past what a clock can hold.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// What a program left behind, when it finished in time.
pub struct Finished {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}

/// Why it didn't.
#[derive(Debug, PartialEq, Eq)]
pub enum Unfinished {
    /// It couldn't be started at all.
    NotStarted,
    TimedOut,
    /// It finished, but what read its output stopped early: it panicked, say.
    Unread,
    /// It printed more than [`RUN_MAX`].
    TooMuch,
    /// It exited, but something it started left its process group and kept its output open past
    /// [`GRACE`].
    HeldOpen,
}

/// Run `program` with `args`, `stdin` written to it, and kill it at `timeout`. Its stderr is
/// dropped: a failing program's message can carry whatever it was handed. At most [`RUN_MAX`] of
/// its output is kept; more is [`Unfinished::TooMuch`].
pub fn run(
    program: impl AsRef<OsStr>,
    args: &[impl AsRef<OsStr>],
    stdin: &[u8],
    timeout: Duration,
) -> Result<Finished, Unfinished> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().map_err(|_| Unfinished::NotStarted)?;
    let mut input = child.stdin.take().expect("piped");
    let stdin = stdin.to_vec();
    // A thread, so a program that writes before it reads can't deadlock with us. Never joined:
    // a program that doesn't read its input could hold it for good.
    thread::spawn(move || {
        let _ = input.write_all(&stdin);
    });
    let output = child.stdout.take().expect("piped");
    let (status, read) = finish(child, deadline(timeout), output, |mut out| {
        let mut bytes = Vec::new();
        (&mut out).take(RUN_MAX + 1).read_to_end(&mut bytes)?;
        io::copy(&mut out, &mut io::sink())?;
        Ok::<_, io::Error>(bytes)
    })?;
    match read {
        Ok(bytes) if bytes.len() as u64 > RUN_MAX => Err(Unfinished::TooMuch),
        Ok(stdout) => Ok(Finished { status, stdout }),
        Err(_) => Err(Unfinished::Unread),
    }
}

/// Run `program` with `args`, handing its stdout to `read` as it comes, so a program with a lot
/// to say is never held in memory, and kill it at `timeout`. Its stderr is dropped.
pub fn stream<T: Send + 'static>(
    program: impl AsRef<OsStr>,
    args: &[impl AsRef<OsStr>],
    timeout: Duration,
    read: impl FnOnce(ChildStdout) -> T + Send + 'static,
) -> Result<(ExitStatus, T), Unfinished> {
    let mut command = Command::new(program);
    command.args(args);
    stream_command(command, timeout, read)
}

/// [`stream`], for a command set up by the caller: its account, environment or directory. Its
/// stdin is empty, and its stderr dropped, whatever the caller set. It runs in a process group
/// of its own, which is killed with it.
pub fn stream_command<T: Send + 'static>(
    mut command: Command,
    timeout: Duration,
    read: impl FnOnce(ChildStdout) -> T + Send + 'static,
) -> Result<(ExitStatus, T), Unfinished> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| Unfinished::NotStarted)?;
    let output = child.stdout.take().expect("piped");
    finish(child, deadline(timeout), output, read)
}

/// A config's `key` of `secs` checked as a timeout: at least a second, at most [`MAX_TIMEOUT`].
pub fn timeout_secs(key: &str, secs: u64) -> Result<Duration, String> {
    if secs == 0 || secs > MAX_TIMEOUT.as_secs() {
        return Err(format!("{key} must be from 1 to {}", MAX_TIMEOUT.as_secs()));
    }
    Ok(Duration::from_secs(secs))
}

/// `timeout` from now, at most [`MAX_TIMEOUT`].
fn deadline(timeout: Duration) -> Instant {
    Instant::now() + timeout.min(MAX_TIMEOUT)
}

/// Wait for `child`, leader of its own process group, until `deadline`, with `read` reading its
/// output on a thread. When it exits, whatever it left running in its group is killed, so a
/// background job can't hold its output open or outlive it; at the deadline the whole group is.
fn finish<T: Send + 'static>(
    child: Child,
    deadline: Instant,
    output: ChildStdout,
    read: impl FnOnce(ChildStdout) -> T + Send + 'static,
) -> Result<(ExitStatus, T), Unfinished> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(read(output));
    });
    let status = wait_until(child, deadline)?;
    // Its group is gone, so its output ends now, unless something it started left the group and
    // kept it open: a moment for the last of it, and no more.
    let got = rx.recv_timeout(GRACE).map_err(|e| match e {
        mpsc::RecvTimeoutError::Timeout => Unfinished::HeldOpen,
        mpsc::RecvTimeoutError::Disconnected => Unfinished::Unread,
    })?;
    Ok((status, got))
}

/// How long after a program exits its output may take to end.
pub const GRACE: Duration = Duration::from_secs(2);

/// SIGKILL to every process in the group `pgid`.
fn kill_group(pgid: u32) {
    if let Ok(pgid) = libc::pid_t::try_from(pgid)
        && pgid > 1
    {
        // SAFETY: killpg has no memory preconditions; a group that's gone is ESRCH, ignored.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
    }
}

/// A running program, leader of its own process group, as far as waiting for one goes. A trait
/// so the tests can stand in a program that a kill can't reap.
pub(crate) trait Running: Send + 'static {
    /// Whether it has exited, without reaping it, so its id, and its group's, stay taken.
    fn exited(&mut self) -> io::Result<bool>;
    /// SIGKILL to its whole group.
    fn kill_group(&mut self);
    /// Reap it.
    fn wait(&mut self) -> io::Result<ExitStatus>;
}

impl Running for Child {
    fn exited(&mut self) -> io::Result<bool> {
        let pid = libc::id_t::from(self.id());
        // SAFETY: siginfo_t is plain data, for which all zeroes is valid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: info is a valid siginfo_t; WNOWAIT leaves the child to be reaped by wait.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // With WNOHANG and nothing to report, waitid leaves the info as it was: zeroes.
        Ok(info.si_signo == libc::SIGCHLD)
    }
    fn kill_group(&mut self) {
        kill_group(self.id());
    }
    fn wait(&mut self) -> io::Result<ExitStatus> {
        Child::wait(self)
    }
}

/// Its exit status, or `TimedOut` at `deadline`. Either way its whole group is killed while its
/// own id still holds the group's, so the kill can reach nothing else: on exit, before it's
/// reaped; at the deadline, before it's reaped on a thread of its own, never waited for here. A
/// `df` stuck in uninterruptible I/O on a failing disk outlives SIGKILL, and waiting for it would
/// hang the whole run.
pub(crate) fn wait_until(
    mut child: impl Running,
    deadline: Instant,
) -> Result<ExitStatus, Unfinished> {
    loop {
        if let Ok(true) = child.exited() {
            child.kill_group();
            return child.wait().map_err(|_| Unfinished::Unread);
        }
        if Instant::now() >= deadline {
            child.kill_group();
            thread::spawn(move || {
                let _ = child.wait();
            });
            return Err(Unfinished::TimedOut);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program in uninterruptible sleep: a kill doesn't end it, and waiting never returns.
    struct Stuck;

    impl Running for Stuck {
        fn exited(&mut self) -> io::Result<bool> {
            Ok(false)
        }
        fn kill_group(&mut self) {}
        fn wait(&mut self) -> io::Result<ExitStatus> {
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
    }

    /// A program that has exited, recording what's done to it.
    struct Exited(std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>);

    impl Running for Exited {
        fn exited(&mut self) -> io::Result<bool> {
            self.0.lock().unwrap().push("exited");
            Ok(true)
        }
        fn kill_group(&mut self) {
            self.0.lock().unwrap().push("kill group");
        }
        fn wait(&mut self) -> io::Result<ExitStatus> {
            self.0.lock().unwrap().push("reap");
            Command::new("true").status()
        }
    }

    #[test]
    fn the_group_is_killed_before_the_leader_is_reaped() {
        let calls = std::sync::Arc::default();
        let status = wait_until(Exited(std::sync::Arc::clone(&calls)), Instant::now());
        assert!(status.unwrap().success());
        assert_eq!(*calls.lock().unwrap(), ["exited", "kill group", "reap"]);
    }

    #[test]
    fn learning_of_an_exit_leaves_the_leader_unreaped_so_its_id_stays_taken() {
        let mut child = Command::new("true").process_group(0).spawn().unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while !Running::exited(&mut child).unwrap() {
            assert!(Instant::now() < until, "true never exited");
            thread::sleep(Duration::from_millis(10));
        }
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        // SAFETY: signal 0 only asks whether the process exists; a zombie does.
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "it was reaped already");
        assert!(Running::wait(&mut child).unwrap().success());
    }

    #[test]
    fn a_program_a_kill_cant_end_doesnt_hold_the_run() {
        let started = Instant::now();
        let got = wait_until(Stuck, started + Duration::from_millis(100));
        assert_eq!(got, Err(Unfinished::TimedOut));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_stream_is_read_as_it_comes_and_ends_with_the_program() {
        let (status, n) = stream("printf", &["a\\nb\\nc\\n"], Duration::from_secs(5), |out| {
            io::BufRead::lines(io::BufReader::new(out)).count()
        })
        .unwrap();
        assert!(status.success());
        assert_eq!(n, 3);
        let late = stream("sleep", &["5"], Duration::from_millis(100), |_| ());
        assert_eq!(late.err(), Some(Unfinished::TimedOut));
        let broken = stream("true", &[] as &[&str], Duration::from_secs(5), |_| {
            panic!("the reader broke")
        });
        assert_eq!(broken.err(), Some(Unfinished::Unread));
    }

    #[test]
    fn output_past_the_cap_is_too_much_and_never_held_whole() {
        let past = (RUN_MAX + 1).to_string();
        let got = run(
            "head",
            &["-c", &past, "/dev/zero"],
            b"",
            Duration::from_secs(20),
        );
        assert_eq!(got.err(), Some(Unfinished::TooMuch));
        let at = RUN_MAX.to_string();
        let got = run(
            "head",
            &["-c", &at, "/dev/zero"],
            b"",
            Duration::from_secs(20),
        )
        .unwrap();
        assert_eq!(got.stdout.len() as u64, RUN_MAX);
    }

    #[test]
    fn a_background_job_holding_the_output_doesnt_hold_the_run() {
        let started = Instant::now();
        let got = run(
            "sh",
            &["-c", "sleep 30 & echo done"],
            b"",
            Duration::from_secs(20),
        )
        .unwrap();
        assert_eq!(got.stdout, b"done\n");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_huge_timeout_is_held_to_a_day() {
        assert!(timeout_secs("t", 0).is_err());
        assert!(timeout_secs("t", 86_401).is_err());
        assert_eq!(timeout_secs("t", 86_400), Ok(Duration::from_secs(86_400)));
        // A deadline past what a clock holds would panic; it's held to the most instead.
        let _ = deadline(Duration::from_secs(u64::MAX));
    }

    #[test]
    fn a_program_that_finishes_in_time_gives_its_status() {
        let got = run("true", &[] as &[&str], b"", Duration::from_secs(5)).unwrap();
        assert!(got.status.success());
    }
}
