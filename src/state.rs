//! The ledger on disk: one JSON file, replaced whole, behind a lock that's the only way in.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::ledger::State;

/// The run's lock file, in the state directory.
pub(crate) const LOCK: &str = "lock";

/// The directory whimbrel keeps its ledger and lock in. Making it, owner-only, is the caller's job.
pub struct StateDir {
    dir: PathBuf,
}

/// The run's hold on the state directory. Loading and saving go through it, so nothing can touch
/// the ledger without the lock.
pub struct Locked<'a> {
    dir: &'a StateDir,
    lock: File,
}

impl StateDir {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        StateDir {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    /// The ledger as it is, read without the lock and never written: for a dry run, which must
    /// change nothing, the lock file included. A run that saves meanwhile is no harm, since the
    /// save swaps the whole file in.
    pub fn peek(&self) -> io::Result<State> {
        read(&self.dir.join("ledger.json"))
    }

    /// The lock, or `None` while another run holds it. A symlink at the lock's path is refused.
    pub fn lock(&self) -> io::Result<Option<Locked<'_>>> {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.dir.join(LOCK))
            .map_err(|e| named(e, &self.dir.join(LOCK)))?;
        match f.try_lock() {
            Ok(()) => Ok(Some(Locked { dir: self, lock: f })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(e),
        }
    }
}

impl Drop for Locked<'_> {
    /// Let go of the lock itself, not only this copy of the file: a child started meanwhile holds
    /// a copy until it execs, and closing ours alone would leave the lock held through it.
    fn drop(&mut self) {
        // Closing lets go anyway if this fails.
        let _ = self.lock.unlock();
    }
}

impl Locked<'_> {
    fn ledger(&self) -> PathBuf {
        self.dir.dir.join("ledger.json")
    }

    /// The ledger, or an empty one on the first run. A file that won't parse is an error: starting
    /// over would forget what each channel was told without saying so.
    pub fn load(&self) -> io::Result<State> {
        read(&self.ledger())
    }

    /// Move a ledger that won't parse out of the way, to `ledger.json.corrupt-<now>`, so the run
    /// can start over without destroying the evidence. Returns where it went.
    pub fn set_aside(&self, now: u64) -> io::Result<PathBuf> {
        let to = self.dir.dir.join(format!("ledger.json.corrupt-{now}"));
        fs::rename(self.ledger(), &to).map_err(|e| named(e, &to))?;
        Ok(to)
    }

    /// Write the ledger whole, owner-only, and swap it in with a rename, so a crash leaves the old
    /// one or the new one and never half of either. A leftover temporary file is removed first
    /// and never written through, so its mode, or a symlink in its place, can't carry over.
    pub fn save(&self, state: &State) -> io::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(state)?;
        bytes.push(b'\n');
        write_whole(&self.ledger(), &bytes)
    }
}

/// Write `bytes` to `path` whole, owner-only, and swap it in with a rename, so a crash leaves the
/// old file or the new one and never half of either. The temporary file beside it, `.<name>.tmp`,
/// is removed first if it's left over and never written through, so its mode, or a symlink in its
/// place, can't carry over. The ledger's, and a check's own files through its `CheckDir`.
pub(crate) fn write_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp"));
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(named(e, &tmp)),
        _ => {}
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| named(e, &tmp))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()
}

/// The ledger at `path`, or an empty one if there's none.
fn read(path: &Path) -> io::Result<State> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(named(e, path)),
    }
}

/// The error, with the path it's about: "No such file or directory" alone doesn't say which.
fn named(e: io::Error, path: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}
