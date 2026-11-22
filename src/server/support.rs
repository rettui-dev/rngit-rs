//! What the parts of the node that answer management requests share.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmpv::Value;

use super::Refusal;
use crate::error::Status;
use crate::transport::Response;

pub(super) fn refuse(status: Status, text: &str) -> Refusal {
    Refusal::new(status, text)
}

/// Seconds since 1970.
pub(super) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Seconds since 1970, with the fraction, as stock rngit writes times.
pub(super) fn now_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// Write a file by way of a temporary one, so a failure leaves nothing half written.
pub(super) fn write_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_file_name(format!(".{}.part", path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned())));
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Most a MessagePack reply sent as one packet may come to. Lists stop short
/// of it, so a folder of big documents can't make the node build a huge reply;
/// rngit clients take up to 16 MiB.
pub(super) const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;

/// At most `max` characters of `text`, cut where a character ends.
pub(super) fn first_chars(text: &str, max: usize) -> &str {
    text.char_indices().nth(max).map_or(text, |(at, _)| &text[..at])
}

/// Whether a name a peer sent is safe as one file or folder name on every
/// system a node runs on. On Windows `C:x` joined to a folder replaces it,
/// `a:b` writes a hidden stream of `a`, a name ending in a dot or a space is
/// saved without it, and `CON`, `NUL.txt` and the like are devices, not files.
pub(super) fn plain_file_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') || name.ends_with(['.', ' ']) {
        return false;
    }
    if name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')) {
        return false;
    }
    if device_name(name) {
        return false;
    }
    // Whatever the checks above missed on this system: one plain part, the name itself.
    let mut parts = Path::new(name).components();
    matches!((parts.next(), parts.next()), (Some(Component::Normal(part)), None) if part == std::ffi::OsStr::new(name))
}

/// A Windows device name, with or without an extension, in any case.
fn device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ').to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    let Some(number) = stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT")) else { return false };
    let mut chars = number.chars();
    matches!((chars.next(), chars.next()), (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None))
}

/// So many at a time of something costly, such as building a bundle: the
/// rest wait their turn, for a while.
#[derive(Debug, Default)]
pub(super) struct Slots {
    taken: Mutex<usize>,
    freed: Condvar,
}

/// A place taken in [`Slots`], given back when dropped.
pub(super) struct Slot<'a>(&'a Slots);

impl Slots {
    /// Wait up to `wait` for one of `most` places.
    pub(super) fn take(&self, most: usize, wait: Duration) -> Option<Slot<'_>> {
        let until = Instant::now() + wait;
        let mut taken = self.taken.lock().ok()?;
        while *taken >= most {
            let left = until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
            taken = self.freed.wait_timeout(taken, left).ok()?.0;
        }
        *taken += 1;
        Some(Slot(self))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if let Ok(mut taken) = self.0.taken.lock() {
            *taken = taken.saturating_sub(1);
        }
        self.0.freed.notify_one();
    }
}

/// One writer at a time per repository: a push and a sync both add packs,
/// and a push that is turned down takes its pack away again, which must not
/// be one another writer is about to point a ref at.
#[derive(Debug, Default)]
pub(super) struct Locks {
    held: Mutex<HashSet<PathBuf>>,
    freed: Condvar,
}

/// A repository held in [`Locks`], let go when dropped.
pub(super) struct Held<'a>(&'a Locks, PathBuf);

impl Locks {
    /// Wait up to `wait` to hold `path`.
    pub(super) fn hold(&self, path: &Path, wait: Duration) -> Option<Held<'_>> {
        let until = Instant::now() + wait;
        let mut held = self.held.lock().ok()?;
        while held.contains(path) {
            let left = until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
            held = self.freed.wait_timeout(held, left).ok()?.0;
        }
        held.insert(path.to_path_buf());
        Some(Held(self, path.to_path_buf()))
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Ok(mut held) = self.0.held.lock() {
            held.remove(&self.1);
        }
        self.0.freed.notify_all();
    }
}

/// Write a file that must not be there yet, such as the rules a new
/// repository starts with: if another is there it is left as it is.
pub(super) fn write_new(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    // Only the file this made goes, if it couldn't be written.
    file.write_all(data).and_then(|()| file.sync_all()).inspect_err(|_| {
        drop(std::fs::remove_file(path));
    })
}

/// Claim a repository's name by making its folder, which only one request
/// can do: anyone after finds it there.
pub(super) fn claim(dir: &Path) -> Result<(), Refusal> {
    std::fs::create_dir(dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            refuse(Status::NotAllowed, "Repository already exists")
        } else {
            refuse(Status::ServerError, "Could not create repository")
        }
    })
}

/// Whether `dir` holds a repository that opens. The empty folder that claims
/// a name while a fork or mirror fetches doesn't, and nothing may be made
/// beside it meanwhile (work documents, releases, rules) for the new
/// repository to take over.
pub(super) fn is_repository(dir: &Path) -> bool {
    dir.join("HEAD").is_file() && gix::open(dir).is_ok()
}

/// Whether `dir` is a folder with nothing in it.
pub(super) fn empty_dir(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none())
}

/// What sits beside a repository and goes where it goes: its rules, releases and work documents.
pub(super) fn beside(group_dir: &Path, repo: &str) -> [PathBuf; 3] {
    ["allowed", "releases", "work"].map(|what| group_dir.join(format!("{repo}.{what}")))
}

/// Refuse to make a repository where an older one of the name left its
/// rules, releases or work documents, so its maker doesn't take them over.
pub(super) fn nothing_left_behind(group_dir: &Path, repo: &str) -> Result<(), Refusal> {
    if beside(group_dir, repo).iter().any(|p| p.symlink_metadata().is_ok()) {
        return Err(refuse(Status::NotAllowed, "A repository of that name had rules, releases or work documents that are still there"));
    }
    Ok(())
}

/// The names of the files in a folder.
pub(super) fn file_names(dir: &Path) -> HashSet<std::ffi::OsString> {
    std::fs::read_dir(dir).map(|entries| entries.flatten().map(|e| e.file_name()).collect()).unwrap_or_default()
}

/// An OK reply with a MessagePack value after the status byte.
pub(super) fn packed(value: &Value) -> Result<Response, Refusal> {
    let mut out = vec![Status::Ok.to_byte()];
    rmpv::encode::write_value(&mut out, value).map_err(|_| refuse(Status::ServerError, "Remote error"))?;
    Ok(Response::Packet(out))
}

pub(super) fn text(value: &str) -> Value {
    Value::from(value)
}

/// Check the lines of a permissions file a client sends, as stock rngit
/// does: each is `perm:who`, blank, or a `#` comment. The first that isn't
/// is named.
pub(super) fn check_rules(content: &str) -> Result<(), Refusal> {
    for (number, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let one_word = line.split_once(':').is_some_and(|(perm, who)| !perm.trim().contains(char::is_whitespace) && !who.contains(':'));
        if !one_word || line.contains(',') || super::Rule::parse(line).is_empty() {
            return Err(refuse(Status::BadRequest, &format!("Invalid permission \"{line}\" on line {}", number + 1)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_file_name_is_one_on_every_system() {
        for good in ["a", "app-1.0.tar.gz", "console", "com10", "lpt", "x.con", "\u{e9}t\u{e9}", "a b"] {
            assert!(plain_file_name(good), "{good:?}");
        }
        for bad in
            ["", ".", "..", ".hidden", "a/b", "a\\b", "C:x", "a:b", "x.", "x ", "CON", "con.txt", "CON .txt", "com3", "lpt\u{b2}", "a\0b"]
        {
            assert!(!plain_file_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn slots_are_taken_so_many_at_a_time_and_given_back() {
        let slots = Slots::default();
        let first = slots.take(2, Duration::ZERO).unwrap();
        let _second = slots.take(2, Duration::ZERO).unwrap();
        assert!(slots.take(2, Duration::from_millis(10)).is_none());
        drop(first);
        assert!(slots.take(2, Duration::ZERO).is_some());
    }

    #[test]
    fn a_repository_is_held_by_one_writer_at_a_time() {
        let locks = Locks::default();
        let held = locks.hold(Path::new("a"), Duration::ZERO).unwrap();
        assert!(locks.hold(Path::new("a"), Duration::from_millis(10)).is_none());
        assert!(locks.hold(Path::new("b"), Duration::ZERO).is_some());
        // One waiting gets it once the first lets go.
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| locks.hold(Path::new("a"), Duration::from_secs(10)).is_some());
            std::thread::sleep(Duration::from_millis(20));
            drop(held);
            assert!(waiting.join().unwrap());
        });
    }
}
