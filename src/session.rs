//! Starting Reticulum and loading the client identity, the way the command
//! line programs do.
//!
//! `RNS_CONFIG` is the Reticulum config directory. `RNGIT_CONFIG` is the
//! directory holding `client_identity` (default `~/.rngit`), which is created
//! on first use. Both match stock rngit.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rns_identity::identity::Identity;
use rns_runtime::prelude::*;

use crate::error::Error;

/// A running Reticulum instance and the identity requests are made as.
pub struct Session {
    pub runtime: ReticulumHandle,
    pub identity: Identity,
}

/// Load `client_identity` from `dir`, making one if it isn't there.
pub fn load_or_create_identity(dir: &std::path::Path) -> Result<Identity, Error> {
    load_identity_named(dir, "client_identity")
}

/// Load the identity file `name` from `dir`, making one if it isn't there.
///
/// Two programs starting for the first time at once must end up with the
/// same identity, so a new one is written in full to a name of its own and
/// then linked into place, which fails if the file appeared meanwhile; the
/// one that lost loads the winner's.
pub fn load_identity_named(dir: &std::path::Path, name: &str) -> Result<Identity, Error> {
    let path = dir.join(name);
    let load = || Identity::from_file(&path).map_err(|e| Error::Transport(format!("could not read {}: {e}", path.display())));
    if path.exists() {
        return load();
    }
    std::fs::create_dir_all(dir).map_err(Error::git)?;
    let identity = Identity::new();
    static MADE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = MADE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let fresh = dir.join(format!(".{name}.new-{}-{nonce}", std::process::id()));
    let written = identity.to_file(&fresh).map_err(|e| Error::Transport(format!("could not write {}: {e}", fresh.display())));
    let placed = written.and_then(|()| match std::fs::hard_link(&fresh, &path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        // A file system without hard links: a rename, which can't tell if
        // another program got there first, but does if it already had.
        Err(_) if !path.exists() => {
            std::fs::rename(&fresh, &path).map(|()| true).map_err(|e| Error::Transport(format!("could not write {}: {e}", path.display())))
        }
        Err(_) => Ok(false),
    });
    let _ = std::fs::remove_file(&fresh);
    if placed? { Ok(identity) } else { load() }
}

impl Session {
    /// Start Reticulum, then wait `settle` for announces and paths to arrive.
    pub async fn start(settle: Duration) -> Result<Session, Error> {
        let dir = match std::env::var_os("RNGIT_CONFIG") {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(std::env::var_os("HOME").ok_or_else(|| Error::InvalidInput("HOME is not set".into()))?).join(".rngit"),
        };
        let identity = load_or_create_identity(&dir)?;
        let config = std::env::var("RNS_CONFIG").ok();
        let runtime = init(config.as_deref(), None, ShutdownSignal::new(), Arc::new(AtomicBool::new(true)))
            .await
            .map_err(|e| Error::Transport(format!("could not start Reticulum: {e}")))?;
        tokio::time::sleep(settle).await;
        Ok(Session { runtime, identity })
    }

    /// How long to wait for a path, from `RNGIT_PATH_WAIT` (seconds, default 5).
    pub fn settle_time() -> Duration {
        Duration::from_secs(std::env::var("RNGIT_PATH_WAIT").ok().and_then(|v| v.parse().ok()).unwrap_or(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_created_once_and_then_reloaded() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested");
        let first = load_or_create_identity(&dir).unwrap();
        let again = load_or_create_identity(&dir).unwrap();
        assert_eq!(first.hash, again.hash);
        std::fs::write(dir.join("client_identity"), b"junk").unwrap();
        assert!(load_or_create_identity(&dir).is_err());
    }

    #[test]
    fn programs_starting_together_share_one_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("fresh");
        let hashes: Vec<[u8; 16]> = std::thread::scope(|scope| {
            let started: Vec<_> = (0..8).map(|_| scope.spawn(|| load_or_create_identity(&dir).unwrap().hash)).collect();
            started.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert!(hashes.iter().all(|h| *h == hashes[0]), "{hashes:?}");
        assert_eq!(load_or_create_identity(&dir).unwrap().hash, hashes[0]);
        // Nothing is left but the identity itself.
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["client_identity"]);
    }
}
