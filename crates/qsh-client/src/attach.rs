//! Attach pipe utilities for bootstrap/responder mode.
//!
//! In reverse-connection flow the responder (`qsh --bootstrap`) creates
//! a Unix-domain socket that a later `qsh --attach <path>` process connects
//! to. This module provides a tiny helper for creating the socket with
//! restrictive permissions, accepting the attach connection, and cleaning
//! up the socket file afterwards.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use libc;
use qsh_core::error::{Error, Result};
use rand::Rng;
use tokio::net::{UnixListener, UnixStream};

/// Generate a per-user attach socket path under /tmp.
///
/// Format: `/tmp/qsh-<uid>-<random>` so multiple sessions don't collide and
/// `find_latest_pipe` can reliably pick the newest for this user.
pub fn pipe_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() as u32 };
    let mut rng = rand::rng();
    let r: u32 = rng.random();
    PathBuf::from(format!("/tmp/qsh-{uid}-{r:08x}"))
}

/// Create the attach socket and return a guard plus listener.
///
/// The socket file is removed automatically when the guard is dropped.
pub fn create_pipe(path: &Path) -> Result<(PipeGuard, UnixListener)> {
    if path.exists() {
        std::fs::remove_file(path).map_err(Error::Io)?;
    }

    let listener = UnixListener::bind(path).map_err(Error::Io)?;

    // Restrict permissions to the current user (0600) to avoid leaking the pipe
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(Error::Io)?;

    Ok((PipeGuard { path: path.to_path_buf() }, listener))
}

/// Accept a single attach connection.
pub async fn accept_attach(listener: &UnixListener) -> Result<UnixStream> {
    let (stream, _) = listener.accept().await.map_err(Error::Io)?;
    Ok(stream)
}

/// Connect to an attach socket.
pub async fn connect_attach(path: &Path) -> Result<UnixStream> {
    UnixStream::connect(path).await.map_err(Error::Io)
}

/// Find the most recent attach pipe for the current user under /tmp.
pub fn find_latest_pipe() -> Result<PathBuf> {
    use std::fs;
    use std::io::ErrorKind;

    let uid = unsafe { libc::geteuid() as u32 };
    let prefix = format!("qsh-{uid}-");

    let mut newest: Option<(SystemTime, PathBuf)> = None;

    let entries = fs::read_dir("/tmp").map_err(Error::Io)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if !name.starts_with(&prefix) {
                continue;
            }
        } else {
            continue;
        }

        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                match &mut newest {
                    Some((ts, _)) if modified <= *ts => {}
                    _ => newest = Some((modified, path.clone())),
                }
            }
        }
    }

    if let Some((_, path)) = newest {
        Ok(path)
    } else {
        Err(Error::Io(std::io::Error::new(
            ErrorKind::NotFound,
            "no recent qsh attach pipes found in /tmp; run qsh --bootstrap first",
        )))
    }
}

/// RAII guard that removes the socket path on drop.
pub struct PipeGuard {
    path: PathBuf,
}

impl Drop for PipeGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
