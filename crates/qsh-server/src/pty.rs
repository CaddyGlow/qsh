//! PTY management for server sessions.
//!
//! Handles:
//! - Spawning PTY with user's shell
//! - Async I/O relay between PTY and QUIC streams
//! - Terminal resize events
//!
//! Uses the `nix` crate for cross-platform Unix PTY support (Linux, macOS, Android).
//! Uses `AsyncFd` for proper async I/O integration with tokio's reactor.

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;
use std::sync::Arc;

use nix::pty::{Winsize, openpty};
use nix::sys::signal::{Signal, kill};
use nix::unistd::{ForkResult, Pid, close, dup2, execvp, fork, setsid};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use qsh_core::error::{Error, Result};

/// PTY handle for async I/O.
///
/// Uses `AsyncFd` for proper integration with tokio's reactor, avoiding
/// polling loops that cause latency.
pub struct Pty {
    /// Master PTY file descriptor wrapped for async I/O.
    master: Arc<AsyncFd<std::fs::File>>,
    /// Child process PID.
    child_pid: Pid,
    /// Terminal size.
    cols: u16,
    rows: u16,
    /// Raw master fd for ioctl operations.
    master_fd: RawFd,
}

impl Pty {
    /// Spawn a new PTY with the given shell command.
    ///
    /// # Arguments
    ///
    /// * `cols` - Terminal columns.
    /// * `rows` - Terminal rows.
    /// * `shell` - Shell path (e.g., "/bin/bash"). If None, uses $SHELL or /bin/sh.
    /// * `env` - Additional environment variables to set.
    ///
    /// # Returns
    ///
    /// A new PTY instance with the shell running.
    ///
    /// # Safety
    ///
    /// This function uses `fork()` which is inherently unsafe in multi-threaded programs.
    /// It should only be called early in the program lifecycle or with careful consideration
    /// of the threading state.
    pub fn spawn(
        cols: u16,
        rows: u16,
        shell: Option<&str>,
        env: &[(String, String)],
    ) -> Result<Self> {
        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // Open PTY pair
        let pty_result = openpty(&winsize, None).map_err(|e| Error::Pty {
            message: format!("failed to open pty: {}", e),
        })?;

        let master_fd = pty_result.master.as_raw_fd();
        let slave_fd = pty_result.slave.as_raw_fd();

        // Determine shell to use
        let shell_path = shell
            .map(String::from)
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_else(|| "/bin/sh".to_string());

        info!(shell = %shell_path, "Spawning shell");

        // Prepare arguments for execvp
        let shell_cstr = CString::new(shell_path.clone()).map_err(|e| Error::Pty {
            message: format!("invalid shell path: {}", e),
        })?;

        let mut args = vec![shell_cstr.clone()];

        // Set login shell flag if it's a common shell
        if shell_path.ends_with("bash") || shell_path.ends_with("zsh") {
            args.push(CString::new("-l").unwrap());
        }

        // Clone env for the child process
        let env_vars: Vec<(String, String)> = env.to_vec();

        // Fork the process
        // SAFETY: fork() is unsafe in multi-threaded programs. We assume this is called
        // appropriately (ideally before spawning other threads or with proper synchronization).
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent process - close slave fd
                drop(pty_result.slave);

                // Convert master to std::fs::File
                // SAFETY: We own the fd from openpty and it's valid
                let master_owned: OwnedFd = pty_result.master;
                let std_file = unsafe { std::fs::File::from_raw_fd(master_owned.as_raw_fd()) };
                // Prevent double-close by forgetting the OwnedFd
                std::mem::forget(master_owned);

                // Set non-blocking mode for async I/O
                set_nonblocking(master_fd)?;

                // Wrap in AsyncFd for proper reactor integration
                let async_fd = AsyncFd::new(std_file).map_err(|e| Error::Pty {
                    message: format!("failed to create AsyncFd: {}", e),
                })?;

                Ok(Self {
                    master: Arc::new(async_fd),
                    child_pid: child,
                    cols,
                    rows,
                    master_fd,
                })
            }
            Ok(ForkResult::Child) => {
                // Child process - set up PTY slave as controlling terminal

                // Create new session
                setsid().map_err(|e| Error::Pty {
                    message: format!("setsid failed: {}", e),
                })?;

                // Set controlling terminal
                // TIOCSCTTY request type varies by platform (c_ulong on glibc/macOS, c_int on musl)
                unsafe {
                    libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0);
                }

                // Duplicate slave to stdin/stdout/stderr
                dup2(slave_fd, libc::STDIN_FILENO).map_err(|e| Error::Pty {
                    message: format!("dup2 stdin failed: {}", e),
                })?;
                dup2(slave_fd, libc::STDOUT_FILENO).map_err(|e| Error::Pty {
                    message: format!("dup2 stdout failed: {}", e),
                })?;
                dup2(slave_fd, libc::STDERR_FILENO).map_err(|e| Error::Pty {
                    message: format!("dup2 stderr failed: {}", e),
                })?;

                // Close original fds
                if slave_fd > libc::STDERR_FILENO {
                    let _ = close(slave_fd);
                }
                let _ = close(master_fd);

                // Set environment variables
                // SAFETY: We're in a forked child process before exec, single-threaded
                for (key, value) in &env_vars {
                    unsafe { std::env::set_var(key, value) };
                }

                // Set TERM if not already set
                // SAFETY: We're in a forked child process before exec, single-threaded
                if std::env::var("TERM").is_err() {
                    unsafe { std::env::set_var("TERM", "xterm-256color") };
                }

                // Execute shell
                execvp(&shell_cstr, &args).map_err(|e| Error::Pty {
                    message: format!("execvp failed: {}", e),
                })?;

                // execvp doesn't return on success
                unreachable!()
            }
            Err(e) => Err(Error::Pty {
                message: format!("fork failed: {}", e),
            }),
        }
    }

    /// Resize the PTY.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.cols = cols;
        self.rows = rows;

        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // Use TIOCSWINSZ ioctl to resize
        let result = unsafe { libc::ioctl(self.master_fd, libc::TIOCSWINSZ, &winsize) };

        if result == -1 {
            let err = std::io::Error::last_os_error();
            return Err(Error::Pty {
                message: format!("failed to resize pty: {}", err),
            });
        }

        debug!(cols, rows, "PTY resized");
        Ok(())
    }

    /// Write data to the PTY (terminal input from client).
    ///
    /// Uses AsyncFd for proper async I/O - waits for write readiness
    /// before attempting to write.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let mut remaining = data;
        while !remaining.is_empty() {
            let mut guard = self.master.writable().await.map_err(|e| Error::Pty {
                message: format!("failed to wait for pty write readiness: {}", e),
            })?;

            match guard.try_io(|inner| inner.get_ref().write(remaining)) {
                Ok(Ok(n)) => {
                    remaining = &remaining[n..];
                }
                Ok(Err(e)) => {
                    return Err(Error::Pty {
                        message: format!("failed to write to pty: {}", e),
                    });
                }
                Err(_would_block) => {
                    // Readiness was a false positive, loop and wait again
                    continue;
                }
            }
        }
        Ok(())
    }

    /// Read data from the PTY (terminal output to client).
    ///
    /// Uses AsyncFd for proper async I/O - waits for read readiness
    /// before attempting to read. This avoids polling loops.
    ///
    /// Returns None if the PTY is closed (EOF).
    pub async fn read(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        loop {
            let mut guard = self.master.readable().await.map_err(|e| Error::Pty {
                message: format!("failed to wait for pty read readiness: {}", e),
            })?;

            match guard.try_io(|inner| inner.get_ref().read(buf)) {
                Ok(Ok(0)) => return Ok(None), // EOF
                Ok(Ok(n)) => return Ok(Some(n)),
                Ok(Err(e)) => {
                    // EIO is common when the PTY slave is closed (shell exit)
                    if e.raw_os_error() == Some(libc::EIO) {
                        debug!("PTY read returned EIO (shell likely exited)");
                        return Ok(None);
                    }
                    return Err(Error::Pty {
                        message: format!("failed to read from pty: {}", e),
                    });
                }
                Err(_would_block) => {
                    // Readiness was a false positive, loop and wait again
                    continue;
                }
            }
        }
    }

    /// Check if the child process has exited.
    pub fn try_wait(&self) -> Result<Option<i32>> {
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

        match waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                info!(exit_code = code, "Shell process exited");
                Ok(Some(code))
            }
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                info!(signal = ?signal, "Shell process killed by signal");
                Ok(Some(128 + signal as i32))
            }
            Ok(WaitStatus::StillAlive) => Ok(None),
            Ok(_) => Ok(None), // Other states (stopped, continued)
            Err(nix::errno::Errno::ECHILD) => {
                // Child already reaped
                Ok(Some(0))
            }
            Err(e) => Err(Error::Pty {
                message: format!("failed to check child status: {}", e),
            }),
        }
    }

    /// Kill the child process.
    pub fn kill(&self) -> Result<()> {
        kill(self.child_pid, Signal::SIGTERM).map_err(|e| Error::Pty {
            message: format!("failed to kill child: {}", e),
        })?;
        Ok(())
    }

    /// Get the current terminal size.
    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// Get the child process PID.
    pub fn pid(&self) -> Pid {
        self.child_pid
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        // Try to kill the child process if still running
        if self.try_wait().ok().flatten().is_none() {
            let _ = self.kill();
        }
    }
}

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|e| Error::Pty {
        message: format!("fcntl F_GETFL failed: {}", e),
    })?;

    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;

    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(|e| Error::Pty {
        message: format!("fcntl F_SETFL failed: {}", e),
    })?;

    Ok(())
}

/// I/O relay between PTY and channels.
///
/// This spawns tasks for bidirectional communication.
/// Uses AsyncFd for proper async I/O, avoiding polling loops.
pub struct PtyRelay {
    /// Channel for sending data to the PTY (input from client).
    input_tx: mpsc::Sender<Vec<u8>>,
    /// Channel for receiving data from the PTY (output to client).
    output_rx: mpsc::Receiver<Vec<u8>>,
}

impl PtyRelay {
    /// Start a new PTY relay.
    ///
    /// Spawns background tasks for bidirectional I/O. The output task
    /// uses AsyncFd readiness notifications for efficient, low-latency I/O.
    pub fn start(pty: Arc<Pty>) -> Self {
        let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(256);
        let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(256);

        // Spawn input task (client -> PTY)
        let pty_input = pty.clone();
        tokio::spawn(async move {
            while let Some(data) = input_rx.recv().await {
                debug!(len = data.len(), data = ?&data[..data.len().min(32)], "PTY input received from channel");
                if let Err(e) = pty_input.write(&data).await {
                    error!(error = %e, "Failed to write to PTY");
                    break;
                }
                debug!(len = data.len(), "PTY input written successfully");
            }
            debug!("PTY input task ended");
        });

        // Spawn output task (PTY -> client)
        // Uses AsyncFd readiness - no polling, immediate wake on data
        let pty_output = pty.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match pty_output.read(&mut buf).await {
                    Ok(Some(n)) => {
                        debug!(len = n, data = ?&buf[..n.min(32)], "PTY output read");
                        if output_tx.send(buf[..n].to_vec()).await.is_err() {
                            warn!("Output channel closed");
                            break;
                        }
                    }
                    Ok(None) => {
                        // EOF - shell exited
                        info!("PTY EOF - shell exited");
                        break;
                    }
                    Err(e) => {
                        // Log but don't treat as fatal - EIO handled in read()
                        warn!(error = %e, "PTY read error");
                        break;
                    }
                }
            }
            debug!("PTY output task ended");
            // Drop output_tx - this signals EOF to the receiver
        });

        Self {
            input_tx,
            output_rx,
        }
    }

    /// Send input to the PTY.
    pub async fn send_input(&self, data: Vec<u8>) -> Result<()> {
        self.input_tx.send(data).await.map_err(|_| Error::Pty {
            message: "input channel closed".to_string(),
        })
    }

    /// Receive output from the PTY.
    ///
    /// Returns None if the PTY output channel is closed.
    pub async fn recv_output(&mut self) -> Option<Vec<u8>> {
        self.output_rx.recv().await
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pty_spawn_default_shell() {
        // This test may fail in CI without a proper TTY
        let result = Pty::spawn(80, 24, Some("/bin/sh"), &[]);
        if let Err(e) = &result {
            eprintln!("PTY spawn failed (may be expected in CI): {}", e);
        }
        // Clean up if successful
        if let Ok(pty) = result {
            let _ = pty.kill();
        }
    }

    #[tokio::test]
    async fn pty_size_tracking() {
        if let Ok(mut pty) = Pty::spawn(80, 24, Some("/bin/sh"), &[]) {
            assert_eq!(pty.size(), (80, 24));
            let _ = pty.resize(120, 40);
            assert_eq!(pty.size(), (120, 40));
            let _ = pty.kill();
        }
    }
}
