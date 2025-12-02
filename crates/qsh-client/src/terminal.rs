//! Terminal handling for raw mode I/O.
//!
//! Provides:
//! - Raw terminal mode setup/restore
//! - Terminal size detection
//! - stdin/stdout async streams

use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::TermSize;

/// Original terminal settings to restore on exit.
static ORIGINAL_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

/// Flag indicating if we're in raw mode.
static RAW_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Guard that restores terminal settings on drop.
pub struct RawModeGuard {
    fd: RawFd,
}

impl RawModeGuard {
    /// Enter raw terminal mode.
    ///
    /// Returns a guard that restores normal mode on drop.
    pub fn enter() -> Result<Self> {
        let fd = io::stdin().as_raw_fd();

        // Get current terminal attributes
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        let result = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };
        if result != 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        let original = unsafe { termios.assume_init() };

        // Save original settings
        if let Ok(mut guard) = ORIGINAL_TERMIOS.lock() {
            *guard = Some(original);
        }

        // Set raw mode
        let mut raw = original;

        // Input flags: disable break signal, CR->NL mapping, parity checking,
        // 8th bit stripping, and XON/XOFF flow control
        raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);

        // Output flags: disable output processing
        raw.c_oflag &= !libc::OPOST;

        // Control flags: set 8-bit characters
        raw.c_cflag |= libc::CS8;

        // Local flags: disable echo, canonical mode, signals, and extended input
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);

        // Control characters: read returns after 1 byte, no timeout
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;

        // Apply settings
        let result = unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) };
        if result != 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);
        debug!("Entered raw terminal mode");

        Ok(Self { fd })
    }

    /// Check if raw mode is currently active.
    pub fn is_active() -> bool {
        RAW_MODE_ACTIVE.load(Ordering::SeqCst)
    }

    /// Restore terminal to original mode.
    fn restore(&self) {
        if let Ok(mut guard) = ORIGINAL_TERMIOS.lock()
            && let Some(original) = guard.take()
        {
            let result = unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &original) };
            if result != 0 {
                warn!("Failed to restore terminal settings");
            } else {
                debug!("Restored terminal settings");
            }
        }
        RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Restore terminal settings (for signal handlers).
pub fn restore_terminal() {
    let fd = io::stdin().as_raw_fd();
    if let Ok(guard) = ORIGINAL_TERMIOS.lock()
        && let Some(ref original) = *guard
    {
        unsafe {
            libc::tcsetattr(fd, libc::TCSAFLUSH, original);
        }
    }
    RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);
}

/// Get the current terminal size.
pub fn get_terminal_size() -> Result<TermSize> {
    let fd = io::stdout().as_raw_fd();

    let mut winsize = std::mem::MaybeUninit::<libc::winsize>::uninit();
    let result = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, winsize.as_mut_ptr()) };

    if result != 0 {
        // Default to 80x24 if we can't get size
        return Ok(TermSize { cols: 80, rows: 24 });
    }

    let winsize = unsafe { winsize.assume_init() };

    Ok(TermSize {
        cols: winsize.ws_col,
        rows: winsize.ws_row,
    })
}

/// Async stdin reader.
///
/// Spawns a blocking thread to read from stdin and sends
/// data through an unbounded channel to never block on stdin reads.
pub struct StdinReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    _cancel_tx: mpsc::Sender<()>,
}

impl StdinReader {
    /// Create a new stdin reader.
    pub fn new() -> Self {
        // Use unbounded channel to never block stdin reads
        let (tx, rx) = mpsc::unbounded_channel();
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);

        std::thread::spawn(move || {
            use std::os::unix::io::AsRawFd;
            let stdin = io::stdin();
            let fd = stdin.as_raw_fd();

            // Lock stdin for the duration to avoid any buffering issues
            let mut stdin_lock = stdin.lock();
            let mut buf = [0u8; 4096];

            loop {
                // Check if cancelled (non-blocking)
                if cancel_rx.try_recv().is_ok() {
                    break;
                }

                // Read directly - in raw mode this returns immediately when data is available
                match stdin_lock.read(&mut buf) {
                    Ok(0) => {
                        // EOF
                        tracing::debug!("stdin EOF");
                        break;
                    }
                    Ok(n) => {
                        tracing::debug!(
                            len = n,
                            data = ?&buf[..n.min(16)],
                            fd = fd,
                            "stdin read"
                        );
                        if tx.send(buf[..n].to_vec()).is_err() {
                            // Receiver dropped
                            tracing::debug!("stdin receiver dropped");
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                        // Interrupted by signal, retry
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "stdin read error");
                        break;
                    }
                }
            }
            tracing::debug!("stdin reader thread exiting");
        });

        Self {
            rx,
            _cancel_tx: cancel_tx,
        }
    }

    /// Read data from stdin.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

impl Default for StdinReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Async stdout writer.
pub struct StdoutWriter {
    stdout: tokio::io::Stdout,
}

impl StdoutWriter {
    /// Create a new stdout writer.
    pub fn new() -> Self {
        Self {
            stdout: tokio::io::stdout(),
        }
    }

    /// Write data to stdout.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.stdout.write_all(data).await.map_err(Error::Io)?;
        self.stdout.flush().await.map_err(Error::Io)?;
        Ok(())
    }
}

impl Default for StdoutWriter {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_terminal_size_returns_valid_dimensions() {
        // This test may fail in CI where there's no terminal
        // Just verify it doesn't panic
        let size = get_terminal_size().unwrap();
        assert!(size.cols > 0);
        assert!(size.rows > 0);
    }

    #[test]
    fn raw_mode_guard_tracks_active_state() {
        // Can't actually enter raw mode in tests, but verify the atomic flag
        assert!(!RawModeGuard::is_active());
    }
}
