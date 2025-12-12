//! Terminal handling for raw mode I/O.
//!
//! Provides:
//! - Raw terminal mode setup/restore
//! - Terminal size detection
//! - stdin/stdout async streams

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::unix::AsyncFd;
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

/// Async stdin reader using AsyncFd for true async I/O.
///
/// Uses tokio's AsyncFd to poll stdin without blocking threads.
/// This allows the read to be cancelled when the select! loop exits.
pub struct StdinReader {
    async_fd: AsyncFd<RawFd>,
    fd: RawFd,
}

impl StdinReader {
    /// Create a new stdin reader.
    ///
    /// Sets stdin to non-blocking mode and wraps it in AsyncFd.
    pub fn new() -> Self {
        Self::from_fd(io::stdin().as_raw_fd())
    }

    /// Create a reader from an arbitrary file descriptor.
    ///
    /// Sets the fd to non-blocking mode and wraps it in AsyncFd.
    /// Useful for bootstrap mode where input comes from a pipe instead of stdin.
    pub fn from_fd(fd: RawFd) -> Self {
        // Set non-blocking mode
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        // AsyncFd requires the fd to be non-blocking
        let async_fd = AsyncFd::new(fd).expect("failed to create AsyncFd for fd");

        Self { async_fd, fd }
    }

    /// Read data from stdin.
    ///
    /// Returns None on EOF or error, Some(data) on successful read.
    /// This is fully async and can be cancelled by dropping the future.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 4096];

        loop {
            // Wait for stdin to be readable
            let mut guard = match self.async_fd.readable().await {
                Ok(guard) => guard,
                Err(e) => {
                    tracing::error!(error = %e, "stdin readable error");
                    return None;
                }
            };

            // Try to read - may return WouldBlock if spurious wakeup
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        *inner.get_ref(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(0)) => {
                    // EOF
                    tracing::debug!("stdin EOF");
                    return None;
                }
                Ok(Ok(n)) => {
                    tracing::debug!(
                        len = n,
                        data = ?&buf[..n.min(16)],
                        fd = self.fd,
                        "stdin read"
                    );
                    return Some(buf[..n].to_vec());
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                    // Interrupted by signal, retry
                    continue;
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "stdin read error");
                    return None;
                }
                Err(_would_block) => {
                    // Spurious wakeup, loop back to wait again
                    continue;
                }
            }
        }
    }
}

impl Drop for StdinReader {
    fn drop(&mut self) {
        // Restore blocking mode for stdin
        unsafe {
            let flags = libc::fcntl(self.fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(self.fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }
        }
        tracing::debug!("stdin reader dropped, restored blocking mode");
    }
}

impl Default for StdinReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Async stdout writer with retry handling for WouldBlock.
pub struct StdoutWriter {
    inner: StdoutWriterInner,
}

enum StdoutWriterInner {
    Stdout(tokio::io::Stdout),
    Fd(AsyncFd<RawFd>, RawFd),
}

impl StdoutWriter {
    /// Create a new stdout writer.
    pub fn new() -> Self {
        Self {
            inner: StdoutWriterInner::Stdout(tokio::io::stdout()),
        }
    }

    /// Create a writer from an arbitrary file descriptor.
    ///
    /// Sets the fd to non-blocking mode and wraps it in AsyncFd.
    /// Useful for bootstrap mode where output goes to a pipe instead of stdout.
    pub fn from_fd(fd: RawFd) -> Self {
        // Set non-blocking mode
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        let async_fd = AsyncFd::new(fd).expect("failed to create AsyncFd for fd");

        Self {
            inner: StdoutWriterInner::Fd(async_fd, fd),
        }
    }

    /// Write data to stdout with retry on WouldBlock.
    ///
    /// Handles EAGAIN/WouldBlock by yielding and retrying up to a limit.
    /// This can happen when the terminal buffer is full (e.g., during fast output).
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.inner {
            StdoutWriterInner::Stdout(stdout) => Self::write_stdout_impl(stdout, data).await,
            StdoutWriterInner::Fd(async_fd, fd) => Self::write_fd_impl(async_fd, *fd, data).await,
        }
    }

    async fn write_stdout_impl(stdout: &mut tokio::io::Stdout, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut written = 0;
        let mut retries = 0;
        const MAX_RETRIES: u32 = 10;
        const RETRY_DELAY_US: u64 = 100; // 100 microseconds

        while written < data.len() {
            match stdout.write(&data[written..]).await {
                Ok(0) => {
                    // No progress - shouldn't happen but treat as error
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "stdout write returned 0 bytes",
                    )));
                }
                Ok(n) => {
                    written += n;
                    retries = 0; // Reset retry counter on success
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        // Give up after too many retries - terminal too slow
                        tracing::trace!(
                            written,
                            total = data.len(),
                            "stdout WouldBlock after max retries, partial write"
                        );
                        break;
                    }
                    // Short yield to let terminal catch up
                    tokio::time::sleep(std::time::Duration::from_micros(RETRY_DELAY_US)).await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // Interrupted by signal, just retry immediately
                    continue;
                }
                Err(e) => {
                    return Err(Error::Io(e));
                }
            }
        }

        // Best effort flush - don't fail on WouldBlock
        if let Err(e) = stdout.flush().await {
            if e.kind() != std::io::ErrorKind::WouldBlock {
                return Err(Error::Io(e));
            }
        }

        Ok(())
    }

    async fn write_fd_impl(async_fd: &AsyncFd<RawFd>, fd: RawFd, data: &[u8]) -> Result<()> {
        let mut written = 0;
        let mut retries = 0;
        const MAX_RETRIES: u32 = 10;
        const RETRY_DELAY_US: u64 = 100;

        while written < data.len() {
            // Wait for fd to be writable
            let mut guard = match async_fd.writable().await {
                Ok(guard) => guard,
                Err(e) => {
                    tracing::error!(error = %e, "fd writable error");
                    return Err(Error::Io(e));
                }
            };

            match guard.try_io(|_| {
                let n = unsafe {
                    libc::write(
                        fd,
                        data[written..].as_ptr() as *const libc::c_void,
                        data.len() - written,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(0)) => {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "fd write returned 0 bytes",
                    )));
                }
                Ok(Ok(n)) => {
                    written += n;
                    retries = 0;
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        tracing::trace!(
                            written,
                            total = data.len(),
                            "fd WouldBlock after max retries, partial write"
                        );
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_micros(RETRY_DELAY_US)).await;
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Ok(Err(e)) => {
                    return Err(Error::Io(e));
                }
                Err(_would_block) => {
                    continue;
                }
            }
        }

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
