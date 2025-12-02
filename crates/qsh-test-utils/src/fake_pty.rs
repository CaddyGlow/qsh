//! Fake PTY for testing without real terminal.
//!
//! Provides a simulated PTY that can be driven programmatically,
//! useful for testing server-side terminal handling without actual processes.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

/// A fake PTY for testing.
#[derive(Debug)]
pub struct FakePty {
    /// Input written by client (goes to "process").
    input: Arc<Mutex<VecDeque<u8>>>,
    /// Output from "process" (goes to client).
    output_tx: mpsc::Sender<Vec<u8>>,
    /// Receiver for output (for tests to read).
    output_rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// Current terminal size.
    cols: u16,
    rows: u16,
    /// Whether the PTY is closed.
    closed: bool,
}

impl FakePty {
    /// Create a new fake PTY with default dimensions (80x24).
    pub fn new() -> Self {
        Self::with_size(80, 24)
    }

    /// Create a new fake PTY with specified dimensions.
    pub fn with_size(cols: u16, rows: u16) -> Self {
        let (output_tx, output_rx) = mpsc::channel(256);
        Self {
            input: Arc::new(Mutex::new(VecDeque::new())),
            output_tx,
            output_rx: Some(output_rx),
            cols,
            rows,
            closed: false,
        }
    }

    /// Take the output receiver (for consuming output in tests).
    pub fn take_output_receiver(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.output_rx.take()
    }

    /// Write data as if it came from the user (input to process).
    pub fn write_input(&self, data: &[u8]) {
        let mut input = self.input.lock().unwrap();
        input.extend(data);
    }

    /// Read pending input (what the process would receive).
    pub fn read_input(&self) -> Vec<u8> {
        let mut input = self.input.lock().unwrap();
        input.drain(..).collect()
    }

    /// Check if there's pending input.
    pub fn has_input(&self) -> bool {
        !self.input.lock().unwrap().is_empty()
    }

    /// Write data as if it came from the process (output to user).
    pub async fn write_output(&self, data: &[u8]) -> Result<(), ()> {
        self.output_tx.send(data.to_vec()).await.map_err(|_| ())
    }

    /// Write output synchronously (for non-async tests).
    pub fn write_output_sync(&self, data: &[u8]) -> Result<(), ()> {
        self.output_tx.try_send(data.to_vec()).map_err(|_| ())
    }

    /// Get current terminal size.
    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// Resize the terminal.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
    }

    /// Check if the PTY is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close the PTY.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Simulate typing a string (with optional delay between characters).
    pub fn type_string(&self, s: &str) {
        self.write_input(s.as_bytes());
    }

    /// Simulate pressing Enter.
    pub fn press_enter(&self) {
        self.write_input(b"\r");
    }

    /// Simulate Ctrl+C.
    pub fn press_ctrl_c(&self) {
        self.write_input(&[0x03]);
    }

    /// Simulate Ctrl+D (EOF).
    pub fn press_ctrl_d(&self) {
        self.write_input(&[0x04]);
    }

    /// Simulate an escape sequence.
    pub fn send_escape(&self, seq: &str) {
        let mut data = vec![0x1b]; // ESC
        data.extend_from_slice(seq.as_bytes());
        self.write_input(&data);
    }

    /// Send arrow key up.
    pub fn press_up(&self) {
        self.send_escape("[A");
    }

    /// Send arrow key down.
    pub fn press_down(&self) {
        self.send_escape("[B");
    }

    /// Send arrow key right.
    pub fn press_right(&self) {
        self.send_escape("[C");
    }

    /// Send arrow key left.
    pub fn press_left(&self) {
        self.send_escape("[D");
    }
}

impl Default for FakePty {
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
    fn fake_pty_new() {
        let pty = FakePty::new();
        assert_eq!(pty.size(), (80, 24));
        assert!(!pty.is_closed());
    }

    #[test]
    fn fake_pty_with_size() {
        let pty = FakePty::with_size(120, 40);
        assert_eq!(pty.size(), (120, 40));
    }

    #[test]
    fn fake_pty_input() {
        let pty = FakePty::new();

        assert!(!pty.has_input());

        pty.write_input(b"hello");
        assert!(pty.has_input());

        let data = pty.read_input();
        assert_eq!(data, b"hello");
        assert!(!pty.has_input());
    }

    #[test]
    fn fake_pty_type_string() {
        let pty = FakePty::new();

        pty.type_string("echo hello");
        pty.press_enter();

        let data = pty.read_input();
        assert_eq!(data, b"echo hello\r");
    }

    #[test]
    fn fake_pty_control_chars() {
        let pty = FakePty::new();

        pty.press_ctrl_c();
        assert_eq!(pty.read_input(), vec![0x03]);

        pty.press_ctrl_d();
        assert_eq!(pty.read_input(), vec![0x04]);
    }

    #[test]
    fn fake_pty_arrow_keys() {
        let pty = FakePty::new();

        pty.press_up();
        assert_eq!(pty.read_input(), b"\x1b[A");

        pty.press_down();
        assert_eq!(pty.read_input(), b"\x1b[B");

        pty.press_right();
        assert_eq!(pty.read_input(), b"\x1b[C");

        pty.press_left();
        assert_eq!(pty.read_input(), b"\x1b[D");
    }

    #[test]
    fn fake_pty_resize() {
        let mut pty = FakePty::new();

        pty.resize(100, 50);
        assert_eq!(pty.size(), (100, 50));
    }

    #[test]
    fn fake_pty_close() {
        let mut pty = FakePty::new();

        assert!(!pty.is_closed());
        pty.close();
        assert!(pty.is_closed());
    }

    #[tokio::test]
    async fn fake_pty_output() {
        let mut pty = FakePty::new();
        let mut rx = pty.take_output_receiver().unwrap();

        pty.write_output(b"test output").await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received, b"test output");
    }

    #[test]
    fn fake_pty_output_sync() {
        let mut pty = FakePty::new();
        let mut rx = pty.take_output_receiver().unwrap();

        pty.write_output_sync(b"sync output").unwrap();

        // Use try_recv for sync check
        let received = rx.try_recv().unwrap();
        assert_eq!(received, b"sync output");
    }
}
