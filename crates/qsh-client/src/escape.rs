//! Escape sequence handling for client-side commands.
//!
//! Implements mosh-style escape sequences: press escape key (default Ctrl+^),
//! then a command key (e.g., `.` to disconnect).

use std::time::{Duration, Instant};

/// Escape sequence commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeCommand {
    /// Disconnect from the server (escape + `.`).
    Disconnect,
    /// Toggle the status overlay (escape + `o`).
    ToggleOverlay,
    /// Send the escape key literally (escape + escape).
    SendEscapeKey,
}

/// Result of processing input through the escape handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscapeResult {
    /// No escape sequence active, pass through all bytes.
    PassThrough(Vec<u8>),
    /// Escape key pressed, waiting for command (bytes consumed).
    Waiting,
    /// Complete escape command recognized.
    Command(EscapeCommand),
}

/// State machine for escape sequence detection.
///
/// Mosh-style: escape key followed by a command key within a timeout.
/// If timeout expires or unknown key pressed, the buffered bytes are released.
#[derive(Debug)]
pub struct EscapeHandler {
    /// The escape key byte (e.g., 0x1e for Ctrl+^).
    escape_key: Option<u8>,
    /// Current state.
    state: EscapeState,
    /// When the escape key was pressed.
    escape_time: Option<Instant>,
    /// Timeout for command key after escape (default 1 second).
    timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeState {
    /// Normal state, not in escape sequence.
    Normal,
    /// Escape key pressed, waiting for command.
    Escaped,
}

impl EscapeHandler {
    /// Create a new escape handler with the given escape key.
    ///
    /// Pass `None` to disable escape handling entirely.
    pub fn new(escape_key: Option<u8>) -> Self {
        Self {
            escape_key,
            state: EscapeState::Normal,
            escape_time: None,
            timeout: Duration::from_secs(1),
        }
    }

    /// Set the timeout for command key after escape.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Process input bytes, returning the result.
    ///
    /// This should be called for each chunk of input from stdin.
    pub fn process(&mut self, input: &[u8]) -> EscapeResult {
        let Some(escape_key) = self.escape_key else {
            // Escape handling disabled
            return EscapeResult::PassThrough(input.to_vec());
        };

        // Check for timeout if we're in escaped state
        if self.state == EscapeState::Escaped
            && self.escape_time.is_some_and(|t| t.elapsed() > self.timeout)
        {
            // Timeout expired, release the escape key and reset
            self.state = EscapeState::Normal;
            self.escape_time = None;
            // Prepend the escape key to the input
            let mut result = vec![escape_key];
            result.extend_from_slice(input);
            return EscapeResult::PassThrough(result);
        }

        match self.state {
            EscapeState::Normal => {
                if input.len() == 1 && input[0] == escape_key {
                    // Single escape key pressed, enter escaped state
                    self.state = EscapeState::Escaped;
                    self.escape_time = Some(Instant::now());
                    EscapeResult::Waiting
                } else if input.starts_with(&[escape_key]) {
                    // Escape key at start of multi-byte input
                    // Check if second byte is a command
                    if input.len() >= 2 {
                        if let Some(cmd) = self.parse_command(input[1]) {
                            // Process remaining bytes after command
                            let remaining = &input[2..];
                            if remaining.is_empty() {
                                return EscapeResult::Command(cmd);
                            }
                            // There's more input after the command - this is unusual
                            // but we should handle it by returning the command
                            return EscapeResult::Command(cmd);
                        } else {
                            // Unknown command, pass through everything
                            return EscapeResult::PassThrough(input.to_vec());
                        }
                    }
                    // Just escape key
                    self.state = EscapeState::Escaped;
                    self.escape_time = Some(Instant::now());
                    EscapeResult::Waiting
                } else {
                    // No escape key, pass through
                    EscapeResult::PassThrough(input.to_vec())
                }
            }
            EscapeState::Escaped => {
                // We're waiting for a command key
                if input.is_empty() {
                    return EscapeResult::Waiting;
                }

                let first = input[0];
                if let Some(cmd) = self.parse_command(first) {
                    self.state = EscapeState::Normal;
                    self.escape_time = None;
                    EscapeResult::Command(cmd)
                } else {
                    // Unknown command key, release escape + this input
                    self.state = EscapeState::Normal;
                    self.escape_time = None;
                    let mut result = vec![escape_key];
                    result.extend_from_slice(input);
                    EscapeResult::PassThrough(result)
                }
            }
        }
    }

    /// Parse a command byte after the escape key.
    fn parse_command(&self, byte: u8) -> Option<EscapeCommand> {
        match byte {
            b'.' => Some(EscapeCommand::Disconnect),
            b'o' | b'O' => Some(EscapeCommand::ToggleOverlay),
            // Pressing escape twice sends the escape key
            key if Some(key) == self.escape_key => Some(EscapeCommand::SendEscapeKey),
            _ => None,
        }
    }

    /// Get the escape key byte, if set.
    pub fn escape_key(&self) -> Option<u8> {
        self.escape_key
    }

    /// Check if we're currently in the escaped state (waiting for command).
    pub fn is_waiting(&self) -> bool {
        self.state == EscapeState::Escaped
    }

    /// Reset the state machine to normal.
    pub fn reset(&mut self) {
        self.state = EscapeState::Normal;
        self.escape_time = None;
    }
}

/// Parse escape key specification.
///
/// Supports:
/// - "ctrl+^" or "ctrl+6" -> 0x1e (Ctrl+^)
/// - "ctrl+]" -> 0x1d
/// - "ctrl+a" through "ctrl+z" -> 0x01-0x1a
/// - "none" -> None (disabled)
pub fn parse_escape_key(spec: &str) -> Option<u8> {
    let spec = spec.to_lowercase();

    if spec == "none" {
        return None;
    }

    if let Some(suffix) = spec.strip_prefix("ctrl+") {
        match suffix {
            "^" | "6" => Some(0x1e), // Ctrl+^ (also Ctrl+6 on US keyboards)
            "]" => Some(0x1d),       // Ctrl+]
            "[" => Some(0x1b),       // Ctrl+[ (ESC)
            "\\" => Some(0x1c),      // Ctrl+\
            "_" => Some(0x1f),       // Ctrl+_
            c if c.len() == 1 => {
                let ch = c.chars().next()?;
                if ch.is_ascii_lowercase() {
                    // ctrl+a = 0x01, ctrl+b = 0x02, ..., ctrl+z = 0x1a
                    Some((ch as u8) - b'a' + 1)
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ctrl_caret() {
        assert_eq!(parse_escape_key("ctrl+^"), Some(0x1e));
        assert_eq!(parse_escape_key("ctrl+6"), Some(0x1e));
        assert_eq!(parse_escape_key("Ctrl+^"), Some(0x1e));
    }

    #[test]
    fn parse_ctrl_bracket() {
        assert_eq!(parse_escape_key("ctrl+]"), Some(0x1d));
        assert_eq!(parse_escape_key("ctrl+["), Some(0x1b));
    }

    #[test]
    fn parse_ctrl_letters() {
        assert_eq!(parse_escape_key("ctrl+a"), Some(0x01));
        assert_eq!(parse_escape_key("ctrl+z"), Some(0x1a));
        assert_eq!(parse_escape_key("ctrl+o"), Some(0x0f));
    }

    #[test]
    fn parse_none() {
        assert_eq!(parse_escape_key("none"), None);
        assert_eq!(parse_escape_key("NONE"), None);
    }

    #[test]
    fn parse_invalid() {
        assert_eq!(parse_escape_key("invalid"), None);
        assert_eq!(parse_escape_key("ctrl+"), None);
        assert_eq!(parse_escape_key("ctrl+ab"), None);
    }

    #[test]
    fn handler_disabled() {
        let mut handler = EscapeHandler::new(None);
        let result = handler.process(&[0x1e, b'.']);
        assert_eq!(result, EscapeResult::PassThrough(vec![0x1e, b'.']));
    }

    #[test]
    fn handler_normal_passthrough() {
        let mut handler = EscapeHandler::new(Some(0x1e));
        let result = handler.process(b"hello");
        assert_eq!(result, EscapeResult::PassThrough(b"hello".to_vec()));
    }

    #[test]
    fn handler_escape_then_dot() {
        let mut handler = EscapeHandler::new(Some(0x1e));

        // First: escape key alone
        let result = handler.process(&[0x1e]);
        assert_eq!(result, EscapeResult::Waiting);
        assert!(handler.is_waiting());

        // Then: dot
        let result = handler.process(&[b'.']);
        assert_eq!(result, EscapeResult::Command(EscapeCommand::Disconnect));
        assert!(!handler.is_waiting());
    }

    #[test]
    fn handler_escape_escape_sends_key() {
        let mut handler = EscapeHandler::new(Some(0x1e));

        let result = handler.process(&[0x1e]);
        assert_eq!(result, EscapeResult::Waiting);

        let result = handler.process(&[0x1e]);
        assert_eq!(result, EscapeResult::Command(EscapeCommand::SendEscapeKey));
    }

    #[test]
    fn handler_escape_o_toggles_overlay() {
        let mut handler = EscapeHandler::new(Some(0x1e));

        let result = handler.process(&[0x1e]);
        assert_eq!(result, EscapeResult::Waiting);

        let result = handler.process(&[b'o']);
        assert_eq!(result, EscapeResult::Command(EscapeCommand::ToggleOverlay));

        // Also works with uppercase
        let result = handler.process(&[0x1e, b'O']);
        assert_eq!(result, EscapeResult::Command(EscapeCommand::ToggleOverlay));
    }

    #[test]
    fn handler_escape_unknown_releases() {
        let mut handler = EscapeHandler::new(Some(0x1e));

        let result = handler.process(&[0x1e]);
        assert_eq!(result, EscapeResult::Waiting);

        // Unknown key 'x' should release escape + x
        let result = handler.process(&[b'x']);
        assert_eq!(result, EscapeResult::PassThrough(vec![0x1e, b'x']));
        assert!(!handler.is_waiting());
    }

    #[test]
    fn handler_fast_escape_dot() {
        let mut handler = EscapeHandler::new(Some(0x1e));

        // Both bytes arrive together
        let result = handler.process(&[0x1e, b'.']);
        assert_eq!(result, EscapeResult::Command(EscapeCommand::Disconnect));
    }

    #[test]
    fn handler_timeout() {
        let mut handler = EscapeHandler::new(Some(0x1e)).with_timeout(Duration::from_millis(1));

        let result = handler.process(&[0x1e]);
        assert_eq!(result, EscapeResult::Waiting);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        // Next input should release the escape key
        let result = handler.process(&[b'a']);
        assert_eq!(result, EscapeResult::PassThrough(vec![0x1e, b'a']));
    }
}
