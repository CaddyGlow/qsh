//! Channel handlers for the qsh server.
//!
//! This module provides type-specific channel implementations:
//! - `TerminalChannel`: Interactive PTY sessions
//! - `FileTransferChannel`: File upload/download operations
//! - `ForwardChannel`: Port forwarding (direct-tcpip, forwarded-tcpip, dynamic)

mod terminal;
mod file_transfer;
mod forward;

pub use terminal::TerminalChannel;
pub use file_transfer::FileTransferChannel;
pub use forward::ForwardChannel;

use qsh_core::error::Result;
use qsh_core::transport::QuicStream;

/// Handle for an active channel.
///
/// This enum wraps the type-specific channel implementations and provides
/// a uniform interface for the connection handler.
#[derive(Clone)]
pub enum ChannelHandle {
    /// Interactive terminal (PTY).
    Terminal(TerminalChannel),
    /// File transfer.
    FileTransfer(FileTransferChannel),
    /// Port forward (direct, remote, or dynamic).
    Forward(ForwardChannel),
}

impl ChannelHandle {
    /// Close the channel and release resources.
    pub async fn close(&self) {
        match self {
            ChannelHandle::Terminal(ch) => ch.close().await,
            ChannelHandle::FileTransfer(ch) => ch.close().await,
            ChannelHandle::Forward(ch) => ch.close().await,
        }
    }

    /// Handle an incoming stream for this channel.
    pub async fn handle_incoming_stream(&self, stream: QuicStream) -> Result<()> {
        match self {
            ChannelHandle::Terminal(ch) => ch.handle_incoming_stream(stream).await,
            ChannelHandle::FileTransfer(ch) => ch.handle_incoming_stream(stream).await,
            ChannelHandle::Forward(ch) => ch.handle_incoming_stream(stream).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_handle_variants() {
        // Just verify the enum compiles with all variants
        fn _assert_send_sync<T: Send + Sync>() {}
        // Note: ChannelHandle may not be Send+Sync due to internal state
        // This is a compile-time check that the enum structure is correct
    }
}
