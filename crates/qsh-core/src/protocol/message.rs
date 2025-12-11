//! Top-level protocol message enum.
//!
//! This module defines the Message enum that encompasses all possible
//! qsh protocol messages across connection-level, channel lifecycle,
//! and channel data operations.

use serde::{Deserialize, Serialize};

use super::{
    ChannelAcceptPayload, ChannelClosePayload, ChannelData, ChannelOpenPayload,
    ChannelRejectPayload, GlobalReplyPayload, GlobalRequestPayload, HeartbeatPayload,
    HelloAckPayload, HelloPayload, ResizePayload, ShutdownPayload, StateAckPayload,
};

#[cfg(feature = "standalone")]
use super::{AuthChallengePayload, AuthFailurePayload, AuthResponsePayload};

// =============================================================================
// Top-level Message Enum
// =============================================================================

/// Top-level protocol message type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    // =========================================================================
    // Connection-level messages (control stream)
    // =========================================================================
    /// Client hello with session key and capabilities.
    Hello(HelloPayload),
    /// Server acknowledgment of hello.
    HelloAck(HelloAckPayload),
    /// Graceful shutdown notification.
    Shutdown(ShutdownPayload),
    /// Heartbeat for RTT measurement (mosh-style timestamp echo).
    Heartbeat(HeartbeatPayload),

    // =========================================================================
    // Global requests (control stream)
    // =========================================================================
    /// Connection-level request (for port forwarding setup, etc.).
    GlobalRequest(GlobalRequestPayload),
    /// Response to a global request.
    GlobalReply(GlobalReplyPayload),

    // =========================================================================
    // Channel lifecycle messages (control stream)
    // =========================================================================
    /// Request to open a new channel.
    ChannelOpen(ChannelOpenPayload),
    /// Accept a channel open request.
    ChannelAccept(ChannelAcceptPayload),
    /// Reject a channel open request.
    ChannelReject(ChannelRejectPayload),
    /// Close a channel.
    ChannelClose(ChannelClosePayload),

    // =========================================================================
    // Per-channel control messages (control stream)
    // =========================================================================
    /// Terminal resize notification.
    Resize(ResizePayload),
    /// Client acknowledgment of state update.
    StateAck(StateAckPayload),

    // =========================================================================
    // Channel data (channel streams)
    // =========================================================================
    /// Data on a channel stream (wrapped payload).
    ChannelDataMsg(ChannelData),

    // =========================================================================
    // Standalone authentication messages (feature-gated)
    // =========================================================================
    /// Server sends after QUIC connect (includes server signature for client to verify).
    #[cfg(feature = "standalone")]
    AuthChallenge(AuthChallengePayload),
    /// Client response (proves client identity).
    #[cfg(feature = "standalone")]
    AuthResponse(AuthResponsePayload),
    /// Authentication failure (sent by server).
    #[cfg(feature = "standalone")]
    AuthFailure(AuthFailurePayload),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        Capabilities, ChannelAcceptData, ChannelId, ChannelParams, ChannelRejectCode, SessionId,
        ShutdownReason, TerminalParams,
    };
    use crate::terminal::TerminalState;

    #[test]
    fn test_message_variants_exist() {
        // Test that all message variants can be constructed
        let _hello = Message::Hello(HelloPayload {
            protocol_version: 1,
            session_key: [0u8; 32],
            client_nonce: 0,
            capabilities: Capabilities::default(),
            resume_session: None,
        });

        let _hello_ack = Message::HelloAck(HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: Capabilities::default(),
            session_id: SessionId::from_bytes([0; 16]),
            server_nonce: 0,
            zero_rtt_available: false,
            existing_channels: Vec::new(),
        });

        let _resize = Message::Resize(ResizePayload {
            channel_id: None,
            cols: 80,
            rows: 24,
        });

        let _shutdown = Message::Shutdown(ShutdownPayload {
            reason: ShutdownReason::UserRequested,
            message: None,
        });

        let _ack = Message::StateAck(StateAckPayload {
            channel_id: None,
            generation: 1,
        });
    }

    #[test]
    fn test_channel_message_variants() {
        // Test new channel-based message variants
        let ch = ChannelId::client(0);

        let _channel_open = Message::ChannelOpen(ChannelOpenPayload {
            channel_id: ch,
            params: ChannelParams::Terminal(TerminalParams::default()),
        });

        let _channel_accept = Message::ChannelAccept(ChannelAcceptPayload {
            channel_id: ch,
            data: ChannelAcceptData::Terminal {
                initial_state: TerminalState::default(),
            },
        });

        let _channel_reject = Message::ChannelReject(ChannelRejectPayload {
            channel_id: ch,
            code: ChannelRejectCode::ResourceShortage,
            message: "too many channels".into(),
        });
    }

    #[test]
    fn test_message_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Message>();
    }
}
