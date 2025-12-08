//! Wire protocol codec for qsh messages.
//!
//! Format: 4-byte little-endian length prefix + bincode-encoded Message
//!
//! The codec ensures:
//! - Messages are length-prefixed for stream framing
//! - Maximum message size is enforced
//! - Partial reads return Ok(None) to support streaming

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::constants::MAX_MESSAGE_SIZE;
use crate::error::{Error, Result};
use crate::protocol::Message;

/// Length of the frame header (4 bytes, little-endian u32).
pub const FRAME_HEADER_LEN: usize = 4;

/// Codec for length-prefixed bincode encoding of messages.
pub struct Codec;

impl Codec {
    /// Encode a message to bytes with length prefix.
    ///
    /// Returns the encoded bytes including the 4-byte length header.
    pub fn encode(msg: &Message) -> Result<Bytes> {
        let payload = bincode::serialize(msg).map_err(|e| Error::Codec {
            message: format!("serialization failed: {}", e),
        })?;

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Codec {
                message: format!(
                    "message too large: {} bytes (max {})",
                    payload.len(),
                    MAX_MESSAGE_SIZE
                ),
            });
        }

        let len = payload.len() as u32;
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
        buf.put_u32_le(len);
        buf.put_slice(&payload);

        Ok(buf.freeze())
    }

    /// Decode a message from a buffer.
    ///
    /// Returns:
    /// - Ok(Some(msg)) if a complete message was decoded (buffer is advanced)
    /// - Ok(None) if more data is needed (buffer unchanged)
    /// - Err if the data is invalid
    ///
    /// The buffer is only consumed on successful decode.
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Message>> {
        // Need at least 4 bytes for length
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        // Peek the length without consuming
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        // Check for oversized message before waiting for more data
        if len > MAX_MESSAGE_SIZE {
            return Err(Error::Codec {
                message: format!(
                    "message length {} exceeds maximum {}",
                    len, MAX_MESSAGE_SIZE
                ),
            });
        }

        // Check if we have the full message
        if buf.len() < FRAME_HEADER_LEN + len {
            return Ok(None);
        }

        // Consume the header
        buf.advance(FRAME_HEADER_LEN);

        // Consume and decode the payload
        let payload = buf.split_to(len);
        let msg = bincode::deserialize(&payload).map_err(|e| Error::Codec {
            message: format!("deserialization failed: {}", e),
        })?;

        Ok(Some(msg))
    }

    /// Decode from a slice (convenience for testing).
    /// Note: This creates a BytesMut copy; for streaming use decode() directly.
    pub fn decode_slice(data: &[u8]) -> Result<Option<Message>> {
        let mut buf = BytesMut::from(data);
        Self::decode(&mut buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        Capabilities, ChannelData, ChannelId, ChannelPayload, HelloAckPayload, HelloPayload,
        ResizePayload, SessionId, ShutdownPayload, ShutdownReason, StateAckPayload,
        TerminalInputData,
    };

    #[test]
    fn encode_decode_roundtrip_resize() {
        let msg = Message::Resize(ResizePayload {
            channel_id: None,
            cols: 80,
            rows: 24,
        });
        let encoded = Codec::encode(&msg).unwrap();
        let decoded = Codec::decode_slice(&encoded).unwrap().unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_hello() {
        let msg = Message::Hello(HelloPayload {
            protocol_version: 1,
            session_key: [0xAB; 32],
            client_nonce: 12345,
            capabilities: Capabilities::default(),
            resume_session: None,
        });

        let encoded = Codec::encode(&msg).unwrap();
        let decoded = Codec::decode_slice(&encoded).unwrap().unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_hello_ack() {
        let msg = Message::HelloAck(HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: Capabilities::default(),
            session_id: SessionId::from_bytes([0; 16]),
            server_nonce: 0,
            zero_rtt_available: false,
            existing_channels: Vec::new(),
        });

        let encoded = Codec::encode(&msg).unwrap();
        let decoded = Codec::decode_slice(&encoded).unwrap().unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_terminal_input() {
        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id: ChannelId::client(0),
            payload: ChannelPayload::TerminalInput(TerminalInputData {
                sequence: 999,
                data: vec![0x61, 0x62, 0x63], // "abc"
                predictable: true,
                timestamp: 1234,
                timestamp_reply: crate::timing::TIMESTAMP_NONE,
            }),
        });

        let encoded = Codec::encode(&msg).unwrap();
        let decoded = Codec::decode_slice(&encoded).unwrap().unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_partial_returns_none() {
        let msg = Message::Resize(ResizePayload {
            channel_id: None,
            cols: 120,
            rows: 40,
        });
        let encoded = Codec::encode(&msg).unwrap();

        // Only provide half the bytes
        let partial = &encoded[..encoded.len() / 2];
        assert!(Codec::decode_slice(partial).unwrap().is_none());
    }

    #[test]
    fn decode_empty_returns_none() {
        assert!(Codec::decode_slice(&[]).unwrap().is_none());
    }

    #[test]
    fn decode_header_only_returns_none() {
        // 4 bytes header saying there's 100 bytes of payload, but no payload
        let mut buf = BytesMut::new();
        buf.put_u32_le(100);
        assert!(Codec::decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_length_too_large_returns_error() {
        let mut buf = BytesMut::new();
        // Put a huge length value
        buf.put_u32_le((MAX_MESSAGE_SIZE + 1) as u32);
        // Add some dummy data
        buf.put_slice(&[0u8; 100]);

        let result = Codec::decode(&mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::Codec { .. }));
    }

    #[test]
    fn decode_invalid_bincode_returns_error() {
        let mut buf = BytesMut::new();
        // Say we have 10 bytes
        buf.put_u32_le(10);
        // Put garbage that won't deserialize
        buf.put_slice(&[0xFF; 10]);

        let result = Codec::decode(&mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::Codec { .. }));
    }

    #[test]
    fn encode_creates_length_prefix() {
        let msg = Message::Resize(ResizePayload {
            channel_id: None,
            cols: 200,
            rows: 50,
        });
        let encoded = Codec::encode(&msg).unwrap();

        // First 4 bytes should be the length
        let len = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;

        // Length should match remaining bytes
        assert_eq!(len, encoded.len() - FRAME_HEADER_LEN);
    }

    #[test]
    fn multiple_messages_in_buffer() {
        let msg1 = Message::Resize(ResizePayload {
            channel_id: None,
            cols: 80,
            rows: 24,
        });
        let msg2 = Message::Shutdown(ShutdownPayload {
            reason: ShutdownReason::UserRequested,
            message: Some("bye".into()),
        });
        let msg3 = Message::StateAck(StateAckPayload {
            channel_id: None,
            generation: 3,
        });

        let enc1 = Codec::encode(&msg1).unwrap();
        let enc2 = Codec::encode(&msg2).unwrap();
        let enc3 = Codec::encode(&msg3).unwrap();

        // Concatenate all messages
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&enc1);
        buf.extend_from_slice(&enc2);
        buf.extend_from_slice(&enc3);

        // Decode should consume exactly one message at a time
        let decoded1 = Codec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded1, msg1);

        let decoded2 = Codec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded2, msg2);

        let decoded3 = Codec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded3, msg3);

        // Buffer should now be empty
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_advances_buffer_only_on_success() {
        let msg = Message::Resize(ResizePayload {
            channel_id: None,
            cols: 20,
            rows: 10,
        });
        let encoded = Codec::encode(&msg).unwrap();

        let mut buf = BytesMut::from(&encoded[..]);

        // Successful decode should consume the message
        let _ = Codec::decode(&mut buf).unwrap().unwrap();
        assert!(buf.is_empty());

        // Reset and try with partial data
        buf = BytesMut::from(&encoded[..encoded.len() - 1]);
        let partial_len = buf.len();

        // Partial decode should not consume anything
        assert!(Codec::decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), partial_len);
    }
}
