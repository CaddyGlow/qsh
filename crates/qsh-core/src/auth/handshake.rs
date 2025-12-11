//! Shared handshake utilities for standalone authentication.
//!
//! Provides common message framing and reading/writing functions
//! used by both client and server during the authentication handshake.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::constants::MAX_MESSAGE_SIZE;
use crate::protocol::{Codec, Message};
use crate::{Error, Result};

/// Read a length-prefixed message from a stream.
///
/// This is the common framing used by both client and server
/// during the authentication handshake.
pub async fn read_message<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Message> {
    // Read length prefix (4 bytes, little-endian)
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(Error::Io)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(Error::Protocol {
            message: "message too large".into(),
        });
    }

    // Read message body
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(Error::Io)?;

    // Decode with length prefix for Codec
    let mut full_buf = BytesMut::with_capacity(4 + len);
    full_buf.extend_from_slice(&len_buf);
    full_buf.extend_from_slice(&buf);

    Codec::decode(&mut full_buf)?.ok_or_else(|| Error::Protocol {
        message: "incomplete message".into(),
    })
}

/// Write a length-prefixed message to a stream.
pub async fn write_message<W: AsyncWrite + Unpin>(send: &mut W, msg: &Message) -> Result<()> {
    let encoded = Codec::encode(msg)?;
    send.write_all(&encoded).await.map_err(Error::Io)?;
    Ok(())
}

/// Read a specific message type, returning an error for unexpected types.
///
/// The `extractor` function should return `Some(T)` if the message is the
/// expected type, or `None` otherwise.
pub async fn read_expected<R, T, F>(recv: &mut R, extractor: F, expected_name: &str) -> Result<T>
where
    R: AsyncRead + Unpin,
    F: FnOnce(Message) -> Option<T>,
{
    let msg = read_message(recv).await?;
    extractor(msg).ok_or_else(|| Error::Protocol {
        message: format!("expected {}", expected_name),
    })
}

/// Read an AuthChallenge message.
pub async fn read_auth_challenge<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<crate::protocol::AuthChallengePayload> {
    read_expected(
        recv,
        |msg| match msg {
            Message::AuthChallenge(c) => Some(c),
            _ => None,
        },
        "AuthChallenge",
    )
    .await
}

/// Read an AuthResponse message.
pub async fn read_auth_response<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<crate::protocol::AuthResponsePayload> {
    read_expected(
        recv,
        |msg| match msg {
            Message::AuthResponse(r) => Some(r),
            _ => None,
        },
        "AuthResponse",
    )
    .await
}

/// Result of reading an auth message that could be either success or failure.
pub enum AuthMessageResult<T> {
    /// Expected message received.
    Success(T),
    /// Auth failure received.
    Failure(crate::protocol::AuthFailurePayload),
    /// Unexpected message type.
    Unexpected(Message),
}

/// Read an auth message, handling AuthFailure gracefully.
///
/// Returns `AuthMessageResult` to let caller handle all cases.
pub async fn read_auth_message_or_failure<R, T, F>(
    recv: &mut R,
    extractor: F,
) -> Result<AuthMessageResult<T>>
where
    R: AsyncRead + Unpin,
    F: FnOnce(&Message) -> Option<T>,
{
    let msg = read_message(recv).await?;

    // Check for expected type first
    if let Some(value) = extractor(&msg) {
        return Ok(AuthMessageResult::Success(value));
    }

    // Check for auth failure
    if let Message::AuthFailure(f) = msg {
        return Ok(AuthMessageResult::Failure(f));
    }

    // Unexpected message
    Ok(AuthMessageResult::Unexpected(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AuthChallengePayload, AuthResponsePayload};
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_write_read_message_roundtrip() {
        let (mut client, mut server) = duplex(4096);

        let original = Message::AuthChallenge(AuthChallengePayload {
            server_public_key: "ssh-ed25519 AAAA...".to_string(),
            challenge: [0x42; 32],
            server_nonce: [0x43; 32],
            server_signature: vec![1, 2, 3, 4],
        });

        // Write from client side
        write_message(&mut client, &original).await.unwrap();

        // Read from server side
        let received = read_message(&mut server).await.unwrap();

        match received {
            Message::AuthChallenge(c) => {
                assert_eq!(c.server_public_key, "ssh-ed25519 AAAA...");
                assert_eq!(c.challenge, [0x42; 32]);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_read_expected_success() {
        let (mut client, mut server) = duplex(4096);

        let original = Message::AuthResponse(AuthResponsePayload {
            client_public_key: "ssh-ed25519 BBBB...".to_string(),
            client_nonce: [0x44; 32],
            signature: vec![5, 6, 7, 8],
        });

        write_message(&mut client, &original).await.unwrap();

        let response = read_auth_response(&mut server).await.unwrap();
        assert_eq!(response.client_public_key, "ssh-ed25519 BBBB...");
    }

    #[tokio::test]
    async fn test_read_expected_wrong_type() {
        let (mut client, mut server) = duplex(4096);

        // Send AuthChallenge but expect AuthResponse
        let wrong = Message::AuthChallenge(AuthChallengePayload {
            server_public_key: "test".to_string(),
            challenge: [0; 32],
            server_nonce: [0; 32],
            server_signature: vec![],
        });

        write_message(&mut client, &wrong).await.unwrap();

        let result = read_auth_response(&mut server).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_message_too_large() {
        let (mut client, mut server) = duplex(4096);

        // Write a fake length that's too large
        let fake_len = (MAX_MESSAGE_SIZE + 1) as u32;
        client.write_all(&fake_len.to_le_bytes()).await.unwrap();

        let result = read_message(&mut server).await;
        assert!(matches!(result, Err(Error::Protocol { .. })));
    }
}
