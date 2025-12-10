//! Property-based tests for the protocol codec.
//!
//! These tests use proptest to verify:
//! - Codec roundtrip for arbitrary messages
//! - Codec never panics on arbitrary input
//! - Length prefix correctness

#![cfg(test)]

use bytes::BytesMut;
use proptest::prelude::*;

use crate::protocol::{
    Capabilities, ChannelData, ChannelId, ChannelOpenPayload, ChannelParams, ChannelPayload, Codec,
    HelloPayload, Message, OutputMode, ResizePayload, ShutdownPayload, ShutdownReason,
    StateAckPayload, TermSize, TerminalInputData, TerminalParams,
};

#[cfg(feature = "standalone")]
use crate::protocol::{
    AuthChallengePayload, AuthErrorCode, AuthFailurePayload, AuthResponsePayload,
};

// =============================================================================
// Arbitrary Generators
// =============================================================================

prop_compose! {
    fn arb_capabilities()(
        predictive_echo in any::<bool>(),
        compression in any::<bool>(),
        max_forwards in any::<u16>(),
        tunnel in any::<bool>(),
    ) -> Capabilities {
        Capabilities {
            predictive_echo,
            compression,
            max_forwards,
            tunnel,
        }
    }
}

prop_compose! {
    fn arb_term_size()(
        cols in 1u16..=500,
        rows in 1u16..=200,
    ) -> TermSize {
        TermSize { cols, rows }
    }
}

prop_compose! {
    fn arb_hello()(
        protocol_version in any::<u32>(),
        session_key in any::<[u8; 32]>(),
        client_nonce in any::<u64>(),
        capabilities in arb_capabilities(),
    ) -> HelloPayload {
        HelloPayload {
            protocol_version,
            session_key,
            client_nonce,
            capabilities,
            resume_session: None,
        }
    }
}

prop_compose! {
    fn arb_terminal_input()(
        sequence in any::<u64>(),
        data in prop::collection::vec(any::<u8>(), 0..1024),
        predictable in any::<bool>(),
    ) -> TerminalInputData {
        TerminalInputData {
            sequence,
            data,
            predictable,
        }
    }
}

fn arb_shutdown_reason() -> impl Strategy<Value = ShutdownReason> {
    prop_oneof![
        Just(ShutdownReason::UserRequested),
        Just(ShutdownReason::IdleTimeout),
        Just(ShutdownReason::ServerShutdown),
        Just(ShutdownReason::ProtocolError),
        Just(ShutdownReason::AuthFailure),
    ]
}

prop_compose! {
    fn arb_channel_id()(
        id in any::<u64>(),
        is_client in any::<bool>(),
    ) -> ChannelId {
        if is_client {
            ChannelId::client(id)
        } else {
            ChannelId::server(id)
        }
    }
}

fn arb_output_mode() -> impl Strategy<Value = OutputMode> {
    prop_oneof![
        Just(OutputMode::Direct),
        Just(OutputMode::Mosh),
        Just(OutputMode::StateDiff),
    ]
}

prop_compose! {
    fn arb_terminal_params()(
        term_size in arb_term_size(),
        term_type in "[a-z0-9-]{1,32}",
        env in prop::collection::vec(("[A-Z_]{1,16}", "[a-zA-Z0-9_-]{0,32}"), 0..3),
        command in prop::option::of("[a-z0-9 -]{1,64}"),
        allocate_pty in any::<bool>(),
        last_generation in any::<u64>(),
        last_input_seq in any::<u64>(),
        output_mode in arb_output_mode(),
    ) -> TerminalParams {
        TerminalParams {
            term_size,
            term_type,
            env: env.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            shell: None,
            command: command.map(|s| s.to_string()),
            allocate_pty,
            last_generation,
            last_input_seq,
            output_mode,
        }
    }
}

// =============================================================================
// Standalone Auth Generators (Feature-gated)
// =============================================================================

#[cfg(feature = "standalone")]
fn arb_auth_error_code() -> impl Strategy<Value = AuthErrorCode> {
    prop_oneof![
        Just(AuthErrorCode::AuthFailed),
        Just(AuthErrorCode::Timeout),
        Just(AuthErrorCode::ProtocolError),
        Just(AuthErrorCode::InternalError),
    ]
}

#[cfg(feature = "standalone")]
prop_compose! {
    fn arb_auth_challenge()(
        server_public_key in "[a-zA-Z0-9+/= -]{64,256}",
        challenge in any::<[u8; 32]>(),
        server_nonce in any::<[u8; 32]>(),
        server_signature in prop::collection::vec(any::<u8>(), 64..256),
    ) -> AuthChallengePayload {
        AuthChallengePayload {
            server_public_key,
            challenge,
            server_nonce,
            server_signature,
        }
    }
}

#[cfg(feature = "standalone")]
prop_compose! {
    fn arb_auth_response()(
        client_public_key in "[a-zA-Z0-9+/= -]{64,256}",
        client_nonce in any::<[u8; 32]>(),
        signature in prop::collection::vec(any::<u8>(), 64..256),
    ) -> AuthResponsePayload {
        AuthResponsePayload {
            client_public_key,
            client_nonce,
            signature,
        }
    }
}

#[cfg(feature = "standalone")]
prop_compose! {
    fn arb_auth_failure()(
        code in arb_auth_error_code(),
        message in "[a-z ]{0,64}",
    ) -> AuthFailurePayload {
        AuthFailurePayload {
            code,
            message,
        }
    }
}

/// Generate an arbitrary Message (base messages without feature-gated variants)
fn arb_message_base() -> impl Strategy<Value = Message> {
    prop_oneof![
        // Control messages
        arb_hello().prop_map(Message::Hello),
        (arb_channel_id(), any::<u16>(), any::<u16>())
            .prop_map(|(ch, cols, rows)| Message::Resize(ResizePayload {
                channel_id: Some(ch),
                cols,
                rows,
            })),
        (arb_shutdown_reason(), any::<Option<String>>())
            .prop_map(|(reason, message)| Message::Shutdown(ShutdownPayload { reason, message })),
        // Channel open
        (arb_channel_id(), arb_terminal_params()).prop_map(|(ch, params)| {
            Message::ChannelOpen(ChannelOpenPayload {
                channel_id: ch,
                params: ChannelParams::Terminal(params),
            })
        }),
        // Channel data with terminal input
        (arb_channel_id(), arb_terminal_input()).prop_map(|(ch, input)| {
            Message::ChannelDataMsg(ChannelData {
                channel_id: ch,
                payload: ChannelPayload::TerminalInput(input),
            })
        }),
        // State ack
        (arb_channel_id(), any::<u64>()).prop_map(|(ch, g)| Message::StateAck(StateAckPayload {
            channel_id: Some(ch),
            generation: g,
        })),
    ]
}

/// Generate an arbitrary Message (without standalone feature)
#[cfg(not(feature = "standalone"))]
fn arb_message() -> impl Strategy<Value = Message> {
    arb_message_base()
}

/// Generate an arbitrary Message (with standalone feature)
#[cfg(feature = "standalone")]
fn arb_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        // Base messages (weighted higher since there are more of them)
        10 => arb_message_base(),
        // Auth messages
        1 => arb_auth_challenge().prop_map(Message::AuthChallenge),
        1 => arb_auth_response().prop_map(Message::AuthResponse),
        1 => arb_auth_failure().prop_map(Message::AuthFailure),
    ]
}

// =============================================================================
// Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn roundtrip_arbitrary_message(msg in arb_message()) {
        let encoded = Codec::encode(&msg).unwrap();
        let decoded = Codec::decode_slice(&encoded).unwrap().unwrap();
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_terminal_input(
        channel_id in arb_channel_id(),
        seq in any::<u64>(),
        data in prop::collection::vec(any::<u8>(), 0..4096),
        predictable in any::<bool>(),
    ) {
        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id,
            payload: ChannelPayload::TerminalInput(TerminalInputData {
                sequence: seq,
                data,
                predictable,
            }),
        });

        let encoded = Codec::encode(&msg).unwrap();
        let decoded = Codec::decode_slice(&encoded).unwrap().unwrap();
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn codec_never_panics_on_arbitrary_input(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        let mut buf = BytesMut::from(&data[..]);
        // Should not panic, may return Ok(None) or Err
        let _ = Codec::decode(&mut buf);
    }

    #[test]
    fn encoded_length_prefix_matches_payload(msg in arb_message()) {
        let encoded = Codec::encode(&msg).unwrap();

        // First 4 bytes should be little-endian length
        let len = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;

        // Length should match actual payload
        prop_assert_eq!(len, encoded.len() - 4);
    }

    #[test]
    fn partial_buffer_returns_none(msg in arb_message(), cut_at in 0usize..=3) {
        let encoded = Codec::encode(&msg).unwrap();

        // Cut at different points to ensure partial always returns None
        if cut_at < encoded.len() {
            let partial = &encoded[..cut_at];
            let result = Codec::decode_slice(partial);
            prop_assert!(result.is_ok());
            prop_assert!(result.unwrap().is_none());
        }
    }
}

// Extended tests (run with --ignored)
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    #[ignore = "extended property test - run with --ignored"]
    fn extended_roundtrip(msg in arb_message()) {
        let encoded = Codec::encode(&msg).unwrap();
        let decoded = Codec::decode_slice(&encoded).unwrap().unwrap();
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    #[ignore = "extended property test - run with --ignored"]
    fn extended_fuzz_decode(data in prop::collection::vec(any::<u8>(), 0..100000)) {
        let mut buf = BytesMut::from(&data[..]);
        let _ = Codec::decode(&mut buf);
    }
}
