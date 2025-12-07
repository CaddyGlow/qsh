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
    Capabilities, Codec, ForwardAcceptPayload, ForwardClosePayload, ForwardDataPayload,
    ForwardEofPayload, ForwardRejectPayload, ForwardRequestPayload, ForwardSpec, HelloPayload,
    Message, ResizePayload, ShutdownPayload, ShutdownReason, StateAckPayload, TermSize,
    TerminalInputPayload,
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
        channel_model in any::<bool>(),
    ) -> Capabilities {
        Capabilities {
            predictive_echo,
            compression,
            max_forwards,
            tunnel,
            channel_model,
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
        term_size in arb_term_size(),
        term_type in "[a-z0-9-]{1,32}",
        env in prop::collection::vec(("[A-Z_]{1,16}", "[a-zA-Z0-9_-]{0,32}"), 0..3),
        last_generation in any::<u64>(),
        last_input_seq in any::<u64>(),
    ) -> HelloPayload {
        HelloPayload {
            protocol_version,
            session_key,
            client_nonce,
            capabilities,
            resume_session: None,
            term_size,
            term_type,
            env: env.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            last_generation,
            last_input_seq,
        }
    }
}

prop_compose! {
    fn arb_terminal_input()(
        sequence in any::<u64>(),
        data in prop::collection::vec(any::<u8>(), 0..1024),
        predictable in any::<bool>(),
    ) -> TerminalInputPayload {
        TerminalInputPayload {
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
    fn arb_forward_spec()(
        variant in 0u8..3,
        bind_ip in any::<[u8; 4]>(),
        bind_port in any::<u16>(),
        target_host in "[a-z.]{1,32}",
        target_port in any::<u16>(),
    ) -> ForwardSpec {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(bind_ip)), bind_port);
        match variant {
            0 => ForwardSpec::Local { bind_addr, target_host, target_port },
            1 => ForwardSpec::Remote { bind_addr, target_host, target_port },
            _ => ForwardSpec::Dynamic { bind_addr },
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
#[allow(deprecated)]
fn arb_message_base() -> impl Strategy<Value = Message> {
    prop_oneof![
        // Control messages
        arb_hello().prop_map(Message::Hello),
        (any::<u16>(), any::<u16>())
            .prop_map(|(cols, rows)| Message::Resize(ResizePayload {
                channel_id: None,
                cols,
                rows,
            })),
        (arb_shutdown_reason(), any::<Option<String>>())
            .prop_map(|(reason, message)| Message::Shutdown(ShutdownPayload { reason, message })),
        // Terminal messages (legacy)
        arb_terminal_input().prop_map(Message::TerminalInput),
        any::<u64>().prop_map(|g| Message::StateAck(StateAckPayload {
            channel_id: None,
            generation: g,
        })),
        // Forward messages (legacy)
        (any::<u64>(), arb_forward_spec()).prop_map(|(id, spec)| {
            Message::ForwardRequest(ForwardRequestPayload {
                forward_id: id,
                spec,
            })
        }),
        any::<u64>().prop_map(|id| Message::ForwardAccept(ForwardAcceptPayload { forward_id: id })),
        (any::<u64>(), "[a-z ]{0,64}").prop_map(|(id, reason)| Message::ForwardReject(
            ForwardRejectPayload {
                forward_id: id,
                reason,
            }
        )),
        (any::<u64>(), prop::collection::vec(any::<u8>(), 0..1024)).prop_map(|(id, data)| {
            Message::ForwardData(ForwardDataPayload {
                forward_id: id,
                data,
            })
        }),
        any::<u64>().prop_map(|id| Message::ForwardEof(ForwardEofPayload { forward_id: id })),
        (any::<u64>(), any::<Option<String>>()).prop_map(|(id, reason)| Message::ForwardClose(
            ForwardClosePayload {
                forward_id: id,
                reason,
            }
        )),
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

    #[allow(deprecated)]
    #[test]
    fn roundtrip_terminal_input(
        seq in any::<u64>(),
        data in prop::collection::vec(any::<u8>(), 0..4096),
        predictable in any::<bool>(),
    ) {
        let msg = Message::TerminalInput(TerminalInputPayload {
            sequence: seq,
            data,
            predictable,
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
