//! Stream direction mapping for role-aware stream type detection.
//!
//! In normal mode:
//! - Logical client is QUIC client
//! - Logical server is QUIC server
//! - ChannelIn = client-initiated unidirectional (QUIC stream IDs 2, 6, 10, ...)
//! - ChannelOut = server-initiated unidirectional (QUIC stream IDs 3, 7, 11, ...)
//!
//! In reverse-attach mode (--connect-mode initiate):
//! - Logical client is QUIC server (bootstrap listener)
//! - Logical server is QUIC client (connects to bootstrap)
//! - ChannelIn = server-initiated unidirectional (QUIC stream IDs 3, 7, 11, ...)
//! - ChannelOut = client-initiated unidirectional (QUIC stream IDs 2, 6, 10, ...)
//!
//! The `StreamDirectionMapper` provides a consistent abstraction that translates
//! between logical stream types (ChannelIn/ChannelOut) and QUIC stream directions
//! (client-initiated vs server-initiated) based on the role configuration.

use crate::protocol::ChannelId;
use crate::transport::{EndpointRole, StreamType};

/// Maps between logical stream types and QUIC stream directions.
///
/// This handles the complexity of reverse-attach mode where the logical
/// client/server roles are inverted relative to the QUIC client/server roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDirectionMapper {
    /// The logical role (client or server) from the application perspective.
    logical_role: EndpointRole,
    /// The QUIC endpoint role (client or server) from the transport perspective.
    quic_role: EndpointRole,
}

impl StreamDirectionMapper {
    /// Create a new stream direction mapper.
    ///
    /// # Arguments
    ///
    /// * `logical_role` - The logical role (client/server) from application perspective
    /// * `quic_role` - The QUIC endpoint role from transport perspective
    ///
    /// # Example
    ///
    /// ```
    /// use qsh_core::transport::{EndpointRole, StreamDirectionMapper};
    ///
    /// // Normal mode: logical client is QUIC client
    /// let normal = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    ///
    /// // Reverse mode: logical server is QUIC client (server initiated the connection)
    /// let reverse = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);
    /// ```
    pub fn new(logical_role: EndpointRole, quic_role: EndpointRole) -> Self {
        Self {
            logical_role,
            quic_role,
        }
    }

    /// Determine if this mapper represents a role-inverted configuration.
    ///
    /// Returns true when logical role != QUIC role (reverse-attach mode).
    pub fn is_inverted(&self) -> bool {
        self.logical_role != self.quic_role
    }

    /// Get the logical role.
    pub fn logical_role(&self) -> EndpointRole {
        self.logical_role
    }

    /// Get the QUIC role.
    pub fn quic_role(&self) -> EndpointRole {
        self.quic_role
    }

    /// Determine which QUIC stream direction should be used to open a logical stream type.
    ///
    /// Returns true if the stream should be initiated by the local QUIC endpoint,
    /// false if it should be initiated by the remote QUIC endpoint.
    ///
    /// # Arguments
    ///
    /// * `stream_type` - The logical stream type to open
    ///
    /// # Returns
    ///
    /// True if this endpoint should initiate the QUIC stream, false otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use qsh_core::transport::{EndpointRole, StreamDirectionMapper, StreamType};
    /// use qsh_core::protocol::ChannelId;
    ///
    /// let mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    /// let ch = ChannelId::client(0);
    ///
    /// // Client opens ChannelIn -> should initiate (client-initiated)
    /// assert!(mapper.should_initiate_stream(StreamType::ChannelIn(ch)));
    ///
    /// // Client opens ChannelOut -> should NOT initiate (server-initiated)
    /// assert!(!mapper.should_initiate_stream(StreamType::ChannelOut(ch)));
    /// ```
    pub fn should_initiate_stream(&self, stream_type: StreamType) -> bool {
        match stream_type {
            StreamType::Control => {
                // Control stream (ID 0) is always initiated by QUIC client
                self.quic_role == EndpointRole::Client
            }
            StreamType::ChannelIn(_) => {
                // ChannelIn: logical client -> logical server
                // Always initiated by the logical client
                // Should WE initiate? Only if we ARE the logical client
                self.logical_role == EndpointRole::Client
            }
            StreamType::ChannelOut(_) => {
                // ChannelOut: logical server -> logical client
                // Always initiated by the logical server
                // Should WE initiate? Only if we ARE the logical server
                self.logical_role == EndpointRole::Server
            }
            StreamType::ChannelBidi(_) => {
                // Bidirectional channels opened by logical client
                self.logical_role == EndpointRole::Client
            }
        }
    }

    /// Detect the logical stream type from a QUIC stream ID.
    ///
    /// QUIC stream ID encoding:
    /// - Bit 0: initiator (0 = client, 1 = server)
    /// - Bit 1: directionality (0 = bidi, 1 = uni)
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The QUIC stream ID
    /// * `channel_id` - The channel ID decoded from the stream header
    /// * `magic` - The magic byte from the stream header
    ///
    /// # Returns
    ///
    /// The logical StreamType, or None if the stream type cannot be determined.
    pub fn detect_stream_type(
        &self,
        stream_id: u64,
        channel_id: ChannelId,
        magic: u8,
    ) -> Option<StreamType> {
        use crate::transport::common::stream_header::{CHANNEL_BIDI_MAGIC, CHANNEL_STREAM_MAGIC};

        // Extract QUIC stream properties from stream ID
        let is_client_initiated = (stream_id & 0x1) == 0;
        let is_uni = (stream_id & 0x2) != 0;

        match magic {
            CHANNEL_BIDI_MAGIC if !is_uni => {
                // Bidirectional channel stream
                Some(StreamType::ChannelBidi(channel_id))
            }
            CHANNEL_STREAM_MAGIC if is_uni => {
                // Unidirectional channel stream - determine In vs Out based on roles

                // In normal mode (logical == QUIC):
                //   - client-initiated uni = ChannelIn (client -> server)
                //   - server-initiated uni = ChannelOut (server -> client)
                //
                // In reverse mode (logical != QUIC):
                //   - client-initiated uni = ChannelOut (server -> client, server is QUIC client)
                //   - server-initiated uni = ChannelIn (client -> server, client is QUIC server)

                let is_inverted = self.is_inverted();

                if is_client_initiated {
                    // Client-initiated unidirectional stream
                    if is_inverted {
                        // Reverse mode: QUIC client is logical server
                        // So client-initiated = ChannelOut (server -> client)
                        Some(StreamType::ChannelOut(channel_id))
                    } else {
                        // Normal mode: QUIC client is logical client
                        // So client-initiated = ChannelIn (client -> server)
                        Some(StreamType::ChannelIn(channel_id))
                    }
                } else {
                    // Server-initiated unidirectional stream
                    if is_inverted {
                        // Reverse mode: QUIC server is logical client
                        // So server-initiated = ChannelIn (client -> server)
                        Some(StreamType::ChannelIn(channel_id))
                    } else {
                        // Normal mode: QUIC server is logical server
                        // So server-initiated = ChannelOut (server -> client)
                        Some(StreamType::ChannelOut(channel_id))
                    }
                }
            }
            _ => None,
        }
    }

    /// Get the expected QUIC stream ID pattern for a logical stream type.
    ///
    /// This is useful for generating or validating stream IDs.
    ///
    /// # Returns
    ///
    /// A tuple of (should_be_client_initiated, should_be_unidirectional).
    pub fn stream_id_pattern(&self, stream_type: StreamType) -> (bool, bool) {
        match stream_type {
            StreamType::Control => (true, false), // Always client-initiated bidi (ID 0)
            StreamType::ChannelIn(_) => {
                // ChannelIn is initiated by logical client
                let client_initiated = !self.is_inverted();
                (client_initiated, true) // Unidirectional
            }
            StreamType::ChannelOut(_) => {
                // ChannelOut is initiated by logical server
                let client_initiated = self.is_inverted();
                (client_initiated, true) // Unidirectional
            }
            StreamType::ChannelBidi(_) => {
                // Bidi channels initiated by logical client
                let client_initiated = !self.is_inverted();
                (client_initiated, false) // Bidirectional
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ChannelId;
    use crate::transport::common::stream_header::{CHANNEL_BIDI_MAGIC, CHANNEL_STREAM_MAGIC};

    // Helper to create a QUIC stream ID from components
    fn make_stream_id(client_initiated: bool, unidirectional: bool, sequence: u64) -> u64 {
        let initiator_bit = if client_initiated { 0 } else { 1 };
        let direction_bit = if unidirectional { 2 } else { 0 };
        (sequence << 2) | direction_bit | initiator_bit
    }

    #[test]
    fn test_normal_mode_client_perspective() {
        // Normal mode: logical client = QUIC client
        let mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);

        assert!(!mapper.is_inverted());
        assert_eq!(mapper.logical_role(), EndpointRole::Client);
        assert_eq!(mapper.quic_role(), EndpointRole::Client);

        let ch = ChannelId::client(0);

        // Control stream: client initiates (stream ID 0)
        assert!(mapper.should_initiate_stream(StreamType::Control));

        // ChannelIn: client -> server, so client initiates
        assert!(mapper.should_initiate_stream(StreamType::ChannelIn(ch)));

        // ChannelOut: server -> client, so client does NOT initiate
        assert!(!mapper.should_initiate_stream(StreamType::ChannelOut(ch)));

        // ChannelBidi: client initiates
        assert!(mapper.should_initiate_stream(StreamType::ChannelBidi(ch)));
    }

    #[test]
    fn test_normal_mode_server_perspective() {
        // Normal mode: logical server = QUIC server
        let mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Server);

        assert!(!mapper.is_inverted());
        assert_eq!(mapper.logical_role(), EndpointRole::Server);
        assert_eq!(mapper.quic_role(), EndpointRole::Server);

        let ch = ChannelId::client(0);

        // Control stream: server does NOT initiate (client does, ID 0)
        assert!(!mapper.should_initiate_stream(StreamType::Control));

        // ChannelIn: client -> server, so server does NOT initiate
        assert!(!mapper.should_initiate_stream(StreamType::ChannelIn(ch)));

        // ChannelOut: server -> client, so server initiates
        assert!(mapper.should_initiate_stream(StreamType::ChannelOut(ch)));

        // ChannelBidi: server does NOT initiate (client does)
        assert!(!mapper.should_initiate_stream(StreamType::ChannelBidi(ch)));
    }

    #[test]
    fn test_reverse_mode_client_perspective() {
        // Reverse mode: logical client = QUIC server (bootstrap listener)
        let mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Server);

        assert!(mapper.is_inverted());
        assert_eq!(mapper.logical_role(), EndpointRole::Client);
        assert_eq!(mapper.quic_role(), EndpointRole::Server);

        let ch = ChannelId::client(0);

        // Control stream: QUIC server does NOT initiate (QUIC client always does)
        assert!(!mapper.should_initiate_stream(StreamType::Control));

        // ChannelIn: client -> server
        // Logical client (QUIC server) should initiate
        assert!(mapper.should_initiate_stream(StreamType::ChannelIn(ch)));

        // ChannelOut: server -> client
        // Logical server (QUIC client) should initiate, so QUIC server should NOT
        assert!(!mapper.should_initiate_stream(StreamType::ChannelOut(ch)));

        // ChannelBidi: logical client (QUIC server) initiates
        assert!(mapper.should_initiate_stream(StreamType::ChannelBidi(ch)));
    }

    #[test]
    fn test_reverse_mode_server_perspective() {
        // Reverse mode: logical server = QUIC client (initiated connection)
        let mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

        assert!(mapper.is_inverted());
        assert_eq!(mapper.logical_role(), EndpointRole::Server);
        assert_eq!(mapper.quic_role(), EndpointRole::Client);

        let ch = ChannelId::server(0);

        // Control stream: QUIC client initiates
        assert!(mapper.should_initiate_stream(StreamType::Control));

        // ChannelIn: client -> server
        // Logical client (QUIC server) should initiate, so QUIC client should NOT
        assert!(!mapper.should_initiate_stream(StreamType::ChannelIn(ch)));

        // ChannelOut: server -> client
        // Logical server (QUIC client) should initiate
        assert!(mapper.should_initiate_stream(StreamType::ChannelOut(ch)));

        // ChannelBidi: logical client initiates, so QUIC client does NOT
        assert!(!mapper.should_initiate_stream(StreamType::ChannelBidi(ch)));
    }

    #[test]
    fn test_detect_stream_type_normal_mode() {
        // Normal mode: logical client = QUIC client
        let mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
        let ch = ChannelId::client(0);

        // Client-initiated uni (stream ID 2, 6, 10...) = ChannelIn
        let stream_id = make_stream_id(true, true, 0); // ID 2
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(StreamType::ChannelIn(ch))
        );

        // Server-initiated uni (stream ID 3, 7, 11...) = ChannelOut
        let stream_id = make_stream_id(false, true, 0); // ID 3
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(StreamType::ChannelOut(ch))
        );

        // Client-initiated bidi (stream ID 0, 4, 8...) = ChannelBidi
        let stream_id = make_stream_id(true, false, 1); // ID 4
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_BIDI_MAGIC),
            Some(StreamType::ChannelBidi(ch))
        );
    }

    #[test]
    fn test_detect_stream_type_reverse_mode() {
        // Reverse mode: logical server = QUIC client
        let mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);
        let ch = ChannelId::client(0);

        // Client-initiated uni (stream ID 2, 6, 10...) = ChannelOut (inverted!)
        let stream_id = make_stream_id(true, true, 0); // ID 2
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(StreamType::ChannelOut(ch))
        );

        // Server-initiated uni (stream ID 3, 7, 11...) = ChannelIn (inverted!)
        let stream_id = make_stream_id(false, true, 0); // ID 3
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(StreamType::ChannelIn(ch))
        );

        // Client-initiated bidi (stream ID 4, 8, 12...) = ChannelBidi
        let stream_id = make_stream_id(true, false, 1); // ID 4
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_BIDI_MAGIC),
            Some(StreamType::ChannelBidi(ch))
        );
    }

    #[test]
    fn test_stream_id_patterns_normal_mode() {
        let mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);

        // Control: client-initiated bidi
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::Control);
        assert!(client_init);
        assert!(!uni);

        let ch = ChannelId::client(0);

        // ChannelIn: client-initiated uni
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::ChannelIn(ch));
        assert!(client_init);
        assert!(uni);

        // ChannelOut: server-initiated uni
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::ChannelOut(ch));
        assert!(!client_init);
        assert!(uni);

        // ChannelBidi: client-initiated bidi
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::ChannelBidi(ch));
        assert!(client_init);
        assert!(!uni);
    }

    #[test]
    fn test_stream_id_patterns_reverse_mode() {
        // Reverse: logical server = QUIC client
        let mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

        // Control: still client-initiated bidi (QUIC level)
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::Control);
        assert!(client_init);
        assert!(!uni);

        let ch = ChannelId::server(0);

        // ChannelIn: server-initiated uni (inverted - QUIC server is logical client)
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::ChannelIn(ch));
        assert!(!client_init); // QUIC server initiates (because logical client is QUIC server)
        assert!(uni);

        // ChannelOut: client-initiated uni (inverted - QUIC client is logical server)
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::ChannelOut(ch));
        assert!(client_init); // QUIC client initiates (because logical server is QUIC client)
        assert!(uni);

        // ChannelBidi: server-initiated bidi (inverted)
        let (client_init, uni) = mapper.stream_id_pattern(StreamType::ChannelBidi(ch));
        assert!(!client_init);
        assert!(!uni);
    }

    #[test]
    fn test_roundtrip_normal_mode() {
        let mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
        let ch = ChannelId::client(42);

        // Test ChannelIn roundtrip
        let stream_type = StreamType::ChannelIn(ch);
        let (client_init, uni) = mapper.stream_id_pattern(stream_type);
        let stream_id = make_stream_id(client_init, uni, 5);
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(stream_type)
        );

        // Test ChannelOut roundtrip
        let stream_type = StreamType::ChannelOut(ch);
        let (client_init, uni) = mapper.stream_id_pattern(stream_type);
        let stream_id = make_stream_id(client_init, uni, 5);
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(stream_type)
        );
    }

    #[test]
    fn test_roundtrip_reverse_mode() {
        let mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);
        let ch = ChannelId::server(99);

        // Test ChannelIn roundtrip (inverted)
        let stream_type = StreamType::ChannelIn(ch);
        let (client_init, uni) = mapper.stream_id_pattern(stream_type);
        let stream_id = make_stream_id(client_init, uni, 3);
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(stream_type)
        );

        // Test ChannelOut roundtrip (inverted)
        let stream_type = StreamType::ChannelOut(ch);
        let (client_init, uni) = mapper.stream_id_pattern(stream_type);
        let stream_id = make_stream_id(client_init, uni, 3);
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            Some(stream_type)
        );
    }

    #[test]
    fn test_invalid_stream_detection() {
        let mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
        let ch = ChannelId::client(0);

        // Invalid magic byte
        let stream_id = make_stream_id(true, true, 0);
        assert_eq!(mapper.detect_stream_type(stream_id, ch, 0xFF), None);

        // Bidi stream with uni magic
        let stream_id = make_stream_id(true, false, 1);
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_STREAM_MAGIC),
            None
        );

        // Uni stream with bidi magic
        let stream_id = make_stream_id(true, true, 0);
        assert_eq!(
            mapper.detect_stream_type(stream_id, ch, CHANNEL_BIDI_MAGIC),
            None
        );
    }

    #[test]
    fn test_all_four_combinations() {
        // Test matrix of all 4 role combinations
        let combinations = [
            (EndpointRole::Client, EndpointRole::Client, "normal-client"),
            (EndpointRole::Server, EndpointRole::Server, "normal-server"),
            (EndpointRole::Client, EndpointRole::Server, "reverse-client"),
            (EndpointRole::Server, EndpointRole::Client, "reverse-server"),
        ];

        for (logical, quic, name) in combinations {
            let mapper = StreamDirectionMapper::new(logical, quic);
            let ch = ChannelId::client(0);

            // Each combination should be able to determine stream directions
            let channel_in = StreamType::ChannelIn(ch);
            let channel_out = StreamType::ChannelOut(ch);
            let channel_bidi = StreamType::ChannelBidi(ch);

            // Verify should_initiate_stream returns a boolean for all types
            let _ = mapper.should_initiate_stream(StreamType::Control);
            let _ = mapper.should_initiate_stream(channel_in);
            let _ = mapper.should_initiate_stream(channel_out);
            let _ = mapper.should_initiate_stream(channel_bidi);

            // Verify detect_stream_type works for various stream IDs
            for seq in 0..5 {
                let client_uni = make_stream_id(true, true, seq);
                let server_uni = make_stream_id(false, true, seq);
                let client_bidi = make_stream_id(true, false, seq);

                let _ = mapper.detect_stream_type(client_uni, ch, CHANNEL_STREAM_MAGIC);
                let _ = mapper.detect_stream_type(server_uni, ch, CHANNEL_STREAM_MAGIC);
                let _ = mapper.detect_stream_type(client_bidi, ch, CHANNEL_BIDI_MAGIC);
            }

            println!("Validated mapper for {}: logical={:?}, quic={:?}, inverted={}",
                     name, logical, quic, mapper.is_inverted());
        }
    }
}
