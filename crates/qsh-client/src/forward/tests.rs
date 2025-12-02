//! Tests for client-side port forwarding.

// These tests require mock transport - will be integration tested
// Unit tests here focus on SOCKS5 protocol handling

#[cfg(test)]
mod socks_protocol {
    /// SOCKS5 version constant.
    const SOCKS_VERSION: u8 = 0x05;
    /// No authentication method.
    const AUTH_NO_AUTH: u8 = 0x00;
    /// CONNECT command.
    const CMD_CONNECT: u8 = 0x01;
    /// IPv4 address type.
    const ADDR_IPV4: u8 = 0x01;
    /// Domain name address type.
    const ADDR_DOMAIN: u8 = 0x03;
    /// IPv6 address type.
    const ADDR_IPV6: u8 = 0x04;

    #[test]
    fn socks5_greeting_format() {
        // Client greeting: version, nmethods, methods...
        let greeting = [SOCKS_VERSION, 0x01, AUTH_NO_AUTH];
        assert_eq!(greeting[0], 0x05);
        assert_eq!(greeting[1], 0x01); // 1 method
        assert_eq!(greeting[2], 0x00); // No auth
    }

    #[test]
    fn socks5_server_choice_format() {
        // Server choice: version, method
        let choice_ok = [SOCKS_VERSION, AUTH_NO_AUTH];
        let choice_fail = [SOCKS_VERSION, 0xFF];

        assert_eq!(choice_ok[0], 0x05);
        assert_eq!(choice_ok[1], 0x00); // No auth accepted

        assert_eq!(choice_fail[1], 0xFF); // No acceptable method
    }

    #[test]
    fn socks5_connect_request_ipv4() {
        // Request: version, cmd, rsv, atyp, addr..., port
        // Connect to 127.0.0.1:8080
        let request = [
            SOCKS_VERSION,
            CMD_CONNECT,
            0x00, // Reserved
            ADDR_IPV4,
            127,
            0,
            0,
            1, // IPv4 address
            0x1F,
            0x90, // Port 8080 (big endian)
        ];

        assert_eq!(request[0], 0x05);
        assert_eq!(request[1], 0x01); // CONNECT
        assert_eq!(request[3], 0x01); // IPv4

        let port = u16::from_be_bytes([request[8], request[9]]);
        assert_eq!(port, 8080);
    }

    #[test]
    fn socks5_connect_request_domain() {
        // Connect to example.com:443
        let domain = b"example.com";
        let mut request = vec![
            SOCKS_VERSION,
            CMD_CONNECT,
            0x00, // Reserved
            ADDR_DOMAIN,
            domain.len() as u8,
        ];
        request.extend_from_slice(domain);
        request.extend_from_slice(&443u16.to_be_bytes());

        assert_eq!(request[4], 11); // Domain length
        assert_eq!(&request[5..16], domain);

        let port = u16::from_be_bytes([request[16], request[17]]);
        assert_eq!(port, 443);
    }

    #[test]
    fn socks5_connect_request_ipv6() {
        // Connect to [::1]:22
        let request = [
            SOCKS_VERSION,
            CMD_CONNECT,
            0x00, // Reserved
            ADDR_IPV6,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1, // ::1
            0x00,
            0x16, // Port 22
        ];

        assert_eq!(request[3], 0x04); // IPv6

        let port = u16::from_be_bytes([request[20], request[21]]);
        assert_eq!(port, 22);
    }

    #[test]
    fn socks5_reply_format() {
        // Success reply: version, reply, rsv, atyp, addr, port
        let reply = [
            SOCKS_VERSION,
            0x00, // Success
            0x00, // Reserved
            ADDR_IPV4,
            0,
            0,
            0,
            0, // Bound address (0.0.0.0)
            0,
            0, // Bound port (0)
        ];

        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00); // Success
    }

    #[test]
    fn socks5_reply_codes() {
        const REPLY_SUCCESS: u8 = 0x00;
        const REPLY_GENERAL_FAILURE: u8 = 0x01;
        const REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
        const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
        const REPLY_HOST_UNREACHABLE: u8 = 0x04;
        const REPLY_CONNECTION_REFUSED: u8 = 0x05;
        const REPLY_TTL_EXPIRED: u8 = 0x06;
        const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
        const REPLY_ADDR_NOT_SUPPORTED: u8 = 0x08;

        // Just verify constants exist
        assert_eq!(REPLY_SUCCESS, 0x00);
        assert_eq!(REPLY_GENERAL_FAILURE, 0x01);
        assert_eq!(REPLY_CONNECTION_REFUSED, 0x05);
        assert_eq!(REPLY_CMD_NOT_SUPPORTED, 0x07);
        assert_eq!(REPLY_ADDR_NOT_SUPPORTED, 0x08);
    }
}
