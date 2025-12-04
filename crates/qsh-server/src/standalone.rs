//! Standalone server mode with SSH key authentication.
//!
//! In standalone mode, the server:
//! 1. Loads a host key for identity
//! 2. Loads authorized_keys for client verification
//! 3. Performs mutual authentication before allowing session establishment
//!
//! This mirrors SSH's trust model without requiring an SSH connection.

use std::path::PathBuf;

use qsh_core::auth::{
    AuthorizedKeyEntry, KnownHosts, LocalSigner, check_authorized,
    default_authorized_keys_paths, default_host_key_paths, default_known_hosts_paths,
    generate_challenge, generate_nonce, key_fingerprint, load_authorized_keys, load_host_key,
    sign_server, verify_client,
};
use qsh_core::constants::AUTH_HANDSHAKE_TIMEOUT;
use qsh_core::protocol::{
    AuthChallengePayload, AuthErrorCode, AuthFailurePayload, AuthResponsePayload, Codec, Message,
};
use qsh_core::{Error, Result};
use ssh_key::public::PublicKey;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Standalone server configuration.
#[derive(Debug, Clone)]
pub struct StandaloneConfig {
    /// Path to host key file (optional, uses defaults if not specified).
    pub host_key_path: Option<PathBuf>,
    /// Path to authorized_keys file (optional, uses defaults if not specified).
    pub authorized_keys_path: Option<PathBuf>,
}

/// Standalone server authenticator.
///
/// Handles the authentication handshake for standalone mode connections.
pub struct StandaloneAuthenticator {
    /// Server's private key signer.
    signer: LocalSigner,
    /// Server's public key.
    public_key: PublicKey,
    /// Server's public key in OpenSSH format.
    public_key_openssh: String,
    /// Authorized client keys.
    authorized_keys: Vec<AuthorizedKeyEntry>,
}

impl StandaloneAuthenticator {
    /// Create a new standalone authenticator.
    pub fn new(config: StandaloneConfig) -> Result<Self> {
        // Load host key
        let host_key_paths = if let Some(path) = &config.host_key_path {
            vec![path.clone()]
        } else {
            default_host_key_paths()
        };

        // Try to load known_hosts for key preference (optional).
        // This allows preferring a host key that already appears in known_hosts
        // when multiple keys are available.
        let known_hosts_paths = default_known_hosts_paths();
        let known_hosts = KnownHosts::load(&known_hosts_paths).ok();
        let known_keys = known_hosts.as_ref().map(|kh| kh.known_keys());

        let (private_key, public_key) =
            load_host_key(&host_key_paths, known_keys.as_deref())?;

        let public_key_openssh = public_key.to_openssh().map_err(|e| Error::Protocol {
            message: format!("failed to encode public key: {}", e),
        })?;

        info!(
            fingerprint = %key_fingerprint(&public_key),
            "loaded server host key"
        );

        // Load authorized_keys
        let authorized_keys_paths = if let Some(path) = &config.authorized_keys_path {
            vec![path.clone()]
        } else {
            default_authorized_keys_paths()
        };

        let authorized_keys = load_authorized_keys(&authorized_keys_paths)?;
        info!(
            count = authorized_keys.len(),
            "loaded authorized keys"
        );

        let signer = LocalSigner::new(private_key);

        Ok(Self {
            signer,
            public_key,
            public_key_openssh,
            authorized_keys,
        })
    }

    /// Generate the authentication challenge to send to client.
    pub fn generate_challenge(&self) -> Result<AuthChallengePayload> {
        let challenge = generate_challenge();
        let server_nonce = generate_nonce();

        // Sign the challenge (SSH-style: no hostname in signature)
        let server_signature = sign_server(&self.signer, &challenge, &server_nonce)?;

        debug!("generated auth challenge");

        Ok(AuthChallengePayload {
            server_public_key: self.public_key_openssh.clone(),
            challenge,
            server_nonce,
            server_signature,
        })
    }

    /// Verify a client's authentication response.
    ///
    /// Returns the client's public key fingerprint on success.
    pub fn verify_response(
        &self,
        challenge: &AuthChallengePayload,
        response: &AuthResponsePayload,
    ) -> Result<String> {
        // Parse client's public key
        let client_key =
            PublicKey::from_openssh(&response.client_public_key).map_err(|e| {
                warn!(error = %e, "failed to parse client public key");
                Error::AuthenticationFailed
            })?;

        let fingerprint = key_fingerprint(&client_key);

        // Check if key is authorized
        match check_authorized(&client_key, &self.authorized_keys) {
            Some(true) => {
                debug!(fingerprint = %fingerprint, "client key is authorized");
            }
            Some(false) => {
                warn!(fingerprint = %fingerprint, "client key is revoked");
                return Err(Error::AuthenticationFailed);
            }
            None => {
                warn!(fingerprint = %fingerprint, "client key not found in authorized_keys");
                return Err(Error::AuthenticationFailed);
            }
        }

        // Verify client signature (SSH-style: no hostname in signature)
        let valid = verify_client(
            &client_key,
            &response.signature,
            &challenge.challenge,
            &challenge.server_nonce,
            &response.client_nonce,
        )?;

        if !valid {
            warn!(fingerprint = %fingerprint, "client signature verification failed");
            return Err(Error::AuthenticationFailed);
        }

        info!(fingerprint = %fingerprint, "client authenticated successfully");
        Ok(fingerprint)
    }

    /// Get the server's public key fingerprint.
    pub fn server_fingerprint(&self) -> String {
        key_fingerprint(&self.public_key)
    }
}

/// Authentication result for a standalone connection.
pub enum AuthResult {
    /// Authentication succeeded.
    Success {
        /// Client's key fingerprint.
        client_fingerprint: String,
    },
    /// Authentication failed.
    Failure {
        /// Error code to send to client.
        code: AuthErrorCode,
        /// Internal error message (for logging only).
        internal_message: String,
    },
}

/// Perform standalone authentication handshake on a connection.
///
/// This function:
/// 1. Sends AuthChallenge to client
/// 2. Waits for AuthResponse
/// 3. Verifies client identity
/// 4. Returns success or sends AuthFailure
pub async fn authenticate_connection<S, R>(
    authenticator: &StandaloneAuthenticator,
    send: &mut S,
    recv: &mut R,
) -> AuthResult
where
    S: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    // Generate and send challenge
    let challenge = match authenticator.generate_challenge() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to generate challenge");
            return AuthResult::Failure {
                code: AuthErrorCode::InternalError,
                internal_message: format!("challenge generation failed: {}", e),
            };
        }
    };

    let challenge_msg = Message::AuthChallenge(challenge.clone());
    let encoded = match Codec::encode(&challenge_msg) {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "failed to encode challenge");
            return AuthResult::Failure {
                code: AuthErrorCode::InternalError,
                internal_message: format!("encoding failed: {}", e),
            };
        }
    };

    // Send challenge
    use tokio::io::AsyncWriteExt;
    if let Err(e) = send.write_all(&encoded).await {
        return AuthResult::Failure {
            code: AuthErrorCode::ProtocolError,
            internal_message: format!("failed to send challenge: {}", e),
        };
    }

    // Wait for response with timeout
    let response = match timeout(
        AUTH_HANDSHAKE_TIMEOUT,
        read_auth_response(recv),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            return AuthResult::Failure {
                code: AuthErrorCode::ProtocolError,
                internal_message: format!("failed to read response: {}", e),
            };
        }
        Err(_) => {
            return AuthResult::Failure {
                code: AuthErrorCode::Timeout,
                internal_message: "auth handshake timeout".into(),
            };
        }
    };

    // Verify response
    match authenticator.verify_response(&challenge, &response) {
        Ok(fingerprint) => AuthResult::Success {
            client_fingerprint: fingerprint,
        },
        Err(e) => AuthResult::Failure {
            code: AuthErrorCode::AuthFailed,
            internal_message: format!("verification failed: {}", e),
        },
    }
}

/// Read an AuthResponse message from the stream.
async fn read_auth_response<R>(recv: &mut R) -> Result<AuthResponsePayload>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;

    let mut buf = BytesMut::with_capacity(4096);

    // Read length prefix
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| Error::Io(e))?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > qsh_core::constants::MAX_MESSAGE_SIZE {
        return Err(Error::Protocol {
            message: "message too large".into(),
        });
    }

    // Read message body
    buf.resize(len, 0);
    recv.read_exact(&mut buf).await.map_err(|e| Error::Io(e))?;

    // Prepend length for decoding
    let mut full_buf = BytesMut::with_capacity(4 + len);
    full_buf.extend_from_slice(&len_buf);
    full_buf.extend_from_slice(&buf);

    // Decode message
    let msg = Codec::decode(&mut full_buf)?.ok_or_else(|| Error::Protocol {
        message: "incomplete message".into(),
    })?;

    match msg {
        Message::AuthResponse(resp) => Ok(resp),
        _ => Err(Error::Protocol {
            message: format!("expected AuthResponse, got {:?}", std::mem::discriminant(&msg)),
        }),
    }
}

/// Send an AuthFailure message.
pub async fn send_auth_failure<S>(
    send: &mut S,
    code: AuthErrorCode,
    _message: &str,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // Always use generic message for non-timeout failures
    let client_message = match code {
        AuthErrorCode::Timeout => "authentication timeout".to_string(),
        _ => "authentication failed".to_string(),
    };

    let failure = Message::AuthFailure(AuthFailurePayload {
        code,
        message: client_message,
    });

    let encoded = Codec::encode(&failure)?;
    send.write_all(&encoded).await.map_err(|e| Error::Io(e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_client::standalone::{DirectAuthenticator, DirectConfig, authenticate as client_authenticate};
    use qsh_client::{ClientConnection, ConnectionConfig};
    use qsh_core::protocol::{Capabilities, HelloAckPayload, TerminalOutputPayload, TermSize};
    use qsh_core::terminal::TerminalState;
    use qsh_core::transport::{Connection, StreamPair, StreamType, server_crypto_config};
    use qsh_test_utils::TestKeys;
    use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{duplex, split};

    #[test]
    fn test_standalone_config_defaults() {
        let config = StandaloneConfig {
            host_key_path: None,
            authorized_keys_path: None,
        };
        assert!(config.host_key_path.is_none());
        assert!(config.authorized_keys_path.is_none());
    }

    #[test]
    fn test_auth_result_variants() {
        let success = AuthResult::Success {
            client_fingerprint: "SHA256:test".into(),
        };
        assert!(matches!(success, AuthResult::Success { .. }));

        let failure = AuthResult::Failure {
            code: AuthErrorCode::AuthFailed,
            internal_message: "test".into(),
        };
        assert!(matches!(failure, AuthResult::Failure { .. }));
    }

    /// End-to-end standalone authentication flow between server and client.
    ///
    /// This test:
    /// - Writes a fixed ed25519 keypair to temporary files
    /// - Uses that key as both server host key and client key
    /// - Adds the public key to authorized_keys and known_hosts
    /// - Runs the standalone auth handshake over an in-memory duplex stream
    /// - Verifies that both sides succeed
    #[tokio::test]
    async fn standalone_auth_end_to_end() {
        // Fixed test key generated via ssh-keygen (ed25519, no passphrase).
        const TEST_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACDUR5TVudhWJVP+Q3Db/3Vna9t3SBxBoj1M4kF+yAgk5gAAAJDP/IPSz/yD\n\
0gAAAAtzc2gtZWQyNTUxOQAAACDUR5TVudhWJVP+Q3Db/3Vna9t3SBxBoj1M4kF+yAgk5g\n\
AAAECBrLZZNM25f1vduElMLpZWAH9g5heM7sv1r62hvVfglNRHlNW52FYlU/5DcNv/dWdr\n\
23dIHEGiPUziQX7ICCTmAAAADHRlc3RAZXhhbXBsZQE=\n\
-----END OPENSSH PRIVATE KEY-----\n";
        const TEST_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRHlNW52FYlU/5DcNv/dWdr23dIHEGiPUziQX7ICCTm test@example\n";

        let tmp = TempDir::new().expect("failed to create temp dir");
        let host_key_path = tmp.path().join("host_ed25519_key");
        let client_key_path = tmp.path().join("id_ed25519");
        let authorized_keys_path = tmp.path().join("authorized_keys");
        let known_hosts_path = tmp.path().join("known_hosts");

        // Write private keys for server host key and client key.
        std::fs::write(&host_key_path, TEST_PRIVATE_KEY).expect("failed to write host key");
        std::fs::write(&client_key_path, TEST_PRIVATE_KEY).expect("failed to write client key");

        // authorized_keys: allow the test public key.
        std::fs::write(&authorized_keys_path, TEST_PUBLIC_KEY).expect("failed to write authorized_keys");

        // known_hosts: record localhost with the server's public key.
        let known_hosts_entry = format!("localhost {}", TEST_PUBLIC_KEY);
        std::fs::write(&known_hosts_path, known_hosts_entry).expect("failed to write known_hosts");

        // Build server-side authenticator.
        let server_config = StandaloneConfig {
            host_key_path: Some(host_key_path.clone()),
            authorized_keys_path: Some(authorized_keys_path.clone()),
        };
        let authenticator = StandaloneAuthenticator::new(server_config)
            .expect("failed to create StandaloneAuthenticator");

        // Build client-side authenticator for direct mode.
        let direct_config = DirectConfig {
            server_addr: "localhost:4433".into(),
            key_path: Some(client_key_path.clone()),
            known_hosts_path: Some(known_hosts_path.clone()),
            accept_unknown_host: false,
            no_agent: true,
        };
        let mut direct_auth =
            DirectAuthenticator::new(&direct_config).await.expect("failed to create DirectAuthenticator");

        // In-memory duplex stream to simulate the QUIC stream used for auth.
        let (client_io, server_io) = duplex(8192);
        let (mut server_read, mut server_write) = split(server_io);
        let (mut client_read, mut client_write) = split(client_io);

        // Run server and client handshakes concurrently.
        let server_fut = async move {
            authenticate_connection(&authenticator, &mut server_write, &mut server_read).await
        };

        let client_fut = async move {
            client_authenticate(&mut direct_auth, &mut client_write, &mut client_read).await
        };

        let (server_res, client_res) = tokio::join!(server_fut, client_fut);

        // Client side should report success.
        client_res.expect("client authentication failed");

        // Server side should see a successful AuthResult with a non-empty fingerprint.
        match server_res {
            AuthResult::Success { client_fingerprint } => {
                assert!(!client_fingerprint.is_empty());
            }
            AuthResult::Failure { code, internal_message } => {
                panic!(
                    "server authentication failed: code={:?} message={}",
                    code, internal_message
                );
            }
        }
    }

    /// Full QUIC + standalone auth + Hello/HelloAck handshake.
    ///
    /// This test:
    /// - Spins up a real QUIC server endpoint with TLS
    /// - Uses standalone auth for mutual SSH key authentication
    /// - Completes the Hello/HelloAck handshake using ClientConnection::from_quic
    #[tokio::test]
    #[ignore = "Full QUIC + standalone session test is slow and intended for manual runs"]
    async fn standalone_quic_session_end_to_end() {
        // Fixed test key generated via ssh-keygen (ed25519, no passphrase).
        const TEST_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACDUR5TVudhWJVP+Q3Db/3Vna9t3SBxBoj1M4kF+yAgk5gAAAJDP/IPSz/yD\n\
0gAAAAtzc2gtZWQyNTUxOQAAACDUR5TVudhWJVP+Q3Db/3Vna9t3SBxBoj1M4kF+yAgk5g\n\
AAAECBrLZZNM25f1vduElMLpZWAH9g5heM7sv1r62hvVfglNRHlNW52FYlU/5DcNv/dWdr\n\
23dIHEGiPUziQX7ICCTmAAAADHRlc3RAZXhhbXBsZQE=\n\
-----END OPENSSH PRIVATE KEY-----\n";
        const TEST_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRHlNW52FYlU/5DcNv/dWdr23dIHEGiPUziQX7ICCTm test@example\n";

        eprintln!("standalone_quic_session: setting up temp keys");
        let tmp = TempDir::new().expect("failed to create temp dir");
        let host_key_path = tmp.path().join("host_ed25519_key");
        let client_key_path = tmp.path().join("id_ed25519");
        let authorized_keys_path = tmp.path().join("authorized_keys");
        let known_hosts_path = tmp.path().join("known_hosts");

        // Write private keys for server host key and client key.
        std::fs::write(&host_key_path, TEST_PRIVATE_KEY).expect("failed to write host key");
        std::fs::write(&client_key_path, TEST_PRIVATE_KEY).expect("failed to write client key");

        // authorized_keys: allow the test public key.
        std::fs::write(&authorized_keys_path, TEST_PUBLIC_KEY).expect("failed to write authorized_keys");

        // known_hosts: record localhost with the server's public key.
        let known_hosts_entry = format!("localhost {}", TEST_PUBLIC_KEY);
        std::fs::write(&known_hosts_path, known_hosts_entry).expect("failed to write known_hosts");

        // Build TLS server config (self-signed).
        eprintln!("standalone_quic_session: generating self-signed cert");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("failed to generate test certificate");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let crypto = server_crypto_config(cert_der, key_der).expect("server_crypto_config failed");
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .expect("failed to create QuicServerConfig"),
        ));

        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_millis(500)));
        transport.max_idle_timeout(IdleTimeout::try_from(Duration::from_secs(30)).ok());
        server_config.transport_config(Arc::new(transport));

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        eprintln!("standalone_quic_session: binding server endpoint");
        let endpoint = Endpoint::server(server_config, bind_addr).expect("failed to bind server");
        let local_addr = endpoint.local_addr().expect("no local addr");
        let port = local_addr.port();

        // Build server-side standalone authenticator.
        let server_auth_config = StandaloneConfig {
            host_key_path: Some(host_key_path.clone()),
            authorized_keys_path: Some(authorized_keys_path.clone()),
        };
        eprintln!("standalone_quic_session: creating StandaloneAuthenticator");
        let authenticator =
            StandaloneAuthenticator::new(server_auth_config).expect("failed to create authenticator");

        // Spawn server task handling a single connection.
        eprintln!("standalone_quic_session: spawning server task");
        let server_task = tokio::spawn(async move {
            // Accept connection
            eprintln!("server: waiting for incoming connection");
            let incoming = endpoint.accept().await.expect("no incoming connection");
            let conn = incoming.await.expect("failed to accept connection");
            eprintln!("server: connection accepted");

            // Standalone auth on dedicated stream
            let (mut auth_send, mut auth_recv) = conn.open_bi().await.expect("open_bi failed");
            eprintln!("server: auth stream opened");
            let auth_result =
                authenticate_connection(&authenticator, &mut auth_send, &mut auth_recv).await;
            eprintln!("server: auth_result = {:?}", match &auth_result {
                AuthResult::Success { .. } => "success",
                AuthResult::Failure { .. } => "failure",
            });

            let client_fingerprint = match auth_result {
                AuthResult::Success { client_fingerprint } => client_fingerprint,
                AuthResult::Failure {
                    code,
                    internal_message,
                } => {
                    panic!(
                        "server standalone auth failed: code={:?} message={}",
                        code, internal_message
                    );
                }
            };
            assert!(!client_fingerprint.is_empty());

            // Wrap QUIC connection for protocol handling
            let quic = qsh_core::transport::QuicConnection::new(conn);

            // Accept control stream and Hello
            eprintln!("server: waiting for control stream");
            let (stream_type, mut control) = quic.accept_stream().await.expect("accept control");
            assert!(matches!(stream_type, StreamType::Control));

            eprintln!("server: waiting for Hello");
            let hello = match control.recv().await.expect("recv hello") {
                Message::Hello(h) => h,
                other => panic!("expected Hello, got {:?}", other),
            };
            assert_eq!(hello.protocol_version, 1);

            // Send HelloAck with a simple initial state
            let initial_state = TerminalState::new(80, 24);
            let ack = HelloAckPayload {
                protocol_version: 1,
                accepted: true,
                reject_reason: None,
                capabilities: Capabilities {
                    predictive_echo: true,
                    compression: false,
                    max_forwards: 10,
                    tunnel: false,
                },
                initial_state: Some(initial_state),
                zero_rtt_available: false,
            };
            eprintln!("server: sending HelloAck");
            control
                .send(&Message::HelloAck(ack))
                .await
                .expect("send HelloAck failed");

            // Accept TerminalIn uni stream from client
            eprintln!("server: waiting for TerminalIn");
            let (ty_in, _in_stream) = quic.accept_stream().await.expect("accept terminal in");
            assert!(matches!(ty_in, StreamType::TerminalIn));

            // Open TerminalOut uni stream and send initial empty output
            eprintln!("server: opening TerminalOut");
            let mut term_out = quic
                .open_stream(StreamType::TerminalOut)
                .await
                .expect("open terminal out failed");
            term_out
                .send(&Message::TerminalOutput(TerminalOutputPayload {
                    data: Vec::new(),
                    confirmed_input_seq: 0,
                }))
                .await
                .expect("send initial terminal output failed");
            eprintln!("server: finished");
        });

        // Client side: build DirectAuthenticator
        let server_addr_str = format!("localhost:{}", port);
        let direct_config = DirectConfig {
            server_addr: server_addr_str,
            key_path: Some(client_key_path.clone()),
            known_hosts_path: Some(known_hosts_path.clone()),
            accept_unknown_host: false,
            no_agent: true,
        };
        eprintln!("client: creating DirectAuthenticator");
        let mut direct_auth =
            DirectAuthenticator::new(&direct_config).await.expect("failed to create DirectAuthenticator");

        // Build ConnectionConfig for QUIC client
        let server_sock_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let conn_config = ConnectionConfig {
            server_addr: server_sock_addr,
            session_key: TestKeys::SESSION_KEY,
            cert_hash: None,
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm-256color".to_string(),
            env: Vec::new(),
            predictive_echo: true,
            connect_timeout: Duration::from_secs(5),
            zero_rtt_available: false,
            keep_alive_interval: Some(Duration::from_millis(500)),
            max_idle_timeout: Duration::from_secs(30),
        };

        // Establish QUIC connection
        eprintln!("client: connecting QUIC");
        let quic_conn =
            ClientConnection::connect_quic(&conn_config).await.expect("connect_quic failed");

        // Accept auth stream and perform client-side standalone auth
        eprintln!("client: waiting for auth stream");
        let (mut client_send, mut client_recv) =
            quic_conn.accept_bi().await.expect("accept auth bidi failed");
        eprintln!("client: performing standalone auth");
        client_authenticate(&mut direct_auth, &mut client_send, &mut client_recv)
            .await
            .expect("client standalone auth failed");

        // Complete Hello/HelloAck handshake and open terminal streams
        eprintln!("client: completing Hello/HelloAck via from_quic");
        let mut client_conn =
            ClientConnection::from_quic(quic_conn, conn_config).await.expect("from_quic failed");

        // Sanity: send a resize and close cleanly
        eprintln!("client: sending resize");
        client_conn
            .send_resize(80, 24)
            .await
            .expect("send_resize failed");
        eprintln!("client: closing");
        client_conn.close().await.expect("close failed");

        // Ensure server task completed successfully
        eprintln!("test: awaiting server_task");
        server_task.await.expect("server task panicked");
        eprintln!("test: done");
    }
}
