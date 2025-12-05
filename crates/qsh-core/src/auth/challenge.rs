//! Challenge generation, signing, and verification.
//!
//! Implements the qsh standalone auth protocol signature scheme (SSH-style):
//! - Server signs: AUTH_CTX || "server" || challenge || server_nonce
//!   (No hostname - client verifies key against known_hosts for the target host)
//! - Client signs: AUTH_CTX || "client" || challenge || server_nonce || client_nonce
//!   (No hostname - server verifies key against authorized_keys)

use ssh_key::{HashAlg, Signature, private::PrivateKey, public::PublicKey};
use tracing::debug;

use crate::constants::{AUTH_CHALLENGE_LEN, AUTH_CTX, AUTH_NONCE_LEN};
use crate::error::{Error, Result};

/// Trait for signing operations.
///
/// Implemented by local private keys and SSH agent.
pub trait Signer: Send + Sync {
    /// Sign the given data.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Get the public key.
    fn public_key(&self) -> &PublicKey;
}

/// Local private key signer.
pub struct LocalSigner {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl LocalSigner {
    /// Create a new local signer from a private key.
    pub fn new(private_key: PrivateKey) -> Self {
        let public_key = private_key.public_key().clone();
        Self {
            private_key,
            public_key,
        }
    }
}

impl Signer for LocalSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let namespace = "qsh-auth";

        // Determine hash algorithm based on key type
        let hash_alg = match self.private_key.algorithm() {
            ssh_key::Algorithm::Ed25519 => HashAlg::Sha512,
            ssh_key::Algorithm::Ecdsa { curve } => {
                match curve {
                    ssh_key::EcdsaCurve::NistP256 => HashAlg::Sha256,
                    ssh_key::EcdsaCurve::NistP384 => HashAlg::Sha512, // Use Sha512 for P384
                    ssh_key::EcdsaCurve::NistP521 => HashAlg::Sha512,
                }
            }
            ssh_key::Algorithm::Rsa { .. } => HashAlg::Sha512,
            _ => HashAlg::Sha256,
        };

        let ssh_sig = self
            .private_key
            .sign(namespace, hash_alg, data)
            .map_err(|e| Error::Protocol {
                message: format!("signing failed: {}", e),
            })?;

        // Get the signature from the SshSig
        // We need to extract just the signature bytes
        Ok(ssh_sig.signature().as_bytes().to_vec())
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Generate a random 32-byte challenge.
pub fn generate_challenge() -> [u8; AUTH_CHALLENGE_LEN] {
    use rand::RngCore;
    let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Generate a random 32-byte nonce.
pub fn generate_nonce() -> [u8; AUTH_NONCE_LEN] {
    use rand::RngCore;
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Build the server signature data.
///
/// SSH-style: no hostname included. The client verifies the key against
/// known_hosts for the target host separately.
fn build_server_sign_data(challenge: &[u8; 32], server_nonce: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(AUTH_CTX.len() + 6 + 32 + 32);

    // AUTH_CTX (21 bytes)
    data.extend_from_slice(AUTH_CTX);

    // "server" (6 bytes)
    data.extend_from_slice(b"server");

    // challenge (32 bytes)
    data.extend_from_slice(challenge);

    // server_nonce (32 bytes)
    data.extend_from_slice(server_nonce);

    data
}

/// Build the client signature data.
///
/// SSH-style: no hostname included. The server verifies the key against
/// authorized_keys separately.
///
/// Public for use by agent signing in client code.
pub fn build_client_sign_data(
    challenge: &[u8; 32],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(AUTH_CTX.len() + 6 + 32 + 32 + 32);

    // AUTH_CTX (21 bytes)
    data.extend_from_slice(AUTH_CTX);

    // "client" (6 bytes)
    data.extend_from_slice(b"client");

    // challenge (32 bytes)
    data.extend_from_slice(challenge);

    // server_nonce (32 bytes)
    data.extend_from_slice(server_nonce);

    // client_nonce (32 bytes)
    data.extend_from_slice(client_nonce);

    data
}

/// Sign as server (proves key ownership).
pub fn sign_server(
    signer: &dyn Signer,
    challenge: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Result<Vec<u8>> {
    let data = build_server_sign_data(challenge, server_nonce);
    debug!(data_len = data.len(), "signing server challenge");
    signer.sign(&data)
}

/// Sign as client (proves key ownership).
pub fn sign_client(
    signer: &dyn Signer,
    challenge: &[u8; 32],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Result<Vec<u8>> {
    let data = build_client_sign_data(challenge, server_nonce, client_nonce);
    debug!(data_len = data.len(), "signing client challenge");
    signer.sign(&data)
}

/// Verify server signature.
pub fn verify_server(
    key: &PublicKey,
    signature: &[u8],
    challenge: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Result<bool> {
    let data = build_server_sign_data(challenge, server_nonce);
    verify_signature(key, signature, &data)
}

/// Verify client signature.
pub fn verify_client(
    key: &PublicKey,
    signature: &[u8],
    challenge: &[u8; 32],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Result<bool> {
    let data = build_client_sign_data(challenge, server_nonce, client_nonce);
    verify_signature(key, signature, &data)
}

/// Verify a signature against data using the given public key.
fn verify_signature(key: &PublicKey, signature_bytes: &[u8], data: &[u8]) -> Result<bool> {
    use ssh_key::SshSig;

    // Determine hash algorithm based on key type
    let hash_alg = match key.algorithm() {
        ssh_key::Algorithm::Ed25519 => HashAlg::Sha512,
        ssh_key::Algorithm::Ecdsa { curve } => match curve {
            ssh_key::EcdsaCurve::NistP256 => HashAlg::Sha256,
            ssh_key::EcdsaCurve::NistP384 => HashAlg::Sha512,
            ssh_key::EcdsaCurve::NistP521 => HashAlg::Sha512,
        },
        ssh_key::Algorithm::Rsa { .. } => HashAlg::Sha512,
        _ => HashAlg::Sha256,
    };

    // Build SshSig from raw signature bytes
    let namespace = "qsh-auth";

    // Parse the raw signature bytes into a Signature
    let signature =
        Signature::new(key.algorithm(), signature_bytes.to_vec()).map_err(|e| Error::Protocol {
            message: format!("failed to create signature: {}", e),
        })?;

    // Create the SshSig for verification
    let ssh_sig =
        SshSig::new(key.key_data().clone(), namespace, hash_alg, signature).map_err(|e| {
            Error::Protocol {
                message: format!("failed to create ssh signature: {}", e),
            }
        })?;

    match key.verify(namespace, data, &ssh_sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            debug!(error = %e, "signature verification failed");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        // Should be different (with overwhelming probability)
        assert_ne!(c1, c2);
        assert_eq!(c1.len(), 32);
    }

    #[test]
    fn test_generate_nonce() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
        assert_eq!(n1.len(), 32);
    }

    #[test]
    fn test_build_server_sign_data() {
        let challenge = [1u8; 32];
        let server_nonce = [2u8; 32];

        let data = build_server_sign_data(&challenge, &server_nonce);

        // Check structure
        assert!(data.starts_with(AUTH_CTX));
        assert!(data[AUTH_CTX.len()..].starts_with(b"server"));

        // Expected length: AUTH_CTX(21) + "server"(6) + challenge(32) + nonce(32)
        assert_eq!(data.len(), AUTH_CTX.len() + 6 + 32 + 32);
    }

    #[test]
    fn test_build_client_sign_data() {
        let challenge = [1u8; 32];
        let server_nonce = [2u8; 32];
        let client_nonce = [3u8; 32];

        let data = build_client_sign_data(&challenge, &server_nonce, &client_nonce);

        // Check structure
        assert!(data.starts_with(AUTH_CTX));
        assert!(data[AUTH_CTX.len()..].starts_with(b"client"));

        // Expected length: AUTH_CTX(21) + "client"(6) + challenge(32) + server_nonce(32) + client_nonce(32)
        assert_eq!(data.len(), AUTH_CTX.len() + 6 + 32 + 32 + 32);
    }

    #[test]
    fn test_sign_data_includes_challenge() {
        let nonce = [0u8; 32];

        let challenge1 = [1u8; 32];
        let challenge2 = [2u8; 32];

        let data1 = build_server_sign_data(&challenge1, &nonce);
        let data2 = build_server_sign_data(&challenge2, &nonce);

        // Different challenges should produce different signature data
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_sign_data_includes_nonce() {
        let challenge = [0u8; 32];

        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];

        let data1 = build_server_sign_data(&challenge, &nonce1);
        let data2 = build_server_sign_data(&challenge, &nonce2);

        // Different nonces should produce different signature data
        assert_ne!(data1, data2);
    }
}
