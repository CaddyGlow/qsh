//! TLS certificate and key handling utilities.
//!
//! Provides functions for loading certificates/keys from PEM data,
//! computing certificate hashes, and generating self-signed certificates.

use crate::error::{Error, Result};

/// Load certificate chain from PEM file.
pub fn load_certs_from_pem(pem_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut reader = std::io::BufReader::new(pem_data);

    for cert in rustls_pemfile::certs(&mut reader) {
        match cert {
            Ok(c) => certs.push(c.to_vec()),
            Err(e) => {
                return Err(Error::CertificateError {
                    message: format!("failed to parse certificate: {}", e),
                });
            }
        }
    }

    if certs.is_empty() {
        return Err(Error::CertificateError {
            message: "no certificates found in PEM data".to_string(),
        });
    }

    Ok(certs)
}

/// Load private key from PEM file.
pub fn load_key_from_pem(pem_data: &[u8]) -> Result<Vec<u8>> {
    let mut reader = std::io::BufReader::new(pem_data);

    // Try PKCS8 first
    for key in rustls_pemfile::pkcs8_private_keys(&mut reader) {
        match key {
            Ok(k) => return Ok(k.secret_pkcs8_der().to_vec()),
            Err(_) => continue,
        }
    }

    // Try RSA
    reader = std::io::BufReader::new(pem_data);
    for key in rustls_pemfile::rsa_private_keys(&mut reader) {
        match key {
            Ok(k) => return Ok(k.secret_pkcs1_der().to_vec()),
            Err(_) => continue,
        }
    }

    Err(Error::CertificateError {
        message: "no private key found in PEM data".to_string(),
    })
}

/// Compute SHA-256 hash of certificate DER bytes.
pub fn cert_hash(cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().to_vec()
}

/// Generate a self-signed certificate and return (cert_pem, key_pem).
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let certified_key = rcgen::generate_simple_self_signed(vec!["qsh-server".to_string()])
        .map_err(|e| Error::CertificateError {
            message: format!("failed to generate certificate: {}", e),
        })?;

    let cert_pem = certified_key.cert.pem().into_bytes();
    let key_pem = certified_key.signing_key.serialize_pem().into_bytes();

    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_hash_sha256() {
        let data = b"test certificate data";
        let hash = cert_hash(data);
        assert_eq!(hash.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn generate_self_signed_cert_works() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok(), "should generate self-signed cert");
        let (cert, key) = result.unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }
}
