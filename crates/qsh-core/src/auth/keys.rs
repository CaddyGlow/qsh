//! SSH key loading and management.
//!
//! Handles loading of:
//! - Server host keys (private keys for signing)
//! - Client private keys (for signing, with passphrase support)
//! - authorized_keys files (for client verification)

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use ssh_key::{Algorithm, HashAlg, private::PrivateKey, public::PublicKey};
use tracing::{debug, warn};

use crate::error::{Error, Result};

/// Key type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Ecdsa,
    Rsa,
}

impl KeyType {
    /// Get preference order (lower is better).
    pub fn preference(&self) -> u8 {
        match self {
            KeyType::Ed25519 => 0,
            KeyType::Ecdsa => 1,
            KeyType::Rsa => 2,
        }
    }
}

impl From<Algorithm> for KeyType {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::Ed25519 => KeyType::Ed25519,
            Algorithm::Ecdsa { .. } => KeyType::Ecdsa,
            Algorithm::Rsa { .. } => KeyType::Rsa,
            _ => KeyType::Rsa, // Default fallback
        }
    }
}

impl From<&Algorithm> for KeyType {
    fn from(alg: &Algorithm) -> Self {
        KeyType::from(alg.clone())
    }
}

/// An entry from an authorized_keys file.
#[derive(Debug, Clone)]
pub struct AuthorizedKeyEntry {
    /// The public key.
    pub key: PublicKey,
    /// Whether this key is revoked (@revoked marker).
    pub revoked: bool,
    /// Optional comment from the key line.
    pub comment: Option<String>,
}

/// Load a host key from the first available path.
///
/// Tries paths in order, preferring keys that match an existing known_hosts entry
/// if `known_hosts_keys` is provided. Otherwise prefers ed25519 > ecdsa > rsa.
pub fn load_host_key(
    paths: &[impl AsRef<Path>],
    known_hosts_keys: Option<&[PublicKey]>,
) -> Result<(PrivateKey, PublicKey)> {
    let mut candidates: Vec<(PrivateKey, PublicKey, KeyType)> = Vec::new();

    for path in paths {
        let path = path.as_ref();
        if !path.exists() {
            continue;
        }

        match load_private_key_file(path) {
            Ok(private_key) => {
                let public_key = private_key.public_key().clone();
                let key_type = KeyType::from(private_key.algorithm());
                debug!(path = %path.display(), key_type = ?key_type, "found host key");
                candidates.push((private_key, public_key, key_type));
            }
            Err(e) => {
                debug!(path = %path.display(), error = %e, "failed to load host key");
            }
        }
    }

    if candidates.is_empty() {
        return Err(Error::Protocol {
            message: "no host key found".into(),
        });
    }

    // If we have known_hosts keys, prefer a matching key
    if let Some(known_keys) = known_hosts_keys {
        for (private, public, _) in &candidates {
            if known_keys.iter().any(|k| k.key_data() == public.key_data()) {
                debug!("selected host key matching known_hosts");
                return Ok((private.clone(), public.clone()));
            }
        }
    }

    // Otherwise, sort by preference and return best
    candidates.sort_by_key(|(_, _, kt)| kt.preference());
    let (private, public, key_type) = candidates.into_iter().next().unwrap();
    debug!(key_type = ?key_type, "selected host key by preference");
    Ok((private, public))
}

/// Load a private key from a file (no passphrase).
fn load_private_key_file(path: &Path) -> Result<PrivateKey> {
    let content = fs::read_to_string(path).map_err(|e| Error::Io(e))?;

    PrivateKey::from_openssh(&content).map_err(|e| Error::Protocol {
        message: format!("failed to parse private key: {}", e),
    })
}

/// Load a private key, prompting for passphrase if encrypted.
///
/// The `passphrase_prompt` function is called for each attempt when the key is encrypted.
/// Fails after `max_attempts` failed passphrase attempts.
pub fn load_private_key<F>(
    path: &Path,
    mut passphrase_prompt: F,
    max_attempts: u8,
) -> Result<PrivateKey>
where
    F: FnMut() -> Result<String>,
{
    let content = fs::read_to_string(path).map_err(|e| Error::Io(e))?;

    // Parse the key once.
    let parsed = PrivateKey::from_openssh(&content).map_err(|e| Error::Protocol {
        message: format!("failed to parse private key: {}", e),
    })?;

    // If the key is not encrypted, we can use it as-is.
    if !parsed.is_encrypted() {
        return Ok(parsed);
    }

    // Key is encrypted, prompt for passphrase and attempt to decrypt.
    for attempt in 1..=max_attempts {
        let passphrase = passphrase_prompt()?;

        match PrivateKey::from_openssh(content.as_bytes())
            .and_then(|k| k.decrypt(passphrase.as_bytes()))
        {
            Ok(key) => {
                return Ok(key);
            }
            Err(ssh_key::Error::Crypto) => {
                if attempt < max_attempts {
                    debug!(attempt, "incorrect passphrase, retrying");
                } else {
                    return Err(Error::AuthenticationFailed);
                }
            }
            Err(e) => {
                return Err(Error::Protocol {
                    message: format!("failed to decrypt private key: {}", e),
                });
            }
        }
    }

    Err(Error::AuthenticationFailed)
}

/// Prompt for passphrase via terminal.
///
/// Returns an error if stdin is not a TTY.
pub fn prompt_passphrase(prompt: &str) -> Result<String> {
    if !atty_check::is_stdin_tty() {
        return Err(Error::Protocol {
            message: "cannot prompt for passphrase: not a terminal".into(),
        });
    }

    eprint!("{}", prompt);
    io::stderr().flush().ok();

    rpassword::read_password().map_err(|e| Error::Io(e))
}

/// Simple TTY check module.
mod atty_check {
    pub fn is_stdin_tty() -> bool {
        // Using libc directly from the crate dependency
        extern crate libc;
        unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
    }
}

/// Load authorized_keys from the first available path.
///
/// Parses OpenSSH authorized_keys format:
/// - Allows trailing comments
/// - Rejects option prefixes (keys with options are skipped)
/// - Respects @revoked markers
/// - Warns and skips @cert-authority lines
pub fn load_authorized_keys(paths: &[impl AsRef<Path>]) -> Result<Vec<AuthorizedKeyEntry>> {
    for path in paths {
        let path = path.as_ref();
        if !path.exists() {
            continue;
        }

        match parse_authorized_keys_file(path) {
            Ok(entries) => {
                debug!(
                    path = %path.display(),
                    count = entries.len(),
                    "loaded authorized_keys"
                );
                return Ok(entries);
            }
            Err(e) => {
                debug!(path = %path.display(), error = %e, "failed to load authorized_keys");
            }
        }
    }

    Err(Error::Protocol {
        message: "no authorized_keys file found".into(),
    })
}

/// Parse an authorized_keys file.
fn parse_authorized_keys_file(path: &Path) -> Result<Vec<AuthorizedKeyEntry>> {
    let file = fs::File::open(path).map_err(|e| Error::Io(e))?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| Error::Io(e))?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Check for @cert-authority (not supported)
        if line.starts_with("@cert-authority") {
            warn!(
                path = %path.display(),
                line = line_num + 1,
                "@cert-authority not supported, skipping"
            );
            continue;
        }

        // Check for @revoked marker
        let (revoked, key_line) = if line.starts_with("@revoked") {
            let rest = line.strip_prefix("@revoked").unwrap().trim_start();
            (true, rest)
        } else {
            (false, line)
        };

        // Check for option prefixes (anything before the key type)
        // SSH key types start with: ssh-rsa, ssh-ed25519, ecdsa-sha2-*, sk-ssh-*, etc.
        let key_start = find_key_start(key_line);
        if key_start > 0 {
            debug!(
                path = %path.display(),
                line = line_num + 1,
                "skipping key with options prefix"
            );
            continue;
        }

        // Parse the key
        match parse_authorized_key_line(key_line) {
            Ok((key, comment)) => {
                debug!(
                    path = %path.display(),
                    line = line_num + 1,
                    fingerprint = %key_fingerprint(&key),
                    revoked = revoked,
                    "parsed authorized key"
                );
                entries.push(AuthorizedKeyEntry {
                    key,
                    revoked,
                    comment,
                });
            }
            Err(e) => {
                debug!(
                    path = %path.display(),
                    line = line_num + 1,
                    error = %e,
                    "failed to parse key, skipping"
                );
            }
        }
    }

    Ok(entries)
}

/// Find where the actual key starts (after any options).
fn find_key_start(line: &str) -> usize {
    // Key types we recognize
    const KEY_PREFIXES: &[&str] = &[
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519",
        "sk-ecdsa-sha2-nistp256",
    ];

    for prefix in KEY_PREFIXES {
        if let Some(pos) = line.find(prefix) {
            return pos;
        }
    }

    0
}

/// Parse a single authorized_keys line into key and optional comment.
fn parse_authorized_key_line(line: &str) -> Result<(PublicKey, Option<String>)> {
    // Format: key_type base64_key [comment]
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 2 {
        return Err(Error::Protocol {
            message: "invalid key format".into(),
        });
    }

    let key_str = if parts.len() >= 2 {
        format!("{} {}", parts[0], parts[1])
    } else {
        return Err(Error::Protocol {
            message: "invalid key format".into(),
        });
    };

    let key = PublicKey::from_openssh(&key_str).map_err(|e| Error::Protocol {
        message: format!("failed to parse public key: {}", e),
    })?;

    let comment = parts.get(2).map(|s| s.to_string());

    Ok((key, comment))
}

/// Get the SHA256 fingerprint of a public key.
pub fn key_fingerprint(key: &PublicKey) -> String {
    let fp = key.fingerprint(HashAlg::Sha256);
    fp.to_string()
}

/// Check if a public key matches any authorized key.
///
/// Returns `Some(true)` if key is authorized, `Some(false)` if key is revoked,
/// `None` if key is not found.
pub fn check_authorized(key: &PublicKey, authorized: &[AuthorizedKeyEntry]) -> Option<bool> {
    for entry in authorized {
        if entry.key.key_data() == key.key_data() {
            return Some(!entry.revoked);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_key_type_preference() {
        assert!(KeyType::Ed25519.preference() < KeyType::Ecdsa.preference());
        assert!(KeyType::Ecdsa.preference() < KeyType::Rsa.preference());
    }

    #[test]
    fn test_find_key_start() {
        assert_eq!(find_key_start("ssh-ed25519 AAAA..."), 0);
        assert_eq!(find_key_start("ssh-rsa AAAA..."), 0);
        assert_eq!(find_key_start("ecdsa-sha2-nistp256 AAAA..."), 0);
    }

    #[test]
    fn test_parse_authorized_keys_empty() {
        let file = create_temp_file("");
        let entries = parse_authorized_keys_file(file.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_authorized_keys_comments() {
        let file = create_temp_file("# This is a comment\n\n# Another comment\n");
        let entries = parse_authorized_keys_file(file.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_key_fingerprint_format() {
        // Test with an actual ed25519 public key
        // This is a test key, not used for any real authentication
        let test_key_openssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example";
        let key = PublicKey::from_openssh(test_key_openssh).unwrap();
        let fingerprint = key_fingerprint(&key);

        // Fingerprint should start with SHA256: and contain base64 characters
        assert!(fingerprint.starts_with("SHA256:"));
        assert!(fingerprint.len() > 10); // SHA256 fingerprints are ~43 chars after prefix
    }
}
