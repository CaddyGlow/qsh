//! Known hosts file parsing and verification.
//!
//! Supports OpenSSH known_hosts format including:
//! - Plain hostname entries
//! - Hashed hostname entries (|1|salt|hash format)
//! - @revoked markers
//! - Port-specific entries ([host]:port format)

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;

use base64::prelude::*;
use aws_lc_rs::hmac;
use ssh_key::public::PublicKey;
use tracing::{debug, warn};

use crate::auth::canonicalize_host;
use crate::error::{Error, Result};

/// Status of a host key lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostStatus {
    /// Key is known and matches.
    Known,
    /// Host is not in known_hosts.
    Unknown,
    /// Host is known but key has changed.
    Changed {
        /// The expected key fingerprint.
        expected_fingerprint: String,
        /// The actual key fingerprint.
        actual_fingerprint: String,
    },
    /// Key is explicitly revoked.
    Revoked,
}

/// An entry from a known_hosts file.
#[derive(Debug, Clone)]
struct KnownHostEntry {
    /// Hostname pattern or hash.
    host_pattern: HostPattern,
    /// The public key.
    key: PublicKey,
    /// Whether this entry is revoked.
    revoked: bool,
}

/// Hostname pattern in known_hosts.
#[derive(Debug, Clone)]
enum HostPattern {
    /// Plain hostname (may include wildcards, but we don't support them).
    Plain(String),
    /// Hashed hostname (|1|salt|hash format).
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

impl HostPattern {
    /// Check if this pattern matches the given hostname.
    fn matches(&self, hostname: &str) -> bool {
        match self {
            HostPattern::Plain(pattern) => pattern == hostname,
            HostPattern::Hashed { salt, hash } => {
                let computed = compute_host_hash(hostname, salt);
                computed == *hash
            }
        }
    }
}

/// Compute HMAC-SHA1 hash for a hostname (OpenSSH known_hosts format).
///
/// Note: SHA-1 is used here for compatibility with OpenSSH's hashed known_hosts
/// format. This is a legacy algorithm but is required to interoperate with
/// existing known_hosts files. The security concern is limited since this is
/// only used for hostname obfuscation, not cryptographic authentication.
fn compute_host_hash(hostname: &str, salt: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let tag = hmac::sign(&key, hostname.as_bytes());
    tag.as_ref().to_vec()
}

/// Generate a fresh salt for hashing.
fn generate_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; 20]; // SHA1 output size
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Known hosts database.
#[derive(Debug, Default)]
pub struct KnownHosts {
    entries: Vec<KnownHostEntry>,
}

impl KnownHosts {
    /// Create an empty known hosts database.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Load known hosts from the first available path.
    pub fn load(paths: &[impl AsRef<Path>]) -> Result<Self> {
        for path in paths {
            let path = path.as_ref();
            if !path.exists() {
                continue;
            }

            match Self::load_file(path) {
                Ok(kh) => {
                    debug!(
                        path = %path.display(),
                        count = kh.entries.len(),
                        "loaded known_hosts"
                    );
                    return Ok(kh);
                }
                Err(e) => {
                    debug!(path = %path.display(), error = %e, "failed to load known_hosts");
                }
            }
        }

        // Return empty if no files found
        Ok(Self::new())
    }

    /// Load known hosts from a specific file.
    fn load_file(path: &Path) -> Result<Self> {
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

            // Parse the entry
            match parse_known_hosts_line(key_line) {
                Ok((host_pattern, key)) => {
                    entries.push(KnownHostEntry {
                        host_pattern,
                        key,
                        revoked,
                    });
                }
                Err(e) => {
                    debug!(
                        path = %path.display(),
                        line = line_num + 1,
                        error = %e,
                        "failed to parse known_hosts entry, skipping"
                    );
                }
            }
        }

        Ok(Self { entries })
    }

    /// Verify a host key.
    ///
    /// Looks up the canonical hostname first, then alternate form if different.
    pub fn verify_host(&self, hostname: &str, port: u16, key: &PublicKey) -> HostStatus {
        let canonical = canonicalize_host(hostname, port);

        // Try canonical form first
        let status = self.verify_host_internal(&canonical, key);
        if !matches!(status, HostStatus::Unknown) {
            return status;
        }

        // Try alternate form if different
        let alternate = if port == 22 {
            format!("[{}]:22", hostname)
        } else {
            hostname.to_string()
        };

        if alternate != canonical {
            let status = self.verify_host_internal(&alternate, key);
            if !matches!(status, HostStatus::Unknown) {
                return status;
            }
        }

        HostStatus::Unknown
    }

    /// Internal verify against a specific hostname string.
    fn verify_host_internal(&self, hostname: &str, key: &PublicKey) -> HostStatus {
        let mut found_host = false;

        for entry in &self.entries {
            if !entry.host_pattern.matches(hostname) {
                continue;
            }

            found_host = true;

            // Check if keys match
            if entry.key.key_data() == key.key_data() {
                if entry.revoked {
                    return HostStatus::Revoked;
                }
                return HostStatus::Known;
            }
        }

        if found_host {
            // Host was found but key didn't match any entry
            // Find the expected key for error reporting
            for entry in &self.entries {
                if entry.host_pattern.matches(hostname) && !entry.revoked {
                    return HostStatus::Changed {
                        expected_fingerprint: crate::auth::key_fingerprint(&entry.key),
                        actual_fingerprint: crate::auth::key_fingerprint(key),
                    };
                }
            }
        }

        HostStatus::Unknown
    }

    /// Get all known public keys (for host key selection).
    pub fn known_keys(&self) -> Vec<PublicKey> {
        self.entries
            .iter()
            .filter(|e| !e.revoked)
            .map(|e| e.key.clone())
            .collect()
    }

    /// Persist a new host key to known_hosts file.
    ///
    /// Writes in hashed format with a fresh salt.
    pub fn persist_host(path: &Path, hostname: &str, port: u16, key: &PublicKey) -> Result<()> {
        let canonical = canonicalize_host(hostname, port);
        let salt = generate_salt();
        let hash = compute_host_hash(&canonical, &salt);

        // Format: |1|base64(salt)|base64(hash) key_type base64(key) [comment]
        let salt_b64 = BASE64_STANDARD.encode(&salt);
        let hash_b64 = BASE64_STANDARD.encode(&hash);
        let host_part = format!("|1|{}|{}", salt_b64, hash_b64);

        let key_openssh = key.to_openssh().map_err(|e| Error::Protocol {
            message: format!("failed to encode public key: {}", e),
        })?;

        let line = format!("{} {}\n", host_part, key_openssh);

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
        }

        // Append to file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Error::Io(e))?;

        file.write_all(line.as_bytes()).map_err(|e| Error::Io(e))?;

        debug!(
            path = %path.display(),
            hostname = canonical,
            "persisted host key to known_hosts"
        );

        Ok(())
    }
}

/// Parse a known_hosts line into host pattern and key.
fn parse_known_hosts_line(line: &str) -> Result<(HostPattern, PublicKey)> {
    // Format: hostname|hash key_type base64_key [comment]
    let parts: Vec<&str> = line.splitn(4, ' ').collect();

    if parts.len() < 3 {
        return Err(Error::Protocol {
            message: "invalid known_hosts format".into(),
        });
    }

    let host_part = parts[0];
    let key_type = parts[1];
    let key_data = parts[2];

    // Parse host pattern
    let host_pattern = if host_part.starts_with("|1|") {
        // Hashed format: |1|salt|hash
        let hash_parts: Vec<&str> = host_part[3..].split('|').collect();
        if hash_parts.len() != 2 {
            return Err(Error::Protocol {
                message: "invalid hashed hostname format".into(),
            });
        }

        let salt = BASE64_STANDARD
            .decode(hash_parts[0])
            .map_err(|e| Error::Protocol {
                message: format!("invalid salt encoding: {}", e),
            })?;

        let hash = BASE64_STANDARD
            .decode(hash_parts[1])
            .map_err(|e| Error::Protocol {
                message: format!("invalid hash encoding: {}", e),
            })?;

        HostPattern::Hashed { salt, hash }
    } else {
        // Plain hostname (might be comma-separated list, but we only check first)
        let hostname = host_part.split(',').next().unwrap_or(host_part);
        HostPattern::Plain(hostname.to_string())
    };

    // Parse key
    let key_str = format!("{} {}", key_type, key_data);
    let key = PublicKey::from_openssh(&key_str).map_err(|e| Error::Protocol {
        message: format!("failed to parse public key: {}", e),
    })?;

    Ok((host_pattern, key))
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
    fn test_host_pattern_plain_match() {
        let pattern = HostPattern::Plain("example.com".to_string());
        assert!(pattern.matches("example.com"));
        assert!(!pattern.matches("other.com"));
    }

    #[test]
    fn test_host_pattern_hashed_match() {
        let hostname = "example.com";
        let salt = generate_salt();
        let hash = compute_host_hash(hostname, &salt);

        let pattern = HostPattern::Hashed { salt, hash };
        assert!(pattern.matches("example.com"));
        assert!(!pattern.matches("other.com"));
    }

    #[test]
    fn test_empty_known_hosts() {
        let file = create_temp_file("");
        let kh = KnownHosts::load_file(file.path()).unwrap();
        assert!(kh.entries.is_empty());
    }

    #[test]
    fn test_known_hosts_comments() {
        let file = create_temp_file("# This is a comment\n\n# Another\n");
        let kh = KnownHosts::load_file(file.path()).unwrap();
        assert!(kh.entries.is_empty());
    }

    #[test]
    fn test_host_status_variants() {
        assert_eq!(HostStatus::Known, HostStatus::Known);
        assert_eq!(HostStatus::Unknown, HostStatus::Unknown);
        assert_eq!(HostStatus::Revoked, HostStatus::Revoked);
    }
}
