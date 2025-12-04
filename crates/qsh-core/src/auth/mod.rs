//! SSH key authentication for standalone mode.
//!
//! This module provides mutual authentication using SSH keys:
//! - Server authentication: Server signs challenge with host key, client verifies via known_hosts
//! - Client authentication: Client signs challenge with private key, server verifies via authorized_keys
//!
//! This mirrors SSH's trust model without requiring an SSH connection.

mod agent;
mod challenge;
mod keys;
mod known_hosts;

pub use agent::Agent;
pub use challenge::LocalSigner;
pub use challenge::Signer;
pub use challenge::{
    build_client_sign_data, generate_challenge, generate_nonce, sign_client, sign_server,
    verify_client, verify_server,
};
pub use keys::{
    check_authorized, key_fingerprint, load_authorized_keys, load_host_key, load_private_key,
    prompt_passphrase, AuthorizedKeyEntry, KeyType,
};
pub use known_hosts::{HostStatus, KnownHosts};

use std::path::PathBuf;

/// Default paths for server host keys (in preference order).
pub fn default_host_key_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // User config directory first
    if let Some(home) = dirs_path::home_dir() {
        let config_dir = home.join(".config").join("qsh");
        paths.push(config_dir.join("qsh_host_ed25519_key"));
        paths.push(config_dir.join("qsh_host_ecdsa_key"));
        paths.push(config_dir.join("qsh_host_rsa_key"));
    }

    // System SSH host keys
    paths.push(PathBuf::from("/etc/ssh/ssh_host_ed25519_key"));
    paths.push(PathBuf::from("/etc/ssh/ssh_host_ecdsa_key"));
    paths.push(PathBuf::from("/etc/ssh/ssh_host_rsa_key"));

    paths
}

/// Default paths for authorized_keys (in preference order).
pub fn default_authorized_keys_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs_path::home_dir() {
        paths.push(home.join(".config").join("qsh").join("authorized_keys"));
        paths.push(home.join(".ssh").join("authorized_keys"));
    }

    paths
}

/// Default paths for client known_hosts (in preference order).
pub fn default_known_hosts_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs_path::home_dir() {
        paths.push(home.join(".config").join("qsh").join("known_hosts"));
        paths.push(home.join(".ssh").join("known_hosts"));
    }

    paths
}

/// Default paths for client private keys (in preference order).
pub fn default_client_key_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs_path::home_dir() {
        // QSH config directory (ed25519 > ecdsa > rsa preference)
        let config_dir = home.join(".config").join("qsh");
        paths.push(config_dir.join("id_ed25519"));
        paths.push(config_dir.join("id_ecdsa"));
        paths.push(config_dir.join("id_rsa"));

        // SSH directory (ed25519 > ecdsa > rsa preference)
        let ssh_dir = home.join(".ssh");
        paths.push(ssh_dir.join("id_ed25519"));
        paths.push(ssh_dir.join("id_ecdsa"));
        paths.push(ssh_dir.join("id_rsa"));
    }

    paths
}

/// Simple home directory lookup (avoid adding dirs crate dependency).
mod dirs_path {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Canonicalize hostname for known_hosts lookup and signature binding.
///
/// Returns bare hostname for port 22, `[hostname]:port` otherwise.
pub fn canonicalize_host(hostname: &str, port: u16) -> String {
    if port == 22 {
        hostname.to_string()
    } else {
        format!("[{}]:{}", hostname, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_host_port_22() {
        assert_eq!(canonicalize_host("example.com", 22), "example.com");
    }

    #[test]
    fn test_canonicalize_host_custom_port() {
        assert_eq!(canonicalize_host("example.com", 4433), "[example.com]:4433");
    }

    #[test]
    fn test_default_paths_not_empty() {
        // These may be empty if HOME is not set, but shouldn't panic
        let _ = default_host_key_paths();
        let _ = default_authorized_keys_paths();
        let _ = default_known_hosts_paths();
        let _ = default_client_key_paths();
    }
}
