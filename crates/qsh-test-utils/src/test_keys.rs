//! Pre-generated keys for deterministic testing.
//!
//! Provides fixed session keys and certificates for tests
//! to avoid generating random keys each time.

use qsh_core::constants::SESSION_KEY_LEN;

/// Test keys and certificates.
pub struct TestKeys;

impl TestKeys {
    /// A fixed session key for testing (32 bytes of 0xAB).
    pub const SESSION_KEY: [u8; SESSION_KEY_LEN] = [0xAB; SESSION_KEY_LEN];

    /// A second session key for testing multiple sessions.
    pub const SESSION_KEY_2: [u8; SESSION_KEY_LEN] = [0xCD; SESSION_KEY_LEN];

    /// A third session key for testing.
    pub const SESSION_KEY_3: [u8; SESSION_KEY_LEN] = [0xEF; SESSION_KEY_LEN];

    /// Generate a deterministic session key from a seed.
    pub fn session_key_from_seed(seed: u8) -> [u8; SESSION_KEY_LEN] {
        [seed; SESSION_KEY_LEN]
    }

    /// Generate a random session key using rand.
    pub fn random_session_key() -> [u8; SESSION_KEY_LEN] {
        use rand::Rng;
        let mut key = [0u8; SESSION_KEY_LEN];
        rand::rng().fill(&mut key);
        key
    }

    /// A fixed certificate hash for testing.
    pub const CERT_HASH: [u8; 32] = [0x11; 32];

    /// A second certificate hash for testing.
    pub const CERT_HASH_2: [u8; 32] = [0x22; 32];
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_constants() {
        assert_eq!(TestKeys::SESSION_KEY.len(), SESSION_KEY_LEN);
        assert_eq!(TestKeys::SESSION_KEY_2.len(), SESSION_KEY_LEN);
        assert_eq!(TestKeys::SESSION_KEY_3.len(), SESSION_KEY_LEN);

        // Keys should be different
        assert_ne!(TestKeys::SESSION_KEY, TestKeys::SESSION_KEY_2);
        assert_ne!(TestKeys::SESSION_KEY_2, TestKeys::SESSION_KEY_3);
    }

    #[test]
    fn test_session_key_from_seed() {
        let key1 = TestKeys::session_key_from_seed(0x42);
        let key2 = TestKeys::session_key_from_seed(0x42);
        let key3 = TestKeys::session_key_from_seed(0x43);

        // Same seed -> same key
        assert_eq!(key1, key2);
        // Different seed -> different key
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_random_session_key() {
        let key1 = TestKeys::random_session_key();
        let key2 = TestKeys::random_session_key();

        // Random keys should (almost certainly) be different
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), SESSION_KEY_LEN);
    }

    #[test]
    fn test_cert_hash_constants() {
        assert_eq!(TestKeys::CERT_HASH.len(), 32);
        assert_eq!(TestKeys::CERT_HASH_2.len(), 32);
        assert_ne!(TestKeys::CERT_HASH, TestKeys::CERT_HASH_2);
    }
}
