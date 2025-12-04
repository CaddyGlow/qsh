# Plan: SSH Key Authentication for Standalone Mode

## Summary

Add `qsh-server --standalone` mode with mutual SSH key authentication (feature-gated):
- **Server authentication**: Server signs challenge with its host key; client verifies via `known_hosts`
- **Client authentication**: Client signs challenge with private key; server verifies via `authorized_keys`

This mirrors SSH's trust model without requiring an SSH connection.

## Feature Gate

All standalone auth code gated behind `#[cfg(feature = "standalone")]`:
- `qsh-core/Cargo.toml`: `standalone = ["dep:ssh-key", "dep:rpassword", "dep:tokio-ssh-agent"]`
- `qsh-server/Cargo.toml`: `standalone = ["qsh-core/standalone"]`
- `qsh-client/Cargo.toml`: `standalone = ["qsh-core/standalone"]`

## Requirements

- Server uses SSH host key for identity (reuses sshd keys, verifiable via known_hosts)
- Client proves identity via SSH private key (verified against authorized_keys)
- Host key lookup: `--host-key`, then `~/.config/qsh/qsh_host_{ed25519,rsa,ecdsa}_key`, then `/etc/ssh/ssh_host_{ed25519,rsa,ecdsa}_key`; prefer a key that matches an existing known_hosts entry (if any), otherwise prefer ed25519 > ecdsa > rsa; allow CLI override of host key path/type
- Authorized keys: `~/.config/qsh/authorized_keys`, then `~/.ssh/authorized_keys`; allow trailing comments; reject ssh options prefixes; honor `@revoked` entries by treating matching keys as revoked (authentication fails even if the key matches); warn and skip lines with `@cert-authority` (certificate auth out of scope for v1)
- Client known_hosts: `--known-hosts`, then `~/.config/qsh/known_hosts`, then `~/.ssh/known_hosts`
- Unknown hosts: fail-closed by default (non-interactive); TOFU allowed only with explicit `--accept-unknown-host`, which appends the accepted key in canonical form to the chosen known_hosts file hashed with a fresh salt
- Passphrase-protected private keys: prompt for passphrase via terminal when encrypted; allow up to 3 attempts per key; fail fast with a clear error if no TTY is available; never cache passphrases across operations (re-prompt on each use)
- SSH agent support: use agent for signing when `SSH_AUTH_SOCK` is set (can be disabled with `--no-agent`)
- Hostname binding (known_hosts only): canonicalize the client-intended host for known_hosts lookup (bare host for port 22, `[host]:port` otherwise); signatures do NOT include hostname (SSH-style)

## Protocol Changes

Add to `Message` enum in `qsh-core/src/protocol/types.rs`:

```rust
const AUTH_CTX: &[u8] = b"qsh-standalone-auth-v1";

// Standalone authentication messages
AuthChallenge(AuthChallengePayload),
AuthResponse(AuthResponsePayload),
AuthFailure(AuthFailurePayload),

/// Server sends after QUIC connect (includes server signature for client to verify)
pub struct AuthChallengePayload {
    pub server_public_key: String,      // Server's host key (OpenSSH format)
    pub challenge: [u8; 32],            // Random nonce for client to sign
    pub server_nonce: [u8; 32],         // Random nonce (not timestamp)
    pub server_signature: Vec<u8>,      // Server signs (see Signature Data Format below)
}

/// Client response (proves client identity)
pub struct AuthResponsePayload {
    pub client_public_key: String,      // Client's public key (OpenSSH format)
    pub client_nonce: [u8; 32],         // Random nonce
    pub signature: Vec<u8>,             // Client signs: AUTH_CTX || "client" || challenge || server_nonce || client_nonce
}

/// Authentication failure (sent by server)
pub struct AuthFailurePayload {
    pub code: AuthErrorCode,
    pub message: String,
}

pub enum AuthErrorCode {
    AuthFailed,      // Generic auth failure (unknown key, revoked, bad signature, etc.)
    Timeout,         // Client took too long to respond
    ProtocolError,   // Malformed or unexpected message
    InternalError,   // Server-side error
}
```

On the wire, the server only exposes coarse-grained errors: `Timeout` is used when the handshake exceeds the 30s deadline; all other authentication failures (unknown key, revoked key, invalid signature, etc.) are mapped to `AuthFailed` with a generic `"authentication failed"` message. The server logs capture the specific internal failure reason, but the client UI treats all non-timeout codes as a generic authentication error.

**Signature algorithms** (no negotiation - determined by key type):
- ed25519: `ssh-ed25519`
- ecdsa-p256: `ecdsa-sha2-nistp256`
- rsa: `rsa-sha2-512` (SHA-512; never SHA-1)

**SSH-style signatures**: Signatures do NOT include hostname/port. The server proves key ownership; the client verifies the key against known_hosts for the target host separately. This mirrors SSH's trust model where the hostname-to-key binding is stored client-side in known_hosts, not proven cryptographically by the server.

**Auth handshake timeout**: 30 seconds from QUIC connect to completed AuthResponse. Server sends `AuthFailure { code: Timeout, .. }` on expiry.

## Signature Data Format

Signatures are computed over a structured byte sequence. SSH-style: no hostname/port in signatures.

**Server signature** (proves key ownership):
```
AUTH_CTX (21 bytes) || "server" (6 bytes) || challenge (32 bytes) || server_nonce (32 bytes)
```

**Client signature** (proves key ownership):
```
AUTH_CTX (21 bytes) || "client" (6 bytes) || challenge (32 bytes) || server_nonce (32 bytes) || client_nonce (32 bytes)
```

The hostname-to-key binding is maintained client-side via known_hosts lookup, not embedded in signatures. This avoids the bind-address vs connect-address mismatch problem (e.g., server binds to 0.0.0.0 but client connects to 127.0.0.1).

## Handshake Flow (Standalone)

```
Client                                    Server
   |                                         |
   |---------- QUIC Connect ---------------->|
   |                                         |
   |<--------- AuthChallenge ----------------|
   |           - server_public_key           |
   |           - challenge (32 bytes)        |
   |           - server_nonce (32 bytes)     |
   |           - server_signature            |
   |                                         |
   |  [Client verifies server_public_key     |
   |   against known_hosts using canonical   |
   |   target; fail-closed unless            |
   |   --accept-unknown-host]                |
   |  [Client verifies server_signature]     |
   |                                         |
   |---------- AuthResponse ---------------->|
   |           - client_public_key           |
   |           - client_nonce (32 bytes)     |
   |           - signature                   |
   |                                         |
   |  [Server verifies client_public_key     |
   |   against authorized_keys]              |
   |  [Server verifies client signature]     |
   |                                         |
   |<--------- AuthFailure (if failed) ------|  (connection closes after)
   |                                         |
   |---------- Hello ----------------------->|  (session continues normally)
   |<--------- HelloAck ---------------------|
```

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `qsh-core/src/auth/mod.rs` | Module root |
| `qsh-core/src/auth/keys.rs` | Load host keys, authorized_keys, private keys (with passphrase) |
| `qsh-core/src/auth/known_hosts.rs` | Parse and check ~/.ssh/known_hosts |
| `qsh-core/src/auth/challenge.rs` | Challenge generation/signing/verification |
| `qsh-core/src/auth/agent.rs` | SSH agent client for key listing and signing |
| `qsh-server/src/standalone.rs` | Standalone server mode |
| `qsh-client/src/standalone.rs` | Direct connection mode |

### Modified Files

| File | Changes |
|------|---------|
| `Cargo.toml` (workspace) | Add `ssh-key = "0.6"`, `rpassword = "7"`, `tokio-ssh-agent = "0.3"` |
| `qsh-core/Cargo.toml` | Add `ssh-key`, `rpassword`, `tokio-ssh-agent` deps |
| `qsh-core/src/lib.rs` | Export `auth` module |
| `qsh-core/src/protocol/types.rs` | Add auth message types |
| `qsh-core/src/constants.rs` | Add key path constants |
| `qsh-server/src/main.rs` | Add `--standalone`, `--host-key`, `--authorized-keys` |
| `qsh-server/src/session.rs` | Add standalone auth flow |
| `qsh-client/src/main.rs` | Add `--direct`, `--server`, `--key` |
| `qsh-client/src/cli.rs` | Add direct mode CLI args |

## Implementation Phases

### Phase 1: Core Auth Module

1. Add `ssh-key`, `rpassword`, and `tokio-ssh-agent` dependencies
2. `keys.rs`:
   - `load_host_key(paths: &[PathBuf]) -> Result<(PrivateKey, PublicKey)>` - try paths in order across ed25519/ecdsa/rsa (prefer a known_hosts match first, else prefer ed25519 > ecdsa > rsa)
   - `load_authorized_keys(paths: &[PathBuf]) -> Result<Vec<AuthorizedKeyEntry>>` - allow trailing comments; reject option prefixes; respect `@revoked` markers by treating matching keys as revoked (authentication fails even if the key matches); warn and skip `cert-authority` lines (certificate auth out of scope for v1)
   - `load_private_key(path: &Path, passphrase_prompt: impl Fn() -> Result<String>) -> Result<PrivateKey>` - decrypt if encrypted; never cache passphrases (call `passphrase_prompt` for each attempt, fail after at most 3 tries)
   - `key_fingerprint(key: &PublicKey) -> String` - SHA256 fingerprint
3. `known_hosts.rs`:
   - `KnownHosts::load(paths: &[PathBuf]) -> Result<Self>` - parse known_hosts (supports hashed entries `|1|`, @revoked handling); warn and skip `@cert-authority` lines (certificate auth out of scope for v1)
   - `verify_host(hostname: &str, port: u16, key: &PublicKey) -> Result<HostStatus>` - lookup order: canonicalized hostname first (bare host for 22, `[host]:port` otherwise), then alternate form if different
   - `persist_host(path: &Path, hostname: &str, port: u16, key: &PublicKey)` - always writes as canonical `[hostname]:port` format (bare host for 22) using a fresh salt when hashing
   - `HostStatus` enum: `Known`, `Unknown`, `Changed`, `Revoked`
4. `agent.rs`:
   - `Agent::connect() -> Result<Option<Self>>` - connect to agent via `SSH_AUTH_SOCK`, returns `None` if not set
   - `list_keys() -> Result<Vec<PublicKey>>` - list all keys held by agent, preserving order
   - `sign(key: &PublicKey, data: &[u8]) -> Result<Vec<u8>>` - request agent to sign data with specified key
   - `MockAgent` (test only) - in-memory agent for unit tests; holds configurable keys and records sign requests
5. `challenge.rs`:
   - `generate_nonce() -> [u8; 32]`
   - `Signer` trait - abstraction over local key and agent signing
   - `sign_server(signer: &impl Signer, challenge: &[u8; 32], server_nonce: &[u8; 32]) -> Result<Vec<u8>>` - signs AUTH_CTX || "server" || challenge || server_nonce
   - `sign_client(signer: &impl Signer, challenge: &[u8; 32], server_nonce: &[u8; 32], client_nonce: &[u8; 32]) -> Result<Vec<u8>>` - signs AUTH_CTX || "client" || challenge || server_nonce || client_nonce
   - `verify_server(key: &PublicKey, signature: &[u8], challenge: &[u8; 32], server_nonce: &[u8; 32]) -> Result<bool>`
   - `verify_client(key: &PublicKey, signature: &[u8], challenge: &[u8; 32], server_nonce: &[u8; 32], client_nonce: &[u8; 32]) -> Result<bool>`

### Phase 2: Protocol Types

1. Add `AuthChallengePayload`, `AuthResponsePayload`, `AuthFailurePayload`, `AuthErrorCode`
2. Add `Message::AuthChallenge`, `Message::AuthResponse`, `Message::AuthFailure`
3. Update proptest generators

### Phase 3: Server Standalone Mode

CLI args:
- `--standalone` - enable standalone mode
- `--host-key <PATH>` - path to host private key
- `--authorized-keys <PATH>` - path to authorized_keys
- `--port <PORT>` - listen port (required)

- `standalone.rs`:
- Load host key from: `--host-key` / `~/.config/qsh/qsh_host_{ed25519,rsa,ecdsa}_key` / `/etc/ssh/ssh_host_{ed25519,rsa,ecdsa}_key` (pick a key matching known_hosts if present; otherwise prefer ed25519 > ecdsa > rsa)
- Load authorized_keys from: `--authorized-keys` / `~/.config/qsh/authorized_keys` / `~/.ssh/authorized_keys`
- On accept: generate challenge + server_nonce, sign with host key, send AuthChallenge
- On AuthResponse: verify client key in authorized_keys, verify signature
- On failure: send AuthFailure with appropriate code, close connection
- On success: continue to normal Hello/HelloAck

### Phase 4: Client Direct Mode

CLI args:
- `--direct` - skip SSH bootstrap
- `--server <HOST:PORT>` - server address
- `--key <PATH>` - private key (default: ~/.ssh/id_ed25519, id_rsa)
- `--known-hosts <PATH>` - known_hosts file (default: ~/.config/qsh/known_hosts, fallback ~/.ssh/known_hosts)
- `--accept-unknown-host` - opt-in TOFU; otherwise unknown hosts fail-closed
- `--no-agent` - disable ssh-agent, use file keys only

`standalone.rs`:
- Connect QUIC to server
- Receive AuthChallenge
- Verify server key against known_hosts using the canonicalized target host (bare host for 22, `[host]:port` otherwise):
  - Lookup canonical form first, then alternate form if different
  - If `Revoked`: fail with error
  - If `Changed`: fail with error (key mismatch)
  - If `Unknown` and no `--accept-unknown-host`: fail-closed
  - If `Unknown` and `--accept-unknown-host`: append canonical entry hashed with fresh salt
- Verify server signature
- Get signing key (in order):
  1. If `--key` specified: load from file (prompt for passphrase if encrypted)
  2. If agent available (SSH_AUTH_SOCK set) and not `--no-agent`: try agent keys in order until one works; allow selection by fingerprint/path override if provided; fall back to file keys before failing
  3. Otherwise: try default key file paths (prompt for passphrase if encrypted)
- Generate client_nonce, sign challenge (via agent or local key)
- Send AuthResponse
- Handle AuthFailure if received
- Continue with Hello

### Phase 5: Tests

1. Unit: key loading (ed25519, rsa, ecdsa formats, encrypted keys)
2. Unit: known_hosts parsing and lookup (plain and hashed entries, port-aware lookup)
3. Unit: challenge sign/verify roundtrip
4. Unit: passphrase prompting for encrypted keys
5. Unit: agent connection and key listing (mock agent)
6. Unit: agent signing (mock agent)
7. Integration: successful mutual auth (file key)
8. Integration: successful mutual auth (agent key)
9. Integration: unknown server key fails closed by default
10. Integration: `--accept-unknown-host` appends `[host]:port` entry and proceeds
11. Integration: unauthorized client rejection with AuthFailure
12. Integration: revoked key rejection
13. Integration: `--no-agent` forces file key usage

## Security Model

| Property | Implementation |
|----------|----------------|
| Server Identity | Host key signed challenge, verified via known_hosts (SSH-style) |
| Client Identity | Private key signed challenge, verified via authorized_keys |
| Context Binding | Domain-separated transcript (AUTH_CTX) covering role + challenge + nonces |
| Host Binding | Client-side via known_hosts lookup (not in signatures) |
| Replay Prevention | Random 32-byte challenge + random 32-byte nonces |
| MITM Prevention | Mutual authentication before any session data |
| Key Compromise | Same as SSH - compromised key requires revocation |

Logging guidelines: log detailed internal authentication failure reasons server-side (unknown key, revoked key, invalid signature), but only expose the generic `AuthFailed` code and message to clients for non-timeout failures, and never log passphrases or private key material.

## Known Hosts Lookup

**Lookup order** (for verifying server):
1. Try canonicalized target (`hostname` for port 22, `[hostname]:port` otherwise)
2. Try the alternate form if different

**New entry format** (for TOFU):
- Always written as the canonical form (`hostname` for 22, `[hostname]:port` otherwise) with a freshly generated hash salt

## Key Discovery Order

**Server host key:**
1. `--host-key <path>`
2. `~/.config/qsh/qsh_host_ed25519_key`
3. `~/.config/qsh/qsh_host_ecdsa_key`
4. `~/.config/qsh/qsh_host_rsa_key`
5. `/etc/ssh/ssh_host_ed25519_key`
6. `/etc/ssh/ssh_host_ecdsa_key`
7. `/etc/ssh/ssh_host_rsa_key`
- When multiple keys exist, prefer one that matches known_hosts; otherwise prefer ed25519 > ecdsa > rsa

**Server authorized_keys:**
1. `--authorized-keys <path>`
2. `~/.config/qsh/authorized_keys`
3. `~/.ssh/authorized_keys`

**Client signing key** (first match wins):
1. `--key <path>` - explicit file
2. SSH agent (if `SSH_AUTH_SOCK` set and not `--no-agent`) - try keys in order until one authenticates; allow selection by fingerprint/path override; fall back to files before failing
3. `~/.config/qsh/id_ed25519`
4. `~/.config/qsh/id_rsa`
5. `~/.ssh/id_ed25519`
6. `~/.ssh/id_rsa`

**Client known_hosts:**
1. `--known-hosts <path>`
2. `~/.config/qsh/known_hosts`
3. `~/.ssh/known_hosts`
- Use canonical form for lookup (`hostname` for port 22, `[hostname]:port` otherwise) and persist hashed with a fresh salt

## Dependencies

```toml
# In workspace Cargo.toml [workspace.dependencies]
ssh-key = { version = "0.6", features = ["ed25519", "rsa", "p256", "std", "encryption"] }
rpassword = "7"
tokio-ssh-agent = "0.3"

# In qsh-core/Cargo.toml
[features]
standalone = ["dep:ssh-key", "dep:rpassword", "dep:tokio-ssh-agent"]

[dependencies]
ssh-key = { workspace = true, optional = true }
rpassword = { workspace = true, optional = true }
tokio-ssh-agent = { workspace = true, optional = true }
```

Pure Rust, no OpenSSL. The `encryption` feature on `ssh-key` enables decrypting passphrase-protected keys. The `tokio-ssh-agent` crate provides async SSH agent protocol support.

## Tests

- **Unit/integration (default)**:
  - `cargo test -p qsh-server --features standalone`
    - Includes `standalone_auth_end_to_end` (`crates/qsh-server/src/standalone.rs`), which runs a full in-memory standalone auth handshake between `StandaloneAuthenticator` (server) and `DirectAuthenticator` (client) using real OpenSSH-format test keys, `authorized_keys`, and `known_hosts`.
- **Full QUIC + standalone + Hello/HelloAck (manual)**:
  - `cargo test -p qsh-server --features standalone standalone_quic_session_end_to_end -- --nocapture`
    - Ignored by default (slow), this spins up a real QUIC endpoint with TLS, performs standalone mutual auth over a dedicated stream, then completes the Hello/HelloAck handshake and opens terminal streams using `ClientConnection::from_quic`.
