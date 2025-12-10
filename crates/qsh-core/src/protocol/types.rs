//! Protocol types (deprecated - types have been moved to specialized modules).
//!
//! This module previously contained all protocol types but they have been
//! reorganized into the following modules for better organization:
//!
//! - `channel.rs` - Channel identification and types (ChannelId, ChannelSide, ChannelType)
//! - `params.rs` - Channel parameters for all channel types
//! - `lifecycle.rs` - Session and channel lifecycle payloads
//! - `control.rs` - Connection-level control messages (Hello, Heartbeat, etc.)
//! - `data.rs` - Channel data payloads (terminal, file transfer, tunnel)
//! - `message.rs` - Top-level Message enum
//!
//! All types are re-exported from `protocol/mod.rs` for backward compatibility.
