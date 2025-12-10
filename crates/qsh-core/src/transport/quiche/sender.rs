//! Cloneable sender handle for QUIC streams.
//!
//! This module provides QuicheSender, a lightweight cloneable handle
//! for sending data on a QUIC stream from multiple tasks.

use std::sync::Arc;

use tracing::trace;

use crate::error::Result;
use crate::protocol::{Codec, Message};

use super::connection::QuicheConnectionInner;

// =============================================================================
// QuicheSender - Cloneable sender handle
// =============================================================================

/// A cloneable sender handle for a QUIC stream.
#[derive(Clone)]
pub struct QuicheSender {
    pub(crate) conn: Arc<QuicheConnectionInner>,
    pub(crate) stream_id: u64,
}

impl QuicheSender {
    /// Send a message (includes flush for low latency).
    pub async fn send(&self, msg: &Message) -> Result<()> {
        trace!(stream_id = self.stream_id, msg = ?msg, "quiche sender send");
        let data = Codec::encode(msg)?;
        self.conn.stream_send(self.stream_id, &data, false).await
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        self.conn.stream_send(self.stream_id, data, false).await
    }

    /// Gracefully finish the send side of the stream.
    pub async fn finish(&self) -> Result<()> {
        self.conn.stream_send(self.stream_id, &[], true).await
    }
}
