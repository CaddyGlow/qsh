//! Cloneable sender handle for S2N streams.
//!
//! This module provides a cloneable sender handle that allows multiple tasks
//! to send on the same stream safely via an internal Mutex.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::protocol::{Codec, Message};

use super::stream::S2nStreamInner;

// =============================================================================
// S2nSender - Cloneable sender handle
// =============================================================================

/// A cloneable sender handle for a QUIC stream.
///
/// This wraps an Arc reference to the stream's inner state, allowing multiple
/// tasks to send on the same stream safely via the internal Mutex.
#[derive(Clone)]
pub struct S2nSender {
    pub(super) inner: Arc<S2nStreamInner>,
}

impl S2nSender {
    /// Send a message (includes flush for low latency).
    pub async fn send(&self, msg: &Message) -> Result<()> {
        let data = Codec::encode(msg)?;
        self.send_raw(&data).await
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        if matches!(self.inner.direction, super::stream::StreamDirection::RecvOnly) {
            return Err(Error::Transport {
                message: "stream is receive-only".to_string(),
            });
        }

        if let Some(ref send) = self.inner.send {
            let mut stream = send.lock().await;
            stream.write_all(data).await.map_err(|e| Error::Transport {
                message: format!("stream send failed: {}", e),
            })?;
            stream.flush().await.map_err(|e| Error::Transport {
                message: format!("stream flush failed: {}", e),
            })?;
        }
        Ok(())
    }

    /// Gracefully finish the send side of the stream (send FIN).
    pub async fn finish(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        if matches!(self.inner.direction, super::stream::StreamDirection::RecvOnly) {
            return Ok(());
        }

        if let Some(ref send) = self.inner.send {
            let mut stream = send.lock().await;
            stream.shutdown().await.map_err(|e| Error::Transport {
                message: format!("stream shutdown failed: {}", e),
            })?;
        }
        Ok(())
    }
}
