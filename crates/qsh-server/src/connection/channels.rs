//! Channel management for connections.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelAcceptData, ChannelAcceptPayload, ChannelClosePayload, ChannelCloseReason, ChannelId,
    ChannelOpenPayload, ChannelParams, ChannelRejectCode, ChannelRejectPayload, Message,
    ResizePayload, StateAckPayload,
};

use crate::channel::{ChannelHandle, FileTransferChannel, ForwardChannel, TerminalChannel};

use super::ConnectionHandler;

/// Channel counts by type.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChannelCounts {
    pub terminals: usize,
    pub file_transfers: usize,
    pub forwards: usize,
}

impl ChannelCounts {
    /// Total channel count.
    pub fn total(&self) -> usize {
        self.terminals + self.file_transfers + self.forwards
    }
}

impl ConnectionHandler {
    /// Allocate a new server-initiated channel ID.
    pub fn next_channel_id(&self) -> ChannelId {
        let id = self
            .next_server_channel_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ChannelId::server(id)
    }

    /// Get the number of active channels.
    pub async fn channel_count(&self) -> usize {
        self.channels.read().await.len()
    }

    /// Count channels by type.
    pub async fn channel_counts(&self) -> ChannelCounts {
        let channels = self.channels.read().await;
        let mut counts = ChannelCounts::default();

        for handle in channels.values() {
            match handle {
                ChannelHandle::Terminal(_) => counts.terminals += 1,
                ChannelHandle::FileTransfer(_) => counts.file_transfers += 1,
                ChannelHandle::Forward(_) => counts.forwards += 1,
            }
        }

        counts
    }

    /// Handle a ChannelOpen request.
    pub async fn handle_channel_open(self: &Arc<Self>, payload: ChannelOpenPayload) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(
            channel_id = %channel_id,
            channel_type = %payload.params.channel_type(),
            "Received ChannelOpen request"
        );

        // Check if channel ID already exists
        {
            let channels = self.channels.read().await;
            if channels.contains_key(&channel_id) {
                return self
                    .send_channel_reject(
                        channel_id,
                        ChannelRejectCode::InvalidChannelId,
                        "channel ID already in use",
                    )
                    .await;
            }
        }

        // Check connection-level limits
        let counts = self.channel_counts().await;
        if counts.total() >= self.config.max_channels {
            return self
                .send_channel_reject(
                    channel_id,
                    ChannelRejectCode::ResourceShortage,
                    "max channels exceeded",
                )
                .await;
        }

        // Dispatch by channel type
        match payload.params {
            ChannelParams::Terminal(params) => {
                if counts.terminals >= self.config.max_terminals {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max terminals exceeded",
                        )
                        .await;
                }
                self.open_terminal_channel(channel_id, params).await
            }
            ChannelParams::FileTransfer(params) => {
                if counts.file_transfers >= self.config.max_file_transfers {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max file transfers exceeded",
                        )
                        .await;
                }
                self.open_file_transfer_channel(channel_id, params).await
            }
            ChannelParams::DirectTcpIp(params) => {
                if counts.forwards >= self.config.max_forwards as usize {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max forwards exceeded",
                        )
                        .await;
                }
                self.open_direct_tcpip_channel(channel_id, params).await
            }
            ChannelParams::ForwardedTcpIp(_) => {
                // ForwardedTcpIp is server-initiated, should never come from client
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::UnknownChannelType,
                    "forwarded-tcpip is server-initiated only",
                )
                .await
            }
            ChannelParams::DynamicForward(params) => {
                if counts.forwards >= self.config.max_forwards as usize {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max forwards exceeded",
                        )
                        .await;
                }
                self.open_dynamic_forward_channel(channel_id, params).await
            }
            #[cfg(feature = "tunnel")]
            ChannelParams::Tunnel(params) => self.open_tunnel_channel(channel_id, params).await,
        }
    }

    /// Handle a ChannelClose request.
    pub async fn handle_channel_close(&self, payload: ChannelClosePayload) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(
            channel_id = %channel_id,
            reason = %payload.reason,
            "Received ChannelClose"
        );

        // Remove and get the channel
        let channel = {
            let mut channels = self.channels.write().await;
            channels.remove(&channel_id)
        };

        match channel {
            Some(handle) => {
                // Clean up channel resources
                handle.close().await;

                // Send close confirmation (SSH-style handshake)
                let confirm = Message::ChannelClose(ChannelClosePayload {
                    channel_id,
                    reason: ChannelCloseReason::Normal,
                });
                self.send_control(&confirm).await?;

                info!(channel_id = %channel_id, "Channel closed");
                Ok(())
            }
            None => {
                warn!(channel_id = %channel_id, "ChannelClose for unknown channel");
                Ok(())
            }
        }
    }

    /// Handle a ChannelAccept from the client (for server-initiated channels).
    pub async fn handle_channel_accept(&self, payload: ChannelAcceptPayload) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(channel_id = %channel_id, "Received ChannelAccept");

        // Notify waiting task
        if let Some(tx) = self.pending_channel_opens.lock().await.remove(&channel_id) {
            let _ = tx.send(Ok(()));
        } else {
            warn!(channel_id = %channel_id, "ChannelAccept for unknown pending channel");
        }

        Ok(())
    }

    /// Handle a ChannelReject from the client (for server-initiated channels).
    pub async fn handle_channel_reject(&self, payload: ChannelRejectPayload) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(
            channel_id = %channel_id,
            code = ?payload.code,
            message = %payload.message,
            "Received ChannelReject"
        );

        // Notify waiting task
        if let Some(tx) = self.pending_channel_opens.lock().await.remove(&channel_id) {
            let _ = tx.send(Err(Error::Forward {
                message: payload.message,
            }));
        } else {
            warn!(channel_id = %channel_id, "ChannelReject for unknown pending channel");
        }

        Ok(())
    }

    /// Handle a Resize message.
    pub async fn handle_resize(&self, payload: ResizePayload) -> Result<()> {
        let channel_id = match payload.channel_id {
            Some(id) => id,
            None => {
                // Legacy: resize applies to first terminal channel
                let channels = self.channels.read().await;
                if let Some((id, _)) = channels
                    .iter()
                    .find(|(_, h)| matches!(h, ChannelHandle::Terminal(_)))
                {
                    *id
                } else {
                    warn!("Resize without channel_id and no terminal channels");
                    return Ok(());
                }
            }
        };

        let channels = self.channels.read().await;
        if let Some(ChannelHandle::Terminal(terminal)) = channels.get(&channel_id) {
            terminal.resize(payload.cols, payload.rows).await?;
        } else {
            warn!(channel_id = %channel_id, "Resize for non-terminal or unknown channel");
        }

        Ok(())
    }

    /// Handle a StateAck message.
    pub async fn handle_state_ack(&self, payload: StateAckPayload) -> Result<()> {
        let channel_id = match payload.channel_id {
            Some(id) => id,
            None => {
                // Legacy: ack applies to first terminal channel
                let channels = self.channels.read().await;
                if let Some((id, _)) = channels
                    .iter()
                    .find(|(_, h)| matches!(h, ChannelHandle::Terminal(_)))
                {
                    *id
                } else {
                    return Ok(());
                }
            }
        };

        let channels = self.channels.read().await;
        if let Some(ChannelHandle::Terminal(terminal)) = channels.get(&channel_id) {
            terminal.handle_state_ack(payload.generation).await;
        }

        Ok(())
    }

    /// Send a ChannelReject message.
    pub async fn send_channel_reject(
        &self,
        channel_id: ChannelId,
        code: ChannelRejectCode,
        message: &str,
    ) -> Result<()> {
        let reject = Message::ChannelReject(ChannelRejectPayload {
            channel_id,
            code,
            message: message.to_string(),
        });
        self.send_control(&reject).await
    }

    /// Send a ChannelAccept message.
    pub async fn send_channel_accept(
        &self,
        channel_id: ChannelId,
        data: ChannelAcceptData,
    ) -> Result<()> {
        let accept = Message::ChannelAccept(ChannelAcceptPayload { channel_id, data });
        self.send_control(&accept).await
    }

    /// Close a channel from the server side (e.g., when PTY exits).
    ///
    /// This removes the channel from the handler and sends a ChannelClose
    /// message to the client. The client should then exit gracefully.
    ///
    /// If this was the last channel, triggers a session shutdown signal.
    pub async fn close_channel(&self, channel_id: ChannelId, reason: ChannelCloseReason) {
        debug!(
            channel_id = %channel_id,
            reason = ?reason,
            "close_channel called"
        );

        // Remove from channels map and get remaining count
        let (channel, remaining_count) = {
            let mut channels = self.channels.write().await;
            let ch = channels.remove(&channel_id);
            (ch, channels.len())
        };

        // Clean up the channel if it existed
        if let Some(handle) = channel {
            debug!(channel_id = %channel_id, "Closing channel handle");
            handle.close().await;
        }

        // Send close notification to client (best effort)
        let close_msg = Message::ChannelClose(ChannelClosePayload {
            channel_id,
            reason: reason.clone(),
        });
        debug!(channel_id = %channel_id, "Sending ChannelClose message");
        if let Err(e) = self.send_control(&close_msg).await {
            debug!(
                channel_id = %channel_id,
                error = %e,
                "Failed to send ChannelClose (client may have disconnected)"
            );
        } else {
            info!(
                channel_id = %channel_id,
                reason = %reason,
                "Sent ChannelClose to client"
            );
        }

        // If no channels remain, trigger session shutdown
        if remaining_count == 0 {
            info!("All channels closed, triggering session shutdown");
            // Close the QUIC connection to wake up any pending recv_control() call in the session loop
            self.quic.read().await.close_connection().await;
            let _ = self
                .shutdown_tx
                .lock()
                .await
                .try_send(super::ShutdownReason::AllChannelsClosed);
        }
    }

    /// Close all channels and clean up.
    pub async fn close_all_channels(&self, reason: ChannelCloseReason) {
        let channels: Vec<_> = {
            let mut guard = self.channels.write().await;
            guard.drain().collect()
        };

        for (channel_id, handle) in channels {
            debug!(channel_id = %channel_id, "Closing channel");
            handle.close().await;

            // Best-effort send close notification
            let _ = self
                .send_control(&Message::ChannelClose(ChannelClosePayload {
                    channel_id,
                    reason: reason.clone(),
                }))
                .await;
        }
    }

    /// Get information about existing channels for session resumption.
    ///
    /// Returns channel info that can be sent to the client in HelloAck
    /// to restore channel state after reconnection.
    pub async fn get_existing_channels(&self) -> Vec<qsh_core::protocol::ExistingChannel> {
        use qsh_core::protocol::{ExistingChannel, ExistingChannelType};

        let channels = self.channels.read().await;
        let mut result = Vec::with_capacity(channels.len());

        for (channel_id, handle) in channels.iter() {
            let channel_type = match handle {
                ChannelHandle::Terminal(terminal) => {
                    // Skip closed terminal channels (PTY has exited)
                    if terminal.is_closed() {
                        debug!(
                            channel_id = %channel_id,
                            "Skipping closed terminal channel in get_existing_channels"
                        );
                        continue;
                    }
                    // Get current terminal state
                    let state = {
                        let parser = terminal.parser();
                        let guard = parser.lock().await;
                        guard.state().clone()
                    };
                    ExistingChannelType::Terminal { state }
                }
                ChannelHandle::FileTransfer(_) | ChannelHandle::Forward(_) => {
                    ExistingChannelType::Other
                }
            };

            result.push(ExistingChannel {
                channel_id: *channel_id,
                channel_type,
            });
        }

        result
    }

    /// Get a terminal channel by ID (for legacy code paths).
    pub async fn get_terminal_channel(&self, channel_id: ChannelId) -> Option<TerminalChannel> {
        let channels = self.channels.read().await;
        if let Some(ChannelHandle::Terminal(terminal)) = channels.get(&channel_id) {
            Some(terminal.clone())
        } else {
            None
        }
    }

    /// Get the first terminal channel (for legacy code paths).
    pub async fn get_first_terminal_channel(&self) -> Option<(ChannelId, TerminalChannel)> {
        let channels = self.channels.read().await;
        for (id, handle) in channels.iter() {
            if let ChannelHandle::Terminal(terminal) = handle {
                return Some((*id, terminal.clone()));
            }
        }
        None
    }

    // =========================================================================
    // Channel Type Handlers
    // =========================================================================

    pub(super) async fn open_terminal_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::TerminalParams,
    ) -> Result<()> {
        debug!(channel_id = %channel_id, "Opening terminal channel");

        // Create terminal channel
        let quic = self.quic().await;
        let output_mode = self.config.output_mode;
        match TerminalChannel::new(channel_id, params, quic, Arc::clone(self), output_mode).await {
            Ok((channel, initial_state)) => {
                // Register channel
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::Terminal(channel));
                }

                // Send accept with initial state
                self.send_channel_accept(channel_id, ChannelAcceptData::Terminal { initial_state })
                    .await
            }
            Err(e) => {
                error!(channel_id = %channel_id, error = %e, "Failed to create terminal channel");
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::InternalError,
                    &e.to_string(),
                )
                .await
            }
        }
    }

    pub(super) async fn open_file_transfer_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::FileTransferParams,
    ) -> Result<()> {
        debug!(channel_id = %channel_id, path = %params.path, "Opening file transfer channel");

        let quic = self.quic().await;
        match FileTransferChannel::new(channel_id, params, quic).await {
            Ok((channel, metadata)) => {
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::FileTransfer(channel));
                }

                self.send_channel_accept(channel_id, ChannelAcceptData::FileTransfer { metadata })
                    .await
            }
            Err(e) => {
                let code = match &e {
                    Error::FileTransfer { message } if message.contains("not found") => {
                        ChannelRejectCode::NotFound
                    }
                    Error::FileTransfer { message } if message.contains("permission") => {
                        ChannelRejectCode::PermissionDenied
                    }
                    _ => ChannelRejectCode::InternalError,
                };
                self.send_channel_reject(channel_id, code, &e.to_string())
                    .await
            }
        }
    }

    pub(super) async fn open_direct_tcpip_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::DirectTcpIpParams,
    ) -> Result<()> {
        debug!(
            channel_id = %channel_id,
            target = %format!("{}:{}", params.target_host, params.target_port),
            "Opening direct-tcpip channel"
        );

        let quic = self.quic().await;
        match ForwardChannel::new_direct(channel_id, params, quic).await {
            Ok(channel) => {
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::Forward(channel));
                }

                self.send_channel_accept(channel_id, ChannelAcceptData::DirectTcpIp)
                    .await
            }
            Err(e) => {
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::ConnectFailed,
                    &e.to_string(),
                )
                .await
            }
        }
    }

    pub(super) async fn open_forwarded_tcpip_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::ForwardedTcpIpParams,
        tcp_stream: tokio::net::TcpStream,
    ) -> Result<()> {
        debug!(
            channel_id = %channel_id,
            bound = %format!("{}:{}", params.bound_host, params.bound_port),
            originator = %format!("{}:{}", params.originator_host, params.originator_port),
            "Setting up forwarded-tcpip relay"
        );

        // Client already accepted - just set up the relay
        // Note: We don't send ChannelAccept here - for server-initiated channels,
        // the CLIENT sends ChannelAccept and we've already received it.
        let quic = self.quic().await;
        let channel = ForwardChannel::new_forwarded(channel_id, params, quic, tcp_stream).await?;

        let mut channels = self.channels.write().await;
        channels.insert(channel_id, ChannelHandle::Forward(channel));

        info!(channel_id = %channel_id, "Forwarded channel relay started");
        Ok(())
    }

    pub(super) async fn open_dynamic_forward_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::DynamicForwardParams,
    ) -> Result<()> {
        debug!(
            channel_id = %channel_id,
            target = %format!("{}:{}", params.target_host, params.target_port),
            "Opening dynamic forward channel"
        );

        let quic = self.quic().await;
        match ForwardChannel::new_dynamic(channel_id, params, quic).await {
            Ok(channel) => {
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::Forward(channel));
                }

                self.send_channel_accept(channel_id, ChannelAcceptData::DynamicForward)
                    .await
            }
            Err(e) => {
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::ConnectFailed,
                    &e.to_string(),
                )
                .await
            }
        }
    }

    #[cfg(feature = "tunnel")]
    pub(super) async fn open_tunnel_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        _params: qsh_core::protocol::TunnelParams,
    ) -> Result<()> {
        // Tunnel channels are not yet implemented
        self.send_channel_reject(
            channel_id,
            ChannelRejectCode::UnknownChannelType,
            "tunnel channels not yet implemented",
        )
        .await
    }

    /// Route an incoming stream to the appropriate channel.
    pub async fn handle_incoming_stream(
        &self,
        stream_type: qsh_core::transport::StreamType,
        stream: qsh_core::transport::QuicStream,
    ) -> Result<()> {
        use qsh_core::transport::StreamType;

        let mapped = match stream_type {
            // Some transports/roles invert ChannelOut/ChannelIn; accept Out as input, too.
            StreamType::ChannelOut(id) => Some((StreamType::ChannelIn(id), id)),
            StreamType::ChannelIn(id) | StreamType::ChannelBidi(id) => Some((stream_type, id)),
            _ => None,
        };

        if let Some((effective_type, channel_id)) = mapped {
            match effective_type {
                StreamType::ChannelIn(_id) | StreamType::ChannelBidi(_id) => {
                    // Clone the handle to release the lock before the potentially long-running
                    // handle_incoming_stream call (which loops forever reading input).
                    let handle = {
                        let channels = self.channels.read().await;
                        channels.get(&channel_id).cloned()
                    };
                    if let Some(handle) = handle {
                        info!(channel_id = %channel_id, stream_type = ?effective_type, "Dispatching incoming channel stream");
                        handle.handle_incoming_stream(stream).await
                    } else {
                        warn!(channel_id = %channel_id, "Stream for unknown channel");
                        Err(Error::Protocol {
                            message: format!("unknown channel: {}", channel_id),
                        })
                    }
                }
                _ => unreachable!(),
            }
        } else {
            match stream_type {
                StreamType::ChannelOut(channel_id) => {
                    // Unexpected in normal flows, but harmless
                    warn!(channel_id = %channel_id, "Unexpected ChannelOut stream from client");
                    Ok(())
                }
                StreamType::ChannelIn(channel_id) | StreamType::ChannelBidi(channel_id) => {
                    warn!(channel_id = %channel_id, "Unexpected channel stream without mapping");
                    Ok(())
                }
                StreamType::Control => {
                    // Control stream is handled separately
                    warn!("Unexpected additional control stream");
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_counts() {
        let counts = ChannelCounts {
            terminals: 2,
            file_transfers: 3,
            forwards: 5,
        };
        assert_eq!(counts.total(), 10);
    }
}
