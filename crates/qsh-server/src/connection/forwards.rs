//! Remote forward management.

use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelId, ChannelOpenPayload, ChannelParams, GlobalReplyData, GlobalReplyPayload,
    GlobalReplyResult, GlobalRequest, GlobalRequestPayload, Message,
};

use super::ConnectionHandler;

/// Handle for a remote forward listener on the server.
pub(super) struct RemoteForwardListener {
    /// Task running the TCP listener accept loop.
    pub listener_task: JoinHandle<()>,
    /// Send to signal shutdown.
    pub shutdown_tx: mpsc::Sender<()>,
}

impl ConnectionHandler {
    /// Handle a GlobalRequest message.
    pub async fn handle_global_request(
        self: &Arc<Self>,
        payload: GlobalRequestPayload,
    ) -> Result<()> {
        let request_id = payload.request_id;
        debug!(request_id, request = ?payload.request, "Received GlobalRequest");

        match payload.request {
            GlobalRequest::TcpIpForward {
                bind_host,
                bind_port,
            } => {
                if !self.config.allow_remote_forwards {
                    return self
                        .send_global_reply(
                            request_id,
                            GlobalReplyResult::Failure {
                                message: "remote forwards not allowed".to_string(),
                            },
                        )
                        .await;
                }

                // Check if we already have a listener for this address
                {
                    let listeners = self.remote_forward_listeners.lock().await;
                    if listeners.contains_key(&(bind_host.clone(), bind_port)) {
                        return self
                            .send_global_reply(
                                request_id,
                                GlobalReplyResult::Failure {
                                    message: "forward already exists".to_string(),
                                },
                            )
                            .await;
                    }
                }

                // Bind the TCP listener
                let bind_addr = if bind_host.is_empty() || bind_host == "0.0.0.0" {
                    format!("0.0.0.0:{}", bind_port)
                } else if bind_host == "localhost" {
                    format!("127.0.0.1:{}", bind_port)
                } else {
                    format!("{}:{}", bind_host, bind_port)
                };

                let listener = match TcpListener::bind(&bind_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(bind_addr = %bind_addr, error = %e, "Failed to bind remote forward");
                        return self
                            .send_global_reply(
                                request_id,
                                GlobalReplyResult::Failure {
                                    message: format!("failed to bind: {}", e),
                                },
                            )
                            .await;
                    }
                };

                let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(bind_port);
                info!(
                    bind_host = %bind_host,
                    requested_port = bind_port,
                    actual_port,
                    "Remote forward listener bound"
                );

                // Create shutdown channel and spawn listener task
                let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
                let handler = Arc::clone(self);
                let bind_host_clone = bind_host.clone();

                let listener_task = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.recv() => {
                                debug!(bind_host = %bind_host_clone, port = actual_port, "Remote forward listener shutting down");
                                break;
                            }
                            result = listener.accept() => {
                                match result {
                                    Ok((tcp_stream, peer_addr)) => {
                                        debug!(
                                            peer = %peer_addr,
                                            bind_host = %bind_host_clone,
                                            bind_port = actual_port,
                                            "Accepted connection on remote forward"
                                        );

                                        // Allocate a server-side channel ID
                                        let channel_id = handler.next_channel_id();

                                        let params = qsh_core::protocol::ForwardedTcpIpParams {
                                            bound_host: bind_host_clone.clone(),
                                            bound_port: actual_port,
                                            originator_host: peer_addr.ip().to_string(),
                                            originator_port: peer_addr.port(),
                                        };

                                        // Send ChannelOpen to client and set up the forward
                                        let handler_clone = Arc::clone(&handler);
                                        tokio::spawn(async move {
                                            if let Err(e) = handler_clone
                                                .initiate_forwarded_channel(channel_id, params, tcp_stream)
                                                .await
                                            {
                                                warn!(
                                                    channel_id = %channel_id,
                                                    error = %e,
                                                    "Failed to initiate forwarded channel"
                                                );
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "Error accepting connection on remote forward");
                                    }
                                }
                            }
                        }
                    }
                });

                // Store the listener handle
                {
                    let mut listeners = self.remote_forward_listeners.lock().await;
                    listeners.insert(
                        (bind_host, actual_port),
                        RemoteForwardListener {
                            listener_task,
                            shutdown_tx,
                        },
                    );
                }

                self.send_global_reply(
                    request_id,
                    GlobalReplyResult::Success(GlobalReplyData::TcpIpForward {
                        bound_port: actual_port,
                    }),
                )
                .await
            }
            GlobalRequest::CancelTcpIpForward {
                bind_host,
                bind_port,
            } => {
                let mut listeners = self.remote_forward_listeners.lock().await;
                if let Some(listener) = listeners.remove(&(bind_host.clone(), bind_port)) {
                    // Signal shutdown and abort the task
                    let _ = listener.shutdown_tx.send(()).await;
                    listener.listener_task.abort();
                    info!(bind_host = %bind_host, bind_port, "Remote forward cancelled");
                    self.send_global_reply(
                        request_id,
                        GlobalReplyResult::Success(GlobalReplyData::CancelTcpIpForward),
                    )
                    .await
                } else {
                    self.send_global_reply(
                        request_id,
                        GlobalReplyResult::Failure {
                            message: "no such forward".to_string(),
                        },
                    )
                    .await
                }
            }
        }
    }

    /// Initiate a forwarded-tcpip channel to the client.
    ///
    /// This sends ChannelOpen to the client and waits for accept/reject.
    pub(super) async fn initiate_forwarded_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::ForwardedTcpIpParams,
        tcp_stream: TcpStream,
    ) -> Result<()> {
        // Set up oneshot channel to receive accept/reject notification
        let (tx, rx) = oneshot::channel();
        self.pending_channel_opens
            .lock()
            .await
            .insert(channel_id, tx);

        // Send ChannelOpen to client (uses control_sender, doesn't block recv)
        let open_payload = ChannelOpenPayload {
            channel_id,
            params: ChannelParams::ForwardedTcpIp(params.clone()),
        };
        self.control_sender
            .read()
            .await
            .send(&Message::ChannelOpen(open_payload))
            .await?;
        debug!(channel_id = %channel_id, "Sent ChannelOpen for forwarded-tcpip, waiting for accept");

        // Wait for accept/reject (main loop will dispatch to us)
        match rx.await {
            Ok(Ok(())) => {
                debug!(channel_id = %channel_id, "Received ChannelAccept for forwarded-tcpip");
            }
            Ok(Err(e)) => {
                warn!(channel_id = %channel_id, error = %e, "Client rejected forwarded channel");
                return Err(e);
            }
            Err(_) => {
                warn!(channel_id = %channel_id, "Channel open cancelled");
                return Err(Error::ConnectionClosed);
            }
        }

        // Now set up the channel and start relay
        self.open_forwarded_tcpip_channel(channel_id, params, tcp_stream)
            .await
    }

    /// Send a GlobalReply message.
    pub(super) async fn send_global_reply(
        &self,
        request_id: u32,
        result: GlobalReplyResult,
    ) -> Result<()> {
        let reply = Message::GlobalReply(GlobalReplyPayload { request_id, result });
        self.send_control(&reply).await
    }

    /// Shutdown all remote forward listeners.
    pub(super) async fn shutdown_remote_forward_listeners(&self) {
        let listeners: Vec<_> = {
            let mut guard = self.remote_forward_listeners.lock().await;
            guard.drain().collect()
        };
        for ((host, port), listener) in listeners {
            debug!(bind_host = %host, bind_port = port, "Shutting down remote forward listener");
            let _ = listener.shutdown_tx.send(()).await;
            listener.listener_task.abort();
        }
    }
}
