//! Terminal attachment registry for tracking client<->terminal I/O bindings.
//!
//! When a control client attaches to a terminal, this registry stores the
//! I/O channels and manages the output forwarding task.

use std::collections::HashMap;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::proto::{self, Message, Stream, StreamDirection, StreamKind};

/// Information about an attached terminal session.
pub struct AttachedTerminal {
    /// Resource ID of the terminal.
    pub resource_id: String,
    /// Channel to send input to the terminal.
    pub input_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Handle to the output forwarding task.
    pub output_task: JoinHandle<()>,
}

/// Registry tracking which control clients are attached to which terminals.
///
/// Each client can only be attached to one terminal at a time.
/// Each terminal can only have one attached client (MVP).
pub struct AttachmentRegistry {
    /// Map from client_id to attached terminal info.
    client_attachments: HashMap<usize, AttachedTerminal>,
    /// Map from resource_id to client_id (reverse lookup).
    resource_to_client: HashMap<String, usize>,
}

impl AttachmentRegistry {
    /// Create a new empty attachment registry.
    pub fn new() -> Self {
        Self {
            client_attachments: HashMap::new(),
            resource_to_client: HashMap::new(),
        }
    }

    /// Register an attachment between a client and terminal.
    ///
    /// The output_rx channel will be drained by a spawned task that forwards
    /// output to the control socket.
    pub fn attach(
        &mut self,
        client_id: usize,
        resource_id: String,
        output_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        input_tx: mpsc::UnboundedSender<Vec<u8>>,
        control_tx: mpsc::UnboundedSender<(usize, Message)>,
    ) -> Result<(), AttachError> {
        // Check if client is already attached somewhere
        if self.client_attachments.contains_key(&client_id) {
            return Err(AttachError::ClientAlreadyAttached);
        }

        // Check if resource is already attached by another client
        if self.resource_to_client.contains_key(&resource_id) {
            return Err(AttachError::ResourceAlreadyAttached);
        }

        // Spawn output forwarding task
        let res_id = resource_id.clone();
        let output_task = tokio::spawn(async move {
            forward_output(client_id, res_id, output_rx, control_tx).await;
        });

        // Store the attachment
        self.client_attachments.insert(
            client_id,
            AttachedTerminal {
                resource_id: resource_id.clone(),
                input_tx,
                output_task,
            },
        );
        self.resource_to_client.insert(resource_id.clone(), client_id);

        info!(
            client_id,
            resource_id = %resource_id,
            "Client attached to terminal"
        );

        Ok(())
    }

    /// Detach a client from their terminal.
    ///
    /// Returns the resource_id that was detached, if any.
    pub fn detach_client(&mut self, client_id: usize) -> Option<String> {
        if let Some(attached) = self.client_attachments.remove(&client_id) {
            // Cancel the output forwarding task
            attached.output_task.abort();

            // Remove reverse mapping
            self.resource_to_client.remove(&attached.resource_id);

            info!(
                client_id,
                resource_id = %attached.resource_id,
                "Client detached from terminal"
            );

            Some(attached.resource_id)
        } else {
            None
        }
    }

    /// Detach any client from a specific resource.
    ///
    /// Returns the client_id that was detached, if any.
    pub fn detach_resource(&mut self, resource_id: &str) -> Option<usize> {
        if let Some(client_id) = self.resource_to_client.remove(resource_id) {
            if let Some(attached) = self.client_attachments.remove(&client_id) {
                attached.output_task.abort();

                info!(
                    client_id,
                    resource_id = %resource_id,
                    "Client detached from terminal (resource detach)"
                );
            }
            Some(client_id)
        } else {
            None
        }
    }

    /// Send input data to a terminal that a client is attached to.
    ///
    /// Returns Ok(()) if sent successfully, Err if the client isn't attached
    /// or the channel is closed.
    pub fn send_input(&self, client_id: usize, data: Vec<u8>) -> Result<(), AttachError> {
        let attached = self
            .client_attachments
            .get(&client_id)
            .ok_or(AttachError::NotAttached)?;

        attached
            .input_tx
            .send(data)
            .map_err(|_| AttachError::ChannelClosed)?;

        Ok(())
    }

    /// Check if a client is attached to any terminal.
    pub fn is_client_attached(&self, client_id: usize) -> bool {
        self.client_attachments.contains_key(&client_id)
    }

    /// Check if a resource has an attached client.
    pub fn is_resource_attached(&self, resource_id: &str) -> bool {
        self.resource_to_client.contains_key(resource_id)
    }

    /// Get the resource_id a client is attached to.
    pub fn client_resource(&self, client_id: usize) -> Option<&str> {
        self.client_attachments
            .get(&client_id)
            .map(|a| a.resource_id.as_str())
    }

    /// Get the client_id attached to a resource.
    pub fn resource_client(&self, resource_id: &str) -> Option<usize> {
        self.resource_to_client.get(resource_id).copied()
    }

    /// Get the number of active attachments.
    pub fn attachment_count(&self) -> usize {
        self.client_attachments.len()
    }
}

impl Default for AttachmentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AttachmentRegistry {
    fn drop(&mut self) {
        // Abort all output forwarding tasks
        for (_, attached) in self.client_attachments.drain() {
            attached.output_task.abort();
        }
    }
}

/// Errors that can occur during attachment operations.
#[derive(Debug, Clone)]
pub enum AttachError {
    /// Client is already attached to a terminal.
    ClientAlreadyAttached,
    /// Resource already has an attached client.
    ResourceAlreadyAttached,
    /// Client is not attached to any terminal.
    NotAttached,
    /// The I/O channel is closed.
    ChannelClosed,
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachError::ClientAlreadyAttached => write!(f, "client already attached to a terminal"),
            AttachError::ResourceAlreadyAttached => write!(f, "terminal already has an attached client"),
            AttachError::NotAttached => write!(f, "client not attached to any terminal"),
            AttachError::ChannelClosed => write!(f, "I/O channel closed"),
        }
    }
}

impl std::error::Error for AttachError {}

/// Task that forwards terminal output to a control client.
///
/// Batches small outputs together to reduce serialization overhead.
async fn forward_output(
    client_id: usize,
    resource_id: String,
    mut output_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    control_tx: mpsc::UnboundedSender<(usize, Message)>,
) {
    debug!(
        client_id,
        resource_id = %resource_id,
        "Starting terminal output forwarding"
    );

    // Batch small outputs to reduce overhead
    const MAX_BATCH_SIZE: usize = 32768; // 32KB max batch

    loop {
        // Wait for first output
        let first = match output_rx.recv().await {
            Some(data) => data,
            None => break,
        };

        // Immediately drain all available output (no waiting)
        let mut batch = first;

        while batch.len() < MAX_BATCH_SIZE {
            match output_rx.try_recv() {
                Ok(data) => batch.extend(data),
                Err(_) => break, // No more data available
            }
        }

        // Send batched output
        let message = Message {
            kind: Some(proto::message::Kind::Stream(Stream {
                resource_id: resource_id.clone(),
                stream_kind: StreamKind::TerminalIo as i32,
                direction: StreamDirection::Out as i32,
                data: batch,
            })),
        };

        if control_tx.send((client_id, message)).is_err() {
            warn!(
                client_id,
                resource_id = %resource_id,
                "Control channel closed, stopping output forwarding"
            );
            break;
        }
    }

    debug!(
        client_id,
        resource_id = %resource_id,
        "Terminal output forwarding ended"
    );
}
