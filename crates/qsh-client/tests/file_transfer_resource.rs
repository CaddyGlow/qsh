//! Tests for the FileTransfer resource.

use std::path::PathBuf;

use qsh_client::control::resources::FileTransfer;
use qsh_core::protocol::{TransferDirection, TransferOptions};

#[test]
fn test_file_transfer_creation() {
    let transfer = FileTransfer::new(
        "xfer-0".to_string(),
        PathBuf::from("/tmp/test.txt"),
        "/remote/test.txt".to_string(),
        TransferDirection::Upload,
        TransferOptions::default(),
        None,
    );

    assert_eq!(transfer.id(), "xfer-0");
    assert_eq!(transfer.kind(), qsh_client::control::resource::ResourceKind::FileTransfer);

    let info = transfer.describe();
    assert_eq!(info.id, "xfer-0");
    assert!(matches!(
        info.state,
        qsh_client::control::resource::ResourceState::Pending
    ));
}
