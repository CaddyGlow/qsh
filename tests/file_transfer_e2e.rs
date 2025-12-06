use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use qsh_client::FileTransfer;
use qsh_core::error::{Error, Result};
use qsh_core::protocol::TransferOptions;
use qsh_core::transport::{Connection, StreamPair, StreamType};
use qsh_server::FileHandler;
use qsh_test_utils::MockStream;

// Simple in-process connection pair for end-to-end file transfer tests.
struct TestConnection {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    incoming_rx: Arc<Mutex<mpsc::Receiver<(StreamType, MockStream)>>>,
    peer_incoming_tx: mpsc::Sender<(StreamType, MockStream)>,
    rtt: Duration,
    connected: AtomicBool,
}

impl TestConnection {
    fn pair() -> (Self, Self) {
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);

        let client_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let server_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4500);

        let client = TestConnection {
            local_addr: client_addr,
            remote_addr: server_addr,
            incoming_rx: Arc::new(Mutex::new(rx1)),
            peer_incoming_tx: tx2.clone(),
            rtt: Duration::from_millis(10),
            connected: AtomicBool::new(true),
        };

        let server = TestConnection {
            local_addr: server_addr,
            remote_addr: client_addr,
            incoming_rx: Arc::new(Mutex::new(rx2)),
            peer_incoming_tx: tx1.clone(),
            rtt: Duration::from_millis(10),
            connected: AtomicBool::new(true),
        };

        (client, server)
    }

    fn open_stream_half(&self) -> (MockStream, MockStream) {
        let (tx1, rx1) = mpsc::channel(64);
        let (tx2, rx2) = mpsc::channel(64);

        let our_half = MockStream::new(tx1, rx2);
        let peer_half = MockStream::new(tx2, rx1);
        (our_half, peer_half)
    }
}

impl Connection for TestConnection {
    type Stream = MockStream;

    fn open_stream(
        &self,
        stream_type: StreamType,
    ) -> impl std::future::Future<Output = Result<Self::Stream>> + Send {
        let sender = self.peer_incoming_tx.clone();
        let (our_half, peer_half) = self.open_stream_half();
        async move {
            sender
                .send((stream_type, peer_half))
                .await
                .map_err(|_| Error::ConnectionClosed)?;
            Ok(our_half)
        }
    }

    fn accept_stream(
        &self,
    ) -> impl std::future::Future<Output = Result<(StreamType, Self::Stream)>> + Send {
        let rx = Arc::clone(&self.incoming_rx);
        async move {
            let mut guard = rx.lock().await;
            guard.recv().await.ok_or(Error::ConnectionClosed)
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn rtt(&self) -> Duration {
        self.rtt
    }
}

async fn spawn_file_server(
    server_conn: Arc<TestConnection>,
    base_dir: PathBuf,
) {
    let handler = Arc::new(FileHandler::new(
        Arc::clone(&server_conn),
        base_dir,
    ));

    loop {
        let res = server_conn.accept_stream().await;
        let (stream_type, stream) = match res {
            Ok(pair) => pair,
            Err(_) => break,
        };

        if let StreamType::FileTransfer(_) = stream_type {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                handler.handle_stream(stream_type, stream).await;
            });
        }
    }
}

#[tokio::test]
async fn upload_single_file_e2e() {
    let temp = tempfile::tempdir().unwrap();
    let local_root = temp.path().join("local");
    let remote_root = temp.path().join("remote");
    std::fs::create_dir_all(&local_root).unwrap();
    std::fs::create_dir_all(&remote_root).unwrap();

    let local_file = local_root.join("test_upload.txt");
    std::fs::write(&local_file, b"hello upload").unwrap();

    let (client_raw, server_raw) = TestConnection::pair();
    let client_conn = Arc::new(client_raw);
    let server_conn = Arc::new(server_raw);

    let server_task = {
        let server_conn = Arc::clone(&server_conn);
        let base = remote_root.clone();
        tokio::spawn(async move {
            spawn_file_server(server_conn, base).await;
        })
    };

    let transfer = FileTransfer::new(client_conn);
    let opts = TransferOptions::default();
    let result = transfer
        .upload(&local_file, "test_upload.txt", opts)
        .await
        .unwrap();

    let local_len = std::fs::metadata(&local_file).unwrap().len();
    assert_eq!(result.bytes, local_len);

    let remote_file = remote_root.join("test_upload.txt");
    let contents = std::fs::read(remote_file).unwrap();
    assert_eq!(contents, b"hello upload");

    server_task.abort();
}

#[tokio::test]
async fn download_single_file_e2e() {
    let temp = tempfile::tempdir().unwrap();
    let local_root = temp.path().join("local");
    let remote_root = temp.path().join("remote");
    std::fs::create_dir_all(&local_root).unwrap();
    std::fs::create_dir_all(&remote_root).unwrap();

    let remote_file = remote_root.join("test_download.txt");
    std::fs::write(&remote_file, b"hello download").unwrap();

    let (client_raw, server_raw) = TestConnection::pair();
    let client_conn = Arc::new(client_raw);
    let server_conn = Arc::new(server_raw);

    let server_task = {
        let server_conn = Arc::clone(&server_conn);
        let base = remote_root.clone();
        tokio::spawn(async move {
            spawn_file_server(server_conn, base).await;
        })
    };

    let transfer = FileTransfer::new(client_conn);
    let opts = TransferOptions::default();
    let local_file = local_root.join("out.txt");
    let result = transfer
        .download("test_download.txt", &local_file, opts)
        .await
        .unwrap();

    let local_len = std::fs::metadata(&local_file).unwrap().len();
    assert_eq!(result.bytes, local_len);
    let contents = std::fs::read(&local_file).unwrap();
    assert_eq!(contents, b"hello download");

    server_task.abort();
}

#[tokio::test]
async fn recursive_directory_copy_e2e() {
    let temp = tempfile::tempdir().unwrap();
    let local_src = temp.path().join("src");
    let local_dst = temp.path().join("dst");
    let remote_root = temp.path().join("remote");
    std::fs::create_dir_all(&local_src).unwrap();
    std::fs::create_dir_all(&remote_root).unwrap();

    // Build a small directory tree.
    std::fs::create_dir_all(local_src.join("subdir")).unwrap();
    std::fs::write(local_src.join("file1.txt"), b"one").unwrap();
    std::fs::write(local_src.join("subdir/file2.txt"), b"two").unwrap();

    let (client_raw, server_raw) = TestConnection::pair();
    let client_conn = Arc::new(client_raw);
    let server_conn = Arc::new(server_raw);

    let server_task = {
        let server_conn = Arc::clone(&server_conn);
        let base = remote_root.clone();
        tokio::spawn(async move {
            spawn_file_server(server_conn, base).await;
        })
    };

    let transfer = FileTransfer::new(Arc::clone(&client_conn));
    let mut opts = TransferOptions::default();
    opts.recursive = true;

    // Upload directory tree.
    transfer
        .upload(local_src.as_path(), "dir", opts.clone())
        .await
        .unwrap();

    // Download it back into a different local destination.
    std::fs::create_dir_all(&local_dst).unwrap();
    transfer
        .download("dir", &local_dst, opts)
        .await
        .unwrap();

    let roundtrip_file1 = std::fs::read(local_dst.join("file1.txt")).unwrap();
    let roundtrip_file2 =
        std::fs::read(local_dst.join("subdir/file2.txt")).unwrap();
    assert_eq!(roundtrip_file1, b"one");
    assert_eq!(roundtrip_file2, b"two");

    server_task.abort();
}

#[tokio::test]
async fn upload_delta_on_existing_remote_e2e() {
    let temp = tempfile::tempdir().unwrap();
    let local_root = temp.path().join("local");
    let remote_root = temp.path().join("remote");
    std::fs::create_dir_all(&local_root).unwrap();
    std::fs::create_dir_all(&remote_root).unwrap();

    let local_file = local_root.join("delta_upload.txt");
    std::fs::write(&local_file, b"delta upload contents").unwrap();

    let (client_raw, server_raw) = TestConnection::pair();
    let client_conn = Arc::new(client_raw);
    let server_conn = Arc::new(server_raw);

    let server_task = {
        let server_conn = Arc::clone(&server_conn);
        let base = remote_root.clone();
        tokio::spawn(async move {
            spawn_file_server(server_conn, base).await;
        })
    };

    let transfer = FileTransfer::new(Arc::clone(&client_conn));
    let mut opts = TransferOptions::default();
    opts.delta = true;

    // Initial upload should not use delta (no existing remote file).
    let result1 = transfer
        .upload(&local_file, "delta_upload.txt", opts.clone())
        .await
        .unwrap();
    assert!(!result1.delta_used);

    // Second upload to the same path should use delta blocks
    // from the existing remote file.
    let result2 = transfer
        .upload(&local_file, "delta_upload.txt", opts.clone())
        .await
        .unwrap();
    assert!(result2.delta_used);

    // Remote content still matches the local file.
    let remote_file = remote_root.join("delta_upload.txt");
    let contents = std::fs::read(remote_file).unwrap();
    assert_eq!(contents, b"delta upload contents");

    server_task.abort();
}

#[tokio::test]
async fn remote_is_directory_detection_e2e() {
    let temp = tempfile::tempdir().unwrap();
    let local_root = temp.path().join("local");
    let remote_root = temp.path().join("remote");
    std::fs::create_dir_all(&local_root).unwrap();
    std::fs::create_dir_all(&remote_root).unwrap();

    // Remote structure:
    //   remote/
    //     folder/
    //       inside.txt
    //     file.txt
    std::fs::create_dir_all(remote_root.join("folder")).unwrap();
    std::fs::write(remote_root.join("folder/inside.txt"), b"dir").unwrap();
    std::fs::write(remote_root.join("file.txt"), b"file").unwrap();

    let (client_raw, server_raw) = TestConnection::pair();
    let client_conn = Arc::new(client_raw);
    let server_conn = Arc::new(server_raw);

    let server_task = {
        let server_conn = Arc::clone(&server_conn);
        let base = remote_root.clone();
        tokio::spawn(async move {
            spawn_file_server(server_conn, base).await;
        })
    };

    let transfer = FileTransfer::new(Arc::clone(&client_conn));

    // Existing directory is detected as such (with or without trailing slash).
    assert!(transfer.remote_is_directory("folder").await.unwrap());
    assert!(transfer.remote_is_directory("folder/").await.unwrap());

    // Regular file is not reported as a directory.
    assert!(!transfer.remote_is_directory("file.txt").await.unwrap());

    // Non-existent path is treated as "not a directory".
    assert!(!transfer.remote_is_directory("missing").await.unwrap());

    server_task.abort();
}
