//! File transfer CLI types and methods.

use std::path::PathBuf;

use super::types::CpCli;

/// Parsed file path (local or remote).
#[derive(Debug, Clone)]
pub enum FilePath {
    /// Local file path.
    Local(PathBuf),
    /// Remote file path: (user, host, path).
    Remote {
        user: Option<String>,
        host: String,
        path: String,
    },
}

impl FilePath {
    /// Parse a string into a FilePath.
    ///
    /// Remote paths use the format: `[user@]host:path`
    /// Local paths are anything else.
    pub fn parse(s: &str) -> FilePath {
        // Check for remote path: [user@]host:path
        // Be careful: Windows paths like C:\foo are not remote
        if let Some(colon_pos) = s.find(':') {
            let before_colon = &s[..colon_pos];

            // Check if this looks like a remote spec (contains @ or no path separator before :)
            let is_remote = before_colon.contains('@')
                || (!before_colon.contains('/') && !before_colon.contains('\\'));

            if is_remote {
                let host_part = before_colon;
                let path = if colon_pos + 1 < s.len() {
                    s[colon_pos + 1..].to_string()
                } else {
                    String::new()
                };

                if let Some(at_pos) = host_part.find('@') {
                    let user = host_part[..at_pos].to_string();
                    let host = host_part[at_pos + 1..].to_string();
                    return FilePath::Remote {
                        user: Some(user),
                        host,
                        path,
                    };
                } else {
                    return FilePath::Remote {
                        user: None,
                        host: host_part.to_string(),
                        path,
                    };
                }
            }
        }

        FilePath::Local(PathBuf::from(s))
    }
}

impl CpCli {
    /// Parse a source/dest string into a FilePath.
    pub fn parse_path(s: &str) -> FilePath {
        FilePath::parse(s)
    }

    /// Get parsed source path.
    pub fn source_path(&self) -> FilePath {
        Self::parse_path(&self.source)
    }

    /// Get parsed destination path.
    pub fn dest_path(&self) -> FilePath {
        Self::parse_path(&self.dest)
    }

    /// Check if this is an upload (local -> remote).
    pub fn is_upload(&self) -> bool {
        matches!(self.source_path(), FilePath::Local(_))
            && matches!(self.dest_path(), FilePath::Remote { .. })
    }

    /// Check if this is a download (remote -> local).
    pub fn is_download(&self) -> bool {
        matches!(self.source_path(), FilePath::Remote { .. })
            && matches!(self.dest_path(), FilePath::Local(_))
    }

    /// Get the remote host for this transfer (host, user).
    pub fn remote_host(&self) -> Option<(String, Option<String>)> {
        match self.source_path() {
            FilePath::Remote { host, user, .. } => Some((host, user)),
            FilePath::Local(_) => match self.dest_path() {
                FilePath::Remote { host, user, .. } => Some((host, user)),
                FilePath::Local(_) => None,
            },
        }
    }

    /// Build TransferOptions from CLI args.
    pub fn transfer_options(&self) -> qsh_core::protocol::TransferOptions {
        use qsh_core::protocol::DeltaAlgo;

        // Map deprecated delta flag to delta_algo
        let delta_algo = if self.no_delta {
            DeltaAlgo::None
        } else {
            // Default to RollingStreaming for best performance
            DeltaAlgo::RollingStreaming
        };

        qsh_core::protocol::TransferOptions {
            compress: !self.no_compress,
            delta: !self.no_delta,
            delta_algo,
            recursive: self.recursive,
            preserve_mode: self.preserve,
            parallel: self.parallel.max(1),
            skip_if_unchanged: self.skip_if_unchanged,
        }
    }
}
