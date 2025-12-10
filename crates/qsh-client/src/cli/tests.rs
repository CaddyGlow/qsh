#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        // Verify the CLI configuration is valid
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_simple_destination() {
        let cli = Cli::try_parse_from(["qsh", "example.com"]).unwrap();
        assert_eq!(cli.destination, Some("example.com".to_string()));
        assert_eq!(cli.parse_destination(), Some((None, "example.com")));
        assert_eq!(cli.host(), Some("example.com"));
        assert!(cli.effective_user().is_none());
    }

    #[test]
    fn parse_user_at_host() {
        let cli = Cli::try_parse_from(["qsh", "user@example.com"]).unwrap();
        assert_eq!(cli.parse_destination(), Some((Some("user"), "example.com")));
        assert_eq!(cli.effective_user(), Some("user"));
        assert_eq!(cli.host(), Some("example.com"));
    }

    #[test]
    fn login_overrides_destination_user() {
        let cli = Cli::try_parse_from(["qsh", "-l", "admin", "user@example.com"]).unwrap();
        assert_eq!(cli.effective_user(), Some("admin"));
    }

    #[test]
    fn parse_port() {
        let cli = Cli::try_parse_from(["qsh", "-p", "2222", "example.com"]).unwrap();
        assert_eq!(cli.port, 2222);
    }

    #[test]
    fn parse_bootstrap_port_range_flag() {
        let cli = Cli::try_parse_from([
            "qsh",
            "--bootstrap-port-range",
            "15000-15100",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.bootstrap_port_range, Some((15000, 15100)));
    }

    #[test]
    fn parse_bootstrap_port_range_invalid() {
        assert!(
            Cli::try_parse_from(["qsh", "--bootstrap-port-range", "150-100", "example.com"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "qsh",
                "--bootstrap-port-range",
                "not-a-range",
                "example.com"
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_bootstrap_server_args() {
        let cli = Cli::try_parse_from([
            "qsh",
            "--bootstrap-server-args",
            "--log-file /tmp/qsh.log -vvv",
            "example.com",
        ])
        .unwrap();
        assert_eq!(
            cli.bootstrap_server_args,
            Some("--log-file /tmp/qsh.log -vvv".to_string())
        );
    }

    #[test]
    fn parse_local_forward() {
        let cli = Cli::try_parse_from(["qsh", "-L", "8080:localhost:80", "example.com"]).unwrap();
        assert_eq!(cli.local_forward, vec!["8080:localhost:80"]);
    }

    #[test]
    fn parse_multiple_forwards() {
        let cli = Cli::try_parse_from([
            "qsh",
            "-L",
            "8080:localhost:80",
            "-L",
            "9090:localhost:90",
            "-R",
            "3000:localhost:3000",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.local_forward.len(), 2);
        assert_eq!(cli.remote_forward.len(), 1);
    }

    #[test]
    fn parse_dynamic_forward() {
        let cli = Cli::try_parse_from(["qsh", "-D", "1080", "example.com"]).unwrap();
        assert_eq!(cli.dynamic_forward, vec!["1080"]);
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn parse_tunnel_auto_ip() {
        let cli = Cli::try_parse_from(["qsh", "--tun", "example.com"]).unwrap();
        assert!(matches!(cli.tunnel, Some(TunnelArg::Auto)));
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn parse_tunnel_with_ip() {
        let cli = Cli::try_parse_from(["qsh", "--tun=10.0.0.2/24", "--route", "0.0.0.0/0", "host"])
            .unwrap();
        assert!(matches!(
            cli.tunnel,
            Some(TunnelArg::Address(ref s)) if s == "10.0.0.2/24"
        ));
        assert_eq!(cli.route, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(cli.tun_mtu, 1280);
    }

    #[test]
    fn parse_verbosity() {
        let cli = Cli::try_parse_from(["qsh", "-vvv", "example.com"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn parse_command() {
        let cli = Cli::try_parse_from(["qsh", "example.com", "ls", "-la"]).unwrap();
        assert_eq!(cli.command, vec!["ls", "-la"]);
        assert_eq!(cli.command_string(), Some("ls -la".to_string()));
    }

    #[test]
    fn command_string_preserves_spaces_with_escaping() {
        let cli = Cli::try_parse_from(["qsh", "example.com", "echo", "hi there"]).unwrap();
        assert_eq!(cli.command_string(), Some("echo 'hi there'".to_string()));
    }

    #[test]
    fn parse_no_pty() {
        let cli = Cli::try_parse_from(["qsh", "-N", "example.com"]).unwrap();
        assert!(cli.no_pty);
    }

    #[test]
    fn parse_force_pty() {
        let cli = Cli::try_parse_from(["qsh", "-t", "example.com"]).unwrap();
        assert!(cli.force_pty);
        assert!(!cli.disable_pty);
    }

    #[test]
    fn parse_disable_pty() {
        let cli = Cli::try_parse_from(["qsh", "-T", "example.com"]).unwrap();
        assert!(cli.disable_pty);
        assert!(!cli.force_pty);
    }

    #[test]
    fn parse_background() {
        let cli = Cli::try_parse_from(["qsh", "-f", "example.com"]).unwrap();
        assert!(cli.background);
    }

    #[test]
    fn parse_identity_files() {
        let cli = Cli::try_parse_from([
            "qsh",
            "-i",
            "~/.ssh/id_rsa",
            "-i",
            "~/.ssh/id_ed25519",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.identity.len(), 2);
    }

    #[test]
    fn parse_log_format() {
        let cli = Cli::try_parse_from(["qsh", "--log-format", "json", "example.com"]).unwrap();
        assert_eq!(cli.log_format, CliLogFormat::Json);
    }

    #[test]
    fn parse_overlay_options() {
        let cli = Cli::try_parse_from([
            "qsh",
            "--overlay-position",
            "top-right",
            "--overlay-key",
            "ctrl+o",
            "--no-overlay",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.overlay_position, OverlayPosition::TopRight);
        assert_eq!(cli.overlay_key, "ctrl+o");
        assert!(cli.no_overlay);
    }

    #[test]
    fn parse_ssh_options() {
        let cli = Cli::try_parse_from([
            "qsh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.ssh_option.len(), 2);
    }

    #[test]
    fn parse_ssh_bootstrap_mode() {
        let cli =
            Cli::try_parse_from(["qsh", "--ssh-bootstrap-mode", "russh", "example.com"]).unwrap();
        assert_eq!(cli.ssh_bootstrap_mode, SshBootstrapMode::Russh);
    }

    #[test]
    fn parse_escape_key() {
        let cli = Cli::try_parse_from(["qsh", "--escape-key", "ctrl+]", "example.com"]).unwrap();
        assert_eq!(cli.escape_key, "ctrl+]");
    }

    #[test]
    fn parse_escape_key_none() {
        let cli = Cli::try_parse_from(["qsh", "--escape-key", "none", "example.com"]).unwrap();
        assert_eq!(cli.escape_key, "none");
    }

    #[test]
    fn parse_notification_style() {
        let cli =
            Cli::try_parse_from(["qsh", "--notification-style", "enhanced", "example.com"]).unwrap();
        assert_eq!(cli.notification_style, NotificationStyle::Enhanced);

        let cli =
            Cli::try_parse_from(["qsh", "--notification-style", "minimal", "example.com"]).unwrap();
        assert_eq!(cli.notification_style, NotificationStyle::Minimal);
    }

    #[test]
    fn default_values() {
        let cli = Cli::try_parse_from(["qsh", "example.com"]).unwrap();
        assert_eq!(cli.port, 22);
        assert_eq!(cli.ssh_bootstrap_mode, SshBootstrapMode::Ssh);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.no_pty);
        assert!(!cli.background);
        assert!(!cli.compress);
        assert!(!cli.no_prediction);
        assert!(!cli.show_status);
        assert_eq!(cli.log_format, CliLogFormat::Text);
        assert_eq!(cli.overlay_position, OverlayPosition::Top);
        assert_eq!(cli.overlay_key, "ctrl+shift+o");
        assert_eq!(cli.escape_key, "ctrl+^");
        assert_eq!(cli.notification_style, NotificationStyle::Minimal);
        assert!(!cli.no_overlay);
        assert!(!cli.force_pty);
        assert!(!cli.disable_pty);
        assert!(cli.ssh_option.is_empty());
        #[cfg(feature = "tunnel")]
        {
            assert!(cli.tunnel.is_none());
            assert!(cli.route.is_empty());
            assert_eq!(cli.tun_mtu, 1280);
        }
        #[cfg(feature = "standalone")]
        {
            assert!(!cli.direct);
            assert!(cli.server.is_none());
            assert!(cli.key.is_none());
            assert!(cli.known_hosts.is_none());
            assert!(!cli.accept_unknown_host);
            assert!(!cli.no_agent);
        }
    }

    // =========================================================================
    // PTY Allocation Tests
    // =========================================================================

    #[test]
    fn pty_allocation_interactive_shell() {
        // Interactive shell: PTY allocated
        let cli = Cli::try_parse_from(["qsh", "example.com"]).unwrap();
        assert!(cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_command_no_pty() {
        // Command without flags: no PTY (SSH semantics)
        let cli = Cli::try_parse_from(["qsh", "example.com", "ls", "-la"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_force_pty_with_command() {
        // -t flag forces PTY even with command
        let cli = Cli::try_parse_from(["qsh", "-t", "example.com", "vim", "file.txt"]).unwrap();
        assert!(cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_disable_pty() {
        // -T flag disables PTY for interactive shell
        let cli = Cli::try_parse_from(["qsh", "-T", "example.com"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_forward_only() {
        // -N flag: no PTY, no shell, forwarding only
        let cli = Cli::try_parse_from(["qsh", "-N", "example.com"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_forward_only_with_forward() {
        // -N with local forward: forwarding only mode
        let cli =
            Cli::try_parse_from(["qsh", "-N", "-L", "8080:localhost:80", "example.com"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(cli.is_forward_only());
    }

    // =========================================================================
    // CpCli Tests
    // =========================================================================

    #[test]
    fn verify_cp_cli() {
        CpCli::command().debug_assert();
    }

    #[test]
    fn cp_parse_local_path() {
        let path = CpCli::parse_path("/home/user/file.txt");
        assert!(matches!(path, FilePath::Local(p) if p.to_str() == Some("/home/user/file.txt")));
    }

    #[test]
    fn cp_parse_remote_path_with_user() {
        let path = CpCli::parse_path("user@host:/path/to/file");
        match path {
            FilePath::Remote { user, host, path } => {
                assert_eq!(user, Some("user".to_string()));
                assert_eq!(host, "host");
                assert_eq!(path, "/path/to/file");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_no_user() {
        let path = CpCli::parse_path("host:/path/to/file");
        match path {
            FilePath::Remote { user, host, path } => {
                assert!(user.is_none());
                assert_eq!(host, "host");
                assert_eq!(path, "/path/to/file");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_relative_with_user() {
        let path = CpCli::parse_path("user@host:relative/path");
        match path {
            FilePath::Remote { user, host, path } => {
                assert_eq!(user, Some("user".to_string()));
                assert_eq!(host, "host");
                assert_eq!(path, "relative/path");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_relative_no_user() {
        let path = CpCli::parse_path("host:relative/path");
        match path {
            FilePath::Remote { user, host, path } => {
                assert!(user.is_none());
                assert_eq!(host, "host");
                assert_eq!(path, "relative/path");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_trailing_colon_with_user() {
        let path = CpCli::parse_path("user@host:");
        match path {
            FilePath::Remote { user, host, path } => {
                assert_eq!(user, Some("user".to_string()));
                assert_eq!(host, "host");
                assert_eq!(path, "");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_trailing_colon_no_user() {
        let path = CpCli::parse_path("host:");
        match path {
            FilePath::Remote { user, host, path } => {
                assert!(user.is_none());
                assert_eq!(host, "host");
                assert_eq!(path, "");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_relative_path() {
        let path = CpCli::parse_path("./relative/path");
        assert!(matches!(path, FilePath::Local(p) if p.to_str() == Some("./relative/path")));
    }

    #[test]
    fn cp_is_upload() {
        let cli =
            CpCli::try_parse_from(["qscp", "/local/file.txt", "user@host:/remote/file.txt"])
                .unwrap();
        assert!(cli.is_upload());
        assert!(!cli.is_download());
    }

    #[test]
    fn cp_is_download() {
        let cli =
            CpCli::try_parse_from(["qscp", "user@host:/remote/file.txt", "/local/file.txt"])
                .unwrap();
        assert!(cli.is_download());
        assert!(!cli.is_upload());
    }

    #[test]
    fn cp_remote_host_upload() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "/local/file.txt",
            "admin@server.example.com:/remote/path",
        ])
        .unwrap();
        let (host, user) = cli.remote_host().unwrap();
        assert_eq!(host, "server.example.com");
        assert_eq!(user, Some("admin".to_string()));
    }

    #[test]
    fn cp_remote_host_download() {
        let cli =
            CpCli::try_parse_from(["qscp", "server.example.com:/remote/path", "/local/path"])
                .unwrap();
        let (host, user) = cli.remote_host().unwrap();
        assert_eq!(host, "server.example.com");
        assert!(user.is_none());
    }

    #[test]
    fn cp_transfer_options_defaults() {
        let cli = CpCli::try_parse_from(["qscp", "/local/file", "host:/remote/file"]).unwrap();
        let opts = cli.transfer_options();
        assert!(opts.compress);
        assert!(opts.delta);
        assert!(!opts.recursive);
        assert!(!opts.preserve_mode);
        assert_eq!(opts.parallel, 4);
    }

    #[test]
    fn cp_transfer_options_custom() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "-r",
            "-p",
            "--no-delta",
            "--no-compress",
            "/local/dir",
            "host:/remote/dir",
        ])
        .unwrap();
        let opts = cli.transfer_options();
        assert!(!opts.compress);
        assert!(!opts.delta);
        assert!(opts.recursive);
        assert!(opts.preserve_mode);
        assert_eq!(opts.parallel, 4);
    }

    #[test]
    fn cp_parallel_flag() {
        let cli = CpCli::try_parse_from(["qscp", "-j", "8", "/local/file", "host:/remote/file"])
            .unwrap();
        assert_eq!(cli.parallel, 8);
    }

    #[test]
    fn cp_port_flag() {
        let cli =
            CpCli::try_parse_from(["qscp", "-P", "2222", "/local/file", "host:/remote/file"])
                .unwrap();
        assert_eq!(cli.port, 2222);
    }

    #[test]
    fn cp_verbose_flag() {
        let cli =
            CpCli::try_parse_from(["qscp", "-vvv", "/local/file", "host:/remote/file"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn cp_identity_files() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "-i",
            "~/.ssh/id_rsa",
            "-i",
            "~/.ssh/id_ed25519",
            "/local/file",
            "host:/remote/file",
        ])
        .unwrap();
        assert_eq!(cli.identity.len(), 2);
    }

    #[test]
    fn cp_resume_flag() {
        let cli = CpCli::try_parse_from(["qscp", "--resume", "/local/file", "host:/remote/file"])
            .unwrap();
        assert!(cli.resume);
    }

    #[test]
    fn cp_defaults() {
        let cli = CpCli::try_parse_from(["qscp", "/local/file", "host:/remote/file"]).unwrap();
        assert_eq!(cli.port, 22);
        assert_eq!(cli.parallel, 4);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.recursive);
        assert!(!cli.no_delta);
        assert!(!cli.no_compress);
        assert!(!cli.resume);
        assert!(!cli.preserve);
        assert!(!cli.skip_if_unchanged);
        assert!(cli.identity.is_empty());
        assert!(cli.log_file.is_none());
        #[cfg(feature = "standalone")]
        {
            assert!(!cli.direct);
            assert!(cli.server.is_none());
            assert!(cli.key.is_none());
            assert!(cli.known_hosts.is_none());
            assert!(!cli.accept_unknown_host);
            assert!(!cli.no_agent);
        }
    }

    #[test]
    fn cp_skip_if_unchanged_flag() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "--skip-if-unchanged",
            "/local/file",
            "host:/remote/file",
        ])
        .unwrap();
        assert!(cli.skip_if_unchanged);

        let cli2 =
            CpCli::try_parse_from(["qscp", "-u", "/local/file", "host:/remote/file"]).unwrap();
        assert!(cli2.skip_if_unchanged);
    }

    #[test]
    fn cp_skip_if_unchanged_in_options() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "--skip-if-unchanged",
            "/local/file",
            "host:/remote/file",
        ])
        .unwrap();
        let opts = cli.transfer_options();
        assert!(opts.skip_if_unchanged);
    }
}
