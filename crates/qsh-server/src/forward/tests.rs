//! Tests for server-side port forwarding.
//!
//! Full integration tests with mock transport are in tests/forwarding_test.rs

#[cfg(test)]
mod forward_spec_handling {
    use qsh_core::protocol::ForwardSpec;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn forward_spec_local_has_full_info() {
        let spec = ForwardSpec::Local {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            target_host: "localhost".into(),
            target_port: 80,
        };
        match spec {
            ForwardSpec::Local {
                bind_addr,
                target_host,
                target_port,
            } => {
                assert_eq!(bind_addr.port(), 8080);
                assert_eq!(target_host, "localhost");
                assert_eq!(target_port, 80);
            }
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn forward_spec_remote_has_full_info() {
        let spec = ForwardSpec::Remote {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000),
            target_host: "backend".into(),
            target_port: 8080,
        };
        match spec {
            ForwardSpec::Remote {
                bind_addr,
                target_host,
                target_port,
            } => {
                assert_eq!(bind_addr.port(), 3000);
                assert_eq!(target_host, "backend");
                assert_eq!(target_port, 8080);
            }
            _ => panic!("expected Remote"),
        }
    }

    #[test]
    fn forward_spec_dynamic() {
        let spec = ForwardSpec::Dynamic {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080),
        };
        match spec {
            ForwardSpec::Dynamic { bind_addr } => {
                assert_eq!(bind_addr.port(), 1080);
            }
            _ => panic!("expected Dynamic"),
        }
    }

    #[test]
    fn forward_spec_helper_methods() {
        let spec = ForwardSpec::parse_local("8080:example.com:80").unwrap();

        assert_eq!(spec.bind_addr().port(), 8080);

        let (host, port) = spec.target().unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }
}
