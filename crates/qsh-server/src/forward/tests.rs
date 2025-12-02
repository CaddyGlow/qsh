//! Tests for server-side port forwarding.
//!
//! Full integration tests with mock transport are in tests/forwarding_test.rs

#[cfg(test)]
mod forward_spec_handling {
    use qsh_core::protocol::ForwardSpec;

    #[test]
    fn forward_spec_local_has_bind_port() {
        let spec = ForwardSpec::Local { bind_port: 8080 };
        match spec {
            ForwardSpec::Local { bind_port } => assert_eq!(bind_port, 8080),
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn forward_spec_remote_has_bind_port() {
        let spec = ForwardSpec::Remote { bind_port: 3000 };
        match spec {
            ForwardSpec::Remote { bind_port } => assert_eq!(bind_port, 3000),
            _ => panic!("expected Remote"),
        }
    }

    #[test]
    fn forward_spec_dynamic() {
        let spec = ForwardSpec::Dynamic;
        assert!(matches!(spec, ForwardSpec::Dynamic));
    }
}
