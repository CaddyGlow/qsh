//! CLI validation tests for qsh-server.

use qsh_server::cli::{Cli, ConnectModeArg};
use clap::Parser;

#[test]
fn test_bootstrap_with_initiate_mode_fails() {
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--bootstrap",
        "--connect-mode",
        "initiate",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("cannot be used with --connect-mode initiate"));
}

#[test]
fn test_bootstrap_with_target_fails() {
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--bootstrap",
        "--target",
        "user@host",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("cannot be used with --target"));
}

#[test]
fn test_initiate_mode_without_target_fails() {
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--connect-mode",
        "initiate",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("requires --target"));
}

#[test]
fn test_target_with_respond_mode_auto_infers_initiate() {
    // --target with --connect-mode respond should auto-infer initiate mode
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--target",
        "user@host",
        "--connect-mode",
        "respond",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Initiate);
}

#[test]
fn test_bootstrap_infers_respond_mode() {
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--bootstrap",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Respond);
}

#[test]
fn test_default_is_respond_mode() {
    let cli = Cli::try_parse_from([
        "qsh-server",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Respond);
}

#[test]
fn test_target_infers_initiate_mode() {
    // --target without explicit --connect-mode should auto-infer initiate
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--target",
        "user@host",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Initiate);
}

#[test]
fn test_explicit_modes_accepted() {
    // Bootstrap with explicit respond mode should work
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--bootstrap",
        "--connect-mode",
        "respond",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Respond);

    // Initiate with explicit mode and target should work
    let cli = Cli::try_parse_from([
        "qsh-server",
        "--connect-mode",
        "initiate",
        "--target",
        "user@client",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Initiate);
}
