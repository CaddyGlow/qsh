//! CLI validation tests for qsh client.

use qsh_client::cli::{Cli, ConnectModeArg};
use clap::Parser;

#[test]
fn test_bootstrap_with_initiate_mode_auto_infers_respond() {
    // Even if user explicitly sets --connect-mode initiate with --bootstrap,
    // we auto-infer respond mode (bootstrap overrides the flag)
    let cli = Cli::try_parse_from([
        "qsh",
        "--bootstrap",
        "--connect-mode",
        "initiate",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Respond);
}

#[test]
fn test_bootstrap_with_destination_fails() {
    // Clap itself will reject this combination due to conflicts_with = "destination"
    let result = Cli::try_parse_from([
        "qsh",
        "--bootstrap",
        "user@host",
    ]);

    // Should fail at parsing level
    assert!(result.is_err());
}

#[test]
fn test_destination_with_respond_mode_fails() {
    let cli = Cli::try_parse_from([
        "qsh",
        "user@host",
        "--connect-mode",
        "respond",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("incompatible"));
}

#[test]
fn test_no_destination_and_no_bootstrap_fails() {
    // This should fail at clap parsing level due to required_unless_present_any
    let result = Cli::try_parse_from(["qsh"]);
    assert!(result.is_err());
}

#[test]
fn test_bootstrap_infers_respond_mode() {
    let cli = Cli::try_parse_from([
        "qsh",
        "--bootstrap",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    if let Err(ref e) = result {
        eprintln!("Validation error: {}", e);
    }
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Respond);
}

#[test]
fn test_destination_infers_initiate_mode() {
    let cli = Cli::try_parse_from([
        "qsh",
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
        "qsh",
        "--bootstrap",
        "--connect-mode",
        "respond",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Respond);

    // Destination with explicit initiate mode should work
    let cli = Cli::try_parse_from([
        "qsh",
        "user@host",
        "--connect-mode",
        "initiate",
    ])
    .unwrap();

    let result = cli.validate_and_infer_connect_mode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), ConnectModeArg::Initiate);
}
