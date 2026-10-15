use super::*;
use clap::Parser;
use serde_json::{Value, json};

fn args(endpoint: &str, allow_http: bool) -> NodeImageStatusArgs {
    NodeImageStatusArgs {
        endpoint: endpoint.into(),
        runtime_node_id: Uuid::from_u128(1),
        token_file: PathBuf::from("unused-token"),
        ca_file: None,
        allow_loopback_http: allow_http,
    }
}

#[test]
fn reader_is_a_separate_oauth_command_without_owner_arguments() {
    let request = [
        "sandbox-admin",
        "node-image-status",
        "--endpoint",
        "https://api.example.com",
        "--runtime-node-id",
        "00000000-0000-0000-0000-000000000001",
        "--token-file",
        "token",
    ];
    assert!(super::super::Args::try_parse_from(request).is_ok());
    let mut owner_args = request.to_vec();
    owner_args.extend(["--database-url", "postgres://not-used"]);
    assert!(super::super::Args::try_parse_from(owner_args).is_err());
    assert!(super::super::Args::try_parse_from(&request[..request.len() - 2]).is_err());
}

#[test]
fn endpoint_is_https_with_an_explicit_literal_loopback_exception() {
    let result = target(&args("https://api.example.com/platform/", false));
    assert!(
        matches!(result, Ok(url) if url.as_str() == "https://api.example.com/platform/v1/operator/nodes/00000000-0000-0000-0000-000000000001/image-status")
    );
    for endpoint in ["http://127.0.0.1:8080", "http://[::1]:8080"] {
        assert!(target(&args(endpoint, false)).is_err());
        assert!(target(&args(endpoint, true)).is_ok());
    }
    for endpoint in [
        "http://localhost:8080",
        "http://192.0.2.1",
        "ftp://127.0.0.1",
        "https://user:secret@api.example.com",
        "https://@api.example.com",
        "https://api.example.com?query=secret",
        "https://api.example.com#fragment",
        " https://api.example.com",
        "https://api.example.com/\n",
        "https://api.example.com/has space",
    ] {
        assert!(target(&args(endpoint, true)).is_err(), "{endpoint:?}");
    }
    let mut nil = args("https://api.example.com", false);
    nil.runtime_node_id = Uuid::nil();
    assert!(target(&nil).is_err());
}

fn document(now: f64) -> Value {
    json!({
        "installation_id": Uuid::from_u128(2), "cluster_epoch": Uuid::from_u128(3),
        "grant_id": Uuid::from_u128(4), "runtime_node_id": Uuid::from_u128(1),
        "node_uid": Uuid::from_u128(5), "host_boot_id": Uuid::from_u128(6),
        "profile_sha256": "a".repeat(64),
        "metrics": {
            "evaluated_at_seconds": now, "source": "RUNTIME_REPORTED", "completeness": "UNKNOWN",
            "accuracy": "APPROXIMATE_F64", "inventory_observation_success": true,
            "filesystem_observation_success": true, "inventory": null,
            "filesystem": {"collector_replica": "agent-a", "scraped_at_seconds": now - 1.0,
                "observed_at_seconds": now - 2.0, "filesystems": []}
        }
    })
}

fn valid(value: Value, now: f64) -> bool {
    serde_json::from_value::<NodeImageStatus>(value)
        .is_ok_and(|status| validate_status(&status, Uuid::from_u128(1), now).is_ok())
}

#[test]
fn unknown_reports_remain_valid_but_wrong_binding_and_stale_data_do_not() {
    let now = 1_000_000.0;
    // A fresh RPC success flag does not imply that a usable original report
    // exists. An empty visible filesystem list still has UNKNOWN completeness.
    assert!(valid(document(now), now));
    for key in [
        "installation_id",
        "cluster_epoch",
        "grant_id",
        "runtime_node_id",
        "node_uid",
        "host_boot_id",
    ] {
        let mut value = document(now);
        value[key] = json!(Uuid::nil());
        assert!(!valid(value, now), "{key}");
    }
    let mut value = document(now);
    value["runtime_node_id"] = json!(Uuid::from_u128(9));
    assert!(!valid(value, now));
    let mut value = document(now);
    value["profile_sha256"] = json!("A".repeat(64));
    assert!(!valid(value, now));
    let mut value = document(now);
    value["metrics"]["filesystem"]["observed_at_seconds"] = json!(now - 60.0);
    assert!(!valid(value, now));
    let mut value = document(now);
    value["metrics"]["filesystem_observation_success"] = json!(false);
    assert!(!valid(value, now));
    let mut value = document(now);
    value["metrics"]["authority_cached"] = json!(true);
    assert!(!valid(value, now));
}

#[cfg(unix)]
#[tokio::test]
async fn token_inode_requires_private_regular_bounded_files_and_reloads_rotation() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir()?;
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    let projected = directory.path().join("token");
    std::fs::write(&first, "first-token")?;
    std::fs::write(&second, "second-token")?;
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o400))?;
    symlink(&first, &projected)?;
    assert_eq!(
        read_file(&projected, MAX_TOKEN_BYTES, true).await?,
        b"first-token"
    );
    std::fs::remove_file(&projected)?;
    symlink(&second, &projected)?;
    assert_eq!(
        read_file(&projected, MAX_TOKEN_BYTES, true).await?,
        b"second-token"
    );
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o644))?;
    assert!(read_file(&projected, MAX_TOKEN_BYTES, true).await.is_err());
    assert!(
        read_file(directory.path(), MAX_TOKEN_BYTES, true)
            .await
            .is_err()
    );
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&first, vec![b'x'; MAX_TOKEN_BYTES + 1])?;
    assert!(read_file(&first, MAX_TOKEN_BYTES, true).await.is_err());
    let fifo = directory.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    assert!(read_file(&fifo, MAX_TOKEN_BYTES, true).await.is_err());
    Ok(())
}
