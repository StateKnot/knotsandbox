//! Validate the actual controller config emitted by the production installer.
use clap::Parser;
use sandbox_platform::{cloud_fencing::AlibabaCloudVolumeDeletion, config::Config};
use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn isolate_production_config(test: &str) -> anyhow::Result<bool> {
    // CLI environment defaults are process-global. Each fixture must start
    // without developer credentials or loopback mode, including parallel runs.
    const CHILD: &str = "SANDBOX_TEST_VOLUME_RENDERER_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        return Ok(false);
    }
    let mut child = Command::new(std::env::current_exe()?);
    child.args(["--exact", test, "--nocapture"]);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SANDBOX_") {
            child.env_remove(name);
        }
    }
    let result = child
        .env(CHILD, test)
        .env("SANDBOX_ALLOW_LOOPBACK_HTTP", "false")
        .output()?;
    anyhow::ensure!(
        result.status.success(),
        "Isolated volume renderer/Config test failed: {} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(true)
}

fn public_manifest() -> anyhow::Result<Value> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let python = std::env::var_os("CLUSTER_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".local/cluster-venv/bin/python"));
    let output = Command::new(python)
        .arg("deploy/volume-deleter/tests/config_fixture.py")
        .current_dir(&root)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "Public volume renderer fixture failed"
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[tokio::test]
async fn generated_volume_controller_matches_real_rust_cli_cloud_identity_and_storage_profile()
-> anyhow::Result<()> {
    if isolate_production_config(
        "generated_volume_controller_matches_real_rust_cli_cloud_identity_and_storage_profile",
    )? {
        return Ok(());
    }
    let manifest = public_manifest()?;
    let items = manifest["items"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Rendered List items missing"))?;
    let configuration = items
        .iter()
        .find_map(|item| item["data"]["config.json"].as_str())
        .ok_or_else(|| anyhow::anyhow!("Rendered controller configuration missing"))?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("controller.json");
    std::fs::write(&path, configuration)?;
    let application = items
        .iter()
        .find(|item| item["kind"] == "Deployment")
        .ok_or_else(|| anyhow::anyhow!("Rendered controller missing"))?;
    let application = &application["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(
        application["command"],
        serde_json::json!(["/usr/local/bin/sandboxd"])
    );
    let mut args: Vec<String> = vec!["sandboxd".into()];
    for arg in application["args"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Rendered CLI arguments missing"))?
    {
        args.push(
            arg.as_str()
                .ok_or_else(|| anyhow::anyhow!("CLI argument type"))?
                .into(),
        );
    }
    let mut database_seen = false;
    let mut pod_uid_seen = false;
    for env in application["env"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Rendered environment missing"))?
    {
        let name = env["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Environment name"))?;
        if name == "SANDBOX_DATABASE_URL" {
            assert_eq!(
                env["valueFrom"]["secretKeyRef"]["name"],
                "volume-db-revision1"
            );
            assert_eq!(env["valueFrom"]["secretKeyRef"]["key"], "url");
            // Public synthetic URL only; this test does not connect to a DB.
            args.extend(["--database-url".into(),
                "postgres://sandbox_volume_deleter:PUBLIC_TEST_ONLY@postgres.example.test/runtime?sslmode=verify-full&sslrootcert=/etc/sandbox-db/ca.crt".into()]);
            database_seen = true;
        } else if name == "SANDBOX_PROCESS_POD_UID" {
            assert!(!pod_uid_seen, "Duplicate Pod UID projection");
            assert_eq!(
                env["valueFrom"],
                serde_json::json!({"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.uid"}})
            );
            assert!(env.get("value").is_none());
            // Executable process telemetry reads this env, not a clap argument.
            pod_uid_seen = true;
        } else if name == "SANDBOX_ALLOW_LOOPBACK_HTTP" {
            assert_eq!(env["value"], "false");
        } else {
            args.push(format!(
                "--{}",
                name.trim_start_matches("SANDBOX_")
                    .to_ascii_lowercase()
                    .replace('_', "-")
            ));
            args.push(if name == "SANDBOX_VOLUME_DELETION_CONFIG_FILE" {
                assert_eq!(env["value"], "/etc/sandbox-volume/config.json");
                path.to_string_lossy().into_owned()
            } else {
                env["value"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Environment value"))?
                    .into()
            });
        }
    }
    anyhow::ensure!(
        database_seen,
        "Independent controller database reference missing"
    );
    anyhow::ensure!(pod_uid_seen, "Downward API Pod UID projection missing");
    let config = Config::try_parse_from(args)?;
    config.validate()?;
    let settings = config.volume_deletion_config()?;
    assert_eq!(settings.storage.deployment, settings.cloud.deployment);
    assert_eq!(settings.storage.zones.len(), 3);
    assert_eq!(settings.storage.storage_class, "sandbox-workspace");
    assert_eq!(
        settings.cloud.oidc_subject,
        "system:serviceaccount:sandbox-system:sandbox-volume-deleter"
    );
    assert_eq!(
        settings.cloud.oidc_token_file,
        PathBuf::from("/var/run/sandbox-cloud/token")
    );
    assert_eq!(
        settings.cloud.oidc_provider_arn,
        "acs:ram::1234567890123456:oidc-provider/sbx-test-kubernetes"
    );
    assert_eq!(settings.concurrency, 2);
    // Real production identity validation/client construction, no request sent.
    AlibabaCloudVolumeDeletion::new(settings.cloud)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn controller_config_reads_opened_projected_targets_but_rejects_fifo_unsafe_mode_and_oversize()
-> anyhow::Result<()> {
    if isolate_production_config(
        "controller_config_reads_opened_projected_targets_but_rejects_fifo_unsafe_mode_and_oversize",
    )? {
        return Ok(());
    }
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        time::Instant,
    };
    let manifest = public_manifest()?;
    let text = manifest["items"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Rendered List missing"))?
        .iter()
        .find_map(|item| item["data"]["config.json"].as_str())
        .ok_or_else(|| anyhow::anyhow!("Rendered configuration missing"))?;
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("config.json");
    let parse = |path: &std::path::Path| -> anyhow::Result<Config> {
        Ok(Config::try_parse_from([
            "sandboxd",
            "--role",
            "volume-deleter",
            "--database-url",
            "postgres://sandbox_volume_deleter:PUBLIC_TEST_ONLY@postgres.example.test/runtime?sslmode=verify-full&sslrootcert=/etc/sandbox-db/ca.crt",
            "--volume-deletion-config-file",
            &path.to_string_lossy(),
        ])?)
    };
    std::fs::write(&config_path, text)?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o440))?;
    parse(&config_path)?.volume_deletion_config()?;
    let projected = directory.path().join("projected.json");
    symlink(&config_path, &projected)?;
    parse(&projected)?.volume_deletion_config()?;
    for mode in [0o664, 0o666, 0o4644] {
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(mode))?;
        let observed = std::fs::metadata(&config_path)?.permissions().mode() & 0o7777;
        // Some host filesystems clear setuid on this non-executable fixture.
        // Assert the actual opened target's permissions, not requested bits.
        if observed & 0o7022 != 0 {
            assert!(
                parse(&config_path)?.volume_deletion_config().is_err(),
                "unsafe mode {observed:o}"
            );
        } else {
            assert_eq!(mode, 0o4644);
            parse(&config_path)?.volume_deletion_config()?;
        }
    }
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&config_path, vec![b'x'; 1_048_577])?;
    assert!(parse(&config_path)?.volume_deletion_config().is_err());
    assert!(parse(directory.path())?.volume_deletion_config().is_err());
    assert!(
        parse(std::path::Path::new("config.json"))?
            .volume_deletion_config()
            .is_err()
    );
    let fifo = directory.path().join("config.fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    let started = Instant::now();
    assert!(parse(&fifo)?.volume_deletion_config().is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    Ok(())
}
