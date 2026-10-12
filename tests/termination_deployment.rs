//! Exercise the production CLI/credential reader with the installer's output.
use clap::Parser;
use sandbox_platform::config::{Config, Role};
use serde_json::Value;
use std::{path::PathBuf, process::Command};

#[test]
fn generated_termination_controller_matches_real_cli_and_trust_material() -> anyhow::Result<()> {
    // Exercise the exact false environment value without inheriting an
    // unrelated developer profile or mutating process-global env in parallel.
    const CHILD: &str = "SANDBOX_TEST_TERMINATION_RENDERER_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let mut child = Command::new(std::env::current_exe()?);
        child.args([
            "--exact",
            "generated_termination_controller_matches_real_cli_and_trust_material",
            "--nocapture",
        ]);
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("SANDBOX_") {
                child.env_remove(name);
            }
        }
        let result = child
            .env(CHILD, "1")
            .env("SANDBOX_ALLOW_LOOPBACK_HTTP", "false")
            .output()?;
        anyhow::ensure!(
            result.status.success(),
            "Isolated renderer/Config test failed: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return Ok(());
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let python = std::env::var_os("CLUSTER_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".local/cluster-venv/bin/python"));
    let output = Command::new(python)
        .arg("deploy/termination/tests/config_fixture.py")
        .current_dir(&root)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "Public termination renderer fixture failed"
    );
    let manifest: Value = serde_json::from_slice(&output.stdout)?;
    let items = manifest["items"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Rendered List missing"))?;
    let trust = items
        .iter()
        .find(|item| item["kind"] == "ConfigMap")
        .ok_or_else(|| anyhow::anyhow!("Rendered trust bundle missing"))?;
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("nodeguard-server-ca.pem");
    std::fs::write(
        &ca,
        trust["data"]["nodeguard-server-ca.pem"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Rendered nodeguard CA missing"))?,
    )?;
    let db_ca = directory.path().join("db-ca.pem");
    std::fs::write(
        &db_ca,
        trust["data"]["db-ca.pem"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Rendered database CA missing"))?,
    )?;
    let identity = directory.path().join("client.pem");
    // Committed public test identity only. No DB, cloud or host call is made.
    std::fs::write(
        &identity,
        concat!(
            include_str!("fixtures/nodeguard/client.pem"),
            include_str!("fixtures/nodeguard/client.key")
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o400))?;
    }
    let deployment = items
        .iter()
        .find(|item| item["kind"] == "Deployment")
        .ok_or_else(|| anyhow::anyhow!("Rendered Deployment missing"))?;
    let pod = &deployment["spec"]["template"]["spec"];
    assert_eq!(pod["securityContext"]["runAsUser"], 10001);
    assert_eq!(pod["securityContext"]["runAsGroup"], 10001);
    let application = &pod["containers"][0];
    assert_eq!(
        application["command"],
        serde_json::json!(["/usr/local/bin/sandboxd"])
    );
    let mut args = vec!["sandboxd".to_string()];
    for arg in application["args"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("CLI arguments missing"))?
    {
        args.push(
            arg.as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid CLI argument"))?
                .to_owned(),
        );
    }
    let mut database_seen = false;
    let mut pod_uid_seen = false;
    for env in application["env"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("CLI environment missing"))?
    {
        let name = env["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Environment name missing"))?;
        if name == "SANDBOX_DATABASE_URL" {
            assert_eq!(
                env["valueFrom"]["secretKeyRef"],
                serde_json::json!({"name":"termination-db-revision1","key":"url"})
            );
            args.extend(["--database-url".to_owned(), format!(
                "postgres://sandbox_termination:PUBLIC_TEST_ONLY@postgres.example.test/runtime?sslmode=verify-full&sslrootcert={}", db_ca.display())]);
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
            args.push(match name {
                "SANDBOX_NODEGUARD_SERVER_CA_FILE" => {
                    assert_eq!(
                        env["value"],
                        "/etc/sandbox-termination-trust/nodeguard-server-ca.pem"
                    );
                    ca.to_string_lossy().into_owned()
                }
                "SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE" => {
                    assert_eq!(env["value"], "/etc/sandbox-termination-identity/client.pem");
                    identity.to_string_lossy().into_owned()
                }
                _ => env["value"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Environment value missing"))?
                    .to_owned(),
            });
        }
    }
    anyhow::ensure!(
        database_seen,
        "Independent database Secret reference missing"
    );
    anyhow::ensure!(pod_uid_seen, "Downward API Pod UID projection missing");
    let config = Config::try_parse_from(args)?;
    config.validate()?;
    assert!(matches!(config.role, Role::Termination));
    assert_eq!(config.termination_concurrency, 2);
    assert_eq!(config.db_max_connections, 10);
    assert_eq!(
        config.deployment_certification_id.as_deref(),
        Some("PUBLIC_TEST_ONLY_NOT_CERTIFIED")
    );
    assert_eq!(config.dns_namespace, "kube-system");
    assert_eq!(config.dns_label, "k8s-app=kube-dns");
    assert!(!config.allow_loopback_http);
    config.nodeguard_credentials()?;
    Ok(())
}
