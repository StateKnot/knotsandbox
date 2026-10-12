//! Cross-language deployment contract, using public fixture inputs only.
#![allow(clippy::unwrap_used)]
use clap::Parser;
use sandbox_platform::{auth::JwtAuthenticator, config::Config, history::CursorSigner};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

fn rewrite(value: &mut Value, root: &Path) {
    match value {
        Value::String(text) if text.starts_with("/run/") => {
            *text = root
                .join(text.trim_start_matches('/'))
                .to_string_lossy()
                .into_owned();
        }
        Value::Array(values) => values.iter_mut().for_each(|value| rewrite(value, root)),
        Value::Object(values) => values.values_mut().for_each(|value| rewrite(value, root)),
        _ => {}
    }
}
#[test]
fn generated_full_manifest_matches_actual_rust_api_config_bff_files_metrics_and_output()
-> anyhow::Result<()> {
    // Production CLI defaults must not inherit a developer's loopback mode or
    // credentials. Use an isolated process instead of mutating shared env.
    const CHILD: &str = "SANDBOX_TEST_API_RENDERER_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let mut child = std::process::Command::new(std::env::current_exe()?);
        child.args([
            "--exact",
            "generated_full_manifest_matches_actual_rust_api_config_bff_files_metrics_and_output",
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
            "Isolated API renderer/Config test failed: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return Ok(());
    }
    let python = std::env::var_os("CLUSTER_PYTHON").unwrap_or_else(|| "python3".into());
    let output = std::process::Command::new(python)
        .arg("deploy/api/tests/config_fixture.py")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "Public API renderer fixture failed"
    );
    let manifest: Value = serde_json::from_slice(&output.stdout)?;
    let items = manifest["items"].as_array().unwrap();
    let dir = tempfile::tempdir()?;
    for item in items.iter().filter(|item| item["kind"] == "ConfigMap") {
        let Some(data) = item["data"].as_object() else {
            continue;
        };
        let trust = data.contains_key("api-ca.pem");
        let path = dir.path().join(if trust {
            "run/api-trust"
        } else if data.contains_key("browser.json") {
            "run/api-config"
        } else {
            "run/storage-config"
        });
        std::fs::create_dir_all(&path)?;
        for (name, value) in data {
            let mut text = value.as_str().unwrap().to_string();
            if name.ends_with(".json") {
                let mut json: Value = serde_json::from_str(&text)?;
                rewrite(&mut json, dir.path());
                text = json.to_string();
            }
            std::fs::write(path.join(name), text)?;
        }
    }
    let private = dir.path().join("run/api-private/private");
    std::fs::create_dir_all(&private)?;
    for (name, bytes) in [
        (
            "cursor.json",
            include_str!("fixtures/history/cursor-keys.json"),
        ),
        (
            "browser-client-secret",
            "PUBLIC_TEST_ONLY_CLIENT_SECRET_01234567890123456789",
        ),
        (
            "browser-session-keys.json",
            r#"{"active":"test","keys":[{"id":"test","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#,
        ),
        ("metrics-token", "PUBLIC_TEST_ONLY_METRICS_CREDENTIAL"),
    ] {
        let path = private.join(name);
        std::fs::write(&path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    let deployment = items
        .iter()
        .find(|item| item["kind"] == "Deployment")
        .unwrap();
    let application = &deployment["spec"]["template"]["spec"]["containers"][0];
    let mut values = BTreeMap::new();
    for env in application["env"].as_array().unwrap() {
        if let Some(text) = env["value"].as_str() {
            values.insert(env["name"].as_str().unwrap().to_owned(), text.to_owned());
        }
    }
    values.insert("SANDBOX_DATABASE_URL".into(),format!("postgres://sandbox_runtime:PUBLIC_TEST_ONLY@database.example.test/runtime?sslmode=verify-full&sslrootcert={}",dir.path().join("run/api-trust/db-ca.pem").display()));
    let mut args = vec!["sandboxd".into(), "--role".into(), "api".into()];
    for (name, text) in values {
        let mut value = Value::String(text);
        rewrite(&mut value, dir.path());
        args.push(format!(
            "--{}",
            name.trim_start_matches("SANDBOX_")
                .to_ascii_lowercase()
                .replace('_', "-")
        ));
        // Clap bool is a flag; leave the production default false explicitly.
        if name == "SANDBOX_ALLOW_LOOPBACK_HTTP" {
            args.pop();
            assert_eq!(value.as_str(), Some("false"));
            continue;
        }
        args.push(value.as_str().unwrap().into());
    }
    let config = Config::try_parse_from(args)?;
    config.validate()?;
    let tls = config.api_tls_files()?.unwrap();
    assert_eq!(
        tls.server_name,
        "sandbox-api.sandbox-system.svc.cluster.local"
    );
    CursorSigner::from_json(&config.cursor_signing_key_json()?)?;
    assert!(config.browser_config()?.is_some());
    assert!(config.file_storage_config()?.is_some());
    assert!(config.output_reader_config()?.is_some());
    assert!(config.metrics_config()?.is_some());
    JwtAuthenticator::new(config.auth_config()?)?;
    Ok(())
}
