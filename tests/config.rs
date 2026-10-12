#![allow(clippy::unwrap_used)]

use clap::Parser;
use sandbox_platform::config::Config;
use std::{io::Write, path::Path};

fn config(path: &Path) -> Config {
    Config::try_parse_from([
        "sandboxd",
        "--database-url",
        "postgres://unused@database.example.test/unused?sslmode=verify-full&sslrootcert=/unused/ca.pem",
        "--cursor-signing-key-file",
        path.to_str().unwrap(),
    ])
    .unwrap()
}

#[test]
fn api_transport_requires_complete_tls_or_explicit_literal_loopback_development() {
    let mut c = config(Path::new("/unused/key-ring"));
    assert!(c.validate().is_err());
    c.allow_loopback_http = true;
    c.validate().unwrap();
    assert!(c.api_tls_files().unwrap().is_none());
    for listen in ["0.0.0.0:8443", "[::]:8443", "10.1.2.3:8443"] {
        c.listen = listen.parse().unwrap();
        assert!(c.validate().is_err());
    }
    c.allow_loopback_http = false;
    c.listen = "0.0.0.0:8443".parse().unwrap();
    c.api_tls_cert_file = Some("/run/api-tls/tls.crt".into());
    assert!(c.validate().is_err());
    c.api_tls_key_file = Some("/run/api-tls/tls.key".into());
    c.api_tls_ca_file = Some("/run/api-tls/ca.crt".into());
    assert!(c.validate().is_err());
    c.api_tls_server_name = Some("api.sandbox-system.svc.cluster.local".into());
    c.validate().unwrap();
    assert_eq!(
        c.api_tls_files().unwrap().unwrap().server_name,
        "api.sandbox-system.svc.cluster.local"
    );
    c.api_tls_key_file = Some("relative-key".into());
    assert!(c.validate().is_err());
    c.role = sandbox_platform::config::Role::Worker;
    c.validate().unwrap();
}

#[test]
fn api_process_rejects_missing_tls_or_bad_san_before_connecting_any_database() {
    let run = |extra: &[&str]| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_sandboxd"));
        command.args([
            "--role",
            "api",
            "--listen",
            "0.0.0.0:8443",
            "--database-url",
            "postgres://unused@127.0.0.1:1/unused?sslmode=verify-full&sslrootcert=/unused/ca.pem",
        ]);
        for name in [
            "SANDBOX_API_TLS_CERT_FILE",
            "SANDBOX_API_TLS_KEY_FILE",
            "SANDBOX_API_TLS_CA_FILE",
            "SANDBOX_API_TLS_SERVER_NAME",
            "SANDBOX_ALLOW_LOOPBACK_HTTP",
        ] {
            command.env_remove(name);
        }
        command.args(extra).output().unwrap()
    };
    let missing = run(&[]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("API TLS is required"));
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("tls.crt");
    let key = dir.path().join("tls.key");
    let ca = dir.path().join("ca.crt");
    std::fs::write(&cert, include_bytes!("fixtures/admission/server.pem")).unwrap();
    std::fs::write(&key, include_bytes!("fixtures/admission/server.key")).unwrap();
    std::fs::write(&ca, include_bytes!("fixtures/admission/server-ca.pem")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let rejected = run(&[
        "--api-tls-cert-file",
        cert.to_str().unwrap(),
        "--api-tls-key-file",
        key.to_str().unwrap(),
        "--api-tls-ca-file",
        ca.to_str().unwrap(),
        "--api-tls-server-name",
        "wrong.fixture.invalid",
    ]);
    assert!(!rejected.status.success());
    let error = String::from_utf8_lossy(&rejected.stderr);
    assert!(error.contains("API TLS certificate chain, SAN or validity check failed"));
    assert!(!error.contains("BEGIN PRIVATE KEY") && !error.contains("BEGIN RSA PRIVATE KEY"));
}

#[test]
fn output_reader_never_falls_back_to_gateway_write_credentials() {
    let mut config = config(Path::new("/unused/key-ring"));
    config.output_sts_file = Some("/unused/writer".into());
    config.output_oss_endpoint = Some("https://oss-cn-hangzhou.aliyuncs.com".into());
    config.output_oss_bucket = Some("sandbox-outputs".into());
    config.output_oss_kms_key_id = Some("output-key".into());
    assert!(config.output_reader_config().unwrap().is_none());
    config.output_read_sts_file = Some("/unused/reader".into());
    let reader = config.output_reader_config().unwrap().unwrap();
    assert_eq!(reader.sts_credentials_file, Path::new("/unused/reader"));
    config.output_oss_bucket = None;
    assert!(config.output_reader_config().is_err());
}

#[test]
fn file_storage_requires_distinct_scoped_credentials_and_bounded_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("files.json");
    let mut config = config(Path::new("/unused/key-ring"));
    assert!(config.file_storage_config().unwrap().is_none());
    config.files_config_file = Some(path.clone());
    let valid = serde_json::json!({
        "endpoint":"https://oss-cn-hangzhou-internal.aliyuncs.com", "bucket":"sandbox-files", "kms_key_id":"file-key",
        "api_upload_sts_file":"/run/api-file-writer/sts.json", "gateway_sts_file":"/run/gateway-files/sts.json",
        "read_sts_file":"/run/api-file-reader/sts.json", "cleanup_sts_file":"/run/worker-file-cleanup/sts.json",
        "max_file_bytes":104857600,
    });
    std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    let settings = config.file_storage_config().unwrap().unwrap();
    assert_eq!(
        settings.api_upload().sts_credentials_file,
        Path::new("/run/api-file-writer/sts.json")
    );
    assert_eq!(
        settings.cleanup().sts_credentials_file,
        Path::new("/run/worker-file-cleanup/sts.json")
    );
    for (key, value) in [
        ("read_sts_file", valid["api_upload_sts_file"].clone()),
        ("gateway_sts_file", serde_json::json!("relative-path")),
        ("max_file_bytes", serde_json::json!(104857601)),
        ("endpoint", serde_json::json!("http://169.254.169.254")),
        ("unrecognized", serde_json::json!("PRIVATE-CONTENT-MARKER")),
    ] {
        let mut changed = valid.clone();
        changed[key] = value;
        std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let error = config.file_storage_config().err().unwrap();
        assert!(!error.to_string().contains("PRIVATE-CONTENT-MARKER"));
    }
    std::fs::write(&path, vec![b'x'; 8193]).unwrap();
    assert!(config.file_storage_config().is_err());
    config.files_config_file = Some(directory.path().to_owned());
    assert!(config.file_storage_config().is_err());
}

#[test]
fn backup_reader_requires_dedicated_file_and_bounded_ed25519_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("signing.der");
    let config_path = directory.path().join("vault.json");
    std::fs::write(&key, [1u8; 44]).unwrap();
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "endpoint":"https://oss-cn-hangzhou-internal.aliyuncs.com","bucket":"test-vault",
            "region":"cn-hangzhou","account_id":"1234567890123456","signing_public_key_file":key,
        }))
        .unwrap(),
    )
    .unwrap();
    let mut config = config(Path::new("/unused/key-ring"));
    config.backup_vault_config_file = Some(config_path.clone());
    config.output_sts_file = Some("/unused/writer".into());
    config.output_read_sts_file = Some("/unused/output-reader".into());
    assert!(config.backup_vault_config().is_err());
    config.backup_read_sts_file = Some("/run/backup-reader/private/credentials.json".into());
    assert!(config.backup_vault_config().is_err());
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend([1u8; 32]);
    std::fs::write(&key, &der).unwrap();
    let settings = config.backup_vault_config().unwrap();
    assert_eq!(
        settings.sts_credentials_file,
        Path::new("/run/backup-reader/private/credentials.json")
    );
    assert_eq!(settings.signing_public_key_spki, der);
    assert!(sandbox_platform::backup_object::BackupVaultVerifier::new(settings).is_ok());
    use base64::Engine;
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&der)
    );
    std::fs::write(&key, pem).unwrap();
    assert_eq!(
        config
            .backup_vault_config()
            .unwrap()
            .signing_public_key_spki,
        der
    );
    std::fs::write(&key, [b'x'; 4097]).unwrap();
    assert!(config.backup_vault_config().is_err());
    std::fs::write(&key, [1u8; 45]).unwrap();
    assert!(config.backup_vault_config().is_err());
    std::fs::write(&key, [1u8; 44]).unwrap();
    std::fs::write(config_path, [b'x'; 32769]).unwrap();
    assert!(config.backup_vault_config().is_err());
}

#[test]
fn cursor_key_reader_is_bounded_and_never_echoes_secret_content() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "PRIVATE-KEY-MARKER").unwrap();
    assert_eq!(
        config(file.path()).cursor_signing_key_json().unwrap(),
        "PRIVATE-KEY-MARKER"
    );
    file.write_all(&vec![b'x'; 8193]).unwrap();
    let error = config(file.path()).cursor_signing_key_json().unwrap_err();
    assert!(error.to_string().contains("8 KiB"));
    assert!(!error.to_string().contains("PRIVATE-KEY-MARKER"));
    assert!(
        config(file.path().parent().unwrap())
            .cursor_signing_key_json()
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn cursor_key_requires_owner_only_permissions_and_supports_projected_secret_links() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("secret");
    let link = directory.path().join("projected");
    std::fs::write(&target, "PRIVATE-KEY-MARKER").unwrap();
    for mode in [0o644, 0o640, 0o444, 0o700] {
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(config(&target).cursor_signing_key_json().is_err());
    }
    symlink(&target, &link).unwrap();
    for mode in [0o400, 0o600] {
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            config(&link).cursor_signing_key_json().unwrap(),
            "PRIVATE-KEY-MARKER"
        );
    }
}

#[test]
fn every_runtime_role_requires_canonical_verified_database_tls_without_query_overrides() {
    use sandbox_platform::config::Role;
    let mut c = config(Path::new("/unused/key-ring"));
    c.api_tls_cert_file = Some("/run/api-tls/tls.crt".into());
    c.api_tls_key_file = Some("/run/api-tls/tls.key".into());
    c.api_tls_ca_file = Some("/run/api-tls/ca.crt".into());
    c.api_tls_server_name = Some("api.sandbox-system.svc.cluster.local".into());
    for role in [
        Role::Api,
        Role::Worker,
        Role::Gateway,
        Role::Termination,
        Role::Fencing,
        Role::VolumeDeleter,
        Role::Backup,
        Role::Migrate,
    ] {
        c.role = role;
        c.database_url="postgresql://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=/run/api-trust/db-ca.pem&application_name=sandbox-api".into();
        c.validate().unwrap();
        for database in [
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=require&sslrootcert=/run/ca.pem",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=relative.pem",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=/run/../other.pem",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=/run/ca.pem&sslmode=disable",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=/run/ca.pem&hostaddr=127.0.0.1",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=/run/ca.pem&password=OVERRIDE",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=/run/ca.pem&options=-c%20role%3Downer",
            "postgres://runtime:PRIVATE-MARKER@db.example.test/runtime?sslmode=verify-full&sslrootcert=/run/ca.pem&%73slmode=disable",
            "postgres://runtime:PRIVATE-MARKER@127.0.0.1/runtime",
            "postgres://runtime:PRIVATE-MARKER@[::1]/runtime",
        ] {
            c.database_url = database.into();
            let error = c.validate().unwrap_err();
            assert!(!error.to_string().contains("PRIVATE-MARKER"));
        }
        c.database_url = "postgres://runtime@127.0.0.1/runtime".into();
        c.allow_loopback_http = true;
        c.validate().unwrap();
        c.database_url = "postgres://runtime@[::1]/runtime?sslmode=disable".into();
        c.validate().unwrap();
        for host in ["localhost", "10.1.2.3", "db.example.test"] {
            c.database_url = format!("postgres://runtime@{host}/runtime?sslmode=disable");
            assert!(c.validate().is_err());
        }
        c.allow_loopback_http = false;
    }
}

#[test]
fn native_api_worker_and_migrate_reject_unsafe_database_options_before_io_without_echoing_secret() {
    for role in [
        "worker",
        "migrate",
        "gateway",
        "termination",
        "fencing",
        "volume-deleter",
        "backup",
    ] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_sandboxd"))
            .args([
                "--role",
                role,
                "--database-url",
                "postgres://unused:PRIVATE-MARKER@127.0.0.1:1/unused?hostaddr=127.0.0.1",
            ])
            .env_remove("SANDBOX_ALLOW_LOOPBACK_HTTP")
            .output()
            .unwrap();
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("Database URL requires canonical"));
        assert!(!stderr.contains("PRIVATE-MARKER") && !stderr.contains("hostaddr="));
    }
}
