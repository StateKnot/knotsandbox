//! Actual FD/PEM tests use committed, explicitly public protocol certificates.
use sandbox_platform::termination_client::NodeguardCredentials;
use std::path::Path;

const CA: &str = include_str!("fixtures/nodeguard/server-ca.pem");
const IDENTITY: &str = concat!(
    include_str!("fixtures/nodeguard/client.pem"),
    include_str!("fixtures/nodeguard/client.key")
);

fn identity(directory: &Path, mode: u32) -> anyhow::Result<std::path::PathBuf> {
    let path = directory.join("identity.pem");
    #[cfg(unix)]
    if path.exists() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(&path, IDENTITY)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(path)
}

#[test]
fn real_owner_only_identity_and_projected_symlink_keep_the_same_tls_contract() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, CA)?;
    for mode in [0o400, 0o600] {
        let path = identity(directory.path(), mode)?;
        NodeguardCredentials::from_files(&ca, &path)?;
    }
    #[cfg(unix)]
    {
        let projected = directory.path().join("projected-identity.pem");
        std::os::unix::fs::symlink(directory.path().join("identity.pem"), &projected)?;
        NodeguardCredentials::from_files(&ca, &projected)?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn projected_identity_requires_owner_or_exact_root_primary_group_and_public_ca_is_immutable()
-> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, CA)?;
    for mode in [0o444, 0o644, 0o640, 0o660, 0o666, 0o440] {
        let path = identity(directory.path(), mode)?;
        let meta = std::fs::metadata(&path)?;
        let exact_root_group = mode == 0o440
            && meta.uid() == 0
            && meta.gid() != 0
            && meta.gid() == nix::unistd::getegid().as_raw();
        assert_eq!(
            NodeguardCredentials::from_files(&ca, &path).is_ok(),
            exact_root_group
        );
    }
    let path = identity(directory.path(), 0o600)?;
    for mode in [0o664, 0o666] {
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(mode))?;
        assert!(NodeguardCredentials::from_files(&ca, &path).is_err());
    }
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o444))?;
    NodeguardCredentials::from_files(&ca, &path)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn trust_rejects_fifo_relative_directory_and_overflow_without_blocking_or_leaking_paths()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, CA)?;
    let path = identity(directory.path(), 0o600)?;
    let fifo = directory
        .path()
        .join("PRIVATE_OPERATOR_PATH_NEVER_LOGGED.fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    let started = std::time::Instant::now();
    for (ca_path, key_path) in [
        (&ca as &Path, &fifo as &Path),
        (&fifo, &path),
        (&ca, directory.path()),
        (directory.path(), &path),
        (&ca, Path::new("relative-key.pem")),
        (Path::new("relative-ca.pem"), &path),
    ] {
        let result = NodeguardCredentials::from_files(ca_path, key_path);
        let error = result
            .err()
            .ok_or_else(|| anyhow::anyhow!("Invalid file accepted"))?
            .to_string();
        assert!(!error.contains("PRIVATE_OPERATOR_PATH") && !error.contains("relative-key"));
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    std::fs::write(&path, vec![b'x'; 65537])?;
    assert!(NodeguardCredentials::from_files(&ca, &path).is_err());
    std::fs::write(&path, b"")?;
    assert!(NodeguardCredentials::from_files(&ca, &path).is_err());
    let path = identity(directory.path(), 0o600)?;
    std::fs::write(&ca, vec![b'x'; 65537])?;
    assert!(NodeguardCredentials::from_files(&ca, &path).is_err());
    std::fs::write(&ca, b"PUBLIC_BUT_NOT_PEM")?;
    assert!(NodeguardCredentials::from_files(&ca, &path).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root-staged public TLS fixtures and real UID/GID 10001 projected-secret execution"]
fn real_linux_projected_identity_uses_primary_group_without_broadening_trust() -> anyhow::Result<()>
{
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(
        nix::unistd::geteuid().as_raw() == 10001 && nix::unistd::getegid().as_raw() == 10001,
        "Run as production UID/GID 10001"
    );
    let fixture =
        std::path::PathBuf::from(std::env::var("SANDBOX_PROJECTED_NODEGUARD_TRUST_FIXTURE")?);
    anyhow::ensure!(fixture.is_absolute(), "Fixture directory must be absolute");
    let ca = fixture.join("server-ca.pem");
    let identity = fixture.join("identity.pem");
    let key = std::fs::metadata(&identity)?;
    anyhow::ensure!(
        key.uid() == 0 && key.gid() == 10001 && key.mode() & 0o7777 == 0o440,
        "Fixture must reproduce root:10001 mode0440 projected identity"
    );
    NodeguardCredentials::from_files(&ca, &identity)?;
    NodeguardCredentials::from_files(&ca, &fixture.join("projected-identity.pem"))?;
    // Even a readable supplementary group is not a substitute for the exact
    // primary group that the production Deployment explicitly fixes.
    anyhow::ensure!(
        nix::unistd::getgroups()?
            .iter()
            .any(|g| g.as_raw() == 10002),
        "Run with supplementary group10002 to exercise the readable wrong-group case"
    );
    let wrong_group = fixture.join("wrong-group-identity.pem");
    std::fs::read(&wrong_group)?;
    for name in [
        "wrong-group-identity.pem",
        "group-write-identity.pem",
        "public-identity.pem",
        "nonroot-group-identity.pem",
    ] {
        assert!(NodeguardCredentials::from_files(&ca, &fixture.join(name)).is_err());
    }
    assert!(NodeguardCredentials::from_files(&fixture.join("writable-ca.pem"), &identity).is_err());
    Ok(())
}
