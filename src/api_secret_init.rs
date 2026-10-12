//! Fixed API credential bundle initialization for a shell-free init container.
//! Nothing is logged, credentials never appear in argv, and no database opens.
use clap::{Parser, ValueEnum};
use std::{ffi::OsString, path::Path};

#[derive(Clone, Copy, ValueEnum)]
enum Profile {
    Bearer,
    Browser,
}
#[derive(Clone, Copy, ValueEnum)]
enum MetricsAuth {
    None,
    Bearer,
    Basic,
}
#[derive(Parser)]
#[command(
    name = "sandboxd secrets-init",
    about = "Copy fixed projected API credentials into an owner-only memory bundle"
)]
struct Arguments {
    #[arg(long, value_enum)]
    profile: Profile,
    #[arg(long, value_enum, default_value = "none")]
    metrics_auth: MetricsAuth,
}

pub fn command(arguments: Vec<OsString>) -> anyhow::Result<()> {
    let args = Arguments::try_parse_from(
        std::iter::once(OsString::from("sandboxd secrets-init"))
            .chain(arguments.into_iter().skip(2)),
    )
    .map_err(|_| anyhow::anyhow!("Invalid secrets-init arguments"))?;
    #[cfg(unix)]
    {
        anyhow::ensure!(
            nix::unistd::geteuid().as_raw() == 10001 && nix::unistd::getegid().as_raw() == 10001,
            "API secrets-init requires UID and primary GID 10001"
        );
        initialize(
            Path::new("/var/run/api-secret-source"),
            Path::new("/run/api-private"),
            args.profile,
            args.metrics_auth,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        anyhow::bail!("API secrets-init requires Unix file ownership")
    }
}

struct Secret {
    source: &'static str,
    target: &'static str,
    limit: usize,
}
fn files(profile: Profile, metrics: MetricsAuth) -> Vec<Secret> {
    let mut files = vec![Secret {
        source: "cursor/keyring.json",
        target: "cursor.json",
        limit: 16384,
    }];
    if matches!(profile, Profile::Browser) {
        files.extend([
            Secret {
                source: "browser/client-secret",
                target: "browser-client-secret",
                limit: 4096,
            },
            Secret {
                source: "browser/session-keys.json",
                target: "browser-session-keys.json",
                limit: 16384,
            },
        ]);
    }
    match metrics {
        MetricsAuth::None => {}
        MetricsAuth::Bearer => files.push(Secret {
            source: "metrics/token",
            target: "metrics-token",
            limit: 8192,
        }),
        MetricsAuth::Basic => files.extend([
            Secret {
                source: "metrics/username",
                target: "metrics-username",
                limit: 1024,
            },
            Secret {
                source: "metrics/password",
                target: "metrics-password",
                limit: 8192,
            },
        ]),
    }
    files
}

#[cfg(unix)]
fn read(path: &Path, limit: usize, projected: bool) -> anyhow::Result<Vec<u8>> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let flags = nix::fcntl::OFlag::O_NONBLOCK
        | if projected {
            nix::fcntl::OFlag::empty()
        } else {
            nix::fcntl::OFlag::O_NOFOLLOW
        };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits())
        .open(path)
        .map_err(|_| anyhow::anyhow!("API credential source unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("API credential metadata unavailable"))?;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let permissions = if projected {
        ((metadata.uid() == uid || metadata.uid() == 0) && matches!(mode, 0o400 | 0o600))
            || (metadata.uid() == 0 && metadata.gid() == gid && gid != 0 && mode == 0o440)
    } else {
        metadata.uid() == uid && mode == 0o600
    };
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= limit as u64 && permissions,
        "API credential type, size or permissions rejected"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("API credential read failed"))?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "API credential size rejected"
    );
    Ok(bytes)
}

#[cfg(unix)]
fn verify_bundle(path: &Path, secrets: &[(Secret, Vec<u8>)]) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("API private bundle unavailable"))?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "API private bundle ownership rejected"
    );
    let mut names = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let mut expected = secrets
        .iter()
        .map(|(secret, _)| OsString::from(secret.target))
        .collect::<Vec<_>>();
    expected.sort();
    anyhow::ensure!(names == expected, "API private bundle inventory rejected");
    for (secret, bytes) in secrets {
        anyhow::ensure!(
            read(&path.join(secret.target), secret.limit, false)? == *bytes,
            "API private bundle differs from the projected Secret; recreate this Pod"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn initialize(
    source: &Path,
    destination: &Path,
    profile: Profile,
    metrics: MetricsAuth,
) -> anyhow::Result<()> {
    use std::{
        fs::{DirBuilder, File, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let metadata = std::fs::symlink_metadata(destination)
        .map_err(|_| anyhow::anyhow!("API memory volume unavailable"))?;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    anyhow::ensure!(
        metadata.is_dir()
            && [0, uid].contains(&metadata.uid())
            && metadata.gid() == gid
            && metadata.permissions().mode() & 0o5002 == 0,
        "API memory volume ownership rejected"
    );
    let secrets = files(profile, metrics)
        .into_iter()
        .map(|secret| {
            read(&source.join(secret.source), secret.limit, true).map(|bytes| (secret, bytes))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let active = destination.join("private");
    if std::fs::symlink_metadata(&active).is_ok() {
        return verify_bundle(&active, &secrets);
    }
    let staging = destination.join(format!(".pending-{}", uuid::Uuid::new_v4().simple()));
    DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|_| anyhow::anyhow!("API credential staging failed"))?;
    let result = (|| -> anyhow::Result<()> {
        for (secret, bytes) in &secrets {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(staging.join(secret.target))
                .map_err(|_| anyhow::anyhow!("API private file creation failed"))?;
            file.write_all(bytes)
                .map_err(|_| anyhow::anyhow!("API private file write failed"))?;
            file.sync_all()
                .map_err(|_| anyhow::anyhow!("API private file sync failed"))?;
        }
        File::open(&staging)?.sync_all()?;
        if std::fs::symlink_metadata(&active).is_ok() {
            verify_bundle(&active, &secrets)?;
            std::fs::remove_dir_all(&staging)?;
        } else {
            std::fs::rename(&staging, &active)
                .map_err(|_| anyhow::anyhow!("API credential bundle publication failed"))?;
        }
        File::open(destination)?.sync_all()?;
        verify_bundle(&active, &secrets)
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(staging);
    }
    result.map_err(|_| anyhow::anyhow!("API credential initialization rejected"))
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fn fixture(
        profile: Profile,
        metrics: MetricsAuth,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("memory");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&destination).unwrap();
        for secret in files(profile, metrics) {
            let path = source.join(secret.source);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "PUBLIC-TEST-ONLY-CREDENTIAL").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (dir, source, destination)
    }
    #[test]
    fn complete_bundle_is_atomic_private_idempotent_and_cannot_replace_changed_credentials() {
        let (_dir, source, destination) = fixture(Profile::Browser, MetricsAuth::Basic);
        initialize(&source, &destination, Profile::Browser, MetricsAuth::Basic).unwrap();
        initialize(&source, &destination, Profile::Browser, MetricsAuth::Basic).unwrap();
        let private = destination.join("private");
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        for secret in files(Profile::Browser, MetricsAuth::Basic) {
            let metadata = std::fs::metadata(private.join(secret.target)).unwrap();
            assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        }
        std::fs::write(
            source.join("browser/client-secret"),
            "CHANGED-PUBLIC-FIXTURE",
        )
        .unwrap();
        assert!(initialize(&source, &destination, Profile::Browser, MetricsAuth::Basic).is_err());
        assert_eq!(
            std::fs::read(private.join("browser-client-secret")).unwrap(),
            b"PUBLIC-TEST-ONLY-CREDENTIAL"
        );
    }
    #[test]
    fn invalid_missing_oversize_or_world_readable_input_publishes_nothing() {
        for failure in ["missing", "mode", "oversize", "fifo"] {
            let (_dir, source, destination) = fixture(Profile::Browser, MetricsAuth::Bearer);
            let path = source.join("browser/client-secret");
            match failure {
                "missing" => std::fs::remove_file(path).unwrap(),
                "mode" => {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "oversize" => std::fs::write(path, vec![b'x'; 4097]).unwrap(),
                _ => {
                    std::fs::remove_file(&path).unwrap();
                    nix::unistd::mkfifo(
                        &path,
                        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                    )
                    .unwrap();
                }
            }
            assert!(
                initialize(&source, &destination, Profile::Browser, MetricsAuth::Bearer).is_err()
            );
            assert!(!destination.join("private").exists());
        }
    }
    #[test]
    fn projected_input_links_work_but_output_links_and_inventory_changes_fail_closed() {
        let (dir, source, destination) = fixture(Profile::Bearer, MetricsAuth::None);
        let real = dir.path().join("keyring");
        std::fs::rename(source.join("cursor/keyring.json"), &real).unwrap();
        std::os::unix::fs::symlink(&real, source.join("cursor/keyring.json")).unwrap();
        initialize(&source, &destination, Profile::Bearer, MetricsAuth::None).unwrap();
        std::fs::write(destination.join("private/extra"), "PUBLIC-FIXTURE").unwrap();
        assert!(initialize(&source, &destination, Profile::Bearer, MetricsAuth::None).is_err());
        std::fs::remove_file(destination.join("private/extra")).unwrap();
        std::fs::remove_file(destination.join("private/cursor.json")).unwrap();
        std::os::unix::fs::symlink(real, destination.join("private/cursor.json")).unwrap();
        assert!(initialize(&source, &destination, Profile::Bearer, MetricsAuth::None).is_err());
    }
    #[test]
    fn cli_rejects_unknown_arguments_without_echoing_their_values() {
        let error = command(
            [
                "sandboxd",
                "secrets-init",
                "--profile",
                "browser",
                "--source",
                "PRIVATE-MARKER",
            ]
            .map(OsString::from)
            .to_vec(),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("PRIVATE-MARKER"));
    }
}
