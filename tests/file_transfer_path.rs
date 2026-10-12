#![allow(clippy::expect_used)]
#[allow(dead_code, unused_imports)]
#[path = "../src/file_transfer_path.rs"]
mod file_transfer_path;
use file_transfer_path::{MAX_FILE_BYTES, RelativeFilePath};

#[test]
fn only_bounded_canonical_workspace_relative_paths_are_accepted() {
    for path in [
        "",
        "/etc/passwd",
        "../secret",
        "a/../../secret",
        "a/./b",
        "a//b",
        "a/",
        "a\\b",
        "a\0b",
        "a\nb",
        ".",
        "..",
    ] {
        assert!(RelativeFilePath::new(path.into()).is_err());
    }
    assert!(RelativeFilePath::new(format!("{}/file", "x".repeat(256))).is_err());
    assert!(RelativeFilePath::new("x/".repeat(3000)).is_err());
    for path in [
        "input.json",
        "directory/input.json",
        "中文/输入数据.json",
        "a file.json",
    ] {
        assert!(RelativeFilePath::new(path.into()).is_ok());
    }
    assert_eq!(MAX_FILE_BYTES, 100 * 1024 * 1024);
}
#[test]
fn path_deserialization_validates_without_echoing_sensitive_path() {
    let error = serde_json::from_str::<RelativeFilePath>("\"../tenant-secret\"")
        .err()
        .expect("invalid path");
    assert!(!error.to_string().contains("tenant-secret"));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use file_transfer_path::{FilePathError, WorkspaceDirectory};
    use sha2::{Digest, Sha256};
    use std::{
        io::{Cursor, Read},
        os::unix::fs::symlink,
    };
    fn path(value: &str) -> RelativeFilePath {
        RelativeFilePath::new(value.into()).expect("fixture relative path")
    }
    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
    #[test]
    fn upload_is_checksum_bound_atomic_and_download_matches_bytes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir(dir.path().join("nested"))?;
        let workspace = WorkspaceDirectory::open(dir.path())?;
        let bytes = b"binary\0payload\xff";
        let uploaded = workspace.upload(
            &path("nested/file"),
            &mut Cursor::new(bytes),
            bytes.len() as u64,
            &sha(bytes),
            false,
        )?;
        assert_eq!(uploaded.byte_length, bytes.len() as u64);
        let mut downloaded = Vec::new();
        let receipt = workspace
            .open_download(&path("nested/file"), 100)?
            .stream_to(&mut downloaded)?;
        assert_eq!(downloaded, bytes);
        assert_eq!(receipt.sha256, sha(bytes));
        assert_eq!(
            workspace
                .upload(
                    &path("nested/file"),
                    &mut Cursor::new(bytes),
                    bytes.len() as u64,
                    &sha(bytes),
                    false
                )
                .err(),
            Some(FilePathError::Exists)
        );
        let replacement = b"replacement";
        workspace.upload(
            &path("nested/file"),
            &mut Cursor::new(replacement),
            replacement.len() as u64,
            &sha(replacement),
            true,
        )?;
        assert_eq!(std::fs::read(dir.path().join("nested/file"))?, replacement);
        Ok(())
    }
    #[test]
    fn symlinks_magic_links_hardlinks_and_fifos_never_become_file_channels() -> anyhow::Result<()> {
        use rustix::fs::{CWD, FileType, Mode, makedev, mknodat};
        let dir = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::fs::write(outside.path().join("secret"), b"outside")?;
        symlink(outside.path(), dir.path().join("link"))?;
        symlink("/proc/self/fd/0", dir.path().join("magic"))?;
        std::fs::write(dir.path().join("inside"), b"inside")?;
        std::fs::hard_link(dir.path().join("inside"), dir.path().join("hard"))?;
        mknodat(
            CWD,
            dir.path().join("fifo"),
            FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            makedev(0, 0),
        )?;
        let workspace = WorkspaceDirectory::open(dir.path())?;
        for candidate in ["link/secret", "magic", "hard", "fifo"] {
            assert!(workspace.open_download(&path(candidate), 100).is_err());
            assert!(
                workspace
                    .upload(
                        &path(candidate),
                        &mut Cursor::new(b"new"),
                        3,
                        &sha(b"new"),
                        true
                    )
                    .is_err()
            );
        }
        assert_eq!(std::fs::read(outside.path().join("secret"))?, b"outside");
        Ok(())
    }
    #[test]
    fn truncation_oversize_and_checksum_failure_do_not_publish_partial_destination()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let workspace = WorkspaceDirectory::open(dir.path())?;
        for (input, size, hash) in [
            (b"abc".to_vec(), 4, sha(b"abcd")),
            (b"abcd".to_vec(), 3, sha(b"abc")),
            (b"abc".to_vec(), 3, sha(b"xyz")),
        ] {
            assert!(
                workspace
                    .upload(&path("file"), &mut Cursor::new(input), size, &hash, false)
                    .is_err()
            );
            assert!(!dir.path().join("file").exists());
        }
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 0);
        workspace.upload(&path("empty"), &mut Cursor::new([]), 0, &sha(b""), false)?;
        let mut bytes = Vec::new();
        workspace
            .open_download(&path("empty"), 0)?
            .stream_to(&mut bytes)?;
        assert!(bytes.is_empty());
        Ok(())
    }
    #[test]
    fn renamed_parent_cannot_redirect_upload_through_replaced_symlink() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::fs::create_dir(root.path().join("parent"))?;
        struct RacingInput<'a> {
            root: &'a std::path::Path,
            outside: &'a std::path::Path,
            done: bool,
        }
        impl Read for RacingInput<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.done {
                    return Ok(0);
                }
                self.done = true;
                std::fs::rename(self.root.join("parent"), self.root.join("original"))?;
                symlink(self.outside, self.root.join("parent"))?;
                buf[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }
        let workspace = WorkspaceDirectory::open(root.path())?;
        let mut input = RacingInput {
            root: root.path(),
            outside: outside.path(),
            done: false,
        };
        assert_eq!(
            workspace
                .upload(&path("parent/file"), &mut input, 3, &sha(b"abc"), false)
                .err(),
            Some(FilePathError::Changed)
        );
        assert!(!outside.path().join("file").exists());
        assert_eq!(std::fs::read(root.path().join("original/file"))?, b"abc");
        Ok(())
    }
    #[test]
    fn download_detects_change_and_respects_hard_limit() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("file"), b"content")?;
        let workspace = WorkspaceDirectory::open(root.path())?;
        assert!(workspace.open_download(&path("file"), 6).is_err());
        let download = workspace.open_download(&path("file"), 10)?;
        std::fs::write(root.path().join("file"), b"different")?;
        assert!(download.stream_to(&mut Vec::new()).is_err());
        Ok(())
    }
}
