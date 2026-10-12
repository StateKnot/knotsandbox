//! Workspace-relative file access. Linux path resolution is kernel-enforced;
//! user paths never become a shell command, host path, or archive member.
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;

// Deliberately no Debug: filenames can contain tenant-sensitive information.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RelativeFilePath(String);
impl RelativeFilePath {
    pub fn new(path: String) -> Result<Self, FilePathError> {
        if path.is_empty()
            || path.len() > MAX_PATH_BYTES
            || path.starts_with('/')
            || path.contains('\\')
            || path.chars().any(char::is_control)
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
        {
            return Err(FilePathError::InvalidPath);
        }
        Ok(Self(path))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    #[cfg(target_os = "linux")]
    fn parent_and_name(&self) -> (&str, &str) {
        self.0.rsplit_once('/').unwrap_or((".", &self.0))
    }
}
impl<'de> Deserialize<'de> for RelativeFilePath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(|_| {
            serde::de::Error::custom("expected a bounded workspace-relative file path")
        })
    }
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FilePathError {
    #[error("invalid workspace-relative file path")]
    InvalidPath,
    #[error("workspace path resolution is unavailable or unsafe")]
    Resolution,
    #[error("only bounded regular files are supported")]
    NotRegular,
    #[error("file size exceeds its authorized byte limit")]
    Size,
    #[error("file checksum differs from its authorized content")]
    Checksum,
    #[error("destination already exists")]
    Exists,
    #[error("file changed during observation")]
    Changed,
    #[error("workspace file I/O failed; outcome may be unknown")]
    Io,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::{
        fd::OwnedFd,
        fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags},
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom, Write},
        path::Path,
    };
    use uuid::Uuid;

    const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS)
        .union(ResolveFlags::NO_XDEV);
    const BUFFER_BYTES: usize = 64 * 1024;
    pub struct WorkspaceDirectory {
        root: OwnedFd,
    }
    pub struct OpenDownload {
        file: File,
        before: std::fs::Metadata,
        limit: u64,
    }
    pub struct FileDigest {
        pub byte_length: u64,
        pub sha256: String,
    }
    impl WorkspaceDirectory {
        /// The runner supplies its fixed /workspace mount; callers cannot set a
        /// root path in the public protocol. Tests use a private fixture mount.
        pub fn open(root: &Path) -> Result<Self, FilePathError> {
            let root = fs::open(
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| FilePathError::Resolution)?;
            Ok(Self { root })
        }
        fn parent(&self, path: &RelativeFilePath) -> Result<OwnedFd, FilePathError> {
            fs::openat2(
                &self.root,
                path.parent_and_name().0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                RESOLVE,
            )
            .map_err(|_| FilePathError::Resolution)
        }
        pub fn open_download(
            &self,
            path: &RelativeFilePath,
            limit: u64,
        ) -> Result<OpenDownload, FilePathError> {
            if limit > MAX_FILE_BYTES {
                return Err(FilePathError::Size);
            }
            // NONBLOCK prevents a hostile FIFO/device from blocking before the
            // fstat regular-file check; it has no effect on regular-file I/O.
            let fd = fs::openat2(
                &self.root,
                path.as_str(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE,
            )
            .map_err(|_| FilePathError::Resolution)?;
            let stat = fs::fstat(&fd).map_err(|_| FilePathError::Io)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1
            {
                return Err(FilePathError::NotRegular);
            }
            let file = File::from(fd);
            let before = file.metadata().map_err(|_| FilePathError::Io)?;
            if before.len() > limit {
                return Err(FilePathError::Size);
            }
            Ok(OpenDownload {
                file,
                before,
                limit,
            })
        }
        /// The source is already checksum-bound by the control plane. A failed
        /// call after rename is not proof of no write: the gateway must retain
        /// UNKNOWN until trusted exec/VM completion, never rerun this attempt.
        pub fn upload(
            &self,
            path: &RelativeFilePath,
            input: &mut impl Read,
            expected_length: u64,
            expected_sha256: &str,
            replace: bool,
        ) -> Result<FileDigest, FilePathError> {
            if expected_length > MAX_FILE_BYTES {
                return Err(FilePathError::Size);
            }
            if !valid_sha(expected_sha256) {
                return Err(FilePathError::Checksum);
            }
            let parent = self.parent(path)?;
            let name = path.parent_and_name().1;
            match fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => {
                    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                        || st.st_nlink != 1
                    {
                        return Err(FilePathError::NotRegular);
                    }
                    if !replace {
                        return Err(FilePathError::Exists);
                    }
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(FilePathError::Resolution),
            }
            let temporary = format!(".sandbox-transfer-{}", Uuid::new_v4().simple());
            let fd = fs::openat2(
                &parent,
                temporary.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
                RESOLVE,
            )
            .map_err(|_| FilePathError::Resolution)?;
            let mut file = File::from(fd);
            let result = (|| {
                let mut buf = [0_u8; BUFFER_BYTES];
                let mut received = 0_u64;
                let mut sha = Sha256::new();
                loop {
                    let n = input.read(&mut buf).map_err(|_| FilePathError::Io)?;
                    if n == 0 {
                        break;
                    }
                    received = received.checked_add(n as u64).ok_or(FilePathError::Size)?;
                    if received > expected_length {
                        return Err(FilePathError::Size);
                    }
                    file.write_all(&buf[..n]).map_err(|_| FilePathError::Io)?;
                    sha.update(&buf[..n]);
                }
                if received != expected_length {
                    return Err(FilePathError::Size);
                }
                if hex::encode(sha.finalize()) != expected_sha256 {
                    return Err(FilePathError::Checksum);
                }
                file.sync_all().map_err(|_| FilePathError::Io)?;
                // Verify this descriptor's stored bytes before publication;
                // guest mutations after completion remain outside the contract.
                file.seek(SeekFrom::Start(0))
                    .map_err(|_| FilePathError::Io)?;
                let mut sha = Sha256::new();
                let mut checked = 0_u64;
                loop {
                    let n = file.read(&mut buf).map_err(|_| FilePathError::Io)?;
                    if n == 0 {
                        break;
                    }
                    checked += n as u64;
                    if checked > expected_length {
                        return Err(FilePathError::Changed);
                    }
                    sha.update(&buf[..n]);
                }
                if checked != expected_length || hex::encode(sha.finalize()) != expected_sha256 {
                    return Err(FilePathError::Changed);
                }
                let original = fs::fstat(&file).map_err(|_| FilePathError::Io)?;
                let named = fs::statat(&parent, temporary.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| FilePathError::Changed)?;
                if original.st_ino != named.st_ino
                    || original.st_dev != named.st_dev
                    || named.st_nlink != 1
                {
                    return Err(FilePathError::Changed);
                }
                fs::renameat_with(
                    &parent,
                    temporary.as_str(),
                    &parent,
                    name,
                    if replace {
                        RenameFlags::empty()
                    } else {
                        RenameFlags::NOREPLACE
                    },
                )
                .map_err(|e| {
                    if e == rustix::io::Errno::EXIST {
                        FilePathError::Exists
                    } else {
                        FilePathError::Io
                    }
                })?;
                fs::fsync(&parent).map_err(|_| FilePathError::Io)?;
                let installed = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| FilePathError::Changed)?;
                if original.st_ino != installed.st_ino
                    || original.st_dev != installed.st_dev
                    || FileType::from_raw_mode(installed.st_mode) != FileType::RegularFile
                {
                    return Err(FilePathError::Changed);
                }
                let current = fs::openat2(
                    &self.root,
                    path.as_str(),
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
                    Mode::empty(),
                    RESOLVE,
                )
                .map_err(|_| FilePathError::Changed)?;
                let current = fs::fstat(&current).map_err(|_| FilePathError::Changed)?;
                if current.st_ino != original.st_ino || current.st_dev != original.st_dev {
                    return Err(FilePathError::Changed);
                }
                Ok(FileDigest {
                    byte_length: received,
                    sha256: expected_sha256.into(),
                })
            })();
            // Only this unpredictable temporary name beneath the pinned parent
            // is cleaned up. No recursive removal or caller path is executed.
            let _ = fs::unlinkat(&parent, temporary.as_str(), AtFlags::empty());
            result
        }
    }
    impl OpenDownload {
        pub fn byte_length(&self) -> u64 {
            self.before.len()
        }
        pub fn stream_to(mut self, output: &mut impl Write) -> Result<FileDigest, FilePathError> {
            use std::os::unix::fs::MetadataExt;
            let mut buf = [0_u8; BUFFER_BYTES];
            let mut sent = 0_u64;
            let mut sha = Sha256::new();
            loop {
                let n = self.file.read(&mut buf).map_err(|_| FilePathError::Io)?;
                if n == 0 {
                    break;
                }
                sent = sent.checked_add(n as u64).ok_or(FilePathError::Size)?;
                if sent > self.limit || sent > self.before.len() {
                    return Err(FilePathError::Changed);
                }
                output.write_all(&buf[..n]).map_err(|_| FilePathError::Io)?;
                sha.update(&buf[..n]);
            }
            let after = self.file.metadata().map_err(|_| FilePathError::Io)?;
            if sent != self.before.len()
                || after.len() != self.before.len()
                || after.mtime() != self.before.mtime()
                || after.mtime_nsec() != self.before.mtime_nsec()
                || after.ctime() != self.before.ctime()
                || after.ctime_nsec() != self.before.ctime_nsec()
            {
                return Err(FilePathError::Changed);
            }
            Ok(FileDigest {
                byte_length: sent,
                sha256: hex::encode(sha.finalize()),
            })
        }
    }
    fn valid_sha(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}
#[cfg(target_os = "linux")]
pub use linux::{FileDigest, OpenDownload, WorkspaceDirectory};
