//! Fixed root-owned runtime endpoint. A binding lasts for its caller's whole
//! lifecycle; reconnect is never permission to learn another listener or peer.
use super::host::parse_start_time;
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::File,
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    sync::{Arc, Mutex},
};

const SOCKET: &str = "/run/containerd/containerd.sock";

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Runtime endpoint identity is untrusted or changed",
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}
fn identity(metadata: &std::fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}
struct PinnedSocket {
    parents: Vec<(&'static str, File)>,
    leaf: File,
}
impl PinnedSocket {
    fn open() -> io::Result<Self> {
        let mut parents = vec![("/", File::open("/")?)];
        for (name, path) in [("run", "/run"), ("containerd", "/run/containerd")] {
            let parent = &parents.last().ok_or_else(invalid)?.1;
            let fd = File::from(openat(
                parent,
                name,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            parents.push((path, fd));
        }
        let leaf = File::from(openat(
            &parents.last().ok_or_else(invalid)?.1,
            "containerd.sock",
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let pinned = Self { parents, leaf };
        pinned.check()?;
        Ok(pinned)
    }
    fn check(&self) -> io::Result<()> {
        for (path, fd) in &self.parents {
            let original = fd.metadata()?;
            let current = std::fs::symlink_metadata(path)?;
            if !original.is_dir()
                || original.uid() != 0
                || original.mode() & 0o022 != 0
                || original.nlink() == 0
                || !current.is_dir()
                || current.uid() != 0
                || current.mode() & 0o022 != 0
                || identity(&original) != identity(&current)
            {
                return Err(invalid());
            }
        }
        let original = self.leaf.metadata()?;
        let current = std::fs::symlink_metadata(SOCKET)?;
        // Socket write permission allows connect, not replacement. The trusted
        // parent prevents unlink; containerd's normal root-owned 0660 is valid.
        if !original.file_type().is_socket()
            || original.uid() != 0
            || original.nlink() == 0
            || !current.file_type().is_socket()
            || current.uid() != 0
            || identity(&original) != identity(&current)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn same_object(&self, other: &Self) -> io::Result<bool> {
        Ok(
            identity(&self.leaf.metadata()?) == identity(&other.leaf.metadata()?)
                && self
                    .parents
                    .iter()
                    .zip(&other.parents)
                    .all(|((_, a), (_, b))| {
                        a.metadata()
                            .ok()
                            .zip(b.metadata().ok())
                            .is_some_and(|(a, b)| identity(&a) == identity(&b))
                    }),
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Peer {
    pid: i32,
    start: u64,
}
fn peer(stream: &tokio::net::UnixStream) -> io::Result<Peer> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != 0 {
        return Err(invalid());
    }
    let pid = credentials
        .pid()
        .filter(|pid| *pid > 0)
        .ok_or_else(invalid)?;
    let start = || -> io::Result<u64> {
        let mut bytes = Vec::new();
        File::open(format!("/proc/{pid}/stat"))?
            .take(65537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(invalid());
        }
        parse_start_time(std::str::from_utf8(&bytes).map_err(|_| invalid())?).map_err(|_| invalid())
    };
    let before = start()?;
    if start()? != before {
        return Err(invalid());
    }
    Ok(Peer { pid, start: before })
}

enum Binding {
    Unbound,
    Bound { socket: PinnedSocket, peer: Peer },
    Rejected,
}
#[derive(Clone)]
pub(super) struct RuntimeEndpoint(Arc<Mutex<Binding>>);
impl Default for RuntimeEndpoint {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Binding::Unbound)))
    }
}
impl RuntimeEndpoint {
    pub(super) fn is_rejected(&self) -> bool {
        self.0
            .lock()
            .map_or(true, |state| matches!(*state, Binding::Rejected))
    }
    fn reject(&self) {
        if let Ok(mut state) = self.0.lock() {
            *state = Binding::Rejected;
        }
    }
    pub(super) async fn connect(&self) -> io::Result<tokio::net::UnixStream> {
        let socket = match PinnedSocket::open() {
            Ok(socket) => socket,
            Err(error) => {
                let bound = self
                    .0
                    .lock()
                    .map_or(true, |state| !matches!(*state, Binding::Unbound));
                if bound || error.kind() == io::ErrorKind::PermissionDenied {
                    self.reject();
                }
                return Err(invalid());
            }
        };
        {
            let mut state = self.0.lock().map_err(|_| invalid())?;
            match &*state {
                Binding::Rejected => return Err(invalid()),
                Binding::Bound {
                    socket: original, ..
                } => {
                    if original.check().is_err() || !original.same_object(&socket).unwrap_or(false)
                    {
                        *state = Binding::Rejected;
                        return Err(invalid());
                    }
                }
                Binding::Unbound => {}
            }
        }
        // Resolve the pinned socket object, not a second lookup of its mutable
        // pathname. The retained O_PATH descriptor also prevents inode reuse.
        let stream =
            tokio::net::UnixStream::connect(format!("/proc/self/fd/{}", socket.leaf.as_raw_fd()))
                .await?;
        let actual = match peer(&stream).and_then(|peer| {
            socket.check()?;
            Ok(peer)
        }) {
            Ok(peer) => peer,
            Err(_) => {
                self.reject();
                return Err(invalid());
            }
        };
        let mut state = self.0.lock().map_err(|_| invalid())?;
        match &*state {
            Binding::Rejected => return Err(invalid()),
            Binding::Bound {
                socket: original,
                peer,
            } => {
                if *peer != actual
                    || original.check().is_err()
                    || !original.same_object(&socket).unwrap_or(false)
                {
                    *state = Binding::Rejected;
                    return Err(invalid());
                }
            }
            Binding::Unbound => {
                *state = Binding::Bound {
                    socket,
                    peer: actual,
                };
            }
        }
        Ok(stream)
    }
}

#[cfg(test)]
#[path = "runtime_endpoint_native_tests.rs"]
mod native_tests;
