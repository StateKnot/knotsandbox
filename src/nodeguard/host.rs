//! Linux observations of registered Kata processes. No guest input and no caller
//! supplied PID, path, executable or cgroup is accepted by the control protocol.
#[cfg(target_os = "linux")]
use super::journal::opaque_id;
use super::{GuardError, protocol::*};
#[cfg(target_os = "linux")]
use chrono::Utc;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, io::Read, path::Path};
use std::{
    collections::BTreeSet,
    path::{Component, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedFile {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfile {
    pub protocol: u32,
    pub runtime_handler: String,
    pub containerd_version: String,
    pub qemu: PinnedFile,
    pub virtiofs: PinnedFile,
    pub shim: PinnedFile,
    pub kata_configuration: PinnedFile,
    pub containerd_configuration: PinnedFile,
    pub kubelet_configuration: PinnedFile,
    pub kubelet_environment: PinnedFile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_observation: Option<super::image_observation::ImageObservationConfig>,
}
impl HostProfile {
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.protocol != PROTOCOL_VERSION
            || self.runtime_handler != "kata-qemu"
            || self.containerd_version != "2.3.5"
        {
            return Err(GuardError::Invalid);
        }
        if let Some(config) = &self.image_observation {
            config.validate()?;
        }
        let files = [
            &self.qemu,
            &self.virtiofs,
            &self.shim,
            &self.kata_configuration,
            &self.containerd_configuration,
            &self.kubelet_configuration,
            &self.kubelet_environment,
        ];
        let mut paths = BTreeSet::new();
        for file in files {
            if !file.path.is_absolute()
                || file
                    .path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                || !valid_sha256(&file.sha256)
                || !paths.insert(&file.path)
            {
                return Err(GuardError::Invalid);
            }
        }
        Ok(())
    }
}

pub fn parse_start_time(stat: &str) -> Result<u64, GuardError> {
    // comm is parenthesized and may itself contain spaces or ')' characters.
    let tail = stat.rsplit_once(')').ok_or(GuardError::Invalid)?.1;
    tail.split_whitespace()
        .nth(19)
        .ok_or(GuardError::Invalid)?
        .parse()
        .map_err(|_| GuardError::Invalid)
}

pub fn parse_cgroup(value: &str) -> Result<String, GuardError> {
    let mut lines = value.lines();
    let result = lines
        .next()
        .and_then(|v| v.strip_prefix("0::"))
        .ok_or(GuardError::Invalid)?;
    if lines.next().is_some()
        || result == "/"
        || !result.starts_with('/')
        || result.len() > 512
        || result.split('/').skip(1).any(|v| {
            v.is_empty()
                || v == "."
                || v == ".."
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        })
    {
        return Err(GuardError::Invalid);
    }
    Ok(result.to_owned())
}

/// Protocol paths are relative to the cgroup2 mount, never filesystem absolutes.
pub fn relative_cgroup_path(absolute: &str) -> Result<String, GuardError> {
    let parsed = parse_cgroup(&format!("0::{absolute}"))?;
    Ok(parsed[1..].to_owned())
}
#[cfg(any(target_os = "linux", test))]
fn cgroup_filesystem_path(relative: &str) -> Result<PathBuf, GuardError> {
    if relative.starts_with('/') || relative_cgroup_path(&format!("/{relative}"))? != relative {
        return Err(GuardError::Invalid);
    }
    Ok(PathBuf::from("/sys/fs/cgroup").join(relative))
}

pub fn pod_cgroup_root(pod: uuid::Uuid, value: &str) -> Result<String, GuardError> {
    let encoded = pod.to_string().replace('-', "_");
    let roots = [
        format!("/kubepods.slice/kubepods-pod{encoded}.slice"),
        format!("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{encoded}.slice"),
        format!("/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{encoded}.slice"),
    ];
    roots
        .into_iter()
        .find(|root| {
            value == root
                || value
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
        .ok_or(GuardError::IdentityMismatch)
}

pub fn mountinfo_has_pod(value: &str, pod: uuid::Uuid) -> Result<bool, GuardError> {
    let prefix = format!("/var/lib/kubelet/pods/{pod}");
    for line in value.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 10 || !fields.contains(&"-") {
            return Err(GuardError::Invalid);
        }
        let mount = decode_mount_path(fields[4])?;
        let block_publish = mount
            .strip_prefix("/var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/publish/")
            .and_then(|v| v.split_once('/'))
            .is_some_and(|(_, tail)| {
                tail == pod.to_string()
                    || tail
                        .strip_prefix(&pod.to_string())
                        .is_some_and(|v| v.starts_with('/'))
            });
        if block_publish
            || mount == prefix
            || mount
                .strip_prefix(&prefix)
                .is_some_and(|v| v.starts_with('/'))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn decode_mount_path(value: &str) -> Result<String, GuardError> {
    let mut result = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' {
            let part = bytes.get(at + 1..at + 4).ok_or(GuardError::Invalid)?;
            if !matches!(part, b"040" | b"011" | b"012" | b"134") {
                return Err(GuardError::Invalid);
            }
            result.push((part[0] - b'0') * 64 + (part[1] - b'0') * 8 + part[2] - b'0');
            at += 4;
        } else {
            result.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(result).map_err(|_| GuardError::Invalid)
}

#[cfg(target_os = "linux")]
fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>, GuardError> {
    let mut result = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut result)?;
    if result.len() > limit {
        return Err(GuardError::Invalid);
    }
    Ok(result)
}
#[cfg(target_os = "linux")]
fn read_text(path: &Path, limit: usize) -> Result<String, GuardError> {
    String::from_utf8(bounded_read(path, limit)?).map_err(|_| GuardError::Invalid)
}
#[cfg(target_os = "linux")]
fn digest_file(path: &Path) -> Result<String, GuardError> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut block = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > 512 * 1024 * 1024 {
            return Err(GuardError::Invalid);
        }
        hash.update(&block[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::{
        event::{PollFd, PollFlags, Timespec, poll},
        process::{Pid, PidfdFlags, pidfd_open},
    };
    use std::{
        fs::{File, Metadata},
        os::{fd::OwnedFd, unix::fs::MetadataExt},
        sync::Mutex,
    };

    struct PinnedProcess {
        identity: ProcessIdentity,
        fd: Option<OwnedFd>,
    }
    struct PinnedSandbox {
        observation: SandboxObservation,
        cgroup: File,
        processes: Vec<PinnedProcess>,
    }
    pub struct HostObserver {
        profile: HostProfile,
        node: NodeBinding,
        sandboxes: Mutex<BTreeMap<String, PinnedSandbox>>,
    }

    fn errno(error: rustix::io::Errno) -> GuardError {
        GuardError::Io(error.into())
    }
    fn trusted_file(path: &Path) -> Result<Metadata, GuardError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(GuardError::Invalid);
        }
        Ok(metadata)
    }
    fn proc_identity(pid: u32, profile: &HostProfile) -> Result<ProcessIdentity, GuardError> {
        let root = PathBuf::from(format!("/proc/{pid}"));
        let start_time_ticks = parse_start_time(&read_text(&root.join("stat"), 65536)?)?;
        let executable = std::fs::read_link(root.join("exe"))?;
        let (role, file) = if executable == profile.qemu.path {
            (ProcessRole::Hypervisor, &profile.qemu)
        } else if executable == profile.virtiofs.path {
            (ProcessRole::Virtiofs, &profile.virtiofs)
        } else if executable == profile.shim.path {
            (ProcessRole::Shim, &profile.shim)
        } else {
            return Err(GuardError::IdentityMismatch);
        };
        let executable_sha256 = digest_file(&root.join("exe"))?;
        if executable_sha256 != file.sha256 {
            return Err(GuardError::IdentityMismatch);
        }
        Ok(ProcessIdentity {
            role,
            pid,
            start_time_ticks,
            executable_sha256,
        })
    }
    fn pin_process(
        expected: &ProcessIdentity,
        profile: &HostProfile,
        restore: bool,
    ) -> Result<PinnedProcess, GuardError> {
        let before = match proc_identity(expected.pid, profile) {
            Ok(found) if found == *expected => found,
            Ok(_) if restore => {
                return Ok(PinnedProcess {
                    identity: expected.clone(),
                    fd: None,
                });
            }
            Err(GuardError::Io(e)) if restore && e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PinnedProcess {
                    identity: expected.clone(),
                    fd: None,
                });
            }
            Ok(_) => return Err(GuardError::IdentityMismatch),
            Err(error) => return Err(error),
        };
        let fd = pidfd_open(
            Pid::from_raw(expected.pid as i32).ok_or(GuardError::Invalid)?,
            PidfdFlags::NONBLOCK,
        )
        .map_err(errno)?;
        let after = proc_identity(expected.pid, profile)?;
        if before != after {
            return Err(GuardError::IdentityMismatch);
        }
        Ok(PinnedProcess {
            identity: after,
            fd: Some(fd),
        })
    }
    fn list_processes(
        path: &Path,
        depth: usize,
        out: &mut BTreeSet<u32>,
        directories: &mut usize,
    ) -> Result<(), GuardError> {
        *directories += 1;
        if depth > 8 || *directories > 256 {
            return Err(GuardError::Invalid);
        }
        for value in read_text(&path.join("cgroup.procs"), 65536)?.lines() {
            let pid: u32 = value.parse().map_err(|_| GuardError::Invalid)?;
            if pid < 2 || pid > i32::MAX as u32 {
                return Err(GuardError::Invalid);
            }
            out.insert(pid);
        }
        if out.len() > 64 {
            return Err(GuardError::Invalid);
        }
        let mut children = 0;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                children += 1;
                if children > 128 {
                    return Err(GuardError::Invalid);
                }
                list_processes(&entry.path(), depth + 1, out, directories)?;
            }
        }
        Ok(())
    }
    impl HostObserver {
        #[cfg(test)]
        pub(crate) fn test_unobserved(node: NodeBinding) -> Self {
            let file = PinnedFile {
                path: PathBuf::from("/test-only-never-observed"),
                sha256: "a".repeat(64),
            };
            Self {
                node,
                profile: HostProfile {
                    protocol: 1,
                    runtime_handler: "kata-qemu".into(),
                    containerd_version: "2.3.5".into(),
                    qemu: file.clone(),
                    virtiofs: file.clone(),
                    shim: file.clone(),
                    kata_configuration: file.clone(),
                    containerd_configuration: file.clone(),
                    kubelet_configuration: file.clone(),
                    kubelet_environment: file,
                    image_observation: None,
                },
                sandboxes: Mutex::new(BTreeMap::new()),
            }
        }
        pub fn new(profile: HostProfile, node: NodeBinding) -> Result<Self, GuardError> {
            profile.validate()?;
            if !node.validate() {
                return Err(GuardError::Invalid);
            }
            let actual = uuid::Uuid::parse_str(
                read_text(Path::new("/proc/sys/kernel/random/boot_id"), 64)?.trim(),
            )
            .map_err(|_| GuardError::Invalid)?;
            if actual != node.boot_id {
                return Err(GuardError::IdentityMismatch);
            }
            for file in [
                &profile.qemu,
                &profile.virtiofs,
                &profile.shim,
                &profile.kata_configuration,
                &profile.containerd_configuration,
                &profile.kubelet_configuration,
                &profile.kubelet_environment,
            ] {
                trusted_file(&file.path)?;
                if digest_file(&file.path)? != file.sha256 {
                    return Err(GuardError::IdentityMismatch);
                }
            }
            if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
                return Err(GuardError::Invalid);
            }
            Ok(Self {
                profile,
                node,
                sandboxes: Mutex::new(BTreeMap::new()),
            })
        }
        pub(in crate::nodeguard) fn expected_kata_configuration(&self) -> &Path {
            &self.profile.kata_configuration.path
        }

        pub fn capture(
            &self,
            sandbox_id: &str,
            launch: &LaunchBinding,
        ) -> Result<SandboxObservation, GuardError> {
            opaque_id(sandbox_id)?;
            let pid_path = PathBuf::from(format!("/run/vc/vm/{sandbox_id}/pid"));
            trusted_file(&pid_path)?;
            let qemu_pid: u32 = read_text(&pid_path, 32)?
                .trim()
                .parse()
                .map_err(|_| GuardError::Invalid)?;
            let relative = parse_cgroup(&read_text(
                &PathBuf::from(format!("/proc/{qemu_pid}/cgroup")),
                65536,
            )?)?;
            pod_cgroup_root(launch.pod_uid, &relative)?;
            let parent = relative;
            let path = cgroup_filesystem_path(&relative_cgroup_path(&parent)?)?;
            let cgroup = File::open(&path)?;
            let metadata = cgroup.metadata()?;
            let mut pids = BTreeSet::new();
            list_processes(&path, 0, &mut pids, &mut 0)?;
            if !pids.contains(&qemu_pid) {
                return Err(GuardError::IdentityMismatch);
            }
            let mut processes = Vec::new();
            let mut roles = BTreeSet::new();
            for pid in pids {
                let identity = proc_identity(pid, &self.profile)?;
                let process_group = parse_cgroup(&read_text(
                    &PathBuf::from(format!("/proc/{pid}/cgroup")),
                    65536,
                )?)?;
                if process_group != parent
                    && !process_group
                        .strip_prefix(&parent)
                        .is_some_and(|v| v.starts_with('/'))
                {
                    return Err(GuardError::IdentityMismatch);
                }
                roles.insert(match identity.role {
                    ProcessRole::Hypervisor => 0,
                    ProcessRole::Virtiofs => 1,
                    ProcessRole::Shim => 2,
                });
                processes.push(pin_process(&identity, &self.profile, false)?);
            }
            if roles.len() != 3 || processes.len() != 3 {
                return Err(GuardError::IdentityMismatch);
            }
            let observation = SandboxObservation {
                sandbox_id: sandbox_id.to_owned(),
                cgroup: CgroupIdentity {
                    relative_path: relative_cgroup_path(&parent)?,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
                processes: processes.iter().map(|p| p.identity.clone()).collect(),
                registered_at: Utc::now(),
            };
            let mut map = self.sandboxes.lock().map_err(|_| GuardError::Unknown)?;
            if map.contains_key(sandbox_id) {
                return Err(GuardError::IdentityMismatch);
            }
            map.insert(
                sandbox_id.to_owned(),
                PinnedSandbox {
                    observation: observation.clone(),
                    cgroup,
                    processes,
                },
            );
            Ok(observation)
        }
        pub fn restore(&self, observations: &[SandboxObservation]) -> Result<bool, GuardError> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let mut all_exited = true;
            // Do not stop after the first live VM: every durable identity needs
            // its own pinned handles before managed traffic can resume.
            for observation in observations {
                all_exited &=
                    self.check_exited(std::slice::from_ref(observation), true, deadline)?;
            }
            Ok(all_exited)
        }
        /// Read the cgroup inode pinned before the durable Run receipt. No
        /// caller-selected filesystem path/PID and no guest-reported counters.
        pub fn metrics(
            &self,
            observation: &SandboxObservation,
        ) -> Result<super::super::metrics::CgroupCounters, GuardError> {
            let pinned = self.metrics_snapshot(observation)?;
            Self::read_metrics(&pinned, observation)
        }
        fn metrics_snapshot(
            &self,
            observation: &SandboxObservation,
        ) -> Result<PinnedSandbox, GuardError> {
            let map = self.sandboxes.try_lock().map_err(|_| GuardError::Unknown)?;
            let pinned = map
                .get(&observation.sandbox_id)
                .ok_or(GuardError::Unknown)?;
            if pinned.observation != *observation {
                return Err(GuardError::IdentityMismatch);
            }
            // dup pins the same kernel objects without any proc/cgroup I/O.
            // No filesystem read may hold the global lifecycle mutex: a stuck
            // metrics read must not prevent CLOSE or handle release.
            Ok(PinnedSandbox {
                observation: observation.clone(),
                cgroup: pinned.cgroup.try_clone()?,
                processes: pinned
                    .processes
                    .iter()
                    .map(|p| {
                        Ok(PinnedProcess {
                            identity: p.identity.clone(),
                            fd: p.fd.as_ref().map(OwnedFd::try_clone).transpose()?,
                        })
                    })
                    .collect::<Result<Vec<_>, GuardError>>()?,
            })
        }
        fn read_metrics(
            pinned: &PinnedSandbox,
            observation: &SandboxObservation,
        ) -> Result<super::super::metrics::CgroupCounters, GuardError> {
            use std::os::fd::AsRawFd;
            let still_live = || -> Result<(), GuardError> {
                let m = pinned.cgroup.metadata()?;
                if m.nlink() == 0
                    || m.dev() != observation.cgroup.device
                    || m.ino() != observation.cgroup.inode
                {
                    return Err(GuardError::IdentityMismatch);
                }
                for process in &pinned.processes {
                    let fd = process.fd.as_ref().ok_or(GuardError::Unknown)?;
                    let mut fds = [PollFd::new(fd, PollFlags::IN)];
                    if poll(
                        &mut fds,
                        Some(&Timespec {
                            tv_sec: 0,
                            tv_nsec: 0,
                        }),
                    )
                    .map_err(errno)?
                        != 0
                    {
                        return Err(GuardError::Unknown);
                    }
                    let path = PathBuf::from(format!("/proc/{}/cgroup", process.identity.pid));
                    let group = relative_cgroup_path(&parse_cgroup(&read_text(&path, 65536)?)?)?;
                    if group != observation.cgroup.relative_path
                        && !group
                            .strip_prefix(&observation.cgroup.relative_path)
                            .is_some_and(|v| v.starts_with('/'))
                    {
                        return Err(GuardError::IdentityMismatch);
                    }
                }
                Ok(())
            };
            still_live()?;
            // Optional capacity is observed from the same registered host
            // inode. Snapshot limits before the accounting and recheck them
            // afterwards; an incomplete hierarchy never erases base usage.
            let capacity = super::super::capacity::CapacityRead::begin(&pinned.cgroup).ok();
            let root = PathBuf::from(format!("/proc/self/fd/{}", pinned.cgroup.as_raw_fd()));
            // Controller-specific files are optional; bounded reads through
            // the pinned inode preserve the same identity as the base sample.
            let memory_stat = read_text(&root.join("memory.stat"), 65536).ok();
            let memory_events = read_text(&root.join("memory.events"), 65536).ok();
            let mut result = super::super::metrics::parse(
                &read_text(&root.join("cpu.stat"), 65536)?,
                &read_text(&root.join("memory.current"), 64)?,
                &read_text(&root.join("io.stat"), 65536)?,
                &read_text(&root.join("pids.current"), 64)?,
                memory_stat.as_deref(),
                memory_events.as_deref(),
            )?;
            if let Some((cpu, memory)) = capacity.and_then(|capacity| capacity.finish().ok()) {
                result.cpu_capacity_cores = cpu;
                result.memory_capacity_bytes = memory;
            }
            // Exit/migration during sampling invalidates the entire observation.
            still_live()?;
            Ok(result)
        }
        fn check_exited(
            &self,
            observations: &[SandboxObservation],
            restore: bool,
            deadline: std::time::Instant,
        ) -> Result<bool, GuardError> {
            // FDs are captured before the journal settles a Run. On guard
            // restart, the controller must reconstruct only durable identities.
            let mut map = self.sandboxes.lock().map_err(|_| GuardError::Unknown)?;
            for observation in observations {
                if std::time::Instant::now() >= deadline {
                    return Err(GuardError::Expired);
                }
                if !map.contains_key(&observation.sandbox_id) {
                    if !restore {
                        return Err(GuardError::Unknown);
                    }
                    let path = cgroup_filesystem_path(&observation.cgroup.relative_path)?;
                    let cgroup = File::open(path)?;
                    let metadata = cgroup.metadata()?;
                    if metadata.dev() != observation.cgroup.device
                        || metadata.ino() != observation.cgroup.inode
                    {
                        return Err(GuardError::IdentityMismatch);
                    }
                    let processes = observation
                        .processes
                        .iter()
                        .map(|p| pin_process(p, &self.profile, true))
                        .collect::<Result<Vec<_>, _>>()?;
                    map.insert(
                        observation.sandbox_id.clone(),
                        PinnedSandbox {
                            observation: observation.clone(),
                            cgroup,
                            processes,
                        },
                    );
                }
                let pinned = map
                    .get(&observation.sandbox_id)
                    .ok_or(GuardError::Unknown)?;
                if pinned.observation != *observation {
                    return Err(GuardError::IdentityMismatch);
                }
                for process in &pinned.processes {
                    if let Some(fd) = &process.fd {
                        let mut fds = [PollFd::new(fd, PollFlags::IN)];
                        if poll(
                            &mut fds,
                            Some(&Timespec {
                                tv_sec: 0,
                                tv_nsec: 0,
                            }),
                        )
                        .map_err(errno)?
                            == 0
                        {
                            return Ok(false);
                        }
                        if !fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP) {
                            return Err(GuardError::Unknown);
                        }
                    }
                }
                // The open cgroup directory pins the inode; a replacement at
                // the same path must never be confused with the observed group.
                let dir = pinned.cgroup.metadata()?;
                if dir.nlink() != 0 {
                    let path = PathBuf::from(format!(
                        "/proc/self/fd/{}/cgroup.events",
                        std::os::fd::AsRawFd::as_raw_fd(&pinned.cgroup)
                    ));
                    let events = read_text(&path, 4096)?;
                    if !events.lines().any(|v| v == "populated 0") {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
        pub fn terminate(
            &self,
            observations: &[SandboxObservation],
            deadline: std::time::Instant,
        ) -> Result<bool, GuardError> {
            if self.check_exited(observations, false, deadline)? {
                return Ok(true);
            }
            {
                use std::io::Write;
                let map = self.sandboxes.lock().map_err(|_| GuardError::Unknown)?;
                for observation in observations {
                    if std::time::Instant::now() >= deadline {
                        return Err(GuardError::Expired);
                    }
                    let pinned = map
                        .get(&observation.sandbox_id)
                        .ok_or(GuardError::Unknown)?;
                    if pinned.observation != *observation {
                        return Err(GuardError::IdentityMismatch);
                    }
                    if pinned.cgroup.metadata()?.nlink() != 0 {
                        let path = format!(
                            "/proc/self/fd/{}/cgroup.kill",
                            std::os::fd::AsRawFd::as_raw_fd(&pinned.cgroup)
                        );
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(path)?
                            .write_all(b"1")?;
                    }
                    for process in &pinned.processes {
                        if std::time::Instant::now() >= deadline {
                            return Err(GuardError::Expired);
                        }
                        if let Some(fd) = &process.fd {
                            match rustix::process::pidfd_send_signal(
                                fd,
                                rustix::process::Signal::KILL,
                            ) {
                                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                                Err(error) => return Err(errno(error)),
                            }
                        }
                    }
                }
            }
            self.check_exited(observations, false, deadline)
        }
        pub fn release_handles(
            &self,
            observations: &[SandboxObservation],
        ) -> Result<(), GuardError> {
            let mut map = self.sandboxes.lock().map_err(|_| GuardError::Unknown)?;
            for observation in observations {
                map.remove(&observation.sandbox_id);
            }
            Ok(())
        }
        pub fn mounts_absent(&self, launch: &LaunchBinding) -> Result<bool, GuardError> {
            let boot = read_text(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
            if boot.trim() != self.node.boot_id.to_string() {
                return Err(GuardError::IdentityMismatch);
            }
            // Native systemd service must run in the initial mount namespace.
            if std::fs::metadata("/proc/self/ns/mnt")?.ino()
                != std::fs::metadata("/proc/1/ns/mnt")?.ino()
            {
                return Err(GuardError::Invalid);
            }
            if let super::super::protocol::LaunchPurpose::Backup { stage, .. } = &launch.purpose
                && *stage != super::super::protocol::BackupStage::Seal
            {
                // Raw CSI publish may be a device node instead of a bind mount.
                // Both the pod symlink and pod-specific global target must be
                // gone; absence from mountinfo alone does not prove unpublish.
                for path in [
                    format!(
                        "/var/lib/kubelet/pods/{}/volumeDevices/kubernetes.io~csi/{}",
                        launch.pod_uid, launch.pv_name
                    ),
                    format!(
                        "/var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/publish/{}/{}",
                        launch.pv_name, launch.pod_uid
                    ),
                ] {
                    match std::fs::symlink_metadata(path) {
                        Ok(_) => return Ok(false),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Ok(!mountinfo_has_pod(
                &read_text(Path::new("/proc/1/mountinfo"), 4 * 1024 * 1024)?,
                launch.pod_uid,
            )?)
        }
    }
    #[cfg(test)]
    mod kernel_tests {
        use super::*;
        #[test]
        fn stalled_metrics_read_does_not_hold_lifecycle_handles_lock() -> anyhow::Result<()> {
            use std::{
                io::Write,
                os::unix::fs::OpenOptionsExt,
                sync::Arc,
                time::{Duration, Instant},
            };
            let directory = tempfile::tempdir()?;
            let cgroup = File::open(directory.path())?;
            rustix::fs::mkfifoat(
                &cgroup,
                "cpu.stat",
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )?;
            for (name, value) in [
                ("memory.current", "1024"),
                ("io.stat", "8:0 rbytes=2 wbytes=3"),
                ("pids.current", "1"),
                ("memory.stat", "anon invalid\nfile 2048"),
                ("memory.events", "oom 2\noom_kill 0"),
            ] {
                std::fs::write(directory.path().join(name), value)?;
            }
            let metadata = cgroup.metadata()?;
            let observation = SandboxObservation {
                sandbox_id: "b".repeat(64),
                cgroup: CgroupIdentity {
                    relative_path: "test-only".into(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
                processes: vec![],
                registered_at: Utc::now(),
            };
            let observer = Arc::new(HostObserver::test_unobserved(NodeBinding {
                cluster_epoch: uuid::Uuid::new_v4(),
                node_uid: uuid::Uuid::new_v4(),
                node_name: "metrics-lock-test".into(),
                boot_id: uuid::Uuid::new_v4(),
                profile_sha256: "a".repeat(64),
            }));
            observer
                .sandboxes
                .lock()
                .map_err(|_| anyhow::anyhow!("Metrics fixture handles lock is poisoned"))?
                .insert(
                    observation.sandbox_id.clone(),
                    PinnedSandbox {
                        observation: observation.clone(),
                        cgroup,
                        processes: vec![],
                    },
                );
            let (sample_observer, sample_observation) = (observer.clone(), observation.clone());
            let sampler = std::thread::spawn(move || sample_observer.metrics(&sample_observation));
            // The writer can open only once the real sampler has reached its
            // blocking read. No test-only callback bypasses the production path.
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut writer = loop {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
                    .open(directory.path().join("cpu.stat"))
                {
                    Ok(file) => break file,
                    Err(error)
                        if error.raw_os_error() == Some(rustix::io::Errno::NXIO.raw_os_error())
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let (released, receiver) = std::sync::mpsc::channel();
            let controller = std::thread::spawn(move || {
                let result = observer.release_handles(&[observation]);
                released
                    .send(result)
                    .map_err(|_| anyhow::anyhow!("Metrics fixture release receiver is closed"))
            });
            let release = receiver.recv_timeout(Duration::from_secs(1));
            // Always unblock and join both workers before asserting, including
            // the regression path where lifecycle release had to wait.
            writer.write_all(b"usage_usec 17\n")?;
            drop(writer);
            let sampled = sampler.join();
            let controlled = controller.join();
            let value = sampled.map_err(|_| anyhow::anyhow!("Metrics sampler panicked"))??;
            controlled.map_err(|_| anyhow::anyhow!("Metrics release controller panicked"))??;
            release??;
            assert_eq!(value.cpu_usage_usec, 17);
            assert_eq!(value.memory_bytes, 1024);
            assert_eq!(value.memory_anon_bytes, None);
            assert_eq!(value.memory_file_bytes, None);
            assert_eq!(value.memory_oom_events, Some(2));
            assert_eq!(value.memory_oom_kills, Some(0));
            assert_eq!(value.cpu_capacity_cores, None);
            assert_eq!(value.memory_capacity_bytes, None);
            Ok(())
        }
        #[test]
        #[ignore = "requires Linux and a complete read-only cgroup v2 mount, Docker --cgroupns=host"]
        fn actual_kernel_cgroup_counters_reject_pid_exit_and_changed_inode() -> anyhow::Result<()> {
            actual_kernel_cgroup_contract(false)
        }

        #[test]
        #[ignore = "requires Linux, Docker --cgroupns=host --cpus=0.75 --memory=268435456 and a complete read-only cgroup v2 mount"]
        fn actual_kernel_cgroup_capacity_uses_trusted_full_hierarchy() -> anyhow::Result<()> {
            actual_kernel_cgroup_contract(true)?;
            println!("NODEGUARD_TRUSTED_CAPACITY_REAL_KERNEL_VERIFIED");
            Ok(())
        }

        fn actual_kernel_cgroup_contract(capacity_required: bool) -> anyhow::Result<()> {
            use anyhow::Context;
            use std::os::fd::AsRawFd;

            let executable = std::fs::canonicalize("/usr/bin/sleep")
                .context("KERNEL_EXECUTABLE_CANONICALIZE")?;
            let file = PinnedFile {
                sha256: digest_file(&executable).context("KERNEL_EXECUTABLE_DIGEST")?,
                path: executable.clone(),
            };
            let other = PinnedFile {
                sha256: "0".repeat(64),
                path: "/test-no-executable".into(),
            };
            let profile = HostProfile {
                protocol: 1,
                runtime_handler: "kata-qemu".into(),
                containerd_version: "2.3.5".into(),
                qemu: file,
                virtiofs: other.clone(),
                shim: other.clone(),
                kata_configuration: other.clone(),
                containerd_configuration: other.clone(),
                kubelet_configuration: other.clone(),
                kubelet_environment: other,
                image_observation: None,
            };
            let mut child = std::process::Command::new(executable)
                .arg("20")
                .spawn()
                .context("KERNEL_PROCESS_SPAWN")?;
            let result = (|| {
                let identity =
                    proc_identity(child.id(), &profile).context("KERNEL_PROC_IDENTITY")?;
                let pinned = pin_process(&identity, &profile, false).context("KERNEL_PIDFD_PIN")?;
                let raw_group = read_text(
                    &PathBuf::from(format!("/proc/{}/cgroup", child.id())),
                    65536,
                )
                .context("KERNEL_CGROUP_READ")?;
                let group = parse_cgroup(&raw_group).context("KERNEL_CGROUP_PARSE")?;
                let relative = relative_cgroup_path(&group).context("KERNEL_CGROUP_RELATIVE")?;
                let path = cgroup_filesystem_path(&relative).context("KERNEL_CGROUP_PATH")?;
                let cgroup = File::open(path).context("KERNEL_CGROUP_OPEN")?;
                let m = cgroup.metadata().context("KERNEL_CGROUP_METADATA")?;
                if capacity_required {
                    let root = PathBuf::from(format!("/proc/self/fd/{}", cgroup.as_raw_fd()));
                    let cpu =
                        read_text(&root.join("cpu.stat"), 65536).context("KERNEL_CPU_STAT_READ")?;
                    println!(
                        "NODEGUARD_KERNEL_CORE_SCHED_FIELD_PRESENT={}",
                        cpu.lines().any(|line| {
                            line.split_ascii_whitespace().next()
                                == Some("core_sched.force_idle_usec")
                        })
                    );
                    let memory = read_text(&root.join("memory.current"), 64)
                        .context("KERNEL_MEMORY_CURRENT_READ")?;
                    let io =
                        read_text(&root.join("io.stat"), 65536).context("KERNEL_IO_STAT_READ")?;
                    let pids = read_text(&root.join("pids.current"), 64)
                        .context("KERNEL_PIDS_CURRENT_READ")?;
                    crate::nodeguard::metrics::parse(&cpu, &memory, &io, &pids, None, None)
                        .context("KERNEL_COUNTER_PARSE")?;
                }
                let obs = SandboxObservation {
                    sandbox_id: "a".repeat(64),
                    cgroup: CgroupIdentity {
                        relative_path: relative,
                        device: m.dev(),
                        inode: m.ino(),
                    },
                    processes: vec![identity],
                    registered_at: Utc::now(),
                };
                let node = NodeBinding {
                    cluster_epoch: uuid::Uuid::new_v4(),
                    node_uid: uuid::Uuid::new_v4(),
                    node_name: "linux-metrics-test".into(),
                    boot_id: uuid::Uuid::parse_str(
                        read_text(Path::new("/proc/sys/kernel/random/boot_id"), 64)
                            .context("KERNEL_BOOT_ID_READ")?
                            .trim(),
                    )
                    .context("KERNEL_BOOT_ID_PARSE")?,
                    profile_sha256: "a".repeat(64),
                };
                // This is a real kernel accounting/pidfd test, not a Kata
                // registration. Production capture still requires all roles.
                let observer = HostObserver {
                    profile,
                    node,
                    sandboxes: Mutex::new(BTreeMap::from([(
                        obs.sandbox_id.clone(),
                        PinnedSandbox {
                            observation: obs.clone(),
                            cgroup,
                            processes: vec![pinned],
                        },
                    )])),
                };
                let values = observer.metrics(&obs).context("KERNEL_METRICS_SAMPLE")?;
                assert!(
                    values.tasks >= 1 && values.memory_bytes > 0,
                    "KERNEL_BASE_COUNTER_ASSERT"
                );
                // The runner bounds this own disposable container. This tests
                // a real full kernel hierarchy, not synthetic controller files
                // or a production Kata registration/capacity certification.
                if capacity_required {
                    assert_eq!(
                        values.cpu_capacity_cores,
                        Some(0.75),
                        "KERNEL_CPU_CAPACITY_ASSERT"
                    );
                    assert_eq!(
                        values.memory_capacity_bytes,
                        Some(268_435_456),
                        "KERNEL_MEMORY_CAPACITY_ASSERT"
                    );
                }
                let mut wrong = obs.clone();
                wrong.cgroup.inode += 1;
                assert!(
                    matches!(observer.metrics(&wrong), Err(GuardError::IdentityMismatch)),
                    "KERNEL_CHANGED_INODE_REJECT_ASSERT"
                );
                child.kill().context("KERNEL_PROCESS_KILL")?;
                child.wait().context("KERNEL_PROCESS_WAIT")?;
                assert!(
                    matches!(observer.metrics(&obs), Err(GuardError::Unknown)),
                    "KERNEL_EXITED_PID_REJECT_ASSERT"
                );
                Ok::<_, anyhow::Error>(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            result
        }
        #[test]
        fn pidfd_tracks_exact_child_and_reports_kernel_exit_after_signal() -> anyhow::Result<()> {
            let executable = std::fs::canonicalize("/usr/bin/sleep")?;
            let qemu = PinnedFile {
                sha256: digest_file(&executable)?,
                path: executable.clone(),
            };
            let other = PinnedFile {
                sha256: "0".repeat(64),
                path: "/not-a-real-executable".into(),
            };
            let profile = HostProfile {
                protocol: 1,
                runtime_handler: "kata-qemu".into(),
                containerd_version: "2.3.5".into(),
                qemu,
                virtiofs: other.clone(),
                shim: other.clone(),
                kata_configuration: other.clone(),
                containerd_configuration: other.clone(),
                kubelet_configuration: other.clone(),
                kubelet_environment: other,
                image_observation: None,
            };
            let mut child = std::process::Command::new(executable)
                .arg("20")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            let identity = proc_identity(child.id(), &profile)?;
            let pinned = pin_process(&identity, &profile, false)?;
            let fd = pinned
                .fd
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("live pidfd missing"))?;
            let mut polls = [PollFd::new(fd, PollFlags::IN)];
            assert_eq!(
                poll(
                    &mut polls,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                )
                .map_err(errno)?,
                0
            );
            rustix::process::pidfd_send_signal(fd, rustix::process::Signal::KILL).map_err(errno)?;
            let mut polls = [PollFd::new(fd, PollFlags::IN)];
            assert_eq!(
                poll(
                    &mut polls,
                    Some(&Timespec {
                        tv_sec: 2,
                        tv_nsec: 0
                    })
                )
                .map_err(errno)?,
                1
            );
            assert!(polls[0].revents().contains(PollFlags::IN));
            assert!(!child.wait()?.success());
            let restored = pin_process(&identity, &profile, true)?;
            assert!(
                restored.fd.is_none(),
                "the recorded process no longer exists"
            );
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::HostObserver;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn systemd_cgroup_protocol_paths_are_relative_and_cannot_escape_mount() -> anyhow::Result<()> {
        let pod = uuid::Uuid::new_v4();
        let absolute = format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{}.slice/cri-containerd-{}.scope",
            pod.to_string().replace('-', "_"),
            "a".repeat(64)
        );
        let parsed = parse_cgroup(&format!("0::{absolute}\n"))?;
        assert!(pod_cgroup_root(pod, &parsed).is_ok());
        let relative = relative_cgroup_path(&parsed)?;
        assert!(!relative.starts_with('/'));
        assert_eq!(
            cgroup_filesystem_path(&relative)?,
            PathBuf::from(format!("/sys/fs/cgroup{absolute}"))
        );
        for invalid in [
            "/absolute",
            "../escape",
            "foo/../escape",
            "foo//bar",
            "foo/.",
            "",
        ] {
            assert!(cgroup_filesystem_path(invalid).is_err());
        }
        Ok(())
    }
    #[test]
    fn proc_and_mount_parsers_do_not_guess_around_malformed_identity() {
        let stat = format!("12 (name ) with space) S {} 999 0", vec!["0"; 18].join(" "));
        assert_eq!(parse_start_time(&stat).ok(), Some(999));
        assert!(parse_cgroup("0::/kubepods.slice/../other").is_err());
        assert!(parse_cgroup("1:cpu:/foo\n0::/bar").is_err());
        let pod = uuid::Uuid::new_v4();
        let line = format!(
            "10 1 8:1 / /var/lib/kubelet/pods/{pod}/volumes/foo/mount rw - ext4 /dev/vdb rw"
        );
        assert_eq!(mountinfo_has_pod(&line, pod).ok(), Some(true));
        assert_eq!(
            mountinfo_has_pod(&line, uuid::Uuid::new_v4()).ok(),
            Some(false)
        );
        let raw = format!(
            "10 1 8:1 / /var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/publish/pvc-test/{pod} rw - devtmpfs /dev/vdb rw"
        );
        assert_eq!(mountinfo_has_pod(&raw, pod).ok(), Some(true));
        assert_eq!(
            mountinfo_has_pod(&raw, uuid::Uuid::new_v4()).ok(),
            Some(false)
        );
        assert!(mountinfo_has_pod("malformed", pod).is_err());
    }
}
