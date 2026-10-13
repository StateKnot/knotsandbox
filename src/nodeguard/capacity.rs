//! Observed host cgroup capacity upper bounds, not reservations or free space.
//! An ancestor budget may be shared with siblings. No guest/configured Flavor
//! capacity is accepted, and unavailable controllers never become zero.
use super::GuardError;

fn number(value: &str) -> Result<u64, GuardError> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GuardError::Invalid);
    }
    value.parse().map_err(|_| GuardError::Invalid)
}

fn cpu_count(value: &str) -> Result<u64, GuardError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 65536 {
        return Err(GuardError::Invalid);
    }
    let (mut previous, mut count) = (None, 0_u64);
    for range in value.split(',') {
        let (first, last) = match range.split_once('-') {
            Some((first, last)) => (number(first)?, number(last)?),
            None => {
                let cpu = number(range)?;
                (cpu, cpu)
            }
        };
        if first > last || last > 1_048_575 || previous.is_some_and(|end| first <= end) {
            return Err(GuardError::Invalid);
        }
        count = count
            .checked_add(last - first + 1)
            .ok_or(GuardError::Invalid)?;
        previous = Some(last);
    }
    Ok(count)
}

fn cpu_limit(value: &str) -> Result<Option<f64>, GuardError> {
    if value.len() > 128 {
        return Err(GuardError::Invalid);
    }
    let fields: Vec<_> = value.split_ascii_whitespace().collect();
    if fields.len() != 2 {
        return Err(GuardError::Invalid);
    }
    let period = number(fields[1])?;
    if period == 0 {
        return Err(GuardError::Invalid);
    }
    if fields[0] == "max" {
        return Ok(None);
    }
    let quota = number(fields[0])?;
    if quota == 0 {
        return Err(GuardError::Invalid);
    }
    Ok(Some(quota as f64 / period as f64))
}

fn memory_limit(value: &str) -> Result<Option<u64>, GuardError> {
    if value.len() > 64 {
        return Err(GuardError::Invalid);
    }
    match value.trim() {
        "max" => Ok(None),
        value => number(value).map(Some),
    }
}

fn cpu_capacity(cpuset: Option<&str>, limits: &[Option<String>]) -> Option<f64> {
    let mut capacity = cpu_count(cpuset?).ok()? as f64;
    for limit in limits {
        if let Some(cores) = cpu_limit(limit.as_deref()?).ok()? {
            capacity = capacity.min(cores);
        }
    }
    Some(capacity)
}

fn memory_capacity(limits: &[Option<String>]) -> Option<u64> {
    let mut capacity = None;
    for limit in limits {
        if let Some(bytes) = memory_limit(limit.as_deref()?).ok()? {
            capacity = Some(capacity.map_or(bytes, |previous: u64| previous.min(bytes)));
        }
    }
    capacity
}

struct Limits {
    cpuset: Option<String>,
    cpu: Vec<Option<String>>,
    memory: Vec<Option<String>>,
}

fn stable_capacity(before: &Limits, after: &Limits) -> (Option<f64>, Option<u64>) {
    let cpu = (before.cpuset == after.cpuset && before.cpu == after.cpu)
        .then(|| cpu_capacity(after.cpuset.as_deref(), &after.cpu))
        .flatten();
    let memory = (before.memory == after.memory)
        .then(|| memory_capacity(&after.memory))
        .flatten();
    (cpu, memory)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::fs::{Mode, OFlags, fstatfs, openat};
    use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

    const CGROUP2_MAGIC: u64 = 0x6367_7270;
    const MAX_DEPTH: usize = 64;

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
    }

    fn identity(file: &File) -> Result<Identity, GuardError> {
        let metadata = file.metadata()?;
        if !metadata.is_dir()
            || metadata.nlink() == 0
            || fstatfs(file)
                .map_err(|error| GuardError::Io(error.into()))?
                .f_type as u64
                != CGROUP2_MAGIC
        {
            return Err(GuardError::IdentityMismatch);
        }
        Ok(Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn directory(parent: &File, name: &str) -> Result<File, GuardError> {
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| GuardError::Io(error.into()))
    }

    fn text(file: &File, name: &str, limit: usize) -> Result<String, GuardError> {
        let file = File::from(
            openat(
                file,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| GuardError::Io(error.into()))?,
        );
        if !file.metadata()?.is_file() {
            return Err(GuardError::Invalid);
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(GuardError::Invalid);
        }
        String::from_utf8(bytes).map_err(|_| GuardError::Invalid)
    }

    fn host_root() -> Result<File, GuardError> {
        // Production is a native host service in PID 1's mount namespace. The
        // dedicated read-only Linux test may use its own mount namespace, but
        // must retain the host cgroup namespace and complete cgroup mount.
        for namespace in ["cgroup", "mnt"] {
            if std::fs::read_link(format!("/proc/self/ns/{namespace}"))?
                != std::fs::read_link(format!("/proc/1/ns/{namespace}"))?
            {
                return Err(GuardError::IdentityMismatch);
            }
        }
        let file = File::open("/proc/self/mountinfo")?;
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(GuardError::Invalid);
        }
        let mountinfo = String::from_utf8(bytes).map_err(|_| GuardError::Invalid)?;
        if !complete_mount(&mountinfo) {
            return Err(GuardError::IdentityMismatch);
        }
        let parent = File::open("/sys/fs")?;
        directory(&parent, "cgroup")
    }

    fn complete_mount(value: &str) -> bool {
        let mut found = false;
        for line in value.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let Some(separator) = fields.iter().position(|field| *field == "-") else {
                return false;
            };
            if fields.len() < 10 || separator < 6 || fields.len() != separator + 4 {
                return false;
            }
            if fields[4] == "/sys/fs/cgroup" {
                if found || fields[3] != "/" || fields[separator + 1] != "cgroup2" {
                    return false;
                }
                found = true;
            } else if fields[4].starts_with("/sys/fs/cgroup/") {
                // An overmount may conceal an ancestor or replace controller
                // files even when the leaf inode itself is still pinned.
                return false;
            }
        }
        found
    }

    struct Level {
        file: File,
        identity: Identity,
    }
    pub(in crate::nodeguard) struct CapacityRead {
        levels: Vec<Level>,
        root: File,
        root_identity: Identity,
        before: Limits,
    }

    impl CapacityRead {
        pub(in crate::nodeguard) fn begin(leaf: &File) -> Result<Self, GuardError> {
            let root = host_root()?;
            let root_identity = identity(&root)?;
            let mut levels = Vec::new();
            let mut current = leaf.try_clone()?;
            loop {
                let current_identity = identity(&current)?;
                if current_identity.device != root_identity.device || levels.len() > MAX_DEPTH {
                    return Err(GuardError::IdentityMismatch);
                }
                if current_identity == root_identity {
                    break;
                }
                if levels
                    .iter()
                    .any(|level: &Level| level.identity == current_identity)
                {
                    return Err(GuardError::IdentityMismatch);
                }
                let parent = directory(&current, "..")?;
                levels.push(Level {
                    file: current,
                    identity: current_identity,
                });
                current = parent;
            }
            if levels.is_empty() {
                // The registered VM may not be the host's root cgroup.
                return Err(GuardError::IdentityMismatch);
            }
            let before = Self::limits(&levels)?;
            Ok(Self {
                levels,
                root,
                root_identity,
                before,
            })
        }

        fn limits(levels: &[Level]) -> Result<Limits, GuardError> {
            let mut cpu = Vec::with_capacity(levels.len());
            let mut memory = Vec::with_capacity(levels.len());
            for level in levels {
                if identity(&level.file)? != level.identity {
                    return Err(GuardError::IdentityMismatch);
                }
                cpu.push(text(&level.file, "cpu.max", 128).ok());
                memory.push(text(&level.file, "memory.max", 64).ok());
            }
            Ok(Limits {
                cpuset: text(&levels[0].file, "cpuset.cpus.effective", 65536).ok(),
                cpu,
                memory,
            })
        }

        pub(in crate::nodeguard) fn finish(self) -> Result<(Option<f64>, Option<u64>), GuardError> {
            // Verify both the pinned identities and current parent links. A
            // cgroup rename/reparent cannot silently change the denominator.
            if identity(&self.root)? != self.root_identity {
                return Err(GuardError::IdentityMismatch);
            }
            for (index, level) in self.levels.iter().enumerate() {
                let parent = directory(&level.file, "..")?;
                let expected = self
                    .levels
                    .get(index + 1)
                    .map_or(self.root_identity, |next| next.identity);
                if identity(&parent)? != expected {
                    return Err(GuardError::IdentityMismatch);
                }
            }
            let after = Self::limits(&self.levels)?;
            let capacity = stable_capacity(&self.before, &after);
            // Verify the fixed mount is still the same complete root. This
            // also rechecks namespaces after all controller reads.
            if identity(&host_root()?)? != self.root_identity {
                return Err(GuardError::IdentityMismatch);
            }
            Ok(capacity)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn capacity_mount_rejects_truncated_overmounted_and_ambiguous_roots() {
            let valid = "12 1 0:27 / /sys/fs/cgroup ro,nosuid - cgroup2 cgroup rw\n";
            assert!(complete_mount(valid));
            for invalid in [
                valid.replace(" / /sys", " /container /sys"),
                valid.replace("cgroup2", "tmpfs"),
                format!("{valid}{valid}"),
                format!("{valid}13 12 0:28 / /sys/fs/cgroup/foo ro - tmpfs tmpfs rw\n"),
                "malformed".into(),
            ] {
                assert!(!complete_mount(&invalid));
            }
        }
        #[test]
        fn capacity_chain_rejects_non_cgroup_inodes_without_erasing_accounting()
        -> anyhow::Result<()> {
            let directory = tempfile::tempdir()?;
            assert!(identity(&File::open(directory.path())?).is_err());
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) use linux::CapacityRead;

#[cfg(test)]
mod tests {
    use super::*;
    fn values(values: &[&str]) -> Vec<Option<String>> {
        values
            .iter()
            .map(|value| Some((*value).to_owned()))
            .collect()
    }
    #[test]
    fn host_capacity_uses_effective_cpuset_and_tightest_shared_ancestor_limits() {
        assert_eq!(
            cpu_capacity(
                Some("0-3,8,10-11\n"),
                &values(&["max 100000", "75000 100000", "200000 100000"])
            ),
            Some(0.75)
        );
        assert_eq!(
            cpu_capacity(Some("0,2\n"), &values(&["max 100000", "500000 100000"])),
            Some(2.0)
        );
        assert_eq!(
            cpu_capacity(
                Some("0-3"),
                &values(&["200000 50000", "150000 100000", "max 100000"])
            ),
            Some(1.5)
        );
        assert_eq!(
            memory_capacity(&values(&["max", "268435456", "536870912"])),
            Some(268435456)
        );
        assert_eq!(memory_capacity(&values(&["max", "max"])), None);
        assert_eq!(memory_capacity(&values(&["1024", "0"])), Some(0));
    }
    #[test]
    fn host_capacity_missing_invalid_and_unlimited_inputs_never_fabricate_zero() {
        for cpuset in [
            "",
            "0-2,2-4",
            "3,1",
            "2-1",
            "0,,1",
            "-1",
            "1-2-3",
            "1 2",
            "1048576",
            "18446744073709551616",
        ] {
            assert_eq!(
                cpu_capacity(Some(cpuset), &values(&["max 100000"])),
                None,
                "{cpuset}"
            );
        }
        for cpu in [
            "max",
            "max 0",
            "0 100000",
            "-1 100000",
            "100000 100000 extra",
            "18446744073709551616 100000",
        ] {
            assert_eq!(cpu_capacity(Some("0-3"), &values(&[cpu])), None, "{cpu}");
        }
        for memory in ["", "-1", "1 2", "18446744073709551616"] {
            assert_eq!(memory_capacity(&values(&[memory])), None, "{memory}");
        }
        assert_eq!(cpu_capacity(None, &values(&["75000 100000"])), None);
        assert_eq!(
            cpu_capacity(Some("0-3"), &[Some("75000 100000".into()), None]),
            None
        );
        assert_eq!(memory_capacity(&[Some("1024".into()), None]), None);
    }

    #[test]
    fn host_capacity_limit_changes_and_optional_failures_are_independent() {
        let before = Limits {
            cpuset: Some("0-3".into()),
            cpu: values(&["max 100000", "75000 100000"]),
            memory: values(&["max", "268435456"]),
        };
        let mut after = Limits {
            cpuset: before.cpuset.clone(),
            cpu: before.cpu.clone(),
            memory: before.memory.clone(),
        };
        assert_eq!(
            stable_capacity(&before, &after),
            (Some(0.75), Some(268435456))
        );
        after.cpu[1] = Some("50000 100000".into());
        assert_eq!(stable_capacity(&before, &after), (None, Some(268435456)));
        after.cpu = before.cpu.clone();
        after.cpuset = Some("0-1".into());
        assert_eq!(stable_capacity(&before, &after), (None, Some(268435456)));
        after.cpuset = before.cpuset.clone();
        after.memory[0] = None;
        assert_eq!(stable_capacity(&before, &after), (Some(0.75), None));
        after.cpu[0] = None;
        assert_eq!(stable_capacity(&before, &after), (None, None));
    }
}
