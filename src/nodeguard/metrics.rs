//! Kernel cgroup v2 accounting for the already-pinned Kata host processes.
//! Values include VMM/virtiofs overhead. They are not guest process counts,
//! guest RAM estimates, filesystem capacity, application health or death proof.
use super::GuardError;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, PartialEq, Eq)]
pub struct CgroupCounters {
    pub cpu_usage_usec: u64,
    pub cpu_throttled_periods: Option<u64>,
    pub cpu_throttled_usec: Option<u64>,
    pub memory_bytes: u64,
    pub memory_anon_bytes: Option<u64>,
    pub memory_file_bytes: Option<u64>,
    pub memory_oom_events: Option<u64>,
    pub memory_oom_kills: Option<u64>,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub tasks: u64,
}

fn number(value: &str) -> Result<u64, GuardError> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GuardError::Invalid);
    }
    value.parse().map_err(|_| GuardError::Invalid)
}
fn scalar(value: &str) -> Result<u64, GuardError> {
    number(value.trim())
}
fn stats(value: &str) -> Result<BTreeMap<&str, u64>, GuardError> {
    if value.len() > 65536 {
        return Err(GuardError::Invalid);
    }
    let mut values = BTreeMap::new();
    for line in value.lines() {
        let parts: Vec<_> = line.split_ascii_whitespace().collect();
        if parts.len() != 2
            || parts[0].is_empty()
            || !parts[0]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
            || values.insert(parts[0], number(parts[1])?).is_some()
        {
            return Err(GuardError::Invalid);
        }
    }
    Ok(values)
}

pub(super) fn parse(
    cpu: &str,
    memory: &str,
    io: &str,
    pids: &str,
    memory_stat: Option<&str>,
    memory_events: Option<&str>,
) -> Result<CgroupCounters, GuardError> {
    if io.len() > 65536 {
        return Err(GuardError::Invalid);
    }
    let mut devices = BTreeSet::new();
    let (mut read, mut written) = (0_u64, 0_u64);
    for line in io.lines() {
        let mut fields = line.split_ascii_whitespace();
        let device = fields.next().ok_or(GuardError::Invalid)?;
        let (major, minor) = device.split_once(':').ok_or(GuardError::Invalid)?;
        if !devices.insert((number(major)?, number(minor)?)) || devices.len() > 256 {
            return Err(GuardError::Invalid);
        }
        let mut values = BTreeMap::new();
        for field in fields {
            let (key, value) = field.split_once('=').ok_or(GuardError::Invalid)?;
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b"_.".contains(&b))
                || value.is_empty()
                || value.len() > 64
                || !value.bytes().all(|b| b.is_ascii_graphic())
                || values.insert(key, value).is_some()
            {
                return Err(GuardError::Invalid);
            }
        }
        read = read
            .checked_add(number(values.get("rbytes").ok_or(GuardError::Invalid)?)?)
            .ok_or(GuardError::Invalid)?;
        written = written
            .checked_add(number(values.get("wbytes").ok_or(GuardError::Invalid)?)?)
            .ok_or(GuardError::Invalid)?;
    }
    let cpu = stats(cpu)?;
    // These kernel interfaces are optional on older/controller-disabled
    // cgroups. Invalid or unreadable optional files must not erase the required
    // accounting, and a missing key must not become a fabricated zero.
    let memory_stat = memory_stat.and_then(|value| stats(value).ok());
    let memory_events = memory_events.and_then(|value| stats(value).ok());
    Ok(CgroupCounters {
        cpu_usage_usec: *cpu.get("usage_usec").ok_or(GuardError::Invalid)?,
        cpu_throttled_periods: cpu.get("nr_throttled").copied(),
        cpu_throttled_usec: cpu.get("throttled_usec").copied(),
        memory_bytes: scalar(memory)?,
        memory_anon_bytes: memory_stat
            .as_ref()
            .and_then(|values| values.get("anon").copied()),
        memory_file_bytes: memory_stat
            .as_ref()
            .and_then(|values| values.get("file").copied()),
        memory_oom_events: memory_events
            .as_ref()
            .and_then(|values| values.get("oom").copied()),
        memory_oom_kills: memory_events
            .as_ref()
            .and_then(|values| values.get("oom_kill").copied()),
        io_read_bytes: read,
        io_write_bytes: written,
        tasks: scalar(pids)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cgroup_accounting_preserves_real_zero_and_rejects_ambiguous_or_overflowing_counters()
    -> anyhow::Result<()> {
        let c = parse(
            "usage_usec 1250000\nuser_usec 900000\nsystem_usec 350000\n",
            "4096\n",
            "8:0 rbytes=300 wbytes=600 rios=1 wios=2 dbytes=0 dios=0\n8:16 rbytes=100 wbytes=50 rios=1 wios=1\n",
            "4\n",
            None,
            None,
        )?;
        assert_eq!(
            c,
            CgroupCounters {
                cpu_usage_usec: 1250000,
                cpu_throttled_periods: None,
                cpu_throttled_usec: None,
                memory_bytes: 4096,
                memory_anon_bytes: None,
                memory_file_bytes: None,
                memory_oom_events: None,
                memory_oom_kills: None,
                io_read_bytes: 400,
                io_write_bytes: 650,
                tasks: 4
            }
        );
        assert_eq!(
            parse("usage_usec 0\n", "0\n", "", "0\n", None, None)?.io_read_bytes,
            0
        );
        assert_eq!(
            parse(
                "usage_usec 1",
                "4096",
                "8:0 rbytes=1 wbytes=2 cost.usage=0 cost.wait=3 cost.indebt=0 cost.indelay=0",
                "4",
                None,
                None,
            )?
            .io_write_bytes,
            2
        );
        for bad in [
            "8:0 rbytes=1",
            "8:0 rbytes=1 wbytes=1 rbytes=2",
            "8:0 rbytes=1 wbytes=1\n8:0 rbytes=1 wbytes=1",
            "8:0 rbytes=18446744073709551615 wbytes=1\n8:1 rbytes=1 wbytes=1",
            "x:0 rbytes=1 wbytes=2",
            "8:0 rbytes=-1 wbytes=2",
        ] {
            assert!(
                parse("usage_usec 1", "1", bad, "1", None, None).is_err(),
                "{bad}"
            );
        }
        for bad in ["max", "-1", "1 2", "18446744073709551616", ""] {
            assert!(parse("usage_usec 1", bad, "", "1", None, None).is_err());
            assert!(parse("usage_usec 1", "1", "", bad, None, None).is_err());
        }
        assert!(parse("usage_usec 1\nusage_usec 2", "1", "", "1", None, None).is_err());
        assert!(parse("user_usec 1", "1", "", "1", None, None).is_err());
        Ok(())
    }

    #[test]
    fn optional_pressure_counters_keep_real_zero_missing_keys_and_independent_files()
    -> anyhow::Result<()> {
        let complete = parse(
            "usage_usec 17\nnr_periods 9\nnr_throttled 3\nthrottled_usec 2500000\n",
            "4096",
            "",
            "1",
            Some("anon 1024\nfile 2048\nshmem 512\n"),
            Some("low 0\nhigh 0\nmax 1\noom 2\noom_kill 0\noom_group_kill 0\n"),
        )?;
        assert_eq!(complete.cpu_throttled_periods, Some(3));
        assert_eq!(complete.cpu_throttled_usec, Some(2500000));
        assert_eq!(complete.memory_anon_bytes, Some(1024));
        assert_eq!(complete.memory_file_bytes, Some(2048));
        assert_eq!(complete.memory_oom_events, Some(2));
        assert_eq!(complete.memory_oom_kills, Some(0));
        // A valid partial file exposes its known key, never the absent one.
        let partial = parse(
            "usage_usec 17\nnr_throttled 0\n",
            "4096",
            "",
            "1",
            Some("anon 0\n"),
            Some("oom_kill 0\n"),
        )?;
        assert_eq!(partial.cpu_throttled_periods, Some(0));
        assert_eq!(partial.cpu_throttled_usec, None);
        assert_eq!(partial.memory_anon_bytes, Some(0));
        assert_eq!(partial.memory_file_bytes, None);
        assert_eq!(partial.memory_oom_events, None);
        assert_eq!(partial.memory_oom_kills, Some(0));
        for bad in [
            "anon -1\nfile 2048",
            "anon 1\nanon 2",
            "anon 18446744073709551616",
            "anon 1 2",
        ] {
            let counters = parse(
                "usage_usec 17",
                "4096",
                "",
                "1",
                Some(bad),
                Some("oom 2\noom_kill 0"),
            )?;
            assert_eq!(counters.memory_anon_bytes, None);
            assert_eq!(counters.memory_file_bytes, None);
            assert_eq!(counters.memory_bytes, 4096);
            assert_eq!(counters.memory_oom_events, Some(2));
        }
        for bad in [
            "oom -1",
            "oom 1\noom 2",
            "oom 18446744073709551616",
            "oom 1 2",
        ] {
            let counters = parse(
                "usage_usec 17",
                "4096",
                "",
                "1",
                Some("anon 1024\nfile 2048"),
                Some(bad),
            )?;
            assert_eq!(counters.memory_oom_events, None);
            assert_eq!(counters.memory_oom_kills, None);
            assert_eq!(counters.memory_anon_bytes, Some(1024));
            assert_eq!(counters.cpu_usage_usec, 17);
        }
        let oversized = format!("anon {}", "0".repeat(65536));
        let counters = parse("usage_usec 17", "4096", "", "1", Some(&oversized), None)?;
        assert_eq!(counters.memory_anon_bytes, None);
        assert_eq!(counters.cpu_usage_usec, 17);
        // cpu.stat remains the required, strictly validated source.
        assert!(
            parse(
                "usage_usec 17\nnr_throttled -1",
                "4096",
                "",
                "1",
                None,
                None
            )
            .is_err()
        );
        Ok(())
    }
}
