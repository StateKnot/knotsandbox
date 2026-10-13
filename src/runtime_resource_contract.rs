//! Provisioning-only resource validation for the fixed ordinary CPU baseline.
//! This is a controlled Quantity subset, not Kubernetes' general parser. CPU
//! accepts unsigned whole cores, whole millicores (`m`), or decimal cores with
//! one to three fractional digits. Byte resources accept unsigned integers with
//! no suffix, Ki/Mi/Gi/Ti, or k/M/G/T. Signs, exponent forms, fractional byte
//! quantities, rounding and saturation are unsupported. Input is at most 64
//! ASCII bytes and normalized values fit PostgreSQL's nonnegative BIGINT range.
//! These values are configuration, never measured/exclusive capacity, historical
//! attribution, a utilization denominator, or permission to release resources.

use std::collections::BTreeMap;

use crate::model::Flavor;
use k8s_openapi::{
    api::core::v1::{Pod, ResourceRequirements},
    apimachinery::pkg::api::resource::Quantity,
};

const MAX_VALUE: u64 = i64::MAX as u64;
const MAX_QUANTITY_BYTES: usize = 64;
const CPU_PROFILES: [Flavor; 3] = [Flavor::Cpu1Mem2, Flavor::Cpu2Mem4, Flavor::Cpu4Mem8];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ResourceError {
    #[error("unsupported controlled resource quantity")]
    Quantity,
    #[error("resource quantity exceeds the supported integer range")]
    Range,
    #[error("CPU quantity cannot be represented as whole millicores")]
    Precision,
    #[error("unsupported runtime resource key")]
    Key,
    #[error("resources differ from the fixed ordinary CPU baseline")]
    Baseline,
    #[error("resources require one ordinary container with explicit requests and limits")]
    Shape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuMillis(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemoryBytes(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EphemeralStorageBytes(u64);

/// The ordinary workload has identical requests and limits. Keep the three
/// dimensions distinct; disk storage must never become memory or compute quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkloadResources {
    cpu: CpuMillis,
    memory: MemoryBytes,
    ephemeral: EphemeralStorageBytes,
}

struct OverheadResources {
    cpu: CpuMillis,
    memory: MemoryBytes,
}

fn quantity_text(value: &str) -> Result<(), ResourceError> {
    if value.is_empty() || value.len() > MAX_QUANTITY_BYTES || !value.is_ascii() {
        return Err(ResourceError::Quantity);
    }
    Ok(())
}

fn integer(value: &str) -> Result<u64, ResourceError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ResourceError::Quantity);
    }
    value.parse().map_err(|_| ResourceError::Range)
}

fn bounded(value: Option<u64>) -> Result<u64, ResourceError> {
    value
        .filter(|n| *n <= MAX_VALUE)
        .ok_or(ResourceError::Range)
}

impl CpuMillis {
    fn parse(value: &str) -> Result<Self, ResourceError> {
        quantity_text(value)?;
        if let Some(millis) = value.strip_suffix('m') {
            return Ok(Self(bounded(Some(integer(millis)?))?));
        }
        let millis = if let Some((whole, fraction)) = value.split_once('.') {
            let whole = integer(whole)?;
            let fraction_value = integer(fraction)?;
            let scale = match fraction.len() {
                1 => 100,
                2 => 10,
                3 => 1,
                _ => return Err(ResourceError::Precision),
            };
            whole.checked_mul(1000).and_then(|n| {
                fraction_value
                    .checked_mul(scale)
                    .and_then(|f| n.checked_add(f))
            })
        } else {
            integer(value)?.checked_mul(1000)
        };
        Ok(Self(bounded(millis)?))
    }
}

fn bytes(value: &str) -> Result<u64, ResourceError> {
    quantity_text(value)?;
    for (suffix, factor) in [
        ("Ki", 1024),
        ("Mi", 1024_u64.pow(2)),
        ("Gi", 1024_u64.pow(3)),
        ("Ti", 1024_u64.pow(4)),
        ("k", 1000),
        ("M", 1000_u64.pow(2)),
        ("G", 1000_u64.pow(3)),
        ("T", 1000_u64.pow(4)),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return bounded(integer(number)?.checked_mul(factor));
        }
    }
    bounded(Some(integer(value)?))
}

impl MemoryBytes {
    fn parse(value: &str) -> Result<Self, ResourceError> {
        Ok(Self(bytes(value)?))
    }
}

impl WorkloadResources {
    pub(crate) fn baseline(
        cpu_millis: i64,
        memory_mib: i64,
        ephemeral_mib: i64,
    ) -> Result<Self, ResourceError> {
        if !CPU_PROFILES
            .iter()
            .any(|profile| profile.resources() == (cpu_millis, memory_mib))
            || !(128..=32768).contains(&ephemeral_mib)
        {
            return Err(ResourceError::Baseline);
        }
        let result = Self {
            cpu: CpuMillis(bounded(u64::try_from(cpu_millis).ok())?),
            memory: MemoryBytes(bounded(
                u64::try_from(memory_mib)
                    .ok()
                    .and_then(|n| n.checked_mul(1024_u64.pow(2))),
            )?),
            ephemeral: EphemeralStorageBytes(bounded(
                u64::try_from(ephemeral_mib)
                    .ok()
                    .and_then(|n| n.checked_mul(1024_u64.pow(2))),
            )?),
        };
        Ok(result)
    }

    pub(crate) fn requirements(self) -> ResourceRequirements {
        let resources = BTreeMap::from([
            (
                "cpu".to_owned(),
                Quantity(if self.cpu.0.is_multiple_of(1000) {
                    (self.cpu.0 / 1000).to_string()
                } else {
                    format!("{}m", self.cpu.0)
                }),
            ),
            (
                "memory".to_owned(),
                Quantity(canonical_bytes(self.memory.0)),
            ),
            (
                "ephemeral-storage".to_owned(),
                Quantity(canonical_bytes(self.ephemeral.0)),
            ),
        ]);
        ResourceRequirements {
            requests: Some(resources.clone()),
            limits: Some(resources),
            claims: None,
        }
    }

    fn parse(values: &BTreeMap<String, Quantity>) -> Result<Self, ResourceError> {
        if values
            .keys()
            .any(|key| !matches!(key.as_str(), "cpu" | "memory" | "ephemeral-storage"))
        {
            return Err(ResourceError::Key);
        }
        let get = |key| values.get(key).ok_or(ResourceError::Shape);
        let result = Self {
            cpu: CpuMillis::parse(&get("cpu")?.0)?,
            memory: MemoryBytes::parse(&get("memory")?.0)?,
            ephemeral: EphemeralStorageBytes(bytes(&get("ephemeral-storage")?.0)?),
        };
        if !result.memory.0.is_multiple_of(1024_u64.pow(2))
            || !result.ephemeral.0.is_multiple_of(1024_u64.pow(2))
        {
            return Err(ResourceError::Baseline);
        }
        Self::baseline(
            i64::try_from(result.cpu.0).map_err(|_| ResourceError::Range)?,
            i64::try_from(result.memory.0 / 1024_u64.pow(2)).map_err(|_| ResourceError::Range)?,
            i64::try_from(result.ephemeral.0 / 1024_u64.pow(2))
                .map_err(|_| ResourceError::Range)?,
        )
    }

    fn pod(pod: &Pod) -> Result<Self, ResourceError> {
        let spec = pod.spec.as_ref().ok_or(ResourceError::Shape)?;
        if spec.containers.len() != 1
            || spec.init_containers.is_some()
            || spec.ephemeral_containers.is_some()
            || spec.resources.is_some()
            || spec.resource_claims.is_some()
        {
            return Err(ResourceError::Shape);
        }
        let requirements = spec.containers[0]
            .resources
            .as_ref()
            .ok_or(ResourceError::Shape)?;
        if requirements.claims.is_some() {
            return Err(ResourceError::Key);
        }
        let requests = Self::parse(requirements.requests.as_ref().ok_or(ResourceError::Shape)?)?;
        let limits = Self::parse(requirements.limits.as_ref().ok_or(ResourceError::Shape)?)?;
        if requests != limits {
            return Err(ResourceError::Baseline);
        }
        Ok(requests)
    }
}

fn canonical_bytes(value: u64) -> String {
    for (suffix, factor) in [
        ("Ti", 1024_u64.pow(4)),
        ("Gi", 1024_u64.pow(3)),
        ("Mi", 1024_u64.pow(2)),
        ("Ki", 1024),
    ] {
        if value.is_multiple_of(factor) {
            return format!("{}{suffix}", value / factor);
        }
    }
    value.to_string()
}

pub(crate) fn validate_overhead(
    values: Option<&BTreeMap<String, Quantity>>,
) -> Result<(), ResourceError> {
    parse_overhead(values).map(|_| ())
}

fn parse_overhead(
    values: Option<&BTreeMap<String, Quantity>>,
) -> Result<OverheadResources, ResourceError> {
    // Absence here describes the complete supplied config's lack of overhead.
    // It must not be used to substitute zero for an unavailable remote object.
    let mut result = OverheadResources {
        cpu: CpuMillis(0),
        memory: MemoryBytes(0),
    };
    if let Some(values) = values {
        for (key, value) in values {
            match key.as_str() {
                "cpu" => {
                    result.cpu = CpuMillis::parse(&value.0)?;
                }
                "memory" => {
                    result.memory = MemoryBytes::parse(&value.0)?;
                }
                _ => return Err(ResourceError::Key),
            }
        }
    }
    Ok(result)
}

/// Called only when provisioning, never by stop/finalizer cleanup. This does
/// not certify the source, compare RuntimeClass versions, or bind historical
/// observations. Existing full Pod/identity validation must still be applied.
pub(crate) fn validate_provision_resources(pod: &Pod, expected: &Pod) -> Result<(), ResourceError> {
    let workload = WorkloadResources::pod(pod)?;
    if workload != WorkloadResources::pod(expected)? {
        return Err(ResourceError::Baseline);
    }
    let overhead = parse_overhead(pod.spec.as_ref().and_then(|spec| spec.overhead.as_ref()))?;
    bounded(workload.cpu.0.checked_add(overhead.cpu.0))?;
    bounded(workload.memory.0.checked_add(overhead.memory.0))?;
    Ok(())
}
