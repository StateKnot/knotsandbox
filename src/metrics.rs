//! Fixed Prometheus queries for a trusted runtime binding. This transport does
//! not authorize tenants or certify a collector; callers must do both and check
//! authority again after I/O. Missing or stale telemetry is never zero-filled.
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, sync::Semaphore};
use uuid::Uuid;

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_POINTS: i64 = 1441;
const STALE_SECONDS: f64 = 60.0;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MetricsError {
    #[error("INVALID_METRICS_CONFIGURATION")]
    Configuration,
    #[error("INVALID_METRICS_QUERY")]
    Query,
    #[error("METRICS_CREDENTIAL_UNAVAILABLE")]
    Credential,
    #[error("METRICS_BACKEND_UNAVAILABLE")]
    Unavailable,
    #[error("METRICS_BACKEND_OVERLOADED")]
    Overloaded,
    #[error("METRICS_BACKEND_REJECTED")]
    Rejected,
    #[error("METRICS_RESPONSE_INVALID")]
    Response,
}
type Result<T> = std::result::Result<T, MetricsError>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeMetric {
    VmCpuCores,
    VmCpuCapacityCores,
    VmCpuThrottledPeriodsPerSecond,
    VmCpuThrottledSecondsPerSecond,
    VmMemoryBytes,
    VmMemoryCapacityBytes,
    VmMemoryAnonBytes,
    VmMemoryFileBytes,
    VmMemoryOomEventsPerSecond,
    VmMemoryOomKillsPerSecond,
    VmIoReadBytesPerSecond,
    VmIoWriteBytesPerSecond,
    VmTasks,
}
impl RuntimeMetric {
    fn counter(&self) -> bool {
        matches!(
            self,
            Self::VmCpuCores
                | Self::VmCpuThrottledPeriodsPerSecond
                | Self::VmCpuThrottledSecondsPerSecond
                | Self::VmMemoryOomEventsPerSecond
                | Self::VmMemoryOomKillsPerSecond
                | Self::VmIoReadBytesPerSecond
                | Self::VmIoWriteBytesPerSecond
        )
    }
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::VmCpuCores => "sandbox_vm_cpu_seconds_total",
            Self::VmCpuCapacityCores => "sandbox_vm_cpu_capacity_cores",
            Self::VmCpuThrottledPeriodsPerSecond => "sandbox_vm_cpu_throttled_periods_total",
            Self::VmCpuThrottledSecondsPerSecond => "sandbox_vm_cpu_throttled_seconds_total",
            Self::VmMemoryBytes => "sandbox_vm_memory_bytes",
            Self::VmMemoryCapacityBytes => "sandbox_vm_memory_capacity_bytes",
            Self::VmMemoryAnonBytes => "sandbox_vm_memory_anon_bytes",
            Self::VmMemoryFileBytes => "sandbox_vm_memory_file_bytes",
            Self::VmMemoryOomEventsPerSecond => "sandbox_vm_memory_oom_events_total",
            Self::VmMemoryOomKillsPerSecond => "sandbox_vm_memory_oom_kills_total",
            Self::VmIoReadBytesPerSecond => "sandbox_vm_io_read_bytes_total",
            Self::VmIoWriteBytesPerSecond => "sandbox_vm_io_write_bytes_total",
            Self::VmTasks => "sandbox_vm_tasks",
        }
    }
    pub fn unit(&self) -> &'static str {
        match self {
            Self::VmCpuCores | Self::VmCpuCapacityCores => "cores",
            Self::VmCpuThrottledPeriodsPerSecond => "periods_per_second",
            Self::VmCpuThrottledSecondsPerSecond => "seconds_per_second",
            Self::VmMemoryBytes
            | Self::VmMemoryCapacityBytes
            | Self::VmMemoryAnonBytes
            | Self::VmMemoryFileBytes => "bytes",
            Self::VmMemoryOomEventsPerSecond | Self::VmMemoryOomKillsPerSecond => {
                "events_per_second"
            }
            Self::VmIoReadBytesPerSecond | Self::VmIoWriteBytesPerSecond => "bytes_per_second",
            Self::VmTasks => "tasks",
        }
    }
}

/// Expected identity comes from the current, authorized runtime permit. These
/// values are query constraints, not assertions that a VM or collector is live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeMetricBinding {
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub generation: i64,
    pub launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub node_uid: Uuid,
    pub host_boot_id: Uuid,
}
impl RuntimeMetricBinding {
    pub(crate) fn labels(&self, deployment: &str) -> Result<BTreeMap<String, String>> {
        if !label(deployment) {
            return Err(MetricsError::Query);
        }
        let mut labels = BTreeMap::new();
        for (key, value) in [
            ("tenant_id", self.tenant_id),
            ("project_id", self.project_id),
            ("instance_id", self.instance_id),
            ("launch_id", self.launch_id),
            ("cluster_epoch", self.cluster_epoch),
            ("node_uid", self.node_uid),
            ("host_boot_id", self.host_boot_id),
        ] {
            if value.is_nil() {
                return Err(MetricsError::Query);
            }
            labels.insert(key.into(), value.to_string());
        }
        if self.generation < 1 {
            return Err(MetricsError::Query);
        }
        labels.insert("generation".into(), self.generation.to_string());
        labels.insert("deployment".into(), deployment.into());
        Ok(labels)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MetricRange {
    start: i64,
    end: i64,
    step: i64,
}
impl MetricRange {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>, step_seconds: i64) -> Result<Self> {
        let now = Utc::now().timestamp();
        let (start, end) = (start.timestamp(), end.timestamp());
        if start <= 0
            || end < start
            || end > now
            || start < now - 90 * 86400
            || end - start > 7 * 86400
            || !(15..=3600).contains(&step_seconds)
            || (end - start) / step_seconds + 1 > MAX_POINTS
        {
            return Err(MetricsError::Query);
        }
        Ok(Self {
            start,
            end,
            step: step_seconds,
        })
    }
    fn points(&self) -> impl Iterator<Item = i64> {
        (self.start..=self.end).step_by(self.step as usize)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsBackendConfig {
    /// Instance-specific HTTP API prefix; no credentials or query parameters.
    pub endpoint: String,
    pub deployment: String,
    pub auth: MetricsAuthentication,
    pub ca_file: Option<PathBuf>,
    /// Explicit expected labels of independently scraping HA collectors.
    pub replicas: Vec<String>,
}
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MetricsAuthentication {
    Bearer {
        token_file: PathBuf,
    },
    Basic {
        username_file: PathBuf,
        password_file: PathBuf,
    },
}

#[derive(Clone)]
pub struct PrometheusMetrics {
    inner: Arc<Inner>,
}
struct Inner {
    client: Client,
    url: url::Url,
    config: MetricsBackendConfig,
    reads: Semaphore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SampleStatus {
    Fresh,
    Stale,
    Missing,
}
#[derive(Debug, Serialize)]
pub struct MetricPoint {
    pub evaluated_at: DateTime<Utc>,
    pub observed_at: Option<DateTime<Utc>>,
    pub value: Option<f64>,
    pub status: SampleStatus,
    pub collector_replica: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct MetricSeries {
    pub metric: RuntimeMetric,
    pub unit: &'static str,
    pub source: &'static str,
    pub stale_after_seconds: u32,
    pub points: Vec<MetricPoint>,
}

impl PrometheusMetrics {
    pub async fn new(config: MetricsBackendConfig) -> Result<Self> {
        let result = Self::build(config, true).await?;
        match &result.inner.config.auth {
            MetricsAuthentication::Bearer { token_file } => {
                secret(token_file).await?;
            }
            MetricsAuthentication::Basic {
                username_file,
                password_file,
            } => {
                if secret(username_file).await?.contains(':') {
                    return Err(MetricsError::Credential);
                }
                secret(password_file).await?;
            }
        }
        Ok(result)
    }
    async fn build(config: MetricsBackendConfig, https: bool) -> Result<Self> {
        let mut url = url::Url::parse(&config.endpoint).map_err(|_| MetricsError::Configuration)?;
        if (url.scheme() != "https"
            && (https || url.scheme() != "http" || url.host_str() != Some("127.0.0.1")))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path().contains('%')
            || !label(&config.deployment)
            || !(1..=2).contains(&config.replicas.len())
            || config.replicas.iter().any(|r| !label(r))
            || config.replicas.len() == 2 && config.replicas[0] == config.replicas[1]
        {
            return Err(MetricsError::Configuration);
        }
        let paths: Vec<_> = match &config.auth {
            MetricsAuthentication::Bearer { token_file } => vec![token_file],
            MetricsAuthentication::Basic {
                username_file,
                password_file,
            } => vec![username_file, password_file],
        };
        if paths.iter().any(|p| !p.is_absolute())
            || config.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
        {
            return Err(MetricsError::Configuration);
        }
        url.set_path(&format!(
            "{}/api/v1/query_range",
            url.path().trim_end_matches('/')
        ));
        let mut client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .https_only(https)
            .http1_only()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(4);
        if let Some(path) = &config.ca_file {
            let bytes = bounded_file(path, 256 * 1024, false).await?;
            let ca =
                reqwest::Certificate::from_pem(&bytes).map_err(|_| MetricsError::Configuration)?;
            client = client.add_root_certificate(ca);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                client: client.build().map_err(|_| MetricsError::Configuration)?,
                url,
                config,
                reads: Semaphore::new(8),
            }),
        })
    }
    pub async fn query(
        &self,
        binding: &RuntimeMetricBinding,
        metric: RuntimeMetric,
        range: MetricRange,
    ) -> Result<MetricSeries> {
        let _permit = self
            .inner
            .reads
            .try_acquire()
            .map_err(|_| MetricsError::Overloaded)?;
        let labels = binding.labels(&self.inner.config.deployment)?;
        let query = expression(&labels, metric);
        let mut request = self.inner.client.get(self.inner.url.clone()).query(&[
            ("query", query),
            ("start", range.start.to_string()),
            ("end", range.end.to_string()),
            ("step", range.step.to_string()),
            ("timeout", "5s".into()),
            ("limit", "5".into()),
        ]);
        match &self.inner.config.auth {
            MetricsAuthentication::Bearer { token_file } => {
                request = request.bearer_auth(secret(token_file).await?)
            }
            MetricsAuthentication::Basic {
                username_file,
                password_file,
            } => {
                let username = secret(username_file).await?;
                if username.contains(':') {
                    return Err(MetricsError::Credential);
                }
                request = request.basic_auth(username, Some(secret(password_file).await?));
            }
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| MetricsError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(
                if response.status().is_server_error()
                    || response.status() == StatusCode::TOO_MANY_REQUESTS
                {
                    MetricsError::Unavailable
                } else {
                    MetricsError::Rejected
                },
            );
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(MetricsError::Response);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| MetricsError::Unavailable)?
        {
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err(MetricsError::Response);
            }
            bytes.extend_from_slice(&chunk);
        }
        decode(&bytes, &labels, &self.inner.config.replicas, metric, range)
    }
}

fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
async fn bounded_file(path: &PathBuf, limit: usize, private: bool) -> Result<Vec<u8>> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    // Inspect the opened inode (projected Secrets use symlinks), but do not
    // allow a misconfigured FIFO path to block the filesystem thread pool.
    #[cfg(unix)]
    options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    let file = options
        .open(path)
        .await
        .map_err(|_| MetricsError::Credential)?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| MetricsError::Credential)?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(MetricsError::Credential);
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if !matches!(metadata.permissions().mode() & 0o777, 0o400 | 0o600) {
            return Err(MetricsError::Credential);
        }
    }
    #[cfg(not(unix))]
    if private {
        return Err(MetricsError::Configuration);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| MetricsError::Credential)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(MetricsError::Credential);
    }
    Ok(bytes)
}
async fn secret(path: &PathBuf) -> Result<String> {
    let bytes = bounded_file(path, 16384, true).await?;
    let value = String::from_utf8(bytes).map_err(|_| MetricsError::Credential)?;
    if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(MetricsError::Credential);
    }
    Ok(value)
}

fn expression(labels: &BTreeMap<String, String>, metric: RuntimeMetric) -> String {
    // All values are UUIDs, integers or a validated deployment identifier.
    let selectors = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{v}\""))
        .collect::<Vec<_>>()
        .join(",");
    let raw = format!("{}{{{selectors}}}", metric.name());
    let value = if metric.counter() {
        format!("rate({raw}[2m])")
    } else {
        raw.clone()
    };
    // One evaluation carries both the value and the *raw sample* timestamp.
    // Range API evaluation times alone would mask Prometheus lookback staleness.
    // Rate ignores stale markers within its range. Mask it by the live instant
    // selector, otherwise a removed target yields an orphan rate for two minutes.
    format!(
        "label_replace((({value}) and timestamp({raw})),\"sandbox_value_kind\",\"value\",\"\",\"\") or label_replace(timestamp({raw}),\"sandbox_value_kind\",\"observed_at\",\"\",\"\")"
    )
}

#[derive(Deserialize)]
struct Envelope {
    status: String,
    data: Data,
    #[serde(default)]
    warnings: Vec<String>,
    #[serde(default)]
    infos: Vec<String>,
}
#[derive(Deserialize)]
struct Data {
    #[serde(rename = "resultType")]
    kind: String,
    result: Vec<Series>,
}
#[derive(Deserialize)]
struct Series {
    metric: BTreeMap<String, String>,
    values: Vec<(f64, String)>,
}
type Samples = BTreeMap<i64, f64>;
fn decode(
    bytes: &[u8],
    labels: &BTreeMap<String, String>,
    replicas: &[String],
    metric: RuntimeMetric,
    range: MetricRange,
) -> Result<MetricSeries> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| MetricsError::Response)?;
    if envelope.status != "success"
        || envelope.data.kind != "matrix"
        || !envelope.warnings.is_empty()
        || !envelope.infos.is_empty()
        || envelope.data.result.len() > replicas.len() * 2
    {
        return Err(MetricsError::Response);
    }
    let mut streams: BTreeMap<(String, String), Samples> = BTreeMap::new();
    for series in envelope.data.result {
        if labels.iter().any(|(k, v)| series.metric.get(k) != Some(v))
            || series.metric.len() > labels.len() + 5
            || series.metric.iter().any(|(k, v)| {
                v.len() > 256
                    || (!labels.contains_key(k)
                        && ![
                            "collector_replica",
                            "sandbox_value_kind",
                            "job",
                            "instance",
                            "__name__",
                        ]
                        .contains(&k.as_str()))
            })
            || series
                .metric
                .get("__name__")
                .is_some_and(|n| n != metric.name())
            || series.values.len() > MAX_POINTS as usize
        {
            return Err(MetricsError::Response);
        }
        let replica = series
            .metric
            .get("collector_replica")
            .ok_or(MetricsError::Response)?
            .clone();
        let kind = series
            .metric
            .get("sandbox_value_kind")
            .ok_or(MetricsError::Response)?
            .clone();
        if !replicas.contains(&replica) || !["value", "observed_at"].contains(&kind.as_str()) {
            return Err(MetricsError::Response);
        }
        let mut values = BTreeMap::new();
        let mut last = None;
        for (time, value) in series.values {
            if !time.is_finite()
                || time.fract() != 0.0
                || time < range.start as f64
                || time > range.end as f64
                || (time as i64 - range.start) % range.step != 0
                || last.is_some_and(|t| time <= t)
            {
                return Err(MetricsError::Response);
            }
            let number = value.parse::<f64>().map_err(|_| MetricsError::Response)?;
            if !number.is_finite()
                || number < 0.0
                || (kind == "observed_at" && (number > time || number <= 0.0))
            {
                return Err(MetricsError::Response);
            }
            values.insert(time as i64, number);
            last = Some(time);
        }
        if streams.insert((replica, kind), values).is_some() {
            return Err(MetricsError::Response);
        }
    }
    let mut points = Vec::new();
    for time in range.points() {
        let mut best: Option<(f64, &str, Option<f64>)> = None;
        for replica in replicas {
            let observed = streams
                .get(&(replica.clone(), "observed_at".into()))
                .and_then(|s| s.get(&time));
            let value = streams
                .get(&(replica.clone(), "value".into()))
                .and_then(|s| s.get(&time))
                .copied();
            if value.is_some() && observed.is_none() {
                return Err(MetricsError::Response);
            }
            if let Some(&observed) = observed
                && best.is_none_or(|b| {
                    let usable = value.is_some() && time as f64 - observed <= STALE_SECONDS;
                    let previous_usable = b.2.is_some() && time as f64 - b.0 <= STALE_SECONDS;
                    usable && !previous_usable
                        || usable == previous_usable
                            && (observed > b.0 || observed == b.0 && replica.as_str() < b.1)
                })
            {
                best = Some((observed, replica, value));
            }
        }
        let (observed_at, value, status, replica) = if let Some((observed, replica, value)) = best {
            let stale = time as f64 - observed > STALE_SECONDS;
            (
                DateTime::from_timestamp_millis((observed * 1000.0) as i64),
                if stale { None } else { value },
                if stale {
                    SampleStatus::Stale
                } else if value.is_some() {
                    SampleStatus::Fresh
                } else {
                    SampleStatus::Missing
                },
                Some(replica.to_owned()),
            )
        } else {
            (None, None, SampleStatus::Missing, None)
        };
        points.push(MetricPoint {
            evaluated_at: DateTime::from_timestamp(time, 0).ok_or(MetricsError::Response)?,
            observed_at,
            value,
            status,
            collector_replica: replica,
        });
    }
    Ok(MetricSeries {
        metric,
        unit: metric.unit(),
        source: "HOST_VM_RUNTIME",
        stale_after_seconds: STALE_SECONDS as u32,
        points,
    })
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
