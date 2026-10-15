//! Read-only image telemetry for one trusted node binding. Inventory and
//! filesystem reports are independent observations, not an atomic snapshot.
use super::{MetricsError, PrometheusMetrics, Result};
use chrono::Utc;
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use uuid::Uuid;

const MAX_BODY: usize = 256 * 1024;
const MAX_ROWS: usize = 216;
const MAX_FILESYSTEMS: usize = 16;
const STALE_SECONDS: f64 = 60.0;
const FUTURE_SECONDS: f64 = 5.0;

/// The caller obtains this identity from the current installation authorization
/// and node enrollment, and must check that authority again after backend I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeImageMetricBinding {
    pub cluster_epoch: Uuid,
    pub node_uid: Uuid,
    pub host_boot_id: Uuid,
    pub profile_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeImageMetricSource {
    RuntimeReported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeImageCompleteness {
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeImageAccuracy {
    ApproximateF64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeImageMetrics {
    pub evaluated_at_seconds: f64,
    pub source: NodeImageMetricSource,
    pub completeness: NodeImageCompleteness,
    pub accuracy: NodeImageAccuracy,
    pub inventory_observation_success: Option<bool>,
    pub filesystem_observation_success: Option<bool>,
    pub inventory: Option<NodeImageInventory>,
    pub filesystem: Option<NodeImageFilesystemReport>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeImageInventory {
    pub collector_replica: String,
    pub scraped_at_seconds: f64,
    pub observed_at_seconds: f64,
    pub count: f64,
    pub compressed_logical_bytes: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeImageFilesystemReport {
    pub collector_replica: String,
    pub scraped_at_seconds: f64,
    pub observed_at_seconds: f64,
    /// Only visible, validated series; UNKNOWN does not certify a complete set.
    pub filesystems: Vec<NodeImageFilesystem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeImageFilesystem {
    pub filesystem_id: String,
    pub reported_at_seconds: f64,
    pub used_bytes: Option<f64>,
    pub inodes_used: Option<f64>,
}

impl PrometheusMetrics {
    pub async fn node_image_status(
        &self,
        binding: &NodeImageMetricBinding,
    ) -> Result<NodeImageMetrics> {
        let _permit = self
            .inner
            .node_reads
            .try_acquire()
            .map_err(|_| MetricsError::Overloaded)?;
        let evaluated = Utc::now().timestamp();
        let query = expression(
            binding,
            &self.inner.config.deployment,
            &self.inner.config.replicas,
        )?;
        let mut url = self.inner.url.clone();
        let prefix = url
            .path()
            .strip_suffix("/query_range")
            .ok_or(MetricsError::Configuration)?;
        let path = format!("{prefix}/query");
        url.set_path(&path);
        let request = self.inner.client.post(url).form(&[
            ("query", query),
            ("time", evaluated.to_string()),
            ("timeout", "5s".into()),
            ("limit", (MAX_ROWS + 1).to_string()),
        ]);
        let bytes = self.request_bytes(request, MAX_BODY).await?;
        decode(
            &bytes,
            binding,
            &self.inner.config.deployment,
            &self.inner.config.replicas,
            evaluated,
            Utc::now().timestamp_millis() as f64 / 1000.0,
        )
    }
}

impl NodeImageMetricBinding {
    fn labels(&self, deployment: &str, up: bool) -> Result<BTreeMap<String, String>> {
        if !super::label(deployment)
            || self.cluster_epoch.is_nil()
            || self.node_uid.is_nil()
            || self.host_boot_id.is_nil()
            || !hex_digest(&self.profile_sha256)
        {
            return Err(MetricsError::Query);
        }
        let mut labels = BTreeMap::from([
            ("deployment".into(), deployment.into()),
            ("cluster_epoch".into(), self.cluster_epoch.to_string()),
            ("job".into(), format!("node-images-{}", self.node_uid)),
        ]);
        if up {
            labels.extend([
                ("scrape_node_uid".into(), self.node_uid.to_string()),
                ("scrape_host_boot_id".into(), self.host_boot_id.to_string()),
                ("scrape_profile_sha256".into(), self.profile_sha256.clone()),
            ]);
        } else {
            labels.extend([
                ("node_uid".into(), self.node_uid.to_string()),
                ("host_boot_id".into(), self.host_boot_id.to_string()),
                ("profile_sha256".into(), self.profile_sha256.clone()),
                ("source".into(), "RUNTIME_REPORTED".into()),
                ("completeness".into(), "UNKNOWN".into()),
            ]);
        }
        Ok(labels)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Metric {
    InventorySuccess,
    FilesystemSuccess,
    ObservedAt,
    InventoryCount,
    CompressedBytes,
    FilesystemReportedAt,
    FilesystemUsedBytes,
    FilesystemInodesUsed,
    Up,
}
impl Metric {
    const ALL: [Self; 9] = [
        Self::InventorySuccess,
        Self::FilesystemSuccess,
        Self::ObservedAt,
        Self::InventoryCount,
        Self::CompressedBytes,
        Self::FilesystemReportedAt,
        Self::FilesystemUsedBytes,
        Self::FilesystemInodesUsed,
        Self::Up,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::InventorySuccess => "sandbox_node_image_inventory_observation_success",
            Self::FilesystemSuccess => "sandbox_node_image_filesystem_observation_success",
            Self::ObservedAt => "sandbox_node_image_observed_at_seconds",
            Self::InventoryCount => "sandbox_node_image_inventory_count",
            Self::CompressedBytes => "sandbox_node_image_compressed_logical_bytes",
            Self::FilesystemReportedAt => "sandbox_node_image_filesystem_reported_at_seconds",
            Self::FilesystemUsedBytes => "sandbox_node_image_filesystem_used_bytes",
            Self::FilesystemInodesUsed => "sandbox_node_image_filesystem_inodes_used",
            Self::Up => "up",
        }
    }
    fn filesystem(self) -> bool {
        matches!(
            self,
            Self::FilesystemReportedAt | Self::FilesystemUsedBytes | Self::FilesystemInodesUsed
        )
    }
    fn valid(self, value: f64) -> bool {
        if !value.is_finite() || value < 0.0 {
            return false;
        }
        match self {
            Self::InventorySuccess | Self::FilesystemSuccess | Self::Up => {
                value == 0.0 || value == 1.0
            }
            Self::InventoryCount => value <= 1024.0 && value.fract() == 0.0,
            Self::ObservedAt | Self::FilesystemReportedAt => value > 0.0,
            Self::CompressedBytes | Self::FilesystemUsedBytes | Self::FilesystemInodesUsed => {
                value <= u64::MAX as f64
            }
        }
    }
}

fn expression(
    binding: &NodeImageMetricBinding,
    deployment: &str,
    replicas: &[String],
) -> Result<String> {
    let mut clauses = Vec::with_capacity(18);
    for metric in Metric::ALL {
        let labels = binding.labels(deployment, metric == Metric::Up)?;
        let selectors = labels
            .iter()
            .map(|(key, value)| format!("{key}=\"{value}\""))
            .chain(std::iter::once(format!(
                "collector_replica=~\"{}\"",
                replicas.join("|")
            )))
            .collect::<Vec<_>>()
            .join(",");
        let raw = format!("{}{{{selectors}}}", metric.name());
        clauses.push(format!(
            "label_replace({raw},\"sandbox_value_kind\",\"value\",\"\",\"\")"
        ));
        // Each timestamp() receives exactly one metric name. Restore that fixed
        // name before union so otherwise identical scalar labels remain distinct.
        clauses.push(format!("label_replace(label_replace(timestamp({raw}),\"__name__\",\"{}\",\"\",\"\"),\"sandbox_value_kind\",\"sampled_at\",\"\",\"\")", metric.name()));
    }
    // Default set matching ignores __name__, so different scalars would
    // otherwise collapse even though each timestamp mate restored its name.
    Ok(clauses.join(" or on(__name__,sandbox_value_kind,deployment,cluster_epoch,node_uid,host_boot_id,profile_sha256,source,completeness,filesystem_id,collector_replica,job,instance,scrape_node_uid,scrape_host_boot_id,scrape_profile_sha256) "))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    status: String,
    data: Vector,
    #[serde(default)]
    warnings: Vec<Value>,
    #[serde(default)]
    infos: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<Row>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    metric: BTreeMap<String, String>,
    value: (f64, String),
}

/// serde_json::Value normally overwrites duplicate object keys. Check every
/// object during the original parse before converting into the closed schema.
struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value.into())))
            }
            fn visit_string<E: de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = access.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, UniqueJson(value))) =
                    access.next_entry::<String, UniqueJson>()?
                {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

#[derive(Default)]
struct Pair {
    value: Option<f64>,
    sampled_at: Option<f64>,
}
type Samples = BTreeMap<(String, Metric, Option<String>), Pair>;

fn decode(
    bytes: &[u8],
    binding: &NodeImageMetricBinding,
    deployment: &str,
    replicas: &[String],
    evaluated: i64,
    now: f64,
) -> Result<NodeImageMetrics> {
    let UniqueJson(json) = serde_json::from_slice(bytes).map_err(|_| MetricsError::Response)?;
    let envelope: Envelope = serde_json::from_value(json).map_err(|_| MetricsError::Response)?;
    if envelope.status != "success"
        || envelope.data.result_type != "vector"
        || !envelope.warnings.is_empty()
        || !envelope.infos.is_empty()
        || envelope.data.result.len() > MAX_ROWS
    {
        return Err(MetricsError::Response);
    }
    let mut samples = Samples::new();
    let mut instances = BTreeMap::<String, String>::new();
    let mut filesystems = BTreeMap::<String, BTreeSet<String>>::new();
    for row in envelope.data.result {
        if !row.value.0.is_finite() || row.value.0 != evaluated as f64 {
            return Err(MetricsError::Response);
        }
        let labels = row.metric;
        let name = labels.get("__name__").ok_or(MetricsError::Response)?;
        let metric = Metric::ALL
            .into_iter()
            .find(|m| m.name() == name)
            .ok_or(MetricsError::Response)?;
        let replica = labels
            .get("collector_replica")
            .filter(|r| replicas.contains(r))
            .ok_or(MetricsError::Response)?;
        let instance = labels
            .get("instance")
            .filter(|s| {
                !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
            })
            .ok_or(MetricsError::Response)?;
        if instances
            .get(replica)
            .is_some_and(|existing| existing != instance)
        {
            return Err(MetricsError::Response);
        }
        instances.insert(replica.clone(), instance.clone());
        let kind = labels
            .get("sandbox_value_kind")
            .ok_or(MetricsError::Response)?;
        let mut expected = binding.labels(deployment, metric == Metric::Up)?;
        expected.insert("__name__".into(), name.clone());
        let filesystem = if metric.filesystem() {
            let id = labels
                .get("filesystem_id")
                .filter(|s| hex_digest(s))
                .ok_or(MetricsError::Response)?;
            let ids = filesystems.entry(replica.clone()).or_default();
            ids.insert(id.clone());
            if ids.len() > MAX_FILESYSTEMS {
                return Err(MetricsError::Response);
            }
            expected.insert("filesystem_id".into(), id.clone());
            Some(id.clone())
        } else {
            None
        };
        if labels.len() != expected.len() + 3
            || expected
                .iter()
                .any(|(key, value)| labels.get(key) != Some(value))
        {
            return Err(MetricsError::Response);
        }
        let number = row
            .value
            .1
            .parse::<f64>()
            .map_err(|_| MetricsError::Response)?;
        if !number.is_finite() {
            return Err(MetricsError::Response);
        }
        let pair = samples
            .entry((replica.clone(), metric, filesystem))
            .or_default();
        let slot = match kind.as_str() {
            "value" if metric.valid(number) => &mut pair.value,
            "sampled_at" if number > 0.0 => &mut pair.sampled_at,
            _ => return Err(MetricsError::Response),
        };
        if slot.replace(number).is_some() {
            return Err(MetricsError::Response);
        }
    }
    let inventory_cohort = cohort(&samples, replicas, Metric::InventorySuccess, evaluated, now);
    let filesystem_cohort = cohort(
        &samples,
        replicas,
        Metric::FilesystemSuccess,
        evaluated,
        now,
    );
    Ok(NodeImageMetrics {
        evaluated_at_seconds: evaluated as f64,
        source: NodeImageMetricSource::RuntimeReported,
        completeness: NodeImageCompleteness::Unknown,
        accuracy: NodeImageAccuracy::ApproximateF64,
        inventory_observation_success: inventory_cohort.as_ref().map(|c| c.success),
        filesystem_observation_success: filesystem_cohort.as_ref().map(|c| c.success),
        inventory: inventory_cohort.and_then(|c| inventory(&samples, c, now)),
        filesystem: filesystem_cohort
            .and_then(|c| filesystem_report(&samples, c, &filesystems, now)),
    })
}

struct Cohort<'a> {
    replica: &'a str,
    sampled_at: f64,
    success: bool,
}
fn cohort<'a>(
    samples: &Samples,
    replicas: &'a [String],
    flag: Metric,
    evaluated: i64,
    now: f64,
) -> Option<Cohort<'a>> {
    // Remote-write batches can expose a newer `up` before its flag/value
    // series. Choose the latest healthy scrape first. An incomplete newest
    // scrape is UNKNOWN, never permission to fall back to older success.
    let mut selected: Option<(&str, f64)> = None;
    let mut ordered = replicas.iter().collect::<Vec<_>>();
    ordered.sort();
    for replica in ordered {
        let Some(up) = samples.get(&(replica.clone(), Metric::Up, None)) else {
            continue;
        };
        let Some(up_time) = up.sampled_at else {
            continue;
        };
        if up.value != Some(1.0) || !fresh_sample(up_time, evaluated, now) {
            continue;
        }
        if selected.is_none_or(|(_, previous)| up_time > previous) {
            selected = Some((replica, up_time));
        }
    }
    let (replica, sampled_at) = selected?;
    let pair = samples.get(&(replica.into(), flag, None))?;
    if pair.sampled_at != Some(sampled_at) {
        return None;
    }
    Some(Cohort {
        replica,
        sampled_at,
        success: pair.value? == 1.0,
    })
}

fn field(
    samples: &Samples,
    cohort: &Cohort<'_>,
    metric: Metric,
    filesystem: Option<&str>,
) -> Option<f64> {
    let pair = samples.get(&(cohort.replica.into(), metric, filesystem.map(str::to_owned)))?;
    if pair.sampled_at != Some(cohort.sampled_at) {
        return None;
    }
    pair.value
}
fn inventory(samples: &Samples, cohort: Cohort<'_>, now: f64) -> Option<NodeImageInventory> {
    if !cohort.success {
        return None;
    }
    let observed = field(samples, &cohort, Metric::ObservedAt, None)?;
    if !fresh_original(observed, now) {
        return None;
    }
    Some(NodeImageInventory {
        collector_replica: cohort.replica.into(),
        scraped_at_seconds: cohort.sampled_at,
        observed_at_seconds: observed,
        count: field(samples, &cohort, Metric::InventoryCount, None)?,
        compressed_logical_bytes: field(samples, &cohort, Metric::CompressedBytes, None)?,
    })
}
fn filesystem_report(
    samples: &Samples,
    cohort: Cohort<'_>,
    ids: &BTreeMap<String, BTreeSet<String>>,
    now: f64,
) -> Option<NodeImageFilesystemReport> {
    if !cohort.success {
        return None;
    }
    let observed = field(samples, &cohort, Metric::ObservedAt, None)?;
    if !fresh_original(observed, now) {
        return None;
    }
    let mut filesystems = Vec::new();
    if let Some(ids) = ids.get(cohort.replica) {
        for id in ids {
            let reported = field(samples, &cohort, Metric::FilesystemReportedAt, Some(id))?;
            if !fresh_original(reported, now) {
                return None;
            }
            // A missing quantity is a legitimate independent runtime field, but
            // a visible stale/different-cohort quantity makes the report partial.
            let quantity = |metric| {
                if samples.contains_key(&(cohort.replica.into(), metric, Some(id.clone()))) {
                    field(samples, &cohort, metric, Some(id)).map(Some)
                } else {
                    Some(None)
                }
            };
            filesystems.push(NodeImageFilesystem {
                filesystem_id: id.clone(),
                reported_at_seconds: reported,
                used_bytes: quantity(Metric::FilesystemUsedBytes)?,
                inodes_used: quantity(Metric::FilesystemInodesUsed)?,
            });
        }
    }
    Some(NodeImageFilesystemReport {
        collector_replica: cohort.replica.into(),
        scraped_at_seconds: cohort.sampled_at,
        observed_at_seconds: observed,
        filesystems,
    })
}
fn fresh_sample(timestamp: f64, evaluated: i64, now: f64) -> bool {
    timestamp > 0.0 && timestamp <= evaluated as f64 && now - timestamp < STALE_SECONDS
}
fn fresh_original(timestamp: f64, now: f64) -> bool {
    timestamp > 0.0 && timestamp <= now + FUTURE_SECONDS && now - timestamp < STALE_SECONDS
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
#[path = "node_image_metrics_tests.rs"]
mod tests;
