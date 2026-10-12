//! Owner installation observation only. This capability is sealed by live DB,
//! Kubernetes, nodeguard mTLS and independently scoped cloud reads; it does not
//! authorize a RESTORE writer, scheduler selection, volume or VM.
use super::storage_contract::{RESTORE_TOPOLOGY_KEY, RestoreStorageMapping};
use crate::{
    backup_host::node_binding,
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    cloud_fencing::node_topology::{AlibabaCloudNodeTopology, NodeTopologyCloudBinding},
    db::Database,
    node_enrollment::EnrollmentReceipt,
    nodeguard::protocol::{NodeBinding, valid_sha256},
    termination_client::{NodeguardClient, NodeguardCredentials},
};
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use k8s_openapi::api::{core::v1::Node, storage::v1::CSINode};
use kube::Api;
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

const MAX_TF_BYTES: usize = 1024 * 1024;
const TOTAL_BUDGET: Duration = Duration::from_secs(30);
const OBSERVATION_BUDGET: Duration = Duration::from_secs(10);
const DRIVER: &str = "diskplugin.csi.alibabacloud.com";
pub(crate) const CSI_TOPOLOGY_KEYS: [&str; 4] = [
    "alibabacloud.com/ecs-instance-id",
    RESTORE_TOPOLOGY_KEY,
    "topology.kubernetes.io/region",
    "topology.kubernetes.io/zone",
];
// Error categories deliberately exclude SQL/provider JSON, TF bytes and keys.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TopologyOwnerError {
    #[error("node topology installation requires the dedicated table owner")]
    Owner,
    #[error("node topology source authority or identity is invalid")]
    Authority,
    #[error("node topology Terraform inventory is invalid or unsupported")]
    Inventory,
    #[error("node topology actual Kubernetes registration differs from authority")]
    Kubernetes,
    #[error("node topology live nodeguard identity verification failed")]
    Nodeguard,
    #[error("node topology cloud observation failed or changed identity")]
    Cloud,
    #[error("node topology observation, authority or acknowledgement budget expired")]
    Expired,
    #[error(
        "node topology database publication failed; preserve the original proof for reconciliation"
    )]
    Database,
}
type Result<T> = std::result::Result<T, TopologyOwnerError>;
#[derive(Clone, Copy)]
pub(crate) struct NodeTopologyRequest {
    pub runtime_node_id: Uuid,
    pub enrollment_id: Uuid,
    pub restore_profile_id: Uuid,
}
// No Deserialize, field access, JSON constructor or alternate trusted flag.
pub(crate) struct VerifiedNodeTopology {
    id: Uuid,
    payload: Value,
    total_deadline: Instant,
    authority_deadline: Instant,
    observation_deadline: Instant,
    certified_until: DateTime<Utc>,
    observed_at: DateTime<Utc>,
}
impl VerifiedNodeTopology {
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }
    fn current(&self) -> Result<()> {
        let now = Instant::now();
        let wall = Utc::now();
        require(
            now < self.total_deadline
                && now < self.authority_deadline
                && now < self.observation_deadline
                && wall < self.certified_until
                && self.observed_at >= wall - ChronoDuration::seconds(10)
                && self.observed_at <= wall + ChronoDuration::seconds(2),
            TopologyOwnerError::Expired,
        )
    }
}
// Returning a persisted historical fact does not turn it into current authority.
pub(crate) struct PersistedNodeTopology {
    row: Value,
}
impl PersistedNodeTopology {
    pub(crate) fn row(&self) -> &Value {
        &self.row
    }
}
fn require(ok: bool, error: TopologyOwnerError) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn micros(t: DateTime<Utc>) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp_micros(t.timestamp_micros()).ok_or(TopologyOwnerError::Authority)
}
fn date(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}
fn timestamp(value: &Value) -> Result<DateTime<Utc>> {
    let text = value.as_str().ok_or(TopologyOwnerError::Database)?;
    let body = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))
        .ok_or(TopologyOwnerError::Database)?;
    require(
        (20..=35).contains(&text.len())
            && body.is_ascii()
            && body.len() >= 19
            && body.as_bytes()[4] == b'-'
            && body.as_bytes()[7] == b'-'
            && body.as_bytes()[10] == b'T'
            && body.as_bytes()[13] == b':'
            && body.as_bytes()[16] == b':'
            && [(11, 23), (14, 59), (17, 59)].iter().all(|(start, max)| {
                body.get(*start..*start + 2).is_some_and(|part| {
                    part.bytes().all(|v| v.is_ascii_digit())
                        && part.parse::<u8>().is_ok_and(|v| v <= *max)
                })
            })
            && body.as_bytes()[..4].iter().all(u8::is_ascii_digit)
            && (body.len() == 19
                || (body.as_bytes()[19] == b'.'
                    && (21..=26).contains(&body.len())
                    && body.as_bytes()[20..].iter().all(u8::is_ascii_digit))),
        TopologyOwnerError::Database,
    )?;
    DateTime::parse_from_rfc3339(text)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| TopologyOwnerError::Database)
}
fn persisted_matches(row: &Value, payload: &Value) -> Result<()> {
    let fields = payload.as_object().ok_or(TopologyOwnerError::Database)?;
    let actual = row.as_object().ok_or(TopologyOwnerError::Database)?;
    require(
        fields.len() == 15 && actual.len() == 16 && actual.contains_key("recorded_at"),
        TopologyOwnerError::Database,
    )?;
    for (key, expected) in fields {
        let value = actual.get(key).ok_or(TopologyOwnerError::Database)?;
        let same = if ["observed_at", "reviewed_at", "certified_until"].contains(&key.as_str()) {
            timestamp(value)? == timestamp(expected)?
        } else {
            value == expected
        };
        require(same, TopologyOwnerError::Database)?;
    }
    let recorded = timestamp(
        actual
            .get("recorded_at")
            .ok_or(TopologyOwnerError::Database)?,
    )?;
    require(
        recorded >= timestamp(&payload["observed_at"])? - ChronoDuration::seconds(2)
            && recorded <= Utc::now() + ChronoDuration::seconds(2),
        TopologyOwnerError::Database,
    )
}
fn visible(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && v.bytes().all(|b| b.is_ascii_graphic())
}
fn canonical_uuid(v: Option<&str>) -> Result<Uuid> {
    let text = v.ok_or(TopologyOwnerError::Kubernetes)?;
    let id = Uuid::parse_str(text).map_err(|_| TopologyOwnerError::Kubernetes)?;
    require(
        !id.is_nil() && id.to_string() == text,
        TopologyOwnerError::Kubernetes,
    )?;
    Ok(id)
}
async fn owner(database: &Database) -> Result<()> {
    let ok:bool=sqlx::query_scalar("SELECT count(*)=6 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY(ARRAY['restore_node_topology_receipts','runtime_nodes','runtime_node_enrollments','platform_configuration','backup_profiles','restore_profile_certifications'])")
        .fetch_one(&database.pool).await.map_err(|_|TopologyOwnerError::Owner)?;
    require(ok, TopologyOwnerError::Owner)
}

#[derive(sqlx::FromRow)]
struct SourceRow {
    cluster_epoch: Uuid,
    safe_mode: bool,
    runtime_node_id: Uuid,
    node_epoch: Uuid,
    node_uid: Uuid,
    node_name: String,
    boot_id: Uuid,
    profile_sha256: String,
    account_id: String,
    region: String,
    instance_id: String,
    private_ip: String,
    guard_port: i32,
    node_enabled: bool,
    enrollment_id: Uuid,
    enrollment_epoch: Uuid,
    enrollment_node_id: Uuid,
    enrollment_receipt: Value,
    artifact_sha256: String,
    terraform_output_sha256: String,
    certification_report_sha256: String,
    enrollment_registered_at: DateTime<Utc>,
    enrollment_reviewed_at: DateTime<Utc>,
    enrollment_expires_at: DateTime<Utc>,
    profile_id: Uuid,
    profile_epoch: Uuid,
    profile_enabled: bool,
    settings: Value,
    backup_certification_sha256: String,
    backup_certified_until: DateTime<Utc>,
    restore_epoch: Uuid,
    restore_backup_sha256: String,
    restore_report_sha256: String,
    restore_report: Value,
    storage_mappings: Value,
    restore_reviewed_at: DateTime<Utc>,
    restore_certified_until: DateTime<Utc>,
    db_now: DateTime<Utc>,
}
struct Source {
    node: NodeBinding,
    request: NodeTopologyRequest,
    private_ip: Ipv4Addr,
    guard_port: u16,
    account_id: String,
    region: String,
    instance_id: String,
    deployment: String,
    oidc_issuer: String,
    oidc_provider_arn: String,
    kms_key_id: String,
    certification_sha256: String,
    raw_tf_sha256: String,
    canonical_tf_sha256: String,
    zones: Vec<String>,
    reviewed_at: DateTime<Utc>,
    certified_until: DateTime<Utc>,
    authority_deadline: Instant,
    pin: Value,
}
impl SourceRow {
    fn validate(self, request: NodeTopologyRequest, began: Instant) -> Result<Source> {
        require(
            !self.safe_mode
                && self.node_enabled
                && self.profile_enabled
                && !self.cluster_epoch.is_nil()
                && self.cluster_epoch == self.node_epoch
                && self.cluster_epoch == self.enrollment_epoch
                && self.cluster_epoch == self.profile_epoch
                && self.cluster_epoch == self.restore_epoch
                && self.runtime_node_id == request.runtime_node_id
                && self.enrollment_id == request.enrollment_id
                && self.profile_id == request.restore_profile_id
                && self.enrollment_node_id == self.runtime_node_id
                && self.restore_backup_sha256 == self.backup_certification_sha256,
            TopologyOwnerError::Authority,
        )?;
        let binding = NodeBinding {
            cluster_epoch: self.cluster_epoch,
            node_uid: self.node_uid,
            node_name: self.node_name.clone(),
            boot_id: self.boot_id,
            profile_sha256: self.profile_sha256.clone(),
        };
        let private_ip: Ipv4Addr = self
            .private_ip
            .parse()
            .map_err(|_| TopologyOwnerError::Authority)?;
        let cloud: BackupCloudSettings = serde_json::from_value(self.settings.clone())
            .map_err(|_| TopologyOwnerError::Authority)?;
        cloud
            .validate()
            .map_err(|_| TopologyOwnerError::Authority)?;
        require(
            binding.validate()
                && private_ip.is_private()
                && private_ip.to_string() == self.private_ip
                && self.guard_port == 9444
                && cloud.account_id == self.account_id
                && cloud.region == self.region
                && [
                    self.artifact_sha256.as_str(),
                    self.terraform_output_sha256.as_str(),
                    self.certification_report_sha256.as_str(),
                    self.restore_report_sha256.as_str(),
                    self.backup_certification_sha256.as_str(),
                ]
                .iter()
                .all(|v| valid_sha256(v)),
            TopologyOwnerError::Authority,
        )?;
        let receipt: EnrollmentReceipt = serde_json::from_value(self.enrollment_receipt.clone())
            .map_err(|_| TopologyOwnerError::Authority)?;
        // Do not rely on permissive UUID/time deserialization for identity keys.
        let raw = &self.enrollment_receipt;
        require(
            raw.as_object().is_some_and(|v| v.len() == 16)
                && raw.get("protocol").is_some_and(|v| v.as_u64() == Some(1))
                && raw
                    .get("guard_port")
                    .is_some_and(|v| v.as_u64() == Some(9444))
                && raw.get("node")
                    == Some(
                        &serde_json::to_value(&binding)
                            .map_err(|_| TopologyOwnerError::Authority)?,
                    )
                && raw.get("enrollment_id") == Some(&json!(self.enrollment_id))
                && raw.get("runtime_node_id") == Some(&json!(self.runtime_node_id))
                && receipt.protocol == 1
                && receipt.node == binding
                && receipt.enrollment_id == self.enrollment_id
                && receipt.runtime_node_id == self.runtime_node_id
                && receipt.cloud_account_id == self.account_id
                && receipt.region == self.region
                && receipt.cloud_instance_id == self.instance_id
                && receipt.private_ip == IpAddr::V4(private_ip)
                && receipt.guard_port == 9444
                && receipt.enabled
                && receipt.artifact_sha256 == self.artifact_sha256
                && receipt.terraform_output_sha256 == self.terraform_output_sha256
                && receipt.certification_report_sha256 == self.certification_report_sha256
                && receipt.registered_at == self.enrollment_registered_at
                && !receipt.certification_id.is_empty()
                && receipt.certification_id.len() <= 128
                && receipt
                    .certification_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            TopologyOwnerError::Authority,
        )?;
        let mappings: Vec<RestoreStorageMapping> =
            serde_json::from_value(self.storage_mappings.clone())
                .map_err(|_| TopologyOwnerError::Authority)?;
        require(
            !mappings.is_empty()
                && mappings.len() <= 64
                && serde_json::to_value(&mappings).map_err(|_| TopologyOwnerError::Authority)?
                    == self.storage_mappings,
            TopologyOwnerError::Authority,
        )?;
        let first = mappings.first().ok_or(TopologyOwnerError::Authority)?;
        let zones = first.topology.zone_ids.clone();
        for mapping in &mappings {
            mapping
                .validate()
                .map_err(|_| TopologyOwnerError::Authority)?;
            require(
                mapping.account_id == self.account_id
                    && mapping.region == self.region
                    && mapping.deployment == cloud.deployment
                    && mapping.workspace_kms_key_id == first.workspace_kms_key_id
                    && mapping.topology.zone_ids == zones,
                TopologyOwnerError::Authority,
            )?;
        }
        let report_binding = self
            .restore_report
            .get("bindings")
            .ok_or(TopologyOwnerError::Authority)?;
        require(
            self.restore_report
                .get("protocol")
                .is_some_and(|v| v.as_u64() == Some(1))
                && report_binding.as_object().is_some_and(|v| v.len() == 10)
                && report_binding.get("profile_id") == Some(&json!(self.profile_id))
                && report_binding.get("cluster_epoch") == Some(&json!(self.cluster_epoch))
                && report_binding.get("backup_certification_sha256")
                    == Some(&json!(self.backup_certification_sha256))
                && report_binding.get("storage_mappings") == Some(&self.storage_mappings)
                && report_binding.get("account_id") == Some(&json!(self.account_id))
                && report_binding.get("region") == Some(&json!(self.region))
                && report_binding.get("deployment") == Some(&json!(cloud.deployment))
                && report_binding.get("workspace_kms_key_id")
                    == Some(&json!(first.workspace_kms_key_id))
                && report_binding
                    .get("versions_lock_sha256")
                    .and_then(Value::as_str)
                    == Some(sha(include_bytes!("../deploy/cluster/versions.lock.json")).as_str()),
            TopologyOwnerError::Authority,
        )?;
        let canonical_tf_sha256 = report_binding
            .get("infrastructure_sha256")
            .and_then(Value::as_str)
            .filter(|v| valid_sha256(v))
            .ok_or(TopologyOwnerError::Authority)?
            .to_owned();
        let certified_until = [
            self.enrollment_expires_at,
            self.restore_certified_until,
            self.backup_certified_until,
            self.restore_reviewed_at + ChronoDuration::days(30),
        ]
        .into_iter()
        .min()
        .ok_or(TopologyOwnerError::Authority)?;
        require(
            self.restore_reviewed_at <= self.db_now + ChronoDuration::seconds(2)
                && self.enrollment_reviewed_at <= self.db_now + ChronoDuration::seconds(2)
                && self.enrollment_reviewed_at < self.enrollment_expires_at
                && self.restore_reviewed_at < certified_until
                && self.db_now < certified_until,
            TopologyOwnerError::Expired,
        )?;
        let ttl = (certified_until - self.db_now)
            .to_std()
            .map_err(|_| TopologyOwnerError::Expired)?;
        // Budget starts before BEGIN, includes row query/validation/COMMIT ACK.
        let authority_deadline = began + ttl.min(TOTAL_BUDGET);
        require(
            Instant::now() < authority_deadline,
            TopologyOwnerError::Expired,
        )?;
        let pin = json!({"node":binding,"private_ip":self.private_ip,"guard_port":self.guard_port,
            "account_id":self.account_id,"region":self.region,"instance_id":self.instance_id,
            "enrollment":self.enrollment_receipt,"settings":self.settings,
            "enrollment_reviewed_at":date(self.enrollment_reviewed_at),
            "enrollment_expires_at":date(self.enrollment_expires_at),
            "restore_report":self.restore_report,"restore_report_sha256":self.restore_report_sha256,
            "restore_reviewed_at":date(self.restore_reviewed_at),
            "restore_certified_until":date(self.restore_certified_until),
            "backup_certification_sha256":self.backup_certification_sha256,
            "backup_certified_until":date(self.backup_certified_until)});
        Ok(Source {
            node: binding,
            request,
            private_ip,
            guard_port: 9444,
            account_id: self.account_id,
            region: self.region,
            instance_id: self.instance_id,
            deployment: cloud.deployment,
            oidc_issuer: cloud.issuer,
            oidc_provider_arn: cloud.oidc_provider_arn,
            kms_key_id: first.workspace_kms_key_id.clone(),
            certification_sha256: self.restore_report_sha256,
            raw_tf_sha256: self.terraform_output_sha256,
            canonical_tf_sha256,
            zones,
            reviewed_at: self.restore_reviewed_at,
            certified_until,
            authority_deadline,
            pin,
        })
    }
}
async fn load_source(database: &Database, request: NodeTopologyRequest) -> Result<Source> {
    require(
        !request.runtime_node_id.is_nil()
            && !request.enrollment_id.is_nil()
            && !request.restore_profile_id.is_nil(),
        TopologyOwnerError::Authority,
    )?;
    let began = Instant::now();
    let mut tx = database
        .pool
        .begin()
        .await
        .map_err(|_| TopologyOwnerError::Database)?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| TopologyOwnerError::Database)?;
    let row:SourceRow=sqlx::query_as("SELECT pc.cluster_epoch,pc.safe_mode,n.id runtime_node_id,n.cluster_epoch node_epoch,n.node_uid,n.node_name,n.boot_id,n.profile_sha256,n.cloud_account_id account_id,n.region,n.cloud_instance_id instance_id,host(n.private_ip) private_ip,n.guard_port,n.enabled node_enabled,e.id enrollment_id,e.cluster_epoch enrollment_epoch,e.runtime_node_id enrollment_node_id,e.receipt enrollment_receipt,e.artifact_sha256,e.terraform_output_sha256,e.certification_report_sha256,e.registered_at enrollment_registered_at,e.certification_reviewed_at enrollment_reviewed_at,e.certification_expires_at enrollment_expires_at,bp.id profile_id,bp.cluster_epoch profile_epoch,bp.enabled profile_enabled,bp.settings,bp.certification_sha256 backup_certification_sha256,bp.certified_until backup_certified_until,rc.cluster_epoch restore_epoch,rc.backup_certification_sha256 restore_backup_sha256,rc.report_sha256 restore_report_sha256,rc.report restore_report,rc.storage_mappings,rc.reviewed_at restore_reviewed_at,rc.certified_until restore_certified_until,clock_timestamp() db_now FROM public.platform_configuration pc JOIN public.runtime_nodes n ON n.id=$1 JOIN public.runtime_node_enrollments e ON e.id=$2 AND e.runtime_node_id=n.id JOIN public.backup_profiles bp ON bp.id=$3 JOIN public.restore_profile_certifications rc ON rc.profile_id=bp.id WHERE pc.singleton")
        .bind(request.runtime_node_id).bind(request.enrollment_id).bind(request.restore_profile_id)
        .fetch_optional(&mut *tx).await.map_err(|_|TopologyOwnerError::Database)?
        .ok_or(TopologyOwnerError::Authority)?;
    let source = row.validate(request, began)?;
    tx.commit()
        .await
        .map_err(|_| TopologyOwnerError::Database)?;
    require(
        Instant::now() < source.authority_deadline && Utc::now() < source.certified_until,
        TopologyOwnerError::Expired,
    )?;
    Ok(source)
}

// One full-document duplicate-free parser. The integer subset avoids changing
// Python float repr semantics, -0, exponents or integers outside i64/u64 into
// an approximate digest. All such unsupported lexemes fail closed.
struct StrictJson(Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrictJson;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("duplicate-free integer JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Err(E::custom("floating JSON is unsupported"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element::<StrictJson>()? {
                    values.push(v.0)
                }
                Ok(StrictJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, StrictJson>()? {
                    if values.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }
        d.deserialize_any(V)
    }
}
fn strict_json(raw: &[u8]) -> Result<Value> {
    require(
        !raw.is_empty() && raw.len() <= MAX_TF_BYTES,
        TopologyOwnerError::Inventory,
    )?;
    // Explicitly check each numeric lexeme outside JSON strings. Serde numeric
    // deserialization must never turn -0 or an oversized integer into an alias.
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if in_string {
            if escaped {
                escaped = false
            } else if c == b'\\' {
                escaped = true
            } else if c == b'"' {
                in_string = false
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if c == b'-' || c.is_ascii_digit() {
            let start = i;
            i += 1;
            while i < raw.len() && (raw[i].is_ascii_digit() || b"-+eE.".contains(&raw[i])) {
                i += 1;
            }
            let token =
                std::str::from_utf8(&raw[start..i]).map_err(|_| TopologyOwnerError::Inventory)?;
            let normalized = if token.starts_with('-') {
                token.parse::<i64>().map(|v| v.to_string())
            } else {
                token.parse::<u64>().map(|v| v.to_string())
            }
            .map_err(|_| TopologyOwnerError::Inventory)?;
            require(token == normalized, TopologyOwnerError::Inventory)?;
            continue;
        }
        i += 1;
    }
    serde_json::from_slice::<StrictJson>(raw)
        .map(|v| v.0)
        .map_err(|_| TopologyOwnerError::Inventory)
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn string(v: &str, out: &mut String) {
        out.push('"');
        for c in v.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if !(' '..='~').contains(&c) => {
                    let mut units = [0; 2];
                    for unit in c.encode_utf16(&mut units) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }
    fn write(v: &Value, out: &mut String) -> Result<()> {
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Number(v) => {
                require(v.is_i64() || v.is_u64(), TopologyOwnerError::Inventory)?;
                out.push_str(&v.to_string());
            }
            Value::String(v) => string(v, out),
            Value::Array(v) => {
                out.push('[');
                for (i, v) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',')
                    }
                    write(v, out)?
                }
                out.push(']');
            }
            Value::Object(v) => {
                out.push('{');
                let mut entries = v.iter().collect::<Vec<_>>();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for (i, (k, v)) in entries.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',')
                    }
                    string(k, out);
                    out.push(':');
                    write(v, out)?
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out.into_bytes())
}
fn exact_keys(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k)))
}
fn output<'a>(tf: &'a Value, key: &str) -> Result<&'a Value> {
    let v = tf.get(key).ok_or(TopologyOwnerError::Inventory)?;
    require(
        v.as_object().is_some_and(|m| {
            m.contains_key("value")
                && m.get("sensitive") == Some(&Value::Bool(false))
                && m.keys()
                    .all(|k| ["value", "sensitive", "type"].contains(&k.as_str()))
        }),
        TopologyOwnerError::Inventory,
    )?;
    v.get("value").ok_or(TopologyOwnerError::Inventory)
}
fn text(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(TopologyOwnerError::Inventory)
}
fn cloud_id(v: &str, prefix: &str) -> bool {
    v.len() <= 128
        && v.strip_prefix(prefix)
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
}
fn zone(v: &str, region: &str) -> bool {
    v.len() <= 64
        && v.strip_prefix(&format!("{region}-")).is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
struct Subnet {
    id: String,
    zone: String,
    start: u32,
    end: u32,
}
fn subnet(cidr: &str) -> Result<(u32, u32)> {
    let (address, prefix) = cidr.split_once('/').ok_or(TopologyOwnerError::Inventory)?;
    let ip: Ipv4Addr = address.parse().map_err(|_| TopologyOwnerError::Inventory)?;
    let p: u32 = prefix.parse().map_err(|_| TopologyOwnerError::Inventory)?;
    require(
        p <= 32 && ip.to_string() == address && p.to_string() == prefix,
        TopologyOwnerError::Inventory,
    )?;
    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let start = u32::from(ip) & mask;
    let end = start | !mask;
    require(
        start == u32::from(ip)
            && Ipv4Addr::from(start).is_private()
            && Ipv4Addr::from(end).is_private()
            && ((start >> 24 == 10 && end >> 24 == 10)
                || (start >> 20 == 0xac1 && end >> 20 == 0xac1)
                || (start >> 16 == 0xc0a8 && end >> 16 == 0xc0a8)),
        TopologyOwnerError::Inventory,
    )?;
    Ok((start, end))
}
fn inventory(source: &Source, raw: &[u8]) -> Result<NodeTopologyCloudBinding> {
    let tf = strict_json(raw)?;
    require(
        sha(raw) == source.raw_tf_sha256 && sha(&canonical(&tf)?) == source.canonical_tf_sha256,
        TopologyOwnerError::Inventory,
    )?;
    // Reject every sensitive wrapper, including outputs not used as authority.
    let outputs = tf.as_object().ok_or(TopologyOwnerError::Inventory)?;
    for key in outputs.keys() {
        output(&tf, key)?;
    }
    let identity = output(&tf, "deployment_identity")?;
    require(
        exact_keys(
            identity,
            &["cloud_account_id", "region", "deployment", "environment"],
        ) && text(identity, "cloud_account_id")? == source.account_id
            && text(identity, "region")? == source.region
            && text(identity, "deployment")? == source.deployment
            && ["preproduction", "production"].contains(&text(identity, "environment")?.as_str())
            && output(&tf, "workspace_kms_key_id")?.as_str() == Some(&source.kms_key_id),
        TopologyOwnerError::Inventory,
    )?;
    require(
        output(&tf, "workload_oidc_provider_arn")?.as_str() == Some(&source.oidc_provider_arn),
        TopologyOwnerError::Inventory,
    )?;
    let vpc_id = output(&tf, "vpc_id")?
        .as_str()
        .ok_or(TopologyOwnerError::Inventory)?
        .to_owned();
    require(cloud_id(&vpc_id, "vpc-"), TopologyOwnerError::Inventory)?;
    let subnets = output(&tf, "subnets")?
        .as_object()
        .ok_or(TopologyOwnerError::Inventory)?;
    require(
        (3..=64).contains(&subnets.len()),
        TopologyOwnerError::Inventory,
    )?;
    let mut nets: Vec<Subnet> = Vec::new();
    let mut subnet_ids = BTreeSet::new();
    for (name, value) in subnets {
        require(
            crate::backup_manifest::valid_name(name) && exact_keys(value, &["id", "zone", "cidr"]),
            TopologyOwnerError::Inventory,
        )?;
        let id = text(value, "id")?;
        let z = text(value, "zone")?;
        let (start, end) = subnet(&text(value, "cidr")?)?;
        require(
            cloud_id(&id, "vsw-")
                && subnet_ids.insert(id.clone())
                && zone(&z, &source.region)
                && nets.iter().all(|v| end < v.start || start > v.end),
            TopologyOwnerError::Inventory,
        )?;
        nets.push(Subnet {
            id,
            zone: z,
            start,
            end,
        });
    }
    let nodes = output(&tf, "node_inventory")?
        .as_object()
        .ok_or(TopologyOwnerError::Inventory)?;
    require(
        (9..=10000).contains(&nodes.len()),
        TopologyOwnerError::Inventory,
    )?;
    let mut ids = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut pools: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut selected = None;
    for (name, value) in nodes {
        require(
            name.len() <= 253
                && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                && name.len() >= 2
                && name
                    .bytes()
                    .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-')
                && exact_keys(value, &["id", "private_ip", "role", "zone"]),
            TopologyOwnerError::Inventory,
        )?;
        let id = text(value, "id")?;
        let role = text(value, "role")?;
        let z = text(value, "zone")?;
        let ipstr = text(value, "private_ip")?;
        let ip: Ipv4Addr = ipstr.parse().map_err(|_| TopologyOwnerError::Inventory)?;
        let matches = nets
            .iter()
            .filter(|n| n.zone == z && u32::from(ip) >= n.start && u32::from(ip) <= n.end)
            .collect::<Vec<_>>();
        require(
            cloud_id(&id, "i-")
                && ids.insert(id.clone())
                && ips.insert(ip)
                && ["control", "platform", "kata"].contains(&role.as_str())
                && zone(&z, &source.region)
                && ip.to_string() == ipstr
                && ip.is_private()
                && matches.len() == 1,
            TopologyOwnerError::Inventory,
        )?;
        pools.entry(role.clone()).or_default().push(z.clone());
        if name == &source.node.node_name {
            require(
                role == "kata" && ip == source.private_ip && id == source.instance_id,
                TopologyOwnerError::Inventory,
            )?;
            selected = Some(NodeTopologyCloudBinding {
                account_id: source.account_id.clone(),
                region: source.region.clone(),
                instance_id: id,
                zone_id: z,
                vpc_id: vpc_id.clone(),
                vswitch_id: matches[0].id.clone(),
                private_ip: ip,
                deployment: source.deployment.clone(),
            });
        }
    }
    for role in ["control", "platform", "kata"] {
        let pool = pools.get(role).ok_or(TopologyOwnerError::Inventory)?;
        require(
            (role == "kata" || pool.len() == 3)
                && pool.iter().cloned().collect::<BTreeSet<_>>()
                    == source.zones.iter().cloned().collect::<BTreeSet<_>>(),
            TopologyOwnerError::Inventory,
        )?;
    }
    require(
        nets.iter().map(|n| n.zone.clone()).collect::<BTreeSet<_>>()
            == source.zones.iter().cloned().collect::<BTreeSet<_>>(),
        TopologyOwnerError::Inventory,
    )?;
    selected.ok_or(TopologyOwnerError::Inventory)
}

fn verify_node(node: &Node, source: &Source, binding: &NodeTopologyCloudBinding) -> Result<String> {
    require(
        node_binding(node, source.node.cluster_epoch)
            .map_err(|_| TopologyOwnerError::Kubernetes)?
            == source.node
            && canonical_uuid(node.metadata.uid.as_deref())? == source.node.node_uid
            && node.metadata.name.as_deref() == Some(&source.node.node_name),
        TopologyOwnerError::Kubernetes,
    )?;
    let labels = node
        .metadata
        .labels
        .as_ref()
        .ok_or(TopologyOwnerError::Kubernetes)?;
    for (key, value) in CSI_TOPOLOGY_KEYS.iter().zip([
        binding.instance_id.as_str(),
        binding.zone_id.as_str(),
        binding.region.as_str(),
        binding.zone_id.as_str(),
    ]) {
        require(
            labels.get(*key).map(String::as_str) == Some(value),
            TopologyOwnerError::Kubernetes,
        )?;
    }
    let status = node.status.as_ref().ok_or(TopologyOwnerError::Kubernetes)?;
    let info = status
        .node_info
        .as_ref()
        .ok_or(TopologyOwnerError::Kubernetes)?;
    require(
        info.operating_system == "linux"
            && info.architecture == "amd64"
            && status.addresses.as_ref().is_some_and(|a| {
                a.iter()
                    .any(|v| v.type_ == "InternalIP" && v.address == binding.private_ip.to_string())
            }),
        TopologyOwnerError::Kubernetes,
    )?;
    let rv = node
        .metadata
        .resource_version
        .as_deref()
        .filter(|v| visible(v, 256))
        .ok_or(TopologyOwnerError::Kubernetes)?;
    Ok(rv.to_owned())
}
fn verify_csi(csi: &CSINode, source: &Source, binding: &NodeTopologyCloudBinding) -> Result<Value> {
    let uid = canonical_uuid(csi.metadata.uid.as_deref())?;
    require(
        csi.metadata.name.as_deref() == Some(&source.node.node_name)
            && csi.metadata.deletion_timestamp.is_none()
            && csi
                .metadata
                .resource_version
                .as_deref()
                .is_some_and(|v| visible(v, 256)),
        TopologyOwnerError::Kubernetes,
    )?;
    let owners = csi.metadata.owner_references.as_deref().unwrap_or_default();
    require(
        owners.len() == 1
            && owners[0].api_version == "v1"
            && owners[0].kind == "Node"
            && owners[0].name == source.node.node_name
            && canonical_uuid(Some(&owners[0].uid))? == source.node.node_uid,
        TopologyOwnerError::Kubernetes,
    )?;
    let drivers = &csi.spec.drivers;
    let mut names = BTreeSet::new();
    require(
        drivers.len() <= 64 && drivers.iter().all(|d| names.insert(d.name.as_str())),
        TopologyOwnerError::Kubernetes,
    )?;
    let matches = drivers
        .iter()
        .filter(|v| v.name == DRIVER)
        .collect::<Vec<_>>();
    require(matches.len() == 1, TopologyOwnerError::Kubernetes)?;
    let driver = matches[0];
    let mut keys = driver.topology_keys.clone().unwrap_or_default();
    keys.sort();
    require(
        driver.node_id == binding.instance_id && keys == CSI_TOPOLOGY_KEYS.map(str::to_owned),
        TopologyOwnerError::Kubernetes,
    )?;
    Ok(json!({"csi_node_uid":uid,"node_id":driver.node_id,"topology_keys":keys}))
}
async fn observe(
    runtime: &BackupJobRuntime,
    guard: &NodeguardClient,
    cloud: &AlibabaCloudNodeTopology,
    source: &Source,
    binding: &NodeTopologyCloudBinding,
) -> Result<(Value, String, String, Value, DateTime<Utc>)> {
    // The injected fixture client obeys the same exact identity binding as a
    // production client; a valid channel to another Node cannot seal evidence.
    require(
        guard.node_binding() == &source.node,
        TopologyOwnerError::Nodeguard,
    )?;
    let nodes = Api::<Node>::all(runtime.runtime().client_clone());
    let csis = Api::<CSINode>::all(runtime.runtime().client_clone());
    let node = nodes
        .get(&source.node.node_name)
        .await
        .map_err(|_| TopologyOwnerError::Kubernetes)?;
    let csi = csis
        .get(&source.node.node_name)
        .await
        .map_err(|_| TopologyOwnerError::Kubernetes)?;
    verify_node(&node, source, binding)?;
    let before = verify_csi(&csi, source, binding)?;
    guard
        .verify_node()
        .await
        .map_err(|_| TopologyOwnerError::Nodeguard)?;
    let observed = cloud
        .observe()
        .await
        .map_err(|_| TopologyOwnerError::Cloud)?;
    require(observed.binding() == binding, TopologyOwnerError::Cloud)?;
    let node = nodes
        .get(&source.node.node_name)
        .await
        .map_err(|_| TopologyOwnerError::Kubernetes)?;
    let csi = csis
        .get(&source.node.node_name)
        .await
        .map_err(|_| TopologyOwnerError::Kubernetes)?;
    let node_rv = verify_node(&node, source, binding)?;
    let registration = verify_csi(&csi, source, binding)?;
    require(before == registration, TopologyOwnerError::Kubernetes)?;
    let finished = micros(Utc::now())?;
    require(
        observed.observed_at() >= finished - ChronoDuration::seconds(10)
            && observed.observed_at() <= finished + ChronoDuration::microseconds(1),
        TopologyOwnerError::Expired,
    )?;
    Ok((
        registration,
        node_rv,
        csi.metadata
            .resource_version
            .ok_or(TopologyOwnerError::Kubernetes)?,
        observed
            .projection()
            .map_err(|_| TopologyOwnerError::Cloud)?,
        finished,
    ))
}
enum GuardSource<'a> {
    Credentials(&'a NodeguardCredentials),
    #[cfg(test)]
    Client(&'a NodeguardClient),
}
async fn capture(
    database: &Database,
    runtime: &BackupJobRuntime,
    cloud: &AlibabaCloudNodeTopology,
    request: NodeTopologyRequest,
    raw: &[u8],
    guard_source: GuardSource<'_>,
    started: Instant,
) -> Result<VerifiedNodeTopology> {
    let source = load_source(database, request).await?;
    let binding = inventory(&source, raw)?;
    require(
        cloud.binding() == &binding
            && cloud.identity_matches(&source.oidc_issuer, &source.oidc_provider_arn),
        TopologyOwnerError::Cloud,
    )?;
    let owned;
    let guard = match guard_source {
        #[cfg(test)]
        GuardSource::Client(client) => client,
        GuardSource::Credentials(credentials) => {
            owned = NodeguardClient::new(
                source.node.clone(),
                SocketAddr::new(IpAddr::V4(source.private_ip), source.guard_port),
                credentials,
            )
            .map_err(|_| TopologyOwnerError::Nodeguard)?;
            &owned
        }
    };
    let observation_started = Instant::now();
    let (registration, node_rv, csi_rv, cloud_projection, observed_at) =
        observe(runtime, guard, cloud, &source, &binding).await?;
    let last = load_source(database, request).await?;
    require(last.pin == source.pin, TopologyOwnerError::Authority)?;
    let id = Uuid::new_v4();
    let proof = VerifiedNodeTopology {
        id,
        payload: json!({"id":id,"runtime_node_id":source.request.runtime_node_id,
        "enrollment_id":source.request.enrollment_id,"restore_profile_id":source.request.restore_profile_id,
        "restore_report_sha256":source.certification_sha256,"terraform_output_sha256":source.raw_tf_sha256,
        "infrastructure_sha256":source.canonical_tf_sha256,"zone_id":binding.zone_id,
        "describe_instance":cloud_projection,"csi_registration":registration,
        "observed_node_resource_version":node_rv,"observed_csi_node_resource_version":csi_rv,
        "observed_at":date(observed_at),"reviewed_at":date(source.reviewed_at),
        "certified_until":date(source.certified_until)}),
        total_deadline: started + TOTAL_BUDGET,
        authority_deadline: source.authority_deadline.min(last.authority_deadline),
        observation_deadline: observation_started + OBSERVATION_BUDGET,
        certified_until: source.certified_until,
        observed_at,
    };
    proof.current()?;
    Ok(proof)
}
pub(crate) async fn collect_node_topology(
    database: &Database,
    runtime: &BackupJobRuntime,
    credentials: &NodeguardCredentials,
    cloud: &AlibabaCloudNodeTopology,
    request: NodeTopologyRequest,
    terraform_output: &Path,
) -> Result<VerifiedNodeTopology> {
    let started = Instant::now();
    tokio::time::timeout(TOTAL_BUDGET, async {
        owner(database).await?;
        // Fixed read-only file helper checks absolute path, opened regular FD,
        // no group/world writes or special mode and 1MiB; read exactly once.
        let raw = crate::api_tls::read(terraform_output, MAX_TF_BYTES, false)
            .map_err(|_| TopologyOwnerError::Inventory)?;
        capture(
            database,
            runtime,
            cloud,
            request,
            &raw,
            GuardSource::Credentials(credentials),
            started,
        )
        .await
    })
    .await
    .map_err(|_| TopologyOwnerError::Expired)?
}
pub(crate) async fn record_node_topology(
    database: &Database,
    proof: &VerifiedNodeTopology,
) -> Result<PersistedNodeTopology> {
    proof.current()?;
    // No retry and no new ID on a possibly committed publication. The borrowed
    // original proof retains exact payload, deadline and evidence across ACK loss.
    let deadline = proof
        .total_deadline
        .min(proof.authority_deadline)
        .min(proof.observation_deadline);
    tokio::time::timeout_at(deadline, async {
        owner(database).await?;
        proof.current()?;
        let mut tx = database
            .pool
            .begin()
            .await
            .map_err(|_| TopologyOwnerError::Database)?;
        let row: Value =
            sqlx::query_scalar("SELECT public.sandbox_record_restore_node_topology($1)")
                .bind(&proof.payload)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| TopologyOwnerError::Database)?;
        proof.current()?;
        tx.commit()
            .await
            .map_err(|_| TopologyOwnerError::Database)?;
        // DB success/INSERT alone cannot extend the original authority budget.
        proof.current()?;
        persisted_matches(&row, &proof.payload)?;
        proof.current()?;
        Ok(PersistedNodeTopology { row })
    })
    .await
    .map_err(|_| TopologyOwnerError::Expired)?
}
#[cfg(test)]
pub(crate) async fn collect_with_client(
    database: &Database,
    runtime: &BackupJobRuntime,
    guard: &NodeguardClient,
    cloud: &AlibabaCloudNodeTopology,
    request: NodeTopologyRequest,
    terraform_raw: &[u8],
) -> Result<VerifiedNodeTopology> {
    let started = Instant::now();
    tokio::time::timeout(TOTAL_BUDGET, async {
        owner(database).await?;
        capture(
            database,
            runtime,
            cloud,
            request,
            terraform_raw,
            GuardSource::Client(guard),
            started,
        )
        .await
    })
    .await
    .map_err(|_| TopologyOwnerError::Expired)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_python_ensure_ascii_full_document_and_integer_subset() -> anyhow::Result<()> {
        let raw = include_bytes!("../tests/fixtures/restore/node-topology-canonical-input.json");
        let expected =
            include_bytes!("../tests/fixtures/restore/node-topology-canonical-output.json");
        let value = strict_json(raw)?;
        assert_eq!(canonical(&value)?, expected);
        assert_ne!(sha(raw), sha(expected));
        assert_eq!(sha(&canonical(&strict_json(expected)?)?), sha(expected));
        for bad in [
            "1.0",
            "-0",
            "1e0",
            "1e-7",
            "18446744073709551616",
            "-9223372036854775809",
            "NaN",
            "{\"x\":0,\"x\":1}",
            "{\"x\":{\"n\":1,\"n\":2}}",
        ] {
            assert!(strict_json(bad.as_bytes()).is_err(), "{bad}");
        }
        assert_eq!(
            canonical(&strict_json(
                b"[-9223372036854775808,18446744073709551615,0]"
            )?)?,
            b"[-9223372036854775808,18446744073709551615,0]"
        );
        Ok(())
    }
    #[test]
    fn persisted_full_identity_and_sql_timestamp_semantics_are_strict() -> anyhow::Result<()> {
        for valid in [
            "2026-10-08T23:59:59Z",
            "2026-10-08T23:59:59+00:00",
            "2026-10-08T23:59:59.123456Z",
        ] {
            assert!(timestamp(&json!(valid)).is_ok(), "{valid}");
        }
        for invalid in [
            "2026-10-08T24:00:00Z",
            "2026-10-08T23:60:00Z",
            "2026-10-08T23:59:60Z",
        ] {
            assert!(timestamp(&json!(invalid)).is_err(), "{invalid}");
        }
        let now = micros(Utc::now())?;
        let payload = json!({"id":Uuid::new_v4(),"runtime_node_id":Uuid::new_v4(),
            "enrollment_id":Uuid::new_v4(),"restore_profile_id":Uuid::new_v4(),
            "restore_report_sha256":"a".repeat(64),"terraform_output_sha256":"b".repeat(64),
            "infrastructure_sha256":"c".repeat(64),"zone_id":"cn-hangzhou-a",
            "describe_instance":{"protocol":1},"csi_registration":{"node_id":"i-testnode"},
            "observed_node_resource_version":"1","observed_csi_node_resource_version":"2",
            "observed_at":date(now),"reviewed_at":date(now-ChronoDuration::days(1)),
            "certified_until":date(now+ChronoDuration::days(1))});
        let mut row = payload.clone();
        row["recorded_at"] = json!(date(now));
        for key in ["observed_at", "reviewed_at", "certified_until"] {
            row[key] = json!(timestamp(&row[key])?.to_rfc3339_opts(SecondsFormat::AutoSi, false));
        }
        persisted_matches(&row, &payload)?;
        for key in payload
            .as_object()
            .ok_or(TopologyOwnerError::Database)?
            .keys()
        {
            let mut wrong = row.clone();
            wrong[key] = json!("changed");
            assert!(persisted_matches(&wrong, &payload).is_err(), "{key}");
        }
        for text in [
            "infinity",
            "2026-10-08T12:00:60Z",
            "2026-10-08T12:00:00.1234567Z",
            "2026-10-08T12:00:00+01:00",
        ] {
            let mut wrong = row.clone();
            wrong["recorded_at"] = json!(text);
            assert!(persisted_matches(&wrong, &payload).is_err());
        }
        let mut wrong = row.clone();
        wrong["unexpected"] = Value::Null;
        assert!(persisted_matches(&wrong, &payload).is_err());
        Ok(())
    }
}
