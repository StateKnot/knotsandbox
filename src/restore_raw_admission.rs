//! One raw PVC CREATE before a Job, bound PV or VM birth. This decision never
//! persists the submitted UID or implies writer closure or cleanup authority.
use super::super::{
    manifest::RestoreStorageContext,
    policy,
    storage_contract::{RestoreStorageContract, RestoreStoragePurpose},
};
use super::{Decision, RestoreAdmissionService, checked, dependency, observation, selector};
use crate::{
    admission::{AdmissionRequest, Denial},
    backup_job::BackupCloudSettings,
    backup_manifest::{NAMESPACE, block_pvc_name, valid_name},
    nodeguard::protocol::valid_sha256,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use std::time::{Duration, Instant};
use uuid::Uuid;

const TOTAL_BUDGET: Duration = Duration::from_secs(10);
const PVC_PROTECTION: &str = "kubernetes.io/pvc-protection";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    id: Uuid,
    tenant_id: Uuid,
    backup_id: Uuid,
    source_project_id: Uuid,
    target_project_id: Uuid,
    workspace_id: Uuid,
    instance_id: Uuid,
    operation_id: Uuid,
    profile_id: Uuid,
    hold_id: Uuid,
    cluster_epoch: Uuid,
    source_manifest_sha256: String,
    source_identity: Value,
    storage_contract: Value,
    size_gib: i64,
    status: String,
    version: i64,
    deadline: DateTime<Utc>,
    created_at: DateTime<Utc>,
    #[serde(rename = "updated_at")]
    _updated_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIntent {
    id: Uuid,
    tenant_id: Uuid,
    restore_id: Uuid,
    kind: String,
    namespace: String,
    name: String,
    expected_object: Value,
    created_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedVault {
    restore_id: Uuid,
    tenant_id: Uuid,
    backup_id: Uuid,
    manifest_sha256: String,
    signing_key_sha256: String,
    vault_endpoint: String,
    #[serde(rename = "verified_at")]
    _verified_at: DateTime<Utc>,
    #[serde(rename = "recorded_at")]
    _recorded_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceVault {
    backup_id: Uuid,
    tenant_id: Uuid,
    manifest_sha256: String,
    manifest: Value,
    #[serde(rename = "verified_at")]
    _verified_at: DateTime<Utc>,
    #[serde(rename = "recorded_at")]
    _recorded_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVault {
    verified: VerifiedVault,
    source: SourceVault,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationIdentity {
    id: Uuid,
    tenant_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    workspace_id: Uuid,
    kind: String,
    actor_principal_id: Uuid,
    request_id: Uuid,
    lease_owner: String,
    lease_token: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzIdentity {
    tenant_version: i64,
    principal_version: i64,
    source_project_version: i64,
    target_project_version: i64,
    instance_spec_version: i64,
    template_id: Uuid,
    template_version: i64,
    security_id: Uuid,
    security_version: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPin {
    record: RawRecord,
    cloud_settings: BackupCloudSettings,
    target_namespace: String,
    vault: RawVault,
    intent: RawIntent,
    operation_identity: OperationIdentity,
    authz_identity: AuthzIdentity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    pin: RawPin,
    valid_for_us: i64,
}
struct RawAuthority {
    pin: Value,
    expected: Value,
    cloud: BackupCloudSettings,
    contract: RestoreStorageContract,
    valid_until: Instant,
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uid| !uid.is_nil() && uid.to_string() == value)
}
fn create_options(request: &AdmissionRequest) -> Decision<()> {
    let Some(options) = &request.options else {
        return Ok(());
    };
    let options = options.as_object().ok_or(Denial {
        code: 403,
        message: "Raw PVC create options malformed",
    })?;
    checked(
        options.keys().all(|key| {
            [
                "apiVersion",
                "kind",
                "dryRun",
                "fieldManager",
                "fieldValidation",
            ]
            .contains(&key.as_str())
        }) && options
            .get("apiVersion")
            .is_none_or(|v| v == "meta.k8s.io/v1")
            && options.get("kind").is_none_or(|v| v == "CreateOptions")
            && options
                .get("dryRun")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && options
                .get("fieldManager")
                .is_none_or(|v| v.as_str().is_some_and(|s| s.is_ascii() && s.len() <= 128))
            && options.get("fieldValidation").is_none_or(|v| {
                v.as_str()
                    .is_some_and(|s| matches!(s, "" | "Strict" | "Warn" | "Ignore"))
            }),
        "Unsupported raw PVC create options or dry-run",
    )
}
fn validate_raw_body(actual: &Value, expected: &Value) -> Decision<()> {
    let mut comparable = actual.clone();
    let metadata = comparable
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or(Denial {
            code: 403,
            message: "Raw PVC metadata missing",
        })?;
    checked(
        metadata.keys().all(|key| {
            [
                "name",
                "namespace",
                "labels",
                "uid",
                "creationTimestamp",
                "resourceVersion",
                "generation",
                "managedFields",
                "finalizers",
                "annotations",
                "ownerReferences",
            ]
            .contains(&key.as_str())
        }) && metadata
            .get("uid")
            .and_then(Value::as_str)
            .is_some_and(canonical_uuid)
            && metadata
                .get("creationTimestamp")
                .and_then(Value::as_str)
                .is_some_and(|s| s.len() <= 64 && DateTime::parse_from_rfc3339(s).is_ok())
            && metadata
                .get("resourceVersion")
                .is_none_or(|v| v.as_str() == Some(""))
            && metadata
                .get("generation")
                .is_none_or(|v| v.as_u64().is_some())
            && metadata.get("managedFields").is_none_or(|v| {
                v.as_array().is_some_and(|entries| {
                    entries.len() <= 128 && entries.iter().all(Value::is_object)
                })
            })
            && metadata
                .get("finalizers")
                .is_none_or(|v| v == &json!([]) || v == &json!([PVC_PROTECTION]))
            && metadata
                .get("annotations")
                .is_none_or(|v| v.as_object().is_some_and(serde_json::Map::is_empty))
            && metadata
                .get("ownerReferences")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "Raw PVC has unknown, deleting, owned or malformed metadata",
    )?;
    // These fields come from apiserver bookkeeping and confer no authority.
    // Every specification, label and behavior annotation remains compared.
    for key in [
        "uid",
        "creationTimestamp",
        "resourceVersion",
        "generation",
        "managedFields",
        "finalizers",
        "annotations",
        "ownerReferences",
    ] {
        metadata.remove(key);
    }
    let object = comparable.as_object_mut().ok_or(Denial {
        code: 403,
        message: "Raw PVC object missing",
    })?;
    if let Some(status) = object.get("status") {
        checked(
            status.is_null() || status == &json!({}),
            "Raw PVC CREATE status must be empty",
        )?;
        object.remove("status");
    }
    checked(
        comparable == *expected,
        "Raw PVC differs from the exact frozen Block manifest",
    )
}
fn check_budget(
    started: Instant,
    first: &RawAuthority,
    current: Option<&RawAuthority>,
) -> Decision<()> {
    let now = Instant::now();
    checked(
        started.elapsed() < TOTAL_BUDGET
            && now < first.valid_until
            && current.is_none_or(|a| now < a.valid_until),
        "Raw PVC authority expired during observation or COMMIT acknowledgement",
    )
}
impl RestoreAdmissionService {
    async fn load_raw_parent(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        restore: Uuid,
        reading: Instant,
    ) -> Decision<RawAuthority> {
        let value: Option<Value> =
            sqlx::query_scalar("SELECT sandbox_restore_raw_parent_admission($1,$2)")
                .bind(tenant)
                .bind(restore)
                .fetch_one(&mut **tx)
                .await
                .map_err(dependency)?;
        let value = value.ok_or(Denial {
            code: 403,
            message: "Current unbound raw PVC authority unavailable",
        })?;
        let pin = value.get("pin").cloned().ok_or(Denial {
            code: 503,
            message: "Raw PVC authority pin missing",
        })?;
        let envelope: RawEnvelope = serde_json::from_value(value).map_err(dependency)?;
        checked(
            (1..=10_000_000).contains(&envelope.valid_for_us),
            "Raw PVC authority horizon invalid",
        )?;
        let raw = envelope.pin;
        let r = raw.record;
        let op = raw.operation_identity;
        let authz = raw.authz_identity;
        checked(
            r.id == restore
                && r.tenant_id == tenant
                && r.status == "BLOCK_PENDING"
                && r.version > 0
                && [
                    r.backup_id,
                    r.source_project_id,
                    r.target_project_id,
                    r.workspace_id,
                    r.instance_id,
                    r.operation_id,
                    r.profile_id,
                    r.hold_id,
                    r.cluster_epoch,
                    raw.intent.id,
                    op.actor_principal_id,
                    op.request_id,
                    authz.template_id,
                    authz.security_id,
                ]
                .iter()
                .all(|v| !v.is_nil())
                && valid_sha256(&r.source_manifest_sha256)
                && (20..=1024).contains(&r.size_gib)
                && r.created_at < r.deadline
                && raw.intent.created_at >= r.created_at
                && raw.intent.created_at < r.deadline
                && op.id == r.operation_id
                && op.tenant_id == tenant
                && op.project_id == r.target_project_id
                && op.instance_id == r.instance_id
                && op.workspace_id == r.workspace_id
                && op.kind == "RESTORE"
                && !op.lease_owner.is_empty()
                && op.lease_owner.chars().count() <= 128
                && op.lease_token > 0
                && [
                    authz.tenant_version,
                    authz.principal_version,
                    authz.source_project_version,
                    authz.target_project_version,
                    authz.instance_spec_version,
                    authz.template_version,
                    authz.security_version,
                ]
                .iter()
                .all(|v| *v > 0)
                && raw.intent.tenant_id == tenant
                && raw.intent.restore_id == restore
                && raw.intent.kind == "BLOCK_PVC"
                && raw.intent.namespace == NAMESPACE
                && raw.intent.name == block_pvc_name(restore)
                && valid_name(&raw.target_namespace)
                && raw.target_namespace != NAMESPACE,
            "Raw PVC immutable scope or current identity differs from reader contract",
        )?;
        let source = policy::Source::from_receipt(
            tenant,
            r.source_project_id,
            r.backup_id,
            r.size_gib,
            raw.vault.source.manifest_sha256.clone(),
            raw.vault.source.manifest,
        )
        .map_err(dependency)?;
        policy::compatible(&source, &raw.cloud_settings, &raw.cloud_settings)
            .map_err(dependency)?;
        checked(
            json!(source.identity) == r.source_identity
                && source.manifest_sha256 == r.source_manifest_sha256
                && raw.vault.source.backup_id == r.backup_id
                && raw.vault.source.tenant_id == tenant
                && raw.vault.verified.restore_id == restore
                && raw.vault.verified.tenant_id == tenant
                && raw.vault.verified.backup_id == r.backup_id
                && raw.vault.verified.manifest_sha256 == source.manifest_sha256
                && raw.vault.verified.signing_key_sha256 == source.signing_key_sha256
                && raw.vault.verified.vault_endpoint == source.vault_endpoint,
            "Raw PVC independent vault verification differs from the immutable source",
        )?;
        let contract = RestoreStorageContract::parse(&r.storage_contract).map_err(dependency)?;
        checked(
            contract.profile_id == r.profile_id && contract.cluster_epoch == r.cluster_epoch,
            "Raw PVC storage certification identity changed",
        )?;
        contract
            .validate_cloud(&raw.cloud_settings)
            .map_err(dependency)?;
        let context = RestoreStorageContext {
            tenant_id: tenant,
            source_backup_id: r.backup_id,
            restore_id: restore,
            target_project_id: r.target_project_id,
            instance_id: r.instance_id,
            workspace_id: r.workspace_id,
            cluster_epoch: r.cluster_epoch,
            target_namespace: raw.target_namespace,
            storage_contract: contract.clone(),
            size_bytes: source.identity.size_bytes,
        };
        let expected = context.block_pvc().map_err(dependency)?;
        checked(
            raw.intent.expected_object == expected,
            "Raw PVC durable intent differs from its typed storage contract",
        )?;
        let budget = u64::try_from(envelope.valid_for_us).map_err(dependency)?;
        let valid_until = reading
            .checked_add(Duration::from_micros(budget))
            .ok_or(Denial {
                code: 403,
                message: "Raw PVC authority horizon overflow",
            })?;
        Ok(RawAuthority {
            pin,
            expected,
            cloud: raw.cloud_settings,
            contract,
            valid_until,
        })
    }
    pub(super) async fn decide_raw_parent(&self, request: &AdmissionRequest) -> Decision<()> {
        // Taken before every database or network operation, including BEGIN and
        // tenant setup. SQL, row-lock waits and both COMMIT ACKs spend the budget.
        let started = Instant::now();
        checked(
            request.resource.group.is_empty()
                && request.resource.version == "v1"
                && request.resource.resource == "persistentvolumeclaims"
                && request.operation == "CREATE"
                && request.namespace == NAMESPACE
                && request.sub_resource.is_empty()
                && !request.dry_run
                && request.old_object.is_none()
                && canonical_uuid(&request.uid),
            "Unsupported raw PVC operation; later CSI and storage mutations remain denied",
        )?;
        checked(
            self.identities.controller.username
                == "system:serviceaccount:sandbox-system:sandbox-backup-controller"
                && canonical_uuid(&self.identities.controller.uid)
                && request.user_info.username == self.identities.controller.username
                && request.user_info.uid == self.identities.controller.uid,
            "Exact reviewed restore controller identity required for raw PVC creation",
        )?;
        create_options(request)?;
        let body = request.object.as_ref().ok_or(Denial {
            code: 403,
            message: "Raw PVC CREATE body missing",
        })?;
        let tenant = selector(body, "/metadata/labels/sandbox.platform~1tenant-id")?;
        let restore = selector(body, "/metadata/labels/sandbox.platform~1restore-id")?;
        checked(
            request.name == block_pvc_name(restore),
            "Raw PVC request name differs from its restore",
        )?;

        let reading = Instant::now();
        let mut tx = self.database.begin(tenant).await.map_err(dependency)?;
        let loaded = self
            .load_raw_parent(&mut tx, tenant, restore, reading)
            .await?;
        validate_raw_body(body, &loaded.expected)?;
        tx.commit().await.map_err(dependency)?;
        check_budget(started, &loaded, None)?;

        self.runtime
            .verify_network(&loaded.cloud)
            .await
            .map_err(observation)?;
        self.runtime
            .verify_profile_secrets(&loaded.cloud)
            .await
            .map_err(observation)?;
        for purpose in [
            RestoreStoragePurpose::Normal,
            RestoreStoragePurpose::Raw,
            RestoreStoragePurpose::Delivery,
        ] {
            self.runtime
                .verify_restore_storage_class(&loaded.contract, purpose)
                .await
                .map_err(observation)?;
        }
        self.runtime
            .verify_restore_snapshot_class(&loaded.contract)
            .await
            .map_err(observation)?;
        check_budget(started, &loaded, None)?;

        let reading = Instant::now();
        let mut tx = self.database.begin(tenant).await.map_err(dependency)?;
        let current = self
            .load_raw_parent(&mut tx, tenant, restore, reading)
            .await?;
        checked(
            current.pin == loaded.pin,
            "Raw PVC authority, operation claim or immutable identity changed during observation",
        )?;
        validate_raw_body(body, &current.expected)?;
        check_budget(started, &loaded, Some(&current))?;
        tx.commit().await.map_err(dependency)?;
        check_budget(started, &loaded, Some(&current))
    }
}
