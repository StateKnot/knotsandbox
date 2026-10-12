//! Restore authority is current, while its signed data identity stays historical.
use crate::{
    backup_job::{BackupCloudSettings, BackupSecretBinding},
    backup_manifest::{BackupManifestContext, block_pvc_name},
    backup_object::{BackupIdentity, BackupVaultExpectation, BackupVaultManifest},
    error::ApiError,
    nodeguard::protocol::{BackupStage, valid_sha256},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) fn blocked(message: &'static str) -> ApiError {
    ApiError::conflict("RESTORE_BLOCKED", message)
}
pub(crate) fn invalid() -> ApiError {
    blocked("The immutable source backup receipt is invalid")
}

pub(crate) struct Source {
    pub identity: BackupIdentity,
    pub snapshot_id: String,
    pub disk_sha256: String,
    pub manifest_sha256: String,
    pub signing_key_sha256: String,
    pub vault_endpoint: String,
}
impl Source {
    pub fn from_receipt(
        tenant: Uuid,
        project: Uuid,
        backup: Uuid,
        size_gib: i64,
        manifest_sha256: String,
        receipt: Value,
    ) -> Result<Self, ApiError> {
        if receipt.as_object().is_none_or(|o| o.len() != 3) {
            return Err(invalid());
        }
        let manifest: BackupVaultManifest =
            serde_json::from_value(receipt.get("manifest").cloned().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        let key = receipt
            .get("signing_key_sha256")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let endpoint = receipt
            .get("vault_endpoint")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let bytes = u64::try_from(size_gib)
            .ok()
            .and_then(|n| n.checked_mul(1024_u64.pow(3)))
            .ok_or_else(invalid)?;
        let identity = &manifest.backup;
        if !(20..=1024).contains(&size_gib)
            || !valid_sha256(&manifest_sha256)
            || !valid_sha256(key)
            || identity.protocol != 1
            || identity.tenant_id != tenant
            || identity.project_id != project
            || identity.backup_id != backup
            || identity.size_bytes != bytes
            || manifest.disk.size_bytes != bytes
            || !valid_sha256(&manifest.disk.sha256)
            || !valid_sha256(&manifest.snapshot_id)
            || endpoint != format!("https://oss-{}-internal.aliyuncs.com", identity.region)
            || manifest.protocol != 2
            || manifest.format != "restic-raw-disk-v2"
            || !manifest.repository_read_data_verified
            || !manifest.raw_restore_sha256_verified
            || manifest.cloud_restore_tested_at.is_some()
            || manifest.repository_prefix != format!("tenants/{tenant}/backups/{backup}/repository")
        {
            return Err(invalid());
        }
        Ok(Self {
            identity: manifest.backup,
            snapshot_id: manifest.snapshot_id,
            disk_sha256: manifest.disk.sha256,
            manifest_sha256,
            signing_key_sha256: key.to_owned(),
            vault_endpoint: endpoint.to_owned(),
        })
    }
    pub fn expectation(&self) -> BackupVaultExpectation {
        BackupVaultExpectation {
            identity: self.identity.clone(),
            snapshot_id: self.snapshot_id.clone(),
            disk_sha256: self.disk_sha256.clone(),
            manifest_sha256: Some(self.manifest_sha256.clone()),
        }
    }
}

fn same_secret(a: &BackupSecretBinding, b: &BackupSecretBinding) -> bool {
    a.name == b.name && a.uid == b.uid && a.content_sha256 == b.content_sha256
}

/// Neither a changed key name nor an equal key under a different Kubernetes UID
/// may reinterpret historical approval. The old profile need not remain enabled.
pub(crate) fn compatible(
    source: &Source,
    historical: &BackupCloudSettings,
    current: &BackupCloudSettings,
) -> Result<(), ApiError> {
    historical.validate_historical().map_err(|_| invalid())?;
    current
        .validate()
        .map_err(|_| blocked("The current restore cloud profile is invalid"))?;
    let i = &source.identity;
    if i.region != historical.region
        || i.account_id != historical.account_id
        || i.bucket != historical.bucket
        || i.vault_bucket != historical.vault_bucket
        || i.kms_key_id != historical.kms_key_id
        || i.vault_kms_key_id != historical.vault_kms_key_id
        || i.key_ref != historical.key_ref
        || source.signing_key_sha256 != historical.signing_key_sha256
        || source.vault_endpoint != historical.vault_endpoint
        || current.region != historical.region
        || current.account_id != historical.account_id
        || current.bucket != historical.bucket
        || current.vault_bucket != historical.vault_bucket
        || current.kms_key_id != historical.kms_key_id
        || current.vault_kms_key_id != historical.vault_kms_key_id
        || current.key_ref != historical.key_ref
        || current.vault_endpoint != historical.vault_endpoint
        || current.signing_key_sha256 != historical.signing_key_sha256
        || !same_secret(
            &current.secret_bindings.password,
            &historical.secret_bindings.password,
        )
        || !same_secret(
            &current.secret_bindings.signing_public,
            &historical.secret_bindings.signing_public,
        )
    {
        return Err(blocked(
            "The current restore profile cannot decrypt and verify this immutable source",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn job_context(
    source: &Source,
    current: &BackupCloudSettings,
    restore_id: Uuid,
    current_epoch: Uuid,
    image: String,
    certification_sha256: String,
    now: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Result<BackupManifestContext, ApiError> {
    let seconds = (deadline - now).num_seconds();
    if !(1..=7200).contains(&seconds) || restore_id.is_nil() || current_epoch.is_nil() {
        return Err(blocked(
            "The restore attempt deadline or identity is invalid",
        ));
    }
    // The cloud data mover verifies this original identity against the signed
    // manifest. Target project, workspace, epoch and template never overwrite it.
    let mut config = serde_json::to_value(&source.identity).map_err(|_| invalid())?;
    let o = config.as_object_mut().ok_or_else(invalid)?;
    o.insert("issuer".into(), json!(current.issuer));
    o.insert("oidc_provider_arn".into(), json!(current.oidc_provider_arn));
    o.insert("roles".into(), json!(current.roles));
    o.insert(
        "runtime_certification_sha256".into(),
        json!(certification_sha256),
    );
    o.insert(
        "deadline".into(),
        json!(deadline.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
    );
    let context = BackupManifestContext {
        tenant_id: source.identity.tenant_id,
        project_id: source.identity.project_id,
        backup_id: source.identity.backup_id,
        attempt_id: restore_id,
        cluster_epoch: current_epoch,
        stage: BackupStage::Restore,
        image,
        certification_sha256,
        deadline_seconds: u32::try_from(seconds).map_err(|_| invalid())?,
        config_json: config.to_string(),
        password_secret: current.secret_bindings.password.name.clone(),
        signing_private_secret: current.secret_bindings.signing_private.name.clone(),
        signing_public_secret: current.secret_bindings.signing_public.name.clone(),
        block_pvc: Some(block_pvc_name(restore_id)),
        expected_manifest_sha256: Some(source.manifest_sha256.clone()),
    };
    crate::backup_manifest::build_backup_manifests(&context)
        .map_err(|_| blocked("Controlled restore manifest is invalid"))?;
    Ok(context)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::backup_object::{BackupDisk, BackupInventory, BackupInventoryShard};
    use chrono::Duration;

    fn fixture() -> (Source, BackupCloudSettings) {
        let cloud: BackupCloudSettings = serde_json::from_value(json!({
            "deployment":"sandbox",
            "secret_bindings": {"password":{"name":"sbx-bkey-password","uid":Uuid::new_v4(),"content_sha256":"a".repeat(64)},
                "signing_private":{"name":"sbx-bkey-private","uid":Uuid::new_v4(),"content_sha256":"b".repeat(64)},
                "signing_public":{"name":"sbx-bkey-public","uid":Uuid::new_v4(),"content_sha256":"c".repeat(64)}},
            "signing_key_sha256":"d".repeat(64),"vault_endpoint":"https://oss-cn-hangzhou-internal.aliyuncs.com",
            "clone_kms_key_id":"clone-key","vault_retention_days":31,"key_ref":"backup/key-v1","region":"cn-hangzhou","account_id":"1234567890123456",
            "bucket":"sandbox-mutable","vault_bucket":"sandbox-vault","kms_key_id":"source-key","vault_kms_key_id":"vault-key",
            "issuer":"https://kubernetes.example.test","oidc_provider_arn":"acs:ram::1234567890123456:oidc-provider/sandbox",
            "roles":{
                "backup":{"arn":"acs:ram::1234567890123456:role/backup","subject":"system:serviceaccount:sandbox-system:sandbox-backup"},
                "backup-export":{"arn":"acs:ram::1234567890123456:role/backup-export","subject":"system:serviceaccount:sandbox-system:sandbox-backup-export"},
                "restore":{"arn":"acs:ram::1234567890123456:role/restore","subject":"system:serviceaccount:sandbox-system:sandbox-restore"}}
        })).expect("cloud fixture");
        let identity = BackupIdentity {
            protocol: 1,
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            backup_id: Uuid::new_v4(),
            source_instance_id: Uuid::new_v4(),
            source_generation: 7,
            source_pvc_uid: Uuid::new_v4(),
            snapshot_content_uid: Uuid::new_v4(),
            clone_pvc_uid: Uuid::new_v4(),
            seal_attempt_id: Uuid::new_v4(),
            cluster_epoch: Uuid::new_v4(),
            size_bytes: 20 * 1024_u64.pow(3),
            data_timestamp: (Utc::now() - Duration::days(1)).to_rfc3339(),
            consistency: "STOPPED_CONSISTENT".into(),
            retention_until: (Utc::now() + Duration::days(40)).to_rfc3339(),
            key_ref: cloud.key_ref.clone(),
            region: cloud.region.clone(),
            account_id: cloud.account_id.clone(),
            bucket: cloud.bucket.clone(),
            vault_bucket: cloud.vault_bucket.clone(),
            kms_key_id: cloud.kms_key_id.clone(),
            vault_kms_key_id: cloud.vault_kms_key_id.clone(),
            template_digest: format!("sha256:{}", "e".repeat(64)),
        };
        let source = Source {
            identity,
            snapshot_id: "1".repeat(64),
            disk_sha256: "2".repeat(64),
            manifest_sha256: "3".repeat(64),
            signing_key_sha256: cloud.signing_key_sha256.clone(),
            vault_endpoint: cloud.vault_endpoint.clone(),
        };
        (source, cloud)
    }
    fn receipt(source: &Source) -> Value {
        let manifest = BackupVaultManifest {
            protocol: 2,
            format: "restic-raw-disk-v2".into(),
            backup: source.identity.clone(),
            snapshot_id: source.snapshot_id.clone(),
            disk: BackupDisk {
                size_bytes: source.identity.size_bytes,
                sha256: source.disk_sha256.clone(),
            },
            repository_prefix: format!(
                "tenants/{}/backups/{}/repository",
                source.identity.tenant_id, source.identity.backup_id
            ),
            sealed_at: Utc::now().to_rfc3339(),
            retain_objects_until: source.identity.retention_until.clone(),
            repository_read_data_verified: true,
            raw_restore_sha256_verified: true,
            cloud_restore_tested_at: None,
            inventory: BackupInventory {
                format: "restic-object-inventory-v1".into(),
                object_count: 5,
                total_bytes: 50,
                shards: vec![BackupInventoryShard {
                    key: "inventory/000000.json".into(),
                    size_bytes: 100,
                    sha256: "4".repeat(64),
                    object_count: 5,
                }],
            },
        };
        json!({"manifest":manifest,"signing_key_sha256":source.signing_key_sha256,"vault_endpoint":source.vault_endpoint})
    }
    #[test]
    fn receipt_cannot_repoint_source_or_claim_an_unverified_disk() {
        let (source, _) = fixture();
        let parse = |v| {
            Source::from_receipt(
                source.identity.tenant_id,
                source.identity.project_id,
                source.identity.backup_id,
                20,
                source.manifest_sha256.clone(),
                v,
            )
        };
        let value = receipt(&source);
        assert_eq!(
            parse(value.clone()).unwrap().expectation().identity,
            source.identity
        );
        for (path, wrong) in [
            ("/manifest/backup/tenant_id", json!(Uuid::new_v4())),
            ("/manifest/backup/project_id", json!(Uuid::new_v4())),
            ("/manifest/backup/backup_id", json!(Uuid::new_v4())),
            (
                "/manifest/backup/size_bytes",
                json!(source.identity.size_bytes + 512),
            ),
            ("/manifest/disk/size_bytes", json!(512)),
            ("/manifest/disk/sha256", json!("invalid")),
            ("/manifest/snapshot_id", json!("invalid")),
            ("/manifest/raw_restore_sha256_verified", json!(false)),
            ("/manifest/repository_read_data_verified", json!(false)),
            ("/manifest/repository_prefix", json!("another/backup")),
            ("/manifest/protocol", json!(1)),
            (
                "/manifest/cloud_restore_tested_at",
                json!(Utc::now().to_rfc3339()),
            ),
            (
                "/vault_endpoint",
                json!("https://oss-cn-shanghai-internal.aliyuncs.com"),
            ),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() = wrong;
            assert!(parse(changed).is_err(), "accepted altered source at {path}");
        }
        let mut changed = value;
        changed["unreviewed"] = json!(true);
        assert!(parse(changed).is_err());
    }
    #[test]
    fn current_profile_requires_historical_decryption_and_verification_keys() {
        let (source, old) = fixture();
        compatible(&source, &old, &old).unwrap();
        let mut new = old.clone();
        new.roles.get_mut("restore").unwrap().arn =
            "acs:ram::1234567890123456:role/restore-current".into();
        new.issuer = "https://current-kubernetes.example.test".into();
        new.clone_kms_key_id = "current-target-key".into();
        new.secret_bindings.signing_private.uid = Uuid::new_v4();
        compatible(&source, &old, &new).unwrap();
        for edit in 0..8 {
            let mut changed = new.clone();
            match edit {
                0 => changed.secret_bindings.password.uid = Uuid::new_v4(),
                1 => changed.secret_bindings.signing_public.uid = Uuid::new_v4(),
                2 => changed.secret_bindings.password.content_sha256 = "0".repeat(64),
                3 => {
                    changed.secret_bindings.signing_public.name =
                        "sbx-bkey-public-replacement".into()
                }
                4 => changed.vault_bucket = "other-vault".into(),
                5 => changed.vault_kms_key_id = "other-kms".into(),
                6 => changed.key_ref = "new-version".into(),
                _ => changed.signing_key_sha256 = "0".repeat(64),
            }
            assert!(
                compatible(&source, &old, &changed).is_err(),
                "accepted incompatible key edit {edit}"
            );
        }
    }

    #[test]
    fn historical_source_without_deployment_requires_a_current_deployment() {
        let (source, current) = fixture();
        let mut historical = current.clone();
        historical.deployment.clear();
        assert!(historical.validate().is_err());
        compatible(&source, &historical, &current).unwrap();
        assert!(compatible(&source, &historical, &historical).is_err());

        // Historical compatibility still binds the original key identities.
        historical.secret_bindings.signing_public.uid = Uuid::new_v4();
        assert!(compatible(&source, &historical, &current).is_err());
    }
    #[test]
    fn restore_job_keeps_signed_source_epoch_project_and_template() {
        let (source, mut cloud) = fixture();
        cloud.roles.get_mut("restore").unwrap().arn =
            "acs:ram::1234567890123456:role/restore-current".into();
        let current_epoch = Uuid::new_v4();
        let restore = Uuid::new_v4();
        let now = Utc::now();
        let context = job_context(
            &source,
            &cloud,
            restore,
            current_epoch,
            format!("registry.example.test/backup@sha256:{}", "a".repeat(64)),
            "b".repeat(64),
            now,
            now + Duration::hours(2),
        )
        .unwrap();
        let mut config: Value = serde_json::from_str(&context.config_json).unwrap();
        let extras = config.as_object_mut().unwrap();
        for key in [
            "issuer",
            "roles",
            "oidc_provider_arn",
            "runtime_certification_sha256",
            "deadline",
        ] {
            extras.remove(key);
        }
        assert_eq!(
            serde_json::from_value::<BackupIdentity>(config).unwrap(),
            source.identity
        );
        assert_ne!(context.cluster_epoch, source.identity.cluster_epoch);
        assert_eq!(context.attempt_id, restore);
        let manifests = crate::backup_manifest::build_backup_manifests(&context).unwrap();
        assert_eq!(
            manifests
                .job
                .pointer("/spec/template/spec/serviceAccountName"),
            Some(&json!("sandbox-restore"))
        );
        assert_eq!(
            manifests
                .job
                .pointer("/spec/template/spec/containers/0/env/0/value"),
            Some(&json!(source.manifest_sha256))
        );
        assert!(
            job_context(
                &source,
                &cloud,
                restore,
                current_epoch,
                context.image,
                context.certification_sha256,
                now,
                now + Duration::seconds(7201)
            )
            .is_err()
        );
    }
}
