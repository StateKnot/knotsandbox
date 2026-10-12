//! Deterministic backup manifests. Callers must load this context from the
//! persistent backup intent and approved deployment settings, never Pod labels.
use crate::nodeguard::protocol::{BackupStage, backup_job_name, pinned_image, valid_sha256};
use crate::runtime_manifest::{ManifestError, TERMINATION_FINALIZER};
use serde_json::{Value, json};
use uuid::Uuid;

pub const NAMESPACE: &str = "sandbox-system";
pub const BACKUP_LABEL: &str = "sandbox.platform/backup-id";
pub const ATTEMPT_LABEL: &str = "sandbox.platform/backup-attempt-id";
pub const PURPOSE_LABEL: &str = "sandbox.platform/purpose";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifestContext {
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub backup_id: Uuid,
    pub attempt_id: Uuid,
    pub cluster_epoch: Uuid,
    pub stage: BackupStage,
    pub image: String,
    pub certification_sha256: String,
    pub deadline_seconds: u32,
    pub config_json: String,
    pub password_secret: String,
    pub signing_private_secret: String,
    pub signing_public_secret: String,
    /// None only for SEAL, which has no data disk.
    pub block_pvc: Option<String>,
    pub expected_manifest_sha256: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BackupManifests {
    pub job: Value,
    pub config_map: Value,
}

pub fn role(stage: BackupStage) -> &'static str {
    match stage {
        BackupStage::Capture => "sandbox-backup",
        BackupStage::Seal => "sandbox-backup-export",
        BackupStage::Restore => "sandbox-restore",
    }
}
pub fn config_name(attempt: Uuid) -> String {
    format!("sbx-bcfg-{attempt}")
}
pub fn capture_name(backup: Uuid) -> String {
    format!("sbx-capture-{backup}")
}
pub fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn build_backup_manifests(c: &BackupManifestContext) -> Result<BackupManifests, ManifestError> {
    if [
        c.tenant_id,
        c.project_id,
        c.backup_id,
        c.attempt_id,
        c.cluster_epoch,
    ]
    .iter()
    .any(Uuid::is_nil)
        || !(1..=7200).contains(&c.deadline_seconds)
        || !valid_sha256(&c.certification_sha256)
        || [
            &c.password_secret,
            &c.signing_private_secret,
            &c.signing_public_secret,
        ]
        .iter()
        .any(|v| !valid_name(v))
        || c.password_secret == c.signing_private_secret
        || c.password_secret == c.signing_public_secret
        || c.signing_private_secret == c.signing_public_secret
        || c.config_json.len() > 64 * 1024
    {
        return Err(ManifestError::InvalidConfiguration("backup context"));
    }
    if !pinned_image(&c.image) {
        return Err(ManifestError::InvalidImage);
    }
    let config: Value =
        serde_json::from_str(&c.config_json).map_err(|_| ManifestError::Encoding)?;
    for (field, id) in [
        ("tenant_id", c.tenant_id),
        ("project_id", c.project_id),
        ("backup_id", c.backup_id),
    ] {
        if config.get(field).and_then(Value::as_str) != Some(id.to_string().as_str()) {
            return Err(ManifestError::InvalidConfiguration(
                "backup config identity",
            ));
        }
    }
    if config.get("protocol") != Some(&json!(1))
        || config.get("runtime_certification_sha256") != Some(&json!(c.certification_sha256))
    {
        return Err(ManifestError::InvalidConfiguration(
            "backup config protocol/certification",
        ));
    }
    let valid_volume = match c.stage {
        BackupStage::Seal => c.block_pvc.is_none(),
        _ => c.block_pvc.as_deref().is_some_and(valid_name),
    };
    let valid_manifest = match c.stage {
        BackupStage::Restore => c
            .expected_manifest_sha256
            .as_deref()
            .is_some_and(valid_sha256),
        _ => c.expected_manifest_sha256.is_none(),
    };
    if !valid_volume || !valid_manifest {
        return Err(ManifestError::InvalidConfiguration("backup stage input"));
    }
    let labels = json!({BACKUP_LABEL:c.backup_id,ATTEMPT_LABEL:c.attempt_id,PURPOSE_LABEL:format!("backup-{}",c.stage.name()),
        "sandbox.platform/tenant-id":c.tenant_id,"sandbox.platform/project-id":c.project_id,
        "sandbox.platform/cluster-epoch":c.cluster_epoch,"app.kubernetes.io/managed-by":"sandbox-backup"});
    let mut volumes = vec![
        json!({"name":"work","emptyDir":if c.stage==BackupStage::Seal {json!({"sizeLimit":"1Gi"})}else{json!({"medium":"Memory","sizeLimit":"128Mi"})}}),
        json!({"name":"config","configMap":{"name":config_name(c.attempt_id),"defaultMode":420}}),
        json!({"name":"key","secret":{"secretName":c.password_secret,"defaultMode":256}}),
        json!({"name":"cloud","projected":{"defaultMode":256,"sources":[{"serviceAccountToken":{"audience":"sts.aliyuncs.com","expirationSeconds":600,"path":"token"}}]}}),
    ];
    let mut mounts = vec![
        json!({"name":"work","mountPath":"/run/backup"}),
        json!({"name":"config","mountPath":"/run/backup-config/job.json","subPath":"job.json","readOnly":true}),
        json!({"name":"key","mountPath":"/run/backup-key/password","subPath":"password","readOnly":true}),
        json!({"name":"cloud","mountPath":"/var/run/sandbox-cloud","readOnly":true}),
    ];
    if let Some(pvc) = &c.block_pvc {
        volumes.push(json!({"name":"data","persistentVolumeClaim":{"claimName":pvc,"readOnly":c.stage==BackupStage::Capture}}));
    }
    if c.stage == BackupStage::Seal {
        volumes.push(json!({"name":"source","configMap":{"name":capture_name(c.backup_id),"defaultMode":420}}));
        volumes.push(json!({"name":"signing","secret":{"secretName":c.signing_private_secret,"defaultMode":256}}));
        mounts.push(json!({"name":"source","mountPath":"/run/backup-source/capture.json","subPath":"capture.json","readOnly":true}));
        mounts.push(json!({"name":"signing","mountPath":"/run/backup-signing/private.pem","subPath":"private.pem","readOnly":true}));
    }
    if c.stage == BackupStage::Restore {
        volumes.push(json!({"name":"signing","secret":{"secretName":c.signing_public_secret,"defaultMode":256}}));
        mounts.push(json!({"name":"signing","mountPath":"/run/backup-signing/public.pem","subPath":"public.pem","readOnly":true}));
    }
    let mut container = json!({"name":"backup","image":c.image,"imagePullPolicy":"Always",
        "command":["/usr/local/bin/python3","/app/backup.py",c.stage.name()],
        "terminationMessagePath":"/run/backup/result.json","terminationMessagePolicy":"File",
        "securityContext":{"runAsUser":0,"runAsGroup":0,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},
        "resources":{"requests":{"cpu":"1","memory":"1Gi","ephemeral-storage":"128Mi"},"limits":{"cpu":"2","memory":"2Gi","ephemeral-storage":"256Mi"}},
        "volumeMounts":mounts});
    if c.stage == BackupStage::Seal {
        container["resources"]["requests"]["ephemeral-storage"] = json!("1Gi");
        container["resources"]["limits"]["ephemeral-storage"] = json!("2Gi");
    }
    if c.block_pvc.is_some() {
        container["volumeDevices"] = json!([{"name":"data","devicePath":"/dev/sandbox-data"}]);
    }
    if let Some(hash) = &c.expected_manifest_sha256 {
        container["env"] = json!([{"name":"SANDBOX_EXPECTED_MANIFEST_SHA256","value":hash}]);
    }
    let pod = json!({"metadata":{"labels":labels,"annotations":{"sandbox.platform/backup-certification":c.certification_sha256},"finalizers":[TERMINATION_FINALIZER]},
        "spec":{"runtimeClassName":"kata-backup-qemu","serviceAccountName":role(c.stage),"automountServiceAccountToken":false,
        "restartPolicy":"Never","enableServiceLinks":false,"hostNetwork":false,"hostPID":false,"hostIPC":false,
        "dnsPolicy":"ClusterFirst","schedulerName":"default-scheduler","terminationGracePeriodSeconds":30,
        "nodeSelector":{"sandbox.platform/node-pool":"kata"},
        "tolerations":[{"key":"sandbox.platform/untrusted","operator":"Equal","value":"true","effect":"NoSchedule"}],
        "securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"containers":[container],"volumes":volumes}});
    Ok(BackupManifests {
        config_map: json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":config_name(c.attempt_id),"namespace":NAMESPACE,"labels":labels},"immutable":true,"data":{"job.json":c.config_json}}),
        job: json!({"apiVersion":"batch/v1","kind":"Job","metadata":{"name":backup_job_name(c.attempt_id,c.stage),"namespace":NAMESPACE,"labels":labels},
          "spec":{"suspend":true,"backoffLimit":0,"parallelism":1,"completions":1,"completionMode":"NonIndexed","podReplacementPolicy":"Failed",
          "activeDeadlineSeconds":c.deadline_seconds,"template":pod}}),
    })
}

#[derive(Clone, Debug)]
pub struct BackupBlockContext {
    pub backup_id: Uuid,
    pub attempt_id: Uuid,
    pub storage_class: String,
    pub size_bytes: u64,
    /// CAPTURE only: exact delegated VolumeSnapshot name from the resource ledger.
    pub snapshot_name: Option<String>,
}
pub fn block_pvc_name(attempt: Uuid) -> String {
    format!("sbx-bvol-{attempt}")
}
pub fn build_backup_block_pvc(c: &BackupBlockContext) -> Result<Value, ManifestError> {
    if c.backup_id.is_nil()
        || c.attempt_id.is_nil()
        || !valid_name(&c.storage_class)
        || c.size_bytes == 0
        || !c.size_bytes.is_multiple_of(512)
        || c.size_bytes > 16 * 1024_u64.pow(4)
        || c.snapshot_name.as_deref().is_some_and(|s| !valid_name(s))
    {
        return Err(ManifestError::InvalidConfiguration("backup block volume"));
    }
    let mut spec = json!({"volumeMode":"Block","accessModes":["ReadWriteOnce"],"storageClassName":c.storage_class,
        "resources":{"requests":{"storage":c.size_bytes.to_string()}}});
    if let Some(name) = &c.snapshot_name {
        spec["dataSource"] =
            json!({"apiGroup":"snapshot.storage.k8s.io","kind":"VolumeSnapshot","name":name});
    }
    Ok(
        json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":block_pvc_name(c.attempt_id),"namespace":NAMESPACE,
        "labels":{BACKUP_LABEL:c.backup_id,ATTEMPT_LABEL:c.attempt_id,"app.kubernetes.io/managed-by":"sandbox-backup"}},"spec":spec}),
    )
}
