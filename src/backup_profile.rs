//! Installation-owner backup profile contracts. Static evidence is an operator
//! claim, not live cloud verification; registration always remains disabled.
use crate::{
    backup_job::BackupCloudSettings, backup_manifest::valid_name, backup_object::canonical_decode,
    nodeguard::protocol::valid_sha256,
};

#[path = "backup_profile_owner.rs"]
mod owner;
use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
pub use owner::{ProfileOwnerReceipt, activate_profile, register_profile, revoke_profile};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const CHECKS: [&str; 9] = [
    "kata_raw_block_no_host_mount",
    "csi_filesystem_snapshot_to_block",
    "nodeguard_backup_launch_and_termination",
    "network_first_packet_and_metadata",
    "isolated_source_vault_ram_prefix",
    "vault_locked_worm",
    "kms_recovery_and_rotation",
    "full_repository_read_and_independent_restore",
    "controller_admission_race_and_recovery",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    protocol: u32,
    profile_id: Uuid,
    cluster_epoch: Uuid,
    enabled: bool,
    certification_report_sha256: String,
    certified_until: DateTime<Utc>,
    image: String,
    snapshot_class: String,
    clone_storage_class: String,
    password_secret: String,
    signing_private_secret: String,
    signing_public_secret: String,
    settings: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    protocol: u32,
    bindings: Value,
    reviewed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    checks: BTreeMap<String, Check>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    result: String,
    evidence_sha256: String,
    observed_at: DateTime<Utc>,
}

pub struct ReviewedBackupProfile {
    artifact: Artifact,
    cloud: BackupCloudSettings,
    profile_sha256: String,
    spec_sha256: String,
}
#[derive(Serialize)]
pub struct StaticProfileReceipt {
    pub profile_id: Uuid,
    pub profile_sha256: String,
    pub profile_spec_sha256: String,
    pub report_sha256: String,
    pub registration_enabled: bool,
    pub live_activation_verified: bool,
}
impl ReviewedBackupProfile {
    pub fn parse(profile_bytes: &[u8], report_bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            !profile_bytes.is_empty()
                && profile_bytes.len() <= 65536
                && !report_bytes.is_empty()
                && report_bytes.len() <= 131072,
            "backup profile/report size rejected"
        );
        // One canonical interchange format rejects duplicate keys and prevents
        // reviewers, the database and the certification tool hashing different inputs.
        let a: Artifact =
            canonical_decode(profile_bytes).context("invalid canonical backup profile")?;
        let report: Report =
            canonical_decode(report_bytes).context("invalid canonical backup report")?;
        ensure!(
            a.protocol == 1 && !a.enabled && !a.profile_id.is_nil() && !a.cluster_epoch.is_nil(),
            "backup profiles must register disabled with exact identity"
        );
        ensure!(
            valid_sha256(&a.certification_report_sha256)
                && digest(report_bytes) == a.certification_report_sha256,
            "backup report digest mismatch"
        );
        ensure!(
            crate::nodeguard::protocol::pinned_image(&a.image),
            "backup image must have an immutable digest"
        );
        for name in [
            &a.snapshot_class,
            &a.clone_storage_class,
            &a.password_secret,
            &a.signing_private_secret,
            &a.signing_public_secret,
        ] {
            ensure!(valid_name(name), "invalid backup resource name");
        }
        ensure!(
            BTreeSet::from([
                &a.password_secret,
                &a.signing_private_secret,
                &a.signing_public_secret
            ])
            .len()
                == 3,
            "backup secrets must remain separate"
        );
        ensure!(
            [
                &a.password_secret,
                &a.signing_private_secret,
                &a.signing_public_secret
            ]
            .into_iter()
            .all(|name| name.starts_with("sbx-bkey-")),
            "backup key secrets require the protected installation prefix"
        );
        let cloud: BackupCloudSettings = serde_json::from_value(a.settings.clone())
            .map_err(|_| anyhow::anyhow!("invalid backup settings"))?;
        cloud
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid backup cloud identity"))?;
        ensure!(
            cloud.secret_bindings.password.name == a.password_secret
                && cloud.secret_bindings.signing_private.name == a.signing_private_secret
                && cloud.secret_bindings.signing_public.name == a.signing_public_secret,
            "backup secret bindings differ from the reviewed mounts"
        );
        ensure!(
            (31..=3650).contains(&cloud.vault_retention_days),
            "vault retention must cover supported backup requests"
        );
        for (name, role) in &cloud.roles {
            ensure!(
                role.arn.ends_with(&format!("-{name}")),
                "backup role ARN does not match its reviewed purpose"
            );
        }
        let mut raw: Value = serde_json::from_slice(profile_bytes)?;
        raw.as_object_mut()
            .context("profile must be an object")?
            .remove("certification_report_sha256");
        let spec_sha256 = digest(&serde_json::to_vec(&raw)?);
        let expected = json!({
            "profile_id":a.profile_id,"cluster_epoch":a.cluster_epoch,"image":a.image,
            "versions_lock_sha256":digest(include_bytes!("../deploy/backup/versions.lock.json")),
            "profile_spec_sha256":spec_sha256,
            "deployment":cloud.deployment,"account_id":cloud.account_id,"region":cloud.region,"bucket":cloud.bucket,"vault_bucket":cloud.vault_bucket,
            "kms_key_id":cloud.kms_key_id,"vault_kms_key_id":cloud.vault_kms_key_id,"clone_kms_key_id":cloud.clone_kms_key_id,
            "signing_key_sha256":cloud.signing_key_sha256,"vault_retention_days":cloud.vault_retention_days,
            "snapshot_class":a.snapshot_class,"clone_storage_class":a.clone_storage_class,
        });
        ensure!(
            report.protocol == 1 && report.bindings == expected,
            "backup report does not bind the full profile and tool versions"
        );
        let now = Utc::now();
        ensure!(
            report.reviewed_at <= now
                && now < report.expires_at
                && report.expires_at <= report.reviewed_at + Duration::days(30)
                && report.expires_at == a.certified_until,
            "backup certification window rejected"
        );
        ensure!(
            report
                .checks
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == CHECKS.into_iter().collect(),
            "backup certification checks incomplete"
        );
        for c in report.checks.values() {
            ensure!(
                c.result == "PASS"
                    && valid_sha256(&c.evidence_sha256)
                    && c.observed_at <= report.reviewed_at
                    && c.observed_at >= report.reviewed_at - Duration::days(7),
                "backup certification check rejected"
            );
        }
        Ok(Self {
            artifact: a,
            cloud,
            profile_sha256: digest(profile_bytes),
            spec_sha256,
        })
    }
    pub fn static_receipt(&self) -> StaticProfileReceipt {
        StaticProfileReceipt {
            profile_id: self.artifact.profile_id,
            profile_sha256: self.profile_sha256.clone(),
            profile_spec_sha256: self.spec_sha256.clone(),
            report_sha256: self.artifact.certification_report_sha256.clone(),
            registration_enabled: false,
            live_activation_verified: false,
        }
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Constructed only by live Kubernetes reads. It deliberately has no unchecked
/// constructor or Deserialize; the exported receipt is an audit record only.
pub struct VerifiedBackupKubernetes {
    profile_sha256: String,
    observed_at: DateTime<Utc>,
    objects: Value,
}
impl VerifiedBackupKubernetes {
    pub fn receipt(&self) -> Value {
        json!({"profile_sha256":self.profile_sha256,"observed_at":self.observed_at,"objects":self.objects})
    }
}
impl ReviewedBackupProfile {
    pub async fn verify_kubernetes(
        &self,
        runtime: &crate::runtime::KubernetesRuntime,
    ) -> anyhow::Result<VerifiedBackupKubernetes> {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.verify_kubernetes_inner(runtime),
        )
        .await
        .map_err(|_| anyhow::anyhow!("backup Kubernetes preflight exceeded deadline"))?
    }
    async fn verify_kubernetes_inner(
        &self,
        runtime: &crate::runtime::KubernetesRuntime,
    ) -> anyhow::Result<VerifiedBackupKubernetes> {
        use crate::backup_manifest::NAMESPACE;
        use k8s_openapi::api::core::v1::Secret;
        use kube::{
            Api,
            core::{ApiResource, DynamicObject, GroupVersionKind},
        };
        use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer, pem::PemObject};
        let jobs = crate::backup_job::BackupJobRuntime::new(runtime.clone());
        jobs.verify_network(&self.cloud)
            .await
            .map_err(|_| anyhow::anyhow!("backup network/runtime preflight failed"))?;
        jobs.verify_profile_secrets(&self.cloud)
            .await
            .map_err(|_| anyhow::anyhow!("backup protected secret preflight failed"))?;
        jobs.verify_clone_storage(&self.artifact.clone_storage_class, &self.cloud)
            .await
            .map_err(|_| anyhow::anyhow!("backup clone storage preflight failed"))?;
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "snapshot.storage.k8s.io",
            "v1",
            "VolumeSnapshotClass",
        ));
        let class = Api::<DynamicObject>::all_with(runtime.client_clone(), &resource)
            .get(&self.artifact.snapshot_class)
            .await
            .map_err(|_| anyhow::anyhow!("backup snapshot class unavailable"))?;
        crate::backup_runtime::validate_snapshot_class(
            &serde_json::to_value(&class)?,
            &self.cloud.deployment,
        )
        .map_err(|_| anyhow::anyhow!("backup snapshot class outside reviewed contract"))?;
        let mut objects = Vec::new();
        fn object(
            meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
            kind: &str,
        ) -> anyhow::Result<Value> {
            let uid = meta
                .uid
                .as_deref()
                .context("preflight object UID missing")?
                .parse::<Uuid>()?;
            let version = meta
                .resource_version
                .as_deref()
                .context("preflight object version missing")?;
            ensure!(
                !uid.is_nil() && !version.is_empty() && version.len() <= 128,
                "preflight object identity invalid"
            );
            Ok(json!({"kind":kind,"name":meta.name,"uid":uid,"resource_version":version}))
        }
        objects.push(object(&class.metadata, "VolumeSnapshotClass")?);
        let secrets = Api::<Secret>::namespaced(runtime.client_clone(), NAMESPACE);
        let mut keys = BTreeMap::new();
        for (binding, entry) in [
            (&self.cloud.secret_bindings.password, "password"),
            (&self.cloud.secret_bindings.signing_private, "private.pem"),
            (&self.cloud.secret_bindings.signing_public, "public.pem"),
        ] {
            let name = &binding.name;
            let secret = secrets
                .get(name)
                .await
                .map_err(|_| anyhow::anyhow!("backup secret unavailable"))?;
            ensure!(
                secret.metadata.deletion_timestamp.is_none()
                    && secret.immutable == Some(true)
                    && secret.type_.as_deref() == Some("Opaque")
                    && secret.string_data.is_none()
                    && secret
                        .metadata
                        .owner_references
                        .as_ref()
                        .is_none_or(Vec::is_empty)
                    && secret
                        .metadata
                        .finalizers
                        .as_ref()
                        .is_none_or(Vec::is_empty)
                    && secret.metadata.uid.as_deref() == Some(binding.uid.to_string().as_str()),
                "backup keys must be immutable Opaque secrets"
            );
            let data = secret.data.as_ref().context("backup secret data missing")?;
            ensure!(
                data.len() == 1 && data.contains_key(entry),
                "backup secret entries differ from the reviewed mount"
            );
            let bytes = data
                .get(entry)
                .context("backup secret entry missing")?
                .0
                .clone();
            ensure!(
                !bytes.is_empty() && bytes.len() <= 4096,
                "backup secret exceeds bounded key size"
            );
            ensure!(
                digest(&bytes) == binding.content_sha256,
                "backup secret contents differ from the reviewed key"
            );
            keys.insert(entry, bytes);
            objects.push(object(&secret.metadata, "Secret")?);
        }
        let password = keys.get("password").context("backup password missing")?;
        ensure!(
            (32..=1024).contains(&password.trim_ascii().len()),
            "backup repository key length rejected"
        );
        let public = SubjectPublicKeyInfoDer::from_pem_slice(
            keys.get("public.pem")
                .context("backup public key missing")?,
        )
        .map_err(|_| anyhow::anyhow!("backup public key encoding rejected"))?;
        const ED25519_SPKI: &[u8] = &[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        ensure!(
            public.as_ref().len() == 44
                && public.as_ref().starts_with(ED25519_SPKI)
                && digest(public.as_ref()) == self.cloud.signing_key_sha256,
            "backup public key does not match certified Ed25519 SPKI"
        );
        let private = PrivateKeyDer::from_pem_slice(
            keys.get("private.pem")
                .context("backup private key missing")?,
        )
        .map_err(|_| anyhow::anyhow!("backup private key encoding rejected"))?;
        let provider = rustls::crypto::ring::default_provider();
        let signing = provider
            .key_provider
            .load_private_key(private)
            .map_err(|_| anyhow::anyhow!("backup private key rejected"))?;
        ensure!(
            signing
                .public_key()
                .as_ref()
                .is_some_and(|key| key.as_ref() == public.as_ref()),
            "backup public and private signing keys differ"
        );
        // No private key/password material is serialized, returned or logged.
        Ok(VerifiedBackupKubernetes {
            profile_sha256: self.profile_sha256.clone(),
            observed_at: Utc::now(),
            objects: json!({"bindings":objects,"network_spec_sha256":digest(&serde_json::to_vec(&self.cloud.network_spec())?),"clone_storage_class":self.artifact.clone_storage_class,"signing_key_sha256":self.cloud.signing_key_sha256}),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn fixture() -> (Value, Value) {
        let now = Utc::now() - Duration::seconds(1);
        let secret_bindings = [
            ("password", "sbx-bkey-password"),
            ("signing_private", "sbx-bkey-signing"),
            ("signing_public", "sbx-bkey-public"),
        ]
        .into_iter()
        .map(|(purpose, name)| {
            (
                purpose,
                json!({"name":name,"uid":Uuid::new_v4(),"content_sha256":"a".repeat(64)}),
            )
        })
        .collect::<BTreeMap<_, _>>();
        let cloud = json!({"deployment":"sandbox","secret_bindings":secret_bindings,"vault_retention_days":31,"clone_kms_key_id":"clone-key","signing_key_sha256":"a".repeat(64),"vault_endpoint":"https://oss-cn-hangzhou-internal.aliyuncs.com","key_ref":"backup/key-v1","region":"cn-hangzhou","account_id":"1234567890123456","bucket":"fixture-backup","vault_bucket":"fixture-backup-vault","kms_key_id":"repo-key","vault_kms_key_id":"vault-key","issuer":"https://issuer.fixture.invalid","oidc_provider_arn":"acs:ram::1234567890123456:oidc-provider/fixture","roles":(["backup","backup-export","restore"].into_iter().map(|role|(role.to_owned(),json!({"arn":format!("acs:ram::1234567890123456:role/sandbox-{role}"),"subject":format!("system:serviceaccount:sandbox-system:sandbox-{role}")}))).collect::<BTreeMap<_,_>>())});
        let mut p = json!({"protocol":1,"profile_id":Uuid::new_v4(),"cluster_epoch":Uuid::new_v4(),"enabled":false,"certified_until":now+Duration::days(1),"image":format!("registry.fixture.invalid/backup@sha256:{}","b".repeat(64)),"snapshot_class":"snapshot-retain","clone_storage_class":"backup-retain","password_secret":"sbx-bkey-password","signing_private_secret":"sbx-bkey-signing","signing_public_secret":"sbx-bkey-public","settings":cloud});
        let mut bindings = json!({"versions_lock_sha256":digest(include_bytes!("../deploy/backup/versions.lock.json")),"profile_spec_sha256":digest(&serde_json::to_vec(&p).unwrap())});
        for key in [
            "profile_id",
            "cluster_epoch",
            "image",
            "snapshot_class",
            "clone_storage_class",
        ] {
            bindings[key] = p[key].clone();
        }
        for key in [
            "deployment",
            "account_id",
            "region",
            "bucket",
            "vault_bucket",
            "kms_key_id",
            "vault_kms_key_id",
            "clone_kms_key_id",
            "signing_key_sha256",
            "vault_retention_days",
        ] {
            bindings[key] = p["settings"][key].clone();
        }
        let report = json!({"protocol":1,"bindings":bindings,"reviewed_at":now,"expires_at":p["certified_until"],"checks":CHECKS.into_iter().map(|check|(check,json!({"result":"PASS","evidence_sha256":"c".repeat(64),"observed_at":now}))).collect::<BTreeMap<_,_>>()});
        p["certification_report_sha256"] = json!(digest(&serde_json::to_vec(&report).unwrap()));
        (p, report)
    }
    fn parse(p: &Value, r: &Value) -> anyhow::Result<ReviewedBackupProfile> {
        ReviewedBackupProfile::parse(&serde_json::to_vec(p)?, &serde_json::to_vec(r)?)
    }
    #[test]
    fn static_review_never_activates_and_full_spec_prevents_report_transplant() {
        let (p, r) = fixture();
        let reviewed = parse(&p, &r).unwrap().static_receipt();
        assert!(!reviewed.registration_enabled && !reviewed.live_activation_verified);
        for (path, value) in [
            ("/settings/deployment", json!("other-installation")),
            ("/settings/issuer", json!("https://other.fixture.invalid")),
            ("/settings/key_ref", json!("backup/different-key")),
            ("/signing_private_secret", json!("other-private-key")),
        ] {
            let mut changed = p.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(parse(&changed, &r).is_err());
        }
        let mut changed = p.clone();
        changed["enabled"] = json!(true);
        assert!(parse(&changed, &r).is_err());
    }
    #[test]
    fn historical_settings_only_support_closure_and_never_new_profile_activation()
    -> anyhow::Result<()> {
        let (mut profile, report) = fixture();
        profile["settings"]
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("settings"))?
            .remove("deployment");
        let cloud: BackupCloudSettings = serde_json::from_value(profile["settings"].clone())?;
        cloud.validate_historical()?;
        assert!(cloud.validate().is_err());
        assert!(parse(&profile, &report).is_err());
        let serialized = serde_json::to_value(cloud)?;
        assert!(serialized.get("deployment").is_none());
        Ok(())
    }
    #[test]
    fn duplicate_or_missing_evidence_and_wrong_tool_matrix_are_rejected() {
        let (p, r) = fixture();
        let mut malformed = p.clone();
        malformed["settings"]["vault_retention_days"] = json!("SECRET_INPUT_MUST_NOT_APPEAR");
        let error = parse(&malformed, &r).err().unwrap();
        assert!(!format!("{error:#}").contains("SECRET_INPUT_MUST_NOT_APPEAR"));
        let raw = serde_json::to_string(&p).unwrap();
        let duplicate = raw.replacen('{', "{\"protocol\":1,", 1);
        assert!(
            ReviewedBackupProfile::parse(duplicate.as_bytes(), &serde_json::to_vec(&r).unwrap())
                .is_err()
        );
        for field in ["check", "tool", "date"] {
            let mut r = r.clone();
            match field {
                "check" => {
                    r["checks"].as_object_mut().unwrap().remove(CHECKS[0]);
                }
                "tool" => r["bindings"]["versions_lock_sha256"] = json!("d".repeat(64)),
                _ => r["checks"][CHECKS[0]]["observed_at"] = json!(Utc::now() + Duration::days(1)),
            }
            let mut p = p.clone();
            p["certification_report_sha256"] = json!(digest(&serde_json::to_vec(&r).unwrap()));
            assert!(parse(&p, &r).is_err());
        }
    }
}

#[cfg(test)]
#[path = "backup_profile_integration_tests.rs"]
mod integration_tests;

#[cfg(test)]
pub(crate) use integration_tests::OwnerProfileTestAssets;
