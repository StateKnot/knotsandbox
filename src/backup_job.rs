//! Actual bounded Job I/O. A container exit is a data report only; nodeguard
//! closure and independent object verification are required elsewhere.
use crate::{
    backup_admission::{verify_job_object, verify_pod_object},
    backup_manifest::{self, BackupManifestContext, NAMESPACE},
    nodeguard::protocol::backup_job_name,
    runtime::{KubernetesRuntime, RuntimeError},
    runtime_manifest::ManifestError,
};
use chrono::{DateTime, Utc};
use k8s_openapi::api::{
    admissionregistration::v1::ValidatingWebhookConfiguration,
    batch::v1::Job,
    core::v1::{ConfigMap, Node, Pod, Secret},
    networking::v1::NetworkPolicy,
    node::v1::RuntimeClass,
    storage::v1::StorageClass,
};
use kube::{
    Api,
    api::{ListParams, Patch, PatchParams, PostParams},
    core::{ApiResource, DynamicObject, GroupVersionKind},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRole {
    pub arn: String,
    pub subject: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSecretBinding {
    pub name: String,
    pub uid: Uuid,
    pub content_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSecretBindings {
    pub password: BackupSecretBinding,
    pub signing_private: BackupSecretBinding,
    pub signing_public: BackupSecretBinding,
}
impl BackupSecretBindings {
    pub(crate) fn entries(&self) -> [(&'static str, &'static str, &BackupSecretBinding); 3] {
        [
            ("password", "password", &self.password),
            ("signing_private", "private.pem", &self.signing_private),
            ("signing_public", "public.pem", &self.signing_public),
        ]
    }
    fn validate(&self) -> bool {
        let entries = self.entries();
        entries.iter().all(|(_, _, binding)| {
            binding.name.starts_with("sbx-bkey-")
                && crate::backup_manifest::valid_name(&binding.name)
                && binding.name.len() > 9
                && !binding.uid.is_nil()
                && crate::nodeguard::protocol::valid_sha256(&binding.content_sha256)
        }) && (0..3).all(|i| {
            ((i + 1)..3).all(|j| {
                entries[i].2.uid != entries[j].2.uid && entries[i].2.name != entries[j].2.name
            })
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCloudSettings {
    #[serde(default, skip_serializing)]
    pub deployment: String,
    #[serde(skip_serializing)]
    pub secret_bindings: BackupSecretBindings,
    #[serde(skip_serializing)]
    pub signing_key_sha256: String,
    #[serde(skip_serializing)]
    pub vault_endpoint: String,
    #[serde(skip_serializing)]
    pub clone_kms_key_id: String,
    #[serde(skip_serializing)]
    pub vault_retention_days: u16,
    pub key_ref: String,
    pub region: String,
    pub account_id: String,
    pub bucket: String,
    pub vault_bucket: String,
    pub kms_key_id: String,
    pub vault_kms_key_id: String,
    pub issuer: String,
    pub oidc_provider_arn: String,
    pub roles: BTreeMap<String, BackupRole>,
}
pub(crate) fn valid_deployment(value: &str) -> bool {
    (4..=20).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
impl BackupCloudSettings {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        check(
            valid_deployment(&self.deployment),
            "reviewed backup deployment tag missing or malformed",
        )?;
        self.validate_historical()
    }
    // Historical source verification and already-closing Jobs use this check.
    // New storage and writer authority must validate the current deployment.
    pub(crate) fn validate_historical(&self) -> Result<(), RuntimeError> {
        check(
            self.secret_bindings.validate(),
            "invalid immutable backup Secret identities",
        )?;
        check(
            crate::nodeguard::protocol::valid_sha256(&self.signing_key_sha256)
                && self.vault_endpoint
                    == format!("https://oss-{}-internal.aliyuncs.com", self.region),
            "approved vault key/endpoint mismatch",
        )?;
        let origin = url::Url::parse(&self.issuer)
            .map_err(|_| ManifestError::InvalidConfiguration("backup issuer"))?;
        let bucket = |s: &str| {
            (3..=63).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !s.starts_with('-')
                && !s.ends_with('-')
        };
        let id = |s: &str| {
            !s.is_empty()
                && s.len() <= 256
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_:-".contains(&b))
        };
        check(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && self.account_id.len() == 16
                && self.account_id.bytes().all(|b| b.is_ascii_digit())
                && self.region.starts_with("cn-")
                && self.region.len() <= 32
                && self
                    .region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && bucket(&self.bucket)
                && bucket(&self.vault_bucket)
                && self.bucket != self.vault_bucket
                && id(&self.key_ref)
                && (31..=3650).contains(&self.vault_retention_days)
                && id(&self.clone_kms_key_id)
                && id(&self.kms_key_id)
                && id(&self.vault_kms_key_id)
                && self.kms_key_id != self.vault_kms_key_id
                && self
                    .oidc_provider_arn
                    .starts_with(&format!("acs:ram::{}:oidc-provider/", self.account_id))
                && self.roles.len() == 3,
            "invalid reviewed backup cloud settings",
        )?;
        for role in ["backup", "backup-export", "restore"] {
            let r = self
                .roles
                .get(role)
                .ok_or(ManifestError::InvalidConfiguration("backup role"))?;
            check(
                r.subject == format!("system:serviceaccount:sandbox-system:sandbox-{role}")
                    && r.arn
                        .starts_with(&format!("acs:ram::{}:role/", self.account_id))
                    && r.arn
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b":/-".contains(&b)),
                "backup role scope changed",
            )?;
        }
        Ok(())
    }
    pub fn network_spec(&self) -> Value {
        let selector =
            json!({"matchExpressions":[{"key":backup_manifest::BACKUP_LABEL,"operator":"Exists"}]});
        let hosts = [
            format!("{}.oss-{}-internal.aliyuncs.com", self.bucket, self.region),
            format!(
                "{}.oss-{}-internal.aliyuncs.com",
                self.vault_bucket, self.region
            ),
            format!("sts.{}.aliyuncs.com", self.region),
        ];
        let names: Vec<Value> = hosts.iter().map(|s| json!({"matchName":s})).collect();
        json!({"endpointSelector":selector,"ingress":[],"ingressDeny":[{"fromEntities":["all"]}],"egressDeny":[{"toCIDR":["169.254.0.0/16","100.100.100.200/32"]},{"toEntities":["host","remote-node","kube-apiserver"]}],"egress":[{"toEndpoints":[{"matchLabels":{"k8s:io.kubernetes.pod.namespace":"kube-system","k8s:k8s-app":"kube-dns"}}],"toPorts":[{"ports":[{"port":"53","protocol":"ANY"}],"rules":{"dns":names}}]},{"toFQDNs":names,"toPorts":[{"ports":[{"port":"443","protocol":"TCP"}]}]}]})
    }
}
fn check(ok: bool, why: &'static str) -> Result<(), RuntimeError> {
    if ok {
        Ok(())
    } else {
        Err(ManifestError::SpecificationDrift(why).into())
    }
}
fn encode(v: &impl Serialize) -> Result<Value, RuntimeError> {
    serde_json::to_value(v).map_err(|_| RuntimeError::MissingIdentity)
}
fn uid(v: Option<&str>) -> Result<Uuid, RuntimeError> {
    v.and_then(|s| Uuid::parse_str(s).ok())
        .filter(|u| !u.is_nil())
        .ok_or(RuntimeError::MissingIdentity)
}
#[derive(Clone)]
pub struct BackupJobRuntime {
    runtime: KubernetesRuntime,
}
#[derive(Clone, Debug)]
pub struct BackupJobObservation {
    pub job_uid: Uuid,
    pub pod: Option<ObservedBackupPod>,
}
#[derive(Clone, Debug)]
pub struct ObservedBackupPod {
    pub uid: Uuid,
    pub name: String,
    pub node_name: Option<String>,
    pub exit: Option<BackupJobExit>,
}
#[derive(Clone, Debug)]
pub struct BackupJobExit {
    pub exit_code: i32,
    pub report: Option<Value>,
    pub finished_at: DateTime<Utc>,
}
impl BackupJobRuntime {
    pub fn new(runtime: KubernetesRuntime) -> Self {
        Self { runtime }
    }
    /// Metadata-only receipt. Secret plaintext is never serialized or retained.
    pub(crate) async fn verify_profile_secrets(
        &self,
        cloud: &BackupCloudSettings,
    ) -> Result<Value, RuntimeError> {
        cloud.validate()?;
        let hook = Api::<ValidatingWebhookConfiguration>::all(self.runtime.client_clone())
            .get("sandbox-runtime-protection")
            .await?;
        check(
            hook.metadata.deletion_timestamp.is_none(),
            "backup Secret protection is deleting",
        )?;
        let hooks = hook
            .webhooks
            .as_ref()
            .ok_or(RuntimeError::MissingIdentity)?;
        let candidates: Vec<_> = hooks
            .iter()
            .filter(|h| h.name == "runtime.sandbox.platform")
            .collect();
        check(
            candidates.len() == 1,
            "backup Secret protection webhook missing",
        )?;
        let h = candidates[0];
        let service = h.client_config.service.as_ref();
        check(
            h.failure_policy.as_deref() == Some("Fail")
                && h.match_conditions.as_ref().is_none_or(Vec::is_empty)
                && h.namespace_selector.as_ref().is_none_or(|s| {
                    s.match_labels.as_ref().is_none_or(BTreeMap::is_empty)
                        && s.match_expressions.as_ref().is_none_or(Vec::is_empty)
                })
                && h.object_selector.as_ref().is_none_or(|s| {
                    s.match_labels.as_ref().is_none_or(BTreeMap::is_empty)
                        && s.match_expressions.as_ref().is_none_or(Vec::is_empty)
                })
                && h.client_config.url.is_none()
                && h.client_config
                    .ca_bundle
                    .as_ref()
                    .is_some_and(|b| !b.0.is_empty())
                && service.is_some_and(|s| {
                    s.name == "sandbox-admission"
                        && s.namespace == NAMESPACE
                        && s.path.as_deref() == Some("/validate")
                        && s.port == Some(443)
                })
                && h.rules.as_ref().is_some_and(|rules| {
                    ["CREATE", "UPDATE", "DELETE"].iter().all(|operation| {
                        rules.iter().any(|rule| {
                            rule.api_groups
                                .as_ref()
                                .is_some_and(|v| v.iter().any(|x| x.is_empty() || x == "*"))
                                && rule
                                    .api_versions
                                    .as_ref()
                                    .is_some_and(|v| v.iter().any(|x| x == "v1" || x == "*"))
                                && rule.resources.as_ref().is_some_and(|v| {
                                    v.iter().any(|x| x == "secrets" || x == "*" || x == "*/*")
                                })
                                && rule
                                    .operations
                                    .as_ref()
                                    .is_some_and(|v| v.iter().any(|x| x == operation || x == "*"))
                                && rule
                                    .scope
                                    .as_deref()
                                    .is_none_or(|s| s == "Namespaced" || s == "*")
                        })
                    })
                }),
            "backup Secret mutation protection absent or bypassable",
        )?;
        let secrets = Api::<Secret>::namespaced(self.runtime.client_clone(), NAMESPACE);
        for (_, key, binding) in cloud.secret_bindings.entries() {
            let secret = secrets.get(&binding.name).await?;
            check(
                secret.metadata.name.as_deref() == Some(binding.name.as_str())
                    && secret.metadata.namespace.as_deref() == Some(NAMESPACE)
                    && uid(secret.metadata.uid.as_deref())? == binding.uid
                    && secret.metadata.deletion_timestamp.is_none()
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
                    && secret.immutable == Some(true)
                    && secret.type_.as_deref() == Some("Opaque")
                    && secret.string_data.as_ref().is_none_or(BTreeMap::is_empty)
                    && secret.data.as_ref().is_some_and(|d| {
                        d.len() == 1
                            && d.get(key).is_some_and(|value| {
                                !value.0.is_empty()
                                    && value.0.len() <= 4096
                                    && hex::encode(Sha256::digest(&value.0))
                                        == binding.content_sha256
                            })
                    }),
                "approved backup Secret UID or content changed",
            )?;
        }
        encode(&cloud.secret_bindings)
    }
    pub(crate) fn runtime(&self) -> &KubernetesRuntime {
        &self.runtime
    }
    pub async fn verify_network(&self, settings: &BackupCloudSettings) -> Result<(), RuntimeError> {
        settings.validate()?;
        let cnp = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "cilium.io",
            "v2",
            "CiliumNetworkPolicy",
        ));
        let policies: Api<DynamicObject> =
            Api::namespaced_with(self.runtime.client_clone(), NAMESPACE, &cnp);
        let policy = policies.get("sandbox-backup-egress").await?;
        check(
            policy.metadata.deletion_timestamp.is_none()
                && policy.data.get("specs").is_none()
                && policy.data.get("spec") == Some(&settings.network_spec()),
            "backup egress policy drift",
        )?;
        // Other CNPs in this processing namespace can union-Allow traffic; require the
        // certified dedicated single-policy installation instead of ignoring them.
        let all = policies.list(&ListParams::default().limit(2)).await?;
        check(
            all.metadata.continue_.as_deref().is_none_or(str::is_empty)
                && all.items.len() == 1
                && all.items[0].metadata.uid == policy.metadata.uid
                && all.items[0].data == policy.data,
            "unreviewed additional backup namespace policy",
        )?;
        let baseline = Api::<NetworkPolicy>::namespaced(self.runtime.client_clone(), NAMESPACE)
            .get("sandbox-backup-default-deny")
            .await?;
        check(
            baseline.metadata.deletion_timestamp.is_none()
                && encode(&baseline)?.get("spec")
                    == Some(
                        &json!({"podSelector":{"matchExpressions":[{"key":backup_manifest::BACKUP_LABEL,"operator":"Exists"}]},"policyTypes":["Ingress","Egress"]}),
                    ),
            "backup default deny drift",
        )?;
        let native = Api::<NetworkPolicy>::namespaced(self.runtime.client_clone(), NAMESPACE)
            .list(&ListParams::default().limit(2))
            .await?;
        check(
            native
                .metadata
                .continue_
                .as_deref()
                .is_none_or(str::is_empty)
                && native.items.len() == 1
                && native.items[0].metadata.uid == baseline.metadata.uid,
            "unreviewed native backup namespace policy union",
        )?;
        let ccnp = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "cilium.io",
            "v2",
            "CiliumClusterwideNetworkPolicy",
        ));
        let all: Api<DynamicObject> = Api::all_with(self.runtime.client_clone(), &ccnp);
        let list = all.list(&ListParams::default().limit(4)).await?;
        check(
            list.metadata.continue_.as_deref().is_none_or(str::is_empty)
                && (2..=3).contains(&list.items.len()),
            "unreviewed clusterwide policy union",
        )?;
        let names: std::collections::BTreeSet<_> = list
            .items
            .iter()
            .filter_map(|p| p.metadata.name.as_deref())
            .collect();
        check(
            names.contains("sandbox-trusted-bootstrap") && names.contains("sandbox-host-bootstrap"),
            "required bootstrap policy missing",
        )?;
        for policy in list {
            check(
                policy.metadata.deletion_timestamp.is_none() && policy.data.get("specs").is_none(),
                "cluster policy deleting or multi-rule policy outside reviewed contract",
            )?;
            match policy.metadata.name.as_deref() {
                Some("sandbox-trusted-bootstrap") => check(
                    policy.data.pointer("/spec/endpointSelector")
                        == Some(
                            &json!({"matchExpressions":[{"key":"k8s:io.kubernetes.pod.namespace","operator":"In","values":["kube-system","sandbox-system"]},{"key":"k8s:sandbox.platform/backup-id","operator":"DoesNotExist"}]}),
                        ),
                    "bootstrap policy allows backup endpoints",
                )?,
                Some("sandbox-host-bootstrap") => check(
                    policy.data.pointer("/spec/nodeSelector").is_some()
                        && policy.data.pointer("/spec/endpointSelector").is_none(),
                    "host policy became endpoint policy",
                )?,
                Some("sandbox-metrics-agent-node-ingress") => check(
                    valid_metrics_host_policy(&policy.data),
                    "metrics policy must target only certified Kata hosts on its TLS port",
                )?,
                _ => {
                    return Err(
                        ManifestError::SpecificationDrift("unknown clusterwide policy").into(),
                    );
                }
            }
        }
        let class = Api::<RuntimeClass>::all(self.runtime.client_clone())
            .get("kata-backup-qemu")
            .await?;
        check(
            class.handler == "kata-qemu" && class.metadata.deletion_timestamp.is_none(),
            "backup runtime is not reviewed Kata",
        )?;
        Ok(())
    }
    pub(crate) async fn verify_clone_storage(
        &self,
        name: &str,
        cloud: &BackupCloudSettings,
    ) -> Result<(), RuntimeError> {
        cloud.validate()?;
        let class = Api::<StorageClass>::all(self.runtime.client_clone())
            .get(name)
            .await?;
        let wanted = BTreeMap::from([
            ("type".to_owned(), "cloud_essd".to_owned()),
            ("encrypted".to_owned(), "true".to_owned()),
            ("kmsKeyId".to_owned(), cloud.clone_kms_key_id.clone()),
            ("diskTags/Deployment".to_owned(), cloud.deployment.clone()),
        ]);
        check(
            class.metadata.deletion_timestamp.is_none()
                && class.provisioner == "diskplugin.csi.alibabacloud.com"
                && class.reclaim_policy.as_deref() == Some("Retain")
                && class.volume_binding_mode.as_deref() == Some("WaitForFirstConsumer")
                && class.allow_volume_expansion != Some(true)
                && class.parameters.as_ref() == Some(&wanted),
            "Clone storage class encryption, binding or retention drift",
        )
    }
    pub async fn ensure_job(
        &self,
        c: &BackupManifestContext,
        known_config: Option<Uuid>,
        known_job: Option<Uuid>,
    ) -> Result<(Uuid, Uuid), RuntimeError> {
        let objects = backup_manifest::build_backup_manifests(c)?;
        let configs = Api::<ConfigMap>::namespaced(self.runtime.client_clone(), NAMESPACE);
        let name = backup_manifest::config_name(c.attempt_id);
        let actual = match configs.get_opt(&name).await? {
            Some(v) => v,
            None => {
                check(known_config.is_none(), "recorded backup config disappeared")?;
                let body = serde_json::from_value(objects.config_map.clone())
                    .map_err(|_| RuntimeError::MissingIdentity)?;
                match configs.create(&PostParams::default(), &body).await {
                    Ok(v) => v,
                    Err(kube::Error::Api(e)) if e.code == 409 => configs.get(&name).await?,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let config_uid = uid(actual.metadata.uid.as_deref())?;
        check(
            known_config.is_none_or(|u| u == config_uid)
                && actual.metadata.deletion_timestamp.is_none()
                && actual.immutable == Some(true)
                && encode(&actual)?.get("data") == objects.config_map.get("data")
                && actual.binary_data.is_none(),
            "backup config identity/content changed",
        )?;
        let jobs = Api::<Job>::namespaced(self.runtime.client_clone(), NAMESPACE);
        let name = backup_job_name(c.attempt_id, c.stage);
        let job = match jobs.get_opt(&name).await? {
            Some(v) => v,
            None => {
                check(known_job.is_none(), "recorded backup Job disappeared")?;
                let body = serde_json::from_value(objects.job)
                    .map_err(|_| RuntimeError::MissingIdentity)?;
                match jobs.create(&PostParams::default(), &body).await {
                    Ok(v) => v,
                    Err(kube::Error::Api(e)) if e.code == 409 => jobs.get(&name).await?,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let job_uid = uid(job.metadata.uid.as_deref())?;
        check(
            known_job.is_none_or(|u| u == job_uid),
            "backup Job UID replaced",
        )?;
        verify_job_object(&encode(&job)?, c, job_uid)
            .map_err(|_| ManifestError::SpecificationDrift("backup Job spec changed"))?;
        Ok((config_uid, job_uid))
    }
    pub async fn start_and_observe(
        &self,
        c: &BackupManifestContext,
        job_uid: Uuid,
        known_pod: Option<Uuid>,
    ) -> Result<BackupJobObservation, RuntimeError> {
        let jobs = Api::<Job>::namespaced(self.runtime.client_clone(), NAMESPACE);
        let name = backup_job_name(c.attempt_id, c.stage);
        let job = jobs.get(&name).await?;
        check(
            uid(job.metadata.uid.as_deref())? == job_uid,
            "backup Job UID replaced",
        )?;
        verify_job_object(&encode(&job)?, c, job_uid)
            .map_err(|_| ManifestError::SpecificationDrift("backup Job changed"))?;
        if job.spec.as_ref().and_then(|s| s.suspend) == Some(true) {
            let version = job
                .metadata
                .resource_version
                .ok_or(RuntimeError::MissingIdentity)?;
            let patch = json!({"metadata":{"uid":job_uid,"resourceVersion":version},"spec":{"suspend":false}});
            jobs.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
                .await?;
        }
        let pods = Api::<Pod>::namespaced(self.runtime.client_clone(), NAMESPACE)
            .list(
                &ListParams::default()
                    .labels(&format!("batch.kubernetes.io/controller-uid={job_uid}"))
                    .limit(2),
            )
            .await?;
        check(
            pods.metadata.continue_.as_deref().is_none_or(str::is_empty) && pods.items.len() <= 1,
            "backup Job created multiple Pods",
        )?;
        let Some(pod) = pods.items.first() else {
            check(
                known_pod.is_none(),
                "recorded backup Pod disappeared before trusted cleanup",
            )?;
            return Ok(BackupJobObservation { job_uid, pod: None });
        };
        let pod_uid = uid(pod.metadata.uid.as_deref())?;
        check(
            known_pod.is_none_or(|u| u == pod_uid),
            "backup Job replaced Pod",
        )?;
        let value = encode(pod)?;
        verify_pod_object(&value, c, job_uid, pod_uid)
            .map_err(|_| ManifestError::SpecificationDrift("backup Pod changed"))?;
        let exit = pod
            .status
            .as_ref()
            .and_then(|s| s.container_statuses.as_ref())
            .and_then(|cs| cs.iter().find(|v| v.name == "backup"))
            .and_then(|c| c.state.as_ref())
            .and_then(|s| s.terminated.as_ref())
            .map(|end| -> Result<BackupJobExit, RuntimeError> {
                let finished_at = end
                    .finished_at
                    .as_ref()
                    .and_then(|t| DateTime::parse_from_rfc3339(&t.0.to_string()).ok())
                    .map(|t| t.with_timezone(&Utc))
                    .ok_or(RuntimeError::MissingIdentity)?;
                check(
                    finished_at <= Utc::now(),
                    "backup termination report time invalid",
                )?;
                let report = end
                    .message
                    .as_ref()
                    .filter(|s| s.len() <= 4096)
                    .and_then(|s| serde_json::from_str(s).ok());
                Ok(BackupJobExit {
                    exit_code: end.exit_code,
                    report,
                    finished_at,
                })
            })
            .transpose()?;
        Ok(BackupJobObservation {
            job_uid,
            pod: Some(ObservedBackupPod {
                uid: pod_uid,
                name: pod
                    .metadata
                    .name
                    .clone()
                    .ok_or(RuntimeError::MissingIdentity)?,
                node_name: pod.spec.as_ref().and_then(|s| s.node_name.clone()),
                exit,
            }),
        })
    }
    pub async fn node(&self, name: &str) -> Result<Node, RuntimeError> {
        Ok(Api::<Node>::all(self.runtime.client_clone())
            .get(name)
            .await?)
    }
}

impl BackupJobRuntime {
    pub(crate) async fn ensure_capture_config(
        &self,
        value: &Value,
        known: Option<Uuid>,
    ) -> Result<Uuid, RuntimeError> {
        let name = value
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::MissingIdentity)?;
        let configs = Api::<ConfigMap>::namespaced(self.runtime.client_clone(), NAMESPACE);
        let actual = match configs.get_opt(name).await? {
            Some(v) => v,
            None => {
                check(known.is_none(), "Recorded capture report disappeared")?;
                let body = serde_json::from_value(value.clone())
                    .map_err(|_| RuntimeError::MissingIdentity)?;
                match configs.create(&PostParams::default(), &body).await {
                    Ok(v) => v,
                    Err(kube::Error::Api(e)) if e.code == 409 => configs.get(name).await?,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let actual_uid = uid(actual.metadata.uid.as_deref())?;
        check(
            known.is_none_or(|v| v == actual_uid)
                && actual.metadata.deletion_timestamp.is_none()
                && actual.immutable == Some(true)
                && actual.binary_data.is_none()
                && encode(&actual)?.get("data") == value.get("data")
                && encode(&actual)?.pointer("/metadata/labels")
                    == value.pointer("/metadata/labels"),
            "Capture handoff config changed",
        )?;
        Ok(actual_uid)
    }
}

fn valid_metrics_host_policy(value: &Value) -> bool {
    if value.get("specs").is_some() {
        return false;
    }
    let Some(spec) = value.get("spec").and_then(Value::as_object) else {
        return false;
    };
    let Some(selector) = spec.get("nodeSelector").and_then(Value::as_object) else {
        return false;
    };
    let Some(expressions) = selector.get("matchExpressions").and_then(Value::as_array) else {
        return false;
    };
    let Some(rule) = expressions.first().and_then(Value::as_object) else {
        return false;
    };
    let Some(names) = rule.get("values").and_then(Value::as_array) else {
        return false;
    };
    spec.len() == 2
        && selector.len() == 2
        && expressions.len() == 1
        && rule.len() == 3
        && selector.get("matchLabels") == Some(&json!({"sandbox.platform/node-pool":"kata"}))
        && rule.get("key") == Some(&json!("kubernetes.io/hostname"))
        && rule.get("operator") == Some(&json!("In"))
        && !names.is_empty()
        && names.len() <= 10000
        && names
            .iter()
            .all(|n| n.as_str().is_some_and(backup_manifest::valid_name))
        && spec.get("ingress")
            == Some(
                &json!([{"fromEndpoints":[{"matchLabels":{"k8s:io.kubernetes.pod.namespace":"sandbox-observability","k8s:app.kubernetes.io/name":"sandbox-metrics-agent"}}],"toPorts":[{"ports":[{"port":"9445","protocol":"TCP"}]}]}]),
            )
}
