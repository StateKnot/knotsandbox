//! Production parsers and private capabilities are exercised through real OSS
//! TLS and a stateful synthetic Kubernetes API. No cloud certification is claimed.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::{
    bucket_retention::{BucketRetentionExpectation, test_live_verifier},
    db::Database,
    runtime::KubernetesRuntime,
    test_support_db,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use k8s_openapi::api::core::v1::Secret;
use kube::{Client, client::Body as KubeBody};
use std::{
    convert::Infallible,
    process::Command,
    sync::{Arc, Mutex},
};
type Objects = Arc<Mutex<BTreeMap<String, Value>>>;
struct LiveFixture {
    profile: ReviewedBackupProfile,
    expected: BucketRetentionExpectation,
    runtime: KubernetesRuntime,
    objects: Objects,
    secret_password: Vec<u8>,
    secret_private: Vec<u8>,
    public_der: Vec<u8>,
    profile_document: Value,
    report_document: Value,
}

// Ordinary generated test material, never an activation capability. Each
// activation below obtains fresh opaque production verification results.
pub(crate) struct OwnerProfileTestAssets {
    live: LiveFixture,
}
impl OwnerProfileTestAssets {
    pub(crate) fn new(epoch: Uuid) -> anyhow::Result<Self> {
        Ok(Self {
            live: LiveFixture::new(epoch)?,
        })
    }
    pub(crate) fn profile_id(&self) -> Uuid {
        self.live.profile.artifact.profile_id
    }
    pub(crate) fn cloud(&self) -> &Value {
        &self.live.profile.artifact.settings
    }
    pub(crate) fn private_key(&self) -> &[u8] {
        &self.live.secret_private
    }
    pub(crate) fn public_spki(&self) -> &[u8] {
        &self.live.public_der
    }
    pub(crate) fn secret_objects(&self) -> anyhow::Result<BTreeMap<String, Value>> {
        let objects = self
            .live
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("generated fixture Secret objects"))?;
        let mut secrets = BTreeMap::new();
        for (_, _, identity) in self.live.profile.cloud.secret_bindings.entries() {
            let path = format!(
                "/api/v1/namespaces/{}/secrets/{}",
                crate::backup_manifest::NAMESPACE,
                identity.name
            );
            secrets.insert(
                path.clone(),
                objects
                    .get(&path)
                    .context("actual generated profile Secret")?
                    .clone(),
            );
        }
        Ok(secrets)
    }
    pub(crate) fn reissue(&self, epoch: Uuid) -> anyhow::Result<Self> {
        let now = Utc::now() - Duration::seconds(1);
        let mut document = self.live.profile_document.clone();
        let profile = document
            .as_object_mut()
            .context("normal profile artifact")?;
        profile.remove("certification_report_sha256");
        profile.insert("profile_id".into(), json!(Uuid::new_v4()));
        profile.insert("cluster_epoch".into(), json!(epoch));
        profile.insert("certified_until".into(), json!(now + Duration::days(2)));
        let mut bindings = json!({"versions_lock_sha256":digest(include_bytes!("../deploy/backup/versions.lock.json")),"profile_spec_sha256":digest(&serde_json::to_vec(&document)?)});
        for field in [
            "profile_id",
            "cluster_epoch",
            "image",
            "snapshot_class",
            "clone_storage_class",
        ] {
            bindings[field] = document[field].clone();
        }
        for field in [
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
            bindings[field] = document["settings"][field].clone();
        }
        let report = json!({"protocol":1,"bindings":bindings,"reviewed_at":now,"expires_at":document["certified_until"],"checks":CHECKS.into_iter().map(|name|(name,json!({"result":"PASS","evidence_sha256":"c".repeat(64),"observed_at":now}))).collect::<BTreeMap<_,_>>()});
        document["certification_report_sha256"] = json!(digest(&serde_json::to_vec(&report)?));
        let reviewed = ReviewedBackupProfile::parse(
            &serde_json::to_vec(&document)?,
            &serde_json::to_vec(&report)?,
        )?;
        let previous = &self.live.profile;
        ensure!(
            reviewed.artifact.settings == previous.artifact.settings
                && reviewed.artifact.profile_id != previous.artifact.profile_id
                && reviewed.artifact.cluster_epoch != previous.artifact.cluster_epoch
                && reviewed.artifact.certification_report_sha256
                    != previous.artifact.certification_report_sha256,
            "Q changes identity/review while retaining exact generated secret material and decrypt settings"
        );
        let mut expected = self.live.expected.clone();
        expected.profile_id = reviewed.artifact.profile_id;
        expected.cluster_epoch = epoch;
        expected.certified_until = reviewed.artifact.certified_until;
        expected.anchor_key = format!(
            "certification/{epoch}/{}/anchor",
            reviewed.artifact.profile_id
        );
        reviewed.validate_retention_expectation(&expected)?;
        Ok(Self {
            live: LiveFixture {
                profile: reviewed,
                expected,
                runtime: self.live.runtime.clone(),
                objects: self.live.objects.clone(),
                secret_password: self.live.secret_password.clone(),
                secret_private: self.live.secret_private.clone(),
                public_der: self.live.public_der.clone(),
                profile_document: document,
                report_document: report,
            },
        })
    }
    pub(crate) async fn activate(&self, owner: &Database) -> anyhow::Result<()> {
        let p = &self.live.profile;
        let registration = register_profile(
            owner,
            p,
            Uuid::new_v4(),
            "PUBLIC_MATCHED_EXPECTATIONS_NOT_CLOUD_CERT/register",
        )
        .await?;
        ensure!(
            !registration.current_enabled,
            "normal new profile registers disabled"
        );
        let kube = p.verify_kubernetes(&self.live.runtime).await?;
        let (_directory, verifier, server) = test_live_verifier(self.live.expected.clone()).await;
        let result = Box::pin(async {
            let vault = verifier.verify().await?;
            sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton").execute(&owner.pool).await?;
            let activation = activate_profile(owner, p, Uuid::new_v4(), "PUBLIC_MATCHED_EXPECTATIONS_NOT_CLOUD_CERT/activate", &kube, &vault).await?;
            ensure!(activation.current_enabled && !activation.replayed, "normal owner activates newly verified exact profile");
            let (row, actions): (Value, i64) = sqlx::query_as("SELECT to_jsonb(p),(SELECT count(*) FROM backup_profile_actions a WHERE a.profile_id=p.id AND a.action IN('REGISTER','ACTIVATE')) FROM backup_profiles p WHERE p.id=$1")
                .bind(p.artifact.profile_id).fetch_one(&owner.pool).await?;
            ensure!(actions == 2 && row["enabled"] == json!(true)
                && row["cluster_epoch"] == json!(p.artifact.cluster_epoch)
                && row["certification_sha256"] == json!(p.artifact.certification_report_sha256)
                && row["settings"] == p.artifact.settings, "actual enabled tuple and two normal owner actions");
            Ok::<_, anyhow::Error>(())
        }).await;
        // Existing TLS test server shutdown API is abort-on-drop, not a joined
        // physical drain receipt; no such claim is made by this helper.
        server.shutdown();
        let reset =
            sqlx::query("UPDATE platform_configuration SET safe_mode=false WHERE singleton")
                .execute(&owner.pool)
                .await;
        result?;
        reset?;
        Ok(())
    }
}
fn metadata(name: &str) -> Value {
    json!({"name":name,"uid":Uuid::new_v4(),"resourceVersion":"1"})
}
fn list(items: Vec<Value>) -> Value {
    json!({"apiVersion":"v1","kind":"List","metadata":{},"items":items})
}
fn openssl(args: &[&std::ffi::OsStr]) -> anyhow::Result<()> {
    let binary = std::env::var_os("BACKUP_OPENSSL_BIN").unwrap_or_else(|| "openssl".into());
    ensure!(
        Command::new(binary).args(args).output()?.status.success(),
        "OpenSSL test key generation failed"
    );
    Ok(())
}
impl LiveFixture {
    fn new(epoch: Uuid) -> anyhow::Result<Self> {
        Self::for_profile(epoch, Uuid::new_v4())
    }
    fn for_profile(epoch: Uuid, profile_id: Uuid) -> anyhow::Result<Self> {
        let key_dir = tempfile::tempdir()?;
        let private_path = key_dir.path().join("private.pem");
        let public_path = key_dir.path().join("public.pem");
        let der_path = key_dir.path().join("public.der");
        openssl(&[
            "genpkey".as_ref(),
            "-algorithm".as_ref(),
            "Ed25519".as_ref(),
            "-out".as_ref(),
            private_path.as_os_str(),
        ])?;
        openssl(&[
            "pkey".as_ref(),
            "-in".as_ref(),
            private_path.as_os_str(),
            "-pubout".as_ref(),
            "-out".as_ref(),
            public_path.as_os_str(),
        ])?;
        openssl(&[
            "pkey".as_ref(),
            "-pubin".as_ref(),
            "-in".as_ref(),
            public_path.as_os_str(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-out".as_ref(),
            der_path.as_os_str(),
        ])?;
        let secret_private = std::fs::read(private_path)?;
        let secret_public = std::fs::read(public_path)?;
        let public_der = std::fs::read(der_path)?;
        let secret_password =
            b"TEST_REPOSITORY_PASSWORD_MUST_NOT_ENTER_RECEIPT_0123456789".to_vec();
        let namespace = crate::backup_manifest::NAMESPACE;
        let mut objects = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        for (purpose, name, entry, bytes) in [
            (
                "password",
                "sbx-bkey-password",
                "password",
                &secret_password,
            ),
            (
                "signing_private",
                "sbx-bkey-private",
                "private.pem",
                &secret_private,
            ),
            (
                "signing_public",
                "sbx-bkey-public",
                "public.pem",
                &secret_public,
            ),
        ] {
            let mut m = metadata(name);
            m["namespace"] = json!(namespace);
            bindings.insert(
                purpose,
                json!({"name":name,"uid":m["uid"],"content_sha256":digest(bytes)}),
            );
            let secret = json!({"apiVersion":"v1","kind":"Secret","metadata":m,"type":"Opaque","immutable":true,"data":{entry:STANDARD.encode(bytes)}});
            // Ensure the wire fixture has actual Kubernetes Secret semantics.
            let _: Secret = serde_json::from_value(secret.clone())?;
            objects.insert(
                format!("/api/v1/namespaces/{namespace}/secrets/{name}"),
                secret,
            );
        }
        objects.insert("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/sandbox-runtime-protection".into(),json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":metadata("sandbox-runtime-protection"),"webhooks":[{"name":"runtime.sandbox.platform","failurePolicy":"Fail","sideEffects":"None","admissionReviewVersions":["v1"],"clientConfig":{"service":{"name":"sandbox-admission","namespace":"sandbox-system","path":"/validate","port":443},"caBundle":STANDARD.encode(include_bytes!("../tests/fixtures/admission/server-ca.pem"))},"rules":[{"apiGroups":[""],"apiVersions":["v1"],"operations":["CREATE","UPDATE","DELETE"],"resources":["secrets"],"scope":"Namespaced"}]}]}));
        let cloud = json!({"deployment":"fixture","secret_bindings":bindings,"vault_retention_days":31,"clone_kms_key_id":"clone-key","signing_key_sha256":digest(&public_der),"vault_endpoint":"https://oss-cn-hangzhou-internal.aliyuncs.com","key_ref":"backup/key-v1","region":"cn-hangzhou","account_id":"1234567890123456","bucket":"fixture-source","vault_bucket":"fixture-vault","kms_key_id":"source-key","vault_kms_key_id":"kms-fixture","issuer":"https://issuer.fixture.invalid","oidc_provider_arn":"acs:ram::1234567890123456:oidc-provider/fixture","roles":(["backup","backup-export","restore"].into_iter().map(|role|(role.to_owned(),json!({"arn":format!("acs:ram::1234567890123456:role/fixture-{role}"),"subject":format!("system:serviceaccount:sandbox-system:sandbox-{role}")}))).collect::<BTreeMap<_,_>>())});
        let now = Utc::now() - Duration::seconds(1);
        let mut p = json!({"protocol":1,"profile_id":profile_id,"cluster_epoch":epoch,"enabled":false,"certified_until":now+Duration::days(1),"image":format!("registry.fixture.invalid/backup@sha256:{}","b".repeat(64)),"snapshot_class":"snapshot-retain","clone_storage_class":"backup-retain","password_secret":"sbx-bkey-password","signing_private_secret":"sbx-bkey-private","signing_public_secret":"sbx-bkey-public","settings":cloud});
        let mut report_bindings = json!({"versions_lock_sha256":digest(include_bytes!("../deploy/backup/versions.lock.json")),"profile_spec_sha256":digest(&serde_json::to_vec(&p)?)});
        for key in [
            "profile_id",
            "cluster_epoch",
            "image",
            "snapshot_class",
            "clone_storage_class",
        ] {
            report_bindings[key] = p[key].clone();
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
            report_bindings[key] = p["settings"][key].clone();
        }
        let report = json!({"protocol":1,"bindings":report_bindings,"reviewed_at":now,"expires_at":p["certified_until"],"checks":CHECKS.into_iter().map(|check|(check,json!({"result":"PASS","evidence_sha256":"c".repeat(64),"observed_at":now}))).collect::<BTreeMap<_,_>>()});
        p["certification_report_sha256"] = json!(digest(&serde_json::to_vec(&report)?));
        let profile =
            ReviewedBackupProfile::parse(&serde_json::to_vec(&p)?, &serde_json::to_vec(&report)?)?;
        let cnp = json!({"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":metadata("sandbox-backup-egress"),"spec":profile.cloud.network_spec()});
        let np = json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":metadata("sandbox-backup-default-deny"),"spec":{"podSelector":{"matchExpressions":[{"key":"sandbox.platform/backup-id","operator":"Exists"}]},"policyTypes":["Ingress","Egress"]}});
        for (path, value) in [
            (
                format!(
                    "/apis/cilium.io/v2/namespaces/{namespace}/ciliumnetworkpolicies/sandbox-backup-egress"
                ),
                cnp.clone(),
            ),
            (
                format!("/apis/cilium.io/v2/namespaces/{namespace}/ciliumnetworkpolicies"),
                list(vec![cnp]),
            ),
            (
                format!(
                    "/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/sandbox-backup-default-deny"
                ),
                np.clone(),
            ),
            (
                format!("/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies"),
                list(vec![np]),
            ),
            (
                "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies".into(),
                list(vec![
                    json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":metadata("sandbox-trusted-bootstrap"),"spec":{"endpointSelector":{"matchExpressions":[{"key":"k8s:io.kubernetes.pod.namespace","operator":"In","values":["kube-system","sandbox-system"]},{"key":"k8s:sandbox.platform/backup-id","operator":"DoesNotExist"}]}}}),
                    json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":metadata("sandbox-host-bootstrap"),"spec":{"nodeSelector":{}}}),
                ]),
            ),
            (
                "/apis/node.k8s.io/v1/runtimeclasses/kata-backup-qemu".into(),
                json!({"apiVersion":"node.k8s.io/v1","kind":"RuntimeClass","metadata":metadata("kata-backup-qemu"),"handler":"kata-qemu"}),
            ),
            (
                "/apis/storage.k8s.io/v1/storageclasses/backup-retain".into(),
                json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":metadata("backup-retain"),"provisioner":"diskplugin.csi.alibabacloud.com","reclaimPolicy":"Retain","volumeBindingMode":"WaitForFirstConsumer","parameters":{"type":"cloud_essd","encrypted":"true","kmsKeyId":"clone-key","diskTags/Deployment":"fixture"}}),
            ),
            (
                "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/snapshot-retain".into(),
                json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotClass","metadata":metadata("snapshot-retain"),"driver":"diskplugin.csi.alibabacloud.com","deletionPolicy":"Retain","parameters":{"snapshotTags/Deployment":"fixture"}}),
            ),
        ] {
            objects.insert(path, value);
        }
        let objects = Arc::new(Mutex::new(objects));
        let wire = objects.clone();
        let service = tower::service_fn(move |r: axum::http::Request<KubeBody>| {
            let wire = wire.clone();
            async move {
                assert_eq!(r.method(), axum::http::Method::GET);
                let value = wire.lock().unwrap().get(r.uri().path()).cloned();
                let status = if value.is_some() { 200 } else { 404 };
                let value = value.unwrap_or_else(||json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}));
                Ok::<_, Infallible>(
                    axum::http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(serde_json::to_vec(&value).unwrap()))
                        .unwrap(),
                )
            }
        });
        let expected = BucketRetentionExpectation {
            profile_id,
            cluster_epoch: epoch,
            deployment: "fixture".into(),
            profile_settings_sha256: digest(&serde_json::to_vec(&profile.artifact.settings)?),
            account_id: profile.cloud.account_id.clone(),
            region: profile.cloud.region.clone(),
            bucket: profile.cloud.vault_bucket.clone(),
            kms_key_id: profile.cloud.vault_kms_key_id.clone(),
            vault_retention_days: 31,
            certified_until: profile.artifact.certified_until,
            anchor_key: format!("certification/{epoch}/{profile_id}/anchor"),
            anchor_etag: "\"opaque-anchor\"".into(),
            anchor_size_bytes: 64,
        };
        Ok(Self {
            profile,
            expected,
            runtime: KubernetesRuntime::from_client(Client::new(service, namespace)),
            objects,
            secret_password,
            secret_private,
            public_der,
            profile_document: p,
            report_document: report,
        })
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL roles, OpenSSL3 and loopback TLS"]
async fn legacy_missing_deployment_owner_paths_reject_old_tuple_and_activate_new_profile()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let base = test_support_db::Fixture::new(10).await?;
    let owner = Database {
        pool: base.owner.clone(),
    };
    let epoch: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&owner.pool)
            .await?;
    let f = LiveFixture::new(epoch)?;
    let mut old_profile = f.profile_document.clone();
    let mut old_report = f.report_document.clone();
    old_profile["settings"]
        .as_object_mut()
        .context("settings")?
        .remove("deployment");
    old_report["bindings"]
        .as_object_mut()
        .context("report bindings")?
        .remove("deployment");
    let mut old_spec = old_profile.clone();
    old_spec
        .as_object_mut()
        .context("profile")?
        .remove("certification_report_sha256");
    old_report["bindings"]["profile_spec_sha256"] = json!(digest(&serde_json::to_vec(&old_spec)?));
    let old_report_bytes = serde_json::to_vec(&old_report)?;
    old_profile["certification_report_sha256"] = json!(digest(&old_report_bytes));
    let old_profile_bytes = serde_json::to_vec(&old_profile)?;
    let rejected = ReviewedBackupProfile::parse(&old_profile_bytes, &old_report_bytes)
        .err()
        .context("legacy profile must not become a current reviewed capability")?;
    assert_eq!(rejected.to_string(), "invalid backup cloud identity");
    // Canonical documents and recomputed hashes reached the actual cloud gate;
    // this is not a deliberately broken report checksum.
    let cloud: BackupCloudSettings = serde_json::from_value(old_profile["settings"].clone())?;
    cloud.validate_historical()?;
    assert!(cloud.validate().is_err());
    let a = &f.profile.artifact;
    sqlx::query("INSERT INTO backup_profiles(id,cluster_epoch,enabled,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings) VALUES($1,$2,false,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(a.profile_id).bind(a.cluster_epoch).bind(old_profile["certification_report_sha256"].as_str().context("old report digest")?)
        .bind(a.certified_until).bind(&a.image).bind(&a.snapshot_class).bind(&a.clone_storage_class)
        .bind(&a.password_secret).bind(&a.signing_private_secret).bind(&a.signing_public_secret)
        .bind(&old_profile["settings"]).execute(&owner.pool).await?;
    let before: Value = sqlx::query_scalar("SELECT to_jsonb(p) FROM backup_profiles p WHERE id=$1")
        .bind(a.profile_id)
        .fetch_one(&owner.pool)
        .await?;
    let registration = register_profile(
        &owner,
        &f.profile,
        Uuid::new_v4(),
        "legacy/current-reviewed-register",
    )
    .await
    .err()
    .context("legacy immutable tuple cannot be replaced by registration")?;
    assert_eq!(
        registration.to_string(),
        "registered profile differs; register a new immutable profile UUID"
    );
    let kube = f.profile.verify_kubernetes(&f.runtime).await?;
    let (_temp, verifier, server) = test_live_verifier(f.expected.clone()).await;
    let vault = verifier.verify().await?;
    sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton")
        .execute(&owner.pool)
        .await?;
    let result: anyhow::Result<()> = async {
        let activation = activate_profile(&owner,&f.profile,Uuid::new_v4(),"legacy/current-reviewed-activate",&kube,&vault)
            .await.err().context("legacy immutable tuple cannot activate from new evidence")?;
        assert_eq!(activation.to_string(),"registered profile differs; register a new immutable profile UUID");
        let (after,actions):(Value,i64) = sqlx::query_as("SELECT to_jsonb(p),(SELECT count(*) FROM backup_profile_actions WHERE profile_id=p.id) FROM backup_profiles p WHERE id=$1")
            .bind(a.profile_id).fetch_one(&owner.pool).await?;
        assert_eq!(after,before);
        assert_eq!(actions,0);
        assert_eq!(after["enabled"],false);
        assert!(after["settings"].get("deployment").is_none());
        // A fresh UUID with a valid current Deployment contract remains usable.
        let current = LiveFixture::new(epoch)?;
        assert_eq!(current.profile.cloud.deployment,"fixture");
        let registered = register_profile(&owner,&current.profile,Uuid::new_v4(),"legacy/new-version-register").await?;
        assert!(!registered.current_enabled);
        let current_kube = current.profile.verify_kubernetes(&current.runtime).await?;
        let (_current_temp,current_verifier,current_server) = test_live_verifier(current.expected.clone()).await;
        let current_result: anyhow::Result<()> = async {
            let current_vault = current_verifier.verify().await?;
            let activated = activate_profile(&owner,&current.profile,Uuid::new_v4(),"legacy/new-version-activate",&current_kube,&current_vault).await?;
            assert!(activated.current_enabled);
            let actions:i64 = sqlx::query_scalar("SELECT count(*) FROM backup_profile_actions WHERE profile_id=$1 AND action IN('REGISTER','ACTIVATE')")
                .bind(current.profile.artifact.profile_id).fetch_one(&owner.pool).await?;
            assert_eq!(actions,2);
            Ok(())
        }.await;
        current_server.shutdown();
        current_result
    }.await;
    server.shutdown();
    sqlx::query("UPDATE platform_configuration SET safe_mode=false WHERE singleton")
        .execute(&owner.pool)
        .await?;
    result
}
#[tokio::test]
async fn live_kubernetes_preflight_rejects_key_replacement_and_never_exports_secrets()
-> anyhow::Result<()> {
    let f = LiveFixture::new(Uuid::new_v4())?;
    let proof = f.profile.verify_kubernetes(&f.runtime).await?;
    let receipt = serde_json::to_string(&proof.receipt())?;
    assert!(!receipt.contains(std::str::from_utf8(&f.secret_password)?));
    assert!(!receipt.contains(&STANDARD.encode(&f.secret_private)));
    let path = format!(
        "/api/v1/namespaces/{}/secrets/sbx-bkey-password",
        crate::backup_manifest::NAMESPACE
    );
    let original = f.objects.lock().unwrap()[&path].clone();
    f.objects.lock().unwrap().get_mut(&path).unwrap()["data"]["password"] =
        json!(STANDARD.encode(b"ANOTHER_PASSWORD_WITH_SAME_NAME_0123456789"));
    assert!(f.profile.verify_kubernetes(&f.runtime).await.is_err());
    f.objects
        .lock()
        .unwrap()
        .insert(path.clone(), original.clone());
    f.objects.lock().unwrap().get_mut(&path).unwrap()["metadata"]["uid"] = json!(Uuid::new_v4());
    assert!(f.profile.verify_kubernetes(&f.runtime).await.is_err());
    f.objects.lock().unwrap().insert(path.clone(), original);
    let webhook_path = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/sandbox-runtime-protection";
    f.objects.lock().unwrap().get_mut(webhook_path).unwrap()["webhooks"][0]["failurePolicy"] =
        json!("Ignore");
    assert!(f.profile.verify_kubernetes(&f.runtime).await.is_err());
    Ok(())
}
#[tokio::test]
async fn live_kubernetes_preflight_rejects_missing_foreign_and_extra_storage_tags()
-> anyhow::Result<()> {
    let f = LiveFixture::new(Uuid::new_v4())?;
    for (path, parameters) in [
        (
            "/apis/storage.k8s.io/v1/storageclasses/backup-retain",
            json!({"type":"cloud_essd","encrypted":"true","kmsKeyId":"clone-key"}),
        ),
        (
            "/apis/storage.k8s.io/v1/storageclasses/backup-retain",
            json!({"type":"cloud_essd","encrypted":"true","kmsKeyId":"clone-key","diskTags/Deployment":"foreign"}),
        ),
        (
            "/apis/storage.k8s.io/v1/storageclasses/backup-retain",
            json!({"type":"cloud_essd","encrypted":"true","kmsKeyId":"clone-key","diskTags/Deployment":"fixture","unexpected":"yes"}),
        ),
        (
            "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/snapshot-retain",
            json!({}),
        ),
        (
            "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/snapshot-retain",
            json!({"snapshotTags/Deployment":"foreign"}),
        ),
        (
            "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/snapshot-retain",
            json!({"snapshotTags/Deployment":"fixture","unexpected":"yes"}),
        ),
    ] {
        let original = {
            let mut objects = f.objects.lock().unwrap();
            let original = objects[path].clone();
            objects.get_mut(path).unwrap()["parameters"] = parameters;
            original
        };
        assert!(
            f.profile.verify_kubernetes(&f.runtime).await.is_err(),
            "{path}"
        );
        f.objects.lock().unwrap().insert(path.to_owned(), original);
    }
    f.profile.verify_kubernetes(&f.runtime).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL roles, OpenSSL3 and loopback TLS"]
async fn live_tls_kubernetes_and_postgres_activation_is_atomic_and_bound() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let base = test_support_db::Fixture::new(10).await?;
    let owner = Database {
        pool: base.owner.clone(),
    };
    let epoch: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&owner.pool)
            .await?;
    let f = LiveFixture::new(epoch)?;
    let registration_request = Uuid::new_v4();
    let registration = register_profile(
        &owner,
        &f.profile,
        registration_request,
        "integration/register",
    )
    .await?;
    assert!(!registration.current_enabled);
    assert!(
        register_profile(
            &owner,
            &f.profile,
            registration_request,
            "integration/register"
        )
        .await?
        .replayed
    );
    assert!(
        register_profile(
            &owner,
            &f.profile,
            registration_request,
            "different approval"
        )
        .await
        .is_err()
    );
    assert!(
        register_profile(&base.database, &f.profile, Uuid::new_v4(), "nonowner")
            .await
            .is_err()
    );
    let conflict = LiveFixture::for_profile(epoch, f.profile.artifact.profile_id)?;
    assert!(
        register_profile(
            &owner,
            &conflict.profile,
            Uuid::new_v4(),
            "immutable conflict"
        )
        .await
        .is_err()
    );
    let wrong_epoch = LiveFixture::new(Uuid::new_v4())?;
    assert!(
        register_profile(&owner, &wrong_epoch.profile, Uuid::new_v4(), "wrong epoch")
            .await
            .is_err()
    );
    let kube = f.profile.verify_kubernetes(&f.runtime).await?;
    let (_temp, verifier, server) = test_live_verifier(f.expected.clone()).await;
    let vault = verifier.verify().await?;
    let request = Uuid::new_v4();
    assert!(
        activate_profile(
            &owner,
            &f.profile,
            request,
            "integration/activate",
            &kube,
            &vault
        )
        .await
        .is_err()
    );
    sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton")
        .execute(&owner.pool)
        .await?;
    let result: anyhow::Result<()> = async {
        assert!(
            activate_profile(
                &base.database,
                &f.profile,
                request,
                "integration/activate",
                &kube,
                &vault
            )
            .await
            .is_err()
        );
        let different = LiveFixture::new(epoch)?;
        assert!(
            activate_profile(
                &owner,
                &different.profile,
                Uuid::new_v4(),
                "integration/transplant",
                &kube,
                &vault
            )
            .await
            .is_err()
        );
        let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&owner.pool)
            .await?;
        ensure!(
            kube.profile_sha256 == f.profile.profile_sha256,
            "fixture profile binding changed"
        );
        ensure!(
            (database_now - Utc::now()).num_seconds().abs() <= 30,
            "database host clock skew is {} seconds",
            (database_now - Utc::now()).num_seconds()
        );
        let (a, b) = tokio::join!(
            activate_profile(
                &owner,
                &f.profile,
                request,
                "integration/activate",
                &kube,
                &vault
            ),
            activate_profile(
                &owner,
                &f.profile,
                request,
                "integration/activate",
                &kube,
                &vault
            )
        );
        let (a, b) = (a?, b?);
        assert!(a.current_enabled && b.current_enabled && a.replayed != b.replayed);
        let (count, evidence): (i64, Value) = sqlx::query_as(
            "SELECT count(*) OVER(),evidence FROM backup_profile_actions WHERE id=$1",
        )
        .bind(request)
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(count, 1);
        let wire = serde_json::to_string(&evidence)?;
        assert!(!wire.contains(std::str::from_utf8(&f.secret_password)?));
        assert!(!wire.contains(&STANDARD.encode(&f.secret_private)));
        let revoked = revoke_profile(
            &owner,
            f.profile.artifact.profile_id,
            Uuid::new_v4(),
            "integration/revoke",
        )
        .await?;
        assert!(!revoked.current_enabled);
        let replay = activate_profile(
            &owner,
            &f.profile,
            request,
            "integration/activate",
            &kube,
            &vault,
        )
        .await?;
        assert!(replay.replayed && !replay.current_enabled);
        Ok(())
    }
    .await;
    server.shutdown();
    sqlx::query("UPDATE platform_configuration SET safe_mode=false WHERE singleton")
        .execute(&owner.pool)
        .await?;
    result
}
