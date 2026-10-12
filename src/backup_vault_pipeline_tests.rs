//! A signed fixture repository is served over the actual OSS transport interface;
//! this tests orchestration and cryptographic verification, not live cloud WORM.
use super::*;
use crate::backup_object::{BackupVaultConfig, BackupVaultExpectation, BackupVaultVerifier};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter};
use sha2::{Digest, Sha256};
use std::{path::Path, process::Command};
#[derive(Clone)]
struct Repository {
    objects: Arc<BTreeMap<String, Vec<u8>>>,
    root: String,
    host: String,
}
impl HttpTransport for Repository {
    async fn fetch(&self, r: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        assert_eq!(r.uri().host(), Some(self.host.as_str()));
        assert!(r.headers().contains_key("authorization"));
        assert!(matches!(r.method().as_str(), "GET" | "HEAD"));
        let (status, data) = if r.uri().path() == "/" {
            let pairs: BTreeMap<_, _> =
                url::form_urlencoded::parse(r.uri().query().unwrap_or("").as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(
                pairs.get("prefix"),
                Some(&format!("{}/repository/", self.root))
            );
            let mut xml = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            for (key, bytes) in self.objects.iter().filter(|(k, _)| {
                k.starts_with(&format!("{}/repository/", self.root))
                    && pairs.get("start-after").is_none_or(|after| *k > after)
            }) {
                xml.push_str(&format!("<Contents><Key>{key}</Key><Size>{}</Size><ETag>fixture</ETag><LastModified>2026-10-01T00:00:00Z</LastModified></Contents>",bytes.len()));
            }
            xml.push_str("</ListBucketResult>");
            (200, xml.into_bytes())
        } else {
            self.objects
                .get(r.uri().path().trim_start_matches('/'))
                .cloned()
                .map(|v| (200, v))
                .unwrap_or((404, Vec::new()))
        };
        let size = data.len() as u64;
        let body = if r.method() == "HEAD" {
            Vec::new()
        } else {
            data
        };
        Response::builder()
            .status(status)
            .header("content-length", size)
            .header("etag", "\"fixture\"")
            .header("last-modified", "Thu, 01 Oct 2026 00:00:00 GMT")
            .body(HttpBody::new(
                futures_util::stream::iter([Ok(Buffer::from(body))]),
                Some(size),
            ))
            .map_err(|_| opendal::Error::new(opendal::ErrorKind::Unexpected, "fixture response"))
    }
}
fn openssl(args: &[&std::ffi::OsStr]) -> anyhow::Result<()> {
    let binary = std::env::var_os("BACKUP_OPENSSL_BIN").unwrap_or_else(|| "openssl".into());
    let output = Command::new(binary).args(args).output()?;
    ensure!(
        output.status.success(),
        "OpenSSL 3 fixture operation failed"
    );
    Ok(())
}
async fn signed_verifier(
    expected: &BackupVaultExpectation,
    private: &Path,
    spki: Vec<u8>,
    dir: &Path,
) -> anyhow::Result<BackupVaultVerifier> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/backup/vault-python-v2.json"
    ))?;
    let mut objects: BTreeMap<String, Vec<u8>> = fixture["objects"]
        .as_object()
        .context("objects")?
        .iter()
        .map(|(key, value)| {
            Ok((
                key.clone(),
                STANDARD.decode(value.as_str().context("object bytes")?)?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let mut shard: Value =
        serde_json::from_slice(objects.get("inventory/000000.json").context("inventory")?)?;
    for (key, value) in [
        ("tenant_id", expected.identity.tenant_id),
        ("backup_id", expected.identity.backup_id),
        ("seal_attempt_id", expected.identity.seal_attempt_id),
        ("cluster_epoch", expected.identity.cluster_epoch),
    ] {
        shard[key] = json!(value)
    }
    let shard = serde_json::to_vec(&shard)?;
    objects.insert("inventory/000000.json".into(), shard.clone());
    let mut manifest: Value =
        serde_json::from_slice(objects.get("manifest.json").context("manifest")?)?;
    manifest["backup"] = json!(expected.identity);
    manifest["snapshot_id"] = json!(expected.snapshot_id);
    manifest["disk"] =
        json!({"size_bytes":expected.identity.size_bytes,"sha256":expected.disk_sha256});
    manifest["sealed_at"] = json!(Utc::now().to_rfc3339());
    manifest["retain_objects_until"] = json!(expected.identity.retention_until);
    let root = format!(
        "tenants/{}/backups/{}",
        expected.identity.tenant_id, expected.identity.backup_id
    );
    manifest["repository_prefix"] = json!(format!("{root}/repository"));
    manifest["inventory"]["shards"][0]["sha256"] = json!(hex::encode(Sha256::digest(&shard)));
    manifest["inventory"]["shards"][0]["size_bytes"] = json!(shard.len());
    let raw = serde_json::to_vec(&manifest)?;
    let input = dir.join("manifest.json");
    let signature = dir.join("manifest.sig");
    std::fs::write(&input, &raw)?;
    openssl(&[
        "pkeyutl".as_ref(),
        "-sign".as_ref(),
        "-rawin".as_ref(),
        "-inkey".as_ref(),
        private.as_os_str(),
        "-in".as_ref(),
        input.as_os_str(),
        "-out".as_ref(),
        signature.as_os_str(),
    ])?;
    objects.insert("manifest.json".into(), raw);
    objects.insert("manifest.sig".into(), std::fs::read(signature)?);
    let credentials = dir.join("sts.json");
    std::fs::write(
        &credentials,
        serde_json::to_vec(
            &json!({"access_key_id":"STS.fixture","access_key_secret":"fixture-secret","security_token":"fixture-token","expires_at":Utc::now()+Duration::minutes(15)}),
        )?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600))?;
    }
    let repo = Repository {
        objects: Arc::new(
            objects
                .into_iter()
                .map(|(key, data)| (format!("{root}/{key}"), data))
                .collect(),
        ),
        root,
        host: format!(
            "{}.oss-{}-internal.aliyuncs.com",
            expected.identity.vault_bucket, expected.identity.region
        ),
    };
    Ok(BackupVaultVerifier::new(BackupVaultConfig {
        endpoint: format!(
            "https://oss-{}-internal.aliyuncs.com",
            expected.identity.region
        ),
        bucket: expected.identity.vault_bucket.clone(),
        region: expected.identity.region.clone(),
        account_id: expected.identity.account_id.clone(),
        sts_credentials_file: credentials,
        signing_public_key_spki: spki,
    })?
    .with_test_transport(HttpTransporter::new(repo)))
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL, loopback TLS and OpenSSL 3"]
async fn both_isolated_tasks_and_independent_signed_vault_complete_available_atomically()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let (p, _verifier, _dir) = completed_source().await?;
    let mut tx = p.f.base.f.owner_transaction().await?;
    let(status,operation,hold,receipts,closed):(String,String,bool,i64,i64)=sqlx::query_as("SELECT b.status,o.status,EXISTS(SELECT 1 FROM workspace_hold_releases h WHERE h.hold_id=b.hold_id),(SELECT count(*) FROM backup_vault_receipts v WHERE v.tenant_id=b.tenant_id AND v.backup_id=b.id),(SELECT count(DISTINCT a.stage) FROM backup_attempts a JOIN backup_termination_proofs p ON p.tenant_id=a.tenant_id AND p.attempt_id=a.id JOIN backup_cleanup_receipts c ON c.proof_id=p.id WHERE a.tenant_id=b.tenant_id AND a.backup_id=b.id) FROM backups b JOIN operations o ON o.tenant_id=b.tenant_id AND o.id=b.operation_id WHERE b.tenant_id=$1 AND b.id=$2").bind(p.claim.tenant_id).bind(p.plan.backup.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        (status, operation, hold, receipts, closed),
        ("AVAILABLE".into(), "SUCCEEDED".into(), true, 1, 2)
    );
    Ok(())
}
/// The restore fixture reuses the actual TLS/CSI/signature pipeline, never an
/// owner-written AVAILABLE flag or a caller-supplied verification capability.
pub(crate) async fn completed_source()
-> anyhow::Result<(Pipeline, BackupVaultVerifier, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let private = dir.path().join("key.pem");
    let public = dir.path().join("key.der");
    openssl(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "ED25519".as_ref(),
        "-out".as_ref(),
        private.as_os_str(),
    ])?;
    openssl(&[
        "pkey".as_ref(),
        "-in".as_ref(),
        private.as_os_str(),
        "-pubout".as_ref(),
        "-outform".as_ref(),
        "DER".as_ref(),
        "-out".as_ref(),
        public.as_os_str(),
    ])?;
    let spki = std::fs::read(public)?;
    let mut settings = super::super::tests::cloud_settings();
    settings["signing_key_sha256"] = json!(hex::encode(Sha256::digest(&spki)));
    let p = Pipeline::with_cloud(settings).await?;
    let (p, verifier) = complete_source_pipeline(p, &private, spki, dir.path()).await?;
    Ok((p, verifier, dir))
}
pub(crate) async fn complete_source_pipeline(
    mut p: Pipeline,
    private: &Path,
    spki: Vec<u8>,
    dir: &Path,
) -> anyhow::Result<(Pipeline, BackupVaultVerifier)> {
    ensure!(
        hex::encode(Sha256::digest(&spki)) == p.plan.cloud.signing_key_sha256,
        "normal source verifier uses the activated profile actual SPKI"
    );
    let secrets = p.fixture_secret_objects()?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/backup/vault-python-v2.json"
    ))?;
    p.close_current(BackupJobExit{exit_code:0,report:Some(json!({"snapshot_id":fixture["snapshot_id"],"disk":{"size_bytes":p.volume.size_bytes,"sha256":fixture["disk_sha256"]}})),finished_at:Utc::now()}).await?;
    p.admit_seal().await?;
    p.install_fixture_secret_objects(secrets)?;
    // Guest success and even signed objects cannot compensate for a live SEAL VM.
    assert!(
        p.f.backup
            .database
            .backup_vault_expectation(&p.f.backup, &p.claim)
            .await
            .is_err()
    );
    p.close_current(BackupJobExit {
        exit_code: 0,
        report: None,
        finished_at: Utc::now(),
    })
    .await?;
    assert!(
        !p.f.backup
            .database
            .backup_completion_expired_or_failed(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    let expected =
        p.f.backup
            .database
            .backup_vault_expectation(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?;
    let verifier = signed_verifier(&expected, private, spki, dir).await?;
    let verified = verifier.verify(&expected).await?;
    p.f.backup
        .database
        .complete_backup(&p.f.backup, &p.claim, &verified)
        .await
        .map_err(api_failure)?;
    Ok((p, verifier))
}
