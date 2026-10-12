#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::BTreeMap;
use tokio::sync::Mutex;

#[derive(Clone)]
struct Wire {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    requests: Arc<Mutex<Vec<String>>>,
    root: String,
}
fn response(status: u16, body: Vec<u8>, length: u64) -> Response<HttpBody> {
    Response::builder()
        .status(status)
        .header("content-length", length)
        .header("last-modified", "Thu, 01 Oct 2026 00:00:00 GMT")
        .header("etag", "\"fixture\"")
        .body(HttpBody::new(
            futures_util::stream::iter([Ok(Buffer::from(body))]),
            Some(length),
        ))
        .unwrap()
}
impl HttpTransport for Wire {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        assert!(valid_target(
            &req,
            "fixture-vault.oss-cn-hangzhou-internal.aliyuncs.com",
            &self.root
        ));
        assert!(
            req.headers()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("OSS4-HMAC-SHA256 ")
        );
        assert_eq!(
            req.headers()
                .get("x-oss-content-sha256")
                .unwrap()
                .to_str()
                .unwrap(),
            hex::encode(Sha256::digest(req.body().to_vec()))
        );
        assert_eq!(
            req.headers().get("x-oss-security-token").unwrap(),
            "test-sts-token"
        );
        self.requests.lock().await.push(req.uri().to_string());
        let objects = self.objects.lock().await;
        if req.uri().path() == "/" {
            let query: BTreeMap<_, _> =
                url::form_urlencoded::parse(req.uri().query().unwrap().as_bytes())
                    .into_owned()
                    .collect();
            let prefix = query.get("prefix").unwrap();
            let after = query.get("start-after").map(String::as_str).unwrap_or("");
            let rows: Vec<_> = objects
                .iter()
                .filter(|(k, _)| k.starts_with(prefix) && k.as_str() > after)
                .take(1000)
                .collect();
            let mut xml = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            for (key, body) in rows {
                xml.push_str(&format!("<Contents><Key>{key}</Key><Size>{}</Size><ETag>\"fixture\"</ETag><LastModified>2026-10-01T00:00:00Z</LastModified></Contents>",body.len()));
            }
            xml.push_str("</ListBucketResult>");
            let length = xml.len() as u64;
            return Ok(response(200, xml.into_bytes(), length));
        }
        let Some(body) = objects.get(req.uri().path().trim_start_matches('/')) else {
            return Ok(response(404, Vec::new(), 0));
        };
        let length = body.len() as u64;
        Ok(response(
            200,
            if req.method() == "HEAD" {
                Vec::new()
            } else {
                body.clone()
            },
            length,
        ))
    }
}
struct Fixture {
    verifier: BackupVaultVerifier,
    expected: BackupVaultExpectation,
    wire: Wire,
    directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/backup/vault-python-v2.json"
        ))
        .unwrap();
        let identity: BackupIdentity = serde_json::from_value(value["identity"].clone()).unwrap();
        let root = format!(
            "tenants/{}/backups/{}",
            identity.tenant_id, identity.backup_id
        );
        let objects = value["objects"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, data)| {
                (
                    format!("{root}/{key}"),
                    STANDARD.decode(data.as_str().unwrap()).unwrap(),
                )
            })
            .collect();
        let wire = Wire {
            objects: Arc::new(Mutex::new(objects)),
            requests: Arc::new(Mutex::new(Vec::new())),
            root,
        };
        let directory = tempfile::tempdir().unwrap();
        let credentials = directory.path().join("backup-only-sts.json");
        std::fs::write(&credentials,serde_json::to_vec(&serde_json::json!({"access_key_id":"STS.test-access-key","access_key_secret":"test-access-secret","security_token":"test-sts-token","expires_at":Utc::now()+chrono::Duration::minutes(15)})).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut verifier = BackupVaultVerifier::new(BackupVaultConfig {
            endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
            bucket: "fixture-vault".into(),
            region: "cn-hangzhou".into(),
            account_id: "1234567890123456".into(),
            sts_credentials_file: credentials,
            signing_public_key_spki: STANDARD
                .decode(value["public_key_spki"].as_str().unwrap())
                .unwrap(),
        })
        .unwrap();
        verifier.test_transport = Some(HttpTransporter::new(wire.clone()));
        let expected = BackupVaultExpectation {
            identity,
            snapshot_id: value["snapshot_id"].as_str().unwrap().into(),
            disk_sha256: value["disk_sha256"].as_str().unwrap().into(),
            manifest_sha256: None,
        };
        Self {
            verifier,
            expected,
            wire,
            directory,
        }
    }
}
#[tokio::test]
async fn python_ed25519_canonical_inventory_verifies_through_signed_oss_requests() {
    let f = Fixture::new().await;
    let proof = f.verifier.verify(&f.expected).await.unwrap();
    assert_eq!(proof.identity(), &f.expected.identity);
    assert_eq!(proof.manifest().inventory.object_count, 5);
    assert!(proof.manifest().cloud_restore_tested_at.is_none());
    assert_eq!(proof.snapshot_id(), f.expected.snapshot_id);
    let calls = f.wire.requests.lock().await;
    assert!(calls.iter().any(|s| s.contains("list-type=2")));
    assert!(!calls.iter().any(|s| s.contains("/repository/data/")));
    // No public construction/Deserialize exists; only actual verification produced proof.
}
#[tokio::test]
async fn signature_identity_old_manifest_and_capture_digest_mismatch_fail() {
    let mut f = Fixture::new().await;
    f.expected.identity.project_id = Uuid::new_v4();
    assert!(matches!(
        f.verifier.verify(&f.expected).await,
        Err(BackupObjectError::Manifest)
    ));
    f = Fixture::new().await;
    f.expected.manifest_sha256 = Some("f".repeat(64));
    assert!(matches!(
        f.verifier.verify(&f.expected).await,
        Err(BackupObjectError::Integrity)
    ));
    f = Fixture::new().await;
    let key = format!("{}/manifest.sig", f.wire.root);
    f.wire.objects.lock().await.get_mut(&key).unwrap()[0] ^= 1;
    assert!(matches!(
        f.verifier.verify(&f.expected).await,
        Err(BackupObjectError::Signature)
    ));
}
#[tokio::test]
async fn missing_extra_corrupt_objects_and_inventory_do_not_produce_proof() {
    for mode in 0..4 {
        let f = Fixture::new().await;
        {
            let mut objects = f.wire.objects.lock().await;
            match mode {
                0 => {
                    let key = objects
                        .keys()
                        .find(|k| k.contains("/data/"))
                        .unwrap()
                        .clone();
                    objects.remove(&key);
                }
                1 => {
                    objects.insert(format!("{}/repository/extra", f.wire.root), vec![1]);
                }
                2 => {
                    let key = format!(
                        "{}/repository/snapshots/{}",
                        f.wire.root, f.expected.snapshot_id
                    );
                    objects.get_mut(&key).unwrap()[0] ^= 1;
                }
                _ => {
                    let key = format!("{}/inventory/000000.json", f.wire.root);
                    objects.get_mut(&key).unwrap()[0] ^= 1;
                }
            }
        }
        assert!(
            matches!(
                f.verifier.verify(&f.expected).await,
                Err(BackupObjectError::Integrity)
            ),
            "mode {mode}"
        );
    }
}
#[tokio::test]
async fn expired_insecure_or_missing_credentials_fail_before_network_and_never_fallback() {
    for mode in 0..3 {
        let f = Fixture::new().await;
        let path = f.directory.path().join("backup-only-sts.json");
        f.verifier.check_credentials().await.unwrap();
        assert!(f.wire.requests.lock().await.is_empty());
        match mode {
            0 => {
                let mut v: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                v["expires_at"] = serde_json::json!(Utc::now());
                std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
            }
            1 => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
            }
            _ => std::fs::remove_file(&path).unwrap(),
        }
        assert!(matches!(
            f.verifier.check_credentials().await,
            Err(BackupObjectError::Credentials)
        ));
        assert!(matches!(
            f.verifier.verify(&f.expected).await,
            Err(BackupObjectError::Credentials)
        ));
        assert!(f.wire.requests.lock().await.is_empty());
    }
}
#[test]
fn canonical_duplicates_floats_escapes_and_foreign_urls_fail_closed() {
    for raw in [
        br#"{"a":1,"a":1}"#.as_slice(),
        br#"{"a": 1}"#,
        br#"{"a":"\u0061"}"#,
        br#"{"a":1} "#,
    ] {
        assert!(canonical_decode::<serde_json::Value>(raw).is_err());
    }
    let root = "tenants/t/backups/b";
    let host = "vault.oss-cn-hangzhou.aliyuncs.com";
    for (method, url) in [
        ("PUT", format!("https://{host}/{root}/manifest.json")),
        (
            "GET",
            format!("https://{host}/tenants/other/backups/b/manifest.json"),
        ),
        (
            "GET",
            format!("https://{host}/?list-type=2&prefix=tenants/other/"),
        ),
        ("GET", format!("http://{host}/{root}/manifest.json")),
        ("GET", format!("https://evil.invalid/{root}/manifest.json")),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(url)
            .body(Buffer::new())
            .unwrap();
        assert!(!valid_target(&req, host, root));
    }
}

#[tokio::test]
async fn inventory_merge_crosses_oss_page_boundary_without_dropping_or_repeating_objects() {
    let f = Fixture::new().await;
    let mut objects = f.wire.objects.lock().await;
    for number in 0..1001 {
        let body = format!("encrypted distinct pack {number}").into_bytes();
        let hash = hex::encode(Sha256::digest(&body));
        objects.insert(
            format!("{}/repository/data/{}/{hash}", f.wire.root, &hash[..2]),
            body,
        );
    }
    let prefix = format!("{}/repository/", f.wire.root);
    let entries: Vec<_> = objects.iter().filter_map(|(key, value)| key.strip_prefix(&prefix).map(|relative| serde_json::json!({"key":relative,"size_bytes":value.len(),"sha256":hex::encode(Sha256::digest(value))}))).collect();
    let count = entries.len();
    let total: u64 = entries
        .iter()
        .map(|v| v["size_bytes"].as_u64().unwrap())
        .sum();
    let shard = serde_json::to_vec(&serde_json::json!({"protocol":1,"tenant_id":f.expected.identity.tenant_id,"backup_id":f.expected.identity.backup_id,"seal_attempt_id":f.expected.identity.seal_attempt_id,"cluster_epoch":f.expected.identity.cluster_epoch,"objects":entries})).unwrap();
    let manifest_key = format!("{}/manifest.json", f.wire.root);
    let mut manifest: serde_json::Value = serde_json::from_slice(&objects[&manifest_key]).unwrap();
    manifest["inventory"] = serde_json::json!({"format":"restic-object-inventory-v1","object_count":count,"total_bytes":total,"shards":[{"key":"inventory/000000.json","sha256":hex::encode(Sha256::digest(&shard)),"size_bytes":shard.len(),"object_count":count}]});
    let raw = serde_json::to_vec(&manifest).unwrap();
    // Fixed, intentionally public test-only private key for the Python fixture.
    let private = STANDARD
        .decode("MC4CAQAwBQYDK2VwBCIEIJJCjG65wTe1ZsE9Fm68Vp4ljwwks+wkgdSW6w973c0d")
        .unwrap();
    let key = rustls::crypto::ring::sign::any_supported_type(
        &rustls::pki_types::PrivateKeyDer::Pkcs8(private.into()),
    )
    .unwrap();
    let signature = key
        .choose_scheme(&[rustls::SignatureScheme::ED25519])
        .unwrap()
        .sign(&raw)
        .unwrap();
    objects.insert(format!("{}/inventory/000000.json", f.wire.root), shard);
    objects.insert(manifest_key, raw);
    objects.insert(format!("{}/manifest.sig", f.wire.root), signature);
    drop(objects);
    let proof = f.verifier.verify(&f.expected).await.unwrap();
    assert_eq!(proof.manifest().inventory.object_count, 1006);
    let calls = f.wire.requests.lock().await;
    assert_eq!(
        calls.iter().filter(|v| v.contains("list-type=2")).count(),
        3
    );
    assert!(calls.iter().any(|v| {
        url::Url::parse(v)
            .unwrap()
            .query_pairs()
            .any(|(key, value)| key == "start-after" && value.contains("/repository/data/"))
    }));
}
