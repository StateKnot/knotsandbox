#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::any,
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct Wire {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    methods: Arc<Mutex<Vec<String>>>,
    retain_on_delete: Arc<Mutex<bool>>,
}
async fn object(
    State(wire): State<Wire>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    assert!(
        headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("OSS4-HMAC-SHA256")
    );
    assert_eq!(
        headers.get("x-oss-security-token").unwrap(),
        "TEST_ONLY_TOKEN"
    );
    assert!(canonical_part_path(uri.path()));
    wire.methods.lock().await.push(method.to_string());
    let mut objects = wire.objects.lock().await;
    let mut response = HeaderMap::new();
    response.insert("etag", "\"test-etag\"".parse().unwrap());
    response.insert(
        "last-modified",
        "Thu, 08 Oct 2026 00:00:00 GMT".parse().unwrap(),
    );
    match method.as_str() {
        "PUT" => {
            assert_eq!(headers.get("x-oss-forbid-overwrite").unwrap(), "true");
            assert_eq!(headers.get("x-oss-server-side-encryption").unwrap(), "KMS");
            assert_eq!(
                headers.get("x-oss-server-side-encryption-key-id").unwrap(),
                "test-file-kms"
            );
            if objects.contains_key(uri.path()) {
                return (
                    StatusCode::CONFLICT,
                    response,
                    b"<Error><Code>FileAlreadyExists</Code></Error>".to_vec(),
                );
            }
            objects.insert(uri.path().to_owned(), body.to_vec());
            (StatusCode::OK, response, Vec::new())
        }
        "GET" | "HEAD" => match objects.get(uri.path()) {
            Some(bytes) => {
                response.insert("content-length", bytes.len().into());
                if method == Method::GET {
                    response.insert(
                        "content-range",
                        format!("bytes 0-{}/{}", bytes.len() - 1, bytes.len())
                            .parse()
                            .unwrap(),
                    );
                    (StatusCode::PARTIAL_CONTENT, response, bytes.clone())
                } else {
                    (StatusCode::OK, response, Vec::new())
                }
            }
            None => (StatusCode::NOT_FOUND, response, Vec::new()),
        },
        "DELETE" => {
            if !*wire.retain_on_delete.lock().await {
                objects.remove(uri.path());
            }
            (StatusCode::NO_CONTENT, response, Vec::new())
        }
        _ => panic!("unexpected method"),
    }
}
#[derive(Clone)]
struct TcpWire {
    origin: String,
    inner: ReqwestTransport,
}
impl HttpTransport for TcpWire {
    async fn fetch(&self, mut req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        assert_eq!(
            req.uri().host(),
            Some("sandbox-files.oss-cn-hangzhou-internal.aliyuncs.com")
        );
        let uri = format!("{}{}", self.origin, req.uri().path())
            .parse()
            .unwrap();
        *req.uri_mut() = uri;
        bound_http_response(self.inner.fetch(req).await?, FILE_PART_BYTES)
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    config: OssFileConfig,
    transport: HttpTransporter,
    wire: Wire,
    task: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("file-sts.json");
        write_credentials(&path, Utc::now() + chrono::Duration::minutes(10))?;
        let wire = Wire::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = Router::new().fallback(any(object)).with_state(wire.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let inner = ReqwestTransport::new(
            reqwest_oss::Client::builder()
                .no_proxy()
                .redirect(reqwest_oss::redirect::Policy::none())
                .retry(reqwest_oss::retry::never())
                .timeout(Duration::from_secs(3))
                .build()?,
        );
        Ok(Self {
            _dir: dir,
            wire,
            task,
            config: OssFileConfig {
                endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
                bucket: "sandbox-files".into(),
                kms_key_id: "test-file-kms".into(),
                sts_credentials_file: path,
            },
            transport: HttpTransporter::new(TcpWire { origin, inner }),
        })
    }
    fn writer(&self) -> OssFileWriter {
        OssFileWriter::from_transport(self.config.clone(), self.transport.clone()).unwrap()
    }
    fn reader(&self) -> OssFileReader {
        OssFileReader::from_transport(self.config.clone(), self.transport.clone()).unwrap()
    }
    fn cleaner(&self) -> OssFileCleaner {
        OssFileCleaner::from_transport(self.config.clone(), self.transport.clone()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn write_credentials(path: &std::path::Path, expires_at: DateTime<Utc>) -> anyhow::Result<()> {
    std::fs::write(
        path,
        serde_json::to_vec(
            &serde_json::json!({"access_key_id":"TEST_ONLY_AK","access_key_secret":"TEST_ONLY_SECRET","security_token":"TEST_ONLY_TOKEN","expires_at":expires_at}),
        )?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn identity() -> FilePartIdentity {
    FilePartIdentity {
        tenant_id: Uuid::new_v4(),
        transfer_id: Uuid::new_v4(),
        content_id: Uuid::new_v4(),
        index: 0,
    }
}

#[tokio::test]
async fn signed_tcp_parts_are_immutable_and_reads_recheck_full_hash() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let id = identity();
    let bytes = b"bounded binary\0payload\xff".to_vec();
    let writer = fixture.writer();
    let first = writer.put_part(id, bytes.clone()).await?;
    assert_eq!(writer.put_part(id, bytes.clone()).await?, first);
    assert_eq!(fixture.reader().read_part(&first).await?, bytes);
    assert!(matches!(
        writer.put_part(id, b"changed".to_vec()).await,
        Err(OutputStoreError::Conflict)
    ));
    fixture.wire.objects.lock().await.insert(
        format!("/{}", first.object_key),
        vec![b'x'; first.byte_length as usize],
    );
    assert!(matches!(
        fixture.reader().read_part(&first).await,
        Err(OutputStoreError::Conflict)
    ));
    assert!(matches!(
        writer.put_part(id, Vec::new()).await,
        Err(OutputStoreError::InvalidObject)
    ));
    assert!(matches!(
        writer.put_part(id, vec![0; FILE_PART_BYTES + 1]).await,
        Err(OutputStoreError::InvalidObject)
    ));
    Ok(())
}
#[tokio::test]
async fn cleanup_requires_observed_absence_and_can_repeat_exact_identity() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let part = fixture
        .writer()
        .put_part(identity(), b"cleanup".to_vec())
        .await?;
    *fixture.wire.retain_on_delete.lock().await = true;
    assert!(matches!(
        fixture.cleaner().delete_part(&part).await,
        Err(OutputStoreError::Conflict)
    ));
    assert_eq!(&fixture.wire.methods.lock().await[1..], ["DELETE", "HEAD"]);
    *fixture.wire.retain_on_delete.lock().await = false;
    let receipt = fixture.cleaner().delete_part(&part).await?;
    assert_eq!(receipt.part, part);
    assert!(receipt.confirmed_absent_at <= Utc::now());
    fixture.cleaner().delete_part(&part).await?;
    Ok(())
}
#[tokio::test]
async fn transplanted_receipt_and_expired_credentials_never_issue_cloud_request()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut part = fixture
        .writer()
        .put_part(identity(), b"abc".to_vec())
        .await?;
    let requests = fixture.wire.methods.lock().await.len();
    part.identity.tenant_id = Uuid::new_v4();
    assert!(matches!(
        fixture.reader().read_part(&part).await,
        Err(OutputStoreError::InvalidObject)
    ));
    assert!(matches!(
        fixture.cleaner().delete_part(&part).await,
        Err(OutputStoreError::InvalidObject)
    ));
    assert_eq!(fixture.wire.methods.lock().await.len(), requests);
    let writer = fixture.writer();
    writer.check_credentials().await?;
    write_credentials(
        &fixture.config.sts_credentials_file,
        Utc::now() + chrono::Duration::seconds(30),
    )?;
    assert!(matches!(
        writer.put_part(identity(), b"abc".to_vec()).await,
        Err(OutputStoreError::Credentials)
    ));
    assert_eq!(fixture.wire.methods.lock().await.len(), requests);
    Ok(())
}
#[tokio::test]
async fn native_transport_rejects_cross_namespace_query_and_excess_capability() -> anyhow::Result<()>
{
    let _ = rustls::crypto::ring::default_provider().install_default();
    let id = identity();
    let good = format!(
        "https://sandbox-files.oss-cn-hangzhou-internal.aliyuncs.com/{}",
        id.object_key()?
    );
    let http = reqwest_oss::Client::builder()
        .no_proxy()
        .retry(reqwest_oss::retry::never())
        .build()?;
    let mut targets = vec![
        format!("{good}?delete"),
        good.replace("/file-transfers/", "/executions/"),
        good.replace("sandbox-files.", "other-bucket."),
        good.replace("https:", "http:"),
    ];
    targets.push(good.replace("/parts/0", "/parts/100"));
    for uri in targets {
        let transport = FileBucketTransport {
            inner: ReqwestTransport::new(http.clone()),
            host: "sandbox-files.oss-cn-hangzhou-internal.aliyuncs.com".into(),
            capability: Capability::Write,
        };
        let req = Request::builder()
            .method("PUT")
            .uri(uri)
            .body(Buffer::new())?;
        assert_eq!(
            transport.fetch(req).await.err().unwrap().kind(),
            opendal::ErrorKind::PermissionDenied
        );
    }
    for (capability, method) in [
        (Capability::Read, "PUT"),
        (Capability::Read, "DELETE"),
        (Capability::Cleanup, "GET"),
        (Capability::Cleanup, "PUT"),
        (Capability::Write, "DELETE"),
    ] {
        let transport = FileBucketTransport {
            inner: ReqwestTransport::new(http.clone()),
            host: "sandbox-files.oss-cn-hangzhou-internal.aliyuncs.com".into(),
            capability,
        };
        let req = Request::builder()
            .method(method)
            .uri(&good)
            .body(Buffer::new())?;
        assert_eq!(
            transport.fetch(req).await.err().unwrap().kind(),
            opendal::ErrorKind::PermissionDenied
        );
    }
    Ok(())
}
