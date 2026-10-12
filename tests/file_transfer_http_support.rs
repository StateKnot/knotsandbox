//! Real TCP OSS protocol fixture. This is not real OSS/KMS/cloud acceptance.
// Missing protocol fields and fixture I/O errors are deliberate assertion failures.
#![allow(dead_code, clippy::unwrap_used)]
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Request, Response, StatusCode, Uri},
    routing::any,
};
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter};
use opendal_http_transport_reqwest::ReqwestTransport;
use sandbox_platform::file_store::{
    FILE_PART_BYTES, OssFileCleaner, OssFileConfig, OssFileReader, OssFileWriter,
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;
#[derive(Clone, Default)]
pub struct Wire {
    pub objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    pub methods: Arc<Mutex<Vec<String>>>,
    pub revoke_on_get: Arc<Mutex<Option<(sqlx::PgPool, uuid::Uuid)>>>,
}
async fn object(
    State(w): State<Wire>,
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
    w.methods.lock().await.push(method.to_string());
    let mut h = HeaderMap::new();
    h.insert("etag", "\"fixture-etag\"".parse().unwrap());
    h.insert(
        "last-modified",
        "Thu, 08 Oct 2026 00:00:00 GMT".parse().unwrap(),
    );
    if method == Method::GET
        && let Some((db, principal)) = w.revoke_on_get.lock().await.take()
    {
        sqlx::query("UPDATE principal_identities SET enabled=false WHERE principal_id=$1")
            .bind(principal)
            .execute(&db)
            .await
            .unwrap();
    }
    let mut objects = w.objects.lock().await;
    match method.as_str() {
        "PUT" => {
            assert_eq!(headers.get("x-oss-forbid-overwrite").unwrap(), "true");
            if objects.contains_key(uri.path()) {
                return (
                    StatusCode::CONFLICT,
                    h,
                    b"<Error><Code>FileAlreadyExists</Code></Error>".to_vec(),
                );
            }
            objects.insert(uri.path().into(), body.to_vec());
            (StatusCode::OK, h, vec![])
        }
        "GET" | "HEAD" => match objects.get(uri.path()) {
            Some(b) => {
                h.insert("content-length", b.len().into());
                if method == Method::GET {
                    h.insert(
                        "content-range",
                        format!("bytes 0-{}/{}", b.len() - 1, b.len())
                            .parse()
                            .unwrap(),
                    );
                    (StatusCode::PARTIAL_CONTENT, h, b.clone())
                } else {
                    (StatusCode::OK, h, vec![])
                }
            }
            None => (StatusCode::NOT_FOUND, h, vec![]),
        },
        "DELETE" => {
            objects.remove(uri.path());
            (StatusCode::NO_CONTENT, h, vec![])
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, h, vec![]),
    }
}
#[derive(Clone)]
struct TcpTransport {
    origin: String,
    inner: ReqwestTransport,
}
impl HttpTransport for TcpTransport {
    async fn fetch(&self, mut req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        assert_eq!(
            req.uri().host(),
            Some("sandbox-files.oss-cn-hangzhou-internal.aliyuncs.com")
        );
        *req.uri_mut() = format!("{}{}", self.origin, req.uri().path())
            .parse()
            .unwrap();
        self.inner.fetch(req).await
    }
}
pub struct Cloud {
    pub wire: Wire,
    config: OssFileConfig,
    transport: HttpTransporter,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}
impl Cloud {
    pub async fn new() -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("file-test-sts.json");
        std::fs::write(
            &path,
            serde_json::to_vec(
                &serde_json::json!({"access_key_id":"TEST_ONLY_AK","access_key_secret":"TEST_ONLY_SECRET","security_token":"TEST_ONLY_TOKEN","expires_at":chrono::Utc::now()+chrono::Duration::minutes(10)}),
            )?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let wire = Wire::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = Router::new()
            .fallback(any(object))
            .layer(axum::extract::DefaultBodyLimit::max(FILE_PART_BYTES))
            .with_state(wire.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let inner = ReqwestTransport::new(
            reqwest_oss::Client::builder()
                .no_proxy()
                .redirect(reqwest_oss::redirect::Policy::none())
                .retry(reqwest_oss::retry::never())
                .timeout(std::time::Duration::from_secs(3))
                .build()?,
        );
        Ok(Self {
            wire,
            config: OssFileConfig {
                endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
                bucket: "sandbox-files".into(),
                kms_key_id: "test-kms".into(),
                sts_credentials_file: path,
            },
            transport: HttpTransporter::new(TcpTransport { origin, inner }),
            _dir: dir,
            task,
        })
    }
    pub fn writer(&self) -> OssFileWriter {
        OssFileWriter::from_transport(self.config.clone(), self.transport.clone()).unwrap()
    }
    pub fn reader(&self) -> OssFileReader {
        OssFileReader::from_transport(self.config.clone(), self.transport.clone()).unwrap()
    }
    pub fn cleaner(&self) -> OssFileCleaner {
        OssFileCleaner::from_transport(self.config.clone(), self.transport.clone()).unwrap()
    }
}
impl Drop for Cloud {
    fn drop(&mut self) {
        self.task.abort();
    }
}
