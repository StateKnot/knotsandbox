//! OpenDAL 0.59's OSS backend defaults to V1. Replace its authentication headers
//! at the transport boundary using the maintained reqsign V4 implementation.
use axum::http::{Request, Response};
use chrono::{DateTime, Utc};
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter};
use reqsign_aliyun_oss::{Credential, RequestSigner, SigningVersion};
use reqsign_core::{Context, SignRequest};
use sha2::{Digest, Sha256};

// No Debug: this capability contains short-lived signing material.
pub(crate) struct V4Transport {
    pub inner: HttpTransporter,
    pub bucket: String,
    pub region: String,
    pub credential: Credential,
    pub expires_at: DateTime<Utc>,
}
impl HttpTransport for V4Transport {
    async fn fetch(&self, request: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        if self.expires_at <= Utc::now() + chrono::Duration::seconds(30) {
            return Err(opendal::Error::new(
                opendal::ErrorKind::PermissionDenied,
                "OSS signing capability expired",
            ));
        }
        let (mut parts, body) = request.into_parts();
        for header in [
            "authorization",
            "date",
            "x-oss-date",
            "x-oss-security-token",
            "x-oss-content-sha256",
        ] {
            parts.headers.remove(header);
        }
        parts.headers.insert(
            "x-oss-content-sha256",
            hex::encode(Sha256::digest(body.to_vec()))
                .parse()
                .map_err(|_| {
                    opendal::Error::new(
                        opendal::ErrorKind::Unexpected,
                        "OSS payload digest unavailable",
                    )
                })?,
        );
        RequestSigner::new(&self.bucket)
            .with_region(&self.region)
            .with_signing_version(SigningVersion::V4)
            .sign_request(&Context::new(), &mut parts, Some(&self.credential), None)
            .await
            .map_err(|_| {
                opendal::Error::new(
                    opendal::ErrorKind::PermissionDenied,
                    "OSS V4 signing failed",
                )
            })?;
        for header in ["authorization", "x-oss-security-token"] {
            if let Some(value) = parts.headers.get_mut(header) {
                value.set_sensitive(true);
            }
        }
        self.inner.fetch(Request::from_parts(parts, body)).await
    }
}
