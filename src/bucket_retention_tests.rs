#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn expected() -> BucketRetentionExpectation {
    let profile_id = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    BucketRetentionExpectation {
        profile_id,
        cluster_epoch: epoch,
        deployment: "fixture".into(),
        profile_settings_sha256: "a".repeat(64),
        account_id: "1234567890123456".into(),
        region: "cn-hangzhou".into(),
        bucket: "fixture-vault".into(),
        kms_key_id: "kms-fixture".into(),
        vault_retention_days: 31,
        certified_until: Utc::now() + ChronoDuration::days(1),
        anchor_key: format!("certification/{epoch}/{profile_id}/anchor"),
        anchor_etag: "\"opaque-anchor\"".into(),
        anchor_size_bytes: 64,
    }
}
fn info() -> Vec<u8> {
    b"<BucketInfo><Bucket><CreationDate>2026-01-01T00:00:00.000Z</CreationDate><Name>fixture-vault</Name><Location>oss-cn-hangzhou</Location><IntranetEndpoint>oss-cn-hangzhou-internal.aliyuncs.com</IntranetEndpoint><ExtranetEndpoint>oss-cn-hangzhou.aliyuncs.com</ExtranetEndpoint><Owner><ID>1234567890123456</ID></Owner><AccessControlList><Grant>private</Grant></AccessControlList><ServerSideEncryptionRule><SSEAlgorithm>KMS</SSEAlgorithm><KMSMasterKeyID>kms-fixture</KMSMasterKeyID></ServerSideEncryptionRule></Bucket></BucketInfo>".to_vec()
}
fn worm() -> Vec<u8> {
    b"<WormConfiguration><WormId>opaqueWorm</WormId><State>Locked</State><RetentionPeriodInDays>31</RetentionPeriodInDays><CreationDate>2026-01-02T00:00:00</CreationDate></WormConfiguration>".to_vec()
}
const VERSION: &[u8] =
    b"<VersioningConfiguration xmlns=\"http://doc.oss-cn-hangzhou.aliyuncs.com\"/>";
#[test]
fn exact_bucket_owner_region_kms_locked_days_and_versioning_are_required() {
    let e = expected();
    let i = info();
    let w = worm();
    assert_eq!(
        validate_bucket(&e, &i, &w, VERSION).unwrap().retention_days,
        31
    );
    for (from, to) in [
        ("1234567890123456", "1234567890123457"),
        ("fixture-vault", "other-vault"),
        ("oss-cn-hangzhou", "oss-cn-beijing"),
        ("kms-fixture", "kms-other"),
        ("private", "public-read"),
        ("KMS", "AES256"),
    ] {
        assert!(
            validate_bucket(
                &e,
                String::from_utf8(i.clone())
                    .unwrap()
                    .replace(from, to)
                    .as_bytes(),
                &w,
                VERSION
            )
            .is_err()
        );
    }
    assert_eq!(
        validate_bucket(
            &e,
            &i,
            String::from_utf8(w.clone())
                .unwrap()
                .replace("Locked", "InProgress")
                .as_bytes(),
            VERSION
        )
        .unwrap_err()
        .code,
        RetentionCode::NotLocked
    );
    assert_eq!(
        validate_bucket(
            &e,
            &i,
            String::from_utf8(w.clone())
                .unwrap()
                .replace(">31<", ">30<")
                .as_bytes(),
            VERSION
        )
        .unwrap_err()
        .code,
        RetentionCode::RetentionTooShort
    );
    for state in ["Enabled", "Suspended", "Disabled", ""] {
        assert!(
            validate_bucket(
                &e,
                &i,
                &w,
                format!(
                    "<VersioningConfiguration><Status>{state}</Status></VersioningConfiguration>"
                )
                .as_bytes()
            )
            .is_err()
        );
    }
}
#[test]
fn xml_rejects_duplicates_entities_doctype_mixed_roots_and_oversize() {
    for bad in [
        "<R><A>1</A><A>2</A></R>",
        "<!DOCTYPE R [<!ENTITY x 'x'>]><R>&x;</R>",
        "<R>&amp;</R>",
        "<R/><R/>",
        "<R><A></R>",
        "<R X='a'/>",
        "<R><![CDATA[secret]]></R>",
        "<R>text<A/></R>",
        "<R><A/>text</R>",
    ] {
        assert!(xml(bad.as_bytes(), "R").is_err(), "{bad}");
    }
    assert!(xml(&vec![b'x'; BODY_LIMIT + 1], "R").is_err());
    assert_eq!(
        xml(
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><R><A/></R>",
            "R"
        )
        .unwrap()
        .get("R/A"),
        Some(&String::new())
    );
}
fn anchor_headers(e: &BucketRetentionExpectation) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (key, value) in [
        ("etag", e.anchor_etag.clone()),
        ("content-length", e.anchor_size_bytes.to_string()),
        (
            "last-modified",
            (Utc::now() - ChronoDuration::hours(1))
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
        ),
        ("x-oss-object-type", "Normal".into()),
        ("x-oss-server-side-encryption", "KMS".into()),
        ("x-oss-server-side-encryption-key-id", e.kms_key_id.clone()),
    ] {
        h.insert(key, value.parse().unwrap());
    }
    h
}
#[test]
fn anchor_must_cover_full_profile_and_job_horizon_and_not_be_a_symlink() {
    let mut e = expected();
    let b = validate_bucket(&e, &info(), &worm(), VERSION).unwrap();
    let mut h = anchor_headers(&e);
    assert!(validate_anchor(&e, &b, &h, Utc::now()).is_ok());
    h.insert("x-oss-object-type", "Symlink".parse().unwrap());
    assert!(validate_anchor(&e, &b, &h, Utc::now()).is_err());
    h.insert("x-oss-object-type", "Normal".parse().unwrap());
    // Official HEAD field is x-oss-versionId (no hyphen before Id).
    h.insert("x-oss-versionid", "current-version".parse().unwrap());
    assert!(validate_anchor(&e, &b, &h, Utc::now()).is_err());
    h.remove("x-oss-versionid");
    e.certified_until = Utc::now() + ChronoDuration::days(31);
    assert!(validate_anchor(&e, &b, &h, Utc::now()).is_err());
}

#[derive(Clone)]
pub(super) struct Wire {
    calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    fault: std::sync::Arc<std::sync::Mutex<String>>,
    expected: BucketRetentionExpectation,
}
async fn wire(
    axum::extract::State(w): axum::extract::State<Wire>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::http::Response<axum::body::Body> {
    let key = request.uri().query().unwrap_or("anchor").to_owned();
    w.calls.lock().unwrap().push(key.clone());
    let authorization = request
        .headers()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(authorization.starts_with("OSS4-HMAC-SHA256 Credential=STS.fixture/"));
    assert!(authorization.contains("/cn-hangzhou/oss/aliyun_v4_request"));
    assert_eq!(
        request.headers()["x-oss-security-token"],
        "TEST_TOKEN_DO_NOT_LOG"
    );
    let fault = w.fault.lock().unwrap().clone();
    let call_count = w.calls.lock().unwrap().len();
    if fault == "redirect" {
        return axum::http::Response::builder()
            .status(307)
            .header("location", "http://127.0.0.1:1/leak")
            .body(axum::body::Body::empty())
            .unwrap();
    }
    if fault == "denied" {
        return axum::http::Response::builder()
            .status(403)
            .body(axum::body::Body::from("TEST_SECRET_PROVIDER_BODY"))
            .unwrap();
    }
    if fault == "unavailable" || (fault == "retry" && call_count == 1) {
        return axum::http::Response::builder()
            .status(503)
            .body(axum::body::Body::empty())
            .unwrap();
    }
    let date = if fault == "clock" {
        Utc::now() - ChronoDuration::hours(1)
    } else {
        Utc::now()
    };
    let mut response = axum::http::Response::builder()
        .status(200)
        .header("date", date.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .header("x-oss-request-id", format!("opaque-request-{call_count}"));
    if key == "anchor" {
        assert_eq!(request.method(), Method::HEAD);
        assert_eq!(request.uri().path(), format!("/{}", w.expected.anchor_key));
        // Stable anchor, independent of wall-clock rounding between rounds.
        let modified = (Utc::now() - ChronoDuration::hours(1))
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        let mut headers = anchor_headers(&w.expected);
        headers.insert(
            "last-modified",
            modified
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string()
                .parse()
                .unwrap(),
        );
        for (name, value) in headers {
            if let Some(name) = name {
                response = response.header(name, value);
            }
        }
        return response.body(axum::body::Body::empty()).unwrap();
    }
    assert_eq!(request.method(), Method::GET);
    let mut body = match key.as_str() {
        "bucketInfo" => String::from_utf8(info())
            .unwrap()
            .replace("fixture-vault", &w.expected.bucket)
            .replace("cn-hangzhou", &w.expected.region)
            .replace("1234567890123456", &w.expected.account_id)
            .replace("kms-fixture", &w.expected.kms_key_id)
            .into_bytes(),
        "worm" => worm(),
        "versioning" => VERSION.to_vec(),
        _ => panic!("unexpected operation"),
    };
    if fault == "changed" && key == "worm" && call_count > 4 {
        body = String::from_utf8(body)
            .unwrap()
            .replace("opaqueWorm", "newWorm")
            .into_bytes();
    }
    if fault == "oversize" {
        body = vec![b'x'; BODY_LIMIT + 1];
    }
    response.body(axum::body::Body::from(body)).unwrap()
}
async fn fixture() -> (
    tempfile::TempDir,
    BucketRetentionVerifier,
    Wire,
    axum_server::Handle<std::net::SocketAddr>,
) {
    fixture_for(expected()).await
}
pub(super) async fn fixture_for(
    e: BucketRetentionExpectation,
) -> (
    tempfile::TempDir,
    BucketRetentionVerifier,
    Wire,
    axum_server::Handle<std::net::SocketAddr>,
) {
    use std::os::unix::fs::PermissionsExt;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("credentials.json");
    std::fs::write(&path, serde_json::to_vec(&serde_json::json!({"access_key_id":"STS.fixture","access_key_secret":"TEST_SECRET_DO_NOT_LOG","security_token":"TEST_TOKEN_DO_NOT_LOG","expires_at":Utc::now()+ChronoDuration::minutes(15)})).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wire_state = Wire {
        calls: Default::default(),
        fault: Default::default(),
        expected: e.clone(),
    };
    let app = axum::Router::new()
        .fallback(wire)
        .with_state(wire_state.clone());
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        include_bytes!("../tests/fixtures/admission/server.pem").to_vec(),
        include_bytes!("../tests/fixtures/admission/server.key").to_vec(),
    )
    .await
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = axum_server::Handle::new();
    let server = axum_server::from_tcp_rustls(listener, tls)
        .unwrap()
        .handle(handle.clone());
    tokio::spawn(async move {
        server.serve(app.into_make_service()).await.unwrap();
    });
    let mut verifier = BucketRetentionVerifier::new(e, path).unwrap();
    verifier.endpoint = format!("https://{address}");
    verifier.client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .add_root_certificate(
            reqwest::Certificate::from_pem(include_bytes!(
                "../tests/fixtures/admission/server-ca.pem"
            ))
            .unwrap(),
        )
        .build()
        .unwrap();
    (temp, verifier, wire_state, handle)
}
#[tokio::test]
async fn real_tls_v4_signed_twice_and_private_fresh_identity_bound_capability() {
    let (_temp, v, wire, server) = fixture().await;
    let mut proof = v.verify().await.unwrap();
    assert_eq!(
        wire.calls.lock().unwrap().as_slice(),
        [
            "bucketInfo",
            "worm",
            "versioning",
            "anchor",
            "bucketInfo",
            "worm",
            "versioning",
            "anchor"
        ]
    );
    assert_eq!(proof.receipt().requests.len(), 8);
    proof.check_current(&v.expected).unwrap();
    let mut other = v.expected.clone();
    other.profile_id = Uuid::new_v4();
    assert_eq!(
        proof.check_current(&other).unwrap_err().code,
        RetentionCode::IdentityMismatch
    );
    let serialized = serde_json::to_string(proof.receipt()).unwrap();
    assert!(
        !serialized.contains("TEST_SECRET")
            && !serialized.contains("TEST_TOKEN")
            && !serialized.contains("STS.fixture")
    );
    proof.receipt.activation_not_after = Utc::now() - ChronoDuration::seconds(1);
    assert_eq!(
        proof.check_current(&v.expected).unwrap_err().code,
        RetentionCode::Expired
    );
    server.shutdown();
}
#[tokio::test]
async fn live_errors_cannot_issue_proof_or_follow_redirect_or_echo_provider_body() {
    let (_temp, v, wire, server) = fixture().await;
    for (fault, code) in [
        ("redirect", RetentionCode::Transport),
        ("denied", RetentionCode::AccessDenied),
        ("clock", RetentionCode::ClockSkew),
        ("oversize", RetentionCode::ResponseLimit),
        ("changed", RetentionCode::Changed),
    ] {
        wire.calls.lock().unwrap().clear();
        *wire.fault.lock().unwrap() = fault.into();
        let error = v.verify().await.err().unwrap();
        assert_eq!(error.code, code, "{fault}");
        assert!(!error.to_string().contains("TEST_SECRET"));
        if fault == "redirect" {
            assert_eq!(wire.calls.lock().unwrap().len(), 1);
        }
    }
    server.shutdown();
}
#[tokio::test]
async fn bounded_read_retry_and_credential_expiry_permissions_no_fallback() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, v, wire, server) = fixture().await;
    *wire.fault.lock().unwrap() = "retry".into();
    assert!(v.verify().await.is_ok());
    assert_eq!(wire.calls.lock().unwrap().len(), 9);
    wire.calls.lock().unwrap().clear();
    *wire.fault.lock().unwrap() = "unavailable".into();
    assert_eq!(
        v.verify().await.err().unwrap().code,
        RetentionCode::Throttled
    );
    assert_eq!(wire.calls.lock().unwrap().len(), 3);
    std::fs::set_permissions(&v.sts_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        v.verify().await.err().unwrap().code,
        RetentionCode::Credentials
    );
    std::fs::set_permissions(&v.sts_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&v.sts_file, b"{\"access_key_id\":\"LTAIpermanent\",\"access_key_secret\":\"x\",\"security_token\":\"x\",\"expires_at\":\"2020-01-01T00:00:00Z\"}").unwrap();
    assert_eq!(
        v.verify().await.err().unwrap().code,
        RetentionCode::Credentials
    );
    server.shutdown();
}
