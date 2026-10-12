#![allow(clippy::expect_used)]
use super::*;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response},
    routing::any,
};
use serde_json::{Value, json};
use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

const ACCOUNT: &str = "1234567890123456";
const ROLE_ID: &str = "1234567890123458";
const AK: &str = "STS.public-volume-test";
const SECRET: &str = "PUBLIC_VOLUME_SECRET_MARKER";
const TOKEN: &str = "PUBLIC_VOLUME_TOKEN_MARKER";
const OIDC: &str = "PUBLIC_VOLUME_OIDC_MARKER";
const REQUEST_ID: &str = "volume-test/request:123";
const SUBJECT: &str = "system:serviceaccount:sandbox-system:sandbox-volume-deleter";

#[derive(Clone)]
struct MockState {
    disk: Arc<StdMutex<Value>>,
    expected_disk: Arc<StdMutex<String>>,
    actions: Arc<StdMutex<Vec<String>>>,
    session: Arc<StdMutex<String>>,
    delete_mode: Arc<AtomicU8>,
    preserve_mode: Arc<AtomicU8>,
    wrong_role: Arc<AtomicBool>,
}
pub(crate) struct Fixture {
    pub(crate) client: AlibabaCloudVolumeDeletion,
    state: MockState,
    task: tokio::task::JoinHandle<()>,
    _token: tempfile::NamedTempFile,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    pub(crate) async fn new() -> anyhow::Result<Self> {
        let token = tempfile::NamedTempFile::new()?;
        std::fs::write(token.path(), OIDC)?;
        let state = MockState {
            disk: Arc::new(StdMutex::new(disk_response())),
            expected_disk: Arc::new(StdMutex::new("d-workspace001".into())),
            actions: Arc::new(StdMutex::new(Vec::new())),
            session: Arc::new(StdMutex::new(String::new())),
            delete_mode: Arc::new(AtomicU8::new(0)),
            preserve_mode: Arc::new(AtomicU8::new(0)),
            wrong_role: Arc::new(AtomicBool::new(false)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let app = Router::new().fallback(any(mock)).with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client =
            AlibabaCloudVolumeDeletion::for_test(config(token.path().to_path_buf()), endpoint)?;
        Ok(Self {
            client,
            state,
            task,
            _token: token,
        })
    }
    pub(crate) fn count(&self, action: &str) -> usize {
        self.state
            .actions
            .lock()
            .expect("mock actions")
            .iter()
            .filter(|a| a.as_str() == action)
            .count()
    }
    pub(crate) fn set_delete_mode(&self, mode: u8) {
        self.state.delete_mode.store(mode, Ordering::SeqCst);
    }
    pub(crate) fn set_preserve_mode(&self, mode: u8) {
        self.state.preserve_mode.store(mode, Ordering::SeqCst);
    }
    pub(crate) fn set_delete_auto_snapshot(&self, enabled: bool) {
        self.mutate(|value| value["Disks"]["Disk"][0]["DeleteAutoSnapshot"] = json!(enabled));
    }
    pub(crate) fn set_disk_response(&self, value: Value) {
        *self.state.disk.lock().expect("mock disk") = value;
    }
    pub(crate) fn set_binding(&self, binding: &CloudDiskBinding) {
        *self.state.expected_disk.lock().expect("expected disk") = binding.disk_id.clone();
        self.mutate(|value| {
            let d = &mut value["Disks"]["Disk"][0];
            d["DiskId"] = json!(binding.disk_id);
            d["RegionId"] = json!(binding.region);
            d["ZoneId"] = json!(binding.zone_id);
            d["KMSKeyId"] = json!(binding.kms_key_id);
            d["Size"] = json!(binding.size_gib);
            d["Tags"]["Tag"] = json!([
                {"TagKey":"Deployment","TagValue":binding.deployment},
                {"TagKey":"kubernetes.io/created-for/pvc/namespace","TagValue":binding.namespace},
                {"TagKey":"kubernetes.io/created-for/pvc/name","TagValue":binding.pvc_name},
                {"TagKey":"kubernetes.io/created-for/pv/name","TagValue":binding.pv_name}
            ]);
        });
    }
    fn mutate(&self, change: impl FnOnce(&mut Value)) {
        change(&mut self.state.disk.lock().expect("mock disk"));
    }
    async fn identity(&self) -> anyhow::Result<CloudDiskIdentity> {
        match self.client.observe_disk(&binding()).await? {
            CloudDiskLookup::Present(observation) => Ok(observation.identity()?),
            CloudDiskLookup::Absent(_) => anyhow::bail!("expected present disk"),
        }
    }
}
fn config(path: PathBuf) -> CloudVolumeDeletionConfig {
    CloudVolumeDeletionConfig {
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        role_arn: format!("acs:ram::{ACCOUNT}:role/production-a-volume-deleter"),
        role_id: ROLE_ID.into(),
        oidc_provider_arn: format!("acs:ram::{ACCOUNT}:oidc-provider/sandbox"),
        oidc_issuer: "https://workload.example.test".into(),
        oidc_audience: "sts.aliyuncs.com".into(),
        oidc_subject: SUBJECT.into(),
        oidc_token_file: path,
        deployment: "production-a".into(),
        requests_per_second: 20,
        max_in_flight: 4,
    }
}
fn binding() -> CloudDiskBinding {
    CloudDiskBinding {
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        disk_id: "d-workspace001".into(),
        zone_id: "cn-hangzhou-h".into(),
        deployment: "production-a".into(),
        namespace: "tenant-a".into(),
        pvc_name: "ws-00000000-0000-4000-8000-000000000001".into(),
        pv_name: "pv-workspace001".into(),
        kms_key_id: "kms-workspace001".into(),
        size_gib: 40,
    }
}
fn disk_response() -> Value {
    // Normal non-shared Available cloud disks omit not-applicable attachment
    // fields. This must stay Incomplete, while DeleteDisk is still usable.
    json!({"RequestId":REQUEST_ID,"TotalCount":0,"NextToken":"","Disks":{"Disk":[{
        "DiskId":"d-workspace001","RegionId":"cn-hangzhou","ZoneId":"cn-hangzhou-h",
        "SerialNumber":"0a9d8df1-0000-4000-8000-000000000001","CreationTime":"2026-01-01T00:00:00Z",
        "Type":"data","Category":"cloud_essd","Portable":true,"Encrypted":true,"KMSKeyId":"kms-workspace001",
        "Size":40,"DiskChargeType":"PostPaid","DeleteWithInstance":false,"DeleteAutoSnapshot":false,
        "MultiAttach":"Disabled","Status":"Available","Tags":{"Tag":[
            {"TagKey":"Deployment","TagValue":"production-a"},
            {"TagKey":"kubernetes.io/created-for/pvc/namespace","TagValue":"tenant-a"},
            {"TagKey":"kubernetes.io/created-for/pvc/name","TagValue":"ws-00000000-0000-4000-8000-000000000001"},
            {"TagKey":"kubernetes.io/created-for/pv/name","TagValue":"pv-workspace001"}
        ]}
    }]}})
}
async fn mock(State(state): State<MockState>, request: Request<Body>) -> Response<Body> {
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let action = request.headers()["x-acs-action"]
        .to_str()
        .expect("action")
        .to_owned();
    state
        .actions
        .lock()
        .expect("mock actions")
        .push(action.clone());
    if action != "AssumeRoleWithOIDC" {
        assert_eq!(request.headers()["x-acs-security-token"], TOKEN);
        let headers: BTreeMap<String, String> = request
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str() == "host" || k.as_str().starts_with("x-acs-"))
            .map(|(k, v)| (k.to_string(), v.to_str().expect("header").into()))
            .collect();
        let (signed, digest) =
            signature(&headers, request.uri().query().unwrap_or(""), SECRET).expect("signature");
        assert_eq!(
            request.headers()["authorization"],
            format!("ACS3-HMAC-SHA256 Credential={AK},SignedHeaders={signed},Signature={digest}")
        );
    }
    let (status, value) = match action.as_str() {
        "AssumeRoleWithOIDC" => {
            assert!(!request.headers().contains_key("authorization"));
            assert_eq!(query.get("OIDCToken").map(String::as_str), Some(OIDC));
            assert_eq!(
                query.get("RoleArn").map(String::as_str),
                Some(format!("acs:ram::{ACCOUNT}:role/production-a-volume-deleter").as_str())
            );
            assert_eq!(
                query.get("DurationSeconds").map(String::as_str),
                Some("900")
            );
            let session = query.get("RoleSessionName").expect("session").clone();
            assert!(session.starts_with("volume-"));
            *state.session.lock().expect("session") = session.clone();
            (
                200,
                json!({"RequestId":REQUEST_ID,
                    "AssumedRoleUser":{"Arn":format!("acs:ram::{ACCOUNT}:role/production-a-volume-deleter/{session}")},
                    "OIDCTokenInfo":{"Issuer":"https://workload.example.test","Subject":SUBJECT,"ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success","ExpirationTime":Utc::now()+ChronoDuration::seconds(600),"IssuanceTime":Utc::now()-ChronoDuration::seconds(10)},
                    "Credentials":{"AccessKeyId":AK,"AccessKeySecret":SECRET,"SecurityToken":TOKEN,"Expiration":Utc::now()+ChronoDuration::seconds(900)}
                }),
            )
        }
        "GetCallerIdentity" => (
            200,
            json!({"RequestId":REQUEST_ID,"AccountId":ACCOUNT,"IdentityType":"AssumedRoleUser",
                "Arn":format!("acs:ram::{ACCOUNT}:role/production-a-volume-deleter/{}",state.session.lock().expect("session")),
                "RoleId":if state.wrong_role.load(Ordering::SeqCst) {"9999999999999999"} else {ROLE_ID}
            }),
        ),
        "DescribeDisks" => {
            assert_eq!(
                query,
                BTreeMap::from([
                    (
                        "DiskIds".into(),
                        json!([state.expected_disk.lock().expect("expected disk").clone()])
                            .to_string()
                    ),
                    ("RegionId".into(), "cn-hangzhou".into()),
                    ("MaxResults".into(), "10".into()),
                ])
            );
            (200, state.disk.lock().expect("disk").clone())
        }
        "DeleteDisk" | "ModifyDiskAttribute" => {
            let mut expected = BTreeMap::from([(
                "DiskId".into(),
                state.expected_disk.lock().expect("expected disk").clone(),
            )]);
            let mode = if action == "ModifyDiskAttribute" {
                expected.insert("DeleteAutoSnapshot".into(), "false".into());
                let mode = state.preserve_mode.load(Ordering::SeqCst);
                if mode == 0 {
                    state.disk.lock().expect("disk")["Disks"]["Disk"][0]["DeleteAutoSnapshot"] =
                        json!(false);
                }
                mode
            } else {
                state.delete_mode.load(Ordering::SeqCst)
            };
            assert_eq!(query, expected);
            match mode {
                1 => (
                    503,
                    json!({"RequestId":REQUEST_ID,"Code":"InternalError","Message":SECRET}),
                ),
                2 => (200, json!({"unexpected":SECRET})),
                3 => (
                    403,
                    json!({"RequestId":REQUEST_ID,"Code":"Forbidden","Message":TOKEN}),
                ),
                4 => (
                    403,
                    json!({"RequestId":REQUEST_ID,"Code":"IncorrectDiskStatus","Message":TOKEN}),
                ),
                5 => (
                    429,
                    json!({"RequestId":REQUEST_ID,"Code":"Throttling","Message":OIDC}),
                ),
                6 => (302, json!({"RequestId":REQUEST_ID})),
                7 => (
                    200,
                    json!({"RequestId":REQUEST_ID,"Code":"InternalError","Message":SECRET}),
                ),
                8 => {
                    let chunks = futures_util::stream::iter([
                        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{")),
                        Err(std::io::Error::other("mock disconnected after dispatch")),
                    ]);
                    return Response::builder()
                        .status(200)
                        .body(Body::from_stream(chunks))
                        .expect("disconnected response");
                }
                _ => (200, json!({"RequestId":REQUEST_ID})),
            }
        }
        _ => panic!("unexpected privileged action: {action}"),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("location", "http://127.0.0.1:9/untrusted-redirect")
        .body(Body::from(serde_json::to_vec(&value).expect("JSON")))
        .expect("response")
}

#[tokio::test]
async fn available_disk_with_omitted_optional_attachment_fields_deletes_once() -> anyhow::Result<()>
{
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    let attempt = Uuid::new_v4();
    let outcome = f.client.delete_disk(&identity, attempt).await?;
    let CloudDiskDeleteOutcome::Accepted(submission) = outcome else {
        anyhow::bail!("accepted")
    };
    assert_eq!(submission.attempt_id(), attempt);
    assert_eq!(submission.evidence().action(), "DeleteDisk");
    assert_eq!(
        submission.evidence().provider_request_id(),
        Some(REQUEST_ID)
    );
    assert_eq!(
        submission.preflight().attachment_state(),
        CloudDiskAttachmentState::Incomplete
    );
    assert_eq!(
        submission.preflight().identity()?.serial_number,
        identity.serial_number
    );
    assert_eq!(f.count("DescribeDisks"), 2); // Fresh preflight after registration.
    assert_eq!(f.count("DeleteDisk"), 1);
    assert_eq!(f.count("AssumeRoleWithOIDC"), 1);
    assert!(f.client.transport.inner.bindings.is_empty());
    assert_eq!(
        f.client
            .transport
            .observe("i-anynode")
            .await
            .expect_err("no node permissions")
            .code,
        CloudErrorCode::UnknownInstance
    );
    Ok(())
}

#[tokio::test]
async fn serial_creation_time_and_ownership_drift_never_delete() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    for (field, value) in [
        ("SerialNumber", json!("different-serial")),
        ("CreationTime", json!("2026-01-02T00:00:00Z")),
        ("DiskId", json!("d-otherdisk")),
        ("RegionId", json!("cn-shanghai")),
        ("ZoneId", json!("cn-hangzhou-i")),
        ("KMSKeyId", json!("kms-other")),
        ("Size", json!(80)),
        ("Encrypted", json!(false)),
        ("DeleteWithInstance", json!(true)),
        ("MultiAttach", json!("Enabled")),
        ("Type", json!("system")),
        ("DiskChargeType", json!("PrePaid")),
    ] {
        f.mutate(|r| {
            *r = disk_response();
            r["Disks"]["Disk"][0][field] = value;
        });
        assert_eq!(
            f.client
                .delete_disk(&identity, Uuid::new_v4())
                .await
                .expect_err(field)
                .code,
            CloudErrorCode::IdentityMismatch
        );
    }
    for index in 0..4 {
        f.mutate(|r| {
            *r = disk_response();
            r["Disks"]["Disk"][0]["Tags"]["Tag"][index]["TagValue"] = json!("other-owner");
        });
        assert_eq!(
            f.client
                .delete_disk(&identity, Uuid::new_v4())
                .await
                .expect_err("tag drift")
                .code,
            CloudErrorCode::IdentityMismatch
        );
    }
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[tokio::test]
async fn active_attachment_unsafe_state_or_snapshot_cascade_never_delete() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    for (field, value) in [
        ("Status", json!("In_use")),
        ("Status", json!("Attaching")),
        ("Status", json!("Detaching")),
        ("Status", json!("Creating")),
        ("Status", json!("ReIniting")),
        ("InstanceId", json!("i-othernode")),
        ("MountInstanceNum", json!(1)),
        (
            "Attachments",
            json!({"Attachment":[{"InstanceId":"i-othernode"}]}),
        ),
        (
            "MountInstances",
            json!({"MountInstance":[{"InstanceId":"i-othernode"}]}),
        ),
        ("DeleteAutoSnapshot", json!(true)),
    ] {
        f.mutate(|r| {
            *r = disk_response();
            r["Disks"]["Disk"][0][field] = value;
        });
        assert_eq!(
            f.client
                .delete_disk(&identity, Uuid::new_v4())
                .await
                .expect_err(field)
                .code,
            CloudErrorCode::InvalidState
        );
    }
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[tokio::test]
async fn identity_registration_requires_serial_and_creation_but_legacy_observation_does_not()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    for field in ["SerialNumber", "CreationTime"] {
        f.mutate(|r| {
            *r = disk_response();
            r["Disks"]["Disk"][0]
                .as_object_mut()
                .expect("disk")
                .remove(field);
        });
        let observation = f.client.observe_disk(&binding()).await?;
        let CloudDiskLookup::Present(observation) = observation else {
            anyhow::bail!("present")
        };
        assert_eq!(
            observation
                .identity()
                .expect_err("missing immutable identity")
                .code,
            CloudErrorCode::MalformedResponse
        );
        assert_eq!(
            f.client
                .delete_disk(&identity, Uuid::new_v4())
                .await
                .expect_err(field)
                .code,
            CloudErrorCode::MalformedResponse
        );
    }
    for (field, value) in [
        ("SerialNumber", json!("")),
        ("SerialNumber", json!("invalid\nserial")),
        ("CreationTime", json!("invalid")),
        ("CreationTime", json!("2999-01-01T00:00:00Z")),
    ] {
        f.mutate(|r| {
            *r = disk_response();
            r["Disks"]["Disk"][0][field] = value;
        });
        assert_eq!(
            f.client
                .delete_disk(&identity, Uuid::new_v4())
                .await
                .expect_err(field)
                .code,
            CloudErrorCode::MalformedResponse
        );
    }
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[tokio::test]
async fn absent_is_observation_without_write_and_unresolved_pagination_is_not_absence()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    f.mutate(|r| {
        r["Disks"]["Disk"] = json!([]);
        r["TotalCount"] = json!(100);
    });
    let outcome = f.client.delete_disk(&identity, Uuid::new_v4()).await?;
    let CloudDiskDeleteOutcome::AlreadyAbsent(absence) = outcome else {
        anyhow::bail!("absence")
    };
    assert_eq!(absence.binding().disk_id, identity.binding.disk_id);
    assert_eq!(absence.evidence().action(), "DescribeDisks");
    f.mutate(|r| r["NextToken"] = json!("more"));
    assert_eq!(
        f.client
            .delete_disk(&identity, Uuid::new_v4())
            .await
            .expect_err("pagination")
            .code,
        CloudErrorCode::IdentityMismatch
    );
    f.mutate(|r| *r = json!({"RequestId":REQUEST_ID}));
    assert_eq!(
        f.client
            .delete_disk(&identity, Uuid::new_v4())
            .await
            .expect_err("missing collection")
            .code,
        CloudErrorCode::MalformedResponse
    );
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[tokio::test]
async fn unknown_results_are_single_attempt_and_explicit_retry_rechecks_identity()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    for (count, mode) in [1, 2, 7, 8].into_iter().enumerate() {
        f.state.delete_mode.store(mode, Ordering::SeqCst);
        let attempt = Uuid::new_v4();
        let result = f.client.delete_disk(&identity, attempt).await?;
        let CloudDiskDeleteOutcome::OutcomeUnknown(submission) = result else {
            anyhow::bail!("unknown")
        };
        assert_eq!(submission.attempt_id(), attempt);
        assert_eq!(f.count("DeleteDisk"), count + 1);
        let json = serde_json::to_string(&submission)?;
        for marker in [SECRET, TOKEN, OIDC] {
            assert!(!json.contains(marker));
        }
    }
    f.mutate(|r| r["Disks"]["Disk"][0]["SerialNumber"] = json!("replaced-disk"));
    assert_eq!(
        f.client
            .delete_disk(&identity, Uuid::new_v4())
            .await
            .expect_err("changed before retry")
            .code,
        CloudErrorCode::IdentityMismatch
    );
    assert_eq!(f.count("DeleteDisk"), 4);
    assert_eq!(f.count("DescribeDisks"), 6);
    Ok(())
}

#[tokio::test]
async fn rejected_writes_throttling_and_redirects_are_not_retried() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    for (count, mode) in [3, 4, 5, 6].into_iter().enumerate() {
        f.state.delete_mode.store(mode, Ordering::SeqCst);
        let failure = f
            .client
            .delete_disk(&identity, Uuid::new_v4())
            .await
            .expect_err("cloud rejected");
        if mode == 4 {
            assert_eq!(failure.code, CloudErrorCode::InvalidState);
        }
        assert_eq!(f.count("DeleteDisk"), count + 1);
        assert_eq!(
            failure
                .evidence
                .as_ref()
                .expect("request evidence")
                .action(),
            "DeleteDisk"
        );
        for marker in [SECRET, TOKEN, OIDC] {
            assert!(!format!("{failure:?}").contains(marker));
        }
    }
    Ok(())
}

#[tokio::test]
async fn dedicated_identity_and_deployment_are_checked_before_disk_actions() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    for field in ["account", "region", "deployment"] {
        let mut b = binding();
        match field {
            "account" => b.account_id = "9999999999999999".into(),
            "region" => b.region = "cn-shanghai".into(),
            _ => b.deployment = "other-deployment".into(),
        }
        assert_eq!(
            f.client.observe_disk(&b).await.expect_err(field).code,
            CloudErrorCode::Configuration
        );
    }
    assert_eq!(f.count("AssumeRoleWithOIDC"), 0);
    f.state.wrong_role.store(true, Ordering::SeqCst);
    assert_eq!(
        f.client
            .observe_disk(&binding())
            .await
            .expect_err("wrong role")
            .code,
        CloudErrorCode::CredentialIdentityMismatch
    );
    assert_eq!(f.count("DescribeDisks"), 0);
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[test]
fn configuration_requires_independent_service_account_and_exact_shape() -> anyhow::Result<()> {
    let mut c = config(PathBuf::from("/var/run/token"));
    AlibabaCloudVolumeDeletion::validate(&c)?;
    c.oidc_subject = "system:serviceaccount:sandbox-system:sandbox-fencing".into();
    assert_eq!(
        AlibabaCloudVolumeDeletion::validate(&c)
            .expect_err("fencing SA")
            .code,
        CloudErrorCode::Configuration
    );
    let mut value = serde_json::to_value(binding())?;
    value["unknown_permission"] = json!(true);
    assert!(serde_json::from_value::<CloudDiskBinding>(value).is_err());
    Ok(())
}

#[tokio::test]
async fn invalid_attempt_and_forged_expected_identity_do_not_send_write() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let mut identity = f.identity().await?;
    assert_eq!(
        f.client
            .delete_disk(&identity, Uuid::nil())
            .await
            .expect_err("nil attempt")
            .code,
        CloudErrorCode::Configuration
    );
    identity.serial_number.clear();
    assert_eq!(
        f.client
            .delete_disk(&identity, Uuid::new_v4())
            .await
            .expect_err("empty serial")
            .code,
        CloudErrorCode::Configuration
    );
    assert_eq!(f.count("DescribeDisks"), 1);
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[tokio::test]
async fn snapshot_preservation_changes_only_cascade_flag_and_requires_readback()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.mutate(|r| r["Disks"]["Disk"][0]["DeleteAutoSnapshot"] = json!(true));
    let identity = f.identity().await?;
    assert_eq!(
        f.client
            .delete_disk(&identity, Uuid::new_v4())
            .await
            .expect_err("must preserve first")
            .code,
        CloudErrorCode::InvalidState
    );
    let attempt = Uuid::new_v4();
    let CloudDiskPreserveOutcome::Accepted(submission) = f
        .client
        .preserve_automatic_snapshots(&identity, attempt)
        .await?
    else {
        anyhow::bail!("accepted");
    };
    assert_eq!(submission.attempt_id(), attempt);
    assert!(submission.preflight().delete_auto_snapshot());
    assert_eq!(submission.evidence().action(), "ModifyDiskAttribute");
    assert_eq!(
        submission.evidence().provider_request_id(),
        Some(REQUEST_ID)
    );
    assert_eq!(f.count("ModifyDiskAttribute"), 1);
    let CloudDiskPreserveOutcome::AlreadyPreserved(observation) = f
        .client
        .preserve_automatic_snapshots(&identity, Uuid::new_v4())
        .await?
    else {
        anyhow::bail!("already preserved");
    };
    assert!(!observation.delete_auto_snapshot());
    assert_eq!(observation.evidence().action(), "DescribeDisks");
    assert_eq!(f.count("ModifyDiskAttribute"), 1);
    assert!(matches!(
        f.client.delete_disk(&identity, Uuid::new_v4()).await?,
        CloudDiskDeleteOutcome::Accepted(_)
    ));
    assert_eq!(f.count("DeleteDisk"), 1);
    Ok(())
}

#[tokio::test]
async fn snapshot_preservation_ack_does_not_allow_delete_without_false_observation()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.mutate(|r| r["Disks"]["Disk"][0]["DeleteAutoSnapshot"] = json!(true));
    f.set_preserve_mode(9); // Successful ACK, provider read-back has not converged.
    let identity = f.identity().await?;
    assert!(matches!(
        f.client
            .preserve_automatic_snapshots(&identity, Uuid::new_v4())
            .await?,
        CloudDiskPreserveOutcome::Accepted(_)
    ));
    assert_eq!(
        f.client
            .delete_disk(&identity, Uuid::new_v4())
            .await
            .expect_err("fresh state still unsafe")
            .code,
        CloudErrorCode::InvalidState
    );
    assert_eq!(f.count("ModifyDiskAttribute"), 1);
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[tokio::test]
async fn snapshot_preservation_unknown_is_single_attempt_and_retry_rechecks_identity()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.mutate(|r| r["Disks"]["Disk"][0]["DeleteAutoSnapshot"] = json!(true));
    let identity = f.identity().await?;
    for (count, mode) in [1, 2, 7, 8].into_iter().enumerate() {
        f.set_preserve_mode(mode);
        let attempt = Uuid::new_v4();
        let CloudDiskPreserveOutcome::OutcomeUnknown(submission) = f
            .client
            .preserve_automatic_snapshots(&identity, attempt)
            .await?
        else {
            anyhow::bail!("unknown");
        };
        assert_eq!(submission.attempt_id(), attempt);
        assert_eq!(submission.evidence().action(), "ModifyDiskAttribute");
        assert_eq!(f.count("ModifyDiskAttribute"), count + 1);
        let serialized = serde_json::to_string(&submission)?;
        for marker in [SECRET, TOKEN, OIDC] {
            assert!(!serialized.contains(marker));
        }
    }
    f.mutate(|r| r["Disks"]["Disk"][0]["SerialNumber"] = json!("replaced-disk"));
    assert_eq!(
        f.client
            .preserve_automatic_snapshots(&identity, Uuid::new_v4())
            .await
            .expect_err("retry preflight drift")
            .code,
        CloudErrorCode::IdentityMismatch
    );
    assert_eq!(f.count("ModifyDiskAttribute"), 4);
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}

#[tokio::test]
async fn snapshot_preservation_refuses_active_or_changed_disk_and_absence_never_deletes()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    for (field, value, code) in [
        (
            "SerialNumber",
            json!("replaced-disk"),
            CloudErrorCode::IdentityMismatch,
        ),
        (
            "CreationTime",
            json!("2026-01-02T00:00:00Z"),
            CloudErrorCode::IdentityMismatch,
        ),
        (
            "KMSKeyId",
            json!("kms-other"),
            CloudErrorCode::IdentityMismatch,
        ),
        ("Status", json!("In_use"), CloudErrorCode::InvalidState),
        (
            "InstanceId",
            json!("i-othernode"),
            CloudErrorCode::InvalidState,
        ),
        ("MountInstanceNum", json!(1), CloudErrorCode::InvalidState),
    ] {
        f.mutate(|r| {
            *r = disk_response();
            r["Disks"]["Disk"][0]["DeleteAutoSnapshot"] = json!(true);
            r["Disks"]["Disk"][0][field] = value;
        });
        assert_eq!(
            f.client
                .preserve_automatic_snapshots(&identity, Uuid::new_v4())
                .await
                .expect_err(field)
                .code,
            code
        );
    }
    f.mutate(|r| {
        *r = disk_response();
        r["Disks"]["Disk"] = json!([]);
    });
    assert!(matches!(
        f.client
            .preserve_automatic_snapshots(&identity, Uuid::new_v4())
            .await?,
        CloudDiskPreserveOutcome::AlreadyAbsent(_)
    ));
    assert_eq!(f.count("ModifyDiskAttribute"), 0);
    assert_eq!(f.count("DeleteDisk"), 0);
    Ok(())
}
