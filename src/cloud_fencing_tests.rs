// Test fixture constants and poisoned mock locks are assertion failures.
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
use std::{
    collections::BTreeMap,
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicU8, Ordering},
    },
};
const ACCOUNT: &str = "1234567890123456";
const ROLE_ID: &str = "1234567890123457";
const AK: &str = "STS.public-test-ak";
const SECRET: &str = "PUBLIC_TEST_SECRET_MARKER";
const TOKEN: &str = "PUBLIC_TEST_STS_MARKER";
const OIDC: &str = "PUBLIC_TEST_OIDC_MARKER";
const INSTANCE: &str = "i-testnode001";
const PROVIDER_REQUEST: &str = "11111111-2222-4333-8444-555555555555";
#[derive(Clone)]
struct MockState {
    mode: Arc<AtomicU8>,
    requests: Arc<StdMutex<Vec<(String, Instant)>>>,
    session: Arc<StdMutex<String>>,
    disk_response: Arc<StdMutex<Option<Value>>>,
}
struct Fixture {
    client: AlibabaCloudFencing,
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
    async fn new(mode: u8) -> anyhow::Result<Self> {
        let token = tempfile::NamedTempFile::new()?;
        std::fs::write(token.path(), OIDC)?;
        let config = config(token.path().to_path_buf());
        validate_config(&config).map_err(|_| anyhow::anyhow!("test config"))?;
        let state = MockState {
            mode: Arc::new(AtomicU8::new(mode)),
            requests: Arc::new(StdMutex::new(vec![])),
            session: Arc::new(StdMutex::new(String::new())),
            disk_response: Arc::new(StdMutex::new(None)),
        };
        let app = Router::new().fallback(any(mock)).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = AlibabaCloudFencing::for_test(config, base)?;
        Ok(Self {
            client,
            state,
            task,
            _token: token,
        })
    }
    fn count(&self, action: &str) -> usize {
        self.state
            .requests
            .lock()
            .expect("test lock")
            .iter()
            .filter(|(a, _)| a == action)
            .count()
    }
}
fn config(path: PathBuf) -> CloudFencingConfig {
    CloudFencingConfig {
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        role_arn: format!("acs:ram::{ACCOUNT}:role/sandbox-fencing"),
        role_id: ROLE_ID.into(),
        oidc_provider_arn: format!("acs:ram::{ACCOUNT}:oidc-provider/sandbox"),
        oidc_issuer: "https://workload-issuer.example.test".into(),
        oidc_audience: "sts.aliyuncs.com".into(),
        oidc_subject: "system:serviceaccount:sandbox-system:sandbox-fencing".into(),
        oidc_token_file: path,
        instances: vec![CloudInstanceBinding {
            instance_id: INSTANCE.into(),
            vpc_id: "vpc-testnetwork".into(),
            private_ip: "10.0.1.4".parse().expect("test IP"),
            deployment: "production-a".into(),
        }],
        requests_per_second: 20,
        max_in_flight: 4,
    }
}
async fn mock(State(state): State<MockState>, request: Request<Body>) -> Response<Body> {
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let action = request
        .headers()
        .get("x-acs-action")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let seen = {
        let mut rows = state.requests.lock().expect("test lock");
        rows.push((action.clone(), Instant::now()));
        rows.iter().filter(|(a, _)| a == &action).count()
    };
    let mode = state.mode.load(Ordering::SeqCst);
    let id = if mode == 18 {
        "opaque-request/eu-2026:abc"
    } else {
        PROVIDER_REQUEST
    };
    if action != "AssumeRoleWithOIDC" {
        assert_eq!(request.headers()["x-acs-security-token"], TOKEN);
        let values: BTreeMap<String, String> = request
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str() == "host" || k.as_str().starts_with("x-acs-"))
            .map(|(k, v)| (k.to_string(), v.to_str().expect("header").into()))
            .collect();
        let (signed, digest) = signature(&values, request.uri().query().unwrap_or(""), SECRET)
            .expect("test signature");
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
                query.get("DurationSeconds").map(String::as_str),
                Some("900")
            );
            let session = query.get("RoleSessionName").expect("session").clone();
            *state.session.lock().expect("test lock") = session.clone();
            if mode == 16 {
                (
                    403,
                    json!({"RequestId":id,"Code":"Forbidden","Message":format!("{SECRET}/{TOKEN}/{OIDC}")}),
                )
            } else {
                (
                    200,
                    json!({"RequestId":id,"AssumedRoleUser":{"Arn":format!("acs:ram::{ACCOUNT}:role/sandbox-fencing/{session}"),"AssumedRoleId":"123:test"},"OIDCTokenInfo":{"Issuer":"https://workload-issuer.example.test","Subject":if mode==2{"wrong-workload"}else{"system:serviceaccount:sandbox-system:sandbox-fencing"},"ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success","ExpirationTime":Utc::now()+ChronoDuration::seconds(600),"IssuanceTime":Utc::now()-ChronoDuration::seconds(10)},"Credentials":{"AccessKeyId":AK,"AccessKeySecret":SECRET,"SecurityToken":TOKEN,"Expiration":Utc::now()+ChronoDuration::seconds(if mode==9{60}else{900})}}),
                )
            }
        }
        "GetCallerIdentity" => (
            200,
            json!({"RequestId":id,"AccountId":if mode==1{"0000000000000000"}else{ACCOUNT},"IdentityType":"AssumedRoleUser","Arn":format!("acs:ram::{ACCOUNT}:role/sandbox-fencing/{}",state.session.lock().expect("test lock")),"RoleId":if mode==19{"9999999999999999"}else{ROLE_ID},"PrincipalId":"ignored-not-a-role-id"}),
        ),
        "DescribeInstances" => {
            assert_eq!(
                query.get("RegionId").map(String::as_str),
                Some("cn-hangzhou")
            );
            assert_eq!(
                query.get("InstanceIds").map(String::as_str),
                Some("[\"i-testnode001\"]")
            );
            assert!(!query.contains_key("Status"));
            if mode == 8 && seen == 1 {
                (
                    429,
                    json!({"RequestId":id,"Code":"Throttling.User","Message":"sensitive marker"}),
                )
            } else {
                (
                    200,
                    json!({"RequestId":id,"TotalCount":1,"NextToken":if mode==5{"unexpected-page"}else{""},"Instances":{"Instance":[{"InstanceId":if mode==3{"i-anothernode"}else{INSTANCE},"RegionId":"cn-hangzhou","InstanceNetworkType":"vpc","Status":if mode==17{"Stopped"}else{"Running"},"VpcAttributes":{"VpcId":if mode==4{"vpc-othernetwork"}else{"vpc-testnetwork"},"PrivateIpAddress":{"IpAddress":[if mode==10{"10.0.1.5"}else{"10.0.1.4"}]}},"Tags":{"Tag":[{"TagKey":"Deployment","TagValue":"production-a"},{"TagKey":"Role","TagValue":if mode==11{"control"}else{"kata"}}]}}]}}),
                )
            }
        }
        "DescribeDisks" => {
            assert_eq!(
                query,
                BTreeMap::from([
                    ("DiskIds".into(), "[\"d-testworkspace001\"]".into()),
                    ("RegionId".into(), "cn-hangzhou".into()),
                    ("MaxResults".into(), "10".into()),
                ])
            );
            (
                200,
                state
                    .disk_response
                    .lock()
                    .expect("test lock")
                    .clone()
                    .expect("disk fixture"),
            )
        }
        "StopInstance" => {
            assert_eq!(
                query,
                BTreeMap::from([
                    ("ForceStop".into(), "true".into()),
                    ("InstanceId".into(), INSTANCE.into()),
                    ("StoppedMode".into(), "KeepCharging".into())
                ])
            );
            match mode {
                6 => (
                    503,
                    json!({"RequestId":id,"Code":"InternalError","Message":"provider secret"}),
                ),
                7 => (200, json!({"unexpected":"MALFORMED_PROVIDER_MARKER"})),
                12 => {
                    return Response::builder()
                        .status(302)
                        .header("location", "/must-not-follow")
                        .body(Body::empty())
                        .expect("test response");
                }
                13 => {
                    return Response::builder()
                        .status(200)
                        .body(Body::from(vec![b'x'; BODY_LIMIT + 1]))
                        .expect("test response");
                }
                14 => {
                    return Response::builder()
                        .status(200)
                        .body(Body::from_stream(futures_util::stream::once(async {
                            Err::<String, std::io::Error>(std::io::Error::other(
                                "mock dropped connection",
                            ))
                        })))
                        .expect("test response");
                }
                15 => (
                    200,
                    json!({"RequestId":id,"Code":"InternalError","Message":"sensitive"}),
                ),
                _ => (200, json!({"RequestId":id})),
            }
        }
        _ => (500, json!({"error":"unexpected mock action"})),
    };
    let mut value = value;
    if action == "DescribeInstances" && mode == 20 {
        value["TotalCount"] = json!(0);
    }
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .expect("test response")
}

#[test]
fn oidc_time_fields_match_the_official_response_example() -> anyhow::Result<()> {
    // Official AssumeRoleWithOIDC response schema/example, checked 2026-10-03:
    // https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerolewithoidc
    let info: OidcInfo = serde_json::from_str(
        r#"{
        "Subject":"KryrkIdjylZb7agUgCEf****",
        "Issuer":"https://dev-xxxxxx.okta.com",
        "ClientIds":"496271242565057****",
        "ExpirationTime":"2021-10-20T04:27:09Z",
        "IssuanceTime":"2021-10-20T03:27:09Z",
        "VerificationInfo":"Success"
    }"#,
    )?;
    assert_eq!(
        info.expiration_time.timestamp() - info.issuance_time.timestamp(),
        3600
    );
    assert_eq!(
        info.expiration_time
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        "2021-10-20T04:27:09Z"
    );
    Ok(())
}

#[test]
fn acs3_signature_matches_official_complete_vector() -> anyhow::Result<()> {
    // Official V3 example, using deliberately public sample credentials.
    let endpoint = url::Url::parse("https://ecs.cn-shanghai.aliyuncs.com/")?;
    let now = "2023-10-26T10:22:32Z".parse::<DateTime<Utc>>()?;
    let headers = signed_headers(
        &endpoint,
        "RunInstances",
        ECS_VERSION,
        "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai",
        None,
        now,
        "3156853299f313e23d1673dc12e1703d",
    )?;
    let values: BTreeMap<String, String> = headers
        .iter()
        .filter(|(k, _)| k.as_str() != "accept")
        .map(|(k, v)| (k.to_string(), v.to_str().expect("sample header").into()))
        .collect();
    let (_, digest) = signature(
        &values,
        "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai",
        "YourAccessKeySecret",
    )?;
    assert_eq!(
        digest,
        "06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"
    );
    assert_eq!(encode("a b+*/~中国"), "a%20b%2B%2A%2F~%E4%B8%AD%E5%9B%BD");
    Ok(())
}
#[test]
fn configuration_rejects_unbound_accounts_targets_and_endpoint_injection() {
    let base = config(PathBuf::from("/tmp/public-test-token"));
    for bad in 0..6 {
        let mut c = base.clone();
        match bad {
            0 => c.region = "cn-hangzhou.attacker.example".into(),
            1 => c.role_arn = "acs:ram::0000000000000000:role/fencing".into(),
            2 => c.instances[0].private_ip = "8.8.8.8".parse().expect("test IP"),
            3 => c.instances.push(c.instances[0].clone()),
            4 => c.oidc_audience = "sts.aliyuncs.com,other".into(),
            _ => c.role_arn += "/*",
        };
        assert!(
            matches!(AlibabaCloudFencing::new(c),Err(e) if e.code==CloudErrorCode::Configuration)
        );
    }
}
#[tokio::test]
async fn oidc_singleflight_bound_identity_and_signed_exact_stop() -> anyhow::Result<()> {
    let f = Fixture::new(0).await?;
    let client = f.client.clone();
    let (a, b, c, d) = tokio::join!(
        f.client.observe(INSTANCE),
        client.observe(INSTANCE),
        f.client.observe(INSTANCE),
        client.observe(INSTANCE)
    );
    for r in [a, b, c, d] {
        assert_eq!(r?.state(), CloudInstanceState::Running);
    }
    assert_eq!(f.count("AssumeRoleWithOIDC"), 1);
    assert_eq!(f.count("GetCallerIdentity"), 1);
    let attempt = Uuid::new_v4();
    let CloudStopOutcome::Accepted(stop) = f.client.force_stop(INSTANCE, attempt).await? else {
        anyhow::bail!("expected submission receipt");
    };
    assert_eq!(stop.attempt_id(), attempt);
    assert_eq!(
        stop.evidence().provider_request_id(),
        Some(PROVIDER_REQUEST)
    );
    assert_eq!(f.count("StopInstance"), 1);
    let observed: Value = serde_json::to_value(stop.preflight())?;
    assert_eq!(observed["state"], "RUNNING");
    assert!(observed.get("fenced").is_none());
    let times = f.state.requests.lock().expect("test lock");
    for pair in times.windows(2) {
        assert!(pair[1].1.duration_since(pair[0].1) >= Duration::from_millis(40));
    }
    Ok(())
}
#[tokio::test]
async fn wrong_identity_network_tags_and_pagination_never_reach_stop() -> anyhow::Result<()> {
    for mode in [1, 2, 3, 4, 5, 9, 10, 11, 19] {
        let f = Fixture::new(mode).await?;
        assert!(f.client.force_stop(INSTANCE, Uuid::new_v4()).await.is_err());
        assert_eq!(f.count("StopInstance"), 0);
    }
    let f = Fixture::new(0).await?;
    assert!(
        matches!(f.client.force_stop("i-unregistered",Uuid::new_v4()).await,Err(e) if e.code==CloudErrorCode::UnknownInstance)
    );
    assert_eq!(f.count("AssumeRoleWithOIDC"), 0);
    Ok(())
}
#[tokio::test]
async fn ambiguous_stop_is_never_retried_and_stopped_is_only_observation() -> anyhow::Result<()> {
    for mode in [6, 7, 13, 14, 15] {
        let f = Fixture::new(mode).await?;
        assert!(matches!(
            f.client.force_stop(INSTANCE, Uuid::new_v4()).await?,
            CloudStopOutcome::OutcomeUnknown(_)
        ));
        assert_eq!(f.count("StopInstance"), 1);
    }
    let f = Fixture::new(17).await?;
    assert!(matches!(
        f.client.force_stop(INSTANCE, Uuid::new_v4()).await?,
        CloudStopOutcome::AlreadyStopped(_)
    ));
    assert_eq!(f.count("StopInstance"), 0);
    let f = Fixture::new(12).await?;
    assert!(f.client.force_stop(INSTANCE, Uuid::new_v4()).await.is_err());
    assert_eq!(f.state.requests.lock().expect("test lock").len(), 4);
    Ok(())
}
#[tokio::test]
async fn read_throttle_retries_but_expired_refresh_and_errors_do_not_leak_credentials()
-> anyhow::Result<()> {
    let f = Fixture::new(8).await?;
    f.client.observe(INSTANCE).await?;
    assert_eq!(f.count("DescribeInstances"), 2);
    // A still-present credential inside the refresh window must never become
    // fallback when the replacement response fails its identity/lifetime checks.
    *f.client.inner.credentials.lock().await = Some(Arc::new(Credentials {
        access_key_id: AK.into(),
        secret: SECRET.into(),
        token: TOKEN.into(),
        expires: Utc::now() + ChronoDuration::seconds(89),
    }));
    f.state.mode.store(9, Ordering::SeqCst);
    assert!(
        matches!(f.client.observe(INSTANCE).await,Err(e) if e.code==CloudErrorCode::CredentialIdentityMismatch)
    );
    assert_eq!(f.count("DescribeInstances"), 2);
    let denied = Fixture::new(16).await?;
    let failure = denied.client.observe(INSTANCE).await.expect_err("denied");
    let message = format!("{failure} {failure:?}");
    for marker in [AK, SECRET, TOKEN, OIDC] {
        assert!(!message.contains(marker));
    }
    Ok(())
}
#[tokio::test]
async fn token_file_permissions_fail_closed_before_network() -> anyhow::Result<()> {
    let f = Fixture::new(0).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(f._token.path(), std::fs::Permissions::from_mode(0o644))?;
        assert!(
            matches!(f.client.observe(INSTANCE).await,Err(e) if e.code==CloudErrorCode::CredentialUnavailable)
        );
        assert_eq!(f.count("AssumeRoleWithOIDC"), 0);
    }
    Ok(())
}

#[tokio::test]
async fn opaque_request_ids_are_preserved_and_stale_preflight_never_dispatches()
-> anyhow::Result<()> {
    let f = Fixture::new(18).await?;
    let observation = f.client.observe(INSTANCE).await?;
    assert_eq!(
        observation.evidence().provider_request_id(),
        Some("opaque-request/eu-2026:abc")
    );
    let credentials = f.client.credentials().await?;
    let result = f
        .client
        .send(
            "StopInstance",
            ECS_VERSION,
            &f.client.inner.ecs,
            &BTreeMap::new(),
            Some(&credentials),
            Some(Utc::now() - ChronoDuration::seconds(1)),
        )
        .await;
    assert!(
        matches!(result,Err(e) if e.code==CloudErrorCode::ObservationStale&&e.evidence.is_none())
    );
    assert_eq!(f.count("StopInstance"), 0);
    assert!(!valid_request_id("line\r\ninjection"));
    Ok(())
}

fn disk_binding() -> CloudDiskBinding {
    CloudDiskBinding {
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        disk_id: "d-testworkspace001".into(),
        zone_id: "cn-hangzhou-i".into(),
        deployment: "production-a".into(),
        namespace: "sandbox-tenant-fixture".into(),
        pvc_name: "ws-public-test".into(),
        pv_name: "pvc-public-test".into(),
        kms_key_id: "public-test-key".into(),
        size_gib: 40,
    }
}

#[tokio::test]
async fn instance_token_pagination_does_not_treat_total_count_as_authoritative()
-> anyhow::Result<()> {
    let f = Fixture::new(20).await?;
    let observation = f.client.observe(INSTANCE).await?;
    assert_eq!(observation.instance_id(), INSTANCE);
    assert_eq!(observation.state(), CloudInstanceState::Running);
    assert_eq!(f.count("DescribeInstances"), 1);
    Ok(())
}
fn disk_response() -> Value {
    json!({"RequestId": PROVIDER_REQUEST,"NextToken":"","TotalCount":0,"Disks":{"Disk":[{
        "DiskId":"d-testworkspace001","RegionId":"cn-hangzhou","ZoneId":"cn-hangzhou-i",
        "Type":"data","Category":"cloud_essd","Portable":true,"Encrypted":true,
        "KMSKeyId":"public-test-key","Size":40,"DiskChargeType":"PostPaid",
        "DeleteWithInstance":false,"DeleteAutoSnapshot":false,"MultiAttach":"Disabled",
        "Status":"Available","InstanceId":"","MountInstanceNum":0,
        "Attachments":{"Attachment":[]},"MountInstances":{"MountInstance":[]},
        "Tags":{"Tag":[
            {"TagKey":"Deployment","TagValue":"production-a"},
            {"TagKey":"kubernetes.io/created-for/pvc/namespace","TagValue":"sandbox-tenant-fixture"},
            {"TagKey":"kubernetes.io/created-for/pvc/name","TagValue":"ws-public-test"},
            {"TagKey":"kubernetes.io/created-for/pv/name","TagValue":"pvc-public-test"}
        ]}
    }]}})
}
fn set_disk(f: &Fixture, response: Value) {
    *f.state.disk_response.lock().expect("test lock") = Some(response);
}

#[tokio::test]
async fn disk_identity_is_bound_and_attachment_empty_is_only_an_observation() -> anyhow::Result<()>
{
    let f = Fixture::new(0).await?;
    set_disk(&f, disk_response());
    let CloudDiskLookup::Present(disk) = f.client.observe_disk(&disk_binding()).await? else {
        anyhow::bail!("expected disk");
    };
    assert_eq!(disk.state(), CloudDiskState::Available);
    assert_eq!(
        disk.attachment_state(),
        CloudDiskAttachmentState::ExplicitlyEmpty
    );
    assert!(disk.attached_instance_ids().is_empty());
    assert!(!disk.delete_auto_snapshot());
    assert_eq!(disk.binding().pv_name, "pvc-public-test");
    assert_eq!(disk.evidence().action(), "DescribeDisks");
    assert_eq!(
        disk.evidence().provider_request_id(),
        Some(PROVIDER_REQUEST)
    );
    let value = serde_json::to_value(&disk)?;
    assert!(value.get("fenced").is_none());
    assert!(value.get("deleted").is_none());
    assert_eq!(f.count("DescribeDisks"), 1);
    assert_eq!(f.count("StopInstance"), 0);
    assert!(
        f.client
            .validate_binding(ACCOUNT, "cn-hangzhou", INSTANCE, "10.0.1.4".parse()?)
    );
    assert!(
        !f.client
            .validate_binding(ACCOUNT, "cn-hangzhou", INSTANCE, "10.0.1.5".parse()?)
    );
    let node = f.client.observe(INSTANCE).await?;
    assert_eq!(node.account_id(), ACCOUNT);
    assert_eq!(node.region(), "cn-hangzhou");
    Ok(())
}

#[tokio::test]
async fn disk_missing_attachment_fields_never_become_explicit_empty() -> anyhow::Result<()> {
    let f = Fixture::new(0).await?;
    for field in [
        "InstanceId",
        "MountInstanceNum",
        "Attachments",
        "MountInstances",
    ] {
        for remove in [true, false] {
            let mut response = disk_response();
            let disk = response["Disks"]["Disk"][0]
                .as_object_mut()
                .expect("fixture object");
            if remove {
                disk.remove(field);
            } else {
                disk.insert(field.into(), Value::Null);
            }
            set_disk(&f, response);
            let CloudDiskLookup::Present(disk) = f.client.observe_disk(&disk_binding()).await?
            else {
                anyhow::bail!("expected disk");
            };
            assert_eq!(
                disk.attachment_state(),
                CloudDiskAttachmentState::Incomplete,
                "{field}"
            );
        }
    }
    for field in ["Attachments", "MountInstances"] {
        let mut response = disk_response();
        response["Disks"]["Disk"][0][field] = json!({});
        set_disk(&f, response);
        let CloudDiskLookup::Present(disk) = f.client.observe_disk(&disk_binding()).await? else {
            anyhow::bail!("expected disk");
        };
        assert_eq!(
            disk.attachment_state(),
            CloudDiskAttachmentState::Incomplete
        );
    }
    Ok(())
}

#[tokio::test]
async fn disk_each_attachment_representation_blocks_empty_even_with_available_status()
-> anyhow::Result<()> {
    let f = Fixture::new(0).await?;
    for (field, value) in [
        ("InstanceId", json!(INSTANCE)),
        ("MountInstanceNum", json!(1)),
        (
            "Attachments",
            json!({"Attachment":[{"InstanceId":INSTANCE}]}),
        ),
        (
            "MountInstances",
            json!({"MountInstance":[{"InstanceId":INSTANCE}]}),
        ),
    ] {
        let mut response = disk_response();
        response["Disks"]["Disk"][0][field] = value;
        set_disk(&f, response);
        let CloudDiskLookup::Present(disk) = f.client.observe_disk(&disk_binding()).await? else {
            anyhow::bail!("expected disk");
        };
        assert_eq!(disk.attachment_state(), CloudDiskAttachmentState::Present);
        assert_eq!(disk.state(), CloudDiskState::Available);
    }
    Ok(())
}

#[tokio::test]
async fn disk_wrong_owner_tags_storage_class_or_identity_are_rejected() -> anyhow::Result<()> {
    let f = Fixture::new(0).await?;
    for (field, value) in [
        ("DiskId", json!("d-other")),
        ("RegionId", json!("cn-shanghai")),
        ("ZoneId", json!("cn-hangzhou-j")),
        ("Type", json!("system")),
        ("Category", json!("cloud_regional_disk_auto")),
        ("Portable", json!(false)),
        ("Encrypted", json!(false)),
        ("KMSKeyId", json!("wrong-key")),
        ("Size", json!(41)),
        ("DiskChargeType", json!("PrePaid")),
        ("DeleteWithInstance", json!(true)),
        ("MultiAttach", json!("Enabled")),
    ] {
        let mut response = disk_response();
        response["Disks"]["Disk"][0][field] = value;
        set_disk(&f, response);
        assert!(
            matches!(f.client.observe_disk(&disk_binding()).await,
            Err(e) if e.code == CloudErrorCode::IdentityMismatch),
            "{field}"
        );
    }
    for tag in 0..4 {
        let mut response = disk_response();
        response["Disks"]["Disk"][0]["Tags"]["Tag"][tag]["TagValue"] = json!("other");
        set_disk(&f, response);
        assert!(matches!(f.client.observe_disk(&disk_binding()).await,
            Err(e) if e.code == CloudErrorCode::IdentityMismatch));
    }
    let mut response = disk_response();
    let tags = response["Disks"]["Disk"][0]["Tags"]["Tag"]
        .as_array_mut()
        .expect("tags");
    tags.push(tags[0].clone());
    set_disk(&f, response);
    assert!(matches!(f.client.observe_disk(&disk_binding()).await,
        Err(e) if e.code == CloudErrorCode::IdentityMismatch));
    assert_eq!(f.count("StopInstance"), 0);
    Ok(())
}

#[tokio::test]
async fn disk_absence_requires_complete_exact_query_and_malformed_is_not_absence()
-> anyhow::Result<()> {
    let f = Fixture::new(0).await?;
    let absent =
        json!({"RequestId":PROVIDER_REQUEST,"TotalCount":99,"NextToken":"","Disks":{"Disk":[]}});
    set_disk(&f, absent.clone());
    let CloudDiskLookup::Absent(observation) = f.client.observe_disk(&disk_binding()).await? else {
        anyhow::bail!("expected absence observation");
    };
    assert_eq!(observation.binding().disk_id, "d-testworkspace001");
    assert_eq!(observation.evidence().action(), "DescribeDisks");
    let mut paginated = absent;
    paginated["NextToken"] = json!("another-page");
    let mut duplicated = disk_response();
    let disks = duplicated["Disks"]["Disk"].as_array_mut().expect("disks");
    disks.push(disks[0].clone());
    for response in [
        paginated,
        duplicated,
        json!({"RequestId":PROVIDER_REQUEST}),
        json!({"RequestId":PROVIDER_REQUEST,"Disks":{}}),
        json!({"RequestId":PROVIDER_REQUEST,"Disks":{"Disk":null}}),
    ] {
        set_disk(&f, response);
        assert!(f.client.observe_disk(&disk_binding()).await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn disk_invalid_binding_is_rejected_before_credentials_or_network() -> anyhow::Result<()> {
    let f = Fixture::new(0).await?;
    for field in 0..7 {
        let mut b = disk_binding();
        match field {
            0 => b.account_id = "0000000000000000".into(),
            1 => b.region = "cn-shanghai".into(),
            2 => b.disk_id = "d-x\",\"d-another".into(),
            3 => b.deployment = "another-deployment".into(),
            4 => b.namespace = "../other".into(),
            5 => b.kms_key_id = "".into(),
            _ => b.size_gib = 0,
        }
        assert!(matches!(f.client.observe_disk(&b).await,
            Err(e) if e.code == CloudErrorCode::Configuration));
    }
    assert_eq!(f.count("AssumeRoleWithOIDC"), 0);
    assert_eq!(f.count("DescribeDisks"), 0);
    Ok(())
}
