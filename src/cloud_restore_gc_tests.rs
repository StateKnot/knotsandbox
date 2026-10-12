#![allow(clippy::expect_used)]
use super::*;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response},
    routing::any,
};
use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicU8, Ordering},
};
const ACCOUNT: &str = "1234567890123456";
const ROLE_ID: &str = "1234567890123458";
const AK: &str = "STS.public-restore-gc-test";
const SECRET: &str = "PUBLIC_RESTORE_GC_SECRET_MARKER";
const TOKEN: &str = "PUBLIC_RESTORE_GC_TOKEN_MARKER";
const SUBJECT: &str = "system:serviceaccount:sandbox-system:sandbox-restore-gc";
#[derive(Clone)]
struct StateData {
    snapshot: Arc<StdMutex<Value>>,
    raw: Arc<StdMutex<Value>>,
    target: Arc<StdMutex<Value>>,
    actions: Arc<StdMutex<Vec<String>>>,
    session: Arc<StdMutex<String>>,
    mode: Arc<AtomicU8>,
    scope: RestoreGcCloudScope,
}
pub(crate) struct Fixture {
    pub(crate) client: AlibabaCloudRestoreGc,
    pub(crate) binding: RestoreSnapshotBinding,
    state: StateData,
    task: tokio::task::JoinHandle<()>,
    _token: tempfile::NamedTempFile,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let scope = RestoreGcCloudScope {
            restore_id: Uuid::new_v4(),
            raw_disk_id: "d-restoreRaw01".into(),
            snapshot_id: "s-restoreTemporary01".into(),
            target_disk_id: "d-restoreTarget01".into(),
        };
        let raw = CloudDiskBinding {
            account_id: ACCOUNT.into(),
            region: "cn-hangzhou".into(),
            disk_id: scope.raw_disk_id.clone(),
            zone_id: "cn-hangzhou-h".into(),
            deployment: "production-a".into(),
            namespace: "sandbox-system".into(),
            pvc_name: "raw-fixture".into(),
            pv_name: "raw-pv".into(),
            kms_key_id: "kms-restore001".into(),
            size_gib: 20,
        };
        let target = CloudDiskBinding {
            disk_id: scope.target_disk_id.clone(),
            namespace: "restore-target".into(),
            pvc_name: "ws-target".into(),
            pv_name: "pv-target".into(),
            ..raw.clone()
        };
        Self::with_bindings(scope, &raw, &target).await
    }
    pub(crate) async fn with_bindings(
        scope: RestoreGcCloudScope,
        raw: &CloudDiskBinding,
        target: &CloudDiskBinding,
    ) -> anyhow::Result<Self> {
        let token = tempfile::NamedTempFile::new()?;
        std::fs::write(token.path(), "PUBLIC_RESTORE_GC_OIDC_MARKER")?;
        let state = StateData {
            snapshot: Arc::new(StdMutex::new(
                json!({"RequestId":"gc-snapshot-query","TotalCount":0,"NextToken":"","Snapshots":{"Snapshot":[{"SnapshotId":scope.snapshot_id,"SourceDiskId":scope.raw_disk_id,"RegionId":"cn-hangzhou","KMSKeyId":"kms-restore001","SourceDiskType":"data","SourceDiskSize":"20","Status":"accomplished","SnapshotType":"user","Encrypted":true,"Usage":"disk","SnapshotSN":"64472-116742336-61976001","CreationTime":"2026-01-01T00:00:00Z"}]}}),
            )),
            raw: Arc::new(StdMutex::new(disk(raw, "gc-raw-serial01", None))),
            target: Arc::new(StdMutex::new(
                json!({"RequestId":"gc-target-query","NextToken":"","Disks":{"Disk":[{"DiskId":scope.target_disk_id,"RegionId":"cn-hangzhou","ZoneId":"cn-hangzhou-h","SerialNumber":"gc-target-serial01","CreationTime":"2026-01-01T00:00:00Z","SourceSnapshotId":scope.snapshot_id,"Type":"data","Category":"cloud_essd","Portable":true,"Encrypted":true,"KMSKeyId":"kms-restore001","Size":20,"DiskChargeType":"PostPaid","DeleteWithInstance":false,"DeleteAutoSnapshot":false,"MultiAttach":"Disabled","Status":"Available","Tags":{"Tag":[{"TagKey":"Deployment","TagValue":"production-a"},{"TagKey":"kubernetes.io/created-for/pvc/namespace","TagValue":"restore-target"},{"TagKey":"kubernetes.io/created-for/pvc/name","TagValue":"ws-target"},{"TagKey":"kubernetes.io/created-for/pv/name","TagValue":"pv-target"}]}}]}}),
            )),
            actions: Arc::new(StdMutex::new(vec![])),
            session: Arc::new(StdMutex::new(String::new())),
            mode: Arc::new(AtomicU8::new(0)),
            scope: scope.clone(),
        };
        {
            let mut snapshot = state.snapshot.lock().expect("snapshot");
            snapshot["Snapshots"]["Snapshot"][0]["KMSKeyId"] = json!(raw.kms_key_id);
            snapshot["Snapshots"]["Snapshot"][0]["SourceDiskSize"] =
                json!(raw.size_gib.to_string());
        }
        *state.target.lock().expect("target") =
            disk(target, "gc-target-serial01", Some(&scope.snapshot_id));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let app = Router::new().fallback(any(mock)).with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let config = RestoreGcCloudConfig {
            account_id: ACCOUNT.into(),
            region: "cn-hangzhou".into(),
            role_arn: format!("acs:ram::{ACCOUNT}:role/production-a-restore-gc"),
            role_id: ROLE_ID.into(),
            oidc_provider_arn: format!("acs:ram::{ACCOUNT}:oidc-provider/sandbox"),
            oidc_issuer: "https://workload.example.test".into(),
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: SUBJECT.into(),
            oidc_token_file: token.path().to_path_buf(),
            deployment: "production-a".into(),
            requests_per_second: 20,
            max_in_flight: 4,
        };
        let client =
            AlibabaCloudRestoreGc::build(config, scope.clone(), endpoint.clone(), endpoint, false)?;
        let binding = RestoreSnapshotBinding {
            scope,
            account_id: ACCOUNT.into(),
            region: "cn-hangzhou".into(),
            kms_key_id: raw.kms_key_id.clone(),
            size_gib: raw.size_gib,
        };
        Ok(Self {
            client,
            binding,
            state,
            task,
            _token: token,
        })
    }
    pub(crate) fn count(&self, a: &str) -> usize {
        self.state
            .actions
            .lock()
            .expect("actions")
            .iter()
            .filter(|v| v.as_str() == a)
            .count()
    }
    pub(crate) async fn identity(&self) -> anyhow::Result<RestoreSnapshotIdentity> {
        match self.client.observe_snapshot(&self.binding).await? {
            RestoreSnapshotLookup::Present(v) => Ok(v.identity().clone()),
            RestoreSnapshotLookup::Absent(_) => anyhow::bail!("expected present"),
        }
    }
    pub(crate) fn raw_absent(&self) {
        *self.state.raw.lock().expect("raw") =
            json!({"RequestId":"gc-raw-absent","NextToken":"","Disks":{"Disk":[]}});
    }
    pub(crate) fn snapshot_absent(&self) {
        *self.state.snapshot.lock().expect("snapshot") =
            json!({"RequestId":"gc-snapshot-absent","NextToken":"","Snapshots":{"Snapshot":[]}});
    }
    async fn target(&self) -> anyhow::Result<CloudDiskIdentity> {
        let b = CloudDiskBinding {
            account_id: ACCOUNT.into(),
            region: "cn-hangzhou".into(),
            disk_id: self.binding.scope.target_disk_id.clone(),
            zone_id: "cn-hangzhou-h".into(),
            deployment: "production-a".into(),
            namespace: "restore-target".into(),
            pvc_name: "ws-target".into(),
            pv_name: "pv-target".into(),
            kms_key_id: "kms-restore001".into(),
            size_gib: 20,
        };
        match self.client.observe_target_disk(&b).await? {
            CloudDiskLookup::Present(v) => Ok(v.identity()?),
            CloudDiskLookup::Absent(_) => anyhow::bail!("target present required"),
        }
    }
}
fn disk(b: &CloudDiskBinding, serial: &str, snapshot: Option<&str>) -> Value {
    json!({"RequestId":"gc-disk-query","NextToken":"","Disks":{"Disk":[{"DiskId":b.disk_id,"RegionId":b.region,"ZoneId":b.zone_id,"SerialNumber":serial,"CreationTime":"2026-01-01T00:00:00Z","SourceSnapshotId":snapshot,"Type":"data","Category":"cloud_essd","Portable":true,"Encrypted":true,"KMSKeyId":b.kms_key_id,"Size":b.size_gib,"DiskChargeType":"PostPaid","DeleteWithInstance":false,"DeleteAutoSnapshot":false,"MultiAttach":"Disabled","Status":"Available","Tags":{"Tag":[{"TagKey":"Deployment","TagValue":b.deployment},{"TagKey":"kubernetes.io/created-for/pvc/namespace","TagValue":b.namespace},{"TagKey":"kubernetes.io/created-for/pvc/name","TagValue":b.pvc_name},{"TagKey":"kubernetes.io/created-for/pv/name","TagValue":b.pv_name}]}}]}})
}
async fn mock(State(s): State<StateData>, request: Request<Body>) -> Response<Body> {
    let q: BTreeMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let action = request.headers()["x-acs-action"]
        .to_str()
        .expect("action")
        .to_owned();
    s.actions.lock().expect("actions").push(action.clone());
    if action != "AssumeRoleWithOIDC" {
        assert_eq!(request.headers()["x-acs-security-token"], TOKEN);
        let h = request
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str() == "host" || k.as_str().starts_with("x-acs-"))
            .map(|(k, v)| (k.to_string(), v.to_str().expect("header").to_owned()))
            .collect();
        let (signed, digest) =
            signature(&h, request.uri().query().unwrap_or(""), SECRET).expect("signature");
        assert_eq!(
            request.headers()["authorization"],
            format!("ACS3-HMAC-SHA256 Credential={AK},SignedHeaders={signed},Signature={digest}")
        );
    }
    let (status, value) = match action.as_str() {
        "AssumeRoleWithOIDC" => {
            assert_eq!(q["OIDCToken"], "PUBLIC_RESTORE_GC_OIDC_MARKER");
            assert_eq!(q["DurationSeconds"], "900");
            assert_eq!(
                q["RoleArn"],
                format!("acs:ram::{ACCOUNT}:role/production-a-restore-gc")
            );
            let policy: Value = serde_json::from_str(&q["Policy"]).expect("session policy");
            let statements = policy["Statement"].as_array().expect("statements");
            assert_eq!(statements.len(), 4);
            assert_eq!(
                statements[0]["Action"],
                json!(["ecs:DescribeSnapshots", "ecs:DeleteSnapshot"])
            );
            assert_eq!(
                statements[0]["Resource"],
                json!([format!(
                    "acs:ecs:cn-hangzhou:{ACCOUNT}:snapshot/{}",
                    s.scope.snapshot_id
                )])
            );
            assert_eq!(
                statements[1]["Resource"],
                json!([format!(
                    "acs:ecs:cn-hangzhou:{ACCOUNT}:disk/{}",
                    s.scope.raw_disk_id
                )])
            );
            assert_eq!(statements[2]["Action"], json!(["ecs:DescribeDisks"]));
            assert_eq!(
                statements[2]["Resource"],
                json!([format!(
                    "acs:ecs:cn-hangzhou:{ACCOUNT}:disk/{}",
                    s.scope.target_disk_id
                )])
            );
            assert_eq!(statements[3]["Action"], json!(["sts:GetCallerIdentity"]));
            let session = q["RoleSessionName"].clone();
            *s.session.lock().expect("session") = session.clone();
            (
                200,
                json!({"RequestId":"gc-sts","AssumedRoleUser":{"Arn":format!("acs:ram::{ACCOUNT}:role/production-a-restore-gc/{session}")},"OIDCTokenInfo":{"Issuer":"https://workload.example.test","Subject":SUBJECT,"ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success","ExpirationTime":Utc::now()+ChronoDuration::seconds(600),"IssuanceTime":Utc::now()-ChronoDuration::seconds(10)},"Credentials":{"AccessKeyId":AK,"AccessKeySecret":SECRET,"SecurityToken":TOKEN,"Expiration":Utc::now()+ChronoDuration::seconds(900)}}),
            )
        }
        "GetCallerIdentity" => (
            200,
            json!({"RequestId":"gc-identity","AccountId":ACCOUNT,"IdentityType":"AssumedRoleUser","Arn":format!("acs:ram::{ACCOUNT}:role/production-a-restore-gc/{}",s.session.lock().expect("session")),"RoleId":ROLE_ID}),
        ),
        "DescribeSnapshots" => {
            assert_eq!(
                q,
                BTreeMap::from([
                    ("RegionId".into(), "cn-hangzhou".into()),
                    (
                        "SnapshotIds".into(),
                        json!([s.scope.snapshot_id]).to_string()
                    ),
                    ("MaxResults".into(), "10".into())
                ])
            );
            (200, s.snapshot.lock().expect("snapshot").clone())
        }
        "DescribeDisks" => {
            let disk_ids: Vec<String> =
                serde_json::from_str(&q["DiskIds"]).expect("exact disk IDs");
            let raw = disk_ids
                .first()
                .is_some_and(|id| id == &s.scope.raw_disk_id);
            assert_eq!(
                q,
                BTreeMap::from([
                    ("RegionId".into(), "cn-hangzhou".into()),
                    (
                        "DiskIds".into(),
                        json!([if raw {
                            &s.scope.raw_disk_id
                        } else {
                            &s.scope.target_disk_id
                        }])
                        .to_string()
                    ),
                    ("MaxResults".into(), "10".into())
                ])
            );
            (
                200,
                if raw {
                    s.raw.lock().expect("raw").clone()
                } else {
                    s.target.lock().expect("target").clone()
                },
            )
        }
        "DeleteDisk" => {
            assert_eq!(
                q,
                BTreeMap::from([("DiskId".into(), s.scope.raw_disk_id.clone())])
            );
            (200, json!({"RequestId":"gc-raw-delete-accepted"}))
        }
        "DeleteSnapshot" => {
            assert_eq!(q.len(), 3);
            assert_eq!(q["SnapshotId"], s.scope.snapshot_id);
            assert_eq!(q["RegionId"], "cn-hangzhou");
            assert!(matches!(q["Force"].as_str(), "true" | "false"));
            if s.mode.load(Ordering::SeqCst) == 1 {
                (
                    503,
                    json!({"RequestId":"gc-unknown","Code":"InternalError","Message":SECRET}),
                )
            } else {
                (200, json!({"RequestId":"gc-submitted"}))
            }
        }
        _ => panic!("unexpected privileged action {action}"),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .expect("response")
}
#[tokio::test]
async fn used_snapshot_defaults_to_denial_and_reviewed_force_is_single_write_not_absence()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    let target = f.target().await?;
    assert!(
        f.client
            .delete_snapshot(&identity, Uuid::new_v4(), false, None)
            .await
            .is_err()
    );
    assert_eq!(f.count("DeleteSnapshot"), 0);
    assert!(matches!(
        f.client
            .delete_snapshot(&identity, Uuid::new_v4(), true, Some(&target))
            .await?,
        RestoreSnapshotDeleteOutcome::Accepted(_)
    ));
    assert_eq!(f.count("DeleteSnapshot"), 1);
    assert!(
        matches!(
            f.client.observe_snapshot(&f.binding).await?,
            RestoreSnapshotLookup::Present(_)
        ),
        "acknowledgement is not absence"
    );
    *f.state.snapshot.lock().expect("snapshot") =
        json!({"RequestId":"gc-absent","TotalCount":99,"NextToken":"","Snapshots":{"Snapshot":[]}});
    assert!(matches!(
        f.client.observe_snapshot(&f.binding).await?,
        RestoreSnapshotLookup::Absent(_)
    ));
    assert_eq!(f.count("DeleteSnapshot"), 1);
    Ok(())
}
#[tokio::test]
async fn changed_serial_source_size_usage_and_incomplete_pages_never_delete() -> anyhow::Result<()>
{
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    let target = f.target().await?;
    let original = f.state.snapshot.lock().expect("snapshot").clone();
    for (path, value) in [
        ("/Snapshots/Snapshot/0/SnapshotSN", json!("changed-serial")),
        (
            "/Snapshots/Snapshot/0/SourceDiskId",
            json!("d-sourceBackup01"),
        ),
        ("/Snapshots/Snapshot/0/SourceDiskSize", json!("21")),
        ("/Snapshots/Snapshot/0/Usage", json!("image_disk")),
        ("/NextToken", json!("more")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).expect("field") = value;
        *f.state.snapshot.lock().expect("snapshot") = changed;
        assert!(
            f.client
                .delete_snapshot(&identity, Uuid::new_v4(), true, Some(&target))
                .await
                .is_err()
        );
        assert_eq!(f.count("DeleteSnapshot"), 0);
    }
    Ok(())
}
#[tokio::test]
async fn dispatched_unknown_has_no_hidden_retry_and_requires_fresh_query() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    let target = f.target().await?;
    f.state.mode.store(1, Ordering::SeqCst);
    let result = f
        .client
        .delete_snapshot(&identity, Uuid::new_v4(), true, Some(&target))
        .await?;
    assert!(matches!(
        result,
        RestoreSnapshotDeleteOutcome::OutcomeUnknown(_)
    ));
    assert_eq!(f.count("DeleteSnapshot"), 1);
    let output = serde_json::to_string(&result)?;
    for marker in [SECRET, TOKEN, "PUBLIC_RESTORE_GC_OIDC_MARKER"] {
        assert!(!output.contains(marker));
    }
    assert!(matches!(
        f.client.observe_snapshot(&f.binding).await?,
        RestoreSnapshotLookup::Present(_)
    ));
    assert_eq!(f.count("DeleteSnapshot"), 1);
    Ok(())
}

#[tokio::test]
async fn force_requires_fresh_fixed_target_and_exact_derived_snapshot_lineage() -> anyhow::Result<()>
{
    let f = Fixture::new().await?;
    let identity = f.identity().await?;
    let target = f.target().await?;
    assert!(
        f.client
            .delete_snapshot(&identity, Uuid::new_v4(), true, None)
            .await
            .is_err()
    );
    let original = f.state.target.lock().expect("target").clone();
    for (path, value) in [
        ("/Disks/Disk/0/SourceSnapshotId", json!("s-sourceBackup01")),
        ("/Disks/Disk/0/SerialNumber", json!("replacement-serial")),
        ("/Disks/Disk/0/DiskId", json!("d-replacement01")),
        ("/NextToken", json!("incomplete")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).expect("field") = value;
        *f.state.target.lock().expect("target") = changed;
        assert!(
            f.client
                .delete_snapshot(&identity, Uuid::new_v4(), true, Some(&target))
                .await
                .is_err()
        );
        assert_eq!(f.count("DeleteSnapshot"), 0);
    }
    f.snapshot_absent();
    assert!(matches!(
        f.client
            .delete_snapshot(&identity, Uuid::new_v4(), true, None)
            .await?,
        RestoreSnapshotDeleteOutcome::AlreadyAbsent(_)
    ));
    assert_eq!(f.count("DeleteSnapshot"), 0);
    Ok(())
}
