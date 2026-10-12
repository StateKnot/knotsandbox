//! Actual consumer candidate: normal Source14/current claim → production
//! collector → opaque observation. Kube/STS/ECS servers are explicit protocol
//! stand-ins; no CSI object creation, cloud IAM, writer or host permit is certified.
use super::*;
use crate::cloud_fencing::node_topology::verify_test_request;
use crate::{
    cloud_fencing::raw_disk::{AdmissionRawDiskProtocolClient, RawDiskCloudConfig},
    restore::{admission::RawBoundDiskScope, raw_bound_collector::BackupRawBoundCollector},
};
use sha2::{Digest, Sha256};
use std::io::Write;

#[path = "restore_raw_handoff_fault_tests.rs"]
mod handoff_faults;

#[path = "restore_raw_vendor_report_consumer_tests.rs"]
mod vendor_report_consumer;

const READ_SUBJECT: &str = "system:serviceaccount:sandbox-system:sandbox-backup-controller";
const READ_OIDC: &str = "PUBLIC_RAW_DISK_READONLY_OIDC";
const READ_ROLE: &str = "raw-disk-fixture";
const READ_ACCESS: &str = "STS.PUBLIC_RAW_DISK_ACCESS";
const READ_SECRET: &str = "PUBLIC_RAW_DISK_SECRET";
const READ_TOKEN: &str = "PUBLIC_RAW_DISK_SESSION_TOKEN";
#[derive(Clone)]
struct DiskWire {
    disk_id: String,
    region: String,
    zone: String,
    deployment: String,
    kms: String,
    size: u32,
    pvc_name: String,
    pv_name: String,
    creation: String,
}
impl DiskWire {
    fn from_scope(scope: &RawBoundDiskScope) -> Self {
        let f = scope.facts();
        Self {
            disk_id: "d-rawnewtarget".into(),
            region: f.region.clone(),
            zone: f.zone_id.clone(),
            deployment: f.deployment.clone(),
            kms: f.workspace_kms_key_id.clone(),
            size: f.size_gib,
            pvc_name: f.pvc_name.clone(),
            pv_name: f.pv_name.clone(),
            creation: Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true),
        }
    }
    fn disk(&self) -> Value {
        json!({"DiskId":self.disk_id,"RegionId":self.region,"ZoneId":self.zone,"Type":"data","Category":"cloud_essd",
            "PerformanceLevel":"PL1","Portable":true,"Encrypted":true,"KMSKeyId":self.kms,"Size":self.size,
            "DiskChargeType":"PostPaid","DeleteWithInstance":false,"MultiAttach":"Disabled","Status":"Available",
            "SerialNumber":"public-raw-serial","CreationTime":self.creation,
            "Tags":{"Tag":[{"TagKey":"Deployment","TagValue":self.deployment},
                {"TagKey":"kubernetes.io/created-for/pvc/namespace","TagValue":NAMESPACE},
                {"TagKey":"kubernetes.io/created-for/pvc/name","TagValue":self.pvc_name},
                {"TagKey":"kubernetes.io/created-for/pv/name","TagValue":self.pv_name}]}})
    }
}
#[derive(Default)]
struct CloudState {
    subject: String,
    issuer: String,
    provider: String,
    role: String,
    session: String,
    sessions: Vec<String>,
    actions: Vec<&'static str>,
    violations: Vec<&'static str>,
    response_hashes: Vec<String>,
    mode: u8,
    describes: usize,
}
#[derive(Clone)]
struct Routes {
    wire: DiskWire,
    shared: Arc<Mutex<CloudState>>,
}
async fn http(State(routes): State<Routes>, r: Request<Body>) -> Response<Body> {
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(r.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let q: BTreeMap<String, String> = pairs.iter().cloned().collect();
    let action = r
        .headers()
        .get("x-acs-action")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let Ok(mut s) = routes.shared.lock() else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let fixed = match action {
        "AssumeRoleWithOIDC" => "AssumeRoleWithOIDC",
        "GetCallerIdentity" => "GetCallerIdentity",
        "DescribeDisks" => "DescribeDisks",
        _ => "UNAPPROVED",
    };
    s.actions.push(fixed);
    if pairs.len() != q.len() || r.method() != Method::POST || r.uri().path() != "/" {
        s.violations.push("fixed route/query");
        return failure(StatusCode::BAD_REQUEST);
    }
    if action != "AssumeRoleWithOIDC"
        && (!verify_test_request(
            r.headers(),
            r.uri().query().unwrap_or_default(),
            READ_ACCESS,
            READ_SECRET,
        ) || r
            .headers()
            .get("x-acs-security-token")
            .and_then(|v| v.to_str().ok())
            != Some(READ_TOKEN))
    {
        s.violations.push("ACS3 signed request");
        return failure(StatusCode::FORBIDDEN);
    }
    let id = format!("public-raw-read-{}", s.actions.len());
    let value = match action {
        "AssumeRoleWithOIDC" => {
            let policy = json!({"Version":"1","Statement":[
                {"Effect":"Allow","Action":["ecs:DescribeDisks"],"Resource":[format!("acs:ecs:{}:{}:disk/{}",routes.wire.region,ACCOUNT,routes.wire.disk_id)]},
                {"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}]});
            let expected = BTreeMap::from([
                ("RoleArn".to_owned(), s.role.clone()),
                ("OIDCProviderArn".into(), s.provider.clone()),
                ("OIDCToken".into(), READ_OIDC.into()),
                ("DurationSeconds".into(), "900".into()),
                ("Action".into(), "AssumeRoleWithOIDC".into()),
                ("Version".into(), "2015-04-01".into()),
                ("Format".into(), "JSON".into()),
            ]);
            let session = q.get("RoleSessionName").cloned().unwrap_or_default();
            if q.len() != expected.len() + 2
                || expected.iter().any(|(k, v)| q.get(k) != Some(v))
                || q.get("Policy")
                    .and_then(|p| serde_json::from_str::<Value>(p).ok())
                    != Some(policy)
                || !session.starts_with("volume-")
                || s.sessions.contains(&session)
                || r.headers().contains_key("authorization")
                || r.headers()
                    .get("x-acs-version")
                    .and_then(|v| v.to_str().ok())
                    != Some("2015-04-01")
            {
                s.violations
                    .push("exact readonly OIDC/policy/common params");
                return failure(StatusCode::BAD_REQUEST);
            }
            s.session = session.clone();
            s.sessions.push(session.clone());
            json!({"RequestId":id,"AssumedRoleUser":{"Arn":format!("{}/{}",s.role,session)},
                "OIDCTokenInfo":{"Issuer":s.issuer,"Subject":s.subject,"ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success",
                    "ExpirationTime":Utc::now()+Days::seconds(600),"IssuanceTime":Utc::now()-Days::seconds(10)},
                "Credentials":{"AccessKeyId":READ_ACCESS,"AccessKeySecret":READ_SECRET,"SecurityToken":READ_TOKEN,"Expiration":Utc::now()+Days::seconds(900)}})
        }
        "GetCallerIdentity" => {
            if !q.is_empty()
                || r.headers()
                    .get("x-acs-version")
                    .and_then(|v| v.to_str().ok())
                    != Some("2015-04-01")
            {
                s.violations.push("exact GetCallerIdentity");
                return failure(StatusCode::BAD_REQUEST);
            }
            json!({"RequestId":id,"IdentityType":"AssumedRoleUser","AccountId":ACCOUNT,"RoleId":ROLE_ID,"Arn":format!("{}/{}",s.role,s.session)})
        }
        "DescribeDisks" => {
            if q != BTreeMap::from([
                ("RegionId".into(), routes.wire.region.clone()),
                ("DiskIds".into(), format!("[\"{}\"]", routes.wire.disk_id)),
                ("MaxResults".into(), "10".into()),
            ]) || r
                .headers()
                .get("x-acs-version")
                .and_then(|v| v.to_str().ok())
                != Some("2014-05-26")
            {
                s.violations.push("exact unfiltered single-disk query");
                return failure(StatusCode::BAD_REQUEST);
            }
            s.describes += 1;
            let mut disk = routes.wire.disk();
            if s.mode == 1 && s.describes == 2 {
                disk["SerialNumber"] = json!("replaced-after-first-read");
            }
            let body = json!({"RequestId":id,"NextToken":"","Disks":{"Disk":[disk]}});
            s.response_hashes
                .push(hex::encode(Sha256::digest(body.to_string().as_bytes())));
            body
        }
        _ => {
            s.violations.push("unapproved action");
            return failure(StatusCode::METHOD_NOT_ALLOWED);
        }
    };
    answer(StatusCode::OK, value)
}
struct DiskCloud {
    shared: Arc<Mutex<CloudState>>,
    wire: DiskWire,
    server: Server,
    token: tempfile::NamedTempFile,
}
impl DiskCloud {
    async fn new(wire: DiskWire, issuer: &str, provider: &str) -> anyhow::Result<Self> {
        let mut token = tempfile::NamedTempFile::new()?;
        token.write_all(READ_OIDC.as_bytes())?;
        token.flush()?;
        let shared = Arc::new(Mutex::new(CloudState {
            subject: READ_SUBJECT.into(),
            issuer: issuer.into(),
            provider: provider.into(),
            role: format!("acs:ram::{ACCOUNT}:role/{READ_ROLE}"),
            ..Default::default()
        }));
        let server = Server::start(Router::new().fallback(any(http)).with_state(Routes {
            shared: shared.clone(),
            wire: wire.clone(),
        }))
        .await?;
        Ok(Self {
            shared,
            wire,
            server,
            token,
        })
    }
    fn config(&self) -> anyhow::Result<RawDiskCloudConfig> {
        let s = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("disk protocol state"))?;
        Ok(RawDiskCloudConfig {
            account_id: ACCOUNT.into(),
            region: self.wire.region.clone(),
            role_arn: s.role.clone(),
            role_id: ROLE_ID.into(),
            oidc_provider_arn: s.provider.clone(),
            oidc_issuer: s.issuer.clone(),
            oidc_subject: s.subject.clone(),
            oidc_token_file: self.token.path().into(),
            requests_per_second: 20,
            max_in_flight: 4,
        })
    }
    fn reset(&self, mode: u8) -> anyhow::Result<()> {
        let mut s = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("disk protocol state"))?;
        s.actions.clear();
        s.sessions.clear();
        s.response_hashes.clear();
        s.describes = 0;
        s.mode = mode;
        Ok(())
    }
    fn exact_actions(&self, rounds: usize) -> anyhow::Result<()> {
        let s = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("disk protocol state"))?;
        ensure!(
            s.violations.is_empty(),
            "no protocol negative may pass through fixture failure"
        );
        ensure!(
            s.actions
                == ["AssumeRoleWithOIDC", "GetCallerIdentity", "DescribeDisks"].repeat(rounds),
            "exact fresh signed action count"
        );
        ensure!(
            s.sessions.len() == rounds && s.response_hashes.len() == rounds,
            "every round exchanges STS and actually observes Describe response"
        );
        if rounds == 2 {
            ensure!(
                s.sessions[0] != s.sessions[1] && s.response_hashes[0] != s.response_hashes[1],
                "fresh session+RequestId evidence, immutable disk identity unchanged"
            );
        }
        Ok(())
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.server.finish().await?;
        ensure!(
            self.shared
                .lock()
                .map_err(|_| anyhow::anyhow!("disk protocol state"))?
                .violations
                .is_empty(),
            "signed disk protocol mismatch"
        );
        Ok(())
    }
}
fn raw_pv(scope: &RawBoundDiskScope, wire: &DiskWire, uid: Uuid) -> Value {
    let f = scope.facts();
    let c = scope.collection();
    let m = &c.storage.storage_contract.mapping;
    json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":f.pv_name,"uid":uid,"resourceVersion":"801",
        "creationTimestamp":wire.creation,"finalizers":["external-provisioner.volume.kubernetes.io/finalizer","kubernetes.io/pv-protection"],
        "annotations":{"pv.kubernetes.io/provisioned-by":DRIVER,"volume.kubernetes.io/provisioner-deletion-secret-name":"","volume.kubernetes.io/provisioner-deletion-secret-namespace":""}},
        "spec":{"capacity":{"storage":format!("{}Gi",f.size_gib)},"accessModes":["ReadWriteOnce"],"volumeMode":"Block","persistentVolumeReclaimPolicy":"Retain","storageClassName":m.raw.name,
            "claimRef":{"apiVersion":"v1","kind":"PersistentVolumeClaim","namespace":NAMESPACE,"name":f.pvc_name,"uid":f.pvc_uid,"resourceVersion":"800"},
            "csi":{"driver":DRIVER,"volumeHandle":wire.disk_id,"volumeAttributes":{
                "storage.kubernetes.io/csiProvisionerIdentity":"1791475000000-001-diskplugin.csi.alibabacloud.com","type":"cloud_essd","encrypted":"true","kmsKeyId":m.workspace_kms_key_id,"diskTags/Deployment":m.deployment,
                "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/region":m.region,
                "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/zone":wire.zone,
                "csi.alibabacloud.com/label-prefix/csi.alibabacloud.com/disktype":"cloud_essd.PL1",
                "csi.alibabacloud.com/annotation-prefix/csi.alibabacloud.com/volume-topology":"{\"nodeSelectorTerms\":[{\"matchExpressions\":[{\"key\":\"node.csi.alibabacloud.com/disktype.cloud_essd\",\"operator\":\"In\",\"values\":[\"available\"]}]}]}"}},
            "nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[{"key":m.topology.key,"operator":"In","values":[wire.zone]}]}]}}},
        "status":{"phase":"Bound","lastPhaseTransitionTime":wire.creation}})
}
fn bound_pvc(original: &Value, scope: &RawBoundDiskScope) -> Value {
    let mut v = original.clone();
    v["metadata"]["resourceVersion"] = json!("800");
    v["spec"]["volumeName"] = json!(scope.facts().pv_name);
    v["metadata"]["annotations"]["pv.kubernetes.io/bound-by-controller"] = json!("yes");
    v["metadata"]["annotations"]["pv.kubernetes.io/bind-completed"] = json!("yes");
    v["status"] = json!({"phase":"Bound","accessModes":["ReadWriteOnce"],"capacity":{"storage":format!("{}Gi",scope.facts().size_gib)}});
    v
}
fn replace(case: &SelectedCase<'_>, path: &str, value: Value) -> anyhow::Result<()> {
    case.w
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("disk workload objects"))?
        .insert(path.into(), value);
    Ok(())
}
fn reads(
    case: &SelectedCase<'_>,
    scope: &RawBoundDiskScope,
    pv_reads: usize,
    pvc_reads: usize,
) -> anyhow::Result<()> {
    ensure!(
        case.w.reads(case.pvc_path)? == pvc_reads
            && case.w.reads(&format!(
                "/api/v1/persistentvolumes/{}",
                scope.facts().pv_name
            ))? == pv_reads
            && case
                .w
                .reads(&format!("/api/v1/nodes/{}", scope.facts().node.node_name))?
                == pv_reads
            && case.w.reads(&format!(
                "/apis/storage.k8s.io/v1/csinodes/{}",
                scope.facts().node.node_name
            ))? == pv_reads,
        "exact locator+round rawGET counts"
    );
    Ok(())
}
async fn unchanged(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    absent_companion(case).await?;
    ensure!(
        facts(&case.source.f.base.f.owner, case.t, case.r).await? == *case.baseline,
        "all source/target/binding/hold/quota rows unchanged by opaque observation"
    );
    Ok(())
}
async fn handoff(
    observed: crate::restore::raw_bound_collector::BackupRawBoundTemplateAttempt,
    engine: &crate::engine::OperationEngine,
    claim: &crate::engine::Claim,
) -> anyhow::Result<()> {
    eprintln!("PRIVATE raw collector owned handoff phase entered");
    // Consume the ACTUAL owned collector result, preserving first, final,
    // original cloud scope, signed disk and PV; no proof factory is available.
    let observed = Box::pin(
        crate::restore::raw_bound_collector::handoff_tests::same_transaction(
            observed, engine, claim,
        ),
    )
    .await?;
    eprintln!("PRIVATE raw collector same-TX shape negative completed");
    let refusal = Box::pin(observed.refuse_unverified_publication(engine, claim))
        .await
        .err()
        .context("template-only owned normal caller never publishes")?;
    ensure!(
        refusal.status == StatusCode::FORBIDDEN
            && refusal.code == "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED"
            && refusal.detail == "Raw restore volume vendor certification unavailable",
        "actual owned handoff reaches the missing production vendor gate, not unrelated authority/dependency failure"
    );
    eprintln!("PRIVATE raw collector normal vendor refusal completed");
    crate::restore::raw_bound_collector::handoff_tests::no_open_transactions(engine).await?;
    eprintln!("PRIVATE raw collector transaction observer completed");
    Ok(())
}
type ExerciseSetup = (Box<BackupRawBoundCollector>, String);

// Test-only construction boundaries leave the large phase constructor stack
// before the original futures are polled. No caller or token is recreated.
#[inline(never)]
fn boxed_exercise_prefix<'a, 'fixture: 'a>(
    case: &'a SelectedCase<'fixture>,
    cloud: &'a DiskCloud,
    scope: &'a RawBoundDiskScope,
    pvc: &'a Value,
    pv: &'a Value,
) -> std::pin::Pin<Box<impl std::future::Future<Output = anyhow::Result<ExerciseSetup>> + 'a>> {
    Box::pin(exercise_prefix(case, cloud, scope, pvc, pv))
}
#[inline(never)]
fn boxed_exercise_suffix<'a, 'fixture: 'a>(
    case: &'a SelectedCase<'fixture>,
    cloud: &'a DiskCloud,
    scope: &'a RawBoundDiskScope,
    pv: &'a Value,
    collector: &'a BackupRawBoundCollector,
    pv_path: &'a str,
) -> std::pin::Pin<Box<impl std::future::Future<Output = anyhow::Result<()>> + 'a>> {
    Box::pin(exercise_suffix(case, cloud, scope, pv, collector, pv_path))
}
async fn exercise_prefix(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
    pvc: &Value,
    pv: &Value,
) -> anyhow::Result<ExerciseSetup> {
    eprintln!("PRIVATE raw collector exercise entered");
    let engine = &case.source.f.backup;
    let db = &engine.database;
    let collector = BackupRawBoundCollector::for_loopback_test(
        case.w.runtime.clone(),
        cloud.config()?,
        cloud.server.url.clone(),
    )
    .map_err(api_failure)?;
    case.configure(0, Fault::None)?;
    cloud.reset(0)?;
    replace(case, case.pvc_path, pvc.clone())?;
    let pv_path = format!("/api/v1/persistentvolumes/{}", scope.facts().pv_name);
    replace(case, &pv_path, pv.clone())?;
    ensure!(
        engine.heartbeat(case.claim).await.map_err(api_failure)?,
        "ordinary current claim heartbeat"
    );
    let observed = Box::pin(collector.observe_pending_restore(db, engine, case.claim, case.r))
        .await
        .map_err(api_failure)?;
    observed.current(engine, case.claim).map_err(api_failure)?;
    let p = observed.projection();
    ensure!(
        p.uid().to_string() == pv["metadata"]["uid"].as_str().context("actual PVUID")?
            && p.parent_uid() == scope.facts().pvc_uid
            && p.name() == scope.facts().pv_name
            && p.disk_id() == cloud.wire.disk_id
            && p.zone_id() == cloud.wire.zone
            && p.spec_sha256().len() == 64,
        "outer normal caller returns opaque full exact Bound template projection"
    );
    cloud.exact_actions(2)?;
    reads(case, scope, 2, 3)?;
    unchanged(case).await?;
    Box::pin(handoff(observed, engine, case.claim)).await?;
    cloud.exact_actions(2)?;
    reads(case, scope, 2, 3)?;
    unchanged(case).await?;
    Ok((Box::new(collector), pv_path))
}

async fn exercise_suffix(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
    pv: &Value,
    collector: &BackupRawBoundCollector,
    pv_path: &str,
) -> anyhow::Result<()> {
    let engine = &case.source.f.backup;
    let db = &engine.database;
    for uid in [
        scope.facts().pvc_uid,
        scope.facts().source_pvc_uid,
        scope.facts().source_pv_uid,
        scope.facts().clone_pvc_uid,
        scope.facts().clone_pv_uid,
    ] {
        case.configure(0, Fault::None)?;
        cloud.reset(0)?;
        let mut wrong = pv.clone();
        wrong["metadata"]["uid"] = json!(uid);
        replace(case, pv_path, wrong)?;
        ensure!(
            engine.heartbeat(case.claim).await.map_err(api_failure)?,
            "ordinary claim before UID counterexample"
        );
        let error = Box::pin(collector.observe_pending_restore(db, engine, case.claim, case.r))
            .await
            .err()
            .context("source/clone/parent PVUID denied")?;
        ensure!(
            error.status == StatusCode::FORBIDDEN && error.code == "RESTORE_RAW_COLLECTION_BLOCKED",
            "exact collection refusal, not a protocol/server error"
        );
        cloud.exact_actions(1)?;
        reads(case, scope, 1, 2)?;
        unchanged(case).await?;
    }
    for fault in [Fault::SecondNodeUid, Fault::SecondCsiUid] {
        case.configure(0, fault)?;
        cloud.reset(0)?;
        replace(case, pv_path, pv.clone())?;
        ensure!(
            engine.heartbeat(case.claim).await.map_err(api_failure)?,
            "current claim before second live node identity drift"
        );
        let error = Box::pin(collector.observe_pending_restore(db, engine, case.claim, case.r))
            .await
            .err()
            .context("actual second Node/CSI identity drift")?;
        ensure!(
            error.status == StatusCode::FORBIDDEN && error.code == "RESTORE_RAW_COLLECTION_BLOCKED",
            "live configured identity refusal before second cloud"
        );
        cloud.exact_actions(1)?;
        reads(case, scope, 2, 3)?;
        unchanged(case).await?;
    }
    case.configure(0, Fault::None)?;
    cloud.reset(1)?;
    replace(case, pv_path, pv.clone())?;
    ensure!(
        engine.heartbeat(case.claim).await.map_err(api_failure)?,
        "ordinary claim before fresh serial drift"
    );
    let error = Box::pin(collector.observe_pending_restore(db, engine, case.claim, case.r))
        .await
        .err()
        .context("second fresh signed serial differs")?;
    ensure!(
        error.status == StatusCode::FORBIDDEN && error.code == "RESTORE_RAW_COLLECTION_BLOCKED",
        "fresh disk immutable identity refusal"
    );
    cloud.exact_actions(2)?;
    reads(case, scope, 2, 3)?;
    unchanged(case).await?;
    // The sibling admission protocol shares neither backup type nor workload
    // subject. It receives its own actual admission first14 and original timer.
    case.configure(0, Fault::None)?;
    cloud.reset(0)?;
    replace(case, pv_path, pv.clone())?;
    {
        let mut s = cloud
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("independent admission subject"))?;
        s.subject = "system:serviceaccount:sandbox-system:sandbox-admission".into();
    }
    let a = RawBoundAttempt::start();
    let first = case
        .service
        .prepare_raw_bound_admission(&a, case.t, case.r, &scope.facts().node.node_name)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let sealed = first
        .admission_disk_scope(&a)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let config = cloud.config()?;
    let mut budget = AdmissionRawDiskProtocolClient::budget(&config)
        .map_err(|_| anyhow::anyhow!("admission readonly identity config"))?;
    budget
        .use_loopback_test_endpoint(cloud.server.url.clone())
        .map_err(|_| anyhow::anyhow!("literal test endpoint"))?;
    let one = AdmissionRawDiskProtocolClient::observe_scope(
        config.clone(),
        &sealed,
        &cloud.wire.disk_id,
        &budget,
    )
    .await
    .map_err(|_| anyhow::anyhow!("first admission signed disk transport"))?;
    let two = AdmissionRawDiskProtocolClient::observe_scope(
        config,
        &sealed,
        &cloud.wire.disk_id,
        &budget,
    )
    .await
    .map_err(|_| anyhow::anyhow!("second admission signed disk transport"))?;
    one.current()
        .map_err(|_| anyhow::anyhow!("first admission original deadline"))?;
    two.current()
        .map_err(|_| anyhow::anyhow!("second admission original deadline"))?;
    one.same_identity(&two)
        .map_err(|_| anyhow::anyhow!("admission fresh identity differs"))?;
    ensure!(
        two.disk_facts()
            .map_err(|_| anyhow::anyhow!("admission ordinary disk comparison"))?
            .disk_id
            == cloud.wire.disk_id,
        "no owner or backup proof cast"
    );
    case.service
        .recheck_raw_bound_admission(&first)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    cloud.exact_actions(2)?;
    unchanged(case).await?;
    Ok(())
}
async fn exercise(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    scope: &RawBoundDiskScope,
    pvc: &Value,
    pv: &Value,
) -> anyhow::Result<()> {
    let (collector, pv_path) = boxed_exercise_prefix(case, cloud, scope, pvc, pv).await?;
    Box::pin(handoff_faults::run(case, cloud, scope)).await?;
    Box::pin(vendor_report_consumer::run(case, cloud, scope)).await?;
    boxed_exercise_suffix(case, cloud, scope, pv, collector.as_ref(), &pv_path).await
}
pub(super) async fn run(case: &SelectedCase<'_>, node_hint: &str) -> anyhow::Result<()> {
    let original = case.w.get(case.pvc_path)?;
    ensure!(
        case.source
            .f
            .backup
            .heartbeat(case.claim)
            .await
            .map_err(api_failure)?,
        "normal current claim before collector setup"
    );
    let a = RawBoundAttempt::start();
    let first = case
        .source
        .f
        .backup
        .database
        .prepare_restore_bound_authority(&a, &case.source.f.backup, case.claim, case.r, node_hint)
        .await
        .map_err(api_failure)?;
    let scope = first
        .backup_disk_scope(&a, &case.source.f.backup, case.claim)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    ensure!(
        scope.collection().recorded.is_none(),
        "unpublished target, not a future identity seed"
    );
    let wire = DiskWire::from_scope(&scope);
    let pv = raw_pv(&scope, &wire, Uuid::new_v4());
    let pvc = bound_pvc(&original, &scope);
    let path = format!("/api/v1/persistentvolumes/{}", scope.facts().pv_name);
    let previous = case
        .w
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("objects"))?
        .get(&path)
        .cloned();
    let cloud = DiskCloud::new(
        wire,
        &scope.collection().cloud_settings.issuer,
        &scope.collection().cloud_settings.oidc_provider_arn,
    )
    .await?;
    // Each production call starts its own attempt and normal first/final SQL.
    // This setup scope supplies fixture shape only, never observation authority.
    let outcome = Box::pin(exercise(case, &cloud, &scope, &pvc, &pv)).await;
    let restore = (|| -> anyhow::Result<()> {
        let mut map = case
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("objects restoration"))?;
        map.insert(case.pvc_path.into(), original);
        match previous {
            Some(p) => {
                map.insert(path, p);
            }
            None => {
                map.remove(&path);
            }
        }
        Ok(())
    })();
    let closed = cloud.finish().await;
    if restore.is_err() {
        eprintln!("PRIVATE raw disk fixture object restoration failed; not certified restored");
    }
    if closed.is_err() {
        eprintln!("PRIVATE raw disk fixture server cleanup failed; not certified drained");
    }
    outcome?;
    restore?;
    closed?;
    unchanged(case).await?;
    eprintln!(
        "VERIFIED private normal Source14 collector outer caller + two real Bound GET rounds + twice fresh OIDC/STS/Identity/ACS3 DescribeDisks; five actual PVUID aliases and second serial drift refuse with exact request counts, independent admission readonly subject; owned final14 same-backend/XID prepublication/missing-three-row403 with acknowledged rollback and normal vendor-gate403; zero publication/host permit; protocol stand-ins, not CSI/IAM/vendor certification"
    );
    Ok(())
}

#[test]
fn address_only_protocol_seam_rejects_nonliteral_or_extended_endpoint_without_io()
-> anyhow::Result<()> {
    let config = RawDiskCloudConfig {
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        role_arn: format!("acs:ram::{ACCOUNT}:role/{READ_ROLE}"),
        role_id: ROLE_ID.into(),
        oidc_provider_arn: format!("acs:ram::{ACCOUNT}:oidc-provider/fixture"),
        oidc_issuer: "https://issuer.fixture.invalid".into(),
        oidc_subject: "system:serviceaccount:sandbox-system:sandbox-admission".into(),
        oidc_token_file: "/__not_read__/public-token".into(),
        requests_per_second: 1,
        max_in_flight: 1,
    };
    let mut budget = AdmissionRawDiskProtocolClient::budget(&config)
        .map_err(|_| anyhow::anyhow!("pure reviewed identity config"))?;
    for raw in [
        "http://localhost:1234/",
        "http://10.0.0.5:1234/",
        "https://127.0.0.1:1234/",
        "http://127.0.0.1/",
        "http://127.0.0.1:1234/unreviewed",
        "http://127.0.0.1:1234/?x=1",
        "http://user@127.0.0.1:1234/",
        "http://127.0.0.1:1234/#x",
    ] {
        ensure!(
            budget.use_loopback_test_endpoint(raw.parse()?).is_err(),
            "only literal bounded loopback root endpoint"
        );
    }
    budget
        .use_loopback_test_endpoint("http://127.0.0.1:1234/".parse()?)
        .map_err(|_| anyhow::anyhow!("literal endpoint"))?;
    Ok(())
}
#[path = "restore_raw_vendor_report_matched_tests.rs"]
mod report_matched;
