//! PRIVATE candidate: normal verified roles, real PG/mTLS and signed TCP cloud
//! stand-ins. No actual Ali CSI installation/cloud certification is asserted.
use crate::{
    backup_job::BackupJobRuntime,
    backup_ledger::pipeline_tests::vault::completed_source,
    cloud_fencing::node_topology::{
        AlibabaCloudNodeTopology, NodeTopologyCloudBinding, NodeTopologyCloudConfig,
        verify_test_request,
    },
    db::Database,
    node_enrollment::{CERTIFICATION_CHECKS, EnrollmentPlan, enroll_with_client_test},
    nodeguard::protocol::NodeBinding,
    restore::node_topology_owner::{
        NodeTopologyRequest, TopologyOwnerError, collect_node_topology, collect_with_client,
        record_node_topology,
    },
    runtime::KubernetesRuntime,
    termination_client::test_support::{FixtureGuard, credentials, node},
    test_support_db,
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, Request, Response, StatusCode},
    routing::any,
};
use chrono::{DateTime, Duration as Days, SecondsFormat, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;
use uuid::Uuid;

#[path = "restore_node_topology_publication_tests.rs"]
mod publication;

#[path = "restore_raw_scheduling_tests.rs"]
mod selected;

// Public fixture markers only. None are deployable credentials.
const ACCOUNT: &str = "1234567890123456";
const ROLE_ID: &str = "1234567890123457";
const ACCESS: &str = "STS.PUBLIC_TOPOLOGY_TEST_AK";
const SECRET: &str = "PUBLIC_TOPOLOGY_TEST_SECRET";
const TOKEN: &str = "PUBLIC_TOPOLOGY_TEST_STS_TOKEN";
const OIDC: &str = "PUBLIC_TOPOLOGY_TEST_OIDC_TOKEN";
const KEYS: [&str; 4] = [
    "alibabacloud.com/ecs-instance-id",
    "topology.diskplugin.csi.alibabacloud.com/zone",
    "topology.kubernetes.io/region",
    "topology.kubernetes.io/zone",
];

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}
fn answer(status: StatusCode, value: Value) -> Response<Body> {
    let mut response = Response::new(Body::from(value.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}
fn failure(code: StatusCode) -> Response<Body> {
    answer(
        code,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"FixtureFailure","code":code.as_u16()}),
    )
}

// Graceful owned servers are joined before a scenario returns. A server-side
// signature/route mismatch is retained separately, so an HTTP error cannot make
// a negative business assertion pass accidentally.
struct Server {
    url: url::Url,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Server {
    async fn start(router: Router) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            url,
            stop: Some(stop),
            task: Some(task),
        })
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .context(
                    "fixture server drain timed out; Drop will abort, not certify drain",
                )???;
        }
        self.task.take();
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Default)]
struct KubeState {
    node: Value,
    csi: Value,
    mode: u8,
    node_reads: usize,
    csi_reads: usize,
    violations: Vec<&'static str>,
}
type KubeShared = Arc<Mutex<KubeState>>;
async fn kube_http(State(shared): State<KubeShared>, request: Request<Body>) -> Response<Body> {
    let Ok(mut state) = shared.lock() else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if request.method() != Method::GET || request.uri().query().is_some() {
        state
            .violations
            .push("Kubernetes route must be an exact readonly GET");
        return failure(StatusCode::BAD_REQUEST);
    }
    let name = state.node["metadata"]["name"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let path = request.uri().path();
    let mode = state.mode;
    let mut body;
    if path == format!("/api/v1/nodes/{name}") {
        state.node_reads += 1;
        body = state.node.clone();
        match mode {
            1 => body["metadata"]["labels"][KEYS[1]] = json!("cn-hangzhou-b"),
            2 => body["metadata"]["labels"][KEYS[2]] = json!("cn-shanghai"),
            3 => body["metadata"]["uid"] = json!(Uuid::new_v4()),
            4 => body["status"]["nodeInfo"]["bootID"] = json!(Uuid::new_v4()),
            5 => {
                body["metadata"]["annotations"]["sandbox.platform/runtime-profile-sha256"] =
                    json!("e".repeat(64))
            }
            6 if state.node_reads == 2 => body["metadata"]["uid"] = json!(Uuid::new_v4()),
            15 => body["metadata"]["deletionTimestamp"] = json!(Utc::now()),
            16 => body["status"]["conditions"] = json!([{"type":"Ready","status":"False"}]),
            _ => {}
        }
    } else if path == format!("/apis/storage.k8s.io/v1/csinodes/{name}") {
        state.csi_reads += 1;
        body = state.csi.clone();
        match mode {
            7 if state.csi_reads == 2 => body["metadata"]["uid"] = json!(Uuid::new_v4()),
            8 => body["spec"]["drivers"][0]["nodeID"] = json!("i-foreign"),
            9 => body["spec"]["drivers"] = json!([]),
            10 => {
                let driver = body["spec"]["drivers"][0].clone();
                body["spec"]["drivers"] = json!([driver, driver]);
            }
            11 => body["metadata"]["ownerReferences"][0]["uid"] = json!(Uuid::new_v4()),
            12 => {
                body["spec"]["drivers"][0]["topologyKeys"] =
                    json!([KEYS[0], KEYS[1], KEYS[2], KEYS[3], "unreviewed.example/key"])
            }
            13 => body["spec"]["drivers"][0]["topologyKeys"] = json!([KEYS[0], KEYS[1], KEYS[2]]),
            14 => body["metadata"]["deletionTimestamp"] = json!(Utc::now()),
            _ => {}
        }
    } else {
        state.violations.push("unreviewed Kubernetes path");
        return failure(StatusCode::NOT_FOUND);
    }
    answer(StatusCode::OK, body)
}
struct KubeFixture {
    shared: KubeShared,
    runtime: BackupJobRuntime,
    server: Server,
}
impl KubeFixture {
    async fn new(binding: &NodeBinding, cloud: &NodeTopologyCloudBinding) -> anyhow::Result<Self> {
        let labels = json!({"sandbox.platform/node-pool":"kata","sandbox.platform/worker-pool":"kata","alibabacloud.com/ecs-instance-id":cloud.instance_id,"topology.diskplugin.csi.alibabacloud.com/zone":cloud.zone_id,"topology.kubernetes.io/region":cloud.region,"topology.kubernetes.io/zone":cloud.zone_id});
        let node = json!({"apiVersion":"v1","kind":"Node","metadata":{"name":binding.node_name,"uid":binding.node_uid,"resourceVersion":"77","labels":labels,"annotations":{"sandbox.platform/runtime-profile-sha256":binding.profile_sha256}},"spec":{"taints":[{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"},{"key":"sandbox.platform/unverified","value":"true","effect":"NoSchedule"}]},"status":{"addresses":[{"type":"InternalIP","address":cloud.private_ip.to_string()}],"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"architecture":"amd64","operatingSystem":"linux","bootID":binding.boot_id,"containerRuntimeVersion":"containerd://2.3.5","kernelVersion":"TEST_ONLY","kubeProxyVersion":"","kubeletVersion":"v1.36.4","machineID":"TEST_ONLY","osImage":"TEST_ONLY","systemUUID":"TEST_ONLY"}}});
        let csi = json!({"apiVersion":"storage.k8s.io/v1","kind":"CSINode","metadata":{"name":binding.node_name,"uid":Uuid::new_v4(),"resourceVersion":"88","ownerReferences":[{"apiVersion":"v1","kind":"Node","name":binding.node_name,"uid":binding.node_uid}]},"spec":{"drivers":[{"name":"diskplugin.csi.alibabacloud.com","nodeID":cloud.instance_id,"topologyKeys":KEYS}]}});
        let shared = Arc::new(Mutex::new(KubeState {
            node,
            csi,
            ..Default::default()
        }));
        let server = Server::start(
            Router::new()
                .fallback(any(kube_http))
                .with_state(shared.clone()),
        )
        .await?;
        let config = kube::Config::new(server.url.as_str().parse()?);
        let runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(
            kube::Client::try_from(config)?,
        ));
        Ok(Self {
            shared,
            runtime,
            server,
        })
    }
    fn mode(&self, mode: u8) -> anyhow::Result<()> {
        let mut state = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?;
        state.mode = mode;
        state.node_reads = 0;
        state.csi_reads = 0;
        Ok(())
    }
    fn eligible(&self) -> anyhow::Result<()> {
        let mut state = self
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?;
        state.node["spec"]["taints"] =
            json!([{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"}]);
        state.node["metadata"]["resourceVersion"] = json!("78");
        Ok(())
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.server.finish().await?;
        ensure!(
            self.shared
                .lock()
                .map_err(|_| anyhow::anyhow!("Kube fixture state"))?
                .violations
                .is_empty(),
            "Kubernetes fixture protocol mismatch"
        );
        Ok(())
    }
}

#[derive(Default)]
struct CloudState {
    mode: u8,
    session: String,
    actions: Vec<String>,
    describe_responses: Vec<(String, String)>,
    violations: Vec<&'static str>,
}
type CloudShared = Arc<Mutex<CloudState>>;
#[derive(Clone)]
struct CloudRoutes {
    shared: CloudShared,
    binding: NodeTopologyCloudBinding,
}
async fn cloud_http(State(routes): State<CloudRoutes>, request: Request<Body>) -> Response<Body> {
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let action = request
        .headers()
        .get("x-acs-action")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Ok(mut state) = routes.shared.lock() else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR);
    };
    state.actions.push(action.clone());
    if request.method() != Method::POST || request.uri().path() != "/" {
        state.violations.push("cloud request method/path");
        return failure(StatusCode::BAD_REQUEST);
    }
    if action != "AssumeRoleWithOIDC"
        && (!verify_test_request(
            request.headers(),
            request.uri().query().unwrap_or_default(),
            ACCESS,
            SECRET,
        ) || request
            .headers()
            .get("x-acs-security-token")
            .and_then(|v| v.to_str().ok())
            != Some(TOKEN))
    {
        state
            .violations
            .push("actual cloud ACS3 signature/token mismatch");
        return failure(StatusCode::FORBIDDEN);
    }
    let b = &routes.binding;
    let id = "public-topology-request/one:2026";
    let value = match action.as_str() {
        "AssumeRoleWithOIDC" => {
            let expected = json!({"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:DescribeInstances"],"Resource":[format!("acs:ecs:{}:{}:instance/{}",b.region,b.account_id,b.instance_id)]},{"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}]});
            let policy = query
                .get("Policy")
                .and_then(|v| serde_json::from_str::<Value>(v).ok());
            if request.headers().contains_key("authorization")
                || query.get("OIDCToken").map(String::as_str) != Some(OIDC)
                || query.get("DurationSeconds").map(String::as_str) != Some("900")
                || policy.as_ref() != Some(&expected)
            {
                state
                    .violations
                    .push("OIDC/exact readonly session policy mismatch");
                return failure(StatusCode::BAD_REQUEST);
            }
            state.session = query.get("RoleSessionName").cloned().unwrap_or_default();
            json!({"RequestId":id,"AssumedRoleUser":{"Arn":format!("acs:ram::{ACCOUNT}:role/sandbox-topology/{}",state.session),"AssumedRoleId":"PUBLIC_TEST:session"},"OIDCTokenInfo":{"Issuer":"https://issuer.fixture.invalid","Subject":if state.mode==15{"system:serviceaccount:foreign:other"}else{"system:serviceaccount:sandbox-system:sandbox-node-topology-owner"},"ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success","ExpirationTime":Utc::now()+Days::seconds(600),"IssuanceTime":Utc::now()-Days::seconds(10)},"Credentials":{"AccessKeyId":ACCESS,"AccessKeySecret":SECRET,"SecurityToken":TOKEN,"Expiration":Utc::now()+Days::seconds(900)}})
        }
        "GetCallerIdentity" => {
            json!({"RequestId":id,"AccountId":if state.mode==1{"9999999999999999"}else{ACCOUNT},"IdentityType":"AssumedRoleUser","Arn":format!("acs:ram::{ACCOUNT}:role/sandbox-topology/{}",state.session),"RoleId":if state.mode==2{"9999999999999999"}else{ROLE_ID},"PrincipalId":"PUBLIC_TEST"})
        }
        "DescribeInstances" => {
            if query
                != BTreeMap::from([
                    ("RegionId".into(), b.region.clone()),
                    ("InstanceIds".into(), format!("[\"{}\"]", b.instance_id)),
                    ("MaxResults".into(), "10".into()),
                ])
            {
                state
                    .violations
                    .push("DescribeInstances must bind one instance and no hiding filters");
                return failure(StatusCode::BAD_REQUEST);
            }
            let mut instance = json!({"InstanceId":b.instance_id,"RegionId":b.region,"ZoneId":b.zone_id,"InstanceNetworkType":"vpc","Status":"Running","VpcAttributes":{"VpcId":b.vpc_id,"VSwitchId":b.vswitch_id,"PrivateIpAddress":{"IpAddress":[b.private_ip.to_string()]}},"Tags":{"Tag":[{"TagKey":"Deployment","TagValue":b.deployment},{"TagKey":"Role","TagValue":"kata"}]}});
            match state.mode {
                3 => instance["RegionId"] = json!("cn-shanghai"),
                4 => instance["InstanceId"] = json!("i-other"),
                5 => instance["ZoneId"] = json!("cn-hangzhou-b"),
                6 => instance["VpcAttributes"]["VpcId"] = json!("vpc-other"),
                7 => instance["VpcAttributes"]["VSwitchId"] = json!("vsw-other"),
                8 => {
                    instance["VpcAttributes"]["PrivateIpAddress"]["IpAddress"] = json!(["10.0.0.9"])
                }
                9 => instance["Tags"]["Tag"][0]["TagValue"] = json!("other-deployment"),
                10 => instance["Tags"]["Tag"][1]["TagValue"] = json!("control"),
                11 => instance["Status"] = json!("Stopped"),
                14 => {
                    instance["Tags"]["Tag"] = json!([{"TagKey":"Deployment","TagValue":b.deployment},{"TagKey":"Role","TagValue":"kata"},{"TagKey":"Role","TagValue":"kata"}])
                }
                _ => {}
            }
            let instances = if state.mode == 12 {
                json!([instance, instance])
            } else {
                json!([instance])
            };
            json!({"RequestId":id,"TotalCount":if state.mode==12{2}else{1},"NextToken":if state.mode==13{"unexpected-next-page"}else{""},"Instances":{"Instance":instances}})
        }
        _ => {
            state.violations.push("unapproved cloud action");
            return failure(StatusCode::METHOD_NOT_ALLOWED);
        }
    };
    if action == "DescribeInstances" {
        state
            .describe_responses
            .push((id.to_owned(), sha(value.to_string().as_bytes())));
    }
    answer(StatusCode::OK, value)
}
struct CloudFixture {
    shared: CloudShared,
    binding: NodeTopologyCloudBinding,
    server: Server,
    token: tempfile::NamedTempFile,
}
impl CloudFixture {
    async fn new(binding: NodeTopologyCloudBinding) -> anyhow::Result<Self> {
        let shared = Arc::new(Mutex::new(CloudState::default()));
        let server = Server::start(Router::new().fallback(any(cloud_http)).with_state(
            CloudRoutes {
                shared: shared.clone(),
                binding: binding.clone(),
            },
        ))
        .await?;
        let mut token = tempfile::NamedTempFile::new()?;
        token.write_all(OIDC.as_bytes())?;
        token.flush()?;
        Ok(Self {
            shared,
            binding,
            server,
            token,
        })
    }
    fn config(&self) -> NodeTopologyCloudConfig {
        NodeTopologyCloudConfig {
            account_id: ACCOUNT.into(),
            region: self.binding.region.clone(),
            role_arn: format!("acs:ram::{ACCOUNT}:role/sandbox-topology"),
            role_id: ROLE_ID.into(),
            oidc_provider_arn: format!("acs:ram::{ACCOUNT}:oidc-provider/fixture"),
            oidc_issuer: "https://issuer.fixture.invalid".into(),
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: "system:serviceaccount:sandbox-system:sandbox-node-topology-owner".into(),
            oidc_token_file: self.token.path().into(),
            requests_per_second: 20,
            max_in_flight: 4,
        }
    }
    fn client(&self, mode: u8) -> anyhow::Result<AlibabaCloudNodeTopology> {
        self.shared
            .lock()
            .map_err(|_| anyhow::anyhow!("cloud fixture state"))?
            .mode = mode;
        AlibabaCloudNodeTopology::for_test(
            self.config(),
            self.binding.clone(),
            self.server.url.clone(),
        )
        .map_err(|e| anyhow::anyhow!("public cloud fixture configuration: {e:?}"))
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.server.finish().await?;
        ensure!(
            self.shared
                .lock()
                .map_err(|_| anyhow::anyhow!("cloud fixture state"))?
                .violations
                .is_empty(),
            "cloud fixture protocol mismatch"
        );
        Ok(())
    }
}

fn terraform(binding: &NodeBinding, cloud: &NodeTopologyCloudBinding) -> Value {
    let mut inventory = BTreeMap::new();
    let mut subnets = BTreeMap::new();
    for (index, suffix) in ["a", "b", "c"].into_iter().enumerate() {
        let zone = format!("cn-hangzhou-{suffix}");
        subnets.insert(format!("subnet-{suffix}"), json!({"id":format!("vsw-zone{suffix}"),"zone":zone,"cidr":format!("10.0.{index}.0/24")}));
        for (pool, offset) in [("control", 20), ("platform", 30), ("kata", 8)] {
            let name = if pool == "kata" && index == 0 {
                binding.node_name.clone()
            } else {
                format!("{pool}-{suffix}")
            };
            let id = if pool == "kata" && index == 0 {
                cloud.instance_id.clone()
            } else {
                format!("i-{pool}{suffix}")
            };
            inventory.insert(name, json!({"id":id,"private_ip":format!("10.0.{index}.{offset}"),"role":pool,"zone":zone}));
        }
    }
    json!({"deployment_identity":{"sensitive":false,"type":"object","value":{"cloud_account_id":ACCOUNT,"region":"cn-hangzhou","deployment":cloud.deployment,"environment":"preproduction"}},"workspace_kms_key_id":{"sensitive":false,"type":"string","value":"restore-compute-key"},"workload_oidc_provider_arn":{"sensitive":false,"type":"string","value":format!("acs:ram::{ACCOUNT}:oidc-provider/fixture")},"vpc_id":{"sensitive":false,"type":"string","value":cloud.vpc_id},"node_inventory":{"sensitive":false,"type":"object","value":inventory},"subnets":{"sensitive":false,"type":"object","value":subnets},"operator_note":{"sensitive":false,"type":"string","value":"公开测试，非云认证"}})
}

// Independent Python implementation is the existing installer digest contract,
// rather than duplicating the new Rust collector's canonical serializer.
fn canonical_sha(raw: &[u8]) -> anyhow::Result<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("python3").args(["-c", "import hashlib,json,sys; v=json.load(sys.stdin); b=json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('utf-8'); print(hashlib.sha256(b).hexdigest())"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    child
        .stdin
        .take()
        .context("Python digest input")?
        .write_all(raw)?;
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "independent Python canonical digest failed"
    );
    let hash = String::from_utf8(output.stdout)?.trim().to_owned();
    ensure!(
        hash.len() == 64 && hash.bytes().all(|v| v.is_ascii_hexdigit()),
        "Python digest output"
    );
    Ok(hash)
}

fn enrollment_plan(
    binding: &NodeBinding,
    cloud: &NodeTopologyCloudBinding,
    tf: &Value,
    raw: &[u8],
    expires: DateTime<Utc>,
) -> anyhow::Result<EnrollmentPlan> {
    let artifact = json!({"protocol":1,"node":binding,"cloud_account_id":ACCOUNT,"region":cloud.region,"cloud_instance_id":cloud.instance_id,"private_ip":cloud.private_ip.to_string(),"guard_port":9444,"certification_id":"PUBLIC_TEST_TOPOLOGY_ENROLLMENT"});
    let mut nodes = vec![];
    for (name, entry) in tf["node_inventory"]["value"]
        .as_object()
        .context("Terraform nodes")?
    {
        if entry["role"] == json!("kata") {
            let mut reviewed = binding.clone();
            if name != &binding.node_name {
                reviewed.node_uid = Uuid::new_v4();
                reviewed.boot_id = Uuid::new_v4();
                reviewed.node_name = name.clone();
            }
            nodes.push(json!({"node":reviewed,"cloud_instance_id":entry["id"],"private_ip":entry["private_ip"]}));
        }
    }
    let checks: BTreeMap<_, _> = CERTIFICATION_CHECKS
        .iter()
        .map(|key| {
            (
                *key,
                json!({"status":"PASS","evidence_sha256":"d".repeat(64)}),
            )
        })
        .collect();
    let versions = sha(include_bytes!("../deploy/cluster/versions.lock.json"));
    let report = serde_json::to_vec(
        &json!({"protocol":1,"certification_id":"PUBLIC_TEST_TOPOLOGY_ENROLLMENT","cluster_epoch":binding.cluster_epoch,"versions_lock_sha256":versions,"nodeguard_binary_sha256":"b".repeat(64),"reviewed_at":stamp(Utc::now()-Days::minutes(1)),"expires_at":stamp(expires),"nodes":nodes,"checks":checks}),
    )?;
    let settings = json!({"deployment":cloud.deployment,"region":"cn-hangzhou","oidc_provider_arn":format!("acs:ram::{ACCOUNT}:oidc-provider/fixture"),"cluster_epoch":binding.cluster_epoch,"certification_id":"PUBLIC_TEST_TOPOLOGY_ENROLLMENT","certification_report_sha256":sha(&report),"nodeguard_binary_sha256":"b".repeat(64),"versions_lock_sha256":versions});
    EnrollmentPlan::parse(
        &serde_json::to_vec(&artifact)?,
        raw,
        &serde_json::to_vec(&settings)?,
        &report,
        Utc::now(),
    )
}

async fn count(owner: &Database) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM restore_node_topology_receipts")
            .fetch_one(&owner.pool)
            .await?,
    )
}
async fn reject_payload(owner: &Database, value: &Value) -> anyhow::Result<()> {
    let mut tx = owner.pool.begin().await?;
    let error = sqlx::query_scalar::<_, Value>("SELECT sandbox_record_restore_node_topology($1)")
        .bind(value)
        .fetch_one(&mut *tx)
        .await
        .err()
        .context("invalid topology payload accepted")?;
    ensure!(
        error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
        "actual strict topology guard must deny, not an unrelated permission or parse failure"
    );
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires fresh private PG, real mTLS enrollment, Python canonical digest and signed loopback STS/ECS; no cloud certification"]
async fn owner_topology_uses_real_enrollment_and_signed_observations_without_mutating_source()
-> anyhow::Result<()> {
    Box::pin(run()).await
}

async fn run() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let target = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        target
            .path()
            .strip_prefix("/sandbox_restore_acceptance_")
            .and_then(|v| v.strip_suffix("_test"))
            .is_some_and(|v| !v.is_empty()
                && v.len() <= 20
                && v.bytes().all(|b| b.is_ascii_digit())),
        "topology candidate needs its own new restore acceptance database"
    );
    let (source, _verifier, _source_files) = Box::pin(completed_source()).await?;
    // Exact normal deployment grants, without role creation, password changes
    // or owner membership. Validate components while only formal SQL exists.
    for grants in [
        include_str!("../scripts/sql/worker-role.sql"),
        include_str!("../scripts/sql/gateway-role.sql"),
        include_str!("../scripts/sql/admission-role.sql"),
        include_str!("../scripts/sql/termination-role.sql"),
        include_str!("../scripts/sql/fencing-role.sql"),
        include_str!("../scripts/sql/volume-deleter-role.sql"),
        include_str!("../scripts/sql/backup-role.sql"),
    ] {
        sqlx::raw_sql(grants)
            .execute(&source.f.base.f.owner)
            .await?;
    }
    let verified = test_support_db::Fixture::prepare_verified_connections().await?;
    let mut ordinary = vec![("sandbox_app", verified.database())];
    for (key, role) in [
        ("TEST_WORKER_DATABASE_URL", "sandbox_worker"),
        ("TEST_GATEWAY_DATABASE_URL", "sandbox_gateway"),
        ("TEST_ADMISSION_DATABASE_URL", "sandbox_admission"),
        ("TEST_TERMINATION_DATABASE_URL", "sandbox_termination"),
        ("TEST_FENCING_DATABASE_URL", "sandbox_fencing"),
        ("TEST_VOLUME_DELETER_DATABASE_URL", "sandbox_volume_deleter"),
        ("TEST_BACKUP_DATABASE_URL", "sandbox_backup"),
    ] {
        let component = verified.runtime(key, role, 2).await?;
        ordinary.push((role, component.database_for(role)?));
    }
    let owner = Database {
        pool: verified.owner(),
    };
    let tenant = source.f.base.f.actor.tenant_id;
    let preserved = preserved_source(&owner, tenant, source.plan.backup.id).await?;
    ensure!(
        preserved["backup"]["status"] == json!("AVAILABLE")
            && preserved["node"].is_object()
            && preserved["contexts"]
                .as_array()
                .is_some_and(|v| v.len() == 2),
        "normal signed source before private schema"
    );
    let mut tx = owner.pool.begin().await?;
    sqlx::raw_sql(include_str!("../tests/fixtures/restore/0038_restores.sql"))
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(include_str!(
        "../tests/fixtures/restore/0038_restore_node_topology.sql"
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    verified.clear_statement_caches().await?;
    for (value, valid) in [
        ("2026-10-08T24:00:00Z", false),
        ("2026-10-08T23:60:00Z", false),
        ("2026-10-08T23:59:60Z", false),
        ("2026-10-08T23:59:59Z", true),
        ("2026-10-08T23:59:59+00:00", true),
        ("2026-10-08T23:59:59.123456Z", true),
        ("2026-10-08T23:59:59.123456+00:00", true),
    ] {
        let accepted: bool =
            sqlx::query_scalar("SELECT sandbox_restore_topology_timestamp_valid($1)")
                .bind(value)
                .fetch_one(&owner.pool)
                .await?;
        ensure!(
            accepted == valid,
            "strict actual PG topology timestamp contract: {value}"
        );
        eprintln!("VERIFIED actual PG topology timestamp {value} accepted={accepted}");
    }

    // Every connection was validated against only normal migrations before the
    // DDL. Draft metadata still makes the production role/schema startup fail.
    for (_, database) in &ordinary {
        let error = database
            .verify_runtime_role()
            .await
            .err()
            .context("private topology draft passed production startup")?;
        ensure!(
            error
                .to_string()
                .contains("successful ordered migration 0038"),
            "production must reject the private schema, not an unrelated failed pool or role"
        );
    }
    let epoch = Uuid::new_v4();
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(epoch)
        .execute(&owner.pool)
        .await?;
    let mut binding = node();
    binding.cluster_epoch = epoch;
    let cloud_binding = NodeTopologyCloudBinding {
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        instance_id: format!("i-topology{}", Uuid::new_v4().simple()),
        zone_id: "cn-hangzhou-a".into(),
        vpc_id: "vpc-publictopology".into(),
        vswitch_id: "vsw-zonea".into(),
        private_ip: "10.0.0.8".parse()?,
        deployment: "sandbox".into(),
    };
    let tf = terraform(&binding, &cloud_binding);
    let raw = serde_json::to_vec_pretty(&tf)?;
    let canonical = canonical_sha(&raw)?;
    ensure!(
        sha(&raw) != canonical,
        "raw bytes and full canonical digest are independently bound"
    );
    let now =
        DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).context("fixture clock")?;
    let enrollment_until = now + Days::days(1);
    let backup_until = now + Days::days(2);
    let restore_until = now + Days::hours(12);
    let plan = enrollment_plan(&binding, &cloud_binding, &tf, &raw, enrollment_until)?;
    let kube = KubeFixture::new(&binding, &cloud_binding).await?;
    let guard = FixtureGuard::start(binding.clone()).await?;
    let cloud = CloudFixture::new(cloud_binding).await?;
    let outcome = Box::pin(exercise(TopologyCase {
        owner: &owner,
        ordinary: &ordinary,
        source: &source,
        tenant,
        preserved: &preserved,
        enrollment_plan: &plan,
        raw: &raw,
        canonical: &canonical,
        backup_until,
        restore_until,
        kube: &kube,
        guard: &guard,
        cloud: &cloud,
    }))
    .await;
    // Run all independent network cleanup even if a business assertion failed.
    let cloud_closed = cloud.finish().await;
    let kube_closed = kube.finish().await;
    let guard_closed = guard.shutdown().await;
    let source_guard_closed = source.f.base.guard.shutdown().await;
    for (name, failed) in [
        ("cloud", cloud_closed.is_err()),
        ("Kubernetes", kube_closed.is_err()),
        ("current Nodeguard", guard_closed.is_err()),
        ("source Nodeguard", source_guard_closed.is_err()),
    ] {
        if failed {
            eprintln!("PRIVATE fixture cleanup failed: {name}; not certified drained");
        }
    }
    outcome?;
    cloud_closed?;
    kube_closed?;
    guard_closed?;
    source_guard_closed?;
    eprintln!(
        "VERIFIED private owner topology real mTLS enrollment, actual signed readonly STS/ECS and Node/CSINode TCP, raw/canonical Terraform bindings, exact least independent expiry, owner-only append-only PG and original source unchanged; not real cloud/CSI certification or selected-node authority"
    );
    Ok(())
}

async fn preserved_source(owner: &Database, tenant: Uuid, backup: Uuid) -> anyhow::Result<Value> {
    let mut tx = owner.pool.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let value = sqlx::query_scalar("SELECT jsonb_build_object('backup',to_jsonb(b),'vault',to_jsonb(v),'profile',to_jsonb(p),'node',(SELECT to_jsonb(n) FROM runtime_nodes n WHERE n.id=(SELECT lp.runtime_node_id FROM launch_permits lp WHERE lp.tenant_id=b.tenant_id AND lp.id=b.source_permit_id)),'contexts',COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.attempt_id) FROM backup_job_contexts c WHERE c.tenant_id=b.tenant_id AND c.backup_id=b.id),'[]'::jsonb),'holds',COALESCE((SELECT jsonb_agg(to_jsonb(h) ORDER BY h.id) FROM workspace_holds h WHERE h.tenant_id=b.tenant_id AND h.workspace_id=b.workspace_id),'[]'::jsonb),'hold_releases',COALESCE((SELECT jsonb_agg(to_jsonb(hr) ORDER BY hr.hold_id) FROM workspace_hold_releases hr JOIN workspace_holds h ON h.tenant_id=hr.tenant_id AND h.id=hr.hold_id WHERE h.tenant_id=b.tenant_id AND h.workspace_id=b.workspace_id),'[]'::jsonb),'quota_accounts',COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM quota_accounts q WHERE q.tenant_id=b.tenant_id),'[]'::jsonb),'quota_reservations',COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM quota_reservations q WHERE q.tenant_id=b.tenant_id),'[]'::jsonb)) FROM backups b JOIN backup_vault_receipts v ON v.tenant_id=b.tenant_id AND v.backup_id=b.id JOIN backup_profiles p ON p.id=b.profile_id WHERE b.tenant_id=$1 AND b.id=$2").bind(tenant).bind(backup).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(value)
}

async fn insert_profile(
    owner: &Database,
    source_profile: Uuid,
    epoch: Uuid,
    canonical: &str,
    backup_until: DateTime<Utc>,
    reviewed_at: DateTime<Utc>,
    restore_until: DateTime<Utc>,
) -> anyhow::Result<Uuid> {
    let profile = Uuid::new_v4();
    let mut tx = owner.pool.begin().await?;
    sqlx::query("INSERT INTO backup_profiles(id,cluster_epoch,enabled,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings) SELECT $1,$3,true,certification_sha256,$4,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings FROM backup_profiles WHERE id=$2").bind(profile).bind(source_profile).bind(epoch).bind(backup_until).execute(&mut *tx).await?;
    let (certification, settings): (String, Value) =
        sqlx::query_as("SELECT certification_sha256,settings FROM backup_profiles WHERE id=$1")
            .bind(profile)
            .fetch_one(&mut *tx)
            .await?;
    let settings: crate::backup_job::BackupCloudSettings = serde_json::from_value(settings)?;
    let (mappings, mut report, _) =
        super::storage_mapping::fixture(&settings, profile, epoch, &certification)?;
    report["bindings"]["infrastructure_sha256"] = json!(canonical);
    sqlx::query("INSERT INTO restore_profile_certifications(profile_id,cluster_epoch,backup_certification_sha256,report_sha256,report,storage_mappings,approval_reference,reviewed_at,certified_until) VALUES($1,$2,$3,$4,$5,$6,'PUBLIC_TEST_NOT_CLOUD_CERTIFICATION',$8,$7)").bind(profile).bind(epoch).bind(certification).bind(super::storage_mapping::digest(&report)?).bind(&report).bind(mappings).bind(restore_until).bind(reviewed_at).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(profile)
}

struct TopologyCase<'a> {
    owner: &'a Database,
    ordinary: &'a [(&'static str, Database)],
    source: &'a crate::backup_ledger::pipeline_tests::Pipeline,
    tenant: Uuid,
    preserved: &'a Value,
    enrollment_plan: &'a EnrollmentPlan,
    raw: &'a [u8],
    canonical: &'a str,
    backup_until: DateTime<Utc>,
    restore_until: DateTime<Utc>,
    kube: &'a KubeFixture,
    guard: &'a FixtureGuard,
    cloud: &'a CloudFixture,
}
async fn exercise(case: TopologyCase<'_>) -> anyhow::Result<()> {
    let TopologyCase {
        owner,
        ordinary,
        source,
        tenant,
        preserved,
        enrollment_plan,
        raw,
        canonical,
        backup_until,
        restore_until,
        kube,
        guard,
        cloud,
    } = case;
    let mut other_node = guard.client.node_binding().clone();
    other_node.boot_id = Uuid::new_v4();
    let other_guard = FixtureGuard::start(other_node).await?;
    other_guard.client.verify_node().await?;
    let other_seen = other_guard
        .identity_verifications
        .load(std::sync::atomic::Ordering::SeqCst);
    let rejected = enroll_with_client_test(
        owner,
        kube.runtime.runtime(),
        &other_guard.client,
        enrollment_plan,
    )
    .await;
    let other_after = other_guard
        .identity_verifications
        .load(std::sync::atomic::Ordering::SeqCst);
    let other_closed = other_guard.shutdown().await;
    ensure!(
        other_seen == 1 && other_after == other_seen,
        "actual other-node mTLS identity is valid, reviewed enrollment sends no request to it"
    );
    ensure!(
        rejected.is_err(),
        "another valid mTLS Nodeguard client cannot authenticate the reviewed Node identity"
    );
    other_closed?;
    ensure!(
        kube.shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?
            .node_reads
            == 0,
        "configured-client identity denial occurs before actual Kubernetes I/O"
    );
    let enrolled = enroll_with_client_test(
        owner,
        kube.runtime.runtime(),
        &guard.client,
        enrollment_plan,
    )
    .await?;
    ensure!(
        enrolled.changed && enrolled.enabled && enrolled.terraform_output_sha256 == sha(raw),
        "normal actual mTLS enrollment emits audited immutable source"
    );
    ensure!(
        kube.shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?
            .node_reads
            == 2,
        "enrollment rechecks actual Node after mTLS"
    );
    ensure!(
        guard
            .identity_verifications
            .load(std::sync::atomic::Ordering::SeqCst)
            == 1,
        "normal enrollment includes one actual mTLS identity response"
    );
    kube.eligible()?;
    let profile = insert_profile(
        owner,
        source.f.profile,
        enrolled.node.cluster_epoch,
        canonical,
        backup_until,
        Utc::now(),
        restore_until,
    )
    .await?;
    let request = NodeTopologyRequest {
        runtime_node_id: enrolled.runtime_node_id,
        enrollment_id: enrolled.enrollment_id,
        restore_profile_id: profile,
    };
    // Wrong owner is rejected before any Node, CSI, STS or ECS I/O.
    let client = cloud.client(0)?;
    kube.mode(0)?;
    let cloud_before = cloud
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("cloud fixture state"))?
        .actions
        .len();
    let mtls_before = guard
        .identity_verifications
        .load(std::sync::atomic::Ordering::SeqCst);
    let production_cloud = AlibabaCloudNodeTopology::new(cloud.config(), cloud.binding.clone())
        .map_err(|e| anyhow::anyhow!("public fixture cloud config: {e:?}"))?;
    let production_credentials = credentials();
    for (_, database) in ordinary {
        ensure!(
            matches!(
                collect_node_topology(
                    database,
                    &kube.runtime,
                    &production_credentials,
                    &production_cloud,
                    request,
                    std::path::Path::new("/DOES_NOT_EXIST_PUBLIC_TOPOLOGY_FIXTURE.json")
                )
                .await,
                Err(TopologyOwnerError::Owner)
            ),
            "production collector rejects nonowner before file or privileged network I/O"
        );
        ensure!(
            matches!(
                collect_with_client(
                    database,
                    &kube.runtime,
                    &guard.client,
                    &client,
                    request,
                    raw
                )
                .await,
                Err(TopologyOwnerError::Owner)
            ),
            "ordinary roles cannot collect owner authority"
        );
    }
    let owner_denied_reads = {
        let state = kube
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?;
        (state.node_reads, state.csi_reads)
    };
    ensure!(
        owner_denied_reads == (0, 0)
            && cloud
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("cloud fixture state"))?
                .actions
                .len()
                == cloud_before,
        "owner denial occurs before privileged I/O"
    );
    ensure!(
        guard
            .identity_verifications
            .load(std::sync::atomic::Ordering::SeqCst)
            == mtls_before,
        "production and injected owner-first denial perform zero actual mTLS requests"
    );
    for mode in 1..=16 {
        kube.mode(mode)?;
        let client = cloud.client(0)?;
        let cloud_before = cloud
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("cloud fixture state"))?
            .actions
            .len();
        let mtls_before = guard
            .identity_verifications
            .load(std::sync::atomic::Ordering::SeqCst);
        ensure!(
            matches!(
                collect_with_client(owner, &kube.runtime, &guard.client, &client, request, raw)
                    .await,
                Err(TopologyOwnerError::Kubernetes)
            ),
            "actual Node/CSI identity fault {mode} must fail through registration guard"
        );
        {
            let state = kube
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("Kube fixture state"))?;
            let second_read = matches!(mode, 6 | 7);
            ensure!(
                (state.node_reads, state.csi_reads) == if second_read { (2, 2) } else { (1, 1) },
                "Kubernetes fault {mode} must reach its exact first/final mutated read"
            );
        }
        {
            let cloud_state = cloud
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("cloud fixture state"))?;
            let seen = &cloud_state.actions[cloud_before..];
            if matches!(mode, 6 | 7) {
                ensure!(
                    seen == [
                        "AssumeRoleWithOIDC",
                        "GetCallerIdentity",
                        "DescribeInstances"
                    ] && guard
                        .identity_verifications
                        .load(std::sync::atomic::Ordering::SeqCst)
                        == mtls_before + 1,
                    "final UID drift must occur after actual mTLS and signed DescribeInstances"
                );
            } else {
                ensure!(
                    seen.is_empty()
                        && guard
                            .identity_verifications
                            .load(std::sync::atomic::Ordering::SeqCst)
                            == mtls_before,
                    "first-read identity fault cannot reach mTLS or cloud"
                );
            }
        }
        ensure!(
            count(owner).await? == 0,
            "invalid actual Kubernetes identity cannot publish receipt"
        );
    }
    kube.mode(0)?;
    for mode in 1..=15 {
        let client = cloud.client(mode)?;
        let before = cloud
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("cloud fixture state"))?
            .actions
            .len();
        ensure!(
            matches!(
                collect_with_client(owner, &kube.runtime, &guard.client, &client, request, raw)
                    .await,
                Err(TopologyOwnerError::Cloud)
            ),
            "actual cloud identity fault {mode} must fail through readonly provider guard"
        );
        {
            let state = cloud
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("cloud fixture state"))?;
            let expected: &[&str] = match mode {
                1 | 2 => &["AssumeRoleWithOIDC", "GetCallerIdentity"],
                15 => &["AssumeRoleWithOIDC"],
                _ => &[
                    "AssumeRoleWithOIDC",
                    "GetCallerIdentity",
                    "DescribeInstances",
                ],
            };
            ensure!(
                state.actions[before..] == *expected,
                "cloud fault {mode} must reach its actual STS/identity/DescribeInstances target"
            );
        }
        ensure!(
            count(owner).await? == 0,
            "invalid cloud identity cannot publish receipt"
        );
    }
    // Both digest paths read the exact same file. Changed whitespace leaves
    // canonical content equal but must fail the enrollment's exact raw hash.
    let compact = serde_json::to_vec(&serde_json::from_slice::<Value>(raw)?)?;
    ensure!(
        canonical_sha(&compact)? == canonical && sha(&compact) != sha(raw),
        "distinct raw/canonical fixture"
    );
    let client = cloud.client(0)?;
    ensure!(
        matches!(
            collect_with_client(
                owner,
                &kube.runtime,
                &guard.client,
                &client,
                request,
                &compact
            )
            .await,
            Err(TopologyOwnerError::Inventory)
        ),
        "same canonical content cannot replace enrolled raw bytes"
    );
    let bad_canonical_profile = insert_profile(
        owner,
        source.f.profile,
        enrolled.node.cluster_epoch,
        &"f".repeat(64),
        backup_until,
        Utc::now(),
        restore_until,
    )
    .await?;
    let bad_canonical_request = NodeTopologyRequest {
        restore_profile_id: bad_canonical_profile,
        ..request
    };
    kube.mode(0)?;
    ensure!(
        matches!(
            collect_with_client(
                owner,
                &kube.runtime,
                &guard.client,
                &client,
                bad_canonical_request,
                raw
            )
            .await,
            Err(TopologyOwnerError::Inventory)
        ),
        "same exact enrolled raw bytes fail a separately mismatched immutable canonical report binding"
    );
    ensure!(
        kube.shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?
            .node_reads
            == 0,
        "digest mismatch is rejected before actual Node I/O"
    );
    let expired_profile = insert_profile(
        owner,
        source.f.profile,
        enrolled.node.cluster_epoch,
        canonical,
        backup_until,
        Utc::now() - Days::days(2),
        Utc::now() - Days::days(1),
    )
    .await?;
    let expired_request = NodeTopologyRequest {
        restore_profile_id: expired_profile,
        ..request
    };
    ensure!(
        matches!(
            collect_with_client(
                owner,
                &kube.runtime,
                &guard.client,
                &client,
                expired_request,
                raw
            )
            .await,
            Err(TopologyOwnerError::Expired)
        ),
        "legal immutable expired historical review cannot provide current topology authority"
    );
    let mut wrong_client_node = guard.client.node_binding().clone();
    wrong_client_node.boot_id = Uuid::new_v4();
    let wrong_guard = FixtureGuard::start(wrong_client_node).await?;
    wrong_guard.client.verify_node().await?;
    let wrong_seen = wrong_guard
        .identity_verifications
        .load(std::sync::atomic::Ordering::SeqCst);
    let wrong_client_result = collect_with_client(
        owner,
        &kube.runtime,
        &wrong_guard.client,
        &client,
        request,
        raw,
    )
    .await;
    let wrong_after = wrong_guard
        .identity_verifications
        .load(std::sync::atomic::Ordering::SeqCst);
    let wrong_guard_closed = wrong_guard.shutdown().await;
    ensure!(
        wrong_seen == 1 && wrong_after == wrong_seen,
        "independently valid mTLS Nodeguard cannot receive collector request for another reviewed Node"
    );
    ensure!(
        matches!(wrong_client_result, Err(TopologyOwnerError::Nodeguard)),
        "another legitimate mTLS client cannot authenticate current collector's reviewed Node"
    );
    wrong_guard_closed?;
    ensure!(
        count(owner).await? == 0,
        "all authority/digest/configured-client failures remain unpublished"
    );
    kube.mode(0)?;
    let proof =
        collect_with_client(owner, &kube.runtime, &guard.client, &client, request, raw).await?;
    let id = proof.id();
    let persisted = record_node_topology(owner, &proof).await?;
    let row = persisted.row().clone();
    ensure!(
        row.as_object().is_some_and(|v| v.len() == 16)
            && row["id"] == json!(id)
            && row["terraform_output_sha256"] == json!(sha(raw))
            && row["infrastructure_sha256"] == json!(canonical),
        "sealed collector persisted exact whole row"
    );
    {
        let state = cloud
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("cloud fixture state"))?;
        let (actual_request, actual_sha) = state
            .describe_responses
            .last()
            .context("actual DescribeInstances response")?;
        ensure!(
            row["describe_instance"]["request_id"] == json!(actual_request)
                && row["describe_instance"]["response_sha256"] == json!(actual_sha),
            "published cloud request ID and digest refer to actual bounded TCP response bytes"
        );
    }
    let expiry: DateTime<Utc> = serde_json::from_value(row["certified_until"].clone())?;
    ensure!(
        expiry == restore_until && expiry < backup_until,
        "exact LEAST across deliberately different source deadlines"
    );
    let (node_reads, csi_reads) = {
        let state = kube
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?;
        (state.node_reads, state.csi_reads)
    };
    ensure!(
        node_reads == 2 && csi_reads == 2,
        "sealed observation rechecks actual Node and CSINode"
    );
    let replay = record_node_topology(owner, &proof).await?;
    ensure!(
        replay.row() == &row && count(owner).await? == 1,
        "same proof ACK reconciliation preserves id/time/RV/evidence without INSERT"
    );
    let mut payload = row.clone();
    payload
        .as_object_mut()
        .context("persisted row")?
        .remove("recorded_at");
    for (field, value) in [
        ("id", json!(Uuid::new_v4())),
        ("observed_node_resource_version", json!("different")),
        ("terraform_output_sha256", json!("e".repeat(64))),
        ("infrastructure_sha256", json!("f".repeat(64))),
        ("certified_until", json!(stamp(backup_until))),
    ] {
        let mut changed = payload.clone();
        changed[field] = value;
        reject_payload(owner, &changed).await?;
    }
    for invalid in [Value::Null, Value::Bool(true), json!({})] {
        reject_payload(owner, &invalid).await?;
    }
    for field in [
        "id",
        "describe_instance",
        "csi_registration",
        "observed_at",
        "certified_until",
    ] {
        let mut missing = payload.clone();
        missing.as_object_mut().context("payload")?.remove(field);
        reject_payload(owner, &missing).await?;
        let mut nulled = payload.clone();
        nulled[field] = Value::Null;
        reject_payload(owner, &nulled).await?;
    }
    let mut changed = payload.clone();
    changed["describe_instance"]["protocol"] = json!(1.0);
    reject_payload(owner, &changed).await?;
    changed["describe_instance"]["protocol"] = Value::Bool(true);
    reject_payload(owner, &changed).await?;
    let mut request_changed = payload.clone();
    request_changed["describe_instance"]["request_id"] = json!("PUBLIC_DIFFERENT_REQUEST");
    reject_payload(owner, &request_changed).await?;
    for query in [
        "UPDATE restore_node_topology_receipts SET observed_node_resource_version='changed' WHERE id=$1",
        "DELETE FROM restore_node_topology_receipts WHERE id=$1",
    ] {
        let error = sqlx::query(query)
            .bind(id)
            .execute(&owner.pool)
            .await
            .err()
            .context("append-only receipt mutation accepted")?;
        ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
            "immutable evidence must reject real SQL mutation"
        );
    }
    for (role, database) in ordinary {
        let privileges:(bool,bool,bool,bool,bool)=sqlx::query_as("SELECT has_table_privilege(current_user,'public.restore_node_topology_receipts','SELECT'),has_table_privilege(current_user,'public.restore_node_topology_receipts','INSERT'),has_table_privilege(current_user,'public.restore_node_topology_receipts','UPDATE'),has_table_privilege(current_user,'public.restore_node_topology_receipts','DELETE'),has_function_privilege(current_user,'public.sandbox_record_restore_node_topology(jsonb)','EXECUTE')").fetch_one(&database.pool).await?;
        ensure!(
            privileges == (false, false, false, false, false),
            "ordinary role {role} must not receive owner authority"
        );
        let select_error = sqlx::query("SELECT * FROM restore_node_topology_receipts")
            .fetch_all(&database.pool)
            .await
            .err()
            .context("ordinary global SELECT accepted")?;
        ensure!(
            select_error
                .as_database_error()
                .and_then(|e| e.code())
                .as_deref()
                == Some("42501"),
            "real SELECT privilege denied for {role}, not an unrelated failure"
        );
        let error =
            sqlx::query_scalar::<_, Value>("SELECT sandbox_record_restore_node_topology($1)")
                .bind(&payload)
                .fetch_one(&database.pool)
                .await
                .err()
                .context("ordinary publication accepted")?;
        ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
            "real ordinary EXEC denied for {role}"
        );
    }
    // This private 38-only login has no formal startup proof. Inspect its
    // effective inherited privileges without pretending it is a verified pool.
    let gc_privileges: (bool,bool,bool,bool,bool) = sqlx::query_as(
        "SELECT has_table_privilege('sandbox_restore_gc','public.restore_node_topology_receipts','SELECT'),has_table_privilege('sandbox_restore_gc','public.restore_node_topology_receipts','INSERT'),has_table_privilege('sandbox_restore_gc','public.restore_node_topology_receipts','UPDATE'),has_table_privilege('sandbox_restore_gc','public.restore_node_topology_receipts','DELETE'),has_function_privilege('sandbox_restore_gc','public.sandbox_record_restore_node_topology(jsonb)','EXECUTE')"
    ).fetch_one(&owner.pool).await?;
    ensure!(
        gc_privileges == (false, false, false, false, false),
        "private GC role privilege metadata must not expose owner topology authority"
    );
    ensure!(
        preserved_source(owner, tenant, source.plan.backup.id).await? == *preserved,
        "old signed source/vault/profile/node/holds remain fully unchanged"
    );
    ensure!(
        count(owner).await? == 1,
        "all failures preserve exactly one immutable publication"
    );
    // A separate boxed helper holds only existing fixture references. It does
    // not add flags/branches to the shared restored-workspace scenario.
    Box::pin(publication::exercise(publication::PublicationCase {
        owner,
        kube,
        guard,
        cloud,
        request,
        raw,
        canonical,
        source_profile: source.f.profile,
        epoch: enrolled.node.cluster_epoch,
        backup_until,
        restore_until,
    }))
    .await?;
    ensure!(
        preserved_source(owner, tenant, source.plan.backup.id).await? == *preserved,
        "ACK/lock-wait faults preserve the original source, holds and quotas"
    );
    Ok(())
}
