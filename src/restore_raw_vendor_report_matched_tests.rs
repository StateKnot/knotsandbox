//! One legal new P/E1 → source → Q/E2 → R expectation chain. All reviewed
//! vendor images/transcripts below are SYNTHETIC EXPECTATIONS, never a Gate.
//! Source CSI/Job/Pod and OSS repository observations retain their existing
//! synthetic prerequisites; normal profile registration/activation, mTLS node
//! enrollment, SQL14, actual restore HTTP admission/readback and closed consuming
//! handoff are tested separately and are not an Alibaba cloud certification.
use super::*;
#[path = "restore_csi_live_matched_tests.rs"]
mod live_csi;
use crate::{
    backup_ledger::{
        pipeline_tests::{Pipeline, vault::complete_source_pipeline},
        tests::Fixture as BackupFixture,
    },
    backup_profile::OwnerProfileTestAssets,
    domain::InstanceAction,
    restore::{
        profile_owner::{RestoreReportRegistrationError, register_restore_report_expectations},
        vendor_profile::RestoreVendorReport,
    },
    termination_ledger::tests::{FixtureRuntime, cleanup_runtime},
};
use chrono::{DateTime, Utc};
use std::{future::Future, pin::Pin};

#[tokio::test]
#[ignore = "requires a fresh isolated PG role database, OpenSSL/Python, real local mTLS/TLS and synthetic Kubernetes/cloud protocol servers; no vendor certification"]
async fn registered_expected_report_matches_normal_source14_and_still_refuses_vendor_publication()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    boxed_run().await
}
#[inline(never)]
fn boxed_run() -> Pin<Box<dyn Future<Output = anyhow::Result<()>>>> {
    Box::pin(run())
}

type NormalSource = (
    Box<Pipeline>,
    crate::backup_object::BackupVaultVerifier,
    tempfile::TempDir,
    OwnerProfileTestAssets,
);
#[inline(never)]
fn boxed_normal_source<'a>(
    verified: &'a crate::test_support_db::VerifiedFixtureConnections,
    termination: &'a crate::test_support_db::VerifiedRuntimeDatabase,
    backup: &'a crate::test_support_db::VerifiedRuntimeDatabase,
    owner: &'a Database,
) -> Pin<Box<dyn Future<Output = anyhow::Result<NormalSource>> + 'a>> {
    Box::pin(normal_source(verified, termination, backup, owner))
}

async fn normal_source(
    verified: &crate::test_support_db::VerifiedFixtureConnections,
    termination: &crate::test_support_db::VerifiedRuntimeDatabase,
    backup: &crate::test_support_db::VerifiedRuntimeDatabase,
    owner: &Database,
) -> anyhow::Result<NormalSource> {
    let base = Box::pin(FixtureRuntime::new_with_verified_connections(
        true,
        verified,
        termination,
    ))
    .await?;
    Box::pin(base.running()).await?;
    let stop = Box::pin(base.accept(InstanceAction::Stop)).await?;
    let (proof, id) = Box::pin(base.proof(&stop)).await?;
    let (runtime, _) = cleanup_runtime(&base.launch, false);
    let cleanup = Box::pin(runtime.cleanup(&proof))
        .await?
        .context("normal source stop cleanup")?;
    Box::pin(
        base.engine
            .database
            .complete_termination(&base.engine, &stop, id, &cleanup),
    )
    .await
    .map_err(api_failure)?;
    let material = OwnerProfileTestAssets::new(base.node.cluster_epoch)?;
    Box::pin(material.activate(owner))
        .await
        .context("P normal registration/fresh verification/activation")?;
    let files = tempfile::tempdir()?;
    let private = files.path().join("public-fixture-private.pem");
    std::fs::write(&private, material.private_key())?;
    let f = Box::pin(BackupFixture::from_activated_profile(
        base,
        material.profile_id(),
        backup,
    ))
    .await?;
    let pipeline = Box::pin(Pipeline::from_fixture(f)).await?;
    pipeline.install_fixture_secret_objects(material.secret_objects()?)?;
    let (pipeline, verifier) = Box::pin(complete_source_pipeline(
        pipeline,
        &private,
        material.public_spki().to_vec(),
        files.path(),
    ))
    .await?;
    ensure!(
        pipeline.plan.backup.profile_id == material.profile_id(),
        "normal source belongs to activated P"
    );
    Ok((Box::new(pipeline), verifier, files, material))
}

struct ReportInputs<'a> {
    cloud: &'a BackupCloudSettings,
    profile: Uuid,
    epoch: Uuid,
    certification: &'a str,
    raw: &'a [u8],
    canonical: &'a str,
    reviewed: DateTime<Utc>,
    expires: DateTime<Utc>,
}
fn report_expectations(input: ReportInputs<'_>) -> anyhow::Result<Arc<RestoreVendorReport>> {
    let ReportInputs {
        cloud,
        profile,
        epoch,
        certification,
        raw,
        canonical,
        reviewed,
        expires,
    } = input;
    let (mappings, _, _) =
        crate::restore::tests::storage_mapping::fixture(cloud, profile, epoch, certification)?;
    let projection: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/restore/csi-pod-projection.synthetic.json"
    ))?;
    let lock_bytes = include_bytes!("../deploy/cluster/versions.lock.json");
    let lock: Value = serde_json::from_slice(lock_bytes)?;
    let locked: BTreeMap<String, Value> = lock["csi_images"]
        .as_object()
        .context("fixed eight image references")?
        .values()
        .map(|v| {
            Ok((
                v.as_str().context("locked image reference")?.to_owned(),
                json!("b".repeat(64)),
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let mut active = vec![];
    for entry in projection
        .as_array()
        .context("fixed two synthetic workloads")?
    {
        active.extend(
            entry["active_images"]
                .as_array()
                .context("synthetic active image expectations")?
                .iter()
                .cloned(),
        );
    }
    active.sort_by(|a, b| {
        [
            &a["workload_name"],
            &a["container_kind"],
            &a["container_name"],
        ]
        .map(Value::as_str)
        .cmp(
            &[
                &b["workload_name"],
                &b["container_kind"],
                &b["container_name"],
            ]
            .map(Value::as_str),
        )
    });
    ensure!(
        active.len() == 8 && locked.len() == 8,
        "fixed locked8 plus controller6/node2 expected containers"
    );
    let stamp = reviewed.to_rfc3339_opts(SecondsFormat::Micros, true);
    let wire: BTreeMap<String,Value> = mappings[0]["topology"]["zone_ids"].as_array().context("three approved mapping zones")?.iter().map(|zone| {
        let cases:BTreeMap<&str,Value>=["initial_pv_create","pl1_idempotent_retry","pv_status_bound","pvc_main_binding","pvc_status_bound","retain_external_finalizer_removal"]
            .into_iter().map(|name|(name,json!({"observed_at":stamp,"transcript_sha256":"4".repeat(64),"decoded_case_sha256":"5".repeat(64)}))).collect();
        Ok((zone.as_str().context("mapping zone")?.to_owned(), json!(cases)))
    }).collect::<anyhow::Result<_>>()?;
    let value = json!({"protocol":1,"bindings":{"profile_id":profile,"cluster_epoch":epoch,"backup_certification_sha256":certification,
        "storage_mappings":mappings,"account_id":cloud.account_id,"region":cloud.region,"deployment":cloud.deployment,
        "workspace_kms_key_id":"restore-compute-key","versions_lock_sha256":hex::encode(Sha256::digest(lock_bytes)),"infrastructure_sha256":canonical},
        "reviewed_at":stamp,"expires_at":expires.to_rfc3339_opts(SecondsFormat::Micros,true),
        "raw_bound_vendor":{"protocol":1,"projector_contract":"ALIYUN_RAW_WFFC_BOUND_V1","terraform_output_sha256":hex::encode(Sha256::digest(raw)),
            "controller":projection[0]["workload_expectation"],"node_plugin":projection[1]["workload_expectation"],
            "images":{"locked":locked,"active":active},"pod_projection_contract":"K8S_1_36_4_CSI_POD_V1",
            "protection":{"webhook_uid":Uuid::new_v4(),"webhook_spec_sha256":"6".repeat(64),"raw_binding_admission_contract_sha256":"7".repeat(64)},
            "wire_cases_by_zone":wire,"evidence_bundle_sha256":"8".repeat(64)}});
    Ok(Arc::new(RestoreVendorReport::parse(&serde_json::to_vec(
        &value,
    )?)?))
}

async fn register_r(
    owner: &Database,
    ordinary: &Database,
    report: &RestoreVendorReport,
    profile: Uuid,
) -> anyhow::Result<Value> {
    sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton")
        .execute(&owner.pool)
        .await?;
    let outcome = Box::pin(async {
        let approval = "PUBLIC_MATCHED_RESTORE_EXPECTATIONS_NOT_CLOUD_CERTIFICATION";
        let first = register_restore_report_expectations(owner, report, approval).await?;
        ensure!(
            first.profile_id == profile
                && first.report_sha256 == report.report_sha256()
                && !first.replayed,
            "normal owner registers fresh R derived entirely from parsed canonical bytes"
        );
        let before: Value = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM restore_profile_certifications r WHERE profile_id=$1",
        )
        .bind(profile)
        .fetch_one(&owner.pool)
        .await?;
        let again = register_restore_report_expectations(owner, report, approval).await?;
        ensure!(
            again.replayed
                && again.recorded_at == first.recorded_at
                && again.report_sha256 == first.report_sha256,
            "normal immutable replay retains original row and time"
        );
        let conflict =
            register_restore_report_expectations(owner, report, "PUBLIC_DIFFERENT_APPROVAL")
                .await
                .err()
                .context("approval cannot replace immutable R")?;
        ensure!(
            conflict == RestoreReportRegistrationError::Binding,
            "actual registration exact immutable conflict"
        );
        let denied = register_restore_report_expectations(ordinary, report, approval)
            .await
            .err()
            .context("ordinary backup cannot register R")?;
        ensure!(
            denied == RestoreReportRegistrationError::Owner,
            "owner metadata guard denies before ordinary global table access"
        );
        let after: Value = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM restore_profile_certifications r WHERE profile_id=$1",
        )
        .bind(profile)
        .fetch_one(&owner.pool)
        .await?;
        ensure!(
            before.is_object()
                && before == after
                && before["profile_id"] == json!(profile)
                && before["report_sha256"] == json!(report.report_sha256()),
            "full immutable R row unchanged by exact replay/denials"
        );
        Ok::<_, anyhow::Error>(before)
    })
    .await;
    let reset = sqlx::query("UPDATE platform_configuration SET safe_mode=false WHERE singleton")
        .execute(&owner.pool)
        .await;
    outcome.and_then(|v| {
        reset?;
        Ok(v)
    })
}

async fn matched_chain(
    source: &crate::backup_ledger::pipeline_tests::Pipeline,
    claim: &crate::engine::Claim,
    connections: (&Database, &bound_authority::hot::HotPools),
    w: &Workload,
    raw: &crate::restore::resources::RestoreStoragePlan,
    kube: &KubeFixture,
    cloud_and_report: (&AdmissionCloud, Arc<RestoreVendorReport>),
) -> anyhow::Result<()> {
    let (admission_db, hot) = connections;
    let (cloud, report) = cloud_and_report;
    let t = claim.tenant_id;
    let r = raw.context.restore_id;
    let pvc_path = format!(
        "/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/{}",
        block_pvc_name(r)
    );
    w.install(service(admission_db.clone(), w.runtime.clone()), None)?;
    let observed = Box::pin(w.runtime.reconcile_restore_block(
        &raw.context,
        &raw.cloud,
        None,
        None,
        &raw.source,
    ))
    .await?;
    ensure!(
        observed.bound.is_none() && w.reads(&pvc_path)? == 3,
        "initial missing GET then two actual admitted Pending GETs; total={}",
        w.reads(&pvc_path)?
    );
    {
        let s = w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("raw creation state"))?;
        let uid = Some(observed.pvc_uid.to_string());
        let pending = Some("Pending".to_owned());
        ensure!(
            s.raw_read_responses
                == vec![
                    (pvc_path.clone(), 404, None, None),
                    (pvc_path.clone(), 200, uid.clone(), pending.clone()),
                    (pvc_path.clone(), 200, uid, pending),
                ],
            "exact initial404 then two Pending successful GETs of observed UID: {:?}",
            s.raw_read_responses
        );
        ensure!(
            s.decisions == vec![("persistentvolumeclaims".into(), 200)]
                && s.stored == vec![pvc_path.clone()],
            "actual rawPOST passes decision before one stored parent"
        );
        ensure!(
            s.requests
                .iter()
                .filter(|(m, _)| *m == Method::POST)
                .count()
                == 1
                && s.requests
                    .iter()
                    .all(|(_, p)| !p.starts_with("/api/v1/persistentvolumes/")),
            "one CREATE, no future PV observation"
        );
    }
    source
        .f
        .backup
        .database
        .record_restore_block(&source.f.backup, claim, &observed)
        .await
        .map_err(api_failure)?;
    let job = source
        .f
        .backup
        .database
        .prepare_restore_job(&source.f.backup, claim)
        .await
        .map_err(api_failure)?;
    let (service, (config_uid, job_uid)) = Box::pin(admission::prepare(
        admission_db.clone(),
        &w.runtime,
        &job,
        &source.f.base,
        &w.objects,
    ))
    .await?;
    source
        .f
        .backup
        .database
        .record_restore_job_objects(&source.f.backup, claim, config_uid, job_uid)
        .await
        .map_err(api_failure)?;
    Box::pin(admission::verify_recorded_objects(
        &source.f.backup,
        claim,
        &source.f.base,
        t,
        r,
        config_uid,
        job_uid,
    ))
    .await?;
    w.install(service.clone(), Some(job_uid))?;
    let no_pod = Box::pin(w.runtime.start_and_observe(&job.context, job_uid, None)).await?;
    ensure!(
        no_pod.pod.is_none(),
        "real normal unsuspend PATCH still creates no Pod by itself"
    );
    let pod_name = format!("{}-sel01", backup_job_name(r, BackupStage::Restore));
    let expected = crate::backup_admission::expected_pod(&job.context, job_uid, &pod_name)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = format!("{}api/v1/namespaces/{NAMESPACE}/pods", w.server.url);
    ensure!(
        client.post(&url).json(&expected).send().await?.status() == StatusCode::CREATED,
        "actual one-shot PodCREATE must Allow then store"
    );
    ensure!(
        client.post(&url).json(&expected).send().await?.status() == StatusCode::FORBIDDEN,
        "second same-name PodCREATE cannot consume a new one-shot authority"
    );
    let actual = Box::pin(w.runtime.start_and_observe(&job.context, job_uid, None)).await?;
    let pod = actual
        .pod
        .context("actual PodLIST after successful CREATE")?;
    ensure!(
        pod.node_name.is_none() && pod.exit.is_none(),
        "Pending Pod is recorded before any node assignment/exit"
    );
    let pod_path = format!("/api/v1/namespaces/{NAMESPACE}/pods/{pod_name}");
    let stored: Value = client
        .get(format!(
            "{}{pod_path}",
            w.server.url.as_str().trim_end_matches('/')
        ))
        .send()
        .await?
        .json()
        .await?;
    ensure!(
        stored["metadata"]["uid"] == json!(pod.uid)
            && stored["metadata"]["generation"] == json!(1)
            && stored["status"] == json!({"phase":"Pending","qosClass":"Burstable"})
            && stored.pointer("/spec/nodeName").is_none()
            && stored["metadata"]["ownerReferences"][0]["uid"] == json!(job_uid),
        "actual PodGET binds server UID and real Job owner, still unassigned"
    );
    source
        .f
        .backup
        .database
        .record_restore_pod(&source.f.backup, claim, job_uid, &pod)
        .await
        .map_err(api_failure)?;
    let current = source
        .f
        .backup
        .database
        .prepare_restore_job(&source.f.backup, claim)
        .await
        .map_err(api_failure)?;
    ensure!(
        current.known_pod == Some(pod.uid),
        "normal Pod ledger refetch"
    );
    {
        let node_state = kube
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("current node state"))?;
        let mut map = w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("workload objects"))?;
        map.insert(
            format!(
                "/api/v1/nodes/{}",
                node_state.node["metadata"]["name"]
                    .as_str()
                    .context("enrolled Node name")?
            ),
            node_state.node.clone(),
        );
        map.insert(
            format!(
                "/apis/storage.k8s.io/v1/csinodes/{}",
                node_state.csi["metadata"]["name"]
                    .as_str()
                    .context("CSI name")?
            ),
            node_state.csi.clone(),
        );
    }
    let baseline = facts(&source.f.base.f.owner, t, r).await?;
    no_future(&baseline)?;
    ensure!(
        baseline["restore"]["cluster_epoch"] != baseline["source"]["cluster_epoch"],
        "current restored epoch remains separate from immutable historical source"
    );
    Box::pin(reader_privileges(source, admission_db, t, r)).await?;
    let csi = ServiceIdentity {
        username: "system:serviceaccount:kube-system:sandbox-csi-controller".into(),
        uid: Uuid::new_v4().to_string(),
    };
    {
        let mut s = w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("caller state"))?;
        s.callers.insert("select".into(), scheduler_user());
        s.callers.insert("provision".into(), control_user());
        s.callers.insert(
            "reset".into(),
            json!({"username":csi.username,"uid":csi.uid}),
        );
        s.callers.insert("wrong-scheduler".into(),json!({"username":"system:kube-scheduler","uid":Uuid::new_v4(),"groups":["system:authenticated"]}));
        s.callers.insert(
            "wrong-csi".into(),
            json!({"username":csi.username,"uid":Uuid::new_v4()}),
        );
        s.callers.insert("backup".into(), user(&service));
    }
    boxed_matched_case(
        SelectedCase {
            source,
            claim,
            t,
            r,
            pvc_path: &pvc_path,
            pod_path: &pod_path,
            job: &current,
            service: &service,
            csi: &csi,
            w,
            cloud,
            hot,
            baseline: &baseline,
        },
        report,
    )
    .await?;
    Ok(())
}

#[inline(never)]
fn boxed_matched_case<'a>(
    case: SelectedCase<'a>,
    report: Arc<RestoreVendorReport>,
) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
    Box::pin(matched_case(case, report))
}

async fn matched_case(
    case: SelectedCase<'_>,
    report: Arc<RestoreVendorReport>,
) -> anyhow::Result<()> {
    let node_hint = {
        let s = case
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("live registered Node objects"))?;
        s.iter()
            .find(|(path, _)| path.starts_with("/api/v1/nodes/"))
            .and_then(|(_, v)| v["metadata"]["name"].as_str())
            .context("current registered Node name")?
            .to_owned()
    };
    case.configure(0, Fault::None)?;
    Box::pin(case.put(
        "select",
        case.changed(|v| selected(v, &node_hint))?,
        StatusCode::OK,
    ))
    .await?;
    let selected_rounds = case.complete_rounds(true);
    if selected_rounds.is_err() && case.safe_diagnostics().is_err() {
        eprintln!("PRIVATE matched SELECT fixed diagnostic collection failed");
    }
    selected_rounds
        .context("matched SELECT must reach two current Node/CSI and workload GET rounds")?;
    case.configure(0, Fault::None)?;
    Box::pin(case.put("provision", case.changed(provision)?, StatusCode::OK)).await?;
    // PROVISIONER, like SELECT, observes the current node twice. Only the
    // distinct RESET metadata purpose intentionally requires no Node/CSI GET.
    let provisioner_rounds = case.complete_rounds(true);
    if provisioner_rounds.is_err() && case.safe_diagnostics().is_err() {
        eprintln!("PRIVATE matched PROVISIONER fixed diagnostic collection failed");
    }
    provisioner_rounds
        .context("matched PROVISIONER must reach two current Node/CSI and workload GET rounds")?;
    let original = case.w.get(case.pvc_path)?;
    let engine = &case.source.f.backup;
    ensure!(
        engine.heartbeat(case.claim).await.map_err(api_failure)?,
        "current claim before matched sealed14 setup read"
    );
    let attempt = RawBoundAttempt::start();
    let pvcs = kube::Api::<k8s_openapi::api::core::v1::PersistentVolumeClaim>::namespaced(
        case.w.runtime.runtime().client_clone(),
        NAMESPACE,
    );
    let locator = pvcs.get(&block_pvc_name(case.r)).await?;
    let hint = locator
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(SELECTED))
        .context("actual selected-node locator")?;
    ensure!(
        hint == &node_hint,
        "locator corresponds to current enrolled node"
    );
    let first = Box::pin(
        engine
            .database
            .prepare_restore_bound_authority(&attempt, engine, case.claim, case.r, hint),
    )
    .await
    .map_err(api_failure)?;
    let shape = first
        .backup_disk_scope(&attempt, engine, case.claim)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    report
        .compare_scope(&shape)
        .context("new registered R matches genuine current sealed14 scope")?;
    ensure!(
        shape.collection().recorded.is_none(),
        "matched report cannot seed future target disk receipt"
    );
    Box::pin(absent_companion(&case)).await?;
    let envelope = Box::pin(envelope(&case, hint)).await?;
    ensure!(
        envelope["pin"]["record"]["profile_id"]
            == json!(shape.collection().storage.storage_contract.profile_id)
            && envelope["pin"]["record"]["cluster_epoch"]
                != envelope["pin"]["source_storage"]["source"]["cluster_epoch"],
        "real source14 remains historical P/E1 and target current Q/E2"
    );
    let wire = DiskWire::from_scope(&shape);
    let cloud = DiskCloud::new(
        wire,
        &shape.collection().cloud_settings.issuer,
        &shape.collection().cloud_settings.oidc_provider_arn,
    )
    .await?;
    let pv = raw_pv(&shape, &cloud.wire, Uuid::new_v4());
    let pvc = bound_pvc(&original, &shape);
    let pv_path = format!("/api/v1/persistentvolumes/{}", shape.facts().pv_name);
    let previous = case
        .w
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("previous synthetic PV"))?
        .get(&pv_path)
        .cloned();
    let outcome = boxed_consume(&case, &cloud, &shape, &pvc, &pv, report).await;
    let restore = (|| -> anyhow::Result<()> {
        let mut objects = case
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("restore HTTP fixture objects"))?;
        objects.insert(case.pvc_path.into(), original);
        if let Some(previous) = previous {
            objects.insert(pv_path, previous);
        } else {
            objects.remove(&pv_path);
        }
        Ok(())
    })();
    let closed = cloud.finish().await;
    if restore.is_err() {
        eprintln!("PRIVATE matched fixture object restoration failed; not certified restored");
    }
    if closed.is_err() {
        eprintln!("PRIVATE matched fixture cloud drain failed; not certified drained");
    }
    outcome?;
    restore?;
    closed?;
    Box::pin(unchanged(&case)).await?;
    Ok(())
}
#[inline(never)]
fn boxed_consume<'a, 'fixture: 'a>(
    case: &'a SelectedCase<'fixture>,
    cloud: &'a DiskCloud,
    shape: &'a RawBoundDiskScope,
    pvc: &'a Value,
    pv: &'a Value,
    report: Arc<RestoreVendorReport>,
) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
    Box::pin(consume_matched(case, cloud, shape, pvc, pv, report))
}
async fn consume_matched(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    shape: &RawBoundDiskScope,
    pvc: &Value,
    pv: &Value,
    report: Arc<RestoreVendorReport>,
) -> anyhow::Result<()> {
    case.configure(0, Fault::None)?;
    cloud.reset(0)?;
    replace(case, case.pvc_path, pvc.clone())?;
    replace(
        case,
        &format!("/api/v1/persistentvolumes/{}", shape.facts().pv_name),
        pv.clone(),
    )?;
    let engine = &case.source.f.backup;
    ensure!(
        engine.heartbeat(case.claim).await.map_err(api_failure)?,
        "current claim before configured matched collector"
    );
    let collector = BackupRawBoundCollector::for_loopback_test(
        case.w.runtime.clone(),
        cloud.config()?,
        cloud.server.url.clone(),
    )
    .map_err(api_failure)?
    .with_vendor_report(Some(report.clone()));
    let owned =
        Box::pin(collector.observe_pending_restore(&engine.database, engine, case.claim, case.r))
            .await
            .map_err(api_failure)?;
    owned.current(engine, case.claim).map_err(api_failure)?;
    ensure!(
        owned.projection().parent_uid() == shape.facts().pvc_uid
            && owned.projection().name() == shape.facts().pv_name
            && owned.projection().uid().to_string()
                == pv["metadata"]["uid"].as_str().context("actual PVGET UID")?,
        "real producer-owned Bound projection, not a scope/proof constructor"
    );
    cloud.exact_actions(2)?;
    reads(case, shape, 2, 3)?;
    Box::pin(unchanged(case)).await?;
    let denial = Box::pin(owned.refuse_unverified_publication(engine, case.claim))
        .await
        .err()
        .context("registered/matched EXPECTATIONS remain missing vendor capability")?;
    ensure!(
        denial.status == StatusCode::FORBIDDEN
            && denial.code == "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED"
            && denial.detail == "Raw restore volume vendor certification unavailable",
        "matched report passes final comparison then reaches exact missing vendor403, never unrelated runtime/authority/dependency denial"
    );
    Box::pin(crate::restore::raw_bound_collector::handoff_tests::no_open_transactions(engine))
        .await?;
    cloud.exact_actions(2)?;
    reads(case, shape, 2, 3)?;
    Box::pin(unchanged(case)).await?;
    Box::pin(live_csi::run(case, cloud, shape, pvc, pv, report)).await?;
    eprintln!(
        "VERIFIED private registered expected report matches normal Source14: P/E1 registered+freshly activated/source completed; Q/E2 same generated Secret material independently reverified+activated; R normal owner immutable register/replay; real restore Pending/Job/oncePod+enrollment/topology and sealed14 report comparison; actual opaque two Bound GET rounds/twice fresh signed cloud then exact missing vendor403 with rollback; zero target publication/host permit, synthetic prerequisite/image/transcript expectations are not vendor/cloud certification"
    );
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let parsed = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        parsed
            .path()
            .strip_prefix("/sandbox_restore_acceptance_")
            .and_then(|p| p.strip_suffix("_test"))
            .is_some_and(|p| !p.is_empty()
                && p.len() <= 20
                && p.bytes().all(|c| c.is_ascii_digit())),
        "dedicated fresh restore acceptance database"
    );
    let verified = test_support_db::Fixture::prepare_verified_connections().await?;
    let owner = Database {
        pool: verified.owner(),
    };
    for grant in [
        include_str!("../scripts/sql/worker-role.sql"),
        include_str!("../scripts/sql/gateway-role.sql"),
        include_str!("../scripts/sql/admission-role.sql"),
        include_str!("../scripts/sql/termination-role.sql"),
        include_str!("../scripts/sql/fencing-role.sql"),
        include_str!("../scripts/sql/volume-deleter-role.sql"),
        include_str!("../scripts/sql/backup-role.sql"),
    ] {
        sqlx::raw_sql(grant).execute(&owner.pool).await?;
    }
    let termination = verified
        .runtime("TEST_TERMINATION_DATABASE_URL", "sandbox_termination", 4)
        .await?;
    let backup = verified
        .runtime("TEST_BACKUP_DATABASE_URL", "sandbox_backup", 4)
        .await?;
    let admission_role = verified
        .runtime("TEST_ADMISSION_DATABASE_URL", "sandbox_admission", 4)
        .await?;
    let admission_db = admission_role.database_for("sandbox_admission")?;
    let (source, verifier, _files, material) =
        boxed_normal_source(&verified, &termination, &backup, &owner).await?;
    let preserved_source: Value = {
        let mut tx = source.f.base.f.owner_transaction().await?;
        let row=sqlx::query_scalar("SELECT jsonb_build_object('profile',to_jsonb(p),'actions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM backup_profile_actions a WHERE a.profile_id=p.id),'backup',to_jsonb(b),'vault',to_jsonb(v),'clone',to_jsonb(c),'instance',to_jsonb(i),'workspace',to_jsonb(w)) FROM backup_profiles p JOIN backups b ON b.profile_id=p.id JOIN backup_vault_receipts v ON v.tenant_id=b.tenant_id AND v.backup_id=b.id JOIN backup_clone_receipts c ON c.tenant_id=b.tenant_id AND c.backup_id=b.id AND c.attempt_id=b.capture_attempt_id JOIN instances i ON i.tenant_id=b.tenant_id AND i.id=b.instance_id JOIN workspaces w ON w.tenant_id=b.tenant_id AND w.id=b.workspace_id WHERE p.id=$1 AND b.id=$2")
            .bind(material.profile_id()).bind(source.plan.backup.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        row
    };
    ensure!(
        preserved_source.is_object()
            && [
                "profile",
                "backup",
                "vault",
                "clone",
                "instance",
                "workspace"
            ]
            .into_iter()
            .all(|k| preserved_source[k].is_object())
            && preserved_source["backup"]["status"] == json!("AVAILABLE")
            && preserved_source["profile"]["enabled"] == json!(true)
            && preserved_source["actions"]
                .as_array()
                .is_some_and(|v| v.len() == 2),
        "normal P/source immutable whole rows exist, not null==null"
    );
    let mut binding = node();
    binding.cluster_epoch = Uuid::new_v4();
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(binding.cluster_epoch)
        .execute(&owner.pool)
        .await?;
    let current = material.reissue(binding.cluster_epoch)?;
    Box::pin(current.activate(&owner))
        .await
        .context("Q independently obtains fresh exact Kube/retention capabilities")?;
    ensure!(
        current.cloud() == material.cloud()
            && current.public_spki() == material.public_spki()
            && current.private_key() == material.private_key(),
        "P/Q exact generated Secret bytes/UID settings preserved without copying opaque proof"
    );
    let hot = bound_authority::hot::HotPools::prepare(
        &verified,
        &admission_db,
        &source.f.backup.database,
    )
    .await?;
    let result = boxed_current_restore(
        &source,
        &verifier,
        &current,
        &owner,
        (&verified, &admission_role),
        (&admission_db, &hot),
        binding,
    )
    .await;
    let hot_closed = hot.finish().await;
    let source_closed = source.f.base.guard.shutdown().await;
    if hot_closed.is_err() {
        eprintln!("PRIVATE matched hot pools physical absence failed; not certified drained");
    }
    if source_closed.is_err() {
        eprintln!(
            "PRIVATE matched historical source nodeguard cleanup failed; not certified drained"
        );
    }
    result?;
    hot_closed?;
    source_closed?;
    let after: Value = {
        let mut tx = source.f.base.f.owner_transaction().await?;
        let row=sqlx::query_scalar("SELECT jsonb_build_object('profile',to_jsonb(p),'actions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM backup_profile_actions a WHERE a.profile_id=p.id),'backup',to_jsonb(b),'vault',to_jsonb(v),'clone',to_jsonb(c),'instance',to_jsonb(i),'workspace',to_jsonb(w)) FROM backup_profiles p JOIN backups b ON b.profile_id=p.id JOIN backup_vault_receipts v ON v.tenant_id=b.tenant_id AND v.backup_id=b.id JOIN backup_clone_receipts c ON c.tenant_id=b.tenant_id AND c.backup_id=b.id AND c.attempt_id=b.capture_attempt_id JOIN instances i ON i.tenant_id=b.tenant_id AND i.id=b.instance_id JOIN workspaces w ON w.tenant_id=b.tenant_id AND w.id=b.workspace_id WHERE p.id=$1 AND b.id=$2")
            .bind(material.profile_id()).bind(source.plan.backup.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        row
    };
    // The whole source snapshot predates the private schema38 installation.
    // Its sole new workspaces column must remain NULL; every original value is
    // still compared, including the complete historical profile and receipts.
    let mut expected = preserved_source.clone();
    let workspace = expected["workspace"]
        .as_object_mut()
        .context("formal37 source workspace whole object")?;
    ensure!(
        !workspace.contains_key("restore_snapshot_name"),
        "formal37 source workspace has no private38 snapshot column"
    );
    workspace.insert("restore_snapshot_name".into(), Value::Null);
    ensure!(
        after == expected,
        "P/source full immutable rows preserve every original value and the sole private38 schema-added NULL workspace column"
    );
    println!(
        "VERIFIED matched full source formal37-to-private38 schema evolution: only the documented restore_snapshot_name NULL key is added; all original whole profile/actions/backup/vault/clone/instance/workspace fields remain unchanged"
    );
    Ok(())
}

#[inline(never)]
fn boxed_current_restore<'a>(
    source: &'a Pipeline,
    verifier: &'a crate::backup_object::BackupVaultVerifier,
    current: &'a OwnerProfileTestAssets,
    owner: &'a Database,
    verified: (
        &'a crate::test_support_db::VerifiedFixtureConnections,
        &'a crate::test_support_db::VerifiedRuntimeDatabase,
    ),
    runtime: (&'a Database, &'a bound_authority::hot::HotPools),
    binding: crate::nodeguard::protocol::NodeBinding,
) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
    Box::pin(current_restore(
        source, verifier, current, owner, verified, runtime, binding,
    ))
}
#[inline(never)]
fn boxed_matched_chain<'a>(
    source: &'a Pipeline,
    claim: &'a crate::engine::Claim,
    connections: (&'a Database, &'a bound_authority::hot::HotPools),
    w: &'a Workload,
    raw: &'a crate::restore::resources::RestoreStoragePlan,
    kube: &'a KubeFixture,
    cloud_and_report: (&'a AdmissionCloud, Arc<RestoreVendorReport>),
) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
    Box::pin(matched_chain(
        source,
        claim,
        connections,
        w,
        raw,
        kube,
        cloud_and_report,
    ))
}

async fn current_restore(
    source: &Pipeline,
    verifier: &crate::backup_object::BackupVaultVerifier,
    current: &OwnerProfileTestAssets,
    owner: &Database,
    verified: (
        &crate::test_support_db::VerifiedFixtureConnections,
        &crate::test_support_db::VerifiedRuntimeDatabase,
    ),
    runtime: (&Database, &bound_authority::hot::HotPools),
    binding: crate::nodeguard::protocol::NodeBinding,
) -> anyhow::Result<()> {
    let (verified, admission_role) = verified;
    let (admission_db, hot) = runtime;
    let mut tx = owner.pool.begin().await?;
    for ddl in [
        include_str!("../tests/fixtures/restore/0038_restores.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_control_admission.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_parent_admission.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_node_topology.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_scheduling_admission.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_disk_receipts.sql"),
        include_str!("../tests/fixtures/restore/0038_restore_raw_bound_authority.sql"),
    ] {
        sqlx::raw_sql(ddl).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    sqlx::raw_sql(include_str!("../scripts/sql/restore-role.sql"))
        .execute(&owner.pool)
        .await?;
    verified.clear_statement_caches().await?;
    admission_role.clear_statement_caches().await?;
    hot.clear_after_draft().await?;
    clear(&[
        &source.f.base.f.database.pool,
        &source.f.base.engine.database.pool,
        &source.f.backup.database.pool,
    ])
    .await?;
    for db in [
        &source.f.base.f.database,
        &source.f.backup.database,
        admission_db,
    ] {
        let e = db
            .verify_runtime_role()
            .await
            .err()
            .context("private38 remains closed for production startup")?;
        ensure!(
            e.to_string().contains("successful ordered migration 0038"),
            "private draft gate, not weakened normal login checks"
        );
    }
    let cloud: BackupCloudSettings = serde_json::from_value(current.cloud().clone())?;
    let cloud_binding = NodeTopologyCloudBinding {
        account_id: cloud.account_id.clone(),
        region: cloud.region.clone(),
        instance_id: format!("i-matched{}", Uuid::new_v4().simple()),
        zone_id: format!("{}-a", cloud.region),
        vpc_id: "vpc-publictopology".into(),
        vswitch_id: "vsw-zonea".into(),
        private_ip: "10.0.0.8".parse()?,
        deployment: cloud.deployment.clone(),
    };
    let tf = terraform(&binding, &cloud_binding);
    let raw = serde_json::to_vec_pretty(&tf)?;
    let canonical = canonical_sha(&raw)?;
    let report_reviewed = DateTime::parse_from_rfc3339(
        &(Utc::now() - Days::seconds(1)).to_rfc3339_opts(SecondsFormat::Micros, true),
    )?
    .with_timezone(&Utc);
    let expires = report_reviewed + Days::hours(12);
    let certification:String=sqlx::query_scalar("SELECT certification_sha256 FROM backup_profiles WHERE id=$1 AND enabled AND cluster_epoch=$2")
        .bind(current.profile_id()).bind(binding.cluster_epoch).fetch_one(&owner.pool).await?;
    let report = report_expectations(ReportInputs {
        cloud: &cloud,
        profile: current.profile_id(),
        epoch: binding.cluster_epoch,
        certification: &certification,
        raw: &raw,
        canonical: &canonical,
        reviewed: report_reviewed,
        expires,
    })?;
    let immutable_r = Box::pin(register_r(
        owner,
        &source.f.backup.database,
        &report,
        current.profile_id(),
    ))
    .await?;
    let plan = enrollment_plan(
        &binding,
        &cloud_binding,
        &tf,
        &raw,
        Utc::now() + Days::hours(18),
    )?;
    let kube = KubeFixture::new(&binding, &cloud_binding).await?;
    {
        let mut state = kube
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("current Node/CSI metadata"))?;
        let created = json!(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        state.node["metadata"]["creationTimestamp"] = created.clone();
        state.csi["metadata"]["creationTimestamp"] = created;
    }
    let guard = FixtureGuard::start(binding.clone()).await?;
    let owner_cloud = CloudFixture::new(cloud_binding.clone()).await?;
    let admission_cloud = AdmissionCloud::new(cloud_binding).await?;
    let outcome=Box::pin(async {
        let enrolled=Box::pin(enroll_with_client_test(owner,kube.runtime.runtime(),&guard.client,&plan)).await?;
        ensure!(enrolled.enabled&&enrolled.changed,"normal new Q/E2 mTLS enrollment, no inserted live-node seed");
        kube.eligible()?;
        let topology=Box::pin(collect_with_client(owner,&kube.runtime,&guard.client,&owner_cloud.client(0)?,NodeTopologyRequest{
            runtime_node_id:enrolled.runtime_node_id,enrollment_id:enrolled.enrollment_id,restore_profile_id:current.profile_id()},&raw)).await?;
        Box::pin(record_node_topology(owner,&topology)).await?;
        let actual_topology:Value=sqlx::query_scalar("SELECT to_jsonb(t) FROM restore_node_topology_receipts t WHERE restore_profile_id=$1 AND runtime_node_id=$2 AND enrollment_id=$3")
            .bind(current.profile_id()).bind(enrolled.runtime_node_id).bind(enrolled.enrollment_id).fetch_one(&owner.pool).await?;
        ensure!(actual_topology.is_object()&&actual_topology["terraform_output_sha256"]==json!(hex::encode(Sha256::digest(&raw)))
            && actual_topology["infrastructure_sha256"]==json!(canonical)
            && actual_topology["restore_report_sha256"]==json!(report.report_sha256()),"normal sealed owner topology binds both actual TF byte/canonical hashes and R bytes");
        let target=Uuid::new_v4();let security=Uuid::new_v4();
        let mut tx=source.f.base.f.owner_transaction().await?;
        sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,'Matched report target',86400,$3,'integration-storage')")
            .bind(target).bind(source.f.base.f.actor.tenant_id).bind(format!("matched-{}",target.simple())).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) SELECT tenant_id,$2,dimension,limit_value FROM quota_accounts WHERE tenant_id=$1 AND project_id=$3")
            .bind(source.f.base.f.actor.tenant_id).bind(target).bind(source.f.base.launch.project_id).execute(&mut *tx).await?;
        for (project,action) in [(None,"backups:restore"),(Some(source.f.base.launch.project_id),"backups:restore"),(None,"instances:create"),(Some(target),"instances:create"),(None,"restores:read"),(Some(target),"restores:read")] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(source.f.base.f.actor.tenant_id).bind(project).bind(source.f.base.f.actor.principal_id).bind(action).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'matched-runtime',1,'APPROVED',$3)")
            .bind(security).bind(source.f.base.f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO launch_guard_contracts(id,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,approval_reference,valid_until) VALUES($1,$2,'NODEGUARD_REQUIRED_V1',$3,$4,'PUBLIC_MATCHED_TEST_ONLY',clock_timestamp()+interval '1 day')")
            .bind(Uuid::new_v4()).bind(binding.cluster_epoch).bind("a".repeat(64)).bind(vec![enrolled.runtime_node_id]).execute(&mut *tx).await?;
        let version:i64=sqlx::query_scalar("SELECT version FROM backups WHERE tenant_id=$1 AND id=$2").bind(source.f.base.f.actor.tenant_id).bind(source.plan.backup.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        let delegated=grants::create(&source.f.base.f.database,&source.f.base.f.owner,&source.f.base.f.actor,source.f.base.launch.project_id,target).await?;
        source.f.base.f.database.update_project_grant(&source.f.base.f.actor,source.f.base.launch.project_id,delegated.source_restore.id,
            &crate::grants::UpdateGrant{enabled:true,expires_at:Some(Utc::now()+Days::hours(1))},"matched-renew-source-grant",delegated.source_restore.version).await.map_err(api_failure)?;
        let accepted=source.f.base.f.database.create_restore(&delegated.actor,source.plan.backup.id,&CreateRestore{
            target_project_id:target,name:"matched-workspace".into(),profile_id:current.profile_id(),template_version_id:source.f.base.f.request.template_version_id,
            security_profile_id:security,flavor:Flavor::Cpu2Mem4},"matched-restore",version).await.map_err(api_failure)?;
        let claim=source.f.backup.claim_backup().await.map_err(api_failure)?.context("normal restore claim")?;
        ensure!(claim.operation_id==accepted.body.operation.id,"same normal management operation");
        let vault=source.f.backup.database.prepare_restore_verification(&source.f.backup,&claim).await.map_err(api_failure)?;
        let verified_vault=Box::pin(verifier.verify(&vault.expectation)).await?;
        source.f.backup.database.record_restore_verification(&source.f.backup,&claim,&verified_vault).await.map_err(api_failure)?;
        let raw_plan=source.f.backup.database.prepare_restore_storage(&source.f.backup,&claim).await.map_err(api_failure)?;
        ensure!(raw_plan.context.storage_contract.report_sha256==report.report_sha256()
            && raw_plan.context.storage_contract.profile_id==current.profile_id(),"normal CreateRestore froze registered R bytes and mapping, not supplied scope");
        let mut objects=support(&raw_plan.cloud,classes(&raw_plan.context.storage_contract));
        objects.extend(current.secret_objects()?);
        let workload=Workload::start(objects).await?;
        let business=boxed_matched_chain(source,&claim,(admission_db,hot),&workload,&raw_plan,&kube,(&admission_cloud,report.clone())).await;
        let drained=workload.finish().await;
        if drained.is_err(){eprintln!("PRIVATE matched workload drain failed; not certified drained");}
        business?;drained?;
        let after_r:Value=sqlx::query_scalar("SELECT to_jsonb(r) FROM restore_profile_certifications r WHERE profile_id=$1").bind(current.profile_id()).fetch_one(&owner.pool).await?;
        ensure!(after_r==immutable_r,"full R immutable row unchanged by normal restore/consumer");
        Ok::<_,anyhow::Error>(())
    }).await;
    let admission_closed = admission_cloud.finish().await;
    let owner_closed = owner_cloud.finish().await;
    let kube_closed = kube.finish().await;
    let node_closed = guard.shutdown().await;
    for (name, failed) in [
        ("admissionCloud", admission_closed.is_err()),
        ("ownerCloud", owner_closed.is_err()),
        ("Kube", kube_closed.is_err()),
        ("currentNodeguard", node_closed.is_err()),
    ] {
        if failed {
            eprintln!("PRIVATE matched fixture cleanup failed {name}; not certified drained");
        }
    }
    outcome?;
    admission_closed?;
    owner_closed?;
    kube_closed?;
    node_closed?;
    Ok(())
}
