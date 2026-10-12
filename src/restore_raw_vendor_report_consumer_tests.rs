//! Normal closed consumer only. The report assembled here is synthetic expected
//! data, never an owner certification, live vendor Gate or writer permission.
use super::*;
use crate::restore::{
    admission::RawBoundAttempt,
    vendor_profile::{RestoreVendorReport, VendorReportError},
};
use std::{collections::BTreeMap, sync::Arc};

async fn expectations(case: &SelectedCase<'_>) -> anyhow::Result<Arc<RestoreVendorReport>> {
    let engine = &case.source.f.backup;
    ensure!(
        engine.heartbeat(case.claim).await.map_err(api_failure)?,
        "normal current claim before separate report fixture read"
    );
    // This separate genuine normal-role read provides expectation shape only.
    // Neither it nor its facts is supplied to the actual configured collector.
    let attempt = RawBoundAttempt::start();
    let client = case.w.runtime.runtime().client_clone();
    let pvcs = kube::Api::<k8s_openapi::api::core::v1::PersistentVolumeClaim>::namespaced(
        client, NAMESPACE,
    );
    let locator = pvcs.get(&block_pvc_name(case.r)).await?;
    let hint = locator
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get("volume.kubernetes.io/selected-node"))
        .context("actual report fixture locator selected-node")?;
    let first = engine
        .database
        .prepare_restore_bound_authority(&attempt, engine, case.claim, case.r, hint)
        .await
        .map_err(api_failure)?;
    let scope = first
        .backup_disk_scope(&attempt, engine, case.claim)
        .map_err(|_| anyhow::anyhow!("real normal14 report fixture scope"))?;
    let facts = scope
        .vendor_facts()
        .map_err(|_| anyhow::anyhow!("real sealed report comparison facts"))?;
    let contract = &scope.collection().storage.storage_contract;
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    // Read the actually installed legacy expected report, never mutate the
    // append-only certification/profile/enrollment or use owner as collector.
    let legacy:Value=sqlx::query_scalar("SELECT report FROM restore_profile_certifications WHERE profile_id=$1 AND cluster_epoch=$2 AND report_sha256=$3")
        .bind(contract.profile_id).bind(contract.cluster_epoch).bind(&contract.report_sha256)
        .fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let legacy_bytes = serde_json::to_vec(&legacy)?;
    ensure!(
        matches!(
            RestoreVendorReport::parse(&legacy_bytes),
            Err(VendorReportError::Unavailable)
        ),
        "actual installed legacy report has no raw vendor member; not a fabricated legacy fixture"
    );
    let bindings = legacy
        .get("bindings")
        .context("actual legacy ten bindings")?
        .clone();
    ensure!(
        bindings.as_object().is_some_and(|v| v.len() == 10),
        "actual existing report bindings10 retained whole"
    );
    let lock_bytes = include_bytes!("../deploy/cluster/versions.lock.json");
    let lock: Value = serde_json::from_slice(lock_bytes)?;
    let refs = lock["csi_images"]
        .as_object()
        .context("actual fixed locked8")?;
    let locked: BTreeMap<String, Value> = refs
        .values()
        .map(|v| {
            Ok((
                v.as_str().context("fixed image ref")?.to_owned(),
                json!("1".repeat(64)),
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let image = refs
        .get("registry.cn-hangzhou.aliyuncs.com/acs/csi-plugin:v1.37.2")
        .and_then(Value::as_str)
        .context("fixed driver image")?;
    let workload = |kind: &str, name: &str, sa: &str| {
        json!({"kind":kind,"namespace":"kube-system","name":name,
        "uid":Uuid::new_v4(),"service_account_name":sa,"service_account_uid":Uuid::new_v4(),"spec_sha256":"2".repeat(64)})
    };
    let active=["csi-plugin","csi-provisioner"].map(|name|json!({"workload_name":name,"container_kind":"regular",
        "container_name":"csi-plugin","image_ref":image,"platform_descriptor_sha256":"3".repeat(64),"runtime_image_id":image}));
    let reviewed = facts
        .reviewed_at()
        .to_rfc3339_opts(SecondsFormat::Micros, true);
    let wire:BTreeMap<String,Value>=contract.mapping.topology.zone_ids.iter().map(|zone|{
        let cases:BTreeMap<&str,Value>=["initial_pv_create","pl1_idempotent_retry","pv_status_bound","pvc_main_binding","pvc_status_bound","retain_external_finalizer_removal"]
            .into_iter().map(|name|(name,json!({"observed_at":reviewed,"transcript_sha256":"4".repeat(64),"decoded_case_sha256":"5".repeat(64)}))).collect();
        (zone.clone(),json!(cases))
    }).collect();
    let expected = json!({"protocol":1,"bindings":bindings,"reviewed_at":reviewed,
        "expires_at":facts.certified_until().to_rfc3339_opts(SecondsFormat::Micros,true),
        "raw_bound_vendor":{"protocol":1,"projector_contract":"ALIYUN_RAW_WFFC_BOUND_V1",
            "terraform_output_sha256":facts.terraform_output_sha256(),
            "controller":workload("Deployment","csi-provisioner","sandbox-csi-controller"),
            "node_plugin":workload("DaemonSet","csi-plugin","sandbox-csi-node"),
            "images":{"locked":locked,"active":active},"pod_projection_contract":"K8S_1_36_4_CSI_POD_V1",
            "protection":{"webhook_uid":Uuid::new_v4(),"webhook_spec_sha256":"6".repeat(64),"raw_binding_admission_contract_sha256":"7".repeat(64)},
            "wire_cases_by_zone":wire,"evidence_bundle_sha256":"8".repeat(64)}});
    ensure!(
        expected["bindings"]["versions_lock_sha256"].as_str()
            == Some(hex::encode(Sha256::digest(lock_bytes)).as_str()),
        "real installed legacy bindings use this exact source lock SHA"
    );
    let parsed = RestoreVendorReport::parse(&serde_json::to_vec(&expected)?)?;
    ensure!(
        parsed.report_sha256() != facts.report_sha256(),
        "synthetic vendor expectations were never registered over immutable legacy cert SHA"
    );
    ensure!(
        matches!(
            parsed.compare_scope(&scope),
            Err(VendorReportError::Binding)
        ),
        "valid parsed expectations reach real sealed14 comparison and differ at immutable report bytes SHA"
    );
    attempt.current().map_err(|_| {
        anyhow::anyhow!(
            "report fixture original attempt remains current after pure parse/comparison"
        )
    })?;
    // No owner INSERT/UPDATE/DELETE, certificate, scope constructor or new future
    // row. The resulting Arc is only expected config for a NEW normal attempt.
    Ok(Arc::new(parsed))
}

async fn consume(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    shape: &RawBoundDiskScope,
    expected: Option<Arc<RestoreVendorReport>>,
    code: &str,
) -> anyhow::Result<()> {
    case.configure(0, Fault::None)?;
    cloud.reset(0)?;
    let engine = &case.source.f.backup;
    ensure!(
        engine.heartbeat(case.claim).await.map_err(api_failure)?,
        "normal current worker heartbeat before actual report consumer attempt"
    );
    let collector = BackupRawBoundCollector::for_loopback_test(
        case.w.runtime.clone(),
        cloud.config()?,
        cloud.server.url.clone(),
    )
    .map_err(api_failure)?
    .with_vendor_report(expected);
    let owned =
        Box::pin(collector.observe_pending_restore(&engine.database, engine, case.claim, case.r))
            .await
            .map_err(api_failure)?;
    owned.current(engine, case.claim).map_err(api_failure)?;
    ensure!(
        owned.projection().parent_uid() == shape.facts().pvc_uid
            && owned.projection().name() == shape.facts().pv_name,
        "configured normal producer supplied genuine opaque Bound observation, not a dummy constructor"
    );
    cloud.exact_actions(2)?;
    reads(case, shape, 2, 3)?;
    let refusal = Box::pin(owned.refuse_unverified_publication(engine, case.claim))
        .await
        .err()
        .context("actual configured consumer never publishes")?;
    ensure!(
        refusal.status == StatusCode::FORBIDDEN && refusal.code == code,
        "actual configured consumer reaches exact report/vendor refusal after same-TX validation/rollback, not dependency or UNKNOWN"
    );
    crate::restore::raw_bound_collector::handoff_tests::no_open_transactions(engine).await?;
    cloud.exact_actions(2)?;
    reads(case, shape, 2, 3)?;
    unchanged(case).await?;
    Ok(())
}

pub(super) async fn run(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    shape: &RawBoundDiskScope,
) -> anyhow::Result<()> {
    let expected = Box::pin(expectations(case)).await?;
    Box::pin(consume(
        case,
        cloud,
        shape,
        None,
        "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED",
    ))
    .await?;
    Box::pin(consume(
        case,
        cloud,
        shape,
        Some(expected),
        "RESTORE_RAW_VENDOR_RUNTIME_BLOCKED",
    ))
    .await?;
    unchanged(case).await?;
    eprintln!(
        "VERIFIED private normal vendor-report consumer: actual legacy unavailable, defaultNone vendor403, valid synthetic expected report versus immutable real sealed14 SHA runtime403; each normal producer two Bound GET rounds/twice fresh cloud, same closed consuming transaction/rollback; no matched certification, publication or host permit"
    );
    Ok(())
}
