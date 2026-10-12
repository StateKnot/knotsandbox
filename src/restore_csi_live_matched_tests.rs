//! Actual outer normal Source14/current-claim consumption. CSI workload/Pod
//! observations remain fixed synthetic HTTP stand-ins, not installed vendor
//! certification. Enrolled Node/CSINode and SQL authority are NOT replaced.
use super::*;
use crate::restore::{
    raw_bound_collector::csi_live_fixture::{fixture, for_actual_node},
    vendor_profile::VendorActiveImageExpectation,
};
type ImageKey = (String, String, String);
type Images = BTreeMap<ImageKey, Value>;
fn keyed(images: &[VendorActiveImageExpectation]) -> anyhow::Result<Images> {
    images
        .iter()
        .map(|image| {
            Ok((
                (
                    image.workload_name.clone(),
                    image.container_kind.clone(),
                    image.container_name.clone(),
                ),
                serde_json::to_value(image)?,
            ))
        })
        .collect()
}

pub(super) async fn run(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    shape: &RawBoundDiskScope,
    pvc: &Value,
    pv: &Value,
    report: Arc<RestoreVendorReport>,
) -> anyhow::Result<()> {
    let node_path = format!("/api/v1/nodes/{}", shape.facts().node.node_name);
    let csi_path = format!(
        "/apis/storage.k8s.io/v1/csinodes/{}",
        shape.facts().node.node_name
    );
    let (original_node, original_csi) = {
        let map = case
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("actual enrolled objects"))?;
        (
            map.get(&node_path).context("actual enrolled Node")?.clone(),
            map.get(&csi_path)
                .context("actual enrolled CSINode")?
                .clone(),
        )
    };
    let input = for_actual_node(
        fixture()?,
        &original_node,
        &original_csi,
        &shape.facts().node,
        &shape.facts().zone_id,
        &shape
            .collection()
            .storage
            .storage_contract
            .mapping
            .topology
            .zone_ids,
    )?;
    ensure!(
        serde_json::to_value(report.controller())? == serde_json::to_value(&input.controller)?
            && serde_json::to_value(report.node_plugin())?
                == serde_json::to_value(&input.node_plugin)?,
        "normal registered report exactly pins fixed synthetic workloads/SA UID/spec SHA"
    );
    ensure!(
        keyed(report.active_images())? == keyed(&input.images)?,
        "actual registered active descriptor/runtime expectations match this explicit synthetic fixture"
    );
    // Build the request inventory from the actual objects to be served. Both
    // semantic Pod lists use the SAME HTTP path, so its expected count is four.
    let mut expected = BTreeMap::<String, usize>::new();
    for key in input.objects.keys() {
        let path = if matches!(key.as_str(), "controller-list" | "selected-plugin-list") {
            "/api/v1/namespaces/kube-system/pods"
        } else {
            key
        };
        *expected.entry(path.to_owned()).or_default() += 2;
    }
    ensure!(
        expected.values().sum::<usize>() == 38 && expected.len() == 18,
        "exact two-round CSI path inventory"
    );
    let previous: BTreeMap<String, Option<Value>> = {
        let mut map = case
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("CSI fixture install"))?;
        let previous = input
            .objects
            .keys()
            .map(|key| (key.clone(), map.get(key).cloned()))
            .collect();
        for (key, value) in &input.objects {
            map.insert(key.clone(), value.clone());
        }
        previous
    };
    // No new server/client is supplied: all GETs use the same original runtime
    // configuration held by the normal producer. Objects alone cannot authorize.
    let result = Box::pin(consume(case, cloud, shape, pvc, pv, report, &expected)).await;
    let restored = (|| -> anyhow::Result<()> {
        let mut map = case
            .w
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("CSI fixture restore"))?;
        for (key, value) in previous {
            if let Some(value) = value {
                map.insert(key, value);
            } else {
                map.remove(&key);
            }
        }
        ensure!(
            map.get(&node_path) == Some(&original_node)
                && map.get(&csi_path) == Some(&original_csi),
            "actual enrolled Node/CSI restored byte-equivalent without lifecycle/DB edits"
        );
        Ok(())
    })();
    if restored.is_err() {
        eprintln!("PRIVATE live CSI fixture restoration failed; not certified restored");
    }
    result?;
    restored?;
    Box::pin(unchanged(case)).await?;
    Ok(())
}

type Counts = BTreeMap<String, usize>;
fn counts(case: &SelectedCase<'_>) -> anyhow::Result<(Counts, usize)> {
    let state = case
        .w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("actual read counters"))?;
    ensure!(
        state.violations.is_empty(),
        "exact HTTP query protocol, no fixture violations"
    );
    Ok((state.reads.clone(), state.requests.len()))
}

async fn consume(
    case: &SelectedCase<'_>,
    cloud: &DiskCloud,
    shape: &RawBoundDiskScope,
    pvc: &Value,
    pv: &Value,
    report: Arc<RestoreVendorReport>,
    expected: &Counts,
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
        "current normal backup claim before live CSI producer"
    );
    let collector = BackupRawBoundCollector::for_loopback_test(
        case.w.runtime.clone(),
        cloud.config()?,
        cloud.server.url.clone(),
    )
    .map_err(api_failure)?
    .with_vendor_report(Some(report));
    let owned =
        Box::pin(collector.observe_pending_restore(&engine.database, engine, case.claim, case.r))
            .await
            .map_err(api_failure)?;
    owned.current(engine, case.claim).map_err(api_failure)?;
    ensure!(
        owned.projection().parent_uid() == shape.facts().pvc_uid
            && owned.projection().uid().to_string()
                == pv["metadata"]["uid"]
                    .as_str()
                    .context("actual raw PV UID")?,
        "actual normal producer owns the same bound raw target, no authority DTO"
    );
    reads(case, shape, 2, 3)?;
    cloud.exact_actions(2)?;
    Box::pin(unchanged(case)).await?;
    let (before, start) = counts(case)?;
    // The consuming method must get past real CSI rounds and genuine new full14
    // SQL before this exact vendor refusal. Other errors/codes are not accepted.
    let refusal = Box::pin(owned.observe_csi_and_refuse(engine, case.claim))
        .await
        .err()
        .context("live CSI observations unexpectedly allowed publication")?;
    ensure!(
        refusal.status == StatusCode::FORBIDDEN
            && refusal.code == "RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED"
            && refusal.detail == "Raw restore volume vendor certification unavailable",
        "matched report+actual CSI HTTP+final same-pin SQL must still reach exact missing vendor capability"
    );
    let (after, end) = counts(case)?;
    ensure!(
        end - start == 38,
        "exact 38 actual CSI HTTP arrivals after normal producer"
    );
    for (path, count) in expected {
        ensure!(
            after.get(path).copied().unwrap_or_default()
                - before.get(path).copied().unwrap_or_default()
                == *count,
            "exact two-round path count for {path}"
        );
    }
    let changed: usize = after
        .iter()
        .map(|(path, count)| count - before.get(path).copied().unwrap_or_default())
        .sum();
    ensure!(
        changed == 38,
        "no extra HTTP fallback or owner/path lookup beyond the exact CSI inventory"
    );
    {
        let state = case
            .w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("exact method arrivals"))?;
        ensure!(
            state.requests[start..]
                .iter()
                .all(|(method, path)| *method == Method::GET && expected.contains_key(path)),
            "all 38 observations are actual GETs from existing same runtime client"
        );
    }
    cloud.exact_actions(2)?;
    ensure!(
        case.w.reads(case.pvc_path)? == 3
            && case.w.reads(&format!(
                "/api/v1/persistentvolumes/{}",
                shape.facts().pv_name
            ))? == 2,
        "live CSI observation does not create another raw parent/PV observation or writer"
    );
    Box::pin(crate::restore::raw_bound_collector::handoff_tests::no_open_transactions(engine))
        .await?;
    Box::pin(unchanged(case)).await?;
    eprintln!(
        "VERIFIED private CSI live matched normal consumption: original runtime client; exact3 synthetic controller Pods across sealed3zones and selected DS/CR/Pod; two complete raw HTTP rounds38GET; actual enrolled Node/CSINode unchanged; normal new full14 final token retained into original minimum handoff then exact vendor403; zero publication/media/host permission, no real CSI installation or OCI provenance certification"
    );
    Ok(())
}
