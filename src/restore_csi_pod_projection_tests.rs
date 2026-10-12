//! Pure fixed-source synthetic comparisons; no real API/vendor certification.
use super::*;
use anyhow::{Context, Result, ensure};

fn fixture(purpose: CsiPodPurpose) -> Result<Value> {
    let all: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/restore/csi-pod-projection.synthetic.json"
    ))?;
    let index = match purpose {
        CsiPodPurpose::Controller => 0,
        CsiPodPurpose::NodePlugin => 1,
    };
    Ok(all.get(index).context("synthetic purpose missing")?.clone())
}
fn checked(v: Value) -> Result<CsiPodProjection> {
    Ok(project_csi_pod(&CsiPodProjectionInput::from_value(v)?)?)
}
fn edit(v: &mut Value, path: &str, new: Value) -> Result<()> {
    *v.pointer_mut(path)
        .with_context(|| format!("fixture target absent: {path}"))? = new;
    Ok(())
}
fn add(v: &mut Value, path: &str, key: &str, new: Value) -> Result<()> {
    v.pointer_mut(path)
        .context("fixture parent absent")?
        .as_object_mut()
        .context("fixture parent not object")?
        .insert(key.into(), new);
    Ok(())
}
fn rejected(v: Value) -> Result<()> {
    let result = CsiPodProjectionInput::from_value(v).and_then(|i| project_csi_pod(&i));
    ensure!(result.is_err(), "drift was accepted");
    Ok(())
}

#[test]
fn fixed_controller_and_node_whole_spec_are_reconstructed() -> Result<()> {
    for purpose in [CsiPodPurpose::Controller, CsiPodPurpose::NodePlugin] {
        let v = fixture(purpose)?;
        let pod_raw = serde_json::to_vec(at(&v, "/pod")?)?;
        ensure!(CsiPodProjectionInput::decode_api_object(&pod_raw)? == *at(&v, "/pod")?);
        let raw = serde_json::to_vec(&v)?;
        let p = project_csi_pod(&CsiPodProjectionInput::parse(&raw)?)?;
        ensure!(
            p.pod_uid() == uuid(at(&v, "/pod/metadata/uid")?)?
                && p.spec_sha256() == hash(at(&v, "/pod/spec")?)?
        );
        ensure!(p.same_runtime(&checked(v)?));
    }
    Ok(())
}
#[test]
fn raw_decoder_rejects_duplicates_numbers_trailing_and_missing_keys() -> Result<()> {
    let v = fixture(CsiPodPurpose::Controller)?;
    let raw = serde_json::to_string(&v)?;
    for bad in [
        format!("{{\"protocol\":1,{}", &raw[1..]),
        raw.replacen("\"protocol\":1", "\"protocol\":1.0", 1),
        raw.replacen("\"protocol\":1", "\"protocol\":1e0", 1),
        raw.replacen("\"protocol\":1", "\"protocol\":true", 1),
        format!("{raw}{{}}"),
    ] {
        ensure!(CsiPodProjectionInput::parse(bad.as_bytes()).is_err());
    }
    let pod_raw = serde_json::to_string(at(&v, "/pod")?)?;
    let dup = format!("{{\"kind\":\"Pod\",{}", &pod_raw[1..]);
    ensure!(CsiPodProjectionInput::decode_api_object(dup.as_bytes()).is_err());
    let mut missing = v;
    missing
        .pointer_mut("/placement")
        .context("placement")?
        .as_object_mut()
        .context("placement map")?
        .remove("selected_node");
    rejected(missing)
}
#[test]
fn unknown_fields_reach_closed_named_shapes_at_every_level() -> Result<()> {
    for path in [
        "",
        "/pod/metadata",
        "/pod/spec",
        "/pod/status",
        "/pod/spec/containers/0",
        "/pod/spec/containers/0/resources",
        "/pod/spec/volumes/0",
        "/pod/status/containerStatuses/0",
        "/pod/status/conditions/0",
        "/workload/spec",
        "/owner/spec",
        "/service_account",
        "/priority_class",
        "/node/status/nodeInfo",
        "/workload_expectation",
        "/active_images/0",
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        add(&mut v, path, "unexpected", json!(true))?;
        rejected(v)?;
    }
    // Equality alone is insufficient when both sides are forged. The named
    // template closure must reject the same unknown on every linked object,
    // even with a freshly computed ordinary expectation hash.
    let mut v = fixture(CsiPodPurpose::NodePlugin)?;
    add(
        &mut v,
        "/workload/spec/template/spec",
        "unexpected",
        json!(true),
    )?;
    add(&mut v, "/pod/spec", "unexpected", json!(true))?;
    let sha = hash(at(&v, "/workload/spec")?)?;
    edit(&mut v, "/workload_expectation/spec_sha256", json!(sha))?;
    let mut template = at(&v, "/workload/spec/template")?.clone();
    put(&mut template, "$patch", json!("replace"))?;
    edit(&mut v, "/owner/data/spec/template", template)?;
    rejected(v)?;
    Ok(())
}
#[test]
fn uid_gvk_and_bookkeeping_are_not_normalized_away() -> Result<()> {
    for (path, new) in [
        ("/pod/metadata/uid", json!(Uuid::nil())),
        (
            "/pod/metadata/uid",
            json!("00000000-0000-4000-8000-00000000000A"),
        ),
        ("/pod/metadata/resourceVersion", json!("")),
        (
            "/pod/metadata/creationTimestamp",
            json!("2026-10-09T24:00:00Z"),
        ),
        (
            "/pod/metadata/creationTimestamp",
            json!("2026-10-09T23:59:60Z"),
        ),
        ("/pod/metadata/generation", json!(1.0)),
        ("/pod/kind", json!("Deployment")),
        ("/owner/apiVersion", json!("v1")),
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        edit(&mut v, path, new)?;
        rejected(v)?;
    }
    for (key, new) in [
        ("deletionTimestamp", json!("2026-10-09T01:00:00Z")),
        ("deletionGracePeriodSeconds", json!(0)),
        (
            "managedFields",
            json!([{"manager":"fixture","operation":"Apply","apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"invalid":{}}}]),
        ),
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        add(&mut v, "/pod/metadata", key, new)?;
        rejected(v)?;
    }
    Ok(())
}
#[test]
fn replica_set_chain_selector_hash_and_rollout_must_agree() -> Result<()> {
    for (path, new) in [
        (
            "/owner/metadata/ownerReferences/0/uid",
            json!(Uuid::from_u128(500)),
        ),
        (
            "/owner/spec/selector/matchLabels/pod-template-hash",
            json!("jklmn"),
        ),
        (
            "/owner/spec/template/spec/containers/0/args/0",
            json!("--other"),
        ),
        ("/owner/metadata/name", json!("csi-provisioner-bad0")),
        ("/pod/metadata/labels/pod-template-hash", json!("jklmn")),
        ("/pod/metadata/ownerReferences/0/controller", json!(false)),
        ("/workload/status/updatedReplicas", json!(2)),
        ("/owner/status/readyReplicas", json!(2)),
        ("/owner/status/observedGeneration", json!(2)),
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        edit(&mut v, path, new)?;
        rejected(v)?;
    }
    Ok(())
}
#[test]
fn daemon_revision_affinity_and_toleration_branches_are_exact() -> Result<()> {
    for (path, new) in [
        (
            "/owner/metadata/ownerReferences/0/uid",
            json!(Uuid::from_u128(500)),
        ),
        ("/owner/data/spec/template/$patch", json!("merge")),
        ("/owner/revision", json!(0)),
        (
            "/pod/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/0/matchFields/0/values/0",
            json!("other-node"),
        ),
        ("/pod/spec/tolerations/2/effect", json!("NoSchedule")),
        ("/pod/spec/tolerations/8/key", json!("other")),
        ("/pod/spec/containers/0/ports/0/hostPort", json!(11261)),
    ] {
        let mut v = fixture(CsiPodPurpose::NodePlugin)?;
        edit(&mut v, path, new)?;
        rejected(v)?;
    }
    let mut v = fixture(CsiPodPurpose::NodePlugin)?;
    add(
        &mut v,
        "/pod/spec/tolerations/2",
        "tolerationSeconds",
        json!(300),
    )?;
    rejected(v)?;
    let mut v = fixture(CsiPodPurpose::NodePlugin)?;
    add(
        &mut v,
        "/pod/metadata",
        "annotations",
        json!({"pod-template-generation":"1"}),
    )?;
    rejected(v)
}
#[test]
fn api_token_is_distinct_from_cloud_token_and_mounted_everywhere() -> Result<()> {
    let base = fixture(CsiPodPurpose::Controller)?;
    let count = arr(at(&base, "/pod/spec/volumes")?)?.len();
    let t = count - 1;
    for (suffix, new) in [
        ("/projected/defaultMode", json!(384)),
        (
            "/projected/sources/0/serviceAccountToken/expirationSeconds",
            json!(600),
        ),
        ("/projected/sources/1/configMap/name", json!("other-root")),
        (
            "/projected/sources/2/downwardAPI/items/0/fieldRef/fieldPath",
            json!("metadata.name"),
        ),
        ("/name", json!("kube-api-access-aaaaa")),
    ] {
        let mut v = base.clone();
        edit(&mut v, &format!("/pod/spec/volumes/{t}{suffix}"), new)?;
        rejected(v)?;
    }
    let mut v = base.clone();
    add(
        &mut v,
        &format!("/pod/spec/volumes/{t}/projected/sources/0/serviceAccountToken"),
        "audience",
        json!("sts.aliyuncs.com"),
    )?;
    rejected(v)?;
    for c in 0..6 {
        let mut v = base.clone();
        let mounts = v
            .pointer_mut(&format!("/pod/spec/containers/{c}/volumeMounts"))
            .context("mounts")?
            .as_array_mut()
            .context("mount array")?;
        mounts.pop();
        rejected(v)?;
    }
    let mut v = base;
    add(
        &mut v,
        "/pod/spec/containers/0/volumeMounts/2",
        "subPath",
        json!("token"),
    )?;
    rejected(v)
}
#[test]
fn priority_serviceaccount_credentials_and_alias_require_exact_inputs() -> Result<()> {
    for (path, new) in [
        ("/priority_class/value", json!(2000001000)),
        ("/priority_class/preemptionPolicy", json!("Never")),
        (
            "/service_account/automountServiceAccountToken",
            json!(false),
        ),
        ("/service_account/metadata/uid", json!(Uuid::from_u128(500))),
        ("/pod/spec/serviceAccount", json!("other")),
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        edit(&mut v, path, new)?;
        rejected(v)?;
    }
    for (path, k, new) in [
        ("/service_account", "secrets", json!([{"name":"extra"}])),
        (
            "/service_account",
            "imagePullSecrets",
            json!([{"name":"extra"}]),
        ),
        ("/pod/spec", "automountServiceAccountToken", json!(false)),
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        add(&mut v, path, k, new)?;
        rejected(v)?;
    }
    for path in ["/service_account/metadata", "/priority_class/metadata"] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        add(
            &mut v,
            path,
            "ownerReferences",
            owner_reference("Deployment", "unrelated", Uuid::from_u128(500)),
        )?;
        rejected(v)?;
    }
    Ok(())
}
#[test]
fn known_spec_mutations_cannot_hide_behind_prepared_fields() -> Result<()> {
    for (path, new) in [
        ("/pod/spec/containers/0/args/0", json!("--other")),
        ("/pod/spec/containers/0/resources/limits/cpu", json!("1")),
        ("/pod/spec/volumes/0/name", json!("extra")),
        ("/pod/spec/topologySpreadConstraints/0/maxSkew", json!(2)),
        ("/pod/spec/enableServiceLinks", json!(false)),
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        edit(&mut v, path, new)?;
        rejected(v)?;
    }
    // Matching both raw specs and an ordinary image DTO still cannot switch
    // the fixed digest set for this comparison profile.
    let mut forged = fixture(CsiPodPurpose::NodePlugin)?;
    let image = format!(
        "registry.cn-hangzhou.aliyuncs.com/acs/csi-plugin@sha256:{}",
        "a".repeat(64)
    );
    edit(
        &mut forged,
        "/workload/spec/template/spec/containers/0/image",
        json!(image),
    )?;
    edit(&mut forged, "/pod/spec/containers/0/image", json!(image))?;
    let active = forged
        .get_mut("active_images")
        .context("active")?
        .as_array_mut()
        .context("active array")?
        .iter_mut()
        .find(|a| a.get("container_name") == Some(&json!("csi-plugin")))
        .context("driver image")?;
    put(active, "image_ref", json!(image))?;
    let sha = hash(at(&forged, "/workload/spec")?)?;
    edit(&mut forged, "/workload_expectation/spec_sha256", json!(sha))?;
    let mut template = at(&forged, "/workload/spec/template")?.clone();
    put(&mut template, "$patch", json!("replace"))?;
    edit(&mut forged, "/owner/data/spec/template", template)?;
    rejected(forged)?;
    let mut v = fixture(CsiPodPurpose::Controller)?;
    add(
        &mut v,
        "/pod/spec/containers/0/securityContext",
        "privileged",
        json!(true),
    )?;
    rejected(v)
}
#[test]
fn unsupported_template_feature_branch_is_explicitly_rejected() -> Result<()> {
    for (key, value) in [
        ("initContainers", json!([])),
        ("resources", json!({"requests":{"cpu":"1"}})),
        ("schedulingGates", json!([])),
        ("runtimeClassName", json!("kata")),
        ("readinessGates", json!([])),
    ] {
        let mut v = fixture(CsiPodPurpose::NodePlugin)?;
        add(&mut v, "/workload/spec/template/spec", key, value)?;
        let sha = hash(at(&v, "/workload/spec")?)?;
        edit(&mut v, "/workload_expectation/spec_sha256", json!(sha))?;
        // Keep the legitimate owner patch in sync so rejection reaches the
        // supported-template branch rather than a fabricated broken lineage.
        let mut template = at(&v, "/workload/spec/template")?.clone();
        put(&mut template, "$patch", json!("replace"))?;
        edit(&mut v, "/owner/data/spec/template", template)?;
        let i = CsiPodProjectionInput::from_value(v)?;
        ensure!(matches!(
            project_csi_pod(&i),
            Err(CsiPodProjectionError::Unsupported)
        ));
    }
    Ok(())
}
#[test]
fn current_node_and_selected_boot_profile_zone_are_distinct_checks() -> Result<()> {
    for (path, new) in [
        ("/node/metadata/uid", json!(Uuid::from_u128(500))),
        ("/node/status/nodeInfo/bootID", json!(Uuid::from_u128(500))),
        ("/node/status/nodeInfo/architecture", json!("arm64")),
        ("/placement/selected_zone", json!("cn-hangzhou-b")),
        ("/node/status/conditions/0/status", json!("False")),
    ] {
        let mut v = fixture(CsiPodPurpose::NodePlugin)?;
        edit(&mut v, path, new)?;
        rejected(v)?;
    }
    let mut v = fixture(CsiPodPurpose::NodePlugin)?;
    add(
        &mut v,
        "/node/metadata/labels",
        ZONE,
        json!("cn-hangzhou-z"),
    )?;
    rejected(v)?;
    let mut v = fixture(CsiPodPurpose::NodePlugin)?;
    add(
        &mut v,
        "/node/metadata/annotations",
        PROFILE,
        json!("b".repeat(64)),
    )?;
    rejected(v)?;
    let mut v = fixture(CsiPodPurpose::Controller)?;
    edit(&mut v, "/placement/selected_zone", json!("cn-hangzhou-a"))?;
    rejected(v)
}
#[test]
fn runtime_ready_and_image_identity_are_checked_not_prefix_normalized() -> Result<()> {
    for (path, new) in [
        ("/pod/status/phase", json!("Pending")),
        ("/pod/status/qosClass", json!("Guaranteed")),
        ("/pod/status/conditions/0/status", json!("False")),
        ("/pod/status/conditions/0/type", json!("DisruptionTarget")),
        ("/pod/status/containerStatuses/0/ready", json!(false)),
        ("/pod/status/containerStatuses/0/restartCount", json!(-1)),
        (
            "/pod/status/containerStatuses/0/imageID",
            json!("synthetic-image-csi-provisioner"),
        ),
        (
            "/pod/status/containerStatuses/0/state/running/startedAt",
            json!("2026-10-09T01:00:60Z"),
        ),
    ] {
        let mut v = fixture(CsiPodPurpose::Controller)?;
        edit(&mut v, path, new)?;
        rejected(v)?;
    }
    let mut v = fixture(CsiPodPurpose::Controller)?;
    let statuses = v
        .pointer_mut("/pod/status/containerStatuses")
        .context("statuses")?
        .as_array_mut()
        .context("status array")?;
    statuses[1] = statuses[0].clone();
    rejected(v)
}
#[test]
fn runtime_snapshot_allows_bookkeeping_but_protects_actual_identity() -> Result<()> {
    let v = fixture(CsiPodPurpose::Controller)?;
    let first = checked(v.clone())?;
    let mut harmless = v.clone();
    edit(
        &mut harmless,
        "/pod/metadata/resourceVersion",
        json!("opaque-new-version"),
    )?;
    add(
        &mut harmless,
        "/pod/status/conditions/0",
        "message",
        json!("new bookkeeping"),
    )?;
    ensure!(first.same_runtime(&checked(harmless)?));
    for (path, value) in [
        ("/pod/metadata/uid", json!(Uuid::from_u128(500))),
        ("/pod/metadata/generation", json!(2)),
        (
            "/pod/status/containerStatuses/0/containerID",
            json!("containerd://replacement"),
        ),
        ("/pod/status/containerStatuses/0/restartCount", json!(1)),
        (
            "/pod/status/containerStatuses/0/state/running/startedAt",
            json!("2026-10-09T02:00:00Z"),
        ),
    ] {
        let mut changed = v.clone();
        edit(&mut changed, path, value)?;
        ensure!(!first.same_runtime(&checked(changed)?));
    }
    let mut changed = v.clone();
    let token = string(&changed, "/pod/spec/volumes/2/name")?.to_owned();
    let new_token = "kube-api-access-jklmn";
    edit(&mut changed, "/pod/spec/volumes/2/name", json!(new_token))?;
    for c in changed
        .pointer_mut("/pod/spec/containers")
        .context("containers")?
        .as_array_mut()
        .context("containers array")?
    {
        for m in c
            .get_mut("volumeMounts")
            .context("mounts")?
            .as_array_mut()
            .context("mounts array")?
        {
            if m.get("name") == Some(&json!(token)) {
                put(m, "name", json!(new_token))?;
            }
        }
    }
    ensure!(!first.same_runtime(&checked(changed)?));
    let mut changed = v;
    edit(
        &mut changed,
        "/priority_class/metadata/uid",
        json!(Uuid::from_u128(501)),
    )?;
    ensure!(!first.same_runtime(&checked(changed)?));
    Ok(())
}
#[test]
fn metadata_fields_trie_and_bounds_are_checked_without_discarding_raw() -> Result<()> {
    let mut good = fixture(CsiPodPurpose::Controller)?;
    add(
        &mut good,
        "/pod/metadata",
        "managedFields",
        json!([{"manager":"kubelet","operation":"Update","apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:phase":{}}},"time":"2026-10-09T01:00:00Z"}]),
    )?;
    checked(good)?;
    let mut bad = fixture(CsiPodPurpose::Controller)?;
    add(
        &mut bad,
        "/node/metadata/labels",
        "oversized",
        json!("x".repeat(65537)),
    )?;
    rejected(bad)?;
    let mut bad = fixture(CsiPodPurpose::Controller)?;
    edit(&mut bad, "/workload_expectation/uid", json!(Uuid::nil()))?;
    rejected(bad)
}
