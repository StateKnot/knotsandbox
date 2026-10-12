//! Synthetic report parsing only. No certification registration, sealed Scope,
//! Gate, cloud evidence, writer or permission is fabricated by these tests.
use super::*;
use anyhow::Context;
use serde_json::json;

fn fixture() -> anyhow::Result<Value> {
    let storage: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/restore/storage-canonical.json"
    ))?;
    let c = &storage["contract"];
    let lock: Value =
        serde_json::from_slice(include_bytes!("../deploy/cluster/versions.lock.json"))?;
    let refs = lock["csi_images"]
        .as_object()
        .context("fixed image sources")?;
    let locked: BTreeMap<String, Value> = refs
        .values()
        .map(|v| {
            Ok((
                v.as_str().context("fixed image ref")?.to_owned(),
                json!("1".repeat(64)),
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let image = |tag: &str| -> anyhow::Result<&str> {
        refs.get(&format!("registry.cn-hangzhou.aliyuncs.com/acs/{tag}"))
            .and_then(Value::as_str)
            .context("locked fixture image")
    };
    let mut active = Vec::new();
    for (workload, name, tag) in [
        ("csi-plugin", "csi-plugin", "csi-plugin:v1.37.2"),
        (
            "csi-plugin",
            "disk-driver-registrar",
            "csi-node-driver-registrar:v2.17.0-aliyun",
        ),
        ("csi-provisioner", "csi-provisioner", "csi-plugin:v1.37.2"),
        (
            "csi-provisioner",
            "external-csi-snapshotter",
            "csi-snapshotter:v8.5.1-aliyun",
        ),
        (
            "csi-provisioner",
            "external-disk-attacher",
            "csi-attacher:v4.12.0-aliyun",
        ),
        (
            "csi-provisioner",
            "external-disk-provisioner",
            "csi-provisioner:v6.2.1-aliyun",
        ),
        (
            "csi-provisioner",
            "external-disk-resizer",
            "csi-resizer:v2.1.1-aliyun",
        ),
        (
            "csi-provisioner",
            "external-snapshot-controller",
            "snapshot-controller:v8.5.1-aliyun",
        ),
    ] {
        active.push(json!({"workload_name":workload,"container_kind":"regular",
            "container_name":name,"image_ref":image(tag)?,
            "platform_descriptor_sha256":"2".repeat(64),"runtime_image_id":image(tag)?}));
    }
    let workload = |kind: &str, name: &str, sa: &str| {
        json!({
        "kind":kind,"namespace":"kube-system","name":name,"uid":Uuid::new_v4(),
        "service_account_name":sa,"service_account_uid":Uuid::new_v4(),"spec_sha256":"3".repeat(64)})
    };
    let mut wire = serde_json::Map::new();
    for zone in c["mapping"]["topology"]["zone_ids"]
        .as_array()
        .context("zones")?
    {
        let cases: BTreeMap<&str, Value> = CASES
            .into_iter()
            .map(|name| {
                (
                    name,
                    json!({"observed_at":"2026-10-01T11:00:00.000000Z",
                "transcript_sha256":"4".repeat(64),"decoded_case_sha256":"5".repeat(64)}),
                )
            })
            .collect();
        wire.insert(zone.as_str().context("zone")?.into(), json!(cases));
    }
    Ok(json!({"protocol":1,"bindings":{
        "profile_id":c["profile_id"],"cluster_epoch":c["cluster_epoch"],
        "backup_certification_sha256":c["backup_certification_sha256"],
        "storage_mappings":[c["mapping"]],"account_id":c["mapping"]["account_id"],
        "region":c["mapping"]["region"],"deployment":c["mapping"]["deployment"],
        "workspace_kms_key_id":c["mapping"]["workspace_kms_key_id"],
        "versions_lock_sha256":hash(include_bytes!("../deploy/cluster/versions.lock.json")),
        "infrastructure_sha256":"6".repeat(64)},
        "reviewed_at":"2026-10-01T12:00:00.000000Z","expires_at":"2026-10-21T12:00:00.000000Z",
        "raw_bound_vendor":{"protocol":1,"projector_contract":POLICY,
            "terraform_output_sha256":"7".repeat(64),
            "controller":workload("Deployment","csi-provisioner","sandbox-csi-controller"),
            "node_plugin":workload("DaemonSet","csi-plugin","sandbox-csi-node"),
            "images":{"locked":locked,"active":active},"pod_projection_contract":POD_POLICY,
            "protection":{"webhook_uid":Uuid::new_v4(),"webhook_spec_sha256":"8".repeat(64),
                "raw_binding_admission_contract_sha256":"9".repeat(64)},
            "wire_cases_by_zone":wire,"evidence_bundle_sha256":"a".repeat(64)}}))
}
fn parsed(v: &Value) -> anyhow::Result<Result<RestoreVendorReport>> {
    Ok(RestoreVendorReport::parse(&serde_json::to_vec(v)?))
}
fn replace(v: &mut Value, pointer: &str, new: Value) -> anyhow::Result<()> {
    *v.pointer_mut(pointer).context("existing fixture field")? = new;
    Ok(())
}
#[test]
fn canonical_claims_only_parse_to_readonly_expectations() -> anyhow::Result<()> {
    let v = fixture()?;
    let raw = serde_json::to_vec(&v)?;
    let report = RestoreVendorReport::parse(&raw)?;
    assert_eq!(report.report_sha256(), hash(&raw));
    assert_eq!(report.controller().name, "csi-provisioner");
    assert_eq!(
        report.node_plugin().service_account_name,
        "sandbox-csi-node"
    );
    assert_eq!(report.active_images().len(), 8);
    // The unused init image is locked but has no fabricated runtime status.
    assert!(
        !report
            .active_images()
            .iter()
            .any(|i| i.container_kind == "init")
    );
    Ok(())
}
#[test]
fn canonical_bytes_duplicate_escapes_whitespace_and_oversize_rejected() -> anyhow::Result<()> {
    let v = fixture()?;
    let raw = serde_json::to_vec(&v)?;
    for candidate in [
        serde_json::to_vec_pretty(&v)?,
        [raw.as_slice(), b"\n"].concat(),
        [b"{\"protocol\":1,\"protocol\":1,".as_slice(), &raw[1..]].concat(),
        String::from_utf8(raw.clone())?
            .replace("csi-plugin", "csi-\\u0070lugin")
            .into_bytes(),
        vec![b' '; REPORT_LIMIT + 1],
    ] {
        assert!(matches!(
            RestoreVendorReport::parse(&candidate),
            Err(VendorReportError::Shape)
        ));
    }
    Ok(())
}
#[test]
fn missing_vendor_is_unavailable_but_unknown_null_and_protocol_types_reject() -> anyhow::Result<()>
{
    let original = fixture()?;
    let mut legacy = original.clone();
    legacy
        .as_object_mut()
        .context("object")?
        .remove("raw_bound_vendor");
    assert!(matches!(
        parsed(&legacy)?,
        Err(VendorReportError::Unavailable)
    ));
    for pointer in ["/protocol", "/raw_bound_vendor/protocol"] {
        for bad in [
            json!(true),
            json!(1.0),
            json!("1"),
            Value::Null,
            json!(0),
            json!(2),
        ] {
            let mut v = original.clone();
            replace(&mut v, pointer, bad)?;
            assert!(
                matches!(parsed(&v)?, Err(VendorReportError::Shape)),
                "{pointer}"
            );
        }
    }
    for pointer in [
        "",
        "/bindings",
        "/raw_bound_vendor",
        "/raw_bound_vendor/controller",
        "/raw_bound_vendor/images",
        "/raw_bound_vendor/images/active/0",
        "/raw_bound_vendor/protection",
    ] {
        let mut v = original.clone();
        v.pointer_mut(pointer)
            .context("object path")?
            .as_object_mut()
            .context("object")?
            .insert("unknown".into(), json!(false));
        assert!(
            matches!(parsed(&v)?, Err(VendorReportError::Shape)),
            "{pointer}"
        );
    }
    let mut v = original;
    v["raw_bound_vendor"] = Value::Null;
    assert!(matches!(parsed(&v)?, Err(VendorReportError::Shape)));
    Ok(())
}
#[test]
fn identities_cloud_binding_and_storage_aliases_cannot_normalize_away() -> anyhow::Result<()> {
    let original = fixture()?;
    for (pointer, value) in [
        ("/bindings/profile_id", json!(Uuid::nil())),
        (
            "/bindings/cluster_epoch",
            json!("11111111-1111-4111-8111-11111111111A"),
        ),
        ("/bindings/account_id", json!(1234567890123456_u64)),
        ("/bindings/deployment", json!("other")),
        ("/bindings/workspace_kms_key_id", json!("source-clone-key")),
        ("/bindings/versions_lock_sha256", json!("b".repeat(64))),
        ("/bindings/storage_mappings/0/raw/uid", json!(Uuid::nil())),
        (
            "/bindings/storage_mappings/0/topology/key",
            json!("topology.kubernetes.io/zone"),
        ),
        (
            "/raw_bound_vendor/controller/namespace",
            json!("sandbox-system"),
        ),
        ("/raw_bound_vendor/node_plugin/kind", json!("Deployment")),
        (
            "/raw_bound_vendor/controller/service_account_name",
            json!("default"),
        ),
        ("/raw_bound_vendor/controller/uid", json!(Uuid::nil())),
        (
            "/raw_bound_vendor/protection/webhook_uid",
            json!(Uuid::nil()),
        ),
        ("/raw_bound_vendor/projector_contract", json!("*")),
        (
            "/raw_bound_vendor/pod_projection_contract",
            json!("upstream-equivalent"),
        ),
    ] {
        let mut v = original.clone();
        replace(&mut v, pointer, value)?;
        assert!(parsed(&v)?.is_err(), "{pointer}");
    }
    let mut v = original.clone();
    let duplicate = v["bindings"]["storage_mappings"][0].clone();
    v["bindings"]["storage_mappings"]
        .as_array_mut()
        .context("mappings")?
        .push(duplicate);
    assert!(parsed(&v)?.is_err(), "duplicate normal purpose");
    let mut shared = original;
    let mut second = shared["bindings"]["storage_mappings"][0].clone();
    second["normal"]["name"] = json!("second-normal");
    second["normal"]["uid"] = json!(Uuid::new_v4());
    shared["bindings"]["storage_mappings"]
        .as_array_mut()
        .context("mappings")?
        .push(second);
    assert!(
        parsed(&shared)?.is_ok(),
        "same exact raw/delivery/snapshot aliases are valid"
    );
    shared["bindings"]["storage_mappings"][1]["raw"]["spec_sha256"] = json!("c".repeat(64));
    assert!(
        parsed(&shared)?.is_err(),
        "shared resource changed identity"
    );
    Ok(())
}
#[test]
fn locked_registry_set_and_runtime_literals_are_exact_expectations() -> anyhow::Result<()> {
    let original = fixture()?;
    let mut missing = original.clone();
    let map = missing["raw_bound_vendor"]["images"]["locked"]
        .as_object_mut()
        .context("images")?;
    let key = map.keys().next().context("first image")?.clone();
    map.remove(&key);
    assert!(parsed(&missing)?.is_err());
    let mut unknown = original.clone();
    unknown["raw_bound_vendor"]["images"]["locked"]["registry.example/csi@sha256:unlocked"] =
        json!("1".repeat(64));
    assert!(parsed(&unknown)?.is_err());
    for (pointer, value) in [
        (
            "/raw_bound_vendor/images/active/0/image_ref",
            json!("registry.example/csi:latest"),
        ),
        (
            "/raw_bound_vendor/images/active/0/runtime_image_id",
            json!("*"),
        ),
        (
            "/raw_bound_vendor/images/active/0/container_kind",
            json!("ephemeral"),
        ),
        (
            "/raw_bound_vendor/images/active/0/workload_name",
            json!("user-controlled"),
        ),
        (
            "/raw_bound_vendor/images/active/0/platform_descriptor_sha256",
            json!("A".repeat(64)),
        ),
    ] {
        let mut v = original.clone();
        replace(&mut v, pointer, value)?;
        assert!(parsed(&v)?.is_err());
    }
    let mut dup = original.clone();
    dup["raw_bound_vendor"]["images"]["active"][1] =
        dup["raw_bound_vendor"]["images"]["active"][0].clone();
    assert!(parsed(&dup)?.is_err());
    let mut swapped = original;
    swapped["raw_bound_vendor"]["images"]["active"]
        .as_array_mut()
        .context("active")?
        .swap(0, 1);
    assert!(parsed(&swapped)?.is_err());
    Ok(())
}
#[test]
fn strict_microsecond_utc_time_does_not_accept_rollover_or_claim_freshness() -> anyhow::Result<()> {
    let original = fixture()?;
    for time in [
        "2026-10-01T24:00:00.000000Z",
        "2026-10-01T23:60:00.000000Z",
        "2026-10-01T23:59:60.000000Z",
        "2026-02-30T12:00:00.000000Z",
        "2026-10-01T12:00:00Z",
        "2026-10-01T12:00:00.000000+00:00",
    ] {
        let mut v = original.clone();
        v["reviewed_at"] = json!(time);
        assert!(parsed(&v)?.is_err(), "{time}");
    }
    assert!(utc_micros("2026-10-01T23:59:59.000000Z").is_ok());
    let mut v = original.clone();
    v["expires_at"] = v["reviewed_at"].clone();
    assert!(parsed(&v)?.is_err());
    let mut v = original;
    v["expires_at"] = json!("2026-11-01T12:00:00.000000Z");
    assert!(parsed(&v)?.is_err());
    Ok(())
}
#[test]
fn all_certified_zones_need_exact_six_case_claims_and_bounded_review_window() -> anyhow::Result<()>
{
    let original = fixture()?;
    let zones = original["raw_bound_vendor"]["wire_cases_by_zone"]
        .as_object()
        .context("wire")?;
    let zone = zones.keys().next().context("zone")?.clone();
    for (field, new) in [
        ("observed_at", json!("2026-10-01T13:00:00.000000Z")),
        ("observed_at", json!("2026-09-23T12:00:00.000000Z")),
        ("transcript_sha256", Value::Null),
    ] {
        let mut v = original.clone();
        v["raw_bound_vendor"]["wire_cases_by_zone"][&zone]["initial_pv_create"][field] = new;
        assert!(parsed(&v)?.is_err());
    }
    let mut v = original.clone();
    v["raw_bound_vendor"]["wire_cases_by_zone"]
        .as_object_mut()
        .context("wire")?
        .remove(&zone);
    assert!(parsed(&v)?.is_err());
    let mut v = original.clone();
    v["raw_bound_vendor"]["wire_cases_by_zone"][&zone]
        .as_object_mut()
        .context("cases")?
        .remove("pl1_idempotent_retry");
    assert!(parsed(&v)?.is_err());
    let mut v = original;
    v["raw_bound_vendor"]["wire_cases_by_zone"][&zone]["fake_PASS"] = json!({"verified":true});
    assert!(parsed(&v)?.is_err());
    Ok(())
}
#[test]
fn report_read_uses_opened_regular_bounded_public_target() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("report.json");
    let raw = serde_json::to_vec(&fixture()?)?;
    std::fs::write(&path, &raw)?;
    assert_eq!(
        RestoreVendorReport::read(&path)?.report_sha256(),
        hash(&raw)
    );
    assert!(matches!(
        RestoreVendorReport::read(Path::new("relative.json")),
        Err(VendorReportError::Read)
    ));
    assert!(matches!(
        RestoreVendorReport::read(directory.path()),
        Err(VendorReportError::Read)
    ));
    let file = std::fs::OpenOptions::new().write(true).open(&path)?;
    file.set_len(REPORT_LIMIT as u64 + 1)?;
    assert!(matches!(
        RestoreVendorReport::read(&path),
        Err(VendorReportError::Read)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, &raw)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664))?;
        assert!(matches!(
            RestoreVendorReport::read(&path),
            Err(VendorReportError::Read)
        ));
    }
    Ok(())
}
