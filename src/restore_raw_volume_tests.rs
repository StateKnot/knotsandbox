//! Pure wire-template tests. These literal facts are NOT sealed observations,
//! owner receipts, current SQL authority, an Ali fork transcript, or CSI proof.
use super::*;
use crate::restore::storage_contract::RestoreStorageContract;

struct Fixture {
    context: RestoreStorageContext,
    parent: Uuid,
    node: RawPvNodeFacts,
    disk: RawPvDiskFacts,
}
impl Fixture {
    fn new() -> Result<Self> {
        let canonical: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/restore/storage-canonical.json"
        ))
        .map_err(|_| ManifestError::Encoding)?;
        let contract = RestoreStorageContract::parse(&canonical["contract"])?;
        let context = RestoreStorageContext {
            tenant_id: Uuid::from_u128(1),
            source_backup_id: Uuid::from_u128(2),
            restore_id: Uuid::from_u128(3),
            target_project_id: Uuid::from_u128(4),
            instance_id: Uuid::from_u128(5),
            workspace_id: Uuid::from_u128(6),
            cluster_epoch: contract.cluster_epoch,
            target_namespace: "tenant-target".into(),
            storage_contract: contract,
            size_bytes: 20 * 1024_u64.pow(3),
        };
        let parent = Uuid::from_u128(7);
        let mapping = &context.storage_contract.mapping;
        let node = RawPvNodeFacts {
            runtime_node_id: Uuid::from_u128(8),
            node_uid: Uuid::from_u128(9),
            boot_id: Uuid::from_u128(10),
            profile_id: context.storage_contract.profile_id,
            cluster_epoch: context.cluster_epoch,
            topology_receipt_id: Uuid::from_u128(11),
            node_name: "kata-zone-a-001".into(),
            cloud: NodeTopologyCloudBinding {
                account_id: mapping.account_id.clone(),
                region: mapping.region.clone(),
                instance_id: "i-selected001".into(),
                zone_id: mapping.topology.zone_ids[0].clone(),
                vpc_id: "vpc-isolated001".into(),
                vswitch_id: "vsw-zone001".into(),
                private_ip: std::net::Ipv4Addr::new(10, 10, 0, 8),
                deployment: mapping.deployment.clone(),
            },
        };
        let disk = RawPvDiskFacts {
            account_id: mapping.account_id.clone(),
            region: mapping.region.clone(),
            disk_id: "d-newraw001".into(),
            zone_id: node.cloud.zone_id.clone(),
            deployment: mapping.deployment.clone(),
            namespace: NAMESPACE.into(),
            pvc_name: block_pvc_name(context.restore_id),
            pv_name: generated_block_pv_name(parent)?,
            kms_key_id: mapping.workspace_kms_key_id.clone(),
            size_gib: 20,
            serial_number: "raw-serial-001".into(),
            creation_time: DateTime::parse_from_rfc3339("2026-10-09T00:00:00Z")
                .map_err(|_| ManifestError::Encoding)?
                .with_timezone(&chrono::Utc),
        };
        Ok(Self {
            context,
            parent,
            node,
            disk,
        })
    }
    fn expected(&self) -> RawPvShapeExpected<'_> {
        RawPvShapeExpected {
            context: &self.context,
            recorded_parent_uid: self.parent,
            selected_node: &self.node,
            disk_identity: &self.disk,
        }
    }
    fn create(&self) -> Value {
        let m = &self.context.storage_contract.mapping;
        json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":self.disk.pv_name,
            "uid":Uuid::from_u128(12),"creationTimestamp":"2026-10-09T00:00:01Z",
            "finalizers":[CSI_FINALIZER,PV_PROTECTION],"annotations":{"pv.kubernetes.io/provisioned-by":DRIVER,
                "volume.kubernetes.io/provisioner-deletion-secret-name":"","volume.kubernetes.io/provisioner-deletion-secret-namespace":""}},
            "spec":{"capacity":{"storage":"20Gi"},"accessModes":["ReadWriteOnce"],"volumeMode":"Block",
                "persistentVolumeReclaimPolicy":"Retain","storageClassName":m.raw.name,
                "claimRef":{"apiVersion":"v1","kind":"PersistentVolumeClaim","namespace":NAMESPACE,
                    "name":self.disk.pvc_name,"uid":self.parent,"resourceVersion":"41"},
                "csi":{"driver":DRIVER,"volumeHandle":self.disk.disk_id,"volumeAttributes":{
                    "storage.kubernetes.io/csiProvisionerIdentity":"1791475000000-001-diskplugin.csi.alibabacloud.com",
                    "type":"cloud_essd","encrypted":"true","kmsKeyId":m.workspace_kms_key_id,"diskTags/Deployment":m.deployment,
                    "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/region":m.region,
                    "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/zone":self.node.cloud.zone_id,
                    "csi.alibabacloud.com/label-prefix/csi.alibabacloud.com/disktype":"cloud_essd.PL1",
                    "csi.alibabacloud.com/annotation-prefix/csi.alibabacloud.com/volume-topology":"{\"nodeSelectorTerms\":[{\"matchExpressions\":[{\"key\":\"node.csi.alibabacloud.com/disktype.cloud_essd\",\"operator\":\"In\",\"values\":[\"available\"]}]}]}"}},
                "nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[{"key":m.topology.key,"operator":"In","values":[self.node.cloud.zone_id]}]}]}}},
            "status":{"phase":"Pending","lastPhaseTransitionTime":"2026-10-09T00:00:01Z"}})
    }
    fn live(&self) -> Value {
        let mut v = self.create();
        v["metadata"]["resourceVersion"] = json!("51");
        v
    }
    fn claim(&self) -> Result<Value> {
        let mut v = self.context.block_pvc()?;
        v["metadata"]["uid"] = json!(self.parent);
        v["metadata"]["resourceVersion"] = json!("49");
        v["metadata"]["creationTimestamp"] = json!("2026-10-09T00:00:00Z");
        v["metadata"]["finalizers"] = json!(["kubernetes.io/pvc-protection"]);
        v["metadata"]["annotations"] =
            json!({SELECTED:self.node.node_name,STABLE:DRIVER,BETA:DRIVER});
        v["status"] = json!({"phase":"Pending"});
        Ok(v)
    }
}
fn change(value: &Value, path: &str, replacement: Value) -> Result<Value> {
    let mut changed = value.clone();
    let target = changed
        .pointer_mut(path)
        .ok_or(ManifestError::SpecificationDrift(
            "pure negative target missing",
        ))?;
    *target = replacement;
    Ok(changed)
}
fn prebound(f: &Fixture, claim: &Value) -> Value {
    let mut v = claim.clone();
    v["spec"]["volumeName"] = json!(f.disk.pv_name);
    v["metadata"]["annotations"][BOUND] = json!("yes");
    v["metadata"]["annotations"][COMPLETED] = json!("yes");
    v
}

#[test]
fn faithful_server_prepared_create_is_pending_and_zero_generation() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let raw = f.create();
    let observed = project_raw_pv_create_template(&raw, &e)?;
    assert_eq!(observed.uid(), Uuid::from_u128(12));
    assert_eq!(observed.parent_uid(), f.parent);
    assert_eq!(observed.name(), generated_block_pv_name(f.parent)?);
    assert_eq!(observed.disk_id(), "d-newraw001");
    assert_eq!(observed.zone_id(), f.node.cloud.zone_id);
    assert_eq!(observed.spec_sha256().len(), 64);
    let mut zero = raw.clone();
    zero["metadata"]["generation"] = json!(0);
    zero["metadata"]["resourceVersion"] = json!("");
    assert_eq!(project_raw_pv_create_template(&zero, &e)?, observed);
    let mut no_uid = raw.clone();
    no_uid["metadata"]
        .as_object_mut()
        .ok_or(ManifestError::Encoding)?
        .remove("uid");
    assert!(project_raw_pv_create_template(&no_uid, &e).is_err());
    Ok(())
}
#[test]
fn candidate_metadata_and_phase_never_hide_unsupported_shapes() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let raw = f.create();
    project_raw_pv_create_template(&raw, &e)?;
    for (path, value) in [
        ("/metadata/uid", json!(Uuid::nil())),
        ("/metadata/uid", json!("0000000000000000000000000000000c")),
        ("/metadata/creationTimestamp", json!("2026-10-09T24:00:00Z")),
        ("/metadata/creationTimestamp", json!("2026-10-09T23:60:00Z")),
        ("/metadata/creationTimestamp", json!("2026-10-09T23:59:60Z")),
        (
            "/metadata/creationTimestamp",
            json!("2026-10-09T00:00:01+00:00"),
        ),
        ("/metadata/creationTimestamp", json!("2026-02-30T00:00:01Z")),
        ("/metadata/finalizers", json!([PV_PROTECTION])),
        (
            "/metadata/finalizers",
            json!([CSI_FINALIZER, PV_PROTECTION, PV_PROTECTION]),
        ),
        (
            "/metadata/finalizers",
            json!([CSI_FINALIZER, "foreign/finalizer"]),
        ),
        ("/status", json!({})),
        ("/status", json!({"phase":"Pending"})),
        ("/status/phase", json!("Bound")),
        (
            "/status/lastPhaseTransitionTime",
            json!("2026-10-09T00:00:01.1234567890Z"),
        ),
    ] {
        assert!(
            project_raw_pv_create_template(&change(&raw, path, value)?, &e).is_err(),
            "{path}"
        );
    }
    for (key, value) in [
        ("generation", json!(1)),
        ("generation", json!(0.0)),
        ("generation", json!(false)),
        ("resourceVersion", json!("51")),
        ("namespace", json!(NAMESPACE)),
        ("deletionTimestamp", Value::Null),
        ("deletionGracePeriodSeconds", json!(0)),
        ("generateName", json!("disk-")),
        ("unknown", json!({})),
        ("ownerReferences", json!([{"uid":f.parent}])),
        (
            "labels",
            json!({"csi.alibabacloud.com/disktype":"cloud_essd.PL1"}),
        ),
    ] {
        let mut altered = raw.clone();
        altered["metadata"][key] = value;
        assert!(
            project_raw_pv_create_template(&altered, &e).is_err(),
            "{key}"
        );
    }
    Ok(())
}
#[test]
fn raw_spec_requires_recorded_parent_compute_kms_and_single_zone() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let raw = f.create();
    project_raw_pv_create_template(&raw, &e)?;
    for (path, value) in [
        ("/spec/volumeMode", json!("Filesystem")),
        ("/spec/persistentVolumeReclaimPolicy", json!("Delete")),
        (
            "/spec/storageClassName",
            json!(f.context.storage_contract.mapping.delivery.name),
        ),
        ("/spec/accessModes", json!(["ReadWriteMany"])),
        ("/spec/capacity/storage", json!("21Gi")),
        ("/spec/capacity/storage", json!("19Gi")),
        ("/spec/capacity/storage", json!(21474836480_u64)),
        ("/spec/claimRef/uid", json!(Uuid::from_u128(99))),
        ("/spec/claimRef/name", json!("other-claim")),
        ("/spec/claimRef/namespace", json!("tenant-target")),
        ("/spec/claimRef/kind", json!("Pod")),
        ("/spec/claimRef/resourceVersion", json!("")),
        ("/spec/csi/driver", json!("other.csi.example")),
        ("/spec/csi/volumeHandle", json!("d-other")),
        ("/spec/csi/volumeAttributes/kmsKeyId", json!("clone-key")),
        ("/spec/csi/volumeAttributes/encrypted", json!(true)),
        ("/spec/csi/volumeAttributes/type", json!("cloud_auto")),
        (
            "/spec/csi/volumeAttributes/diskTags~1Deployment",
            json!("foreign"),
        ),
        (
            "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/values",
            json!(f.context.storage_contract.mapping.topology.zone_ids),
        ),
        (
            "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/operator",
            json!("Exists"),
        ),
    ] {
        assert!(
            project_raw_pv_create_template(&change(&raw, path, value)?, &e).is_err(),
            "{path}"
        );
    }
    for (key, value) in [
        ("mountOptions", json!(["ro"])),
        ("volumeAttributesClassName", json!("mutable")),
        ("dataSource", json!({})),
        ("hostPath", json!({"path":"/"})),
        ("unknown", json!(false)),
    ] {
        let mut altered = raw.clone();
        altered["spec"][key] = value;
        assert!(
            project_raw_pv_create_template(&altered, &e).is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("readOnly", json!(true)),
        ("readOnly", json!(0)),
        ("fsType", json!("ext4")),
        ("nodePublishSecretRef", json!({"name":"secret"})),
        ("unknown", Value::Null),
    ] {
        let mut altered = raw.clone();
        altered["spec"]["csi"][key] = value;
        assert!(
            project_raw_pv_create_template(&altered, &e).is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("performanceLevel", json!("PL2")),
        ("csi.storage.k8s.io/pv/name", json!(f.disk.pv_name)),
        (
            "volume.kubernetes.io/selected-node",
            json!(f.node.node_name),
        ),
        ("allowVolumeExpansion", json!("true")),
        ("unknown", json!("value")),
    ] {
        let mut altered = raw.clone();
        altered["spec"]["csi"]["volumeAttributes"][key] = value;
        assert!(
            project_raw_pv_create_template(&altered, &e).is_err(),
            "{key}"
        );
    }
    let mut or_zone = raw.clone();
    or_zone["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"]
        .as_array_mut()
        .ok_or(ManifestError::Encoding)?
        .push(json!({"matchExpressions":[]}));
    assert!(project_raw_pv_create_template(&or_zone, &e).is_err());
    Ok(())
}
#[test]
fn equivalent_capacity_normalizes_digest_but_provisioner_provenance_is_pinned() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let raw = f.create();
    let original = project_raw_pv_create_template(&raw, &e)?;
    for quantity in ["20480Mi", "21474836480"] {
        assert_eq!(
            project_raw_pv_create_template(
                &change(&raw, "/spec/capacity/storage", json!(quantity))?,
                &e
            )?,
            original
        );
    }
    for quantity in [
        "020Gi",
        "20.0Gi",
        "-20Gi",
        "20e9",
        "18446744073709551615Ti",
        "0",
    ] {
        assert!(
            project_raw_pv_create_template(
                &change(&raw, "/spec/capacity/storage", json!(quantity))?,
                &e
            )
            .is_err()
        );
    }
    let changed = change(
        &raw,
        "/spec/csi/volumeAttributes/storage.kubernetes.io~1csiProvisionerIdentity",
        json!("other-instance"),
    )?;
    assert_ne!(
        project_raw_pv_create_template(&changed, &e)?.spec_sha256(),
        original.spec_sha256()
    );
    let mut rv = raw.clone();
    rv["spec"]["claimRef"]["resourceVersion"] = json!("older-opaque-cache-revision");
    assert_ne!(
        project_raw_pv_create_template(&rv, &e)?.spec_sha256(),
        original.spec_sha256()
    );
    Ok(())
}
#[test]
fn api_bookkeeping_is_bounded_and_never_strips_arbitrary_fields() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let mut raw = f.create();
    raw["metadata"]["managedFields"] = json!([{"manager":"csi-provisioner","operation":"Update","apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:spec":{"f:claimRef":{}}},"time":"2026-10-09T00:00:01Z"}]);
    project_raw_pv_create_template(&raw, &e)?;
    for (key, value) in [
        ("unknown", json!("strip-me")),
        ("operation", json!("Delete")),
        ("fieldsV1", json!({"unknown":{}})),
        ("fieldsV1", json!({"f:spec":true})),
        ("apiVersion", json!("batch/v1")),
        ("subresource", json!("binding")),
    ] {
        let mut malformed = raw.clone();
        malformed["metadata"]["managedFields"][0][key] = value;
        assert!(
            project_raw_pv_create_template(&malformed, &e).is_err(),
            "{key}"
        );
    }
    let mut oversized = raw.clone();
    oversized["metadata"]["managedFields"] =
        json!(vec![raw["metadata"]["managedFields"][0].clone(); 129]);
    assert!(project_raw_pv_create_template(&oversized, &e).is_err());
    Ok(())
}
#[test]
fn binding_status_and_retain_finalizer_follow_separate_normal_order() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let pending = f.live();
    let first = project_raw_pv_live_template(&pending, &e, None)?;
    let mut bound = pending.clone();
    bound["status"] = json!({"phase":"Bound","lastPhaseTransitionTime":"2026-10-09T00:00:02Z"});
    validate_raw_pv_prebound_update(&pending, &pending, &e)?;
    validate_raw_pv_status_update(&pending, &bound, &e)?;
    validate_raw_pv_status_update(&bound, &bound, &e)?;
    assert_eq!(
        project_raw_pv_live_template(&bound, &e, Some(first.uid()))?,
        first
    );
    let unbound = f.claim()?;
    let pre = prebound(&f, &unbound);
    validate_raw_pvc_binding_update(&unbound, &pre, &e)?;
    let mut claim_bound = pre.clone();
    claim_bound["status"] =
        json!({"phase":"Bound","accessModes":["ReadWriteOnce"],"capacity":{"storage":"20Gi"}});
    validate_raw_pvc_status_update(&pre, &claim_bound, &e)?;
    validate_raw_pvc_status_update(&claim_bound, &claim_bound, &e)?;
    validate_raw_pvc_binding_update(&claim_bound, &claim_bound, &e)?;
    let mut retained = bound.clone();
    retained["metadata"]["finalizers"] = json!([PV_PROTECTION]);
    validate_raw_pv_retain_finalizer_update(&bound, &retained, &e)?;
    validate_raw_pv_retain_finalizer_update(&retained, &retained, &e)?;
    assert_eq!(
        project_raw_pv_live_template(&retained, &e, Some(first.uid()))?,
        first
    );
    assert!(validate_raw_pvc_status_update(&unbound, &claim_bound, &e).is_err());
    assert!(validate_raw_pvc_binding_update(&unbound, &claim_bound, &e).is_err());
    assert!(validate_raw_pv_prebound_update(&pending, &bound, &e).is_err());
    assert!(validate_raw_pv_status_update(&bound, &pending, &e).is_err());
    Ok(())
}
#[test]
fn update_diffs_reject_every_protected_identity_and_spec_change() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let old = f.live();
    let mut new = old.clone();
    new["status"]["phase"] = json!("Bound");
    for (path, value) in [
        ("/metadata/uid", json!(Uuid::from_u128(99))),
        ("/metadata/resourceVersion", json!("52")),
        ("/metadata/creationTimestamp", json!("2026-10-09T00:00:02Z")),
        ("/spec/claimRef/resourceVersion", json!("42")),
        (
            "/spec/csi/volumeAttributes/storage.kubernetes.io~1csiProvisionerIdentity",
            json!("new-leader"),
        ),
    ] {
        assert!(
            validate_raw_pv_status_update(&old, &change(&new, path, value.clone())?, &e).is_err(),
            "{path}"
        );
        let mut after = change(&old, path, value)?;
        after["metadata"]["finalizers"] = json!([PV_PROTECTION]);
        assert!(
            validate_raw_pv_retain_finalizer_update(&old, &after, &e).is_err(),
            "{path}"
        );
    }
    let mut bound = old.clone();
    bound["status"]["phase"] = json!("Bound");
    let changed_time = change(
        &bound,
        "/status/lastPhaseTransitionTime",
        json!("2026-10-09T00:00:03Z"),
    )?;
    assert!(validate_raw_pv_status_update(&bound, &changed_time, &e).is_err());
    assert!(project_raw_pv_live_template(&old, &e, Some(Uuid::from_u128(99))).is_err());
    let mut no_protection = old.clone();
    no_protection["metadata"]["finalizers"] = json!([CSI_FINALIZER]);
    assert!(validate_raw_pv_retain_finalizer_update(&old, &no_protection, &e).is_err());
    Ok(())
}
#[test]
fn claim_status_rejects_resize_aliases_and_binding_metadata_drift() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let pending = f.claim()?;
    let before = prebound(&f, &pending);
    let mut bound = before.clone();
    bound["status"] =
        json!({"phase":"Bound","accessModes":["ReadWriteOnce"],"capacity":{"storage":"20Gi"}});
    for key in [
        "conditions",
        "allocatedResources",
        "allocatedResourceStatuses",
        "currentVolumeAttributesClassName",
        "modifyVolumeStatus",
        "unknown",
    ] {
        let mut malformed = bound.clone();
        malformed["status"][key] = json!({});
        assert!(
            validate_raw_pvc_status_update(&before, &malformed, &e).is_err(),
            "{key}"
        );
    }
    for (path, value) in [
        ("/metadata/uid", json!(Uuid::from_u128(99))),
        ("/metadata/resourceVersion", json!("50")),
        (
            "/metadata/annotations/volume.kubernetes.io~1selected-node",
            json!("other-node"),
        ),
        (
            "/metadata/annotations/pv.kubernetes.io~1bind-completed",
            json!(true),
        ),
        ("/spec/resources/requests/storage", json!("21Gi")),
        ("/spec/volumeName", json!("disk-other")),
        ("/metadata/finalizers", json!([])),
        ("/status/capacity/storage", json!("21Gi")),
    ] {
        assert!(
            validate_raw_pvc_status_update(&before, &change(&bound, path, value)?, &e).is_err(),
            "{path}"
        );
    }
    let mut cross = before.clone();
    cross["metadata"]["annotations"]["alibabacloud.com/kms-key-id"] = json!("override");
    assert!(validate_raw_pvc_binding_update(&pending, &cross, &e).is_err());
    let mut unknown = before.clone();
    unknown["spec"]["volumeAttributesClassName"] = json!("new-class");
    assert!(validate_raw_pvc_binding_update(&pending, &unknown, &e).is_err());
    Ok(())
}
#[test]
fn facts_are_exact_comparisons_not_source_kms_or_other_epoch_fallbacks() -> Result<()> {
    let mut f = Fixture::new()?;
    let raw = f.create();
    project_raw_pv_create_template(&raw, &f.expected())?;
    f.disk.kms_key_id = "clone-key".into();
    assert!(project_raw_pv_create_template(&raw, &f.expected()).is_err());
    f.disk.kms_key_id = f
        .context
        .storage_contract
        .mapping
        .workspace_kms_key_id
        .clone();
    f.node.profile_id = Uuid::from_u128(99);
    assert!(project_raw_pv_create_template(&raw, &f.expected()).is_err());
    f.node.profile_id = f.context.storage_contract.profile_id;
    f.node.cluster_epoch = Uuid::from_u128(99);
    assert!(project_raw_pv_create_template(&raw, &f.expected()).is_err());
    f.node.cluster_epoch = f.context.cluster_epoch;
    f.node.topology_receipt_id = Uuid::nil();
    assert!(project_raw_pv_create_template(&raw, &f.expected()).is_err());
    f.node.topology_receipt_id = Uuid::from_u128(11);
    f.node.cloud.zone_id = "cn-hangzhou-other".into();
    assert!(project_raw_pv_create_template(&raw, &f.expected()).is_err());
    Ok(())
}

#[test]
fn official_initial_and_idempotent_retry_contexts_have_distinct_full_spec_digests() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let initial = f.create();
    let mut retry = initial.clone();
    retry["spec"]["csi"]["volumeAttributes"]["performanceLevel"] = json!("PL1");
    let first = project_raw_pv_create_template(&initial, &e)?;
    let second = project_raw_pv_create_template(&retry, &e)?;
    assert_eq!(first.uid(), second.uid());
    assert_eq!(first.parent_uid(), second.parent_uid());
    assert_eq!(first.name(), second.name());
    assert_eq!(first.disk_id(), second.disk_id());
    assert_eq!(first.zone_id(), second.zone_id());
    assert_ne!(first.spec_sha256(), second.spec_sha256());
    for (candidate, projected, attribute_count) in [(&initial, &first, 9), (&retry, &second, 10)] {
        assert_eq!(
            candidate["spec"]["csi"]["volumeAttributes"]
                .as_object()
                .ok_or(ManifestError::Encoding)?
                .len(),
            attribute_count
        );
        // The literal spec is already canonical 20Gi without optional aliases.
        // Compare the whole spec, so no accepted driver output can escape SHA.
        assert_eq!(
            projected.spec_sha256(),
            hex::encode(Sha256::digest(
                serde_json::to_vec(&candidate["spec"]).map_err(|_| ManifestError::Encoding)?
            ))
        );
        let mut live = candidate.clone();
        live["metadata"]["resourceVersion"] = json!("51");
        assert_eq!(
            project_raw_pv_live_template(&live, &e, Some(projected.uid()))?,
            *projected
        );
    }
    Ok(())
}

#[test]
fn retry_context_rejects_non_pl1_types_unknown_fields_and_frozen_attribute_drift() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let initial = f.create();
    let mut retry = initial.clone();
    retry["spec"]["csi"]["volumeAttributes"]["performanceLevel"] = json!("PL1");
    project_raw_pv_create_template(&retry, &e)?;
    for level in [
        json!("PL0"),
        json!("PL2"),
        json!("PL3"),
        json!("pl1"),
        json!("PL1 "),
        json!(""),
        json!(1),
        json!(true),
        Value::Null,
        json!(["PL1"]),
        json!({"value":"PL1"}),
    ] {
        let mut invalid = retry.clone();
        invalid["spec"]["csi"]["volumeAttributes"]["performanceLevel"] = level;
        assert!(project_raw_pv_create_template(&invalid, &e).is_err());
    }
    for variant in [&initial, &retry] {
        for (key, value) in [
            ("type", json!("cloud_auto")),
            ("encrypted", json!(false)),
            ("kmsKeyId", json!("clone-key")),
            ("diskTags/Deployment", json!("foreign-deployment")),
            (
                "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/region",
                json!("cn-other"),
            ),
            (
                "csi.alibabacloud.com/label-prefix/topology.diskplugin.csi.alibabacloud.com/zone",
                json!("cn-hangzhou-other"),
            ),
            (
                "csi.alibabacloud.com/label-prefix/csi.alibabacloud.com/disktype",
                json!("cloud_essd.PL2"),
            ),
            (
                "csi.alibabacloud.com/annotation-prefix/csi.alibabacloud.com/volume-topology",
                json!("{}"),
            ),
            ("storage.kubernetes.io/csiProvisionerIdentity", json!("")),
            ("performanceLevelAlias", json!("PL1")),
            ("unknown", Value::Null),
        ] {
            let mut invalid = variant.clone();
            invalid["spec"]["csi"]["volumeAttributes"][key] = value;
            assert!(
                project_raw_pv_create_template(&invalid, &e).is_err(),
                "{key}"
            );
        }
        let mut missing = variant.clone();
        missing["spec"]["csi"]["volumeAttributes"]
            .as_object_mut()
            .ok_or(ManifestError::Encoding)?
            .remove("encrypted");
        assert!(project_raw_pv_create_template(&missing, &e).is_err());
    }
    for (path, value) in [
        ("/spec/claimRef/uid", json!(Uuid::from_u128(99))),
        ("/spec/csi/driver", json!("other.csi.example")),
        ("/spec/csi/volumeHandle", json!("d-other")),
        (
            "/spec/storageClassName",
            json!(f.context.storage_contract.mapping.delivery.name),
        ),
        ("/spec/volumeMode", json!("Filesystem")),
        ("/spec/persistentVolumeReclaimPolicy", json!("Delete")),
        (
            "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/values",
            json!(f.context.storage_contract.mapping.topology.zone_ids),
        ),
        ("/metadata/finalizers", json!([CSI_FINALIZER])),
    ] {
        assert!(
            project_raw_pv_create_template(&change(&retry, path, value)?, &e).is_err(),
            "{path}"
        );
    }
    let mut live = retry;
    live["metadata"]["resourceVersion"] = json!("51");
    assert!(project_raw_pv_live_template(&live, &e, Some(Uuid::from_u128(99))).is_err());
    Ok(())
}

#[test]
fn accepted_retry_variant_is_immutable_through_status_and_retain_finalizer_updates() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let initial = f.live();
    let mut retry = initial.clone();
    retry["spec"]["csi"]["volumeAttributes"]["performanceLevel"] = json!("PL1");
    for (old, new) in [(&initial, &retry), (&retry, &initial)] {
        project_raw_pv_live_template(old, &e, None)?;
        project_raw_pv_live_template(new, &e, None)?;
        assert!(validate_raw_pv_prebound_update(old, new, &e).is_err());
        let mut bound = new.clone();
        bound["status"] = json!({"phase":"Bound","lastPhaseTransitionTime":"2026-10-09T00:00:02Z"});
        assert!(validate_raw_pv_status_update(old, &bound, &e).is_err());
        let mut retained = new.clone();
        retained["metadata"]["finalizers"] = json!([PV_PROTECTION]);
        assert!(validate_raw_pv_retain_finalizer_update(old, &retained, &e).is_err());
    }
    let first = project_raw_pv_live_template(&retry, &e, None)?;
    validate_raw_pv_prebound_update(&retry, &retry, &e)?;
    let mut bound = retry.clone();
    bound["status"] = json!({"phase":"Bound","lastPhaseTransitionTime":"2026-10-09T00:00:02Z"});
    validate_raw_pv_status_update(&retry, &bound, &e)?;
    validate_raw_pv_status_update(&bound, &bound, &e)?;
    let mut retained = bound.clone();
    retained["metadata"]["finalizers"] = json!([PV_PROTECTION]);
    validate_raw_pv_retain_finalizer_update(&bound, &retained, &e)?;
    validate_raw_pv_retain_finalizer_update(&retained, &retained, &e)?;
    assert_eq!(
        project_raw_pv_live_template(&retained, &e, Some(first.uid()))?,
        first
    );
    Ok(())
}

#[test]
fn actual_get_parent_wrapper_preserves_strict_shape_and_returns_no_authority() -> Result<()> {
    let f = Fixture::new()?;
    let e = f.expected();
    let pending = f.claim()?;
    validate_raw_pvc_live_template(&pending, &e)?;
    let mut bound = prebound(&f, &pending);
    bound["status"] =
        json!({"phase":"Bound","accessModes":["ReadWriteOnce"],"capacity":{"storage":"20Gi"}});
    validate_raw_pvc_live_template(&bound, &e)?;
    for (path, value) in [
        ("/metadata/uid", json!(Uuid::nil())),
        (
            "/metadata/annotations/volume.kubernetes.io~1selected-node",
            json!("foreign-node"),
        ),
        ("/spec/volumeName", json!("foreign-pv")),
        ("/status/phase", json!("Lost")),
    ] {
        let altered = change(&bound, path, value)?;
        assert!(validate_raw_pvc_live_template(&altered, &e).is_err());
    }
    let mut unknown = bound;
    unknown["spec"]["volumeAttributesClassName"] = json!("unapproved");
    assert!(validate_raw_pvc_live_template(&unknown, &e).is_err());
    Ok(())
}
