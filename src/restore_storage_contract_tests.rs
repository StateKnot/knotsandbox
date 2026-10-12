#![allow(clippy::unwrap_used)]
use super::*;

fn fixture() -> Value {
    serde_json::from_slice(include_bytes!(
        "../tests/fixtures/restore/storage-canonical.json"
    ))
    .unwrap()
}
fn contract() -> RestoreStorageContract {
    RestoreStorageContract::parse(&fixture()["contract"]).unwrap()
}
fn class(contract: &RestoreStorageContract, purpose: RestoreStoragePurpose) -> Value {
    let mut value = expected_storage_class_spec(&contract.mapping, purpose);
    let identity = contract.mapping.class(purpose);
    value["metadata"] = json!({"name":identity.name,"uid":identity.uid});
    value
}
#[test]
fn fixed_python_rust_bytes_and_four_purpose_hashes_agree() {
    let raw = include_bytes!("../tests/fixtures/restore/storage-canonical.json");
    let fixture = fixture();
    assert_eq!(serde_json::to_vec(&fixture).unwrap(), raw);
    assert_eq!(fixture["production_activation"], false);
    let c = contract();
    for (purpose, key) in [
        (RestoreStoragePurpose::Normal, "normal"),
        (RestoreStoragePurpose::Raw, "raw"),
        (RestoreStoragePurpose::Delivery, "delivery"),
    ] {
        let value = expected_storage_class_spec(&c.mapping, purpose);
        assert_eq!(
            serde_json::to_vec(&value).unwrap(),
            serde_json::to_vec(&fixture["specs"][key]).unwrap()
        );
        assert_eq!(
            storage_class_spec_sha256(&value, &c.mapping, purpose).unwrap(),
            fixture["hashes"][key]
        );
        validate_storage_class(&class(&c, purpose), &c, purpose).unwrap();
    }
    let mut value = expected_snapshot_class_spec(&c.mapping);
    assert_eq!(
        serde_json::to_vec(&value).unwrap(),
        serde_json::to_vec(&fixture["specs"]["snapshot"]).unwrap()
    );
    assert_eq!(
        snapshot_class_spec_sha256(&value, &c.mapping).unwrap(),
        fixture["hashes"]["snapshot"]
    );
    value["metadata"] = json!({"name":c.mapping.snapshot.name,"uid":c.mapping.snapshot.uid});
    validate_snapshot_class(&value, &c).unwrap();
}
#[test]
fn contract_rejects_missing_unknown_null_numeric_and_noncanonical_identities() {
    let original = fixture()["contract"].clone();
    for pointer in [
        "/protocol",
        "/profile_id",
        "/cluster_epoch",
        "/mapping/normal",
        "/mapping/topology/zone_ids",
    ] {
        let mut v = original.clone();
        *v.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(RestoreStorageContract::parse(&v).is_err(), "{pointer}");
    }
    for value in [json!(true), json!(1.0), json!("1"), json!(0), json!(2)] {
        let mut v = original.clone();
        v["protocol"] = value;
        assert!(RestoreStorageContract::parse(&v).is_err());
    }
    for (pointer, value) in [
        ("/mapping/raw/uid", json!(Uuid::nil())),
        ("/mapping/raw/spec_sha256", json!("A".repeat(64))),
        ("/mapping/deployment", json!("Bad-Tag")),
        ("/mapping/account_id", json!(1234567890123456_u64)),
        (
            "/mapping/normal/uid",
            json!("11111111-1111-4111-8111-11111111111A"),
        ),
        (
            "/mapping/topology/key",
            json!("topology.kubernetes.io/zone"),
        ),
        (
            "/mapping/topology/zone_ids",
            json!(["cn-hangzhou-h", "cn-hangzhou-h", "cn-hangzhou-j"]),
        ),
        (
            "/mapping/topology/zone_ids",
            json!(["cn-hangzhou-j", "cn-hangzhou-i", "cn-hangzhou-h"]),
        ),
        (
            "/mapping/topology/zone_ids",
            json!(["cn-beijing-h", "cn-hangzhou-i", "cn-hangzhou-j"]),
        ),
        (
            "/mapping/topology/zone_ids",
            json!(["cn-hangzhou-h", "cn-hangzhou-i"]),
        ),
    ] {
        let mut v = original.clone();
        *v.pointer_mut(pointer).unwrap() = value;
        assert!(RestoreStorageContract::parse(&v).is_err(), "{pointer}");
    }
    for pointer in ["", "/mapping", "/mapping/raw", "/mapping/topology"] {
        let mut v = original.clone();
        v.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(false));
        assert!(RestoreStorageContract::parse(&v).is_err());
    }
    let mut v = original.clone();
    v.as_object_mut().unwrap().remove("report_sha256");
    assert!(RestoreStorageContract::parse(&v).is_err());
    let mut v = original.clone();
    v["mapping"]["delivery"]["name"] = v["mapping"]["raw"]["name"].clone();
    assert!(RestoreStorageContract::parse(&v).is_err());
    let mut v = original;
    v["mapping"]["snapshot"]["uid"] = v["mapping"]["raw"]["uid"].clone();
    assert!(RestoreStorageContract::parse(&v).is_err());
}
#[test]
fn purpose_policy_and_uid_both_precede_hash_acceptance() {
    let c = contract();
    let good = class(&c, RestoreStoragePurpose::Raw);
    for (pointer, value) in [
        ("/metadata/uid", json!(Uuid::new_v4())),
        ("/metadata/name", json!("foreign-class")),
        ("/metadata/deletionTimestamp", json!("2026-10-08T00:00:00Z")),
        (
            "/metadata/annotations",
            json!({"storageclass.kubernetes.io/is-default-class":"false"}),
        ),
        ("/metadata/namespace", json!("sandbox-system")),
        ("/metadata/ownerReferences", json!([{}])),
        ("/parameters/fsType", json!("ext4")),
        ("/parameters/kmsKeyId", json!("foreign-key")),
        ("/parameters/zoneId", json!("cn-hangzhou-h")),
        (
            "/parameters/csi.storage.k8s.io/provisioner-secret-name",
            json!("credential"),
        ),
        ("/volumeBindingMode", json!("Immediate")),
        ("/allowVolumeExpansion", json!(0)),
        ("/mountOptions", json!(["discard"])),
        (
            "/allowedTopologies",
            json!([{"matchLabelExpressions":[{"key":RESTORE_TOPOLOGY_KEY,"values":["cn-hangzhou-h"]}]}]),
        ),
    ] {
        let mut v = good.clone();
        // JSON pointer fields not yet present are added explicitly below.
        if let Some(field) = v.pointer_mut(pointer) {
            *field = value;
        } else if let Some(key) = pointer.strip_prefix("/metadata/") {
            v["metadata"][key] = value;
        } else if let Some(key) = pointer.strip_prefix("/parameters/") {
            v["parameters"][key] = value;
        }
        assert!(
            validate_storage_class(&v, &c, RestoreStoragePurpose::Raw).is_err(),
            "{pointer}"
        );
    }
    let mut v = good.clone();
    v["multiAttach"] = json!(true);
    assert!(validate_storage_class(&v, &c, RestoreStoragePurpose::Raw).is_err());
    let mut v = good;
    v["metadata"]["resourceVersion"] = json!("42");
    v["metadata"]["labels"] = json!({"app.kubernetes.io/managed-by":"sandbox-restore-storage"});
    v["metadata"]["annotations"] = json!({"kubectl.kubernetes.io/last-applied-configuration":"{}"});
    validate_storage_class(&v, &c, RestoreStoragePurpose::Raw).unwrap();
    let mut changed = c.clone();
    changed.mapping.raw.spec_sha256 = "c".repeat(64);
    assert!(validate_storage_class(&v, &changed, RestoreStoragePurpose::Raw).is_err());
    let mut wrong_purpose = class(&c, RestoreStoragePurpose::Delivery);
    wrong_purpose["metadata"] = v["metadata"].clone();
    assert!(validate_storage_class(&wrong_purpose, &c, RestoreStoragePurpose::Raw).is_err());
    let mut normal = class(&c, RestoreStoragePurpose::Normal);
    normal.as_object_mut().unwrap().remove("mountOptions");
    normal.as_object_mut().unwrap().remove("allowedTopologies");
    validate_storage_class(&normal, &c, RestoreStoragePurpose::Normal).unwrap();
    let mut delivery = class(&c, RestoreStoragePurpose::Delivery);
    delivery["parameters"]
        .as_object_mut()
        .unwrap()
        .remove("fsType");
    assert!(validate_storage_class(&delivery, &c, RestoreStoragePurpose::Delivery).is_err());
}
