//! Authored pure protocol tests, not signed TCP, cloud IAM or SQL acceptance.
#![allow(clippy::expect_used)]
use super::*;

fn expected() -> ExpectedDisk {
    ExpectedDisk {
        restore_id: Uuid::parse_str("10000000-0000-4000-8000-000000000001").expect("fixture"),
        parent_uid: Uuid::parse_str("20000000-0000-4000-8000-000000000002").expect("fixture"),
        account_id: "1234567890123456".into(),
        region: "cn-hangzhou".into(),
        disk_id: "d-target".into(),
        zone_id: "cn-hangzhou-a".into(),
        deployment: "sandbox".into(),
        kms_key_id: "compute/key-1".into(),
        size_gib: 20,
        selected_instance_id: "i-target".into(),
        source_disk_id: "d-source".into(),
        clone_disk_ids: BTreeSet::from(["d-clone".into()]),
        parent_intent_created_at: Utc::now() - ChronoDuration::seconds(30),
        recorded_identity: None,
    }
}
fn value(e: &ExpectedDisk) -> Value {
    json!({"RequestId":"raw-disk-public-fixture","NextToken":"","Disks":{"Disk":[{
        "DiskId":e.disk_id,"RegionId":e.region,"ZoneId":e.zone_id,"Type":"data",
        "Category":"cloud_essd","PerformanceLevel":"PL1","Portable":true,"Encrypted":true,
        "KMSKeyId":e.kms_key_id,"Size":e.size_gib,"DiskChargeType":"PostPaid",
        "DeleteWithInstance":false,"MultiAttach":"Disabled","Status":"Available",
        "SerialNumber":"fixture-serial","CreationTime":(Utc::now()-ChronoDuration::seconds(1))
            .to_rfc3339_opts(SecondsFormat::Micros,true),
        "Tags":{"Tag":[{"TagKey":"Deployment","TagValue":e.deployment},
            {"TagKey":"kubernetes.io/created-for/pvc/namespace","TagValue":"sandbox-system"},
            {"TagKey":"kubernetes.io/created-for/pvc/name","TagValue":e.pvc_name()},
            {"TagKey":"kubernetes.io/created-for/pv/name","TagValue":e.pv_name()}]}
    }]}})
}
fn response(body: &Value) -> Response {
    let bytes = serde_json::to_vec(body).expect("fixture");
    let now = Utc::now();
    Response {
        status: StatusCode::OK,
        body: bytes.clone(),
        retry_after: None,
        evidence: CloudRequestEvidence {
            action: "DescribeDisks",
            local_request_id: Uuid::new_v4(),
            provider_request_id: Some("raw-disk-public-fixture".into()),
            sent_at: now,
            received_at: now,
            http_status: Some(200),
            response_sha256: Some(hex::encode(Sha256::digest(&bytes))),
        },
    }
}
fn accepted(body: &Value) -> bool {
    decode(
        expected(),
        &response(body),
        AbsoluteDeadline::now() + Duration::from_secs(5),
    )
    .is_ok()
}
#[test]
fn exact_identity_wire_and_incomplete_available_attachments_do_not_assert_absence() {
    let e = expected();
    let body = value(&e);
    let o = decode(
        e,
        &response(&body),
        AbsoluteDeadline::now() + Duration::from_secs(5),
    )
    .expect("fixture");
    assert_eq!(o.status, DiskStatus::Available);
    assert!(o.attached_instance_ids.is_empty());
    let (identity, evidence) = o.identity_and_evidence().expect("fixture");
    assert_eq!(identity.as_object().expect("fixture").len(), 3);
    assert_eq!(identity["binding"].as_object().expect("fixture").len(), 10);
    assert_eq!(evidence.as_object().expect("fixture").len(), 3);
    assert_eq!(
        identity["binding"]["pv_name"],
        "disk-20000000-0000-4000-8000-000000000002"
    );
    assert_eq!(
        evidence["response_sha256"],
        hex::encode(Sha256::digest(&response(&body).body))
    );
    assert!(identity.get("absence").is_none());
    assert!(evidence.get("absence").is_none());
}
#[test]
fn changed_disk_properties_source_relationships_and_tag_duplicates_are_rejected() {
    let body = value(&expected());
    for (key, v) in [
        ("DiskId", json!("d-source")),
        ("RegionId", json!("cn-beijing")),
        ("ZoneId", json!("cn-hangzhou-b")),
        ("Type", json!("system")),
        ("Category", json!("cloud_auto")),
        ("PerformanceLevel", json!("PL2")),
        ("Portable", json!(false)),
        ("Encrypted", json!(false)),
        ("KMSKeyId", json!("vault-key")),
        ("Size", json!(21)),
        ("Size", json!(20.0)),
        ("DiskChargeType", json!("PrePaid")),
        ("DeleteWithInstance", json!(true)),
        ("MultiAttach", json!("Enabled")),
        ("SourceDiskId", json!("d-source")),
        ("SourceSnapshotId", json!("s-source")),
        ("ImageId", json!("m-source")),
        ("DataSource", json!({"Id":"d-source","Type":"disk"})),
        ("Status", json!("Attaching")),
        ("Status", json!("Detaching")),
        ("SerialNumber", json!("")),
    ] {
        let mut changed = body.clone();
        changed["Disks"]["Disk"][0][key] = v;
        assert!(!accepted(&changed), "{key}");
    }
    for key in [
        "PerformanceLevel",
        "SerialNumber",
        "CreationTime",
        "KMSKeyId",
        "Tags",
    ] {
        let mut changed = body.clone();
        changed["Disks"]["Disk"][0]
            .as_object_mut()
            .expect("fixture")
            .remove(key);
        assert!(!accepted(&changed), "{key}");
    }
    for i in 0..4 {
        let mut changed = body.clone();
        changed["Disks"]["Disk"][0]["Tags"]["Tag"][i]["TagValue"] = json!("foreign");
        assert!(!accepted(&changed));
    }
    let mut duplicate = body.clone();
    let tag = duplicate["Disks"]["Disk"][0]["Tags"]["Tag"][0].clone();
    duplicate["Disks"]["Disk"][0]["Tags"]["Tag"]
        .as_array_mut()
        .expect("fixture")
        .push(tag);
    assert!(!accepted(&duplicate));
    let mut reused = expected();
    reused.disk_id = "d-source".into();
    assert!(reused.validate().is_err());
    reused.disk_id = "d-clone".into();
    assert!(reused.validate().is_err());
}
#[test]
fn exact_query_response_cannot_prove_absence_or_follow_pagination() {
    let body = value(&expected());
    let mut empty = body.clone();
    empty["Disks"]["Disk"] = json!([]);
    assert!(!accepted(&empty));
    let mut page = body.clone();
    page["NextToken"] = json!("next");
    assert!(!accepted(&page));
    let mut multi = body.clone();
    let disk = multi["Disks"]["Disk"][0].clone();
    multi["Disks"]["Disk"]
        .as_array_mut()
        .expect("fixture")
        .push(disk);
    assert!(!accepted(&multi));
    let mut wrong_request = body.clone();
    wrong_request["RequestId"] = json!("wrong-request");
    assert!(!accepted(&wrong_request));
    let mut missing_hash = response(&body);
    missing_hash.evidence.response_sha256 = None;
    assert!(
        decode(
            expected(),
            &missing_hash,
            AbsoluteDeadline::now() + Duration::from_secs(5)
        )
        .is_err()
    );
}
#[test]
fn attachments_only_allow_selected_instance_and_stable_status() {
    let body = value(&expected());
    for instance in ["i-foreign", "i-target"] {
        let mut changed = body.clone();
        changed["Disks"]["Disk"][0]["InstanceId"] = json!(instance);
        assert!(!accepted(&changed)); // Available with a positive attachment is inconsistent.
    }
    let mut attached = body.clone();
    attached["Disks"]["Disk"][0]["Status"] = json!("In_use");
    attached["Disks"]["Disk"][0]["InstanceId"] = json!("i-target");
    attached["Disks"]["Disk"][0]["Attachments"] = json!({"Attachment":[{"InstanceId":"i-target"}]});
    assert!(accepted(&attached));
    for (key, v) in [
        ("InstanceId", json!("i-foreign")),
        ("MountInstanceNum", json!(2)),
        (
            "Attachments",
            json!({"Attachment":[{"InstanceId":"i-foreign"}]}),
        ),
        (
            "MountInstances",
            json!({"MountInstance":[{"InstanceId":"i-foreign"}]}),
        ),
        (
            "Attachments",
            json!({"Attachment":[{"InstanceId":"i-target"},{"InstanceId":"i-target"}]}),
        ),
    ] {
        let mut changed = attached.clone();
        changed["Disks"]["Disk"][0][key] = v;
        assert!(!accepted(&changed), "{key}");
    }
    attached["Disks"]["Disk"][0]
        .as_object_mut()
        .expect("fixture")
        .remove("InstanceId");
    assert!(!accepted(&attached));
}
#[test]
fn original_deadline_serial_creation_and_utc_precision_are_fenced() {
    let body = value(&expected());
    assert!(
        decode(
            expected(),
            &response(&body),
            AbsoluteDeadline::now() - Duration::from_secs(1)
        )
        .is_err()
    );
    let mut earlier = body.clone();
    earlier["Disks"]["Disk"][0]["CreationTime"] =
        json!((Utc::now() - ChronoDuration::days(1)).to_rfc3339_opts(SecondsFormat::Micros, true));
    assert!(!accepted(&earlier));
    let mut pinned = expected();
    pinned.recorded_identity = Some(RecordedIdentity {
        serial_number: "old-serial".into(),
        creation_time: utc(body["Disks"]["Disk"][0]["CreationTime"]
            .as_str()
            .expect("fixture"))
        .expect("fixture"),
    });
    assert!(
        decode(
            pinned,
            &response(&body),
            AbsoluteDeadline::now() + Duration::from_secs(5)
        )
        .is_err()
    );
    assert!(utc("2026-10-09T23:59:59Z").is_ok());
    assert!(utc("2026-10-09T23:59:59.123456+00:00").is_ok());
    for s in [
        "2026-10-09T24:00:00Z",
        "2026-10-09T23:60:00Z",
        "2026-10-09T23:59:60Z",
        "2026-10-09T23:59:59.123456789Z",
        "2026-10-09T23:59:59+08:00",
        "2026-02-30T00:00:00Z",
    ] {
        assert!(utc(s).is_err(), "{s}");
    }
}
#[test]
fn subjects_are_fixed_to_real_processes_and_no_credentials_are_read() {
    let identity = |subject: &str| RawDiskCloudConfig {
        account_id: "1234567890123456".into(),
        region: "cn-hangzhou".into(),
        role_arn: "acs:ram::1234567890123456:role/raw-disk-readonly-fixture".into(),
        role_id: "1234567890".into(),
        oidc_provider_arn: "acs:ram::1234567890123456:oidc-provider/fixture".into(),
        oidc_issuer: "https://issuer.fixture.invalid".into(),
        oidc_subject: subject.into(),
        oidc_token_file: "/__not_read__/fixture-token".into(),
        requests_per_second: 20,
        max_in_flight: 1,
    };
    let admission =
        AdmissionRawDiskProtocolClient::new(identity(ReadPurpose::Admission.subject()), expected())
            .expect("fixture");
    let backup = BackupRawDiskProtocolClient::new(
        identity(ReadPurpose::BackupController.subject()),
        expected(),
    )
    .expect("fixture");
    for client in [&admission.0, &backup.0] {
        let policy: Value = serde_json::from_str(
            client
                .transport
                .inner
                .config
                .session_policy
                .as_deref()
                .expect("fixture"),
        )
        .expect("fixture");
        assert_eq!(
            policy,
            json!({"Version":"1","Statement":[
                {"Effect":"Allow","Action":["ecs:DescribeDisks"],"Resource":["acs:ecs:cn-hangzhou:1234567890123456:disk/d-target"]},
                {"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}
            ]})
        );
        assert_eq!(
            client.transport.inner.sts.as_str(),
            "https://sts.cn-hangzhou.aliyuncs.com/"
        );
        assert_eq!(
            client.transport.inner.ecs.as_str(),
            "https://ecs.cn-hangzhou.aliyuncs.com/"
        );
        assert!(client.transport.inner.bindings.is_empty());
    }
    for p in [ReadPurpose::Admission, ReadPurpose::BackupController] {
        assert!(ProtocolClient::new(identity(p.subject()), expected(), p).is_ok());
        for other in [
            "system:serviceaccount:sandbox-system:sandbox-node-topology-owner",
            "system:serviceaccount:sandbox-system:sandbox-backup",
            "system:serviceaccount:sandbox-system:sandbox-restore-gc",
            "system:serviceaccount:sandbox-system:sandbox-volume-deleter",
        ] {
            assert!(ProtocolClient::new(identity(other), expected(), p).is_err());
        }
    }
    assert!(
        ProtocolClient::new(
            identity(ReadPurpose::Admission.subject()),
            expected(),
            ReadPurpose::BackupController
        )
        .is_err()
    );
    assert!(
        ProtocolClient::new(
            identity(ReadPurpose::BackupController.subject()),
            expected(),
            ReadPurpose::Admission
        )
        .is_err()
    );
}

#[test]
fn recorded_target_is_typed_and_cannot_fall_back_to_another_disk_or_serial() {
    let mut r = RawBoundRecordedDiskFacts {
        pv_uid: Uuid::from_u128(3),
        pv_spec_sha256: "a".repeat(64),
        disk_id: "d-target".into(),
        serial_number: "immutable-serial".into(),
        creation_time: Utc::now(),
    };
    assert!(recorded_target(Some(&r), "d-other").is_err());
    assert_eq!(
        recorded_target(Some(&r), "d-target")
            .expect("typed comparison")
            .expect("recorded")
            .serial_number,
        "immutable-serial"
    );
    r.serial_number.clear();
    assert!(recorded_target(Some(&r), "d-target").is_err());
    assert!(
        recorded_target(None, "d-target")
            .expect("first record only")
            .is_none()
    );
}
#[test]
fn fresh_transports_share_only_rate_and_inflight_guards_not_credentials() {
    let c = RawDiskCloudConfig {
        account_id: "1234567890123456".into(),
        region: "cn-hangzhou".into(),
        role_arn: "acs:ram::1234567890123456:role/raw-disk-readonly-fixture".into(),
        role_id: "1234567890".into(),
        oidc_provider_arn: "acs:ram::1234567890123456:oidc-provider/fixture".into(),
        oidc_issuer: "https://issuer.fixture.invalid".into(),
        oidc_subject: ReadPurpose::BackupController.subject().into(),
        oidc_token_file: "/__not_read__/fixture-token".into(),
        requests_per_second: 20,
        max_in_flight: 1,
    };
    let budget = BackupRawDiskProtocolClient::budget(&c).expect("pure config");
    let mut one =
        ProtocolClient::new(c.clone(), expected(), ReadPurpose::BackupController).expect("fresh");
    let mut two = ProtocolClient::new(c, expected(), ReadPurpose::BackupController).expect("fresh");
    one.attach_budget(&budget).expect("same budget");
    two.attach_budget(&budget).expect("same budget");
    assert!(!Arc::ptr_eq(&one.transport.inner, &two.transport.inner));
    assert!(Arc::ptr_eq(
        &one.transport.inner.next_request,
        &two.transport.inner.next_request
    ));
    assert!(Arc::ptr_eq(
        &one.transport.inner.in_flight,
        &two.transport.inner.in_flight
    ));
    assert!(!std::ptr::eq(
        &one.transport.inner.credentials,
        &two.transport.inner.credentials
    ));
    let held = one
        .transport
        .inner
        .in_flight
        .try_acquire()
        .expect("first slot");
    assert!(two.transport.inner.in_flight.try_acquire().is_err());
    drop(held);
    assert!(two.transport.inner.in_flight.try_acquire().is_ok());
}
#[test]
fn fresh_response_evidence_may_differ_but_disk_serial_and_creation_are_fixed() {
    let deadline = AbsoluteDeadline::now() + Duration::from_secs(5);
    let body = value(&expected());
    let first = decode(expected(), &response(&body), deadline).expect("pure decoded comparison");
    let mut second_body = body.clone();
    second_body["RequestId"] = json!("new-read-request");
    let mut r = response(&second_body);
    r.evidence.provider_request_id = Some("new-read-request".into());
    let second = decode(expected(), &r, deadline).expect("pure decoded comparison");
    first
        .same_identity(&second)
        .expect("evidence differs, immutable identity same");
    assert_ne!(
        first.evidence.provider_request_id,
        second.evidence.provider_request_id
    );
    let mut changed = body.clone();
    changed["Disks"]["Disk"][0]["SerialNumber"] = json!("replacement-serial");
    let replacement = decode(expected(), &response(&changed), deadline).expect("pure shape");
    assert!(first.same_identity(&replacement).is_err());
    changed = body;
    changed["Disks"]["Disk"][0]["CreationTime"] = json!(
        (Utc::now() - ChronoDuration::seconds(2)).to_rfc3339_opts(SecondsFormat::Micros, true)
    );
    let replacement = decode(expected(), &response(&changed), deadline).expect("pure shape");
    assert!(first.same_identity(&replacement).is_err());
}
