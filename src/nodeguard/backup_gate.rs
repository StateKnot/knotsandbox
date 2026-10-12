//! Extra CRI constraints for trusted backup images. Admission still proves the
//! Job/Secret/PVC/CSI bindings; this gate is not a substitute for that authority.
use super::{
    cri_proto::ContainerConfig,
    protocol::{BackupStage, LaunchBinding, LaunchPurpose, valid_sha256},
};
use std::collections::HashMap;

pub(crate) fn purpose_labels_match(
    labels: &HashMap<String, String>,
    launch: &LaunchBinding,
) -> bool {
    match &launch.purpose {
        LaunchPurpose::Workload => {
            !labels.contains_key("sandbox.platform/backup-id")
                && !labels.contains_key("sandbox.platform/backup-attempt-id")
                && !labels.contains_key("sandbox.platform/purpose")
        }
        LaunchPurpose::Backup {
            backup_id,
            attempt_id,
            stage,
            ..
        } => {
            labels.get("sandbox.platform/backup-id") == Some(&backup_id.to_string())
                && labels.get("sandbox.platform/backup-attempt-id") == Some(&attempt_id.to_string())
                && labels.get("sandbox.platform/purpose")
                    == Some(&format!("backup-{}", stage.name()))
        }
    }
}

pub(crate) fn controlled_container(c: &ContainerConfig, l: &LaunchBinding) -> bool {
    if c.metadata
        .as_ref()
        .is_none_or(|m| m.name != l.container_name())
    {
        return false;
    }
    let LaunchPurpose::Backup {
        stage, image_ref, ..
    } = &l.purpose
    else {
        return true;
    };
    if c.metadata.as_ref().is_none_or(|m| m.attempt != 0)
        || c.image.as_ref().is_none_or(|i| {
            &i.user_specified_image != image_ref
                || !(i.image == *image_ref
                    || i.image.strip_prefix("sha256:").is_some_and(valid_sha256))
        })
        || c.command != ["/usr/local/bin/python3", "/app/backup.py", stage.name()]
        || !c.args.is_empty()
        || c.stdin
        || c.stdin_once
        || c.tty
        || !c.cdi_devices.is_empty()
        || c.windows.is_some()
    {
        return false;
    }
    let Some(security) = c
        .linux
        .as_ref()
        .and_then(|linux| linux.security_context.as_ref())
    else {
        return false;
    };
    if security.privileged
        || !security.readonly_rootfs
        || !security.no_new_privs
        || security.run_as_user.as_ref().is_none_or(|v| v.value != 0)
        || security.run_as_group.as_ref().is_none_or(|v| v.value != 0)
        || !security.run_as_username.is_empty()
        || security.capabilities.as_ref().is_none_or(|caps| {
            !caps.add_capabilities.is_empty()
                || !caps.add_ambient_capabilities.is_empty()
                || caps.drop_capabilities != ["ALL"]
        })
    {
        return false;
    }
    match stage {
        BackupStage::Seal => c.devices.is_empty(),
        BackupStage::Capture | BackupStage::Restore => {
            let [device] = c.devices.as_slice() else {
                return false;
            };
            // Kubelet derives this pod-scoped CSI device symlink from the exact
            // Pod UID and PV name; it is not an arbitrary /dev hostPath.
            let path = format!(
                "/var/lib/kubelet/pods/{}/volumeDevices/kubernetes.io~csi/{}",
                l.pod_uid, l.pv_name
            );
            device.container_path == "/dev/sandbox-data"
                && device.host_path == path
                && device.permissions
                    == if *stage == BackupStage::Capture {
                        "r"
                    } else {
                        "mrw"
                    }
                && c.mounts
                    .iter()
                    .all(|m| m.container_path != "/dev/sandbox-data" && m.host_path != path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodeguard::{cri_proto::*, protocol::backup_job_name};
    use uuid::Uuid;
    fn fixture(stage: BackupStage) -> (LaunchBinding, ContainerConfig) {
        let launch_id = Uuid::new_v4();
        let image = format!("registry.example.test/backup@sha256:{}", "a".repeat(64));
        let l = LaunchBinding {
            purpose: LaunchPurpose::Backup {
                backup_id: Uuid::new_v4(),
                attempt_id: launch_id,
                job_uid: Uuid::new_v4(),
                stage,
                image_ref: image.clone(),
                source_pvc_uid: Uuid::new_v4(),
            },
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            generation: 1,
            launch_id,
            pod_uid: Uuid::new_v4(),
            namespace: "sandbox-system".into(),
            pod_name: format!("{}-abc12", backup_job_name(launch_id, stage)),
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: "pvc-derived".into(),
            csi_volume_handle: "d-derived".into(),
        };
        let c = ContainerConfig {
            metadata: Some(ContainerMetadata {
                name: "backup".into(),
                attempt: 0,
            }),
            image: Some(ImageSpec {
                image: format!("sha256:{}", "d".repeat(64)),
                user_specified_image: image,
                ..Default::default()
            }),
            command: vec![
                "/usr/local/bin/python3".into(),
                "/app/backup.py".into(),
                stage.name().into(),
            ],
            devices: if stage == BackupStage::Seal {
                vec![]
            } else {
                vec![Device {
                    container_path: "/dev/sandbox-data".into(),
                    host_path: format!(
                        "/var/lib/kubelet/pods/{}/volumeDevices/kubernetes.io~csi/{}",
                        l.pod_uid, l.pv_name
                    ),
                    permissions: if stage == BackupStage::Capture {
                        "r".into()
                    } else {
                        "mrw".into()
                    },
                }]
            },
            linux: Some(LinuxContainerConfig {
                security_context: Some(LinuxContainerSecurityContext {
                    readonly_rootfs: true,
                    no_new_privs: true,
                    run_as_user: Some(Int64Value { value: 0 }),
                    run_as_group: Some(Int64Value { value: 0 }),
                    capabilities: Some(Capability {
                        drop_capabilities: vec!["ALL".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        (l, c)
    }
    #[test]
    fn raw_cri_device_image_args_and_attempt_cannot_drift() {
        let (l, c) = fixture(BackupStage::Capture);
        assert!(controlled_container(&c, &l));
        for mutation in 0..9 {
            let mut wrong = c.clone();
            match mutation {
                0 => wrong.devices[0].host_path = "/dev/vda".into(),
                1 => wrong.devices[0].permissions = "mrw".into(),
                2 => wrong.command[1] = "/workspace/evil.py".into(),
                3 => wrong.args.push("--shell".into()),
                4 => wrong
                    .metadata
                    .as_mut()
                    .map(|m| m.attempt = 1)
                    .unwrap_or_default(),
                5 => wrong
                    .image
                    .as_mut()
                    .map(|i| i.user_specified_image = "registry.example.test/backup:latest".into())
                    .unwrap_or_default(),
                6 => wrong.devices.push(wrong.devices[0].clone()),
                7 => wrong.stdin = true,
                _ => wrong.linux = None,
            };
            assert!(!controlled_container(&wrong, &l), "mutation {mutation}");
        }
        let (l, c) = fixture(BackupStage::Restore);
        assert!(controlled_container(&c, &l));
        let (l, mut c) = fixture(BackupStage::Seal);
        assert!(controlled_container(&c, &l));
        c.devices.push(Device::default());
        assert!(!controlled_container(&c, &l));
    }
    #[test]
    fn backup_purpose_is_not_an_unmanaged_runc_label() {
        let (l, _) = fixture(BackupStage::Capture);
        let mut labels = HashMap::new();
        assert!(!purpose_labels_match(&labels, &l));
        if let LaunchPurpose::Backup {
            backup_id,
            attempt_id,
            stage,
            ..
        } = &l.purpose
        {
            labels.insert("sandbox.platform/backup-id".into(), backup_id.to_string());
            labels.insert(
                "sandbox.platform/backup-attempt-id".into(),
                attempt_id.to_string(),
            );
            labels.insert(
                "sandbox.platform/purpose".into(),
                format!("backup-{}", stage.name()),
            );
        }
        assert!(purpose_labels_match(&labels, &l));
        let mut workload = l.clone();
        workload.purpose = LaunchPurpose::Workload;
        assert!(!purpose_labels_match(&labels, &workload));
    }
}
