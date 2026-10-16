//! Native acceptance of the production startup gate, without starting a shim or VM.
use crate::nodeguard::{
    GuardError,
    cri::CriProxy,
    cri_proto::{ListPodSandboxRequest, StatusRequest, VersionRequest},
    host::{HostObserver, HostProfile},
    journal::GateJournal,
    protocol::{
        GateState, LaunchBinding, LaunchPurpose, NodeBinding, PROTOCOL_VERSION,
        RegisterLaunchRequest,
    },
};
use anyhow::{Context, ensure};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

const LOADED_KATA_CONFIGURATION: &str = "/fixture/profile-files/kata_configuration";

fn request(node: NodeBinding) -> RegisterLaunchRequest {
    let workspace_id = Uuid::new_v4();
    RegisterLaunchRequest {
        protocol: PROTOCOL_VERSION,
        permit_id: Uuid::new_v4(),
        node,
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        launch: LaunchBinding {
            purpose: LaunchPurpose::Workload,
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id,
            generation: 1,
            launch_id: Uuid::new_v4(),
            pod_uid: Uuid::new_v4(),
            namespace: "native-runtime-profile".into(),
            pod_name: format!("sbx-ws-{workspace_id}"),
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: "pv-native-runtime-profile".into(),
            csi_volume_handle: "d-native-runtime-profile".into(),
        },
    }
}

async fn startup_case(
    profile: HostProfile,
    profile_bytes: &[u8],
    mismatch: bool,
) -> anyhow::Result<()> {
    let node = NodeBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        node_name: "native-runtime-profile-fixture".into(),
        boot_id: Uuid::parse_str(
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        )?,
        profile_sha256: hex::encode(Sha256::digest(profile_bytes)),
    };
    let expected_kata = profile.kata_configuration.path.clone();
    let observer = Arc::new(HostObserver::new(profile, node.clone())?);
    let directory = tempfile::tempdir()?;
    let journal =
        GateJournal::open(&directory.path().join("journal.sqlite3"), node.clone()).await?;
    let registration = request(node);
    let mut proxy = None;
    let outcome = async {
        ensure!(
            matches!(
                journal.register(&registration).await,
                Err(GuardError::Closed)
            ),
            "a fresh journal must refuse registration before actual startup verification"
        );
        proxy = Some(CriProxy::connect(journal.clone(), observer).await?);
        let proxy = proxy.as_ref().context("owned runtime connection")?;
        let version = tokio::time::timeout(
            Duration::from_secs(5),
            proxy.upstream.clone().version(VersionRequest {
                version: "0.1.0".into(),
            }),
        )
        .await??
        .into_inner();
        ensure!(
            version.runtime_name == "containerd"
                && version.runtime_version.trim_start_matches('v') == "2.3.5"
                && version.runtime_api_version == "v1",
            "the mismatch case must have a normally functioning pinned Version RPC"
        );
        let sandboxes = tokio::time::timeout(
            Duration::from_secs(5),
            proxy
                .upstream
                .clone()
                .list_pod_sandbox(ListPodSandboxRequest::default()),
        )
        .await??
        .into_inner();
        ensure!(
            sandboxes.items.is_empty(),
            "the mismatch case must have a functioning empty ListPodSandbox RPC"
        );
        let status = tokio::time::timeout(
            Duration::from_secs(5),
            proxy
                .upstream
                .clone()
                .status(StatusRequest { verbose: true }),
        )
        .await??
        .into_inner();
        let conditions = &status
            .status
            .as_ref()
            .context("actual CRI conditions")?
            .conditions;
        ensure!(
            conditions
                .iter()
                .any(|c| c.r#type == "RuntimeReady" && c.status)
                && conditions
                    .iter()
                    .any(|c| c.r#type == "NetworkReady" && !c.status),
            "the owned daemon must be runtime-ready while its intentionally absent CNI is not ready"
        );
        let config: serde_json::Value = serde_json::from_str(
            status
                .info
                .get("config")
                .context("actual verbose runtime config")?,
        )?;
        ensure!(
            config["containerd"]["runtimes"]["kata-qemu"]["options"]["ConfigPath"]
                == LOADED_KATA_CONFIGURATION,
            "the real daemon must report the immutable fixture's loaded Kata configuration"
        );
        ensure!(
            (expected_kata != Path::new(LOADED_KATA_CONFIGURATION)) == mismatch,
            "the independently pinned profile must differ only in the negative case"
        );
        let startup = proxy.verify_startup().await;
        if mismatch {
            ensure!(
                matches!(startup, Err(GuardError::IdentityMismatch)),
                "a loaded runtime/profile mismatch must be rejected before coverage opens"
            );
            ensure!(
                matches!(
                    journal.register(&registration).await,
                    Err(GuardError::Closed)
                ),
                "a functioning runtime with a mismatched profile must leave registration closed"
            );
        } else {
            startup?;
            let response = journal.register(&registration).await?;
            ensure!(
                response.protocol == PROTOCOL_VERSION
                    && response.state == GateState::Open
                    && response.node == registration.node
                    && response.launch == registration.launch
                    && response.permit_id == registration.permit_id
                    && response.effective_expires_at == registration.expires_at,
                "matching actual runtime readback must admit the exact registration without a VM"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Some(proxy) = proxy {
        proxy.close_reads();
        proxy.tasks.close();
        proxy.tasks.wait().await;
        drop(proxy);
    }
    journal.shutdown().await;
    outcome
}

#[tokio::test]
#[ignore = "Requires the exact isolated containerd 2.3.5 fixture and native Linux filesystem"]
async fn native_loaded_runtime_profile_keeps_mismatches_closed() -> anyhow::Result<()> {
    let profile_path = std::env::var("SANDBOX_NATIVE_IMAGE_PROFILE")?;
    ensure!(
        profile_path == "/fixture/host-profile.json",
        "fixed owned profile required"
    );
    let metadata = std::fs::symlink_metadata(&profile_path)?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "the fixture profile must be a root-owned immutable regular file"
    );
    let mut profile_bytes = Vec::new();
    std::fs::File::open(&profile_path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut profile_bytes)?;
    ensure!(
        profile_bytes.len() <= 64 * 1024,
        "bounded host profile required"
    );
    let profile: HostProfile = serde_json::from_slice(&profile_bytes)?;
    ensure!(profile.kata_configuration.path == Path::new(LOADED_KATA_CONFIGURATION));
    startup_case(profile.clone(), &profile_bytes, false).await?;

    // A separate valid, root-owned profile changes the approved path while the
    // real daemon and its immutable configuration remain untouched.
    let alternate = tempfile::Builder::new()
        .prefix("runtime-profile-")
        .tempdir_in("/run")?;
    let alternate_path = alternate.path().join("alternate-kata-configuration");
    let alternate_bytes =
        b"Public alternate approved Kata configuration fixture; never executed.\n";
    std::fs::write(&alternate_path, alternate_bytes)?;
    std::fs::set_permissions(&alternate_path, std::fs::Permissions::from_mode(0o444))?;
    let mut mismatch = profile;
    mismatch.kata_configuration.path = alternate_path;
    mismatch.kata_configuration.sha256 = hex::encode(Sha256::digest(alternate_bytes));
    let mismatch_bytes = serde_json::to_vec(&mismatch)?;
    startup_case(mismatch, &mismatch_bytes, true).await?;
    println!("NODEGUARD_NATIVE_LOADED_RUNTIME_PROFILE_GATE_VERIFIED");
    Ok(())
}
