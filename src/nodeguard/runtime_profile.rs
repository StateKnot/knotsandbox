//! Startup-only readback of the pinned containerd runtime plugin configuration.
//! This is not an images configuration, shim capability or preparation permit.
use super::{GuardError, cri_proto::*};
use serde::Deserialize;
use std::{collections::BTreeSet, path::Path, time::Duration};
use tonic::transport::Channel;

const RPC_LIMIT: usize = 256 * 1024;
const CONFIG_LIMIT: usize = 64 * 1024;

pub(super) async fn verify(
    client: runtime_service_client::RuntimeServiceClient<Channel>,
    expected_kata_configuration: &Path,
) -> Result<(), GuardError> {
    let mut request = tonic::Request::new(StatusRequest { verbose: true });
    request.set_timeout(Duration::from_secs(5));
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client.max_decoding_message_size(RPC_LIMIT).status(request),
    )
    .await
    .map_err(|_| GuardError::Expired)?
    .map_err(|_| GuardError::Unknown)?
    .into_inner();
    check(&response, expected_kata_configuration)
}

// Typed structs reject duplicate interpreted members, including escaped keys.
// Extra top-level plugin settings are deliberately not interpreted. In contrast,
// runtime and Kata options are closed to unreviewed execution overrides.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Configuration {
    containerd_root_dir: String,
    containerd_endpoint: String,
    root_dir: String,
    state_dir: String,
    containerd: Containerd,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Containerd {
    default_runtime_name: String,
    runtimes: Runtimes,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtimes {
    runc: Runtime<RuncOptions>,
    #[serde(rename = "kata-qemu")]
    kata: Runtime<KataOptions>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Runtime<O> {
    runtime_type: String,
    runtime_path: String,
    base_runtime_spec: String,
    snapshotter: String,
    sandboxer: String,
    #[serde(rename = "io_type")]
    io_type: String,
    options: O,
    #[serde(rename = "PodAnnotations")]
    pod_annotations: Option<Vec<String>>,
    #[serde(rename = "ContainerAnnotations")]
    container_annotations: Option<Vec<String>>,
    cgroup_writable: bool,
    #[serde(rename = "privileged_without_host_devices")]
    privileged_without_host_devices: bool,
    #[serde(rename = "privileged_without_host_devices_all_devices_allowed")]
    privileged_without_host_devices_all_devices_allowed: bool,
    cni_conf_dir: String,
    cni_max_conf_num: u32,
}
#[derive(Deserialize)]
struct RuncOptions {
    #[serde(rename = "SystemdCgroup")]
    systemd_cgroup: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KataOptions {
    #[serde(rename = "ConfigPath")]
    config_path: String,
}

fn safe_runtime<O>(runtime: &Runtime<O>) -> bool {
    runtime.runtime_path.is_empty()
        && runtime.base_runtime_spec.is_empty()
        && matches!(runtime.snapshotter.as_str(), "" | "overlayfs")
        && runtime.sandboxer == "podsandbox"
        && matches!(runtime.io_type.as_str(), "" | "fifo")
        && runtime.pod_annotations.as_ref().is_none_or(Vec::is_empty)
        && runtime
            .container_annotations
            .as_ref()
            .is_none_or(Vec::is_empty)
        && !runtime.cgroup_writable
        && !runtime.privileged_without_host_devices
        && !runtime.privileged_without_host_devices_all_devices_allowed
        && runtime.cni_conf_dir.is_empty()
        && runtime.cni_max_conf_num == 0
}

fn check(response: &StatusResponse, expected_kata: &Path) -> Result<(), GuardError> {
    let invalid = || GuardError::IdentityMismatch;
    if response.info.len() > 8
        || response
            .info
            .iter()
            .any(|(key, value)| key.len() > 64 || value.len() > CONFIG_LIMIT)
        || response.runtime_handlers.len() != 3
        || response
            .runtime_handlers
            .iter()
            .map(|handler| handler.name.as_str())
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["", "runc", "kata-qemu"])
    {
        return Err(invalid());
    }
    let conditions = &response.status.as_ref().ok_or_else(invalid)?.conditions;
    if conditions.len() > 16 {
        return Err(invalid());
    }
    let mut ready = conditions
        .iter()
        .filter(|condition| condition.r#type == "RuntimeReady");
    if ready.next().is_none_or(|condition| !condition.status) || ready.next().is_some() {
        return Err(invalid());
    }
    // NetworkReady may be false during bootstrap. No Pod or guest is started.
    let json = response.info.get("config").ok_or_else(invalid)?;
    let config: Configuration = serde_json::from_str(json).map_err(|_| invalid())?;
    if config.containerd_root_dir != "/var/lib/containerd"
        || config.containerd_endpoint != "/run/containerd/containerd.sock"
        || config.root_dir != "/var/lib/containerd/io.containerd.grpc.v1.cri"
        || config.state_dir != "/run/containerd/io.containerd.grpc.v1.cri"
        || config.containerd.default_runtime_name != "runc"
        || config.containerd.runtimes.runc.runtime_type != "io.containerd.runc.v2"
        || !config.containerd.runtimes.runc.options.systemd_cgroup
        || !safe_runtime(&config.containerd.runtimes.runc)
        || config.containerd.runtimes.kata.runtime_type != "io.containerd.kata.v2"
        || !safe_runtime(&config.containerd.runtimes.kata)
        || Some(config.containerd.runtimes.kata.options.config_path.as_str())
            != expected_kata.to_str()
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", test))]
#[path = "runtime_profile_native_tests.rs"]
mod native_tests;
#[cfg(test)]
#[path = "runtime_profile_tests.rs"]
mod tests;
