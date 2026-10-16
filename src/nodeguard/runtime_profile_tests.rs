use super::*;
use anyhow::Context;
use serde_json::{Value, json};

fn configuration() -> Value {
    fn runtime(kind: &str, options: Value) -> Value {
        json!({"runtimeType":kind,"runtimePath":"","baseRuntimeSpec":"","snapshotter":"",
            "sandboxer":"podsandbox","io_type":"","options":options,
            "PodAnnotations":null,"ContainerAnnotations":null,"cgroupWritable":false,
            "privileged_without_host_devices":false,
            "privileged_without_host_devices_all_devices_allowed":false,
            "cniConfDir":"","cniMaxConfNum":0})
    }
    json!({"containerdRootDir":"/var/lib/containerd",
        "containerdEndpoint":"/run/containerd/containerd.sock",
        "rootDir":"/var/lib/containerd/io.containerd.grpc.v1.cri",
        "stateDir":"/run/containerd/io.containerd.grpc.v1.cri",
        "containerd":{"defaultRuntimeName":"runc","runtimes":{
            "runc":runtime("io.containerd.runc.v2",json!({"SystemdCgroup":true})),
            "kata-qemu":runtime("io.containerd.kata.v2",json!({"ConfigPath":"/public/kata.toml"}))}}})
}
fn response(config: String) -> StatusResponse {
    StatusResponse {
        status: Some(RuntimeStatus {
            conditions: vec![
                RuntimeCondition {
                    r#type: "RuntimeReady".into(),
                    status: true,
                    ..Default::default()
                },
                RuntimeCondition {
                    r#type: "NetworkReady".into(),
                    status: false,
                    ..Default::default()
                },
            ],
        }),
        info: std::collections::HashMap::from([("config".into(), config)]),
        runtime_handlers: ["", "runc", "kata-qemu"]
            .into_iter()
            .map(|name| RuntimeHandler {
                name: name.into(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}
fn accepted(value: Value) -> bool {
    check(&response(value.to_string()), Path::new("/public/kata.toml")).is_ok()
}

#[test]
fn loaded_runtime_subset_accepts_bootstrap_without_claiming_network_or_shim_readiness() {
    assert!(accepted(configuration()));
    let mut config = configuration();
    config["containerd"]["runtimes"]["kata-qemu"]["snapshotter"] = json!("overlayfs");
    config["containerd"]["runtimes"]["kata-qemu"]["io_type"] = json!("fifo");
    config["containerd"]["runtimes"]["kata-qemu"]["PodAnnotations"] = json!([]);
    config["uninterpretedPluginSetting"] =
        json!({"public":"extra top-level config is not certified"});
    assert!(accepted(config));
}

#[test]
fn roots_default_handlers_runtime_and_kata_overrides_reject() -> anyhow::Result<()> {
    for pointer in [
        "/containerdRootDir",
        "/containerdEndpoint",
        "/rootDir",
        "/stateDir",
        "/containerd/defaultRuntimeName",
        "/containerd/runtimes/kata-qemu/runtimeType",
        "/containerd/runtimes/runc/runtimeType",
        "/containerd/runtimes/kata-qemu/runtimePath",
        "/containerd/runtimes/kata-qemu/baseRuntimeSpec",
        "/containerd/runtimes/kata-qemu/snapshotter",
        "/containerd/runtimes/kata-qemu/sandboxer",
        "/containerd/runtimes/kata-qemu/io_type",
        "/containerd/runtimes/kata-qemu/cniConfDir",
        "/containerd/runtimes/kata-qemu/options/ConfigPath",
    ] {
        let mut value = configuration();
        *value.pointer_mut(pointer).context("fixture pointer")? = json!("PRIVATE_PROVIDER_DETAIL");
        assert!(!accepted(value), "{pointer}");
    }
    for pointer in [
        "/containerd/runtimes/kata-qemu/cgroupWritable",
        "/containerd/runtimes/kata-qemu/privileged_without_host_devices",
        "/containerd/runtimes/kata-qemu/privileged_without_host_devices_all_devices_allowed",
    ] {
        let mut value = configuration();
        *value.pointer_mut(pointer).context("fixture pointer")? = json!(true);
        assert!(!accepted(value));
    }
    for pointer in [
        "/containerd/runtimes/kata-qemu/PodAnnotations",
        "/containerd/runtimes/kata-qemu/ContainerAnnotations",
    ] {
        let mut value = configuration();
        *value.pointer_mut(pointer).context("fixture pointer")? = json!(["*"]);
        assert!(!accepted(value));
    }
    let mut value = configuration();
    value["containerd"]["runtimes"]["kata-qemu"]["cniMaxConfNum"] = json!(1);
    assert!(!accepted(value));
    let mut value = configuration();
    value["containerd"]["runtimes"]["runc"]["options"]["SystemdCgroup"] = json!(false);
    assert!(!accepted(value));
    for (pointer, key) in [
        ("/containerd/runtimes", "extra-handler"),
        ("/containerd/runtimes/kata-qemu", "extra"),
        ("/containerd/runtimes/kata-qemu/options", "BinaryName"),
    ] {
        let mut value = configuration();
        value
            .pointer_mut(pointer)
            .context("fixture pointer")?
            .as_object_mut()
            .context("fixture object")?
            .insert(key.into(), json!("unexpected"));
        assert!(!accepted(value));
    }
    Ok(())
}

#[test]
fn missing_ambiguous_malformed_and_oversized_reports_reject_without_provider_details()
-> anyhow::Result<()> {
    let config = configuration().to_string();
    for raw in [
        "{}".into(),
        "[]".into(),
        "not JSON PRIVATE_PROVIDER_DETAIL".into(),
        config.replace(
            "\"runtimeType\":\"io.containerd.kata.v2\"",
            "\"runtimeType\":\"bad\",\"runtimeType\":\"io.containerd.kata.v2\"",
        ),
        config.replace(
            "\"ConfigPath\":",
            "\"ConfigPath\":\"bad\",\"Config\\u0050ath\":",
        ),
        config.replace(
            "\"defaultRuntimeName\":",
            "\"defaultRuntimeName\":\"bad\",\"defaultRuntimeName\":",
        ),
        format!("{config}{{}}"),
        " ".repeat(CONFIG_LIMIT + 1),
    ] {
        let error = check(&response(raw), Path::new("/public/kata.toml"))
            .err()
            .context("malformed report accepted")?;
        assert!(!error.to_string().contains("PRIVATE_PROVIDER_DETAIL"));
    }
    let mut report = response(config.clone());
    report.info.clear();
    assert!(check(&report, Path::new("/public/kata.toml")).is_err());
    let mut report = response(config.clone());
    report.status = None;
    assert!(check(&report, Path::new("/public/kata.toml")).is_err());
    let mut report = response(config.clone());
    report.runtime_handlers[0].name = "runc".into();
    assert!(check(&report, Path::new("/public/kata.toml")).is_err());
    let mut report = response(config.clone());
    report
        .status
        .as_mut()
        .context("fixture conditions")?
        .conditions[0]
        .status = false;
    assert!(check(&report, Path::new("/public/kata.toml")).is_err());
    let mut report = response(config);
    report
        .status
        .as_mut()
        .context("fixture conditions")?
        .conditions
        .push(RuntimeCondition {
            r#type: "RuntimeReady".into(),
            status: true,
            ..Default::default()
        });
    assert!(check(&report, Path::new("/public/kata.toml")).is_err());
    Ok(())
}

mod wire {
    use super::*;
    use std::{
        convert::Infallible,
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };
    use tonic::{Request, Response, Status, body::Body, codegen::http};
    use tower::Service;
    type Reply = Pin<Box<dyn Future<Output = Result<Response<StatusResponse>, Status>> + Send>>;
    #[derive(Clone)]
    struct Fixture(Arc<Mutex<Option<StatusResponse>>>);
    impl tonic::server::UnaryService<StatusRequest> for Fixture {
        type Response = StatusResponse;
        type Future = Reply;
        fn call(&mut self, request: Request<StatusRequest>) -> Self::Future {
            assert!(request.get_ref().verbose);
            assert!(request.metadata().contains_key("grpc-timeout"));
            let response = self
                .0
                .lock()
                .map(|state| state.clone())
                .map_err(|_| Status::internal("fixture state poisoned"));
            Box::pin(async move {
                match response? {
                    Some(value) => Ok(Response::new(value)),
                    None => futures_util::future::pending().await,
                }
            })
        }
    }
    impl tonic::server::NamedService for Fixture {
        const NAME: &'static str = "runtime.v1.RuntimeService";
    }
    impl Service<http::Request<Body>> for Fixture {
        type Response = http::Response<Body>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, request: http::Request<Body>) -> Self::Future {
            assert_eq!(request.uri().path(), "/runtime.v1.RuntimeService/Status");
            let service = self.clone();
            Box::pin(async move {
                Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                    .unary(service, request)
                    .await)
            })
        }
    }
    #[tokio::test]
    async fn actual_grpc_verbose_contract_decode_bounds_and_original_timeout() -> anyhow::Result<()>
    {
        let state = Arc::new(Mutex::new(Some(response(configuration().to_string()))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let shutdown = tokio_util::sync::CancellationToken::new();
        let ending = shutdown.clone();
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(Fixture(state.clone()))
                .serve_with_incoming_shutdown(
                    futures_util::stream::unfold(listener, |listener| async move {
                        Some((listener.accept().await.map(|(stream, _)| stream), listener))
                    }),
                    ending.cancelled_owned(),
                ),
        );
        let client =
            runtime_service_client::RuntimeServiceClient::connect(format!("http://{address}"))
                .await?;
        let outcome = async {
            verify(client.clone(), Path::new("/public/kata.toml")).await?;
            let mismatch = verify(client.clone(), Path::new("/public/other.toml")).await;
            assert!(matches!(mismatch, Err(GuardError::IdentityMismatch)));
            *state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture state poisoned"))? =
                Some(response("x".repeat(CONFIG_LIMIT + 1)));
            assert!(matches!(
                verify(client.clone(), Path::new("/public/kata.toml")).await,
                Err(GuardError::IdentityMismatch)
            ));
            *state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture state poisoned"))? =
                Some(response("x".repeat(RPC_LIMIT + 1)));
            assert!(matches!(
                verify(client.clone(), Path::new("/public/kata.toml")).await,
                Err(GuardError::Unknown)
            ));
            *state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture state poisoned"))? = None;
            let started = std::time::Instant::now();
            assert!(
                verify(client, Path::new("/public/kata.toml"))
                    .await
                    .is_err()
            );
            assert!(started.elapsed() < Duration::from_secs(6));
            Ok::<_, anyhow::Error>(())
        }
        .await;
        shutdown.cancel();
        server.await??;
        outcome
    }
}
