//! Exercise the production TLS Kubernetes client against an explicit fixture
//! kubeconfig. Successful readback is not a Kata/cloud isolation certificate.
#[tokio::main]
async fn main() {
    use sandbox_platform::runtime::{KubernetesRuntime, RuntimeError};
    let result = match KubernetesRuntime::connect().await {
        Ok(runtime) => runtime.verify_runtime_class().await,
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => println!("PASS_CURRENT_MANAGED_RUNTIMECLASS_READBACK"),
        Err(error) => {
            let category = match error {
                RuntimeError::Kubernetes(Some(404)) => "READBACK_REJECTED_NOT_FOUND",
                RuntimeError::InvalidRuntimeClass => "READBACK_REJECTED_CONFIGURATION",
                _ => "READBACK_FAILED_TRANSPORT_OR_OTHER",
            };
            eprintln!("{category}");
            std::process::exit(1);
        }
    }
}
