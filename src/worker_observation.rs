//! Internal call observations, never lifecycle or resource-release evidence.
//!
//! The monotonic duration covers one polled control-plane future. In particular,
//! ensure calls include their transport/validation work, not PVC provisioning or
//! VM boot time. OK means that call returned Ok; it does not mean an operation
//! completed or the guest executed a command. Dropping an in-flight future says
//! nothing about whether a remote side effect occurred.

use std::{future::Future, time::Instant};

use crate::{engine::Claim, error::ApiError};

#[derive(Clone, Copy)]
pub(crate) enum ObservedPhase {
    ClaimRoundTrip,
    ReconcileAttempt,
    RuntimeClassVerify,
    NamespaceVerify,
    NetworkPolicyEnsure,
    WorkspaceEnsure,
    PodEnsure,
    TrustedReadyCommit,
}

impl ObservedPhase {
    fn name(self) -> &'static str {
        match self {
            Self::ClaimRoundTrip => "CLAIM_ROUND_TRIP",
            Self::ReconcileAttempt => "RECONCILE_ATTEMPT",
            Self::RuntimeClassVerify => "RUNTIME_CLASS_VERIFY",
            Self::NamespaceVerify => "NAMESPACE_VERIFY",
            Self::NetworkPolicyEnsure => "NETWORK_POLICY_ENSURE",
            Self::WorkspaceEnsure => "WORKSPACE_ENSURE",
            Self::PodEnsure => "POD_ENSURE",
            Self::TrustedReadyCommit => "TRUSTED_READY_COMMIT",
        }
    }
}

/// Observe the existing interface without changing its result or execution.
/// None is for claim calls before an operation has been returned. Claim identity
/// is private log correlation only; no identifier becomes a metric label.
pub(crate) async fn observe<T>(
    claim: Option<&Claim>,
    phase: ObservedPhase,
    future: impl Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    let mut observation = CallObservation {
        phase,
        started: Instant::now(),
        dispatcher: tracing::dispatcher::get_default(Clone::clone),
        operation_id: claim.map(|claim| claim.operation_id.to_string()),
        lease_token: claim.map(|claim| claim.lease_token),
        outcome: "CANCELLED_UNKNOWN",
        error_code: None,
    };
    let result = future.await;
    match &result {
        Ok(_) => observation.outcome = "OK",
        Err(error) => {
            observation.outcome = "ERROR";
            observation.error_code = Some(error.code);
        }
    }
    result
}

struct CallObservation {
    phase: ObservedPhase,
    started: Instant,
    // WithSubscriber installs its dispatcher during polls, not necessarily when
    // an outer timeout/task drops the future. Retain the same dispatch for Drop.
    dispatcher: tracing::Dispatch,
    operation_id: Option<String>,
    lease_token: Option<i64>,
    outcome: &'static str,
    error_code: Option<&'static str>,
}

impl Drop for CallObservation {
    fn drop(&mut self) {
        let duration_micros = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        tracing::dispatcher::with_default(&self.dispatcher, || {
            tracing::info!(
                scope = "CONTROL_PLANE_CALL",
                phase = self.phase.name(),
                duration_micros,
                outcome = self.outcome,
                error_code = self.error_code,
                operation_id = self.operation_id.as_deref(),
                lease_token = self.lease_token,
                "control-plane call observed"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
        task::Poll,
    };

    use anyhow::{Context, ensure};
    use serde_json::Value;
    use tracing::instrument::WithSubscriber;
    use uuid::Uuid;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("capture poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
            let output = self.clone();
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_writer(move || output.clone())
                .finish()
        }

        fn events(&self) -> anyhow::Result<Vec<Value>> {
            let output = self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("capture poisoned"))?;
            let text = std::str::from_utf8(&output)?;
            ensure!(!text.contains("PRIVATE_OBSERVATION_MARKER"));
            text.lines()
                .map(|line| serde_json::from_str(line).map_err(Into::into))
                .collect()
        }
    }

    fn claim() -> Claim {
        Claim {
            tenant_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            lease_token: 17,
        }
    }

    fn single_event(events: &[Value]) -> anyhow::Result<&Value> {
        ensure!(events.len() == 1, "each started call must finish once");
        let fields = &events[0]["fields"];
        ensure!(fields["scope"] == "CONTROL_PLANE_CALL");
        ensure!(fields["duration_micros"].as_u64().is_some());
        Ok(fields)
    }

    #[tokio::test]
    async fn success_returns_the_original_value_without_logging_it() -> anyhow::Result<()> {
        let output = Capture::default();
        let claim = claim();
        let result = observe(Some(&claim), ObservedPhase::PodEnsure, async {
            tokio::task::yield_now().await;
            Ok(("PRIVATE_OBSERVATION_MARKER", 41))
        })
        .with_subscriber(output.subscriber())
        .await;
        ensure!(matches!(result, Ok(("PRIVATE_OBSERVATION_MARKER", 41))));
        let events = output.events()?;
        let fields = single_event(&events)?;
        ensure!(fields["phase"] == "POD_ENSURE");
        ensure!(fields["outcome"] == "OK");
        ensure!(fields["operation_id"] == claim.operation_id.to_string());
        ensure!(fields["lease_token"] == claim.lease_token);
        ensure!(fields.get("error_code").is_none());
        ensure!(!events[0].to_string().contains(&claim.tenant_id.to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn error_preserves_the_error_and_logs_only_its_fixed_code() -> anyhow::Result<()> {
        let output = Capture::default();
        let error = ApiError::conflict("WORKER_LEASE_LOST", "PRIVATE_OBSERVATION_MARKER");
        let request_id = error.request_id;
        let result = observe(None, ObservedPhase::ClaimRoundTrip, async {
            tokio::task::yield_now().await;
            Err::<(), _>(error)
        })
        .with_subscriber(output.subscriber())
        .await;
        let returned = result.err().context("failure must not become success")?;
        ensure!(returned.code == "WORKER_LEASE_LOST");
        ensure!(returned.detail == "PRIVATE_OBSERVATION_MARKER");
        ensure!(returned.request_id == request_id);
        let events = output.events()?;
        let fields = single_event(&events)?;
        ensure!(fields["phase"] == "CLAIM_ROUND_TRIP");
        ensure!(fields["outcome"] == "ERROR");
        ensure!(fields["error_code"] == "WORKER_LEASE_LOST");
        ensure!(fields.get("operation_id").is_none());
        ensure!(fields.get("lease_token").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn dropping_a_started_pending_call_records_unknown_on_its_dispatcher()
    -> anyhow::Result<()> {
        let output = Capture::default();
        let claim = claim();
        let mut future = Box::pin(
            observe(Some(&claim), ObservedPhase::NetworkPolicyEnsure, async {
                std::future::pending::<Result<(), ApiError>>().await
            })
            .with_subscriber(output.subscriber()),
        );
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        ensure!(output.events()?.is_empty());
        // Drop occurs outside WithSubscriber's poll dispatch, as for an outer
        // timeout or task abortion. No global subscriber is installed.
        drop(future);
        let events = output.events()?;
        let fields = single_event(&events)?;
        ensure!(fields["phase"] == "NETWORK_POLICY_ENSURE");
        ensure!(fields["outcome"] == "CANCELLED_UNKNOWN");
        ensure!(fields["operation_id"] == claim.operation_id.to_string());
        ensure!(fields.get("error_code").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn dropping_an_unpolled_call_creates_no_observation() -> anyhow::Result<()> {
        let output = Capture::default();
        let future = observe(None, ObservedPhase::ReconcileAttempt, async {
            Ok::<_, ApiError>(())
        })
        .with_subscriber(output.subscriber());
        drop(future);
        ensure!(output.events()?.is_empty());
        Ok(())
    }
}
