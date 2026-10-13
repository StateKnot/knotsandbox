//! Trusted host-side CRI call timing, not guest readiness or VM death evidence.
//! Image pulling uses the separate containerd image endpoint and is outside this
//! interval. The existing owner/deadline is retained; observation grants no work.
use std::{future::Future, time::Instant};

use tonic::Status;
use uuid::Uuid;

pub(super) async fn observe_run<T>(
    launch_id: Uuid,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    let mut call = RunObservation {
        started: Instant::now(),
        dispatcher: tracing::dispatcher::get_default(Clone::clone),
        launch_id,
        outcome: "CANCELLED_UNKNOWN",
        grpc_code: None,
    };
    let result = future.await;
    match &result {
        Ok(_) => call.outcome = "OK",
        Err(error) => {
            call.outcome = if matches!(
                error.code(),
                tonic::Code::Cancelled | tonic::Code::DeadlineExceeded
            ) {
                "CANCELLED_UNKNOWN"
            } else {
                "ERROR"
            };
            call.grpc_code = Some(error.code());
        }
    }
    result
}

struct RunObservation {
    started: Instant,
    dispatcher: tracing::Dispatch,
    launch_id: Uuid,
    outcome: &'static str,
    grpc_code: Option<tonic::Code>,
}

impl Drop for RunObservation {
    fn drop(&mut self) {
        tracing::dispatcher::with_default(&self.dispatcher, || {
            tracing::info!(
                scope="HOST_RUNTIME_CALL",phase="CRI_RUN_SANDBOX_ROUND_TRIP",
                duration_micros=u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX),
                outcome=self.outcome,grpc_code=?self.grpc_code,launch_id=%self.launch_id,
                "host runtime call observed"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("test writer lock"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Output {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
    fn capture() -> (Output, tracing::Dispatch) {
        let output = Output::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(output.clone())
            .json()
            .without_time()
            .with_ansi(false)
            .finish();
        (output, tracing::Dispatch::new(subscriber))
    }
    fn events(output: &Output) -> anyhow::Result<Vec<serde_json::Value>> {
        let bytes = output
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("test writer lock"))?
            .clone();
        String::from_utf8(bytes)?
            .lines()
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }

    #[tokio::test]
    async fn host_run_returns_original_value_and_records_only_fixed_call_scope()
    -> anyhow::Result<()> {
        let (output, dispatch) = capture();
        let launch = Uuid::new_v4();
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let value = observe_run(launch, async {
            tokio::time::sleep(Duration::from_millis(2)).await;
            Ok::<_, Status>("PRIVATE_RUNTIME_RESPONSE")
        })
        .await?;
        assert_eq!(value, "PRIVATE_RUNTIME_RESPONSE");
        let rows = events(&output)?;
        assert_eq!(rows.len(), 1);
        let fields = &rows[0]["fields"];
        assert_eq!(fields["scope"], "HOST_RUNTIME_CALL");
        assert_eq!(fields["phase"], "CRI_RUN_SANDBOX_ROUND_TRIP");
        assert_eq!(fields["outcome"], "OK");
        assert_eq!(fields["launch_id"], launch.to_string());
        assert!(fields["duration_micros"].as_u64().is_some_and(|v| v > 0));
        assert!(!rows[0].to_string().contains("PRIVATE_RUNTIME_RESPONSE"));
        Ok(())
    }

    #[tokio::test]
    async fn host_run_error_preserves_status_without_logging_provider_message() -> anyhow::Result<()>
    {
        let (output, dispatch) = capture();
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let error = observe_run(Uuid::new_v4(), async {
            Err::<(), _>(Status::unavailable("PRIVATE_REGISTRY_AUTH_AND_URL"))
        })
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("expected original status"))?;
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(error.message(), "PRIVATE_REGISTRY_AUTH_AND_URL");
        let rows = events(&output)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["fields"]["outcome"], "ERROR");
        assert!(
            rows[0]["fields"]["grpc_code"]
                .as_str()
                .is_some_and(|v| v.contains("Unavailable"))
        );
        assert!(
            !rows[0]
                .to_string()
                .contains("PRIVATE_REGISTRY_AUTH_AND_URL")
        );
        Ok(())
    }

    #[tokio::test]
    async fn host_run_returned_cancel_and_deadline_keep_unknown_and_original_status()
    -> anyhow::Result<()> {
        for status in [
            Status::cancelled("PRIVATE_CANCEL"),
            Status::deadline_exceeded("PRIVATE_DEADLINE"),
        ] {
            let (output, dispatch) = capture();
            let _guard = tracing::dispatcher::set_default(&dispatch);
            let expected = status.code();
            let returned = observe_run(Uuid::new_v4(), async { Err::<(), _>(status) })
                .await
                .err()
                .ok_or_else(|| anyhow::anyhow!("expected original status"))?;
            assert_eq!(returned.code(), expected);
            let rows = events(&output)?;
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["fields"]["outcome"], "CANCELLED_UNKNOWN");
            assert!(!rows[0].to_string().contains("PRIVATE_CANCEL"));
            assert!(!rows[0].to_string().contains("PRIVATE_DEADLINE"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn host_run_started_cancellation_records_unknown_on_original_dispatcher()
    -> anyhow::Result<()> {
        let (output, dispatch) = capture();
        let launch = Uuid::new_v4();
        let mut call = Box::pin(observe_run(
            launch,
            std::future::pending::<Result<(), Status>>(),
        ));
        {
            let _guard = tracing::dispatcher::set_default(&dispatch);
            std::future::poll_fn(|cx| {
                assert!(call.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert!(events(&output)?.is_empty());
        drop(call);
        let rows = events(&output)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["fields"]["outcome"], "CANCELLED_UNKNOWN");
        assert_eq!(rows[0]["fields"]["launch_id"], launch.to_string());
        assert!(!rows[0].to_string().contains("PRIVATE_RUNTIME_RESPONSE"));
        Ok(())
    }

    #[test]
    fn host_run_unpolled_future_does_not_fabricate_an_observation() -> anyhow::Result<()> {
        let (output, dispatch) = capture();
        let _guard = tracing::dispatcher::set_default(&dispatch);
        drop(observe_run(Uuid::new_v4(), async { Ok::<_, Status>(()) }));
        assert!(events(&output)?.is_empty());
        Ok(())
    }
}
