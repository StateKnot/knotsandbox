//! Runtime request ownership shared by the Linux CRI proxy and actual gRPC
//! cancellation tests. It grants no launch authority and creates no evidence.
use super::cri_transport::RuntimeTransport;
use futures_util::{Stream, StreamExt};
use std::{future::Future, pin::Pin};
use tokio_util::{
    sync::CancellationToken,
    task::{TaskTracker, task_tracker::TaskTrackerToken},
};
use tonic::{Response, Status};

pub(super) fn request_token(tasks: &TaskTracker) -> Result<TaskTrackerToken, Status> {
    // Acquiring before testing closed makes admission atomic with drain:
    // pre-close work is counted; post-close work cannot execute the closure.
    let token = tasks.token();
    if tasks.is_closed() {
        return Err(Status::failed_precondition("Host runtime is draining"));
    }
    Ok(token)
}

/// Reject new CRI/CONTROL work before cancelling only the pure read RPCs.
/// Existing owners retain their tokens until the actual side effect settles.
pub(super) fn begin_drain(tasks: &TaskTracker, reads: &CancellationToken) {
    tasks.close();
    reads.cancel();
}

pub(super) async fn owned_rpc<T, F, Fut>(tasks: &TaskTracker, work: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, Status>> + Send + 'static,
{
    let token = request_token(tasks)?;
    tokio::spawn(async move {
        let _token = token;
        work().await
    })
    .await
    .map_err(|_| Status::failed_precondition("Host runtime work did not complete"))?
}

pub(super) async fn read_rpc<T, F, Fut>(
    tasks: &TaskTracker,
    shutdown: &CancellationToken,
    work: F,
) -> Result<T, Status>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, Status>>,
{
    let _token = request_token(tasks)?;
    if shutdown.is_cancelled() {
        return Err(Status::unavailable("Host runtime reads are draining"));
    }
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err(Status::unavailable("Host runtime reads are draining")),
        result = async { work().await } => result,
    }
}

pub(super) type ReadStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// End only this read stream. A terminal error avoids presenting a truncated
/// finite list as a successful complete response. Dropping the upstream body
/// resets that RPC, while other streams on the connection keep their owners.
pub(super) fn read_stream<T, S>(source: S, shutdown: CancellationToken) -> ReadStream<T>
where
    T: Send + 'static,
    S: Stream<Item = Result<T, Status>> + Send + 'static,
{
    Box::pin(futures_util::stream::unfold(
        Some(Box::pin(source)),
        move |source| {
            let shutdown = shutdown.clone();
            async move {
                let mut source = source?;
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        drop(source);
                        Some((Err(Status::unavailable("Host runtime reads are draining")), None))
                    },
                    item = source.next() => item.map(|item| (item, Some(source))),
                }
            }
        },
    ))
}

pub(super) fn read_stream_response<T, S>(
    response: Response<S>,
    shutdown: CancellationToken,
) -> Response<ReadStream<T>>
where
    T: Send + 'static,
    S: Stream<Item = Result<T, Status>> + Send + 'static,
{
    response.map(|source| read_stream(source, shutdown))
}

/// Close pure reads without dropping the real tonic parent. Existing mutation
/// owners and host work must still settle, including after transport failure.
pub(super) async fn serve_read_parent<P, T, F>(
    shutdown: &CancellationToken,
    parent: P,
    close_reads: F,
    transport: &RuntimeTransport,
) -> T
where
    P: Future<Output = T>,
    F: FnOnce(),
{
    tokio::pin!(parent);
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            close_reads();
            transport.stop_accepting();
            let result = tokio::select! {
                biased;
                result = &mut parent => result,
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    transport.close_io();
                    parent.await
                },
            };
            transport.close_io();
            transport.wait_closed().await;
            result
        },
        result = &mut parent => {
            close_reads();
            transport.close_io();
            transport.wait_closed().await;
            result
        },
    }
}

#[cfg(test)]
#[path = "cri_work_tests.rs"]
mod tests;
