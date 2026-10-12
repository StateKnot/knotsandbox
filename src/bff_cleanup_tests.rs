use super::cleanup_loop;
use crate::service_lifecycle::run_pair;
use anyhow::Context;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn canceled_cleanup_does_not_start_an_already_ready_tick() -> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    // The first tick is already ready, as it is in the production interval.
    cleanup_loop(
        shutdown,
        tokio::time::interval(Duration::from_secs(60)),
        move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok(0) }
        },
    )
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn api_shutdown_waits_for_in_flight_cleanup_and_does_not_start_another() -> anyhow::Result<()>
{
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let cleanup_shutdown = shutdown.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let (server_done_tx, server_done_rx) = oneshot::channel();
    let mut operation = Some((started_tx, release_rx));
    let task = tokio::spawn(run_pair(
        shutdown.clone(),
        async move {
            server_shutdown.cancelled().await;
            server_done_tx
                .send(())
                .map_err(|_| anyhow::anyhow!("SERVER_OBSERVER_CLOSED"))?;
            Ok(())
        },
        cleanup_loop(
            cleanup_shutdown,
            tokio::time::interval(Duration::from_secs(60)),
            move || {
                let operation = operation.take();
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let (started, release) = operation.ok_or(sqlx::Error::PoolClosed)?;
                    started.send(()).map_err(|_| sqlx::Error::PoolClosed)?;
                    release.await.map_err(|_| sqlx::Error::PoolClosed)?;
                    Ok(0)
                }
            },
        ),
    ));
    // These bounds belong to the test observers, not the production loop.
    tokio::time::timeout(Duration::from_secs(1), started_rx)
        .await
        .context("Cleanup did not dispatch its immediate operation")?
        .context("Cleanup start observer was lost")?;
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), server_done_rx)
        .await
        .context("Server did not finish shutdown")?
        .context("Server completion observer was lost")?;
    assert!(
        !task.is_finished(),
        "Cleanup acknowledgment is still pending"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release_tx
        .send(())
        .map_err(|_| anyhow::anyhow!("Cleanup operation was dropped before acknowledgment"))?;
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .context("Pair did not finish after cleanup acknowledgment")?
        .context("Pair task did not join")??;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn cleanup_operation_error_keeps_the_service_running_until_shutdown() -> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let stop_after_second = shutdown.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    // A short interval only makes this ordinary test finish quickly. Production
    // constructs its own unchanged 60-second interval before calling this loop.
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::time::timeout(
        Duration::from_secs(1),
        cleanup_loop(shutdown, interval, move || {
            let attempt = observed.fetch_add(1, Ordering::SeqCst);
            let shutdown = stop_after_second.clone();
            async move {
                if attempt == 0 {
                    Err(sqlx::Error::PoolClosed)
                } else {
                    shutdown.cancel();
                    Ok(0)
                }
            }
        }),
    )
    .await
    .context("A transient cleanup error stopped subsequent work")??;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}
