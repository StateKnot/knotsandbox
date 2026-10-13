//! Transient hints, never a work queue. Share the configured pool budget and
//! preserve periodic authoritative scans when LISTEN is absent or reconnecting.
use std::time::Duration;

use sqlx::{PgPool, postgres::PgListener};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub(super) async fn listen(pool: PgPool, wake: watch::Sender<()>, shutdown: CancellationToken) {
    // A listener retains one pool connection. Max-one configurations must keep
    // that connection available for claims, heartbeats and lifecycle timers.
    if pool.options().get_max_connections() < 2 {
        tracing::warn!(
            "worker dispatch hints disabled: single-connection pool; periodic scans active"
        );
        shutdown.cancelled().await;
        return;
    }
    loop {
        let subscribed = async {
            let mut listener = PgListener::connect_with(&pool).await?;
            listener.listen("sandbox_worker_dispatch").await?;
            Ok::<_, sqlx::Error>(listener)
        };
        let subscription = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            result = subscribed => result,
        };
        if let Ok(mut listener) = subscription {
            // LISTEN is committed before requesting a fresh authoritative scan.
            // try_recv exposes a reconnect so lost notifications are recovered.
            tracing::info!("worker dispatch hints subscribed; authoritative scan requested");
            wake.send_replace(());
            loop {
                let message = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    result = listener.try_recv() => result,
                };
                match message {
                    Ok(None) => {
                        tracing::info!(
                            "worker dispatch hints reconnected; authoritative scan requested"
                        );
                        wake.send_replace(());
                    }
                    Ok(Some(_)) => {
                        // Payloads (including forged hints) carry no authority.
                        // A watch channel retains one coalesced wakeup, not an
                        // unbounded in-memory notification/operation backlog.
                        wake.send_replace(());
                    }
                    Err(_) => break,
                }
            }
            if shutdown.is_cancelled() {
                // Bound explicit cleanup. SQLx Drop also returns the borrowed
                // connection asynchronously; awaited outer pool close is the
                // final physical drain proof, never this task's completion.
                let _ = tokio::time::timeout(Duration::from_secs(2), listener.unlisten_all()).await;
                return;
            }
        }
        // Failed subscriptions drop their borrowed connection before retrying.
        // Listener failures degrade only latency, not durable claim correctness.
        tracing::warn!("worker dispatch hints unavailable; periodic scans active");
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {},
        }
    }
}
