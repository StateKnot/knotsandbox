//! Connected services retain their PostgreSQL pool until awaited shutdown.
//! These local lifecycle guarantees do not certify VM/cloud effect completion.
use std::future::Future;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// A controller may retry dependency/lock outages, but cannot recover a closed
/// pool or a permanent database contract error by repeatedly claiming work.
/// Business conflicts and remote runtime errors keep their domain retry policy.
pub(crate) fn fatal_database_failure(pool: &PgPool, error: &crate::error::ApiError) -> bool {
    pool.is_closed() || (error.code == "INTERNAL_ERROR" && !error.retryable)
}

/// Preserve the business outcome on every ordinary return, including startup
/// errors. A returned result always follows completion of local pool close.
pub async fn with_database_drain(
    pool: PgPool,
    business: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let result = business.await;
    pool.close().await;
    tracing::info!("database connection pool drained");
    result
}

/// Both parents must finish. Any first completion stops further sibling work;
/// an error never drops that sibling's shutdown future. Preserve the first
/// selected error without exposing a secondary error's potentially private text.
pub async fn run_pair(
    shutdown: CancellationToken,
    left: impl Future<Output = anyhow::Result<()>>,
    right: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    tokio::pin!(left, right);
    let (first, second) = tokio::select! {
        result = &mut left => {
            shutdown.cancel();
            (result, right.await)
        }
        result = &mut right => {
            shutdown.cancel();
            (result, left.await)
        }
    };
    first.and(second)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn first_error_cancels_and_waits_for_real_sibling_completion() {
        let token = CancellationToken::new();
        let sibling_token = token.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let sibling_completed = completed.clone();
        let (arrived_tx, arrived_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let task = tokio::spawn(run_pair(
            token,
            async { anyhow::bail!("FIRST_ERROR") },
            async move {
                sibling_token.cancelled().await;
                arrived_tx.send(()).expect("test observer alive");
                release_rx.await.expect("test release alive");
                sibling_completed.store(true, Ordering::SeqCst);
                Ok(())
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), arrived_rx)
            .await
            .expect("sibling must observe cancellation")
            .expect("observer delivered");
        assert!(!task.is_finished());
        assert!(!completed.load(Ordering::SeqCst));
        release_tx.send(()).expect("sibling still retained");
        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("joined after real completion")
            .expect("pair task joined")
            .expect_err("first error preserved");
        assert_eq!(error.to_string(), "FIRST_ERROR");
        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn first_success_propagates_sibling_shutdown_error() {
        let token = CancellationToken::new();
        let sibling_token = token.clone();
        let error = run_pair(token, async { Ok(()) }, async move {
            sibling_token.cancelled().await;
            anyhow::bail!("SECOND_ERROR")
        })
        .await
        .expect_err("successful first service must not mask later failure");
        assert_eq!(error.to_string(), "SECOND_ERROR");
    }

    #[tokio::test]
    async fn right_first_error_is_preserved_without_secondary_private_text() {
        let token = CancellationToken::new();
        let left_token = token.clone();
        let error = run_pair(
            token,
            async move {
                left_token.cancelled().await;
                anyhow::bail!("SECOND_PRIVATE_MARKER")
            },
            async { anyhow::bail!("RIGHT_FIRST_ERROR") },
        )
        .await
        .expect_err("right selected first");
        assert_eq!(error.to_string(), "RIGHT_FIRST_ERROR");
        assert!(!format!("{error:#}").contains("SECOND_PRIVATE_MARKER"));
    }

    #[tokio::test]
    async fn external_cancellation_still_waits_for_both_parents() {
        let token = CancellationToken::new();
        let left_token = token.clone();
        let right_token = token.clone();
        let (arrived_tx, arrived_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let task = tokio::spawn(run_pair(
            token.clone(),
            async move {
                left_token.cancelled().await;
                Ok(())
            },
            async move {
                right_token.cancelled().await;
                arrived_tx.send(()).expect("test observer alive");
                release_rx.await.expect("test release alive");
                Ok(())
            },
        ));
        token.cancel();
        tokio::time::timeout(Duration::from_secs(1), arrived_rx)
            .await
            .expect("actual sibling reached shutdown")
            .expect("observer delivered");
        assert!(!task.is_finished());
        release_tx.send(()).expect("sibling still retained");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("both parents finished")
            .expect("pair task joined")
            .expect("both succeeded");
    }
}
