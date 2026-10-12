//! A single-purpose real loopback PostgreSQL proxy. It forwards SCRAM and all
//! wire traffic without recording it, delaying only the second COMMIT response.
use super::{AdmissionRequest, HttpFixture, RestoreGcAdmissionService};
use crate::{db::Database, termination_ledger::tests::FixtureRuntime};
use anyhow::{Context, ensure};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct CommitProxy {
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    completed: Arc<AtomicUsize>,
    delayed: Arc<tokio::sync::Notify>,
    shutdown: CancellationToken,
}
impl Drop for CommitProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl CommitProxy {
    async fn finish(&mut self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        let mut task = self.task.take().context("proxy task must remain owned")?;
        match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
            Ok(result) => result
                .context("proxy socket teardown task must join")?
                .context("proxy socket forwarding failed"),
            Err(error) => {
                // This task owns only test proxy TCP futures. Preserve the
                // deadline failure, but still join cancellation before return.
                task.abort();
                let _ = task.await;
                Err(error).context("proxy must join actual socket teardown after pool drain")
            }
        }
    }

    async fn connect() -> anyhow::Result<(Self, Database)> {
        let mut url = url::Url::parse(&std::env::var("TEST_ADMISSION_DATABASE_URL")?)?;
        ensure!(
            matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
                && url.username() == "sandbox_admission",
            "only dedicated loopback admission PostgreSQL is allowed"
        );
        let upstream = (
            url.host_str().context("loopback host")?.to_owned(),
            url.port().unwrap_or(5432),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let completed = Arc::new(AtomicUsize::new(0));
        let delayed = Arc::new(tokio::sync::Notify::new());
        let shutdown = CancellationToken::new();
        let cancelled = shutdown.clone();
        let (count, ready) = (completed.clone(), delayed.clone());
        let task = tokio::spawn(async move {
            let forwarding = async {
                // Exactly one eager pool connection. The proxy never parses client
                // SQL, startup credentials, SCRAM exchanges, rows, or error bodies.
                let (client, _) = listener.accept().await?;
                let backend = TcpStream::connect(upstream).await?;
                client.set_nodelay(true)?;
                backend.set_nodelay(true)?;
                let (mut client_read, mut client_write) = client.into_split();
                let (mut backend_read, mut backend_write) = backend.into_split();
                tokio::try_join!(
                    async {
                        tokio::io::copy(&mut client_read, &mut backend_write).await?;
                        backend_write.shutdown().await
                    },
                    async {
                        loop {
                            let mut tag = [0u8; 1];
                            match backend_read.read_exact(&mut tag).await {
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                    return Ok(());
                                }
                                Err(e) => return Err(e),
                            }
                            let mut encoded = [0u8; 4];
                            backend_read.read_exact(&mut encoded).await?;
                            let size = u32::from_be_bytes(encoded);
                            if !(4..=16 * 1024 * 1024).contains(&size) {
                                return Err(std::io::Error::other(
                                    "invalid PostgreSQL response frame",
                                ));
                            }
                            let mut payload =
                                vec![0; usize::try_from(size - 4).map_err(std::io::Error::other)?];
                            backend_read.read_exact(&mut payload).await?;
                            if tag[0] == b'C' && payload == b"COMMIT\0" {
                                let ordinal = count.fetch_add(1, Ordering::SeqCst) + 1;
                                if ordinal == 2 {
                                    // The real server has already completed COMMIT;
                                    // its response and following ReadyForQuery are held.
                                    ready.notify_one();
                                    tokio::time::sleep(Duration::from_secs(3)).await;
                                }
                            }
                            client_write.write_all(&tag).await?;
                            client_write.write_all(&encoded).await?;
                            client_write.write_all(&payload).await?;
                        }
                    }
                )?;
                Ok::<(), std::io::Error>(())
            };
            tokio::select! {
                biased;
                _ = cancelled.cancelled() => Ok(()),
                result = forwarding => result,
            }
        });
        let proxy = Self {
            task: Some(task),
            completed,
            delayed,
            shutdown,
        };
        url.set_host(Some("127.0.0.1"))
            .map_err(|_| anyhow::anyhow!("proxy host"))?;
        url.set_port(Some(port))
            .map_err(|_| anyhow::anyhow!("proxy port"))?;
        // Clear TLS negotiation for this test-only loopback wire proxy. The
        // production Database remote TLS rule and credentials are unchanged.
        let parameters: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(key, _)| key != "sslmode")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut()
            .extend_pairs(parameters)
            .append_pair("sslmode", "disable");
        let database = Database::connect(url.as_str(), 1).await?;
        Ok((proxy, database))
    }
}

pub(super) async fn run(
    fixture: &HttpFixture,
    service: &RestoreGcAdmissionService,
    review: &AdmissionRequest,
    base: &FixtureRuntime,
    tenant: Uuid,
    restore: Uuid,
) -> anyhow::Result<()> {
    let (mut proxy, database) = CommitProxy::connect().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&database.pool)
        .await?;
    let delayed = RestoreGcAdmissionService {
        database,
        ..service.clone()
    };
    fixture.state.pause.store(true, Ordering::SeqCst);
    let (copy, request) = (delayed.clone(), review.clone());
    let started = Instant::now();
    let task = tokio::spawn(async move { copy.decide(&request).await });
    tokio::time::timeout(Duration::from_secs(2), fixture.state.seen.notified())
        .await
        .with_context(|| {
            format!(
                "proxy first authority must reach real GET; COMMIT count {}",
                proxy.completed.load(Ordering::SeqCst)
            )
        })?;
    assert_eq!(
        proxy.completed.load(Ordering::SeqCst),
        1,
        "first authority COMMIT ACK is never delayed"
    );
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("UPDATE restore_gc_runs SET lease_until=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND restore_id=$2")
        .bind(tenant).bind(restore).execute(&mut *tx).await?;
    tx.commit().await?;
    fixture.state.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), proxy.delayed.notified())
        .await
        .with_context(|| {
            format!(
                "proxy must hold second COMMIT response; COMMIT count {}",
                proxy.completed.load(Ordering::SeqCst)
            )
        })?;
    let released: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND locktype IN('relation','transactionid'))")
        .bind(pid)
        .fetch_one(&base.f.owner)
        .await?;
    ensure!(
        released,
        "real backend COMMIT must release transaction locks before ACK delay"
    );
    let decision = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .context("proxy decision must finish after 3s ACK delay")??;
    ensure!(
        started.elapsed() < Duration::from_secs(10),
        "overall observation must remain inside 10 seconds"
    );
    ensure!(
        decision.err().is_some_and(|e| e.code == 403),
        "expired second-reader authority must be denied after delayed COMMIT ACK"
    );
    assert_eq!(proxy.completed.load(Ordering::SeqCst), 2);
    delayed.database.pool.close().await;
    // Pool close does not guarantee both byte-copy halves receive EOF. Cancel
    // the owned forwarding future and join it, so the actual sockets are dropped
    // before verifying that PostgreSQL has removed this connection.
    proxy.finish().await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let absent: bool = sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database())",
            )
            .bind(pid)
            .fetch_one(&base.f.owner)
            .await?;
            if absent {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("joined proxy backend must disappear from real PostgreSQL")??;
    eprintln!(
        "VERIFIED real PostgreSQL second authority COMMIT completed on backend; 3s delayed ACK crosses 2s lease, <10s whole decision denied by database-derived monotonic budget"
    );
    Ok(())
}
