use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "Requires PostgreSQL, Node.js 22+ and the built TypeScript output SDK"]
async fn real_node_output_sdk_resumes_verifies_end_and_obeys_revocation() -> anyhow::Result<()> {
    let _serial = serial().await;
    let fixture = OutputFixture::new().await?;
    let first = fixture.segment(0, "a").await?;
    let shutdown = CancellationToken::new();
    let (app, token, jwks) = fixture.app(300, shutdown.clone()).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let outcome = async {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        anyhow::ensure!(root.join("sdk/typescript/dist/output-stream.js").is_file(), "Build TypeScript SDK first");
        let mut child = tokio::process::Command::new("node")
            .arg(root.join("sdk/typescript/test/integration/output-stream.mjs"))
            .env_clear().env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .kill_on_drop(true).spawn().context("Cannot start output SDK integration")?;
        let mut input = child.stdin.take().context("child stdin missing")?;
        let output = child.stdout.take().context("child stdout missing")?;
        let mut lines = tokio::io::BufReader::new(output).lines();
        let setup = json!({"baseUrl":format!("http://{address}"),"tenantId":fixture.db.actor.tenant_id,"executionId":fixture.execution,"token":token});
        // Only a private pipe carries the JWT; no environment, argv or logs.
        input.write_all(serde_json::to_string(&setup)?.as_bytes()).await?;
        input.write_all(b"\n").await?;
        let received = protocol(&mut lines).await?;
        anyhow::ensure!(received["phase"] == "received" && received["sequence"] == 0, "First committed segment was not consumed");
        let second = fixture.segment(1, "b").await?;
        let resumed = protocol(&mut lines).await?;
        anyhow::ensure!(resumed["phase"] == "resumed" && resumed["sequence"] == 1, "SDK did not resume at next segment");
        fixture.close(Some(vec![first, second])).await?;
        input.write_all(b"{\"action\":\"closed\"}\n").await?;
        anyhow::ensure!(protocol(&mut lines).await?["phase"] == "complete", "SDK did not verify final manifest");
        let mut tx = fixture.db.owner_transaction().await?;
        let unknown:bool = sqlx::query_scalar("SELECT status='OUTCOME_UNKNOWN' AND termination_status='UNKNOWN' FROM executions WHERE tenant_id=$1 AND id=$2")
            .bind(fixture.db.actor.tenant_id).bind(fixture.execution).fetch_one(&mut *tx).await?;
        anyhow::ensure!(unknown, "Output completion changed VM termination evidence");
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='executions:output:read'")
            .bind(fixture.db.actor.tenant_id).bind(fixture.db.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        input.write_all(b"{\"action\":\"revoked\"}\n").await?;
        anyhow::ensure!(protocol(&mut lines).await?["phase"] == "revoked", "SDK did not honor revoked output permission");
        drop(input);
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        anyhow::ensure!(status.success(), "Output SDK integration child failed");
        Ok::<_,anyhow::Error>(())
    }.await;
    shutdown.cancel();
    server.abort();
    jwks.abort();
    outcome
}

async fn protocol(
    lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
) -> anyhow::Result<Value> {
    let line = tokio::time::timeout(Duration::from_secs(15), lines.next_line())
        .await??
        .context("Output SDK child ended before expected phase")?;
    anyhow::ensure!(line.len() < 8192, "Child protocol exceeded bound");
    Ok(serde_json::from_str(&line)?)
}
