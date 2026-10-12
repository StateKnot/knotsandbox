use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "Requires PostgreSQL, Node.js 22+ and the built TypeScript SDK"]
async fn real_node_sdk_streams_reconnects_and_obeys_revocation_over_tcp() -> anyhow::Result<()> {
    let _serial = serial().await;
    let fixture = fixture().await?;
    let mut tx = fixture.owner_transaction().await?;
    let first = insert_event(&mut tx, &fixture, Uuid::new_v4(), 1, 0).await?;
    tx.commit().await?;
    let shutdown = CancellationToken::new();
    let (app, token, jwks) = http_app(&fixture, 300, shutdown.clone()).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let outcome=async {
        let root=std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        anyhow::ensure!(root.join("sdk/typescript/dist/events.js").is_file(),"Build the TypeScript SDK before running its real integration test");
        let mut child=tokio::process::Command::new("node")
            .arg(root.join("sdk/typescript/test/integration/event-stream.mjs"))
            .env_clear().env("PATH",std::env::var_os("PATH").unwrap_or_default())
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .kill_on_drop(true).spawn().context("Cannot start SDK integration child")?;
        let mut input=child.stdin.take().context("child stdin missing")?;
        let output=child.stdout.take().context("child stdout missing")?;
        let mut lines=tokio::io::BufReader::new(output).lines();
        let setup=json!({"baseUrl":format!("http://{address}"),"tenantId":fixture.actor.tenant_id,"projectId":fixture.request.project_id,"token":token});
        // Credentials only cross the private pipe; never argv, disk or logs.
        input.write_all(serde_json::to_string(&setup)?.as_bytes()).await?;
        input.write_all(b"\n").await?;
        let line=tokio::time::timeout(Duration::from_secs(15),lines.next_line()).await??.context("Node ended before first event")?;
        anyhow::ensure!(line.len()<8192,"Child output exceeded protocol bound");
        let received:Value=serde_json::from_str(&line)?;
        anyhow::ensure!(received["phase"]=="received" && received["eventId"]==first.to_string(),"SDK did not receive the first committed event");
        let mut tx=fixture.owner_transaction().await?;
        let second=insert_event(&mut tx,&fixture,Uuid::new_v4(),1,-3600).await?;
        tx.commit().await?;
        let line=tokio::time::timeout(Duration::from_secs(15),lines.next_line()).await??.context("Node ended before resumed event")?;
        anyhow::ensure!(line.len()<8192,"Child output exceeded protocol bound");
        let resumed:Value=serde_json::from_str(&line)?;
        anyhow::ensure!(resumed["phase"]=="resumed" && resumed["eventId"]==second.to_string(),"SDK did not resume the later commit from its original cursor");
        let mut tx=fixture.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='events:read'").bind(fixture.actor.tenant_id).execute(&mut *tx).await?;
        tx.commit().await?;
        input.write_all(b"{\"action\":\"continue\"}\n").await?;
        let line=tokio::time::timeout(Duration::from_secs(15),lines.next_line()).await??.context("Node ended before revocation acknowledgement")?;
        anyhow::ensure!(line.len()<8192,"Child output exceeded protocol bound");
        let revoked:Value=serde_json::from_str(&line)?;
        anyhow::ensure!(revoked["phase"]=="revoked","SDK did not reject the revoked subscription");
        drop(input);
        let status=tokio::time::timeout(Duration::from_secs(5),child.wait()).await??;
        anyhow::ensure!(status.success(),"Node event stream integration failed");
        Ok::<_,anyhow::Error>(())
    }.await;
    shutdown.cancel();
    server.abort();
    jwks.abort();
    outcome
}
