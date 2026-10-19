#![allow(clippy::unwrap_used)]
use super::*;
use crate::metrics::{MetricsAuthentication, MetricsBackendConfig};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

fn binding() -> NodeImageMetricBinding {
    NodeImageMetricBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        host_boot_id: Uuid::new_v4(),
        profile_sha256: "a".repeat(64),
    }
}

#[derive(Clone)]
struct Backend {
    binding: NodeImageMetricBinding,
    request: Arc<Mutex<Option<CapturedRequest>>>,
    reply: Arc<Mutex<Reply>>,
    status: Arc<AtomicU16>,
    calls: Arc<AtomicUsize>,
    blocking: Arc<AtomicBool>,
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}
struct CapturedRequest {
    authorization: String,
    form: BTreeMap<String, String>,
}
type Reply = fn(&NodeImageMetricBinding, i64) -> String;
impl Backend {
    fn new(binding: NodeImageMetricBinding) -> Self {
        Self {
            binding,
            request: Arc::new(Mutex::new(None)),
            reply: Arc::new(Mutex::new(normal)),
            status: Arc::new(AtomicU16::new(200)),
            calls: Arc::new(AtomicUsize::new(0)),
            blocking: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }
}

fn response(binding: &NodeImageMetricBinding, evaluated: i64) -> Value {
    let mut rows = Vec::new();
    for (name, value, filesystem) in [
        ("inventory_observation_success", 1.0, false),
        ("filesystem_observation_success", 1.0, false),
        ("observed_at_seconds", (evaluated - 5) as f64, false),
        ("inventory_count", 7.0, false),
        ("compressed_logical_bytes", 10789.0, false),
        (
            "filesystem_reported_at_seconds",
            (evaluated - 7) as f64,
            true,
        ),
        ("filesystem_used_bytes", 0.0, true),
        ("filesystem_inodes_used", 3.0, true),
        ("up", 1.0, false),
    ] {
        let mut labels = BTreeMap::from([
            (
                "__name__",
                if name == "up" {
                    "up".to_string()
                } else {
                    format!("sandbox_node_image_{name}")
                },
            ),
            ("deployment", "production-a".into()),
            ("cluster_epoch", binding.cluster_epoch.to_string()),
            ("collector_replica", "a".into()),
            ("job", format!("node-images-{}", binding.node_uid)),
            ("instance", "node.example:9443".into()),
        ]);
        if name == "up" {
            labels.extend([
                ("scrape_node_uid", binding.node_uid.to_string()),
                ("scrape_host_boot_id", binding.host_boot_id.to_string()),
                ("scrape_profile_sha256", binding.profile_sha256.clone()),
            ]);
        } else {
            labels.extend([
                ("node_uid", binding.node_uid.to_string()),
                ("host_boot_id", binding.host_boot_id.to_string()),
                ("profile_sha256", binding.profile_sha256.clone()),
                ("source", "RUNTIME_REPORTED".into()),
                ("completeness", "UNKNOWN".into()),
            ]);
            if filesystem {
                labels.insert("filesystem_id", "f".repeat(64));
            }
        }
        for (kind, number) in [("value", value), ("sampled_at", (evaluated - 1) as f64)] {
            labels.insert("sandbox_value_kind", kind.into());
            rows.push(json!({"metric": labels, "value": [evaluated, number.to_string()]}));
        }
    }
    json!({"status":"success","data":{"resultType":"vector","result":rows}})
}

async fn serve(State(state): State<Backend>, request: Request<Body>) -> Response<Body> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let auth = request
        .headers()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
    let form: BTreeMap<String, String> = url::form_urlencoded::parse(&bytes).into_owned().collect();
    let evaluated = form
        .get("time")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap();
    *state.request.lock().unwrap() = Some(CapturedRequest {
        authorization: auth,
        form,
    });
    if state.blocking.load(Ordering::SeqCst) {
        state.entered.add_permits(1);
        state.release.acquire().await.unwrap().forget();
    }
    let body = (*state.reply.lock().unwrap())(&state.binding, evaluated);
    Response::builder()
        .status(state.status.load(Ordering::SeqCst))
        .header("content-type", "application/json")
        .header("location", "http://127.0.0.1:9/not-a-query")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn fixed_node_query_over_http_returns_one_complete_replica_without_zero_filling()
-> anyhow::Result<()> {
    let binding = binding();
    let token = tempfile::NamedTempFile::new()?;
    std::fs::write(token.path(), "PUBLIC_NODE_IMAGE_TEST_TOKEN")?;
    let state = Backend::new(binding.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = Router::new()
        .route("/managed/api/v1/query", post(serve))
        .with_state(state.clone());
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
    });
    let result = async {
        let client = PrometheusMetrics::build(
            MetricsBackendConfig {
                endpoint: format!("http://{address}/managed"),
                deployment: "production-a".into(),
                auth: MetricsAuthentication::Bearer {
                    token_file: token.path().into(),
                },
                ca_file: None,
                replicas: vec!["a".into(), "b".into()],
            },
            false,
        )
        .await?;
        client.node_image_status(&binding).await
    }
    .await;
    cancel.cancel();
    server.await??;
    // Close the real TCP server before any assertion, including the RED stub.
    let metrics = result?;
    assert_eq!(metrics.source, NodeImageMetricSource::RuntimeReported);
    assert_eq!(metrics.completeness, NodeImageCompleteness::Unknown);
    assert_eq!(metrics.accuracy, NodeImageAccuracy::ApproximateF64);
    assert_eq!(metrics.inventory_observation_success, Some(true));
    assert_eq!(metrics.filesystem_observation_success, Some(true));
    let inventory = metrics.inventory.unwrap();
    assert_eq!(inventory.collector_replica, "a");
    assert_eq!(inventory.count, 7.0);
    assert_eq!(inventory.compressed_logical_bytes, 10789.0);
    assert_eq!(
        inventory.observed_at_seconds,
        metrics.evaluated_at_seconds - 5.0
    );
    assert_eq!(
        inventory.scraped_at_seconds,
        metrics.evaluated_at_seconds - 1.0
    );
    let filesystem = metrics.filesystem.unwrap();
    assert_eq!(filesystem.collector_replica, "a");
    assert_eq!(
        filesystem.filesystems,
        vec![NodeImageFilesystem {
            filesystem_id: "f".repeat(64),
            reported_at_seconds: metrics.evaluated_at_seconds - 7.0,
            used_bytes: Some(0.0),
            inodes_used: Some(3.0),
        }]
    );
    let captured = state.request.lock().unwrap();
    let CapturedRequest {
        authorization,
        form,
    } = captured.as_ref().unwrap();
    assert_eq!(authorization, "Bearer PUBLIC_NODE_IMAGE_TEST_TOKEN");
    assert_eq!(form.len(), 4);
    assert_eq!(form.get("timeout").map(String::as_str), Some("5s"));
    assert_eq!(form.get("limit").map(String::as_str), Some("217"));
    assert!(
        form.get("query")
            .unwrap()
            .contains("sandbox_node_image_inventory_count")
    );
    assert!(form.get("query").unwrap().contains("timestamp("));
    assert!(form.get("query").unwrap().contains("or on(__name__,sandbox_value_kind,deployment,cluster_epoch,node_uid,host_boot_id,profile_sha256,source,completeness,filesystem_id,collector_replica,job,instance,scrape_node_uid,scrape_host_boot_id,scrape_profile_sha256)"));
    assert!(!form.get("query").unwrap().contains("sandbox_vm_"));
    Ok(())
}

fn normal(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    response(binding, evaluated).to_string()
}

struct Fixture {
    binding: NodeImageMetricBinding,
    client: PrometheusMetrics,
    backend: Backend,
    token: tempfile::NamedTempFile,
    cancel: CancellationToken,
    server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let binding = binding();
        let token = tempfile::NamedTempFile::new()?;
        std::fs::write(token.path(), "PUBLIC_NODE_IMAGE_TEST_TOKEN")?;
        let backend = Backend::new(binding.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = PrometheusMetrics::build(
            MetricsBackendConfig {
                endpoint: format!("http://{address}/managed"),
                deployment: "production-a".into(),
                auth: MetricsAuthentication::Bearer {
                    token_file: token.path().into(),
                },
                ca_file: None,
                replicas: vec!["a".into(), "b".into()],
            },
            false,
        )
        .await?;
        let app = Router::new()
            .route("/managed/api/v1/query", post(serve))
            .route(
                "/managed/api/v1/query_range",
                get(|| async {
                    axum::Json(
                        json!({"status":"success","data":{"resultType":"matrix","result":[]}}),
                    )
                }),
            )
            .with_state(backend.clone());
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await
        });
        Ok(Self {
            binding,
            client,
            backend,
            token,
            cancel,
            server: Some(server),
        })
    }
    fn reply(&self, reply: Reply) {
        *self.backend.reply.lock().unwrap() = reply;
    }
    async fn close(mut self) -> anyhow::Result<()> {
        self.cancel.cancel();
        if let Some(server) = self.server.take() {
            server.await??;
        }
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.backend.release.add_permits(3);
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

fn rows(binding: &NodeImageMetricBinding, evaluated: i64, replica: &str, age: i64) -> Vec<Value> {
    let mut rows = response(binding, evaluated)["data"]["result"]
        .as_array()
        .unwrap()
        .clone();
    for row in &mut rows {
        row["metric"]["collector_replica"] = json!(replica);
        if row["metric"]["sandbox_value_kind"] == "sampled_at" {
            row["value"][1] = json!((evaluated - age).to_string());
        }
    }
    rows
}
fn set(rows: &mut [Value], name: &str, kind: &str, value: f64) {
    let full = if name == "up" {
        "up".to_owned()
    } else {
        format!("sandbox_node_image_{name}")
    };
    for row in rows {
        if row["metric"]["__name__"] == full && row["metric"]["sandbox_value_kind"] == kind {
            row["value"][1] = json!(value.to_string());
        }
    }
}
fn envelope(rows: Vec<Value>) -> String {
    json!({"status":"success","data":{"resultType":"vector","result":rows}}).to_string()
}
fn ha_tuples(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 2);
    set(&mut a, "compressed_logical_bytes", "value", 200.0);
    let mut b = rows(binding, evaluated, "b", 1);
    set(&mut b, "inventory_count", "value", 9.0);
    set(&mut b, "compressed_logical_bytes", "value", 100.0);
    set(&mut b, "filesystem_used_bytes", "value", 7.0);
    b.retain(|r| r["metric"]["__name__"] != "sandbox_node_image_filesystem_inodes_used");
    for row in &mut b {
        if row["metric"].get("filesystem_id").is_some() {
            row["metric"]["filesystem_id"] = json!("b".repeat(64));
        }
    }
    a.extend(b);
    envelope(a)
}
fn newer_failure(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    set(&mut a, "inventory_observation_success", "value", 0.0);
    set(&mut a, "filesystem_observation_success", "value", 0.0);
    a.extend(rows(binding, evaluated, "b", 2));
    envelope(a)
}
fn recovered(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    set(&mut a, "inventory_count", "value", 13.0);
    set(&mut a, "compressed_logical_bytes", "value", 17.0);
    a.extend(rows(binding, evaluated, "b", 2));
    envelope(a)
}
fn failed_agent(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    set(&mut a, "up", "value", 0.0);
    set(&mut a, "inventory_count", "value", 99.0);
    a.extend(rows(binding, evaluated, "b", 2));
    envelope(a)
}

#[tokio::test]
async fn ha_selects_whole_latest_component_and_new_failure_clears_old_success() -> anyhow::Result<()>
{
    let fixture = Fixture::new().await?;
    let mut results = Vec::new();
    for reply in [ha_tuples as Reply, newer_failure, recovered, failed_agent] {
        fixture.reply(reply);
        results.push(fixture.client.node_image_status(&fixture.binding).await);
    }
    fixture.close().await?;
    let mut results = results.into_iter();
    let tuples = results.next().unwrap()?;
    let inventory = tuples.inventory.unwrap();
    assert_eq!(
        (
            inventory.collector_replica.as_str(),
            inventory.count,
            inventory.compressed_logical_bytes
        ),
        ("b", 9.0, 100.0)
    );
    assert_eq!(
        tuples.filesystem.unwrap().filesystems,
        vec![NodeImageFilesystem {
            filesystem_id: "b".repeat(64),
            reported_at_seconds: tuples.evaluated_at_seconds - 7.0,
            used_bytes: Some(7.0),
            inodes_used: None,
        }]
    );
    let failure = results.next().unwrap()?;
    assert_eq!(failure.inventory_observation_success, Some(false));
    assert_eq!(failure.filesystem_observation_success, Some(false));
    assert!(failure.inventory.is_none());
    assert!(failure.filesystem.is_none());
    let recovered = results.next().unwrap()?.inventory.unwrap();
    assert_eq!(
        (
            recovered.collector_replica.as_str(),
            recovered.count,
            recovered.compressed_logical_bytes
        ),
        ("a", 13.0, 17.0)
    );
    let healthy = results.next().unwrap()?.inventory.unwrap();
    assert_eq!(
        (healthy.collector_replica.as_str(), healthy.count),
        ("b", 7.0)
    );
    Ok(())
}

fn stale_original(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    set(
        &mut a,
        "observed_at_seconds",
        "value",
        (evaluated - 60) as f64,
    );
    a.extend(rows(binding, evaluated, "b", 2));
    envelope(a)
}
fn partial_inventory(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    set(
        &mut a,
        "inventory_count",
        "sampled_at",
        (evaluated - 2) as f64,
    );
    a.extend(rows(binding, evaluated, "b", 2));
    envelope(a)
}
fn stale_filesystem(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    set(
        &mut a,
        "filesystem_reported_at_seconds",
        "value",
        (evaluated - 60) as f64,
    );
    envelope(a)
}
fn future_original(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    // Keep the real HTTP fixture outside the future tolerance as the decoding
    // clock advances. The exact five-second boundary is tested with fixed time.
    set(&mut a, "observed_at_seconds", "value", f64::MAX);
    envelope(a)
}

#[test]
fn future_http_fixture_is_rejected_after_decode_clock_advances_one_second() -> anyhow::Result<()> {
    let binding = binding();
    let evaluated = 1_700_000_000;
    let replicas = ["a".to_owned(), "b".to_owned()];
    let metrics = decode(
        future_original(&binding, evaluated).as_bytes(),
        &binding,
        "production-a",
        &replicas,
        evaluated,
        evaluated as f64 + 1.0,
    )?;
    assert_eq!(metrics.inventory_observation_success, Some(true));
    assert_eq!(metrics.filesystem_observation_success, Some(true));
    assert!(metrics.inventory.is_none() && metrics.filesystem.is_none());
    Ok(())
}

#[test]
fn future_original_timestamps_obey_the_inclusive_five_second_boundary() -> anyhow::Result<()> {
    let binding = binding();
    let evaluated = 1_700_000_000;
    let now = evaluated as f64 + 1.0;
    let boundary = now + 5.0;
    let replicas = ["a".to_owned(), "b".to_owned()];
    let baseline_inventory = decode(
        normal(&binding, evaluated).as_bytes(),
        &binding,
        "production-a",
        &replicas,
        evaluated,
        now,
    )?
    .inventory;
    assert!(baseline_inventory.is_some());
    for metric in ["observed_at_seconds", "filesystem_reported_at_seconds"] {
        for (timestamp, accepted) in [
            (boundary.next_down(), true),
            (boundary, true),
            (boundary.next_up(), false),
        ] {
            let mut sample = rows(&binding, evaluated, "a", 1);
            set(&mut sample, metric, "value", timestamp);
            let metrics = decode(
                envelope(sample).as_bytes(),
                &binding,
                "production-a",
                &replicas,
                evaluated,
                now,
            )?;
            assert_eq!(metrics.inventory_observation_success, Some(true));
            assert_eq!(metrics.filesystem_observation_success, Some(true));
            assert_eq!(
                metrics.inventory.is_some(),
                metric == "filesystem_reported_at_seconds" || accepted,
                "{metric} at {timestamp}"
            );
            assert_eq!(
                metrics.filesystem.is_some(),
                accepted,
                "{metric} at {timestamp}"
            );
            if metric == "filesystem_reported_at_seconds" {
                assert_eq!(metrics.inventory, baseline_inventory);
            }
            if let Some(inventory) = &metrics.inventory
                && metric == "observed_at_seconds"
            {
                assert_eq!(inventory.observed_at_seconds, timestamp);
            }
            if let Some(filesystem) = &metrics.filesystem {
                assert_eq!(filesystem.filesystems.len(), 1);
                if metric == "filesystem_reported_at_seconds" {
                    assert_eq!(filesystem.filesystems[0].reported_at_seconds, timestamp);
                } else {
                    assert_eq!(filesystem.observed_at_seconds, timestamp);
                }
            }
        }
    }
    Ok(())
}

fn stale_samples(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    envelope(rows(binding, evaluated, "a", 60))
}
fn empty_filesystems(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    a.retain(|r| r["metric"].get("filesystem_id").is_none());
    envelope(a)
}
fn missing_filesystem_time(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    a.retain(|r| r["metric"]["__name__"] != "sandbox_node_image_filesystem_reported_at_seconds");
    envelope(a)
}
#[tokio::test]
async fn stale_or_partial_newest_components_stay_unknown_without_fallback_or_empty_invention()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut results = Vec::new();
    for reply in [
        stale_original as Reply,
        partial_inventory,
        stale_filesystem,
        future_original,
        stale_samples,
        empty_filesystems,
        missing_filesystem_time,
    ] {
        fixture.reply(reply);
        results.push(fixture.client.node_image_status(&fixture.binding).await);
    }
    fixture.close().await?;
    let results = results.into_iter().collect::<Result<Vec<_>>>()?;
    assert_eq!(results[0].inventory_observation_success, Some(true));
    assert!(results[0].inventory.is_none() && results[0].filesystem.is_none());
    assert!(results[1].inventory.is_none() && results[1].filesystem.is_some());
    assert!(results[2].inventory.is_some() && results[2].filesystem.is_none());
    assert!(results[3].inventory.is_none() && results[3].filesystem.is_none());
    assert_eq!(results[4].inventory_observation_success, None);
    assert!(results[4].inventory.is_none() && results[4].filesystem.is_none());
    assert!(
        results[5]
            .filesystem
            .as_ref()
            .unwrap()
            .filesystems
            .is_empty()
    );
    assert_eq!(results[5].completeness, NodeImageCompleteness::Unknown);
    assert!(results[6].filesystem.is_none());
    Ok(())
}

fn warning(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut value = response(binding, evaluated);
    value["warnings"] = json!(["partial"]);
    value.to_string()
}
fn too_many_rows(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let row = response(binding, evaluated)["data"]["result"][0].clone();
    envelope(vec![row; 217])
}
fn oversized(_: &NodeImageMetricBinding, _: i64) -> String {
    " ".repeat(256 * 1024 + 1)
}
fn duplicate_status(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    normal(binding, evaluated).replacen(
        "\"status\":\"success\"",
        "\"status\":\"success\",\"status\":\"success\"",
        1,
    )
}
fn duplicate_label(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    normal(binding, evaluated).replacen(
        "\"deployment\":\"production-a\"",
        "\"deployment\":\"production-a\",\"deployment\":\"production-a\"",
        1,
    )
}
fn foreign_label(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut value = response(binding, evaluated);
    value["data"]["result"][0]["metric"]["tenant_id"] = json!(Uuid::new_v4());
    value.to_string()
}
fn nonfinite(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut value = response(binding, evaluated);
    value["data"]["result"][0]["value"][1] = json!("NaN");
    value.to_string()
}
fn duplicate_series(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    a.push(a[0].clone());
    envelope(a)
}
fn too_many_filesystems(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut a = rows(binding, evaluated, "a", 1);
    let filesystem = a
        .iter()
        .filter(|r| r["metric"].get("filesystem_id").is_some())
        .cloned()
        .collect::<Vec<_>>();
    a.retain(|r| r["metric"].get("filesystem_id").is_none());
    for id in 0..17 {
        let mut fs = filesystem.clone();
        for row in &mut fs {
            row["metric"]["filesystem_id"] = json!(format!("{id:064x}"));
        }
        a.extend(fs);
    }
    envelope(a)
}
fn maximum_reports(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
    let mut all = Vec::new();
    for (replica, age) in [("a", 1), ("b", 2)] {
        let mut replica_rows = rows(binding, evaluated, replica, age);
        let filesystem = replica_rows
            .iter()
            .filter(|r| r["metric"].get("filesystem_id").is_some())
            .cloned()
            .collect::<Vec<_>>();
        replica_rows.retain(|r| r["metric"].get("filesystem_id").is_none());
        for id in 0..16 {
            let mut fs = filesystem.clone();
            for row in &mut fs {
                row["metric"]["filesystem_id"] = json!(format!("{id:064x}"));
            }
            replica_rows.extend(fs);
        }
        all.extend(replica_rows);
    }
    envelope(all)
}
#[tokio::test]
async fn node_response_rejects_partial_envelopes_duplicates_nonfinite_and_budget_overflow()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut results = Vec::new();
    for reply in [
        warning as Reply,
        too_many_rows,
        oversized,
        duplicate_status,
        duplicate_label,
        foreign_label,
        nonfinite,
        duplicate_series,
        too_many_filesystems,
    ] {
        fixture.reply(reply);
        results.push(fixture.client.node_image_status(&fixture.binding).await);
    }
    fixture.reply(maximum_reports);
    let maximum = fixture.client.node_image_status(&fixture.binding).await;
    fixture.close().await?;
    for result in results {
        assert_eq!(result.unwrap_err(), MetricsError::Response);
    }
    assert_eq!(maximum?.filesystem.unwrap().filesystems.len(), 16);
    Ok(())
}

#[tokio::test]
async fn node_transport_rotates_credentials_requires_production_tls_and_never_redirects_or_retries()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let config = fixture.client.inner.config.clone();
    let plain_http = PrometheusMetrics::new(config).await;
    let first = fixture.client.node_image_status(&fixture.binding).await;
    std::fs::write(fixture.token.path(), "PUBLIC_NODE_IMAGE_ROTATED_TOKEN")?;
    let rotated = fixture.client.node_image_status(&fixture.binding).await;
    let captured = fixture
        .backend
        .request
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .authorization
        .clone();
    std::fs::write(fixture.token.path(), "TOKEN\nHEADER: INJECTION")?;
    let invalid_credential = fixture.client.node_image_status(&fixture.binding).await;
    std::fs::write(fixture.token.path(), "PUBLIC_NODE_IMAGE_ROTATED_TOKEN")?;
    fixture.backend.status.store(302, Ordering::SeqCst);
    let redirect = fixture.client.node_image_status(&fixture.binding).await;
    fixture.backend.status.store(503, Ordering::SeqCst);
    let unavailable = fixture.client.node_image_status(&fixture.binding).await;
    let calls = fixture.backend.calls.load(Ordering::SeqCst);
    fixture.close().await?;
    assert!(matches!(plain_http, Err(MetricsError::Configuration)));
    first?;
    rotated?;
    assert_eq!(captured, "Bearer PUBLIC_NODE_IMAGE_ROTATED_TOKEN");
    assert_eq!(invalid_credential.unwrap_err(), MetricsError::Credential);
    assert_eq!(redirect.unwrap_err(), MetricsError::Rejected);
    assert_eq!(unavailable.unwrap_err(), MetricsError::Unavailable);
    assert_eq!(calls, 4);
    Ok(())
}

#[tokio::test]
async fn two_node_reads_exhaust_only_their_own_slots_and_leave_vm_queries_available()
-> anyhow::Result<()> {
    use crate::metrics::{MetricRange, RuntimeMetric, RuntimeMetricBinding};
    let fixture = Fixture::new().await?;
    fixture.backend.blocking.store(true, Ordering::SeqCst);
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let client = fixture.client.clone();
        let binding = fixture.binding.clone();
        tasks.push(tokio::spawn(async move {
            client.node_image_status(&binding).await
        }));
    }
    let entered = tokio::time::timeout(Duration::from_secs(2), async {
        fixture
            .backend
            .entered
            .acquire_many(2)
            .await
            .map(|permit| permit.forget())
    })
    .await;
    let overloaded = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.client.node_image_status(&fixture.binding),
    )
    .await;
    let now = chrono::Utc::now();
    let range = MetricRange::new(now - chrono::Duration::seconds(30), now, 15)?;
    let vm_binding = RuntimeMetricBinding {
        tenant_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        instance_id: Uuid::new_v4(),
        generation: 1,
        launch_id: Uuid::new_v4(),
        cluster_epoch: fixture.binding.cluster_epoch,
        node_uid: fixture.binding.node_uid,
        host_boot_id: fixture.binding.host_boot_id,
    };
    let vm = fixture
        .client
        .query(&vm_binding, RuntimeMetric::VmCpuCores, range)
        .await;
    fixture.backend.release.add_permits(3);
    let mut completed = Vec::new();
    for task in tasks {
        completed.push(task.await);
    }
    fixture.close().await?;
    entered??;
    assert_eq!(overloaded?.unwrap_err(), MetricsError::Overloaded);
    assert!(vm?.points.iter().all(|p| p.value.is_none()));
    for result in completed {
        result??;
    }
    Ok(())
}

#[tokio::test]
async fn newer_healthy_scrape_with_incomplete_flag_cannot_fall_back_to_old_replica()
-> anyhow::Result<()> {
    fn partial_flag(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
        let mut a = rows(binding, evaluated, "a", 1);
        set(
            &mut a,
            "inventory_observation_success",
            "sampled_at",
            (evaluated - 3) as f64,
        );
        a.extend(rows(binding, evaluated, "b", 2));
        envelope(a)
    }
    fn missing_flag(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
        let mut a = rows(binding, evaluated, "a", 1);
        a.retain(|r| r["metric"]["__name__"] != "sandbox_node_image_inventory_observation_success");
        a.extend(rows(binding, evaluated, "b", 2));
        envelope(a)
    }
    fn missing_flag_timestamp(binding: &NodeImageMetricBinding, evaluated: i64) -> String {
        let mut a = rows(binding, evaluated, "a", 1);
        a.retain(|r| {
            !(r["metric"]["__name__"] == "sandbox_node_image_inventory_observation_success"
                && r["metric"]["sandbox_value_kind"] == "sampled_at")
        });
        a.extend(rows(binding, evaluated, "b", 2));
        envelope(a)
    }
    let fixture = Fixture::new().await?;
    let mut results = Vec::new();
    for reply in [partial_flag as Reply, missing_flag, missing_flag_timestamp] {
        fixture.reply(reply);
        results.push(fixture.client.node_image_status(&fixture.binding).await);
    }
    fixture.close().await?;
    for result in results {
        let result = result?;
        assert_eq!(result.inventory_observation_success, None);
        assert!(result.inventory.is_none());
        assert_eq!(result.filesystem_observation_success, Some(true));
        assert_eq!(result.filesystem.unwrap().collector_replica, "a");
    }
    Ok(())
}
