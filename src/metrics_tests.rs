#![allow(clippy::unwrap_used)]
use super::*;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::sync::{
    Mutex,
    atomic::{AtomicU16, AtomicUsize, Ordering},
};

fn binding() -> RuntimeMetricBinding {
    RuntimeMetricBinding {
        tenant_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        instance_id: Uuid::new_v4(),
        generation: 1,
        launch_id: Uuid::new_v4(),
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        host_boot_id: Uuid::new_v4(),
    }
}
fn range() -> MetricRange {
    MetricRange {
        start: 1791020000,
        end: 1791020030,
        step: 15,
    }
}
fn series(labels: &BTreeMap<String, String>, replica: &str, kind: &str, values: Value) -> Value {
    let mut labels = labels.clone();
    labels.insert("collector_replica".into(), replica.into());
    labels.insert("sandbox_value_kind".into(), kind.into());
    json!({"metric":labels,"values":values})
}
fn response(series: Vec<Value>) -> Value {
    json!({"status":"success","data":{"resultType":"matrix","result":series}})
}
fn parsed(value: &Value, labels: &BTreeMap<String, String>) -> Result<MetricSeries> {
    decode(
        &serde_json::to_vec(value).unwrap(),
        labels,
        &["a".into(), "b".into()],
        RuntimeMetric::VmCpuCores,
        range(),
    )
}

#[test]
fn historical_points_use_raw_observation_time_and_never_fill_stale_or_missing_with_zero() {
    let labels = binding().labels("production-a").unwrap();
    let t = range().start;
    let result = parsed(
        &response(vec![
            series(&labels, "a", "value", json!([[t, "0"], [t + 15, "2"]])),
            series(
                &labels,
                "a",
                "observed_at",
                json!([[t, (t - 5).to_string()], [t + 15, (t - 90).to_string()]]),
            ),
        ]),
        &labels,
    )
    .unwrap();
    assert_eq!(result.points.len(), 3);
    assert_eq!(result.points[0].value, Some(0.0)); // A real measured zero is retained.
    assert_eq!(result.points[0].status, SampleStatus::Fresh);
    assert_eq!(result.points[0].observed_at.unwrap().timestamp(), t - 5);
    assert_eq!(result.points[1].status, SampleStatus::Stale);
    assert!(result.points[1].value.is_none());
    assert_eq!(result.points[2].status, SampleStatus::Missing);
    assert!(result.points[2].value.is_none());
    assert!(result.points[2].observed_at.is_none());
}

#[test]
fn ha_selects_one_fresh_replica_without_summing_and_warming_replica_cannot_hide_valid_rate() {
    let labels = binding().labels("production-a").unwrap();
    let t = range().start;
    let result = parsed(
        &response(vec![
            series(&labels, "a", "value", json!([[t, "1.5"], [t + 15, "1.6"]])),
            series(
                &labels,
                "a",
                "observed_at",
                json!([[t, (t - 10).to_string()], [t + 15, (t + 5).to_string()]]),
            ),
            series(&labels, "b", "value", json!([[t + 15, "1.7"]])),
            series(
                &labels,
                "b",
                "observed_at",
                json!([[t, (t - 1).to_string()], [t + 15, (t + 14).to_string()]]),
            ),
        ]),
        &labels,
    )
    .unwrap();
    assert_eq!(result.points[0].value, Some(1.5));
    assert_eq!(result.points[0].collector_replica.as_deref(), Some("a"));
    assert_eq!(result.points[1].value, Some(1.7));
    assert_eq!(result.points[1].collector_replica.as_deref(), Some("b"));
}

#[test]
fn wrong_binding_duplicate_series_warnings_and_invalid_timestamps_fail_closed() {
    let labels = binding().labels("production-a").unwrap();
    let t = range().start;
    let base = response(vec![
        series(&labels, "a", "value", json!([[t, "1"]])),
        series(&labels, "a", "observed_at", json!([[t, t.to_string()]])),
    ]);
    for key in labels.keys() {
        let mut bad = base.clone();
        bad["data"]["result"][0]["metric"][key] = json!("foreign");
        assert_eq!(parsed(&bad, &labels).unwrap_err(), MetricsError::Response);
    }
    for mutation in 0..10 {
        let mut bad = base.clone();
        match mutation {
            0 => bad["warnings"] = json!(["query was truncated"]),
            1 => bad["infos"] = json!(["histogram samples were removed"]),
            2 => bad["data"]["result"][1]["values"][0][1] = json!((t + 1).to_string()),
            3 => bad["data"]["result"][0]["values"][0][1] = json!("NaN"),
            4 => bad["data"]["result"][0]["values"][0][1] = json!("-1"),
            5 => bad["data"]["result"][0]["values"][0][0] = json!(t + 1),
            6 => {
                let s = bad["data"]["result"][0].clone();
                bad["data"]["result"].as_array_mut().unwrap().push(s);
            }
            7 => bad["data"]["result"][0]["metric"]["collector_replica"] = json!("rogue"),
            8 => {
                bad["data"]["result"].as_array_mut().unwrap().remove(1);
            }
            _ => {
                bad["data"]["result"][0]["metric"]["secret"] = json!("not part of metric contract")
            }
        }
        assert_eq!(
            parsed(&bad, &labels).unwrap_err(),
            MetricsError::Response,
            "mutation {mutation}"
        );
    }
}

#[test]
fn query_identity_is_closed_and_cost_is_bounded() {
    let mut b = binding();
    b.generation = 0;
    assert!(b.labels("production-a").is_err());
    b.generation = 1;
    b.host_boot_id = Uuid::nil();
    assert!(b.labels("production-a").is_err());
    let labels = binding().labels("production-a").unwrap();
    let query = expression(&labels, RuntimeMetric::VmCpuCores);
    assert!(query.contains("rate(sandbox_vm_cpu_seconds_total{"));
    assert!(query.contains("timestamp(sandbox_vm_cpu_seconds_total{"));
    assert!(!query.contains("sum("));
    let now = Utc::now();
    assert!(MetricRange::new(now - chrono::Duration::days(1), now, 60).is_ok());
    assert!(MetricRange::new(now - chrono::Duration::days(1), now, 15).is_err());
    assert!(MetricRange::new(now, now + chrono::Duration::seconds(1), 15).is_err());
    assert!(MetricRange::new(now - chrono::Duration::days(91), now, 3600).is_err());
}

#[test]
fn efficiency_series_keep_real_zero_over_one_missing_and_ha_freshness() {
    let labels = binding().labels("production-a").unwrap();
    let t = range().start;
    for (metric, unit, measured) in [
        (
            RuntimeMetric::VmCpuThrottledPeriodsPerSecond,
            "periods_per_second",
            2.0,
        ),
        (
            RuntimeMetric::VmCpuThrottledSecondsPerSecond,
            "seconds_per_second",
            1.5,
        ),
        (RuntimeMetric::VmCpuCapacityCores, "cores", 0.75),
        (RuntimeMetric::VmMemoryCapacityBytes, "bytes", 268435456.0),
        (RuntimeMetric::VmMemoryAnonBytes, "bytes", 4096.0),
        (RuntimeMetric::VmMemoryFileBytes, "bytes", 8192.0),
        (
            RuntimeMetric::VmMemoryOomEventsPerSecond,
            "events_per_second",
            0.5,
        ),
        (
            RuntimeMetric::VmMemoryOomKillsPerSecond,
            "events_per_second",
            0.25,
        ),
    ] {
        let decoded = decode(
            &serde_json::to_vec(&response(vec![
                series(
                    &labels,
                    "a",
                    "value",
                    json!([[t, measured.to_string()], [t + 15, "0"]]),
                ),
                series(
                    &labels,
                    "a",
                    "observed_at",
                    json!([[t, t.to_string()], [t + 15, (t + 15).to_string()]]),
                ),
                series(
                    &labels,
                    "b",
                    "value",
                    json!([[t, (measured * 4.0).to_string()]]),
                ),
                series(
                    &labels,
                    "b",
                    "observed_at",
                    json!([[t, (t - 90).to_string()]]),
                ),
            ]))
            .unwrap(),
            &labels,
            &["a".into(), "b".into()],
            metric,
            range(),
        )
        .unwrap();
        assert_eq!(decoded.unit, unit);
        assert_eq!(decoded.points[0].value, Some(measured));
        assert_eq!(decoded.points[0].collector_replica.as_deref(), Some("a"));
        assert_eq!(decoded.points[1].value, Some(0.0));
        assert_eq!(decoded.points[2].value, None);
        assert_eq!(decoded.points[2].status, SampleStatus::Missing);
        let absent = decode(
            &serde_json::to_vec(&response(vec![])).unwrap(),
            &labels,
            &["a".into()],
            metric,
            range(),
        )
        .unwrap();
        assert!(
            absent
                .points
                .iter()
                .all(|p| p.value.is_none() && p.status == SampleStatus::Missing)
        );
    }
}

/// The actual pinned Prometheus evaluator, not a handwritten PromQL substitute.
/// Docker must already have the locked image; no registry pull occurs here.
#[test]
#[ignore = "requires Docker and the checksum-locked Prometheus image"]
fn official_prometheus_preserves_identity_raw_sample_time_and_separate_ha_series()
-> anyhow::Result<()> {
    fn selector(labels: &BTreeMap<String, String>) -> String {
        format!(
            "{{{}}}",
            labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{v}\""))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
    let labels = binding().labels("production-a")?;
    let mut inputs = Vec::new();
    let mut expected = Vec::new();
    for (replica, increment) in [("a", 15), ("b", 30)] {
        let mut l = labels.clone();
        l.insert("collector_replica".into(), replica.into());
        inputs.push(json!({"series":format!("{}{}",RuntimeMetric::VmCpuCores.name(),selector(&l)),"values":format!("0+{increment}x8")}));
        l.insert("sandbox_value_kind".into(), "value".into());
        expected.push(json!({"labels":selector(&l),"value":increment as f64 / 15.0}));
        l.insert("sandbox_value_kind".into(), "observed_at".into());
        expected.push(json!({"labels":selector(&l),"value":120}));
    }
    let mut gauge = labels.clone();
    gauge.insert("collector_replica".into(), "a".into());
    let input = format!(
        "{}{}",
        RuntimeMetric::VmMemoryBytes.name(),
        selector(&gauge)
    );
    let mut value = gauge.clone();
    let counter_input = format!("{}{}", RuntimeMetric::VmCpuCores.name(), selector(&gauge));
    value.insert(
        "__name__".into(),
        RuntimeMetric::VmMemoryBytes.name().into(),
    );
    value.insert("sandbox_value_kind".into(), "value".into());
    gauge.insert("sandbox_value_kind".into(), "observed_at".into());
    let mut test = json!({"evaluation_interval":"15s","fuzzy_compare":true,"tests":[
        {"name":"exact identity and HA remain separate", "interval":"15s", "input_series":inputs,
        "promql_expr_test":[{"expr":expression(&labels,RuntimeMetric::VmCpuCores),"eval_time":"2m","exp_samples":expected}]},
        {"name":"lookback does not replace original sample time", "interval":"15s",
        "input_series":[{"series":input,"values":"500+0x8 _x30"}],
        "promql_expr_test":[
            {"expr":expression(&labels,RuntimeMetric::VmMemoryBytes),"eval_time":"3m15s","exp_samples":[{"labels":selector(&value),"value":500},{"labels":selector(&gauge),"value":120}]},
            {"expr":expression(&labels,RuntimeMetric::VmMemoryBytes),"eval_time":"7m15s","exp_samples":[]}
        ]},
        {"name":"a real stale marker suppresses remaining range-window rates", "interval":"15s",
        "input_series":[{"series":counter_input,"values":"0+15x8 stale _x16"}],
        "promql_expr_test":[
            {"expr":expression(&labels,RuntimeMetric::VmCpuCores),"eval_time":"2m15s","exp_samples":[]},
            {"expr":expression(&labels,RuntimeMetric::VmCpuCores),"eval_time":"3m","exp_samples":[]}
        ]}
    ]});
    // Literal workload expectations exercise the actual Prometheus evaluator.
    // Throttled seconds/s is deliberately >1; it is not a utilization ratio.
    for (metric, values, expected_value, gauge) in [
        (
            RuntimeMetric::VmCpuThrottledPeriodsPerSecond,
            "0+30x8",
            2.0,
            false,
        ),
        (
            RuntimeMetric::VmCpuThrottledSecondsPerSecond,
            "0+22.5x8",
            1.5,
            false,
        ),
        (RuntimeMetric::VmCpuCapacityCores, "0.75+0x8", 0.75, true),
        (
            RuntimeMetric::VmMemoryCapacityBytes,
            "268435456+0x8",
            268435456.0,
            true,
        ),
        (RuntimeMetric::VmMemoryAnonBytes, "4096+0x8", 4096.0, true),
        (RuntimeMetric::VmMemoryFileBytes, "8192+0x8", 8192.0, true),
        (
            RuntimeMetric::VmMemoryOomEventsPerSecond,
            "0+0x8",
            0.0,
            false,
        ),
        (
            RuntimeMetric::VmMemoryOomKillsPerSecond,
            "0+3x8",
            0.2,
            false,
        ),
    ] {
        let mut input_labels = labels.clone();
        input_labels.insert("collector_replica".into(), "a".into());
        let input = format!("{}{}", metric.name(), selector(&input_labels));
        let mut value_labels = input_labels.clone();
        value_labels.insert("sandbox_value_kind".into(), "value".into());
        if gauge {
            value_labels.insert("__name__".into(), metric.name().into());
        }
        input_labels.insert("sandbox_value_kind".into(), "observed_at".into());
        test["tests"].as_array_mut().unwrap().push(json!({
            "name":format!("optional efficiency metric {} retains units, zero and missing", metric.name()),
            "interval":"15s",
            "input_series":[{"series":input,"values":format!("{values} _x30")}],
            "promql_expr_test":[
                {"expr":expression(&labels,metric),"eval_time":"2m","exp_samples":[
                    {"labels":selector(&value_labels),"value":expected_value},
                    {"labels":selector(&input_labels),"value":120}
                ]},
                {"expr":expression(&labels,metric),"eval_time":"7m15s","exp_samples":[]}
            ]
        }));
    }
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("queries.yml"), serde_json::to_vec(&test)?)?;
    let lock: Value =
        serde_json::from_str(include_str!("../deploy/observability/versions.lock.json"))?;
    let image = lock["prometheus_image"].as_str().unwrap();
    let output = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--mount",
        ])
        .arg(format!(
            "type=bind,src={},dst=/test,readonly",
            dir.path().display()
        ))
        .args([
            "--entrypoint",
            "/bin/promtool",
            image,
            "test",
            "rules",
            "/test/queries.yml",
        ])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "Official Prometheus semantics failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[derive(Clone)]
struct Backend {
    body: Arc<Mutex<Value>>,
    status: Arc<AtomicU16>,
    calls: Arc<AtomicUsize>,
    auth: Arc<Mutex<String>>,
}
async fn serve(State(state): State<Backend>, request: Request<Body>) -> Response<Body> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        request.headers()["authorization"],
        state.auth.lock().unwrap().as_str()
    );
    let query: BTreeMap<_, _> =
        url::form_urlencoded::parse(request.uri().query().unwrap().as_bytes())
            .into_owned()
            .collect();
    assert_eq!(query.get("limit").unwrap(), "5");
    assert_eq!(query.get("timeout").unwrap(), "5s");
    assert!(
        query
            .get("query")
            .unwrap()
            .contains("timestamp(sandbox_vm_cpu_seconds_total")
    );
    Response::builder()
        .status(state.status.load(Ordering::SeqCst))
        .header("content-type", "application/json")
        .header("location", "http://127.0.0.1:9/steal")
        .body(Body::from(state.body.lock().unwrap().to_string()))
        .unwrap()
}

#[tokio::test]
async fn http_transport_rotates_private_credentials_and_rejects_redirects_foreign_series_and_oversize()
-> anyhow::Result<()> {
    let b = binding();
    let labels = b.labels("production-a")?;
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), "PUBLIC_TEST_TOKEN_A")?;
    let state = Backend {
        body: Arc::new(Mutex::new(response(vec![]))),
        status: Arc::new(AtomicU16::new(200)),
        calls: Arc::new(AtomicUsize::new(0)),
        auth: Arc::new(Mutex::new("Bearer PUBLIC_TEST_TOKEN_A".into())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = Router::new()
        .route("/managed/api/v1/query_range", get(serve))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let config = MetricsBackendConfig {
        endpoint: format!("http://{address}/managed"),
        deployment: "production-a".into(),
        auth: MetricsAuthentication::Bearer {
            token_file: file.path().into(),
        },
        ca_file: None,
        replicas: vec!["a".into(), "b".into()],
    };
    assert!(matches!(
        PrometheusMetrics::new(config.clone()).await,
        Err(MetricsError::Configuration)
    ));
    let client = PrometheusMetrics::build(config, false).await?;
    let outcome = async {
        assert!(
            client
                .query(&b, RuntimeMetric::VmCpuCores, range())
                .await?
                .points
                .iter()
                .all(|p| p.status == SampleStatus::Missing)
        );
        std::fs::write(file.path(), "PUBLIC_TEST_TOKEN_B")?;
        *state.auth.lock().unwrap() = "Bearer PUBLIC_TEST_TOKEN_B".into();
        client.query(&b, RuntimeMetric::VmCpuCores, range()).await?;
        state.status.store(302, Ordering::SeqCst);
        assert_eq!(
            client
                .query(&b, RuntimeMetric::VmCpuCores, range())
                .await
                .unwrap_err(),
            MetricsError::Rejected
        );
        assert_eq!(state.calls.load(Ordering::SeqCst), 3); // No redirect/automatic retry.
        state.status.store(200, Ordering::SeqCst);
        let mut foreign = labels;
        foreign.insert("tenant_id".into(), Uuid::new_v4().to_string());
        *state.body.lock().unwrap() = response(vec![series(&foreign, "a", "value", json!([]))]);
        assert_eq!(
            client
                .query(&b, RuntimeMetric::VmCpuCores, range())
                .await
                .unwrap_err(),
            MetricsError::Response
        );
        *state.body.lock().unwrap() = json!({"error":"X".repeat(MAX_BODY+1)});
        assert_eq!(
            client
                .query(&b, RuntimeMetric::VmCpuCores, range())
                .await
                .unwrap_err(),
            MetricsError::Response
        );
        std::fs::write(file.path(), "TOKEN\nHEADER: INJECTION")?;
        let count = state.calls.load(Ordering::SeqCst);
        assert_eq!(
            client
                .query(&b, RuntimeMetric::VmCpuCores, range())
                .await
                .unwrap_err(),
            MetricsError::Credential
        );
        assert_eq!(state.calls.load(Ordering::SeqCst), count);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    outcome
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and loopback HTTP/TLS"]
async fn real_pg_metric_binding_is_scoped_and_rechecks_revocation_and_dr_epoch_after_io()
-> anyhow::Result<()> {
    use crate::{
        instance_metrics::InstanceMetricQuery, termination_ledger::tests::FixtureRuntime,
        test_support_db as support,
    };
    let _serial = support::serial().await;
    let f = FixtureRuntime::new(true).await?;
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), "PUBLIC_TEST_TOKEN")?;
    let mode = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (owner, tenant, principal) = (
        f.f.owner.clone(),
        f.f.actor.tenant_id,
        f.f.actor.principal_id,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (state_mode, state_calls) = (mode.clone(), calls.clone());
    let app=Router::new().route("/api/v1/query_range",get(move || {
        let (owner,mode,calls)=(owner.clone(),state_mode.clone(),state_calls.clone());
        async move {
            calls.fetch_add(1,Ordering::SeqCst);
            let mut tx=owner.begin().await.unwrap();
            sqlx::query("SELECT set_config('app.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await.unwrap();
            match mode.load(Ordering::SeqCst) {
                1=>{sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'").bind(tenant).bind(principal).execute(&mut *tx).await.unwrap();},
                2=>{sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton").bind(Uuid::new_v4()).execute(&mut *tx).await.unwrap();},
                4=>{sqlx::query("UPDATE principal_identities SET enabled=false WHERE principal_id=$1").bind(principal).execute(&mut *tx).await.unwrap();},
                _=>{},
            }
            tx.commit().await.unwrap();
            if mode.load(Ordering::SeqCst)==3 { tokio::time::sleep(Duration::from_millis(3100)).await; }
            axum::Json(response(vec![]))
        }
    }));
    let app=app.route("/jwks",get(||async {axum::Json(json!({"keys":[serde_json::from_str::<Value>(include_str!("../tests/fixtures/auth/jwk-a.json")).unwrap()]}))}));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let backend = PrometheusMetrics::build(
        MetricsBackendConfig {
            endpoint: format!("http://{address}"),
            deployment: "production-a".into(),
            auth: MetricsAuthentication::Bearer {
                token_file: file.path().into(),
            },
            ca_file: None,
            replicas: vec!["a".into()],
        },
        false,
    )
    .await?;
    let now = Utc::now() - chrono::Duration::seconds(1);
    let mut q = InstanceMetricQuery {
        metric: RuntimeMetric::VmCpuCores,
        start: now - chrono::Duration::minutes(1),
        end: now,
        step_seconds: 15,
        launch_id: None,
    };
    let result=async {
        let got=f.f.database.instance_metrics(&f.f.actor,f.launch.instance_id,&q,Some(&backend)).await.map_err(support::api_failure)?;
        assert_eq!(got.launch_id,f.launch.launch_id);
        assert_eq!(got.series.points.len(),5);
        assert!(got.series.points.iter().all(|p|p.status==SampleStatus::Missing && p.value.is_none()));
        let mut other=f.f.actor.clone();other.tenant_id=Uuid::new_v4();
        assert_eq!(f.f.database.instance_metrics(&other,f.launch.instance_id,&q,Some(&backend)).await.unwrap_err().status,StatusCode::NOT_FOUND);
        q.launch_id=Some(Uuid::new_v4());
        assert_eq!(f.f.database.instance_metrics(&f.f.actor,f.launch.instance_id,&q,Some(&backend)).await.unwrap_err().code,"METRICS_RUNTIME_UNBOUND");
        assert_eq!(calls.load(Ordering::SeqCst),1);
        q.launch_id=Some(f.launch.launch_id);
        f.f.database.instance_metrics(&f.f.actor,f.launch.instance_id,&q,Some(&backend)).await.map_err(support::api_failure)?;
        check_metrics_http_contract(&f,&backend,address,&q,&mode).await?;
        mode.store(1,Ordering::SeqCst);
        assert_eq!(f.f.database.instance_metrics(&f.f.actor,f.launch.instance_id,&q,Some(&backend)).await.unwrap_err().status,StatusCode::NOT_FOUND);
        let mut tx=f.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'").bind(f.f.actor.tenant_id).bind(f.f.actor.principal_id).execute(&mut *tx).await?;tx.commit().await?;
        mode.store(2,Ordering::SeqCst);
        assert_eq!(f.f.database.instance_metrics(&f.f.actor,f.launch.instance_id,&q,Some(&backend)).await.unwrap_err().code,"METRICS_RUNTIME_UNBOUND");
        Ok::<_,anyhow::Error>(())
    }.await;
    // Restore the shared epoch even on assertion-free error paths.
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(f.node.cluster_epoch)
        .execute(&f.f.owner)
        .await?;
    server.abort();
    f.guard.shutdown().await?;
    result
}

async fn check_metrics_http_contract(
    f: &crate::termination_ledger::tests::FixtureRuntime,
    backend: &PrometheusMetrics,
    address: std::net::SocketAddr,
    q: &crate::instance_metrics::InstanceMetricQuery,
    mode: &Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    use crate::{
        api::{AppState, router},
        auth::{AuthConfig, JwtAuthenticator},
        history::CursorSigner,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use tower::ServiceExt;
    f.f.bind_client_id("metrics-test").await?;
    let app = router(Arc::new(AppState {
        database: f.f.database.clone(),
        auth: JwtAuthenticator::new(AuthConfig {
            scope_profile: Default::default(),
            issuer: "https://issuer.example.test".into(),
            audience: "sandbox-api".into(),
            jwks_url: format!("http://{address}/jwks"),
            required_scopes: vec!["sandbox:access".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })?,
        cursor_signer: CursorSigner::from_json(include_str!(
            "../tests/fixtures/history/cursor-keys.json"
        ))?,
        output_reader: None,
        metrics: Some(backend.clone()),
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let token = |life: i64| -> anyhow::Result<String> {
        let now = Utc::now().timestamp();
        let mut h = Header::new(Algorithm::RS256);
        h.typ = Some("at+jwt".into());
        h.kid = Some("key-a".into());
        Ok(encode(
            &h,
            &json!({"iss":"https://issuer.example.test","sub":f.f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"metrics-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+life,"scope":"sandbox:access"}),
            &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
        )?)
    };
    let parameters = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("metric", "VM_MEMORY_ANON_BYTES")
        .append_pair("start", &q.start.to_rfc3339())
        .append_pair("end", &q.end.to_rfc3339())
        .append_pair("step_seconds", "15")
        .finish();
    let send = |suffix: &str, token: String| -> anyhow::Result<Request<Body>> {
        Ok(Request::get(format!(
            "/v1/instances/{}/metrics?{parameters}{suffix}",
            f.launch.instance_id
        ))
        .header("authorization", format!("Bearer {token}"))
        .header("x-tenant-id", f.f.actor.tenant_id.to_string())
        .body(Body::empty())?)
    };
    for suffix in ["&query=up", "&metric=VM_MEMORY_BYTES", "&step_seconds=30"] {
        assert_eq!(
            app.clone()
                .oneshot(send(suffix, token(300)?)?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let response = app.clone().oneshot(send("", token(300)?)?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let data: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 128 * 1024).await?)?;
    assert_eq!(data["launch_id"], f.launch.launch_id.to_string());
    assert_eq!(data["series"]["points"][0]["status"], "MISSING");
    assert!(data["series"]["points"][0]["value"].is_null());
    for metric in [
        "VM_CPU_THROTTLED_PERIODS_PER_SECOND",
        "VM_CPU_THROTTLED_SECONDS_PER_SECOND",
        "VM_MEMORY_ANON_BYTES",
        "VM_MEMORY_FILE_BYTES",
        "VM_MEMORY_OOM_EVENTS_PER_SECOND",
        "VM_MEMORY_OOM_KILLS_PER_SECOND",
        "VM_CPU_CAPACITY_CORES",
        "VM_MEMORY_CAPACITY_BYTES",
    ] {
        let query = parameters.replace("VM_MEMORY_ANON_BYTES", metric);
        let response = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/v1/instances/{}/metrics?{query}",
                    f.launch.instance_id
                ))
                .header("authorization", format!("Bearer {}", token(300)?))
                .header("x-tenant-id", f.f.actor.tenant_id.to_string())
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "{metric}");
        let value: Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 128 * 1024).await?)?;
        assert_eq!(value["series"]["metric"], metric);
        assert!(
            value["series"]["points"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["status"] == "MISSING" && p["value"].is_null())
        );
    }
    mode.store(3, Ordering::SeqCst);
    let expired = app.clone().oneshot(send("", token(3)?)?).await?;
    mode.store(0, Ordering::SeqCst);
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
    mode.store(4, Ordering::SeqCst);
    let revoked = app.oneshot(send("", token(300)?)?).await?;
    mode.store(0, Ordering::SeqCst);
    sqlx::query("UPDATE principal_identities SET enabled=true WHERE principal_id=$1")
        .bind(f.f.actor.principal_id)
        .execute(&f.f.owner)
        .await?;
    assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn production_tls_basic_reader_verifies_ca_and_rotates_files_without_ambient_credentials()
-> anyhow::Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::os::unix::fs::PermissionsExt;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = tempfile::NamedTempFile::new()?;
    std::fs::write(
        ca.path(),
        include_bytes!("../tests/fixtures/admission/server-ca.pem"),
    )?;
    let user = tempfile::NamedTempFile::new()?;
    let password = tempfile::NamedTempFile::new()?;
    std::fs::write(user.path(), "PUBLIC_METRICS_READER")?;
    std::fs::write(password.path(), "PUBLIC_PASSWORD_A")?;
    let state = Backend {
        body: Arc::new(Mutex::new(response(vec![]))),
        status: Arc::new(AtomicU16::new(200)),
        calls: Arc::new(AtomicUsize::new(0)),
        auth: Arc::new(Mutex::new(format!(
            "Basic {}",
            STANDARD.encode("PUBLIC_METRICS_READER:PUBLIC_PASSWORD_A")
        ))),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        include_bytes!("../tests/fixtures/admission/server.pem").to_vec(),
        include_bytes!("../tests/fixtures/admission/server.key").to_vec(),
    )
    .await?;
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    let app = Router::new()
        .route("/managed/api/v1/query_range", get(serve))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)?
            .handle(handle)
            .serve(app.into_make_service())
            .await
    });
    let mut config = MetricsBackendConfig {
        endpoint: format!("https://{address}/managed"),
        deployment: "production-a".into(),
        auth: MetricsAuthentication::Basic {
            username_file: user.path().into(),
            password_file: password.path().into(),
        },
        ca_file: None,
        replicas: vec!["a".into()],
    };
    let result = async {
        let wrong = PrometheusMetrics::new(config.clone()).await?;
        assert_eq!(
            wrong
                .query(&binding(), RuntimeMetric::VmCpuCores, range())
                .await
                .unwrap_err(),
            MetricsError::Unavailable
        );
        assert_eq!(state.calls.load(Ordering::SeqCst), 0);
        config.ca_file = Some(ca.path().into());
        let client = PrometheusMetrics::new(config).await?;
        client
            .query(&binding(), RuntimeMetric::VmCpuCores, range())
            .await?;
        std::fs::write(password.path(), "PUBLIC_PASSWORD_B")?;
        *state.auth.lock().unwrap() = format!(
            "Basic {}",
            STANDARD.encode("PUBLIC_METRICS_READER:PUBLIC_PASSWORD_B")
        );
        client
            .query(&binding(), RuntimeMetric::VmCpuCores, range())
            .await?;
        std::fs::set_permissions(password.path(), std::fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            client
                .query(&binding(), RuntimeMetric::VmCpuCores, range())
                .await
                .unwrap_err(),
            MetricsError::Credential
        );
        assert_eq!(state.calls.load(Ordering::SeqCst), 2);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    shutdown.graceful_shutdown(Some(Duration::from_secs(1)));
    server.await??;
    result
}
