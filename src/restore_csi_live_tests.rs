//! Kube-client HTTP reads against fixed synthetic CSI objects. No SA token
//! is supplied by these loopback units: they are not authentication evidence.
//! These units have no sealed Source14 scope, PG authority or vendor Gate.
use super::super::csi_live_fixture::{Input, fixture};
use super::*;
use anyhow::{Context, Result as TestResult, ensure};
use axum::{
    Router,
    extract::{Request as Incoming, State},
    response::{IntoResponse, Response},
    routing::get as route_get,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type Objects = BTreeMap<String, Value>;
#[derive(Default)]
struct WireState {
    objects: Objects,
    arrivals: Vec<String>,
    raw: BTreeMap<String, String>,
    status: BTreeMap<String, u16>,
    second_uid_path: Option<String>,
    protocol_errors: usize,
}
type Shared = Arc<Mutex<WireState>>;
struct HttpFixture {
    client: Client,
    state: Shared,
    stop: CancellationToken,
    server: Option<JoinHandle<std::io::Result<()>>>,
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(server) = self.server.take() {
            server.abort();
        }
        // Failure fallback does not prove server/task join or pool drain.
    }
}
async fn handler(State(shared): State<Shared>, request: Incoming) -> Response {
    let path = request.uri().path().to_owned();
    let mut state = match shared.lock() {
        Ok(state) => state,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let query: BTreeMap<String, String> = pairs.iter().cloned().collect();
    let key = if path == "/api/v1/namespaces/kube-system/pods" {
        if pairs.len() == query.len()
            && query.len() == 2
            && query.get("labelSelector").map(String::as_str) == Some("app=csi-provisioner")
            && query.get("limit").map(String::as_str) == Some("4")
        {
            "controller-list".to_owned()
        } else if pairs.len() == query.len()
            && query.len() == 3
            && query.get("labelSelector").map(String::as_str) == Some("app=csi-plugin")
            && query.get("limit").map(String::as_str) == Some("2")
            && query.get("fieldSelector").map(String::as_str) == Some("spec.nodeName=kata-node-1")
        {
            "selected-plugin-list".to_owned()
        } else {
            state.protocol_errors += 1;
            return StatusCode::BAD_REQUEST.into_response();
        }
    } else if pairs.is_empty() {
        path.clone()
    } else {
        state.protocol_errors += 1;
        return StatusCode::BAD_REQUEST.into_response();
    };
    state.arrivals.push(key.clone());
    if let Some(code) = state.status.get(&key) {
        return StatusCode::from_u16(*code)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            .into_response();
    }
    if let Some(raw) = state.raw.get(&key) {
        return ([("content-type", "application/json")], raw.clone()).into_response();
    }
    let mut value = match state.objects.get(&key) {
        Some(v) => v.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    if state.second_uid_path.as_ref() == Some(&key)
        && state.arrivals.iter().filter(|x| *x == &key).count() == 2
    {
        value["metadata"]["resourceVersion"] = json!("2");
    }
    axum::Json(value).into_response()
}
impl HttpFixture {
    async fn start(objects: Objects) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let state = Arc::new(Mutex::new(WireState {
            objects,
            ..Default::default()
        }));
        let router = Router::new()
            .fallback(route_get(handler))
            .with_state(state.clone());
        let stop = CancellationToken::new();
        let cancelled = stop.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(cancelled.cancelled_owned())
                .await
        });
        let mut config = kube::Config::new(format!("http://{address}").parse()?);
        // Classification-only units count terminal HTTP errors; production
        // held client retry/defaults are unchanged by this fixture setting.
        config.default_retry = false;
        let client = match Client::try_from(config) {
            Ok(client) => client,
            Err(error) => {
                stop.cancel();
                server.abort();
                let _ = server.await;
                return Err(error.into());
            }
        };
        Ok(Self {
            client,
            state,
            stop,
            server: Some(server),
        })
    }
    async fn finish(&mut self) -> TestResult<()> {
        self.stop.cancel();
        let Some(mut server) = self.server.take() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
            Ok(result) => {
                result
                    .context("CSI HTTP fixture join failed")?
                    .context("CSI HTTP fixture server failed")?;
                Ok(())
            }
            Err(_) => {
                server.abort();
                let _ = server.await;
                anyhow::bail!("CSI HTTP fixture did not join before unit cleanup deadline")
            }
        }
    }
}
fn expected(input: &Input) -> Expected<'_> {
    Expected {
        controller: &input.controller,
        node_plugin: &input.node_plugin,
        images: &input.images,
        zones: &input.zones,
        selected: &input.selected,
        selected_zone: &input.selected_zone,
    }
}
#[tokio::test]
async fn two_rounds_read_exact_current_controller_set_and_selected_plugin() -> TestResult<()> {
    let input = fixture()?;
    let mut http = HttpFixture::start(input.objects.clone()).await?;
    let result: TestResult<()> = async {
        let deadline = Instant::now() + Duration::from_secs(5);
        let first = Box::pin(round(&http.client, &expected(&input), deadline))
            .await
            .map_err(|_| anyhow::anyhow!("first real HTTP round rejected"))?;
        let second = Box::pin(round(&http.client, &expected(&input), deadline))
            .await
            .map_err(|_| anyhow::anyhow!("second real HTTP round rejected"))?;
        same_snapshot(&first, &second)
            .map_err(|_| anyhow::anyhow!("same raw observations drifted"))?;
        ensure!(first.objects.len() == 19);
        let state = http
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?;
        ensure!(state.protocol_errors == 0 && state.arrivals.len() == 38);
        for count in state
            .arrivals
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut m, k| {
                *m.entry(k).or_default() += 1;
                m
            })
            .values()
        {
            ensure!(*count == 2);
        }
        Ok(())
    }
    .await;
    let cleanup = http.finish().await;
    result?;
    cleanup
}
#[tokio::test]
async fn raw_duplicate_key_rejected_before_lossy_value_and_retry_is_unit_only() -> TestResult<()> {
    let input = fixture()?;
    let path = "/apis/apps/v1/namespaces/kube-system/deployments/csi-provisioner";
    let mut http = HttpFixture::start(input.objects.clone()).await?;
    let result: TestResult<()> = async {
        let original = serde_json::to_string(input.objects.get(path).context("deployment")?)?;
        http.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
            .raw
            .insert(
                path.into(),
                format!("{{\"kind\":\"Deployment\",{}", &original[1..]),
            );
        let error = Box::pin(round(
            &http.client,
            &expected(&input),
            Instant::now() + Duration::from_secs(5),
        ))
        .await
        .err()
        .context("duplicate wire accepted")?;
        ensure!(error.status == StatusCode::FORBIDDEN);
        ensure!(
            http.state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
                .arrivals
                .as_slice()
                == [path]
        );
        Ok(())
    }
    .await;
    let cleanup = http.finish().await;
    result?;
    cleanup
}
#[tokio::test]
async fn continuation_extra_controller_owner_and_unknown_pod_are_denied_at_actual_http()
-> TestResult<()> {
    for fault in 0..4 {
        let mut input = fixture()?;
        match fault {
            0 => {
                input.objects.get_mut("controller-list").context("list")?["metadata"]["continue"] =
                    json!("more")
            }
            1 => {
                let extra = input.objects["controller-list"]["items"][0].clone();
                input.objects.get_mut("controller-list").context("list")?["items"]
                    .as_array_mut()
                    .context("items")?
                    .push(extra);
            }
            2 => {
                let path = input
                    .objects
                    .keys()
                    .find(|p| p.contains("/replicasets/"))
                    .context("rs path")?
                    .clone();
                input.objects.get_mut(&path).context("rs")?["metadata"]["uid"] =
                    json!(Uuid::new_v4());
            }
            _ => {
                input.objects.get_mut("controller-list").context("list")?["items"][0]["spec"]["unknownRuntimeField"] =
                    json!(true);
                let pod = input.objects["controller-list"]["items"][0].clone();
                let name = pod["metadata"]["name"].as_str().context("pod name")?;
                input
                    .objects
                    .insert(format!("/api/v1/namespaces/kube-system/pods/{name}"), pod);
            }
        }
        let mut http = HttpFixture::start(input.objects.clone()).await?;
        let result: TestResult<()> = async {
            let error = Box::pin(round(
                &http.client,
                &expected(&input),
                Instant::now() + Duration::from_secs(5),
            ))
            .await
            .err()
            .context("bad real HTTP object accepted")?;
            ensure!(error.status == StatusCode::FORBIDDEN);
            let state = http
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?;
            ensure!(
                state.protocol_errors == 0
                    && state.arrivals.len() == if fault < 2 { 7 } else { 10 }
            );
            Ok(())
        }
        .await;
        let cleanup = http.finish().await;
        result?;
        cleanup?;
    }
    Ok(())
}
#[tokio::test]
async fn second_round_priority_identity_observation_changes_and_notfound_are_distinct()
-> TestResult<()> {
    let input = fixture()?;
    let pc = "/apis/scheduling.k8s.io/v1/priorityclasses/system-node-critical";
    let mut http = HttpFixture::start(input.objects.clone()).await?;
    let result: TestResult<()> = async {
        http.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
            .second_uid_path = Some(pc.into());
        let deadline = Instant::now() + Duration::from_secs(5);
        let first = Box::pin(round(&http.client, &expected(&input), deadline))
            .await
            .map_err(|_| anyhow::anyhow!("first round rejected"))?;
        let second = Box::pin(round(&http.client, &expected(&input), deadline))
            .await
            .map_err(|_| anyhow::anyhow!("second round rejected"))?;
        ensure!(same_snapshot(&first, &second).is_err());
        {
            let state = http
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?;
            ensure!(state.protocol_errors == 0 && state.arrivals.len() == 38);
        }
        for (status, expected_status) in [
            (404, StatusCode::FORBIDDEN),
            (503, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            http.state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
                .status
                .insert(
                    "/apis/apps/v1/namespaces/kube-system/deployments/csi-provisioner".into(),
                    status,
                );
            let error = Box::pin(round(&http.client, &expected(&input), deadline))
                .await
                .err()
                .context("HTTP error accepted")?;
            ensure!(error.status == expected_status);
        }
        Ok(())
    }
    .await;
    let cleanup = http.finish().await;
    result?;
    cleanup
}

#[tokio::test]
async fn expired_original_observation_budget_and_oversize_wire_never_progress() -> TestResult<()> {
    let input = fixture()?;
    let mut http = HttpFixture::start(input.objects.clone()).await?;
    let result: TestResult<()> = async {
        let error = Box::pin(round(&http.client, &expected(&input), Instant::now()))
            .await
            .err()
            .context("expired deadline accepted")?;
        ensure!(error.status == StatusCode::FORBIDDEN);
        ensure!(
            http.state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
                .arrivals
                .is_empty()
        );
        let path = "/apis/apps/v1/namespaces/kube-system/deployments/csi-provisioner";
        http.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
            .raw
            .insert(path.into(), " ".repeat(LIMIT + 1));
        let error = Box::pin(round(
            &http.client,
            &expected(&input),
            Instant::now() + Duration::from_secs(5),
        ))
        .await
        .err()
        .context("oversize stream accepted")?;
        ensure!(error.status == StatusCode::FORBIDDEN);
        ensure!(
            http.state
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
                .arrivals
                .as_slice()
                == [path]
        );
        Ok(())
    }
    .await;
    let cleanup = http.finish().await;
    result?;
    cleanup
}
