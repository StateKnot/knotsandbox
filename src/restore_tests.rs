//! Draft-schema integration runs only in a named dedicated restore test database. Production
//! activation remains closed until the complete data-mover/CSI path is certified.
use super::*;
use crate::{backup_ledger::pipeline_tests::vault::completed_source, test_support_db};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use sqlx::Connection;
#[path = "restore_admission_tests.rs"]
mod admission;
#[path = "restore_control_admission_tests.rs"]
mod control;
#[path = "restore_delete_tests.rs"]
mod deletion;
#[path = "restore_file_role_tests.rs"]
mod file_role;
#[path = "restore_gc_tests.rs"]
mod gc;
#[path = "restore_gc_admission_tests.rs"]
mod gc_admission;
#[path = "restore_grant_tests.rs"]
mod grants;
#[path = "restore_node_topology_tests.rs"]
mod node_topology;
#[path = "restore_node_admission_tests.rs"]
mod nodes;
#[path = "restore_raw_admission_tests.rs"]
mod raw_parent;
#[path = "restore_start_tests.rs"]
mod start;
#[path = "restore_storage_mapping_http_tests.rs"]
mod storage_http;
#[path = "restore_storage_mapping_tests.rs"]
mod storage_mapping;

#[tokio::test]
#[ignore = "requires dedicated restore database, backup TLS fixture and OpenSSL 3"]
async fn signed_available_source_atomic_cross_project_restore_acceptance_and_revocation()
-> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        true,
        GcValidation::None,
        false,
        false,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires a fresh dedicated restore database, real PG/mTLS and loopback signed STS/ECS"]
async fn restored_workspace_never_started_delete_preserves_source_and_releases_only_proven_storage()
-> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        false,
        GcValidation::None,
        false,
        false,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires a fresh dedicated restore database, independent GC SCRAM and signed TCP"]
async fn restored_temporary_storage_gc_then_first_start_keeps_fixed_filesystem_and_source()
-> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        true,
        GcValidation::Normal,
        false,
        false,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires a fresh dedicated restore database, independent GC SCRAM and signed TCP"]
async fn restore_gc_direct_results_and_event_wait_cannot_bypass_current_claim() -> anyhow::Result<()>
{
    Box::pin(run_restored_workspace(
        true,
        GcValidation::Guards,
        false,
        false,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires a fresh dedicated restore database, narrow admission role, Kube and real mTLS"]
async fn restore_admission_job_config_pod_current_authority_and_one_shot_creation()
-> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        true,
        GcValidation::None,
        false,
        false,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires fresh restore database, independent admission/GC roles and actual loopback HTTP"]
async fn restore_gc_metadata_admission_requires_closed_exact_resources_and_live_claim()
-> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        false,
        GcValidation::Admission,
        false,
        false,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires fresh dedicated restore DB, exact admission login, real HTTP and mTLS"]
async fn restore_historical_control_cleanup_and_job_status_require_exact_recorded_authority()
-> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        false,
        GcValidation::None,
        true,
        false,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires fresh private PG, narrow roles and actual TCP storage HTTP; never cloud certification"]
async fn restore_storage_mapping_atomic_authority_and_actual_http_drift() -> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        true,
        GcValidation::None,
        false,
        true,
        false,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires fresh private PG, exact admission role and actual TCP Pending PVC; not CSI certification"]
async fn restore_raw_parent_initial_create_pending_uid_and_earlyintent_are_atomic()
-> anyhow::Result<()> {
    Box::pin(run_restored_workspace(
        false,
        GcValidation::None,
        false,
        false,
        true,
    ))
    .await
}

#[derive(Clone, Copy)]
enum GcValidation {
    None,
    Normal,
    Guards,
    Admission,
}

struct PendingParentHttp {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl PendingParentHttp {
    async fn finish(mut self) -> anyhow::Result<()> {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            match tokio::time::timeout(std::time::Duration::from_secs(3), task).await {
                Ok(result) => result??,
                Err(_) => anyhow::bail!("Pending parent HTTP fixture did not drain"),
            }
        }
        self.task.take();
        Ok(())
    }
}
impl Drop for PendingParentHttp {
    fn drop(&mut self) {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// Establish the parent through the actual runtime and DB before the legacy
/// full-flow fixture supplies its explicit Bound disk. This loopback API serves
/// only Pending storage and is not a vendor CSI or cloud certification.
async fn record_pending_raw_parent(
    engine: &crate::engine::OperationEngine,
    claim: &crate::engine::Claim,
    plan: resources::RestoreStoragePlan,
    mut initial: std::collections::BTreeMap<String, Value>,
    pvc_uid: Uuid,
) -> anyhow::Result<resources::RestoreStoragePlan> {
    use axum::{
        Router,
        body::Body,
        http::{Method, Request, Response, StatusCode},
    };
    use std::sync::{Arc, Mutex};

    ensure!(
        plan.known_pvc.is_none() && plan.known_pv.is_none(),
        "initial parent fixture must have no recorded raw storage"
    );
    let expected = plan.context.block_pvc()?;
    let pvc_path = format!(
        "/api/v1/namespaces/{}/persistentvolumeclaims/{}",
        crate::backup_manifest::NAMESPACE,
        crate::backup_manifest::block_pvc_name(plan.context.restore_id)
    );
    let mut pending = expected.clone();
    pending["metadata"]["uid"] = json!(pvc_uid);
    pending["metadata"]["resourceVersion"] = json!("1");
    pending["metadata"]["creationTimestamp"] = json!(Utc::now());
    pending["metadata"]["finalizers"] = json!(["kubernetes.io/pvc-protection"]);
    pending["status"] = json!({"phase":"Pending"});
    initial.retain(|path, _| {
        !path.starts_with("/api/v1/persistentvolumes/")
            && !path.contains("/pods/")
            && !path.contains("/jobs/")
    });
    initial.insert(pvc_path.clone(), pending);
    let values = Arc::new(initial);
    let requests = Arc::new(Mutex::new(Vec::<(Method, String)>::new()));
    let callback = requests.clone();
    let app = Router::new().fallback(move |r: Request<Body>| {
        let values = values.clone();
        let requests = callback.clone();
        async move {
            let method = r.method().clone();
            let path = r.uri().path().to_owned();
            let (code, body) = if let Ok(mut seen) = requests.lock() {
                seen.push((method.clone(), path.clone()));
                if method == Method::GET {
                    values.get(&path).cloned().map_or_else(
                        || (StatusCode::NOT_FOUND, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404})),
                        |v| (StatusCode::OK, v),
                    )
                } else {
                    (StatusCode::METHOD_NOT_ALLOWED, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"MethodNotAllowed","code":405}))
                }
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, json!({"code":500}))
            };
            let mut response = Response::new(Body::from(body.to_string()));
            *response.status_mut() = code;
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
            response
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let runtime =
        crate::backup_job::BackupJobRuntime::new(crate::runtime::KubernetesRuntime::from_client(
            kube::Client::try_from(kube::Config::new(endpoint.parse()?))?,
        ));
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let server = PendingParentHttp {
        shutdown: Some(shutdown),
        task: Some(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        })),
    };
    let observed = Box::pin(runtime.reconcile_restore_block(
        &plan.context,
        &plan.cloud,
        plan.known_pvc,
        plan.known_pv,
        &plan.source,
    ))
    .await?;
    ensure!(
        observed.pvc_uid == pvc_uid && observed.bound.is_none(),
        "initial parent must be a stable unbound Pending observation"
    );
    {
        let seen = requests
            .lock()
            .map_err(|_| anyhow::anyhow!("Pending parent request log poisoned"))?;
        ensure!(
            seen.iter().filter(|(m, p)| *m == Method::GET && *p == pvc_path).count() == 2
                && seen.iter().all(|(m, p)| *m == Method::GET && !p.starts_with("/api/v1/persistentvolumes/")),
            "Pending parent must reach two actual claim GETs with no PV read or mutation"
        );
    }
    Box::pin(server.finish()).await?;
    Box::pin(
        engine
            .database
            .record_restore_block(engine, claim, &observed),
    )
    .await
    .map_err(test_support_db::api_failure)?;
    let mut tx = engine
        .database
        .begin(claim.tenant_id)
        .await
        .map_err(test_support_db::api_failure)?;
    let artifacts: Value = sqlx::query_scalar("SELECT jsonb_build_object('pvc_binding',(SELECT count(*) FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind='BLOCK_PVC'),'pv_intent',(SELECT count(*) FROM restore_resource_intents i WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind='BLOCK_PV' AND i.namespace='' AND i.name=$3 AND i.expected_object IS NULL),'pv_binding',(SELECT count(*) FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind='BLOCK_PV'),'raw',(SELECT count(*) FROM restore_block_receipts x WHERE x.tenant_id=$1 AND x.restore_id=$2),'permit',(SELECT count(*) FROM restore_launch_permits x WHERE x.tenant_id=$1 AND x.restore_id=$2),'proof',(SELECT count(*) FROM restore_termination_proofs x WHERE x.tenant_id=$1 AND x.restore_id=$2),'cleanup',(SELECT count(*) FROM restore_cleanup_receipts x WHERE x.tenant_id=$1 AND x.restore_id=$2))")
        .bind(claim.tenant_id).bind(plan.context.restore_id).bind(manifest::generated_block_pv_name(pvc_uid)?).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        artifacts
            == json!({"pvc_binding":1,"pv_intent":1,"pv_binding":0,"raw":0,"permit":0,"proof":0,"cleanup":0}),
        "Pending parent record must create only its PVC binding and identity-only PV intent: {artifacts}"
    );
    let recorded = Box::pin(engine.database.prepare_restore_storage(engine, claim))
        .await
        .map_err(test_support_db::api_failure)?;
    ensure!(
        recorded.known_pvc == Some(observed.pvc_uid)
            && recorded.known_pv.is_none()
            && recorded.context.block_pvc()? == expected,
        "Bound fixture must obtain its immutable parent from the actual DB storage plan"
    );
    Ok(recorded)
}

async fn run_restored_workspace(
    start: bool,
    validation: GcValidation,
    controls: bool,
    mappings: bool,
    raw_parent: bool,
) -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .without_time()
        .with_test_writer()
        .try_init();
    let parsed = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        matches!(
            parsed.path(),
            "/sandbox_restore_test" | "/sandbox_restore_acceptance_test"
        ) || parsed
            .path()
            .strip_prefix("/sandbox_restore_acceptance_")
            .and_then(|s| s.strip_suffix("_test"))
            .is_some_and(|id| !id.is_empty()
                && id.len() <= 20
                && id.bytes().all(|b| b.is_ascii_digit())),
        "restore draft must use its independent disposable database"
    );
    // The ordinary termination path includes file-transfer closure. Load the
    // normal ordered migrations before constructing the real signed source;
    // the restore draft never modifies the normal migration ledger.
    let owner_url = std::env::var("TEST_MIGRATION_DATABASE_URL")?;
    let owner_target = url::Url::parse(&owner_url)?;
    ensure!(
        owner_target.path() == parsed.path()
            && owner_target.host_str() == parsed.host_str()
            && owner_target.port_or_known_default() == parsed.port_or_known_default()
            && owner_target.username() != parsed.username(),
        "restore owner and runtime identities must share the dedicated database"
    );
    let owner = sqlx::PgPool::connect(&owner_url).await?;
    sqlx::migrate!().run(&owner).await?;
    // The real admission reader needs its normal tenant/RLS helper grants;
    // the previous consume-only fixture invoked a definer without direct reads.
    sqlx::raw_sql(include_str!("../scripts/sql/admission-role.sql"))
        .execute(&owner)
        .await?;
    owner.close().await;
    // Construct the normal certified-cold source and all narrow live roles
    // before explicitly applying the private draft. Draft presence must refuse
    // production startup; it never acquires a fake successful SQLx record.
    let (p, verifier, _dir) = Box::pin(completed_source()).await?;
    crate::workspace_restore::verify_component_schema(&p.f.base.f.database.pool).await?;
    // Establish fresh-role proofs before any private DDL. They cannot be
    // constructed from a failed production verifier or after the draft exists.
    let next_epoch_connections = if raw_parent {
        let connections = test_support_db::Fixture::prepare_verified_connections().await?;
        let termination = connections
            .runtime("TEST_TERMINATION_DATABASE_URL", "sandbox_termination", 5)
            .await?;
        Some((connections, termination))
    } else {
        None
    };
    // A lone private function is also an incomplete installation. This false
    // metadata probe cannot authorize a writer and is removed before the real
    // draft; no SQLx migration record is created or bypassed.
    sqlx::raw_sql("CREATE FUNCTION sandbox_lock_restore_admission(uuid,uuid) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
        .execute(&p.f.base.f.owner).await?;
    let partial = crate::workspace_restore::verify_component_schema(&p.f.base.f.database.pool)
        .await
        .err()
        .context("partial restore function must close production startup")?;
    ensure!(
        partial
            .to_string()
            .contains("successful ordered migration 0038"),
        "schema gate must reject partial metadata, not fail through missing grants"
    );
    sqlx::raw_sql("DROP FUNCTION sandbox_lock_restore_admission(uuid,uuid)")
        .execute(&p.f.base.f.owner)
        .await?;
    crate::workspace_restore::verify_component_schema(&p.f.base.f.database.pool).await?;
    let mut schema = p.f.base.f.owner.begin().await?;
    let draft = include_str!("../tests/fixtures/restore/0038_restores.sql");
    ensure!(draft.len() <= 512 * 1024, "bounded draft schema required");
    sqlx::raw_sql(draft).execute(&mut *schema).await?;
    sqlx::raw_sql(include_str!(
        "../tests/fixtures/restore/0038_restore_control_admission.sql"
    ))
    .execute(&mut *schema)
    .await?;
    if raw_parent {
        sqlx::raw_sql(include_str!(
            "../tests/fixtures/restore/0038_restore_raw_parent_admission.sql"
        ))
        .execute(&mut *schema)
        .await?;
    }
    schema.commit().await?;
    sqlx::raw_sql(include_str!("../scripts/sql/restore-role.sql"))
        .execute(&p.f.base.f.owner)
        .await?;
    // A migration changes SELECT * result shapes. Drain every already-open
    // private fixture connection's statement cache, as a deployment drains its
    // old connection pool. This is only a test boundary; startup still rejects
    // the draft, and no permission failure is swallowed or bypassed.
    for database in [
        &p.f.base.f.database,
        &p.f.base.engine.database,
        &p.f.backup.database,
    ] {
        let mut connections = Vec::new();
        for _ in 0..database.pool.options().get_max_connections() {
            let mut connection = database.pool.acquire().await?;
            connection.clear_cached_statements().await?;
            connections.push(connection);
        }
    }
    for database in [
        &p.f.base.f.database,
        &p.f.base.engine.database,
        &p.f.backup.database,
    ] {
        assert!(
            database.verify_runtime_role().await.is_err(),
            "draft 38 cannot pass production startup"
        );
    }
    // Source is already signed, AVAILABLE and immutable in the old epoch.
    // A separate normal mTLS fixture registers a fresh current-epoch Node;
    // its identity supplies only the reviewed global launch guard contract.
    let current_epoch_node = if let Some((connections, termination)) = &next_epoch_connections {
        connections.clear_statement_caches().await?;
        termination.clear_statement_caches().await?;
        let mut tx = p.f.base.f.owner_transaction().await?;
        let preserved: Value = sqlx::query_scalar("SELECT jsonb_build_object('backup',to_jsonb(b),'vault',to_jsonb(v),'node',(SELECT to_jsonb(n) FROM runtime_nodes n WHERE n.cluster_epoch=b.cluster_epoch AND n.node_uid=$3 AND n.boot_id=$4)) FROM backups b JOIN backup_vault_receipts v ON v.tenant_id=b.tenant_id AND v.backup_id=b.id WHERE b.tenant_id=$1 AND b.id=$2")
            .bind(p.f.base.f.actor.tenant_id).bind(p.plan.backup.id).bind(p.f.base.node.node_uid).bind(p.f.base.node.boot_id).fetch_one(&mut *tx).await?;
        let epoch = Uuid::new_v4();
        ensure!(
            preserved["backup"]["cluster_epoch"] != json!(epoch) && preserved["node"].is_object(),
            "old source and its node are immutable historical facts"
        );
        sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
            .bind(epoch)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let current = Box::pin(
            crate::termination_ledger::tests::FixtureRuntime::new_with_verified_connections(
                true,
                connections,
                termination,
            ),
        )
        .await?;
        ensure!(
            current.node.cluster_epoch == epoch
                && current.node.cluster_epoch != p.f.base.node.cluster_epoch,
            "fresh normal runtime fixture belongs to the new current epoch"
        );
        let mut tx = p.f.base.f.owner_transaction().await?;
        let original_tenant: Uuid = sqlx::query_scalar("SELECT sandbox_current_tenant_id()")
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            original_tenant == p.f.base.f.actor.tenant_id,
            "fresh node tenant must not leak into the original owner's transaction"
        );
        let after: Value = sqlx::query_scalar("SELECT jsonb_build_object('backup',to_jsonb(b),'vault',to_jsonb(v),'node',(SELECT to_jsonb(n) FROM runtime_nodes n WHERE n.cluster_epoch=b.cluster_epoch AND n.node_uid=$3 AND n.boot_id=$4)) FROM backups b JOIN backup_vault_receipts v ON v.tenant_id=b.tenant_id AND v.backup_id=b.id WHERE b.tenant_id=$1 AND b.id=$2")
            .bind(p.f.base.f.actor.tenant_id).bind(p.plan.backup.id).bind(p.f.base.node.node_uid).bind(p.f.base.node.boot_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        ensure!(
            after == preserved,
            "epoch switch must not rewrite the frozen source, signed vault or original Node"
        );
        Some(current)
    } else {
        None
    };
    let ordinary_guard = current_epoch_node.as_ref().unwrap_or(&p.f.base);
    let restore_epoch = ordinary_guard.node.cluster_epoch;
    let actor = &p.f.base.f.actor;
    let backup = p.plan.backup.id;
    let project = Uuid::new_v4();
    let profile = Uuid::new_v4();
    let target_policy = Uuid::new_v4();
    // Keep this completed fixture transaction's temporaries out of the shared
    // scenario poll frame used later by trusted termination and cleanup.
    let (_storage_mappings, _storage_report, storage_objects, version) = Box::pin(async {
        let mut tx = p.f.base.f.owner_transaction().await?;
        sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,'Restore target',86400,$3,'integration-storage')")
            .bind(project).bind(actor.tenant_id).bind(format!("restore-{}",project.simple())).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) SELECT tenant_id,$2,dimension,limit_value FROM quota_accounts WHERE tenant_id=$1 AND project_id=$3")
            .bind(actor.tenant_id).bind(project).bind(p.f.base.launch.project_id).execute(&mut *tx).await?;
        for (project, action) in [
            (None, "backups:restore"),
            (Some(p.f.base.launch.project_id), "backups:restore"),
            (None, "instances:create"),
            (Some(project), "instances:create"),
            (None, "restores:read"),
            (Some(project), "restores:read"),
        ] {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            )
            .bind(actor.tenant_id)
            .bind(project)
            .bind(actor.principal_id)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'restored-runtime',1,'APPROVED',$3)")
            .bind(target_policy).bind(actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO backup_profiles(id,cluster_epoch,enabled,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings) SELECT $1,$3,true,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings FROM backup_profiles WHERE id=$2")
            .bind(profile).bind(p.f.profile).bind(restore_epoch).execute(&mut *tx).await?;
        let (storage_epoch, backup_cert_sha, cloud_settings): (Uuid, String, Value) = sqlx::query_as(
            "SELECT cluster_epoch,certification_sha256,settings FROM backup_profiles WHERE id=$1",
        )
        .bind(profile)
        .fetch_one(&mut *tx)
        .await?;
        let fixture_cloud: crate::backup_job::BackupCloudSettings =
            serde_json::from_value(cloud_settings)?;
        let (storage_mappings, storage_report, storage_objects) =
            storage_mapping::fixture(&fixture_cloud, profile, storage_epoch, &backup_cert_sha)?;
        if mappings {
            Box::pin(storage_mapping::certification_inputs(
                &mut tx,
                profile,
                &storage_mappings,
                &storage_report,
            ))
            .await?;
        }
        sqlx::query("INSERT INTO restore_profile_certifications(profile_id,cluster_epoch,backup_certification_sha256,report_sha256,report,storage_mappings,approval_reference,reviewed_at,certified_until) SELECT id,cluster_epoch,certification_sha256,$2,$3,$4,'DISPOSABLE_TEST_NOT_PRODUCTION',clock_timestamp(),certified_until FROM backup_profiles WHERE id=$1")
            .bind(profile).bind(storage_mapping::digest(&storage_report)?).bind(&storage_report).bind(&storage_mappings).execute(&mut *tx).await?;
        let node: Uuid = sqlx::query_scalar("SELECT id FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3 AND enabled")
            .bind(ordinary_guard.node.cluster_epoch).bind(ordinary_guard.node.node_uid).bind(ordinary_guard.node.boot_id).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO launch_guard_contracts(id,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,approval_reference,valid_until) VALUES($1,$2,'NODEGUARD_REQUIRED_V1',$3,$4,'TEST ONLY: restore ordinary launch contract',clock_timestamp()+interval '1 day')")
            .bind(Uuid::new_v4()).bind(restore_epoch).bind("a".repeat(64)).bind(vec![node]).execute(&mut *tx).await?;
        sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
            .bind(p.f.profile)
            .execute(&mut *tx)
            .await?;
        let version: i64 =
            sqlx::query_scalar("SELECT version FROM backups WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(backup)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>((storage_mappings, storage_report, storage_objects, version))
    })
    .await?;
    let request = CreateRestore {
        target_project_id: project,
        name: "recovered-workspace".into(),
        profile_id: profile,
        template_version_id: p.f.base.f.request.template_version_id,
        security_profile_id: target_policy,
        flavor: Flavor::Cpu2Mem4,
    };
    let delegated = grants::create(
        &p.f.base.f.database,
        &p.f.base.f.owner,
        &p.f.base.f.actor,
        p.f.base.launch.project_id,
        project,
    )
    .await?;
    let actor = &delegated.actor;
    let db = &p.f.base.f.database;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(
        db.create_restore(actor, backup, &request, "expired-project-grant", version)
            .await
            .is_err(),
        "expired delegated source permission cannot accept a restore"
    );
    let restore_grant = db
        .update_project_grant(
            &p.f.base.f.actor,
            p.f.base.launch.project_id,
            delegated.source_restore.id,
            &crate::grants::UpdateGrant {
                enabled: true,
                expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            },
            "renew-delegated-restore-grant",
            delegated.source_restore.version,
        )
        .await
        .map_err(test_support_db::api_failure)?
        .body
        .resource;
    eprintln!(
        "VERIFIED real project-grant delegation, bounded expiry, expired restore refusal and API renewal"
    );
    let bad_version = db
        .create_restore(actor, backup, &request, "wrong-version", version - 1)
        .await
        .err()
        .context("version guard")?;
    assert_eq!(bad_version.code, "VERSION_MISMATCH");
    let (first, replay) = tokio::join!(
        db.create_restore(actor, backup, &request, "same-restore", version),
        db.create_restore(actor, backup, &request, "same-restore", version)
    );
    let first = first.map_err(test_support_db::api_failure)?;
    let replay = replay.map_err(test_support_db::api_failure)?;
    assert_eq!(first.body.resource.id, replay.body.resource.id);
    assert_eq!(first.body.resource.target_project_id, project);
    assert_eq!(
        first.body.resource.source_project_id,
        p.f.base.launch.project_id
    );
    assert_eq!(first.body.resource.status, "QUEUED");
    let restore = first.body.resource.id;
    assert!(
        p.f.backup
            .database
            .restore_bound_volume(actor.tenant_id, restore)
            .await
            .map_err(test_support_db::api_failure)?
            .is_none(),
        "an accepted recovery has no pre-existing raw device receipt"
    );
    let mut tx = p.f.base.f.owner_transaction().await?;
    let counts:(i64,i64,i64,String,String,Value)=sqlx::query_as("SELECT (SELECT count(*) FROM restores WHERE tenant_id=$1 AND id=$2),(SELECT count(*) FROM workspace_holds WHERE tenant_id=$1 AND reference_id=$2),(SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND operation_id=$3),i.desired_state,i.observed_state,r.source_identity FROM restores r JOIN instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id WHERE r.tenant_id=$1 AND r.id=$2")
        .bind(actor.tenant_id).bind(restore).bind(first.body.operation.id).fetch_one(&mut *tx).await?;
    assert_eq!(
        (
            counts.0,
            counts.1,
            counts.2,
            counts.3.as_str(),
            counts.4.as_str()
        ),
        (1, 1, 10, "STOPPED", "STOPPED")
    );
    assert_eq!(counts.5["project_id"], json!(p.f.base.launch.project_id));
    let old_enabled: bool = sqlx::query_scalar("SELECT enabled FROM backup_profiles WHERE id=$1")
        .bind(p.f.profile)
        .fetch_one(&mut *tx)
        .await?;
    assert!(!old_enabled);
    tx.commit().await?;
    if mappings {
        Box::pin(storage_mapping::accepted(
            &p.f.base.f.owner,
            [db, &p.f.backup.database],
            actor,
            backup,
            &request,
            version,
            &first.body,
        ))
        .await?;
    }
    let claim =
        p.f.backup
            .claim_backup()
            .await
            .map_err(test_support_db::api_failure)?
            .context("restore-only claim")?;
    assert_eq!(claim.operation_id, first.body.operation.id);
    let plan =
        p.f.backup
            .database
            .prepare_restore_verification(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    assert_eq!(plan.record.id, restore);
    assert_eq!(
        plan.cloud.vault_bucket,
        plan.expectation.identity.vault_bucket
    );
    assert_eq!(
        plan.expectation.identity.project_id,
        p.f.base.launch.project_id
    );
    let proof = verifier.verify(&plan.expectation).await?;
    p.f.backup
        .database
        .record_restore_verification(&p.f.backup, &claim, &proof)
        .await
        .map_err(test_support_db::api_failure)?;
    if raw_parent {
        let raw =
            p.f.backup
                .database
                .prepare_restore_storage(&p.f.backup, &claim)
                .await
                .map_err(test_support_db::api_failure)?;
        return Box::pin(raw_parent::verify(raw_parent::RawParentCase {
            engine: &p.f.backup,
            claim,
            base: &p.f.base,
            plan: raw,
            objects: storage_objects,
        }))
        .await;
    }
    let job =
        p.f.backup
            .database
            .prepare_restore_job(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    assert_eq!(job.context.cluster_epoch, p.f.base.node.cluster_epoch);
    let config: Value = serde_json::from_str(&job.context.config_json)?;
    assert_eq!(config["project_id"], json!(p.f.base.launch.project_id));
    assert_eq!(job.record.target_project_id, project);
    let raw =
        p.f.backup
            .database
            .prepare_restore_storage(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    let raw_pvc_uid = Uuid::new_v4();
    let volume = crate::backup_runtime::BoundBackupVolume {
        pvc_uid: raw_pvc_uid,
        pv_uid: Uuid::new_v4(),
        pv_name: manifest::generated_block_pv_name(raw_pvc_uid)?,
        cloud_disk: "d-restorefixture01".into(),
        size_bytes: raw.context.size_bytes,
    };
    let pod_name = format!(
        "{}-abcde",
        crate::nodeguard::protocol::backup_job_name(
            restore,
            crate::nodeguard::protocol::BackupStage::Restore
        )
    );
    // runtime_objects supplies mature network/secret/storage fixtures. Its Pod
    // entry is removed immediately; no Job UID or future Pod is pre-seeded.
    let pod_placeholder = json!({"metadata":{"name":pod_name}});
    let synthetic = crate::backup_ledger::JobPlan {
        clone_storage_class: raw.context.storage_contract.mapping.raw.name.clone(),
        backup: p.plan.backup.clone(),
        context: job.context.clone(),
        cloud: job.cloud.clone(),
        deadline: Utc::now() + chrono::Duration::hours(2),
        known_config: None,
        known_job: None,
        known_pod: None,
    };
    let (objects, runtime) = crate::backup_ledger::pipeline_tests::runtime_objects(
        &synthetic,
        &volume,
        &p.f.base.node,
        &pod_placeholder,
    )?;
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects"))?;
        map.remove(&format!(
            "/api/v1/namespaces/sandbox-system/pods/{pod_name}"
        ));
        map.remove(&format!(
            "/apis/batch/v1/namespaces/sandbox-system/jobs/{}",
            crate::nodeguard::protocol::backup_job_name(
                restore,
                crate::nodeguard::protocol::BackupStage::Restore
            )
        ));
        map.remove(&format!(
            "/api/v1/namespaces/sandbox-system/configmaps/{}",
            crate::backup_manifest::config_name(restore)
        ));
    }
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?
        .extend(storage_objects.clone());
    if mappings {
        let initial = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?
            .clone();
        Box::pin(storage_http::pending_and_drift(
            &raw.context,
            &raw.cloud,
            &raw.source,
            initial,
        ))
        .await?;
    }
    let raw = Box::pin(async {
        let initial = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?
            .clone();
        Box::pin(record_pending_raw_parent(
            &p.f.backup,
            &claim,
            raw,
            initial,
            volume.pvc_uid,
        ))
        .await
    })
    .await?;
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?;
        let mut pvc = raw.context.block_pvc()?;
        pvc["metadata"]["uid"] = json!(volume.pvc_uid);
        pvc["spec"]["volumeName"] = json!(volume.pv_name);
        pvc["status"] = json!({"phase":"Bound"});
        map.insert(
            format!(
                "/api/v1/namespaces/sandbox-system/persistentvolumeclaims/{}",
                crate::backup_manifest::block_pvc_name(restore)
            ),
            pvc,
        );
        let pv = map
            .get_mut(&format!("/api/v1/persistentvolumes/{}", volume.pv_name))
            .context("raw volume")?;
        pv["spec"]["storageClassName"] = json!(raw.context.storage_contract.mapping.raw.name);
        pv["spec"]["capacity"] =
            json!({"storage":format!("{}Gi",raw.context.size_bytes/1024_u64.pow(3))});
        pv["spec"]["claimRef"]["kind"] = json!("PersistentVolumeClaim");
    }
    let observed = Box::pin(runtime.reconcile_restore_block(
        &raw.context,
        &raw.cloud,
        raw.known_pvc,
        raw.known_pv,
        &raw.source,
    ))
    .await?;
    p.f.backup
        .database
        .record_restore_block(&p.f.backup, &claim, &observed)
        .await
        .map_err(test_support_db::api_failure)?;
    let prepared =
        p.f.backup
            .database
            .prepare_restore_job(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    assert_eq!(prepared.record.status, "RESTORE_PENDING");
    let admission_db =
        crate::db::Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 4).await?;
    let (admission_service, (config_uid, job_uid)) = Box::pin(admission::prepare(
        admission_db,
        &runtime,
        &prepared,
        &p.f.base,
        &objects,
    ))
    .await?;
    let control_http = if controls {
        // The actual created Job remains suspended before normal DB binding.
        Some(control::Fixture::new(admission_service.clone(), objects.clone()).await?)
    } else {
        None
    };
    if let Some(http) = &control_http {
        Box::pin(http.job_status(false)).await?;
    }
    let restore_admission_db = admission_service.database.clone();
    if mappings {
        Box::pin(storage_mapping::admission_role(
            &restore_admission_db,
            actor,
            &job.storage_contract,
        ))
        .await?;
    }
    let node_http = nodes::Fixture::new(
        admission_service.clone(),
        objects.clone(),
        &p.f.backup,
        &claim,
    )
    .await?;
    admission::node_authority(
        &restore_admission_db,
        actor.tenant_id,
        restore,
        &p.f.base.node,
        false,
        false,
    )
    .await?;
    p.f.backup
        .database
        .record_restore_job_objects(&p.f.backup, &claim, config_uid, job_uid)
        .await
        .map_err(test_support_db::api_failure)?;
    Box::pin(admission::verify_recorded_objects(
        &p.f.backup,
        &claim,
        &p.f.base,
        actor.tenant_id,
        restore,
        config_uid,
        job_uid,
    ))
    .await?;
    if let Some(http) = &control_http {
        Box::pin(http.job_status(true)).await?;
    }
    admission::consume(admission_service, &prepared, job_uid, &pod_name, &objects).await?;
    // The existing once-only Pod review just succeeded. Only now does this
    // storage stand-in construct/store its child with the actual recorded owner.
    let pod_uid = Uuid::new_v4();
    let mut pod = crate::backup_admission::expected_pod(&prepared.context, job_uid, &pod_name)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    pod["metadata"]["uid"] = json!(pod_uid);
    pod["metadata"]["resourceVersion"] = json!("1");
    pod["spec"]["nodeName"] = json!(p.f.base.node.node_name);
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture objects"))?
        .insert(
            format!("/api/v1/namespaces/sandbox-system/pods/{pod_name}"),
            pod.clone(),
        );
    if let Some(http) = &control_http {
        Box::pin(http.no_permit(&pod)).await?;
    }
    admission::node_authority(
        &restore_admission_db,
        actor.tenant_id,
        restore,
        &p.f.base.node,
        true,
        false,
    )
    .await?;
    p.f.backup
        .database
        .record_restore_pod(
            &p.f.backup,
            &claim,
            job_uid,
            &crate::backup_job::ObservedBackupPod {
                uid: pod_uid,
                name: pod_name.clone(),
                node_name: Some(p.f.base.node.node_name.clone()),
                exit: None,
            },
        )
        .await
        .map_err(test_support_db::api_failure)?;
    let active =
        p.f.backup
            .database
            .prepare_restore_job(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    Box::pin(node_http.binding(&active, &p.f.base, &pod_name)).await?;
    let launch = runtime
        .observe_restore_launch(&active, &pod_name, &volume)
        .await?;
    let permit =
        p.f.backup
            .database
            .prepare_restore_launch(&p.f.backup, &claim, &launch)
            .await
            .map_err(test_support_db::api_failure)?;
    let replay =
        p.f.backup
            .database
            .prepare_restore_launch(&p.f.backup, &claim, &launch)
            .await
            .map_err(test_support_db::api_failure)?;
    assert_eq!(permit.request.permit_id, replay.request.permit_id);
    Box::pin(node_http.status(&p.f.base, &pod_name)).await?;
    node_http.heartbeat().await?;
    admission::postwait_node_revocation(&restore_admission_db, &active, &p.f.base).await?;
    admission::node_authority(
        &restore_admission_db,
        actor.tenant_id,
        restore,
        &p.f.base.node,
        true,
        true,
    )
    .await?;
    p.f.base
        .guard
        .registration_revision
        .store(3, std::sync::atomic::Ordering::SeqCst);
    let registered = p.f.base.guard.client.register(&permit.request).await?;
    p.f.backup
        .database
        .record_restore_registration(&p.f.backup, &claim, &registered)
        .await
        .map_err(test_support_db::api_failure)?;
    // An ordinary API identity cannot manufacture independently verified source
    // evidence, or release the hold before delivery/closed-task evidence.
    let mut api = db
        .begin(actor.tenant_id)
        .await
        .map_err(test_support_db::api_failure)?;
    assert!(sqlx::query("INSERT INTO restore_io_reports(restore_id,tenant_id,exit_code,finished_at) VALUES($1,$2,0,clock_timestamp())").bind(restore).bind(actor.tenant_id).execute(&mut *api).await.is_err());
    api.rollback().await?;
    let mut tx = p.f.base.f.owner_transaction().await?;
    let hold: Uuid =
        sqlx::query_scalar("SELECT hold_id FROM restores WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id)
            .bind(restore)
            .fetch_one(&mut *tx)
            .await?;
    assert!(sqlx::query("INSERT INTO workspace_hold_releases(hold_id,tenant_id,reason) VALUES($1,$2,'premature')").bind(hold).bind(actor.tenant_id).execute(&mut *tx).await.is_err());
    tx.rollback().await?;
    let stale_revoke = db
        .revoke_project_grant(
            &p.f.base.f.actor,
            p.f.base.launch.project_id,
            restore_grant.id,
            "revoke-delegated-restore-grant-stale",
            restore_grant.version,
        )
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("expiry fixtures must invalidate the cached grant ETag"))?;
    assert_eq!(
        stale_revoke.status,
        axum::http::StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(stale_revoke.code, "VERSION_MISMATCH");
    let current_grant = db
        .get_project_grant(
            &p.f.base.f.actor,
            p.f.base.launch.project_id,
            restore_grant.id,
        )
        .await
        .map_err(test_support_db::api_failure)?;
    assert!(current_grant.version > restore_grant.version);
    let revoked_grant = db
        .revoke_project_grant(
            &p.f.base.f.actor,
            p.f.base.launch.project_id,
            current_grant.id,
            "revoke-delegated-restore-grant-current",
            current_grant.version,
        )
        .await
        .map_err(test_support_db::api_failure)?
        .body
        .resource;
    eprintln!(
        "VERIFIED management API revocation blocks new restore work; trusted closure remains allowed"
    );
    assert!(
        db.create_restore(actor, backup, &request, "same-restore", version)
            .await
            .is_err()
    );
    assert!(
        p.f.backup
            .database
            .prepare_restore_job(&p.f.backup, &claim)
            .await
            .is_err()
    );
    // Already admitted work closes after grant revocation. No new permit or
    // workspace publication follows from container completion alone.
    let exit = crate::backup_job::BackupJobExit {
        exit_code: if controls { 1 } else { 0 },
        finished_at: Utc::now(),
        report: if controls {
            None
        } else {
            Some(
                json!({"protocol":1,"backup_id":backup,"bytes":volume.size_bytes,"sha256":proof.disk_sha256(),"restored_at":Utc::now(),"filesystem_mounted":false,"application_recovery_tested":false,"cloud_restore_certified":false}),
            )
        },
    };
    p.f.backup
        .database
        .close_restore_task(&p.f.backup, &claim, Some(&exit))
        .await
        .map_err(test_support_db::api_failure)?;
    Box::pin(node_http.revoked_status(&active, &p.f.base, &pod_name)).await?;
    if let Some(http) = &control_http {
        Box::pin(http.job_status(true)).await?;
        Box::pin(http.protected_delete(&pod)).await?;
        Box::pin(http.final_ack(&pod, &p.f.base)).await?;
    }
    node_http.heartbeat().await?;
    admission::node_authority(
        &restore_admission_db,
        actor.tenant_id,
        restore,
        &p.f.base.node,
        false,
        true,
    )
    .await?;
    eprintln!(
        "VERIFIED dedicated RESTORE node readers: no admission/permit adoption, exact UID/name/boot/profile/tenant/source denials; revocation denies new binding while fixed historical permit remains observable for trusted mTLS closure"
    );
    assert!(
        p.f.backup
            .database
            .prepare_restore_launch(&p.f.backup, &claim, &launch)
            .await
            .is_err()
    );
    let closing =
        p.f.backup
            .database
            .prepare_restore_cleanup_job(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    assert_eq!(
        closing.storage_contract, job.storage_contract,
        "historical closure reads the frozen raw purpose"
    );
    if mappings {
        let mut tx = p.f.base.f.owner_transaction().await?;
        sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
            .bind(profile)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let historical =
            p.f.backup
                .database
                .prepare_restore_cleanup_job(&p.f.backup, &claim)
                .await
                .map_err(test_support_db::api_failure)?;
        assert_eq!(historical.storage_contract, closing.storage_contract);
        assert_eq!(
            serde_json::to_value(historical.context)?,
            serde_json::to_value(&closing.context)?
        );
        let mut tx = p.f.base.f.owner_transaction().await?;
        sqlx::query("UPDATE backup_profiles SET enabled=true WHERE id=$1")
            .bind(profile)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    let challenge =
        p.f.backup
            .database
            .prepare_restore_close(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    let cleanup_runtime = control_http
        .as_ref()
        .map_or(&runtime, |http| http.runtime());
    cleanup_runtime
        .request_restore_close(&closing, &challenge.permit.request.launch)
        .await?;
    let mut response = crate::termination_client::test_support::response(&challenge.request);
    response
        .evidence
        .as_mut()
        .context("wire evidence")?
        .journal_revision = 4;
    *p.f.base
        .guard
        .override_response
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture guard poisoned"))? = Some(response);
    let crate::termination_client::TerminationObservation::Verified(termination) =
        p.f.base.guard.client.close(&challenge.request).await?
    else {
        anyhow::bail!("authenticated close required")
    };
    let proof_id =
        p.f.backup
            .database
            .record_restore_termination(&p.f.backup, &claim, &termination)
            .await
            .map_err(test_support_db::api_failure)?;
    Box::pin(node_http.proven_status(&p.f.base, &pod_name)).await?;
    node_http.heartbeat().await?;
    if let Some(http) = &control_http {
        let path = format!("/api/v1/namespaces/sandbox-system/pods/{pod_name}");
        Box::pin(http.finalizer_after_proof(&path)).await?;
        ensure!(
            Box::pin(
                http.runtime()
                    .finish_restore_cleanup(&closing, &termination)
            )
            .await?
            .is_none(),
            "Job tracking must retain the Pod after real own-finalizer PATCH"
        );
        Box::pin(http.job_tracking(&path)).await?;
    }
    let cleanup = Box::pin(cleanup_runtime.finish_restore_cleanup(&closing, &termination))
        .await?
        .context("actual Kube cleanup")?;
    p.f.backup
        .database
        .record_restore_cleanup(&p.f.backup, &claim, proof_id, &cleanup)
        .await
        .map_err(test_support_db::api_failure)?;
    if let Some(http) = &control_http {
        Box::pin(http.artifacts_before_delivery(&closing)).await?;
    }
    let mut tx = p.f.base.f.owner_transaction().await?;
    let pending:i64=sqlx::query_scalar("SELECT sum(amount)::bigint FROM quota_reservations WHERE tenant_id=$1 AND operation_id=$2 AND status='PENDING'")
        .bind(actor.tenant_id).bind(first.body.operation.id).fetch_one(&mut *tx).await?;
    assert!(
        pending > 0,
        "revocation cannot erase retained target accounting"
    );
    let releases: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workspace_hold_releases WHERE tenant_id=$1 AND hold_id=$2",
    )
    .bind(actor.tenant_id)
    .bind(hold)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(releases, 0);
    tx.commit().await?;
    assert_eq!(
        db.get_restore(actor, restore)
            .await
            .map_err(test_support_db::api_failure)?
            .status,
        "RESTORE_CLOSING"
    );
    if let Some(http) = &control_http {
        let artifacts =
            p.f.backup
                .database
                .prepare_restore_artifacts(&p.f.backup, &claim)
                .await
                .map_err(test_support_db::api_failure)?;
        let absence = Box::pin(http.finish_artifacts(&artifacts)).await?;
        ensure!(
            p.f.backup
                .database
                .publish_restore(&p.f.backup, &claim, &absence)
                .await
                .is_err(),
            "failed restore cannot publish through historical control cleanup"
        );
        http.assert_mutations(pod_uid, job_uid, config_uid)?;
        let mut tx = p.f.base.f.owner_transaction().await?;
        let retained:bool = sqlx::query_scalar("SELECT r.status='RESTORE_CLOSING' AND io.exit_code=1 AND w.status<>'AVAILABLE' AND NOT EXISTS(SELECT 1 FROM restore_delivery_receipts d WHERE d.tenant_id=r.tenant_id AND d.restore_id=r.id) AND NOT EXISTS(SELECT 1 FROM workspace_hold_releases release WHERE release.tenant_id=r.tenant_id AND release.hold_id=r.hold_id) AND EXISTS(SELECT 1 FROM quota_reservations q WHERE q.tenant_id=r.tenant_id AND q.operation_id=r.operation_id AND q.status='PENDING') FROM restores r JOIN restore_io_reports io ON io.tenant_id=r.tenant_id AND io.restore_id=r.id JOIN workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id WHERE r.tenant_id=$1 AND r.id=$2")
            .bind(actor.tenant_id).bind(restore).fetch_one(&mut *tx).await?;
        ensure!(
            retained,
            "failed cleanup must retain workspace exclusion, quota and source hold without success delivery"
        );
        let source: Value =
            sqlx::query_scalar("SELECT source FROM backups WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id)
                .bind(backup)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            source == p.plan.backup.source,
            "original historical source binding must remain unchanged"
        );
        tx.commit().await?;
        eprintln!(
            "VERIFIED actual failed restore after revocation: Job-only status without permit, protected Pod DELETE, trusted mTLS proof then own PATCH/tracking PATCH, exact Foreground Job/config DELETE→retained retry→reviewed GC PATCH→404; no success delivery, publication or accounting release"
        );
        return Ok(());
    }
    // Re-authorizing the original principal permits the next independent stage;
    // the already-closed writer still cannot receive another permit.
    assert!(
        p.f.backup
            .database
            .prepare_restore_snapshot(&p.f.backup, &claim)
            .await
            .is_err()
    );
    db.update_project_grant(
        &p.f.base.f.actor,
        p.f.base.launch.project_id,
        revoked_grant.id,
        &crate::grants::UpdateGrant {
            enabled: true,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        },
        "renew-source-after-trusted-close",
        revoked_grant.version,
    )
    .await
    .map_err(test_support_db::api_failure)?;
    let snapshot_plan =
        p.f.backup
            .database
            .prepare_restore_snapshot(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    let raw_path = format!(
        "/apis/snapshot.storage.k8s.io/v1/namespaces/sandbox-system/volumesnapshots/{}",
        snapshot_plan.context.raw_snapshot_name()
    );
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?;
        map.insert("/apis/storage.k8s.io/v1/volumeattachments".into(),json!({"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachmentList","metadata":{},"items":[{"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachment","metadata":{"name":"unexpected-rebind"},"spec":{"attacher":"diskplugin.csi.alibabacloud.com","nodeName":"fixture","source":{"persistentVolumeName":volume.pv_name}}}]}));
    }
    assert!(
        Box::pin(runtime.reconcile_restore_snapshot(&snapshot_plan))
            .await?
            .is_none()
    );
    assert!(
        !objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?
            .contains_key(&raw_path)
    );
    objects.lock().map_err(|_|anyhow::anyhow!("fixture objects poisoned"))?.insert("/apis/storage.k8s.io/v1/volumeattachments".into(),json!({"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachmentList","metadata":{},"items":[]}));
    let first_snapshot = Box::pin(runtime.reconcile_restore_snapshot(&snapshot_plan))
        .await?
        .context("raw CSI create observation")?;
    assert!(first_snapshot.ready.is_none());
    p.f.backup
        .database
        .record_restore_snapshot(&p.f.backup, &claim, &first_snapshot)
        .await
        .map_err(test_support_db::api_failure)?;
    let snapshot_plan =
        p.f.backup
            .database
            .prepare_restore_snapshot(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    assert_eq!(
        snapshot_plan.known_snapshot,
        Some(first_snapshot.snapshot_uid)
    );
    let content_name = "snapcontent-restored-fixture";
    let content_path =
        format!("/apis/snapshot.storage.k8s.io/v1/volumesnapshotcontents/{content_name}");
    let raw_content_uid = Uuid::new_v4();
    let now = Utc::now();
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?;
        let snapshot = map.get_mut(&raw_path).context("created raw snapshot")?;
        snapshot["status"] = json!({"boundVolumeSnapshotContentName":content_name,"readyToUse":true,"creationTime":now,"restoreSize":format!("{}Gi",volume.size_bytes/1024_u64.pow(3))});
        map.insert(content_path.clone(),json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotContent","metadata":{"name":content_name,"uid":raw_content_uid},"spec":{"driver":"diskplugin.csi.alibabacloud.com","deletionPolicy":"Retain","sourceVolumeMode":"Block","source":{"volumeHandle":volume.cloud_disk},"volumeSnapshotClassName":snapshot_plan.context.storage_contract.mapping.snapshot.name,"volumeSnapshotRef":{"uid":first_snapshot.snapshot_uid,"name":snapshot_plan.context.raw_snapshot_name(),"namespace":"sandbox-system"}},"status":{"readyToUse":true,"snapshotHandle":"s-restoredFixture01","creationTime":now.timestamp_nanos_opt().context("timestamp")?,"restoreSize":volume.size_bytes}}));
    }
    let restored_snapshot = Box::pin(runtime.reconcile_restore_snapshot(&snapshot_plan))
        .await?
        .context("raw CSI ready")?;
    assert!(restored_snapshot.ready.is_some());
    p.f.backup
        .database
        .record_restore_snapshot(&p.f.backup, &claim, &restored_snapshot)
        .await
        .map_err(test_support_db::api_failure)?;
    let delivery =
        p.f.backup
            .database
            .prepare_restore_delivery(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    let c = &delivery.snapshot.context;
    let target_pvc_path = format!(
        "/api/v1/namespaces/{}/persistentvolumeclaims/ws-{}",
        c.target_namespace, c.workspace_id
    );
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?;
        map.insert(format!("/api/v1/namespaces/{}",c.target_namespace),json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":c.target_namespace,"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":c.tenant_id,"sandbox.platform/project-id":c.target_project_id,"sandbox.platform/cluster-epoch":c.cluster_epoch},"annotations":{"sandbox.platform/certification-id":"fixture-target"}}}));
        map.insert(format!("/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies/sandbox-default-deny",c.target_namespace),json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-default-deny","namespace":c.target_namespace},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}));
    }
    if mappings {
        let snapshot_objects = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?
            .clone();
        Box::pin(storage_http::snapshot_and_delivery_drift(
            &delivery,
            snapshot_objects,
            "fixture-target",
        ))
        .await?;
    }
    let waiting = Box::pin(runtime.reconcile_restore_delivery(&delivery, "fixture-target")).await?;
    assert!(waiting.bound.is_none());
    p.f.backup
        .database
        .record_restore_delivery(&p.f.backup, &claim, &waiting)
        .await
        .map_err(test_support_db::api_failure)?;
    let mut tx = p.f.base.f.owner_transaction().await?;
    let premature: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM restore_delivery_receipts WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(actor.tenant_id)
    .bind(restore)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(
        premature, 0,
        "Pending Immediate PVC creation cannot claim filesystem delivery"
    );
    tx.commit().await?;
    let delivery =
        p.f.backup
            .database
            .prepare_restore_delivery(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    let c = &delivery.snapshot.context;
    let delivered_pv = Uuid::new_v4();
    let delivered_pv_name = "pv-restored-workspace";
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?;
        let name = c.delivery_snapshot_name();
        let content = map
            .get_mut(&format!(
                "/apis/snapshot.storage.k8s.io/v1/volumesnapshotcontents/{name}"
            ))
            .context("static content")?;
        content["spec"]["volumeSnapshotRef"]["uid"] = json!(waiting.snapshot_uid);
        content["status"] = json!({"readyToUse":true,"snapshotHandle":"s-restoredFixture01"});
        let snapshot = map
            .get_mut(&format!(
                "/apis/snapshot.storage.k8s.io/v1/namespaces/{}/volumesnapshots/{name}",
                c.target_namespace
            ))
            .context("static snapshot")?;
        snapshot["status"] = json!({"readyToUse":true,"boundVolumeSnapshotContentName":name});
        let pvc = map.get_mut(&target_pvc_path).context("target PVC")?;
        pvc["spec"]["volumeName"] = json!(delivered_pv_name);
        pvc["status"] = json!({"phase":"Bound"});
        map.insert(format!("/api/v1/persistentvolumes/{delivered_pv_name}"),json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":delivered_pv_name,"uid":delivered_pv},"spec":{"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],"persistentVolumeReclaimPolicy":"Retain","storageClassName":c.storage_contract.mapping.delivery.name,"capacity":{"storage":format!("{}Gi",volume.size_bytes/1024_u64.pow(3))},"csi":{"driver":"diskplugin.csi.alibabacloud.com","volumeHandle":"d-restoredWorkspace01"},"claimRef":{"kind":"PersistentVolumeClaim","uid":waiting.pvc_uid,"namespace":c.target_namespace,"name":format!("ws-{}",c.workspace_id)}},"status":{"phase":"Bound"}}));
    }
    // A ready static snapshot still cannot authorize converting the raw PVC.
    let target_pv_path = format!("/api/v1/persistentvolumes/{delivered_pv_name}");
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?;
        map.get_mut(&target_pv_path).context("target PV")?["spec"]["csi"]["volumeHandle"] =
            json!(volume.cloud_disk);
    }
    assert!(
        Box::pin(runtime.reconcile_restore_delivery(&delivery, "fixture-target"))
            .await
            .is_err()
    );
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?
        .get_mut(&target_pv_path)
        .context("target PV")?["spec"]["csi"]["volumeHandle"] = json!("d-restoredWorkspace01");
    let delivered =
        Box::pin(runtime.reconcile_restore_delivery(&delivery, "fixture-target")).await?;
    assert_eq!(
        delivered.bound.as_ref().context("delivery bound")?.pv_uid,
        delivered_pv
    );
    p.f.backup
        .database
        .record_restore_delivery(&p.f.backup, &claim, &delivered)
        .await
        .map_err(test_support_db::api_failure)?;
    assert_eq!(
        db.get_restore(actor, restore)
            .await
            .map_err(test_support_db::api_failure)?
            .status,
        "DELIVERY_PENDING"
    );
    // Delivery alone is not publication: temporary raw disk/snapshot/resources
    // still require actual cleanup and accounting settlement.
    let mut tx = p.f.base.f.owner_transaction().await?;
    let releases: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workspace_hold_releases WHERE tenant_id=$1 AND hold_id=$2",
    )
    .bind(actor.tenant_id)
    .bind(hold)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(releases, 0);
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM restore_delivery_receipts WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(actor.tenant_id)
    .bind(restore)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(receipts, 1);
    tx.commit().await?;
    let artifacts =
        p.f.backup
            .database
            .prepare_restore_artifacts(&p.f.backup, &claim)
            .await
            .map_err(test_support_db::api_failure)?;
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture objects poisoned"))?;
        // Preserve the actual created Job/config system identity and generated
        // fields through historical cleanup instead of reconstructing manifests.
        map.insert(
            "/api/v1/namespaces/sandbox-system/pods".into(),
            json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[]}),
        );
    }
    let mut tx =
        p.f.backup
            .database
            .begin(actor.tenant_id)
            .await
            .map_err(test_support_db::api_failure)?;
    let premature: bool = sqlx::query_scalar("SELECT sandbox_publish_restore($1,$2,$3)")
        .bind(actor.tenant_id)
        .bind(restore)
        .bind(claim.lease_token)
        .fetch_one(&mut *tx)
        .await?;
    assert!(
        !premature,
        "publication requires actual Job/config absence receipt"
    );
    tx.commit().await?;
    let absence = cleanup_runtime
        .finish_restore_artifacts(&artifacts)
        .await?
        .context("observed control cleanup")?;
    p.f.backup
        .database
        .publish_restore(&p.f.backup, &claim, &absence)
        .await
        .map_err(test_support_db::api_failure)?;
    let result = db
        .get_restore(actor, restore)
        .await
        .map_err(test_support_db::api_failure)?;
    assert_eq!(result.status, "AVAILABLE");
    let mut tx = p.f.base.f.owner_transaction().await?;
    #[derive(sqlx::FromRow)]
    struct Published {
        desired: String,
        observed: String,
        workspace: String,
        operation: String,
        snapshot: Option<String>,
        instance_operation: Option<Uuid>,
        workspace_operation: Option<Uuid>,
        disk: String,
    }
    let result:Published=sqlx::query_as("SELECT i.desired_state AS desired,i.observed_state AS observed,w.status AS workspace,o.status AS operation,w.restore_snapshot_name AS snapshot,i.active_operation_id AS instance_operation,w.active_operation_id AS workspace_operation,w.csi_volume_id AS disk FROM restores r JOIN instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id JOIN workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id JOIN operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id WHERE r.tenant_id=$1 AND r.id=$2").bind(actor.tenant_id).bind(restore).fetch_one(&mut *tx).await?;
    assert_eq!(
        (
            result.desired.as_str(),
            result.observed.as_str(),
            result.workspace.as_str(),
            result.operation.as_str()
        ),
        ("STOPPED", "STOPPED", "AVAILABLE", "SUCCEEDED")
    );
    assert_eq!(result.snapshot, Some(format!("sbx-rs-{restore}")));
    assert!(result.instance_operation.is_none() && result.workspace_operation.is_none());
    assert_eq!(result.disk, "d-restoredWorkspace01");
    let accounting:Vec<(String,String,i64)>=sqlx::query_as("SELECT q.dimension,r.status,r.amount FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.operation_id=$2 ORDER BY q.dimension,q.id").bind(actor.tenant_id).bind(claim.operation_id).fetch_all(&mut *tx).await?;
    assert_eq!(accounting.len(), 10);
    for (dimension, status, amount) in accounting {
        if matches!(dimension.as_str(), "CPU_MILLIS" | "MEMORY_MIB") {
            assert_eq!(status, "RELEASED");
        } else {
            assert_eq!(status, "ALLOCATED");
        }
        if dimension == "BACKUP_TEMP_GIB" {
            assert_eq!(
                amount, 40,
                "raw disk plus single cloud snapshot; no duplicate charge for original backup or static CSI references"
            );
        }
    }
    let releases: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workspace_hold_releases WHERE tenant_id=$1 AND hold_id=$2",
    )
    .bind(actor.tenant_id)
    .bind(hold)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(releases, 1);
    let source_refs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM restores WHERE tenant_id=$1 AND backup_id=$2")
            .bind(actor.tenant_id)
            .bind(backup)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(
        source_refs, 1,
        "immutable source lineage survives publication and requires explicit GC review"
    );
    tx.commit().await?;
    if mappings {
        Box::pin(storage_mapping::published(
            &p.f.base.f.owner,
            db,
            actor.tenant_id,
            restore,
            first.body.resource.workspace_id,
        ))
        .await?;
    }
    // Exercise the actual restore INSERT guard against identical PostgreSQL
    // columns in a temporary table. This is guard coverage, not a substitute
    // for the still-required real ordinary worker/admission START integration.
    let mut tx = p.f.base.f.owner_transaction().await?;
    sqlx::query("CREATE TEMP TABLE restore_launch_guard_test (LIKE public.launch_permits INCLUDING DEFAULTS)").execute(&mut *tx).await?;
    sqlx::query("CREATE TRIGGER exact_restore_volume BEFORE INSERT ON restore_launch_guard_test FOR EACH ROW EXECUTE FUNCTION public.sandbox_guard_restored_launch()").execute(&mut *tx).await?;
    let mut binding: Value =
        sqlx::query_scalar("SELECT to_jsonb(p) FROM launch_permits p WHERE tenant_id=$1 LIMIT 1")
            .bind(actor.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
    binding["id"] = json!(Uuid::new_v4());
    binding["project_id"] = json!(request.target_project_id);
    binding["instance_id"] = json!(first.body.resource.instance_id);
    binding["workspace_id"] = json!(first.body.resource.workspace_id);
    binding["cluster_epoch"] = json!(delivery.snapshot.context.cluster_epoch);
    binding["namespace"] = json!(delivery.snapshot.context.target_namespace);
    binding["pvc_uid"] = json!(delivered.pvc_uid);
    binding["pv_uid"] = json!(delivered_pv);
    binding["pv_name"] = json!(delivered_pv_name);
    binding["csi_volume_handle"] = json!("d-restoredWorkspace01");
    sqlx::query("INSERT INTO restore_launch_guard_test SELECT (jsonb_populate_record(NULL::restore_launch_guard_test,$1)).*").bind(&binding).execute(&mut *tx).await?;
    for (field, value) in [
        ("pvc_uid", json!(Uuid::new_v4())),
        ("pv_uid", json!(Uuid::new_v4())),
        ("csi_volume_handle", json!("d-replacedTarget01")),
    ] {
        sqlx::query("SAVEPOINT changed_identity")
            .execute(&mut *tx)
            .await?;
        let mut changed = binding.clone();
        changed["id"] = json!(Uuid::new_v4());
        changed[field] = value;
        assert!(sqlx::query("INSERT INTO restore_launch_guard_test SELECT (jsonb_populate_record(NULL::restore_launch_guard_test,$1)).*").bind(changed).execute(&mut *tx).await.is_err(),"replaced {field} cannot launch");
        sqlx::query("ROLLBACK TO SAVEPOINT changed_identity")
            .execute(&mut *tx)
            .await?;
        sqlx::query("RELEASE SAVEPOINT changed_identity")
            .execute(&mut *tx)
            .await?;
    }
    tx.rollback().await?;
    if !matches!(validation, GcValidation::None) {
        Box::pin(gc::run(gc::GcCase {
            base: &p.f.base,
            restore,
            objects: &objects,
            guards: matches!(validation, GcValidation::Guards),
            admission: matches!(validation, GcValidation::Admission),
        }))
        .await?;
        if matches!(validation, GcValidation::Admission) {
            return Ok(());
        }
    }
    if start {
        start::run(start::StartCase {
            base: &p.f.base,
            instance: first.body.resource.instance_id,
            workspace: first.body.resource.workspace_id,
            runtime: runtime.runtime(),
            objects: &objects,
        })
        .await?;
        eprintln!(
            "VERIFIED real ordinary START lifecycle/worker/admission/permit, PVC/PV/disk replacements refused, actual mTLS registration, RUNNING/SUCCEEDED"
        );
        file_role::run(
            &p.f.base,
            &p.f.backup.database,
            first.body.resource.instance_id,
            project,
        )
        .await?;
    } else {
        deletion::run(deletion::DeleteCase {
            base: &p.f.base,
            instance: first.body.resource.instance_id,
            workspace: first.body.resource.workspace_id,
            restore,
            objects: &objects,
        })
        .await?;
        eprintln!(
            "VERIFIED never ordinary START concurrent DELETE, fixed delivery provenance, actual signed cloud absence and UID cleanup, single storage release/source retained"
        );
    }
    // Tenant-private RLS hides the source and result from unrelated tenants.
    let foreign = crate::db::Actor {
        authorization: None,
        tenant_id: Uuid::new_v4(),
        ..actor.clone()
    };
    assert!(db.get_restore(&foreign, restore).await.is_err());
    assert!(
        db.create_restore(&foreign, backup, &request, "foreign", version)
            .await
            .is_err()
    );
    Ok(())
}
