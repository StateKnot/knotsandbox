use std::env;

use anyhow::{Context, bail, ensure};
use sandbox_platform::{
    db::{Actor, Database, MutationResult},
    error::ApiError,
    model::{CreateInstance, Flavor, WorkspaceSpec},
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use tokio::sync::{Mutex, MutexGuard, OnceCell};
use url::Url;
use uuid::Uuid;

static INITIALIZED: OnceCell<()> = OnceCell::const_new();
// Cases mutate the installation-wide safe-mode fixture. Serialize cases, while
// concurrency tests deliberately run many real transactions within one case.
static TEST_SCOPE: Mutex<()> = Mutex::const_new(());

pub async fn serial() -> MutexGuard<'static, ()> {
    TEST_SCOPE.lock().await
}

pub struct Fixture {
    pub database: Database,
    pub owner: PgPool,
    pub actor: Actor,
    pub request: CreateInstance,
}

// Test-only opaque connections established and fully verified while the
// installation has only normally applied migrations. Private draft fixtures
// may retain these pools across an explicit DDL boundary; they never catch a
// failed production startup or construct this proof from an unverified pool.
#[derive(Clone)]
pub struct VerifiedFixtureConnections {
    database: Database,
    owner: PgPool,
}
#[derive(Clone)]
#[allow(
    dead_code,
    reason = "opaque lib-test draft component; standalone integration crates share this support source"
)]
pub struct VerifiedRuntimeDatabase {
    database: Database,
    role: String,
}
#[allow(
    dead_code,
    reason = "draft methods are exercised in lib tests; standalone integration crates use normal new"
)]
impl VerifiedFixtureConnections {
    pub fn database(&self) -> Database {
        self.database.clone()
    }
    pub fn owner(&self) -> PgPool {
        self.owner.clone()
    }
    pub async fn runtime(
        &self,
        environment_key: &str,
        expected_role: &str,
        max_connections: u32,
    ) -> anyhow::Result<VerifiedRuntimeDatabase> {
        let runtime_url = required_url(environment_key)?;
        let actual = Url::parse(&runtime_url)?;
        let expected = Url::parse(&required_url("TEST_DATABASE_URL")?)?;
        ensure!(
            actual.username() == expected_role
                && actual.host_str() == expected.host_str()
                && actual.port_or_known_default() == expected.port_or_known_default()
                && actual.path() == expected.path(),
            "verified fixture components must share one database and their exact login"
        );
        let database = Database::connect(&runtime_url, max_connections).await?;
        database.verify_runtime_role().await?;
        let role: String = sqlx::query_scalar("SELECT session_user::text")
            .fetch_one(&database.pool)
            .await?;
        ensure!(
            role == expected_role,
            "fixture connection must use its exact authenticated role"
        );
        Ok(VerifiedRuntimeDatabase { database, role })
    }
    pub async fn clear_statement_caches(&self) -> anyhow::Result<()> {
        clear_statement_caches(&self.database.pool).await?;
        clear_statement_caches(&self.owner).await
    }
}
#[allow(
    dead_code,
    reason = "opaque component methods are exercised by the private lib-test fixture"
)]
impl VerifiedRuntimeDatabase {
    pub fn database(&self) -> Database {
        self.database.clone()
    }
    pub fn database_for(&self, expected_role: &str) -> anyhow::Result<Database> {
        ensure!(
            self.role == expected_role,
            "verified fixture component identity mismatch"
        );
        Ok(self.database.clone())
    }
    pub async fn clear_statement_caches(&self) -> anyhow::Result<()> {
        clear_statement_caches(&self.database.pool).await
    }
}
#[allow(
    dead_code,
    reason = "explicit draft DDL boundary is exercised only in the lib-test fixture"
)]
async fn clear_statement_caches(pool: &PgPool) -> anyhow::Result<()> {
    use sqlx::Connection;
    let mut connections = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        let mut connection = pool.acquire().await?;
        connection.clear_cached_statements().await?;
        connections.push(connection);
    }
    Ok(())
}

impl Fixture {
    /// Explicit IdP metadata binding for HTTP tests. Never infer a client from
    /// a subject, and never grant a runtime actor ownership privileges.
    #[allow(
        dead_code,
        reason = "shared support is compiled by integration targets that do not authenticate HTTP"
    )]
    pub async fn bind_client_id(&self, client_id: &str) -> anyhow::Result<()> {
        let current: Option<String> = sqlx::query_scalar("SELECT service_client_id FROM principal_identities WHERE issuer='https://issuer.example.test' AND subject=$1")
            .bind(self.actor.principal_id.to_string()).fetch_one(&self.owner).await?;
        sqlx::query("SELECT sandbox_bind_service_identity('https://issuer.example.test',$1,$2,$3,'Reviewed test-only client metadata')")
            .bind(self.actor.principal_id.to_string()).bind(current).bind(client_id).execute(&self.owner).await?;
        Ok(())
    }
    pub async fn new(instance_limit: i64) -> anyhow::Result<Self> {
        let verified = Self::prepare_verified_connections().await?;
        Self::new_with_verified_connections(instance_limit, &verified).await
    }
    pub async fn prepare_verified_connections() -> anyhow::Result<VerifiedFixtureConnections> {
        let runtime_url = required_url("TEST_DATABASE_URL")?;
        let owner_url = required_url("TEST_MIGRATION_DATABASE_URL")?;
        let runtime_target = Url::parse(&runtime_url).context("Invalid TEST_DATABASE_URL")?;
        let owner_target = Url::parse(&owner_url).context("Invalid TEST_MIGRATION_DATABASE_URL")?;
        ensure!(
            runtime_target.host_str() == owner_target.host_str()
                && runtime_target.port_or_known_default() == owner_target.port_or_known_default()
                && runtime_target.path() == owner_target.path(),
            "The runtime and migration URLs must target the same disposable database"
        );
        ensure!(
            runtime_target.username() != owner_target.username(),
            "Integration tests require distinct runtime and migration identities"
        );
        let owner = PgPoolOptions::new()
            .max_connections(2)
            .connect(&owner_url)
            .await
            .context("Cannot connect to the integration migration database")?;
        INITIALIZED
            .get_or_try_init(|| async {
                let version: String = sqlx::query_scalar("SHOW server_version_num")
                    .fetch_one(&owner)
                    .await?;
                ensure!(
                    version.parse::<u32>()? >= 170000,
                    "PostgreSQL 17+ is required"
                );
                sqlx::migrate!().run(&owner).await?;
                sqlx::raw_sql(include_str!("../../scripts/sql/roles.sql"))
                    .execute(&owner)
                    .await?;
                sqlx::raw_sql(include_str!("../../scripts/sql/automation-role.sql"))
                    .execute(&owner)
                    .await?;
                sqlx::query(
                    "INSERT INTO platform_configuration(singleton,cluster_epoch,safe_mode) \
                     VALUES(true,$1,false) ON CONFLICT(singleton) DO UPDATE SET safe_mode=false",
                )
                .bind(Uuid::new_v4())
                .execute(&owner)
                .await?;
                Ok::<(), anyhow::Error>(())
            })
            .await?;
        let database = Database::connect(&runtime_url, 16).await?;
        database.verify_runtime_role().await?;
        Ok(VerifiedFixtureConnections { database, owner })
    }
    pub async fn new_with_verified_connections(
        instance_limit: i64,
        verified: &VerifiedFixtureConnections,
    ) -> anyhow::Result<Self> {
        let database = verified.database.clone();
        let owner = verified.owner.clone();
        let tenant_id = Uuid::new_v4();
        let principal_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let template_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let mut tx = owner.begin().await?;
        set_tenant(&mut tx, tenant_id).await?;
        sqlx::query("INSERT INTO tenants(id,name) VALUES($1,'Integration tenant')")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','Integration service')")
            .bind(principal_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject) VALUES($1,'https://issuer.example.test',$2)")
            .bind(principal_id)
            .bind(principal_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,'Integration project',86400,$3,'integration-storage')")
            .bind(project_id)
            .bind(tenant_id)
            .bind(format!("it-{}", project_id.simple()))
            .execute(&mut *tx)
            .await?;
        for action in [
            "instances:create",
            "instances:read",
            "operations:read",
            "instances:renew",
            "instances:start",
            "instances:stop",
            "instances:restart",
            "instances:delete",
            "instances:hard_stop",
        ] {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
            )
            .bind(tenant_id)
            .bind(project_id)
            .bind(principal_id)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("INSERT INTO template_versions(id,tenant_id,name,version,image_ref,image_digest,runner_version,status) VALUES($1,$2,'integration-template',1,'registry.example.test/sandbox',$3,'integration','APPROVED')")
            .bind(template_id)
            .bind(tenant_id)
            .bind(format!("sha256:{}", "a".repeat(64)))
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'integration-policy',1,'APPROVED','{}'::jsonb)")
            .bind(policy_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        for project in [None, Some(project_id)] {
            for (dimension, limit) in [
                ("INSTANCES", instance_limit),
                ("CPU_MILLIS", 1_000_000),
                ("MEMORY_MIB", 2_048_000),
                ("WORKSPACE_GIB", 20_000),
            ] {
                sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,$4)")
                    .bind(tenant_id)
                    .bind(project)
                    .bind(dimension)
                    .bind(limit)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(Self {
            database,
            owner,
            actor: Actor {
                authorization: None,
                tenant_id,
                principal_id,
                request_id: Uuid::new_v4(),
            },
            request: CreateInstance {
                project_id,
                name: "integration-instance".to_owned(),
                template_version_id: template_id,
                security_profile_id: policy_id,
                flavor: Flavor::Cpu1Mem2,
                workspace: WorkspaceSpec { size_gib: 20 },
                ttl_seconds: Some(300),
                client_reference: Some("database-integration".to_owned()),
            },
        })
    }

    pub async fn owner_transaction(&self) -> anyhow::Result<Transaction<'_, Postgres>> {
        let mut tx = self.owner.begin().await?;
        set_tenant(&mut tx, self.actor.tenant_id).await?;
        Ok(tx)
    }

    pub async fn create(&self, key: &str) -> Result<MutationResult, ApiError> {
        self.database
            .create_instance(&self.actor, &self.request, key, 300, 86400)
            .await
    }

    pub async fn count(&self, table: &str) -> anyhow::Result<i64> {
        // Identifiers are a closed test-only list; they never contain caller input.
        ensure!(
            [
                "instances",
                "workspaces",
                "operations",
                "idempotency_keys",
                "audit_events",
                "domain_events",
                "quota_reservations"
            ]
            .contains(&table),
            "Unknown integration-test table"
        );
        let mut tx = self.owner_transaction().await?;
        let count = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE tenant_id=$1"))
            .bind(self.actor.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn assert_empty_mutation(&self) -> anyhow::Result<()> {
        for table in [
            "instances",
            "workspaces",
            "operations",
            "idempotency_keys",
            "audit_events",
            "domain_events",
            "quota_reservations",
        ] {
            ensure!(
                self.count(table).await? == 0,
                "Failed transaction left rows in {table}"
            );
        }
        let mut tx = self.owner_transaction().await?;
        let dirty: i64 = sqlx::query_scalar("SELECT count(*) FROM quota_accounts WHERE tenant_id=$1 AND (pending<>0 OR allocated<>0)")
            .bind(self.actor.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
        ensure!(dirty == 0, "Failed transaction leaked quota reservations");
        tx.commit().await?;
        Ok(())
    }

    /// Seed an operator-observed prerequisite for API acceptance tests. This is
    /// not a runtime/Kubernetes test and does not claim that a VM was stopped.
    pub async fn seed_observed_state(&self, id: Uuid, state: &str) -> anyhow::Result<()> {
        ensure!(
            matches!(state, "RUNNING" | "STOPPED"),
            "Unsupported test state"
        );
        let mut tx = self.owner_transaction().await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',stage='COMPLETED',completed_at=clock_timestamp() WHERE id=(SELECT active_operation_id FROM instances WHERE tenant_id=$1 AND id=$2)")
            .bind(self.actor.tenant_id).bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE instances SET active_operation_id=NULL,desired_state=$3,observed_state=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(self.actor.tenant_id).bind(id).bind(state).execute(&mut *tx).await?;
        sqlx::query("UPDATE workspaces SET status=$3,active_operation_id=NULL WHERE id=(SELECT workspace_id FROM instances WHERE tenant_id=$1 AND id=$2)")
            .bind(self.actor.tenant_id).bind(id).bind(if state == "STOPPED" { "AVAILABLE" } else { "IN_USE" }).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Explicit owner-only fake enrollment/permit for API and admission tests.
    /// This does not certify a physical node, KVM, CSI, or nodeguard deployment.
    #[allow(dead_code)]
    pub async fn seed_test_launch_certification(
        &self,
        instance: Uuid,
        expiry: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Uuid> {
        let mut tx = self.owner_transaction().await?;
        let node = Uuid::new_v4();
        sqlx::query(
            "UPDATE instances SET pod_uid=COALESCE(pod_uid,$3) WHERE tenant_id=$1 AND id=$2",
        )
        .bind(self.actor.tenant_id)
        .bind(instance)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,profile_sha256,boot_id,enabled) SELECT $1,cluster_epoch,$2,'test-only-certified-node','alicloud','test-account','test-region',$3,'10.2.3.4',$4,$5,true FROM instances WHERE tenant_id=$6 AND id=$7")
            .bind(node).bind(Uuid::new_v4()).bind(format!("test-{node}")).bind("ab".repeat(32)).bind(Uuid::new_v4()).bind(self.actor.tenant_id).bind(instance).execute(&mut *tx).await?;
        seed_test_node_certification(&mut tx, node, expiry).await?;
        sqlx::query("INSERT INTO launch_permits(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_node_id,cluster_epoch,generation,launch_id,pod_uid,namespace,pod_name,pvc_uid,pv_uid,pv_name,csi_volume_handle,expires_at) SELECT $1,i.tenant_id,i.project_id,i.id,i.workspace_id,(SELECT o.id FROM operations o WHERE o.tenant_id=i.tenant_id AND o.instance_id=i.id AND o.kind='CREATE' ORDER BY o.created_at LIMIT 1),$2,i.cluster_epoch,i.runtime_generation,i.launch_id,i.pod_uid,i.namespace,i.pod_name,$3,$4,'test-only-pv','test-only-disk',i.compute_lease_expires_at FROM instances i WHERE i.tenant_id=$5 AND i.id=$6")
            .bind(Uuid::new_v4()).bind(node).bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(self.actor.tenant_id).bind(instance).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(node)
    }

    /// Owner-seeded API prerequisite, with explicit synthetic launch, STOP,
    /// termination and cleanup records. This exercises the normal accounting
    /// guards; these test-only records do not certify a host or a physical VM.
    pub async fn release_fixture_compute(&self, instance: Uuid) -> anyhow::Result<()> {
        let node = self
            .seed_test_launch_certification(
                instance,
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .await?;
        let mut tx = self.owner_transaction().await?;
        sqlx::query("SELECT w.id FROM workspaces w JOIN instances i ON(i.tenant_id,i.workspace_id)=(w.tenant_id,w.id) WHERE i.tenant_id=$1 AND i.id=$2 FOR UPDATE OF w")
            .bind(self.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
        let stopped: bool = sqlx::query_scalar("SELECT observed_state='STOPPED' AND desired_state='STOPPED' AND active_operation_id IS NULL FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(self.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
        ensure!(
            stopped,
            "synthetic release requires the explicit STOPPED API prerequisite"
        );
        let operation = Uuid::new_v4();
        let challenge = Uuid::new_v4();
        let proof = Uuid::new_v4();
        let evidence = serde_json::json!({"test_only":true,"physical_runtime_certified":false,"purpose":"API_STOPPED_PREREQUISITE"});
        let evidence_sha256 = hex::encode(Sha256::digest(evidence.to_string().as_bytes()));
        sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,status,stage,request,actor_principal_id,request_id,deadline,completed_at) SELECT $1,tenant_id,project_id,id,workspace_id,'STOP','SUCCEEDED','TEST_ONLY_SYNTHETIC_CLEANUP',$2,$3,$4,clock_timestamp()+interval '30 minutes',clock_timestamp() FROM instances WHERE tenant_id=$5 AND id=$6")
            .bind(operation).bind(&evidence).bind(self.actor.principal_id).bind(Uuid::new_v4()).bind(self.actor.tenant_id).bind(instance).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO termination_challenges(id,tenant_id,project_id,permit_id,operation_id,lease_token,reason,created_at,expires_at) SELECT $1,p.tenant_id,p.project_id,p.id,$2,1,'STOP',clock_timestamp(),clock_timestamp()+interval '29 seconds' FROM launch_permits p JOIN instances i ON(i.tenant_id,i.id,i.runtime_generation,i.launch_id,i.pod_uid,i.cluster_epoch)=(p.tenant_id,p.instance_id,p.generation,p.launch_id,p.pod_uid,p.cluster_epoch) WHERE i.tenant_id=$3 AND i.id=$4 AND p.runtime_node_id=$5")
            .bind(challenge).bind(operation).bind(self.actor.tenant_id).bind(instance).bind(node).execute(&mut *tx).await?;
        let pod_uid: Uuid = sqlx::query_scalar("INSERT INTO local_termination_proofs(id,tenant_id,project_id,challenge_id,permit_id,instance_id,workspace_id,generation,launch_id,pod_uid,cluster_epoch,runtime_node_id,journal_revision,evidence,evidence_sha256,observed_at) SELECT $1,p.tenant_id,p.project_id,$2,p.id,p.instance_id,p.workspace_id,p.generation,p.launch_id,p.pod_uid,p.cluster_epoch,p.runtime_node_id,1,$3,$4,clock_timestamp() FROM launch_permits p JOIN termination_challenges c ON(c.tenant_id,c.permit_id)=(p.tenant_id,p.id) WHERE c.tenant_id=$5 AND c.id=$2 RETURNING pod_uid")
            .bind(proof).bind(challenge).bind(&evidence).bind(evidence_sha256).bind(self.actor.tenant_id).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO termination_cleanup_receipts(proof_id,tenant_id,old_pod_uid,pod_resource_version,pod_absent_at,volume_checked_at,completion) VALUES($1,$2,$3,'test-only-no-apiserver-observation',clock_timestamp(),clock_timestamp(),'STOPPED')")
            .bind(proof).bind(self.actor.tenant_id).bind(pod_uid).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE instances SET last_termination_proof_id=$3 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(self.actor.tenant_id)
        .bind(instance)
        .bind(proof)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT id FROM quota_accounts WHERE tenant_id=$1 AND(project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE")
            .bind(self.actor.tenant_id).bind(self.request.project_id).fetch_all(&mut *tx).await?;
        let reservations: Vec<(Uuid, Uuid, i64)> = sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND r.status='PENDING' AND q.dimension IN ('CPU_MILLIS','MEMORY_MIB') ORDER BY r.quota_account_id,r.id FOR UPDATE OF r")
            .bind(self.actor.tenant_id).bind(instance).fetch_all(&mut *tx).await?;
        ensure!(
            reservations.len() == 4,
            "Expected the create's tenant/project compute reservations"
        );
        for (reservation, account, amount) in reservations {
            sqlx::query("UPDATE quota_accounts SET pending=pending-$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1")
                .bind(account)
                .bind(amount)
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp() WHERE id=$1")
                .bind(reservation).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Owner-seeded test report, intentionally labelled synthetic. An expired
/// fixture represents a historical review, without mutating append-only data.
#[allow(dead_code)]
pub async fn seed_test_node_certification(
    tx: &mut Transaction<'_, Postgres>,
    node: Uuid,
    expiry: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    let report = Uuid::new_v4().simple().to_string().repeat(2);
    sqlx::query("INSERT INTO runtime_node_enrollments(id,runtime_node_id,cluster_epoch,artifact_sha256,terraform_output_sha256,settings_sha256,certification_report_sha256,certification_expires_at,certification_reviewed_at,observed_node_resource_version,observed_at,database_role,receipt,registered_at) SELECT $1,id,cluster_epoch,$2,$2,$2,$3,$4,LEAST(clock_timestamp(),$4-interval '1 day'),'test-only-rv',LEAST(clock_timestamp(),$4-interval '1 day'),current_user,'{\"test_only\":true,\"physical_runtime_certified\":false}'::jsonb,LEAST(clock_timestamp(),$4-interval '1 day') FROM runtime_nodes WHERE id=$5")
        .bind(Uuid::new_v4()).bind("ab".repeat(32)).bind(report).bind(expiry).bind(node).execute(&mut **tx).await?;
    Ok(())
}

async fn set_tenant(tx: &mut Transaction<'_, Postgres>, tenant: Uuid) -> anyhow::Result<()> {
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn required_url(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).with_context(|| {
        format!("{name} is required; start development dependencies and load .local/dev.env")
    })?;
    let parsed = Url::parse(&value).with_context(|| format!("Invalid {name}"))?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql") && parsed.path().ends_with("_test"),
        "{name} must identify an explicitly disposable database whose name ends with _test"
    );
    Ok(value)
}

pub fn api_failure(error: ApiError) -> anyhow::Error {
    anyhow::anyhow!("{} ({}): {}", error.code, error.status, error.detail)
}

pub fn require_api_error(result: Result<MutationResult, ApiError>) -> anyhow::Result<ApiError> {
    match result {
        Ok(_) => bail!("Mutation unexpectedly succeeded"),
        Err(error) => Ok(error),
    }
}

pub fn require_pg_error<T>(result: Result<T, sqlx::Error>, code: &str) -> anyhow::Result<()> {
    match result {
        Ok(_) => bail!("SQL operation unexpectedly succeeded; expected {code}"),
        Err(error) => {
            ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code),
                "Expected PostgreSQL {code}, got {error}"
            );
            Ok(())
        }
    }
}
pub mod runtime_class_guard;
