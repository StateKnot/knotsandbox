//! A nonempty released-v45 SQLx database is upgraded normally by its ordinary
//! migration owner. The owner seeds historical rows; runtime never authors a
//! baseline and an old unacknowledged permit never receives an exemption.
use std::{borrow::Cow, env};

use anyhow::{Context, ensure};
use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};
use url::Url;
use uuid::Uuid;

use crate::{db::Database, test_support_db::require_pg_error};

#[tokio::test]
#[ignore = "Requires owned local verify-full PostgreSQL, sandbox_owner and fixture administrator"]
async fn v45_committed_base_and_extension_acks_freeze_across_tenants_but_open_permits_do_not()
-> anyhow::Result<()> {
    let _serial = crate::test_support_db::serial().await;
    let raw = env::var("TEST_MIGRATION_DATABASE_URL")?;
    let mut owner_url = Url::parse(&raw)?;
    ensure!(
        matches!(owner_url.scheme(), "postgres" | "postgresql")
            && owner_url.host_str() == Some("127.0.0.1")
            && owner_url.port().is_some()
            && owner_url.username() == "sandbox_owner"
            && owner_url.path().ends_with("_test")
            && owner_url
                .query_pairs()
                .any(|(k, v)| k == "sslmode" && v == "verify-full")
            && owner_url
                .query_pairs()
                .any(|(k, v)| k == "sslrootcert" && std::path::Path::new(v.as_ref()).is_absolute()),
        "Upgrade test requires the explicitly owned loopback verify-full fixture"
    );
    let mut admin_url = owner_url.clone();
    let admin_user =
        env::var("TEST_POSTGRES_ADMIN_USER").unwrap_or_else(|_| "sandbox_dev_admin".into());
    ensure!(
        matches!(
            admin_user.as_str(),
            "sandbox_dev_admin" | "sandbox_review_fixture_admin"
        ),
        "Only fixed local fixture administrators are allowed"
    );
    admin_url
        .set_username(&admin_user)
        .map_err(|_| anyhow::anyhow!("admin fixture user"))?;
    admin_url
        .set_password(Some(&env::var("SANDBOX_POSTGRES_ADMIN_PASSWORD")?))
        .map_err(|_| anyhow::anyhow!("admin fixture password"))?;
    admin_url.set_path("/postgres");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url.as_str())
        .await
        .map_err(|_| anyhow::anyhow!("Cannot connect to exact local TLS fixture administrator"))?;
    let identity: (String,String,bool) = sqlx::query_as("SELECT session_user::text,current_user::text,(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())")
        .fetch_one(&admin).await?;
    ensure!(identity == (admin_user.clone(), admin_user, true));
    let name = format!("sandbox_observe_upgrade_{}_test", Uuid::new_v4().simple());
    ensure!(
        name.len() <= 63,
        "owned PostgreSQL identifier must not be truncated"
    );
    sqlx::query(&format!("CREATE DATABASE \"{name}\" OWNER sandbox_owner"))
        .execute(&admin)
        .await?;
    owner_url.set_path(&format!("/{name}"));
    let result = async {
        sqlx::query(&format!("REVOKE ALL ON DATABASE \"{name}\" FROM PUBLIC"))
            .execute(&admin)
            .await?;
        sqlx::query(&format!(
            "GRANT CONNECT ON DATABASE \"{name}\" TO sandbox_app,sandbox_termination"
        ))
        .execute(&admin)
        .await?;
        let owner = PgPoolOptions::new()
            .max_connections(2)
            .connect(owner_url.as_str())
            .await
            .map_err(|_| anyhow::anyhow!("Cannot connect to owned historical TLS fixture"))?;
        let outcome = exercise(&owner, &owner_url).await;
        owner.close().await;
        outcome
    }
    .await;
    let cleaned = sqlx::query(&format!("DROP DATABASE \"{name}\""))
        .execute(&admin)
        .await;
    admin.close().await;
    match (result, cleaned) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(error)) => Err(error).context("Owned upgrade database cleanup failed"),
        (Err(error), Err(cleanup)) => Err(error).context(format!(
            "Owned upgrade database cleanup also failed: {cleanup}"
        )),
    }
}

async fn exercise(owner: &PgPool, owner_url: &Url) -> anyhow::Result<()> {
    let identity:(String,String,bool,bool)=sqlx::query_as("SELECT session_user::text,current_user::text,r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole,s.ssl FROM pg_roles r JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=session_user")
        .fetch_one(owner).await?;
    ensure!(identity == ("sandbox_owner".into(), "sandbox_owner".into(), false, true));
    let all = sqlx::migrate!("./migrations");
    let released = Migrator {
        migrations: Cow::Owned(
            all.iter()
                .filter(|migration| migration.version <= 45)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    released.run(owner).await?;
    sqlx::raw_sql(HISTORICAL).execute(owner).await?;
    let old_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version=46")
            .fetch_one(owner)
            .await?;
    ensure!(old_count == 0);
    all.run(owner).await?;
    sqlx::raw_sql(include_str!("../scripts/sql/roles.sql"))
        .execute(owner)
        .await?;
    sqlx::raw_sql(include_str!("../scripts/sql/termination-role.sql"))
        .execute(owner)
        .await?;
    // The owner reads across tenants only while the test's transaction holds
    // the baseline lock. FORCE RLS remains installed after that rollback.
    let mut inspect = owner.begin().await?;
    sqlx::query("ALTER TABLE launch_registration_legacy_baseline NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *inspect)
        .await?;
    let rows:ValueRows=sqlx::query_as("SELECT count(*),count(DISTINCT tenant_id),count(*) FILTER(WHERE registration_kind='BASE'),count(*) FILTER(WHERE registration_kind='EXTENSION') FROM launch_registration_legacy_baseline")
        .fetch_one(&mut *inspect).await?;
    ensure!(
        rows == (4, 2, 2, 2),
        "all committed base/extension ACKs across both tenants must be frozen"
    );
    let tenants: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT tenant_id FROM launch_registration_legacy_baseline ORDER BY tenant_id",
    )
    .fetch_all(&mut *inspect)
    .await?;
    // launch_permits is FORCE-RLS, so inspect each explicit tenant below instead
    // of weakening its permanent policy for cross-tenant queries.
    inspect.rollback().await?;
    ensure!(tenants.len() == 2);
    let mut runtime_url = Url::parse(&env::var("TEST_TERMINATION_DATABASE_URL")?)?;
    let original = Url::parse(&env::var("TEST_MIGRATION_DATABASE_URL")?)?;
    ensure!(
        runtime_url.username() == "sandbox_termination"
            && runtime_url.host_str() == original.host_str()
            && runtime_url.port() == original.port()
            && runtime_url.path() == original.path(),
        "runtime fixture must target the same owned TLS PostgreSQL"
    );
    runtime_url.set_path(owner_url.path());
    let runtime = Database::connect(runtime_url.as_str(), 2).await?;
    let outcome=async {
        runtime.verify_runtime_role().await?;
        for tenant in tenants {
            let mut tx=owner.begin().await?;
            sqlx::query("SELECT set_config('app.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await?;
            let exact:bool=sqlx::query_scalar("SELECT count(*)=2 AND bool_and((b.project_id,b.instance_id,b.workspace_id,b.generation,b.launch_id,b.cluster_epoch,b.pod_uid,b.runtime_node_id,b.node_uid,b.node_boot_id)=(p.project_id,p.instance_id,p.workspace_id,p.generation,p.launch_id,p.cluster_epoch,p.pod_uid,p.runtime_node_id,n.node_uid,n.boot_id)) FROM launch_registration_legacy_baseline b JOIN launch_permits p ON(p.tenant_id,p.id)=(b.tenant_id,b.base_permit_id) JOIN runtime_nodes n ON n.id=b.runtime_node_id")
                .fetch_one(&mut *tx).await?;
            ensure!(exact);
            let open:(Uuid,Uuid)=sqlx::query_as("SELECT p.id,e.id FROM launch_permits p JOIN launch_permit_extensions e ON(e.tenant_id,e.base_permit_id)=(p.tenant_id,p.id) WHERE NOT EXISTS(SELECT 1 FROM launch_permit_receipts r WHERE r.tenant_id=p.tenant_id AND r.permit_id=p.id)")
                .fetch_one(&mut *tx).await?;
            let observation_count:i64=sqlx::query_scalar("SELECT count(*) FROM launch_pod_resource_observations").fetch_one(&mut *tx).await?;
            ensure!(observation_count==0,"migration must not invent resource observations for old ACKs");
            tx.commit().await?;
            for (kind,id) in [("BASE",open.0),("EXTENSION",open.1)] {
                let mut tx=runtime.begin(tenant).await.map_err(crate::test_support_db::api_failure)?;
                if kind=="BASE" {
                    sqlx::query("INSERT INTO launch_permit_receipts(tenant_id,permit_id,journal_revision) VALUES($1,$2,9)")
                        .bind(tenant).bind(id).execute(&mut *tx).await?;
                } else {
                    sqlx::query("INSERT INTO launch_permit_extension_receipts(tenant_id,extension_id,journal_revision,effective_expires_at) SELECT $1,$2,9,expires_at FROM launch_permit_extensions WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).execute(&mut *tx).await?;
                }
                require_pg_error(tx.commit().await,"23514")?;
            }
            let mut tx=owner.begin().await?;
            sqlx::query("SELECT set_config('app.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await?;
            require_pg_error(sqlx::query("INSERT INTO launch_registration_legacy_baseline SELECT * FROM launch_registration_legacy_baseline LIMIT 1").execute(&mut *tx).await,"23514")?;
            tx.rollback().await?;
        }
        Ok::<(),anyhow::Error>(())
    }.await;
    runtime.pool.close().await;
    outcome
}
type ValueRows = (i64, i64, i64, i64);

const HISTORICAL: &str = r#"
DO $fixture$
DECLARE tenant uuid;project uuid;principal uuid;template uuid;policy uuid;workspace uuid;instance uuid;
    operation uuid;node uuid;permit uuid;extension uuid;epoch uuid:=gen_random_uuid();t integer;i integer;
BEGIN
    INSERT INTO public.platform_configuration(singleton,cluster_epoch,safe_mode) VALUES(true,epoch,false);
    FOR t IN 1..2 LOOP
        tenant:=gen_random_uuid();project:=gen_random_uuid();principal:=gen_random_uuid();
        template:=gen_random_uuid();policy:=gen_random_uuid();node:=gen_random_uuid();
        PERFORM set_config('app.tenant_id',tenant::text,true);
        INSERT INTO public.tenants(id,name) VALUES(tenant,'Historical observation tenant');
        INSERT INTO public.principals(id,kind,display_name) VALUES(principal,'SERVICE','Historical trusted fixture');
        INSERT INTO public.projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class)
            VALUES(project,tenant,'Historical project',86400,'hist-'||replace(project::text,'-',''),'integration-storage');
        INSERT INTO public.template_versions(id,tenant_id,name,version,image_ref,image_digest,runner_version,status)
            VALUES(template,tenant,'Historical template',1,'registry.example.test/sandbox','sha256:'||repeat('a',64),'fixture','APPROVED');
        INSERT INTO public.security_policy_versions(id,tenant_id,name,version,status,rules)
            VALUES(policy,tenant,'Historical policy',1,'APPROVED','{}');
        INSERT INTO public.runtime_nodes(id,cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,
            cloud_instance_id,private_ip,profile_sha256,boot_id,enabled)
            VALUES(node,epoch,gen_random_uuid(),'hist-node-'||t,'alicloud','fixture-account','fixture-region',
                'i-'||node,'10.2.3.4',repeat('a',64),gen_random_uuid(),true);
        FOR i IN 1..2 LOOP
            workspace:=gen_random_uuid();instance:=gen_random_uuid();operation:=gen_random_uuid();
            permit:=gen_random_uuid();extension:=gen_random_uuid();
            INSERT INTO public.workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name,status)
                VALUES(workspace,tenant,project,20,'integration-storage','hist-'||replace(project::text,'-',''),'ws-'||workspace,'AVAILABLE');
            -- STOPPED is an intentionally historical launch, not a fabricated
            -- post-v45 RUNNING transition with missing quota reservations.
            INSERT INTO public.instances(id,tenant_id,project_id,name,template_version_id,security_policy_version_id,
                workspace_id,cpu_millis,memory_mib,desired_state,observed_state,cluster_epoch,launch_id,pod_uid,
                namespace,pod_name,compute_lease_id,compute_lease_started_at,compute_lease_expires_at)
                VALUES(instance,tenant,project,'Historical instance',template,policy,workspace,1000,2048,'STOPPED','STOPPED',epoch,
                    gen_random_uuid(),gen_random_uuid(),'hist-'||replace(project::text,'-',''),'sbx-ws-'||workspace,
                    gen_random_uuid(),clock_timestamp(),clock_timestamp()+interval '1 hour');
            INSERT INTO public.operations(id,tenant_id,project_id,instance_id,workspace_id,kind,status,request,
                actor_principal_id,request_id,deadline,completed_at)
                VALUES(operation,tenant,project,instance,workspace,'CREATE','SUCCEEDED','{}',principal,gen_random_uuid(),
                    clock_timestamp()+interval '1 hour',clock_timestamp());
            INSERT INTO public.launch_permits(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_node_id,
                cluster_epoch,generation,launch_id,pod_uid,namespace,pod_name,pvc_uid,pv_uid,pv_name,csi_volume_handle,expires_at)
                SELECT permit,tenant,project,instance,workspace,operation,node,epoch,1,launch_id,pod_uid,namespace,pod_name,
                    gen_random_uuid(),gen_random_uuid(),'fixture-pv','fixture-volume',clock_timestamp()+interval '1 hour'
                    FROM public.instances WHERE id=instance;
            INSERT INTO public.launch_permit_extensions(id,tenant_id,base_permit_id,compute_lease_id,compute_lease_version,expires_at)
                SELECT extension,tenant,permit,compute_lease_id,2,clock_timestamp()+interval '2 hours'
                    FROM public.instances WHERE id=instance;
            IF i=1 THEN
                INSERT INTO public.launch_permit_receipts(tenant_id,permit_id,journal_revision) VALUES(tenant,permit,4);
                INSERT INTO public.launch_permit_extension_receipts(tenant_id,extension_id,journal_revision,effective_expires_at)
                    VALUES(tenant,extension,5,clock_timestamp()+interval '2 hours');
            END IF;
        END LOOP;
    END LOOP;
END
$fixture$;
"#;
