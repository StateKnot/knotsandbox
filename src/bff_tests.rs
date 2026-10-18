#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    auth::{AuthConfig, JwtAuthenticator},
    bff_crypto::SessionKeys,
    bff_oidc::{BrowserOidc, OidcSettings},
    db::Database,
    history::CursorSigner,
};
use anyhow::Context;
use axum::response::{Sse, sse::Event};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sqlx::{Connection, PgPool, postgres::PgPoolOptions};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{net::TcpListener, sync::Mutex};

const ISSUER: &str = "https://identity.bff.invalid/realms/sandbox";
const ORIGIN: &str = "https://console.bff.invalid";
const SECRET: &str = "FIXTURE_BROWSER_SECRET_0123456789ABCDEF";
fn api_failure(error: ApiError) -> anyhow::Error {
    anyhow::anyhow!(
        "browser database call failed: {} {}",
        error.status,
        error.code
    )
}
#[derive(Clone)]
struct Provider {
    nonce: Arc<Mutex<String>>,
    mode: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}
struct Fixture {
    owner: PgPool,
    admin: PgPool,
    database_name: String,
    runtime: Arc<BrowserRuntime>,
    tenant: Uuid,
    principal: Uuid,
    project: Uuid,
    base: String,
    client: reqwest::Client,
    provider: Provider,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    keys: tempfile::TempDir,
}

#[derive(Clone, sqlx::FromRow)]
struct FixturePeer {
    role: String,
    pool: String,
    state: String,
    wait: String,
    xact_open: bool,
}

// Keep only fixed classifications and monotonic timings. A completed old
// observation remains a sample; it never establishes the state at timeout.
#[derive(Clone, Copy)]
enum FixtureDrainStage {
    PeersQuery,
    OwnerQuery,
    ObservationComplete,
    Sleeping,
    AfterSleep,
}

struct FixtureDrainProgress {
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
    stage: FixtureDrainStage,
    stage_started: tokio::time::Instant,
    stage_remaining_ms: u128,
    completed_rounds: u64,
    // Sample time, total peers, exact idle owners, exact idle runtimes.
    peers: Option<(tokio::time::Instant, usize, usize, usize)>,
    owner: Option<(tokio::time::Instant, bool)>,
    last_sleep: Option<(u128, u128, u128)>,
}

impl FixtureDrainProgress {
    fn new(deadline: tokio::time::Instant) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            started: now,
            deadline,
            stage: FixtureDrainStage::PeersQuery,
            stage_started: now,
            stage_remaining_ms: deadline.saturating_duration_since(now).as_millis(),
            completed_rounds: 0,
            peers: None,
            owner: None,
            last_sleep: None,
        }
    }

    fn enter(&mut self, stage: FixtureDrainStage) {
        let now = tokio::time::Instant::now();
        self.stage = stage;
        self.stage_started = now;
        self.stage_remaining_ms = self.deadline.saturating_duration_since(now).as_millis();
    }

    fn after_sleep(&mut self) {
        let now = tokio::time::Instant::now();
        self.last_sleep = Some((
            now.duration_since(self.stage_started).as_millis(),
            self.stage_remaining_ms,
            self.deadline.saturating_duration_since(now).as_millis(),
        ));
        self.enter(FixtureDrainStage::AfterSleep);
    }

    fn describe(&self) -> String {
        let now = tokio::time::Instant::now();
        let stage = match self.stage {
            FixtureDrainStage::PeersQuery => "PEERS_QUERY",
            FixtureDrainStage::OwnerQuery => "OWNER_QUERY",
            FixtureDrainStage::ObservationComplete => "OBSERVATION_COMPLETE",
            FixtureDrainStage::Sleeping => "SLEEPING",
            FixtureDrainStage::AfterSleep => "AFTER_SLEEP",
        };
        let peers = match self.peers {
            Some((at, total, owner, runtime)) => format!(
                "peers={total} owner_idle={owner} runtime_idle={runtime} unexpected={} peers_age_ms={}",
                total - owner - runtime,
                now.duration_since(at).as_millis(),
            ),
            None => "peers=UNKNOWN owner_idle=UNKNOWN runtime_idle=UNKNOWN unexpected=UNKNOWN peers_age_ms=UNKNOWN".into(),
        };
        let owner = match self.owner {
            Some((at, matches)) => format!(
                "owner_matches={matches} owner_age_ms={}",
                now.duration_since(at).as_millis(),
            ),
            None => "owner_matches=UNKNOWN owner_age_ms=UNKNOWN".into(),
        };
        let sleep = match self.last_sleep {
            Some((elapsed, before, after)) => format!(
                "last_sleep_ms={elapsed} last_sleep_before_remaining_ms={before} last_sleep_after_remaining_ms={after}",
            ),
            None => "last_sleep_ms=UNKNOWN last_sleep_before_remaining_ms=UNKNOWN last_sleep_after_remaining_ms=UNKNOWN".into(),
        };
        format!(
            "BFF_FIXTURE_DRAIN stage={stage} completed_rounds={} elapsed_ms={} stage_elapsed_ms={} stage_remaining_ms={} {peers} {owner} {sleep}",
            self.completed_rounds,
            now.duration_since(self.started).as_millis(),
            now.duration_since(self.stage_started).as_millis(),
            self.stage_remaining_ms,
        )
    }
}

// A tag identifies a tail we may wait for; it never authorizes DROP or termination.
fn idle_owned_tail(
    peer: &FixturePeer,
    owner: &str,
    owner_pool: &str,
    runtime: &str,
    runtime_pool: &str,
) -> bool {
    ((peer.role == owner && peer.pool == owner_pool)
        || (peer.role == runtime && peer.pool == runtime_pool))
        && peer.state == "idle"
        && !peer.xact_open
        && matches!(peer.wait.as_str(), "" | "ClientRead")
}

fn fixture_pool_url(url: &mut url::Url, name: &str) {
    let retained: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key != "application_name")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair("application_name", name);
}

async fn fixture_peers(admin: &PgPool, database: &str) -> anyhow::Result<Vec<FixturePeer>> {
    // Each call is an independent autocommit snapshot, never a cached long TX.
    Ok(sqlx::query_as("SELECT usename AS role,COALESCE(application_name,'') AS pool,COALESCE(state,'') AS state,COALESCE(wait_event,'') AS wait,xact_start IS NOT NULL AS xact_open FROM pg_stat_activity WHERE datname=$1")
        .bind(database).fetch_all(admin).await?)
}

#[test]
fn fixture_backend_drain_rejects_active_transaction_and_foreign_tails() {
    let owner = FixturePeer {
        role: "owner".into(),
        pool: "owned_owner".into(),
        state: "idle".into(),
        wait: String::new(),
        xact_open: false,
    };
    let runtime = FixturePeer {
        role: "runtime".into(),
        pool: "owned_runtime".into(),
        wait: "ClientRead".into(),
        ..owner.clone()
    };
    let allowed =
        |p: &FixturePeer| idle_owned_tail(p, "owner", "owned_owner", "runtime", "owned_runtime");
    assert!(allowed(&owner) && allowed(&runtime));
    for forbidden in [
        FixturePeer {
            state: "active".into(),
            ..owner.clone()
        },
        FixturePeer {
            state: "idle in transaction".into(),
            ..owner.clone()
        },
        FixturePeer {
            xact_open: true,
            ..owner.clone()
        },
        FixturePeer {
            role: "foreign".into(),
            ..owner.clone()
        },
        FixturePeer {
            pool: "another_fixture_owner".into(),
            ..owner.clone()
        },
        FixturePeer {
            state: String::new(),
            ..owner.clone()
        },
        FixturePeer {
            wait: "ClientWrite".into(),
            ..runtime
        },
    ] {
        assert!(!allowed(&forbidden));
    }
}

#[test]
fn fixture_pool_tag_preserves_tls_query_and_replaces_duplicate_names() -> anyhow::Result<()> {
    let mut url = url::Url::parse(
        "postgresql://owner:placeholder@127.0.0.1:5432/test_test?sslmode=verify-full&application_name=old&sslrootcert=%2Ftmp%2Fca.crt&application_name=older",
    )?;
    fixture_pool_url(&mut url, "owned_owner");
    let pairs: Vec<_> = url.query_pairs().collect();
    assert_eq!(
        pairs
            .iter()
            .filter(|(k, _)| k == "application_name")
            .count(),
        1
    );
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == "application_name" && v == "owned_owner")
    );
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == "sslmode" && v == "verify-full")
    );
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == "sslrootcert" && v == "/tmp/ca.crt")
    );
    assert_eq!(url.username(), "owner");
    assert_eq!(url.password(), Some("placeholder"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL with ordinary owner/runtime roles"]
async fn browser_fixture_tagged_pools_drain_before_ordinary_database_drop() -> anyhow::Result<()> {
    let f = Fixture::start().await?;
    let admin_options = f.admin.connect_options();
    let name = f.database_name.clone();
    for pool in [&f.owner, &f.runtime.app.database.pool] {
        let expected_role = pool.connect_options().get_username().to_owned();
        let expected_pool = pool
            .connect_options()
            .get_application_name()
            .ok_or_else(|| anyhow::anyhow!("fixture pool tag required"))?
            .to_owned();
        let (session, current, tag): (String, String, String) = sqlx::query_as(
            "SELECT session_user::text,current_user::text,current_setting('application_name')",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            session == expected_role
                && current == expected_role
                && tag == expected_pool
                && tag.is_ascii()
                && tag.len() < 64,
            "actual fixture pool identity mismatch"
        );
    }
    f.close().await?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*admin_options).clone())
        .await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(name)
            .fetch_one(&admin)
            .await?;
    anyhow::ensure!(
        !exists,
        "fixture requires actual ordinary DROP, no deferral"
    );
    admin.close().await;
    println!("BFF_FIXTURE_TAGGED_BACKENDS_DRAINED_ORDINARY_DROP_VERIFIED");
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL with ordinary owner/runtime roles"]
async fn browser_fixture_drain_distinguishes_unobserved_query_and_observed_idle_tail()
-> anyhow::Result<()> {
    // Occupy exactly the fixture's two admin permits. The independent direct
    // observer stays usable and has no connection to the child database.
    let f = Fixture::start().await?;
    let name = f.database_name.clone();
    let admin_options = f.admin.connect_options();
    let mut observer = sqlx::PgConnection::connect_with(&admin_options).await?;
    let first = f.admin.acquire().await?;
    let second = f.admin.acquire().await?;
    let result = f.close().await;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&name)
            .fetch_one(&mut observer)
            .await?;
    let peers: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=$1")
        .bind(&name)
        .fetch_one(&mut observer)
        .await?;
    first.close().await?;
    second.close().await?;
    anyhow::ensure!(
        exists && peers == 0,
        "unobserved drain must retain the empty child database"
    );
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&mut observer)
        .await?;
    let exists_after: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&name)
            .fetch_one(&mut observer)
            .await?;
    observer.close().await?;
    anyhow::ensure!(
        !exists_after,
        "ordinary observer-case DROP must remove the child database"
    );
    println!("BFF_FIXTURE_DRAIN_UNOBSERVED_EMPTY_CHILD_ORDINARY_DROP_VERIFIED");
    let detail = format!(
        "{:#}",
        result
            .err()
            .ok_or_else(|| anyhow::anyhow!("occupied observer must fail closed"))?
    );
    assert!(detail.starts_with("fixture backend drain deadline exceeded"));
    assert!(
        detail.contains("stage=PEERS_QUERY"),
        "missing stage: {detail}"
    );
    assert!(
        detail.contains("completed_rounds=0"),
        "unexpected completed observation: {detail}"
    );
    assert!(
        detail.contains("peers=UNKNOWN"),
        "unobserved peers cannot become zero: {detail}"
    );
    assert!(
        detail.contains("owner_matches=UNKNOWN"),
        "unobserved owner cannot become known: {detail}"
    );

    // This precise tagged owner is deliberately outside the fixture pool.
    // Closing the pool cannot retire it, and must never authorize a DROP.
    let f = Fixture::start().await?;
    let name = f.database_name.clone();
    let owner_options = f.owner.connect_options();
    let owner_role = owner_options.get_username().to_owned();
    let owner_tag = owner_options
        .get_application_name()
        .ok_or_else(|| anyhow::anyhow!("fixture owner tag required"))?
        .to_owned();
    let mut held = sqlx::PgConnection::connect_with(&owner_options).await?;
    let mut observer = sqlx::PgConnection::connect_with(&f.admin.connect_options()).await?;
    let result = f.close().await;
    let still_usable: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&mut held).await?;
    let (exists, peers, exact_idle): (bool, i64, i64) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1),count(*),count(*) FILTER (WHERE usename=$2 AND application_name=$3 AND state='idle' AND xact_start IS NULL AND (wait_event IS NULL OR wait_event='ClientRead')) FROM pg_stat_activity WHERE datname=$1",
    )
    .bind(&name)
    .bind(owner_role)
    .bind(owner_tag)
    .fetch_one(&mut observer)
    .await?;
    held.close().await?;
    // This separate cleanup phase begins only after the tested close has
    // already failed under its original deadline and the live client is released.
    // Sending Terminate does not synchronously acknowledge server retirement.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let after_release: i64 =
                sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=$1")
                    .bind(&name)
                    .fetch_one(&mut observer)
                    .await?;
            if after_release == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("held-owner cleanup observation deadline exceeded")??;
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&mut observer)
        .await?;
    let exists_after: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&name)
            .fetch_one(&mut observer)
            .await?;
    observer.close().await?;
    anyhow::ensure!(
        still_usable == 1 && exists && peers == 1 && exact_idle == 1,
        "bounded drain must retain the exact live idle owner without terminating it"
    );
    anyhow::ensure!(
        !exists_after,
        "ordinary tail-case DROP must remove the child database"
    );
    let error = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("live owner tail must fail closed"))?;
    let detail = format!("{error:#}");
    assert!(
        detail.starts_with("fixture backend drain deadline exceeded")
            || detail
                .starts_with("fixture closed pools still have server backends after bounded drain")
    );
    // Read this context itself, not the colon-separated display of the
    // complete anyhow chain, whose separator is not part of a timing value.
    let diagnostic = error
        .chain()
        .find_map(|cause| {
            let value = cause.to_string();
            value.starts_with("BFF_FIXTURE_DRAIN ").then_some(value)
        })
        .ok_or_else(|| anyhow::anyhow!("bounded drain context required"))?;
    let field = |name: &str| {
        let prefix = format!("{name}=");
        diagnostic
            .split_whitespace()
            .find_map(|part| part.strip_prefix(&prefix))
    };
    assert!(matches!(
        field("stage"),
        Some("PEERS_QUERY" | "OWNER_QUERY" | "OBSERVATION_COMPLETE")
    ));
    assert!(
        field("completed_rounds")
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > 0)
    );
    assert_eq!(field("peers"), Some("1"));
    assert_eq!(field("owner_idle"), Some("1"));
    assert_eq!(field("runtime_idle"), Some("0"));
    assert_eq!(field("unexpected"), Some("0"));
    assert_eq!(field("owner_matches"), Some("true"));
    for name in [
        "peers_age_ms",
        "owner_age_ms",
        "elapsed_ms",
        "stage_elapsed_ms",
        "stage_remaining_ms",
        "last_sleep_ms",
        "last_sleep_before_remaining_ms",
        "last_sleep_after_remaining_ms",
    ] {
        assert!(
            field(name).and_then(|v| v.parse::<u128>().ok()).is_some(),
            "missing bounded timing {name}: {detail}"
        );
    }
    println!("BFF_FIXTURE_DRAIN_OBSERVER_AND_IDLE_TAIL_DIAGNOSTICS_VERIFIED");
    Ok(())
}

fn jwt(value: Value, id: bool) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("key-a".into());
    header.typ = Some(if id { "JWT" } else { "at+jwt" }.into());
    jsonwebtoken::encode(
        &header,
        &value,
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
    )
    .unwrap()
}
impl Fixture {
    async fn start() -> anyhow::Result<Self> {
        let owner_url = url::Url::parse(&std::env::var("TEST_MIGRATION_DATABASE_URL")?)?;
        let runtime_url = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        anyhow::ensure!(
            owner_url.path().ends_with("_test")
                && runtime_url.path().ends_with("_test")
                && owner_url.host_str() == Some("127.0.0.1")
                && owner_url.host_str() == runtime_url.host_str()
                && owner_url.port() == runtime_url.port(),
            "local disposable PostgreSQL required"
        );
        let database_name = format!("sandbox_bff_{}_test", Uuid::new_v4().simple());
        let mut admin_url = owner_url.clone();
        admin_url.set_path("/postgres");
        if let Ok(url) = std::env::var("TEST_POSTGRES_ADMIN_DATABASE_URL") {
            admin_url = url::Url::parse(&url)?;
            anyhow::ensure!(
                admin_url.host_str() == owner_url.host_str()
                    && admin_url.port() == owner_url.port()
                    && admin_url.path() == "/postgres",
                "fixture administrator must be on the same literal-loopback server"
            );
        } else if let Ok(password) = std::env::var("SANDBOX_POSTGRES_ADMIN_PASSWORD") {
            admin_url
                .set_username("sandbox_dev_admin")
                .map_err(|_| anyhow::anyhow!("invalid local administrator identity"))?;
            admin_url
                .set_password(Some(&password))
                .map_err(|_| anyhow::anyhow!("invalid local administrator credential"))?;
        }
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(admin_url.as_str())
            .await?;
        anyhow::ensure!(
            owner_url
                .username()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "fixed local migration identity required"
        );
        sqlx::query(&format!(
            "CREATE DATABASE {database_name} OWNER {}",
            owner_url.username()
        ))
        .execute(&admin)
        .await?;
        let mut owner_target = owner_url.clone();
        owner_target.set_path(&database_name);
        let mut runtime_target = runtime_url;
        runtime_target.set_path(&database_name);
        fixture_pool_url(&mut owner_target, &format!("{database_name}_owner"));
        fixture_pool_url(&mut runtime_target, &format!("{database_name}_runtime"));
        let owner = PgPoolOptions::new()
            .max_connections(8)
            .connect(owner_target.as_str())
            .await?;
        sqlx::migrate!().run(&owner).await?;
        let formal: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=37 AND success)",
        )
        .fetch_one(&owner)
        .await?;
        anyhow::ensure!(
            formal,
            "BFF fixture requires normally applied migration 0037"
        );
        sqlx::raw_sql(include_str!("../scripts/sql/roles.sql"))
            .execute(&owner)
            .await?;
        sqlx::raw_sql(include_str!("../scripts/sql/browser-role.sql"))
            .execute(&owner)
            .await?;
        // This owned child database follows the normal migration entry point:
        // install each already-provisioned component's reviewed narrow grants
        // before the ordinary API startup verifies the complete schema.
        for (role, grants) in [
            (
                "sandbox_worker",
                include_str!("../scripts/sql/worker-role.sql"),
            ),
            (
                "sandbox_gateway",
                include_str!("../scripts/sql/gateway-role.sql"),
            ),
            (
                "sandbox_admission",
                include_str!("../scripts/sql/admission-role.sql"),
            ),
            (
                "sandbox_termination",
                include_str!("../scripts/sql/termination-role.sql"),
            ),
            (
                "sandbox_fencing",
                include_str!("../scripts/sql/fencing-role.sql"),
            ),
            (
                "sandbox_volume_deleter",
                include_str!("../scripts/sql/volume-deleter-role.sql"),
            ),
            (
                "sandbox_backup",
                include_str!("../scripts/sql/backup-role.sql"),
            ),
        ] {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)")
                    .bind(role)
                    .fetch_one(&owner)
                    .await?;
            if exists {
                sqlx::raw_sql(grants).execute(&owner).await?;
            }
        }
        sqlx::raw_sql(include_str!("../scripts/sql/automation-role.sql"))
            .execute(&owner)
            .await?;
        let tenant = Uuid::new_v4();
        let principal = Uuid::new_v4();
        let project = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let mut tx = owner.begin().await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO platform_configuration(singleton,cluster_epoch,safe_mode) VALUES(true,$1,false)").bind(epoch).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO tenants(id,name) VALUES($1,'Browser test tenant')")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO principals(id,kind,display_name) VALUES($1,'USER','Browser test user')",
        )
        .bind(principal)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject) VALUES($1,$2,'browser-user')").bind(principal).bind(ISSUER).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO tenant_principals(tenant_id,principal_id,display_name) VALUES($1,$2,'Browser user')").bind(tenant).bind(principal).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds) VALUES($1,$2,'Browser project',86400)").bind(project).bind(tenant).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'instances:read')").bind(tenant).bind(project).bind(principal).execute(&mut *tx).await?;
        tx.commit().await?;
        let provider = Provider {
            nonce: Arc::new(Mutex::new(String::new())),
            mode: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let idp=Router::new().route("/jwks",get(||async{Json(json!({"keys":[serde_json::from_str::<Value>(include_str!("../tests/fixtures/auth/jwk-a.json")).unwrap()]}))})).route("/token",post(provider_token)).with_state(provider.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let idp_base = format!("http://{}", listener.local_addr()?);
        let idp_task = tokio::spawn(async move {
            axum::serve(listener, idp).await.unwrap();
        });
        let settings = OidcSettings {
            issuer: ISSUER.into(),
            authorization_url: "https://identity.bff.invalid/auth".into(),
            token_url: format!("{idp_base}/token"),
            jwks_url: format!("{idp_base}/jwks"),
            client_id: "sandbox-browser".into(),
            public_origin: ORIGIN.into(),
            scopes: vec!["openid".into(), "sandbox:access".into()],
        };
        let auth = JwtAuthenticator::new(AuthConfig {
            scope_profile: Default::default(),
            issuer: ISSUER.into(),
            audience: "sandbox-api".into(),
            jwks_url: settings.jwks_url.clone(),
            required_scopes: vec!["sandbox:access".into()],
            jwks_ttl_seconds: 60,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })?;
        let keys = tempfile::tempdir()?;
        let path = keys.path().join("session-keys.json");
        std::fs::write(
            &path,
            json!({"active":"a","keys":[{"id":"a","key":URL_SAFE_NO_PAD.encode([42;32])}]})
                .to_string(),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let database = Database::connect(runtime_target.as_str(), 16).await?;
        database.verify_runtime_role().await?;
        let app = Arc::new(AppState {
            database,
            auth,
            cursor_signer: CursorSigner::from_json(
                &json!({"active":{"kid":"a","key_base64":STANDARD.encode([43;32])},"previous":[]})
                    .to_string(),
            )?,
            output_reader: None,
            metrics: None,
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86400,
        });
        let runtime = Arc::new(BrowserRuntime::new(
            app,
            BrowserConfig {
                oidc: BrowserOidc::test_transport(settings, SECRET.into())?,
                keys: SessionKeys::from_file(&path)?,
            },
        ));
        let api = Router::new()
            .route(
                "/v1/probe",
                get(|| async { StatusCode::NO_CONTENT }).post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/test-stream",
                get(|| async {
                    let events = futures_util::stream::unfold(0u64, |n| async move {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Some((
                            Ok::<_, Infallible>(Event::default().data(n.to_string())),
                            n + 1,
                        ))
                    });
                    Sse::new(events)
                }),
            )
            .route(
                "/v1/test-binary",
                get(|| async {
                    let bytes = futures_util::stream::unfold(0u64, |n| async move {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Some((Ok::<_, Infallible>(n.to_string()), n + 1))
                    });
                    (
                        [("content-type", "application/octet-stream")],
                        Body::from_stream(bytes),
                    )
                }),
            );
        let api = crate::api::router_with_shutdown(
            runtime.app.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .merge(api);
        let router = runtime
            .clone()
            .attach(api)
            .layer(middleware::from_fn(crate::api::request_boundary));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let api_task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Self {
            owner,
            admin,
            database_name,
            runtime,
            tenant,
            principal,
            project,
            base,
            client,
            provider,
            tasks: vec![idp_task, api_task],
            keys,
        })
    }
    async fn login(&self) -> anyhow::Result<(String, String)> {
        let response = self
            .client
            .post(format!("{}/auth/login", self.base))
            .header("origin", ORIGIN)
            .json(&json!({"tenant_id":self.tenant}))
            .send()
            .await?;
        anyhow::ensure!(
            response.status() == StatusCode::OK,
            "login begin status {}",
            response.status()
        );
        let binding = response.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let value: Value = response.json().await?;
        let url = url::Url::parse(value["authorization_url"].as_str().unwrap())?;
        let params = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
        *self.provider.nonce.lock().await = params["nonce"].clone();
        let response = self
            .client
            .get(format!("{}/auth/callback", self.base))
            .query(&[
                ("state", &params["state"]),
                ("code", &"fixture-code".into()),
            ])
            .header("cookie", binding)
            .send()
            .await?;
        anyhow::ensure!(
            response.status() == StatusCode::SEE_OTHER,
            "login callback status {} body {}",
            response.status(),
            response.text().await?
        );
        let header = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|h| h.to_str().unwrap())
            .find(|h| h.starts_with(SESSION_COOKIE))
            .unwrap();
        assert!(header.contains("Secure; HttpOnly; SameSite=Strict"));
        assert!(!header.contains("Domain="));
        let cookie = header.split(';').next().unwrap().to_owned();
        let response = self
            .client
            .get(format!("{}/auth/session", self.base))
            .header("cookie", &cookie)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = response.json().await?;
        assert_eq!(view["tenant_id"], self.tenant.to_string());
        assert_eq!(view["principal_id"], self.principal.to_string());
        assert!(view.get("access_token").is_none());
        assert!(view.get("refresh_token").is_none());
        Ok((cookie, view["csrf_token"].as_str().unwrap().to_owned()))
    }
    async fn owner_sql(&self, sql: &str) -> anyhow::Result<()> {
        let mut tx = self.owner.begin().await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(self.tenant.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(sql).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn close(self) -> anyhow::Result<()> {
        let owner_role = self.owner.connect_options().get_username().to_owned();
        let runtime_role = self
            .runtime
            .app
            .database
            .pool
            .connect_options()
            .get_username()
            .to_owned();
        let owner_pool = self
            .owner
            .connect_options()
            .get_application_name()
            .ok_or_else(|| anyhow::anyhow!("fixture owner pool tag missing"))?
            .to_owned();
        let runtime_pool = self
            .runtime
            .app
            .database
            .pool
            .connect_options()
            .get_application_name()
            .ok_or_else(|| anyhow::anyhow!("fixture runtime pool tag missing"))?
            .to_owned();
        anyhow::ensure!(
            owner_pool == format!("{}_owner", self.database_name)
                && runtime_pool == format!("{}_runtime", self.database_name)
                && owner_pool.len() < 64
                && runtime_pool.len() < 64
                && owner_pool.is_ascii()
                && runtime_pool.is_ascii(),
            "fixture pool tags mismatch"
        );
        for t in self.tasks {
            t.abort();
            let _ = t.await;
        }
        self.runtime.app.database.pool.close().await;
        self.owner.close().await;
        drop(self.runtime);
        drop(self.keys);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut progress = FixtureDrainProgress::new(deadline);
        loop {
            progress.enter(FixtureDrainStage::PeersQuery);
            let (peers, actual_owner) = tokio::time::timeout_at(deadline, async {
                let peers = fixture_peers(&self.admin, &self.database_name).await?;
                let owner_idle = peers
                    .iter()
                    .filter(|peer| {
                        peer.role == owner_role
                            && peer.pool == owner_pool
                            && idle_owned_tail(
                                peer,
                                &owner_role,
                                &owner_pool,
                                &runtime_role,
                                &runtime_pool,
                            )
                    })
                    .count();
                let runtime_idle = peers
                    .iter()
                    .filter(|peer| {
                        peer.role == runtime_role
                            && peer.pool == runtime_pool
                            && idle_owned_tail(
                                peer,
                                &owner_role,
                                &owner_pool,
                                &runtime_role,
                                &runtime_pool,
                            )
                    })
                    .count();
                progress.peers = Some((
                    tokio::time::Instant::now(),
                    peers.len(),
                    owner_idle,
                    runtime_idle,
                ));
                progress.enter(FixtureDrainStage::OwnerQuery);
                let actual_owner: String = sqlx::query_scalar(
                    "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1",
                )
                .bind(&self.database_name)
                .fetch_one(&self.admin)
                .await?;
                progress.owner = Some((tokio::time::Instant::now(), actual_owner == owner_role));
                progress.completed_rounds += 1;
                progress.enter(FixtureDrainStage::ObservationComplete);
                Ok::<_, anyhow::Error>((peers, actual_owner))
            })
            .await
            .map_err(|error| anyhow::Error::new(error).context(progress.describe()))
            .context("fixture backend drain deadline exceeded")??;
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(progress.describe())
                    .context("fixture backend drain deadline exceeded"));
            }
            let cleanup_safe = actual_owner == owner_role
                && peers.iter().all(|peer| {
                    idle_owned_tail(peer, &owner_role, &owner_pool, &runtime_role, &runtime_pool)
                });
            if !cleanup_safe {
                eprintln!(
                    "BFF_FIXTURE_CLEANUP_REFUSED owner_matches={} peers={}",
                    actual_owner == owner_role,
                    peers.len()
                );
                for peer in &peers {
                    let class = if peer.role == owner_role {
                        "OWNER"
                    } else if peer.role == runtime_role {
                        "RUNTIME"
                    } else {
                        "FOREIGN"
                    };
                    let state = match peer.state.as_str() {
                        "active"
                        | "idle"
                        | "idle in transaction"
                        | "idle in transaction (aborted)"
                        | "fastpath function call"
                        | "disabled" => peer.state.as_str(),
                        _ => "OTHER",
                    };
                    let wait = if peer.wait.len() <= 64
                        && peer
                            .wait
                            .bytes()
                            .all(|v| v.is_ascii_alphanumeric() || v == b'_')
                    {
                        peer.wait.as_str()
                    } else {
                        "OTHER"
                    };
                    eprintln!(
                        "BFF_FIXTURE_CLEANUP_PEER role={class} state={state} wait={wait} xact_open={} pool_matches={}",
                        peer.xact_open,
                        idle_owned_tail(
                            peer,
                            &owner_role,
                            &owner_pool,
                            &runtime_role,
                            &runtime_pool
                        )
                    );
                }
            }
            anyhow::ensure!(
                cleanup_safe,
                "fixture cleanup refuses unexpected owner, active or foreign connections"
            );
            if peers.is_empty() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(progress.describe()).context(
                    "fixture closed pools still have server backends after bounded drain",
                ));
            }
            progress.enter(FixtureDrainStage::Sleeping);
            tokio::time::sleep(Duration::from_millis(100)).await;
            progress.after_sleep();
        }
        // Use only an ordinary DROP. An idle migration-owner socket can survive
        // until process exit; retain that fixture and record separate cleanup.
        match sqlx::query(&format!("DROP DATABASE {}", self.database_name))
            .execute(&self.admin)
            .await
        {
            Ok(_) => {}
            Err(sqlx::Error::Database(ref e)) if e.code().as_deref() == Some("55006") => {
                // Recheck the race after the zero-peer snapshot. Runtime or
                // foreign connections can never become an owner-only deferral.
                let peers = fixture_peers(&self.admin, &self.database_name).await?;
                let actual_owner: String = sqlx::query_scalar(
                    "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1",
                )
                .bind(&self.database_name)
                .fetch_one(&self.admin)
                .await?;
                anyhow::ensure!(
                    actual_owner == owner_role
                        && !peers.is_empty()
                        && peers.iter().all(|peer| peer.role == owner_role
                            && peer.pool == owner_pool
                            && idle_owned_tail(
                                peer,
                                &owner_role,
                                &owner_pool,
                                &runtime_role,
                                &runtime_pool
                            )),
                    "ordinary DROP refuses non-owner or unknown connection race"
                );
                std::fs::create_dir_all(".local")?;
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(".local/bff-test-cleanup-pending.jsonl")?;
                writeln!(
                    file,
                    "{}",
                    json!({"database":self.database_name,"owner":owner_role,"reason":"idle_fixture_owner_connection","ordinary_drop_after_test_process_exit":true})
                )?;
                eprintln!(
                    "BFF fixture retained; ordinary cleanup task recorded in .local/bff-test-cleanup-pending.jsonl"
                );
            }
            Err(error) => return Err(error.into()),
        }
        self.admin.close().await;
        Ok(())
    }
}
async fn provider_token(State(provider): State<Provider>, body: String) -> Response {
    provider.calls.fetch_add(1, Ordering::SeqCst);
    let params = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    if params
        .get("grant_type")
        .is_some_and(|v| v == "refresh_token")
    {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    if provider.mode.load(Ordering::SeqCst) == 1 {
        return (
            StatusCode::BAD_GATEWAY,
            "PRIVATE_PROVIDER_BODY_MUST_NOT_ECHO",
        )
            .into_response();
    }
    let nonce = provider.nonce.lock().await.clone();
    let now = Utc::now().timestamp();
    Json(json!({"access_token":jwt(json!({"iss":ISSUER,"aud":"sandbox-api","sub":"browser-user","client_id":"sandbox-browser","jti":Uuid::new_v4(),"iat":now,"exp":now+240,"scope":"sandbox:access"}),false),"id_token":jwt(json!({"iss":ISSUER,"aud":"sandbox-browser","sub":"browser-user","iat":now,"exp":now+240,"nonce":nonce}),true),"refresh_token":"fixture-rotating-refresh","expires_in":240,"token_type":"Bearer"})).into_response()
}
#[tokio::test]
#[ignore = "requires local disposable PostgreSQL and loopback TCP"]
async fn browser_http_login_csrf_refresh_revocation_and_stream_close() -> anyhow::Result<()> {
    let f = Fixture::start().await?;
    let (cookie, csrf) = f.login().await?;
    let db = &f.runtime.app.database;
    assert!(
        sqlx::query("SELECT payload FROM browser_sessions")
            .fetch_all(&db.pool)
            .await
            .is_err()
    );
    let probe = |method: reqwest::Method| {
        f.client
            .request(method, format!("{}/v1/probe", f.base))
            .header("cookie", &cookie)
            .header("x-tenant-id", f.tenant.to_string())
    };
    assert_eq!(
        probe(reqwest::Method::GET).send().await?.status(),
        StatusCode::NO_CONTENT
    );
    let instances = || {
        f.client
            .get(format!("{}/v1/instances", f.base))
            .query(&[("project_id", f.project.to_string())])
            .header("cookie", &cookie)
            .header("x-tenant-id", f.tenant.to_string())
    };
    assert_eq!(instances().send().await?.status(), StatusCode::OK);
    f.owner_sql("UPDATE grants SET enabled=false WHERE action='instances:read'")
        .await?;
    assert_eq!(instances().send().await?.status(), StatusCode::FORBIDDEN);
    f.owner_sql("UPDATE grants SET enabled=true WHERE action='instances:read'")
        .await?;
    assert_eq!(
        probe(reqwest::Method::POST)
            .header("origin", "https://attacker.invalid")
            .header("x-csrf-token", &csrf)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        probe(reqwest::Method::POST)
            .header("origin", ORIGIN)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        probe(reqwest::Method::POST)
            .header("origin", ORIGIN)
            .header("x-csrf-token", &csrf)
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        probe(reqwest::Method::GET)
            .header("authorization", "Bearer untrusted")
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.client
            .get(format!("{}/v1/probe", f.base))
            .header("cookie", &cookie)
            .header("x-tenant-id", Uuid::new_v4().to_string())
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    f.owner_sql(
        "UPDATE browser_sessions SET access_expires_at=clock_timestamp()+interval '5 seconds'",
    )
    .await?;
    let calls = f.provider.calls.load(Ordering::SeqCst);
    let requests = (0..10).map(|_| {
        f.client
            .get(format!("{}/auth/session", f.base))
            .header("cookie", &cookie)
            .send()
    });
    let results = futures_util::future::join_all(requests).await;
    assert!(
        results
            .iter()
            .any(|r| r.as_ref().is_ok_and(|r| r.status() == StatusCode::OK))
    );
    for r in results {
        assert!(matches!(
            r?.status(),
            StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
        ));
    }
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), calls + 1);
    let mut stream = f
        .client
        .get(format!("{}/v1/test-stream", f.base))
        .header("cookie", &cookie)
        .header("x-tenant-id", f.tenant.to_string())
        .send()
        .await?;
    assert_eq!(stream.status(), StatusCode::OK);
    assert!(stream.chunk().await?.is_some());
    let mut binary = f
        .client
        .get(format!("{}/v1/test-binary", f.base))
        .header("cookie", &cookie)
        .header("x-tenant-id", f.tenant.to_string())
        .send()
        .await?;
    assert_eq!(binary.status(), StatusCode::OK);
    assert!(binary.chunk().await?.is_some());
    let response = f
        .client
        .post(format!("{}/auth/logout", f.base))
        .header("cookie", &cookie)
        .header("origin", ORIGIN)
        .header("x-csrf-token", &csrf)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // Delay the consumer while the source keeps producing; authorization must
    // close the server stream rather than waiting for a client heartbeat.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        let chunk = tokio::time::timeout_at(deadline, stream.chunk()).await?;
        if chunk?.is_none() {
            break;
        }
    }
    loop {
        let chunk = tokio::time::timeout_at(deadline, binary.chunk()).await?;
        if chunk?.is_none() {
            break;
        }
    }
    assert_eq!(
        probe(reqwest::Method::GET).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let (cookie, _) = f.login().await?;
    f.owner_sql("UPDATE browser_sessions SET access_expires_at=clock_timestamp()+interval '5 seconds' WHERE status='ACTIVE'").await?;
    f.provider.mode.store(1, Ordering::SeqCst);
    let calls = f.provider.calls.load(Ordering::SeqCst);
    let response = f
        .client
        .get(format!("{}/auth/session", f.base))
        .header("cookie", &cookie)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!response.text().await?.contains("PRIVATE_PROVIDER"));
    assert_eq!(
        f.client
            .get(format!("{}/auth/session", f.base))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), calls + 1);
    f.provider.mode.store(0, Ordering::SeqCst);
    let (cookie, _) = f.login().await?;
    f.owner_sql("UPDATE tenant_principals SET enabled=false")
        .await?;
    assert_eq!(
        f.client
            .get(format!("{}/auth/session", f.base))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    f.owner_sql("UPDATE tenant_principals SET enabled=true")
        .await?;
    let (cookie, _) = f.login().await?;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1")
        .bind(Uuid::new_v4())
        .execute(&f.owner)
        .await?;
    assert_eq!(
        f.client
            .get(format!("{}/auth/session", f.base))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    f.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires local disposable PostgreSQL and loopback TCP"]
async fn browser_challenge_binding_once_and_lock_wait_expiry() -> anyhow::Result<()> {
    let f = Fixture::start().await?;
    let response = f
        .client
        .post(format!("{}/auth/login", f.base))
        .header("origin", ORIGIN)
        .json(&json!({"tenant_id":f.tenant}))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let binding = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let value: Value = response.json().await?;
    let url = url::Url::parse(value["authorization_url"].as_str().unwrap())?;
    let params = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
    *f.provider.nonce.lock().await = params["nonce"].clone();
    let callback = || {
        f.client
            .get(format!("{}/auth/callback", f.base))
            .query(&[("state", &params["state"]), ("code", &"once-code".into())])
    };
    let wrong = format!("{LOGIN_COOKIE}={}", random_token()?);
    assert_eq!(
        callback().header("cookie", wrong).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        callback().header("cookie", &binding).send().await?.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        callback().header("cookie", &binding).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 1);
    let db = f.runtime.app.database.clone();
    let epoch = db.browser_epoch().await.map_err(api_failure)?;
    let challenge = Uuid::new_v4();
    let state = hash_cookie(&random_token()?).map_err(api_failure)?;
    let binding = hash_cookie(&random_token()?).map_err(api_failure)?;
    let encrypted =
        f.runtime
            .config
            .keys
            .encrypt(Purpose::Login, challenge, epoch, b"private challenge")?;
    assert!(
        db.browser_login_create(challenge, f.tenant, epoch, &state, &binding, &encrypted)
            .await
            .map_err(api_failure)?
    );
    assert!(
        db.browser_login_consume(&state, &binding)
            .await
            .map_err(api_failure)?
            .is_some()
    );
    let mut lock = f.owner.begin().await?;
    sqlx::query("SELECT id FROM principals WHERE id=$1 FOR UPDATE")
        .bind(f.principal)
        .fetch_one(&mut *lock)
        .await?;
    let session = Uuid::new_v4();
    let hash = hash_cookie(&random_token()?).map_err(api_failure)?;
    let csrf = hash_cookie(&random_token()?).map_err(api_failure)?;
    let payload =
        f.runtime
            .config
            .keys
            .encrypt(Purpose::Session, session, epoch, b"private session")?;
    let expiry = Utc::now() + chrono::Duration::seconds(1);
    let create = tokio::spawn(async move {
        db.browser_session_create(
            challenge,
            session,
            hash,
            csrf,
            ISSUER.into(),
            "browser-user".into(),
            expiry,
            payload,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT sandbox_browser_session_create%')").bind(&f.database_name).fetch_one(&f.admin).await?;
    assert!(
        waiting,
        "the create attempt must actually wait on the principal lock"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    lock.commit().await?;
    assert!(!create.await?.map_err(api_failure)?);
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(f.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let inserted: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM browser_sessions WHERE id=$1)")
            .bind(session)
            .fetch_one(&mut *tx)
            .await?;
    assert!(!inserted);
    tx.commit().await?;
    f.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires local disposable PostgreSQL and loopback TCP"]
async fn browser_session_idle_abandoned_refresh_and_retention_cleanup() -> anyhow::Result<()> {
    let f = Fixture::start().await.context("retention fixture start")?;
    let formal: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=37 AND success)",
    )
    .fetch_one(&f.owner)
    .await
    .context("formal browser migration query")?;
    assert_eq!(f.runtime.check_schema().await.is_ok(), formal);
    let (cookie, _) = f.login().await.context("first retention login")?;
    f.owner_sql("UPDATE browser_sessions SET idle_expires_at=clock_timestamp()-interval '1 second' WHERE status='ACTIVE'").await?;
    assert_eq!(
        f.client
            .get(format!("{}/auth/session", f.base))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf) = f.login().await.context("second retention login")?;
    f.owner_sql("UPDATE browser_sessions SET status='REFRESHING',refresh_started_at=clock_timestamp()-interval '16 seconds',version=version+1 WHERE status='ACTIVE'").await?;
    let calls = f.provider.calls.load(Ordering::SeqCst);
    assert_eq!(
        f.client
            .get(format!("{}/auth/session", f.base))
            .header("cookie", &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), calls);
    assert_eq!(
        f.client
            .post(format!("{}/auth/logout", f.base))
            .header("origin", ORIGIN)
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let _ = f.login().await.context("third retention login")?;
    f.owner_sql(
        "UPDATE browser_session_routes SET expires_at=clock_timestamp()-interval '1 second'",
    )
    .await?;
    let changed: i64 = sqlx::query_scalar("SELECT sandbox_browser_cleanup($1)")
        .bind(Uuid::new_v4())
        .fetch_one(&f.runtime.app.database.pool)
        .await
        .context("retention cleanup scrub query")?;
    assert!(changed > 0);
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(f.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM browser_sessions WHERE payload IS NOT NULL")
            .fetch_one(&mut *tx)
            .await
            .context("retention ciphertext count")?;
    assert_eq!(remaining, 0);
    tx.commit().await?;
    f.owner_sql(
        "UPDATE browser_session_routes SET expires_at=clock_timestamp()-interval '31 days'",
    )
    .await?;
    sqlx::query("SELECT sandbox_browser_cleanup($1)")
        .bind(Uuid::new_v4())
        .execute(&f.runtime.app.database.pool)
        .await
        .context("retention route count")?;
    let routes: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_session_routes")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(routes, 0);
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(f.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action LIKE 'browser_sessions:%'",
    )
    .fetch_one(&mut *tx)
    .await
    .context("retention audit count")?;
    assert!(audits > 0);
    tx.commit().await?;
    f.close()
        .await
        .context("retention ordinary fixture close")?;
    Ok(())
}

#[test]
fn browser_cookie_capabilities_reject_duplicates_and_noncanonical_tokens() {
    let token = random_token().unwrap();
    let mut h = HeaderMap::new();
    h.insert(
        "cookie",
        HeaderValue::from_str(&format!("{SESSION_COOKIE}={token}")).unwrap(),
    );
    assert_eq!(cookie(&h, SESSION_COOKIE).unwrap(), Some(token.clone()));
    h.append(
        "cookie",
        HeaderValue::from_str(&format!("{SESSION_COOKIE}={token}")).unwrap(),
    );
    assert!(cookie(&h, SESSION_COOKIE).is_err());
    h.clear();
    h.insert(
        "cookie",
        HeaderValue::from_static("__Host-sandbox-session=invalid"),
    );
    assert!(cookie(&h, SESSION_COOKIE).is_err());
    assert!(digest("invalid+state").is_err());
    assert!(digest(&"s".repeat(22)).is_ok());
}
