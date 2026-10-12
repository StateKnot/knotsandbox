#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use axum::{Router, body::Body, extract::State, http::Request, routing::any};
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

const ACCOUNT: &str = "1234567890123456";
const ROLE_ID: &str = "1234567890123457";
const SECRET: &str = "PUBLIC_TEST_SECRET";
const SECURITY_TOKEN: &str = "PUBLIC_TEST_SESSION";

fn config(directory: &Path) -> CredentialAgentConfig {
    CredentialAgentConfig {
        deployment: "sandbox-test".into(),
        account_id: ACCOUNT.into(),
        region: "cn-hangzhou".into(),
        purpose: StoragePurpose::FileReader,
        role_id: ROLE_ID.into(),
        oidc_issuer: "https://workload.example.test".into(),
        oidc_token_file: directory.join("token"),
        output_file: directory.join("private/sts.json"),
    }
}

#[derive(Clone)]
struct Server {
    config: CredentialAgentConfig,
    mode: Arc<AtomicU8>,
    sessions: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<String>>>,
}

async fn serve(
    State(server): State<Server>,
    request: Request<Body>,
) -> axum::Json<serde_json::Value> {
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let action = request.headers()["x-acs-action"]
        .to_str()
        .unwrap()
        .to_owned();
    server.calls.lock().unwrap().push(action.clone());
    let identity = server.config.identity();
    let mode = server.mode.load(Ordering::SeqCst);
    if action == "AssumeRoleWithOIDC" {
        assert_eq!(query["RoleArn"], identity.role_arn);
        assert_eq!(query["OIDCProviderArn"], identity.oidc_provider_arn);
        assert_eq!(query["OIDCToken"], "public.test.token");
        assert_eq!(query["DurationSeconds"], "900");
        assert!(request.headers().get("authorization").is_none());
        let session = query["RoleSessionName"].clone();
        assert!(session.starts_with("storage-"));
        server.sessions.lock().unwrap().push(session.clone());
        return axum::Json(json!({
            "RequestId":"fixture-only", "AssumedRoleUser":{"Arn":format!("{}/{session}",identity.role_arn)},
            "OIDCTokenInfo":{"Issuer":identity.oidc_issuer,"Subject":if mode==1{"wrong-subject"}else{identity.oidc_subject.as_str()},
                "ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success", "IssuanceTime":Utc::now()-ChronoDuration::seconds(1), "ExpirationTime":Utc::now()+ChronoDuration::seconds(600)},
            "Credentials":{"AccessKeyId":"STS.public-test","AccessKeySecret":SECRET,"SecurityToken":SECURITY_TOKEN,
                "Expiration":Utc::now()+ChronoDuration::seconds(if mode==3{60}else{900})},
        }));
    }
    assert_eq!(action, "GetCallerIdentity");
    assert_eq!(request.headers()["x-acs-security-token"], SECURITY_TOKEN);
    let values = request
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str() == "host" || k.as_str().starts_with("x-acs-"))
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
        .collect();
    let (signed, digest) =
        super::super::signature(&values, request.uri().query().unwrap_or_default(), SECRET)
            .unwrap();
    assert_eq!(
        request.headers()["authorization"],
        format!(
            "ACS3-HMAC-SHA256 Credential=STS.public-test,SignedHeaders={signed},Signature={digest}"
        )
    );
    axum::Json(
        json!({"RequestId":"fixture-only","AccountId":if mode==2{"0000000000000000"}else{ACCOUNT},"RoleId":if mode==4{"9999999999999999"}else{ROLE_ID},
        "IdentityType":"AssumedRoleUser","Arn":format!("{}/{}",identity.role_arn,server.sessions.lock().unwrap().last().unwrap())}),
    )
}

struct Fixture {
    agent: CredentialAgent,
    server: Server,
    _directory: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let c = config(directory.path());
        std::fs::write(&c.oidc_token_file, "public.test.token")?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&c.oidc_token_file, std::fs::Permissions::from_mode(0o440))?;
        let server = Server {
            config: c.clone(),
            mode: Arc::new(AtomicU8::new(0)),
            sessions: Arc::new(Mutex::new(vec![])),
            calls: Arc::new(Mutex::new(vec![])),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let router = Router::new()
            .fallback(any(serve))
            .with_state(server.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let transport = AlibabaCloudFencing::build_transport(
            c.identity(),
            BTreeMap::new(),
            None,
            endpoint.clone(),
            endpoint,
            false,
        )?;
        Ok(Self {
            agent: CredentialAgent {
                config: c,
                transport,
            },
            server,
            _directory: directory,
            task,
        })
    }
}

#[test]
fn configuration_derives_only_exact_component_identity_and_rejects_injection() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let c = config(directory.path());
    c.validate()?;
    let identity = c.identity();
    assert_eq!(
        identity.role_arn,
        format!("acs:ram::{ACCOUNT}:role/sandbox-test-file-reader")
    );
    assert_eq!(identity.oidc_subject, StoragePurpose::FileReader.subject());
    for mutation in 0..7 {
        let mut bad = c.clone();
        match mutation {
            0 => bad.deployment = "../operator".into(),
            1 => bad.account_id = "0000000000000000.inject".into(),
            2 => bad.region = "cn-hangzhou.attacker.test".into(),
            3 => bad.oidc_issuer = "http://metadata.internal".into(),
            4 => bad.output_file = directory.path().join("private/other.json"),
            5 => bad.oidc_token_file = PathBuf::from("/tmp/../secret"),
            _ => bad.oidc_issuer = "https://issuer.test:8443".into(),
        }
        assert!(bad.validate().is_err());
    }
    let path = directory.path().join("config.json");
    std::fs::write(&path, br#"{"PRIVATE_SECRET_MARKER":"invalid"}"#)?;
    assert!(
        !CredentialAgentConfig::from_file(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("PRIVATE_SECRET_MARKER")
    );
    Ok(())
}

#[test]
fn publisher_excludes_competitors_and_atomically_replaces_credentials() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let c = config(directory.path());
    let publisher = Publisher::new(&c.output_file)?;
    publisher.publish(b"original")?;
    assert!(Publisher::new(&c.output_file).is_err());
    assert_eq!(std::fs::read(&c.output_file)?, b"original");
    publisher.publish(b"replacement")?;
    assert_eq!(std::fs::read(&c.output_file)?, b"replacement");
    assert_eq!(
        std::fs::metadata(&c.output_file)?.permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        std::fs::read_dir(c.output_file.parent().unwrap())?.count(),
        2
    );
    drop(publisher);
    let reopened = Publisher::new(&c.output_file)?;
    reopened.remove();
    assert!(!c.output_file.exists());
    Ok(())
}

#[tokio::test]
async fn refresh_requires_oidc_and_signed_caller_proof_and_never_reuses_cached_session()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let publisher = Publisher::new(&f.agent.config.output_file)?;
    f.agent.refresh(&publisher).await?;
    check_credentials(&f.agent.config)?;
    f.agent.refresh(&publisher).await?;
    check_credentials(&f.agent.config)?;
    let sessions = f.server.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions[0], sessions[1]);
    assert_eq!(
        *f.server.calls.lock().unwrap(),
        vec![
            "AssumeRoleWithOIDC",
            "GetCallerIdentity",
            "AssumeRoleWithOIDC",
            "GetCallerIdentity"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn mismatch_or_expired_credentials_remove_previous_record_without_echoing_payload()
-> anyhow::Result<()> {
    for mode in 1..=4 {
        let f = Fixture::new().await?;
        let publisher = Publisher::new(&f.agent.config.output_file)?;
        f.agent.refresh(&publisher).await?;
        drop(publisher);
        f.server.mode.store(mode, Ordering::SeqCst);
        // Clone only the private transport/config so the fixture retains its TCP server.
        let agent = CredentialAgent {
            config: f.agent.config.clone(),
            transport: f.agent.transport.clone(),
        };
        let error = agent
            .run(true, CancellationToken::new())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains(SECRET) && !error.contains(SECURITY_TOKEN));
        assert!(!f.agent.config.output_file.exists());
    }
    Ok(())
}

#[tokio::test]
async fn projected_token_symlink_rotation_is_read_again_and_special_files_cannot_stall()
-> anyhow::Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new().await?;
    let c = &f.agent.config;
    let actual = f._directory.path().join("projected-token");
    std::fs::rename(&c.oidc_token_file, &actual)?;
    symlink(&actual, &c.oidc_token_file)?;
    let publisher = Publisher::new(&c.output_file)?;
    f.agent.refresh(&publisher).await?;
    std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o444))?;
    assert!(f.agent.refresh(&publisher).await.is_err());
    std::fs::remove_file(&c.oidc_token_file)?;
    nix::unistd::mkfifo(
        &c.oidc_token_file,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), f.agent.refresh(&publisher))
            .await?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_removes_credentials_and_health_rejects_expiry_and_symlinks()
-> anyhow::Result<()> {
    use std::os::unix::fs::symlink;
    let f = Fixture::new().await?;
    let publisher = Publisher::new(&f.agent.config.output_file)?;
    f.agent.refresh(&publisher).await?;
    check_credentials(&f.agent.config)?;
    let mut data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&f.agent.config.output_file)?)?;
    data["expires_at"] = serde_json::to_value(Utc::now() + ChronoDuration::seconds(60))?;
    publisher.publish(&serde_json::to_vec(&data)?)?;
    assert!(check_credentials(&f.agent.config).is_err());
    let elsewhere = f._directory.path().join("elsewhere");
    std::fs::rename(&f.agent.config.output_file, &elsewhere)?;
    symlink(&elsewhere, &f.agent.config.output_file)?;
    assert!(check_credentials(&f.agent.config).is_err());
    drop(publisher);
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    CredentialAgent {
        config: f.agent.config.clone(),
        transport: f.agent.transport.clone(),
    }
    .run(false, shutdown)
    .await?;
    assert!(!f.agent.config.output_file.symlink_metadata().is_ok());
    Ok(())
}
