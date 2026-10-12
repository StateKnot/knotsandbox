//! Database telemetry only. This label authenticates neither a process nor a
//! Kubernetes Pod, authorizes no SQL, and proves no connection/VM was released.
use std::{ffi::OsString, sync::OnceLock};

use anyhow::ensure;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sqlx::postgres::PgConnectOptions;
use uuid::Uuid;

const POD_UID_ENV: &str = "SANDBOX_PROCESS_POD_UID";
static PROCESS_ID: OnceLock<Uuid> = OnceLock::new();

fn current_process_uuid() -> Uuid {
    *PROCESS_ID.get_or_init(Uuid::new_v4)
}

/// Selected by an executable's fixed role branch, never URL/label/free-form input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseProcessRole {
    Api,
    Worker,
    Gateway,
    Admission,
    Termination,
    Fencing,
    VolumeDeleter,
    Backup,
    Automation,
    Migrate,
    Admin,
}
impl DatabaseProcessRole {
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Worker => "worker",
            Self::Gateway => "gateway",
            Self::Admission => "admission",
            Self::Termination => "termination",
            Self::Fencing => "fencing",
            Self::VolumeDeleter => "volume",
            Self::Backup => "backup",
            Self::Automation => "automation",
            Self::Migrate => "migrate",
            Self::Admin => "admin",
        }
    }
}

pub(super) struct DatabaseProcessIdentity {
    pub(super) role: DatabaseProcessRole,
    pub(super) process_id: Uuid,
    pub(super) pod_uid: Option<Uuid>,
    application_name: String,
}
impl DatabaseProcessIdentity {
    pub(super) fn current(role: DatabaseProcessRole) -> anyhow::Result<Self> {
        let pod_uid = parse_pod_uid(
            std::env::var_os(POD_UID_ENV),
            std::env::var_os("KUBERNETES_SERVICE_HOST").is_some(),
        )?;
        // Every pool created by this executable shares one UUID. A real process
        // restart generates a new UUID even when Kubernetes retains the Pod UID.
        Self::build(role, current_process_uuid(), pod_uid)
    }

    fn build(
        role: DatabaseProcessRole,
        process_id: Uuid,
        pod_uid: Option<Uuid>,
    ) -> anyhow::Result<Self> {
        ensure!(
            !process_id.is_nil() && pod_uid.is_none_or(|id| !id.is_nil()),
            "Database telemetry identity UUID must not be nil"
        );
        // Both UUIDs retain all 128 bits: no lossy hash/truncated PID and no
        // dependence on an invented restart counter. URL-safe base64 is 22 bytes.
        let process = URL_SAFE_NO_PAD.encode(process_id.as_bytes());
        let pod = pod_uid.map_or_else(|| "-".into(), |id| URL_SAFE_NO_PAD.encode(id.as_bytes()));
        let application_name = format!("sbx1.{}.{process}.{pod}", role.tag());
        ensure!(
            application_name.len() <= 63
                && application_name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "Database telemetry identity exceeds the PostgreSQL identifier bound"
        );
        Ok(Self {
            role,
            process_id,
            pod_uid,
            application_name,
        })
    }

    pub(super) fn apply(&self, options: PgConnectOptions) -> PgConnectOptions {
        options.application_name(&self.application_name)
    }

    pub(super) fn application_name(&self) -> &str {
        &self.application_name
    }
}

fn parse_pod_uid(raw: Option<OsString>, in_kubernetes: bool) -> anyhow::Result<Option<Uuid>> {
    let Some(raw) = raw else {
        ensure!(
            !in_kubernetes,
            "Kubernetes database process requires its Downward API Pod UID"
        );
        return Ok(None);
    };
    let value = raw
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid database process Pod UID"))?;
    let uid =
        Uuid::parse_str(value).map_err(|_| anyhow::anyhow!("Invalid database process Pod UID"))?;
    ensure!(
        !uid.is_nil() && uid.to_string() == value,
        "Database process Pod UID must be canonical and nonnil"
    );
    Ok(Some(uid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{ConnectOptions as _, postgres::PgSslMode};

    fn process() -> Uuid {
        Uuid::from_u128(1)
    }
    fn pod() -> Uuid {
        Uuid::from_u128(2)
    }

    #[test]
    fn fixed_roles_encode_full_process_and_pod_uuids_within_pg_63_bytes() -> anyhow::Result<()> {
        for role in [
            DatabaseProcessRole::Api,
            DatabaseProcessRole::Worker,
            DatabaseProcessRole::Gateway,
            DatabaseProcessRole::Admission,
            DatabaseProcessRole::Termination,
            DatabaseProcessRole::Fencing,
            DatabaseProcessRole::VolumeDeleter,
            DatabaseProcessRole::Backup,
            DatabaseProcessRole::Automation,
            DatabaseProcessRole::Migrate,
            DatabaseProcessRole::Admin,
        ] {
            let identity = DatabaseProcessIdentity::build(role, process(), Some(pod()))?;
            let parts: Vec<_> = identity.application_name().split('.').collect();
            assert_eq!(parts.len(), 4);
            assert_eq!(parts[0], "sbx1");
            assert_eq!(parts[1], role.tag());
            assert_eq!(
                URL_SAFE_NO_PAD.decode(parts[2])?,
                process().as_bytes().to_vec()
            );
            assert_eq!(URL_SAFE_NO_PAD.decode(parts[3])?, pod().as_bytes().to_vec());
            assert_eq!(parts[2].len(), 22);
            assert_eq!(parts[3].len(), 22);
            assert!(identity.application_name().is_ascii());
            assert!(identity.application_name().len() <= 63);
        }
        Ok(())
    }

    #[test]
    fn same_process_same_pod_is_stable_and_restart_on_same_pod_is_distinct() -> anyhow::Result<()> {
        let current = current_process_uuid();
        assert!(!current.is_nil());
        assert_eq!(current_process_uuid(), current);
        let first =
            DatabaseProcessIdentity::build(DatabaseProcessRole::Api, process(), Some(pod()))?;
        let second =
            DatabaseProcessIdentity::build(DatabaseProcessRole::Api, process(), Some(pod()))?;
        let restarted = DatabaseProcessIdentity::build(
            DatabaseProcessRole::Api,
            Uuid::from_u128(3),
            Some(pod()),
        )?;
        assert_eq!(first.application_name(), second.application_name());
        assert_ne!(first.application_name(), restarted.application_name());
        assert!(
            DatabaseProcessIdentity::build(DatabaseProcessRole::Api, Uuid::nil(), Some(pod()))
                .is_err()
        );
        assert!(
            DatabaseProcessIdentity::build(DatabaseProcessRole::Api, process(), Some(Uuid::nil()))
                .is_err()
        );
        let host = DatabaseProcessIdentity::build(DatabaseProcessRole::Admin, process(), None)?;
        assert!(host.application_name().ends_with(".-"));
        Ok(())
    }

    #[test]
    fn pod_metadata_is_required_in_cluster_and_never_accepts_fallback_label_text()
    -> anyhow::Result<()> {
        assert_eq!(parse_pod_uid(None, false)?, None);
        assert!(parse_pod_uid(None, true).is_err());
        assert_eq!(
            parse_pod_uid(Some(pod().to_string().into()), true)?,
            Some(pod())
        );
        for invalid in [
            "",
            "pod-name",
            "process-label",
            "00000000-0000-0000-0000-000000000000",
            "00000000000000000000000000000002",
            " 00000000-0000-0000-0000-000000000002",
        ] {
            assert!(parse_pod_uid(Some(invalid.into()), true).is_err());
        }
        let uppercase = Uuid::from_u128(0xabcd).to_string().to_uppercase();
        assert!(parse_pod_uid(Some(uppercase.into()), false).is_err());
        Ok(())
    }

    #[test]
    fn production_options_override_url_label_while_legacy_connect_fixture_retains_it()
    -> anyhow::Result<()> {
        const URL: &str = "postgresql://sandbox_app:PUBLIC_TEST_ONLY@127.0.0.1:5432/sandbox_test?application_name=fixture-preserved";
        let plain = super::super::database_connect_options(URL, None)?;
        assert_eq!(plain.get_application_name(), Some("fixture-preserved"));
        let identity =
            DatabaseProcessIdentity::build(DatabaseProcessRole::Api, process(), Some(pod()))?;
        let production = super::super::database_connect_options(URL, Some(&identity))?;
        assert_eq!(
            production.get_application_name(),
            Some(identity.application_name())
        );
        assert_eq!(production.get_username(), plain.get_username());
        assert_eq!(production.get_host(), plain.get_host());
        assert_eq!(production.get_database(), plain.get_database());
        assert!(matches!(plain.get_ssl_mode(), PgSslMode::Prefer));
        assert!(matches!(production.get_ssl_mode(), PgSslMode::Prefer));

        // Parse only public synthetic options: no connection or certificate I/O.
        // Identity overrides the label, preserving verified remote TLS settings.
        const REMOTE_URL: &str = "postgresql://sandbox_app:PUBLIC_TEST_ONLY@database.example.test:5439/sandbox_test?sslmode=verify-full&sslrootcert=/etc/sandbox-test/db-ca.pem&application_name=remote-fixture";
        crate::config::validate_database_url(REMOTE_URL, false)?;
        let remote_plain = super::super::database_connect_options(REMOTE_URL, None)?;
        let remote_production =
            super::super::database_connect_options(REMOTE_URL, Some(&identity))?;
        assert_eq!(remote_plain.get_application_name(), Some("remote-fixture"));
        assert_eq!(
            remote_production.get_application_name(),
            Some(identity.application_name())
        );
        for options in [&remote_plain, &remote_production] {
            assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
            assert_eq!(options.get_username(), "sandbox_app");
            assert_eq!(options.get_host(), "database.example.test");
            assert_eq!(options.get_port(), 5439);
            assert_eq!(options.get_database(), Some("sandbox_test"));
            assert!(options.get_options().is_none());
            // SQLx has no public root-CA getter. Inspect just this public path,
            // never display the URL/password returned by to_url_lossy().
            let root_cert = options
                .to_url_lossy()
                .query_pairs()
                .find(|(key, _)| key == "sslrootcert")
                .map(|(_, value)| value.into_owned());
            // Pinned SQLx 0.8.6 serializes CertificateInput::File's diagnostic
            // representation; this is not a round-trip connection URL.
            assert_eq!(
                root_cert.as_deref(),
                Some("file: /etc/sandbox-test/db-ca.pem")
            );
        }
        // Setting options does not change the production URL allowlist.
        assert!(crate::config::validate_database_url("postgresql://sandbox_app:PUBLIC_TEST_ONLY@database.example.test/sandbox?sslmode=verify-full&sslrootcert=/ca.pem&options=-crole%3Dsandbox_owner", false).is_err());
        Ok(())
    }
}
