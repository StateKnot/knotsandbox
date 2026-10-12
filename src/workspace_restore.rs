//! Immutable restore provenance for ordinary runtime consumers. A legal base
//! installation without the restore component remains supported; partial
//! restore schemas and marked workspaces without receipts fail closed.
use crate::{
    error::ApiError, nodeguard::protocol::LaunchBinding, runtime_manifest::RuntimeManifestContext,
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
pub(crate) struct WorkspaceRestoreBinding {
    pub restore_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub cluster_epoch: Uuid,
    pub namespace: String,
    pub snapshot_name: String,
    pub pvc_uid: Uuid,
    pub pv_uid: Uuid,
    pub pv_name: String,
    pub cloud_disk: String,
    pub size_bytes: i64,
    pub delivery_storage_class: String,
}
fn blocked() -> ApiError {
    ApiError::conflict(
        "RESTORE_PROVENANCE_UNAVAILABLE",
        "Restored workspace requires complete immutable filesystem delivery identity",
    )
}
impl WorkspaceRestoreBinding {
    pub(crate) fn apply(&self, c: &mut RuntimeManifestContext) -> Result<(), ApiError> {
        if self.tenant_id != c.tenant_id
            || self.project_id != c.project_id
            || self.instance_id != c.instance_id
            || self.workspace_id != c.workspace_id
            || self.cluster_epoch != c.cluster_epoch
            || self.namespace != c.namespace
            || self.delivery_storage_class != c.storage_class
            || self.snapshot_name != format!("sbx-rs-{}", self.restore_id)
            || self.size_bytes
                != c.workspace_size_gib
                    .checked_mul(1024_i64.pow(3))
                    .ok_or_else(blocked)?
            || [self.restore_id, self.pvc_uid, self.pv_uid]
                .iter()
                .any(Uuid::is_nil)
            || !crate::backup_manifest::valid_name(&self.pv_name)
            || !self
                .cloud_disk
                .strip_prefix("d-")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
        {
            return Err(blocked());
        }
        if c.workspace_snapshot
            .as_ref()
            .is_some_and(|name| name != &self.snapshot_name)
        {
            return Err(blocked());
        }
        c.workspace_snapshot = Some(self.snapshot_name.clone());
        Ok(())
    }
    pub(crate) fn matches_launch(&self, launch: &LaunchBinding) -> bool {
        self.tenant_id == launch.tenant_id
            && self.project_id == launch.project_id
            && self.instance_id == launch.instance_id
            && self.workspace_id == launch.workspace_id
            && self.namespace == launch.namespace
            && self.pvc_uid == launch.pvc_uid
            && self.pv_uid == launch.pv_uid
            && self.pv_name == launch.pv_name
            && self.cloud_disk == launch.csi_volume_handle
    }
}
/// Must be called again inside the consumer's workspace/instance/operation
/// fence after any wait. This read is provenance, not live cloud/VM authority.
pub(crate) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    context: &RuntimeManifestContext,
) -> Result<Option<WorkspaceRestoreBinding>, ApiError> {
    let (marker,table,reader):(bool,bool,bool)=sqlx::query_as("SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='public.workspaces'::regclass AND attname='restore_snapshot_name' AND NOT attisdropped),to_regclass('public.restores') IS NOT NULL,to_regprocedure('public.sandbox_workspace_restore_binding(uuid,uuid)') IS NOT NULL").fetch_one(&mut **tx).await?;
    if !marker && !table && !reader {
        return Ok(None);
    }
    if !marker || !table || !reader {
        return Err(blocked());
    }
    let binding: Option<WorkspaceRestoreBinding> =
        sqlx::query_as("SELECT * FROM sandbox_workspace_restore_binding($1,$2)")
            .bind(context.tenant_id)
            .bind(context.workspace_id)
            .fetch_optional(&mut **tx)
            .await?;
    let marker: Option<String> = sqlx::query_scalar(
        "SELECT restore_snapshot_name FROM workspaces WHERE tenant_id=$1 AND id=$2",
    )
    .bind(context.tenant_id)
    .bind(context.workspace_id)
    .fetch_one(&mut **tx)
    .await?;
    if binding.as_ref().map(|v| v.snapshot_name.as_str()) != marker.as_deref() {
        return Err(blocked());
    }
    if let Some(ref value) = binding {
        let mut c = context.clone();
        value.apply(&mut c)?;
    }
    Ok(binding)
}
pub(crate) async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    context: &mut RuntimeManifestContext,
) -> Result<(), ApiError> {
    if let Some(binding) = load(tx, context).await? {
        binding.apply(context)?;
    }
    Ok(())
}

/// A successfully installed 0038, or any restore schema marker, requires the
/// complete component on every runtime-role startup. Draft schema presence is
/// not interpreted as successful production migration/certification.
pub(crate) async fn verify_component_schema(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let (installed,marker,table,reader,partial):(bool,bool,bool,bool,bool)=sqlx::query_as("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=38 AND success),EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='public.workspaces'::regclass AND attname='restore_snapshot_name' AND NOT attisdropped),to_regclass('public.restores') IS NOT NULL,to_regprocedure('public.sandbox_workspace_restore_binding(uuid,uuid)') IS NOT NULL,EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace AND relname LIKE 'restore\\_%' ESCAPE '\\') OR EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname LIKE 'sandbox\\_%restore%' ESCAPE '\\')").fetch_one(pool).await?;
    if !installed && !marker && !table && !reader && !partial {
        return Ok(());
    }
    let complete:bool=sqlx::query_scalar("SELECT $1 AND $2 AND $3 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['restore_profile_certifications','restores','restore_vault_receipts','restore_resource_intents','restore_resource_bindings','restore_block_receipts','restore_job_contexts','restore_pod_admissions','restore_launch_permits','restore_launch_receipts','restore_close_challenges','restore_termination_proofs','restore_cleanup_receipts','restore_io_reports','restore_snapshot_receipts','restore_delivery_receipts','restore_artifact_cleanup_receipts']) name WHERE to_regclass('public.'||name) IS NULL) AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('public.restores') AND attname='storage_contract' AND atttypid='jsonb'::regtype AND NOT attisdropped) AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('public.restore_profile_certifications') AND attname='storage_mappings' AND atttypid='jsonb'::regtype AND NOT attisdropped) AND EXISTS(SELECT 1 FROM pg_proc WHERE oid=to_regprocedure('public.sandbox_lock_restore_configuration(uuid,uuid,uuid,uuid,timestamptz)') AND prorettype='jsonb'::regtype) AND to_regprocedure('public.sandbox_restore_storage_contract_certified(uuid,uuid,jsonb)') IS NOT NULL AND (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled IN('O','A') AND tgrelid=to_regclass('public.restore_profile_certifications') AND tgname IN('restore_certification_binding_guard','restore_certification_append_only'))=2 AND to_regprocedure('public.sandbox_publish_restore(uuid,uuid,bigint)') IS NOT NULL AND to_regprocedure('public.sandbox_lock_restore_admission(uuid,uuid)') IS NOT NULL AND to_regprocedure('public.sandbox_lock_restore_observation(uuid,uuid)') IS NOT NULL AND to_regprocedure('public.sandbox_restore_node_binding(uuid,uuid,uuid,text,uuid,text)') IS NOT NULL AND to_regprocedure('public.sandbox_restore_node_observation(uuid,uuid,uuid,text,uuid,text)') IS NOT NULL AND to_regprocedure('public.sandbox_lock_restored_runtime(uuid,uuid,uuid)') IS NOT NULL AND to_regprocedure('public.sandbox_restore_birth_guard(uuid,uuid,uuid,uuid)') IS NOT NULL AND to_regprocedure('public.sandbox_restored_never_started(uuid,uuid,uuid)') IS NOT NULL AND to_regprocedure('public.sandbox_restored_workspace_delete_binding(uuid,uuid)') IS NOT NULL AND to_regprocedure('public.sandbox_workspace_ordinary_writers_closed(uuid,uuid)') IS NOT NULL AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='public.workspace_delete_bindings'::regclass AND attname='restore_id' AND NOT attisdropped) AND (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled IN('O','A') AND((tgrelid='public.launch_permits'::regclass AND tgname='restored_launch_binding_guard') OR(tgrelid='public.workspaces'::regclass AND tgname='restore_datasource_guard') OR(tgrelid=to_regclass('public.restores') AND tgname='restore_guard') OR(tgrelid='public.workspace_delete_bindings'::regclass AND tgname='restore_workspace_delete_binding'))) = 4")
        .bind(marker).bind(table).bind(reader).fetch_one(pool).await?;
    anyhow::ensure!(
        installed && complete,
        "Restore component requires successful ordered migration 0038 and a complete schema; runtime startup is refused"
    );
    Ok(())
}
