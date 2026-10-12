//! Cleanup has its own STS capability. Cloud object absence releases bytes only
//! through the ledger's write-completion and receipt guards.
use crate::{db::Database, file_store::OssFileCleaner};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct FileCleanupController {
    database: Database,
    cleaner: OssFileCleaner,
}
impl FileCleanupController {
    pub fn new(database: Database, cleaner: OssFileCleaner) -> Self {
        Self { database, cleaner }
    }
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.database.verify_runtime_role().await?;
        let authorized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=36 AND success) AND current_user='sandbox_worker' AND COALESCE(has_function_privilege(current_user,to_regprocedure('public.sandbox_file_cleanup_candidates(integer)'),'EXECUTE'),false)")
            .fetch_one(&self.database.pool).await?;
        anyhow::ensure!(
            authorized,
            "file cleanup requires the dedicated worker identity and queue grant"
        );
        self.cleaner.check_credentials().await?;
        loop {
            tokio::select! { biased; _=shutdown.cancelled()=>return Ok(()), _=tokio::time::sleep(Duration::from_secs(5))=>{} }
            let candidates = tokio::select! { biased; _=shutdown.cancelled()=>return Ok(()), result=self.database.file_cleanup_candidates()=>result };
            let candidates = match candidates {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(code = e.code, "file cleanup queue unavailable");
                    continue;
                }
            };
            for (tenant, id) in candidates {
                let batch = tokio::select! { biased; _=shutdown.cancelled()=>return Ok(()), result=self.database.prepare_file_cleanup(tenant,id)=>result };
                let batch = match batch {
                    Ok(Some(v)) => v,
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(transfer_id=%id,code=e.code,"file cleanup prerequisites unavailable");
                        continue;
                    }
                };
                for part in &batch.parts {
                    let receipt = tokio::select! { biased; _=shutdown.cancelled()=>return Ok(()), result=self.cleaner.delete_part(part)=>result };
                    let receipt = match receipt {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::warn!(transfer_id=%id,part_index=part.identity.index,"file cleanup cloud observation failed");
                            break;
                        }
                    };
                    let result = tokio::select! { biased; _=shutdown.cancelled()=>return Ok(()), result=self.database.record_file_part_cleanup(&receipt)=>result };
                    if let Err(e) = result {
                        tracing::warn!(transfer_id=%id,code=e.code,"file cleanup receipt not committed");
                        break;
                    }
                }
                if batch.writer_outcome_unknown {
                    tracing::warn!(transfer_id=%id,"file storage writer outcome unknown; byte budget remains held");
                    continue;
                }
                let result = tokio::select! { biased; _=shutdown.cancelled()=>return Ok(()), result=self.database.finish_file_cleanup(tenant,id)=>result };
                if let Err(e) = result {
                    tracing::warn!(transfer_id=%id,code=e.code,"file cleanup finalization deferred");
                }
            }
        }
    }
}
