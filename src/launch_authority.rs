//! Owner-only activation of the reviewed CRI guard protocol. Generations born
//! before activation receive no retrospective non-execution proof.
use anyhow::{Context, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{db::Database, nodeguard::protocol::valid_sha256};

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuardContractRequest {
    Activate {
        contract_id: Uuid,
        cluster_epoch: Uuid,
        certification_report_sha256: String,
        runtime_node_ids: Vec<Uuid>,
        approval_reference: String,
    },
    Revoke {
        contract_id: Uuid,
        approval_reference: String,
    },
}
impl GuardContractRequest {
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 65536,
            "guard contract exceeds 64 KiB"
        );
        let request: Self = serde_json::from_slice(bytes).context("invalid guard contract JSON")?;
        let (id, reference) = match &request {
            Self::Activate {
                contract_id,
                cluster_epoch,
                certification_report_sha256,
                runtime_node_ids,
                approval_reference,
            } => {
                ensure!(
                    !cluster_epoch.is_nil() && valid_sha256(certification_report_sha256),
                    "invalid contract epoch or report digest"
                );
                ensure!(
                    !runtime_node_ids.is_empty()
                        && runtime_node_ids.len() <= 1024
                        && runtime_node_ids.iter().all(|id| !id.is_nil()),
                    "exact reviewed runtime node set required"
                );
                let mut unique = runtime_node_ids.clone();
                unique.sort_unstable();
                unique.dedup();
                ensure!(
                    unique.len() == runtime_node_ids.len(),
                    "duplicate runtime node"
                );
                (contract_id, approval_reference)
            }
            Self::Revoke {
                contract_id,
                approval_reference,
            } => (contract_id, approval_reference),
        };
        ensure!(
            !id.is_nil()
                && !reference.trim().is_empty()
                && reference.len() <= 256
                && !reference.chars().any(char::is_control),
            "contract ID and bounded approval reference required"
        );
        Ok(request)
    }
}
#[derive(Serialize)]
pub struct GuardContractReceipt {
    pub contract_id: Uuid,
    pub revoked: bool,
    pub valid_until: Option<DateTime<Utc>>,
    pub changed: bool,
}
pub async fn apply_guard_contract(
    db: &Database,
    request: &GuardContractRequest,
) -> anyhow::Result<GuardContractReceipt> {
    let owner: bool = sqlx::query_scalar("SELECT count(*)=3 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY(ARRAY['launch_guard_contracts','launch_guard_contract_revocations','platform_configuration'])")
        .fetch_one(&db.pool).await?;
    ensure!(owner, "guard contract requires the installation owner");
    let mut tx = db.pool.begin().await?;
    let (epoch, safe_mode): (Uuid, bool) = sqlx::query_as(
        "SELECT cluster_epoch,safe_mode FROM platform_configuration WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let receipt = match request {
        GuardContractRequest::Activate {
            contract_id,
            cluster_epoch,
            certification_report_sha256,
            runtime_node_ids,
            approval_reference,
        } => {
            ensure!(
                *cluster_epoch == epoch && safe_mode,
                "activation requires current epoch and safe mode; it never resumes tenant traffic"
            );
            let mut expected = runtime_node_ids.clone();
            expected.sort_unstable();
            let current: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM runtime_nodes WHERE cluster_epoch=$1 AND enabled ORDER BY id FOR SHARE").bind(epoch).fetch_all(&mut *tx).await?;
            ensure!(
                current == expected,
                "reviewed set must exactly cover all currently enabled nodes"
            );
            let expiry: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT CASE WHEN count(*)=$3 THEN min(certification_expires_at) ELSE NULL END FROM (SELECT DISTINCT ON(runtime_node_id) runtime_node_id,certification_expires_at,certification_report_sha256 FROM runtime_node_enrollments WHERE cluster_epoch=$1 AND runtime_node_id=ANY($2) ORDER BY runtime_node_id,certification_reviewed_at DESC,registered_at DESC,id DESC) latest WHERE certification_report_sha256=$4 AND certification_expires_at>clock_timestamp()")
                .bind(epoch).bind(&expected).bind(i64::try_from(expected.len())?).bind(certification_report_sha256).fetch_one(&mut *tx).await?;
            let expiry = expiry.context(
                "all nodes require current reviewed evidence with this exact report digest",
            )?;
            let changed = sqlx::query("INSERT INTO launch_guard_contracts(id,cluster_epoch,protocol,certification_report_sha256,runtime_node_ids,approval_reference,valid_until) VALUES($1,$2,'NODEGUARD_REQUIRED_V1',$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING")
                .bind(contract_id).bind(epoch).bind(certification_report_sha256).bind(&expected).bind(approval_reference).bind(expiry).execute(&mut *tx).await?.rows_affected() == 1;
            let exact: bool = sqlx::query_scalar("SELECT cluster_epoch=$2 AND certification_report_sha256=$3 AND runtime_node_ids=$4 AND approval_reference=$5 AND valid_until=$6 AND NOT EXISTS(SELECT 1 FROM launch_guard_contract_revocations r WHERE r.contract_id=c.id) FROM launch_guard_contracts c WHERE id=$1")
                .bind(contract_id).bind(epoch).bind(certification_report_sha256).bind(&expected).bind(approval_reference).bind(expiry).fetch_one(&mut *tx).await?;
            ensure!(
                exact,
                "contract ID is immutable; renewed evidence requires a new contract ID"
            );
            GuardContractReceipt {
                contract_id: *contract_id,
                revoked: false,
                valid_until: Some(expiry),
                changed,
            }
        }
        GuardContractRequest::Revoke {
            contract_id,
            approval_reference,
        } => {
            let changed = sqlx::query("INSERT INTO launch_guard_contract_revocations(contract_id,approval_reference) VALUES($1,$2) ON CONFLICT(contract_id) DO NOTHING")
                .bind(contract_id).bind(approval_reference).execute(&mut *tx).await?.rows_affected() == 1;
            let exact: bool = sqlx::query_scalar("SELECT approval_reference=$2 FROM launch_guard_contract_revocations WHERE contract_id=$1").bind(contract_id).bind(approval_reference).fetch_one(&mut *tx).await?;
            ensure!(exact, "revocation approval reference is immutable");
            GuardContractReceipt {
                contract_id: *contract_id,
                revoked: true,
                valid_until: None,
                changed,
            }
        }
    };
    tx.commit().await?;
    Ok(receipt)
}
