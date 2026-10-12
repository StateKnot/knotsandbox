//! Private acceptance context. This is neither bearer authentication nor a
//! credential: the dedicated automation login and SQL gate must also validate
//! the durable run, live delegation and exact current claim in the same TX.
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::ApiError;

pub(crate) struct AutomationAcceptanceFence {
    pub run_id: Uuid,
    pub lease_owner: String,
    pub lease_token: i64,
    pub dispatch_attempt_id: Uuid,
    pub produced_resource_id: Uuid,
    pub management_key: String,
    pub request_sha256: String,
}

impl AutomationAcceptanceFence {
    pub(crate) fn check_request<T: serde::Serialize>(
        &self,
        request: &T,
        key: &str,
        expected: i64,
    ) -> Result<(), ApiError> {
        if key != self.management_key
            || hex::encode(crate::request::request_digest(request, Some(expected))?)
                != self.request_sha256
        {
            return Err(ApiError::conflict(
                "AUTOMATION_REQUEST_CHANGED",
                "The durable automation request cannot change",
            ));
        }
        Ok(())
    }
    pub(crate) async fn bind(&self, tx: &mut Transaction<'_, Postgres>) -> Result<(), ApiError> {
        sqlx::query("SELECT set_config('app.automation_run_id',$1,true),set_config('app.automation_owner',$2,true),set_config('app.automation_token',$3,true),set_config('app.automation_attempt',$4,true),set_config('app.automation_resource',$5,true),set_config('app.automation_key',$6,true),set_config('app.automation_digest',$7,true)")
            .bind(self.run_id.to_string()).bind(&self.lease_owner)
            .bind(self.lease_token.to_string()).bind(self.dispatch_attempt_id.to_string())
            .bind(self.produced_resource_id.to_string()).bind(&self.management_key)
            .bind(&self.request_sha256).execute(&mut **tx).await?;
        Ok(())
    }
}
