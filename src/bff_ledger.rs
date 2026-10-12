//! Durable browser login/session state; only narrow capability functions are granted.
use crate::{db::Database, error::ApiError};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
pub(crate) struct LoginChallenge {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub cluster_epoch: Uuid,
    pub payload: Vec<u8>,
}
#[derive(FromRow)]
pub(crate) struct SessionRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub cluster_epoch: Uuid,
    pub issuer: String,
    pub subject: String,
    pub csrf_hash: String,
    pub payload: Vec<u8>,
    pub status: String,
    pub version: i64,
    pub access_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
}
impl Database {
    pub(crate) async fn browser_epoch(&self) -> Result<Uuid, ApiError> {
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }
    pub(crate) async fn browser_login_create(
        &self,
        id: Uuid,
        tenant: Uuid,
        epoch: Uuid,
        state: &str,
        binding: &str,
        payload: &[u8],
    ) -> Result<bool, ApiError> {
        Ok(
            sqlx::query_scalar("SELECT sandbox_browser_login_create($1,$2,$3,$4,$5,$6)")
                .bind(id)
                .bind(tenant)
                .bind(epoch)
                .bind(state.to_owned())
                .bind(binding.to_owned())
                .bind(payload.to_vec())
                .fetch_one(&self.pool)
                .await?,
        )
    }
    pub(crate) async fn browser_login_consume(
        &self,
        state: &str,
        binding: &str,
    ) -> Result<Option<LoginChallenge>, ApiError> {
        // Autocommit consumes the challenge before any identity-provider request.
        Ok(
            sqlx::query_as("SELECT * FROM sandbox_browser_login_consume($1,$2)")
                .bind(state.to_owned())
                .bind(binding.to_owned())
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn browser_session_create(
        &self,
        challenge: Uuid,
        id: Uuid,
        cookie: String,
        csrf: String,
        issuer: String,
        subject: String,
        expiry: DateTime<Utc>,
        payload: Vec<u8>,
    ) -> Result<bool, ApiError> {
        let result =
            sqlx::query_scalar("SELECT sandbox_browser_session_create($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind(challenge)
                .bind(id)
                .bind(cookie)
                .bind(csrf)
                .bind(issuer)
                .bind(subject)
                .bind(expiry)
                .bind(payload)
                .bind(crate::error::request_id())
                .fetch_one(&self.pool)
                .await;
        match result {
            Err(sqlx::Error::Database(ref e)) if e.code().as_deref() == Some("42501") => Ok(false),
            v => v.map_err(Into::into),
        }
    }
    pub(crate) async fn browser_session_read(
        &self,
        cookie: &str,
        touch: bool,
    ) -> Result<Option<SessionRecord>, ApiError> {
        Ok(
            sqlx::query_as("SELECT * FROM sandbox_browser_session_read($1,$2)")
                .bind(cookie.to_owned())
                .bind(touch)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    pub(crate) async fn browser_refresh_begin(
        &self,
        cookie: &str,
        version: i64,
    ) -> Result<Option<SessionRecord>, ApiError> {
        Ok(
            sqlx::query_as("SELECT * FROM sandbox_browser_refresh_begin($1,$2)")
                .bind(cookie.to_owned())
                .bind(version)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    pub(crate) fn browser_refresh_finish(
        &self,
        cookie: &str,
        version: i64,
        expiry: DateTime<Utc>,
        payload: &[u8],
    ) -> futures_util::future::BoxFuture<'static, Result<bool, ApiError>> {
        let pool = self.pool.clone();
        let cookie = cookie.to_owned();
        let payload = payload.to_vec();
        Box::pin(async move {
            Ok(
                sqlx::query_scalar("SELECT sandbox_browser_refresh_finish($1,$2,$3,$4)")
                    .bind(cookie)
                    .bind(version)
                    .bind(expiry)
                    .bind(payload)
                    .fetch_one(&pool)
                    .await?,
            )
        })
    }
    pub(crate) async fn browser_session_revoke(
        &self,
        cookie: String,
        csrf: Option<String>,
        version: Option<i64>,
    ) -> Result<bool, ApiError> {
        Ok(
            sqlx::query_scalar("SELECT sandbox_browser_session_revoke($1,$2,$3,$4)")
                .bind(cookie)
                .bind(csrf)
                .bind(version)
                .bind(crate::error::request_id())
                .fetch_one(&self.pool)
                .await?,
        )
    }
}
