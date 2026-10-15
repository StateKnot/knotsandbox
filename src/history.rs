//! Project-scoped history views. Payloads remain private; cursors are signed,
//! scoped to the requesting principal, and never bypass live authorization.

use std::{collections::HashSet, sync::Arc};

use axum::http::StatusCode;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    db::{Actor, Database, load_instance},
    error::ApiError,
};

const CURSOR_TTL_SECONDS: i64 = 86400;
const MAX_CURSOR_LENGTH: usize = 2048;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKeyInput {
    kid: String,
    key_base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKeysInput {
    active: SigningKeyInput,
    previous: Vec<SigningKeyInput>,
}
struct SigningKey {
    kid: String,
    bytes: Vec<u8>,
}

/// Key material is intentionally neither Debug nor Serialize. A shared,
/// operator-managed key file keeps pagination valid across replicas/restarts.
#[derive(Clone)]
pub struct CursorSigner {
    keys: Arc<Vec<SigningKey>>,
}

impl CursorSigner {
    pub fn from_json(contents: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(contents.len() <= 8192, "Cursor key file exceeds 8 KiB");
        let input: SigningKeysInput = serde_json::from_str(contents)
            .map_err(|_| anyhow::anyhow!("Cursor key file is not a valid key configuration"))?;
        anyhow::ensure!(
            input.previous.len() <= 2,
            "At most two previous cursor keys are allowed"
        );
        let mut ids = HashSet::new();
        let mut keys = Vec::new();
        for entry in std::iter::once(input.active).chain(input.previous) {
            anyhow::ensure!(
                !entry.kid.is_empty()
                    && entry.kid.len() <= 32
                    && entry
                        .kid
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                "Invalid cursor key identifier"
            );
            anyhow::ensure!(
                ids.insert(entry.kid.clone()),
                "Duplicate cursor key identifier"
            );
            let bytes = STANDARD
                .decode(entry.key_base64)
                .map_err(|_| anyhow::anyhow!("Cursor signing key is not valid base64"))?;
            anyhow::ensure!(
                (32..=64).contains(&bytes.len()),
                "Cursor signing keys must contain 32 to 64 bytes"
            );
            keys.push(SigningKey {
                kid: entry.kid,
                bytes,
            });
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    pub(crate) fn encode_payload<T: Serialize>(&self, cursor: &T) -> Result<String, ApiError> {
        let key = &self.keys[0];
        let payload = serde_json::to_vec(cursor).map_err(|_| invalid_cursor())?;
        let unsigned = format!("{}.{}", key.kid, URL_SAFE_NO_PAD.encode(payload));
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.bytes).map_err(|_| invalid_cursor())?;
        mac.update(unsigned.as_bytes());
        Ok(format!(
            "{unsigned}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    pub(crate) fn decode_payload<T: serde::de::DeserializeOwned>(
        &self,
        encoded: &str,
    ) -> Result<T, ApiError> {
        if encoded.len() > MAX_CURSOR_LENGTH {
            return Err(invalid_cursor());
        }
        let mut parts = encoded.split('.');
        let (Some(kid), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid_cursor());
        };
        let key = self
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(invalid_cursor)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| invalid_cursor())?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.bytes).map_err(|_| invalid_cursor())?;
        mac.update(format!("{kid}.{payload}").as_bytes());
        mac.verify_slice(&signature).map_err(|_| invalid_cursor())?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| invalid_cursor())?;
        serde_json::from_slice(&bytes).map_err(|_| invalid_cursor())
    }

    fn encode(&self, cursor: &Cursor) -> Result<String, ApiError> {
        self.encode_payload(cursor)
    }

    fn decode(&self, encoded: &str, now: DateTime<Utc>) -> Result<Cursor, ApiError> {
        let cursor: Cursor = self.decode_payload(encoded)?;
        if cursor.version != 1
            || cursor.expires_at <= now
            || cursor.expires_at > cursor.cutoff + Duration::seconds(CURSOR_TTL_SECONDS)
            || cursor.cutoff > now
            || cursor.after_time > cursor.cutoff
        {
            return Err(invalid_cursor());
        }
        Ok(cursor)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    pub project_id: Uuid,
    pub instance_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    kind: String,
    tenant_id: Uuid,
    principal_id: Uuid,
    project_id: Uuid,
    instance_id: Option<Uuid>,
    limit: i64,
    cutoff: DateTime<Utc>,
    after_time: DateTime<Utc>,
    after_id: Uuid,
    expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<PinnedHistoryRow>,
}

/// A signed selection records absence as a fact. A later page must not turn a
/// first-page miss into a newly committed row merely because its clock is old.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", content = "id", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PinnedHistoryRow {
    NotCaptured,
    Captured(Uuid),
}

pub(crate) struct Window {
    pub(crate) limit: i64,
    pub(crate) cutoff: DateTime<Utc>,
    pub(crate) after_time: Option<DateTime<Utc>>,
    pub(crate) after_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
    pub(crate) snapshot: Option<PinnedHistoryRow>,
}
impl Window {
    pub(crate) fn new(
        query: &HistoryQuery,
        actor: &Actor,
        kind: &str,
        signer: &CursorSigner,
        now: DateTime<Utc>,
    ) -> Result<Self, ApiError> {
        let limit = query.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(ApiError::invalid("limit must be between 1 and 100"));
        }
        if let Some(token) = &query.cursor {
            let cursor = signer.decode(token, now)?;
            if cursor.kind != kind
                || cursor.tenant_id != actor.tenant_id
                || cursor.principal_id != actor.principal_id
                || cursor.project_id != query.project_id
                || cursor.instance_id != query.instance_id
                || cursor.limit != limit
            {
                return Err(invalid_cursor());
            }
            Ok(Self {
                limit,
                cutoff: cursor.cutoff,
                after_time: Some(cursor.after_time),
                after_id: Some(cursor.after_id),
                expires_at: cursor.expires_at,
                snapshot: cursor.snapshot,
            })
        } else {
            Ok(Self {
                limit,
                cutoff: now,
                after_time: None,
                after_id: None,
                expires_at: now + Duration::seconds(CURSOR_TTL_SECONDS),
                snapshot: None,
            })
        }
    }
    pub(crate) fn page<T: HistoryRow>(
        &self,
        mut rows: Vec<T>,
        query: &HistoryQuery,
        actor: &Actor,
        kind: &str,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<T>, ApiError> {
        let more = rows.len() > self.limit as usize;
        rows.truncate(self.limit as usize);
        let next_cursor = if more {
            let row = rows.last().ok_or_else(invalid_cursor)?;
            Some(signer.encode(&Cursor {
                version: 1,
                kind: kind.into(),
                tenant_id: actor.tenant_id,
                principal_id: actor.principal_id,
                project_id: query.project_id,
                instance_id: query.instance_id,
                limit: self.limit,
                cutoff: self.cutoff,
                after_time: row.time(),
                after_id: row.id(),
                expires_at: self.expires_at,
                snapshot: self.snapshot.clone(),
            })?)
        } else {
            None
        };
        Ok(HistoryPage {
            items: rows,
            next_cursor,
            cutoff: self.cutoff,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub cutoff: DateTime<Utc>,
}
pub(crate) trait HistoryRow {
    fn time(&self) -> DateTime<Utc>;
    fn id(&self) -> Uuid;
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct OperationRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub kind: String,
    pub status: String,
    pub stage: String,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
impl HistoryRow for OperationRecord {
    fn time(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct EventRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub aggregate_id: Uuid,
    pub aggregate_version: i64,
    pub event_type: String,
    pub schema_version: i32,
    pub operation_id: Option<Uuid>,
    pub request_id: Uuid,
    pub occurred_at: DateTime<Utc>,
}
impl HistoryRow for EventRecord {
    fn time(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub actor_principal_id: Option<Uuid>,
    pub request_id: Uuid,
    pub operation_id: Option<Uuid>,
    pub resource_id: Option<Uuid>,
    pub action: String,
    pub outcome: String,
    pub occurred_at: DateTime<Utc>,
}
impl HistoryRow for AuditRecord {
    fn time(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}

impl Database {
    pub async fn list_operations(
        &self,
        actor: &Actor,
        query: &HistoryQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<OperationRecord>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let window = authorize_window(&mut tx, actor, query, "operations:read", signer).await?;
        let rows=sqlx::query_as::<_,OperationRecord>("SELECT id,tenant_id,project_id,instance_id,workspace_id,kind,status,stage,attempts,created_at,updated_at,completed_at FROM operations WHERE tenant_id=$1 AND project_id=$2 AND ($3::uuid IS NULL OR instance_id=$3) AND created_at<=$4 AND ($5::timestamptz IS NULL OR (created_at,id)<($5,$6)) ORDER BY created_at DESC,id DESC LIMIT $7")
            .bind(actor.tenant_id).bind(query.project_id).bind(query.instance_id).bind(window.cutoff).bind(window.after_time).bind(window.after_id).bind(window.limit+1).fetch_all(&mut *tx).await?;
        let result = window.page(rows, query, actor, "operations:read", signer)?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn list_events(
        &self,
        actor: &Actor,
        query: &HistoryQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<EventRecord>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let window = authorize_window(&mut tx, actor, query, "events:read", signer).await?;
        let rows=sqlx::query_as::<_,EventRecord>("SELECT e.id,e.tenant_id,e.project_id,e.aggregate_id,e.aggregate_version,e.event_type,e.schema_version,e.operation_id,e.request_id,e.occurred_at FROM domain_events e WHERE e.tenant_id=$1 AND e.project_id=$2 AND ($3::uuid IS NULL OR e.aggregate_id=$3 OR EXISTS(SELECT 1 FROM operations o WHERE o.tenant_id=e.tenant_id AND o.id=e.operation_id AND o.instance_id=$3)) AND e.occurred_at<=$4 AND ($5::timestamptz IS NULL OR (e.occurred_at,e.id)<($5,$6)) ORDER BY e.occurred_at DESC,e.id DESC LIMIT $7")
            .bind(actor.tenant_id).bind(query.project_id).bind(query.instance_id).bind(window.cutoff).bind(window.after_time).bind(window.after_id).bind(window.limit+1).fetch_all(&mut *tx).await?;
        let result = window.page(rows, query, actor, "events:read", signer)?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn list_audit_records(
        &self,
        actor: &Actor,
        query: &HistoryQuery,
        signer: &CursorSigner,
    ) -> Result<HistoryPage<AuditRecord>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let window = authorize_window(&mut tx, actor, query, "audit:read", signer).await?;
        let rows=sqlx::query_as::<_,AuditRecord>("SELECT a.id,a.tenant_id,a.project_id,a.actor_principal_id,a.request_id,a.operation_id,a.resource_id,a.action,a.outcome,a.occurred_at FROM audit_events a WHERE a.tenant_id=$1 AND a.project_id=$2 AND ($3::uuid IS NULL OR a.resource_id=$3 OR EXISTS(SELECT 1 FROM operations o WHERE o.tenant_id=a.tenant_id AND o.id=a.operation_id AND o.instance_id=$3)) AND a.occurred_at<=$4 AND ($5::timestamptz IS NULL OR (a.occurred_at,a.id)<($5,$6)) ORDER BY a.occurred_at DESC,a.id DESC LIMIT $7")
            .bind(actor.tenant_id).bind(query.project_id).bind(query.instance_id).bind(window.cutoff).bind(window.after_time).bind(window.after_id).bind(window.limit+1).fetch_all(&mut *tx).await?;
        let result = window.page(rows, query, actor, "audit:read", signer)?;
        tx.commit().await?;
        Ok(result)
    }
}

pub(crate) async fn authorize_window(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    query: &HistoryQuery,
    action: &str,
    signer: &CursorSigner,
) -> Result<Window, ApiError> {
    Database::authorize_resource(tx, actor, query.project_id, action).await?;
    if let Some(instance) = query.instance_id {
        let instance = load_instance(tx, actor.tenant_id, instance, false).await?;
        if instance.project_id != query.project_id {
            return Err(ApiError::not_found());
        }
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    Window::new(query, actor, action, signer, now)
}
fn invalid_cursor() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "INVALID_CURSOR",
        "Cursor is invalid, expired or does not match this request",
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(kid: &str, byte: u8) -> serde_json::Value {
        json!({"kid":kid,"key_base64":STANDARD.encode([byte;32])})
    }
    fn signer(active: &str, previous: Vec<serde_json::Value>) -> CursorSigner {
        CursorSigner::from_json(
            &json!({"active":key(active,if active=="old" {1}else{2}),"previous":previous})
                .to_string(),
        )
        .unwrap()
    }
    fn cursor(now: DateTime<Utc>) -> Cursor {
        Cursor {
            version: 1,
            kind: "audit:read".into(),
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: None,
            limit: 50,
            cutoff: now,
            after_time: now,
            after_id: Uuid::new_v4(),
            expires_at: now + Duration::days(1),
            snapshot: None,
        }
    }
    #[test]
    fn cursor_tampering_expiry_and_removed_keys_are_rejected_while_rotation_accepts_old_signatures()
    {
        let now = Utc::now();
        let old = signer("old", vec![]);
        let value = cursor(now);
        let token = old.encode(&value).unwrap();
        let rotated = signer("new", vec![key("old", 1)]);
        assert_eq!(
            rotated.decode(&token, now).unwrap().tenant_id,
            value.tenant_id
        );
        assert!(signer("new", vec![]).decode(&token, now).is_err());
        assert!(rotated.decode(&token, now + Duration::days(1)).is_err());
        assert!(rotated.encode(&value).unwrap().starts_with("new."));
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        let mut changed: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
        changed["tenant_id"] = json!(Uuid::new_v4());
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap());
        assert!(rotated.decode(&parts.join("."), now).is_err());
        assert!(rotated.decode(&format!("{token}.extra"), now).is_err());
        assert!(
            rotated
                .decode(&"x".repeat(MAX_CURSOR_LENGTH + 1), now)
                .is_err()
        );
    }
    #[test]
    fn cursor_scope_is_bound_to_actor_filter_kind_and_page_size() {
        let now = Utc::now();
        let signer = signer("new", vec![]);
        let value = cursor(now);
        let actor = Actor {
            authorization: None,
            tenant_id: value.tenant_id,
            principal_id: value.principal_id,
            request_id: Uuid::new_v4(),
        };
        let query = HistoryQuery {
            project_id: value.project_id,
            instance_id: None,
            limit: Some(50),
            cursor: Some(signer.encode(&value).unwrap()),
        };
        assert!(Window::new(&query, &actor, "audit:read", &signer, now).is_ok());
        assert!(Window::new(&query, &actor, "events:read", &signer, now).is_err());
        for modified in [
            HistoryQuery {
                project_id: Uuid::new_v4(),
                ..query.clone()
            },
            HistoryQuery {
                instance_id: Some(Uuid::new_v4()),
                ..query.clone()
            },
            HistoryQuery {
                limit: Some(51),
                ..query.clone()
            },
        ] {
            assert!(Window::new(&modified, &actor, "audit:read", &signer, now).is_err());
        }
        let other_actor = Actor {
            authorization: None,
            principal_id: Uuid::new_v4(),
            ..actor
        };
        assert!(Window::new(&query, &other_actor, "audit:read", &signer, now).is_err());
    }
    #[test]
    fn invalid_key_configuration_never_echoes_key_material() {
        for value in [
            json!({"active":{"kid":"new","key_base64":"SECRET-MARKER"},"previous":[]}),
            json!({"active":key("new",2),"previous":[key("new",1)]}),
            json!({"active":{"kid":"invalid.kid","key_base64":"SECRET-MARKER"},"previous":[]}),
            json!({"active":{"kid":"new","key_base64":STANDARD.encode([0;31])},"previous":[]}),
        ] {
            let Err(error) = CursorSigner::from_json(&value.to_string()) else {
                panic!("Invalid config accepted")
            };
            assert!(!error.to_string().contains("SECRET-MARKER"));
        }
    }

    #[test]
    fn signed_row_selection_distinguishes_missing_from_a_fixed_row() {
        let now = Utc::now();
        let signer = signer("new", vec![]);
        let mut value = cursor(now);
        // Absence is explicit and survives signing; it cannot be replaced by a
        // read-time query for a row that committed after the first page.
        value.snapshot = Some(PinnedHistoryRow::NotCaptured);
        let token = signer.encode(&value).unwrap();
        assert!(token.len() <= MAX_CURSOR_LENGTH);
        assert_eq!(
            signer.decode(&token, now).unwrap().snapshot,
            Some(PinnedHistoryRow::NotCaptured)
        );
        let id = Uuid::new_v4();
        value.snapshot = Some(PinnedHistoryRow::Captured(id));
        let token = signer.encode(&value).unwrap();
        assert_eq!(
            signer.decode(&token, now).unwrap().snapshot,
            Some(PinnedHistoryRow::Captured(id))
        );
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
        payload["snapshot"] = json!({"state":"NOT_CAPTURED"});
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        assert!(signer.decode(&parts.join("."), now).is_err());
    }
}
