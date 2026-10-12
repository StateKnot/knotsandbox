use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use uuid::Uuid;

tokio::task_local! { pub static REQUEST_ID: Uuid; }
pub fn request_id() -> Uuid {
    REQUEST_ID
        .try_with(|id| *id)
        .unwrap_or_else(|_| Uuid::new_v4())
}

#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: &'static str,
    pub status: u16,
    pub code: &'static str,
    pub detail: String,
    pub request_id: Uuid,
    pub retryable: bool,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: String,
    pub retryable: bool,
    pub request_id: Uuid,
    /// Internal provenance only; fixed five-byte SQLSTATE, never provider text.
    pub(crate) sqlstate: Option<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
            retryable: status.is_server_error(),
            request_id: request_id(),
            sqlstate: None,
        }
    }

    pub fn invalid(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", detail)
    }

    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "RESOURCE_NOT_FOUND",
            "Resource not found",
        )
    }

    pub fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Permission denied",
        )
    }

    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, detail)
    }

    pub fn with_request_id(mut self, id: Uuid) -> Self {
        self.request_id = id;
        self
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        let id = request_id();
        // SQL statements and bound values can contain tenant data; log only the class/code.
        let database_code = error.as_database_error().and_then(|e| e.code());
        let sqlstate = sqlstate_metadata(database_code.as_deref());
        tracing::error!(request_id = %id, database_code = ?sqlstate, "database operation failed");
        let transient = match &error {
            sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed => true,
            sqlx::Error::Database(_) => database_code.as_deref().is_some_and(|code| {
                code.starts_with("08")
                    || code.starts_with("53")
                    || matches!(
                        code,
                        "40001" | "40P01" | "55P03" | "57014" | "57P01" | "57P02" | "57P03"
                    )
            }),
            _ => false,
        };
        if transient {
            Self { status: StatusCode::SERVICE_UNAVAILABLE, code: "DEPENDENCY_UNAVAILABLE", detail: "Database operation unavailable; retry a mutation only with its original idempotency key".to_owned(), retryable: true, request_id: id, sqlstate }
        } else {
            Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "INTERNAL_ERROR",
                detail: "Request failed; retain the request ID for investigation".to_owned(),
                retryable: false,
                request_id: id,
                sqlstate,
            }
        }
    }
}

fn sqlstate_metadata(code: Option<&str>) -> Option<String> {
    code.filter(|code| {
        code.len() == 5
            && code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
    .map(str::to_owned)
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = Problem {
            kind: format!("urn:sandbox:error:{}", self.code.to_ascii_lowercase()),
            title: self.status.canonical_reason().unwrap_or("Request failed"),
            status: self.status.as_u16(),
            code: self.code,
            detail: self.detail,
            request_id: self.request_id,
            retryable: self.retryable,
        };
        let mut response = (self.status, Json(problem)).into_response();
        if self.retryable {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("2"),
            );
        }
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
        }
        if self.code == "INSUFFICIENT_SCOPE" {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer error=\"insufficient_scope\""),
            );
        }
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        if let Ok(value) = axum::http::HeaderValue::from_str(&self.request_id.to_string()) {
            response.headers_mut().insert("x-request-id", value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlstate_provenance_is_not_part_of_the_problem_response() -> anyhow::Result<()> {
        use http_body_util::BodyExt;

        let mut error = ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Fixed public message",
        );
        error.retryable = false;
        error.sqlstate = Some("P4090".to_owned());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await?.to_bytes();
        let problem: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(problem["code"], "INTERNAL_ERROR");
        assert_eq!(problem["retryable"], false);
        assert!(problem.get("sqlstate").is_none());
        assert!(!String::from_utf8_lossy(&body).contains("P4090"));
        Ok(())
    }

    #[test]
    fn programming_errors_are_not_advertised_as_retryable_database_outages() {
        let bug = ApiError::from(sqlx::Error::ColumnNotFound("private_column".into()));
        assert_eq!(bug.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!bug.retryable);
        assert!(!bug.detail.contains("private_column"));
        let outage = ApiError::from(sqlx::Error::PoolTimedOut);
        assert_eq!(outage.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(outage.retryable);
    }
}
