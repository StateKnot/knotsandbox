use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ApiError;

/// A tenant header selects a scope; it never proves membership or permission.
pub fn tenant_id(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    single_header(headers, "x-tenant-id")?
        .parse()
        .map_err(|_| ApiError::invalid("X-Tenant-ID must be a UUID"))
}

pub fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = single_header(headers, "authorization").map_err(|_| unauthenticated())?;
    let (scheme, token) = value.split_once(' ').ok_or_else(unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(unauthenticated());
    }
    Ok(token)
}

pub fn unauthenticated() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "UNAUTHENTICATED",
        "A valid access token is required",
    )
}

pub fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| ApiError::invalid(format!("{name} is required")))?;
    if values.next().is_some() {
        return Err(ApiError::invalid(format!("{name} must occur once")));
    }
    value
        .to_str()
        .map_err(|_| ApiError::invalid(format!("{name} is invalid")))
}

pub fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = single_header(headers, "idempotency-key")?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(ApiError::invalid(
            "Idempotency-Key must be 1..128 ASCII letters, digits, or -_.:",
        ));
    }
    Ok(value)
}

/// Only one strong, numeric specification ETag is accepted; '*' is unsafe here.
pub fn expected_version(headers: &HeaderMap) -> Result<i64, ApiError> {
    if !headers.contains_key("if-match") {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "PRECONDITION_REQUIRED",
            "If-Match is required",
        ));
    }
    let value = single_header(headers, "if-match")?;
    let number = value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| ApiError::invalid("If-Match must contain one strong numeric ETag"))?;
    let version: i64 = number
        .parse()
        .map_err(|_| ApiError::invalid("Invalid ETag"))?;
    if version < 1 {
        return Err(ApiError::invalid("Invalid ETag"));
    }
    Ok(version)
}

/// Call after parsing a deny_unknown_fields DTO. serde_json's default map is
/// sorted, so equivalent property order produces the same digest.
pub fn request_digest<T: Serialize>(body: &T, expected: Option<i64>) -> Result<Vec<u8>, ApiError> {
    let body =
        serde_json::to_value(body).map_err(|_| ApiError::invalid("Cannot encode request"))?;
    let value = serde_json::json!({"body": body, "expected_version": expected});
    let encoded =
        serde_json::to_vec(&value).map_err(|_| ApiError::invalid("Cannot encode request"))?;
    Ok(Sha256::digest(encoded).to_vec())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn ambiguous_preconditions_and_credentials_are_rejected() {
        let mut headers = HeaderMap::new();
        for bad in ["*", "W/\"1\"", "\"1\",\"2\"", "0", "\"0\"", "\"-1\""] {
            headers.insert("if-match", HeaderValue::from_str(bad).expect("test value"));
            assert!(expected_version(&headers).is_err());
        }
        headers.insert("if-match", HeaderValue::from_static("\"12\""));
        assert_eq!(expected_version(&headers).expect("valid etag"), 12);
        headers.append("authorization", HeaderValue::from_static("Bearer first"));
        headers.append("authorization", HeaderValue::from_static("Bearer second"));
        assert!(bearer(&headers).is_err());
    }

    #[test]
    fn request_property_order_does_not_change_hash_but_precondition_does() {
        let a: serde_json::Value = serde_json::from_str("{\"a\":1,\"b\":2}").expect("json");
        let b: serde_json::Value = serde_json::from_str("{\"b\":2,\"a\":1}").expect("json");
        assert_eq!(
            request_digest(&a, Some(1)).ok(),
            request_digest(&b, Some(1)).ok()
        );
        assert_ne!(
            request_digest(&a, Some(1)).ok(),
            request_digest(&a, Some(2)).ok()
        );
    }
}
