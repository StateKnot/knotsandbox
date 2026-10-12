//! OAuth access-token validation shared by standalone Keycloak and external OIDC.
//!
//! Supported profiles are RFC 9068 (`typ=at+jwt`, including `client_id` and
//! `jti`) and Keycloak (`typ=JWT` header, signed `typ=Bearer` and `azp` claims).
//! An ID token with a matching audience is deliberately insufficient. Identity
//! validation does not grant tenant access: callers must resolve `(issuer, sub)`
//! and check the current principal/grants in the product database.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::{Mutex, RwLock},
    time::Instant,
};
use url::{Host, Url};

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 128 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const UNKNOWN_KID_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const FAILED_REFRESH_BACKOFF: Duration = Duration::from_secs(5);
#[cfg(test)]
fn diagnose(stage: &'static str, category: &'static str) {
    eprintln!("LOCAL_ACCESS_DIAGNOSTICS stage={stage} category={category}");
}
#[cfg(test)]
fn jwt_category(error: &jsonwebtoken::errors::Error) -> &'static str {
    use jsonwebtoken::errors::ErrorKind as E;
    match error.kind() {
        E::InvalidToken => "INVALID_TOKEN_SHAPE",
        E::InvalidSignature => "INVALID_SIGNATURE",
        E::MissingRequiredClaim(_) => "MISSING_REQUIRED_CLAIM",
        E::InvalidClaimFormat(_) => "INVALID_CLAIM_FORMAT",
        E::ExpiredSignature => "EXPIRED",
        E::InvalidIssuer => "INVALID_ISSUER",
        E::InvalidAudience => "INVALID_AUDIENCE",
        E::InvalidSubject => "INVALID_SUBJECT",
        E::ImmatureSignature => "IMMATURE_SIGNATURE",
        E::InvalidAlgorithm | E::InvalidAlgorithmName | E::MissingAlgorithm => "ALGORITHM",
        E::Json(_) => "JSON_CLAIM_PARSE",
        E::Base64(_) => "BASE64",
        E::Utf8(_) => "UTF8",
        _ => "KEY_OR_PROVIDER",
    }
}
#[cfg(test)]
fn diagnose_unverified_claim_shape(token: &str) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let Some(payload) = token.split('.').nth(1) else {
        return;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return;
    };
    for name in [
        "iss",
        "sub",
        "iat",
        "exp",
        "nbf",
        "typ",
        "azp",
        "client_id",
        "scope",
        "jti",
        "aud",
    ] {
        let kind = match value.get(name) {
            None => "ABSENT",
            Some(serde_json::Value::Null) => "NULL",
            Some(serde_json::Value::String(_)) => "STRING",
            Some(serde_json::Value::Number(_)) => "NUMBER",
            Some(serde_json::Value::Bool(_)) => "BOOL",
            Some(serde_json::Value::Array(_)) => "ARRAY",
            Some(serde_json::Value::Object(_)) => "OBJECT",
        };
        // Unverified shape is diagnostic only, never an identity assertion.
        eprintln!("LOCAL_UNVERIFIED_CLAIM_SHAPE name={name} type={kind}");
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub required_scopes: Vec<String>,
    /// Generic access uses local grants; action scopes additionally cap every
    /// product action by its exact OAuth scope. Chosen by the operator, not JWT.
    #[serde(default)]
    pub scope_profile: ScopeProfile,
    pub jwks_ttl_seconds: u64,
    pub clock_skew_seconds: u64,
    /// Development only: allows HTTP to literal loopback IPs, never hostnames.
    pub allow_loopback_http: bool,
    pub max_token_lifetime_seconds: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeProfile {
    #[default]
    GenericAccess,
    ActionScopes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub scope_profile: ScopeProfile,
    pub expires_at: i64,
}

impl VerifiedIdentity {
    pub fn permits(&self, action: &str) -> bool {
        self.scope_profile == ScopeProfile::GenericAccess
            || self
                .scopes
                .iter()
                .any(|scope| scope == action && scope != "*")
    }
}

/// Errors contain no token, key, response body, or secret-bearing URL.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid authentication configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("invalid access token")]
    InvalidToken,
    #[error("unsupported access token algorithm")]
    UnsupportedAlgorithm,
    #[error("unsupported access token profile")]
    InvalidTokenType,
    #[error("unknown signing key")]
    UnknownKey,
    #[error("signing keys unavailable")]
    JwksUnavailable,
    #[error("invalid signing key document")]
    InvalidJwks,
    #[error("required scope missing")]
    InsufficientScope,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    valid_until: Option<Instant>,
    last_unknown_refresh: Option<Instant>,
    last_failed_refresh: Option<Instant>,
}

impl KeyCache {
    fn fresh(&self, now: Instant) -> bool {
        self.valid_until.is_some_and(|until| now < until)
    }
}

pub struct JwtAuthenticator {
    config: AuthConfig,
    client: Client,
    jwks_url: Url,
    validation: Validation,
    cache: RwLock<KeyCache>,
    refresh: Mutex<()>,
}

#[derive(Clone, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: i64,
    iat: i64,
    nbf: Option<i64>,
    typ: Option<String>,
    client_id: Option<String>,
    azp: Option<String>,
    jti: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    key_ops: Option<Vec<String>>,
    n: Option<String>,
    e: Option<String>,
}

impl JwtAuthenticator {
    /// The single operator-configured issuer; never taken from an unverified request.
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        validate_url(&config.issuer, config.allow_loopback_http, true)?;
        let jwks_url = validate_url(&config.jwks_url, config.allow_loopback_http, false)?;
        if !valid_identifier(&config.audience, 1024) {
            return Err(AuthError::InvalidConfig("audience is empty or invalid"));
        }
        if !(1..=3600).contains(&config.jwks_ttl_seconds) {
            return Err(AuthError::InvalidConfig(
                "JWKS TTL must be 1..=3600 seconds",
            ));
        }
        if config.clock_skew_seconds > 60 {
            return Err(AuthError::InvalidConfig(
                "clock skew must not exceed 60 seconds",
            ));
        }
        if !(1..=3600).contains(&config.max_token_lifetime_seconds) {
            return Err(AuthError::InvalidConfig(
                "token lifetime must be 1..=3600 seconds",
            ));
        }
        if config.required_scopes.is_empty()
            || config.required_scopes.len() > 64
            || config.required_scopes.iter().any(|s| !valid_scope(s))
        {
            return Err(AuthError::InvalidConfig("invalid required scopes"));
        }
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            // A process-level HTTP_PROXY must not silently reroute identity trust.
            .no_proxy()
            .https_only(!config.allow_loopback_http)
            .build()
            .map_err(|_| AuthError::InvalidConfig("cannot create JWKS client"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = config.clock_skew_seconds;
        Ok(Self {
            config,
            client,
            jwks_url,
            validation,
            cache: RwLock::new(KeyCache::default()),
            refresh: Mutex::new(()),
        })
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedIdentity, AuthError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
            return Err(AuthError::InvalidToken);
        }
        let header = decode_header(token).map_err(|error| {
            #[cfg(test)]
            diagnose("JWT_HEADER", jwt_category(&error));
            let _ = error;
            AuthError::InvalidToken
        })?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::UnsupportedAlgorithm);
        }
        // Never follow or use keys supplied by the untrusted token. No critical
        // extensions, nested JWTs, or alternate payload encodings are supported.
        if header.crit.is_some()
            || header.cty.is_some()
            || header.enc.is_some()
            || header.zip.is_some()
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.extras.contains_key("b64")
        {
            #[cfg(test)]
            diagnose("JWT_HEADER", "FORBIDDEN_EXTENSIONS");
            return Err(AuthError::InvalidToken);
        }
        let typ = header.typ.as_deref().ok_or(AuthError::InvalidTokenType)?;
        let standard_profile =
            typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt");
        if !standard_profile && !typ.eq_ignore_ascii_case("JWT") {
            return Err(AuthError::InvalidTokenType);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| valid_identifier(kid, 128))
            .ok_or(AuthError::InvalidToken)?;
        let key = self.signing_key(kid).await?;
        let claims = decode::<Claims>(token, &key, &self.validation)
            .map_err(|error| {
                #[cfg(test)]
                {
                    diagnose("JWT_CLAIMS", jwt_category(&error));
                    if matches!(error.kind(), jsonwebtoken::errors::ErrorKind::Json(_)) {
                        diagnose_unverified_claim_shape(token);
                    }
                }
                let _ = error;
                AuthError::InvalidToken
            })?
            .claims;
        let now = Utc::now().timestamp();
        let skew = self.config.clock_skew_seconds as i64;
        if !valid_identifier(&claims.sub, 1024)
            || claims.iat < 0
            || claims.iat > now.saturating_add(skew)
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > self.config.max_token_lifetime_seconds as i64
            || claims.exp <= now.saturating_sub(skew)
            || claims
                .nbf
                .is_some_and(|nbf| nbf < 0 || nbf >= claims.exp || nbf > now.saturating_add(skew))
        {
            #[cfg(test)]
            diagnose(
                "SIGNED_TIME",
                if !valid_identifier(&claims.sub, 1024) {
                    "SUBJECT_SHAPE"
                } else if claims.iat < 0 {
                    "NEGATIVE_ISSUED_AT"
                } else if claims.iat > now.saturating_add(skew) {
                    "FUTURE_ISSUED_AT"
                } else if claims.exp <= claims.iat {
                    "EXPIRY_ORDER"
                } else if claims.exp.saturating_sub(claims.iat)
                    > self.config.max_token_lifetime_seconds as i64
                {
                    "LIFETIME_LIMIT"
                } else if claims.exp <= now.saturating_sub(skew) {
                    "EXPIRED"
                } else {
                    "NOT_BEFORE"
                },
            );
            return Err(AuthError::InvalidToken);
        }
        // Access-token type checks run on authenticated claims only. The realm
        // must reserve signed typ=Bearer for access tokens, not custom ID claims.
        let client_id = if standard_profile {
            if claims.typ.as_deref().is_some_and(|typ| typ != "Bearer")
                || !claims
                    .jti
                    .as_deref()
                    .is_some_and(|v| valid_identifier(v, 1024))
            {
                return Err(AuthError::InvalidTokenType);
            }
            claims.client_id.as_deref()
        } else {
            if claims.typ.as_deref() != Some("Bearer") {
                return Err(AuthError::InvalidTokenType);
            }
            claims.azp.as_deref()
        }
        .filter(|id| valid_client_id(id))
        .ok_or(AuthError::InvalidTokenType)?;
        if let (Some(client), Some(azp)) = (&claims.client_id, &claims.azp)
            && client != azp
        {
            #[cfg(test)]
            diagnose("SIGNED_PROFILE", "CLIENT_AUTHORIZED_PARTY_MISMATCH");
            return Err(AuthError::InvalidToken);
        }
        let mut scopes = parse_scopes(claims.scope.as_deref())?;
        if self
            .config
            .required_scopes
            .iter()
            .any(|required| !scopes.contains(required))
        {
            return Err(AuthError::InsufficientScope);
        }
        scopes.sort_unstable();
        scopes.dedup();
        Ok(VerifiedIdentity {
            scope_profile: self.config.scope_profile,
            issuer: claims.iss,
            subject: claims.sub,
            client_id: Some(client_id.to_owned()),
            scopes,
            expires_at: claims.exp,
        })
    }

    async fn signing_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        {
            let cache = self.cache.read().await;
            if cache.fresh(Instant::now())
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }
        // Only one network refresh per authenticator is in flight. Other
        // requests recheck the completed refresh before issuing another fetch.
        let _refresh = self.refresh.lock().await;
        {
            let mut cache = self.cache.write().await;
            let now = Instant::now();
            if cache.fresh(now) {
                if let Some(key) = cache.keys.get(kid) {
                    return Ok(key.clone());
                }
                if cache
                    .last_unknown_refresh
                    .is_some_and(|last| now.duration_since(last) < UNKNOWN_KID_REFRESH_INTERVAL)
                {
                    return Err(AuthError::UnknownKey);
                }
                cache.last_unknown_refresh = Some(now);
            }
            if cache
                .last_failed_refresh
                .is_some_and(|last| now.duration_since(last) < FAILED_REFRESH_BACKOFF)
            {
                return Err(AuthError::JwksUnavailable);
            }
        }
        let fetched = self.fetch_keys().await;
        let mut cache = self.cache.write().await;
        match fetched {
            Ok(keys) => {
                cache.keys = keys;
                cache.valid_until =
                    Some(Instant::now() + Duration::from_secs(self.config.jwks_ttl_seconds));
                cache.last_failed_refresh = None;
                let key = cache.keys.get(kid).cloned();
                if key.is_none() {
                    cache.last_unknown_refresh = Some(Instant::now());
                }
                key.ok_or(AuthError::UnknownKey)
            }
            Err(error) => {
                cache.last_failed_refresh = Some(Instant::now());
                // Existing keys are usable only until their original expiry.
                // A failed refresh never extends validity or accepts stale keys.
                Err(error)
            }
        }
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, DecodingKey>, AuthError> {
        let mut response = self
            .client
            .get(self.jwks_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| AuthError::JwksUnavailable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(AuthError::JwksUnavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(AuthError::InvalidJwks);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthError::JwksUnavailable)?
        {
            if chunk.len() > MAX_JWKS_BYTES.saturating_sub(body.len()) {
                return Err(AuthError::InvalidJwks);
            }
            body.extend_from_slice(&chunk);
        }
        let jwks: Jwks = serde_json::from_slice(&body).map_err(|_| AuthError::InvalidJwks)?;
        if jwks.keys.is_empty() || jwks.keys.len() > MAX_JWKS_KEYS {
            return Err(AuthError::InvalidJwks);
        }
        let mut seen = HashSet::new();
        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            let kid = jwk
                .kid
                .filter(|v| valid_identifier(v, 128))
                .ok_or(AuthError::InvalidJwks)?;
            if !seen.insert(kid.clone()) {
                return Err(AuthError::InvalidJwks);
            }
            if jwk.kty != "RSA"
                || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256")
                || jwk.key_use.as_deref().is_some_and(|usage| usage != "sig")
                || jwk
                    .key_ops
                    .as_ref()
                    .is_some_and(|ops| ops.len() != 1 || ops[0] != "verify")
            {
                continue;
            }
            let n = jwk.n.ok_or(AuthError::InvalidJwks)?;
            let e = jwk.e.ok_or(AuthError::InvalidJwks)?;
            // This deployment profile supports common 2048/3072/4096-bit RSA
            // moduli and exponent 65537. Canonical base64url decoding is also
            // checked by the crypto library; the high bit excludes padded weak keys.
            if !matches!(n.len(), 342 | 512 | 683)
                || !matches!(
                    n.as_bytes().first(),
                    Some(b'g'..=b'z' | b'0'..=b'9' | b'-' | b'_')
                )
                || e != "AQAB"
            {
                return Err(AuthError::InvalidJwks);
            }
            let key =
                DecodingKey::from_rsa_components(&n, &e).map_err(|_| AuthError::InvalidJwks)?;
            keys.insert(kid, key);
        }
        if keys.is_empty() {
            return Err(AuthError::InvalidJwks);
        }
        Ok(keys)
    }
}

fn validate_url(value: &str, allow_loopback_http: bool, issuer: bool) -> Result<Url, AuthError> {
    let url = Url::parse(value).map_err(|_| AuthError::InvalidConfig("invalid identity URL"))?;
    if value.len() > 2048
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (issuer && url.query().is_some())
    {
        return Err(AuthError::InvalidConfig("invalid identity URL"));
    }
    let literal_loopback = matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback());
    if url.scheme() != "https"
        && !(url.scheme() == "http" && allow_loopback_http && literal_loopback)
    {
        return Err(AuthError::InvalidConfig(
            "identity URLs require HTTPS; HTTP is limited to explicit loopback development",
        ));
    }
    Ok(url)
}

/// Exact OAuth client contract shared by JWT, registration and owner CLI.
/// The limit counts UTF-8 bytes, never Unicode scalar values.
pub fn valid_client_id(value: &str) -> bool {
    valid_identifier(value, 256)
}

fn valid_identifier(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_length
        && !value.trim().is_empty()
        && !value.chars().any(char::is_control)
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 128
        && scope
            .bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn parse_scopes(scope: Option<&str>) -> Result<Vec<String>, AuthError> {
    let Some(scope) = scope.filter(|scope| !scope.is_empty()) else {
        return Ok(Vec::new());
    };
    if scope.len() > 8192 {
        return Err(AuthError::InvalidToken);
    }
    let scopes: Vec<_> = scope.split(' ').collect();
    if scopes.len() > 64 || scopes.iter().any(|scope| !valid_scope(scope)) {
        return Err(AuthError::InvalidToken);
    }
    Ok(scopes.into_iter().map(str::to_owned).collect())
}
