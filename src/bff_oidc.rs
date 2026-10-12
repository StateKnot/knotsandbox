//! Confidential-client OIDC flow. This module never accepts a caller-selected
//! issuer/endpoint, retries a code or refresh exchange, or exports tokens to HTTP.
use crate::auth::{JwtAuthenticator, VerifiedIdentity};
use chrono::{Duration as ChronoDuration, Utc};
use openidconnect::{
    AccessTokenHash, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreTokenResponse, CoreTokenType,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::Instant;
use url::Url;

type Client = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
#[cfg(test)]
fn diagnose(stage: &'static str, category: &'static str) {
    // Classifiers are static allowlists; never format upstream error text,
    // tokens, claims, HTTP bodies, requests or URLs, even in local test logs.
    eprintln!("LOCAL_OIDC_DIAGNOSTICS stage={stage} category={category}");
}
#[cfg(test)]
fn auth_category(error: &crate::auth::AuthError) -> &'static str {
    use crate::auth::AuthError::*;
    match error {
        InvalidConfig(_) => "INVALID_CONFIG",
        InvalidToken => "INVALID_TOKEN",
        UnsupportedAlgorithm => "UNSUPPORTED_ALGORITHM",
        InvalidTokenType => "INVALID_TOKEN_TYPE",
        UnknownKey => "UNKNOWN_KEY",
        JwksUnavailable => "JWKS_UNAVAILABLE",
        InvalidJwks => "INVALID_JWKS",
        InsufficientScope => "INSUFFICIENT_SCOPE",
    }
}
#[cfg(test)]
fn id_category(error: &openidconnect::ClaimsVerificationError) -> &'static str {
    use openidconnect::{ClaimsVerificationError as C, SignatureVerificationError as S};
    match error {
        C::Expired(_) => "EXPIRED",
        C::InvalidAudience(_) => "INVALID_AUDIENCE",
        C::InvalidAuthContext(_) => "INVALID_AUTH_CONTEXT",
        C::InvalidAuthTime(_) => "INVALID_AUTH_TIME",
        C::InvalidIssuer(_) => "INVALID_ISSUER",
        C::InvalidNonce(_) => "INVALID_NONCE",
        C::InvalidSubject(_) => "INVALID_SUBJECT",
        C::Other(_) => "OTHER_CLAIMS",
        C::Unsupported(_) => "UNSUPPORTED_CLAIMS",
        C::SignatureVerification(signature) => match signature {
            S::AmbiguousKeyId(_) => "SIGNATURE_AMBIGUOUS_KEY",
            S::CryptoError(_) => "SIGNATURE_CRYPTO",
            S::DisallowedAlg(_) => "SIGNATURE_DISALLOWED_ALG",
            S::InvalidKey(_) => "SIGNATURE_INVALID_KEY",
            S::NoMatchingKey => "SIGNATURE_NO_MATCHING_KEY",
            S::NoSignature => "SIGNATURE_MISSING",
            S::UnsupportedAlg(_) => "SIGNATURE_UNSUPPORTED_ALG",
            _ => "SIGNATURE_OTHER",
        },
        _ => "UNKNOWN_CLAIMS_CATEGORY",
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSettings {
    pub issuer: String,
    pub authorization_url: String,
    pub token_url: String,
    pub jwks_url: String,
    pub client_id: String,
    pub public_origin: String,
    pub scopes: Vec<String>,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcError {
    #[error("invalid browser identity configuration")]
    Configuration,
    #[error("browser identity provider unavailable")]
    Unavailable,
    #[error("browser identity exchange rejected; begin a new login")]
    Rejected,
    #[error("browser identity concurrency limit reached")]
    Busy,
}
/// Private persisted login values; encrypt before writing to PostgreSQL.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSecrets {
    pub verifier: String,
    pub nonce: String,
}
pub struct LoginRequest {
    pub authorization_url: String,
    pub state: String,
    pub secrets: LoginSecrets,
}
/// Persist only as session AEAD ciphertext. No Debug implementation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub nonce: String,
}
pub struct VerifiedBrowserTokens {
    pub tokens: BrowserTokens,
    pub identity: VerifiedIdentity,
}
pub struct BrowserOidc {
    settings: OidcSettings,
    secret: String,
    http: reqwest::Client,
    cache: RwLock<Option<(Instant, Arc<Client>)>>,
    refresh: Mutex<()>,
    permits: Semaphore,
}
fn endpoint(value: &str, origin: bool, allow_loopback: bool) -> Result<Url, OidcError> {
    let u = Url::parse(value).map_err(|_| OidcError::Configuration)?;
    let loopback = matches!(u.host(),Some(url::Host::Ipv4(v)) if v.is_loopback())
        || matches!(u.host(),Some(url::Host::Ipv6(v)) if v.is_loopback());
    if value.len() > 2048
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || !(u.scheme() == "https" || (allow_loopback && loopback && u.scheme() == "http"))
        || (origin && (u.path() != "/" || u.origin().ascii_serialization() != value))
    {
        return Err(OidcError::Configuration);
    }
    Ok(u)
}
impl BrowserOidc {
    #[cfg(test)]
    pub(crate) fn test_transport(
        settings: OidcSettings,
        secret: String,
    ) -> Result<Self, OidcError> {
        Self::with_transport(settings, secret, true)
    }
    pub fn new(settings: OidcSettings, client_secret: String) -> Result<Self, OidcError> {
        Self::with_transport(settings, client_secret, false)
    }
    fn with_transport(
        settings: OidcSettings,
        secret: String,
        allow_loopback: bool,
    ) -> Result<Self, OidcError> {
        for v in [
            &settings.issuer,
            &settings.authorization_url,
            &settings.token_url,
            &settings.jwks_url,
        ] {
            endpoint(v, false, allow_loopback)?;
        }
        endpoint(&settings.public_origin, true, allow_loopback)?;
        if secret.len() < 32
            || secret.len() > 4096
            || secret.chars().any(char::is_control)
            || settings.client_id.is_empty()
            || settings.client_id.len() > 256
            || settings.client_id.chars().any(char::is_control)
            || settings.scopes.is_empty()
            || settings.scopes.len() > 64
            || !settings.scopes.iter().any(|s| s == "openid")
            || settings.scopes.iter().collect::<BTreeSet<_>>().len() != settings.scopes.len()
            || settings.scopes.iter().any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
            })
        {
            return Err(OidcError::Configuration);
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!allow_loopback)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| OidcError::Configuration)?;
        Ok(Self {
            settings,
            secret,
            http,
            cache: RwLock::new(None),
            refresh: Mutex::new(()),
            permits: Semaphore::new(16),
        })
    }
    pub fn settings(&self) -> &OidcSettings {
        &self.settings
    }
    fn client(&self, jwks: CoreJsonWebKeySet) -> Result<Client, OidcError> {
        Ok(CoreClient::new(
            ClientId::new(self.settings.client_id.clone()),
            IssuerUrl::new(self.settings.issuer.clone()).map_err(|_| OidcError::Configuration)?,
            jwks,
        )
        .set_auth_uri(
            AuthUrl::new(self.settings.authorization_url.clone())
                .map_err(|_| OidcError::Configuration)?,
        )
        .set_token_uri(
            TokenUrl::new(self.settings.token_url.clone()).map_err(|_| OidcError::Configuration)?,
        )
        .set_client_secret(ClientSecret::new(self.secret.clone()))
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/auth/callback", self.settings.public_origin))
                .map_err(|_| OidcError::Configuration)?,
        ))
    }
    pub fn begin(&self) -> Result<LoginRequest, OidcError> {
        // A login redirect does not need network I/O; validation is mandatory at exchange.
        let client = self.client(CoreJsonWebKeySet::new(Vec::new()))?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in self
            .settings
            .scopes
            .iter()
            .filter(|s| s.as_str() != "openid")
        {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, state, nonce) = request.url();
        Ok(LoginRequest {
            authorization_url: url.to_string(),
            state: state.secret().clone(),
            secrets: LoginSecrets {
                verifier: verifier.secret().clone(),
                nonce: nonce.secret().clone(),
            },
        })
    }
    async fn verified_client(&self) -> Result<Arc<Client>, OidcError> {
        if let Some((until, client)) = &*self.cache.read().await
            && *until > Instant::now()
        {
            return Ok(client.clone());
        }
        let _refresh = tokio::time::timeout(Duration::from_secs(6), self.refresh.lock())
            .await
            .map_err(|_| OidcError::Unavailable)?;
        if let Some((until, client)) = &*self.cache.read().await
            && *until > Instant::now()
        {
            return Ok(client.clone());
        }
        let response = self
            .http
            .get(&self.settings.jwks_url)
            .send()
            .await
            .map_err(|_| OidcError::Unavailable)?;
        if !response.status().is_success() {
            return Err(OidcError::Unavailable);
        }
        let bytes = bounded(response, 131072).await?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| OidcError::Unavailable)?;
        let keys = value
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .ok_or(OidcError::Unavailable)?;
        if keys.is_empty() || keys.len() > 32 {
            return Err(OidcError::Unavailable);
        }
        let mut ids = BTreeSet::new();
        for key in keys {
            let id = key
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .ok_or(OidcError::Unavailable)?;
            if id.is_empty()
                || id.len() > 128
                || !ids.insert(id)
                || key.get("d").is_some()
                || key.get("k").is_some()
            {
                return Err(OidcError::Unavailable);
            }
        }
        let jwks = serde_json::from_slice(&bytes).map_err(|_| OidcError::Unavailable)?;
        let client = Arc::new(self.client(jwks)?);
        *self.cache.write().await =
            Some((Instant::now() + Duration::from_secs(60), client.clone()));
        Ok(client)
    }
    fn exchange_http(
        &self,
        request: openidconnect::HttpRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<openidconnect::HttpResponse, OidcError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            if request.method() != reqwest::Method::POST
                || request.uri().to_string() != self.settings.token_url
                || request.body().len() > 65536
            {
                return Err(OidcError::Rejected);
            }
            let (parts, body) = request.into_parts();
            let response = self
                .http
                .post(&self.settings.token_url)
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|_| OidcError::Unavailable)?;
            if response.status().is_redirection() {
                return Err(OidcError::Rejected);
            }
            let status = response.status();
            let headers = response.headers().clone();
            let body = bounded(response, 131072).await?;
            let mut result = openidconnect::HttpResponse::new(body);
            *result.status_mut() = status;
            *result.headers_mut() = headers;
            Ok(result)
        })
    }
    pub async fn exchange(
        &self,
        code: String,
        login: &LoginSecrets,
        auth: &JwtAuthenticator,
    ) -> Result<VerifiedBrowserTokens, OidcError> {
        if code.is_empty()
            || code.len() > 4096
            || code.chars().any(char::is_control)
            || !(43..=128).contains(&login.verifier.len())
            || login.nonce.is_empty()
            || login.nonce.len() > 256
        {
            return Err(OidcError::Rejected);
        }
        let _permit = self.permits.try_acquire().map_err(|_| OidcError::Busy)?;
        let client = self.verified_client().await.inspect_err(|_| {
            #[cfg(test)]
            diagnose("CODE_JWKS", "CLIENT_UNAVAILABLE");
        })?;
        let response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(login.verifier.clone()))
            .request_async(self)
            .await
            .map_err(|error| {
                #[cfg(test)]
                diagnose(
                    "CODE_EXCHANGE",
                    match &error {
                        openidconnect::RequestTokenError::ServerResponse(_) => "SERVER_RESPONSE",
                        openidconnect::RequestTokenError::Request(_) => "TRANSPORT",
                        openidconnect::RequestTokenError::Parse(_, _) => "RESPONSE_PARSE",
                        openidconnect::RequestTokenError::Other(_) => "OTHER_PROTOCOL",
                    },
                );
                let _ = error;
                OidcError::Rejected
            })?;
        self.verify(&client, response, &login.nonce, None, auth)
            .await
    }
    /// The durable session ledger must consume one refresh attempt before calling
    /// this method. Any uncertain result ends that session; do not retry it.
    pub async fn refresh_tokens(
        &self,
        old: &BrowserTokens,
        subject: &str,
        auth: &JwtAuthenticator,
    ) -> Result<VerifiedBrowserTokens, OidcError> {
        let _permit = self.permits.try_acquire().map_err(|_| OidcError::Busy)?;
        let refresh = old
            .refresh_token
            .as_ref()
            .filter(|s| !s.is_empty() && s.len() <= 32768)
            .ok_or(OidcError::Rejected)?;
        let client = self.verified_client().await?;
        let response = client
            .exchange_refresh_token(&RefreshToken::new(refresh.clone()))
            .request_async(self)
            .await
            .map_err(|_| OidcError::Rejected)?;
        let mut verified = self
            .verify(&client, response, &old.nonce, Some(subject), auth)
            .await?;
        if verified.tokens.refresh_token.is_none() {
            verified.tokens.refresh_token = Some(refresh.clone());
        }
        Ok(verified)
    }
    async fn verify(
        &self,
        client: &Client,
        response: CoreTokenResponse,
        nonce: &str,
        subject: Option<&str>,
        auth: &JwtAuthenticator,
    ) -> Result<VerifiedBrowserTokens, OidcError> {
        if response.token_type() != &CoreTokenType::Bearer
            || response.access_token().secret().len() > 16384
            || response
                .refresh_token()
                .is_some_and(|t| t.secret().is_empty() || t.secret().len() > 32768)
        {
            #[cfg(test)]
            diagnose("TOKEN_ENVELOPE", "TYPE_OR_SIZE");
            return Err(OidcError::Rejected);
        }
        let identity = auth
            .verify(response.access_token().secret())
            .await
            .map_err(|error| {
                #[cfg(test)]
                diagnose("ACCESS_TOKEN", auth_category(&error));
                let _ = error;
                OidcError::Rejected
            })?;
        #[cfg(test)]
        diagnose("ACCESS_TOKEN", "VERIFIED");
        let now = Utc::now();
        if identity.issuer != self.settings.issuer
            || identity.client_id.as_deref() != Some(self.settings.client_id.as_str())
            || identity.expires_at <= now.timestamp()
            || identity.expires_at > now.timestamp() + 300
            || subject.is_some_and(|s| s != identity.subject)
        {
            #[cfg(test)]
            diagnose(
                "ACCESS_BINDING",
                if identity.issuer != self.settings.issuer {
                    "ISSUER"
                } else if identity.client_id.as_deref() != Some(self.settings.client_id.as_str()) {
                    "CLIENT"
                } else if subject.is_some_and(|s| s != identity.subject) {
                    "SUBJECT"
                } else {
                    "LIFETIME"
                },
            );
            return Err(OidcError::Rejected);
        }
        if let Some(id) = response.id_token() {
            let verifier = client
                .id_token_verifier()
                .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
            let claims = id
                .claims(&verifier, |received: Option<&Nonce>| {
                    if received.is_some_and(|n| n.secret() == nonce)
                        || (subject.is_some() && received.is_none())
                    {
                        Ok(())
                    } else {
                        Err("invalid login nonce".into())
                    }
                })
                .map_err(|error| {
                    #[cfg(test)]
                    diagnose("ID_TOKEN", id_category(&error));
                    let _ = error;
                    OidcError::Rejected
                })?;
            #[cfg(test)]
            diagnose("ID_TOKEN", "VERIFIED");
            if claims.subject().as_str() != identity.subject
                || claims.issue_time() > now + ChronoDuration::seconds(30)
                || claims.issue_time() < now - ChronoDuration::minutes(10)
                || claims.expiration() > claims.issue_time() + ChronoDuration::minutes(10)
                || claims
                    .authorized_party()
                    .as_ref()
                    .is_some_and(|party| party.as_str() != self.settings.client_id)
            {
                #[cfg(test)]
                diagnose(
                    "ID_BINDING",
                    if claims.subject().as_str() != identity.subject {
                        "SUBJECT"
                    } else if claims
                        .authorized_party()
                        .as_ref()
                        .is_some_and(|party| party.as_str() != self.settings.client_id)
                    {
                        "AUTHORIZED_PARTY"
                    } else {
                        "LIFETIME"
                    },
                );
                return Err(OidcError::Rejected);
            }
            if let Some(expected) = claims.access_token_hash() {
                let hash = AccessTokenHash::from_token(
                    response.access_token(),
                    id.signing_alg().map_err(|_| OidcError::Rejected)?,
                    id.signing_key(&verifier).map_err(|_| OidcError::Rejected)?,
                )
                .map_err(|_| OidcError::Rejected)?;
                if &hash != expected {
                    #[cfg(test)]
                    diagnose("ACCESS_HASH", "MISMATCH");
                    return Err(OidcError::Rejected);
                }
            }
        } else if subject.is_none() {
            #[cfg(test)]
            diagnose("ID_TOKEN", "MISSING");
            return Err(OidcError::Rejected);
        }
        #[cfg(test)]
        diagnose("TOKEN_VERIFICATION", "COMPLETE");
        Ok(VerifiedBrowserTokens {
            identity,
            tokens: BrowserTokens {
                access_token: response.access_token().secret().clone(),
                refresh_token: response.refresh_token().map(|v| v.secret().clone()),
                nonce: nonce.to_owned(),
            },
        })
    }
}
impl<'c> openidconnect::AsyncHttpClient<'c> for BrowserOidc {
    type Error = OidcError;
    type Future =
        futures_util::future::BoxFuture<'c, Result<openidconnect::HttpResponse, OidcError>>;
    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        self.exchange_http(request)
    }
}
async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, OidcError> {
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(OidcError::Unavailable);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| OidcError::Unavailable)? {
        if bytes.len() + chunk.len() > limit {
            return Err(OidcError::Unavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "bff_oidc_tests.rs"]
mod tests;
