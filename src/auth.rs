use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, header};
use shared_auth_client::{Introspection, SharedAuthClient};
use uuid::Uuid;

pub const READ_SCOPE: &str = "embedded-alerts:alerts:read";
pub const WRITE_SCOPE: &str = "embedded-alerts:alerts:write";
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct AuthPolicy {
    pub issuer: String,
    pub audience: String,
    pub authorized_client: String,
    pub provider_tenant: String,
    pub product_tenant: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedActor {
    pub subject: Uuid,
    pub product_tenant: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("identity authority unavailable")]
    Degraded,
    #[error("identity configuration invalid")]
    Configuration,
}

#[derive(Clone)]
pub struct AuthBoundary {
    client: SharedAuthClient,
    policy: AuthPolicy,
}

impl AuthBoundary {
    pub fn from_env() -> Result<Self, AuthError> {
        let base = required_env("SHARED_AUTH_BASE_URL")?;
        let service_credential = required_env("SHARED_AUTH_SERVICE_CREDENTIAL")?;
        if !strict_credential(&service_credential) {
            return Err(AuthError::Configuration);
        }
        let policy = AuthPolicy {
            issuer: required_env("SHARED_AUTH_ISSUER")?,
            audience: required_env("EAL_AUTH_AUDIENCE")?,
            authorized_client: required_env("EAL_AUTHORIZED_CLIENT")?,
            provider_tenant: required_env("EAL_PROVIDER_TENANT")?,
            product_tenant: required_env("EAL_PRODUCT_TENANT")?,
        };
        if !bounded_identifier(&policy.audience)
            || !bounded_identifier(&policy.authorized_client)
            || !bounded_identifier(&policy.provider_tenant)
            || !bounded_identifier(&policy.product_tenant)
        {
            return Err(AuthError::Configuration);
        }
        let client = SharedAuthClient::try_new(base)
            .map_err(|_| AuthError::Configuration)?
            .with_service_credential(service_credential)
            .with_max_response_bytes(64 * 1024);
        Ok(Self { client, policy })
    }

    pub async fn verify_authorization(
        &self,
        headers: &HeaderMap,
        required_scope: &str,
    ) -> Result<VerifiedActor, AuthError> {
        let token = bearer_from_headers(headers)?;
        self.verify_token(token, required_scope).await
    }

    pub async fn verify_token(
        &self,
        token: &str,
        required_scope: &str,
    ) -> Result<VerifiedActor, AuthError> {
        if !strict_credential(token) || !bounded_identifier(required_scope) {
            return Err(AuthError::Unauthorized);
        }
        let claims = self
            .client
            .introspect_with_requirements(token, &self.policy.audience, &[required_scope])
            .await
            .map_err(|error| match error {
                shared_auth_client::ClientError::Unauthorized
                | shared_auth_client::ClientError::InvalidInput(_) => AuthError::Unauthorized,
                _ => AuthError::Degraded,
            })?;
        authorize_introspection(&claims, &self.policy, required_scope, unix_seconds()?)
    }

    pub fn policy(&self) -> &AuthPolicy {
        &self.policy
    }
}

pub fn authorize_introspection(
    claims: &Introspection,
    policy: &AuthPolicy,
    required_scope: &str,
    now: u64,
) -> Result<VerifiedActor, AuthError> {
    let tenant_id = claim_string(claims, "tenant_id");
    let application_id = claim_string(claims, "application_id");
    let actor_kind = claim_string(claims, "actor_kind");
    let subject = claims
        .sub
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok());
    let session_present = claims.sid.as_deref().is_some_and(bounded_identifier);
    if !claims.active
        || claims.iss.as_deref() != Some(policy.issuer.as_str())
        || claims.aud.as_deref() != Some(policy.audience.as_str())
        || claims.azp.as_deref() != Some(policy.authorized_client.as_str())
        || claims.provider_tenant.as_deref() != Some(policy.provider_tenant.as_str())
        || tenant_id != Some(policy.product_tenant.as_str())
        || application_id != Some(policy.authorized_client.as_str())
        || actor_kind != Some("user")
        || !claims.has_scope(required_scope)
        || claims.exp.is_none_or(|expiry| expiry <= now)
        || claims.nbf.is_none_or(|not_before| not_before > now)
        || subject.is_none()
        || !session_present
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(VerifiedActor {
        subject: subject.expect("subject was checked"),
        product_tenant: policy.product_tenant.clone(),
    })
}

fn claim_string<'a>(claims: &'a Introspection, key: &str) -> Option<&'a str> {
    claims
        .rest
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| bounded_identifier(value))
}

pub fn bearer_from_headers(headers: &HeaderMap) -> Result<&str, AuthError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(AuthError::Unauthorized)?;
    if values.next().is_some() {
        return Err(AuthError::Unauthorized);
    }
    let value = value.to_str().map_err(|_| AuthError::Unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| strict_credential(token))
        .ok_or(AuthError::Unauthorized)?;
    Ok(token)
}

fn strict_credential(value: &str) -> bool {
    value.len() >= 16
        && value.len() <= MAX_CREDENTIAL_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn required_env(name: &str) -> Result<String, AuthError> {
    crate::flags::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(AuthError::Configuration)
}

fn unix_seconds() -> Result<u64, AuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthError::Degraded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<(HeaderMap, serde_json::Value)>>>);

    async fn introspect(
        State(capture): State<Capture>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        *capture.0.lock().unwrap() = Some((headers, body));
        Json(serde_json::json!({
            "active": true,
            "sub": "00000000-0000-4000-8000-000000000001",
            "sid": "00000000-0000-4000-8000-000000000002",
            "iss": "https://auth.oresoftware.dev/customer",
            "aud": "embedded-alerts-api",
            "azp": "embedded-alerts-web",
            "scope": READ_SCOPE,
            "nbf": 1,
            "exp": u64::MAX,
            "provider_tenant": "embedded-alerts-provider",
            "tenant_id": "embedded-alerts",
            "application_id": "embedded-alerts-web",
            "actor_kind": "user"
        }))
    }

    #[test]
    fn repeated_or_malformed_bearers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            "Bearer valid-token-value".parse().unwrap(),
        );
        assert_eq!(bearer_from_headers(&headers).unwrap(), "valid-token-value");
        headers.append(
            header::AUTHORIZATION,
            "Bearer second-token-value".parse().unwrap(),
        );
        assert!(bearer_from_headers(&headers).is_err());
    }

    #[test]
    fn configuration_and_auth_errors_never_include_credentials() {
        assert_eq!(AuthError::Unauthorized.to_string(), "unauthorized");
        assert_eq!(
            AuthError::Degraded.to_string(),
            "identity authority unavailable"
        );
    }

    #[tokio::test]
    async fn official_client_separates_service_credential_and_user_payload() {
        let capture = Capture::default();
        let app = Router::new()
            .route("/auth/introspect", post(introspect))
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let boundary = AuthBoundary {
            client: SharedAuthClient::try_new(format!("http://{address}"))
                .unwrap()
                .with_service_credential("independent-service-credential"),
            policy: AuthPolicy {
                issuer: "https://auth.oresoftware.dev/customer".to_owned(),
                audience: "embedded-alerts-api".to_owned(),
                authorized_client: "embedded-alerts-web".to_owned(),
                provider_tenant: "embedded-alerts-provider".to_owned(),
                product_tenant: "embedded-alerts".to_owned(),
            },
        };
        boundary
            .verify_token("end-user-access-token", READ_SCOPE)
            .await
            .unwrap();
        let (headers, body) = capture.0.lock().unwrap().clone().unwrap();
        assert_eq!(
            headers[header::AUTHORIZATION],
            "Bearer independent-service-credential"
        );
        assert_eq!(body["contract"], "IntrospectionRequest");
        assert_eq!(body["payload"]["token"], "end-user-access-token");
        assert_eq!(body["payload"]["audience"], "embedded-alerts-api");
        assert_eq!(body["payload"]["requiredScopes"][0], READ_SCOPE);
        task.abort();
    }
}
