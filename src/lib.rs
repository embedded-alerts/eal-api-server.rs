pub mod auth;
pub mod model;
pub mod store;
pub mod telemetry;
pub mod transport;

use std::env;

use anyhow::Context;
use auth::{AuthBoundary, AuthError, READ_SCOPE, VerifiedActor, WRITE_SCOPE};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use model::{AlertRule, CreateAlertRule, Health};
use sea_orm::{Database, DatabaseConnection};
use serde::Serialize;
use store::AlertStore;
use tokio::sync::broadcast;
use tower_http::trace::TraceLayer;
use tracing::info;
use transport::{spawn_jetstream_from_env, spawn_mtls_from_env};
use uuid::Uuid;

const MAX_JSON_BODY_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub struct AppState {
    store: AlertStore,
    auth: AuthBoundary,
    events: broadcast::Sender<ScopedAlertEvent>,
    mtls_configured: bool,
    jetstream_configured: bool,
}

#[derive(Clone, Serialize)]
struct ScopedAlertEvent {
    #[serde(skip)]
    product_tenant: String,
    #[serde(skip)]
    owner_subject: Uuid,
    kind: &'static str,
    alert: AlertRule,
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("identity authority unavailable")]
    Degraded,
    #[error("invalid request")]
    InvalidRequest,
    #[error("not found")]
    NotFound,
    #[error("service unavailable")]
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Degraded | Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

impl From<AuthError> for ApiError {
    fn from(value: AuthError) -> Self {
        match value {
            AuthError::Unauthorized => Self::Unauthorized,
            AuthError::Degraded | AuthError::Configuration => Self::Degraded,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/v1/alerts", get(list_alerts).post(create_alert))
        .route("/v1/alerts/{id}", get(get_alert))
        .route("/v1/web/alerts", get(list_alerts))
        .route("/v1/ws", get(ws_upgrade))
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let _telemetry = telemetry::init("eal-api-server");
    let auth = AuthBoundary::from_env().context("load Shared Auth boundary")?;
    let database = connect_database().await?;
    let store = AlertStore::new(database);
    let (events, _) = broadcast::channel(512);
    let mtls = spawn_mtls_from_env(store.clone(), auth.clone())
        .await
        .map_err(anyhow::Error::msg)?;
    let jetstream = spawn_jetstream_from_env(store.clone(), auth.policy().product_tenant.clone())
        .await
        .map_err(anyhow::Error::msg)?;
    let state = AppState {
        store,
        auth,
        events,
        mtls_configured: mtls.is_some(),
        jetstream_configured: jetstream.is_some(),
    };
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}"))
        .await
        .context("bind API listener")?;
    info!(address = %listener.local_addr()?, "Embedded Alerts API listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve API")?;
    Ok(())
}

async fn connect_database() -> anyhow::Result<Option<DatabaseConnection>> {
    match env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Ok(Some(
            tokio::time::timeout(std::time::Duration::from_secs(5), Database::connect(url))
                .await
                .context("database connection timed out")?
                .context("connect database")?,
        )),
        _ => Ok(None),
    }
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        service: "eal-api-server",
        status: "ok",
        database_configured: state.store.database_configured(),
        shared_auth_configured: true,
        mtls_configured: state.mtls_configured,
        jetstream_configured: state.jetstream_configured,
    })
}

async fn list_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AlertRule>>, ApiError> {
    let actor = state
        .auth
        .verify_authorization(&headers, READ_SCOPE)
        .await?;
    let alerts = state
        .store
        .list(&actor)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(alerts))
}

async fn get_alert(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AlertRule>, ApiError> {
    let actor = state
        .auth
        .verify_authorization(&headers, READ_SCOPE)
        .await?;
    state
        .store
        .get(&actor, id)
        .await
        .map_err(|_| ApiError::Unavailable)?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn create_alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateAlertRule>,
) -> Result<(StatusCode, Json<AlertRule>), ApiError> {
    let actor = state
        .auth
        .verify_authorization(&headers, WRITE_SCOPE)
        .await?;
    input.validate().map_err(|_| ApiError::InvalidRequest)?;
    let alert = state
        .store
        .create(&actor, input)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let event = ScopedAlertEvent {
        product_tenant: actor.product_tenant,
        owner_subject: actor.subject,
        kind: "created",
        alert: alert.clone(),
    };
    let _ = state.events.send(event);
    Ok((StatusCode::CREATED, Json(alert)))
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let actor = state
        .auth
        .verify_authorization(&headers, READ_SCOPE)
        .await?;
    Ok(ws.on_upgrade(move |socket| websocket(socket, state, actor)))
}

async fn websocket(socket: WebSocket, state: AppState, actor: VerifiedActor) {
    let (mut sender, mut receiver) = socket.split();
    let mut events = state.events.subscribe();
    loop {
        tokio::select! {
            message = receiver.next() => match message {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
            event = events.recv() => match event {
                Ok(event)
                    if event.product_tenant == actor.product_tenant
                        && event.owner_subject == actor.subject => {
                    let Ok(payload) = serde_json::to_string(&event) else { break; };
                    if sender.send(Message::Text(payload.into())).await.is_err() { break; }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => break,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_flat_and_non_probing() {
        assert_eq!(ApiError::Unauthorized.to_string(), "unauthorized");
        assert_eq!(ApiError::Unavailable.to_string(), "service unavailable");
        assert_eq!(MAX_JSON_BODY_BYTES, 32 * 1024);
    }
}
