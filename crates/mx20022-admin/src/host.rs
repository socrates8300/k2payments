// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::header::{
    AUTHORIZATION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::map_response;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::cors::CorsLayer;

use crate::auth::{authorize_request, AdminResource, AuthConfig, AuthError};
use crate::controller::{AdminController, AdminControllerError};
use crate::rate_limit::AdminRateLimiter;
use crate::tls::TlsConfig;

const MAX_ADMIN_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone)]
struct HostState {
    controller: Arc<dyn AdminController>,
    auth: AuthConfig,
    rate_limiter: Arc<AdminRateLimiter>,
}

pub async fn serve(
    addr: &str,
    controller: Arc<dyn AdminController>,
    auth: AuthConfig,
) -> Result<(), HostError> {
    serve_with_tls_and_cors(addr, controller, auth, None, Vec::new()).await
}

pub async fn serve_with_tls(
    addr: &str,
    controller: Arc<dyn AdminController>,
    auth: AuthConfig,
    tls: Option<TlsConfig>,
) -> Result<(), HostError> {
    serve_with_tls_and_cors(addr, controller, auth, tls, Vec::new()).await
}

pub async fn serve_with_tls_and_cors(
    addr: &str,
    controller: Arc<dyn AdminController>,
    auth: AuthConfig,
    tls: Option<TlsConfig>,
    allowed_origins: Vec<String>,
) -> Result<(), HostError> {
    let state = HostState {
        controller,
        auth,
        rate_limiter: Arc::new(AdminRateLimiter::default()),
    };

    let router = admin_router(state).layer(build_cors_layer(&allowed_origins));

    if let Some(tls) = tls {
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                .await
                .map_err(|e| HostError::Tls(e.to_string()))?;

        let socket: std::net::SocketAddr =
            addr.parse().map_err(|e: std::net::AddrParseError| {
                HostError::Bind(addr.to_string(), e.to_string())
            })?;

        tracing::info!(addr = %addr, "admin host starting with TLS");
        axum_server::bind_rustls(socket, config)
            .serve(router.into_make_service())
            .await
            .map_err(|e| HostError::Serve(e.to_string()))
    } else {
        tracing::warn!("admin host starting without TLS");
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| HostError::Bind(addr.to_string(), e.to_string()))?;

        axum::serve(listener, router)
            .await
            .map_err(|e| HostError::Serve(e.to_string()))
    }
}

fn admin_router(state: HostState) -> Router {
    Router::new()
        .route("/health", get(get_health))
        .route("/ready", get(get_ready))
        .route("/status", get(get_status))
        .route("/reload", post(reload_config))
        .route("/tx/:tx_id", get(get_tx))
        .route("/metrics", get(get_metrics))
        .layer(map_response(add_security_headers))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_ADMIN_BODY_BYTES))
        .with_state(state)
}

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("x-client-cert-subject"),
        ]);

    let parsed_origins = allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();
    if !parsed_origins.is_empty() {
        layer = layer.allow_origin(parsed_origins);
    }
    layer
}

async fn add_security_headers(mut response: axum::response::Response) -> axum::response::Response {
    let headers = response.headers_mut();
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("accelerometer=(), camera=(), geolocation=(), microphone=()"),
    );
    response
}

async fn get_metrics(
    State(state): State<HostState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // /metrics exposes operational data (counts, latencies, pipeline health)
    // and must not be served unauthenticated. Gated at Status (read) level,
    // matching /status.
    authorize(&state, &headers, AdminResource::Status)?;

    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        mx20022_metrics::gather(),
    ))
}

async fn get_health(
    State(state): State<HostState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .controller
        .get_health()
        .await
        .map(|dto| {
            Json(serde_json::json!({
                "ok": dto.ok,
            }))
        })
        .map_err(map_error)
}

async fn get_ready(
    State(state): State<HostState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    authorize(&state, &headers, AdminResource::Ready)?;

    state
        .controller
        .get_ready()
        .await
        .map(|dto| {
            let status = if dto.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (
                status,
                Json(serde_json::json!({
                    "ready": dto.ready,
                    "details": dto.details,
                })),
            )
        })
        .map_err(map_error)
}

async fn get_status(
    State(state): State<HostState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    authorize(&state, &headers, AdminResource::Status)?;

    state
        .controller
        .get_status()
        .await
        .map(|dto| {
            Json(serde_json::json!({
                "runtime": dto.runtime,
                "pipelines": dto.pipelines,
                "channels": dto.channels,
                "store": dto.store,
                "uptime_ms": dto.uptime_ms,
                "store_ok": dto.store_ok,
                "store_details": dto.store_details,
                "in_flight_count": dto.in_flight_count,
                "pending_correlation_count": dto.pending_correlation_count,
                "dead_letter_count": dto.dead_letter_count,
                "config_version": dto.config_version,
                "last_reload_result": dto.last_reload_result,
                "last_reload_at": dto.last_reload_at,
            }))
        })
        .map_err(map_error)
}

async fn get_tx(
    State(state): State<HostState>,
    Path(tx_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    authorize(&state, &headers, AdminResource::Transaction)?;

    state
        .controller
        .get_transaction(&tx_id)
        .await
        .map(|dto| {
            Json(serde_json::json!({
                "tx_id": dto.tx_id,
                "pipeline": dto.pipeline,
                "message_type": dto.message_type,
                "state": dto.state,
                "received_at": dto.received_at,
                "completed_at": dto.completed_at,
            }))
        })
        .map_err(map_error)
}

async fn reload_config(
    State(state): State<HostState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    authorize(&state, &headers, AdminResource::Reload)?;

    state
        .controller
        .reload_config()
        .await
        .map(|dto| {
            Json(serde_json::json!({
                "reloaded": dto.reloaded,
                "details": dto.details,
            }))
        })
        .map_err(map_error)
}

fn authorize(
    state: &HostState,
    headers: &HeaderMap,
    resource: AdminResource,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let bearer = headers.get("authorization").and_then(|h| h.to_str().ok());
    let mtls = headers
        .get(state.auth.mtls_subject_header.as_str())
        .and_then(|h| h.to_str().ok());
    let key = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or(headers.get("x-real-ip").and_then(|h| h.to_str().ok()))
        .or(mtls)
        .or(bearer)
        .unwrap_or("anonymous");
    if !state.rate_limiter.allow(&format!("{resource:?}:{key}")) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate limit exceeded"})),
        ));
    }
    authorize_request(&state.auth, resource, bearer, mtls).map_err(map_auth_error)
}

fn map_error(error: AdminControllerError) -> (StatusCode, Json<serde_json::Value>) {
    match error {
        AdminControllerError::NotFound => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        ),
        AdminControllerError::Forbidden => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        ),
        AdminControllerError::Internal(message) => {
            tracing::error!(error = %message, "admin request failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

fn map_auth_error(error: AuthError) -> (StatusCode, Json<serde_json::Value>) {
    match error {
        AuthError::MissingBearer | AuthError::InvalidBearer => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": error.to_string()})),
        ),
        AuthError::Forbidden | AuthError::UntrustedMtlsSubject => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": error.to_string()})),
        ),
        AuthError::MissingMtlsSubject => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": error.to_string()})),
        ),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("failed to bind admin host on {0}: {1}")]
    Bind(String, String),
    #[error("failed to serve admin host: {0}")]
    Serve(String),
    #[error("TLS configuration error: {0}")]
    Tls(String),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use mx20022_store::Store;
    use mx20022_store_sqlite::SqliteStore;
    use secrecy::SecretString;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use super::{admin_router, HostState};
    use crate::auth::{AuthConfig, AuthMode};
    use crate::rate_limit::AdminRateLimiter;
    use crate::service::{ReloadStatus, RuntimeStatusSnapshot, StoreBackedAdminController};

    async fn test_state(auth: AuthConfig) -> HostState {
        let store: Arc<dyn Store> =
            Arc::new(SqliteStore::new("sqlite::memory:").expect("sqlite store should initialize"));
        let controller = StoreBackedAdminController::new(
            store,
            RuntimeStatusSnapshot {
                runtime: "test-runtime".to_string(),
                pipelines: vec!["demo".to_string()],
                channels: vec!["http".to_string()],
                store: "sqlite".to_string(),
                started_at: SystemTime::now(),
                reload_status: Arc::new(RwLock::new(ReloadStatus {
                    config_version: "cfg-v1".to_string(),
                    last_result: None,
                    last_reloaded_at: None,
                })),
            },
        );
        HostState {
            controller: Arc::new(controller),
            auth,
            rate_limiter: Arc::new(AdminRateLimiter::default()),
        }
    }

    #[tokio::test]
    async fn metrics_requires_status_auth_on_live_host() {
        let auth = AuthConfig {
            mode: AuthMode::LegacyBearer,
            legacy_bearer_token: Some(SecretString::new("admin-token".into())),
            ..AuthConfig::default()
        };
        let app = admin_router(test_state(auth).await);

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", "Bearer admin-token")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; version=0.0.4")
        );
    }
}
