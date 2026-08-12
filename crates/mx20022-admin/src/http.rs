// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::OnceLock;

use crate::auth::{authorize_request, AdminResource, AuthConfig, AuthError};
use crate::controller::{AdminController, AdminControllerError};
use crate::middleware::{MiddlewareStage, DEFAULT_MIDDLEWARE_CHAIN};
use crate::rate_limit::AdminRateLimiter;
use crate::routes::HttpMethod;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub bearer_token: Option<String>,
    pub mtls_subject: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

pub async fn dispatch(controller: &dyn AdminController, request: HttpRequest) -> HttpResponse {
    dispatch_with_auth(controller, request, &AuthConfig::default()).await
}

pub async fn dispatch_with_auth(
    controller: &dyn AdminController,
    request: HttpRequest,
    auth: &AuthConfig,
) -> HttpResponse {
    if let Err(response) = run_middleware(&request, auth) {
        return response;
    }

    match (request.method, request.path.as_str()) {
        (HttpMethod::Get, "/health") => match controller.get_health().await {
            Ok(dto) => HttpResponse {
                status: 200,
                body: serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string()),
            },
            Err(error) => map_controller_error(error),
        },
        (HttpMethod::Get, "/ready") => match controller.get_ready().await {
            Ok(dto) => HttpResponse {
                status: if dto.ready { 200 } else { 503 },
                body: serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string()),
            },
            Err(error) => map_controller_error(error),
        },
        (HttpMethod::Get, "/status") => match controller.get_status().await {
            Ok(dto) => HttpResponse {
                status: 200,
                body: serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string()),
            },
            Err(error) => map_controller_error(error),
        },
        (HttpMethod::Post, "/reload") => match controller.reload_config().await {
            Ok(dto) => HttpResponse {
                status: 200,
                body: serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string()),
            },
            Err(error) => map_controller_error(error),
        },
        (HttpMethod::Get, path) if path.starts_with("/tx/") => {
            let tx_id = path.trim_start_matches("/tx/");
            match controller.get_transaction(tx_id).await {
                Ok(dto) => HttpResponse {
                    status: 200,
                    body: serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string()),
                },
                Err(error) => map_controller_error(error),
            }
        }
        _ => HttpResponse {
            status: 404,
            body: "{\"error\":\"not found\"}".to_string(),
        },
    }
}

fn run_middleware(request: &HttpRequest, auth: &AuthConfig) -> Result<(), HttpResponse> {
    for stage in DEFAULT_MIDDLEWARE_CHAIN {
        match stage {
            MiddlewareStage::Authentication => {
                // Only /health is unauthenticated (liveness probe).
                // /metrics exposes operational data and is gated at the same
                // level as /status (read access) via the resource mapping below.
                if request.path != "/health" {
                    let resource = if request.path == "/ready" {
                        AdminResource::Ready
                    } else if request.path == "/status" || request.path == "/metrics" {
                        AdminResource::Status
                    } else if request.path == "/reload" {
                        AdminResource::Reload
                    } else if request.path.starts_with("/tx/") {
                        AdminResource::Transaction
                    } else {
                        AdminResource::Status
                    };
                    let bearer = request.bearer_token.as_ref().map(|v| format!("Bearer {v}"));
                    authorize_request(
                        auth,
                        resource,
                        bearer.as_deref(),
                        request.mtls_subject.as_deref(),
                    )
                    .map_err(map_auth_error)?;
                }
            }
            MiddlewareStage::Authorization => {}
            MiddlewareStage::RateLimit => {
                let key = rate_limit_key(request);
                if !global_rate_limiter().allow(&key) {
                    return Err(HttpResponse {
                        status: 429,
                        body: "{\"error\":\"rate limit exceeded\"}".to_string(),
                    });
                }
            }
            MiddlewareStage::Validation => {
                if request.path.trim().is_empty() {
                    return Err(HttpResponse {
                        status: 400,
                        body: "{\"error\":\"invalid path\"}".to_string(),
                    });
                }
            }
            MiddlewareStage::ErrorTransform => {}
            MiddlewareStage::StructuredLogging => {}
        }
    }

    Ok(())
}

fn map_auth_error(error: AuthError) -> HttpResponse {
    let status = match error {
        AuthError::MissingBearer | AuthError::InvalidBearer | AuthError::MissingMtlsSubject => 401,
        AuthError::Forbidden | AuthError::UntrustedMtlsSubject => 403,
    };
    HttpResponse {
        status,
        body: format!("{{\"error\":\"{}\"}}", error),
    }
}

fn global_rate_limiter() -> &'static AdminRateLimiter {
    static RATE_LIMITER: OnceLock<AdminRateLimiter> = OnceLock::new();
    RATE_LIMITER.get_or_init(AdminRateLimiter::default)
}

fn rate_limit_key(request: &HttpRequest) -> String {
    request
        .mtls_subject
        .as_deref()
        .or(request.bearer_token.as_deref())
        .map(ToString::to_string)
        .unwrap_or_else(|| "anonymous".to_string())
}

fn map_controller_error(error: AdminControllerError) -> HttpResponse {
    match error {
        AdminControllerError::NotFound => HttpResponse {
            status: 404,
            body: "{\"error\":\"not found\"}".to_string(),
        },
        AdminControllerError::Forbidden => HttpResponse {
            status: 403,
            body: "{\"error\":\"forbidden\"}".to_string(),
        },
        AdminControllerError::Internal(message) => {
            tracing::error!(error = %message, "admin request failed");
            HttpResponse {
                status: 500,
                body: "{\"error\":\"internal server error\"}".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::SystemTime;

    use mx20022_store::{Store, TransactionRecord};
    use mx20022_store_sqlite::SqliteStore;
    use secrecy::SecretString;
    use tokio::sync::RwLock;

    use crate::auth::{AuthConfig, AuthMode};
    use crate::http::{dispatch, dispatch_with_auth, HttpRequest};
    use crate::routes::HttpMethod;
    use crate::service::{ReloadStatus, RuntimeStatusSnapshot, StoreBackedAdminController};

    #[tokio::test]
    async fn dispatches_status_and_tx_routes() {
        let store: Arc<dyn Store> =
            Arc::new(SqliteStore::new("sqlite::memory:").expect("sqlite store should initialize"));

        store
            .begin_transaction(&TransactionRecord {
                tx_id: "TX-E1".to_string(),
                pipeline: "demo".to_string(),
                source_channel: "http".to_string(),
                message_type: "pacs.008".to_string(),
                raw_message: "<Document/>".to_string(),
                state: "COMMITTED".to_string(),
                received_at: SystemTime::now(),
                completed_at: None,
                key_fields: HashMap::new(),
            })
            .await
            .expect("insert tx should succeed");

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

        let status = dispatch(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/status".to_string(),
                bearer_token: Some("admin".to_string()),
                mtls_subject: None,
            },
        )
        .await;
        assert_eq!(status.status, 200);

        let tx = dispatch(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/tx/TX-E1".to_string(),
                bearer_token: Some("admin".to_string()),
                mtls_subject: None,
            },
        )
        .await;
        assert_eq!(tx.status, 200);
    }

    /// Helper: build a minimal admin controller backed by an in-memory store.
    /// Used by the authz tests below (status route needs no seeded data).
    async fn test_controller() -> StoreBackedAdminController {
        let store: Arc<dyn Store> =
            Arc::new(SqliteStore::new("sqlite::memory:").expect("sqlite store should initialize"));
        StoreBackedAdminController::new(
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
        )
    }

    /// Pin the authz status-code mapping for legacy bearer auth: missing
    /// token -> 401, wrong token -> 401, valid admin token -> 200, valid
    /// readonly token on a write route -> 403. No test previously exercised
    /// dispatch_with_auth with a non-Disabled AuthConfig, so a regression
    /// swapping 401/403 would have shipped undetected.
    #[tokio::test]
    async fn legacy_bearer_authz_maps_to_correct_status_codes() {
        let controller = test_controller().await;
        let auth = AuthConfig {
            mode: AuthMode::LegacyBearer,
            legacy_bearer_token: Some(SecretString::new("admin-token".into())),
            legacy_readonly_token: Some(SecretString::new("readonly-token".into())),
            ..AuthConfig::default()
        };

        let missing = dispatch_with_auth(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/status".to_string(),
                bearer_token: None,
                mtls_subject: None,
            },
            &auth,
        )
        .await;
        assert_eq!(missing.status, 401, "missing token should be 401");

        let wrong = dispatch_with_auth(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/status".to_string(),
                bearer_token: Some("not-the-token".to_string()),
                mtls_subject: None,
            },
            &auth,
        )
        .await;
        // A presented-but-unrecognized token is Forbidden (403), not 401:
        // the caller supplied credentials; they just don't match. This pins
        // the 401-vs-403 boundary in authorize_legacy.
        assert_eq!(
            wrong.status, 403,
            "presented-but-unrecognized token should be 403"
        );

        let admin_ok = dispatch_with_auth(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/status".to_string(),
                bearer_token: Some("admin-token".to_string()),
                mtls_subject: None,
            },
            &auth,
        )
        .await;
        assert_eq!(admin_ok.status, 200, "valid admin token should be 200");

        // Readonly token is allowed on /status (read)...
        let readonly_read = dispatch_with_auth(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/status".to_string(),
                bearer_token: Some("readonly-token".to_string()),
                mtls_subject: None,
            },
            &auth,
        )
        .await;
        assert_eq!(
            readonly_read.status, 200,
            "readonly token on read route should be 200"
        );

        // ...but forbidden on /reload (write).
        let readonly_write = dispatch_with_auth(
            &controller,
            HttpRequest {
                method: HttpMethod::Post,
                path: "/reload".to_string(),
                bearer_token: Some("readonly-token".to_string()),
                mtls_subject: None,
            },
            &auth,
        )
        .await;
        assert_eq!(
            readonly_write.status, 403,
            "readonly token on write route should be 403"
        );

        // /metrics is gated at status level (regression for the earlier
        // change that made /metrics authenticated).
        let metrics_ok = dispatch_with_auth(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/metrics".to_string(),
                bearer_token: Some("admin-token".to_string()),
                mtls_subject: None,
            },
            &auth,
        )
        .await;
        assert_eq!(
            metrics_ok.status, 404,
            "/metrics passes auth then 404s (not wired in dispatch; axum serves it)"
        );
        let metrics_noauth = dispatch_with_auth(
            &controller,
            HttpRequest {
                method: HttpMethod::Get,
                path: "/metrics".to_string(),
                bearer_token: None,
                mtls_subject: None,
            },
            &auth,
        )
        .await;
        assert_eq!(
            metrics_noauth.status, 401,
            "/metrics without a token should be 401 (no longer unauthenticated)"
        );
    }
}
