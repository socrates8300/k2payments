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
    use tokio::sync::RwLock;

    use crate::http::{dispatch, HttpRequest};
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
}
