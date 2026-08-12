// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::{
    AUTHORIZATION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::map_response;
use axum::routing::post;
use axum::Router;
use mx20022_channels::auth::{authorize_inbound, InboundAuthConfig, InboundAuthContext};
use mx20022_channels::{
    ChannelError, ChannelHealth, DeliveryReceipt, InboundChannel, InboundMessage, OutboundChannel,
    OutboundMessage,
};
use tokio::sync::{mpsc, watch, RwLock};
use tower_http::cors::CorsLayer;

#[derive(Debug, Clone)]
pub struct HttpInboundConfig {
    pub name: String,
    pub bind: String,
    pub content_type: String,
    pub auth: InboundAuthConfig,
    pub cors_allowed_origins: Vec<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Clone)]
struct InboundState {
    sender: mpsc::Sender<InboundMessage>,
    content_type: String,
    paused: Arc<RwLock<bool>>,
    auth: InboundAuthConfig,
}

pub struct HttpInboundChannel {
    config: HttpInboundConfig,
    paused: Arc<RwLock<bool>>,
    shutdown_tx: Arc<watch::Sender<bool>>,
    shutdown_rx: watch::Receiver<bool>,
}

impl HttpInboundChannel {
    pub fn new(config: HttpInboundConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            paused: Arc::new(RwLock::new(false)),
            shutdown_tx: Arc::new(shutdown_tx),
            shutdown_rx,
        }
    }
}

#[async_trait]
impl InboundChannel for HttpInboundChannel {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn run(&self, sender: mpsc::Sender<InboundMessage>) -> Result<(), ChannelError> {
        let state = InboundState {
            sender,
            content_type: self.config.content_type.clone(),
            paused: Arc::clone(&self.paused),
            auth: self.config.auth.clone(),
        };

        let app = Router::new()
            .route("/", post(handle_post))
            .layer(build_cors_layer(&self.config.cors_allowed_origins))
            .layer(map_response(add_security_headers))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
            .with_state(state);
        match (
            self.config.tls_cert_path.as_deref(),
            self.config.tls_key_path.as_deref(),
        ) {
            (Some(cert_path), Some(key_path)) => {
                let socket: std::net::SocketAddr = self.config.bind.parse().map_err(|e| {
                    ChannelError::new(format!("invalid inbound bind {}: {e}", self.config.bind))
                })?;
                let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .map_err(|e| {
                        ChannelError::new(format!(
                            "failed to load inbound TLS cert/key for {}: {e}",
                            self.config.name
                        ))
                    })?;
                tracing::info!(channel = %self.config.name, bind = %self.config.bind, "http inbound channel starting with TLS");
                let handle = axum_server::Handle::new();
                let shutdown_handle = handle.clone();
                let mut shutdown_rx = self.shutdown_rx.clone();
                tokio::spawn(async move {
                    let _ = shutdown_rx.changed().await;
                    tracing::info!("TLS graceful shutdown triggered");
                    shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
                });
                axum_server::bind_rustls(socket, tls)
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
                    .map_err(|e| ChannelError::new(format!("inbound channel serve failed: {e}")))
            }
            (None, None) => {
                let listener = tokio::net::TcpListener::bind(&self.config.bind)
                    .await
                    .map_err(|e| {
                        ChannelError::new(format!("failed to bind inbound channel: {e}"))
                    })?;
                tracing::warn!(channel = %self.config.name, bind = %self.config.bind, "http inbound channel starting without TLS");
                let mut shutdown_rx = self.shutdown_rx.clone();
                let shutdown_signal = async move {
                    let _ = shutdown_rx.changed().await;
                    tracing::info!("graceful shutdown triggered");
                };
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal)
                    .await
                    .map_err(|e| ChannelError::new(format!("inbound channel serve failed: {e}")))
            }
            _ => Err(ChannelError::new(
                "http inbound TLS requires both tls_cert and tls_key",
            )),
        }
    }

    async fn shutdown(&self) -> Result<(), ChannelError> {
        tracing::info!(channel = %self.config.name, "http inbound channel shutting down");
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }

    async fn health(&self) -> Result<ChannelHealth, ChannelError> {
        Ok(ChannelHealth {
            ok: true,
            message: Some(format!("listening on {}", self.config.bind)),
        })
    }

    async fn pause(&self) -> Result<(), ChannelError> {
        *self.paused.write().await = true;
        Ok(())
    }

    async fn resume(&self) -> Result<(), ChannelError> {
        *self.paused.write().await = false;
        Ok(())
    }
}

async fn handle_post(
    State(state): State<InboundState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, String) {
    if *state.paused.read().await {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    }

    if let Err(error) = authorize_inbound(
        &state.auth,
        InboundAuthContext {
            authorization_header: headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            mtls_subject: headers
                .get(state.auth.mtls_subject_header.as_str())
                .and_then(|value| value.to_str().ok()),
        },
    ) {
        let code = if error.to_string().contains("forbidden")
            || error.to_string().contains("untrusted mTLS")
        {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::UNAUTHORIZED
        };
        return (code, String::new());
    }

    let payload = match String::from_utf8(body.to_vec()) {
        Ok(payload) => payload,
        Err(_) => return (StatusCode::BAD_REQUEST, String::new()),
    };
    let result = state
        .sender
        .send(InboundMessage {
            raw: payload,
            content_type: state.content_type.clone(),
        })
        .await;

    match result {
        Ok(_) => (StatusCode::ACCEPTED, String::new()),
        Err(err) => {
            tracing::error!(error=%err, "failed to enqueue inbound message");
            (StatusCode::INTERNAL_SERVER_ERROR, String::new())
        }
    }
}

const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024;

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods([Method::POST])
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

#[derive(Debug, Clone)]
pub struct HttpOutboundConfig {
    pub name: String,
    pub endpoint: String,
    pub content_type: String,
}

pub struct HttpOutboundChannel {
    config: HttpOutboundConfig,
    client: reqwest::Client,
}

impl HttpOutboundChannel {
    pub fn new(config: HttpOutboundConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OutboundChannel for HttpOutboundChannel {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, msg: OutboundMessage) -> Result<DeliveryReceipt, ChannelError> {
        let content_type = if msg.content_type.is_empty() {
            self.config.content_type.as_str()
        } else {
            msg.content_type.as_str()
        };

        let response = self
            .client
            .post(&self.config.endpoint)
            .header("content-type", content_type)
            .body(msg.raw)
            .send()
            .await
            .map_err(|e| ChannelError::new(format!("failed outbound HTTP request: {e}")))?;

        if !response.status().is_success() {
            return Err(ChannelError::new(format!(
                "downstream did not acknowledge delivery: {}",
                response.status()
            )));
        }

        Ok(DeliveryReceipt {
            id: format!("http:{}", now_millis()),
        })
    }

    async fn shutdown(&self) -> Result<(), ChannelError> {
        Ok(())
    }

    async fn health(&self) -> Result<ChannelHealth, ChannelError> {
        Ok(ChannelHealth {
            ok: true,
            message: Some(format!("endpoint={}", self.config.endpoint)),
        })
    }
}

fn now_millis() -> u128 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::HeaderMap;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{extract::State, Router};
    use mx20022_channels::auth::InboundAuthConfig;
    use mx20022_channels::{InboundChannel, OutboundChannel, OutboundMessage};
    use tokio::sync::{mpsc, RwLock};

    use super::{
        handle_post, HttpInboundChannel, HttpInboundConfig, HttpOutboundChannel,
        HttpOutboundConfig, InboundState,
    };

    #[tokio::test]
    async fn inbound_handler_enqueues_message() {
        let (tx, mut rx) = mpsc::channel(1);
        let state = InboundState {
            sender: tx,
            content_type: "application/xml".to_string(),
            paused: Arc::new(RwLock::new(false)),
            auth: InboundAuthConfig::default(),
        };

        let (status, _) = handle_post(State(state), HeaderMap::new(), "<Document/>".into()).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let queued = rx.recv().await.expect("message should be queued");
        assert_eq!(queued.raw, "<Document/>");
        assert_eq!(queued.content_type, "application/xml");
    }

    #[tokio::test]
    async fn shutdown_drain() {
        let (tx, mut rx) = mpsc::channel(10);

        // Bind to a free port by creating a temporary listener.
        let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temp listener");
        let addr = temp_listener.local_addr().expect("resolve addr");
        drop(temp_listener);

        let channel = Arc::new(HttpInboundChannel::new(HttpInboundConfig {
            name: "test-shutdown".to_string(),
            bind: addr.to_string(),
            content_type: "application/xml".to_string(),
            auth: InboundAuthConfig::default(),
            cors_allowed_origins: vec![],
            tls_cert_path: None,
            tls_key_path: None,
        }));

        let run_channel = Arc::clone(&channel);
        let handle = tokio::spawn(async move { run_channel.run(tx).await });

        assert!(
            mx20022_channels::wait_for_tcp(addr.to_string(), Duration::from_secs(2)).await,
            "http inbound should become ready within 2s"
        );

        // Send a message before shutdown — should succeed.
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/"))
            .header("content-type", "application/xml")
            .body("<Document/>")
            .send()
            .await
            .expect("pre-shutdown request");
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Verify the message was queued.
        let msg = rx
            .recv()
            .await
            .expect("should receive pre-shutdown message");
        assert_eq!(msg.raw, "<Document/>");

        // Trigger graceful shutdown.
        channel.shutdown().await.expect("shutdown");

        // Wait for the server to drain.
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "server should shut down within timeout");
        assert!(result.unwrap().is_ok(), "server task should not error");

        // After shutdown, new requests should be rejected.
        let err = client
            .post(format!("http://{addr}/"))
            .header("content-type", "application/xml")
            .body("<AfterShutdown/>")
            .send()
            .await;
        assert!(
            err.is_err(),
            "post-shutdown request should fail (connection refused)"
        );
    }

    #[tokio::test]
    async fn outbound_channel_posts_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("resolve local addr");
        let (tx, mut rx) = mpsc::channel::<String>(1);
        let app = Router::new()
            .route(
                "/",
                post(
                    |State(sender): State<mpsc::Sender<String>>, body: String| async move {
                        let _ = sender.send(body).await;
                        StatusCode::OK
                    },
                ),
            )
            .with_state(tx);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let channel = HttpOutboundChannel::new(HttpOutboundConfig {
            name: "http-out".to_string(),
            endpoint: format!("http://{addr}/"),
            content_type: "application/xml".to_string(),
        });

        channel
            .send(OutboundMessage {
                raw: "<Document/>".to_string(),
                content_type: String::new(),
            })
            .await
            .expect("outbound send should succeed");

        let posted = rx.recv().await.expect("server should receive payload");
        assert_eq!(posted, "<Document/>");
    }
}
