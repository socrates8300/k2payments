// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "channel-amqp")]
use mx20022_channel_amqp::{AmqpInboundChannel, AmqpInboundConfig};
#[cfg(feature = "channel-file")]
use mx20022_channel_file::FileInboundChannel;
#[cfg(feature = "channel-grpc")]
use mx20022_channel_grpc::{GrpcInboundChannel, GrpcInboundConfig};
#[cfg(feature = "channel-http")]
use mx20022_channel_http::{HttpInboundChannel, HttpInboundConfig};
#[cfg(feature = "channel-kafka")]
use mx20022_channel_kafka::{KafkaInboundChannel, KafkaInboundConfig};
#[cfg(feature = "channel-nats")]
use mx20022_channel_nats::{NatsInboundChannel, NatsInboundConfig};
#[cfg(feature = "channel-tcp")]
use mx20022_channel_tcp::{TcpFraming, TcpInboundChannel, TcpInboundConfig};
#[cfg(any(feature = "channel-http", feature = "channel-grpc"))]
use mx20022_channels::auth::{InboundAuthConfig, InboundAuthMode};
use mx20022_channels::{InboundChannel, InboundMessage};
use mx20022_config::{ChannelSection, RuntimeConfig};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use crate::app::RuntimeApp;

static TX_COUNTER: AtomicU64 = AtomicU64::new(1);
const INBOUND_CHANNEL_BUFFER: usize = 1024;

pub async fn run_pipelines(
    app: Arc<RuntimeApp>,
    config: RuntimeConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), EngineError> {
    let mut tasks = JoinSet::new();
    let mut channels: Vec<Arc<dyn InboundChannel>> = Vec::new();
    let mut started = 0usize;
    let tx_id_prefix = build_tx_id_prefix(&config.runtime.instance_id);

    for pipeline in &config.pipelines {
        let Some(channel_cfg) = config.channels.get(&pipeline.channel_in) else {
            continue;
        };

        let channel_name = pipeline.channel_in.clone();
        let pipeline_name = pipeline.name.clone();
        let message_type_default = pipeline
            .message_types
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let inbound: Arc<dyn InboundChannel> =
            match (channel_cfg.channel_type.as_str(), channel_cfg.mode.as_str()) {
                #[cfg(feature = "channel-http")]
                ("http", "server") => Arc::new(HttpInboundChannel::new(HttpInboundConfig {
                    name: channel_name.clone(),
                    bind: extract_bind(channel_cfg)?,
                    content_type: "application/xml".to_string(),
                    auth: extract_inbound_auth(channel_cfg)?,
                    cors_allowed_origins: extract_string_vec_or_single(
                        channel_cfg,
                        "cors_allowed_origins",
                    ),
                    tls_cert_path: extract_optional(channel_cfg, "tls_cert"),
                    tls_key_path: extract_optional(channel_cfg, "tls_key"),
                })),
                #[cfg(feature = "channel-file")]
                ("file", "watch") => Arc::new(FileInboundChannel::new(
                    channel_name.clone(),
                    extract_required(channel_cfg, "directory")?,
                    extract_optional(channel_cfg, "pattern").unwrap_or_else(|| "*.xml".to_string()),
                    Duration::from_millis(
                        extract_u64(channel_cfg, "poll_interval_ms").unwrap_or(1000),
                    ),
                    extract_optional(channel_cfg, "move_processed_to").map(Into::into),
                    extract_optional(channel_cfg, "move_failed_to").map(Into::into),
                )),
                #[cfg(feature = "channel-grpc")]
                ("grpc", "server") => Arc::new(GrpcInboundChannel::new(GrpcInboundConfig {
                    name: channel_name.clone(),
                    bind: extract_bind(channel_cfg)?,
                    auth: extract_inbound_auth(channel_cfg)?,
                    tls_cert_path: extract_optional(channel_cfg, "tls_cert"),
                    tls_key_path: extract_optional(channel_cfg, "tls_key"),
                })),
                #[cfg(feature = "channel-tcp")]
                ("tcp", "server") => Arc::new(TcpInboundChannel::new(TcpInboundConfig {
                    name: channel_name.clone(),
                    bind: extract_bind(channel_cfg)?,
                    framing: extract_tcp_framing(channel_cfg),
                    content_type: extract_optional(channel_cfg, "content_type")
                        .unwrap_or_else(|| "application/xml".to_string()),
                    auth_token: extract_optional(channel_cfg, "auth_token")
                        .map(|value| SecretString::new(value.into_boxed_str())),
                })),
                #[cfg(feature = "channel-nats")]
                ("nats", "subscriber") => Arc::new(NatsInboundChannel::new(NatsInboundConfig {
                    name: channel_name.clone(),
                    endpoint: extract_required(channel_cfg, "endpoint")
                        .or_else(|_| extract_required(channel_cfg, "url"))?,
                    subject: extract_required(channel_cfg, "subject")?,
                    queue_group: extract_optional(channel_cfg, "queue_group"),
                    content_type: extract_optional(channel_cfg, "content_type")
                        .unwrap_or_else(|| "application/xml".to_string()),
                })),
                #[cfg(feature = "channel-kafka")]
                ("kafka", "consumer") => Arc::new(KafkaInboundChannel::new(KafkaInboundConfig {
                    name: channel_name.clone(),
                    brokers: extract_string_list_or_single(channel_cfg, "brokers")
                        .or_else(|| extract_optional(channel_cfg, "bootstrap_servers"))
                        .ok_or_else(|| {
                            EngineError::Config(
                                "kafka channel requires `brokers` or `bootstrap_servers`"
                                    .to_string(),
                            )
                        })?,
                    topic: extract_required(channel_cfg, "topic")?,
                    group_id: extract_optional(channel_cfg, "group_id")
                        .unwrap_or_else(|| format!("mxruntime-{}", channel_name)),
                    content_type: extract_optional(channel_cfg, "content_type")
                        .unwrap_or_else(|| "application/xml".to_string()),
                    security_protocol: extract_optional(channel_cfg, "security_protocol"),
                    ssl_ca_location: extract_optional(channel_cfg, "ssl_ca_location")
                        .or_else(|| extract_optional(channel_cfg, "tls_ca_cert")),
                })),
                #[cfg(feature = "channel-amqp")]
                ("amqp", "consumer") => Arc::new(AmqpInboundChannel::new(AmqpInboundConfig {
                    name: channel_name.clone(),
                    url: extract_required(channel_cfg, "url")?,
                    queue: extract_required(channel_cfg, "queue")?,
                    consumer_tag: extract_optional(channel_cfg, "consumer_tag")
                        .unwrap_or_else(|| format!("mxruntime-{}", channel_name)),
                    content_type: extract_optional(channel_cfg, "content_type")
                        .unwrap_or_else(|| "application/xml".to_string()),
                })),
                _ => {
                    tracing::warn!(
                        pipeline = %pipeline.name,
                        channel = %pipeline.channel_in,
                        channel_type = %channel_cfg.channel_type,
                        mode = %channel_cfg.mode,
                        "skipping unsupported inbound channel"
                    );
                    continue;
                }
            };

        channels.push(Arc::clone(&inbound));

        let (tx, mut rx) = mpsc::channel::<InboundMessage>(INBOUND_CHANNEL_BUFFER);
        let inbound_channel = Arc::clone(&inbound);
        tasks.spawn(async move {
            inbound_channel
                .run(tx)
                .await
                .map_err(|e| EngineError::ChannelRun {
                    pipeline: pipeline_name,
                    channel: channel_name,
                    message: e.to_string(),
                })
        });

        let app_for_pipeline = Arc::clone(&app);
        let pipeline_name = pipeline.name.clone();
        let source_channel = pipeline.channel_in.clone();
        let default_message_type = message_type_default;
        let max_concurrent = pipeline.max_concurrent.unwrap_or(1000);
        let tx_id_prefix = tx_id_prefix.clone();
        tasks.spawn(async move {
            let semaphore = Arc::new(Semaphore::new(max_concurrent));

            while let Some(msg) = rx.recv().await {
                let permit = semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|e| EngineError::Concurrency(e.to_string()))?;

                let app = Arc::clone(&app_for_pipeline);
                let pipeline = pipeline_name.clone();
                let source_channel = source_channel.clone();
                let message_type = infer_message_type(&msg, &default_message_type);
                let raw = msg.raw;
                let tx_id_prefix = tx_id_prefix.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let tx_id = next_tx_id(&tx_id_prefix);

                    if let Err(error) = app
                        .process(&pipeline, tx_id.clone(), source_channel, message_type, raw)
                        .await
                    {
                        tracing::error!(
                            tx_id = %tx_id,
                            pipeline = %pipeline,
                            error = %error,
                            "pipeline processing failed"
                        );
                    }
                });
            }

            Ok(())
        });

        started += 1;
        tracing::info!(
            pipeline = %pipeline.name,
            channel = %pipeline.channel_in,
            max_concurrent,
            "started inbound pipeline"
        );
    }

    if started == 0 {
        return Err(EngineError::NoSupportedPipelines);
    }

    const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

    // Spawn a task that waits for the shutdown signal and propagates it to all channels.
    let shutdown_channels = channels.clone();
    let shutdown_app = Arc::clone(&app);
    let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        shutdown.await;
        tracing::info!("shutdown signal received, draining channels");
        for channel in &shutdown_channels {
            if let Err(e) = channel.shutdown().await {
                tracing::warn!(channel = %channel.name(), error = %e, "shutdown error");
            }
        }
        // After inbound channels stop accepting new work, flush outbound
        // channels (Kafka producer buffers, AMQP publisher confirms, etc.).
        // In-flight transactions still complete via the JoinSet drain below.
        shutdown_app.shutdown_outbound_channels().await;
        let _ = drain_tx.send(());
    });

    // Capture a store handle for the post-drain flush below.
    let drain_store = app.store_handle();

    // Wait for either all tasks to complete or the shutdown signal.
    enum WaitResult {
        AllCompleted,
        TaskError(EngineError),
        ShutdownTriggered,
    }

    let wait_result = tokio::select! {
        result = async {
            while let Some(task) = tasks.join_next().await {
                match task {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return WaitResult::TaskError(error),
                    Err(error) => return WaitResult::TaskError(EngineError::TaskJoin(error.to_string())),
                }
            }
            WaitResult::AllCompleted
        } => { result }
        _ = drain_rx => { WaitResult::ShutdownTriggered }
    };

    match wait_result {
        WaitResult::AllCompleted => Ok(()),
        WaitResult::TaskError(error) => {
            tracing::error!(error = %error, "pipeline task failed, shutting down");
            for channel in &channels {
                let _ = channel.shutdown().await;
            }
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
                while let Some(task) = tasks.join_next().await {
                    let _ = task;
                }
            })
            .await;
            Err(error)
        }
        WaitResult::ShutdownTriggered => {
            tracing::info!("draining in-flight tasks");
            let drain_result = tokio::time::timeout(DRAIN_TIMEOUT, async {
                while let Some(task) = tasks.join_next().await {
                    match task {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(error) => return Err(EngineError::TaskJoin(error.to_string())),
                    }
                }
                Ok(())
            })
            .await;

            // Flush the store after in-flight tasks finish. Best-effort:
            // a flush failure is logged but does not block exit.
            if let Err(error) = drain_store.shutdown().await {
                tracing::warn!(error = %error, "store shutdown error");
            }
            match drain_result {
                Ok(result) => {
                    tracing::info!("channels drained successfully");
                    result
                }
                Err(_) => {
                    tracing::warn!("drain timeout exceeded, forcing shutdown");
                    Ok(())
                }
            }
        }
    }
}

#[cfg(any(
    feature = "channel-http",
    feature = "channel-grpc",
    feature = "channel-tcp",
    feature = "channel-file",
    feature = "channel-nats",
    feature = "channel-kafka",
    feature = "channel-amqp"
))]
fn extract_bind(channel_cfg: &ChannelSection) -> Result<String, EngineError> {
    extract_required(channel_cfg, "bind")
}

#[cfg(any(
    feature = "channel-http",
    feature = "channel-grpc",
    feature = "channel-tcp",
    feature = "channel-file",
    feature = "channel-nats",
    feature = "channel-kafka",
    feature = "channel-amqp"
))]
fn extract_required(channel_cfg: &ChannelSection, key: &str) -> Result<String, EngineError> {
    channel_cfg
        .extra
        .get(key)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| EngineError::Config(format!("channel requires `{key}`")))
}

#[cfg(any(
    feature = "channel-http",
    feature = "channel-grpc",
    feature = "channel-tcp",
    feature = "channel-file",
    feature = "channel-nats",
    feature = "channel-kafka",
    feature = "channel-amqp"
))]
fn extract_optional(channel_cfg: &ChannelSection, key: &str) -> Option<String> {
    channel_cfg
        .extra
        .get(key)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

#[cfg(feature = "channel-http")]
fn extract_string_vec_or_single(channel_cfg: &ChannelSection, key: &str) -> Vec<String> {
    let Some(value) = channel_cfg.extra.get(key) else {
        return Vec::new();
    };
    if let Some(single) = value.as_str() {
        return vec![single.to_string()];
    }
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[cfg(any(feature = "channel-tcp", feature = "channel-file"))]
fn extract_u64(channel_cfg: &ChannelSection, key: &str) -> Option<u64> {
    channel_cfg
        .extra
        .get(key)
        .and_then(|v| v.as_integer())
        .and_then(|v| u64::try_from(v).ok())
}

#[cfg(feature = "channel-kafka")]
fn extract_string_list_or_single(channel_cfg: &ChannelSection, key: &str) -> Option<String> {
    let value = channel_cfg.extra.get(key)?;
    if let Some(v) = value.as_str() {
        return Some(v.to_string());
    }
    if let Some(values) = value.as_array() {
        let items = values
            .iter()
            .filter_map(|v| v.as_str().map(ToString::to_string))
            .collect::<Vec<_>>();
        if items.is_empty() {
            None
        } else {
            Some(items.join(","))
        }
    } else {
        None
    }
}

#[cfg(feature = "channel-tcp")]
fn extract_tcp_framing(channel_cfg: &ChannelSection) -> TcpFraming {
    match extract_optional(channel_cfg, "framing").as_deref() {
        Some("delimiter") => {
            let delimiter = extract_u64(channel_cfg, "delimiter_byte")
                .and_then(|v| u8::try_from(v).ok())
                .unwrap_or(b'\n');
            TcpFraming::Delimiter(delimiter)
        }
        _ => TcpFraming::LengthPrefixed,
    }
}

fn infer_message_type(msg: &InboundMessage, fallback: &str) -> String {
    if msg.content_type.contains("json") {
        return "json-message".to_string();
    }

    fallback.to_string()
}

#[cfg(any(feature = "channel-http", feature = "channel-grpc"))]
fn extract_inbound_auth(channel_cfg: &ChannelSection) -> Result<InboundAuthConfig, EngineError> {
    let mode = extract_optional(channel_cfg, "auth_mode").unwrap_or_else(|| "disabled".to_string());
    let mode = match mode.as_str() {
        "disabled" => InboundAuthMode::Disabled,
        "static_bearer" => InboundAuthMode::StaticBearer,
        "jwt_hs256" => InboundAuthMode::JwtHs256,
        other => {
            return Err(EngineError::Config(format!(
                "invalid auth_mode `{other}` for channel `{}`",
                channel_cfg.channel_type
            )))
        }
    };

    let required_roles = channel_cfg
        .extra
        .get("auth_required_roles")
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let auth = InboundAuthConfig {
        mode,
        bearer_token: extract_optional(channel_cfg, "auth_bearer_token")
            .map(|value| SecretString::new(value.into_boxed_str())),
        jwt_hs256_secret: extract_optional(channel_cfg, "auth_jwt_hs256_secret")
            .map(|value| SecretString::new(value.into_boxed_str())),
        jwt_issuer: extract_optional(channel_cfg, "auth_jwt_issuer"),
        jwt_audience: extract_optional(channel_cfg, "auth_jwt_audience"),
        required_roles,
        require_mtls_subject: channel_cfg
            .extra
            .get("auth_require_mtls_subject")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        mtls_subject_header: extract_optional(channel_cfg, "auth_mtls_subject_header")
            .unwrap_or_else(|| "x-client-cert-subject".to_string()),
        mtls_allowed_subjects: channel_cfg
            .extra
            .get("auth_mtls_allowed_subjects")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|item| item.as_str().map(ToString::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    };

    match auth.mode {
        InboundAuthMode::Disabled => {
            tracing::warn!(
                channel_type = %channel_cfg.channel_type,
                mode = %channel_cfg.mode,
                "inbound channel auth is disabled"
            );
            Ok(auth)
        }
        InboundAuthMode::StaticBearer => {
            if auth
                .bearer_token
                .as_ref()
                .map(|value| !value.expose_secret().trim().is_empty())
                .unwrap_or(false)
            {
                Ok(auth)
            } else {
                Err(EngineError::Config(
                    "channel auth_mode=static_bearer requires auth_bearer_token".to_string(),
                ))
            }
        }
        InboundAuthMode::JwtHs256 => {
            if auth
                .jwt_hs256_secret
                .as_ref()
                .map(|value| !value.expose_secret().trim().is_empty())
                .unwrap_or(false)
            {
                Ok(auth)
            } else {
                Err(EngineError::Config(
                    "channel auth_mode=jwt_hs256 requires auth_jwt_hs256_secret".to_string(),
                ))
            }
        }
    }
}

fn build_tx_id_prefix(instance_id: &str) -> String {
    let safe_instance = instance_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("TX-{safe_instance}-p{}", std::process::id())
}

fn next_tx_id(prefix: &str) -> String {
    let count = TX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();
    format!("{prefix}-{now}-{count}")
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("config error: {0}")]
    Config(String),
    #[error("no supported pipelines were configured")]
    NoSupportedPipelines,
    #[error("channel task failed for pipeline `{pipeline}` channel `{channel}`: {message}")]
    ChannelRun {
        pipeline: String,
        channel: String,
        message: String,
    },
    #[error("concurrency error: {0}")]
    Concurrency(String),
    #[error("task join error: {0}")]
    TaskJoin(String),
}

#[cfg(test)]
mod tests {
    use mx20022_channels::InboundMessage;
    use mx20022_config::RuntimeConfig;
    use secrecy::ExposeSecret;

    use super::{build_tx_id_prefix, infer_message_type, next_tx_id};
    #[cfg(any(feature = "channel-http", feature = "channel-grpc"))]
    use super::{extract_inbound_auth, EngineError};

    #[test]
    fn infer_message_type_uses_json_marker() {
        let msg = InboundMessage {
            raw: "{\"ok\":true}".to_string(),
            content_type: "application/json".to_string(),
        };
        assert_eq!(infer_message_type(&msg, "pacs.008"), "json-message");
    }

    #[test]
    fn infer_message_type_falls_back_for_xml_and_unknown_types() {
        let xml = InboundMessage {
            raw: "<Document/>".to_string(),
            content_type: "application/xml".to_string(),
        };
        let plain = InboundMessage {
            raw: "plain".to_string(),
            content_type: "text/plain".to_string(),
        };
        assert_eq!(infer_message_type(&xml, "pacs.008"), "pacs.008");
        assert_eq!(infer_message_type(&plain, "pacs.008"), "pacs.008");
    }

    #[test]
    fn tx_id_prefix_includes_instance_id_and_pid() {
        let prefix = build_tx_id_prefix("local.node/01");
        assert!(prefix.starts_with("TX-local-node-01-p"));
    }

    #[test]
    fn next_tx_id_is_prefixed_and_unique() {
        let prefix = "TX-local-01-p1234";
        let first = next_tx_id(prefix);
        let second = next_tx_id(prefix);
        assert!(first.starts_with(prefix));
        assert!(second.starts_with(prefix));
        assert_ne!(first, second);
    }

    #[cfg(any(feature = "channel-http", feature = "channel-grpc"))]
    fn channel_config_block(extra_lines: &str) -> RuntimeConfig {
        let raw = format!(
            r#"
[runtime]
name = "test-runtime"
instance_id = "local-01"

[store]
backend = "sqlite"
url = "sqlite::memory:"

[channels.http-in]
type = "http"
mode = "server"
bind = "127.0.0.1:0"
{extra_lines}

[[pipeline]]
name = "demo"
channel_in = "http-in"
participants = [{{ name = "message-logger" }}]
"#
        );
        RuntimeConfig::parse(&raw).expect("config should parse")
    }

    #[cfg(any(feature = "channel-http", feature = "channel-grpc"))]
    #[test]
    fn extract_inbound_auth_rejects_missing_static_bearer_token() {
        let cfg = channel_config_block(r#"auth_mode = "static_bearer""#);
        let channel = cfg.channels.get("http-in").expect("channel should exist");
        let err = extract_inbound_auth(channel).expect_err("config should be rejected");
        assert!(
            matches!(err, EngineError::Config(message) if message.contains("auth_bearer_token"))
        );
    }

    #[cfg(any(feature = "channel-http", feature = "channel-grpc"))]
    #[test]
    fn extract_inbound_auth_accepts_valid_static_bearer() {
        let cfg = channel_config_block(
            r#"
auth_mode = "static_bearer"
auth_bearer_token = "secret"
"#,
        );
        let channel = cfg.channels.get("http-in").expect("channel should exist");
        let auth = extract_inbound_auth(channel).expect("auth should parse");
        assert!(
            auth.bearer_token
                .as_ref()
                .map(|value| value.expose_secret())
                == Some("secret")
        );
    }

    #[cfg(feature = "channel-http")]
    fn pick_free_port() -> u16 {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("must bind ephemeral port");
        listener.local_addr().expect("must read local addr").port()
    }

    #[cfg(feature = "channel-http")]
    fn runnable_config(port: u16) -> RuntimeConfig {
        RuntimeConfig::parse(&format!(
            r#"
[runtime]
name = "engine-test"
instance_id = "engine-test-01"

[store]
backend = "sqlite"
url = "sqlite::memory:"

[channels.http-in]
type = "http"
mode = "server"
bind = "127.0.0.1:{port}"
auth_mode = "disabled"
allow_plaintext = true

[[pipeline]]
name = "demo"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [{{ name = "message-logger" }}]
"#
        ))
        .expect("config should parse")
    }

    #[cfg(feature = "channel-http")]
    #[tokio::test]
    async fn run_pipelines_returns_ok_when_shutdown_signals_immediately() {
        use std::sync::Arc;

        use super::run_pipelines;
        use crate::app::RuntimeApp;

        let port = pick_free_port();
        let config = runnable_config(port);
        let app = Arc::new(
            RuntimeApp::from_config(&config)
                .await
                .expect("app should build"),
        );
        // Already-resolved future = signal the engine to drain on first poll.
        let shutdown = async {};
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_pipelines(app, config, shutdown),
        )
        .await
        .expect("engine should exit before timeout");
        assert!(result.is_ok(), "engine returned error: {:?}", result.err());
    }

    #[cfg(feature = "channel-http")]
    #[tokio::test]
    async fn run_pipelines_returns_no_supported_pipelines_when_no_inbound_starts() {
        use std::sync::Arc;

        use super::{run_pipelines, EngineError};
        use crate::app::RuntimeApp;

        let port = pick_free_port();
        let mut config = runnable_config(port);
        let app = Arc::new(
            RuntimeApp::from_config(&config)
                .await
                .expect("app should build"),
        );
        // After the app has built (with the real http channel), poison the
        // config so the engine's per-pipeline match rejects every pipeline.
        // The validate() guard runs only at parse time, so direct mutation is
        // legal and exercises the engine's defensive `started == 0` branch.
        if let Some(channel) = config.channels.get_mut("http-in") {
            channel.channel_type = "nonexistent".to_string();
        }
        let result = run_pipelines(app, config, async {}).await;
        assert!(matches!(result, Err(EngineError::NoSupportedPipelines)));
    }

    #[cfg(feature = "channel-http")]
    #[tokio::test]
    async fn shutdown_outbound_channels_invokes_outbound_shutdown_without_error() {
        use std::sync::Arc;

        use crate::app::RuntimeApp;

        // Build an app whose pipeline declares an http outbound; the call
        // must complete without panic regardless of whether the outbound is
        // currently reachable (it is not — the URL is bogus).
        let in_port = pick_free_port();
        let toml = format!(
            r#"
[runtime]
name = "engine-test"
instance_id = "engine-test-02"

[store]
backend = "sqlite"
url = "sqlite::memory:"

[channels.http-in]
type = "http"
mode = "server"
bind = "127.0.0.1:{in_port}"
auth_mode = "disabled"
allow_plaintext = true

[channels.http-out]
type = "http"
mode = "client"
endpoint = "http://127.0.0.1:1/never-listened"
auth_mode = "disabled"
allow_plaintext = true

[[pipeline]]
name = "demo"
channel_in = "http-in"
channel_out = "http-out"
message_types = ["pacs.008"]
participants = [{{ name = "message-logger" }}]
"#
        );
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = Arc::new(
            RuntimeApp::from_config(&config)
                .await
                .expect("app should build"),
        );
        // Direct call — must complete cleanly.
        app.shutdown_outbound_channels().await;
    }
}
