// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(any(
    feature = "store-sqlite",
    feature = "store-postgres",
    feature = "store-rocksdb"
)))]
compile_error!(
    "at least one store backend feature must be enabled: store-sqlite, store-postgres, or store-rocksdb"
);

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;

#[cfg(feature = "channel-amqp")]
use mx20022_channel_amqp::{AmqpOutboundChannel, AmqpOutboundConfig};
#[cfg(feature = "channel-file")]
use mx20022_channel_file::FileOutboundChannel;
#[cfg(feature = "channel-grpc")]
use mx20022_channel_grpc::{GrpcOutboundChannel, GrpcOutboundConfig};
#[cfg(feature = "channel-http")]
use mx20022_channel_http::{HttpOutboundChannel, HttpOutboundConfig};
#[cfg(feature = "channel-kafka")]
use mx20022_channel_kafka::{KafkaOutboundChannel, KafkaOutboundConfig};
#[cfg(feature = "channel-nats")]
use mx20022_channel_nats::{NatsOutboundChannel, NatsOutboundConfig};
#[cfg(feature = "channel-tcp")]
use mx20022_channel_tcp::{TcpFraming, TcpOutboundChannel, TcpOutboundConfig};
use mx20022_channels::{OutboundChannel, OutboundMessage};
use mx20022_config::{ChannelSection, ParticipantConfig, RuntimeConfig};
use mx20022_correlation::{CorrelationEngine, CorrelationLookupKey};
use mx20022_participants::acknowledgement_builder::AcknowledgementBuilder;
use mx20022_participants::business_rule_validator::BusinessRuleValidator;
use mx20022_participants::cbpr_rule_validator::CbprRuleValidator;
use mx20022_participants::circuit_breaker::CircuitBreaker;
use mx20022_participants::duplicate_checker::{DuplicateChecker, DuplicateKey};
use mx20022_participants::error_response_builder::ErrorResponseBuilder;
use mx20022_participants::fednow_rule_validator::FednowRuleValidator;
use mx20022_participants::message_logger::MessageLogger;
use mx20022_participants::rate_limiter::{LimitScope, RateLimiter};
use mx20022_participants::routing_engine::{RouteRule, RoutingEngine};
use mx20022_participants::schema_validator::SchemaValidator;
use mx20022_participants::sepa_rule_validator::SepaRuleValidator;
use mx20022_participants::status_response_builder::StatusResponseBuilder;
use mx20022_runtime_core::context::{Context, ContextMeta};
use mx20022_runtime_core::participant::Participant;
use mx20022_runtime_core::transaction_manager::{TransactionManager, TransactionReport};
use mx20022_store::{DeadLetter, Store, StoreQuery};
#[cfg(feature = "store-postgres")]
use mx20022_store_postgres::PostgresStore;
#[cfg(feature = "store-rocksdb")]
use mx20022_store_rocksdb::RocksDbStore;
#[cfg(feature = "store-sqlite")]
use mx20022_store_sqlite::SqliteStore;

use crate::application::TransactionUseCase;
use crate::domain::{DomainError, TransactionRequest};

struct ActiveTransactionGuard {
    pipeline: String,
}

impl ActiveTransactionGuard {
    fn new(pipeline: impl Into<String>) -> Self {
        let pipeline = pipeline.into();
        mx20022_metrics::inc_active_transactions(&pipeline);
        Self { pipeline }
    }
}

impl Drop for ActiveTransactionGuard {
    fn drop(&mut self) {
        mx20022_metrics::dec_active_transactions(&self.pipeline);
    }
}

pub struct RuntimeApp {
    pipelines: RwLock<HashMap<String, PipelineRuntime>>,
    store: Arc<dyn Store>,
    correlation: Arc<CorrelationEngine>,
    runtime_name: String,
    instance_id: String,
    channel_names: Vec<String>,
    store_backend: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryReport {
    pub attempted: usize,
    pub recovered: usize,
    pub failed: usize,
    /// Transactions that failed recovery and were moved to the dead-letter
    /// store + marked Poison so they exit the recovery set on the next
    /// restart. Without this, a perpetually-failing tx replays on every
    /// startup forever.
    pub dead_lettered: usize,
}

struct PipelineRuntime {
    message_types: Vec<String>,
    participant_names: Vec<String>,
    manager: Arc<TransactionManager>,
    channel_out: Option<String>,
    outbound: Option<Arc<dyn OutboundChannel>>,
    timeout_ms: Option<u64>,
}

impl Clone for PipelineRuntime {
    fn clone(&self) -> Self {
        Self {
            message_types: self.message_types.clone(),
            participant_names: self.participant_names.clone(),
            manager: Arc::clone(&self.manager),
            channel_out: self.channel_out.clone(),
            outbound: self.outbound.as_ref().map(Arc::clone),
            timeout_ms: self.timeout_ms,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReloadReport {
    pub pipelines_reloaded: usize,
    pub participants_reloaded: usize,
}

impl RuntimeApp {
    pub async fn from_config(config: &RuntimeConfig) -> Result<Self, RuntimeBuildError> {
        let store: Arc<dyn Store> = match config.store.backend.as_str() {
            #[cfg(feature = "store-sqlite")]
            "sqlite" => Arc::new(SqliteStore::with_pool_size(
                config.store.url.clone(),
                config.store.pool_size,
            )?),
            #[cfg(feature = "store-postgres")]
            "postgres" => Arc::new(
                PostgresStore::connect_with_pool_size(
                    config.store.url.clone(),
                    config.store.pool_size,
                )
                .await?,
            ),
            #[cfg(feature = "store-rocksdb")]
            "rocksdb" => Arc::new(RocksDbStore::open(config.store.url.clone())?),
            other => {
                return Err(RuntimeBuildError::UnsupportedStoreBackend(
                    other.to_string(),
                ))
            }
        };

        let correlation = Arc::new(CorrelationEngine::new(Arc::clone(&store)).await?);
        let scan_interval_ms = config
            .runtime
            .correlation_scan_interval_ms
            .unwrap_or(10_000);
        if scan_interval_ms > 0 {
            Arc::clone(&correlation).spawn_timeout_worker(Duration::from_millis(scan_interval_ms));
        }

        let mut pipelines = HashMap::new();

        for pipeline_cfg in &config.pipelines {
            let participants = build_participants(&pipeline_cfg.participants, Arc::clone(&store))?;
            let channel_out = pipeline_cfg.channel_out.clone();
            let outbound = if let Some(channel_name) = channel_out.as_ref() {
                let channel_cfg = config.channels.get(channel_name).ok_or_else(|| {
                    RuntimeBuildError::Channel(format!(
                        "pipeline `{}` references missing channel_out `{}`",
                        pipeline_cfg.name, channel_name
                    ))
                })?;
                Some(build_outbound_channel(channel_name, channel_cfg)?)
            } else {
                None
            };
            let runtime = PipelineRuntime {
                message_types: pipeline_cfg.message_types.clone(),
                participant_names: pipeline_cfg
                    .participants
                    .iter()
                    .map(|participant| participant.name.clone())
                    .collect(),
                manager: Arc::new(TransactionManager::new(participants)),
                channel_out,
                outbound,
                timeout_ms: pipeline_cfg.timeout_ms,
            };
            pipelines.insert(pipeline_cfg.name.clone(), runtime);
        }

        Ok(Self {
            pipelines: RwLock::new(pipelines),
            store,
            correlation,
            runtime_name: config.runtime.name.clone(),
            instance_id: config.runtime.instance_id.clone(),
            channel_names: config.channels.keys().cloned().collect(),
            store_backend: config.store.backend.clone(),
        })
    }

    pub async fn pipeline_count(&self) -> usize {
        self.pipelines.read().await.len()
    }

    pub async fn pipeline_names(&self) -> Vec<String> {
        self.pipelines.read().await.keys().cloned().collect()
    }

    pub fn channel_names(&self) -> Vec<String> {
        self.channel_names.clone()
    }

    pub fn runtime_name(&self) -> &str {
        &self.runtime_name
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn store_backend(&self) -> &str {
        &self.store_backend
    }

    pub fn store_handle(&self) -> Arc<dyn Store> {
        Arc::clone(&self.store)
    }

    /// Shut down every outbound channel currently registered on the app's
    /// pipelines. Errors are logged and swallowed — drain is best-effort and
    /// must not block on a single channel.
    pub async fn shutdown_outbound_channels(&self) {
        let outbounds: Vec<(String, Arc<dyn OutboundChannel>)> = {
            let pipelines = self.pipelines.read().await;
            pipelines
                .iter()
                .filter_map(|(name, pipeline)| {
                    pipeline
                        .outbound
                        .as_ref()
                        .map(|out| (name.clone(), Arc::clone(out)))
                })
                .collect()
        };
        for (pipeline_name, outbound) in outbounds {
            if let Err(error) = outbound.shutdown().await {
                tracing::warn!(
                    pipeline = %pipeline_name,
                    error = %error,
                    "outbound channel shutdown error",
                );
            }
        }
    }

    pub async fn accepts_message_type(&self, pipeline: &str, message_type: &str) -> bool {
        let pipelines = self.pipelines.read().await;
        let Some(runtime) = pipelines.get(pipeline) else {
            return false;
        };

        if runtime.message_types.is_empty() {
            return true;
        }

        runtime.message_types.iter().any(|mt| mt == message_type)
    }

    pub async fn process(
        &self,
        pipeline: &str,
        tx_id: impl Into<String>,
        source_channel: impl Into<String>,
        message_type: impl Into<String>,
        raw_message: impl Into<String>,
    ) -> Result<TransactionReport, RuntimeBuildError> {
        let started = SystemTime::now();
        let runtime = self
            .pipelines
            .read()
            .await
            .get(pipeline)
            .cloned()
            .ok_or_else(|| RuntimeBuildError::UnknownPipeline(pipeline.to_string()))?;

        let now = SystemTime::now();
        let request = TransactionRequest::new(
            tx_id.into(),
            pipeline.to_string(),
            source_channel.into(),
            message_type.into(),
            raw_message.into(),
            HashMap::new(),
            now,
        );
        request.validate()?;
        let tx = &request.record;

        if !self.accepts_message_type(pipeline, &tx.message_type).await {
            return Err(RuntimeBuildError::MessageTypeNotAccepted {
                pipeline: pipeline.to_string(),
                message_type: tx.message_type.clone(),
            });
        }

        let _active_guard = ActiveTransactionGuard::new(pipeline.to_string());
        let mut ctx = Context::new(ContextMeta {
            transaction_id: tx.tx_id.clone(),
            received_at: tx.received_at,
            pipeline: tx.pipeline.clone(),
            source_channel: tx.source_channel.clone(),
            message_type: tx.message_type.clone(),
            raw_message: tx.raw_message.clone(),
        });

        self.store
            .begin_transaction(tx)
            .await
            .map_err(RuntimeBuildError::Store)?;

        let mut report = match runtime.timeout_ms.filter(|timeout_ms| *timeout_ms > 0) {
            Some(timeout_ms) => {
                let timed = tokio::time::timeout(
                    Duration::from_millis(timeout_ms),
                    runtime.manager.process(&mut ctx),
                )
                .await;
                match timed {
                    Ok(result) => result.map_err(RuntimeBuildError::Processing)?,
                    Err(_) => {
                        let context_entries = context_entries_for_tx(&tx.tx_id, &ctx);
                        self.store
                            .batch_append_context_entries(&tx.tx_id, &context_entries)
                            .await
                            .map_err(RuntimeBuildError::Store)?;
                        self.store
                            .complete_transaction(&tx.tx_id, mx20022_store::Outcome::Poison)
                            .await
                            .map_err(RuntimeBuildError::Store)?;
                        let duration_seconds = started
                            .elapsed()
                            .unwrap_or_else(|_| Duration::from_secs(0))
                            .as_secs_f64();
                        mx20022_metrics::record_transaction_duration(
                            pipeline,
                            &tx.message_type,
                            duration_seconds,
                        );
                        mx20022_metrics::record_transaction_total(
                            pipeline,
                            &tx.message_type,
                            "poison",
                        );
                        return Err(RuntimeBuildError::PipelineTimeout {
                            pipeline: pipeline.to_string(),
                            timeout_ms,
                        });
                    }
                }
            }
            None => runtime
                .manager
                .process(&mut ctx)
                .await
                .map_err(RuntimeBuildError::Processing)?,
        };

        let mut outbound_error = None::<String>;
        if report.outcome == mx20022_runtime_core::transaction_manager::Outcome::Committed {
            if let Some(outbound) = runtime.outbound.as_ref() {
                if let Some(payload) = ctx.get_or_none::<String>("response.xml") {
                    let content_type = ctx
                        .get_or_none::<String>("response.content_type")
                        .cloned()
                        .unwrap_or_else(|| "application/xml".to_string());
                    if let Err(error) = outbound
                        .send(OutboundMessage {
                            raw: payload.clone(),
                            content_type,
                        })
                        .await
                    {
                        outbound_error = Some(error.to_string());
                        report.outcome = mx20022_runtime_core::transaction_manager::Outcome::Poison;
                    }
                } else {
                    tracing::warn!(
                        tx_id = %tx.tx_id,
                        pipeline = %pipeline,
                        channel_out = ?runtime.channel_out,
                        "committed transaction has channel_out configured but no response.xml in context"
                    );
                }
            }
        }

        let context_entries = context_entries_for_tx(&tx.tx_id, &ctx);
        self.store
            .batch_append_context_entries(&tx.tx_id, &context_entries)
            .await
            .map_err(RuntimeBuildError::Store)?;

        self.store
            .complete_transaction(&tx.tx_id, TransactionUseCase::map_outcome(report.outcome))
            .await
            .map_err(RuntimeBuildError::Store)?;

        if report.outcome == mx20022_runtime_core::transaction_manager::Outcome::Committed {
            if let Some(key) = ctx.get_or_none::<CorrelationLookupKey>("correlation.lookup_key") {
                self.correlation
                    .match_response(key.clone(), tx.tx_id.clone())
                    .await
                    .map_err(RuntimeBuildError::Correlation)?;
            }
            if let Some(expectation) =
                ctx.get_or_none::<mx20022_store::Expectation>("correlation.expectation")
            {
                self.correlation
                    .register(expectation.clone())
                    .await
                    .map_err(RuntimeBuildError::Correlation)?;
            }
        }

        let duration_seconds = started
            .elapsed()
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs_f64();
        mx20022_metrics::record_transaction_duration(pipeline, &tx.message_type, duration_seconds);
        mx20022_metrics::record_transaction_total(
            pipeline,
            &tx.message_type,
            match report.outcome {
                mx20022_runtime_core::transaction_manager::Outcome::Committed => "committed",
                mx20022_runtime_core::transaction_manager::Outcome::Aborted => "aborted",
                mx20022_runtime_core::transaction_manager::Outcome::Poison => "poison",
            },
        );
        if let Some(error) = outbound_error {
            return Err(RuntimeBuildError::Outbound(error));
        }
        Ok(report)
    }

    pub async fn recover_incomplete_transactions(
        &self,
        limit: usize,
    ) -> Result<RecoveryReport, RuntimeBuildError> {
        let mut report = RecoveryReport::default();
        let states = [
            "RECEIVED",
            "PREPARING",
            "PREPARED",
            "COMMITTING",
            "ABORTING",
        ];

        for state in states {
            let remaining = limit.saturating_sub(report.attempted);
            if remaining == 0 {
                break;
            }

            let result = self
                .store
                .query(StoreQuery {
                    pipeline: None,
                    message_type: None,
                    state: Some(state.to_string()),
                    since: None,
                    until: None,
                    limit: Some(remaining),
                })
                .await
                .map_err(RuntimeBuildError::Store)?;

            for record in result.records {
                report.attempted += 1;
                let tx_id = record.tx_id.clone();
                let pipeline = record.pipeline.clone();
                let state = record.state.clone();
                // Clone raw_message up front; process() takes it by value and
                // we need it again to save a dead letter if recovery fails.
                let raw_message = record.raw_message.clone();
                let recovery = self
                    .process(
                        &pipeline,
                        tx_id.clone(),
                        record.source_channel,
                        record.message_type,
                        record.raw_message,
                    )
                    .await;

                match recovery {
                    Ok(_) => report.recovered += 1,
                    Err(error) => {
                        report.failed += 1;
                        if self
                            .maybe_quarantine_failed_recovery(&tx_id, &state, &raw_message, &error)
                            .await
                        {
                            report.dead_lettered += 1;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    async fn maybe_quarantine_failed_recovery(
        &self,
        tx_id: &str,
        prior_state: &str,
        raw_message: &str,
        error: &RuntimeBuildError,
    ) -> bool {
        let current_state = match self.store.find_by_id(tx_id).await {
            Ok(Some(record)) => record.state,
            Ok(None) => prior_state.to_string(),
            Err(store_err) => {
                tracing::error!(
                    tx_id = %tx_id,
                    error = %store_err,
                    "recovery failed and the row could not be re-read; leaving for retry"
                );
                return false;
            }
        };

        if !recovery_should_quarantine(&current_state, error) {
            tracing::error!(
                tx_id = %tx_id,
                state = %current_state,
                error = %error,
                "recovery replay failed; leaving transaction in place"
            );
            return false;
        }

        tracing::error!(
            tx_id = %tx_id,
            state = %current_state,
            error = %error,
            "startup recovery replay failed permanently; dead-lettering transaction"
        );

        if let Err(dl_error) = self
            .store
            .save_dead_letter(&DeadLetter {
                id: format!("DL-{tx_id}"),
                tx_id: tx_id.to_string(),
                reason: format!("recovery failed: {error}"),
                failed_at: std::time::SystemTime::now(),
                raw_message: raw_message.to_string(),
            })
            .await
        {
            tracing::error!(
                tx_id = %tx_id,
                error = %dl_error,
                "failed to save dead letter during recovery; transaction will replay on next restart"
            );
            return false;
        }
        if let Err(c_error) = self
            .store
            .complete_transaction(tx_id, mx20022_store::Outcome::Poison)
            .await
        {
            tracing::error!(
                tx_id = %tx_id,
                error = %c_error,
                "failed to mark transaction Poison after dead-letter; transaction will replay on next restart"
            );
            return false;
        }
        true
    }

    pub async fn reload_participant_configs(
        &self,
        config: &RuntimeConfig,
    ) -> Result<ReloadReport, RuntimeBuildError> {
        let current = self.pipelines.read().await;

        if current.len() != config.pipelines.len() {
            return Err(RuntimeBuildError::TopologyReloadNotAllowed(
                "pipeline count changed; restart is required".to_string(),
            ));
        }

        for pipeline_cfg in &config.pipelines {
            let Some(existing) = current.get(&pipeline_cfg.name) else {
                return Err(RuntimeBuildError::TopologyReloadNotAllowed(format!(
                    "pipeline `{}` does not exist in running topology",
                    pipeline_cfg.name
                )));
            };
            if existing.message_types != pipeline_cfg.message_types {
                return Err(RuntimeBuildError::TopologyReloadNotAllowed(format!(
                    "pipeline `{}` message_types changed; restart is required",
                    pipeline_cfg.name
                )));
            }
            if existing.channel_out != pipeline_cfg.channel_out {
                return Err(RuntimeBuildError::TopologyReloadNotAllowed(format!(
                    "pipeline `{}` channel_out changed; restart is required",
                    pipeline_cfg.name
                )));
            }
            if existing.timeout_ms != pipeline_cfg.timeout_ms {
                return Err(RuntimeBuildError::TopologyReloadNotAllowed(format!(
                    "pipeline `{}` timeout_ms changed; restart is required",
                    pipeline_cfg.name
                )));
            }

            let incoming_names = pipeline_cfg
                .participants
                .iter()
                .map(|participant| participant.name.clone())
                .collect::<Vec<_>>();
            if existing.participant_names != incoming_names {
                return Err(RuntimeBuildError::TopologyReloadNotAllowed(format!(
                    "pipeline `{}` participant order/topology changed; restart is required",
                    pipeline_cfg.name
                )));
            }
        }
        drop(current);

        let mut rebuilt = HashMap::new();
        for pipeline_cfg in &config.pipelines {
            let participants =
                build_participants(&pipeline_cfg.participants, Arc::clone(&self.store))?;
            let channel_out = pipeline_cfg.channel_out.clone();
            let outbound = if let Some(channel_name) = channel_out.as_ref() {
                let channel_cfg = config.channels.get(channel_name).ok_or_else(|| {
                    RuntimeBuildError::Channel(format!(
                        "pipeline `{}` references missing channel_out `{}`",
                        pipeline_cfg.name, channel_name
                    ))
                })?;
                Some(build_outbound_channel(channel_name, channel_cfg)?)
            } else {
                None
            };
            rebuilt.insert(
                pipeline_cfg.name.clone(),
                PipelineRuntime {
                    message_types: pipeline_cfg.message_types.clone(),
                    participant_names: pipeline_cfg
                        .participants
                        .iter()
                        .map(|participant| participant.name.clone())
                        .collect(),
                    manager: Arc::new(TransactionManager::new(participants)),
                    channel_out,
                    outbound,
                    timeout_ms: pipeline_cfg.timeout_ms,
                },
            );
        }

        let mut pipelines = self.pipelines.write().await;
        for (name, runtime) in rebuilt {
            pipelines.insert(name, runtime);
        }

        Ok(ReloadReport {
            pipelines_reloaded: config.pipelines.len(),
            participants_reloaded: config.pipelines.iter().map(|p| p.participants.len()).sum(),
        })
    }
}

fn context_entries_for_tx(tx_id: &str, ctx: &Context) -> Vec<mx20022_store::ContextEntry> {
    ctx.audit_log()
        .iter()
        .map(|entry| mx20022_store::ContextEntry {
            tx_id: tx_id.to_string(),
            key: entry.key.clone(),
            writer: entry.writer.clone(),
            written_at: entry.written_at,
        })
        .collect()
}

fn build_outbound_channel(
    channel_name: &str,
    channel_cfg: &ChannelSection,
) -> Result<Arc<dyn OutboundChannel>, RuntimeBuildError> {
    match (channel_cfg.channel_type.as_str(), channel_cfg.mode.as_str()) {
        #[cfg(feature = "channel-http")]
        ("http", "client") => Ok(Arc::new(HttpOutboundChannel::new(HttpOutboundConfig {
            name: channel_name.to_string(),
            endpoint: extract_required(channel_cfg, "endpoint")
                .or_else(|_| extract_required(channel_cfg, "url"))?,
            content_type: extract_optional(channel_cfg, "content_type")
                .unwrap_or_else(|| "application/xml".to_string()),
        }))),
        #[cfg(feature = "channel-grpc")]
        ("grpc", "client") => Ok(Arc::new(GrpcOutboundChannel::new(GrpcOutboundConfig {
            name: channel_name.to_string(),
            endpoint: extract_required(channel_cfg, "endpoint")
                .or_else(|_| extract_required(channel_cfg, "url"))?,
            tls_ca_cert_path: extract_optional(channel_cfg, "tls_ca_cert"),
        }))),
        #[cfg(feature = "channel-tcp")]
        ("tcp", "client") => Ok(Arc::new(TcpOutboundChannel::new(TcpOutboundConfig {
            name: channel_name.to_string(),
            endpoint: extract_required(channel_cfg, "endpoint")
                .or_else(|_| extract_required(channel_cfg, "url"))?,
            framing: extract_tcp_framing(channel_cfg),
            content_type: extract_optional(channel_cfg, "content_type")
                .unwrap_or_else(|| "application/xml".to_string()),
        }))),
        #[cfg(feature = "channel-file")]
        ("file", "write") => Ok(Arc::new(FileOutboundChannel::new(
            channel_name.to_string(),
            extract_required(channel_cfg, "directory")?,
            extract_optional(channel_cfg, "extension").unwrap_or_else(|| "xml".to_string()),
        ))),
        #[cfg(feature = "channel-nats")]
        ("nats", "publisher") => Ok(Arc::new(NatsOutboundChannel::new(NatsOutboundConfig {
            name: channel_name.to_string(),
            endpoint: extract_required(channel_cfg, "endpoint")
                .or_else(|_| extract_required(channel_cfg, "url"))?,
            subject: extract_required(channel_cfg, "subject")?,
        }))),
        #[cfg(feature = "channel-kafka")]
        ("kafka", "producer") => Ok(Arc::new(KafkaOutboundChannel::new(KafkaOutboundConfig {
            name: channel_name.to_string(),
            brokers: extract_string_list_or_single(channel_cfg, "brokers")
                .or_else(|| extract_optional(channel_cfg, "bootstrap_servers"))
                .ok_or_else(|| {
                    RuntimeBuildError::Channel(format!(
                        "channel `{channel_name}` requires `brokers` or `bootstrap_servers`"
                    ))
                })?,
            topic: extract_required(channel_cfg, "topic")?,
            security_protocol: extract_optional(channel_cfg, "security_protocol"),
            ssl_ca_location: extract_optional(channel_cfg, "ssl_ca_location")
                .or_else(|| extract_optional(channel_cfg, "tls_ca_cert")),
        }))),
        #[cfg(feature = "channel-amqp")]
        ("amqp", "publisher") => Ok(Arc::new(AmqpOutboundChannel::new(AmqpOutboundConfig {
            name: channel_name.to_string(),
            url: extract_required(channel_cfg, "url")?,
            exchange: extract_optional(channel_cfg, "exchange").unwrap_or_default(),
            routing_key: extract_required(channel_cfg, "routing_key")
                .or_else(|_| extract_required(channel_cfg, "queue"))?,
        }))),
        _ => Err(RuntimeBuildError::Channel(format!(
            "unsupported outbound channel `{channel_name}` type=`{}` mode=`{}`",
            channel_cfg.channel_type, channel_cfg.mode
        ))),
    }
}

fn extract_required(channel_cfg: &ChannelSection, key: &str) -> Result<String, RuntimeBuildError> {
    channel_cfg
        .extra
        .get(key)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| RuntimeBuildError::Channel(format!("channel requires `{key}`")))
}

fn extract_optional(channel_cfg: &ChannelSection, key: &str) -> Option<String> {
    channel_cfg
        .extra
        .get(key)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
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
fn extract_u64(channel_cfg: &ChannelSection, key: &str) -> Option<u64> {
    channel_cfg
        .extra
        .get(key)
        .and_then(|v| v.as_integer())
        .and_then(|v| u64::try_from(v).ok())
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

fn build_participants(
    configs: &[ParticipantConfig],
    store: Arc<dyn Store>,
) -> Result<Vec<Arc<dyn Participant>>, RuntimeBuildError> {
    let registry = ParticipantRegistry::with_defaults();
    configs
        .iter()
        .map(|cfg| registry.build(cfg, Arc::clone(&store)))
        .collect()
}

type ParticipantBuilderFn =
    fn(&ParticipantConfig, Arc<dyn Store>) -> Result<Arc<dyn Participant>, RuntimeBuildError>;

#[derive(Default)]
struct ParticipantRegistry {
    builders: HashMap<&'static str, ParticipantBuilderFn>,
}

impl ParticipantRegistry {
    fn with_defaults() -> Self {
        let mut registry = Self::default();
        registry.register("message-logger", build_message_logger);
        registry.register("schema-validator", build_schema_validator);
        registry.register("fednow-rule-validator", build_fednow_rule_validator);
        registry.register("sepa-rule-validator", build_sepa_rule_validator);
        registry.register("cbpr-rule-validator", build_cbpr_rule_validator);
        registry.register("business-rule-validator", build_business_rule_validator);
        registry.register("status-response-builder", build_status_response_builder);
        registry.register("acknowledgement-builder", build_acknowledgement_builder);
        registry.register("error-response-builder", build_error_response_builder);
        registry.register("duplicate-checker", build_duplicate_checker);
        registry.register("routing-engine", build_routing_engine);
        registry.register("rate-limiter", build_rate_limiter);
        registry.register("circuit-breaker", build_circuit_breaker);
        #[cfg(test)]
        registry.register("slow", build_slow_participant);
        #[cfg(test)]
        registry.register("correlation-key-setter", build_correlation_key_setter);
        #[cfg(test)]
        registry.register(
            "correlation-expectation-setter",
            build_correlation_expectation_setter,
        );
        registry
    }

    fn register(&mut self, name: &'static str, builder: ParticipantBuilderFn) {
        self.builders.insert(name, builder);
    }

    fn build(
        &self,
        cfg: &ParticipantConfig,
        store: Arc<dyn Store>,
    ) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
        let Some(builder) = self.builders.get(cfg.name.as_str()) else {
            return Err(RuntimeBuildError::UnknownParticipant(cfg.name.clone()));
        };
        builder(cfg, store)
    }
}

fn build_message_logger(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let mut participant = MessageLogger::new();
    if let Some(tag) = cfg.config.get("tag").and_then(|v| v.as_str()) {
        participant = participant.with_tag(tag.to_string());
    }
    Ok(Arc::new(participant))
}

fn build_schema_validator(
    _cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    Ok(Arc::new(SchemaValidator::new()))
}

fn build_fednow_rule_validator(
    _cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    Ok(Arc::new(FednowRuleValidator::new()))
}

fn build_sepa_rule_validator(
    _cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    Ok(Arc::new(SepaRuleValidator::new()))
}

fn build_cbpr_rule_validator(
    _cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    Ok(Arc::new(CbprRuleValidator::new()))
}

fn build_business_rule_validator(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let mut validator = BusinessRuleValidator::new();
    if let Some(scheme) = cfg.config.get("scheme").and_then(|v| v.as_str()) {
        validator = validator.with_scheme(match scheme {
            "fednow" => mx20022_participants::business_rule_validator::ValidationScheme::FedNow,
            "sepa" => mx20022_participants::business_rule_validator::ValidationScheme::Sepa,
            "cbpr" => mx20022_participants::business_rule_validator::ValidationScheme::Cbpr,
            other => {
                return Err(RuntimeBuildError::UnknownParticipant(format!(
                    "business-rule-validator scheme `{other}`"
                )));
            }
        });
    }
    Ok(Arc::new(validator))
}

fn build_status_response_builder(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let auto = cfg
        .config
        .get("auto_pacs002")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Ok(Arc::new(StatusResponseBuilder::new(auto)))
}

fn build_acknowledgement_builder(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let overwrite = cfg
        .config
        .get("overwrite_existing")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    Ok(Arc::new(AcknowledgementBuilder::new(overwrite)))
}

fn build_error_response_builder(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let overwrite = cfg
        .config
        .get("overwrite_existing")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    Ok(Arc::new(ErrorResponseBuilder::new(overwrite)))
}

fn build_duplicate_checker(
    cfg: &ParticipantConfig,
    store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let keys = cfg
        .config
        .get("keys")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(|item| match item {
                    "message_id" | "msg_id" => Ok(DuplicateKey::MessageId),
                    "end_to_end_id" | "e2e_id" => Ok(DuplicateKey::EndToEndId),
                    "uetr" => Ok(DuplicateKey::Uetr),
                    other => Err(RuntimeBuildError::UnknownParticipant(format!(
                        "duplicate-checker key `{other}`"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_else(|| {
            vec![
                DuplicateKey::MessageId,
                DuplicateKey::EndToEndId,
                DuplicateKey::Uetr,
            ]
        });
    Ok(Arc::new(DuplicateChecker::new(store).with_keys(keys)))
}

fn build_routing_engine(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let default_route = cfg
        .config
        .get("default_route")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let mut engine = RoutingEngine::new(default_route);

    if let Some(rules) = cfg.config.get("rules").and_then(|value| value.as_array()) {
        for rule in rules {
            let table = rule.as_table().ok_or_else(|| {
                RuntimeBuildError::UnknownParticipant(
                    "routing-engine rule must be an inline table".to_string(),
                )
            })?;
            let destination = table
                .get("destination")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    RuntimeBuildError::UnknownParticipant(
                        "routing-engine rule requires destination".to_string(),
                    )
                })?
                .to_string();
            engine = engine.with_rule(RouteRule {
                destination,
                message_type: table
                    .get("message_type")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string),
                currency: table
                    .get("currency")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string),
                bic_prefix: table
                    .get("bic_prefix")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string),
            });
        }
    }

    Ok(Arc::new(engine))
}

fn build_rate_limiter(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let rate = read_f64(cfg, "rate_per_second").unwrap_or(100.0);
    let burst = read_f64(cfg, "burst").unwrap_or(rate.max(1.0));
    let scope = match cfg
        .config
        .get("scope")
        .and_then(|value| value.as_str())
        .unwrap_or("global")
    {
        "global" => LimitScope::Global,
        "message_type" => LimitScope::MessageType,
        "source_channel" => LimitScope::SourceChannel,
        other => {
            return Err(RuntimeBuildError::UnknownParticipant(format!(
                "rate-limiter scope `{other}`"
            )))
        }
    };
    Ok(Arc::new(RateLimiter::new(
        rate.max(0.1),
        burst.max(1.0),
        scope,
    )))
}

fn build_circuit_breaker(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let threshold = cfg
        .config
        .get("failure_threshold")
        .and_then(|value| value.as_integer())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(5);
    let open_ms = cfg
        .config
        .get("open_ms")
        .and_then(|value| value.as_integer())
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(30_000);
    Ok(Arc::new(CircuitBreaker::new(
        threshold,
        Duration::from_millis(open_ms),
    )))
}

fn read_f64(cfg: &ParticipantConfig, key: &str) -> Option<f64> {
    cfg.config
        .get(key)
        .and_then(|value| value.as_float())
        .or_else(|| {
            cfg.config
                .get(key)
                .and_then(|value| value.as_integer().map(|v| v as f64))
        })
}

const RECOVERY_STATES: &[&str] = &[
    "RECEIVED",
    "PREPARING",
    "PREPARED",
    "COMMITTING",
    "ABORTING",
];

fn recovery_error_is_permanent(error: &RuntimeBuildError) -> bool {
    matches!(
        error,
        RuntimeBuildError::UnknownPipeline(_)
            | RuntimeBuildError::UnknownParticipant(_)
            | RuntimeBuildError::MessageTypeNotAccepted { .. }
    )
}

fn recovery_should_quarantine(current_state: &str, error: &RuntimeBuildError) -> bool {
    RECOVERY_STATES.contains(&current_state) && recovery_error_is_permanent(error)
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeBuildError {
    #[error("unknown participant `{0}`")]
    UnknownParticipant(String),
    #[error("unsupported store backend `{0}`")]
    UnsupportedStoreBackend(String),
    #[error("unknown pipeline `{0}`")]
    UnknownPipeline(String),
    #[error("topology reload is not allowed: {0}")]
    TopologyReloadNotAllowed(String),
    #[error("message type `{message_type}` not accepted by pipeline `{pipeline}`")]
    MessageTypeNotAccepted {
        pipeline: String,
        message_type: String,
    },
    #[error("channel configuration error: {0}")]
    Channel(String),
    #[error("pipeline `{pipeline}` timed out after {timeout_ms}ms")]
    PipelineTimeout { pipeline: String, timeout_ms: u64 },
    #[error("outbound delivery failed: {0}")]
    Outbound(String),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Store(#[from] mx20022_store::StoreError),
    #[error(transparent)]
    Processing(mx20022_runtime_core::transaction_manager::TransactionError),
    #[error(transparent)]
    Correlation(#[from] mx20022_correlation::CorrelationError),
}

#[cfg(test)]
struct SlowParticipant {
    sleep_ms: u64,
}

#[cfg(test)]
#[async_trait::async_trait]
impl Participant for SlowParticipant {
    fn name(&self) -> &str {
        "slow"
    }
    async fn prepare(
        &self,
        _ctx: &mut Context,
    ) -> Result<
        mx20022_runtime_core::participant::Action,
        mx20022_runtime_core::participant::ParticipantError,
    > {
        tokio::time::sleep(Duration::from_millis(self.sleep_ms)).await;
        Ok(mx20022_runtime_core::participant::Action::Prepared)
    }
}

#[cfg(test)]
fn build_slow_participant(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let sleep_ms = cfg
        .config
        .get("sleep_ms")
        .and_then(|v| v.as_integer())
        .map(|v| v as u64)
        .unwrap_or(100);
    Ok(Arc::new(SlowParticipant { sleep_ms }))
}

#[cfg(test)]
struct CorrelationKeySetter {
    correlation_key: String,
    expected_message_type: String,
}

#[cfg(test)]
#[async_trait::async_trait]
impl Participant for CorrelationKeySetter {
    fn name(&self) -> &str {
        "correlation-key-setter"
    }
    async fn prepare(
        &self,
        ctx: &mut Context,
    ) -> Result<
        mx20022_runtime_core::participant::Action,
        mx20022_runtime_core::participant::ParticipantError,
    > {
        ctx.put(
            "correlation.lookup_key",
            CorrelationLookupKey {
                correlation_key: self.correlation_key.clone(),
                expected_message_type: self.expected_message_type.clone(),
            },
        );
        Ok(mx20022_runtime_core::participant::Action::Prepared)
    }
}

#[cfg(test)]
fn build_correlation_key_setter(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let correlation_key = cfg
        .config
        .get("correlation_key")
        .and_then(|v| v.as_str())
        .unwrap_or("MSG-DEFAULT")
        .to_string();
    let expected_message_type = cfg
        .config
        .get("expected_message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("pacs.002")
        .to_string();
    Ok(Arc::new(CorrelationKeySetter {
        correlation_key,
        expected_message_type,
    }))
}

#[cfg(test)]
struct CorrelationExpectationSetter {
    expectation_id: String,
    correlation_key: String,
    expected_message_type: String,
    timeout_ms: u64,
}

#[cfg(test)]
#[async_trait::async_trait]
impl Participant for CorrelationExpectationSetter {
    fn name(&self) -> &str {
        "correlation-expectation-setter"
    }
    async fn prepare(
        &self,
        ctx: &mut Context,
    ) -> Result<
        mx20022_runtime_core::participant::Action,
        mx20022_runtime_core::participant::ParticipantError,
    > {
        ctx.put(
            "correlation.expectation",
            mx20022_store::Expectation {
                id: self.expectation_id.clone(),
                correlation_key: self.correlation_key.clone(),
                expected_message_type: self.expected_message_type.clone(),
                timeout_at: SystemTime::now() + Duration::from_millis(self.timeout_ms),
            },
        );
        Ok(mx20022_runtime_core::participant::Action::Prepared)
    }
}

#[cfg(test)]
fn build_correlation_expectation_setter(
    cfg: &ParticipantConfig,
    _store: Arc<dyn Store>,
) -> Result<Arc<dyn Participant>, RuntimeBuildError> {
    let expectation_id = cfg
        .config
        .get("expectation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("EXP-DEFAULT")
        .to_string();
    let correlation_key = cfg
        .config
        .get("correlation_key")
        .and_then(|v| v.as_str())
        .unwrap_or("MSG-DEFAULT")
        .to_string();
    let expected_message_type = cfg
        .config
        .get("expected_message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("pacs.002")
        .to_string();
    let timeout_ms = cfg
        .config
        .get("timeout_ms")
        .and_then(|v| v.as_integer())
        .map(|v| v as u64)
        .unwrap_or(60_000);
    Ok(Arc::new(CorrelationExpectationSetter {
        expectation_id,
        correlation_key,
        expected_message_type,
        timeout_ms,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use mx20022_config::RuntimeConfig;
    use mx20022_runtime_core::transaction_manager::Outcome;
    use mx20022_store::{Store, TransactionRecord};

    use crate::app::{RuntimeApp, RuntimeBuildError};

    const TEST_CONFIG: &str = r#"
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

[[pipeline]]
name = "demo"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "message-logger", config = {} },
]
"#;

    #[tokio::test]
    async fn builds_runtime_from_valid_config() {
        let config = RuntimeConfig::parse(TEST_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        assert_eq!(app.pipeline_count().await, 1);
        assert!(app.accepts_message_type("demo", "pacs.008").await);
        assert!(!app.accepts_message_type("demo", "pacs.002").await);
    }

    #[tokio::test]
    async fn processes_message_through_pipeline() {
        let config = RuntimeConfig::parse(TEST_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        let report = app
            .process("demo", "TX-42", "http-in", "pacs.008", "<Document/>")
            .await
            .expect("process should succeed");

        assert_eq!(report.outcome, Outcome::Committed);
    }

    const DUPLICATE_GUARD_CONFIG: &str = r#"
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

[[pipeline]]
name = "duplicate-guard"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "error-response-builder", config = { overwrite_existing = true } },
  { name = "duplicate-checker", config = { keys = ["message_id"] } },
]
"#;

    const OUTBOUND_CONFIG: &str = r#"
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

[channels.http-out]
type = "http"
mode = "client"
endpoint = "http://127.0.0.1:9/outbox"

[[pipeline]]
name = "outbound"
channel_in = "http-in"
channel_out = "http-out"
message_types = ["pacs.008"]
participants = [
  { name = "acknowledgement-builder", config = {} },
]
"#;

    #[tokio::test]
    async fn duplicate_checker_aborts_pipeline_when_message_id_exists() {
        let config = RuntimeConfig::parse(DUPLICATE_GUARD_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        let store: Arc<dyn Store> = app.store_handle();
        let mut key_fields = HashMap::new();
        key_fields.insert("message_id".to_string(), "MSG-DUP-1".to_string());
        store
            .begin_transaction(&TransactionRecord {
                tx_id: "TX-OLD".to_string(),
                pipeline: "duplicate-guard".to_string(),
                source_channel: "http-in".to_string(),
                message_type: "pacs.008".to_string(),
                raw_message: "<Document/>".to_string(),
                state: "COMMITTED".to_string(),
                received_at: SystemTime::now(),
                completed_at: Some(SystemTime::now()),
                key_fields,
            })
            .await
            .expect("seed tx should succeed");

        let xml = "<Document><FIToFICstmrCdtTrf><GrpHdr><MsgId>MSG-DUP-1</MsgId></GrpHdr></FIToFICstmrCdtTrf></Document>";
        let report = app
            .process("duplicate-guard", "TX-NEW", "http-in", "pacs.008", xml)
            .await
            .expect("process should return report");

        assert_eq!(report.outcome, Outcome::Aborted);
    }

    #[tokio::test]
    async fn outbound_delivery_failure_marks_transaction_poison() {
        let config = RuntimeConfig::parse(OUTBOUND_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");
        let err = app
            .process("outbound", "TX-OUT-1", "http-in", "pacs.008", "<Document/>")
            .await
            .expect_err("outbound send should fail");
        assert!(
            err.to_string().contains("outbound delivery failed"),
            "unexpected error: {err}"
        );

        let record = app
            .store_handle()
            .find_by_id("TX-OUT-1")
            .await
            .expect("lookup")
            .expect("record");
        assert_eq!(record.state, "POISON");
    }

    const RECOVERY_CONFIG: &str = r#"
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

[[pipeline]]
name = "recovery"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "message-logger", config = {} },
]
"#;

    #[tokio::test]
    async fn recovers_incomplete_transactions_from_store() {
        let config = RuntimeConfig::parse(RECOVERY_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        let store: Arc<dyn Store> = app.store_handle();
        store
            .begin_transaction(&TransactionRecord {
                tx_id: "TX-REC-1".to_string(),
                pipeline: "recovery".to_string(),
                source_channel: "http-in".to_string(),
                message_type: "pacs.008".to_string(),
                raw_message: "<Document/>".to_string(),
                state: "PREPARING".to_string(),
                received_at: SystemTime::now(),
                completed_at: None,
                key_fields: HashMap::new(),
            })
            .await
            .expect("seed tx should succeed");

        let report = app
            .recover_incomplete_transactions(10)
            .await
            .expect("recovery should run");
        assert_eq!(report.attempted, 1);
        assert_eq!(report.recovered, 1);
        assert_eq!(report.failed, 0);

        let updated = store
            .find_by_id("TX-REC-1")
            .await
            .expect("lookup should succeed")
            .expect("record should exist");
        assert_eq!(updated.state, "COMMITTED");
    }

    #[tokio::test]
    async fn recovery_dead_letters_transactions_that_fail_replay() {
        // Permanent recovery failures (unknown pipeline) must leave the
        // recovery query set via dead-letter + Poison.
        let config = RuntimeConfig::parse(RECOVERY_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        let store: Arc<dyn Store> = app.store_handle();
        // Seed a tx whose pipeline does not exist in the config, so process()
        // returns UnknownPipeline and recovery fails deterministically.
        store
            .begin_transaction(&TransactionRecord {
                tx_id: "TX-REC-FAIL".to_string(),
                pipeline: "nonexistent-pipeline".to_string(),
                source_channel: "http-in".to_string(),
                message_type: "pacs.008".to_string(),
                raw_message: "<Document/>".to_string(),
                state: "PREPARING".to_string(),
                received_at: SystemTime::now(),
                completed_at: None,
                key_fields: HashMap::new(),
            })
            .await
            .expect("seed tx should succeed");

        let report = app
            .recover_incomplete_transactions(10)
            .await
            .expect("recovery should run");
        assert_eq!(report.attempted, 1);
        assert_eq!(report.recovered, 0);
        assert_eq!(report.failed, 1);
        assert_eq!(report.dead_lettered, 1);

        // The failed tx is now Poison (outside the recovery query states),
        // so a second recovery pass does not replay it.
        let second = app
            .recover_incomplete_transactions(10)
            .await
            .expect("recovery should run");
        assert_eq!(second.attempted, 0, "failed tx should not replay");

        let updated = store
            .find_by_id("TX-REC-FAIL")
            .await
            .expect("lookup should succeed")
            .expect("record should exist");
        assert_eq!(updated.state, "POISON");

        // The raw message is preserved in the dead-letter store for operator
        // replay once the root cause is fixed.
        use mx20022_store::DeadLetterQuery;
        let letters = store
            .list_dead_letters(DeadLetterQuery {
                pipeline: None,
                limit: Some(10),
            })
            .await
            .expect("list dead letters");
        assert_eq!(letters.len(), 1);
        assert_eq!(letters[0].tx_id, "TX-REC-FAIL");
        assert_eq!(letters[0].raw_message, "<Document/>");
    }

    #[test]
    fn recovery_quarantine_skips_terminal_and_retryable_errors() {
        use super::{recovery_should_quarantine, RuntimeBuildError};

        let permanent = RuntimeBuildError::UnknownPipeline("missing".to_string());
        let retryable = RuntimeBuildError::Outbound("downstream down".to_string());

        assert!(recovery_should_quarantine("PREPARING", &permanent));
        assert!(!recovery_should_quarantine("COMMITTED", &permanent));
        assert!(!recovery_should_quarantine("POISON", &permanent));
        assert!(!recovery_should_quarantine("PREPARING", &retryable));
        assert!(!recovery_should_quarantine("COMMITTING", &retryable));
    }

    #[tokio::test]
    async fn recovery_does_not_poison_already_committed_row() {
        let config = RuntimeConfig::parse(RECOVERY_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        let store: Arc<dyn Store> = app.store_handle();
        store
            .begin_transaction(&TransactionRecord {
                tx_id: "TX-REC-COMMITTED".to_string(),
                pipeline: "recovery".to_string(),
                source_channel: "http-in".to_string(),
                message_type: "pacs.008".to_string(),
                raw_message: "<Document/>".to_string(),
                state: "COMMITTED".to_string(),
                received_at: SystemTime::now(),
                completed_at: None,
                key_fields: HashMap::new(),
            })
            .await
            .expect("seed tx should succeed");

        let quarantined = app
            .maybe_quarantine_failed_recovery(
                "TX-REC-COMMITTED",
                "PREPARING",
                "<Document/>",
                &RuntimeBuildError::UnknownPipeline("missing".to_string()),
            )
            .await;
        assert!(!quarantined);

        let updated = store
            .find_by_id("TX-REC-COMMITTED")
            .await
            .expect("lookup should succeed")
            .expect("record should exist");
        assert_eq!(updated.state, "COMMITTED");
    }

    const RELOAD_CONFIG_BASE: &str = r#"
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

[[pipeline]]
name = "reloadable"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "rate-limiter", config = { rate_per_second = 10, burst = 20, scope = "global" } },
  { name = "message-logger", config = { tag = "v1" } },
]
"#;

    const RELOAD_CONFIG_UPDATED: &str = r#"
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

[[pipeline]]
name = "reloadable"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "rate-limiter", config = { rate_per_second = 100, burst = 200, scope = "source_channel" } },
  { name = "message-logger", config = { tag = "v2" } },
]
"#;

    const RELOAD_CONFIG_TOPOLOGY_CHANGE: &str = r#"
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

[[pipeline]]
name = "reloadable"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "message-logger", config = { tag = "v2" } },
]
"#;

    #[tokio::test]
    async fn reloads_participant_configs_when_topology_is_unchanged() {
        let base = RuntimeConfig::parse(RELOAD_CONFIG_BASE).expect("base config should parse");
        let app = RuntimeApp::from_config(&base)
            .await
            .expect("app should build");
        let updated =
            RuntimeConfig::parse(RELOAD_CONFIG_UPDATED).expect("updated config should parse");

        let report = app
            .reload_participant_configs(&updated)
            .await
            .expect("reload should succeed");
        assert_eq!(report.pipelines_reloaded, 1);
        assert_eq!(report.participants_reloaded, 2);
    }

    #[tokio::test]
    async fn rejects_reload_when_participant_topology_changes() {
        let base = RuntimeConfig::parse(RELOAD_CONFIG_BASE).expect("base config should parse");
        let app = RuntimeApp::from_config(&base)
            .await
            .expect("app should build");
        let changed = RuntimeConfig::parse(RELOAD_CONFIG_TOPOLOGY_CHANGE)
            .expect("changed config should parse");

        let error = app
            .reload_participant_configs(&changed)
            .await
            .expect_err("reload should fail");
        assert!(
            error
                .to_string()
                .contains("participant order/topology changed"),
            "unexpected error: {error}"
        );
    }

    const TIMEOUT_CONFIG: &str = r#"
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

[[pipeline]]
name = "timeout-pipeline"
channel_in = "http-in"
message_types = ["pacs.008"]
timeout_ms = 1
participants = [
  { name = "slow", config = { sleep_ms = 100 } },
]
"#;

    #[tokio::test]
    async fn timeout_forces_poison_state() {
        let config = RuntimeConfig::parse(TIMEOUT_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        let err = app
            .process(
                "timeout-pipeline",
                "TX-TO-1",
                "http-in",
                "pacs.008",
                "<Document/>",
            )
            .await
            .expect_err("should timeout");

        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );

        let record = app
            .store_handle()
            .find_by_id("TX-TO-1")
            .await
            .expect("lookup")
            .expect("record");
        assert_eq!(record.state, "POISON");
    }

    const CORRELATION_MATCH_CONFIG: &str = r#"
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

[[pipeline]]
name = "correlation-match"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "correlation-key-setter", config = { correlation_key = "MSG-CORR-1", expected_message_type = "pacs.002" } },
]
"#;

    #[tokio::test]
    async fn correlation_match_response_invoked_for_committed_transaction() {
        let config = RuntimeConfig::parse(CORRELATION_MATCH_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        // Seed the store with a pending expectation that our lookup key will match
        let store: Arc<dyn Store> = app.store_handle();
        store
            .save_expectation(&mx20022_store::Expectation {
                id: "EXP-MATCH-1".to_string(),
                correlation_key: "MSG-CORR-1".to_string(),
                expected_message_type: "pacs.002".to_string(),
                timeout_at: SystemTime::now() + Duration::from_secs(60),
            })
            .await
            .expect("seed expectation should succeed");

        let report = app
            .process(
                "correlation-match",
                "TX-CORR-1",
                "http-in",
                "pacs.008",
                "<Document/>",
            )
            .await
            .expect("process should succeed");

        assert_eq!(report.outcome, Outcome::Committed);

        // The expectation should have been matched (no longer pending)
        let pending = store
            .count_pending_expectations()
            .await
            .expect("count should succeed");
        assert_eq!(
            pending, 0,
            "expectation should have been matched and removed from pending"
        );
    }

    const CORRELATION_REGISTER_CONFIG: &str = r#"
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

[[pipeline]]
name = "correlation-register"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "correlation-expectation-setter", config = { expectation_id = "EXP-REG-1", correlation_key = "MSG-CORR-2", expected_message_type = "pacs.002", timeout_ms = 60000 } },
]
"#;

    #[tokio::test]
    async fn correlation_register_invoked_for_committed_transaction() {
        let config =
            RuntimeConfig::parse(CORRELATION_REGISTER_CONFIG).expect("config should parse");
        let app = RuntimeApp::from_config(&config)
            .await
            .expect("app should build");

        let report = app
            .process(
                "correlation-register",
                "TX-CORR-2",
                "http-in",
                "pacs.008",
                "<Document/>",
            )
            .await
            .expect("process should succeed");

        assert_eq!(report.outcome, Outcome::Committed);

        // The expectation should have been registered in the store
        let store: Arc<dyn Store> = app.store_handle();
        let pending = store
            .load_pending_expectations()
            .await
            .expect("load should succeed");
        assert_eq!(pending.len(), 1, "expectation should have been registered");
        assert_eq!(pending[0].id, "EXP-REG-1");
        assert_eq!(pending[0].correlation_key, "MSG-CORR-2");
        assert_eq!(pending[0].expected_message_type, "pacs.002");
    }

    // ── Builder config tests: happy-path ───────────────────────────

    macro_rules! builder_config {
        ($name:expr, $config:expr) => {
            format!(
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

[[pipeline]]
name = "test-pipeline"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  {{ name = "{}", config = {{ {} }} }},
]
"#,
                $name, $config
            )
        };
    }

    #[tokio::test]
    async fn build_message_logger_extracts_tag() {
        let toml = builder_config!("message-logger", "tag = 'audit'");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(app.is_ok(), "message-logger with tag should build");
    }

    #[tokio::test]
    async fn build_business_rule_validator_extracts_scheme() {
        for scheme in &["fednow", "sepa", "cbpr"] {
            let toml = builder_config!("business-rule-validator", format!("scheme = '{}'", scheme));
            let config = RuntimeConfig::parse(&toml).expect("config should parse");
            let app = RuntimeApp::from_config(&config).await;
            assert!(
                app.is_ok(),
                "business-rule-validator with scheme '{}' should build",
                scheme
            );
        }
    }

    #[tokio::test]
    async fn build_duplicate_checker_extracts_keys() {
        let toml = builder_config!(
            "duplicate-checker",
            "keys = ['message_id', 'end_to_end_id', 'uetr']"
        );
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(app.is_ok(), "duplicate-checker with keys should build");
    }

    #[tokio::test]
    async fn build_routing_engine_extracts_rules() {
        let toml = builder_config!(
            "routing-engine",
            "default_route = 'eu-out', rules = [{destination = 'us-out', message_type = 'pacs.008'}]"
        );
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(app.is_ok(), "routing-engine with rules should build");
    }

    #[tokio::test]
    async fn build_rate_limiter_extracts_scope() {
        for scope in &["global", "message_type", "source_channel"] {
            let toml = builder_config!(
                "rate-limiter",
                format!("rate_per_second = 50.0, burst = 100.0, scope = '{}'", scope)
            );
            let config = RuntimeConfig::parse(&toml).expect("config should parse");
            let app = RuntimeApp::from_config(&config).await;
            assert!(
                app.is_ok(),
                "rate-limiter with scope '{}' should build",
                scope
            );
        }
    }

    #[tokio::test]
    async fn build_circuit_breaker_extracts_threshold() {
        let toml = builder_config!("circuit-breaker", "failure_threshold = 10, open_ms = 5000");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(app.is_ok(), "circuit-breaker with threshold should build");
    }

    #[tokio::test]
    async fn build_status_response_builder_extracts_auto_pacs002() {
        let toml = builder_config!("status-response-builder", "auto_pacs002 = false");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(
            app.is_ok(),
            "status-response-builder with auto_pacs002 should build"
        );
    }

    #[tokio::test]
    async fn build_acknowledgement_builder_extracts_overwrite() {
        let toml = builder_config!("acknowledgement-builder", "overwrite_existing = true");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(
            app.is_ok(),
            "acknowledgement-builder with overwrite should build"
        );
    }

    #[tokio::test]
    async fn build_error_response_builder_extracts_overwrite() {
        let toml = builder_config!("error-response-builder", "overwrite_existing = true");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(
            app.is_ok(),
            "error-response-builder with overwrite should build"
        );
    }

    // ── Builder config tests: invalid config rejection ─────────────

    #[tokio::test]
    async fn build_business_rule_validator_rejects_unknown_scheme() {
        let toml = builder_config!("business-rule-validator", "scheme = 'unknown-scheme'");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let err = match RuntimeApp::from_config(&config).await {
            Ok(_) => panic!("unknown scheme should fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("unknown-scheme"),
            "error should mention the bad scheme: {}",
            err
        );
    }

    #[tokio::test]
    async fn build_duplicate_checker_rejects_unknown_key() {
        let toml = builder_config!("duplicate-checker", "keys = ['bogus_field']");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let err = match RuntimeApp::from_config(&config).await {
            Ok(_) => panic!("unknown key should fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("bogus_field"),
            "error should mention the bad key: {}",
            err
        );
    }

    #[tokio::test]
    async fn build_routing_engine_rejects_rule_without_destination() {
        let toml = builder_config!("routing-engine", "rules = [{message_type = 'pacs.008'}]");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let err = match RuntimeApp::from_config(&config).await {
            Ok(_) => panic!("rule without destination should fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("destination"),
            "error should mention missing destination: {}",
            err
        );
    }

    #[tokio::test]
    async fn build_rate_limiter_rejects_unknown_scope() {
        let toml = builder_config!("rate-limiter", "scope = 'per_participant'");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let err = match RuntimeApp::from_config(&config).await {
            Ok(_) => panic!("unknown scope should fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("per_participant"),
            "error should mention the bad scope: {}",
            err
        );
    }

    // ── Builder config tests: graceful handling of invalid types ───

    #[tokio::test]
    async fn build_message_logger_handles_non_string_tag() {
        let toml = builder_config!("message-logger", "tag = 12345");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(app.is_ok(), "message-logger should ignore non-string tag");
    }

    #[tokio::test]
    async fn build_circuit_breaker_handles_non_integer_threshold() {
        let toml = builder_config!("circuit-breaker", "failure_threshold = 'not-a-number'");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(
            app.is_ok(),
            "circuit-breaker should ignore non-integer threshold"
        );
    }

    #[tokio::test]
    async fn build_status_response_builder_handles_non_bool_auto() {
        let toml = builder_config!("status-response-builder", "auto_pacs002 = 'yes'");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(
            app.is_ok(),
            "status-response-builder should ignore non-bool auto_pacs002"
        );
    }

    #[tokio::test]
    async fn build_acknowledgement_builder_handles_non_bool_overwrite() {
        let toml = builder_config!("acknowledgement-builder", "overwrite_existing = 'yes'");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(
            app.is_ok(),
            "acknowledgement-builder should ignore non-bool overwrite"
        );
    }

    #[tokio::test]
    async fn build_error_response_builder_handles_non_bool_overwrite() {
        let toml = builder_config!("error-response-builder", "overwrite_existing = 'yes'");
        let config = RuntimeConfig::parse(&toml).expect("config should parse");
        let app = RuntimeApp::from_config(&config).await;
        assert!(
            app.is_ok(),
            "error-response-builder should ignore non-bool overwrite"
        );
    }

    // ── T6: Negative Config Path Tests ───────────────────────────────────────

    const UNSUPPORTED_STORE_BACKEND_CONFIG: &str = r#"
[runtime]
name = "test-runtime"
instance_id = "local-01"

[store]
backend = "mongodb"
url = "mongodb://localhost:27017/test"

[channels.http-in]
type = "http"
mode = "server"
bind = "127.0.0.1:0"

[[pipeline]]
name = "demo"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "message-logger", config = {} },
]
"#;

    #[tokio::test]
    async fn unsupported_store_backend_returns_error() {
        let config =
            RuntimeConfig::parse(UNSUPPORTED_STORE_BACKEND_CONFIG).expect("config should parse");
        match RuntimeApp::from_config(&config).await {
            Err(RuntimeBuildError::UnsupportedStoreBackend(backend)) => {
                assert_eq!(backend, "mongodb");
            }
            Err(other) => panic!("expected UnsupportedStoreBackend, got: {:?}", other),
            Ok(_) => panic!("should reject unsupported store backend"),
        }
    }

    const INCOMPATIBLE_OUTBOUND_CHANNEL_CONFIG: &str = r#"
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

[[pipeline]]
name = "bad-outbound"
channel_in = "http-in"
channel_out = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "message-logger", config = {} },
]
"#;

    #[tokio::test]
    async fn incompatible_outbound_channel_returns_error() {
        // Config validation only checks that channel_out *exists* in the
        // channels map — it does not verify type/mode compatibility.
        // from_config catches the case when the referenced channel cannot
        // serve as an outbound (e.g., a server-mode channel).
        let config = RuntimeConfig::parse(INCOMPATIBLE_OUTBOUND_CHANNEL_CONFIG)
            .expect("config should parse (validation passes)");
        match RuntimeApp::from_config(&config).await {
            Err(RuntimeBuildError::Channel(msg)) => {
                assert!(
                    msg.contains("unsupported outbound channel"),
                    "error should describe unsupported outbound, got: {}",
                    msg
                );
                assert!(
                    msg.contains("http-in"),
                    "error should mention the channel name, got: {}",
                    msg
                );
            }
            Err(other) => panic!("expected Channel error, got: {:?}", other),
            Ok(_) => panic!("should reject server-mode channel as outbound"),
        }
    }

    const UNKNOWN_PARTICIPANT_CONFIG: &str = r#"
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

[[pipeline]]
name = "demo"
channel_in = "http-in"
message_types = ["pacs.008"]
participants = [
  { name = "nonexistent-participant", config = {} },
]
"#;

    #[tokio::test]
    async fn unknown_participant_name_returns_error() {
        let config = RuntimeConfig::parse(UNKNOWN_PARTICIPANT_CONFIG).expect("config should parse");
        match RuntimeApp::from_config(&config).await {
            Err(RuntimeBuildError::UnknownParticipant(name)) => {
                assert_eq!(name, "nonexistent-participant");
            }
            Err(other) => panic!("expected UnknownParticipant, got: {:?}", other),
            Ok(_) => panic!("should reject unknown participant name"),
        }
    }
}
