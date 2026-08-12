// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::env;
use std::process;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use mx20022_admin::auth::{AuthConfig as AdminAuthConfig, AuthMode as AdminAuthMode};
use mx20022_admin::controller::{AdminController, AdminControllerError};
use mx20022_admin::grpc;
use mx20022_admin::host;
use mx20022_admin::service::{
    ReloadStatus, RuntimeReloader, RuntimeStatusSnapshot, StoreBackedAdminController,
};
use mx20022_admin::tls::TlsConfig as AdminTlsConfig;
use mx20022_config::RuntimeConfig;
use mx20022_runtime::app::RuntimeApp;
use mx20022_runtime::engine;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    let reload_handle = init_tracing();

    if let Err(error) = run(reload_handle).await {
        tracing::error!(error = %error, "runtime startup failed");
        process::exit(1);
    }
}

/// Install the tracing subscriber with an early filter (RUST_LOG, else "info")
/// and return a reload handle so the runtime can re-target the filter after
/// the config-supplied `runtime.log_level` is known.
fn init_tracing() -> Handle<EnvFilter, tracing_subscriber::Registry> {
    let early = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, handle) = tracing_subscriber::reload::Layer::new(early);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
    handle
}

async fn run(
    reload_handle: Handle<EnvFilter, tracing_subscriber::Registry>,
) -> Result<(), RuntimeBootstrapError> {
    let cli = parse_cli(env::args())?;
    let config = RuntimeConfig::load_from_path(&cli.config_path)?;
    // RUST_LOG wins over runtime.log_level so operators can override at
    // deploy time without editing config. Only re-target if RUST_LOG is unset.
    if env::var_os("RUST_LOG").is_none() {
        if let Ok(filter) = EnvFilter::try_new(&config.runtime.log_level) {
            let _ = reload_handle.modify(|f| *f = filter);
        }
    }
    let app = Arc::new(RuntimeApp::from_config(&config).await?);
    let reload_status = Arc::new(RwLock::new(ReloadStatus {
        config_version: compute_config_version(&cli.config_path)
            .unwrap_or_else(|| "unknown".to_string()),
        last_result: None,
        last_reloaded_at: None,
    }));
    let _reload_watcher = spawn_participant_reload_watcher(
        Arc::clone(&app),
        cli.config_path.clone(),
        Arc::clone(&reload_status),
        config.runtime.participant_reload_poll_ms,
    );

    tracing::info!(
        runtime = %app.runtime_name(),
        instance_id = %app.instance_id(),
        pipelines = app.pipeline_count().await,
        channels = app.channel_names().len(),
        store_backend = %app.store_backend(),
        "runtime configuration loaded"
    );

    tracing::debug!(pipelines = ?app.pipeline_names().await, "pipeline names loaded");

    if config.runtime.recover_incomplete_on_startup {
        let limit = config.runtime.recovery_startup_limit.unwrap_or(500);
        let recovery = app.recover_incomplete_transactions(limit).await?;
        tracing::info!(
            attempted = recovery.attempted,
            recovered = recovery.recovered,
            failed = recovery.failed,
            dead_lettered = recovery.dead_lettered,
            limit,
            "startup recovery run completed"
        );
    }

    let admin_bind = config
        .runtime
        .admin_bind
        .clone()
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    let admin_grpc_bind = config
        .runtime
        .admin_grpc_bind
        .clone()
        .unwrap_or_else(|| "127.0.0.1:9091".to_string());
    let admin_auth = build_admin_auth(&config)?;
    let admin_tls = build_admin_tls(&config);
    let admin_cors_allowed_origins = config.runtime.admin_cors_allowed_origins.clone();
    let service_mode = (cli.run_pipelines, cli.serve_admin, cli.serve_admin_grpc);
    reject_insecure_admin_bind(
        matches!(admin_auth.mode, AdminAuthMode::Disabled),
        config.runtime.admin_allow_insecure_bind,
        cli.serve_admin,
        cli.serve_admin_grpc,
        &admin_bind,
        &admin_grpc_bind,
    )?;

    match service_mode {
        (true, true, true) => {
            let controller =
                build_admin_controller(&app, cli.config_path.clone(), Arc::clone(&reload_status))
                    .await;
            tracing::info!(bind = %admin_bind, grpc_bind = %admin_grpc_bind, "starting admin http+grpc hosts and pipeline engine");

            tokio::select! {
                res = engine::run_pipelines(Arc::clone(&app), config.clone(), shutdown_signal()) => {
                    res.map_err(RuntimeBootstrapError::Engine)?;
                }
                res = host::serve_with_tls_and_cors(&admin_bind, Arc::clone(&controller), admin_auth.clone(), admin_tls.clone(), admin_cors_allowed_origins.clone()) => {
                    res.map_err(RuntimeBootstrapError::AdminHost)?;
                }
                res = grpc::serve_with_tls(&admin_grpc_bind, controller, admin_auth.clone(), admin_tls.clone()) => {
                    res.map_err(RuntimeBootstrapError::AdminGrpcHost)?;
                }
            }
        }
        (true, true, false) => {
            let controller =
                build_admin_controller(&app, cli.config_path.clone(), Arc::clone(&reload_status))
                    .await;
            tracing::info!(bind = %admin_bind, "starting admin host and pipeline engine");

            tokio::select! {
                res = engine::run_pipelines(Arc::clone(&app), config.clone(), shutdown_signal()) => {
                    res.map_err(RuntimeBootstrapError::Engine)?;
                }
                res = host::serve_with_tls_and_cors(&admin_bind, controller, admin_auth.clone(), admin_tls.clone(), admin_cors_allowed_origins.clone()) => {
                    res.map_err(RuntimeBootstrapError::AdminHost)?;
                }
            }
        }
        (true, false, true) => {
            let controller =
                build_admin_controller(&app, cli.config_path.clone(), Arc::clone(&reload_status))
                    .await;
            tracing::info!(grpc_bind = %admin_grpc_bind, "starting admin grpc host and pipeline engine");

            tokio::select! {
                res = engine::run_pipelines(Arc::clone(&app), config.clone(), shutdown_signal()) => {
                    res.map_err(RuntimeBootstrapError::Engine)?;
                }
                res = grpc::serve_with_tls(&admin_grpc_bind, controller, admin_auth.clone(), admin_tls.clone()) => {
                    res.map_err(RuntimeBootstrapError::AdminGrpcHost)?;
                }
            }
        }
        (true, false, false) => {
            tracing::info!("starting pipeline engine");
            engine::run_pipelines(Arc::clone(&app), config.clone(), shutdown_signal())
                .await
                .map_err(RuntimeBootstrapError::Engine)?;
        }
        (false, true, true) => {
            let controller =
                build_admin_controller(&app, cli.config_path.clone(), Arc::clone(&reload_status))
                    .await;
            tracing::info!(bind = %admin_bind, grpc_bind = %admin_grpc_bind, "starting admin http+grpc hosts");

            tokio::select! {
                res = host::serve_with_tls_and_cors(&admin_bind, Arc::clone(&controller), admin_auth.clone(), admin_tls.clone(), admin_cors_allowed_origins.clone()) => {
                    res.map_err(RuntimeBootstrapError::AdminHost)?;
                }
                res = grpc::serve_with_tls(&admin_grpc_bind, controller, admin_auth.clone(), admin_tls.clone()) => {
                    res.map_err(RuntimeBootstrapError::AdminGrpcHost)?;
                }
            }
        }
        (false, true, false) => {
            let controller =
                build_admin_controller(&app, cli.config_path.clone(), Arc::clone(&reload_status))
                    .await;
            tracing::info!(bind = %admin_bind, "starting admin host");
            host::serve_with_tls_and_cors(
                &admin_bind,
                controller,
                admin_auth.clone(),
                admin_tls.clone(),
                admin_cors_allowed_origins.clone(),
            )
            .await
            .map_err(RuntimeBootstrapError::AdminHost)?;
        }
        (false, false, true) => {
            let controller =
                build_admin_controller(&app, cli.config_path.clone(), Arc::clone(&reload_status))
                    .await;
            tracing::info!(grpc_bind = %admin_grpc_bind, "starting admin grpc host");
            grpc::serve_with_tls(&admin_grpc_bind, controller, admin_auth, admin_tls)
                .await
                .map_err(RuntimeBootstrapError::AdminGrpcHost)?;
        }
        (false, false, false) => {
            tracing::info!("mxruntime initialized with no active services (--no-pipelines)");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "failed to install SIGTERM handler; falling back to SIGINT only"
                );
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("received SIGINT");
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received Ctrl-C");
    }
}

fn spawn_participant_reload_watcher(
    app: Arc<RuntimeApp>,
    config_path: String,
    reload_status: Arc<RwLock<ReloadStatus>>,
    poll_ms: Option<u64>,
) -> Option<tokio::task::JoinHandle<()>> {
    let interval_ms = poll_ms?;
    if interval_ms == 0 {
        return None;
    }

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        let mut last_hash = None::<u64>;

        loop {
            ticker.tick().await;

            let bytes = match tokio::fs::read(&config_path).await {
                Ok(content) => content,
                Err(error) => {
                    mx20022_metrics::record_runtime_config_reload("error");
                    mx20022_metrics::record_runtime_config_reload_error("read");
                    tracing::warn!(path = %config_path, error = %error, "participant reload watcher failed to read config");
                    continue;
                }
            };
            let hash = hash_bytes(&bytes);
            if last_hash == Some(hash) {
                continue;
            }
            last_hash = Some(hash);

            let content = match String::from_utf8(bytes) {
                Ok(content) => content,
                Err(error) => {
                    mx20022_metrics::record_runtime_config_reload("error");
                    mx20022_metrics::record_runtime_config_reload_error("utf8");
                    tracing::warn!(path = %config_path, error = %error, "participant reload watcher read invalid UTF-8 config");
                    continue;
                }
            };

            let config = match RuntimeConfig::parse(&content) {
                Ok(config) => config,
                Err(error) => {
                    mx20022_metrics::record_runtime_config_reload("error");
                    mx20022_metrics::record_runtime_config_reload_error("parse");
                    tracing::warn!(path = %config_path, error = %error, "participant reload watcher failed to parse config");
                    continue;
                }
            };

            match app.reload_participant_configs(&config).await {
                Ok(report) => {
                    mx20022_metrics::record_runtime_config_reload("success");
                    let mut status = reload_status.write().await;
                    status.config_version = format!("h{:016x}", hash);
                    status.last_result = Some("success".to_string());
                    status.last_reloaded_at = Some(SystemTime::now());
                    tracing::info!(
                        pipelines = report.pipelines_reloaded,
                        participants = report.participants_reloaded,
                        "participant config watcher applied reload"
                    );
                }
                Err(error) => {
                    mx20022_metrics::record_runtime_config_reload("error");
                    mx20022_metrics::record_runtime_config_reload_error("apply");
                    let mut status = reload_status.write().await;
                    status.last_result = Some(format!("error:{error}"));
                    status.last_reloaded_at = Some(SystemTime::now());
                    tracing::warn!(error = %error, "participant reload watcher rejected config update");
                }
            }
        }
    }))
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let digest = Sha256::digest(bytes);
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

fn build_admin_tls(config: &RuntimeConfig) -> Option<AdminTlsConfig> {
    admin_tls_pair(config).map(|(cert_path, key_path)| AdminTlsConfig {
        cert_path,
        key_path,
    })
}

fn admin_tls_pair(config: &RuntimeConfig) -> Option<(String, String)> {
    match (
        &config.runtime.admin_tls_cert,
        &config.runtime.admin_tls_key,
    ) {
        (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
        (None, None) => None,
        _ => {
            tracing::error!("admin_tls_cert and admin_tls_key must both be set or both be absent");
            None
        }
    }
}

fn reject_insecure_admin_bind(
    auth_disabled: bool,
    allow_insecure: bool,
    serve_admin: bool,
    serve_admin_grpc: bool,
    admin_bind: &str,
    admin_grpc_bind: &str,
) -> Result<(), RuntimeBootstrapError> {
    if !auth_disabled {
        return Ok(());
    }

    let served: Vec<&str> = [
        serve_admin.then_some(admin_bind),
        serve_admin_grpc.then_some(admin_grpc_bind),
    ]
    .into_iter()
    .flatten()
    .collect();
    if served.is_empty() {
        return Ok(());
    }

    if allow_insecure {
        tracing::warn!(
            binds = ?served,
            "admin auth is disabled and admin_allow_insecure_bind=true; admin surface is reachable without credentials"
        );
        return Ok(());
    }

    for bind in served {
        if !is_loopback_bind(bind) {
            return Err(RuntimeBootstrapError::InsecureAdminBind {
                bind: bind.to_string(),
            });
        }
    }
    Ok(())
}

/// Returns true if `bind` (a `host:port` or `[ip]:port` string) points at a
/// loopback address. Conservative: only explicit loopback IP literals
/// (127.0.0.0/8, ::1) and the `localhost` hostname are treated as loopback;
/// any other value (including `0.0.0.0`, `::`, or a resolvable hostname) is
/// treated as non-loopback so that the caller fails closed.
fn is_loopback_bind(bind: &str) -> bool {
    // Strip a trailing port. SocketAddr::parse handles bracketed IPv6.
    let candidate = match bind.rsplit_once(':') {
        Some((host, _port)) => host,
        None => bind,
    };
    let host = candidate.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // 127.0.0.0/8 is loopback; ::1 is the IPv6 loopback.
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn admin_auth_mode(mode: &str) -> Result<AdminAuthMode, RuntimeBootstrapError> {
    match mode {
        "disabled" => Ok(AdminAuthMode::Disabled),
        "legacy_bearer" => Ok(AdminAuthMode::LegacyBearer),
        "jwt_hs256" => Ok(AdminAuthMode::JwtHs256),
        other => Err(RuntimeBootstrapError::InvalidAdminAuthMode {
            mode: other.to_string(),
        }),
    }
}

fn build_admin_auth(config: &RuntimeConfig) -> Result<AdminAuthConfig, RuntimeBootstrapError> {
    let mode = admin_auth_mode(&config.runtime.admin_auth.mode)?;
    if mode == AdminAuthMode::JwtHs256 {
        for (name, roles) in [
            ("ready_roles", &config.runtime.admin_auth.ready_roles),
            ("status_roles", &config.runtime.admin_auth.status_roles),
            ("tx_roles", &config.runtime.admin_auth.tx_roles),
            ("reload_roles", &config.runtime.admin_auth.reload_roles),
        ] {
            if roles.iter().all(|role| role.trim().is_empty()) {
                return Err(RuntimeBootstrapError::AdminJwtMissingRoles {
                    field: name.to_string(),
                });
            }
        }
    }

    Ok(AdminAuthConfig {
        mode,
        jwt_hs256_secret: config.runtime.admin_auth.jwt_hs256_secret.clone(),
        legacy_bearer_token: config.runtime.admin_auth.legacy_bearer_token.clone(),
        legacy_readonly_token: config.runtime.admin_auth.legacy_readonly_token.clone(),
        jwt_issuer: config.runtime.admin_auth.jwt_issuer.clone(),
        jwt_audience: config.runtime.admin_auth.jwt_audience.clone(),
        ready_roles: config.runtime.admin_auth.ready_roles.clone(),
        status_roles: config.runtime.admin_auth.status_roles.clone(),
        tx_roles: config.runtime.admin_auth.tx_roles.clone(),
        reload_roles: config.runtime.admin_auth.reload_roles.clone(),
        require_mtls_subject: config.runtime.admin_auth.require_mtls_subject,
        mtls_subject_header: config.runtime.admin_auth.mtls_subject_header.clone(),
        mtls_allowed_subjects: config.runtime.admin_auth.mtls_allowed_subjects.clone(),
    })
}

async fn build_admin_controller(
    app: &Arc<RuntimeApp>,
    config_path: String,
    reload_status: Arc<RwLock<ReloadStatus>>,
) -> Arc<dyn AdminController> {
    let reloader: Arc<dyn RuntimeReloader> = Arc::new(AppConfigReloader {
        app: Arc::clone(app),
        config_path,
        reload_status: Arc::clone(&reload_status),
    });
    Arc::new(
        StoreBackedAdminController::new(
            app.store_handle(),
            RuntimeStatusSnapshot {
                runtime: app.runtime_name().to_string(),
                pipelines: app.pipeline_names().await,
                channels: app.channel_names(),
                store: app.store_backend().to_string(),
                started_at: SystemTime::now(),
                reload_status,
            },
        )
        .with_reloader(reloader),
    )
}

struct AppConfigReloader {
    app: Arc<RuntimeApp>,
    config_path: String,
    reload_status: Arc<RwLock<ReloadStatus>>,
}

#[async_trait]
impl RuntimeReloader for AppConfigReloader {
    async fn reload(&self) -> Result<String, AdminControllerError> {
        let bytes = tokio::fs::read(&self.config_path).await.map_err(|error| {
            mx20022_metrics::record_runtime_config_reload("error");
            mx20022_metrics::record_runtime_config_reload_error("read");
            AdminControllerError::Internal(format!("reload failed to read config: {error}"))
        })?;
        let raw = String::from_utf8(bytes).map_err(|error| {
            mx20022_metrics::record_runtime_config_reload("error");
            mx20022_metrics::record_runtime_config_reload_error("utf8");
            AdminControllerError::Internal(format!("reload failed to decode UTF-8 config: {error}"))
        })?;
        let version_hash = hash_bytes(raw.as_bytes());
        let config = RuntimeConfig::parse(&raw).map_err(|error| {
            mx20022_metrics::record_runtime_config_reload("error");
            mx20022_metrics::record_runtime_config_reload_error("parse");
            AdminControllerError::Internal(format!("reload failed to parse config: {error}"))
        })?;

        let report = match self.app.reload_participant_configs(&config).await {
            Ok(report) => report,
            Err(error) => {
                mx20022_metrics::record_runtime_config_reload("error");
                mx20022_metrics::record_runtime_config_reload_error("apply");
                let mut status = self.reload_status.write().await;
                status.last_result = Some(format!("error:{error}"));
                status.last_reloaded_at = Some(SystemTime::now());
                return Err(AdminControllerError::Internal(format!(
                    "reload failed: {error}"
                )));
            }
        };

        mx20022_metrics::record_runtime_config_reload("success");
        let mut status = self.reload_status.write().await;
        status.config_version = format!("h{:016x}", version_hash);
        status.last_result = Some("success".to_string());
        status.last_reloaded_at = Some(SystemTime::now());
        Ok(format!(
            "reloaded participant config for {} pipelines and {} participants",
            report.pipelines_reloaded, report.participants_reloaded
        ))
    }
}

fn compute_config_version(path: &str) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|bytes| format!("h{:016x}", hash_bytes(&bytes)))
}

struct CliArgs {
    config_path: String,
    serve_admin: bool,
    serve_admin_grpc: bool,
    run_pipelines: bool,
}

fn parse_cli<I>(args: I) -> Result<CliArgs, RuntimeBootstrapError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter().skip(1);
    let mut config_path = None;
    let mut serve_admin = false;
    let mut serve_admin_grpc = false;
    let mut run_pipelines = true;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = Some(
                    args.next()
                        .ok_or(RuntimeBootstrapError::MissingConfigValue)?,
                );
            }
            "--serve-admin" => {
                serve_admin = true;
            }
            "--serve-admin-grpc" => {
                serve_admin_grpc = true;
            }
            "--no-pipelines" => {
                run_pipelines = false;
            }
            _ => {}
        }
    }

    let config_path = config_path.ok_or(RuntimeBootstrapError::MissingConfigFlag)?;

    Ok(CliArgs {
        config_path,
        serve_admin,
        serve_admin_grpc,
        run_pipelines,
    })
}

#[derive(Debug, thiserror::Error)]
enum RuntimeBootstrapError {
    #[error("missing required --config <path> argument")]
    MissingConfigFlag,
    #[error("--config was provided without a path")]
    MissingConfigValue,
    #[error(transparent)]
    Config(#[from] mx20022_config::ConfigError),
    #[error(transparent)]
    Build(#[from] mx20022_runtime::app::RuntimeBuildError),
    #[error(transparent)]
    AdminHost(#[from] mx20022_admin::host::HostError),
    #[error(transparent)]
    AdminGrpcHost(#[from] mx20022_admin::grpc::GrpcHostError),
    #[error(transparent)]
    Engine(#[from] engine::EngineError),
    #[error("admin service is bound to non-loopback address `{bind}` with auth disabled; refusing to start. Either bind to 127.0.0.1/localhost, enable runtime.admin_auth.mode (legacy_bearer or jwt_hs256), or set runtime.admin_allow_insecure_bind=true to acknowledge the risk")]
    InsecureAdminBind { bind: String },
    #[error(
        "runtime.admin_auth.mode `{mode}` is invalid (expected disabled|legacy_bearer|jwt_hs256)"
    )]
    InvalidAdminAuthMode { mode: String },
    #[error("runtime.admin_auth.{field} must be non-empty when mode=jwt_hs256")]
    AdminJwtMissingRoles { field: String },
}

#[cfg(test)]
mod tests {
    use super::{admin_auth_mode, is_loopback_bind, reject_insecure_admin_bind};

    #[test]
    fn loopback_detection_for_ipv4() {
        assert!(is_loopback_bind("127.0.0.1:9090"));
        assert!(is_loopback_bind("127.1.2.3:9090")); // 127.0.0.0/8 is loopback
    }

    #[test]
    fn loopback_detection_for_ipv6_and_localhost() {
        assert!(is_loopback_bind("[::1]:9090"));
        assert!(is_loopback_bind("localhost:9090"));
        assert!(is_loopback_bind("LOCALHOST:9090"));
    }

    #[test]
    fn non_loopback_binds_fail_closed() {
        assert!(!is_loopback_bind("0.0.0.0:9090"));
        assert!(!is_loopback_bind("[::]:9090"));
        assert!(!is_loopback_bind("10.0.0.5:9090"));
        assert!(!is_loopback_bind("admin.internal:9090"));
    }

    #[test]
    fn insecure_bind_check_ignores_unused_admin_surfaces() {
        let result =
            reject_insecure_admin_bind(true, false, true, false, "127.0.0.1:9090", "0.0.0.0:9091");
        assert!(
            result.is_ok(),
            "unused gRPC bind must not fail HTTP-only serve: {result:?}"
        );

        let grpc_only =
            reject_insecure_admin_bind(true, false, false, true, "0.0.0.0:9090", "127.0.0.1:9091");
        assert!(
            grpc_only.is_ok(),
            "unused HTTP bind must not fail gRPC-only serve: {grpc_only:?}"
        );
    }

    #[test]
    fn insecure_bind_check_rejects_served_non_loopback() {
        let result =
            reject_insecure_admin_bind(true, false, true, false, "0.0.0.0:9090", "127.0.0.1:9091");
        assert!(result.is_err());
    }

    #[test]
    fn unknown_admin_auth_mode_fails_closed() {
        let err = admin_auth_mode("jwt-hs256").expect_err("typo must not become Disabled");
        assert!(err.to_string().contains("jwt-hs256"));
    }

    #[test]
    fn insecure_bind_check_allows_explicit_opt_in() {
        let result =
            reject_insecure_admin_bind(true, true, true, true, "0.0.0.0:9090", "0.0.0.0:9091");
        assert!(result.is_ok());
    }
}
