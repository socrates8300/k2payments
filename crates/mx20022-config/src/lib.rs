// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    pub runtime: RuntimeSection,
    pub store: StoreSection,
    #[serde(default)]
    pub channels: HashMap<String, ChannelSection>,
    #[serde(default, rename = "pipeline")]
    pub pipelines: Vec<PipelineSection>,
}

impl RuntimeConfig {
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let mut value: toml::Value = toml::from_str(content)?;
        resolve_value_secrets(&mut value)?;
        let cfg: RuntimeConfig = value.try_into()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::parse(&content)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.runtime.name.trim().is_empty() {
            return Err(ConfigError::Validation(
                "runtime.name must not be empty".to_string(),
            ));
        }

        if self.runtime.instance_id.trim().is_empty() {
            return Err(ConfigError::Validation(
                "runtime.instance_id must not be empty".to_string(),
            ));
        }

        if self.pipelines.is_empty() {
            return Err(ConfigError::Validation(
                "at least one [[pipeline]] is required".to_string(),
            ));
        }

        for pipeline in &self.pipelines {
            if pipeline.name.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "pipeline.name must not be empty".to_string(),
                ));
            }

            if !self.channels.contains_key(&pipeline.channel_in) {
                return Err(ConfigError::Validation(format!(
                    "pipeline `{}` references missing channel_in `{}`",
                    pipeline.name, pipeline.channel_in
                )));
            }

            if let Some(channel_out) = &pipeline.channel_out {
                if !self.channels.contains_key(channel_out) {
                    return Err(ConfigError::Validation(format!(
                        "pipeline `{}` references missing channel_out `{}`",
                        pipeline.name, channel_out
                    )));
                }
            }

            if pipeline.participants.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "pipeline `{}` must include at least one participant",
                    pipeline.name
                )));
            }
        }

        for (channel_name, channel) in &self.channels {
            validate_channel_security(channel_name, channel, self.runtime.enforce_secure_channels)?;
        }

        let auth = &self.runtime.admin_auth;
        match auth.mode.as_str() {
            "disabled" => {
                tracing::warn!(
                    "runtime.admin_auth.mode=disabled leaves admin endpoints unauthenticated"
                );
            }
            "legacy_bearer" => {
                tracing::warn!(
                    "admin_auth.mode=legacy_bearer is insecure; consider jwt_hs256 or disabled"
                );
                if auth
                    .legacy_bearer_token
                    .as_ref()
                    .map(|value| value.expose_secret().trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err(ConfigError::Validation(
                        "runtime.admin_auth.legacy_bearer_token must be set when mode=legacy_bearer"
                            .to_string(),
                    ));
                }
            }
            "jwt_hs256" => {
                if auth
                    .jwt_hs256_secret
                    .as_ref()
                    .map(|value| value.expose_secret().trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err(ConfigError::Validation(
                        "runtime.admin_auth.jwt_hs256_secret must be set when mode=jwt_hs256"
                            .to_string(),
                    ));
                }
            }
            other => {
                return Err(ConfigError::Validation(format!(
                    "runtime.admin_auth.mode `{other}` is invalid (expected disabled|legacy_bearer|jwt_hs256)"
                )));
            }
        }

        if auth.require_mtls_subject && auth.mtls_subject_header.trim().is_empty() {
            return Err(ConfigError::Validation(
                "runtime.admin_auth.mtls_subject_header must not be empty when require_mtls_subject=true".to_string(),
            ));
        }

        if let Some(limit) = self.runtime.recovery_startup_limit {
            if limit == 0 {
                return Err(ConfigError::Validation(
                    "runtime.recovery_startup_limit must be greater than 0".to_string(),
                ));
            }
        }

        Ok(())
    }
}

fn resolve_value_secrets(value: &mut toml::Value) -> Result<(), ConfigError> {
    match value {
        toml::Value::String(s) => {
            let expanded = expand_env_tokens(s)?;
            if let Some(secret_path) = expanded.strip_prefix("secret://") {
                let secret = fs::read_to_string(secret_path).map_err(|e| {
                    ConfigError::Validation(format!(
                        "failed to read secret file `{secret_path}`: {e}"
                    ))
                })?;
                *s = secret.trim_end_matches(['\n', '\r']).to_string();
            } else {
                *s = expanded;
            }
            Ok(())
        }
        toml::Value::Array(items) => {
            for item in items {
                resolve_value_secrets(item)?;
            }
            Ok(())
        }
        toml::Value::Table(table) => {
            for item in table.iter_mut().map(|(_, value)| value) {
                resolve_value_secrets(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn expand_env_tokens(input: &str) -> Result<String, ConfigError> {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;

    loop {
        let Some(start) = remaining.find("${") else {
            output.push_str(remaining);
            return Ok(output);
        };

        output.push_str(&remaining[..start]);
        let after_start = &remaining[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(ConfigError::Validation(
                "unterminated environment token `${...}`".to_string(),
            ));
        };
        let var_name = &after_start[..end];
        if var_name.trim().is_empty() {
            return Err(ConfigError::Validation(
                "empty environment token `${}` is invalid".to_string(),
            ));
        }
        let value = std::env::var(var_name).map_err(|_| {
            ConfigError::Validation(format!(
                "environment variable `{var_name}` referenced in config is not set"
            ))
        })?;
        output.push_str(&value);
        remaining = &after_start[end + 1..];
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeSection {
    pub name: String,
    pub instance_id: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub metrics_bind: Option<String>,
    #[serde(default)]
    pub admin_bind: Option<String>,
    #[serde(default)]
    pub admin_grpc_bind: Option<String>,
    #[serde(default)]
    pub admin_cors_allowed_origins: Vec<String>,
    #[serde(default)]
    pub enforce_secure_channels: bool,
    #[serde(default)]
    pub correlation_scan_interval_ms: Option<u64>,
    #[serde(default)]
    pub participant_reload_poll_ms: Option<u64>,
    #[serde(default = "default_recover_incomplete_on_startup")]
    pub recover_incomplete_on_startup: bool,
    #[serde(default)]
    pub recovery_startup_limit: Option<usize>,
    #[serde(default)]
    pub admin_auth: AdminAuthSection,
    #[serde(default)]
    pub admin_tls_cert: Option<String>,
    #[serde(default)]
    pub admin_tls_key: Option<String>,
}

fn validate_channel_security(
    channel_name: &str,
    channel: &ChannelSection,
    enforce_secure_channels: bool,
) -> Result<(), ConfigError> {
    if channel.channel_type == "file" {
        return Ok(());
    }
    let allow_plaintext = channel
        .extra
        .get("allow_plaintext")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    let secure = is_channel_secure(channel);
    if secure || allow_plaintext {
        return Ok(());
    }

    if enforce_secure_channels {
        return Err(ConfigError::Validation(format!(
            "channel `{channel_name}` type=`{}` mode=`{}` is plaintext; configure TLS or set allow_plaintext=true for an explicit exception",
            channel.channel_type, channel.mode
        )));
    }

    tracing::warn!(
        channel = %channel_name,
        channel_type = %channel.channel_type,
        mode = %channel.mode,
        "channel is configured without transport security"
    );
    Ok(())
}

fn is_channel_secure(channel: &ChannelSection) -> bool {
    let has_server_tls = matches!(
        (
            channel.extra.get("tls_cert").and_then(toml::Value::as_str),
            channel.extra.get("tls_key").and_then(toml::Value::as_str),
        ),
        (Some(_), Some(_))
    );

    let endpoint_like = channel
        .extra
        .get("endpoint")
        .and_then(toml::Value::as_str)
        .or_else(|| channel.extra.get("url").and_then(toml::Value::as_str))
        .unwrap_or_default();
    let uses_secure_url = endpoint_like.starts_with("https://")
        || endpoint_like.starts_with("amqps://")
        || endpoint_like.starts_with("tls://");
    let kafka_secure = channel
        .extra
        .get("security_protocol")
        .and_then(toml::Value::as_str)
        .map(|value| matches!(value.to_ascii_uppercase().as_str(), "SSL" | "SASL_SSL"))
        .unwrap_or(false);
    let tcp_tls_enabled = channel
        .extra
        .get("tls_enabled")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);

    has_server_tls || uses_secure_url || kafka_secure || tcp_tls_enabled
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_recover_incomplete_on_startup() -> bool {
    true
}

#[derive(Clone, Deserialize)]
pub struct AdminAuthSection {
    #[serde(default = "default_admin_auth_mode")]
    pub mode: String,
    #[serde(default)]
    pub jwt_hs256_secret: Option<SecretString>,
    #[serde(default)]
    pub legacy_bearer_token: Option<SecretString>,
    #[serde(default)]
    pub legacy_readonly_token: Option<SecretString>,
    #[serde(default)]
    pub jwt_issuer: Option<String>,
    #[serde(default)]
    pub jwt_audience: Option<String>,
    #[serde(default = "default_ready_roles")]
    pub ready_roles: Vec<String>,
    #[serde(default = "default_status_roles")]
    pub status_roles: Vec<String>,
    #[serde(default = "default_tx_roles")]
    pub tx_roles: Vec<String>,
    #[serde(default = "default_reload_roles")]
    pub reload_roles: Vec<String>,
    #[serde(default)]
    pub require_mtls_subject: bool,
    #[serde(default = "default_mtls_subject_header")]
    pub mtls_subject_header: String,
    #[serde(default)]
    pub mtls_allowed_subjects: Vec<String>,
}

impl std::fmt::Debug for AdminAuthSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminAuthSection")
            .field("mode", &self.mode)
            .field(
                "jwt_hs256_secret",
                &self.jwt_hs256_secret.as_ref().map(|_| "***redacted***"),
            )
            .field(
                "legacy_bearer_token",
                &self.legacy_bearer_token.as_ref().map(|_| "***redacted***"),
            )
            .field(
                "legacy_readonly_token",
                &self
                    .legacy_readonly_token
                    .as_ref()
                    .map(|_| "***redacted***"),
            )
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("ready_roles", &self.ready_roles)
            .field("status_roles", &self.status_roles)
            .field("tx_roles", &self.tx_roles)
            .field("reload_roles", &self.reload_roles)
            .field("require_mtls_subject", &self.require_mtls_subject)
            .field("mtls_subject_header", &self.mtls_subject_header)
            .field("mtls_allowed_subjects", &self.mtls_allowed_subjects)
            .finish()
    }
}

impl Default for AdminAuthSection {
    fn default() -> Self {
        Self {
            mode: default_admin_auth_mode(),
            jwt_hs256_secret: None,
            legacy_bearer_token: None,
            legacy_readonly_token: None,
            jwt_issuer: None,
            jwt_audience: None,
            ready_roles: default_ready_roles(),
            status_roles: default_status_roles(),
            tx_roles: default_tx_roles(),
            reload_roles: default_reload_roles(),
            require_mtls_subject: false,
            mtls_subject_header: default_mtls_subject_header(),
            mtls_allowed_subjects: Vec::new(),
        }
    }
}

fn default_admin_auth_mode() -> String {
    "disabled".to_string()
}

fn default_ready_roles() -> Vec<String> {
    vec!["admin.read".to_string(), "admin".to_string()]
}

fn default_status_roles() -> Vec<String> {
    vec!["admin.read".to_string(), "admin".to_string()]
}

fn default_tx_roles() -> Vec<String> {
    vec!["admin.tx.read".to_string(), "admin".to_string()]
}

fn default_reload_roles() -> Vec<String> {
    vec!["admin.write".to_string(), "admin".to_string()]
}

fn default_mtls_subject_header() -> String {
    "x-client-cert-subject".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreSection {
    pub backend: String,
    pub url: String,
    #[serde(default)]
    pub pool_size: Option<u32>,
    #[serde(default)]
    pub retention_days: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelSection {
    #[serde(rename = "type")]
    pub channel_type: String,
    pub mode: String,
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineSection {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub channel_in: String,
    #[serde(default)]
    pub channel_out: Option<String>,
    #[serde(default)]
    pub message_types: Vec<String>,
    #[serde(default)]
    pub max_concurrent: Option<usize>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub participants: Vec<ParticipantConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParticipantConfig {
    pub name: String,
    #[serde(default)]
    pub config: HashMap<String, toml::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("toml parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("config validation error: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use secrecy::ExposeSecret;

    use super::RuntimeConfig;

    const BASE_CONFIG: &str = r#"
[runtime]
name = "runtime"
instance_id = "local"

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
participants = [{ name = "message-logger" }]
"#;

    #[test]
    fn rejects_invalid_admin_auth_mode() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "invalid"
"#
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
    }

    #[test]
    fn requires_jwt_secret_when_jwt_mode_enabled() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "jwt_hs256"
"#
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_jwt_mode_with_secret() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "jwt_hs256"
jwt_hs256_secret = "secret"
"#
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_empty_runtime_name() {
        let config = BASE_CONFIG.replace(r#"name = "runtime""#, r#"name = "   ""#);
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("runtime.name must not be empty"));
    }

    #[test]
    fn rejects_missing_channel_in_reference() {
        let config = BASE_CONFIG.replace(
            r#"channel_in = "http-in""#,
            r#"channel_in = "missing-channel""#,
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("references missing channel_in"));
    }

    #[test]
    fn rejects_missing_channel_out_reference() {
        let config = format!(
            r#"{BASE_CONFIG}
[[pipeline]]
name = "with-out"
channel_in = "http-in"
channel_out = "missing-out"
participants = [{{ name = "message-logger" }}]
"#
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("references missing channel_out"));
    }

    #[test]
    fn rejects_pipeline_without_participants() {
        let config = BASE_CONFIG.replace(
            r#"participants = [{ name = "message-logger" }]"#,
            "participants = []",
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must include at least one participant"));
    }

    #[test]
    fn rejects_zero_recovery_startup_limit() {
        let config = BASE_CONFIG.replace(
            r#"instance_id = "local""#,
            r#"instance_id = "local"
recovery_startup_limit = 0"#,
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("recovery_startup_limit must be greater than 0"));
    }

    #[test]
    fn rejects_empty_mtls_subject_header_when_required() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
require_mtls_subject = true
mtls_subject_header = "   "
"#
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("mtls_subject_header must not be empty"));
    }

    fn assert_validation_error(config: &str, expected: &str) {
        let result = RuntimeConfig::parse(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(expected));
    }

    #[test]
    fn rejects_empty_runtime_instance_id() {
        let config = BASE_CONFIG.replace(r#"instance_id = "local""#, r#"instance_id = """#);
        assert_validation_error(&config, "runtime.instance_id must not be empty");
    }

    #[test]
    fn rejects_runtime_instance_id_with_only_whitespace() {
        let config = BASE_CONFIG.replace(r#"instance_id = "local""#, r#"instance_id = "   ""#);
        assert_validation_error(&config, "runtime.instance_id must not be empty");
    }

    #[test]
    fn rejects_when_no_pipeline_is_defined() {
        let config = BASE_CONFIG.replace(
            r#"
[[pipeline]]
name = "demo"
channel_in = "http-in"
participants = [{ name = "message-logger" }]
"#,
            "
",
        );
        assert_validation_error(&config, "at least one [[pipeline]] is required");
    }

    #[test]
    fn rejects_pipeline_name_when_empty() {
        let config = BASE_CONFIG.replace(r#"name = "demo""#, r#"name = """#);
        assert_validation_error(&config, "pipeline.name must not be empty");
    }

    #[test]
    fn rejects_pipeline_name_when_whitespace_only() {
        let config = BASE_CONFIG.replace(r#"name = "demo""#, r#"name = "   ""#);
        assert_validation_error(&config, "pipeline.name must not be empty");
    }

    #[test]
    fn accepts_admin_auth_mode_disabled() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "disabled"
"#
        );
        assert!(RuntimeConfig::parse(&config).is_ok());
    }

    #[test]
    fn accepts_admin_auth_mode_legacy_bearer() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "legacy_bearer"
legacy_bearer_token = "admin-token"
"#
        );
        assert!(RuntimeConfig::parse(&config).is_ok());
    }

    #[test]
    fn rejects_legacy_bearer_mode_without_token() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "legacy_bearer"
"#
        );
        assert_validation_error(
            &config,
            "runtime.admin_auth.legacy_bearer_token must be set when mode=legacy_bearer",
        );
    }

    #[test]
    fn rejects_jwt_mode_when_secret_is_empty() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "jwt_hs256"
jwt_hs256_secret = ""
"#
        );
        assert_validation_error(
            &config,
            "runtime.admin_auth.jwt_hs256_secret must be set when mode=jwt_hs256",
        );
    }

    #[test]
    fn rejects_jwt_mode_when_secret_is_whitespace_only() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "jwt_hs256"
jwt_hs256_secret = "   "
"#
        );
        assert_validation_error(
            &config,
            "runtime.admin_auth.jwt_hs256_secret must be set when mode=jwt_hs256",
        );
    }

    #[test]
    fn accepts_recovery_startup_limit_when_positive() {
        let config = BASE_CONFIG.replace(
            r#"instance_id = "local""#,
            r#"instance_id = "local"
recovery_startup_limit = 10"#,
        );
        assert!(RuntimeConfig::parse(&config).is_ok());
    }

    #[test]
    fn accepts_when_mtls_subject_not_required_and_header_empty() {
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
require_mtls_subject = false
mtls_subject_header = ""
"#
        );
        assert!(RuntimeConfig::parse(&config).is_ok());
    }

    #[test]
    fn parse_returns_toml_parse_error_for_malformed_input() {
        let malformed = r#"[runtime
name = "runtime""#;
        let result = RuntimeConfig::parse(malformed);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("toml parse error"));
    }

    #[test]
    fn parse_preserves_message_type_entries() {
        let config = format!(
            r#"{BASE_CONFIG}
[[pipeline]]
name = "typed"
channel_in = "http-in"
message_types = ["pacs.008", "pain.001"]
participants = [{{ name = "message-logger" }}]
"#
        );
        let parsed = RuntimeConfig::parse(&config).expect("config should parse");
        let typed = parsed
            .pipelines
            .iter()
            .find(|p| p.name == "typed")
            .expect("typed pipeline should exist");
        assert_eq!(typed.message_types, vec!["pacs.008", "pain.001"]);
    }

    #[test]
    fn parse_preserves_channel_extra_fields() {
        let config = format!(
            r#"{BASE_CONFIG}
[channels.http-extra]
type = "http"
mode = "server"
bind = "0.0.0.0:9090"
path = "/inbox"
"#
        );
        let parsed = RuntimeConfig::parse(&config).expect("config should parse");
        let channel = parsed
            .channels
            .get("http-extra")
            .expect("http-extra channel should exist");
        assert_eq!(channel.channel_type, "http");
        assert_eq!(channel.mode, "server");
        assert_eq!(
            channel.extra.get("path").and_then(|value| value.as_str()),
            Some("/inbox")
        );
    }

    #[test]
    fn validate_accepts_minimal_valid_configuration() {
        let parsed = RuntimeConfig::parse(BASE_CONFIG).expect("base config should be valid");
        assert_eq!(parsed.runtime.name, "runtime");
        assert_eq!(parsed.pipelines.len(), 1);
    }

    #[test]
    fn parse_expands_env_tokens() {
        std::env::set_var("MX20022_TEST_SECRET", "from-env");
        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "jwt_hs256"
jwt_hs256_secret = "${{MX20022_TEST_SECRET}}"
"#
        );
        let parsed = RuntimeConfig::parse(&config).expect("config should parse");
        assert_eq!(
            parsed
                .runtime
                .admin_auth
                .jwt_hs256_secret
                .as_ref()
                .map(|secret| secret.expose_secret()),
            Some("from-env")
        );
    }

    #[test]
    fn parse_reads_secret_file_reference() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mx20022-secret-{now}.txt"));
        fs::write(&path, "file-secret\n").expect("write secret file");

        let config = format!(
            r#"{BASE_CONFIG}
[runtime.admin_auth]
mode = "jwt_hs256"
jwt_hs256_secret = "secret://{}"
"#,
            path.display()
        );
        let parsed = RuntimeConfig::parse(&config).expect("config should parse");
        assert_eq!(
            parsed
                .runtime
                .admin_auth
                .jwt_hs256_secret
                .as_ref()
                .map(|secret| secret.expose_secret()),
            Some("file-secret")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_plaintext_channel_when_secure_channels_enforced() {
        let config = BASE_CONFIG.replace(
            r#"instance_id = "local""#,
            r#"instance_id = "local"
enforce_secure_channels = true"#,
        );
        let result = RuntimeConfig::parse(&config);
        assert!(result.is_err());
        assert!(result
            .expect_err("config should fail")
            .to_string()
            .contains("plaintext"));
    }

    #[test]
    fn accepts_plaintext_channel_with_explicit_exception() {
        let config = r#"
[runtime]
name = "runtime"
instance_id = "local"
enforce_secure_channels = true

[store]
backend = "sqlite"
url = "sqlite::memory:"

[channels.http-in]
type = "http"
mode = "server"
bind = "127.0.0.1:0"
allow_plaintext = true

[[pipeline]]
name = "demo"
channel_in = "http-in"
participants = [{ name = "message-logger" }]
"#
        .to_string();
        assert!(RuntimeConfig::parse(&config).is_ok());
    }
}
