// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use mx20022_crypto::auth::{constant_time_eq, parse_bearer_token};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminResource {
    Ready,
    Status,
    Transaction,
    Reload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Disabled,
    LegacyBearer,
    JwtHs256,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub jwt_hs256_secret: Option<SecretString>,
    pub legacy_bearer_token: Option<SecretString>,
    pub legacy_readonly_token: Option<SecretString>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub ready_roles: Vec<String>,
    pub status_roles: Vec<String>,
    pub tx_roles: Vec<String>,
    pub reload_roles: Vec<String>,
    pub require_mtls_subject: bool,
    pub mtls_subject_header: String,
    pub mtls_allowed_subjects: Vec<String>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
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

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Disabled,
            jwt_hs256_secret: None,
            legacy_bearer_token: None,
            legacy_readonly_token: None,
            jwt_issuer: None,
            jwt_audience: None,
            ready_roles: Vec::new(),
            status_roles: Vec::new(),
            tx_roles: Vec::new(),
            reload_roles: Vec::new(),
            require_mtls_subject: false,
            mtls_subject_header: "x-client-cert-subject".to_string(),
            mtls_allowed_subjects: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingBearer,
    #[error("invalid bearer token")]
    InvalidBearer,
    #[error("forbidden")]
    Forbidden,
    #[error("missing mTLS subject")]
    MissingMtlsSubject,
    #[error("untrusted mTLS subject")]
    UntrustedMtlsSubject,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    scope: Option<String>,
}

pub fn authorize_request(
    config: &AuthConfig,
    resource: AdminResource,
    bearer_header: Option<&str>,
    mtls_subject: Option<&str>,
) -> Result<(), AuthError> {
    verify_mtls_subject(config, mtls_subject)?;

    match config.mode {
        AuthMode::Disabled => Ok(()),
        AuthMode::LegacyBearer => authorize_legacy(config, resource, bearer_header),
        AuthMode::JwtHs256 => authorize_jwt(config, resource, bearer_header),
    }
}

fn authorize_legacy(
    config: &AuthConfig,
    resource: AdminResource,
    bearer_header: Option<&str>,
) -> Result<(), AuthError> {
    let token = parse_bearer_token(bearer_header).ok_or(AuthError::MissingBearer)?;
    if token.trim().is_empty() {
        return Err(AuthError::InvalidBearer);
    }
    let admin_token = config
        .legacy_bearer_token
        .as_ref()
        .map(ExposeSecret::expose_secret)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string);
    let readonly_token = config
        .legacy_readonly_token
        .as_ref()
        .map(ExposeSecret::expose_secret)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string);

    if let Some(expected_admin) = admin_token.as_deref() {
        if constant_time_eq(token, expected_admin) {
            return Ok(());
        }
    } else {
        return Err(AuthError::InvalidBearer);
    }

    if matches!(resource, AdminResource::Ready | AdminResource::Status)
        && readonly_token
            .as_deref()
            .is_some_and(|expected| constant_time_eq(token, expected))
    {
        return Ok(());
    }

    Err(AuthError::Forbidden)
}

fn authorize_jwt(
    config: &AuthConfig,
    resource: AdminResource,
    bearer_header: Option<&str>,
) -> Result<(), AuthError> {
    let token = parse_bearer_token(bearer_header).ok_or(AuthError::MissingBearer)?;
    let secret = config
        .jwt_hs256_secret
        .as_ref()
        .map(ExposeSecret::expose_secret)
        .ok_or(AuthError::InvalidBearer)?;

    let mut validation = Validation::new(Algorithm::HS256);
    // Build the required-claims set dynamically: exp is always required
    // (jsonwebtoken default), and iss/aud are required *when configured*.
    // Without requiring them, a token that omits the claim entirely bypasses
    // the audience/issuer check (jsonwebtoken only validates the claim if it
    // is present).
    let mut required_spec_claims: std::collections::HashSet<&str> =
        std::collections::HashSet::new();
    if let Some(iss) = &config.jwt_issuer {
        validation.set_issuer(&[iss]);
        required_spec_claims.insert("iss");
    }
    if let Some(aud) = &config.jwt_audience {
        validation.set_audience(&[aud]);
        required_spec_claims.insert("aud");
    }
    if !required_spec_claims.is_empty() {
        validation.set_required_spec_claims(&required_spec_claims.into_iter().collect::<Vec<_>>());
    }

    let data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AuthError::InvalidBearer)?;

    let required_roles = required_roles(config, resource);
    if required_roles.is_empty() {
        return Ok(());
    }

    let mut principal_roles: HashSet<String> = data.claims.roles.into_iter().collect();
    if let Some(role) = data.claims.role {
        principal_roles.insert(role);
    }
    if let Some(scope) = data.claims.scope {
        for entry in scope.split_whitespace() {
            if !entry.is_empty() {
                principal_roles.insert(entry.to_string());
            }
        }
    }

    if required_roles
        .iter()
        .any(|required| principal_roles.contains(required))
    {
        return Ok(());
    }

    Err(AuthError::Forbidden)
}

fn required_roles(config: &AuthConfig, resource: AdminResource) -> &[String] {
    match resource {
        AdminResource::Ready => &config.ready_roles,
        AdminResource::Status => &config.status_roles,
        AdminResource::Transaction => &config.tx_roles,
        AdminResource::Reload => &config.reload_roles,
    }
}

fn verify_mtls_subject(config: &AuthConfig, mtls_subject: Option<&str>) -> Result<(), AuthError> {
    if !config.require_mtls_subject {
        return Ok(());
    }

    let subject = mtls_subject
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(AuthError::MissingMtlsSubject)?;

    if config.mtls_allowed_subjects.is_empty() {
        return Ok(());
    }

    if config
        .mtls_allowed_subjects
        .iter()
        .any(|allowed| allowed == subject)
    {
        return Ok(());
    }

    Err(AuthError::UntrustedMtlsSubject)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use mx20022_crypto::auth::constant_time_eq;
    use secrecy::SecretString;
    use serde::Serialize;

    use super::{authorize_request, AdminResource, AuthConfig, AuthError, AuthMode};

    #[derive(Debug, Serialize)]
    struct Claims {
        sub: String,
        exp: usize,
        roles: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,
    }

    #[test]
    fn jwt_mode_requires_expected_roles() {
        let cfg = AuthConfig {
            mode: AuthMode::JwtHs256,
            jwt_hs256_secret: Some(SecretString::new("test-secret".into())),
            tx_roles: vec!["admin.tx.read".to_string()],
            ..AuthConfig::default()
        };
        let claims = Claims {
            sub: "operator".to_string(),
            exp: 4_102_444_800,
            roles: vec!["admin.tx.read".to_string()],
            aud: None,
            iss: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("test-secret".as_bytes()),
        )
        .expect("token should encode");
        let header = format!("Bearer {token}");

        let result = authorize_request(
            &cfg,
            AdminResource::Transaction,
            Some(header.as_str()),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn jwt_mode_denies_missing_role() {
        let cfg = AuthConfig {
            mode: AuthMode::JwtHs256,
            jwt_hs256_secret: Some(SecretString::new("test-secret".into())),
            tx_roles: vec!["admin.tx.read".to_string()],
            ..AuthConfig::default()
        };
        let claims = Claims {
            sub: "readonly".to_string(),
            exp: 4_102_444_800,
            roles: vec!["admin.read".to_string()],
            aud: None,
            iss: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("test-secret".as_bytes()),
        )
        .expect("token should encode");
        let header = format!("Bearer {token}");

        let result = authorize_request(
            &cfg,
            AdminResource::Transaction,
            Some(header.as_str()),
            None,
        );
        assert!(matches!(result, Err(AuthError::Forbidden)));
    }

    #[test]
    fn jwt_audience_required_when_configured() {
        // Regression: a token that omits the `aud` claim must be rejected
        // when an audience is configured. Without requiring the claim,
        // jsonwebtoken skips audience validation for claim-less tokens,
        // letting them bypass the audience check.
        let cfg = AuthConfig {
            mode: AuthMode::JwtHs256,
            jwt_hs256_secret: Some(SecretString::new("test-secret".into())),
            jwt_audience: Some("mx20022-admin".to_string()),
            ready_roles: vec!["admin.read".to_string()],
            ..AuthConfig::default()
        };
        let claims_without_aud = Claims {
            sub: "operator".to_string(),
            exp: 4_102_444_800,
            roles: vec!["admin.read".to_string()],
            aud: None,
            iss: None,
        };
        let token = encode(
            &Header::default(),
            &claims_without_aud,
            &EncodingKey::from_secret("test-secret".as_bytes()),
        )
        .expect("token should encode");
        let header = format!("Bearer {token}");

        let result = authorize_request(
            &cfg,
            AdminResource::Ready,
            Some(header.as_str()),
            None,
        );
        assert!(
            matches!(result, Err(AuthError::InvalidBearer)),
            "token missing aud should be rejected: {result:?}"
        );

        // A token carrying the configured audience is accepted.
        let claims_with_aud = Claims {
            sub: "operator".to_string(),
            exp: 4_102_444_800,
            roles: vec!["admin.read".to_string()],
            aud: Some("mx20022-admin".to_string()),
            iss: None,
        };
        let token_ok = encode(
            &Header::default(),
            &claims_with_aud,
            &EncodingKey::from_secret("test-secret".as_bytes()),
        )
        .expect("token should encode");
        let header_ok = format!("Bearer {token_ok}");
        let result_ok = authorize_request(
            &cfg,
            AdminResource::Ready,
            Some(header_ok.as_str()),
            None,
        );
        assert!(result_ok.is_ok(), "token with correct aud should pass");
    }

    #[test]
    fn jwt_issuer_required_when_configured() {
        let cfg = AuthConfig {
            mode: AuthMode::JwtHs256,
            jwt_hs256_secret: Some(SecretString::new("test-secret".into())),
            jwt_issuer: Some("mx20022-issuer".to_string()),
            ready_roles: vec!["admin.read".to_string()],
            ..AuthConfig::default()
        };
        let claims_without_iss = Claims {
            sub: "operator".to_string(),
            exp: 4_102_444_800,
            roles: vec!["admin.read".to_string()],
            aud: None,
            iss: None,
        };
        let token = encode(
            &Header::default(),
            &claims_without_iss,
            &EncodingKey::from_secret("test-secret".as_bytes()),
        )
        .expect("token should encode");
        let header = format!("Bearer {token}");

        let result = authorize_request(&cfg, AdminResource::Ready, Some(header.as_str()), None);
        assert!(
            matches!(result, Err(AuthError::InvalidBearer)),
            "token missing iss should be rejected: {result:?}"
        );
    }

    #[test]
    fn mtls_subject_is_enforced_when_enabled() {
        let cfg = AuthConfig {
            mode: AuthMode::Disabled,
            require_mtls_subject: true,
            mtls_allowed_subjects: vec!["CN=trusted-client".to_string()],
            ..AuthConfig::default()
        };

        let denied = authorize_request(&cfg, AdminResource::Ready, None, Some("CN=other-client"));
        assert!(matches!(denied, Err(AuthError::UntrustedMtlsSubject)));

        let accepted =
            authorize_request(&cfg, AdminResource::Ready, None, Some("CN=trusted-client"));
        assert!(accepted.is_ok());
    }

    #[test]
    fn legacy_mode_requires_explicit_token_configuration() {
        let cfg = AuthConfig {
            mode: AuthMode::LegacyBearer,
            ..AuthConfig::default()
        };

        let denied = authorize_request(&cfg, AdminResource::Ready, Some("Bearer anything"), None);
        assert!(matches!(denied, Err(AuthError::InvalidBearer)));
    }

    #[test]
    fn legacy_mode_readonly_token_cannot_access_write_paths() {
        let cfg = AuthConfig {
            mode: AuthMode::LegacyBearer,
            legacy_bearer_token: Some(SecretString::new("admin-token".into())),
            legacy_readonly_token: Some(SecretString::new("readonly-token".into())),
            ..AuthConfig::default()
        };

        let readonly_status = authorize_request(
            &cfg,
            AdminResource::Status,
            Some("Bearer readonly-token"),
            None,
        );
        assert!(readonly_status.is_ok());

        let readonly_reload = authorize_request(
            &cfg,
            AdminResource::Reload,
            Some("Bearer readonly-token"),
            None,
        );
        assert!(matches!(readonly_reload, Err(AuthError::Forbidden)));

        let admin_reload = authorize_request(
            &cfg,
            AdminResource::Reload,
            Some("Bearer admin-token"),
            None,
        );
        assert!(admin_reload.is_ok());
    }

    #[test]
    fn constant_time_eq_rejects_mismatched_lengths() {
        assert!(!constant_time_eq("one", "three"));
    }
}
