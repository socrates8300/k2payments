// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use mx20022_crypto::auth::{constant_time_eq, parse_bearer_token};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::ChannelError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundAuthMode {
    Disabled,
    StaticBearer,
    JwtHs256,
}

#[derive(Clone)]
pub struct InboundAuthConfig {
    pub mode: InboundAuthMode,
    pub bearer_token: Option<SecretString>,
    pub jwt_hs256_secret: Option<SecretString>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub required_roles: Vec<String>,
    pub require_mtls_subject: bool,
    pub mtls_subject_header: String,
    pub mtls_allowed_subjects: Vec<String>,
}

impl std::fmt::Debug for InboundAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundAuthConfig")
            .field("mode", &self.mode)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "***redacted***"),
            )
            .field(
                "jwt_hs256_secret",
                &self.jwt_hs256_secret.as_ref().map(|_| "***redacted***"),
            )
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("required_roles", &self.required_roles)
            .field("require_mtls_subject", &self.require_mtls_subject)
            .field("mtls_subject_header", &self.mtls_subject_header)
            .field("mtls_allowed_subjects", &self.mtls_allowed_subjects)
            .finish()
    }
}

impl Default for InboundAuthConfig {
    fn default() -> Self {
        Self {
            mode: InboundAuthMode::Disabled,
            bearer_token: None,
            jwt_hs256_secret: None,
            jwt_issuer: None,
            jwt_audience: None,
            required_roles: Vec::new(),
            require_mtls_subject: false,
            mtls_subject_header: "x-client-cert-subject".to_string(),
            mtls_allowed_subjects: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InboundAuthContext<'a> {
    pub authorization_header: Option<&'a str>,
    pub mtls_subject: Option<&'a str>,
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

pub fn authorize_inbound(
    config: &InboundAuthConfig,
    context: InboundAuthContext<'_>,
) -> Result<(), ChannelError> {
    verify_mtls(config, context.mtls_subject)?;

    match config.mode {
        InboundAuthMode::Disabled => Ok(()),
        InboundAuthMode::StaticBearer => {
            let token = parse_bearer_token(context.authorization_header)
                .ok_or_else(|| ChannelError::new("missing bearer token"))?;
            let expected = config
                .bearer_token
                .as_ref()
                .map(ExposeSecret::expose_secret)
                .ok_or_else(|| ChannelError::new("inbound auth is misconfigured"))?;
            if constant_time_eq(token, expected) {
                Ok(())
            } else {
                Err(ChannelError::new("invalid bearer token"))
            }
        }
        InboundAuthMode::JwtHs256 => authorize_inbound_jwt(config, context.authorization_header),
    }
}

fn authorize_inbound_jwt(
    config: &InboundAuthConfig,
    authorization_header: Option<&str>,
) -> Result<(), ChannelError> {
    let token = parse_bearer_token(authorization_header)
        .ok_or_else(|| ChannelError::new("missing bearer token"))?;
    let secret = config
        .jwt_hs256_secret
        .as_ref()
        .map(ExposeSecret::expose_secret)
        .ok_or_else(|| ChannelError::new("inbound auth is misconfigured"))?;

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
    .map_err(|_| ChannelError::new("invalid bearer token"))?;

    if config.required_roles.is_empty() {
        return Ok(());
    }

    let mut principal_roles: HashSet<String> = data.claims.roles.into_iter().collect();
    if let Some(role) = data.claims.role {
        principal_roles.insert(role);
    }
    if let Some(scope) = data.claims.scope {
        for item in scope.split_whitespace() {
            if !item.is_empty() {
                principal_roles.insert(item.to_string());
            }
        }
    }

    if config
        .required_roles
        .iter()
        .any(|required| principal_roles.contains(required))
    {
        Ok(())
    } else {
        Err(ChannelError::new("forbidden"))
    }
}

fn verify_mtls(config: &InboundAuthConfig, mtls_subject: Option<&str>) -> Result<(), ChannelError> {
    if !config.require_mtls_subject {
        return Ok(());
    }

    let subject = mtls_subject
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ChannelError::new("missing mTLS subject"))?;

    if config.mtls_allowed_subjects.is_empty() {
        return Ok(());
    }

    if config
        .mtls_allowed_subjects
        .iter()
        .any(|allowed| allowed == subject)
    {
        Ok(())
    } else {
        Err(ChannelError::new("untrusted mTLS subject"))
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use mx20022_crypto::auth::constant_time_eq;
    use secrecy::SecretString;
    use serde::Serialize;

    use super::{authorize_inbound, InboundAuthConfig, InboundAuthContext, InboundAuthMode};

    #[derive(Debug, Serialize)]
    struct Claims {
        sub: String,
        exp: usize,
        roles: Vec<String>,
    }

    #[test]
    fn static_bearer_passes_and_fails() {
        let cfg = InboundAuthConfig {
            mode: InboundAuthMode::StaticBearer,
            bearer_token: Some(SecretString::new("secret".into())),
            ..InboundAuthConfig::default()
        };

        let ok = authorize_inbound(
            &cfg,
            InboundAuthContext {
                authorization_header: Some("Bearer secret"),
                mtls_subject: None,
            },
        );
        assert!(ok.is_ok());

        let denied = authorize_inbound(
            &cfg,
            InboundAuthContext {
                authorization_header: Some("Bearer wrong"),
                mtls_subject: None,
            },
        );
        assert!(denied.is_err());
    }

    #[test]
    fn constant_time_eq_handles_length_mismatch() {
        assert!(!constant_time_eq("short", "a-very-different-length"));
    }

    #[test]
    fn jwt_requires_role_when_configured() {
        let cfg = InboundAuthConfig {
            mode: InboundAuthMode::JwtHs256,
            jwt_hs256_secret: Some(SecretString::new("secret".into())),
            required_roles: vec!["channel.ingress".to_string()],
            ..InboundAuthConfig::default()
        };
        let claims = Claims {
            sub: "client".to_string(),
            exp: 4_102_444_800,
            roles: vec!["channel.ingress".to_string()],
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("secret".as_bytes()),
        )
        .expect("token should encode");
        let header = format!("Bearer {token}");

        let ok = authorize_inbound(
            &cfg,
            InboundAuthContext {
                authorization_header: Some(header.as_str()),
                mtls_subject: None,
            },
        );
        assert!(ok.is_ok());
    }
}
