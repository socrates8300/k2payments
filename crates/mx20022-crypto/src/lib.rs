// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

pub mod auth;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

pub struct CryptoService {
    key_bytes: [u8; 32],
}

const HKDF_SALT: &[u8] = b"mx20022-runtime-hkdf-sha256-v1";

impl std::fmt::Debug for CryptoService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoService")
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

impl CryptoService {
    /// Minimum byte length of the HKDF input. Unprefixed keys are raw UTF-8.
    /// `hex:` and `base64:` prefixes opt in to decode-then-measure.
    const MIN_MASTER_KEY_BYTES: usize = 32;

    pub fn from_master_key(master_key: &str) -> Result<Self, CryptoError> {
        let trimmed = master_key.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::InvalidMasterKey(
                "master key must not be empty".to_string(),
            ));
        }
        let key_material = decode_master_key_material(trimmed)?;
        if key_material.len() < Self::MIN_MASTER_KEY_BYTES {
            return Err(CryptoError::InvalidMasterKey(format!(
                "master key must be at least {} bytes of key material (got {}); unprefixed values are raw UTF-8, or use hex:<64+ hex chars> / base64:<32+ bytes>",
                Self::MIN_MASTER_KEY_BYTES,
                key_material.len()
            )));
        }

        // Derive a fixed-length key for AES-256 using HKDF-SHA256 with a domain-separated salt.
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &key_material);
        let mut key_bytes = [0_u8; 32];
        hk.expand(b"aes-256-gcm-key", &mut key_bytes)
            .map_err(|e| CryptoError::InvalidMasterKey(format!("HKDF expand failed: {e}")))?;

        Ok(Self { key_bytes })
    }

    pub fn from_env(var_name: &str) -> Result<Self, CryptoError> {
        let value =
            std::env::var(var_name).map_err(|_| CryptoError::MissingEnv(var_name.to_string()))?;
        Self::from_master_key(&value)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedBlob, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key_bytes)
            .map_err(|e| CryptoError::Cipher(format!("cipher init failed: {e}")))?;

        let mut nonce_bytes = [0_u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::Cipher(format!("encrypt failed: {e}")))?;

        Ok(EncryptedBlob {
            algorithm: "AES-256-GCM".to_string(),
            nonce_b64: STANDARD.encode(nonce_bytes),
            ciphertext_b64: STANDARD.encode(ciphertext),
        })
    }

    pub fn decrypt(&self, blob: &EncryptedBlob) -> Result<Vec<u8>, CryptoError> {
        if blob.algorithm != "AES-256-GCM" {
            return Err(CryptoError::UnsupportedAlgorithm(blob.algorithm.clone()));
        }

        let nonce_bytes = STANDARD
            .decode(&blob.nonce_b64)
            .map_err(|e| CryptoError::Cipher(format!("nonce decode failed: {e}")))?;
        if nonce_bytes.len() != 12 {
            return Err(CryptoError::Cipher("invalid nonce length".to_string()));
        }

        let ciphertext = STANDARD
            .decode(&blob.ciphertext_b64)
            .map_err(|e| CryptoError::Cipher(format!("ciphertext decode failed: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&self.key_bytes)
            .map_err(|e| CryptoError::Cipher(format!("cipher init failed: {e}")))?;

        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|e| CryptoError::Cipher(format!("decrypt failed: {e}")))
    }
}

fn decode_master_key_material(trimmed: &str) -> Result<Vec<u8>, CryptoError> {
    if let Some(hex) = trimmed.strip_prefix("hex:") {
        return decode_hex(hex).ok_or_else(|| {
            CryptoError::InvalidMasterKey(
                "master key hex: prefix requires even-length hex digits".to_string(),
            )
        });
    }
    if let Some(b64) = trimmed.strip_prefix("base64:") {
        return STANDARD.decode(b64).map_err(|error| {
            CryptoError::InvalidMasterKey(format!(
                "master key base64: prefix is not valid base64: {error}"
            ))
        });
    }
    Ok(trimmed.as_bytes().to_vec())
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() < 2
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

impl Drop for CryptoService {
    fn drop(&mut self) {
        self.key_bytes.fill(0);
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedBlob {
    pub algorithm: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("missing environment variable: {0}")]
    MissingEnv(String),
    #[error("invalid master key: {0}")]
    InvalidMasterKey(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("cipher error: {0}")]
    Cipher(String),
}

#[cfg(test)]
mod tests {
    use crate::{CryptoService, EncryptedBlob};

    // 64 raw UTF-8 bytes. Unprefixed hex-looking strings stay raw so existing
    // deployments keep the same HKDF input.
    const TEST_MASTER_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = CryptoService::from_master_key(TEST_MASTER_KEY).expect("crypto should init");

        let plaintext = b"secret-payment-field";
        let blob = crypto.encrypt(plaintext).expect("encrypt should work");
        let roundtrip = crypto.decrypt(&blob).expect("decrypt should work");

        assert_eq!(roundtrip, plaintext);
    }

    #[test]
    fn rejects_empty_master_key() {
        let result = CryptoService::from_master_key("   ");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_short_master_key() {
        let result = CryptoService::from_master_key("x");
        assert!(result.is_err());
    }

    #[test]
    fn unprefixed_hex_looking_key_stays_raw_utf8() {
        let raw = TEST_MASTER_KEY;
        let prefixed = format!("hex:{raw}");
        let from_raw = CryptoService::from_master_key(raw).expect("raw key");
        let from_hex = CryptoService::from_master_key(&prefixed).expect("hex: key");
        let blob = from_raw.encrypt(b"secret").expect("encrypt");
        assert!(
            from_hex.decrypt(&blob).is_err(),
            "hex: decode must not match raw UTF-8 derivation of the same digits"
        );
    }

    #[test]
    fn prefixed_hex_measures_decoded_bytes() {
        assert!(CryptoService::from_master_key("hex:0123456789abcdef0123456789abcdef").is_err());
        assert!(CryptoService::from_master_key(&format!("hex:{TEST_MASTER_KEY}")).is_ok());
    }

    #[test]
    fn unprefixed_base64_looking_passphrase_stays_raw() {
        // 40 alphanumeric chars: valid standard base64 for 30 bytes, so a
        // silent decode would reject it. Raw UTF-8 is 40 bytes and must pass.
        let passphrase = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";
        assert!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, passphrase).is_ok()
        );
        assert!(CryptoService::from_master_key(passphrase).is_ok());
        assert!(CryptoService::from_master_key(&format!("base64:{passphrase}")).is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let crypto_a = CryptoService::from_master_key(TEST_MASTER_KEY).expect("crypto A");
        let crypto_b = CryptoService::from_master_key(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
        )
        .expect("crypto B");
        let blob = crypto_a.encrypt(b"secret").expect("encrypt");
        let result = crypto_b.decrypt(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_rejects_unsupported_algorithm() {
        let crypto = CryptoService::from_master_key(TEST_MASTER_KEY).expect("crypto");
        let blob = EncryptedBlob {
            algorithm: "AES-128-GCM".to_string(),
            nonce_b64: "AAAAAAAAAAAAAAAA".to_string(),
            ciphertext_b64: "AAAA".to_string(),
        };
        let result = crypto.decrypt(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let crypto = CryptoService::from_master_key(TEST_MASTER_KEY).expect("crypto");
        let mut blob = crypto.encrypt(b"secret").expect("encrypt");
        blob.ciphertext_b64.push('A');
        let result = crypto.decrypt(&blob);
        assert!(result.is_err());
    }
}
