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
    /// Minimum raw byte length of the master key. HKDF expands this to the
    /// 32-byte AES-256 key, so a master key shorter than 32 bytes provides
    /// less than 256 bits of effective key strength. Operators must supply a
    /// high-entropy secret (e.g. 32+ random bytes, base64-encoded).
    const MIN_MASTER_KEY_BYTES: usize = 32;

    pub fn from_master_key(master_key: &str) -> Result<Self, CryptoError> {
        let trimmed = master_key.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::InvalidMasterKey(
                "master key must not be empty".to_string(),
            ));
        }
        if trimmed.len() < Self::MIN_MASTER_KEY_BYTES {
            return Err(CryptoError::InvalidMasterKey(format!(
                "master key must be at least {} bytes (got {}); use a high-entropy secret such as 32+ random bytes",
                Self::MIN_MASTER_KEY_BYTES,
                trimmed.len()
            )));
        }

        // Derive a fixed-length key for AES-256 using HKDF-SHA256 with a domain-separated salt.
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), trimmed.as_bytes());
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

    // 48-byte high-entropy test key (> MIN_MASTER_KEY_BYTES of 32).
    const TEST_MASTER_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef";

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
        // A 1-character key is accepted structurally but provides ~1 char of
        // entropy; the floor rejects it so operators don't ship a weak key
        // that HKDF would silently stretch to 32 bytes.
        let result = CryptoService::from_master_key("x");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let crypto_a =
            CryptoService::from_master_key(TEST_MASTER_KEY).expect("crypto A");
        let crypto_b = CryptoService::from_master_key(
            "abcdef0123456789abcdef0123456789abcdef0123456789ab",
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
