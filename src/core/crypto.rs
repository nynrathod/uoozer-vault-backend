//! Server-side cryptographic operations.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::config::{Argon2Config, JwtConfig};
use crate::core::error::AppError;

// ──────────────────────────────────────────────────────────────
// Salt generation
// ──────────────────────────────────────────────────────────────

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    salt
}

// ──────────────────────────────────────────────────────────────
// Anti-enumeration: deterministic fake salt for unknown emails
// ──────────────────────────────────────────────────────────────

pub fn deterministic_fake_salt(email: &str, pepper: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pepper);
    hasher.update(email.to_lowercase().as_bytes());
    let hash = hasher.finalize();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash.as_bytes()[..16]);
    salt
}

// ──────────────────────────────────────────────────────────────
// Argon2id parameter serialization
// ──────────────────────────────────────────────────────────────

pub fn argon2_params_json(cfg: &Argon2Config) -> serde_json::Value {
    serde_json::json!({
        "m_cost": cfg.m_cost,
        "t_cost": cfg.t_cost,
        "p_cost": cfg.p_cost,
        "output_len": cfg.output_len,
        "algorithm": "argon2id"
    })
}

// ──────────────────────────────────────────────────────────────
// Auth Key hashing (bcrypt)
// ──────────────────────────────────────────────────────────────

pub fn hash_auth_key(auth_key_b64: &str, cost: u32) -> Result<String, AppError> {
    bcrypt::hash(auth_key_b64, cost).map_err(|e| {
        tracing::error!(error = ?e, "bcrypt hashing failed");
        AppError::Internal(anyhow::anyhow!("key hashing failed"))
    })
}

pub fn verify_auth_key(auth_key_b64: &str, hash: &str) -> bool {
    bcrypt::verify(auth_key_b64, hash).unwrap_or(false)
}

// ──────────────────────────────────────────────────────────────
// Refresh token hashing (SHA-256)
// ──────────────────────────────────────────────────────────────

pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// ──────────────────────────────────────────────────────────────
// JWT (EdDSA / Ed25519)
// ──────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub did: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub typ: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub did: Uuid,
    pub jti: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub typ: String,
}

pub struct JwtKeyPair {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKeyPair {
    pub fn from_pem(pem: &str) -> Result<Self, AppError> {
        // Parse the PEM using ed25519-dalek instead of jsonwebtoken
        let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|e| {
            AppError::Internal(anyhow::anyhow!(
                "failed to parse Ed25519 private key: {}",
                e
            ))
        })?;

        // Convert the parsed key to PKCS8 DER format for jsonwebtoken's rust_crypto backend
        let der = signing_key.to_pkcs8_der().map_err(|e| {
            AppError::Internal(anyhow::anyhow!(
                "failed to encode Ed25519 key to DER: {}",
                e
            ))
        })?;
        let encoding = EncodingKey::from_ed_der(der.as_bytes());

        let verifying_key: VerifyingKey = signing_key.verifying_key();
        // Use explicit URL_SAFE_NO_PAD engine to avoid any invalid characters
        let pub_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
        let decoding = DecodingKey::from_ed_components(&pub_key_b64).map_err(|e| {
            AppError::Internal(anyhow::anyhow!("failed to parse Ed25519 public key: {}", e))
        })?;

        Ok(Self { encoding, decoding })
    }

    pub fn generate_dev_keypair() -> (String, Self) {
        let mut csprng = rand::rng();
        let signing_key = SigningKey::generate(&mut csprng);

        let pem = signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("failed to encode Ed25519 key to PEM");

        let pem_string = pem.to_string();

        let keypair = Self::from_pem(&pem_string).expect("dev keypair must parse");

        (pem_string, keypair)
    }

    pub fn sign_access_token(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        device_id: Uuid,
        config: &JwtConfig,
    ) -> Result<String, AppError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = AccessTokenClaims {
            sub: user_id,
            sid: session_id,
            did: device_id,
            iat: now,
            exp: now + config.access_ttl_seconds as usize,
            iss: config.issuer.clone(),
            typ: "access".to_string(),
        };

        let header = Header::new(Algorithm::EdDSA);
        encode(&header, &claims, &self.encoding).map_err(|e| {
            tracing::error!(error = ?e, "failed to sign access token");
            AppError::Internal(anyhow::anyhow!("token signing failed"))
        })
    }

    pub fn sign_refresh_token(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        device_id: Uuid,
        jti: Uuid,
        config: &JwtConfig,
    ) -> Result<String, AppError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = RefreshTokenClaims {
            sub: user_id,
            sid: session_id,
            did: device_id,
            jti,
            iat: now,
            exp: now + config.refresh_ttl_seconds as usize,
            iss: config.issuer.clone(),
            typ: "refresh".to_string(),
        };

        let header = Header::new(Algorithm::EdDSA);
        encode(&header, &claims, &self.encoding).map_err(|e| {
            tracing::error!(error = ?e, "failed to sign refresh token");
            AppError::Internal(anyhow::anyhow!("token signing failed"))
        })
    }

    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["uoozer-vault"]);
        validation.leeway = 5;

        let token_data =
            decode::<AccessTokenClaims>(token, &self.decoding, &validation).map_err(|e| match e
                .kind()
            {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                _ => AppError::Unauthorized,
            })?;

        if token_data.claims.typ != "access" {
            return Err(AppError::Unauthorized);
        }

        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["uoozer-vault"]);
        validation.leeway = 5;

        let token_data = decode::<RefreshTokenClaims>(token, &self.decoding, &validation).map_err(
            |e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                _ => AppError::InvalidRefreshToken,
            },
        )?;

        if token_data.claims.typ != "refresh" {
            return Err(AppError::InvalidRefreshToken);
        }

        Ok(token_data.claims)
    }
}

// ──────────────────────────────────────────────────────────────
// BLAKE3 (for chunk hash verification)
// ──────────────────────────────────────────────────────────────

pub fn verify_blake3(data: &[u8], expected_hash: &[u8]) -> bool {
    let computed = blake3::hash(data);
    let computed_bytes = computed.as_bytes();
    let computed_slice: &[u8] = computed_bytes;
    computed_slice.ct_eq(expected_hash).into()
}

// ──────────────────────────────────────────────────────────────
// Base64 helpers
// ──────────────────────────────────────────────────────────────

pub fn decode_b64(s: &str) -> Result<Vec<u8>, AppError> {
    B64.decode(s)
        .map_err(|_| AppError::BadRequest("invalid base64 encoding".to_string()))
}

pub fn encode_b64(data: &[u8]) -> String {
    B64.encode(data)
}

// ──────────────────────────────────────────────────────────────
// Zeroization wrapper for sensitive data
// ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SecretBox<T: Zeroize + Clone> {
    inner: Arc<T>,
}

impl<T: Zeroize + Clone> SecretBox<T> {
    pub fn new(val: T) -> Self {
        Self {
            inner: Arc::new(val),
        }
    }

    pub fn as_ref(&self) -> &T {
        &self.inner
    }
}
