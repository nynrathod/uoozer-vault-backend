use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// ── Prelogin ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct PreloginRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PreloginResponse {
    pub salt: String, // base64, 16 bytes
    pub argon2_params: serde_json::Value,
}

// ── Signup Init ───────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct SignupInitRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct SignupInitResponse {
    pub signup_token: String,
    pub salt: String,
    pub argon2_params: serde_json::Value,
}

// ── Signup Complete ───────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct SignupCompleteRequest {
    pub signup_token: String,

    /// Base64-encoded Auth Key (32 bytes). Derived client-side via:
    ///   Argon2id(password, salt) -> 32 bytes -> HKDF -> Auth Key branch
    /// Server bcrypt-hashes this and stores only the hash.
    #[validate(length(min = 1))]
    pub auth_key: String,

    /// Base64-encoded Recovery Auth Key (32 bytes). Same derivation path
    /// but from the Recovery Key instead of the password.
    #[validate(length(min = 1))]
    pub recovery_auth_key: String,

    /// Base64-encoded DEK wrapped by the Master Key (XChaCha20-Poly1305).
    /// Opaque to the server.
    pub wrapped_dek: String,
    pub wrapped_dek_nonce: String, // base64, 24 bytes

    /// Base64-encoded DEK wrapped by the Recovery Key.
    pub recovery_wrapped_dek: String,
    pub recovery_wrapped_dek_nonce: String, // base64, 24 bytes

    /// Base64-encoded Ed25519 identity public key (32 bytes).
    pub identity_pubkey: String,

    /// Base64-encoded Ed25519 device public key (32 bytes).
    pub device_pubkey: String,
    pub device_name: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user_id: Uuid,
    pub device_id: Uuid,
}

// ── Login ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,

    /// Base64-encoded Auth Key (32 bytes). Derived from either:
    ///   - Argon2id(password, salt) via HKDF, OR
    ///   - Recovery Key via HKDF
    /// The server verifies against both stored hashes (auth_key_hash
    /// and recovery_auth_key_hash) to support both login paths.
    #[validate(length(min = 1))]
    pub auth_key: String,

    /// Optional: existing device ID for session reuse.
    /// If provided, device_pubkey must match the stored key.
    pub device_id: Option<Uuid>,

    pub device_pubkey: String,
    pub device_name: String,
}

// ── Refresh ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshRequest {
    #[validate(length(min = 1))]
    pub refresh_token: String,
}

// ── Password Change ───────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct PasswordChangeRequest {
    /// New Auth Key derived from the new password.
    #[validate(length(min = 1))]
    pub new_auth_key: String,

    /// DEK re-wrapped under the new Master Key.
    pub new_wrapped_dek: String,
    pub new_wrapped_dek_nonce: String,
}

// ── Logout ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: Option<String>,
    pub revoke_device: Option<bool>,
}
